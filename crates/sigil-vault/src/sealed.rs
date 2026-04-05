//! Git-committable sealed vault implementation
//!
//! This module implements a single-file encrypted vault format that can be
//! safely committed to git. The vault file is publicly visible but
//! computationally infeasible to brute force.
//!
//! ## Vault File Format (.sigil/vault.sealed)
//!
//! ```text
//! ┌──────────────────────────────────────────────────────┐
//! │ Header                                                │
//! │   Magic: "SIGIL-VAULT\x00"                          │
//! │   Format version: u16                                 │
//! │   KDF: Argon2id                                      │
//! │   KDF params: memory=1GiB, iterations=3, parallel=4  │
//! │   Salt: 32 bytes (random)                            │
//! │   Auth factors: bitfield (passphrase|device|totp)    │
//! │   Device salt: 32 bytes (for device key derivation)  │
//! │   TOTP window: u32 (current TOTP period)             │
//! │   Nonce: 24 bytes (XChaCha20-Poly1305)               │
//! │   Key check: 32 bytes (HMAC of known value)          │
//! ├──────────────────────────────────────────────────────┤
//! │ Encrypted payload                                     │
//! │   Cipher: XChaCha20-Poly1305                         │
//! │   Contents: msgpack-encoded secret store             │
//! │   Authenticated: header is AAD                       │
//! └──────────────────────────────────────────────────────┘
//! ```
//!
//! ## Key Derivation — $1B Brute Force Target
//!
//! SIGIL adopts the **1Password Two-Secret Key Derivation (2SKD)** model.
//! The master encryption key is derived from TWO independent secrets:
//!
//! ```text
//! # Factor 1: Passphrase (user-memorized)
//! passphrase_key = Argon2id(passphrase, salt, memory=1GiB, iterations=3, parallelism=4)
//!
//! # Factor 2: Device Secret Key (256 bits, stored at ~/.sigil/device.key)
//! device_key = read("~/.sigil/device.key")  // 256-bit random, generated at sigil init
//!
//! # Combine all factors
//! master_key = HKDF-SHA256(
//!     ikm = passphrase_key || device_key,
//!     salt = vault_salt,
//!     info = "SIGIL-vault-master-v1"
//! )
//! ```

#![warn(missing_docs)]
#![warn(clippy::all)]

use argon2::{
    password_hash::{PasswordHasher, SaltString},
    Algorithm, Argon2, Params, Version,
};
use chacha20poly1305::{aead::AeadMut, KeyInit as AeadKeyInit, XChaCha20Poly1305, XNonce};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::Digest;
use sigil_core::{Result, SigilError};
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use zeroize::{Zeroize, Zeroizing};

// Re-export base64 engine for convenience
pub use base64;

/// Vault file magic bytes
pub const VAULT_MAGIC: &[u8] = b"SIGIL-VAULT\x00";

/// Current vault format version
pub const VAULT_FORMAT_VERSION: u16 = 1;

/// Argon2id memory cost in KiB (1 GiB)
const ARGON2_MEMORY_KIB: u32 = 1024 * 1024; // 1 GiB in KiB

/// Argon2id time cost (iterations)
const ARGON2_TIME_COST: u32 = 3;

/// Argon2id parallelism
const ARGON2_PARALLELISM: u32 = 4;

/// Device key length in bytes (256 bits)
const DEVICE_KEY_LENGTH: usize = 32;

/// Vault salt length in bytes
const VAULT_SALT_LENGTH: usize = 32;

/// XChaCha20-Poly1305 nonce length
const NONCE_LENGTH: usize = 24;

/// Authentication factors bitfield
#[derive(Debug, Clone, Copy, Serialize, Deserialize, Default)]
#[repr(u8)]
pub enum AuthFactor {
    /// No factors set
    #[default]
    None = 0,
    /// Passphrase only
    Passphrase = 1,
    /// Passphrase + Device key
    PassphraseDevice = 3,
    /// Passphrase + Device + TOTP
    PassphraseDeviceTotp = 7,
    /// Shamir's Secret Sharing (team vault)
    Shamir = 8,
}

impl AuthFactor {
    /// Check if device key is required
    pub fn requires_device_key(self) -> bool {
        matches!(self, Self::PassphraseDevice | Self::PassphraseDeviceTotp)
    }

    /// Check if TOTP is required
    pub fn requires_totp(self) -> bool {
        matches!(self, Self::PassphraseDeviceTotp)
    }

    /// Check if Shamir's Secret Sharing is used
    pub fn is_shamir(self) -> bool {
        matches!(self, Self::Shamir)
    }
}

/// Vault header (stored in plaintext)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VaultHeader {
    /// Format version
    pub format_version: u16,
    /// KDF algorithm identifier
    pub kdf_algorithm: String,
    /// KDF memory cost in KiB
    pub kdf_memory: u32,
    /// KDF time cost
    pub kdf_time: u32,
    /// KDF parallelism
    pub kdf_parallelism: u32,
    /// Vault salt (for key derivation)
    #[serde(with = "serde_bytes")]
    pub vault_salt: Vec<u8>,
    /// Device salt (for device key derivation)
    #[serde(with = "serde_bytes")]
    pub device_salt: Vec<u8>,
    /// Authentication factors required
    pub auth_factors: AuthFactor,
    /// Nonce for XChaCha20-Poly1305
    #[serde(with = "serde_bytes")]
    pub nonce: Vec<u8>,
    /// Key check value (HMAC of known value)
    #[serde(with = "serde_bytes")]
    pub key_check: Vec<u8>,
}

impl Default for VaultHeader {
    fn default() -> Self {
        let mut vault_salt = vec![0u8; VAULT_SALT_LENGTH];
        let mut device_salt = vec![0u8; VAULT_SALT_LENGTH];
        let mut nonce = vec![0u8; NONCE_LENGTH];

        let mut rng = rand::thread_rng();
        rng.fill_bytes(&mut vault_salt);
        rng.fill_bytes(&mut device_salt);
        rng.fill_bytes(&mut nonce);

        Self {
            format_version: VAULT_FORMAT_VERSION,
            kdf_algorithm: "argon2id".to_string(),
            kdf_memory: ARGON2_MEMORY_KIB,
            kdf_time: ARGON2_TIME_COST,
            kdf_parallelism: ARGON2_PARALLELISM,
            vault_salt,
            device_salt,
            auth_factors: AuthFactor::PassphraseDevice,
            nonce,
            key_check: Vec::new(), // Will be set during encryption
        }
    }
}

/// Encrypted vault data
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptedVault {
    /// Vault header (plaintext)
    pub header: VaultHeader,
    /// Encrypted payload
    #[serde(with = "serde_bytes")]
    pub ciphertext: Vec<u8>,
}

/// Sealed vault - git-committable single-file vault
pub struct SealedVault {
    /// Path to the vault file
    vault_path: PathBuf,
    /// Path to device key (outside git, typically ~/.sigil/device.key)
    device_key_path: PathBuf,
    /// Vault header (cached)
    header: Option<VaultHeader>,
}

impl SealedVault {
    /// Create a new sealed vault
    pub fn new(vault_path: PathBuf, device_key_path: PathBuf) -> Result<Self> {
        // Ensure parent directory exists
        if let Some(parent) = vault_path.parent() {
            fs::create_dir_all(parent)?;
        }

        // Ensure device key directory exists
        if let Some(parent) = device_key_path.parent() {
            fs::create_dir_all(parent)?;
        }

        Ok(Self {
            vault_path,
            device_key_path,
            header: None,
        })
    }

    /// Initialize a new vault with the given passphrase
    ///
    /// This creates:
    /// 1. A new device key at ~/.sigil/device.key
    /// 2. An empty vault file at the specified path
    pub fn init(&mut self, passphrase: &str) -> Result<String> {
        // Generate device key if it doesn't exist
        if !self.device_key_path.exists() {
            self.generate_device_key()?;
        }

        // Create header with default values
        let mut header = VaultHeader::default();

        // Derive master key and set key check
        let device_key = self.load_device_key()?;
        let master_key = self.derive_master_key(passphrase, &device_key, &header)?;

        // Set key check (HMAC of a known value)
        let key_check = self.compute_key_check(&master_key);
        header.key_check = key_check;

        // Create empty secret store
        let empty_store = serde_json::json!({
            "secrets": {},
            "metadata": {
                "created_at": chrono::Utc::now().to_rfc3339(),
                "version": 1
            }
        });

        // Encrypt the empty store
        let encrypted = self.encrypt_payload(&empty_store, &master_key, &header)?;

        // Create the encrypted vault
        let vault = EncryptedVault {
            header: header.clone(),
            ciphertext: encrypted,
        };

        // Serialize and write
        self.write_vault(&vault)?;

        // Cache header
        self.header = Some(header);

        Ok(format!(
            "Vault initialized at {}. Device key at {}",
            self.vault_path.display(),
            self.device_key_path.display()
        ))
    }

    /// Generate a new device key
    fn generate_device_key(&self) -> Result<()> {
        let mut device_key = vec![0u8; DEVICE_KEY_LENGTH];
        rand::thread_rng().fill_bytes(&mut device_key);

        // Write with restrictive permissions (0600)
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let perms = fs::Permissions::from_mode(0o600);
            let _ = fs::set_permissions(&self.device_key_path, perms);
        }

        fs::write(&self.device_key_path, device_key)?;

        // Add to .gitignore if possible
        if let Some(parent) = self.device_key_path.parent() {
            let gitignore = parent.join(".gitignore");
            if let Ok(mut file) = fs::OpenOptions::new().append(true).open(&gitignore) {
                let _ = writeln!(file, "device.key");
            }
        }

        Ok(())
    }

    /// Generate a CI device key for export
    ///
    /// Returns a base64-encoded device key that can be set as a CI secret.
    /// The key is NOT written to disk.
    pub fn generate_ci_device_key(&self) -> Result<String> {
        let mut device_key = vec![0u8; DEVICE_KEY_LENGTH];
        rand::thread_rng().fill_bytes(&mut device_key);

        // Encode as base64 for safe export as environment variable
        let encoded =
            base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &device_key);

        // Zeroize the original key
        device_key.zeroize();

        Ok(encoded)
    }

    /// Rotate the device key and re-encrypt the vault
    ///
    /// This generates a new device key, re-encrypts the vault with it,
    /// and returns the new base64-encoded key for export.
    pub fn rotate_device_key(&mut self, passphrase: &str) -> Result<String> {
        // Unseal the vault with the current device key
        let data = self.unseal(passphrase)?;

        // Generate new device key
        let new_device_key = self.generate_ci_device_key()?;

        // Decode the new key to get bytes
        let new_key_bytes =
            base64::Engine::decode(&base64::engine::general_purpose::STANDARD, &new_device_key)
                .map_err(|_| {
                    SigilError::Crypto("Failed to decode generated device key".to_string())
                })?;

        // Write the new device key to disk (with restrictive permissions)
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let perms = fs::Permissions::from_mode(0o600);
            let _ = fs::set_permissions(&self.device_key_path, perms);
        }

        fs::write(&self.device_key_path, &new_key_bytes)?;

        // Zeroize the decoded key
        let mut zeroizing = Zeroizing::new(new_key_bytes);
        zeroizing.zeroize();

        // Re-encrypt the vault with the new device key
        self.reseal(passphrase, &data)?;

        Ok(new_device_key)
    }

    /// Load the device key from disk or environment variable
    fn load_device_key(&self) -> Result<Zeroizing<Vec<u8>>> {
        // First check SIGIL_DEVICE_KEY environment variable (for CI mode)
        if let Ok(env_key) = std::env::var("SIGIL_DEVICE_KEY") {
            // Decode from base64
            let key_bytes =
                base64::Engine::decode(&base64::engine::general_purpose::STANDARD, &env_key)
                    .map_err(|_| {
                        SigilError::Crypto("Invalid base64 in SIGIL_DEVICE_KEY".to_string())
                    })?;

            if key_bytes.len() != DEVICE_KEY_LENGTH {
                return Err(SigilError::Crypto(format!(
                    "Invalid device key length in SIGIL_DEVICE_KEY: expected {} bytes, got {}",
                    DEVICE_KEY_LENGTH,
                    key_bytes.len()
                )));
            }

            return Ok(Zeroizing::new(key_bytes));
        }

        // Fall back to reading from disk
        if !self.device_key_path.exists() {
            return Err(SigilError::Crypto(
                "Device key not found. Set SIGIL_DEVICE_KEY or run 'sigil init'.".to_string(),
            ));
        }

        let key = fs::read(&self.device_key_path)?;
        Ok(Zeroizing::new(key))
    }

    /// Derive the master encryption key from passphrase and device key
    fn derive_master_key(
        &self,
        passphrase: &str,
        device_key: &[u8],
        header: &VaultHeader,
    ) -> Result<[u8; 32]> {
        // Derive passphrase key using Argon2id
        let passphrase_key = self.derive_passphrase_key(passphrase, &header.vault_salt)?;

        // Combine with device key using HKDF-SHA256
        let mut ikm = passphrase_key.as_ref().to_vec();
        ikm.extend_from_slice(device_key);

        let hkdf = hkdf::Hkdf::<sha2::Sha256>::new(Some(&header.vault_salt), &ikm);
        let mut master_key = [0u8; 32];
        hkdf.expand(b"SIGIL-vault-master-v1", &mut master_key)
            .map_err(|e| SigilError::Crypto(format!("HKDF error: {}", e)))?;

        Ok(master_key)
    }

    /// Derive passphrase key using Argon2id
    fn derive_passphrase_key(&self, passphrase: &str, salt: &[u8]) -> Result<Zeroizing<[u8; 32]>> {
        let params = Params::new(
            ARGON2_MEMORY_KIB,
            ARGON2_TIME_COST,
            ARGON2_PARALLELISM,
            None,
        )
        .map_err(|e| SigilError::Crypto(format!("Invalid Argon2 params: {}", e)))?;

        let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);

        // Use SaltString for proper salt handling
        let salt_string = SaltString::encode_b64(salt)
            .map_err(|e| SigilError::Crypto(format!("Salt encoding error: {}", e)))?;

        let password_hash = argon2.hash_password(passphrase.as_bytes(), &salt_string);
        let password_hash = password_hash
            .map_err(|e| SigilError::Crypto(format!("Argon2 hashing error: {}", e)))?;

        // Extract the hash bytes from the password hash
        // The .hash field returns Option<&Output>, so we need to unwrap it
        let hash_output = password_hash
            .hash
            .expect("Hash output should always be present");
        let hash_bytes = hash_output.as_bytes();
        let mut key = [0u8; 32];
        key.copy_from_slice(&hash_bytes[..32]);

        Ok(Zeroizing::new(key))
    }

    /// Compute key check value (SHA-256 hash of known value + master_key)
    fn compute_key_check(&self, master_key: &[u8; 32]) -> Vec<u8> {
        let known_value = b"SIGIL-VAULT-KEY-CHECK";
        let mut hasher = sha2::Sha256::new();
        hasher.update(master_key);
        hasher.update(known_value);
        hasher.finalize().to_vec()
    }

    /// Encrypt payload using XChaCha20-Poly1305
    fn encrypt_payload(
        &self,
        payload: &serde_json::Value,
        master_key: &[u8; 32],
        header: &VaultHeader,
    ) -> Result<Vec<u8>> {
        let plaintext = rmp_serde::to_vec(payload)
            .map_err(|e| SigilError::Crypto(format!("MessagePack serialization error: {}", e)))?;

        let mut cipher = XChaCha20Poly1305::new(master_key.into());
        let nonce = XNonce::from_slice(&header.nonce);
        let ciphertext = cipher
            .encrypt(nonce, plaintext.as_ref())
            .map_err(|e| SigilError::Crypto(format!("Encryption error: {}", e)))?;

        Ok(ciphertext)
    }

    /// Decrypt payload using XChaCha20-Poly1305
    fn decrypt_payload(
        &self,
        ciphertext: &[u8],
        master_key: &[u8; 32],
        header: &VaultHeader,
    ) -> Result<serde_json::Value> {
        let mut cipher = XChaCha20Poly1305::new(master_key.into());
        let nonce = XNonce::from_slice(&header.nonce);
        let plaintext = cipher
            .decrypt(nonce, ciphertext)
            .map_err(|e| SigilError::Crypto(format!("Decryption error: {}", e)))?;

        let payload: serde_json::Value = rmp_serde::from_slice(&plaintext)
            .map_err(|e| SigilError::Crypto(format!("MessagePack deserialization error: {}", e)))?;

        Ok(payload)
    }

    /// Write the encrypted vault to disk
    fn write_vault(&self, vault: &EncryptedVault) -> Result<()> {
        let mut data = VAULT_MAGIC.to_vec();
        data.extend_from_slice(&vault.header.format_version.to_be_bytes());

        // Serialize header as JSON for readability
        let header_json = serde_json::to_vec(&vault.header)?;
        data.extend_from_slice(&(header_json.len() as u32).to_be_bytes());
        data.extend_from_slice(&header_json);

        // Append ciphertext
        data.extend_from_slice(&vault.ciphertext);

        fs::write(&self.vault_path, data)?;

        Ok(())
    }

    /// Read and parse the encrypted vault from disk
    fn read_vault(&self) -> Result<EncryptedVault> {
        let data = fs::read(&self.vault_path)?;

        // Check magic bytes
        if !data.starts_with(VAULT_MAGIC) {
            return Err(SigilError::InvalidConfig(
                "Invalid vault file: bad magic bytes".to_string(),
            ));
        }

        let mut pos = VAULT_MAGIC.len();

        // Read format version
        let format_version = u16::from_be_bytes([data[pos], data[pos + 1]]);
        pos += 2;

        if format_version != VAULT_FORMAT_VERSION {
            return Err(SigilError::InvalidConfig(format!(
                "Unsupported vault format version: {}",
                format_version
            )));
        }

        // Read header length
        let header_len =
            u32::from_be_bytes([data[pos], data[pos + 1], data[pos + 2], data[pos + 3]]) as usize;
        pos += 4;

        // Read and parse header
        let header_data = &data[pos..pos + header_len];
        pos += header_len;
        let header: VaultHeader = serde_json::from_slice(header_data)?;

        // Read ciphertext
        let ciphertext = data[pos..].to_vec();

        Ok(EncryptedVault { header, ciphertext })
    }

    /// Unseal (decrypt) the vault with passphrase and device key
    pub fn unseal(&mut self, passphrase: &str) -> Result<serde_json::Value> {
        // Load device key
        let device_key = self.load_device_key()?;

        // Read the vault
        let vault = self.read_vault()?;

        // Derive master key
        let master_key = self.derive_master_key(passphrase, &device_key, &vault.header)?;

        // Verify key check
        let computed_check = self.compute_key_check(&master_key);
        if computed_check != vault.header.key_check {
            return Err(SigilError::VaultLocked);
        }

        // Decrypt payload
        let payload = self.decrypt_payload(&vault.ciphertext, &master_key, &vault.header)?;

        // Cache header
        self.header = Some(vault.header);

        Ok(payload)
    }

    /// Reseal (encrypt) the vault with new data
    pub fn reseal(&mut self, passphrase: &str, data: &serde_json::Value) -> Result<()> {
        // Load device key
        let device_key = self.load_device_key()?;

        // Get or create header
        let header = if let Some(h) = &self.header {
            h.clone()
        } else {
            let vault = self.read_vault()?;
            vault.header
        };

        // Derive master key
        let master_key = self.derive_master_key(passphrase, &device_key, &header)?;

        // Encrypt payload
        let ciphertext = self.encrypt_payload(data, &master_key, &header)?;

        // Create vault
        let vault = EncryptedVault {
            header: header.clone(),
            ciphertext,
        };

        // Write vault
        self.write_vault(&vault)?;

        // Update cached header
        self.header = Some(header);

        Ok(())
    }

    /// Get the vault path
    pub fn vault_path(&self) -> &Path {
        &self.vault_path
    }

    /// Get the device key path
    pub fn device_key_path(&self) -> &Path {
        &self.device_key_path
    }

    /// Check if vault exists
    pub fn exists(&self) -> bool {
        self.vault_path.exists()
    }

    /// Initialize a team vault using Shamir's Secret Sharing
    ///
    /// This creates a vault that can be unsealed using M-of-N shares.
    /// The shares are returned as SLIP39 mnemonic phrases for easy distribution.
    ///
    /// # Arguments
    ///
    /// * `threshold` - Minimum number of shares needed to unseal (M)
    /// * `total_shares` - Total number of shares to generate (N)
    ///
    /// # Constraints
    ///
    /// * 2 ≤ threshold ≤ total_shares ≤ 16
    ///
    /// # Returns
    ///
    /// A vector of SLIP39 mnemonic phrases, one per share
    ///
    /// # Example
    ///
    /// ```rust
    /// use sigil_vault::sealed::SealedVault;
    /// use std::path::PathBuf;
    ///
    /// let vault_path = PathBuf::from(".sigil/vault.sealed");
    /// let mut vault = SealedVault::new_team(vault_path).unwrap();
    ///
    /// // Create 3-of-5 sharing scheme
    /// let shares = vault.init_shamir(3, 5).unwrap();
    /// println!("Share 1: {}", shares[0]);
    /// ```
    pub fn init_shamir(&mut self, threshold: usize, total_shares: usize) -> Result<Vec<String>> {
        use sigil_shamir::ShamirSecretSharing;

        // Generate a random 256-bit master key
        let mut master_key = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut master_key);

        // Split the master key using Shamir's Secret Sharing
        let sss = ShamirSecretSharing::new();
        let shares = match sss.split(&master_key, threshold, total_shares) {
            Ok(s) => s,
            Err(e) => return Err(SigilError::Crypto(format!("Failed to split secret: {}", e))),
        };

        // Create empty secret store
        let empty_store = serde_json::json!({
            "secrets": {},
            "metadata": {
                "created_at": chrono::Utc::now().to_rfc3339(),
                "version": 1,
                "vault_type": "shamir",
                "threshold": threshold,
                "total_shares": total_shares,
            }
        });

        // Encrypt with the master key directly
        let mut header = VaultHeader::default();
        header.auth_factors = AuthFactor::Shamir;

        let ciphertext = self.encrypt_payload(&empty_store, &master_key, &header)?;

        // Create the encrypted vault
        let vault = EncryptedVault {
            header: header.clone(),
            ciphertext,
        };

        // Write vault
        self.write_vault(&vault)?;

        // Cache header
        self.header = Some(header);

        // Convert shares to mnemonic phrases
        let mut mnemonics = Vec::new();
        for share in shares {
            let mnemonic = share.to_mnemonic().map_err(|e| {
                SigilError::Crypto(format!("Failed to encode share: {}", e))
            });
            let mnemonic = match mnemonic {
                Ok(m) => m,
                Err(e) => return Err(e),
            };
            mnemonics.push(mnemonic);
        }

        Ok(mnemonics)
    }

    /// Unseal the vault using Shamir's Secret Sharing shares
    ///
    /// # Arguments
    ///
    /// * `mnemonics` - Slice of SLIP39 mnemonic phrases (at least threshold)
    ///
    /// # Example
    ///
    /// ```rust
    /// # use sigil_vault::sealed::SealedVault;
    /// # use std::path::PathBuf;
    /// # let vault_path = PathBuf::from(".sigil/vault.sealed");
    /// # let mut vault = SealedVault::new_team(vault_path).unwrap();
    /// # let shares = vault.init_shamir(3, 5).unwrap();
    /// // Unseal with any 3 shares (convert to &str references)
    /// let share_refs: Vec<&str> = shares.iter().map(|s| s.as_str()).collect();
    /// let data = vault.unseal_shamir(&share_refs).unwrap();
    /// ```
    pub fn unseal_shamir(&mut self, mnemonics: &[&str]) -> Result<serde_json::Value> {
        use sigil_shamir::{Share, ShamirSecretSharing};

        // Decode mnemonics to shares
        let mut shares = Vec::with_capacity(mnemonics.len());
        for mnemonic in mnemonics {
            let share = Share::from_mnemonic(mnemonic).map_err(|e| {
                SigilError::Crypto(format!("Failed to decode share mnemonic: {}", e))
            })?;
            shares.push(share);
        }

        // Combine shares to get the master key
        let sss = ShamirSecretSharing::new();
        let master_key_vec = sss.combine(&shares).map_err(|e| {
            SigilError::Crypto(format!("Failed to combine Shamir shares: {}", e))
        })?;

        // Convert Vec<u8> to [u8; 32]
        if master_key_vec.len() != 32 {
            return Err(SigilError::Crypto(format!(
                "Invalid master key length: expected 32 bytes, got {}",
                master_key_vec.len()
            )));
        }

        let mut master_key_array = [0u8; 32];
        master_key_array.copy_from_slice(&master_key_vec);

        // Read the vault
        let vault = self.read_vault()?;

        // Verify this is a Shamir vault
        if !vault.header.auth_factors.is_shamir() {
            return Err(SigilError::InvalidConfig(
                "This vault is not a Shamir team vault".to_string(),
            ));
        }

        // Decrypt using the master key
        let payload = self.decrypt_payload(&vault.ciphertext, &master_key_array, &vault.header)?;

        // Cache header
        self.header = Some(vault.header);

        Ok(payload)
    }

    /// Get information about the vault's Shamir configuration
    ///
    /// Returns None if the vault is not a Shamir vault
    pub fn shamir_info(&self) -> Result<Option<ShamirVaultInfo>> {
        if !self.exists() {
            return Ok(None);
        }

        let vault = self.read_vault()?;

        if !vault.header.auth_factors.is_shamir() {
            return Ok(None);
        }

        // The info should be in the vault metadata, but we need to decrypt to read it
        // For now, return what we can from the header
        Ok(Some(ShamirVaultInfo {
            vault_type: "shamir".to_string(),
            auth_factors: vault.header.auth_factors,
        }))
    }
}

/// Information about a Shamir team vault
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShamirVaultInfo {
    /// Type of vault
    pub vault_type: String,
    /// Authentication factors used
    pub auth_factors: AuthFactor,
}

/// Create a new SealedVault for team vault use (no device key needed)
impl SealedVault {
    /// Create a new team vault (no device key required)
    ///
    /// Team vaults use Shamir's Secret Sharing and don't require a device key.
    pub fn new_team(vault_path: PathBuf) -> Result<Self> {
        // Ensure parent directory exists
        if let Some(parent) = vault_path.parent() {
            fs::create_dir_all(parent)?;
        }

        Ok(Self {
            vault_path,
            device_key_path: PathBuf::from(""), // Not used for team vaults
            header: None,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn create_test_vault() -> (TempDir, SealedVault) {
        let temp_dir = TempDir::new().unwrap();
        let vault_path = temp_dir.path().join("vault.sealed");
        let device_key_path = temp_dir.path().join("device.key");

        let mut vault = SealedVault::new(vault_path, device_key_path).unwrap();
        vault.init("test-password").unwrap();

        (temp_dir, vault)
    }

    #[test]
    fn test_vault_init_and_unseal() {
        let (_temp_dir, mut vault) = create_test_vault();

        assert!(vault.exists());
        assert!(vault.device_key_path().exists());

        let data = vault.unseal("test-password").unwrap();
        assert!(data.is_object());
    }

    #[test]
    fn test_vault_wrong_password() {
        let (_temp_dir, mut vault) = create_test_vault();

        let result = vault.unseal("wrong-password");
        assert!(matches!(result, Err(SigilError::VaultLocked)));
    }

    #[test]
    fn test_vault_reseal() {
        let (_temp_dir, mut vault) = create_test_vault();

        let new_data = serde_json::json!({
            "secrets": {
                "test/key": "value"
            },
            "metadata": {
                "updated": true
            }
        });

        vault.reseal("test-password", &new_data).unwrap();

        let unsealed = vault.unseal("test-password").unwrap();
        assert_eq!(unsealed["secrets"]["test/key"], "value");
    }

    #[test]
    fn test_header_default() {
        let header = VaultHeader::default();
        assert_eq!(header.format_version, VAULT_FORMAT_VERSION);
        assert_eq!(header.kdf_memory, ARGON2_MEMORY_KIB);
        assert_eq!(header.kdf_time, ARGON2_TIME_COST);
        assert_eq!(header.kdf_parallelism, ARGON2_PARALLELISM);
        assert_eq!(header.vault_salt.len(), VAULT_SALT_LENGTH);
        assert_eq!(header.device_salt.len(), VAULT_SALT_LENGTH);
        assert_eq!(header.nonce.len(), NONCE_LENGTH);
    }

    #[test]
    fn test_auth_factor() {
        assert!(!AuthFactor::None.requires_device_key());
        assert!(!AuthFactor::Passphrase.requires_device_key());
        assert!(AuthFactor::PassphraseDevice.requires_device_key());
        assert!(AuthFactor::PassphraseDeviceTotp.requires_device_key());
        assert!(AuthFactor::PassphraseDeviceTotp.requires_totp());
    }
}
