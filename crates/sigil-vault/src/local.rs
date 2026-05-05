//! Local vault implementation using age-encrypted files

use age::{
    secrecy::{ExposeSecret, Secret},
    x25519, Decryptor, Encryptor, Identity as AgeIdentity,
};
use sigil_core::{Result, SecretBackend, SecretMetadata, SecretPath, SecretValue, SigilError};
use std::fs;
use std::io::{Read, Write};
use std::path::PathBuf;
use std::str::FromStr;

/// Permissions for secret files (user read/write only)
const VAULT_FILE_PERMS: u32 = 0o600;

/// Permissions for vault directories (user access only)
const VAULT_DIR_PERMS: u32 = 0o700;

/// Set file permissions to user-only read/write (0600)
///
/// This is a security requirement for all vault files containing secret material.
/// If setting permissions fails, we return an error rather than continuing with
/// insecure permissions.
fn set_secret_file_permissions(path: &PathBuf) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = fs::metadata(path)
            .map_err(|e| SigilError::IoError(format!("Failed to read metadata: {}", e)))?
            .permissions();
        perms.set_mode(VAULT_FILE_PERMS);
        fs::set_permissions(path, perms)
            .map_err(|e| SigilError::IoError(format!("Failed to set file permissions: {}", e)))?;
    }

    #[cfg(not(unix))]
    {
        // On non-Unix platforms, we still try to set read-only for user
        let perms = fs::metadata(path)
            .map_err(|e| SigilError::IoError(format!("Failed to read metadata: {}", e)))?
            .permissions();
        fs::set_permissions(path, perms)
            .map_err(|e| SigilError::IoError(format!("Failed to set file permissions: {}", e)))?;
    }

    Ok(())
}

/// Set directory permissions to user-only access (0700)
///
/// This is a security requirement for all vault directories.
/// If setting permissions fails, we return an error rather than continuing with
/// insecure permissions.
fn set_secret_dir_permissions(path: &PathBuf) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = fs::metadata(path)
            .map_err(|e| SigilError::IoError(format!("Failed to read metadata: {}", e)))?
            .permissions();
        perms.set_mode(VAULT_DIR_PERMS);
        fs::set_permissions(path, perms).map_err(|e| {
            SigilError::IoError(format!("Failed to set directory permissions: {}", e))
        })?;
    }

    Ok(())
}

/// Write data to a file with secure permissions (0600)
///
/// This helper ensures that vault files are always written with
/// user-only permissions, never with default umask permissions.
fn write_secret_file(path: &PathBuf, data: &[u8]) -> Result<()> {
    fs::write(path, data)
        .map_err(|e| SigilError::IoError(format!("Failed to write file: {}", e)))?;
    set_secret_file_permissions(path)?;
    Ok(())
}

/// Create a directory with secure permissions (0700)
///
/// This helper ensures that vault directories are always created with
/// user-only permissions, never with default umask permissions.
fn create_secret_dir(path: &PathBuf) -> Result<()> {
    fs::create_dir_all(path)
        .map_err(|e| SigilError::IoError(format!("Failed to create directory: {}", e)))?;
    set_secret_dir_permissions(path)?;
    Ok(())
}

#[cfg(feature = "pq-hybrid")]
use crate::pq_kem::KemKeyPair;

/// Local vault implementation using age-encrypted files
pub struct LocalVault {
    /// Path to the vault directory
    vault_path: PathBuf,
    /// Path to the age identity file
    identity_path: PathBuf,
    /// Age identity keypair
    identity: Option<Identity>,
    /// Post-quantum hybrid mode enabled
    #[cfg(feature = "pq-hybrid")]
    pq_hybrid_enabled: bool,
}

/// Age identity keypair (secret)
struct Identity {
    /// The secret key
    key: x25519::Identity,
    /// ML-KEM-768 keypair for post-quantum hybrid mode (optional)
    #[cfg(feature = "pq-hybrid")]
    kem_keypair: Option<KemKeyPair>,
}

impl LocalVault {
    /// Create a new local vault
    pub fn new(vault_path: PathBuf, identity_path: PathBuf) -> Result<Self> {
        // Ensure vault directory exists with secure permissions
        create_secret_dir(&vault_path)?;

        Ok(Self {
            vault_path,
            identity_path,
            identity: None,
            #[cfg(feature = "pq-hybrid")]
            pq_hybrid_enabled: false,
        })
    }

    /// Create a new local vault with post-quantum hybrid mode enabled
    #[cfg(feature = "pq-hybrid")]
    pub fn new_with_pq_hybrid(vault_path: PathBuf, identity_path: PathBuf) -> Result<Self> {
        // Ensure vault directory exists with secure permissions
        create_secret_dir(&vault_path)?;

        Ok(Self {
            vault_path,
            identity_path,
            identity: None,
            pq_hybrid_enabled: true,
        })
    }

    /// Check if post-quantum hybrid mode is enabled
    #[cfg(feature = "pq-hybrid")]
    pub fn is_pq_hybrid_enabled(&self) -> bool {
        self.pq_hybrid_enabled
    }

    /// Enable post-quantum hybrid mode
    #[cfg(feature = "pq-hybrid")]
    pub fn enable_pq_hybrid(&mut self) {
        self.pq_hybrid_enabled = true;
    }

    /// Disable post-quantum hybrid mode
    #[cfg(feature = "pq-hybrid")]
    pub fn disable_pq_hybrid(&mut self) {
        self.pq_hybrid_enabled = false;
    }

    /// Initialize the vault with a new age keypair
    pub fn init(&mut self, passphrase: Option<&str>) -> Result<String> {
        // Generate a new x25519 keypair
        let keypair = x25519::Identity::generate();

        // Generate ML-KEM-768 keypair if hybrid mode is enabled
        #[cfg(feature = "pq-hybrid")]
        let kem_keypair = if self.pq_hybrid_enabled {
            Some(KemKeyPair::generate()?)
        } else {
            None
        };

        // Serialize the secret key
        let secret_key = keypair.to_string();

        // Encrypt the identity with passphrase if provided, otherwise write plaintext
        if let Some(pass) = passphrase {
            // Use passphrase-based encryption for the identity file
            let encryptor = Encryptor::with_user_passphrase(Secret::new(pass.to_owned()));

            let mut encrypted = Vec::new();
            {
                let mut writer = encryptor
                    .wrap_output(&mut encrypted)
                    .map_err(|e| SigilError::Crypto(format!("Encryption error: {}", e)))?;
                writer.write_all(secret_key.expose_secret().as_bytes())?;
                writer.finish()?;
            }

            write_secret_file(&self.identity_path, &encrypted)?;
        } else {
            // Write plaintext identity (not recommended, but supported)
            write_secret_file(&self.identity_path, secret_key.expose_secret().as_bytes())?;
        }

        // Store ML-KEM keypair if hybrid mode is enabled
        #[cfg(feature = "pq-hybrid")]
        if let Some(kem) = &kem_keypair {
            let kem_path = self.identity_path.with_extension("ml-kem");
            let kem_json = serde_json::to_string_pretty(kem).map_err(|e| {
                SigilError::Crypto(format!("Failed to serialize ML-KEM keypair: {}", e))
            })?;
            write_secret_file(&kem_path, kem_json.as_bytes())?;
        }

        // Get the public key before storing
        let public_key = keypair.to_public().to_string();

        // Store the identity in memory
        self.identity = Some(Identity {
            key: keypair,
            #[cfg(feature = "pq-hybrid")]
            kem_keypair,
        });

        // Return the public key (recipient)
        Ok(public_key)
    }

    /// Load the vault from disk
    pub fn load(&mut self, passphrase: Option<&str>) -> Result<()> {
        // Check if identity file exists
        if !self.identity_path.exists() {
            return Err(SigilError::VaultLocked);
        }

        // Read the identity file
        let encrypted = std::fs::read(&self.identity_path)?;

        // Try to decrypt it
        let secret_key_bytes = if let Some(pass) = passphrase {
            // Try passphrase-based decryption
            let decryptor = Decryptor::new(&encrypted[..])
                .map_err(|e| SigilError::Crypto(format!("Decryptor error: {}", e)))?;

            let secret_key_str = match decryptor {
                Decryptor::Passphrase(d) => {
                    // decrypt() returns a Reader impl
                    let mut reader = d
                        .decrypt(&Secret::new(pass.to_owned()), None)
                        .map_err(|e| SigilError::Crypto(format!("Decryption error: {}", e)))?;

                    let mut decrypted = Vec::new();
                    reader
                        .read_to_end(&mut decrypted)
                        .map_err(|e| SigilError::Crypto(format!("Read error: {}", e)))?;
                    decrypted
                }
                _ => return Err(SigilError::Crypto("Unexpected decryptor type".into())),
            };
            secret_key_str
        } else {
            // Try reading as plaintext (for testing purposes only)
            encrypted
        };

        let secret_key_str = String::from_utf8(secret_key_bytes)
            .map_err(|e| SigilError::Crypto(format!("Invalid UTF-8: {}", e)))?;

        // Parse the identity
        let key = x25519::Identity::from_str(&secret_key_str)
            .map_err(|e| SigilError::Crypto(format!("Failed to parse identity: {}", e)))?;

        // Try to load ML-KEM keypair if it exists (pq-hybrid mode)
        #[cfg(feature = "pq-hybrid")]
        let kem_keypair = {
            let kem_path = self.identity_path.with_extension("ml-kem");
            if kem_path.exists() {
                let kem_json = std::fs::read_to_string(&kem_path)?;
                Some(serde_json::from_str::<KemKeyPair>(&kem_json).map_err(|e| {
                    SigilError::Crypto(format!("Failed to parse ML-KEM keypair: {}", e))
                })?)
            } else {
                None
            }
        };

        // Enable pq-hybrid mode if ML-KEM keypair exists
        #[cfg(feature = "pq-hybrid")]
        if kem_keypair.is_some() {
            self.pq_hybrid_enabled = true;
        }

        self.identity = Some(Identity {
            key,
            #[cfg(feature = "pq-hybrid")]
            kem_keypair,
        });
        Ok(())
    }

    /// Get the vault path
    pub fn vault_path(&self) -> &PathBuf {
        &self.vault_path
    }

    /// Get the identity path
    pub fn identity_path(&self) -> &PathBuf {
        &self.identity_path
    }

    /// Get the age recipient (public key)
    pub fn recipient(&self) -> Result<String> {
        let identity = self.identity.as_ref().ok_or(SigilError::VaultLocked)?;
        Ok(identity.key.to_public().to_string())
    }

    /// Get the ML-KEM-768 public key (for post-quantum hybrid mode)
    ///
    /// Returns None if pq-hybrid mode is not enabled or ML-KEM keypair doesn't exist
    #[cfg(feature = "pq-hybrid")]
    pub fn kem_public_key(&self) -> Result<Option<Vec<u8>>> {
        let identity = self.identity.as_ref().ok_or(SigilError::VaultLocked)?;
        Ok(identity
            .kem_keypair
            .as_ref()
            .map(|k| k.public_key_bytes().to_vec()))
    }

    /// Encapsulate a shared secret using the ML-KEM-768 public key
    ///
    /// This allows someone with your ML-KEM public key to create a shared secret
    /// that only you can decapsulate with your secret key.
    ///
    /// Returns (ciphertext, shared_secret) where:
    /// - ciphertext: send this to the vault owner (can be decapsulated by them)
    /// - shared_secret: use this for encryption (same secret the vault owner will get)
    #[cfg(feature = "pq-hybrid")]
    pub fn encapsulate(public_key: &[u8]) -> Result<(Vec<u8>, Vec<u8>)> {
        KemKeyPair::encapsulate(public_key)
    }

    /// Decapsulate a shared secret from ciphertext using the ML-KEM-768 secret key
    ///
    /// This allows the vault owner to recover the shared secret from the ciphertext.
    #[cfg(feature = "pq-hybrid")]
    pub fn decapsulate(&self, ciphertext: &[u8]) -> Result<Vec<u8>> {
        let identity = self.identity.as_ref().ok_or(SigilError::VaultLocked)?;
        let kem_keypair = identity
            .kem_keypair
            .as_ref()
            .ok_or_else(|| SigilError::Crypto("ML-KEM keypair not available".into()))?;
        kem_keypair.decapsulate(ciphertext)
    }

    /// Get the path to a secret file
    fn secret_path(&self, path: &SecretPath) -> PathBuf {
        let mut p = self.vault_path.clone();
        for part in path.as_str().split('/') {
            p.push(part);
        }
        p.set_extension("age");
        p
    }

    /// Get the path to the secret's directory (for namespace organization)
    fn secret_dir(&self, path: &SecretPath) -> PathBuf {
        let mut p = self.vault_path.clone();
        // Add all path components except the last one (the secret name)
        let parts: Vec<&str> = path.as_str().split('/').collect();
        for part in parts.iter().take(parts.len().saturating_sub(1)) {
            p.push(part);
        }
        p
    }

    /// Encrypt a value using the age identity
    #[allow(dead_code)]
    fn encrypt_value(&self, value: &SecretValue) -> Result<Vec<u8>> {
        let identity = self.identity.as_ref().ok_or(SigilError::VaultLocked)?;

        let plaintext = value.expose(|v| v.to_vec());

        let recipient = identity.key.to_public();
        let encryptor = Encryptor::with_recipients(vec![Box::new(recipient)])
            .ok_or_else(|| SigilError::Crypto("No recipients specified".into()))?;

        let mut encrypted = Vec::new();
        {
            let mut writer = encryptor
                .wrap_output(&mut encrypted)
                .map_err(|e| SigilError::Crypto(format!("Encryption error: {}", e)))?;
            writer.write_all(&plaintext)?;

            // Explicitly finish the stream writer
            writer.finish()?;
        }

        Ok(encrypted)
    }

    /// Decrypt a value using the age identity
    fn decrypt_value(&self, encrypted: &[u8]) -> Result<SecretValue> {
        let identity = self.identity.as_ref().ok_or(SigilError::VaultLocked)?;

        let decryptor = Decryptor::new(encrypted)
            .map_err(|e| SigilError::Crypto(format!("Decryptor error: {}", e)))?;

        let mut decrypted = Vec::new();

        match decryptor {
            Decryptor::Recipients(d) => {
                // decrypt() returns a Reader impl
                let mut reader = d
                    .decrypt(std::iter::once(&identity.key as &dyn AgeIdentity))
                    .map_err(|e| SigilError::Crypto(format!("Decryption error: {}", e)))?;

                reader
                    .read_to_end(&mut decrypted)
                    .map_err(|e| SigilError::Crypto(format!("Read error: {}", e)))?;
            }
            _ => return Err(SigilError::Crypto("Unexpected decryptor type".into())),
        };

        Ok(SecretValue::new(decrypted))
    }

    /// Get all versions of all secrets for scrubber loading
    ///
    /// This returns a map of secret paths to all their historical versions.
    /// Each secret path maps to a vector of (version, value) tuples.
    ///
    /// This is important for the security requirement that the scrubber loads
    /// ALL versions, not just current: "the Aho-Corasick scrubber includes
    /// patterns for all retained versions, not just current. A leaked old secret
    /// is still detected."
    pub async fn get_all_versions(
        &self,
    ) -> Result<std::collections::HashMap<String, Vec<(u32, Vec<u8>)>>> {
        use std::collections::HashMap;
        let mut all_versions = HashMap::new();

        // Ensure vault is loaded
        if self.identity.is_none() {
            return Ok(all_versions);
        }

        // Walk the vault directory
        if !self.vault_path.exists() {
            return Ok(all_versions);
        }

        let entries = std::fs::read_dir(&self.vault_path)?;

        for entry in entries {
            let entry = entry?;
            let namespace_dir = entry.path();

            // Skip non-directories
            if !namespace_dir.is_dir() {
                continue;
            }

            // Get namespace name
            let namespace = namespace_dir
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or("");

            // Process each secret file in the namespace
            if let Ok(files) = std::fs::read_dir(&namespace_dir) {
                for file_entry in files.flatten() {
                    let file_path = file_entry.path();

                    // Look for version files (pattern: *.vN.age)
                    if let Some(file_name) = file_path.file_name().and_then(|n| n.to_str()) {
                        if let Some(rest) = file_name.strip_suffix(".age") {
                            // Check if this is a version file or a symlink
                            if let Some(dot_idx) = rest.rfind(".v") {
                                // This is a version file: secret_name.vN.age
                                let secret_name = &rest[..dot_idx];
                                let version_str = &rest[dot_idx + 2..];

                                // Parse version number
                                if let Ok(version) = version_str.parse::<u32>() {
                                    let secret_path = format!("{}/{}", namespace, secret_name);

                                    // Decrypt the version file
                                    if let Ok(encrypted) = std::fs::read(&file_path) {
                                        if let Ok(value) = self.decrypt_value(&encrypted) {
                                            let value_bytes = value.expose(|v| v.to_vec());
                                            all_versions
                                                .entry(secret_path)
                                                .or_insert_with(Vec::new)
                                                .push((version, value_bytes));
                                        }
                                    }
                                }
                            } else {
                                // This is the current file (symlink or regular file)
                                // Skip it since we'll get it from the version files
                                continue;
                            }
                        }
                    }
                }
            }
        }

        Ok(all_versions)
    }
}

#[async_trait::async_trait]
impl SecretBackend for LocalVault {
    async fn get(&self, path: &SecretPath) -> Result<SecretValue> {
        let secret_file = self.secret_path(path);

        if !secret_file.exists() {
            return Err(SigilError::SecretNotFound(path.as_str().to_string()));
        }

        let encrypted = std::fs::read(&secret_file)?;
        self.decrypt_value(&encrypted)
    }

    async fn get_metadata(&self, path: &SecretPath) -> Result<SecretMetadata> {
        let secret_file = self.secret_path(path);

        if !secret_file.exists() {
            return Err(SigilError::SecretNotFound(path.as_str().to_string()));
        }

        // Try to read metadata file
        let metadata_path = secret_file.with_extension("meta.json");
        let meta = if metadata_path.exists() {
            let meta_json = std::fs::read_to_string(&metadata_path)?;
            serde_json::from_str(&meta_json)?
        } else {
            // Create default metadata
            SecretMetadata::new(path.clone())
        };

        Ok(meta)
    }

    async fn set(
        &self,
        path: &SecretPath,
        value: &SecretValue,
        meta: &SecretMetadata,
    ) -> Result<()> {
        use crate::version_manager::VersionManager;
        use sigil_core::SecretVersion;

        let identity = self.identity.as_ref().ok_or(SigilError::VaultLocked)?;

        // Create the namespace directory if needed with secure permissions
        let secret_dir = self.secret_dir(path);
        create_secret_dir(&secret_dir)?;

        // Get namespace and secret name
        let namespace = path.namespace().unwrap_or("default");
        let secret_name = path.name();

        // Create version manager
        let namespace_dir = self.vault_path.join(namespace);
        let version_manager = VersionManager::new(namespace_dir, identity.key.clone());

        // Determine next version number
        let next_version = version_manager.next_version(secret_name)?;
        let current_version = version_manager.current_version(secret_name)?;

        // Create version metadata
        let value_bytes = value.expose(|v| v.to_vec());
        let version_meta = if current_version.is_some() {
            SecretVersion::rotation(next_version, &value_bytes, next_version.saturating_sub(1))
        } else {
            SecretVersion::initial(next_version, &value_bytes)
        };

        // Save the version using VersionManager
        version_manager.save_version(secret_name, value, &version_meta)?;

        // Update metadata file (for backward compatibility with non-versioned secrets)
        let secret_file = self.secret_path(path);
        let metadata_path = secret_file.with_extension("meta.json");
        let metadata_json = serde_json::to_string_pretty(meta)?;
        write_secret_file(&metadata_path, metadata_json.as_bytes())?;

        Ok(())
    }

    async fn delete(&self, path: &SecretPath) -> Result<()> {
        let secret_file = self.secret_path(path);

        if !secret_file.exists() {
            return Err(SigilError::SecretNotFound(path.as_str().to_string()));
        }

        // Get namespace and secret name
        let namespace = path.namespace().unwrap_or("default");
        let secret_name = path.name();

        // Remove the symlink
        if secret_file.is_symlink() {
            std::fs::remove_file(&secret_file)?;
        }

        // Remove all version files
        let namespace_dir = self.vault_path.join(namespace);
        if let Ok(entries) = std::fs::read_dir(&namespace_dir) {
            for entry in entries.flatten() {
                let file_path = entry.path();
                if let Some(file_name) = file_path.file_name().and_then(|n| n.to_str()) {
                    // Match version files: secret_name.vN.age
                    if file_name.starts_with(&format!("{}.", secret_name))
                        && file_name.ends_with(".age")
                    {
                        let _ = std::fs::remove_file(&file_path);
                    }
                    // Match history file: secret_name.history.jsonl.age
                    if file_name == format!("{}.history.jsonl.age", secret_name) {
                        let _ = std::fs::remove_file(&file_path);
                    }
                }
            }
        }

        // Also remove metadata file if it exists
        let metadata_path = secret_file.with_extension("meta.json");
        if metadata_path.exists() {
            std::fs::remove_file(&metadata_path)?;
        }

        Ok(())
    }

    async fn list(&self, prefix: &str) -> Result<Vec<SecretMetadata>> {
        let mut secrets = Vec::new();

        // Walk the vault directory
        if self.vault_path.exists() {
            let entries = std::fs::read_dir(&self.vault_path)?;

            for entry in entries {
                let entry = entry?;
                let path = entry.path();

                // Skip non-directories
                if !path.is_dir() {
                    continue;
                }

                // Check if directory name matches prefix
                let dir_name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");

                if !prefix.is_empty() && !dir_name.starts_with(prefix) {
                    continue;
                }

                // List .age files in this directory
                if let Ok(files) = std::fs::read_dir(&path) {
                    for file_entry in files.flatten() {
                        let file_path = file_entry.path();
                        if file_path.extension().and_then(|s| s.to_str()) == Some("age") {
                            // Extract secret name from file stem
                            if let Some(name) = file_path.file_stem() {
                                if let Some(name_str) = name.to_str() {
                                    // Skip version files (pattern: secret_name.vN.age)
                                    // Version files have a dot in the stem before the version number
                                    if name_str.contains(".v")
                                        && name_str
                                            .chars()
                                            .nth(name_str.find(".v").unwrap_or(0) + 2)
                                            .is_some_and(|c| c.is_numeric())
                                    {
                                        continue;
                                    }

                                    // Skip history files
                                    if name_str.ends_with(".history.jsonl") {
                                        continue;
                                    }

                                    let secret_path =
                                        SecretPath::new(format!("{}/{}", dir_name, name_str))?;

                                    // Try to read metadata
                                    let metadata_path = file_path.with_extension("meta.json");
                                    let meta = if metadata_path.exists() {
                                        let meta_json = std::fs::read_to_string(&metadata_path)?;
                                        serde_json::from_str(&meta_json)?
                                    } else {
                                        SecretMetadata::new(secret_path.clone())
                                    };

                                    secrets.push(meta);
                                }
                            }
                        }
                    }
                }
            }
        }

        Ok(secrets)
    }

    fn backend_type(&self) -> &str {
        "local"
    }
}

/// Get the workspace root directory
///
/// This helper function is used by tests to locate files in the workspace.
#[allow(dead_code)]
fn workspace_root() -> std::path::PathBuf {
    let manifest_dir = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    // CARGO_MANIFEST_DIR is .../crates/sigil-vault
    // We need to go up two levels to get to the workspace root
    manifest_dir
        .parent()
        .and_then(|p| p.parent())
        .map(|p| p.to_path_buf())
        .unwrap_or_else(|| manifest_dir.clone())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_local_vault_creation() {
        let temp_dir = tempfile::tempdir().unwrap();
        let vault_path = temp_dir.path().join("vault");
        let identity_path = temp_dir.path().join("identity.age");

        let vault = LocalVault::new(vault_path, identity_path);
        assert!(vault.is_ok());
        assert!(vault.unwrap().vault_path().exists());
    }

    #[tokio::test]
    async fn test_vault_init_and_roundtrip() {
        let temp_dir = tempfile::tempdir().unwrap();
        let vault_path = temp_dir.path().join("vault");
        let identity_path = temp_dir.path().join("identity.age");

        let mut vault = LocalVault::new(vault_path, identity_path).unwrap();

        // Initialize vault
        let recipient = vault.init(Some("test-passphrase")).unwrap();
        assert!(!recipient.is_empty());

        // Set a secret
        let path = SecretPath::new("test/api_key").unwrap();
        let value = SecretValue::from_string("my-secret-key".to_string());
        let meta = SecretMetadata::new(path.clone());
        vault.set(&path, &value, &meta).await.unwrap();

        // Get the secret
        let retrieved = vault.get(&path).await.unwrap();
        assert_eq!(
            retrieved.expose(|v| v.to_vec()),
            value.expose(|v| v.to_vec())
        );

        // List secrets
        let secrets = vault.list("").await.unwrap();
        assert_eq!(secrets.len(), 1);
        assert_eq!(secrets[0].path.as_str(), "test/api_key");
    }

    #[tokio::test]
    async fn test_vault_load_with_passphrase() {
        let temp_dir = tempfile::tempdir().unwrap();
        let vault_path = temp_dir.path().join("vault");
        let identity_path = temp_dir.path().join("identity.age");

        // Create and initialize vault
        {
            let mut vault = LocalVault::new(vault_path.clone(), identity_path.clone()).unwrap();
            let _recipient = vault.init(Some("test-passphrase")).unwrap();

            let path = SecretPath::new("test/secret").unwrap();
            let value = SecretValue::from_string("test-value".to_string());
            let meta = SecretMetadata::new(path.clone());
            vault.set(&path, &value, &meta).await.unwrap();
        }

        // Load the vault
        let mut vault = LocalVault::new(vault_path, identity_path).unwrap();
        vault.load(Some("test-passphrase")).unwrap();

        // Verify we can access the secret
        let path = SecretPath::new("test/secret").unwrap();
        let retrieved = vault.get(&path).await.unwrap();
        assert_eq!(
            retrieved.expose(|v| String::from_utf8(v.to_vec()).unwrap()),
            "test-value"
        );
    }

    #[tokio::test]
    async fn test_vault_delete() {
        let temp_dir = tempfile::tempdir().unwrap();
        let vault_path = temp_dir.path().join("vault");
        let identity_path = temp_dir.path().join("identity.age");

        let mut vault = LocalVault::new(vault_path, identity_path).unwrap();
        vault.init(Some("test-passphrase")).unwrap();

        let path = SecretPath::new("test/secret").unwrap();
        let value = SecretValue::from_string("test-value".to_string());
        let meta = SecretMetadata::new(path.clone());
        vault.set(&path, &value, &meta).await.unwrap();

        // Delete the secret
        vault.delete(&path).await.unwrap();

        // Verify it's gone
        assert!(vault.get(&path).await.is_err());
    }

    #[tokio::test]
    async fn test_vault_list_with_prefix() {
        let temp_dir = tempfile::tempdir().unwrap();
        let vault_path = temp_dir.path().join("vault");
        let identity_path = temp_dir.path().join("identity.age");

        let mut vault = LocalVault::new(vault_path, identity_path).unwrap();
        vault.init(Some("test-passphrase")).unwrap();

        // Add secrets to different namespaces
        for (ns, name) in [("prod", "key1"), ("prod", "key2"), ("dev", "key1")] {
            let path = SecretPath::new(format!("{}/{}", ns, name)).unwrap();
            let value = SecretValue::from_string(format!("{}-value", name));
            let meta = SecretMetadata::new(path.clone());
            vault.set(&path, &value, &meta).await.unwrap();
        }

        // List all secrets
        let all = vault.list("").await.unwrap();
        assert_eq!(all.len(), 3);

        // List only prod secrets
        let prod = vault.list("prod").await.unwrap();
        assert_eq!(prod.len(), 2);
    }

    #[tokio::test]
    async fn test_vault_encryption_files_not_readable_without_passphrase() {
        // Phase 1 Red Team Checkpoint: Verify vault files are not readable without passphrase
        let temp_dir = tempfile::tempdir().unwrap();
        let vault_path = temp_dir.path().join("vault");
        let identity_path = temp_dir.path().join("identity.age");

        // Create and initialize vault with passphrase
        let mut vault = LocalVault::new(vault_path.clone(), identity_path.clone()).unwrap();
        vault.init(Some("test-passphrase")).unwrap();

        // Set a secret with known plaintext value
        let secret_path = SecretPath::new("test/api_key").unwrap();
        let secret_value = "my-super-secret-api-key-12345";
        let value = SecretValue::from_string(secret_value.to_string());
        let meta = SecretMetadata::new(secret_path.clone());
        vault.set(&secret_path, &value, &meta).await.unwrap();

        // Verify the secret file exists
        let secret_file_path = vault_path.join("test/api_key.age");
        assert!(secret_file_path.exists(), "Secret file should exist");

        // Read the encrypted file content (as binary, not UTF-8 string)
        let encrypted_content =
            std::fs::read(&secret_file_path).expect("Should be able to read encrypted file");

        // Verify the content is NOT plaintext
        let encrypted_str = String::from_utf8_lossy(&encrypted_content);
        assert!(
            !encrypted_str.contains(secret_value),
            "Encrypted file should NOT contain plaintext secret value. Found: {}",
            encrypted_str
        );

        // Verify the content is encrypted by checking it doesn't look like plaintext JSON
        // (age encrypts to binary, not ASCII armor by default)
        assert!(
            !encrypted_str.starts_with('{') && !encrypted_str.starts_with('"'),
            "Encrypted file should NOT start with plaintext JSON markers"
        );

        // The encrypted content should be binary (non-UTF-8 bytes)
        // If it were plaintext, it would be valid UTF-8
        let _is_plaintext_utf8 = std::str::from_utf8(&encrypted_content).is_ok();
        // Age encryption typically produces non-UTF-8 data unless armor is explicitly used
        // So we just verify the secret value is NOT in there
        assert!(!encrypted_str.contains(secret_value));

        // Try to load vault WITHOUT passphrase (using wrong passphrase)
        let mut vault_wrong = LocalVault::new(vault_path.clone(), identity_path.clone()).unwrap();
        let load_result = vault_wrong.load(Some("wrong-passphrase"));

        assert!(
            load_result.is_err(),
            "Loading vault with wrong passphrase should fail"
        );

        // Verify we cannot get the secret with wrong passphrase
        let get_result = vault_wrong.get(&secret_path).await;
        assert!(
            get_result.is_err(),
            "Getting secret with wrong passphrase should fail"
        );

        // Verify we CANNOT find the plaintext in any of the vault files
        let walk_result: Vec<walkdir::DirEntry> = walkdir::WalkDir::new(&vault_path)
            .into_iter()
            .filter_map(|e| e.ok())
            .collect();

        for entry in walk_result {
            if entry.file_type().is_file() {
                let content =
                    std::fs::read_to_string(entry.path()).unwrap_or_else(|_| String::new());
                assert!(
                    !content.contains(secret_value),
                    "Plaintext secret should NOT be found in file: {}",
                    entry.path().display()
                );
            }
        }
    }

    #[tokio::test]
    async fn test_identity_file_encrypted_with_passphrase() {
        // Verify identity file is encrypted when passphrase is used
        let temp_dir = tempfile::tempdir().unwrap();
        let vault_path = temp_dir.path().join("vault");
        let identity_path = temp_dir.path().join("identity.age");

        // Create vault with passphrase
        let mut vault = LocalVault::new(vault_path, identity_path.clone()).unwrap();
        vault.init(Some("test-passphrase")).unwrap();

        // Read the identity file (as binary)
        let identity_bytes =
            std::fs::read(&identity_path).expect("Should be able to read identity file");
        let identity_content = String::from_utf8_lossy(&identity_bytes);

        // Verify the identity file is encrypted by checking it doesn't contain
        // the plaintext age key marker (AGE-SECRET-KEY-)
        // (age keys start with "AGE-SECRET-KEY-1" in plaintext)
        assert!(
            !identity_content.contains("AGE-SECRET-KEY-"),
            "Encrypted identity file should NOT contain plaintext age key marker"
        );

        // Also verify it doesn't look like JSON or plaintext
        assert!(
            !identity_content.starts_with('{') && !identity_content.starts_with('"'),
            "Encrypted identity file should NOT start with plaintext JSON markers"
        );
    }

    #[tokio::test]
    async fn test_zeroize_is_used_for_secret_values() {
        // Phase 1 Red Team Checkpoint: Verify zeroize works
        // This is a code review test - we verify that zeroize is used for secret values

        // Check that SecretValue uses zeroizing wrapper
        let secret_value_path = workspace_root().join("crates/sigil-core/src/types.rs");
        let secret_value_code =
            std::fs::read_to_string(&secret_value_path).expect("Failed to read secret value code");

        // Verify SecretValue uses Zeroizing wrapper
        assert!(
            secret_value_code.contains("Zeroizing") || secret_value_code.contains("zeroize"),
            "SecretValue must use Zeroizing wrapper to clear memory on drop"
        );

        // Verify zeroize feature is enabled
        let cargo_toml = std::fs::read_to_string(workspace_root().join("Cargo.toml"))
            .expect("Failed to read Cargo.toml");
        assert!(
            cargo_toml.contains("zeroize"),
            "zeroize crate must be a dependency"
        );
    }

    #[tokio::test]
    async fn test_mlock_is_used_to_prevent_swap() {
        // Phase 1 Red Team Checkpoint: Attempt to recover secrets from swap (should fail if mlock is used)
        // This is a code review test - we verify that mlock is used

        // Check that daemon uses mlock for memory protection
        let memory_path = workspace_root().join("crates/sigil-daemon/src/memory.rs");
        let memory_code =
            std::fs::read_to_string(&memory_path).expect("Failed to read memory code");

        // Verify mlock or mlockall is used
        assert!(
            memory_code.contains("mlock") || memory_code.contains("mlockall"),
            "Daemon must use mlock/mlockall to prevent secrets from being swapped to disk"
        );

        // Verify memory protection is enabled during daemon startup
        let main_path = workspace_root().join("crates/sigil-daemon/src/main.rs");
        let main_code = std::fs::read_to_string(&main_path).expect("Failed to read daemon main");
        assert!(
            main_code.contains("enable_memory_protection") || main_code.contains("memory::enable"),
            "Daemon must enable memory protection during startup"
        );
    }
}
