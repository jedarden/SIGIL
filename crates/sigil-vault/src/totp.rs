//! TOTP (Time-based One-Time Password) implementation for SIGIL vault authentication
//!
//! This module implements RFC 6238 TOTP as the 4th authentication factor for vault unsealing.
//! TOTP provides time-based, one-time passwords that add an additional security layer
//! beyond passphrase and device key.
//!
//! ## TOTP Design
//!
//! - **Algorithm**: HMAC-based One-Time Password (HOTP) with time-based counter
//! - **Time step**: 30 seconds (standard RFC 6238 default)
//! - **Digits**: 6-digit codes (user-friendly, secure enough)
//! - **Hash function**: SHA-256 (balance of security and performance)
//! - **Clock skew tolerance**: Accept current + previous period (60-second window)
//!
//! ## Storage
//!
//! TOTP secrets are stored separately from the vault (typically in ~/.sigil/totp.age)
//! and encrypted with age to prevent circular dependency (we can't store TOTP secret
//! in the vault that requires TOTP to unseal).
//!
//! ## Usage
//!
//! ```rust
//! use sigil_vault::totp::TotpManager;
//!
//! // Generate a new TOTP secret
//! let secret = TotpManager::generate_secret();
//!
//! // Generate current TOTP code
//! let code = TotpManager::generate_code(&secret).unwrap();
//!
//! // Verify TOTP code (with clock skew tolerance)
//! let is_valid = TotpManager::verify_code(&secret, &code.to_string()).unwrap();
//! ```

#![warn(missing_docs)]
#![warn(clippy::all)]

use anyhow::{Context, Result};
use rand::RngCore;
use secrecy::SecretString;
use serde::{Deserialize, Serialize};
use std::fmt;
use std::fs;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use zeroize::Zeroize;

/// Length of TOTP secret in bytes (160 bits = 20 bytes)
const TOTP_SECRET_LENGTH: usize = 20;

/// TOTP time step in seconds (RFC 6238 standard)
const TOTP_TIME_STEP: u64 = 30;

/// TOTP code digit count (6-digit codes)
const TOTP_DIGITS: u32 = 6;

/// Clock skew tolerance: accept current + previous period
const TOTP_SKEW_TOLERANCE: u64 = 1; // ±1 period = ±30 seconds

/// TOTP secret (160-bit base32-encoded string)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TotpSecret {
    /// Raw secret bytes (160 bits)
    #[serde(with = "serde_bytes")]
    pub bytes: Vec<u8>,
}

impl TotpSecret {
    /// Generate a new random TOTP secret
    pub fn generate() -> Self {
        let mut bytes = vec![0u8; TOTP_SECRET_LENGTH];
        rand::thread_rng().fill_bytes(&mut bytes);
        Self { bytes }
    }

    /// Get the base32-encoded representation (user-friendly format)
    pub fn to_base32(&self) -> String {
        base32::encode(base32::Alphabet::Rfc4648 { padding: true }, &self.bytes)
    }

    /// Parse from base32-encoded representation
    pub fn from_base32(encoded: &str) -> Result<Self> {
        let bytes = base32::decode(base32::Alphabet::Rfc4648 { padding: true }, encoded)
            .context("Invalid base32 encoding for TOTP secret")?;

        if bytes.len() != TOTP_SECRET_LENGTH {
            return Err(anyhow::anyhow!(
                "Invalid TOTP secret length: expected {} bytes, got {}",
                TOTP_SECRET_LENGTH,
                bytes.len()
            ));
        }

        Ok(Self { bytes })
    }

    /// Get the hex-encoded representation (for encrypted storage)
    pub fn to_hex(&self) -> String {
        hex::encode(&self.bytes)
    }

    /// Parse from hex-encoded representation
    pub fn from_hex(hex_str: &str) -> Result<Self> {
        let bytes = hex::decode(hex_str).context("Invalid hex encoding for TOTP secret")?;

        if bytes.len() != TOTP_SECRET_LENGTH {
            return Err(anyhow::anyhow!(
                "Invalid TOTP secret length: expected {} bytes, got {}",
                TOTP_SECRET_LENGTH,
                bytes.len()
            ));
        }

        Ok(Self { bytes })
    }
}

impl fmt::Display for TotpSecret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.to_base32())
    }
}

/// TOTP manager for handling time-based one-time password operations
pub struct TotpManager {
    /// Path to TOTP secret storage (encrypted with age)
    storage_path: PathBuf,
}

impl TotpManager {
    /// Create a new TOTP manager
    pub fn new(storage_path: PathBuf) -> Self {
        Self { storage_path }
    }

    /// Generate a new TOTP secret
    pub fn generate_secret() -> TotpSecret {
        TotpSecret::generate()
    }

    /// Generate the current TOTP code for a given secret
    ///
    /// Uses the current Unix time divided by the time step (30 seconds).
    /// Returns a 6-digit numeric code.
    pub fn generate_code(secret: &TotpSecret) -> Result<String> {
        let current_time = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .context("Failed to get current time")?
            .as_secs();

        let counter = current_time / TOTP_TIME_STEP;
        Self::generate_hotp_code(secret, counter)
    }

    /// Generate TOTP code for a specific time counter
    fn generate_hotp_code(secret: &TotpSecret, counter: u64) -> Result<String> {
        // Convert counter to 8-byte big-endian array
        let counter_bytes = counter.to_be_bytes();

        // Calculate HMAC-SHA256
        let hmac_result = Self::hmac_sha256(&secret.bytes, &counter_bytes);

        // Dynamic truncation (RFC 4228)
        let offset = (hmac_result[hmac_result.len() - 1] & 0x0f) as usize;
        let binary = ((hmac_result[offset] & 0x7f) as u32) << 24
            | (hmac_result[offset + 1] as u32) << 16
            | (hmac_result[offset + 2] as u32) << 8
            | hmac_result[offset + 3] as u32;

        let code = binary % 1_000_000; // 6-digit code

        Ok(format!("{:06}", code))
    }

    /// Verify a TOTP code with clock skew tolerance
    ///
    /// Accepts codes from current period and ±1 period (60-second window)
    /// to accommodate clock skew between client and server.
    pub fn verify_code(secret: &TotpSecret, code: &str) -> Result<bool> {
        // Validate code format (6 digits)
        if code.len() != TOTP_DIGITS as usize || !code.chars().all(|c| c.is_ascii_digit()) {
            return Ok(false);
        }

        let current_time = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .context("Failed to get current time")?
            .as_secs();

        let current_counter = current_time / TOTP_TIME_STEP;

        // Check current period and ±1 period for clock skew tolerance
        for offset in -(TOTP_SKEW_TOLERANCE as i64)..=(TOTP_SKEW_TOLERANCE as i64) {
            let counter = current_counter as i64 + offset;
            if counter < 0 {
                continue; // Skip negative counters
            }

            let expected_code = Self::generate_hotp_code(secret, counter as u64)?;
            if expected_code == code {
                return Ok(true);
            }
        }

        Ok(false)
    }

    /// Calculate HMAC-SHA256 for HOTP
    fn hmac_sha256(key: &[u8], counter: &[u8]) -> Vec<u8> {
        use hmac::Hmac;
        use hmac::Mac;
        type HmacSha256 = Hmac<sha2::Sha256>;

        let mut mac = HmacSha256::new_from_slice(key).expect("HMAC key size is valid");
        mac.update(counter);
        mac.finalize().into_bytes().to_vec()
    }

    /// Get the current TOTP period (for debugging and display)
    pub fn current_period() -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
            / TOTP_TIME_STEP
    }

    /// Get time remaining in current TOTP period (in seconds)
    pub fn period_remaining() -> u64 {
        let current_time = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        TOTP_TIME_STEP - (current_time % TOTP_TIME_STEP)
    }

    /// Store TOTP secret encrypted with age
    ///
    /// Encrypts the TOTP secret with age using the vault passphrase.
    /// This prevents circular dependency (TOTP secret can't be stored in vault).
    pub fn store_secret(&self, secret: &TotpSecret, passphrase: &str) -> Result<()> {
        // Ensure parent directory exists
        if let Some(parent) = self.storage_path.parent() {
            fs::create_dir_all(parent).context("Failed to create TOTP storage directory")?;
        }

        // Encrypt with age using passphrase
        let encryptor = age::Encryptor::with_user_passphrase(SecretString::new(passphrase.to_owned().into()));

        let secret_hex = secret.to_hex();
        let mut encrypted = Vec::new();
        {
            let mut writer = encryptor
                .wrap_output(&mut encrypted)
                .context("Failed to create age encryptor")?;
            writer
                .write_all(secret_hex.as_bytes())
                .context("Failed to encrypt TOTP secret")?;
            writer.finish().context("Failed to finalize encryption")?;
        }

        // Write encrypted secret to file
        fs::write(&self.storage_path, encrypted)
            .context("Failed to write encrypted TOTP secret")?;

        // Set restrictive permissions (0600)
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let perms = fs::Permissions::from_mode(0o600);
            let _ = fs::set_permissions(&self.storage_path, perms);
        }

        Ok(())
    }

    /// Load and decrypt TOTP secret
    pub fn load_secret(&self, passphrase: &str) -> Result<TotpSecret> {
        if !self.storage_path.exists() {
            return Err(anyhow::anyhow!(
                "TOTP secret not found at {}. Generate one first with 'sigil totp generate'.",
                self.storage_path.display()
            ));
        }

        let encrypted_data =
            fs::read(&self.storage_path).context("Failed to read encrypted TOTP secret")?;

        // Decrypt with age
        let decryptor =
            age::Decryptor::new(&encrypted_data[..]).context("Failed to create age decryptor")?;

        let secret_hex_bytes = {
            let passphrase_secret = SecretString::new(passphrase.to_owned().into());
            let scrypt_identity = age::scrypt::Identity::new(passphrase_secret);
            let mut reader = decryptor
                .decrypt(std::iter::once(&scrypt_identity as &dyn age::Identity))
                .context("Failed to decrypt TOTP secret")?;

            let mut decrypted = Vec::new();
            reader
                .read_to_end(&mut decrypted)
                .context("Failed to read decrypted secret")?;
            decrypted
        };

        let secret_hex =
            String::from_utf8(secret_hex_bytes).context("Decrypted secret is not valid UTF-8")?;

        TotpSecret::from_hex(&secret_hex)
    }

    /// Check if TOTP secret exists
    pub fn has_secret(&self) -> bool {
        self.storage_path.exists()
    }

    /// Get the storage path (for display purposes)
    pub fn storage_path(&self) -> &Path {
        &self.storage_path
    }
}

/// Zeroize sensitive data on drop
impl Drop for TotpSecret {
    fn drop(&mut self) {
        self.bytes.zeroize();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_totp_secret_generation() {
        let secret = TotpSecret::generate();
        assert_eq!(secret.bytes.len(), TOTP_SECRET_LENGTH);

        let base32 = secret.to_base32();
        assert!(!base32.is_empty());

        let hex = secret.to_hex();
        assert_eq!(hex.len(), TOTP_SECRET_LENGTH * 2);
    }

    #[test]
    fn test_totp_secret_roundtrip() {
        let secret = TotpSecret::generate();

        let base32 = secret.to_base32();
        let restored = TotpSecret::from_base32(&base32).unwrap();
        assert_eq!(restored.bytes, secret.bytes);

        let hex = secret.to_hex();
        let restored_hex = TotpSecret::from_hex(&hex).unwrap();
        assert_eq!(restored_hex.bytes, secret.bytes);
    }

    #[test]
    fn test_totp_code_generation() {
        let secret = TotpSecret::generate();

        let code = TotpManager::generate_code(&secret).unwrap();
        assert_eq!(code.len(), TOTP_DIGITS as usize);
        assert!(code.chars().all(|c| c.is_ascii_digit()));
    }

    #[test]
    fn test_totp_verification() {
        let secret = TotpSecret::generate();

        let code = TotpManager::generate_code(&secret).unwrap();
        let is_valid = TotpManager::verify_code(&secret, &code).unwrap();
        assert!(is_valid);

        // Invalid code should fail
        let is_invalid = TotpManager::verify_code(&secret, "000000").unwrap();
        assert!(!is_invalid);
    }

    #[test]
    fn test_totp_clock_skew_tolerance() {
        let secret = TotpSecret::generate();

        // Current period code
        let current_code = TotpManager::generate_code(&secret).unwrap();
        assert!(TotpManager::verify_code(&secret, &current_code).unwrap());

        // Next period code (should also be valid due to skew tolerance)
        let current_time = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let next_counter = (current_time / TOTP_TIME_STEP) + 1;
        let next_code = TotpManager::generate_hotp_code(&secret, next_counter).unwrap();
        assert!(TotpManager::verify_code(&secret, &next_code).unwrap());

        // Previous period code (should also be valid)
        let prev_counter = (current_time / TOTP_TIME_STEP).saturating_sub(1);
        let prev_code = TotpManager::generate_hotp_code(&secret, prev_counter).unwrap();
        assert!(TotpManager::verify_code(&secret, &prev_code).unwrap());
    }

    #[test]
    fn test_totp_period_calculation() {
        let period = TotpManager::current_period();
        assert!(period > 0);

        let remaining = TotpManager::period_remaining();
        assert!(remaining > 0 && remaining <= TOTP_TIME_STEP);
    }

    #[test]
    fn test_totp_invalid_code_format() {
        let secret = TotpSecret::generate();

        // Too short
        assert!(!TotpManager::verify_code(&secret, "12345").unwrap());

        // Too long
        assert!(!TotpManager::verify_code(&secret, "1234567").unwrap());

        // Non-digits
        assert!(!TotpManager::verify_code(&secret, "abcdef").unwrap());
    }
}
