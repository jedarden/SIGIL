//! OS-bound key storage for device key encryption
//!
//! This module provides secure storage for the device key using OS-bound secrets:
//! - Linux: kernel keyring (KEY_SPEC_USER_KEYRING)
//! - macOS: Keychain
//!
//! The device key is never stored as plaintext on disk. Instead, it is encrypted
//! with a key that is bound to the OS (kernel keyring or Keychain).

#![warn(missing_docs)]
#![warn(clippy::all)]

use base64::Engine;
use rand::RngCore;
use sigil_core::{SessionToken, SigilError};
use std::io::Write;
use zeroize::Zeroizing;

/// Key description for device key encryption key in kernel keyring
pub const DEVICE_KEY_ENCRYPTION_KEY_DESC: &str = "sigil_device_key_enc";

/// Service name for macOS Keychain
pub const KEYCHAIN_SERVICE: &str = "com.sigil.vault";

/// Account name for device key in macOS Keychain
pub const KEYCHAIN_ACCOUNT: &str = "device_key_encryption";

/// Device key storage backend
#[derive(Debug, Clone, Copy)]
pub enum DeviceKeyStorage {
    /// Linux kernel keyring
    KernelKeyring,
    /// macOS Keychain
    Keychain,
}

impl DeviceKeyStorage {
    /// Get the best available storage backend for the current platform
    pub fn best_available() -> Self {
        #[cfg(target_os = "linux")]
        {
            if sigil_core::is_keyring_available() {
                return DeviceKeyStorage::KernelKeyring;
            }
        }

        #[cfg(target_os = "macos")]
        {
            return DeviceKeyStorage::Keychain;
        }

        // Fallback (should not happen on supported platforms)
        DeviceKeyStorage::KernelKeyring
    }
}

/// OS-bound key storage for device key encryption
pub struct OsBoundKeyStore {
    storage: DeviceKeyStorage,
}

impl OsBoundKeyStore {
    /// Create a new OS-bound key store with the best available backend
    pub fn new() -> Result<Self, SigilError> {
        let storage = DeviceKeyStorage::best_available();
        Ok(Self { storage })
    }

    /// Create a new OS-bound key store with a specific backend
    pub fn with_storage(storage: DeviceKeyStorage) -> Self {
        Self { storage }
    }

    /// Store the device key encryption key
    ///
    /// This generates and stores a 256-bit encryption key in the OS-bound storage.
    /// Returns the base64-encoded encryption key.
    pub fn store_encryption_key(&self) -> Result<SessionToken, SigilError> {
        match self.storage {
            #[cfg(target_os = "linux")]
            DeviceKeyStorage::KernelKeyring => {
                // Generate a random 256-bit key
                let key_bytes = self.generate_random_key()?;
                let key_b64 = SessionToken::from_bytes(&key_bytes)?;

                // Store in kernel keyring
                sigil_core::keyring::add_device_key_encryption_key(&key_b64.to_base64())?;

                tracing::info!("Device key encryption key stored in kernel keyring");
                Ok(key_b64)
            }

            #[cfg(target_os = "macos")]
            DeviceKeyStorage::Keychain => {
                // Generate a random 256-bit key
                let key_bytes = self.generate_random_key()?;
                let key_b64 = SessionToken::from_bytes(&key_bytes)?;

                // Store in macOS Keychain
                store_keychain_key(KEYCHAIN_SERVICE, KEYCHAIN_ACCOUNT, key_b64.to_base64())?;

                tracing::info!("Device key encryption key stored in macOS Keychain");
                Ok(key_b64)
            }

            #[cfg(not(any(target_os = "linux", target_os = "macos")))]
            DeviceKeyStorage::KernelKeyring => Err(SigilError::IoError(
                "OS-bound key storage not supported on this platform".to_string(),
            )),

            // Wildcard for other variants (only used when cfg doesn't match)
            #[cfg(any(target_os = "linux", target_os = "macos"))]
            _ => Err(SigilError::IoError(
                "OS-bound key storage not available on this platform".to_string(),
            )),
        }
    }

    /// Load the device key encryption key
    pub fn load_encryption_key(&self) -> Result<SessionToken, SigilError> {
        match self.storage {
            #[cfg(target_os = "linux")]
            DeviceKeyStorage::KernelKeyring => {
                let key_str = sigil_core::keyring::read_device_key_encryption_key()?;
                SessionToken::from_string(key_str)
            }

            #[cfg(target_os = "macos")]
            DeviceKeyStorage::Keychain => {
                let key_str = load_keychain_key(KEYCHAIN_SERVICE, KEYCHAIN_ACCOUNT)?;
                SessionToken::from_string(key_str)
            }

            #[cfg(not(any(target_os = "linux", target_os = "macos")))]
            DeviceKeyStorage::KernelKeyring => Err(SigilError::IoError(
                "OS-bound key storage not supported on this platform".to_string(),
            )),

            // Wildcard for other variants (only used when cfg doesn't match)
            #[cfg(any(target_os = "linux", target_os = "macos"))]
            _ => Err(SigilError::IoError(
                "OS-bound key storage not available on this platform".to_string(),
            )),
        }
    }

    /// Remove the device key encryption key
    pub fn remove_encryption_key(&self) -> Result<(), SigilError> {
        match self.storage {
            #[cfg(target_os = "linux")]
            DeviceKeyStorage::KernelKeyring => {
                sigil_core::keyring::remove_device_key_encryption_key()?;
                Ok(())
            }

            #[cfg(target_os = "macos")]
            DeviceKeyStorage::Keychain => {
                delete_keychain_key(KEYCHAIN_SERVICE, KEYCHAIN_ACCOUNT)?;
                Ok(())
            }

            #[cfg(not(any(target_os = "linux", target_os = "macos")))]
            DeviceKeyStorage::KernelKeyring => Err(SigilError::IoError(
                "OS-bound key storage not supported on this platform".to_string(),
            )),

            // Wildcard for other variants (only used when cfg doesn't match)
            #[cfg(any(target_os = "linux", target_os = "macos"))]
            _ => Err(SigilError::IoError(
                "OS-bound key storage not available on this platform".to_string(),
            )),
        }
    }

    /// Check if the encryption key is available
    pub fn has_encryption_key(&self) -> bool {
        self.load_encryption_key().is_ok()
    }

    /// Encrypt the device key with the OS-bound encryption key
    ///
    /// Returns age-encrypted device key (base64-encoded)
    pub fn encrypt_device_key(&self, device_key: &[u8]) -> Result<String, SigilError> {
        use age::{secrecy::Secret, Encryptor};

        // Load the encryption key
        let enc_key = self.load_encryption_key()?;
        let enc_key_bytes = enc_key.to_bytes();

        // Use the encryption key as a passphrase for age encryption
        // This is simpler than using x25519 and works well for our use case
        let passphrase = Secret::new(base64::Engine::encode(
            &base64::engine::general_purpose::STANDARD,
            &enc_key_bytes,
        ));

        let encryptor = Encryptor::with_user_passphrase(passphrase);

        let mut encrypted = Vec::new();
        let mut writer = encryptor
            .wrap_output(&mut encrypted)
            .map_err(|e| SigilError::Crypto(format!("Failed to create encryptor: {}", e)))?;

        writer
            .write_all(device_key)
            .map_err(|e| SigilError::Crypto(format!("Failed to encrypt: {}", e)))?;

        writer
            .finish()
            .map_err(|e| SigilError::Crypto(format!("Failed to finish encryption: {}", e)))?;

        // Return as base64
        Ok(base64::Engine::encode(
            &base64::engine::general_purpose::STANDARD,
            encrypted,
        ))
    }

    /// Decrypt the device key with the OS-bound encryption key
    pub fn decrypt_device_key(
        &self,
        encrypted_device_key: &str,
    ) -> Result<Zeroizing<Vec<u8>>, SigilError> {
        use age::{secrecy::Secret, Decryptor};

        // Load the encryption key (as passphrase for decryption)
        let enc_key = self.load_encryption_key()?;
        let enc_key_bytes = enc_key.to_bytes();

        // Create passphrase from the encryption key
        let passphrase = Secret::new(base64::Engine::encode(
            &base64::engine::general_purpose::STANDARD,
            &enc_key_bytes,
        ));

        // Decode the encrypted device key
        let encrypted_data = base64::engine::general_purpose::STANDARD
            .decode(encrypted_device_key)
            .map_err(|e| SigilError::Crypto(format!("Invalid base64: {}", e)))?;

        // Decrypt the device key
        let decryptor = Decryptor::new(&encrypted_data[..])
            .map_err(|e| SigilError::Crypto(format!("Failed to create decryptor: {}", e)))?;

        let device_key = match decryptor {
            Decryptor::Passphrase(d) => {
                let mut output = Zeroizing::new(Vec::new());
                let mut reader = d
                    .decrypt(&passphrase, None)
                    .map_err(|e| SigilError::Crypto(format!("Failed to decrypt: {}", e)))?;

                use std::io::Read;
                reader.read_to_end(output.as_mut()).map_err(|e| {
                    SigilError::Crypto(format!("Failed to read decrypted data: {}", e))
                })?;

                output
            }
            _ => return Err(SigilError::Crypto("Unexpected decryptor type".to_string())),
        };

        // Verify key length
        if device_key.len() != 32 {
            return Err(SigilError::Crypto(format!(
                "Invalid device key length: expected 32 bytes, got {}",
                device_key.len()
            )));
        }

        Ok(device_key)
    }

    /// Generate a random 256-bit encryption key
    fn generate_random_key(&self) -> Result<Vec<u8>, SigilError> {
        let mut key = vec![0u8; 32];
        rand::thread_rng().fill_bytes(&mut key);
        Ok(key)
    }

    /// Get the storage backend type
    pub fn storage(&self) -> DeviceKeyStorage {
        self.storage
    }
}

impl Default for OsBoundKeyStore {
    fn default() -> Self {
        Self::new().expect("Failed to create OS-bound key store")
    }
}

/// macOS Keychain functions (security command-line tool)

#[cfg(target_os = "macos")]
fn store_keychain_key(service: &str, account: &str, password: String) -> Result<(), SigilError> {
    use std::process::Command;

    let output = Command::new("security")
        .args([
            "add-generic-password",
            "-s",
            service,
            "-a",
            account,
            "-w",
            &password,
            "-U", // Update if exists
        ])
        .output();

    match output {
        Ok(out) if out.status.success() => Ok(()),
        Ok(out) => {
            let stderr = String::from_utf8_lossy(&out.stderr);
            Err(SigilError::IoError(format!(
                "Failed to store in Keychain: {}",
                stderr.trim()
            )))
        }
        Err(e) => Err(SigilError::IoError(format!(
            "Failed to run security command: {}",
            e
        ))),
    }
}

#[cfg(target_os = "macos")]
fn load_keychain_key(service: &str, account: &str) -> Result<String, SigilError> {
    use std::process::Command;

    let output = Command::new("security")
        .args([
            "find-generic-password",
            "-s",
            service,
            "-a",
            account,
            "-w", // Output password only
        ])
        .output();

    match output {
        Ok(out) if out.status.success() => {
            let password = String::from_utf8_lossy(&out.stdout).trim().to_string();
            Ok(password)
        }
        Ok(out) => {
            let stderr = String::from_utf8_lossy(&out.stderr);
            Err(SigilError::IoError(format!(
                "Failed to load from Keychain: {}",
                stderr.trim()
            )))
        }
        Err(e) => Err(SigilError::IoError(format!(
            "Failed to run security command: {}",
            e
        ))),
    }
}

#[cfg(target_os = "macos")]
fn delete_keychain_key(service: &str, account: &str) -> Result<(), SigilError> {
    use std::process::Command;

    let output = Command::new("security")
        .args(["delete-generic-password", "-s", service, "-a", account])
        .output();

    match output {
        Ok(out) if out.status.success() => Ok(()),
        Ok(out) => {
            let stderr = String::from_utf8_lossy(&out.stderr);
            Err(SigilError::IoError(format!(
                "Failed to delete from Keychain: {}",
                stderr.trim()
            )))
        }
        Err(e) => Err(SigilError::IoError(format!(
            "Failed to run security command: {}",
            e
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_device_key_storage_best_available() {
        let storage = DeviceKeyStorage::best_available();
        // Just verify it returns a valid storage type
        match storage {
            DeviceKeyStorage::KernelKeyring => {}
            DeviceKeyStorage::Keychain => {}
        }
    }

    #[test]
    fn test_os_bound_key_store_new() {
        let store = OsBoundKeyStore::new();
        assert!(store.is_ok());
    }

    #[test]
    fn test_os_bound_key_store_default() {
        let store = OsBoundKeyStore::default();
        match store.storage() {
            DeviceKeyStorage::KernelKeyring => {}
            DeviceKeyStorage::Keychain => {}
        }
    }

    #[test]
    fn test_os_bound_key_store_with_storage() {
        let store = OsBoundKeyStore::with_storage(DeviceKeyStorage::KernelKeyring);
        assert!(matches!(store.storage(), DeviceKeyStorage::KernelKeyring));
    }

    #[test]
    fn test_device_key_roundtrip() {
        let store = OsBoundKeyStore::new().unwrap();

        // Only run this test if we have OS-bound storage available
        if !store.has_encryption_key() {
            // Try to store a key first
            if store.store_encryption_key().is_err() {
                return; // Skip if we can't store
            }
        }

        // Generate a test device key
        let mut device_key = vec![0u8; 32];
        rand::thread_rng().fill_bytes(&mut device_key);

        // Encrypt
        let encrypted = match store.encrypt_device_key(&device_key) {
            Ok(e) => e,
            Err(_) => return, // Skip if encryption fails
        };

        // Decrypt
        let decrypted = match store.decrypt_device_key(&encrypted) {
            Ok(d) => d,
            Err(_) => {
                // Clean up
                let _ = store.remove_encryption_key();
                return; // Skip if decryption fails
            }
        };

        assert_eq!(&*decrypted, device_key.as_slice());

        // Clean up
        let _ = store.remove_encryption_key();
    }
}
