//! Local vault implementation using age-encrypted files

use age::{
    secrecy::{ExposeSecret, Secret},
    x25519, Decryptor, Encryptor, Identity as AgeIdentity,
};
use sigil_core::{Result, SecretBackend, SecretMetadata, SecretPath, SecretValue, SigilError};
use std::io::{Read, Write};
use std::path::PathBuf;
use std::str::FromStr;

/// Local vault implementation using age-encrypted files
pub struct LocalVault {
    /// Path to the vault directory
    vault_path: PathBuf,
    /// Path to the age identity file
    identity_path: PathBuf,
    /// Age identity keypair
    identity: Option<Identity>,
}

/// Age identity keypair (secret)
struct Identity {
    /// The secret key
    key: x25519::Identity,
}

impl LocalVault {
    /// Create a new local vault
    pub fn new(vault_path: PathBuf, identity_path: PathBuf) -> Result<Self> {
        // Ensure vault directory exists
        std::fs::create_dir_all(&vault_path)?;

        Ok(Self {
            vault_path,
            identity_path,
            identity: None,
        })
    }

    /// Initialize the vault with a new age keypair
    pub fn init(&mut self, passphrase: Option<&str>) -> Result<String> {
        // Generate a new x25519 keypair
        let keypair = x25519::Identity::generate();

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

            std::fs::write(&self.identity_path, encrypted)?;
        } else {
            // Write plaintext identity (not recommended, but supported)
            std::fs::write(&self.identity_path, secret_key.expose_secret().as_bytes())?;
        }

        // Get the public key before storing
        let public_key = keypair.to_public().to_string();

        // Store the identity in memory
        self.identity = Some(Identity { key: keypair });

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

        self.identity = Some(Identity { key });
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
        // Create the namespace directory if needed
        let secret_dir = self.secret_dir(path);
        std::fs::create_dir_all(&secret_dir)?;

        // Encrypt the value
        let encrypted = self.encrypt_value(value)?;

        // Write the encrypted file
        let secret_file = self.secret_path(path);
        std::fs::write(&secret_file, encrypted)?;

        // Update metadata (for now, we'll store it alongside the secret)
        // In a full implementation, we'd have a separate metadata store
        let metadata_path = secret_file.with_extension("meta.json");
        let metadata_json = serde_json::to_string_pretty(meta)?;
        std::fs::write(&metadata_path, metadata_json)?;

        Ok(())
    }

    async fn delete(&self, path: &SecretPath) -> Result<()> {
        let secret_file = self.secret_path(path);

        if !secret_file.exists() {
            return Err(SigilError::SecretNotFound(path.as_str().to_string()));
        }

        std::fs::remove_file(&secret_file)?;

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
                            // Extract secret name
                            if let Some(name) = file_path.file_stem() {
                                if let Some(name_str) = name.to_str() {
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
}
