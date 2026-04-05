//! SSH key management for SIGIL SSH agent
//!
//! This module handles SSH key operations including loading keys from the vault
//! and performing signing operations.

use anyhow::{anyhow, Context, Result};
use bytes::{BufMut, BytesMut};
use serde::{Deserialize, Serialize};
use sigil_sdk::SigilClient;
use ssh_key::{HashAlg, PrivateKey, PublicKey};
use std::collections::HashMap;
use std::time::{Duration, Instant};
use tracing::{debug, info};

/// SSH identity loaded from vault
#[derive(Debug, Clone)]
pub struct SshIdentity {
    /// Path in vault (e.g., "ssh/github")
    pub vault_path: String,
    /// Public key blob for agent protocol
    pub key_blob: Vec<u8>,
    /// Comment (typically the vault path or hostname)
    pub comment: String,
    /// When the key was loaded
    pub loaded_at: Instant,
    /// Key constraints
    pub constraints: Vec<KeyConstraint>,
}

/// Key constraint for limiting key usage
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum KeyConstraint {
    /// Confirm before each use
    Confirm {
        /// Confirmation prompt message
        message: Option<String>,
    },
    /// Maximum lifetime for this key
    Lifetime {
        /// Duration in seconds
        seconds: u64,
    },
    /// Limit to specific commands (future)
    Command {
        /// Allowed commands
        allowed: Vec<String>,
    },
}

impl KeyConstraint {
    /// Check if a key has expired based on its lifetime constraint
    pub fn is_expired(&self, loaded_at: Instant) -> bool {
        if let KeyConstraint::Lifetime { seconds } = self {
            let duration = Duration::from_secs(*seconds);
            loaded_at.elapsed() > duration
        } else {
            false
        }
    }
}

/// Key manager for SSH agent
pub struct KeyManager {
    /// Loaded identities from vault
    pub(super) identities: HashMap<String, SshIdentity>,
    /// Session token for SIGIL daemon
    pub(super) session_token: String,
    /// Socket path for SIGIL daemon
    pub(super) sigil_socket: std::path::PathBuf,
}

impl KeyManager {
    /// Create a new key manager
    pub fn new(sigil_socket: std::path::PathBuf, session_token: String) -> Self {
        Self {
            identities: HashMap::new(),
            session_token,
            sigil_socket,
        }
    }

    /// Load SSH keys from the vault
    pub async fn load_keys_from_vault(&mut self) -> Result<()> {
        debug!("Loading SSH keys from vault");

        // Create a client to connect to the daemon
        let client =
            SigilClient::new(self.sigil_socket.clone()).context("Failed to create SDK client")?;

        // Connect to the daemon
        client
            .connect()
            .await
            .context("Failed to connect to SIGIL daemon")?;

        // List all secrets to find SSH keys
        let secrets = client
            .list("")
            .await
            .context("Failed to list secrets from daemon")?;

        // Filter for SSH keys (secrets with "ssh/" prefix or SSH-related tags)
        let ssh_keys: Vec<_> = secrets
            .into_iter()
            .filter(|s| s.path.starts_with("ssh/") || s.tags.iter().any(|t| t == "ssh"))
            .collect();

        debug!("Found {} SSH key(s) in vault", ssh_keys.len());

        // Try to load each SSH key
        for secret_meta in ssh_keys {
            let path = &secret_meta.path;
            match self.load_key_from_vault(&client, path).await {
                Ok(vault_key) => {
                    // Generate key blob from public key
                    let key_blob = Self::public_key_to_blob(&vault_key.public_key)?;

                    self.identities.insert(
                        path.clone(),
                        SshIdentity {
                            vault_path: path.clone(),
                            key_blob,
                            comment: path.clone(),
                            loaded_at: Instant::now(),
                            constraints: vec![],
                        },
                    );
                    info!("Loaded SSH key: {}", path);
                }
                Err(e) => {
                    debug!("Failed to load SSH key {}: {}", path, e);
                }
            }
        }

        debug!("Loaded {} SSH keys from vault", self.identities.len());
        Ok(())
    }

    /// Load a single key from the vault
    async fn load_key_from_vault(&self, client: &SigilClient, path: &str) -> Result<VaultKey> {
        // Get the secret value from the vault
        let secret_value = client
            .get(path)
            .await
            .context("Failed to get secret from vault")?;

        // Expose the secret value and parse it
        secret_value.expose(|bytes| {
            // Try to parse as an SSH private key
            let key_str = String::from_utf8_lossy(bytes);
            let private_key = PrivateKey::from_openssh(key_str.trim())
                .context("Failed to parse private key as OpenSSH format")?;

            let public_key = private_key.public_key().clone();
            let key_type = public_key.key_data().algorithm().to_string();

            Ok(VaultKey {
                private_key: key_str.to_string(),
                public_key,
                key_type,
            })
        })
    }

    /// Get all identities, excluding expired ones
    pub fn get_identities(&self) -> Vec<SshIdentity> {
        self.identities
            .values()
            .filter(|id| !id.constraints.iter().any(|c| c.is_expired(id.loaded_at)))
            .cloned()
            .collect()
    }

    /// Find an identity by public key blob
    pub fn find_identity_by_blob(&self, key_blob: &[u8]) -> Option<SshIdentity> {
        self.identities
            .values()
            .find(|id| id.key_blob == key_blob)
            .filter(|id| !id.constraints.iter().any(|c| c.is_expired(id.loaded_at)))
            .cloned()
    }

    /// Sign data with a key from the vault
    pub async fn sign_with_key(
        &self,
        vault_path: &str,
        data: &[u8],
        flags: u32,
    ) -> Result<Vec<u8>> {
        info!("Signing data with key: {}", vault_path);

        // Create a client to connect to the daemon
        let client =
            SigilClient::new(self.sigil_socket.clone()).context("Failed to create SDK client")?;

        // Get the secret value from the vault
        let secret_value = client
            .get(vault_path)
            .await
            .context("Failed to get secret from vault")?;

        // Expose the secret value and sign the data
        secret_value.expose(|bytes| {
            // Parse the private key
            let key_str = String::from_utf8_lossy(bytes);
            let private_key = PrivateKey::from_openssh(key_str.trim())
                .context("Failed to parse private key as OpenSSH format")?;

            let public_key = private_key.public_key();

            // Determine the signature algorithm name based on key type
            let alg_name = match public_key.key_data().algorithm() {
                ssh_key::Algorithm::Rsa { .. } => "ssh-rsa",
                ssh_key::Algorithm::Ed25519 => "ssh-ed25519",
                ssh_key::Algorithm::Ecdsa { curve } => match curve.as_str() {
                    "nistp256" => "ecdsa-sha2-nistp256",
                    "nistp384" => "ecdsa-sha2-nistp384",
                    "nistp521" => "ecdsa-sha2-nistp521",
                    _ => return Err(anyhow!("Unsupported ECDSA curve: {}", curve)),
                },
                _ => return Err(anyhow!("Unsupported key type")),
            };

            // Determine the hash algorithm from flags
            let hash_alg = if flags == 2 {
                HashAlg::Sha512
            } else {
                HashAlg::Sha256
            };

            // Sign the data
            let ssh_sig = private_key
                .sign("ssh-agent", hash_alg, data)
                .context("Failed to sign data")?;

            // Convert to blob format
            let mut buffer = BytesMut::new();
            Self::write_string(&mut buffer, alg_name);

            // Get the signature data - for most signatures this is just the raw bytes
            let sig_data = ssh_sig.signature_bytes();
            Self::write_bytes(&mut buffer, sig_data);

            Ok(buffer.to_vec())
        })
    }
}

/// Vault key representation
#[derive(Debug)]
struct VaultKey {
    /// Private key in OpenSSH format
    #[allow(dead_code)]
    private_key: String,
    /// Public key
    public_key: PublicKey,
    /// Key type
    #[allow(dead_code)]
    key_type: String,
}

impl KeyManager {
    /// Convert a public key to SSH agent protocol blob format
    fn public_key_to_blob(public_key: &PublicKey) -> Result<Vec<u8>> {
        use bytes::BytesMut;

        let mut buffer = BytesMut::new();

        // Write key type
        let key_type = public_key.key_data().algorithm();
        Self::write_string(&mut buffer, key_type.as_str());

        // Write key data based on type
        match public_key.key_data() {
            ssh_key::public::KeyData::Rsa(key) => {
                // Write exponent and modulus as MPINT
                let e_bytes = key.e.as_bytes();
                let n_bytes = key.n.as_bytes();
                Self::write_mpint(&mut buffer, e_bytes);
                Self::write_mpint(&mut buffer, n_bytes);
            }
            ssh_key::public::KeyData::Ed25519(key) => {
                Self::write_bytes(&mut buffer, key.as_ref());
            }
            ssh_key::public::KeyData::Ecdsa(key) => {
                // For ECDSA, we need to write the curve identifier and the public point
                Self::write_bytes(&mut buffer, key.as_ref());
            }
            _ => {
                return Err(anyhow!("Unsupported key type: {:?}", key_type));
            }
        }

        Ok(buffer.to_vec())
    }

    /// Write a string to buffer (length-prefixed)
    pub fn write_string(buffer: &mut BytesMut, s: &str) {
        let bytes = s.as_bytes();
        buffer.put_u32(bytes.len() as u32);
        buffer.extend_from_slice(bytes);
    }

    /// Write bytes to buffer (length-prefixed)
    pub fn write_bytes(buffer: &mut BytesMut, bytes: &[u8]) {
        buffer.put_u32(bytes.len() as u32);
        buffer.extend_from_slice(bytes);
    }

    /// Write a multi-precision integer to buffer
    pub fn write_mpint(buffer: &mut BytesMut, n: &[u8]) {
        // MPINT encoding: if high bit is set, prefix with zero byte
        let data = if !n.is_empty() && n[0] & 0x80 == 0x80 {
            let mut prefixed = vec![0u8];
            prefixed.extend_from_slice(n);
            prefixed
        } else {
            n.to_vec()
        };

        buffer.put_u32(data.len() as u32);
        buffer.extend_from_slice(&data);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_key_constraint_expiration() {
        let constraint = KeyConstraint::Lifetime { seconds: 1 };
        let loaded = Instant::now();
        assert!(!constraint.is_expired(loaded));

        // Wait for expiration
        std::thread::sleep(Duration::from_secs(2));
        assert!(constraint.is_expired(loaded));
    }

    #[test]
    fn test_key_manager_empty() {
        let manager = KeyManager::new(
            std::path::PathBuf::from("/tmp/test.sock"),
            "test-token".to_string(),
        );
        assert!(manager.get_identities().is_empty());
    }
}
