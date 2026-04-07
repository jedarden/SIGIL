//! Vault integration for proxy configuration
//!
//! This module provides functionality to load proxy configuration
//! from the SIGIL vault, storing rules as encrypted vault entries.

use crate::{ProxyConfig, ProxyError, ProxyResult};
use sigil_core::{SecretBackend, SecretPath, SecretValue, SigilError};
use std::path::PathBuf;
use zeroize::Zeroizing;

/// Vault path for proxy rules configuration
pub const PROXY_RULES_PATH: &str = "_sigil/proxy_rules";

/// Load proxy configuration from the vault
///
/// This function loads the proxy configuration from the encrypted vault entry
/// at `_sigil/proxy_rules`. If the entry doesn't exist, it returns the default
/// configuration.
///
/// # Arguments
///
/// * `vault_path` - Path to the vault directory (e.g., `~/.sigil/vault`)
/// * `identity_path` - Path to the age identity file (e.g., `~/.sigil/identity.age`)
/// * `passphrase` - Optional passphrase for the vault
///
/// # Returns
///
/// Returns the loaded proxy configuration, or a default configuration if the
/// vault entry doesn't exist.
pub fn load_config_from_vault(
    vault_path: PathBuf,
    identity_path: PathBuf,
    passphrase: Option<&str>,
) -> ProxyResult<ProxyConfig> {
    use sigil_vault::LocalVault;

    // Create and load the vault
    let mut vault = LocalVault::new(vault_path, identity_path)
        .map_err(|e| ProxyError::InvalidConfig(format!("Failed to create vault: {}", e)))?;

    vault
        .load(passphrase)
        .map_err(|e| ProxyError::InvalidConfig(format!("Failed to unlock vault: {}", e)))?;

    // Try to load proxy rules from the vault
    let secret_path = SecretPath::new(PROXY_RULES_PATH.to_string())
        .map_err(|e| ProxyError::InvalidConfig(format!("Invalid secret path: {}", e)))?;

    // Use blocking task for async vault operations
    let rt = tokio::runtime::Runtime::new()
        .map_err(|e| ProxyError::InvalidConfig(format!("Failed to create runtime: {}", e)))?;

    let config_data = rt.block_on(async {
        // Check if the proxy rules entry exists
        Ok::<Option<String>, ProxyError>(match vault.get(&secret_path).await {
            Ok(secret_value) => {
                // Decrypt the config data
                let toml_str =
                    secret_value.expose(|bytes| String::from_utf8_lossy(bytes).to_string());
                Some(toml_str)
            }
            Err(SigilError::SecretNotFound(_)) => None,
            Err(e) => {
                return Err(ProxyError::InvalidConfig(format!(
                    "Failed to load proxy rules: {}",
                    e
                )));
            }
        })
    })?;

    match config_data {
        Some(toml_str) => {
            // Parse the TOML configuration
            ProxyConfig::from_toml(&toml_str).map_err(|e| {
                ProxyError::InvalidConfig(format!("Failed to parse proxy config: {}", e))
            })
        }
        None => {
            // Proxy rules don't exist yet, return default config
            tracing::info!("No proxy rules found in vault, using default configuration");
            Ok(ProxyConfig::default())
        }
    }
}

/// Save proxy configuration to the vault
///
/// This function saves the proxy configuration to the encrypted vault entry
/// at `_sigil/proxy_rules`.
///
/// # Arguments
///
/// * `config` - The proxy configuration to save
/// * `vault_path` - Path to the vault directory
/// * `identity_path` - Path to the age identity file
/// * `passphrase` - Optional passphrase for the vault
pub fn save_config_to_vault(
    config: &ProxyConfig,
    vault_path: PathBuf,
    identity_path: PathBuf,
    passphrase: Option<&str>,
) -> ProxyResult<()> {
    use sigil_vault::LocalVault;

    // Create and load the vault
    let mut vault = LocalVault::new(vault_path, identity_path)
        .map_err(|e| ProxyError::InvalidConfig(format!("Failed to create vault: {}", e)))?;

    vault
        .load(passphrase)
        .map_err(|e| ProxyError::InvalidConfig(format!("Failed to unlock vault: {}", e)))?;

    // Serialize the config to TOML
    let toml_str = config
        .to_toml()
        .map_err(|e| ProxyError::InvalidConfig(format!("Failed to serialize config: {}", e)))?;

    // Create secret path for metadata
    let secret_path = SecretPath::new(PROXY_RULES_PATH.to_string())
        .map_err(|e| ProxyError::InvalidConfig(format!("Invalid secret path: {}", e)))?;

    // Create a secret value with zeroized bytes
    let secret_bytes = Zeroizing::new(toml_str.into_bytes());
    let secret_vec: Vec<u8> = (**secret_bytes).to_vec();
    let secret_value = SecretValue::new(secret_vec);

    // Create metadata for the secret
    use sigil_core::SecretMetadata;
    let metadata = SecretMetadata::new(secret_path.clone());

    // Use blocking task for async vault operations
    let rt = tokio::runtime::Runtime::new()
        .map_err(|e| ProxyError::InvalidConfig(format!("Failed to create runtime: {}", e)))?;

    rt.block_on(async {
        vault
            .set(&secret_path, &secret_value, &metadata)
            .await
            .map_err(|e| ProxyError::InvalidConfig(format!("Failed to save proxy rules: {}", e)))
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn test_proxy_rules_path_constant() {
        assert_eq!(PROXY_RULES_PATH, "_sigil/proxy_rules");
    }

    #[test]
    fn test_load_default_config_from_vault() {
        // Create a temporary vault directory
        let temp_dir = TempDir::new().unwrap();
        let vault_path = temp_dir.path().join("vault");
        let identity_path = temp_dir.path().join("identity.age");

        // Initialize the vault
        let mut vault =
            sigil_vault::LocalVault::new(vault_path.clone(), identity_path.clone()).unwrap();
        vault.init(None).unwrap();

        // Load config from vault (should return default since no rules exist)
        let config = load_config_from_vault(vault_path, identity_path, None).unwrap();

        // Should return default config
        assert_eq!(config.rules.len(), 0);
        assert_eq!(config.listen, "127.0.0.1:0");
    }

    #[test]
    fn test_save_and_load_config_from_vault() {
        // Create a temporary vault directory
        let temp_dir = TempDir::new().unwrap();
        let vault_path = temp_dir.path().join("vault");
        let identity_path = temp_dir.path().join("identity.age");

        // Initialize the vault
        let mut vault =
            sigil_vault::LocalVault::new(vault_path.clone(), identity_path.clone()).unwrap();
        vault.init(None).unwrap();

        // Create a test config
        let config = ProxyConfig {
            listen: "127.0.0.1:8080".to_string(),
            rules: vec![],
            allowlist_only: true,
            audit_logging: true,
            timeout_secs: 30,
        };

        // Save the config to the vault
        save_config_to_vault(&config, vault_path.clone(), identity_path.clone(), None).unwrap();

        // Load the config from the vault
        let loaded_config = load_config_from_vault(vault_path, identity_path, None).unwrap();

        // Verify the loaded config matches the saved config
        assert_eq!(loaded_config.listen, "127.0.0.1:8080");
        assert!(loaded_config.allowlist_only);
        assert!(loaded_config.audit_logging);
        assert_eq!(loaded_config.timeout_secs, 30);
    }
}
