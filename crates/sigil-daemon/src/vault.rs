//! Vault unlock and secret loading for SIGIL daemon
//!
//! This module handles:
//! - Prompting for vault passphrase (or reading from inherited fd)
//! - Loading and decrypting all secrets from the vault
//! - Storing secrets in protected memory
//! - Session token management using kernel keyring (Linux) or file fallback

use crate::memory::ProtectedSecrets;
use sigil_core::{SecretBackend, SessionToken, SigilError};
use sigil_vault::LocalVault;
use std::fs::OpenOptions;
use std::io::Write;
use std::path::PathBuf;
use tracing::{debug, info, warn};
use zeroize::Zeroizing;

#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;

/// Session token manager
///
/// Handles secure storage of session tokens using the kernel keyring
/// on Linux (preferred) or falling back to a restricted file on other platforms.
///
/// # Security
///
/// On Linux with kernel keyring support:
/// - Token is stored in kernel memory, never written to disk
/// - Token is inherited by child processes but not by processes in a new session
/// - Token can be revoked or expire
///
/// On other platforms or as fallback:
/// - Token file is stored in $XDG_RUNTIME_DIR with 0400 permissions
pub struct SessionTokenFile {
    /// Token file path (fallback only)
    token_path: PathBuf,
    /// Whether kernel keyring is available
    use_keyring: bool,
}

impl SessionTokenFile {
    /// Create a new session token manager
    ///
    /// The token file is stored in $XDG_RUNTIME_DIR with 0400 permissions
    /// as a fallback if kernel keyring is not available.
    pub fn new() -> Result<Self, SigilError> {
        let runtime_dir = std::env::var("XDG_RUNTIME_DIR")
            .map_err(|_| SigilError::IoError("XDG_RUNTIME_DIR not set".into()))?;

        let token_path = PathBuf::from(runtime_dir).join("sigil-session-token");

        // Check if kernel keyring is available (Linux only)
        let use_keyring = sigil_core::is_keyring_available();

        if use_keyring {
            info!("Kernel keyring available, will use for session token storage");
        } else {
            info!("Kernel keyring not available, will use file-based storage");
        }

        Ok(Self {
            token_path,
            use_keyring,
        })
    }

    /// Write a session token
    ///
    /// On Linux with kernel keyring support, stores the token in the kernel's
    /// session keyring. Otherwise, falls back to file storage with 0400 permissions.
    pub fn write_token(&self, token: &SessionToken) -> Result<(), SigilError> {
        if self.use_keyring {
            // Use kernel keyring (preferred)
            let token_str = token.to_base64();
            sigil_core::add_session_token(&token_str)?;
            info!("Session token stored in kernel keyring");
            Ok(())
        } else {
            // Fallback to file storage
            self.write_token_file(token)
        }
    }

    /// Write a session token to file (fallback)
    fn write_token_file(&self, token: &SessionToken) -> Result<(), SigilError> {
        // Create the file with restricted permissions
        let mut file = OpenOptions::new()
            .create_new(true)
            .write(true)
            .mode(0o400)
            .open(&self.token_path)
            .map_err(|e| SigilError::IoError(format!("Failed to create token file: {}", e)))?;

        // Write the token
        file.write_all(token.to_base64().as_bytes())
            .map_err(|e| SigilError::IoError(format!("Failed to write token: {}", e)))?;

        file.flush()
            .map_err(|e| SigilError::IoError(format!("Failed to flush token: {}", e)))?;

        info!("Session token written to {}", self.token_path.display());

        Ok(())
    }

    /// Read the session token
    ///
    /// On Linux with kernel keyring support, reads from the kernel's session keyring.
    /// Otherwise, reads from the fallback file.
    #[allow(dead_code)]
    pub fn read_token(&self) -> Result<SessionToken, SigilError> {
        if self.use_keyring {
            // Read from kernel keyring
            let token_str = sigil_core::read_session_token()?;
            SessionToken::from_string(token_str)
        } else {
            // Read from file
            let token_str = std::fs::read_to_string(&self.token_path)
                .map_err(|e| SigilError::IoError(format!("Failed to read token file: {}", e)))?;
            SessionToken::from_string(token_str.trim().to_string())
        }
    }

    /// Remove the session token
    ///
    /// On Linux with kernel keyring support, revokes the key from the kernel.
    /// Otherwise, removes the fallback file.
    #[allow(dead_code)]
    pub fn remove(&self) -> Result<(), SigilError> {
        if self.use_keyring {
            // Revoke from kernel keyring
            sigil_core::remove_session_token()?;
            info!("Session token revoked from kernel keyring");
        } else {
            // Remove file
            if self.token_path.exists() {
                std::fs::remove_file(&self.token_path).map_err(|e| {
                    SigilError::IoError(format!("Failed to remove token file: {}", e))
                })?;
                info!("Session token file removed");
            }
        }
        Ok(())
    }

    /// Get the token file path (for fallback mode only)
    ///
    /// Returns None if using kernel keyring mode
    pub fn path(&self) -> Option<&PathBuf> {
        if self.use_keyring {
            None
        } else {
            Some(&self.token_path)
        }
    }

    /// Check if kernel keyring is being used
    #[allow(dead_code)]
    pub fn is_using_keyring(&self) -> bool {
        self.use_keyring
    }
}

/// Vault manager for the daemon
pub struct VaultManager {
    vault_path: PathBuf,
    identity_path: PathBuf,
    vault: Option<LocalVault>,
    session_token_file: SessionTokenFile,
    /// Tier 2 configuration loaded from vault (_sigil/config/*)
    /// Phase 5.7 Configuration Opacity
    tier2_config: std::collections::HashMap<String, String>,
}

impl VaultManager {
    /// Create a new vault manager
    ///
    /// The vault_path is expected to be the `.sigil` directory (e.g., `~/.sigil`),
    /// not the vault subdirectory. This matches the CLI's convention where:
    /// - identity file is at `~/.sigil/identity.age`
    /// - vault data is at `~/.sigil/vault/`
    pub fn new(vault_path: PathBuf) -> Result<Self, SigilError> {
        // The vault_path is actually the .sigil directory
        // Identity file is in the .sigil directory, not in the vault subdirectory
        let identity_path = vault_path.join("identity.age");
        let vault_data_path = vault_path.join("vault");
        let session_token_file = SessionTokenFile::new()?;

        Ok(Self {
            vault_path: vault_data_path,
            identity_path,
            vault: None,
            session_token_file,
            tier2_config: std::collections::HashMap::new(),
        })
    }

    /// Get Tier 2 configuration value
    ///
    /// Phase 5.7 Configuration Opacity: Returns security-sensitive config
    /// loaded from the vault. Returns None if the key doesn't exist.
    #[allow(dead_code)]
    pub fn get_tier2_config(&self, key: &str) -> Option<String> {
        self.tier2_config.get(key).cloned()
    }

    /// Get all Tier 2 configuration
    ///
    /// Phase 5.7 Configuration Opacity: Returns all security-sensitive config
    /// loaded from the vault as a key-value map.
    #[allow(dead_code)]
    pub fn tier2_config(&self) -> &std::collections::HashMap<String, String> {
        &self.tier2_config
    }

    /// Get the session token file
    pub fn session_token_file(&self) -> &SessionTokenFile {
        &self.session_token_file
    }

    /// Check if the vault exists
    pub fn exists(&self) -> bool {
        self.identity_path.exists() && self.vault_path.exists()
    }

    /// Prompt for passphrase
    ///
    /// In production, this should use a secure prompt method (e.g., inherited fd from TUI).
    /// For now, we use a simple readline implementation.
    ///
    /// Returns an empty string for vaults initialized with --no-passphrase.
    fn prompt_passphrase() -> Result<Zeroizing<String>, SigilError> {
        // Use rpassword for secure password input
        // Empty passphrase is accepted for vaults initialized with --no-passphrase
        let passphrase =
            rpassword::prompt_password("Enter vault passphrase (press Enter for none): ")
                .map_err(|e| SigilError::IoError(format!("Failed to read passphrase: {}", e)))?;

        Ok(Zeroizing::new(passphrase))
    }

    /// Load all secrets from the vault into protected memory
    fn load_all_secrets(
        vault: &LocalVault,
        protected_secrets: &ProtectedSecrets,
    ) -> Result<usize, SigilError> {
        use tokio::runtime::Runtime;

        // Create a new runtime for the async operations
        let rt = Runtime::new()
            .map_err(|e| SigilError::IoError(format!("Failed to create runtime: {}", e)))?;

        rt.block_on(async {
            let mut loaded = 0;

            // List all secrets in the vault
            let secrets = vault
                .list("")
                .await
                .map_err(|e| SigilError::IoError(format!("Failed to list secrets: {}", e)))?;

            for meta in secrets {
                let path = meta.path.as_str();

                // Load each secret
                match vault.get(&meta.path).await {
                    Ok(value) => {
                        let secret_bytes = value.expose(|v: &[u8]| v.to_vec());

                        // Store in protected memory
                        if let Err(e) = protected_secrets
                            .insert(path.to_string(), secret_bytes)
                            .await
                        {
                            warn!("Failed to store secret {} in protected memory: {}", path, e);
                        } else {
                            debug!("Loaded secret: {}", path);
                            loaded += 1;
                        }
                    }
                    Err(e) => {
                        warn!("Failed to load secret {}: {}", path, e);
                    }
                }
            }

            Ok(loaded)
        })
    }

    /// Load Tier 2 configuration from the vault
    ///
    /// Phase 5.7 Configuration Opacity: Security-sensitive configuration is stored
    /// encrypted in the vault as `_sigil/config/*` entries. This function loads
    /// those values and returns them as a key-value map.
    ///
    /// Tier 2 config includes:
    /// - Canary file paths and canary values
    /// - Secret path ACLs and access policies
    /// - Hook bypass tokens (if any)
    /// - Lockdown thresholds and alert destinations
    /// - Sandbox exception rules
    fn load_tier2_config(
        vault: &LocalVault,
    ) -> Result<std::collections::HashMap<String, String>, SigilError> {
        use tokio::runtime::Runtime;

        let rt = Runtime::new()
            .map_err(|e| SigilError::IoError(format!("Failed to create runtime: {}", e)))?;

        rt.block_on(async {
            let mut config = std::collections::HashMap::new();

            // List all secrets in the _sigil/config/ namespace
            let secrets = vault
                .list("_sigil/config/")
                .await
                .map_err(|e| SigilError::IoError(format!("Failed to list Tier 2 config: {}", e)))?;

            for meta in secrets {
                let path = meta.path.as_str();

                // Extract the config key from the path (remove _sigil/config/ prefix)
                let key = path
                    .strip_prefix("_sigil/config/")
                    .unwrap_or(path)
                    .to_string();

                // Load the config value
                match vault.get(&meta.path).await {
                    Ok(value) => {
                        let config_value =
                            value.expose(|v: &[u8]| String::from_utf8_lossy(v).to_string());
                        config.insert(key, config_value);
                        debug!("Loaded Tier 2 config: {}", meta.path.as_str());
                    }
                    Err(e) => {
                        warn!("Failed to load Tier 2 config {}: {}", path, e);
                    }
                }
            }

            if !config.is_empty() {
                info!("Loaded {} Tier 2 config entries from vault", config.len());
            }

            Ok(config)
        })
    }

    /// Prompt for passphrase and unlock the vault (sync version)
    ///
    /// This will:
    /// 1. Prompt the user for the vault passphrase
    /// 2. Load and decrypt the vault identity
    /// 3. Load all secrets into the protected secrets store
    /// 4. Load Tier 2 configuration from vault (_sigil/config/*)
    /// 5. Generate and write the session token to a file
    ///
    /// Note: This function cannot be called from within a Tokio runtime.
    /// Use `unlock_async` instead when in an async context.
    #[allow(dead_code)]
    pub fn unlock(
        &mut self,
        protected_secrets: &ProtectedSecrets,
    ) -> Result<SessionToken, SigilError> {
        // Check if vault exists
        if !self.exists() {
            return Err(SigilError::VaultLocked);
        }

        // Prompt for passphrase (may be empty for --no-passphrase vaults)
        let passphrase = Self::prompt_passphrase()?;

        // Create and load the vault
        let mut vault = LocalVault::new(self.vault_path.clone(), self.identity_path.clone())
            .map_err(|e| SigilError::IoError(format!("Failed to create vault: {}", e)))?;

        // Convert empty passphrase to None (for --no-passphrase vaults)
        let passphrase_ref = if passphrase.is_empty() {
            None
        } else {
            Some(passphrase.as_str())
        };

        vault.load(passphrase_ref).map_err(|e| {
            warn!("Failed to unlock vault: {}", e);
            SigilError::VaultLocked
        })?;

        // Zeroize the passphrase immediately after use
        drop(passphrase);

        // Store the vault
        self.vault = Some(vault);

        // Load all secrets into protected memory
        let vault = self.vault.as_ref().unwrap();
        let secrets_loaded = Self::load_all_secrets(vault, protected_secrets)?;

        // Phase 5.7: Load Tier 2 configuration from vault and store it
        self.tier2_config = Self::load_tier2_config(vault).unwrap_or_default();
        if !self.tier2_config.is_empty() {
            info!("Tier 2 config loaded: {} entries", self.tier2_config.len());
        }

        info!("Vault unlocked and {} secrets loaded", secrets_loaded);

        // Generate and write session token
        let session_token = SessionToken::generate();
        self.session_token_file.write_token(&session_token)?;

        info!(
            "Session token written to {}",
            match self.session_token_file.path() {
                Some(path) => path.display().to_string(),
                None => "kernel keyring".to_string(),
            }
        );

        Ok(session_token)
    }

    /// Async version of unlock for use within Tokio runtime
    pub async fn unlock_async(
        &mut self,
        protected_secrets: &ProtectedSecrets,
    ) -> Result<SessionToken, SigilError> {
        use tokio::task::spawn_blocking;

        // Clone the necessary data for the blocking task
        let vault_path = self.vault_path.clone();
        let identity_path = self.identity_path.clone();
        // Clone ProtectedSecrets (which is now cheap due to Arc inside)
        let protected_secrets = (*protected_secrets).clone();

        // Run the sync unlock in a blocking task
        let (session_token, vault_instance, tier2_config) = spawn_blocking(move || {
            // Prompt for passphrase
            let passphrase = Self::prompt_passphrase()?;

            // Create and load the vault
            let mut vault = LocalVault::new(vault_path, identity_path)
                .map_err(|e| SigilError::IoError(format!("Failed to create vault: {}", e)))?;

            // Convert empty passphrase to None (for --no-passphrase vaults)
            let passphrase_ref = if passphrase.is_empty() {
                None
            } else {
                Some(passphrase.as_str())
            };

            vault.load(passphrase_ref).map_err(|e| {
                tracing::warn!("Failed to unlock vault: {}", e);
                SigilError::VaultLocked
            })?;

            // Load all secrets
            let secrets_loaded = Self::load_all_secrets(&vault, &protected_secrets)?;

            // Phase 5.7: Load Tier 2 configuration from vault
            let tier2_config = Self::load_tier2_config(&vault).unwrap_or_default();
            if !tier2_config.is_empty() {
                tracing::info!("Tier 2 config loaded: {} entries", tier2_config.len());
            }

            tracing::info!("Vault unlocked and {} secrets loaded", secrets_loaded);

            // Generate session token
            let session_token = SessionToken::generate();

            Ok::<
                (
                    SessionToken,
                    LocalVault,
                    std::collections::HashMap<String, String>,
                ),
                SigilError,
            >((session_token, vault, tier2_config))
        })
        .await
        .map_err(|e| SigilError::IoError(format!("Task join error: {}", e)))??;

        // Store the vault and Tier 2 config
        self.vault = Some(vault_instance);
        self.tier2_config = tier2_config;

        // Write session token
        self.session_token_file.write_token(&session_token)?;

        tracing::info!(
            "Session token written to {}",
            match self.session_token_file.path() {
                Some(path) => path.display().to_string(),
                None => "kernel keyring".to_string(),
            }
        );

        Ok(session_token)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_vault_manager_creation() {
        let temp_dir = tempfile::tempdir().unwrap();
        let vault_path = temp_dir.path().join("vault");

        // Set XDG_RUNTIME_DIR for test
        std::env::set_var("XDG_RUNTIME_DIR", temp_dir.path());

        let manager = VaultManager::new(vault_path.clone()).unwrap();
        assert!(!manager.exists());
    }

    #[test]
    fn test_vault_manager_vault_exists() {
        let temp_dir = tempfile::tempdir().unwrap();
        let vault_path = temp_dir.path().join("vault");
        std::fs::create_dir_all(&vault_path).unwrap();

        // Set XDG_RUNTIME_DIR for test
        std::env::set_var("XDG_RUNTIME_DIR", temp_dir.path());

        // Create a fake identity file
        std::fs::write(vault_path.join("identity.age"), b"fake identity").unwrap();

        // Create the vault subdirectory (required for exists() check)
        std::fs::create_dir_all(vault_path.join("vault")).unwrap();

        let manager = VaultManager::new(vault_path).unwrap();
        assert!(manager.exists());
    }

    #[test]
    fn test_session_token_file_write_read() {
        let temp_dir = tempfile::tempdir().unwrap();
        std::env::set_var("XDG_RUNTIME_DIR", temp_dir.path());

        let token_file = SessionTokenFile::new().unwrap();
        let token = SessionToken::generate();

        // Write token
        token_file.write_token(&token).unwrap();

        // Read token
        let read_token = token_file.read_token().unwrap();
        assert_eq!(token.to_base64(), read_token.to_base64());

        // Clean up
        token_file.remove().unwrap();
    }
}
