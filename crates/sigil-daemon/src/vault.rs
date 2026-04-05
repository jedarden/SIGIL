//! Vault unlock and secret loading for SIGIL daemon
//!
//! This module handles:
//! - Prompting for vault passphrase (or reading from inherited fd)
//! - Loading and decrypting all secrets from the vault
//! - Storing secrets in protected memory
//! - Session token file management

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

/// Session token file manager
///
/// Handles secure storage of session tokens in a restricted file.
pub struct SessionTokenFile {
    token_path: PathBuf,
}

impl SessionTokenFile {
    /// Create a new session token file manager
    ///
    /// The token file is stored in $XDG_RUNTIME_DIR with 0400 permissions.
    pub fn new() -> Result<Self, SigilError> {
        let runtime_dir = std::env::var("XDG_RUNTIME_DIR")
            .map_err(|_| SigilError::IoError("XDG_RUNTIME_DIR not set".into()))?;

        let token_path = PathBuf::from(runtime_dir).join("sigil-session-token");

        Ok(Self { token_path })
    }

    /// Write a session token to the file
    ///
    /// The file is created with 0400 permissions (owner read-only).
    pub fn write_token(&self, token: &SessionToken) -> Result<(), SigilError> {
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

    /// Read the session token from the file
    #[allow(dead_code)]
    pub fn read_token(&self) -> Result<SessionToken, SigilError> {
        let token_str = std::fs::read_to_string(&self.token_path)
            .map_err(|e| SigilError::IoError(format!("Failed to read token file: {}", e)))?;

        SessionToken::from_string(token_str.trim().to_string())
    }

    /// Remove the token file
    #[allow(dead_code)]
    pub fn remove(&self) -> Result<(), SigilError> {
        if self.token_path.exists() {
            std::fs::remove_file(&self.token_path)
                .map_err(|e| SigilError::IoError(format!("Failed to remove token file: {}", e)))?;
            info!("Session token file removed");
        }
        Ok(())
    }

    /// Get the token file path
    pub fn path(&self) -> &PathBuf {
        &self.token_path
    }
}

/// Vault manager for the daemon
pub struct VaultManager {
    vault_path: PathBuf,
    identity_path: PathBuf,
    vault: Option<LocalVault>,
    session_token_file: SessionTokenFile,
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
        })
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
        let passphrase = rpassword::prompt_password("Enter vault passphrase (press Enter for none): ")
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

    /// Prompt for passphrase and unlock the vault (sync version)
    ///
    /// This will:
    /// 1. Prompt the user for the vault passphrase
    /// 2. Load and decrypt the vault identity
    /// 3. Load all secrets into the protected secrets store
    /// 4. Generate and write the session token to a file
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

        info!("Vault unlocked and {} secrets loaded", secrets_loaded);

        // Generate and write session token
        let session_token = SessionToken::generate();
        self.session_token_file.write_token(&session_token)?;

        info!(
            "Session token written to {}",
            self.session_token_file.path().display()
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
        let (session_token, vault_instance) = spawn_blocking(move || {
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

            tracing::info!("Vault unlocked and {} secrets loaded", secrets_loaded);

            // Generate session token
            let session_token = SessionToken::generate();

            Ok::<(SessionToken, LocalVault), SigilError>((session_token, vault))
        })
        .await
        .map_err(|e| SigilError::IoError(format!("Task join error: {}", e)))??;

        // Store the vault
        self.vault = Some(vault_instance);

        // Write session token
        self.session_token_file.write_token(&session_token)?;

        tracing::info!(
            "Session token written to {}",
            self.session_token_file.path().display()
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
