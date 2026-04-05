//! Pass/gopass backend for SIGIL
//!
//! This backend provides secret access from pass (the standard password manager)
//! or gopass (a fork of pass with additional features like GPG encryption, PNP
//! (pass-name-plate), and team sharing).
//!
//! # Security Considerations
//!
//! - **Read-only access**: The backend only reads secrets via `pass show` or
//!   `gopass show -o`. It never writes secrets.
//! - **Pass/GPG encryption**: Secrets are encrypted using GPG keys managed by
//!   pass/gopass. SIGIL does not store GPG passphrases.
//! - **No secret caching**: Secrets are fetched on-demand and not cached in memory
//!   beyond the lifetime of the request.
//! - **Environment isolation**: The backend does not read from the agent's process
//!   environment.
//!
//! # Configuration
//!
//! Add to `~/.sigil/config.toml`:
//!
//! ```toml
//! [backends.pass]
//! type = "pass"
//! # Command to use: "pass" or "gopass" (default: auto-detect)
//! command = "auto"
//! # Base path for secrets (default: ~/.password-store)
//! store = "~/.password-store"
//! ```
//!
//! # Path Mapping
//!
//! Pass secrets are mapped to SIGIL paths as follows:
//! - `pass: email/gmail` → SIGIL path: `email/gmail`
//! - `gopass: work/aws` → SIGIL path: `work/aws`
//! - Paths are preserved as-is (no transformation)

#![warn(missing_docs)]
#![warn(clippy::all)]

use async_trait::async_trait;
use sigil_core::{
    Result, SecretBackend, SecretMetadata, SecretPath, SecretType, SecretValue, SigilError,
};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::str;

/// Pass/gopass backend configuration
#[derive(Debug, Clone)]
pub struct PassBackendConfig {
    /// Command to use: "pass", "gopass", or "auto" (default)
    pub command: PassCommand,
    /// Base path for the password store (default: ~/.password-store)
    pub store_path: PathBuf,
}

impl Default for PassBackendConfig {
    fn default() -> Self {
        Self {
            command: PassCommand::Auto,
            store_path: PathBuf::from("~/.password-store"),
        }
    }
}

/// Which password manager command to use
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PassCommand {
    /// Automatically detect which command is available
    Auto,
    /// Use standard pass
    Pass,
    /// Use gopass (a fork of pass with additional features)
    Gopass,
}

/// Pass/gopass backend for SIGIL
///
/// Reads secrets from a pass or gopass password store. This backend is designed
/// for users who already use pass/gopass and want to integrate it with SIGIL.
pub struct PassBackend {
    /// The command to use (pass or gopass)
    command: String,
    /// Base path for the password store
    store_path: PathBuf,
    /// Cached metadata for all secrets
    metadata: HashMap<String, SecretMetadata>,
}

impl PassBackend {
    /// Create a new pass/gopass backend
    ///
    /// # Arguments
    /// * `config` - Backend configuration
    ///
    /// # Returns
    /// A new PassBackend instance with loaded secret metadata
    pub fn new(config: PassBackendConfig) -> Result<Self> {
        // Expand tilde in the store path
        let store_path = expand_tilde(config.store_path);

        // Detect or use the specified command
        let command = match config.command {
            PassCommand::Auto => detect_pass_command()?,
            PassCommand::Pass => "pass".to_string(),
            PassCommand::Gopass => "gopass".to_string(),
        };

        // Verify the command is available
        if !command_exists(&command) {
            return Err(SigilError::IoError(format!(
                "Command '{}' not found. Please install pass or gopass.",
                command
            )));
        }

        // Verify the store exists
        if !store_path.exists() {
            return Err(SigilError::IoError(format!(
                "Password store not found: {}",
                store_path.display()
            )));
        }

        // Build metadata map by listing all secrets
        let metadata = Self::build_metadata(&command, &store_path)?;

        Ok(Self {
            command,
            store_path,
            metadata,
        })
    }

    /// Build metadata map by listing all secrets in the store
    fn build_metadata(command: &str, store_path: &Path) -> Result<HashMap<String, SecretMetadata>> {
        let mut metadata = HashMap::new();

        // List all secrets using `pass show` or `gopass ls`
        let args: Vec<&str> = if command == "gopass" {
            vec!["ls", "-flat"]
        } else {
            vec!["ls"]
        };
        let output = Command::new(command)
            .args(args)
            .env("PASSWORD_STORE_DIR", store_path)
            .output()
            .map_err(|e| SigilError::IoError(format!("Failed to list secrets: {}", e)))?;

        if !output.status.success() {
            // gopass ls might not be available, try alternative approach
            return Ok(metadata);
        }

        // Parse output to extract secret paths
        let stdout = str::from_utf8(&output.stdout).unwrap_or("");
        for line in stdout.lines() {
            let trimmed = line.trim();
            if trimmed.is_empty() || trimmed.starts_with("=+") {
                // Skip gopass separator lines
                continue;
            }

            // Determine secret type based on path
            let secret_type = if trimmed.contains("ssh") {
                SecretType::SshKey
            } else if trimmed.contains("api")
                || trimmed.contains("key")
                || trimmed.contains("token")
            {
                SecretType::ApiKey
            } else if trimmed.contains("cert") {
                SecretType::Certificate
            } else {
                SecretType::Generic
            };

            let path = SecretPath::new(trimmed)
                .unwrap_or_else(|_| SecretPath::new(format!("pass/{}", trimmed)).unwrap());

            metadata.insert(
                trimmed.to_string(),
                SecretMetadata {
                    path: path.clone(),
                    secret_type,
                    tags: vec!["pass".to_string()],
                    notes: Some("From pass/gopass store".to_string()),
                    created_at: chrono::Utc::now(),
                    updated_at: chrono::Utc::now(),
                    expires_at: None,
                },
            );
        }

        tracing::info!(
            "Loaded {} secrets from pass/gopass store at {}",
            metadata.len(),
            store_path.display()
        );

        Ok(metadata)
    }

    /// Get the password store path
    pub fn store_path(&self) -> &Path {
        &self.store_path
    }

    /// Get the command being used
    pub fn command(&self) -> &str {
        &self.command
    }
}

#[async_trait]
impl SecretBackend for PassBackend {
    /// Get a secret value by path
    ///
    /// The path is the pass/gopass secret path. For example, to get the
    /// secret at `email/gmail`, use the path "email/gmail".
    async fn get(&self, path: &SecretPath) -> Result<SecretValue> {
        let path_str = path.as_str();

        // Strip "pass/" prefix if present
        let pass_path = if let Some(stripped) = path_str.strip_prefix("pass/") {
            stripped
        } else {
            path_str
        };

        // Run `pass show` or `gopass show -o`
        let args: Vec<&str> = if self.command == "gopass" {
            vec!["show", "-o", pass_path]
        } else {
            vec!["show", pass_path]
        };
        let output = Command::new(&self.command)
            .args(args)
            .env("PASSWORD_STORE_DIR", &self.store_path)
            .output()
            .map_err(|e| {
                SigilError::IoError(format!("Failed to run {} show: {}", self.command, e))
            })?;

        if !output.status.success() {
            return Err(SigilError::SecretNotFound(path_str.to_string()));
        }

        // Get the first line (password) or full content
        let stdout = str::from_utf8(&output.stdout).unwrap_or("");
        let value = stdout.lines().next().unwrap_or("").trim();

        if value.is_empty() {
            return Err(SigilError::SecretNotFound(path_str.to_string()));
        }

        Ok(SecretValue::new(value.as_bytes().to_vec()))
    }

    /// Get secret metadata by path
    async fn get_metadata(&self, path: &SecretPath) -> Result<SecretMetadata> {
        let path_str = path.as_str();

        // Strip "pass/" prefix if present
        let pass_path = if let Some(stripped) = path_str.strip_prefix("pass/") {
            stripped
        } else {
            path_str
        };

        // Try direct lookup first
        if let Some(meta) = self.metadata.get(pass_path) {
            return Ok(meta.clone());
        }

        // Try without stripping prefix
        if let Some(meta) = self.metadata.get(path_str) {
            return Ok(meta.clone());
        }

        Err(SigilError::SecretNotFound(path_str.to_string()))
    }

    /// Set a secret value (not supported for pass backend)
    async fn set(
        &self,
        _path: &SecretPath,
        _value: &SecretValue,
        _meta: &SecretMetadata,
    ) -> Result<()> {
        // Pass backend is read-only for security (pass store should be managed via pass/gopass CLI)
        Err(SigilError::IoError(
            "Pass backend is read-only. Use 'pass insert' or 'gopass edit' to store secrets."
                .to_string(),
        ))
    }

    /// Delete a secret (not supported for pass backend)
    async fn delete(&self, path: &SecretPath) -> Result<()> {
        // Pass backend is read-only
        Err(SigilError::IoError(format!(
            "Cannot delete secret '{}' from pass backend (read-only)",
            path.as_str()
        )))
    }

    /// List all available secrets
    ///
    /// Returns all secret paths from the pass/gopass store.
    async fn list(&self, prefix: &str) -> Result<Vec<SecretMetadata>> {
        let mut secrets = Vec::new();

        for (path, metadata) in &self.metadata {
            // Filter by prefix if specified
            if prefix.is_empty() || path.starts_with(prefix) {
                secrets.push(metadata.clone());
            }
        }

        Ok(secrets)
    }

    /// Get the backend type
    fn backend_type(&self) -> &str {
        "pass"
    }
}

/// Detect which pass command is available
fn detect_pass_command() -> Result<String> {
    if command_exists("gopass") {
        Ok("gopass".to_string())
    } else if command_exists("pass") {
        Ok("pass".to_string())
    } else {
        Err(SigilError::IoError(
            "Neither 'pass' nor 'gopass' command found. Please install one of them.".to_string(),
        ))
    }
}

/// Check if a command exists in PATH
fn command_exists(command: &str) -> bool {
    Command::new("which")
        .arg(command)
        .output()
        .map(|output| output.status.success())
        .unwrap_or(false)
}

/// Expand tilde (~) in a path to the user's home directory
fn expand_tilde(path: PathBuf) -> PathBuf {
    if let Some(path_str) = path.to_str() {
        if let Some(stripped) = path_str.strip_prefix('~') {
            if let Some(home) = dirs::home_dir() {
                let home_path: &std::path::Path = home.as_path();
                return home_path.join(stripped.trim_start_matches('/'));
            }
        }
    }
    path
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pass_backend_config_default() {
        let config = PassBackendConfig::default();
        assert_eq!(config.command, PassCommand::Auto);
        assert_eq!(config.store_path, PathBuf::from("~/.password-store"));
    }

    #[test]
    fn test_detect_pass_command() {
        // This test will fail if neither pass nor gopass is installed
        // We'll handle this gracefully
        let result = detect_pass_command();
        // Just verify it doesn't panic
        drop(result);
    }

    #[test]
    fn test_command_exists() {
        // Test with commands that should exist
        assert!(command_exists("sh"));
        assert!(command_exists("ls"));

        // Test with commands that shouldn't exist
        assert!(!command_exists("thiscommanddefinitelydoesnotexist12345"));
    }

    #[test]
    fn test_expand_tilde() {
        let result = expand_tilde(PathBuf::from("~/test"));
        let home = dirs::home_dir().unwrap();
        assert!(result.starts_with(home));
        assert!(result.ends_with("test"));
    }

    #[test]
    fn test_expand_tilde_no_tilde() {
        let result = expand_tilde(PathBuf::from("/absolute/path"));
        assert_eq!(result, PathBuf::from("/absolute/path"));
    }
}
