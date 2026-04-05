//! Environment variable backend for SIGIL
//!
//! This backend provides secret access from a restricted environment file
//! (not the agent's process environment). This is useful for CI/CD integration
//! and other scenarios where secrets are provided via environment variables.
//!
//! # Security Considerations
//!
//! - **Never reads from the agent's process environment**: The backend reads
//!   from a specific env file, not `std::env::var()`. This prevents agents from
//!   accessing secrets via environment inspection.
//! - **File permissions**: The env file must have restrictive permissions (0600).
//! - **No shell expansion**: Environment variable values are not expanded through
//!   the shell, preventing injection attacks.
//!
//! # Configuration
//!
//! Add to `~/.sigil/config.toml`:
//!
//! ```toml
//! [backends.env]
//! type = "env"
//! file = "~/.sigil/secrets.env"  # Path to env file
//! prefix = "SIGIL_"              # Optional prefix for filtering
//! ```
//!
//! # Environment File Format
//!
//! The env file uses a simple KEY=VALUE format (similar to .env files):
//!
//! ```text
//! SIGIL_API_KEY=sk_live_12345
//! SIGIL_DATABASE_URL=postgresql://user:pass@host/db
//! SIGIL_SECRET_TOKEN=abc123def456
//! ```

#![warn(missing_docs)]
#![warn(clippy::all)]

use sigil_core::{Result, SecretBackend, SecretMetadata, SecretPath, SecretValue, SigilError};
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use zeroize::Zeroizing;

/// Environment variable backend configuration
#[derive(Debug, Clone)]
pub struct EnvBackendConfig {
    /// Path to the environment file
    pub env_file: PathBuf,
    /// Optional prefix for filtering variables
    pub prefix: Option<String>,
}

impl Default for EnvBackendConfig {
    fn default() -> Self {
        Self {
            env_file: PathBuf::from("~/.sigil/secrets.env"),
            prefix: Some("SIGIL_".to_string()),
        }
    }
}

/// Environment variable backend for SIGIL
///
/// Reads secrets from a restricted environment file. This backend is designed
/// for CI/CD integration and other scenarios where secrets are provided via
/// environment variables.
pub struct EnvBackend {
    /// The environment file path
    env_file: PathBuf,
    /// Optional prefix for filtering variables
    prefix: Option<String>,
    /// Cached environment variables (loaded at startup)
    env_vars: HashMap<String, Zeroizing<Vec<u8>>>,
    /// Metadata for cached secrets
    metadata: HashMap<String, SecretMetadata>,
}

impl EnvBackend {
    /// Create a new environment variable backend
    ///
    /// # Arguments
    /// * `config` - Backend configuration
    ///
    /// # Returns
    /// A new EnvBackend instance with loaded environment variables
    pub fn new(config: EnvBackendConfig) -> Result<Self> {
        // Expand tilde in the path
        let env_file = expand_tilde(config.env_file);

        // Check if the file exists
        if !env_file.exists() {
            return Err(SigilError::IoError(format!(
                "Environment file not found: {}",
                env_file.display()
            )));
        }

        // Check file permissions
        let metadata = fs::metadata(&env_file).map_err(|e| {
            SigilError::IoError(format!("Failed to read env file metadata: {}", e))
        })?;

        // On Unix, check permissions
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let perms = metadata.permissions();
            let mode = perms.mode();

            // Check if file is readable by others (group or world)
            if mode & 0o044 != 0 {
                tracing::warn!(
                    "Environment file has宽松 permissions: {:?} (should be 0600)",
                    env_file
                );
            }
        }

        // Load environment variables
        let env_vars = Self::load_env_file(&env_file)?;

        // Build metadata map
        let mut metadata_map: HashMap<String, SecretMetadata> = HashMap::new();
        for key in env_vars.keys() {
            let path = SecretPath::new(key).unwrap_or_else(|_| SecretPath::new(format!("env/{}", key)).unwrap());

            metadata_map.insert(
                key.clone(),
                SecretMetadata {
                    path: path.clone(),
                    secret_type: sigil_core::SecretType::Generic,
                    tags: vec!["env".to_string()],
                    notes: Some(format!("Loaded from {}", env_file.display())),
                    created_at: chrono::Utc::now(),
                    updated_at: chrono::Utc::now(),
                    expires_at: None,
                },
            );
        }

        Ok(Self {
            env_file,
            prefix: config.prefix,
            env_vars,
            metadata: metadata_map,
        })
    }

    /// Load environment variables from a file
    ///
    /// The file format is KEY=VALUE, one per line. Comments start with #.
    /// Empty lines are ignored.
    fn load_env_file(path: &Path) -> Result<HashMap<String, Zeroizing<Vec<u8>>>> {
        let content = fs::read_to_string(path).map_err(|e| {
            SigilError::IoError(format!("Failed to read env file: {}", e))
        })?;

        let mut env_vars = HashMap::new();

        for (line_num, line) in content.lines().enumerate() {
            let line = line.trim();

            // Skip empty lines and comments
            if line.is_empty() || line.starts_with('#') {
                continue;
            }

            // Parse KEY=VALUE format
            if let Some(eq_pos) = line.find('=') {
                let key = line[..eq_pos].trim();
                let value = line[eq_pos + 1..].trim();

                // Skip empty keys
                if key.is_empty() {
                    tracing::warn!("Skipping empty key at line {}", line_num + 1);
                    continue;
                }

                // Store the value (zeroized on drop)
                env_vars.insert(key.to_string(), Zeroizing::new(value.as_bytes().to_vec()));
            } else {
                tracing::warn!("Skipping malformed line {}: {}", line_num + 1, line);
            }
        }

        tracing::info!("Loaded {} environment variables from {}", env_vars.len(), path.display());

        Ok(env_vars)
    }

    /// Get the env file path
    pub fn env_file(&self) -> &Path {
        &self.env_file
    }

    /// Reload the environment file
    ///
    /// This can be called to reload secrets after the env file has been modified.
    pub fn reload(&mut self) -> Result<()> {
        let new_vars = Self::load_env_file(&self.env_file)?;

        // Update metadata for new keys
        for key in new_vars.keys() {
            if !self.metadata.contains_key::<str>(key) {
                let path = SecretPath::new(key).unwrap_or_else(|_| {
                    SecretPath::new(format!("env/{}", key)).unwrap()
                });

                self.metadata.insert(
                    key.clone(),
                    SecretMetadata {
                        path: path.clone(),
                        secret_type: sigil_core::SecretType::Generic,
                        tags: vec!["env".to_string()],
                        notes: Some(format!("Loaded from {}", self.env_file.display())),
                        created_at: chrono::Utc::now(),
                        updated_at: chrono::Utc::now(),
                        expires_at: None,
                    },
                );
            }
        }

        self.env_vars = new_vars;
        tracing::info!("Reloaded environment variables from {}", self.env_file.display());

        Ok(())
    }
}

#[async_trait::async_trait]
impl SecretBackend for EnvBackend {
    /// Get a secret value by path
    ///
    /// The path is the environment variable name. For example, to get the
    /// value of `SIGIL_API_KEY`, use the path "SIGIL_API_KEY" or "api_key"
    /// (if the prefix is "SIGIL_").
    async fn get(&self, path: &SecretPath) -> Result<SecretValue> {
        let path_str = path.as_str();

        // Try direct lookup first
        if let Some(value) = self.env_vars.get(path_str) {
            return Ok(SecretValue::new(std::ops::Deref::deref(value).to_vec()));
        }

        // Try with prefix
        if let Some(ref prefix) = self.prefix {
            let prefixed = format!("{}{}", prefix, path_str);
            if let Some(value) = self.env_vars.get(&prefixed) {
                return Ok(SecretValue::new(std::ops::Deref::deref(value).to_vec()));
            }

            // Try converting path to uppercase
            let upper_path = path_str.to_uppercase();
            let upper_prefixed = format!("{}{}", prefix, upper_path);
            if let Some(value) = self.env_vars.get(&upper_prefixed) {
                return Ok(SecretValue::new(std::ops::Deref::deref(value).to_vec()));
            }
        }

        // Try uppercase path
        let upper_path = path_str.to_uppercase();
        if let Some(value) = self.env_vars.get(&upper_path) {
            return Ok(SecretValue::new(std::ops::Deref::deref(value).to_vec()));
        }

        Err(SigilError::SecretNotFound(path_str.to_string()))
    }

    /// Get secret metadata by path
    async fn get_metadata(&self, path: &SecretPath) -> Result<SecretMetadata> {
        let path_str = path.as_str();

        // Try to find the metadata by path
        if let Some(meta) = self.metadata.get(path_str) {
            return Ok(meta.clone());
        }

        // Try with prefix
        if let Some(ref prefix) = self.prefix {
            let prefixed = format!("{}{}", prefix, path_str);
            if let Some(meta) = self.metadata.get(&prefixed) {
                return Ok(meta.clone());
            }

            let upper_path = path_str.to_uppercase();
            let upper_prefixed = format!("{}{}", prefix, upper_path);
            if let Some(meta) = self.metadata.get(&upper_prefixed) {
                return Ok(meta.clone());
            }
        }

        // Try uppercase path
        let upper_path = path_str.to_uppercase();
        if let Some(meta) = self.metadata.get(&upper_path) {
            return Ok(meta.clone());
        }

        Err(SigilError::SecretNotFound(path_str.to_string()))
    }

    /// Set a secret value (writes to the env file)
    async fn set(&self, _path: &SecretPath, _value: &SecretValue, _meta: &SecretMetadata) -> Result<()> {
        // Env backend is read-only for security (env file should be managed externally)
        Err(SigilError::IoError(
            "Environment backend is read-only. Use 'sigil add' to store secrets in the local vault.".to_string()
        ))
    }

    /// Delete a secret (not supported for env backend)
    async fn delete(&self, path: &SecretPath) -> Result<()> {
        // Env backend is read-only
        Err(SigilError::IoError(format!(
            "Cannot delete secret '{}' from environment backend (read-only)",
            path.as_str()
        )))
    }

    /// List all available secrets
    ///
    /// Returns all environment variable names that match the prefix (if configured).
    async fn list(&self, _prefix: &str) -> Result<Vec<SecretMetadata>> {
        let mut secrets = Vec::new();

        for (key, metadata) in &self.metadata {
            // Filter by prefix if configured
            if let Some(ref p) = self.prefix {
                if key.starts_with(p) {
                    secrets.push(metadata.clone());
                }
            } else {
                secrets.push(metadata.clone());
            }
        }

        Ok(secrets)
    }

    /// Get the backend type
    fn backend_type(&self) -> &str {
        "env"
    }
}

/// Expand tilde (~) in a path to the user's home directory
fn expand_tilde(path: PathBuf) -> PathBuf {
    if let Some(path_str) = path.to_str() {
        if let Some(stripped) = path_str.strip_prefix('~') {
            if let Some(home) = dirs::home_dir() {
                return home.join(stripped.trim_start_matches('/'));
            }
        }
    }
    path
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn test_env_backend_config_default() {
        let config = EnvBackendConfig::default();
        assert_eq!(config.env_file, PathBuf::from("~/.sigil/secrets.env"));
        assert_eq!(config.prefix, Some("SIGIL_".to_string()));
    }

    #[test]
    fn test_load_env_file() {
        let temp_dir = TempDir::new().unwrap();
        let env_file = temp_dir.path().join("test.env");

        // Write test env file
        fs::write(
            &env_file,
            "# Test environment file\nSIGIL_API_KEY=sk_live_12345\nSIGIL_SECRET=abc123\n\n# Comment\n",
        )
        .unwrap();

        let env_vars = EnvBackend::load_env_file(&env_file).unwrap();

        assert_eq!(env_vars.len(), 2);
        assert!(env_vars.contains_key("SIGIL_API_KEY"));
        assert!(env_vars.contains_key("SIGIL_SECRET"));
    }

    #[test]
    fn test_env_backend_creation() {
        let temp_dir = TempDir::new().unwrap();
        let env_file = temp_dir.path().join("test.env");

        // Write test env file
        fs::write(
            &env_file,
            "SIGIL_API_KEY=sk_live_12345\nSIGIL_DATABASE_URL=postgresql://user:pass@host/db\n",
        )
        .unwrap();

        let config = EnvBackendConfig {
            env_file: env_file.clone(),
            prefix: Some("SIGIL_".to_string()),
        };

        let backend = EnvBackend::new(config).unwrap();
        assert_eq!(backend.env_file(), &env_file);
    }

    #[tokio::test]
    async fn test_env_backend_get() {
        let temp_dir = TempDir::new().unwrap();
        let env_file = temp_dir.path().join("test.env");

        // Write test env file
        fs::write(&env_file, "SIGIL_API_KEY=sk_live_12345\n").unwrap();

        let config = EnvBackendConfig {
            env_file: env_file.clone(),
            prefix: Some("SIGIL_".to_string()),
        };

        let backend = EnvBackend::new(config).unwrap();

        // Test direct lookup
        let path = SecretPath::new("SIGIL_API_KEY").unwrap();
        let value = backend.get(&path).await.unwrap();
        assert_eq!(value.expose(|v| v.to_vec()), b"sk_live_12345");

        // Test lookup without prefix
        let path = SecretPath::new("api_key").unwrap();
        let value = backend.get(&path).await.unwrap();
        assert_eq!(value.expose(|v| v.to_vec()), b"sk_live_12345");
    }

    #[tokio::test]
    async fn test_env_backend_get_not_found() {
        let temp_dir = TempDir::new().unwrap();
        let env_file = temp_dir.path().join("test.env");

        // Write test env file
        fs::write(&env_file, "SIGIL_API_KEY=sk_live_12345\n").unwrap();

        let config = EnvBackendConfig {
            env_file: env_file.clone(),
            prefix: Some("SIGIL_".to_string()),
        };

        let backend = EnvBackend::new(config).unwrap();

        // Test lookup for non-existent secret
        let path = SecretPath::new("nonexistent").unwrap();
        let result = backend.get(&path).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_env_backend_list() {
        let temp_dir = TempDir::new().unwrap();
        let env_file = temp_dir.path().join("test.env");

        // Write test env file
        fs::write(&env_file, "SIGIL_API_KEY=sk_live_12345\nSIGIL_SECRET=abc123\n").unwrap();

        let config = EnvBackendConfig {
            env_file: env_file.clone(),
            prefix: Some("SIGIL_".to_string()),
        };

        let backend = EnvBackend::new(config).unwrap();
        let secrets = backend.list("").await.unwrap();

        assert_eq!(secrets.len(), 2);
    }

    #[test]
    fn test_env_backend_missing_file() {
        let config = EnvBackendConfig {
            env_file: PathBuf::from("/nonexistent/path/secrets.env"),
            prefix: None,
        };

        let result = EnvBackend::new(config);
        assert!(result.is_err());
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
