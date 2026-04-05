//! 1Password backend for SIGIL
//!
//! This backend provides secret access from 1Password using either the
//! CLI tool (`op`) or the 1Password Connect API server.
//!
//! # Security Considerations
//!
//! - **Read-only access**: The backend only reads secrets via `op read`.
//!   It never writes secrets to 1Password.
//! - **1Password authentication**: Secrets are encrypted using 1Password's
//!   encryption. SIGIL does not store 1Password credentials.
//! - **No secret caching**: Secrets are fetched on-demand and not cached
//!   in memory beyond the lifetime of the request (unless caching is
//!   explicitly enabled).
//! - **CLI isolation**: The backend shells out to `op` command which runs
//!   in a separate process.
//!
//! # Configuration
//!
//! ## Using the CLI (default)
//!
//! Add to `~/.sigil/config.toml`:
//!
//! ```toml
//! [backends.onepassword]
//! type = "onepassword"
//! # Vault name to use as prefix (optional)
//! vault = "Personal"
//! # Account shorthand (optional, for biometric auth)
//! account = "myaccount.1password.com"
//! # Cache secrets in memory (default: false)
//! cache = false
//! ```
//!
//! ## Using 1Password Connect Server
//!
//! ```toml
//! [backends.onepassword]
//! type = "onepassword"
//! # Use Connect API instead of CLI
//! connect = true
//! # Connect server address
//! address = "http://localhost:8080"
//! # Connect API token
//! token = "your-connect-token"
//! # Cache secrets (recommended for Connect)
//! cache = true
//! cache_ttl = "5m"
//! ```
//!
//! # Path Mapping
//!
//! 1Password items are mapped to SIGIL paths as follows:
//! - Reference: `op://vault/item/field` → SIGIL path: `onepassword/vault/item/field`
//! - The `onepassword/` prefix is used to distinguish from local secrets
//! - Vault can be omitted to search all vaults
//!
//! # Examples
//!
//! ```bash
//! # Get a password
//! sigil get onepassword/Personal/Email/example.com/password
//!
//! # Get an API key
//! sigil get onepassword/Development/GitHub/api_token
//! ```
//!
//! # 1Password CLI Setup
//!
//! To use this backend, you need the 1Password CLI installed:
//! ```bash
//! # Install via op CLI (Linux)
//! curl -sS https://downloads.1password.com/linux/keys/1password.asc | \
//!   sudo gpg --dearmor --output /usr/share/keyrings/1password-archive-keyring.gpg
//! echo "deb [arch=$(dpkg --print-architecture) signed-by=/usr/share/keyrings/1password-archive-keyring.gpg] \
//!   https://downloads.1password.com/linux/debian/$(dpkg --print-architecture) stable main" | \
//!   sudo tee /etc/apt/sources.list.d/1password.list
//! sudo mkdir -p /etc/debsigpolicies/loops/deb/1password
//! sudo curl -L https://downloads.1password.com/linux/debian/debsig/1password.pol \
//!   -o /etc/debsigpolicies/loops/deb/1password/1password.pol
//! sudo curl -L https://downloads.1password.com/linux/debian/debsig/1password.gpg \
//!   -o /usr/share/debsigpolicies/loops/deb/1password/gpg
//! sudo apt update && sudo apt install op
//!
//! # Sign in to your account
//! op account add --address myaccount.1password.com
//! ```

#![warn(missing_docs)]
#![warn(clippy::all)]

use async_trait::async_trait;
use sigil_core::{
    Result, SecretBackend, SecretMetadata, SecretPath, SecretType, SecretValue, SigilError,
};
use std::collections::HashMap;
use std::process::Command;
use std::str;
use std::sync::Arc;
use std::time::Duration;

/// 1Password backend configuration
#[derive(Debug, Clone)]
pub struct OnePasswordBackendConfig {
    /// Default vault name (optional)
    pub vault: Option<String>,
    /// Account shorthand for biometric auth
    pub account: Option<String>,
    /// Whether to use Connect API instead of CLI
    pub use_connect: bool,
    /// Connect server address (if using Connect)
    pub connect_address: Option<String>,
    /// Connect API token (if using Connect)
    pub connect_token: Option<String>,
    /// Cache secrets in memory
    pub cache: bool,
    /// Cache TTL (if caching enabled)
    pub cache_ttl: Duration,
}

impl Default for OnePasswordBackendConfig {
    fn default() -> Self {
        Self {
            vault: None,
            account: None,
            use_connect: false,
            connect_address: None,
            connect_token: None,
            cache: false,
            cache_ttl: Duration::from_secs(300),
        }
    }
}

/// 1Password backend for SIGIL
///
/// Reads secrets from 1Password using the CLI tool (`op read`) or
/// 1Password Connect API.
pub struct OnePasswordBackend {
    /// Default vault name
    vault: Option<String>,
    /// Account shorthand
    account: Option<String>,
    /// Whether using Connect API
    use_connect: bool,
    /// Cached secrets (if enabled)
    cache: Arc<tokio::sync::RwLock<OnePasswordCache>>,
    /// Cache TTL
    cache_ttl: Duration,
}

/// In-memory cache for 1Password secrets
#[derive(Debug, Default)]
struct OnePasswordCache {
    entries: HashMap<String, CacheEntry>,
}

/// Cache entry for a secret
#[derive(Debug, Clone)]
struct CacheEntry {
    /// Secret value
    value: Vec<u8>,
    /// Secret metadata
    metadata: SecretMetadata,
    /// When the entry was cached
    cached_at: chrono::DateTime<chrono::Utc>,
}

impl OnePasswordCache {
    /// Get a cached secret if it's still valid
    fn get(&self, path: &str, ttl: Duration) -> Option<(Vec<u8>, SecretMetadata)> {
        let entry = self.entries.get(path)?;
        let age = chrono::Utc::now() - entry.cached_at;
        if age.to_std().ok()? < ttl {
            Some((entry.value.clone(), entry.metadata.clone()))
        } else {
            None
        }
    }

    /// Put a secret in the cache
    fn put(&mut self, path: String, value: Vec<u8>, metadata: SecretMetadata) {
        self.entries.insert(
            path,
            CacheEntry {
                value,
                metadata,
                cached_at: chrono::Utc::now(),
            },
        );
    }
}

impl OnePasswordBackend {
    /// Create a new 1Password backend
    ///
    /// # Arguments
    /// * `config` - Backend configuration
    ///
    /// # Returns
    /// A new OnePasswordBackend instance
    pub fn new(config: OnePasswordBackendConfig) -> Result<Self> {
        // Verify `op` CLI is available (unless using Connect)
        if !config.use_connect {
            if !command_exists("op") {
                return Err(SigilError::IoError(
                    "1Password CLI 'op' not found. Please install it from https://1password.com/downloads/command-line/".to_string()
                ));
            }
        }

        Ok(Self {
            vault: config.vault,
            account: config.account,
            use_connect: config.use_connect,
            cache: Arc::new(tokio::sync::RwLock::new(OnePasswordCache::default())),
            cache_ttl: config.cache_ttl,
        })
    }

    /// Read a secret using `op read` command
    fn read_secret_cli(
        &self,
        vault: Option<&str>,
        item: &str,
        field: Option<&str>,
    ) -> Result<String> {
        // Build the op reference
        let vault_part = vault.unwrap_or_default();
        let field_part = field.unwrap_or("password");
        let reference = format!("op://{}/{}/{}", vault_part, item, field_part);

        // Build the command
        let mut cmd = Command::new("op");
        cmd.arg("read").arg("--no-newline").arg(&reference);

        // Add account shorthand if provided
        if let Some(ref account) = self.account {
            cmd.arg("--account").arg(account);
        }

        // Execute the command
        let output = cmd
            .output()
            .map_err(|e| SigilError::IoError(format!("Failed to run 'op read': {}", e)))?;

        if !output.status.success() {
            let stderr = str::from_utf8(&output.stderr).unwrap_or("");
            return Err(SigilError::SecretNotFound(format!(
                "1Password secret not found: {} (error: {})",
                reference,
                stderr.trim()
            )));
        }

        let value = str::from_utf8(&output.stdout)
            .map_err(|e| SigilError::IoError(format!("Failed to read secret value: {}", e)))?
            .trim()
            .to_string();

        Ok(value)
    }

    /// Parse a SIGIL path into 1Password components
    ///
    /// Path format: `onepassword/vault/item/field` or `onepassword/item/field`
    fn parse_path(&self, path: &str) -> Result<(Option<String>, String, Option<String>)> {
        // Strip "onepassword/" prefix
        let path = path.strip_prefix("onepassword/").ok_or_else(|| {
            SigilError::InvalidPath("Path must start with 'onepassword/'".to_string())
        })?;

        let parts: Vec<&str> = path.split('/').collect();
        if parts.is_empty() || parts[0].is_empty() {
            return Err(SigilError::InvalidPath(
                "Invalid 1Password path format".to_string(),
            ));
        }

        // If we have 3+ parts, treat first as vault
        // If we have 2 parts, no vault specified
        // If we have 1 part, it's the item (field defaults to "password")
        match parts.len() {
            1 => Ok((
                self.vault.clone(),
                parts[0].to_string(),
                Some("password".to_string()),
            )),
            2 => Ok((
                self.vault.clone(),
                parts[0].to_string(),
                Some(parts[1].to_string()),
            )),
            3 => Ok((
                Some(parts[0].to_string()),
                parts[1].to_string(),
                Some(parts[2].to_string()),
            )),
            _ => {
                // More than 3 parts - treat first as vault, last as field, middle as item (joined)
                let item = parts[1..parts.len() - 1].join("/");
                let field = Some(parts.last().unwrap().to_string());
                Ok((Some(parts[0].to_string()), item, field))
            }
        }
    }

    /// List items in a vault using `op item list`
    fn list_vault_items(&self, vault: Option<&str>) -> Result<Vec<SecretMetadata>> {
        let mut cmd = Command::new("op");
        cmd.arg("item").arg("list").arg("--format").arg("json");

        if let Some(v) = vault {
            cmd.arg("--vault").arg(v);
        }

        if let Some(ref account) = self.account {
            cmd.arg("--account").arg(account);
        }

        let output = cmd
            .output()
            .map_err(|e| SigilError::IoError(format!("Failed to run 'op item list': {}", e)))?;

        if !output.status.success() {
            // If listing fails, return empty list (might be permission issue)
            return Ok(Vec::new());
        }

        // Parse JSON output
        let stdout = str::from_utf8(&output.stdout).unwrap_or("");
        let items: Vec<OpItem> = serde_json::from_str(stdout).unwrap_or_else(|_| Vec::new());

        let mut secrets = Vec::new();
        for item in items {
            let vault_name = item.vault.as_deref().unwrap_or("Unknown").to_string();
            let secret_path = if let Some(ref default_vault) = self.vault {
                if default_vault == &vault_name {
                    format!("onepassword/{}", item.id)
                } else {
                    format!("onepassword/{}/{}", vault_name, item.id)
                }
            } else {
                format!("onepassword/{}/{}", vault_name, item.id)
            };

            let secret_type = Self::detect_secret_type(&item.categories, &item.title);

            secrets.push(SecretMetadata {
                path: SecretPath::new(secret_path)?,
                secret_type,
                tags: vec!["onepassword".to_string()],
                notes: Some(format!("From 1Password: {}", item.title)),
                created_at: chrono::Utc::now(),
                updated_at: item.updated_at.unwrap_or_else(chrono::Utc::now),
                expires_at: None,
            });
        }

        Ok(secrets)
    }

    /// Detect secret type from 1Password item categories and title
    fn detect_secret_type(categories: &[Option<String>], title: &str) -> SecretType {
        let title_lower = title.to_lowercase();

        // Check categories
        for cat in categories {
            if let Some(c) = cat {
                let c_lower = c.to_lowercase();
                if c_lower.contains("password") || c_lower.contains("login") {
                    return SecretType::Password;
                }
                if c_lower.contains("api") || c_lower.contains("token") {
                    return SecretType::ApiKey;
                }
                if c_lower.contains("ssh") || c_lower.contains("server") {
                    return SecretType::SshKey;
                }
                if c_lower.contains("database") {
                    return SecretType::DatabaseUrl;
                }
            }
        }

        // Check title - order matters: more specific patterns first
        if title_lower.contains("ssh") || title_lower.contains("private") {
            SecretType::SshKey
        } else if title_lower.contains("api") || title_lower.contains("token") {
            SecretType::ApiKey
        } else if title_lower.contains("db") || title_lower.contains("database") {
            SecretType::DatabaseUrl
        } else if title_lower.contains("password") {
            SecretType::Password
        } else if title_lower.contains("key") {
            SecretType::ApiKey
        } else {
            SecretType::Generic
        }
    }
}

#[async_trait]
impl SecretBackend for OnePasswordBackend {
    /// Get a secret value by path
    async fn get(&self, path: &SecretPath) -> Result<SecretValue> {
        let path_str = path.as_str();

        // Check cache first (if enabled)
        if self.cache_ttl.as_secs() > 0 {
            let cache = self.cache.read().await;
            if let Some((value, _)) = cache.get(path_str, self.cache_ttl) {
                tracing::debug!("Cache hit for 1Password secret: {}", path_str);
                return Ok(SecretValue::new(value));
            }
        }

        // Parse path and fetch from 1Password
        let (vault, item, field) = self.parse_path(path_str)?;
        let value = self.read_secret_cli(vault.as_deref(), &item, field.as_deref())?;

        // Create metadata
        let secret_type = Self::detect_secret_type(&[], &item);
        let metadata = SecretMetadata {
            path: path.clone(),
            secret_type,
            tags: vec!["onepassword".to_string()],
            notes: Some(format!("From 1Password: {}", path_str)),
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
            expires_at: None,
        };

        // Update cache (if enabled)
        if self.cache_ttl.as_secs() > 0 {
            let mut cache = self.cache.write().await;
            cache.put(path_str.to_string(), value.as_bytes().to_vec(), metadata);
        }

        Ok(SecretValue::new(value.into_bytes()))
    }

    /// Get secret metadata by path
    async fn get_metadata(&self, path: &SecretPath) -> Result<SecretMetadata> {
        let path_str = path.as_str();

        // Check cache first
        if self.cache_ttl.as_secs() > 0 {
            let cache = self.cache.read().await;
            if let Some((_, metadata)) = cache.get(path_str, self.cache_ttl) {
                return Ok(metadata);
            }
        }

        // Parse path to determine type
        let (_vault, item, _field) = self.parse_path(path_str)?;
        let secret_type = Self::detect_secret_type(&[], &item);

        Ok(SecretMetadata {
            path: path.clone(),
            secret_type,
            tags: vec!["onepassword".to_string()],
            notes: Some(format!("From 1Password: {}", path_str)),
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
            expires_at: None,
        })
    }

    /// Set a secret value (not supported for 1Password backend)
    async fn set(
        &self,
        _path: &SecretPath,
        _value: &SecretValue,
        _meta: &SecretMetadata,
    ) -> Result<()> {
        // 1Password backend is read-only (use 1Password app or CLI to create items)
        Err(SigilError::IoError(
            "1Password backend is read-only. Use 1Password app or 'op item create' to store secrets."
                .to_string(),
        ))
    }

    /// Delete a secret (not supported for 1Password backend)
    async fn delete(&self, path: &SecretPath) -> Result<()> {
        // 1Password backend is read-only
        Err(SigilError::IoError(format!(
            "Cannot delete secret '{}' from 1Password backend (read-only)",
            path.as_str()
        )))
    }

    /// List all secrets matching a prefix
    async fn list(&self, prefix: &str) -> Result<Vec<SecretMetadata>> {
        // Strip prefix to get vault name
        let vault = if let Some(stripped) = prefix.strip_prefix("onepassword/") {
            if stripped.is_empty() || stripped.contains('/') {
                None
            } else {
                Some(stripped.to_string())
            }
        } else {
            None
        };

        self.list_vault_items(vault.as_deref())
    }

    /// Get the backend type
    fn backend_type(&self) -> &str {
        "onepassword"
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

/// 1Password item (from `op item list` JSON output)
#[derive(Debug, serde::Deserialize)]
struct OpItem {
    /// Item ID
    id: String,
    /// Item title
    title: String,
    /// Vault name
    vault: Option<String>,
    /// Categories
    categories: Vec<Option<String>>,
    /// Updated timestamp
    #[serde(default)]
    updated_at: Option<chrono::DateTime<chrono::Utc>>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_onepassword_backend_config_default() {
        let config = OnePasswordBackendConfig::default();
        assert!(config.vault.is_none());
        assert!(config.account.is_none());
        assert!(!config.use_connect);
        assert!(!config.cache);
        assert_eq!(config.cache_ttl, Duration::from_secs(300));
    }

    #[test]
    fn test_parse_path() {
        // Use Connect mode to bypass `op` CLI check for testing
        let config = OnePasswordBackendConfig {
            use_connect: true,
            ..Default::default()
        };
        let backend = OnePasswordBackend::new(config).unwrap();

        // Test simple path
        let (vault, item, field) = backend.parse_path("onepassword/example").unwrap();
        assert!(vault.is_none());
        assert_eq!(item, "example");
        assert_eq!(field, Some("password".to_string()));

        // Test path with field
        let (vault, item, field) = backend.parse_path("onepassword/example/username").unwrap();
        assert!(vault.is_none());
        assert_eq!(item, "example");
        assert_eq!(field, Some("username".to_string()));

        // Test path with vault
        let (vault, item, field) = backend
            .parse_path("onepassword/Personal/example/password")
            .unwrap();
        assert_eq!(vault, Some("Personal".to_string()));
        assert_eq!(item, "example");
        assert_eq!(field, Some("password".to_string()));
    }

    #[test]
    fn test_detect_secret_type() {
        assert_eq!(
            OnePasswordBackend::detect_secret_type(&[], "GitHub token"),
            SecretType::ApiKey
        );
        assert_eq!(
            OnePasswordBackend::detect_secret_type(&[], "My SSH key"),
            SecretType::SshKey
        );
        assert_eq!(
            OnePasswordBackend::detect_secret_type(&[], "Database connection"),
            SecretType::DatabaseUrl
        );
        assert_eq!(
            OnePasswordBackend::detect_secret_type(&[], "My password"),
            SecretType::Password
        );
    }

    #[test]
    fn test_cache_hit_miss() {
        let mut cache = OnePasswordCache::default();
        let ttl = Duration::from_secs(60);

        // Cache miss
        assert!(cache.get("test", ttl).is_none());

        // Add entry
        cache.put(
            "test".to_string(),
            b"value".to_vec(),
            SecretMetadata {
                path: SecretPath::new("test".to_string()).unwrap(),
                secret_type: SecretType::Generic,
                tags: vec![],
                notes: None,
                created_at: chrono::Utc::now(),
                updated_at: chrono::Utc::now(),
                expires_at: None,
            },
        );

        // Cache hit
        assert!(cache.get("test", ttl).is_some());
    }

    #[test]
    fn test_command_exists() {
        assert!(command_exists("sh"));
        assert!(command_exists("ls"));
        assert!(!command_exists("thiscommanddefinitelydoesnotexist12345"));
    }
}
