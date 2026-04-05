//! Core types for SIGIL

use crate::{error::Result, SigilError};
use chrono::{DateTime, Utc};
use std::sync::Arc;
use zeroize::Zeroizing;

/// A secret path (e.g., "kalshi/api_key")
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct SecretPath(String);

impl SecretPath {
    /// Create a new secret path from a string
    pub fn new(path: impl Into<String>) -> Result<Self> {
        let path = path.into();
        // Validate path format
        if path.is_empty() {
            return Err(SigilError::InvalidPath("path cannot be empty".into()));
        }
        // Path must not contain ".." to prevent directory traversal
        if path.contains("..") {
            return Err(SigilError::InvalidPath("path cannot contain '..'".into()));
        }
        // Path must not start with "/"
        if path.starts_with('/') {
            return Err(SigilError::InvalidPath("path cannot start with '/'".into()));
        }
        Ok(SecretPath(path))
    }

    /// Get the path as a string slice
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Get the parent namespace (e.g., "kalshi/api_key" -> "kalshi")
    pub fn namespace(&self) -> Option<&str> {
        self.0.split('/').next()
    }

    /// Get the secret name (e.g., "kalshi/api_key" -> "api_key")
    pub fn name(&self) -> &str {
        self.0.split('/').next_back().unwrap_or(&self.0)
    }
}

impl std::fmt::Display for SecretPath {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl AsRef<str> for SecretPath {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

/// A secret value that zeroizes on drop
#[derive(Clone)]
pub struct SecretValue(Arc<Zeroizing<Vec<u8>>>);

impl SecretValue {
    /// Create a new secret value from bytes
    pub fn new(data: Vec<u8>) -> Self {
        Self(Arc::new(Zeroizing::new(data)))
    }

    /// Create a new secret value from a string
    pub fn from_string(s: String) -> Self {
        Self(Arc::new(Zeroizing::new(s.into_bytes())))
    }

    /// Get the length of the secret value
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Check if the secret value is empty
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Expose the secret value within a closure
    ///
    /// # Safety
    /// The closure receives the raw bytes of the secret and must handle them carefully.
    pub fn expose<F, R>(&self, f: F) -> R
    where
        F: FnOnce(&[u8]) -> R,
    {
        f(&self.0)
    }
}

impl std::fmt::Debug for SecretValue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SecretValue")
            .field("len", &self.0.len())
            .field("value", &"<redacted>")
            .finish()
    }
}

/// The type of secret
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SecretType {
    /// API key or token
    ApiKey,
    /// X.509 certificate
    Certificate,
    /// SSH private key
    SshKey,
    /// JSON data
    Json,
    /// Generic secret
    #[default]
    Generic,
    /// Password
    Password,
    /// Database connection string
    DatabaseUrl,
}

/// Metadata about a secret
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct SecretMetadata {
    /// The secret path
    pub path: SecretPath,
    /// The type of secret
    #[serde(default)]
    pub secret_type: SecretType,
    /// Tags associated with the secret
    #[serde(default)]
    pub tags: Vec<String>,
    /// Notes about the secret
    pub notes: Option<String>,
    /// When the secret was created
    pub created_at: DateTime<Utc>,
    /// When the secret was last updated
    pub updated_at: DateTime<Utc>,
    /// When the secret expires (optional)
    pub expires_at: Option<DateTime<Utc>>,
}

impl SecretMetadata {
    /// Create new secret metadata
    pub fn new(path: SecretPath) -> Self {
        let now = Utc::now();
        Self {
            path,
            secret_type: SecretType::default(),
            tags: Vec::new(),
            notes: None,
            created_at: now,
            updated_at: now,
            expires_at: None,
        }
    }

    /// Check if the secret is expired
    pub fn is_expired(&self) -> bool {
        if let Some(expires_at) = self.expires_at {
            Utc::now() > expires_at
        } else {
            false
        }
    }
}

/// Trait for secret backend implementations
#[async_trait::async_trait]
pub trait SecretBackend: Send + Sync {
    /// Get a secret value by path
    async fn get(&self, path: &SecretPath) -> Result<SecretValue>;

    /// Get secret metadata by path
    async fn get_metadata(&self, path: &SecretPath) -> Result<SecretMetadata>;

    /// Set a secret value by path
    async fn set(
        &self,
        path: &SecretPath,
        value: &SecretValue,
        meta: &SecretMetadata,
    ) -> Result<()>;

    /// Delete a secret by path
    async fn delete(&self, path: &SecretPath) -> Result<()>;

    /// List all secrets matching a prefix
    async fn list(&self, prefix: &str) -> Result<Vec<SecretMetadata>>;

    /// Get the backend type identifier
    fn backend_type(&self) -> &str;
}

// Implement SecretPath serialization/deserialization
impl serde::Serialize for SecretPath {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&self.0)
    }
}

impl<'de> serde::Deserialize<'de> for SecretPath {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        SecretPath::new(s).map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_secret_path_valid() {
        assert!(SecretPath::new("kalshi/api_key").is_ok());
        assert!(SecretPath::new("single").is_ok());
        assert!(SecretPath::new("deep/nested/path").is_ok());
    }

    #[test]
    fn test_secret_path_invalid() {
        assert!(SecretPath::new("").is_err());
        assert!(SecretPath::new("/absolute").is_err());
        assert!(SecretPath::new("../escape").is_err());
        assert!(SecretPath::new("path/../../escape").is_err());
    }

    #[test]
    fn test_secret_path_parts() {
        let path = SecretPath::new("kalshi/api_key").unwrap();
        assert_eq!(path.namespace(), Some("kalshi"));
        assert_eq!(path.name(), "api_key");
    }

    #[test]
    fn test_secret_value() {
        let value = SecretValue::from_string("my-secret".to_string());
        assert_eq!(value.len(), 9);
        assert!(!value.is_empty());

        let exposed = value.expose(|bytes| String::from_utf8(bytes.to_vec()).unwrap());
        assert_eq!(exposed, "my-secret");
    }

    #[test]
    fn test_secret_metadata_expiry() {
        let mut meta = SecretMetadata::new(SecretPath::new("test/secret").unwrap());
        assert!(!meta.is_expired());

        meta.expires_at = Some(Utc::now() - chrono::Duration::hours(1));
        assert!(meta.is_expired());
    }
}
