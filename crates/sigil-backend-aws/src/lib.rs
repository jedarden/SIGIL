//! AWS Secrets Manager backend for SIGIL
//!
//! This backend provides secret access from AWS Secrets Manager, supporting
//! both standard secrets and automatic rotation via AWS Lambda.
//!
//! # Security Considerations
//!
//! - **AWS authentication**: The backend uses AWS SDK's default credential
//!   chain (environment variables, ~/.aws/credentials, IAM role, etc.)
//! - **Encryption**: Secrets are encrypted at rest in AWS Secrets Manager
//!   and decrypted only in memory.
//! - **In-memory caching**: Secrets are cached in memory with a configurable
//!   TTL to reduce AWS API calls and costs.
//! - **Automatic rotation**: Supports secrets that are automatically rotated
//!   by AWS Lambda, ensuring fresh credentials.
//!
//! # Configuration
//!
//! Add to `~/.sigil/config.toml`:
//!
//! ```toml
//! [backends.aws]
//! type = "aws"
//! # AWS region (optional, uses default from AWS SDK)
//! region = "us-east-1"
//! # Cache secrets in memory (recommended)
//! cache = true
//! cache_ttl = "5m"
//! # Prefix for secret names (optional)
//! prefix = "prod"
//! ```
//!
//! # AWS Credentials
//!
//! The backend uses the AWS SDK's default credential chain:
//! 1. Environment variables: `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, `AWS_SESSION_TOKEN`
//! 2. AWS credential file: `~/.aws/credentials` and `~/.aws/config`
//! 3. IAM role from EC2 instance profile or ECS task role
//! 4. IAM role from EKS pod identity (IRSA)
//!
//! # Path Mapping
//!
//! AWS Secrets Manager secrets are mapped to SIGIL paths as follows:
//! - Secret name: `myapp/db` → SIGIL path: `aws/myapp/db`
//! - The `aws/` prefix is used to distinguish from local secrets
//!
//! # Examples
//!
//! ```bash
//! # Get a database password
//! sigil get aws/prod/db/password
//!
//! # Get an API key
//! sigil get aws/prod/api/key
//! ```

#![warn(missing_docs)]
#![warn(clippy::all)]

use async_trait::async_trait;
use aws_config::BehaviorVersion;
use aws_sdk_secretsmanager::Client as SecretsClient;
use sigil_core::{
    Result, SecretBackend, SecretMetadata, SecretPath, SecretType, SecretValue, SigilError,
};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::RwLock;

/// AWS Secrets Manager backend configuration
#[derive(Debug, Clone)]
pub struct AwsBackendConfig {
    /// AWS region (optional, uses default from AWS SDK)
    pub region: Option<String>,
    /// Cache secrets in memory
    pub cache: bool,
    /// Cache TTL (if caching enabled)
    pub cache_ttl: Duration,
    /// Prefix for secret names (optional)
    pub prefix: Option<String>,
}

impl Default for AwsBackendConfig {
    fn default() -> Self {
        Self {
            region: None,
            cache: true,
            cache_ttl: Duration::from_secs(300),
            prefix: None,
        }
    }
}

/// AWS Secrets Manager backend for SIGIL
///
/// Reads secrets from AWS Secrets Manager with support for automatic
/// rotation and in-memory caching.
pub struct AwsBackend {
    /// AWS Secrets Manager client
    client: Arc<SecretsClient>,
    /// AWS region
    region: Option<String>,
    /// Cached secrets
    cache: Arc<RwLock<AwsCache>>,
    /// Cache TTL
    cache_ttl: Duration,
    /// Prefix for secret names
    prefix: Option<String>,
}

/// In-memory cache for AWS secrets
#[derive(Debug, Default)]
struct AwsCache {
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
    /// Version ID (for rotation detection)
    version_id: Option<String>,
}

impl AwsCache {
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
    fn put(
        &mut self,
        path: String,
        value: Vec<u8>,
        metadata: SecretMetadata,
        version_id: Option<String>,
    ) {
        self.entries.insert(
            path,
            CacheEntry {
                value,
                metadata,
                cached_at: chrono::Utc::now(),
                version_id,
            },
        );
    }

    /// Invalidate a cache entry
    fn invalidate(&mut self, path: &str) {
        self.entries.remove(path);
    }
}

impl AwsBackend {
    /// Create a new AWS Secrets Manager backend
    ///
    /// # Arguments
    /// * `config` - Backend configuration
    ///
    /// # Returns
    /// A new AwsBackend instance with initialized AWS client
    pub async fn new(config: AwsBackendConfig) -> Result<Self> {
        // Load AWS SDK configuration
        let mut loader = aws_config::defaults(BehaviorVersion::latest());

        if let Some(ref region) = config.region {
            use aws_sdk_secretsmanager::config::Region;
            loader = loader.region(Region::new(region.clone()));
        }

        let sdk_config = loader.load().await;

        // Create Secrets Manager client
        let client = Arc::new(SecretsClient::new(&sdk_config));

        Ok(Self {
            client,
            region: config.region,
            cache: Arc::new(RwLock::new(AwsCache::default())),
            cache_ttl: config.cache_ttl,
            prefix: config.prefix,
        })
    }

    /// Strip the "aws/" prefix from a path if present
    fn strip_prefix(&self, path: &str) -> String {
        let path = path.strip_prefix("aws/").unwrap_or(path).to_string();

        // Add configured prefix if present
        if let Some(ref prefix) = self.prefix {
            if !path.starts_with(prefix) {
                format!("{}/{}", prefix, path)
            } else {
                path
            }
        } else {
            path
        }
    }

    /// Get a secret from AWS Secrets Manager
    async fn get_secret(
        &self,
        secret_name: &str,
    ) -> Result<(Vec<u8>, SecretMetadata, Option<String>)> {
        let response = self
            .client
            .get_secret_value()
            .secret_id(secret_name)
            .send()
            .await
            .map_err(|e| SigilError::IoError(format!("Failed to get secret from AWS: {}", e)))?;

        let secret_bytes = response
            .secret_string()
            .map(|s| s.as_bytes().to_vec())
            .unwrap_or_else(Vec::new);

        // Determine secret type based on name and content
        let secret_type = Self::detect_secret_type(secret_name, &secret_bytes);

        // Parse metadata
        let created_at = response
            .created_date()
            .and_then(|d| {
                // Try to convert AWS SDK DateTime to chrono DateTime
                // AWS SDK DateTime has as_secs_f64 method
                let secs = d.as_secs_f64();
                chrono::DateTime::<chrono::Utc>::from_timestamp(
                    secs as i64,
                    (secs.fract() * 1e9) as u32,
                )
            })
            .unwrap_or_else(chrono::Utc::now);

        let metadata = SecretMetadata {
            path: SecretPath::new(format!("aws/{}", secret_name))?,
            secret_type,
            tags: vec!["aws".to_string()],
            notes: Some(format!("From AWS Secrets Manager: {}", secret_name)),
            created_at,
            updated_at: chrono::Utc::now(),
            expires_at: None,
        };

        let version_id = response.version_id().map(|s| s.to_string());

        Ok((secret_bytes, metadata, version_id))
    }

    /// List secrets in AWS Secrets Manager
    async fn list_secrets(&self, prefix: &str) -> Result<Vec<SecretMetadata>> {
        let mut secrets = Vec::new();
        let mut next_token: Option<String> = None;

        loop {
            let mut builder = self.client.list_secrets();

            if let Some(token) = next_token.take() {
                builder = builder.next_token(token);
            }

            let response = builder
                .send()
                .await
                .map_err(|e| SigilError::IoError(format!("Failed to list secrets: {}", e)))?;

            // Get the secret list - collect into a vector
            let secret_list: Vec<aws_sdk_secretsmanager::types::SecretListEntry> =
                response.secret_list().to_vec();

            for secret in secret_list {
                if let Some(secret_name) = secret.name() {
                    // Skip if prefix doesn't match
                    if !prefix.is_empty() && !secret_name.starts_with(prefix) {
                        continue;
                    }

                    let secret_type = Self::detect_secret_type(secret_name, &[]);

                    // Convert AWS SDK DateTime to chrono DateTime
                    let created_at = secret
                        .created_date()
                        .and_then(|d| {
                            let secs = d.as_secs_f64();
                            chrono::DateTime::<chrono::Utc>::from_timestamp(
                                secs as i64,
                                (secs.fract() * 1e9) as u32,
                            )
                        })
                        .unwrap_or_else(chrono::Utc::now);

                    let updated_at = secret
                        .last_changed_date()
                        .and_then(|d| {
                            let secs = d.as_secs_f64();
                            chrono::DateTime::<chrono::Utc>::from_timestamp(
                                secs as i64,
                                (secs.fract() * 1e9) as u32,
                            )
                        })
                        .unwrap_or_else(chrono::Utc::now);

                    secrets.push(SecretMetadata {
                        path: SecretPath::new(format!("aws/{}", secret_name))?,
                        secret_type,
                        tags: vec!["aws".to_string()],
                        notes: Some(format!("From AWS Secrets Manager: {}", secret_name)),
                        created_at,
                        updated_at,
                        expires_at: None,
                    });
                }
            }

            next_token = response.next_token().map(|s| s.to_string());
            if next_token.is_none() {
                break;
            }
        }

        Ok(secrets)
    }

    /// Detect secret type from name and content
    fn detect_secret_type(name: &str, content: &[u8]) -> SecretType {
        let name_lower = name.to_lowercase();

        if name_lower.contains("db")
            || name_lower.contains("database")
            || name_lower.contains("rds")
            || name_lower.contains("aurora")
        {
            SecretType::DatabaseUrl
        } else if name_lower.contains("api")
            || name_lower.contains("token")
            || name_lower.contains("key")
        {
            SecretType::ApiKey
        } else if name_lower.contains("ssh") || name_lower.contains("private") {
            SecretType::SshKey
        } else if name_lower.contains("cert") || name_lower.contains("certificate") {
            SecretType::Certificate
        } else {
            // Check content
            let content_str = String::from_utf8_lossy(content);
            if content_str.contains("postgres://")
                || content_str.contains("mysql://")
                || content_str.contains("mongodb://")
            {
                SecretType::DatabaseUrl
            } else if content_str.contains("-----BEGIN") {
                SecretType::SshKey
            } else {
                SecretType::Generic
            }
        }
    }
}

#[async_trait]
impl SecretBackend for AwsBackend {
    /// Get a secret value by path
    async fn get(&self, path: &SecretPath) -> Result<SecretValue> {
        let path_str = path.as_str();
        let secret_name = self.strip_prefix(path_str);

        // Check cache first
        if self.cache_ttl.as_secs() > 0 {
            let cache = self.cache.read().await;
            if let Some((value, _)) = cache.get(&secret_name, self.cache_ttl) {
                tracing::debug!("Cache hit for AWS secret: {}", secret_name);
                return Ok(SecretValue::new(value));
            }
        }

        // Fetch from AWS
        tracing::debug!(
            "Cache miss for AWS secret: {}, fetching from AWS",
            secret_name
        );
        let (value, metadata, version_id) = self.get_secret(&secret_name).await?;

        // Update cache
        if self.cache_ttl.as_secs() > 0 {
            let mut cache = self.cache.write().await;
            cache.put(secret_name.clone(), value.clone(), metadata, version_id);
        }

        Ok(SecretValue::new(value))
    }

    /// Get secret metadata by path
    async fn get_metadata(&self, path: &SecretPath) -> Result<SecretMetadata> {
        let path_str = path.as_str();
        let secret_name = self.strip_prefix(path_str);

        // Check cache first
        if self.cache_ttl.as_secs() > 0 {
            let cache = self.cache.read().await;
            if let Some((_, metadata)) = cache.get(&secret_name, self.cache_ttl) {
                return Ok(metadata);
            }
        }

        // Fetch from AWS
        let (_, metadata, _) = self.get_secret(&secret_name).await?;

        Ok(metadata)
    }

    /// Set a secret value (write to AWS Secrets Manager)
    async fn set(
        &self,
        path: &SecretPath,
        value: &SecretValue,
        meta: &SecretMetadata,
    ) -> Result<()> {
        let path_str = path.as_str();
        let secret_name = self.strip_prefix(path_str);

        // Extract the secret string
        let secret_string = value.expose(|bytes| String::from_utf8_lossy(bytes).to_string());

        // Build the create secret request
        let result = self
            .client
            .create_secret()
            .name(&secret_name)
            .secret_string(&secret_string)
            .description(meta.notes.as_deref().unwrap_or("Managed by SIGIL"))
            .send()
            .await;

        match result {
            Ok(_) => {
                // Invalidate cache
                let mut cache = self.cache.write().await;
                cache.invalidate(&secret_name);
                Ok(())
            }
            Err(e) => {
                let error_str = format!("{:?}", e);
                if error_str.contains("ResourceExists")
                    || error_str.contains("ResourceAlreadyExists")
                {
                    // Secret already exists, try to update it
                    self.client
                        .put_secret_value()
                        .secret_id(&secret_name)
                        .secret_string(&secret_string)
                        .send()
                        .await
                        .map_err(|e| {
                            SigilError::IoError(format!("Failed to update secret: {}", e))
                        })?;

                    // Invalidate cache
                    let mut cache = self.cache.write().await;
                    cache.invalidate(&secret_name);
                    Ok(())
                } else {
                    Err(SigilError::IoError(format!(
                        "Failed to create secret: {}",
                        e
                    )))
                }
            }
        }
    }

    /// Delete a secret from AWS Secrets Manager
    async fn delete(&self, path: &SecretPath) -> Result<()> {
        let path_str = path.as_str();
        let secret_name = self.strip_prefix(path_str);

        self.client
            .delete_secret()
            .secret_id(&secret_name)
            .force_delete_without_recovery(true) // Skip recovery window for immediate deletion
            .send()
            .await
            .map_err(|e| SigilError::IoError(format!("Failed to delete secret: {}", e)))?;

        // Invalidate cache
        let mut cache = self.cache.write().await;
        cache.invalidate(&secret_name);

        Ok(())
    }

    /// List all secrets matching a prefix
    async fn list(&self, prefix: &str) -> Result<Vec<SecretMetadata>> {
        let prefix_str = self.strip_prefix(prefix);
        self.list_secrets(&prefix_str).await
    }

    /// Get the backend type
    fn backend_type(&self) -> &str {
        "aws"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_aws_backend_config_default() {
        let config = AwsBackendConfig::default();
        assert!(config.region.is_none());
        assert!(config.cache);
        assert_eq!(config.cache_ttl, Duration::from_secs(300));
        assert!(config.prefix.is_none());
    }

    #[test]
    fn test_detect_secret_type() {
        assert_eq!(
            AwsBackend::detect_secret_type("prod/db", &[]),
            SecretType::DatabaseUrl
        );
        assert_eq!(
            AwsBackend::detect_secret_type("prod/api/key", &[]),
            SecretType::ApiKey
        );
        assert_eq!(
            AwsBackend::detect_secret_type("prod/ssh", &[]),
            SecretType::SshKey
        );
        assert_eq!(
            AwsBackend::detect_secret_type("generic", b"-----BEGIN RSA PRIVATE KEY-----"),
            SecretType::SshKey
        );
        assert_eq!(
            AwsBackend::detect_secret_type("generic", b"postgres://user:pass@host/db"),
            SecretType::DatabaseUrl
        );
    }

    #[test]
    fn test_cache_hit_miss() {
        let mut cache = AwsCache::default();
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
            Some("v1".to_string()),
        );

        // Cache hit
        assert!(cache.get("test", ttl).is_some());

        // Invalidate
        cache.invalidate("test");
        assert!(cache.get("test", ttl).is_none());
    }
}
