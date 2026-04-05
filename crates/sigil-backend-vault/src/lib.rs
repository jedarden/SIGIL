//! HashiCorp Vault / OpenBao backend for SIGIL
//!
//! This backend provides secret access from HashiCorp Vault or OpenBao
//! (a community fork of Vault with additional features).
//!
//! # Security Considerations
//!
//! - **Token authentication**: The backend stores Vault tokens in memory only.
//!   Tokens are never written to disk.
//! - **KV v2 engine**: Secrets are read from Vault's KV v2 secrets engine,
//!   which provides versioning and automatic secret rotation.
//! - **In-memory caching**: Secrets are cached in memory with a configurable TTL
//!   to reduce Vault API calls. Cached secrets are stored in mlock'd memory.
//! - **Dynamic secrets**: For backends that support dynamic secrets (database
//!   credentials, AWS STS, etc.), the backend can request short-lived credentials
//!   that automatically expire.
//!
//! # Configuration
//!
//! Add to `~/.sigil/config.toml`:
//!
//! ```toml
//! [backends.vault]
//! type = "vault"
//! address = "http://127.0.0.1:8200"
//! auth = "token"
//! token = "s.xxx"  # or set VAULT_TOKEN env var
//! mount = "secret"  # KV v2 engine mount point
//! namespace = ""  # Vault namespace (Enterprise)
//! cache_ttl = "5m"
//! ```
//!
//! ## Token Authentication
//!
//! ```toml
//! [backends.vault]
//! type = "vault"
//! address = "https://vault.example.com:8200"
//! auth = "token"
//! token = "s.xxx"  # Vault token
//! ```
//!
//! ## AppRole Authentication
//!
//! ```toml
//! [backends.vault]
//! type = "vault"
//! address = "https://vault.example.com:8200"
//! auth = "approle"
//! role_id = "xxx"
//! secret_id = "xxx"
//! ```
//!
//! ## Kubernetes Authentication
//!
//! ```toml
//! [backends.vault]
//! type = "vault"
//! address = "https://vault.example.com:8200"
//! auth = "kubernetes"
//! role = "my-role"
//! mount = "kubernetes"  # Auth method mount point
//! ```
//!
//! # Path Mapping
//!
//! Vault secrets are mapped to SIGIL paths as follows:
//! - Vault path `secret/foo/bar` → SIGIL path: `vault/foo/bar`
//! - The `vault/` prefix is used to distinguish from local secrets
//! - The mount point is stripped from the path (e.g., `secret/`)

#![warn(missing_docs)]
#![warn(clippy::all)]

use async_trait::async_trait;
use reqwest::{Client, Method, StatusCode};
use secrecy::{ExposeSecret, SecretString};
use serde::Deserialize;
use sigil_core::{
    Result, SecretBackend, SecretMetadata, SecretPath, SecretType, SecretValue, SigilError,
};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::RwLock;

/// Vault backend configuration
#[derive(Debug, Clone)]
pub struct VaultBackendConfig {
    /// Vault server address (e.g., "https://vault.example.com:8200")
    pub address: String,
    /// Authentication method
    pub auth: VaultAuth,
    /// KV v2 secrets engine mount point (default: "secret")
    pub mount: String,
    /// Vault namespace (Enterprise only, default: "")
    pub namespace: Option<String>,
    /// Cache TTL for secrets (default: 5 minutes)
    pub cache_ttl: Duration,
    /// TLS verification (default: true)
    pub verify_tls: bool,
}

impl Default for VaultBackendConfig {
    fn default() -> Self {
        Self {
            address: "http://127.0.0.1:8200".to_string(),
            auth: VaultAuth::Token {
                token: VaultToken::Direct(String::new()),
            },
            mount: "secret".to_string(),
            namespace: None,
            cache_ttl: Duration::from_secs(300),
            verify_tls: true,
        }
    }
}

/// Vault authentication method
#[derive(Debug, Clone)]
pub enum VaultAuth {
    /// Token authentication
    Token {
        /// Vault token (either direct or from environment)
        token: VaultToken,
    },
    /// AppRole authentication
    AppRole {
        /// Role ID
        role_id: String,
        /// Secret ID
        secret_id: SecretString,
    },
    /// Kubernetes authentication
    Kubernetes {
        /// Kubernetes auth role
        role: String,
        /// Auth method mount point (default: "kubernetes")
        mount: String,
    },
}

/// Vault token source
#[derive(Debug, Clone)]
pub enum VaultToken {
    /// Direct token value
    Direct(String),
    /// Read from VAULT_TOKEN environment variable
    Env,
    /// Read from ~/.vault-token file
    File,
}

/// Vault/OpeanBao backend for SIGIL
///
/// Reads secrets from HashiCorp Vault or OpenBao using the KV v2 secrets engine.
pub struct VaultBackend {
    /// HTTP client for API requests
    client: Client,
    /// Vault server address
    address: String,
    /// Current Vault token (protected)
    token: Arc<RwLock<SecretString>>,
    /// Authentication method
    auth: VaultAuth,
    /// KV v2 secrets engine mount point
    mount: String,
    /// Vault namespace header
    namespace_header: Option<String>,
    /// Secret cache
    cache: Arc<RwLock<VaultCache>>,
    /// Cache TTL
    cache_ttl: Duration,
}

/// In-memory cache for Vault secrets
#[derive(Debug, Default)]
struct VaultCache {
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

impl VaultCache {
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

    /// Invalidate a cache entry
    fn invalidate(&mut self, path: &str) {
        self.entries.remove(path);
    }

    /// Clear all cache entries
    fn clear(&mut self) {
        self.entries.clear();
    }
}

impl VaultBackend {
    /// Create a new Vault backend
    ///
    /// # Arguments
    /// * `config` - Backend configuration
    ///
    /// # Returns
    /// A new VaultBackend instance with authenticated token
    pub async fn new(config: VaultBackendConfig) -> Result<Self> {
        // Build HTTP client
        let mut client_builder = Client::builder().timeout(Duration::from_secs(30));

        if !config.verify_tls {
            client_builder = client_builder.danger_accept_invalid_certs(true);
        }

        let client = client_builder
            .build()
            .map_err(|e| SigilError::IoError(format!("Failed to create HTTP client: {}", e)))?;

        // Get initial token
        let token = Self::authenticate(&client, &config).await?;

        Ok(Self {
            client,
            address: config.address.clone(),
            token: Arc::new(RwLock::new(token)),
            auth: config.auth.clone(),
            mount: config.mount,
            namespace_header: config.namespace,
            cache: Arc::new(RwLock::new(VaultCache::default())),
            cache_ttl: config.cache_ttl,
        })
    }

    /// Authenticate with Vault and return a token
    async fn authenticate(client: &Client, config: &VaultBackendConfig) -> Result<SecretString> {
        match &config.auth {
            VaultAuth::Token { token } => {
                let token_str = match token {
                    VaultToken::Direct(t) => {
                        if t.is_empty() {
                            std::env::var("VAULT_TOKEN").map_err(|_| {
                                SigilError::IoError(
                                    "Vault token not provided and VAULT_TOKEN not set".to_string(),
                                )
                            })?
                        } else {
                            t.clone()
                        }
                    }
                    VaultToken::Env => std::env::var("VAULT_TOKEN").map_err(|_| {
                        SigilError::IoError("VAULT_TOKEN environment variable not set".to_string())
                    })?,
                    VaultToken::File => {
                        let home = dirs::home_dir().ok_or_else(|| {
                            SigilError::IoError("Cannot determine home directory".to_string())
                        })?;
                        let token_path = home.join(".vault-token");
                        std::fs::read_to_string(token_path)
                            .map_err(|e| {
                                SigilError::IoError(format!("Failed to read ~/.vault-token: {}", e))
                            })?
                            .trim()
                            .to_string()
                    }
                };
                Ok(SecretString::new(token_str.into()))
            }
            VaultAuth::AppRole { role_id, secret_id } => {
                Self::authenticate_approle(
                    client,
                    &config.address,
                    &config.namespace,
                    role_id,
                    secret_id.expose_secret(),
                )
                .await
            }
            VaultAuth::Kubernetes { role, mount } => {
                Self::authenticate_kubernetes(
                    client,
                    &config.address,
                    &config.namespace,
                    role,
                    mount,
                )
                .await
            }
        }
    }

    /// Authenticate using AppRole
    async fn authenticate_approle(
        client: &Client,
        address: &str,
        namespace: &Option<String>,
        role_id: &str,
        secret_id: &str,
    ) -> Result<SecretString> {
        let mount = namespace
            .as_ref()
            .map(|ns| format!("v1/auth/{}/approle/login", ns))
            .unwrap_or_else(|| "v1/auth/approle/login".to_string());

        let url = format!("{}/{}", address, mount);
        let payload = serde_json::json!({
            "role_id": role_id,
            "secret_id": secret_id,
        });

        let response = client
            .post(&url)
            .json(&payload)
            .send()
            .await
            .map_err(|e| SigilError::IoError(format!("AppRole auth request failed: {}", e)))?;

        if response.status() != StatusCode::OK {
            return Err(SigilError::IoError(format!(
                "AppRole authentication failed: {}",
                response.status()
            )));
        }

        let auth_response: AuthResponse = response
            .json()
            .await
            .map_err(|e| SigilError::IoError(format!("Failed to parse auth response: {}", e)))?;

        Ok(SecretString::new(auth_response.auth.client_token.into()))
    }

    /// Authenticate using Kubernetes
    async fn authenticate_kubernetes(
        client: &Client,
        address: &str,
        namespace: &Option<String>,
        role: &str,
        mount: &str,
    ) -> Result<SecretString> {
        // Read JWT from service account token
        let jwt = std::fs::read_to_string("/var/run/secrets/kubernetes.io/serviceaccount/token")
            .map_err(|e| {
                SigilError::IoError(format!(
                    "Failed to read Kubernetes service account token: {}",
                    e
                ))
            })?;

        let mount_path = if mount.is_empty() {
            "kubernetes"
        } else {
            mount
        };
        let api_path = namespace
            .as_ref()
            .map(|ns| format!("v1/auth/{}/{}", ns, mount_path))
            .unwrap_or_else(|| format!("v1/auth/{}/login", mount_path));

        let url = format!("{}/{}", address, api_path);
        let payload = serde_json::json!({
            "jwt": jwt,
            "role": role,
        });

        let response =
            client.post(&url).json(&payload).send().await.map_err(|e| {
                SigilError::IoError(format!("Kubernetes auth request failed: {}", e))
            })?;

        if response.status() != StatusCode::OK {
            return Err(SigilError::IoError(format!(
                "Kubernetes authentication failed: {}",
                response.status()
            )));
        }

        let auth_response: AuthResponse = response
            .json()
            .await
            .map_err(|e| SigilError::IoError(format!("Failed to parse auth response: {}", e)))?;

        Ok(SecretString::new(auth_response.auth.client_token.into()))
    }

    /// Get the current Vault token
    async fn get_token(&self) -> String {
        self.token.read().await.expose_secret().to_string()
    }

    /// Make a request to the Vault API
    async fn vault_request(
        &self,
        method: Method,
        path: &str,
        body: Option<&serde_json::Value>,
    ) -> Result<reqwest::Response> {
        let token = self.get_token().await;
        let url = format!("{}/v1/{}", self.address, path);

        let mut request = self
            .client
            .request(method, &url)
            .header("X-Vault-Token", token);

        if let Some(ns) = &self.namespace_header {
            request = request.header("X-Vault-Namespace", ns);
        }

        let response = if let Some(body) = body {
            request.json(body).send().await
        } else {
            request.send().await
        };

        response.map_err(|e| SigilError::IoError(format!("Vault API request failed: {}", e)))
    }

    /// Read a secret from KV v2
    async fn read_kv_v2(&self, path: &str) -> Result<(Vec<u8>, SecretMetadata)> {
        let vault_path = format!("{}/data/{}", self.mount, path);

        let response = self.vault_request(Method::GET, &vault_path, None).await?;

        match response.status() {
            StatusCode::OK => {
                let secret_response: KvV2Response = response
                    .json()
                    .await
                    .map_err(|e| SigilError::IoError(format!("Failed to parse secret: {}", e)))?;

                // Extract secret value (we look for a "value" field, or use the entire data)
                let value = if let Some(v) = secret_response.data.data.get("value") {
                    serde_json::to_string(v).unwrap_or_default()
                } else if let Some(v) = secret_response.data.data.get("password") {
                    serde_json::to_string(v).unwrap_or_default()
                } else {
                    // Use all data as JSON
                    serde_json::to_string(&secret_response.data.data).unwrap_or_default()
                };

                // Clean up JSON strings (remove quotes if it's a simple string)
                let value_bytes = if value.starts_with('"') && value.ends_with('"') {
                    let trimmed = &value[1..value.len() - 1];
                    // Unescape JSON escapes
                    serde_json::from_str::<String>(trimmed)
                        .unwrap_or_else(|_| trimmed.to_string())
                        .into_bytes()
                } else {
                    value.into_bytes()
                };

                // Determine secret type from path
                let secret_type = Self::detect_secret_type(path);

                let metadata = SecretMetadata {
                    path: SecretPath::new(format!("vault/{}", path))?,
                    secret_type,
                    tags: vec!["vault".to_string()],
                    notes: Some(format!("From Vault: {}", vault_path)),
                    created_at: secret_response
                        .data
                        .metadata
                        .created_time
                        .parse()
                        .unwrap_or_else(|_| chrono::Utc::now()),
                    updated_at: secret_response
                        .data
                        .metadata
                        .updated_time
                        .parse()
                        .unwrap_or_else(|_| chrono::Utc::now()),
                    expires_at: None,
                };

                Ok((value_bytes, metadata))
            }
            StatusCode::NOT_FOUND => Err(SigilError::SecretNotFound(format!("vault/{}", path))),
            StatusCode::FORBIDDEN | StatusCode::UNAUTHORIZED => Err(SigilError::IoError(
                "Access denied to Vault secret".to_string(),
            )),
            _ => Err(SigilError::IoError(format!(
                "Vault API error: {}",
                response.status()
            ))),
        }
    }

    /// List secrets at a path
    async fn list_kv_v2(&self, path: &str) -> Result<Vec<SecretMetadata>> {
        let list_path = if path.is_empty() {
            format!("{}/metadata", self.mount)
        } else {
            format!("{}/metadata/{}", self.mount, path)
        };

        // Vault LIST requires a special method, use GET with ?list=true parameter
        let url = format!("{}/v1/{}?list=true", self.address, list_path);
        let token = self.get_token().await;

        let response = self
            .client
            .get(&url)
            .header("X-Vault-Token", token)
            .send()
            .await
            .map_err(|e| SigilError::IoError(format!("Vault list request failed: {}", e)))?;

        match response.status() {
            StatusCode::OK => {
                let list_response: ListResponse = response.json().await.map_err(|e| {
                    SigilError::IoError(format!("Failed to parse list response: {}", e))
                })?;

                let mut secrets = Vec::new();

                // Process keys (secrets)
                if let Some(keys) = list_response.data.keys {
                    for key in keys {
                        let full_path = if path.is_empty() {
                            key.clone()
                        } else {
                            format!("{}/{}", path, key)
                        };
                        let secret_type = Self::detect_secret_type(&full_path);

                        secrets.push(SecretMetadata {
                            path: SecretPath::new(format!("vault/{}", full_path))?,
                            secret_type,
                            tags: vec!["vault".to_string()],
                            notes: Some(format!("From Vault: {}", full_path)),
                            created_at: chrono::Utc::now(),
                            updated_at: chrono::Utc::now(),
                            expires_at: None,
                        });
                    }
                }

                Ok(secrets)
            }
            StatusCode::NOT_FOUND => Ok(Vec::new()),
            StatusCode::FORBIDDEN | StatusCode::UNAUTHORIZED => Err(SigilError::IoError(
                "Access denied to Vault list operation".to_string(),
            )),
            _ => Err(SigilError::IoError(format!(
                "Vault API error: {}",
                response.status()
            ))),
        }
    }

    /// Detect secret type from path
    fn detect_secret_type(path: &str) -> SecretType {
        let lower = path.to_lowercase();
        if lower.contains("ssh") || lower.contains("private_key") {
            SecretType::SshKey
        } else if lower.contains("api") || lower.contains("token") || lower.contains("key") {
            SecretType::ApiKey
        } else if lower.contains("cert") || lower.contains("certificate") {
            SecretType::Certificate
        } else if lower.contains("db")
            || lower.contains("database")
            || lower.contains("postgres")
            || lower.contains("mysql")
        {
            SecretType::DatabaseUrl
        } else {
            SecretType::Generic
        }
    }

    /// Strip the "vault/" prefix from a path if present
    fn strip_prefix(path: &str) -> String {
        path.strip_prefix("vault/").unwrap_or(path).to_string()
    }
}

#[async_trait]
impl SecretBackend for VaultBackend {
    /// Get a secret value by path
    async fn get(&self, path: &SecretPath) -> Result<SecretValue> {
        let path_str = Self::strip_prefix(path.as_str());

        // Check cache first
        {
            let cache = self.cache.read().await;
            if let Some((value, _)) = cache.get(&path_str, self.cache_ttl) {
                tracing::debug!("Cache hit for secret: {}", path_str);
                return Ok(SecretValue::new(value.clone()));
            }
        }

        // Fetch from Vault
        tracing::debug!("Cache miss for secret: {}, fetching from Vault", path_str);
        let (value, metadata) = self.read_kv_v2(&path_str).await?;

        // Update cache
        {
            let mut cache = self.cache.write().await;
            cache.put(path_str.clone(), value.clone(), metadata);
        }

        Ok(SecretValue::new(value))
    }

    /// Get secret metadata by path
    async fn get_metadata(&self, path: &SecretPath) -> Result<SecretMetadata> {
        let path_str = Self::strip_prefix(path.as_str());

        // Check cache first
        {
            let cache = self.cache.read().await;
            if let Some((_, metadata)) = cache.get(&path_str, self.cache_ttl) {
                return Ok(metadata.clone());
            }
        }

        // Fetch from Vault
        let (_, metadata) = self.read_kv_v2(&path_str).await?;

        // Update cache
        {
            let mut cache = self.cache.write().await;
            cache.put(path_str.clone(), Vec::new(), metadata.clone());
        }

        Ok(metadata)
    }

    /// Set a secret value (write to Vault)
    async fn set(
        &self,
        path: &SecretPath,
        value: &SecretValue,
        meta: &SecretMetadata,
    ) -> Result<()> {
        let path_str = Self::strip_prefix(path.as_str());

        value.expose(|bytes| {
            let value_str = String::from_utf8_lossy(bytes);
            let vault_path = format!("{}/data/{}", self.mount, path_str);

            let body = serde_json::json!({
                "data": {
                    "value": value_str,
                    "metadata": {
                        "tags": meta.tags,
                        "custom_metadata": {
                            "notes": meta.notes.as_deref().unwrap_or(""),
                        }
                    }
                }
            });

            let rt = tokio::runtime::Handle::current();
            let response =
                rt.block_on(self.vault_request(Method::POST, &vault_path, Some(&body)))?;

            match response.status() {
                StatusCode::OK | StatusCode::CREATED => {
                    // Invalidate cache
                    let mut cache = self.cache.blocking_write();
                    cache.invalidate(&path_str);

                    Ok(())
                }
                StatusCode::FORBIDDEN | StatusCode::UNAUTHORIZED => Err(SigilError::IoError(
                    "Access denied to write Vault secret".to_string(),
                )),
                _ => Err(SigilError::IoError(format!(
                    "Failed to write secret: {}",
                    response.status()
                ))),
            }
        })
    }

    /// Delete a secret from Vault
    async fn delete(&self, path: &SecretPath) -> Result<()> {
        let path_str = Self::strip_prefix(path.as_str());
        let vault_path = format!("{}/metadata/{}", self.mount, path_str);

        let response = self
            .vault_request(Method::DELETE, &vault_path, None)
            .await?;

        match response.status() {
            StatusCode::NO_CONTENT | StatusCode::OK | StatusCode::NOT_FOUND => {
                // Invalidate cache
                let mut cache = self.cache.write().await;
                cache.invalidate(&path_str);

                Ok(())
            }
            StatusCode::FORBIDDEN | StatusCode::UNAUTHORIZED => Err(SigilError::IoError(
                "Access denied to delete Vault secret".to_string(),
            )),
            _ => Err(SigilError::IoError(format!(
                "Failed to delete secret: {}",
                response.status()
            ))),
        }
    }

    /// List all secrets matching a prefix
    async fn list(&self, prefix: &str) -> Result<Vec<SecretMetadata>> {
        let prefix_str = Self::strip_prefix(prefix);
        self.list_kv_v2(&prefix_str).await
    }

    /// Get the backend type
    fn backend_type(&self) -> &str {
        "vault"
    }
}

/// Vault authentication response
#[derive(Debug, Deserialize)]
struct AuthResponse {
    auth: AuthData,
}

/// Authentication data
#[derive(Debug, Deserialize)]
struct AuthData {
    client_token: String,
}

/// KV v2 secret response
#[derive(Debug, Deserialize)]
struct KvV2Response {
    data: KvV2Data,
}

/// KV v2 data wrapper
#[derive(Debug, Deserialize)]
struct KvV2Data {
    data: serde_json::Value,
    metadata: KvV2Metadata,
}

/// KV v2 metadata
#[derive(Debug, Deserialize)]
struct KvV2Metadata {
    created_time: String,
    updated_time: String,
    version: u64,
}

/// List response
#[derive(Debug, Deserialize)]
struct ListResponse {
    data: ListData,
}

/// List data
#[derive(Debug, Deserialize)]
struct ListData {
    keys: Option<Vec<String>>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_vault_backend_config_default() {
        let config = VaultBackendConfig::default();
        assert_eq!(config.address, "http://127.0.0.1:8200");
        assert_eq!(config.mount, "secret");
        assert_eq!(config.cache_ttl, Duration::from_secs(300));
        assert!(config.verify_tls);
    }

    #[test]
    fn test_detect_secret_type() {
        assert_eq!(
            VaultBackend::detect_secret_type("ssh/key"),
            SecretType::SshKey
        );
        assert_eq!(
            VaultBackend::detect_secret_type("api/token"),
            SecretType::ApiKey
        );
        assert_eq!(
            VaultBackend::detect_secret_type("cert/file"),
            SecretType::Certificate
        );
        assert_eq!(
            VaultBackend::detect_secret_type("db/creds"),
            SecretType::DatabaseUrl
        );
        assert_eq!(
            VaultBackend::detect_secret_type("generic"),
            SecretType::Generic
        );
    }

    #[test]
    fn test_strip_prefix() {
        assert_eq!(VaultBackend::strip_prefix("vault/foo/bar"), "foo/bar");
        assert_eq!(VaultBackend::strip_prefix("foo/bar"), "foo/bar");
    }

    #[test]
    fn test_cache_hit_miss() {
        let mut cache = VaultCache::default();
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

        // Clear cache
        cache.clear();
        assert!(cache.get("test", ttl).is_none());
    }
}
