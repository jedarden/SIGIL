//! Dynamic secret support for ephemeral per-command credentials
//!
//! This module provides interfaces for requesting and managing dynamic secrets
//! from external backends like Vault, AWS, and Kubernetes. Dynamic secrets are
//! short-lived credentials that are automatically rotated and can be revoked.

use anyhow::{anyhow, Result};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::Duration;

/// Configuration for a dynamic secret
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DynamicSecretConfig {
    /// Secret path (e.g., "database/creds/prod-db")
    pub path: String,

    /// Backend type (vault, aws, kubernetes)
    pub backend_type: String,

    /// TTL for the credential (default: 1 hour)
    #[serde(default = "default_ttl")]
    pub ttl: String,

    /// Whether to track this lease for revocation
    #[serde(default = "default_track_lease")]
    pub track_lease: bool,

    /// Additional backend-specific parameters
    #[serde(flatten)]
    pub params: HashMap<String, serde_json::Value>,
}

fn default_ttl() -> String {
    "1h".to_string()
}

fn default_track_lease() -> bool {
    true
}

impl DynamicSecretConfig {
    /// Parse TTL string into Duration
    pub fn parse_ttl(&self) -> Result<Duration> {
        let s = self.ttl.to_lowercase();
        let num: u64 = s
            .chars()
            .take_while(|c| c.is_ascii_digit())
            .collect::<String>()
            .parse()
            .map_err(|_| anyhow!("Invalid TTL format: {}", self.ttl))?;

        let unit = s
            .chars()
            .skip_while(|c| c.is_ascii_digit())
            .collect::<String>();

        let duration = match unit.as_str() {
            "s" | "sec" | "second" | "seconds" => Duration::from_secs(num),
            "m" | "min" | "minute" | "minutes" => Duration::from_secs(num * 60),
            "h" | "hour" | "hours" => Duration::from_secs(num * 3600),
            "d" | "day" | "days" => Duration::from_secs(num * 86400),
            _ => return Err(anyhow!("Unknown TTL unit: {}", unit)),
        };

        Ok(duration)
    }
}

/// Response from a dynamic secret request
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DynamicSecretResponse {
    /// Lease ID (for revocation)
    pub lease_id: Option<String>,

    /// Lease duration (seconds)
    pub lease_duration: Option<u64>,

    /// Whether the lease is renewable
    pub renewable: Option<bool>,

    /// Secret data (username, password, access_key, etc.)
    pub data: HashMap<String, String>,

    /// Expiration time
    pub expires_at: Option<DateTime<Utc>>,

    /// Backend-specific metadata
    pub metadata: HashMap<String, serde_json::Value>,
}

impl DynamicSecretResponse {
    /// Calculate expiration time from lease duration
    pub fn calculate_expiration(&mut self, duration_secs: u64) {
        self.expires_at = Some(Utc::now() + chrono::Duration::seconds(duration_secs as i64));
        self.lease_duration = Some(duration_secs);
    }

    /// Check if the credential is expired
    pub fn is_expired(&self) -> bool {
        if let Some(expires_at) = self.expires_at {
            Utc::now() > expires_at
        } else {
            false
        }
    }

    /// Get the primary secret value
    ///
    /// Returns the first value in order of preference:
    /// - password
    /// - token
    /// - secret
    /// - access_key
    /// - value
    /// - first available key
    pub fn get_primary_value(&self) -> Option<String> {
        for key in &["password", "token", "secret", "access_key", "value"] {
            if let Some(val) = self.data.get(*key) {
                return Some(val.clone());
            }
        }
        self.data.values().next().cloned()
    }

    /// Get a specific field from the secret data
    pub fn get_field(&self, key: &str) -> Option<String> {
        self.data.get(key).cloned()
    }
}

/// Trait for dynamic secret providers
#[async_trait::async_trait]
pub trait DynamicSecretProvider: Send + Sync {
    /// Request a dynamic secret
    async fn request_dynamic_secret(
        &self,
        config: &DynamicSecretConfig,
    ) -> Result<DynamicSecretResponse>;

    /// Revoke a dynamic secret lease
    async fn revoke_lease(&self, lease_id: &str) -> Result<()>;

    /// Get the provider type
    fn provider_type(&self) -> &str;
}

/// Vault dynamic secret provider
pub struct VaultDynamicProvider {
    /// Vault client (we'll use a simple HTTP client here)
    client: reqwest::Client,
    /// Vault address
    address: String,
    /// Vault token
    token: String,
    /// Vault namespace (optional)
    namespace: Option<String>,
    /// TLS verification (used during client construction only)
    #[allow(dead_code)]
    verify_tls: bool,
}

impl VaultDynamicProvider {
    /// Create a new Vault dynamic provider
    pub fn new(
        address: String,
        token: String,
        namespace: Option<String>,
        verify_tls: bool,
    ) -> Self {
        let mut client_builder = reqwest::Client::builder()
            .timeout(Duration::from_secs(30));

        if !verify_tls {
            client_builder = client_builder.danger_accept_invalid_certs(true);
        }

        let client = client_builder.build().unwrap_or_default();

        Self {
            client,
            address,
            token,
            namespace,
            verify_tls,
        }
    }

    /// Build Vault API URL
    fn build_url(&self, path: &str) -> String {
        format!("{}/v1/{}", self.address, path)
    }
}

#[async_trait::async_trait]
impl DynamicSecretProvider for VaultDynamicProvider {
    async fn request_dynamic_secret(
        &self,
        config: &DynamicSecretConfig,
    ) -> Result<DynamicSecretResponse> {
        let ttl = config.parse_ttl()?;
        let ttl_secs = ttl.as_secs() as i64;

        // Build request body
        let mut body = serde_json::json!({
            "ttl": format!("{}s", ttl_secs),
        });

        // Add any additional parameters
        for (key, value) in &config.params {
            if let Ok(val_str) = serde_json::to_string(value) {
                let val: serde_json::Value = serde_json::from_str(&val_str).unwrap_or(value.clone());
                body[key] = val;
            }
        }

        // Make request to Vault
        let url = self.build_url(&config.path);
        let mut request = self
            .client
            .post(&url)
            .header("X-Vault-Token", &self.token)
            .json(&body);

        if let Some(ns) = &self.namespace {
            request = request.header("X-Vault-Namespace", ns);
        }

        let response = request.send().await?;

        if response.status().is_success() {
            let json: serde_json::Value = response.json().await?;
            let data = &json["data"];

            let mut secret_data = HashMap::new();

            // Extract data fields ( Vault returns them in different structures)
            if let Some(data_obj) = data.as_object() {
                // For database credentials, AWS keys, etc.
                for (key, val) in data_obj {
                    if key != "metadata" && key != "lease_id" && key != "lease_duration" && key != "renewable" {
                        if let Some(s) = val.as_str() {
                            secret_data.insert(key.clone(), s.to_string());
                        } else if let Some(n) = val.as_i64() {
                            secret_data.insert(key.clone(), n.to_string());
                        } else if let Some(b) = val.as_bool() {
                            secret_data.insert(key.clone(), b.to_string());
                        } else {
                            secret_data.insert(key.clone(), val.to_string());
                        }
                    }
                }
            }

            let lease_id = data["lease_id"].as_str().map(|s| s.to_string());
            let lease_duration = data["lease_duration"].as_u64().or(Some(ttl_secs as u64));
            let renewable = data["renewable"].as_bool();

            let mut response = DynamicSecretResponse {
                lease_id,
                lease_duration,
                renewable,
                data: secret_data,
                expires_at: None,
                metadata: HashMap::new(),
            };

            if let Some(duration) = lease_duration {
                response.calculate_expiration(duration);
            }

            Ok(response)
        } else {
            let status = response.status();
            let error_text = response.text().await.unwrap_or_default();
            Err(anyhow!(
                "Vault dynamic secret request failed: {} - {}",
                status,
                error_text
            ))
        }
    }

    async fn revoke_lease(&self, lease_id: &str) -> Result<()> {
        let url = self.build_url(&format!("sys/leases/revoke/{}", lease_id));

        let mut request = self
            .client
            .post(&url)
            .header("X-Vault-Token", &self.token);

        if let Some(ns) = &self.namespace {
            request = request.header("X-Vault-Namespace", ns);
        }

        let response = request.send().await?;

        if response.status().is_success() {
            Ok(())
        } else {
            let status = response.status();
            let error_text = response.text().await.unwrap_or_default();
            Err(anyhow!("Lease revocation failed: {} - {}", status, error_text))
        }
    }

    fn provider_type(&self) -> &str {
        "vault"
    }
}

/// AWS STS AssumeRole provider
pub struct AwsStsProvider {
    /// STS client
    client: aws_sdk_sts::Client,
    /// AWS region
    region: String,
}

impl AwsStsProvider {
    /// Create a new AWS STS provider
    pub async fn new(region: Option<String>) -> Result<Self> {
        let region_str = region.unwrap_or_else(|| {
            std::env::var("AWS_REGION")
                .or_else(|_| std::env::var("AWS_DEFAULT_REGION"))
                .unwrap_or_else(|_| "us-east-1".to_string())
        });

        use aws_config::BehaviorVersion;
        let config = aws_config::defaults(BehaviorVersion::latest())
            .region(aws_config::Region::new(region_str.clone()))
            .load()
            .await;

        let client = aws_sdk_sts::Client::new(&config);

        Ok(Self {
            client,
            region: region_str,
        })
    }
}

#[async_trait::async_trait]
impl DynamicSecretProvider for AwsStsProvider {
    async fn request_dynamic_secret(
        &self,
        config: &DynamicSecretConfig,
    ) -> Result<DynamicSecretResponse> {
        let role_arn = config
            .params
            .get("role_arn")
            .and_then(|v| v.as_str())
            .ok_or_else(|| anyhow!("Missing role_arn parameter for AWS STS"))?;

        let session_name = config
            .params
            .get("session_name")
            .and_then(|v| v.as_str())
            .unwrap_or("sigil-session");

        let ttl = config.parse_ttl()?;
        let duration_secs = ttl.as_secs().clamp(900, 43200); // Min 15m, max 12h

        let response = self
            .client
            .assume_role()
            .role_arn(role_arn)
            .role_session_name(session_name)
            .duration_seconds(duration_secs as i32)
            .send()
            .await
            .map_err(|e| anyhow!("AWS STS AssumeRole failed: {}", e))?;

        let credentials = response
            .credentials()
            .ok_or_else(|| anyhow!("No credentials in STS response"))?;

        let mut data = HashMap::new();
        data.insert(
            "access_key_id".to_string(),
            credentials.access_key_id().to_string(),
        );
        data.insert(
            "secret_access_key".to_string(),
            credentials.secret_access_key().to_string(),
        );
        // session_token is optional in some STS responses
        // In AWS SDK 1.x, session_token() returns &str (empty string if not set)
        let session_token = credentials.session_token();
        if !session_token.is_empty() {
            data.insert("session_token".to_string(), session_token.to_string());
        }

        // Convert AWS SDK DateTime to chrono DateTime
        // expiration() returns &aws_smithy_types::DateTime
        let exp = credentials.expiration();
        let expiration = Some(DateTime::from_timestamp(exp.secs(), exp.subsec_nanos())
            .unwrap_or_else(Utc::now));

        Ok(DynamicSecretResponse {
            lease_id: Some(format!("aws-sts-{}", role_arn)),
            lease_duration: Some(duration_secs),
            renewable: Some(true),
            data,
            expires_at: expiration,
            metadata: {
                let mut meta = HashMap::new();
                meta.insert("role_arn".to_string(), serde_json::json!(role_arn));
                meta.insert("region".to_string(), serde_json::json!(self.region));
                meta
            },
        })
    }

    async fn revoke_lease(&self, _lease_id: &str) -> Result<()> {
        // AWS STS credentials cannot be explicitly revoked
        // They expire automatically based on the duration
        // This is a no-op but we return Ok for interface compatibility
        Ok(())
    }

    fn provider_type(&self) -> &str {
        "aws-sts"
    }
}

/// Kubernetes TokenRequest API provider
pub struct KubernetesTokenProvider {
    /// Kubernetes API server address
    api_server: String,
    /// Path to service account token
    sa_token_path: String,
    /// CA certificate path
    ca_path: Option<String>,
}

impl KubernetesTokenProvider {
    /// Create a new Kubernetes TokenRequest provider
    ///
    /// If api_server is empty, tries to detect from cluster environment
    pub async fn new(api_server: Option<String>, ca_path: Option<String>) -> Result<Self> {
        let api_server_addr = if let Some(addr) = api_server {
            addr
        } else {
            // Try to detect from in-cluster environment
            std::env::var("KUBERNETES_SERVICE_HOST")
                .ok()
                .zip(std::env::var("KUBERNETES_SERVICE_PORT").ok())
                .map(|(host, port)| format!("https://{}:{}", host, port))
                .ok_or_else(|| anyhow!("Cannot detect Kubernetes API server"))?
        };

        let sa_token_path = std::env::var("SIGIL_SA_TOKEN_PATH")
            .unwrap_or_else(|_| "/var/run/secrets/kubernetes.io/serviceaccount/token".to_string());

        Ok(Self {
            api_server: api_server_addr,
            sa_token_path,
            ca_path,
        })
    }

    /// Build HTTP client with proper TLS
    fn build_client(&self) -> Result<reqwest::Client> {
        let mut builder = reqwest::Client::builder()
            .timeout(Duration::from_secs(10));

        if let Some(ca_path) = &self.ca_path {
            let ca_cert = std::fs::read(ca_path)
                .map_err(|e| anyhow!("Failed to read CA certificate: {}", e))?;

            let cert_pem = reqwest::Certificate::from_pem(&ca_cert)
                .map_err(|e| anyhow!("Failed to parse CA certificate: {}", e))?;

            builder = builder.add_root_certificate(cert_pem);
        } else {
            // Try default Kubernetes CA
            let default_ca = "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt";
            if std::path::Path::new(default_ca).exists() {
                if let Ok(ca_cert) = std::fs::read(default_ca) {
                    if let Ok(cert_pem) = reqwest::Certificate::from_pem(&ca_cert) {
                        builder = builder.add_root_certificate(cert_pem);
                    }
                }
            }
        }

        builder.build().map_err(|e| anyhow!("Failed to build HTTP client: {}", e))
    }

    /// Get the service account token
    fn get_sa_token(&self) -> Result<String> {
        std::fs::read_to_string(&self.sa_token_path)
            .map_err(|e| anyhow!("Failed to read service account token: {}", e))
    }
}

#[async_trait::async_trait]
impl DynamicSecretProvider for KubernetesTokenProvider {
    async fn request_dynamic_secret(
        &self,
        config: &DynamicSecretConfig,
    ) -> Result<DynamicSecretResponse> {
        let service_account_name = config
            .params
            .get("service_account_name")
            .and_then(|v| v.as_str())
            .ok_or_else(|| anyhow!("Missing service_account_name parameter"))?;

        let namespace = config
            .params
            .get("namespace")
            .and_then(|v| v.as_str())
            .unwrap_or("default");

        let ttl = config.parse_ttl()?;
        let duration_secs = ttl.as_secs().clamp(600, 86400) as i64; // Min 10m, max 24h

        let client = self.build_client()?;
        let token = self.get_sa_token()?;

        // Build TokenRequest API URL
        let url = format!(
            "{}/api/v1/namespaces/{}/serviceaccounts/{}/token",
            self.api_server, namespace, service_account_name
        );

        let body = serde_json::json!({
            "apiVersion": "authentication.k8s.io/v1",
            "kind": "TokenRequest",
            "spec": {
                "audiences": config.params.get("audiences").cloned().unwrap_or_else(|| {
                    serde_json::json!(["https://kubernetes.default.svc"])
                }),
                "expirationSeconds": duration_secs,
            }
        });

        let response = client
            .post(&url)
            .header("Authorization", format!("Bearer {}", token))
            .json(&body)
            .send()
            .await?;

        if response.status().is_success() {
            let json: serde_json::Value = response.json().await?;
            let token_response = &json["status"];

            let token_value = token_response["token"]
                .as_str()
                .ok_or_else(|| anyhow!("No token in TokenRequest response"))?;

            let expiration_str = token_response["expirationTimestamp"]
                .as_str()
                .ok_or_else(|| anyhow!("No expirationTimestamp in response"))?;

            let expiration = expiration_str.parse::<DateTime<Utc>>()
                .map_err(|e| anyhow!("Failed to parse expiration timestamp: {}", e))?;

            let mut data = HashMap::new();
            data.insert("token".to_string(), token_value.to_string());
            data.insert("type".to_string(), "Bearer".to_string());
            data.insert("api_server".to_string(), self.api_server.clone());
            data.insert("namespace".to_string(), namespace.to_string());
            data.insert("service_account".to_string(), service_account_name.to_string());

            Ok(DynamicSecretResponse {
                lease_id: Some(format!("k8s-token-{}-{}", namespace, service_account_name)),
                lease_duration: Some(duration_secs as u64),
                renewable: Some(true),
                data,
                expires_at: Some(expiration),
                metadata: {
                    let mut meta = HashMap::new();
                    meta.insert("namespace".to_string(), serde_json::json!(namespace));
                    meta.insert("service_account".to_string(), serde_json::json!(service_account_name));
                    meta
                },
            })
        } else {
            let status = response.status();
            let error_text = response.text().await.unwrap_or_default();
            Err(anyhow!(
                "Kubernetes TokenRequest failed: {} - {}",
                status,
                error_text
            ))
        }
    }

    async fn revoke_lease(&self, _lease_id: &str) -> Result<()> {
        // Kubernetes tokens cannot be explicitly revoked
        // They expire automatically based on the expiration time
        Ok(())
    }

    fn provider_type(&self) -> &str {
        "kubernetes-token"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dynamic_secret_config_parse_ttl() {
        let config = DynamicSecretConfig {
            path: "test".to_string(),
            backend_type: "vault".to_string(),
            ttl: "1h".to_string(),
            track_lease: true,
            params: HashMap::new(),
        };

        let duration = config.parse_ttl().unwrap();
        assert_eq!(duration, Duration::from_secs(3600));
    }

    #[test]
    fn test_parse_ttl_various_formats() {
        let test_cases = vec![
            ("30s", Duration::from_secs(30)),
            ("5m", Duration::from_secs(300)),
            ("2h", Duration::from_secs(7200)),
            ("1d", Duration::from_secs(86400)),
            ("15minutes", Duration::from_secs(900)),
            ("3600seconds", Duration::from_secs(3600)),
        ];

        for (input, expected) in test_cases {
            let config = DynamicSecretConfig {
                path: "test".to_string(),
                backend_type: "vault".to_string(),
                ttl: input.to_string(),
                track_lease: true,
                params: HashMap::new(),
            };

            let result = config.parse_ttl().unwrap();
            assert_eq!(result, expected, "Failed to parse TTL: {}", input);
        }
    }

    #[test]
    fn test_dynamic_secret_response_get_primary_value() {
        let mut data = HashMap::new();
        data.insert("username".to_string(), "admin".to_string());
        data.insert("password".to_string(), "secret123".to_string());
        data.insert("host".to_string(), "db.example.com".to_string());

        let response = DynamicSecretResponse {
            lease_id: None,
            lease_duration: None,
            renewable: None,
            data,
            expires_at: None,
            metadata: HashMap::new(),
        };

        assert_eq!(response.get_primary_value(), Some("secret123".to_string()));
        assert_eq!(response.get_field("username"), Some("admin".to_string()));
        assert_eq!(response.get_field("host"), Some("db.example.com".to_string()));
        assert_eq!(response.get_field("missing"), None);
    }

    #[test]
    fn test_dynamic_secret_response_expiration() {
        let mut response = DynamicSecretResponse {
            lease_id: Some("lease-123".to_string()),
            lease_duration: None,
            renewable: None,
            data: HashMap::new(),
            expires_at: None,
            metadata: HashMap::new(),
        };

        response.calculate_expiration(3600);

        assert_eq!(response.lease_duration, Some(3600));
        assert!(response.expires_at.is_some());
        assert!(!response.is_expired());

        // Test expired
        response.expires_at = Some(Utc::now() - chrono::Duration::seconds(10));
        assert!(response.is_expired());
    }

    #[test]
    fn test_dynamic_secret_response_get_primary_value_priority() {
        let test_cases = vec![
            (vec![("token", "xyz")], "xyz"),
            (vec![("secret", "abc")], "abc"),
            (vec![("access_key", "key123")], "key123"),
            (vec![("value", "val123")], "val123"),
            (vec![("other", "fallback")], "fallback"),
        ];

        for (items, expected) in test_cases {
            let mut data = HashMap::new();
            for (k, v) in items {
                data.insert(k.to_string(), v.to_string());
            }

            let response = DynamicSecretResponse {
                lease_id: None,
                lease_duration: None,
                renewable: None,
                data,
                expires_at: None,
                metadata: HashMap::new(),
            };

            assert_eq!(
                response.get_primary_value(),
                Some(expected.to_string())
            );
        }
    }
}
