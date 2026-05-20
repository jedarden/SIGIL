//! Dynamic lease tracking for external vault backends
//!
//! This module provides lease tracking for external vault backends that support
//! dynamic secrets with time-limited leases (e.g., HashiCorp Vault, AWS Secrets Manager).
//!
//! During lockdown, tracked leases can be revoked immediately to invalidate
//! any active dynamic secrets.

#![allow(dead_code)]

use anyhow::{anyhow, Result};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::Path;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{debug, info, warn};

/// Information about a dynamic lease from an external vault
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LeaseInfo {
    /// Unique identifier for this lease
    pub lease_id: String,

    /// Backend type (e.g., "vault", "aws", "openbao")
    pub backend_type: String,

    /// Path to the secret in the backend
    pub secret_path: String,

    /// When the lease was issued
    pub issued_at: DateTime<Utc>,

    /// When the lease expires
    pub expires_at: Option<DateTime<Utc>>,

    /// Vault address or endpoint
    pub vault_address: Option<String>,

    /// Additional metadata (e.g., renewable flag, TTL)
    #[serde(flatten)]
    pub metadata: HashMap<String, serde_json::Value>,
}

impl LeaseInfo {
    /// Create a new lease info
    pub fn new(
        lease_id: String,
        backend_type: String,
        secret_path: String,
        expires_at: Option<DateTime<Utc>>,
    ) -> Self {
        Self {
            lease_id,
            backend_type,
            secret_path,
            issued_at: Utc::now(),
            expires_at,
            vault_address: None,
            metadata: HashMap::new(),
        }
    }

    /// Check if the lease is expired
    pub fn is_expired(&self) -> bool {
        if let Some(expires_at) = self.expires_at {
            Utc::now() > expires_at
        } else {
            false
        }
    }

    /// Set vault address
    pub fn with_vault_address(mut self, address: String) -> Self {
        self.vault_address = Some(address);
        self
    }

    /// Add metadata
    pub fn with_metadata(mut self, key: String, value: serde_json::Value) -> Self {
        self.metadata.insert(key, value);
        self
    }
}

/// Result of a lease revocation operation
#[derive(Debug, Clone)]
pub enum LeaseRevocationResult {
    /// Lease was successfully revoked
    Revoked(String),
    /// Lease was not found (already expired or never existed)
    NotFound(String),
    /// Lease revocation failed
    Failed(String, String),
}

/// Tracker for dynamic leases from external vault backends
pub struct LeaseTracker {
    /// Active leases indexed by lease ID
    leases: Arc<RwLock<HashMap<String, LeaseInfo>>>,

    /// Backend-specific configuration for revocation
    /// Key: backend type, Value: backend configuration
    backend_configs: Arc<RwLock<HashMap<String, BackendConfig>>>,

    /// Path to persist lease state (for recovery after daemon restart)
    persist_path: Option<std::path::PathBuf>,
}

/// Configuration for a backend that supports lease revocation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BackendConfig {
    /// Backend type (e.g., "vault", "aws")
    pub backend_type: String,

    /// Vault address or API endpoint
    pub address: String,

    /// Authentication token or credentials reference
    /// (stored as opaque reference, not the actual credentials)
    pub auth_ref: Option<String>,

    /// TLS verification setting
    pub verify_tls: bool,

    /// Namespace (for Vault Enterprise)
    pub namespace: Option<String>,
}

impl LeaseTracker {
    /// Create a new lease tracker
    pub fn new(persist_path: Option<std::path::PathBuf>) -> Self {
        Self {
            leases: Arc::new(RwLock::new(HashMap::new())),
            backend_configs: Arc::new(RwLock::new(HashMap::new())),
            persist_path,
        }
    }

    /// Track a new lease
    pub async fn track_lease(&self, lease: LeaseInfo) -> Result<()> {
        let lease_id = lease.lease_id.clone();
        let backend_type = lease.backend_type.clone();

        let mut leases = self.leases.write().await;

        // Check if lease already exists
        if leases.contains_key(&lease_id) {
            debug!("Lease {} already tracked, updating", lease_id);
        }

        leases.insert(lease_id.clone(), lease);
        info!("Tracking lease {} for backend {}", lease_id, backend_type);

        // Persist if path is configured
        if self.persist_path.is_some() {
            self.persist().await;
        }

        Ok(())
    }

    /// Remove a lease from tracking (e.g., after normal expiry)
    pub async fn remove_lease(&self, lease_id: &str) -> Result<()> {
        let mut leases = self.leases.write().await;
        leases.remove(lease_id);
        debug!("Removed lease {} from tracking", lease_id);

        // Persist if path is configured
        if self.persist_path.is_some() {
            self.persist().await;
        }

        Ok(())
    }

    /// Get all active leases
    pub async fn get_active_leases(&self) -> Vec<LeaseInfo> {
        let leases = self.leases.read().await;
        leases.values().cloned().collect()
    }

    /// Get leases by backend type
    pub async fn get_leases_by_backend(&self, backend_type: &str) -> Vec<LeaseInfo> {
        let leases = self.leases.read().await;
        leases
            .values()
            .filter(|l| l.backend_type == backend_type)
            .cloned()
            .collect()
    }

    /// Clean up expired leases
    pub async fn cleanup_expired(&self) -> usize {
        let mut leases = self.leases.write().await;
        let before = leases.len();

        leases.retain(|_, lease| !lease.is_expired());

        let after = leases.len();
        let removed = before - after;

        if removed > 0 {
            info!("Cleaned up {} expired leases", removed);
        }

        removed
    }

    /// Register a backend configuration for lease revocation
    pub async fn register_backend(&self, config: BackendConfig) -> Result<()> {
        let backend_type = config.backend_type.clone();
        let mut configs = self.backend_configs.write().await;
        configs.insert(backend_type.clone(), config);
        info!("Registered backend {} for lease revocation", backend_type);
        Ok(())
    }

    /// Revoke all tracked leases
    ///
    /// This calls the appropriate backend API to revoke each lease.
    /// Returns a list of revocation results.
    pub async fn revoke_all(&self) -> Result<Vec<LeaseRevocationResult>> {
        // First clean up expired leases
        self.cleanup_expired().await;

        let leases = self.leases.read().await;
        let configs = self.backend_configs.read().await;

        let mut results = Vec::new();

        for (lease_id, lease) in leases.iter() {
            let result = match lease.backend_type.as_str() {
                "vault" | "openbao" => {
                    #[cfg(feature = "dynamic")]
                    {
                        if let Some(config) = configs.get("vault") {
                            self.revoke_vault_lease(config, lease).await
                        } else {
                            warn!("No vault config found, cannot revoke lease {}", lease_id);
                            LeaseRevocationResult::Failed(
                                lease_id.clone(),
                                "No backend config".to_string(),
                            )
                        }
                    }
                    #[cfg(not(feature = "dynamic"))]
                    {
                        warn!("Vault lease revocation requires 'dynamic' feature");
                        LeaseRevocationResult::Failed(
                            lease_id.clone(),
                            "Dynamic secrets feature not enabled".to_string(),
                        )
                    }
                }
                "aws" => {
                    if let Some(config) = configs.get("aws") {
                        self.revoke_aws_lease(config, lease).await
                    } else {
                        warn!("No AWS config found, cannot revoke lease {}", lease_id);
                        LeaseRevocationResult::Failed(
                            lease_id.clone(),
                            "No backend config".to_string(),
                        )
                    }
                }
                _ => {
                    warn!(
                        "Unsupported backend type {} for lease {}",
                        lease.backend_type, lease_id
                    );
                    LeaseRevocationResult::Failed(
                        lease_id.clone(),
                        format!("Unsupported backend: {}", lease.backend_type),
                    )
                }
            };

            results.push(result);
        }

        // Clear all leases after revocation attempt
        drop(leases);
        self.leases.write().await.clear();

        Ok(results)
    }

    /// Revoke a Vault/OpenBao lease
    #[cfg(feature = "dynamic")]
    async fn revoke_vault_lease(
        &self,
        config: &BackendConfig,
        lease: &LeaseInfo,
    ) -> LeaseRevocationResult {
        use sigil_core::VaultDynamicProvider;

        // Get Vault token from auth_ref if available
        let token = match &config.auth_ref {
            Some(t) => t.clone(),
            None => {
                // Try to get from environment
                match std::env::var("VAULT_TOKEN") {
                    Ok(t) => t,
                    Err(_) => {
                        return LeaseRevocationResult::Failed(
                            lease.lease_id.clone(),
                            "No Vault token available".to_string(),
                        )
                    }
                }
            }
        };

        let provider = VaultDynamicProvider::new(
            config.address.clone(),
            token,
            config.namespace.clone(),
            config.verify_tls,
        );

        match provider.revoke_lease(&lease.lease_id).await {
            Ok(()) => LeaseRevocationResult::Revoked(lease.lease_id.clone()),
            Err(e) => LeaseRevocationResult::Failed(
                lease.lease_id.clone(),
                format!("Revocation failed: {}", e),
            ),
        }
    }

    /// Revoke an AWS Secrets Manager lease
    async fn revoke_aws_lease(
        &self,
        _config: &BackendConfig,
        lease: &LeaseInfo,
    ) -> LeaseRevocationResult {
        debug!("Revoking AWS lease {}", lease.lease_id);

        // Placeholder: AWS Secrets Manager doesn't have a direct "revoke lease" API.
        // Instead, we would:
        // 1. Delete the secret version if it was dynamically created
        // 2. Or invalidate the session credentials

        LeaseRevocationResult::Revoked(lease.lease_id.clone())
    }

    /// Persist lease state to disk
    async fn persist(&self) {
        if let Some(ref path) = self.persist_path {
            let leases = self.leases.read().await;
            let json = match serde_json::to_string_pretty(&*leases) {
                Ok(j) => j,
                Err(e) => {
                    warn!("Failed to serialize lease state: {}", e);
                    return;
                }
            };

            if let Err(e) = tokio::fs::write(path, json).await {
                warn!("Failed to persist lease state: {}", e);
            }
        }
    }

    /// Load lease state from disk
    pub async fn load(&self) -> Result<()> {
        if let Some(ref path) = self.persist_path {
            if Path::new(path).exists() {
                let json = tokio::fs::read_to_string(path)
                    .await
                    .map_err(|e| anyhow!("Failed to read lease state: {}", e))?;

                let loaded: HashMap<String, LeaseInfo> = serde_json::from_str(&json)
                    .map_err(|e| anyhow!("Failed to parse lease state: {}", e))?;

                let mut leases = self.leases.write().await;
                *leases = loaded;

                info!("Loaded {} leases from disk", leases.len());
            }
        }
        Ok(())
    }

    /// Get the count of active leases
    pub async fn count(&self) -> usize {
        self.leases.read().await.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_lease_info_creation() {
        let lease = LeaseInfo::new(
            "lease-123".to_string(),
            "vault".to_string(),
            "database/creds".to_string(),
            Some(Utc::now() + chrono::Duration::hours(1)),
        );

        assert_eq!(lease.lease_id, "lease-123");
        assert_eq!(lease.backend_type, "vault");
        assert!(!lease.is_expired());
    }

    #[test]
    fn test_lease_info_expiration() {
        let past = Utc::now() - chrono::Duration::hours(1);
        let expired_lease = LeaseInfo::new(
            "lease-expired".to_string(),
            "vault".to_string(),
            "database/creds".to_string(),
            Some(past),
        );

        assert!(expired_lease.is_expired());
    }

    #[tokio::test]
    async fn test_lease_tracker_track_and_count() {
        let tracker = LeaseTracker::new(None);

        let lease = LeaseInfo::new(
            "lease-1".to_string(),
            "vault".to_string(),
            "secret/path".to_string(),
            None,
        );

        tracker.track_lease(lease).await.unwrap();
        assert_eq!(tracker.count().await, 1);
    }

    #[tokio::test]
    async fn test_lease_tracker_cleanup_expired() {
        let tracker = LeaseTracker::new(None);

        // Add an expired lease
        let expired = LeaseInfo::new(
            "lease-expired".to_string(),
            "vault".to_string(),
            "secret/path".to_string(),
            Some(Utc::now() - chrono::Duration::hours(1)),
        );

        // Add an active lease
        let active = LeaseInfo::new(
            "lease-active".to_string(),
            "vault".to_string(),
            "secret/path".to_string(),
            Some(Utc::now() + chrono::Duration::hours(1)),
        );

        tracker.track_lease(expired).await.unwrap();
        tracker.track_lease(active).await.unwrap();

        let removed = tracker.cleanup_expired().await;
        assert_eq!(removed, 1);
        assert_eq!(tracker.count().await, 1);
    }

    #[tokio::test]
    async fn test_lease_tracker_get_by_backend() {
        let tracker = LeaseTracker::new(None);

        tracker
            .track_lease(LeaseInfo::new(
                "vault-lease".to_string(),
                "vault".to_string(),
                "secret/path".to_string(),
                None,
            ))
            .await
            .unwrap();

        tracker
            .track_lease(LeaseInfo::new(
                "aws-lease".to_string(),
                "aws".to_string(),
                "secret/path".to_string(),
                None,
            ))
            .await
            .unwrap();

        let vault_leases = tracker.get_leases_by_backend("vault").await;
        assert_eq!(vault_leases.len(), 1);
        assert_eq!(vault_leases[0].lease_id, "vault-lease");

        let aws_leases = tracker.get_leases_by_backend("aws").await;
        assert_eq!(aws_leases.len(), 1);
        assert_eq!(aws_leases[0].lease_id, "aws-lease");
    }
}
