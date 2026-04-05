//! Lease/TTL management for high-sensitivity secrets
//!
//! This module implements time-bounded access to secrets through leases.
//! Each lease grants access to a secret for a limited duration, after which
//! the access is automatically revoked. This reduces the blast radius of
//! secret leakage — even if a secret is exfiltrated, it expires quickly.
//!
//! # Lease Model
//!
//! - **Lease**: A time-bounded grant of access to a secret
//! - **TTL**: Time-to-live, the maximum duration of a lease (default: 1 hour)
//! - **Lease ID**: Unique identifier for tracking lease usage
//! - **Auto-revocation**: Leases are automatically revoked when they expire
//!
//! # Example
//!
//! ```rust
//! use sigil_core::lease::{LeaseManager, LeaseConfig};
//! use sigil_core::SecretPath;
//!
//! # #[tokio::main]
//! # async fn main() -> anyhow::Result<()> {
//! let config = LeaseConfig::default();
//! let manager = LeaseManager::new(config);
//!
//! // Grant a lease for a high-sensitivity secret
//! let path = SecretPath::new("prod/api_key".to_string())?;
//! let lease = manager.grant_lease(path, 300).await?; // 5 minutes
//!
//! // Check if lease is still valid
//! assert!(manager.is_lease_valid(&lease.id).await?);
//!
//! // Revoke the lease early
//! manager.revoke_lease(&lease.id).await?;
//! # Ok(())
//! # }
//! ```

use crate::SecretPath;
use anyhow::Result;
use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::{RwLock, Semaphore};

/// Default TTL for leases (1 hour)
pub const DEFAULT_LEASE_TTL_SECS: i64 = 3600;

/// Maximum TTL for leases (24 hours)
pub const MAX_LEASE_TTL_SECS: i64 = 86400;

/// Minimum TTL for leases (10 seconds)
pub const MIN_LEASE_TTL_SECS: i64 = 10;

/// Lease configuration
#[derive(Debug, Clone)]
pub struct LeaseConfig {
    /// Default TTL for leases in seconds
    pub default_ttl_secs: i64,
    /// Maximum TTL for leases in seconds
    pub max_ttl_secs: i64,
    /// Minimum TTL for leases in seconds
    pub min_ttl_secs: i64,
    /// Whether to enable automatic cleanup of expired leases
    pub auto_cleanup: bool,
    /// Interval for cleanup in seconds
    pub cleanup_interval_secs: i64,
}

impl Default for LeaseConfig {
    fn default() -> Self {
        Self {
            default_ttl_secs: DEFAULT_LEASE_TTL_SECS,
            max_ttl_secs: MAX_LEASE_TTL_SECS,
            min_ttl_secs: MIN_LEASE_TTL_SECS,
            auto_cleanup: true,
            cleanup_interval_secs: 300, // 5 minutes
        }
    }
}

impl LeaseConfig {
    /// Create a new lease configuration
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the default TTL
    pub fn with_default_ttl(mut self, ttl_secs: i64) -> Self {
        self.default_ttl_secs = ttl_secs.clamp(self.min_ttl_secs, self.max_ttl_secs);
        self
    }

    /// Set the maximum TTL
    pub fn with_max_ttl(mut self, ttl_secs: i64) -> Self {
        self.max_ttl_secs = ttl_secs;
        self
    }

    /// Set the minimum TTL
    pub fn with_min_ttl(mut self, ttl_secs: i64) -> Self {
        self.min_ttl_secs = ttl_secs;
        self
    }

    /// Enable or disable automatic cleanup
    pub fn with_auto_cleanup(mut self, enabled: bool) -> Self {
        self.auto_cleanup = enabled;
        self
    }

    /// Set the cleanup interval
    pub fn with_cleanup_interval(mut self, interval_secs: i64) -> Self {
        self.cleanup_interval_secs = interval_secs;
        self
    }

    /// Validate a TTL value
    pub fn validate_ttl(&self, ttl_secs: i64) -> Result<i64> {
        if ttl_secs < self.min_ttl_secs {
            anyhow::bail!(
                "TTL {} seconds is below minimum of {} seconds",
                ttl_secs,
                self.min_ttl_secs
            );
        }
        if ttl_secs > self.max_ttl_secs {
            anyhow::bail!(
                "TTL {} seconds exceeds maximum of {} seconds",
                ttl_secs,
                self.max_ttl_secs
            );
        }
        Ok(ttl_secs)
    }
}

/// A lease granting time-bounded access to a secret
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Lease {
    /// Unique lease identifier
    pub id: String,
    /// Path to the secret this lease grants access to
    pub secret_path: SecretPath,
    /// When the lease was granted
    pub granted_at: DateTime<Utc>,
    /// When the lease expires
    pub expires_at: DateTime<Utc>,
    /// Session token that requested this lease (if any)
    pub session_token: Option<String>,
    /// Process ID that requested this lease (if any)
    pub pid: Option<u32>,
    /// Whether the lease has been revoked
    pub revoked: bool,
    /// When the lease was revoked (if applicable)
    pub revoked_at: Option<DateTime<Utc>>,
    /// Reason for revocation (if applicable)
    pub revoke_reason: Option<String>,
}

impl Lease {
    /// Create a new lease
    fn new(
        secret_path: SecretPath,
        ttl_secs: i64,
        session_token: Option<String>,
        pid: Option<u32>,
    ) -> Self {
        let id = Self::generate_id();
        let granted_at = Utc::now();
        let expires_at = granted_at + Duration::seconds(ttl_secs);

        Self {
            id,
            secret_path,
            granted_at,
            expires_at,
            session_token,
            pid,
            revoked: false,
            revoked_at: None,
            revoke_reason: None,
        }
    }

    /// Generate a unique lease ID
    fn generate_id() -> String {
        use rand::Rng;
        let mut rng = rand::thread_rng();
        let bytes: [u8; 16] = rng.gen();
        format!("lease_{}", hex::encode(bytes))
    }

    /// Check if the lease is currently valid
    pub fn is_valid(&self) -> bool {
        if self.revoked {
            return false;
        }
        Utc::now() < self.expires_at
    }

    /// Get the remaining time in seconds
    pub fn remaining_secs(&self) -> i64 {
        if self.revoked {
            return 0;
        }
        let now = Utc::now();
        if now >= self.expires_at {
            0
        } else {
            (self.expires_at - now).num_seconds()
        }
    }

    /// Get the duration of the lease in seconds
    pub fn duration_secs(&self) -> i64 {
        (self.expires_at - self.granted_at).num_seconds()
    }

    /// Revoke the lease
    pub fn revoke(&mut self, reason: Option<String>) {
        self.revoked = true;
        self.revoked_at = Some(Utc::now());
        self.revoke_reason = reason;
    }
}

/// Summary of a lease for display
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LeaseSummary {
    /// Lease ID
    pub id: String,
    /// Secret path
    pub secret_path: String,
    /// Granted at timestamp
    pub granted_at: DateTime<Utc>,
    /// Expires at timestamp
    pub expires_at: DateTime<Utc>,
    /// Remaining time in seconds
    pub remaining_secs: i64,
    /// Whether the lease is valid
    pub is_valid: bool,
    /// Whether the lease was revoked
    pub revoked: bool,
    /// Session token (truncated)
    pub session_token: Option<String>,
    /// Process ID
    pub pid: Option<u32>,
}

impl From<&Lease> for LeaseSummary {
    fn from(lease: &Lease) -> Self {
        Self {
            id: lease.id.clone(),
            secret_path: lease.secret_path.as_str().to_string(),
            granted_at: lease.granted_at,
            expires_at: lease.expires_at,
            remaining_secs: lease.remaining_secs(),
            is_valid: lease.is_valid(),
            revoked: lease.revoked,
            session_token: lease.session_token.as_ref().map(|t| {
                // Truncate token for display
                if t.len() > 16 {
                    format!("{}...", &t[..16])
                } else {
                    t.clone()
                }
            }),
            pid: lease.pid,
        }
    }
}

/// Lease manager for tracking and enforcing secret access leases
pub struct LeaseManager {
    /// Active leases
    leases: Arc<RwLock<HashMap<String, Lease>>>,
    /// Configuration
    config: LeaseConfig,
    /// Semaphore for limiting concurrent access
    #[allow(dead_code)]
    semaphore: Arc<Semaphore>,
}

impl LeaseManager {
    /// Create a new lease manager
    pub fn new(config: LeaseConfig) -> Self {
        let leases = Arc::new(RwLock::new(HashMap::new()));
        let semaphore = Arc::new(Semaphore::new(100)); // Max 100 concurrent leases

        // Start cleanup task if enabled
        if config.auto_cleanup {
            let leases_clone = leases.clone();
            let cleanup_interval = config.cleanup_interval_secs;
            tokio::spawn(async move {
                Self::cleanup_task(leases_clone, cleanup_interval).await;
            });
        }

        Self {
            leases,
            config,
            semaphore,
        }
    }

    /// Create a lease manager with default configuration
    pub fn default_config() -> Self {
        Self::new(LeaseConfig::default())
    }

    /// Grant a lease for a secret
    ///
    /// # Arguments
    ///
    /// * `secret_path` - Path to the secret
    /// * `ttl_secs` - Time-to-live in seconds (uses default if None)
    ///
    /// # Returns
    ///
    /// The granted lease
    pub async fn grant_lease(
        &self,
        secret_path: SecretPath,
        ttl_secs: Option<i64>,
    ) -> Result<Lease> {
        let ttl = ttl_secs.unwrap_or(self.config.default_ttl_secs);
        self.config.validate_ttl(ttl)?;

        let lease = Lease::new(secret_path, ttl, None, None);

        tracing::info!(
            "Granted lease {} for {} (TTL: {}s, expires: {})",
            lease.id,
            lease.secret_path.as_str(),
            ttl,
            lease.expires_at
        );

        let mut leases = self.leases.write().await;
        leases.insert(lease.id.clone(), lease.clone());

        Ok(lease)
    }

    /// Grant a lease with session tracking
    pub async fn grant_lease_for_session(
        &self,
        secret_path: SecretPath,
        ttl_secs: Option<i64>,
        session_token: String,
        pid: u32,
    ) -> Result<Lease> {
        let ttl = ttl_secs.unwrap_or(self.config.default_ttl_secs);
        self.config.validate_ttl(ttl)?;

        let lease = Lease::new(secret_path, ttl, Some(session_token), Some(pid));

        tracing::info!(
            "Granted lease {} for {} (TTL: {}s, session: {}, pid: {})",
            lease.id,
            lease.secret_path.as_str(),
            ttl,
            lease
                .session_token
                .as_ref()
                .map(|t| &t[..8])
                .unwrap_or("none"),
            pid
        );

        let mut leases = self.leases.write().await;
        leases.insert(lease.id.clone(), lease.clone());

        Ok(lease)
    }

    /// Check if a lease is valid
    pub async fn is_lease_valid(&self, lease_id: &str) -> Result<bool> {
        let leases = self.leases.read().await;
        match leases.get(lease_id) {
            Some(lease) => Ok(lease.is_valid()),
            None => Ok(false),
        }
    }

    /// Get a lease by ID
    pub async fn get_lease(&self, lease_id: &str) -> Result<Option<Lease>> {
        let leases = self.leases.read().await;
        Ok(leases.get(lease_id).cloned())
    }

    /// Get all active leases
    pub async fn get_active_leases(&self) -> Result<Vec<LeaseSummary>> {
        let leases = self.leases.read().await;
        let mut summaries = Vec::new();

        for lease in leases.values() {
            summaries.push(LeaseSummary::from(lease));
        }

        // Sort by expiration time
        summaries.sort_by(|a, b| a.expires_at.cmp(&b.expires_at));

        Ok(summaries)
    }

    /// Get leases for a specific secret
    pub async fn get_leases_for_secret(&self, secret_path: &SecretPath) -> Result<Vec<Lease>> {
        let leases = self.leases.read().await;
        let secret_leases: Vec<Lease> = leases
            .values()
            .filter(|l| l.secret_path.as_str() == secret_path.as_str())
            .cloned()
            .collect();
        Ok(secret_leases)
    }

    /// Get leases for a session
    pub async fn get_leases_for_session(&self, session_token: &str) -> Result<Vec<Lease>> {
        let leases = self.leases.read().await;
        let session_leases: Vec<Lease> = leases
            .values()
            .filter(|l| l.session_token.as_deref() == Some(session_token))
            .cloned()
            .collect();
        Ok(session_leases)
    }

    /// Revoke a lease
    pub async fn revoke_lease(&self, lease_id: &str, reason: Option<String>) -> Result<bool> {
        let mut leases = self.leases.write().await;
        if let Some(lease) = leases.get_mut(lease_id) {
            lease.revoke(reason.clone());
            tracing::warn!(
                "Revoked lease {} for {} (reason: {:?})",
                lease_id,
                lease.secret_path.as_str(),
                reason
            );
            Ok(true)
        } else {
            Ok(false)
        }
    }

    /// Revoke all leases for a secret
    pub async fn revoke_leases_for_secret(
        &self,
        secret_path: &SecretPath,
        reason: Option<String>,
    ) -> Result<usize> {
        let mut leases = self.leases.write().await;
        let mut count = 0;

        for lease in leases.values_mut() {
            if lease.secret_path.as_str() == secret_path.as_str() && lease.is_valid() {
                lease.revoke(reason.clone());
                count += 1;
            }
        }

        if count > 0 {
            tracing::warn!(
                "Revoked {} leases for {} (reason: {:?})",
                count,
                secret_path.as_str(),
                reason
            );
        }

        Ok(count)
    }

    /// Revoke all leases for a session
    pub async fn revoke_leases_for_session(
        &self,
        session_token: &str,
        reason: Option<String>,
    ) -> Result<usize> {
        let mut leases = self.leases.write().await;
        let mut count = 0;

        for lease in leases.values_mut() {
            if lease.session_token.as_deref() == Some(session_token) && lease.is_valid() {
                lease.revoke(reason.clone());
                count += 1;
            }
        }

        if count > 0 {
            tracing::warn!(
                "Revoked {} leases for session {} (reason: {:?})",
                count,
                &session_token[..8.min(session_token.len())],
                reason
            );
        }

        Ok(count)
    }

    /// Clean up expired and revoked leases
    pub async fn cleanup_expired(&self) -> Result<usize> {
        let mut leases = self.leases.write().await;
        let before = leases.len();

        // Keep only valid leases (remove expired or revoked)
        leases.retain(|_, lease| lease.is_valid());

        let after = leases.len();
        let removed = before - after;

        if removed > 0 {
            tracing::info!("Cleaned up {} expired/revoked leases", removed);
        }

        Ok(removed)
    }

    /// Get statistics
    pub async fn stats(&self) -> LeaseStats {
        let leases = self.leases.read().await;

        let total = leases.len();
        let active = leases.values().filter(|l| l.is_valid()).count();
        let expired = leases
            .values()
            .filter(|l| !l.is_valid() && !l.revoked)
            .count();
        let revoked = leases.values().filter(|l| l.revoked).count();

        LeaseStats {
            total_leases: total,
            active_leases: active,
            expired_leases: expired,
            revoked_leases: revoked,
        }
    }

    /// Background task for cleaning up expired leases
    async fn cleanup_task(leases: Arc<RwLock<HashMap<String, Lease>>>, interval_secs: i64) {
        let mut interval =
            tokio::time::interval(tokio::time::Duration::from_secs(interval_secs as u64));

        loop {
            interval.tick().await;

            let mut leases_guard = leases.write().await;
            let before = leases_guard.len();

            // Keep only valid leases (remove expired or revoked)
            leases_guard.retain(|_, lease| lease.is_valid());

            let after = leases_guard.len();
            let removed = before - after;

            if removed > 0 {
                tracing::debug!("Cleanup task removed {} expired leases", removed);
            }
        }
    }
}

/// Lease statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LeaseStats {
    /// Total number of leases
    pub total_leases: usize,
    /// Number of active (valid) leases
    pub active_leases: usize,
    /// Number of expired leases
    pub expired_leases: usize,
    /// Number of revoked leases
    pub revoked_leases: usize,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_lease_config_defaults() {
        let config = LeaseConfig::default();
        assert_eq!(config.default_ttl_secs, DEFAULT_LEASE_TTL_SECS);
        assert_eq!(config.max_ttl_secs, MAX_LEASE_TTL_SECS);
        assert_eq!(config.min_ttl_secs, MIN_LEASE_TTL_SECS);
        assert!(config.auto_cleanup);
    }

    #[test]
    fn test_lease_config_builder() {
        let config = LeaseConfig::new()
            .with_default_ttl(1800)
            .with_max_ttl(7200)
            .with_min_ttl(30)
            .with_auto_cleanup(false);

        assert_eq!(config.default_ttl_secs, 1800);
        assert_eq!(config.max_ttl_secs, 7200);
        assert_eq!(config.min_ttl_secs, 30);
        assert!(!config.auto_cleanup);
    }

    #[test]
    fn test_lease_config_validation() {
        let config = LeaseConfig::default();

        // Valid TTL
        assert!(config.validate_ttl(3600).is_ok());

        // TTL too small
        assert!(config.validate_ttl(5).is_err());

        // TTL too large
        assert!(config.validate_ttl(100000).is_err());
    }

    #[tokio::test]
    async fn test_lease_creation() {
        let path = SecretPath::new("test/secret".to_string()).unwrap();
        let lease = Lease::new(path.clone(), 3600, None, None);

        assert!(lease.is_valid());
        // remaining_secs should be close to 3600 (within 1 second tolerance)
        assert!(lease.remaining_secs() >= 3599 && lease.remaining_secs() <= 3600);
        assert_eq!(lease.duration_secs(), 3600);
        assert!(!lease.revoked);
        assert!(lease.id.starts_with("lease_"));
    }

    #[tokio::test]
    async fn test_lease_expiration() {
        let path = SecretPath::new("test/secret".to_string()).unwrap();
        let mut lease = Lease::new(path, 10, None, None); // 10 second TTL (minimum allowed)

        assert!(lease.is_valid());

        // Simulate expiration by setting expires_at to past
        lease.expires_at = Utc::now() - chrono::Duration::seconds(10);

        assert!(!lease.is_valid());
        assert_eq!(lease.remaining_secs(), 0);
    }

    #[tokio::test]
    async fn test_lease_revocation() {
        let path = SecretPath::new("test/secret".to_string()).unwrap();
        let mut lease = Lease::new(path, 3600, None, None);

        assert!(lease.is_valid());

        lease.revoke(Some("test revocation".to_string()));

        assert!(!lease.is_valid());
        assert!(lease.revoked);
        assert_eq!(lease.remaining_secs(), 0);
        assert_eq!(lease.revoke_reason, Some("test revocation".to_string()));
    }

    #[tokio::test]
    async fn test_lease_manager_grant() {
        let manager = LeaseManager::default_config();
        let path = SecretPath::new("test/secret".to_string()).unwrap();

        let lease = manager.grant_lease(path, Some(300)).await.unwrap();

        assert!(lease.is_valid());
        assert!(manager.is_lease_valid(&lease.id).await.unwrap());
    }

    #[tokio::test]
    async fn test_lease_manager_stats() {
        let manager = LeaseManager::default_config();
        let path = SecretPath::new("test/secret".to_string()).unwrap();

        // Grant a few leases
        manager.grant_lease(path.clone(), Some(300)).await.unwrap();
        manager.grant_lease(path.clone(), Some(600)).await.unwrap();

        let stats = manager.stats().await;
        assert_eq!(stats.total_leases, 2);
        assert_eq!(stats.active_leases, 2);
        assert_eq!(stats.expired_leases, 0);
        assert_eq!(stats.revoked_leases, 0);
    }

    #[tokio::test]
    async fn test_lease_manager_revoke() {
        let manager = LeaseManager::default_config();
        let path = SecretPath::new("test/secret".to_string()).unwrap();

        let lease = manager.grant_lease(path, Some(300)).await.unwrap();
        assert!(manager.is_lease_valid(&lease.id).await.unwrap());

        manager
            .revoke_lease(&lease.id, Some("test".to_string()))
            .await
            .unwrap();

        assert!(!manager.is_lease_valid(&lease.id).await.unwrap());

        let stats = manager.stats().await;
        assert_eq!(stats.revoked_leases, 1);
    }

    #[tokio::test]
    async fn test_lease_manager_cleanup() {
        let manager = LeaseManager::new(
            LeaseConfig::new()
                .with_auto_cleanup(false)
                .with_min_ttl(1) // Override minimum for testing
                .with_max_ttl(3600),
        );
        let path = SecretPath::new("test/secret".to_string()).unwrap();

        // Grant an expired lease (using very short TTL)
        let lease = manager.grant_lease(path.clone(), Some(1)).await.unwrap();

        // Wait for expiration
        tokio::time::sleep(tokio::time::Duration::from_millis(1100)).await;

        // Lease should be expired
        assert!(!manager.is_lease_valid(&lease.id).await.unwrap());

        // Grant a valid lease
        manager.grant_lease(path, Some(300)).await.unwrap();

        // Cleanup should remove expired leases
        let removed = manager.cleanup_expired().await.unwrap();
        assert_eq!(removed, 1);

        let stats = manager.stats().await;
        assert_eq!(stats.total_leases, 1);
        assert_eq!(stats.active_leases, 1);
    }

    #[tokio::test]
    async fn test_lease_summary() {
        let manager = LeaseManager::default_config();
        let path = SecretPath::new("test/secret".to_string()).unwrap();

        let lease = manager
            .grant_lease_for_session(
                path,
                Some(300),
                "test_session_token_12345".to_string(),
                12345,
            )
            .await
            .unwrap();

        let summaries = manager.get_active_leases().await.unwrap();
        assert_eq!(summaries.len(), 1);

        let summary = &summaries[0];
        assert_eq!(summary.id, lease.id);
        assert_eq!(summary.secret_path, "test/secret");
        assert!(summary.is_valid);
        assert!(!summary.revoked);
        assert_eq!(summary.pid, Some(12345));
        assert!(summary.session_token.is_some());
    }

    #[tokio::test]
    async fn test_revoke_leases_for_secret() {
        let manager = LeaseManager::default_config();
        let path1 = SecretPath::new("test/secret1".to_string()).unwrap();
        let path2 = SecretPath::new("test/secret2".to_string()).unwrap();

        // Grant leases for two secrets
        manager.grant_lease(path1.clone(), Some(300)).await.unwrap();
        manager.grant_lease(path1.clone(), Some(300)).await.unwrap();
        manager.grant_lease(path2.clone(), Some(300)).await.unwrap();

        // Revoke all leases for secret1
        let count = manager
            .revoke_leases_for_secret(&path1, Some("test".to_string()))
            .await
            .unwrap();

        assert_eq!(count, 2);

        // Check stats
        let stats = manager.stats().await;
        assert_eq!(stats.revoked_leases, 2);
        assert_eq!(stats.active_leases, 1);
    }

    #[tokio::test]
    async fn test_revoke_leases_for_session() {
        let manager = LeaseManager::default_config();
        let path = SecretPath::new("test/secret".to_string()).unwrap();

        // Grant leases for two sessions
        manager
            .grant_lease_for_session(path.clone(), Some(300), "session1_token".to_string(), 111)
            .await
            .unwrap();
        manager
            .grant_lease_for_session(path.clone(), Some(300), "session1_token".to_string(), 111)
            .await
            .unwrap();
        manager
            .grant_lease_for_session(path.clone(), Some(300), "session2_token".to_string(), 222)
            .await
            .unwrap();

        // Revoke all leases for session1
        let count = manager
            .revoke_leases_for_session("session1_token", Some("test".to_string()))
            .await
            .unwrap();

        assert_eq!(count, 2);

        // Check stats
        let stats = manager.stats().await;
        assert_eq!(stats.revoked_leases, 2);
        assert_eq!(stats.active_leases, 1);
    }

    #[test]
    fn test_lease_id_generation() {
        let ids = std::iter::repeat_with(Lease::generate_id)
            .take(100)
            .collect::<std::collections::HashSet<_>>();

        assert_eq!(ids.len(), 100); // All unique
        assert!(ids.iter().all(|id| id.starts_with("lease_")));
    }
}
