//! Backend routing and management
//!
//! This module provides namespace prefix routing for external backends.
//! Secrets are routed based on their path prefix:
//! - `vault/secret/path` → Vault backend
//! - `onepassword/secret/path` → 1Password backend
//! - `pass/secret/path` → Pass/gopass backend
//! - `aws/secret/path` → AWS Secrets Manager backend
//! - `sops/secret/path` → SOPS backend
//! - `env/secret/path` → Environment backend
//!
//! Resolution order:
//! 1. Local vault (no prefix)
//! 2. Backends in priority order (highest first)
//! 3. Default backend if configured

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use crate::types::SecretBackend;

/// Known backend types with their namespace prefixes
pub const BACKEND_PREFIXES: &[(&str, &str)] = &[
    ("vault", "vault"),
    ("openbao", "vault"),
    ("onepassword", "onepassword"),
    ("op", "onepassword"),
    ("pass", "pass"),
    ("gopass", "pass"),
    ("aws", "aws"),
    ("sops", "sops"),
    ("env", "env"),
];

/// Entry describing a backend configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BackendEntry {
    /// Backend identifier
    pub id: String,
    /// Backend type (e.g., "vault", "env", "aws")
    pub backend_type: String,
    /// Namespace prefix for routing (e.g., "vault", "aws")
    pub prefix: String,
    /// Priority for routing (higher = more preferred)
    pub priority: u32,
    /// Configuration options
    pub config: HashMap<String, String>,
    /// Whether this backend is enabled
    pub enabled: bool,
}

impl BackendEntry {
    /// Create a new backend entry
    pub fn new(id: String, backend_type: String, prefix: String, priority: u32) -> Self {
        Self {
            id,
            backend_type,
            prefix,
            priority,
            config: HashMap::new(),
            enabled: true,
        }
    }

    /// Add a configuration option
    pub fn with_config(mut self, key: String, value: String) -> Self {
        self.config.insert(key, value);
        self
    }

    /// Check if this backend matches the given path prefix
    pub fn matches_path(&self, path: &str) -> bool {
        if !self.enabled {
            return false;
        }
        // Check if path starts with "prefix/"
        path.starts_with(&format!("{}/", self.prefix))
    }

    /// Strip the backend prefix from a path
    pub fn strip_prefix(&self, path: &str) -> Option<String> {
        if !self.matches_path(path) {
            return None;
        }
        path.strip_prefix(&format!("{}/", self.prefix))
            .map(|s| s.to_string())
    }
}

/// Router for directing secret requests to appropriate backends
///
/// Resolution order:
/// 1. Local vault (paths without a backend prefix)
/// 2. Backends in priority order (highest first)
/// 3. Default backend if configured
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BackendRouter {
    /// Available backends
    pub backends: Vec<BackendEntry>,
    /// Default backend to use when no path matches
    pub default_backend: Option<String>,
}

impl BackendRouter {
    /// Create a new backend router
    pub fn new() -> Self {
        Self {
            backends: Vec::new(),
            default_backend: None,
        }
    }

    /// Add a backend to the router
    pub fn add_backend(&mut self, entry: BackendEntry) {
        self.backends.push(entry);
        // Sort by priority (highest first)
        self.backends.sort_by(|a, b| b.priority.cmp(&a.priority));
    }

    /// Get the best backend for a given path
    ///
    /// Resolution order:
    /// 1. Check for namespace prefix match (e.g., "vault/secret" → vault backend)
    /// 2. Return default backend if configured
    /// 3. Return highest priority backend
    pub fn route(&self, path: &str) -> Option<&BackendEntry> {
        // First, try to find a backend by namespace prefix
        for backend in &self.backends {
            if backend.matches_path(path) {
                return Some(backend);
            }
        }

        // Use default backend if configured
        if let Some(ref default_id) = self.default_backend {
            for backend in &self.backends {
                if backend.id == *default_id && backend.enabled {
                    return Some(backend);
                }
            }
        }

        // If no prefix match and no default backend, check if we should use local vault
        // (paths without a known backend prefix go to local vault)
        if self.is_local_vault_path(path) {
            return None; // Local vault, not an external backend
        }

        // Fall back to highest priority enabled backend
        self.backends.iter().find(|b| b.enabled)
    }

    /// Check if a path should use the local vault (no backend prefix)
    fn is_local_vault_path(&self, path: &str) -> bool {
        // Check if path starts with any known backend prefix
        for (prefix, _) in BACKEND_PREFIXES {
            if path.starts_with(&format!("{}/", prefix)) {
                return false;
            }
        }
        // No backend prefix means local vault
        true
    }

    /// Get backend by ID
    pub fn get_backend(&self, id: &str) -> Option<&BackendEntry> {
        self.backends.iter().find(|b| b.id == id)
    }

    /// Get all enabled backends
    pub fn enabled_backends(&self) -> Vec<&BackendEntry> {
        self.backends.iter().filter(|b| b.enabled).collect()
    }
}

impl Default for BackendRouter {
    fn default() -> Self {
        Self::new()
    }
}

/// Configuration for backend router
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BackendRouterConfig {
    /// Enable backend routing
    pub enabled: bool,
    /// Backend entries
    pub backends: Vec<BackendEntry>,
    /// Default backend ID
    pub default_backend: Option<String>,
}

impl BackendRouterConfig {
    /// Create a new router config
    pub fn new() -> Self {
        Self {
            enabled: true,
            backends: Vec::new(),
            default_backend: None,
        }
    }

    /// Build a router from this config
    pub fn build(&self) -> BackendRouter {
        let mut router = BackendRouter::new();
        for entry in &self.backends {
            router.add_backend(entry.clone());
        }
        router.default_backend = self.default_backend.clone();
        router
    }

    /// Add a backend to the config
    pub fn add_backend(&mut self, entry: BackendEntry) {
        self.backends.push(entry);
    }
}

impl Default for BackendRouterConfig {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_backend_entry_matches_path() {
        let entry = BackendEntry::new(
            "vault".to_string(),
            "vault".to_string(),
            "vault".to_string(),
            100,
        );

        assert!(entry.matches_path("vault/secret/foo"));
        assert!(entry.matches_path("vault/secret/foo/bar"));
        assert!(!entry.matches_path("foo/secret/bar"));
        assert!(!entry.matches_path("vaultsecret")); // No slash after prefix
    }

    #[test]
    fn test_backend_entry_strip_prefix() {
        let entry = BackendEntry::new(
            "vault".to_string(),
            "vault".to_string(),
            "vault".to_string(),
            100,
        );

        assert_eq!(
            entry.strip_prefix("vault/secret/foo"),
            Some("secret/foo".to_string())
        );
        assert_eq!(entry.strip_prefix("foo/secret/bar"), None);
    }

    #[test]
    fn test_router_namespace_routing() {
        let mut router = BackendRouter::new();
        router.add_backend(BackendEntry::new(
            "vault".to_string(),
            "vault".to_string(),
            "vault".to_string(),
            100,
        ));
        router.add_backend(BackendEntry::new(
            "aws".to_string(),
            "aws".to_string(),
            "aws".to_string(),
            50,
        ));

        // Test namespace prefix routing
        let vault_backend = router.route("vault/secret/foo");
        assert!(vault_backend.is_some());
        assert_eq!(vault_backend.unwrap().backend_type, "vault");

        let aws_backend = router.route("aws/secret/bar");
        assert!(aws_backend.is_some());
        assert_eq!(aws_backend.unwrap().backend_type, "aws");
    }

    #[test]
    fn test_router_local_vault_paths() {
        let router = BackendRouter::new();

        // Paths without backend prefixes should return None (local vault)
        assert!(router.route("secret/foo").is_none());
        assert!(router.route("foo/bar/baz").is_none());
    }

    #[test]
    fn test_router_default_backend() {
        let mut router = BackendRouter::new();
        router.add_backend(BackendEntry::new(
            "vault".to_string(),
            "vault".to_string(),
            "vault".to_string(),
            100,
        ));
        router.default_backend = Some("vault".to_string());

        // Unknown path should use default backend
        let backend = router.route("unknown/path");
        assert!(backend.is_some());
        assert_eq!(backend.unwrap().backend_type, "vault");
    }

    #[test]
    fn test_router_priority_ordering() {
        let mut router = BackendRouter::new();
        router.add_backend(BackendEntry::new(
            "low".to_string(),
            "low".to_string(),
            "low".to_string(),
            10,
        ));
        router.add_backend(BackendEntry::new(
            "high".to_string(),
            "high".to_string(),
            "high".to_string(),
            100,
        ));
        router.add_backend(BackendEntry::new(
            "medium".to_string(),
            "medium".to_string(),
            "medium".to_string(),
            50,
        ));

        // Check that backends are sorted by priority
        assert_eq!(router.backends[0].priority, 100);
        assert_eq!(router.backends[1].priority, 50);
        assert_eq!(router.backends[2].priority, 10);
    }

    #[test]
    fn test_router_enabled_backends() {
        let mut router = BackendRouter::new();
        router.add_backend({
            let mut entry = BackendEntry::new(
                "vault".to_string(),
                "vault".to_string(),
                "vault".to_string(),
                100,
            );
            entry.enabled = true;
            entry
        });
        router.add_backend({
            let mut entry =
                BackendEntry::new("aws".to_string(), "aws".to_string(), "aws".to_string(), 50);
            entry.enabled = false;
            entry
        });

        let enabled = router.enabled_backends();
        assert_eq!(enabled.len(), 1);
        assert_eq!(enabled[0].id, "vault");
    }

    #[test]
    fn test_backend_entry_with_config() {
        let entry = BackendEntry::new(
            "vault".to_string(),
            "vault".to_string(),
            "vault".to_string(),
            100,
        )
        .with_config("address".to_string(), "http://localhost:8200".to_string())
        .with_config("token".to_string(), "s.xxx".to_string());

        assert_eq!(entry.config.len(), 2);
        assert_eq!(
            entry.config.get("address"),
            Some(&"http://localhost:8200".to_string())
        );
    }
}

/// Trait for creating backend instances from configuration
///
/// This trait allows each backend crate to implement its own
/// configuration parsing logic. The `BackendFactory` uses this
/// trait to dynamically create backend instances.
pub trait BackendFromConfig: Sized {
    /// Create a backend instance from a backend entry configuration
    ///
    /// # Errors
    ///
    /// Returns an error if the configuration is invalid or the backend
    /// cannot be created (e.g., missing required fields, connection failure).
    fn from_config(entry: &BackendEntry) -> Result<Self, String>;
}

/// Backend cache entry with TTL
#[derive(Debug, Clone)]
struct CacheEntry {
    /// Cached secret value
    value: Vec<u8>,
    /// When this entry expires
    expires_at: std::time::Instant,
}

/// In-memory cache for backend secrets with mlock'd memory
///
/// This cache stores secret values in memory with a configurable TTL.
/// Cached secrets are stored in regular memory for now - mlock support
/// is planned for Phase 2.
pub struct BackendCache {
    /// Cache storage: backend_id -> path -> entry
    storage: HashMap<String, HashMap<String, CacheEntry>>,
    /// Default TTL for cache entries
    default_ttl: Duration,
}

impl BackendCache {
    /// Create a new backend cache
    pub fn new(default_ttl: Duration) -> Self {
        Self {
            storage: HashMap::new(),
            default_ttl,
        }
    }

    /// Get a cached value
    pub fn get(&self, backend_id: &str, path: &str) -> Option<Vec<u8>> {
        let backend_cache = self.storage.get(backend_id)?;
        let entry = backend_cache.get(path)?;

        // Check if expired
        if entry.expires_at <= std::time::Instant::now() {
            return None;
        }

        Some(entry.value.clone())
    }

    /// Set a cached value
    pub fn set(&mut self, backend_id: &str, path: &str, value: Vec<u8>) {
        let expires_at = std::time::Instant::now() + self.default_ttl;
        let entry = CacheEntry { value, expires_at };

        self.storage
            .entry(backend_id.to_string())
            .or_default()
            .insert(path.to_string(), entry);
    }

    /// Invalidate a cache entry
    pub fn invalidate(&mut self, backend_id: &str, path: &str) {
        if let Some(backend_cache) = self.storage.get_mut(backend_id) {
            backend_cache.remove(path);
        }
    }

    /// Clear all cache entries for a backend
    pub fn clear_backend(&mut self, backend_id: &str) {
        self.storage.remove(backend_id);
    }

    /// Clear all cache entries
    pub fn clear_all(&mut self) {
        self.storage.clear();
    }

    /// Clean up expired entries
    pub fn cleanup_expired(&mut self) {
        let now = std::time::Instant::now();
        for backend_cache in self.storage.values_mut() {
            backend_cache.retain(|_, entry| entry.expires_at > now);
        }
        // Remove empty backend caches
        self.storage.retain(|_, cache| !cache.is_empty());
    }
}

/// Factory for creating backend instances from configuration
///
/// This factory provides a unified interface for instantiating backends
/// from `BackendEntry` configurations. Each backend crate must be
/// enabled as a feature to be available.
pub struct BackendFactory;

impl BackendFactory {
    /// Create a backend instance from a backend entry
    ///
    /// This function dynamically creates a backend instance based on the
    /// backend type in the entry. The backend must be enabled as a feature
    /// on the sigil-core crate.
    ///
    /// # Returns
    ///
    /// A `Result` containing an `Arc<dyn SecretBackend>` or an error if
    /// the backend type is unknown or creation fails.
    #[allow(unexpected_cfgs)]
    pub fn create_backend(entry: &BackendEntry) -> Result<Arc<dyn SecretBackend>, String> {
        match entry.backend_type.as_str() {
            "vault" => {
                #[cfg(feature = "backend-vault")]
                {
                    sigil_backend_vault::VaultBackend::from_config(entry)
                        .map(|b| Arc::new(b) as Arc<dyn SecretBackend>)
                        .map_err(|e| format!("Failed to create vault backend: {}", e))
                }
                #[cfg(not(feature = "backend-vault"))]
                {
                    Err("Vault backend feature not enabled".to_string())
                }
            }
            "onepassword" => {
                #[cfg(feature = "backend-onepassword")]
                {
                    sigil_backend_onepassword::OnepasswordBackend::from_config(entry)
                        .map(|b| Arc::new(b) as Arc<dyn SecretBackend>)
                        .map_err(|e| format!("Failed to create onepassword backend: {}", e))
                }
                #[cfg(not(feature = "backend-onepassword"))]
                {
                    Err("1Password backend feature not enabled".to_string())
                }
            }
            "pass" => {
                #[cfg(feature = "backend-pass")]
                {
                    sigil_backend_pass::PassBackend::from_config(entry)
                        .map(|b| Arc::new(b) as Arc<dyn SecretBackend>)
                        .map_err(|e| format!("Failed to create pass backend: {}", e))
                }
                #[cfg(not(feature = "backend-pass"))]
                {
                    Err("Pass backend feature not enabled".to_string())
                }
            }
            "aws" => {
                #[cfg(feature = "backend-aws")]
                {
                    sigil_backend_aws::AwsBackend::from_config(entry)
                        .map(|b| Arc::new(b) as Arc<dyn SecretBackend>)
                        .map_err(|e| format!("Failed to create AWS backend: {}", e))
                }
                #[cfg(not(feature = "backend-aws"))]
                {
                    Err("AWS backend feature not enabled".to_string())
                }
            }
            "sops" => {
                #[cfg(feature = "backend-sops")]
                {
                    sigil_backend_sops::SopsBackend::from_config(entry)
                        .map(|b| Arc::new(b) as Arc<dyn SecretBackend>)
                        .map_err(|e| format!("Failed to create SOPS backend: {}", e))
                }
                #[cfg(not(feature = "backend-sops"))]
                {
                    Err("SOPS backend feature not enabled".to_string())
                }
            }
            "env" => {
                #[cfg(feature = "backend-env")]
                {
                    sigil_backend_env::EnvBackend::from_config(entry)
                        .map(|b| Arc::new(b) as Arc<dyn SecretBackend>)
                        .map_err(|e| format!("Failed to create env backend: {}", e))
                }
                #[cfg(not(feature = "backend-env"))]
                {
                    Err("Env backend feature not enabled".to_string())
                }
            }
            _ => Err(format!("Unknown backend type: {}", entry.backend_type)),
        }
    }

    /// Create all backends from a router configuration
    ///
    /// Returns a map of backend_id -> Arc<dyn SecretBackend> for all
    /// enabled backends in the router config.
    pub fn create_backends_from_router(
        router: &BackendRouter,
    ) -> Result<HashMap<String, Arc<dyn SecretBackend>>, String> {
        let mut backends = HashMap::new();

        for entry in router.enabled_backends() {
            match Self::create_backend(entry) {
                Ok(backend) => {
                    backends.insert(entry.id.clone(), backend);
                }
                Err(e) => {
                    tracing::warn!("Failed to create backend {}: {}", entry.id, e);
                    // Continue with other backends
                }
            }
        }

        Ok(backends)
    }
}

#[cfg(test)]
mod tests_cache {
    use super::*;

    #[test]
    fn test_cache_set_get() {
        let mut cache = BackendCache::new(Duration::from_secs(60));

        cache.set("vault", "secret/foo", b"my-secret".to_vec());
        let value = cache.get("vault", "secret/foo");

        assert_eq!(value, Some(b"my-secret".to_vec()));
    }

    #[test]
    fn test_cache_miss() {
        let cache = BackendCache::new(Duration::from_secs(60));

        let value = cache.get("vault", "secret/foo");
        assert_eq!(value, None);
    }

    #[test]
    fn test_cache_invalidate() {
        let mut cache = BackendCache::new(Duration::from_secs(60));

        cache.set("vault", "secret/foo", b"my-secret".to_vec());
        cache.invalidate("vault", "secret/foo");

        let value = cache.get("vault", "secret/foo");
        assert_eq!(value, None);
    }

    #[test]
    fn test_cache_clear_backend() {
        let mut cache = BackendCache::new(Duration::from_secs(60));

        cache.set("vault", "secret/foo", b"secret1".to_vec());
        cache.set("vault", "secret/bar", b"secret2".to_vec());
        cache.set("aws", "secret/baz", b"secret3".to_vec());

        cache.clear_backend("vault");

        assert_eq!(cache.get("vault", "secret/foo"), None);
        assert_eq!(cache.get("vault", "secret/bar"), None);
        assert_eq!(cache.get("aws", "secret/baz"), Some(b"secret3".to_vec()));
    }

    #[test]
    fn test_cache_clear_all() {
        let mut cache = BackendCache::new(Duration::from_secs(60));

        cache.set("vault", "secret/foo", b"secret1".to_vec());
        cache.set("aws", "secret/bar", b"secret2".to_vec());

        cache.clear_all();

        assert_eq!(cache.get("vault", "secret/foo"), None);
        assert_eq!(cache.get("aws", "secret/bar"), None);
    }

    #[test]
    fn test_cache_expiration() {
        let mut cache = BackendCache::new(Duration::from_millis(100));

        cache.set("vault", "secret/foo", b"my-secret".to_vec());

        // Should be available immediately
        assert_eq!(
            cache.get("vault", "secret/foo"),
            Some(b"my-secret".to_vec())
        );

        // Wait for expiration
        std::thread::sleep(Duration::from_millis(150));

        // Should be expired
        assert_eq!(cache.get("vault", "secret/foo"), None);
    }

    #[test]
    fn test_cache_cleanup_expired() {
        let mut cache = BackendCache::new(Duration::from_millis(100));

        cache.set("vault", "secret/foo", b"secret1".to_vec());
        cache.set("aws", "secret/bar", b"secret2".to_vec());

        // Wait for expiration
        std::thread::sleep(Duration::from_millis(150));

        cache.cleanup_expired();

        // Expired entries should be removed
        assert_eq!(cache.get("vault", "secret/foo"), None);
        assert_eq!(cache.get("aws", "secret/bar"), None);
    }
}
