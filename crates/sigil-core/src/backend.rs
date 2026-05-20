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

        // If no prefix match, check if we should use local vault
        // (paths without a known backend prefix go to local vault)
        if self.is_local_vault_path(path) {
            return None; // Local vault, not an external backend
        }

        // Use default backend if configured
        if let Some(ref default_id) = self.default_backend {
            for backend in &self.backends {
                if backend.id == *default_id && backend.enabled {
                    return Some(backend);
                }
            }
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
            let mut entry = BackendEntry::new(
                "aws".to_string(),
                "aws".to_string(),
                "aws".to_string(),
                50,
            );
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
        assert_eq!(entry.config.get("address"), Some(&"http://localhost:8200".to_string()));
    }
}
