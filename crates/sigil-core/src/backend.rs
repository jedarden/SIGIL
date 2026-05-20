//! Backend routing and management

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Entry describing a backend configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BackendEntry {
    /// Backend identifier
    pub id: String,
    /// Backend type (e.g., "vault", "env", "aws")
    pub backend_type: String,
    /// Priority for routing (higher = more preferred)
    pub priority: u32,
    /// Configuration options
    pub config: HashMap<String, String>,
}

impl BackendEntry {
    /// Create a new backend entry
    pub fn new(id: String, backend_type: String, priority: u32) -> Self {
        Self {
            id,
            backend_type,
            priority,
            config: HashMap::new(),
        }
    }

    /// Add a configuration option
    pub fn with_config(mut self, key: String, value: String) -> Self {
        self.config.insert(key, value);
        self
    }
}

/// Router for directing secret requests to appropriate backends
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
    pub fn route(&self, _path: &str) -> Option<&BackendEntry> {
        // For now, return the highest priority backend
        // In a full implementation, this would check path patterns
        self.backends.first()
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
}

impl Default for BackendRouterConfig {
    fn default() -> Self {
        Self::new()
    }
}
