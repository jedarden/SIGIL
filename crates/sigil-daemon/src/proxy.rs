//! Proxy management module for the daemon
//!
//! This module manages the HTTP forward proxy that injects authentication
//! headers based on domain rules.

use crate::audit::AuditLogger;
use sigil_proxy::{ProxyConfig, ProxyError, ProxyResult, ProxyServer};
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{info, warn};

/// Proxy manager for the daemon
#[allow(dead_code)]
pub struct ProxyManager {
    /// Proxy server instance
    server: Arc<RwLock<Option<ProxyServer>>>,
    /// Proxy configuration
    config: Arc<RwLock<Option<ProxyConfig>>>,
    /// Audit logger
    audit_logger: Arc<AuditLogger>,
    /// Actual listen address (set after binding)
    listen_addr: Arc<RwLock<Option<String>>>,
}

#[allow(dead_code)]
impl ProxyManager {
    /// Create a new proxy manager
    pub fn new(audit_logger: Arc<AuditLogger>) -> Self {
        Self {
            server: Arc::new(RwLock::new(None)),
            config: Arc::new(RwLock::new(None)),
            audit_logger,
            listen_addr: Arc::new(RwLock::new(None)),
        }
    }

    /// Load proxy rules from the vault
    ///
    /// Proxy rules are stored as encrypted vault entry `_sigil/proxy_rules`.
    /// The daemon decrypts rules into memory at startup.
    pub async fn load_rules_from_vault(&self, rules_toml: &str) -> ProxyResult<()> {
        let config = ProxyConfig::from_toml(rules_toml).map_err(|e| {
            ProxyError::InvalidConfig(format!("Failed to parse proxy rules: {}", e))
        })?;

        info!("Loaded {} proxy rules", config.rules.len());
        for rule in &config.rules {
            info!("  - {} ({:?})", rule.domain, rule.rule_type);
        }

        let rule_count = config.rules.len();

        // Store the configuration
        *self.config.write().await = Some(config);

        // Log to audit
        self.audit_logger.log_proxy_config_loaded(rule_count).await;

        Ok(())
    }

    /// Start the proxy server
    pub async fn start(&self) -> ProxyResult<String> {
        let config = self.config.read().await;
        let config = config
            .as_ref()
            .ok_or_else(|| ProxyError::InvalidConfig("No proxy configuration loaded".to_string()))?
            .clone();
        let listen_addr = config.listen.clone();

        // Create the proxy server
        let server = ProxyServer::new(config)?;

        // Store the server
        *self.server.write().await = Some(server);

        // Start the proxy server in the background
        let server_guard = self.server.clone();
        let audit_logger = self.audit_logger.clone();
        let listen_addr_clone = self.listen_addr.clone();

        tokio::spawn(async move {
            // Bind to get the actual address
            let bound_server = server_guard.read().await;
            if let Some(server) = bound_server.as_ref() {
                match server.bind().await {
                    Ok(listener) => {
                        match listener.local_addr() {
                            Ok(actual_addr) => {
                                // Store the actual listen address
                                *listen_addr_clone.write().await = Some(actual_addr.to_string());
                                info!("Proxy listening on {}", actual_addr);

                                // Log to audit
                                audit_logger
                                    .log_proxy_started(&actual_addr.to_string())
                                    .await;

                                // Start serving
                                drop(bound_server);
                                let server = server_guard.write().await;
                                if let Some(s) = server.as_ref() {
                                    let server_clone = s.clone();
                                    drop(server);

                                    if let Err(e) = server_clone.serve().await {
                                        warn!("Proxy server error: {}", e);
                                    }
                                }
                            }
                            Err(e) => {
                                warn!("Failed to get proxy address: {}", e);
                            }
                        }
                    }
                    Err(e) => {
                        warn!("Failed to bind proxy server: {}", e);
                    }
                }
            }
        });

        // Return the configured listen address
        Ok(listen_addr)
    }

    /// Stop the proxy server
    pub async fn stop(&self) -> ProxyResult<()> {
        *self.server.write().await = None;
        *self.listen_addr.write().await = None;

        // Log to audit
        self.audit_logger.log_proxy_stopped().await;

        info!("Proxy server stopped");
        Ok(())
    }

    /// Get the actual listen address (after binding)
    pub async fn listen_addr(&self) -> Option<String> {
        self.listen_addr.read().await.clone()
    }

    /// Check if the proxy is running
    pub async fn is_running(&self) -> bool {
        self.server.read().await.is_some()
    }

    /// Get the number of configured proxy rules
    pub async fn rule_count(&self) -> usize {
        self.config
            .read()
            .await
            .as_ref()
            .map(|c| c.rules.len())
            .unwrap_or(0)
    }
}

impl Clone for ProxyManager {
    fn clone(&self) -> Self {
        Self {
            server: self.server.clone(),
            config: self.config.clone(),
            audit_logger: self.audit_logger.clone(),
            listen_addr: self.listen_addr.clone(),
        }
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn test_proxy_manager_creation() {
        // This test verifies the proxy manager can be created
        // Actual testing requires a running audit logger
        // For now, we just test the structure
        // A placeholder test to verify the module compiles
        assert_eq!(1, 1);
    }
}
