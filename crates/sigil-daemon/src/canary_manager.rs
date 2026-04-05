//! Canary integration for the daemon
//!
//! Manages canary secrets during daemon runtime, integrating with
//! the scrubber and monitoring for access attempts.

use anyhow::Result;
use sigil_canary::{CanaryGenerator, CanaryMonitor};
use sigil_core::SecretPath;
use std::path::PathBuf;
use std::sync::Arc;
use tracing::info;

/// Manages canary secrets in the daemon
pub struct CanaryManager {
    /// The underlying canary monitor
    monitor: Arc<CanaryMonitor>,
    /// Whether canaries are enabled
    enabled: bool,
}

impl CanaryManager {
    /// Create a new canary manager
    pub fn new(overlay_path: PathBuf, enabled: bool) -> Self {
        Self {
            monitor: Arc::new(CanaryMonitor::new(overlay_path)),
            enabled,
        }
    }

    /// Initialize canaries (generate and register)
    pub async fn initialize(&self) -> Result<()> {
        if !self.enabled {
            info!("Canary system disabled");
            return Ok(());
        }

        info!("Initializing canary system...");

        // Generate standard canaries
        let generator = CanaryGenerator::new();
        let canaries = generator.generate_all();

        // Add canaries to monitor
        self.monitor.add_canaries(canaries).await?;

        // Start monitoring
        self.monitor.start().await?;

        info!("Canary system initialized with {} canaries", 4);

        Ok(())
    }

    /// Get the canary monitor
    #[allow(dead_code)]
    pub fn monitor(&self) -> &Arc<CanaryMonitor> {
        &self.monitor
    }

    /// Get canary values for scrubber registration
    #[allow(dead_code)]
    pub async fn get_canary_values(&self) -> Vec<(SecretPath, Vec<u8>)> {
        if !self.enabled {
            return Vec::new();
        }
        self.monitor.get_canary_values().await
    }

    /// Check if any canaries have been triggered
    #[allow(dead_code)]
    pub async fn has_breaches(&self) -> bool {
        if !self.enabled {
            return false;
        }
        self.monitor.has_breaches().await
    }

    /// Generate a breach report
    #[allow(dead_code)]
    pub async fn generate_report(&self) -> String {
        if !self.enabled {
            return "Canary system disabled\n".to_string();
        }
        self.monitor.generate_report().await.format()
    }

    /// Shutdown the canary system
    #[allow(dead_code)]
    pub async fn shutdown(&self) -> Result<()> {
        if !self.enabled {
            return Ok(());
        }

        self.monitor.stop().await?;
        info!("Canary system stopped");

        Ok(())
    }

    /// Check if a path is a canary file (potential breach indicator)
    ///
    /// Canary files are paths that should never be accessed via FUSE,
    /// as they indicate the agent is trying to read files that are
    /// specifically monitored for breach detection.
    pub fn is_canary_path(&self, path: &str) -> bool {
        if !self.enabled {
            return false;
        }

        // Check if path matches known canary patterns
        // These are the paths where canaries are "placed" in the sandbox
        let canary_paths = [
            ".aws/credentials",
            ".ssh/id_sigil_canary",
            ".config/gh/hosts.yml",
            ".env",
            ".sigil-canary",
            // Also check with sigil prefix (for FUSE paths)
            "sigil/.aws/credentials",
            "sigil/.ssh/id_sigil_canary",
            "sigil/.config/gh/hosts.yml",
            "sigil/.env",
            "sigil/.sigil-canary",
        ];

        for canary in &canary_paths {
            if path == *canary || path.ends_with(&format!("/{}", canary)) {
                return true;
            }
        }

        false
    }

    /// Generate a decoy response for a canary path
    ///
    /// Returns a realistic-looking fake value for the canary type.
    /// This is used instead of returning "access denied" to avoid
    /// tipping off the agent that they've triggered a canary.
    pub fn generate_decoy_response(&self, path: &str) -> Option<Vec<u8>> {
        if !self.enabled {
            return None;
        }

        let generator = sigil_canary::CanaryGenerator::new();

        // Match the path to the appropriate canary kind
        let canary_kind = if path.contains("aws/credentials") || path.contains(".aws/") {
            Some(sigil_canary::CanaryKind::AwsCredentials)
        } else if path.contains("ssh/") || path.contains("id_sigil") {
            Some(sigil_canary::CanaryKind::SshKey)
        } else if path.contains("gh/") || path.contains("github") {
            Some(sigil_canary::CanaryKind::GitHubToken)
        } else if path.contains(".env") {
            Some(sigil_canary::CanaryKind::EnvFile)
        } else if path.contains("stripe") {
            Some(sigil_canary::CanaryKind::StripeKey)
        } else if path.contains("jwt") {
            Some(sigil_canary::CanaryKind::JwtToken)
        } else if path.contains("cert") || path.contains("pem") {
            Some(sigil_canary::CanaryKind::PemCertificate)
        } else {
            None
        };

        match canary_kind {
            Some(sigil_canary::CanaryKind::AwsCredentials) => {
                let secret = generator.generate_aws_credentials();
                Some(secret.value().to_vec())
            }
            Some(sigil_canary::CanaryKind::SshKey) => {
                let secret = generator.generate_ssh_key();
                Some(secret.value().to_vec())
            }
            Some(sigil_canary::CanaryKind::GitHubToken) => {
                let secret = generator.generate_github_token();
                Some(secret.value().to_vec())
            }
            Some(sigil_canary::CanaryKind::StripeKey) => {
                let secret = generator.generate_stripe_key();
                Some(secret.value().to_vec())
            }
            Some(sigil_canary::CanaryKind::JwtToken) => {
                let secret = generator.generate_jwt_token();
                Some(secret.value().to_vec())
            }
            Some(sigil_canary::CanaryKind::PemCertificate) => {
                let secret = generator.generate_pem_certificate();
                Some(secret.value().to_vec())
            }
            Some(sigil_canary::CanaryKind::EnvFile) => {
                // Use the env file generator
                let secret = generator.generate_env_file();
                Some(secret.value().to_vec())
            }
            Some(sigil_canary::CanaryKind::Generic) => {
                // For generic canary, use the env file as a fallback
                let secret = generator.generate_env_file();
                Some(secret.value().to_vec())
            }
            None => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_canary_manager_disabled() {
        let overlay = tempfile::tempdir().unwrap();
        let manager = CanaryManager::new(overlay.path().to_path_buf(), false);

        manager.initialize().await.unwrap();
        assert!(!manager.has_breaches().await);

        let values = manager.get_canary_values().await;
        assert!(values.is_empty());

        let report = manager.generate_report().await;
        assert!(report.contains("disabled"));
    }

    #[tokio::test]
    async fn test_canary_manager_enabled() {
        let overlay = tempfile::tempdir().unwrap();
        let manager = CanaryManager::new(overlay.path().to_path_buf(), true);

        manager.initialize().await.unwrap();
        assert!(!manager.has_breaches().await);

        let values = manager.get_canary_values().await;
        assert!(!values.is_empty());

        manager.shutdown().await.unwrap();
    }
}
