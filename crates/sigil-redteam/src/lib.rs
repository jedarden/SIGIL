//! SIGIL Red-Team Mode — Collaborative Adversarial Testing
//!
//! This module provides built-in adversarial testing that spawns an attacker
//! agent against your SIGIL configuration to detect security weaknesses.
//!
//! # Example
//!
//! ```rust,no_run
//! use sigil_redteam::{RedTeamRunner, AttackConfig};
//!
//! #[tokio::main]
//! async fn main() -> anyhow::Result<()> {
//!     let config = AttackConfig::default();
//!     let runner = RedTeamRunner::new(config)?;
//!
//!     let report = runner.run_all_attacks().await?;
//!     println!("{}", report.format());
//!
//!     Ok(())
//! }
//! ```

#![warn(missing_docs)]
#![warn(clippy::all)]

pub mod attack;
pub mod playbook;
pub mod report;
pub mod tui;

pub use attack::{Attack, AttackResult, AttackStatus};
pub use playbook::{AttackPlaybook, PlaybookFormat};
pub use report::{SecurityReport, SecurityScore};
pub use tui::{DashboardConfig, RedTeamDashboard};

use std::sync::Arc;

use std::time::Duration;

/// Configuration for red-team testing
#[derive(Debug, Clone)]
pub struct AttackConfig {
    /// Duration to run attacks (None = indefinite)
    pub duration: Option<Duration>,
    /// Profile to use (e.g., "prod", "staging", "dev")
    pub profile: String,
    /// Whether to run in regression mode (replay previous attacks)
    pub regression_mode: bool,
    /// Minimum security score threshold (0-100)
    pub min_score: Option<u8>,
    /// Verbose output
    pub verbose: bool,
    /// Path to custom playbook YAML
    pub custom_playbook: Option<std::path::PathBuf>,
}

impl Default for AttackConfig {
    fn default() -> Self {
        Self {
            duration: Some(Duration::from_secs(1800)), // 30 minutes default
            profile: "default".to_string(),
            regression_mode: false,
            min_score: None,
            verbose: false,
            custom_playbook: None,
        }
    }
}

impl AttackConfig {
    /// Create a new attack configuration
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the attack duration
    pub fn with_duration(mut self, duration: Duration) -> Self {
        self.duration = Some(duration);
        self
    }

    /// Set the profile
    pub fn with_profile(mut self, profile: String) -> Self {
        self.profile = profile;
        self
    }

    /// Enable regression mode
    pub fn with_regression(mut self, regression: bool) -> Self {
        self.regression_mode = regression;
        self
    }

    /// Set minimum score threshold
    pub fn with_min_score(mut self, score: u8) -> Self {
        self.min_score = Some(score);
        self
    }

    /// Enable verbose output
    pub fn with_verbose(mut self, verbose: bool) -> Self {
        self.verbose = verbose;
        self
    }

    /// Set custom playbook path
    pub fn with_playbook(mut self, path: std::path::PathBuf) -> Self {
        self.custom_playbook = Some(path);
        self
    }
}

/// Red-team test runner
pub struct RedTeamRunner {
    /// Attack configuration
    config: AttackConfig,
    /// Attack playbook
    playbook: AttackPlaybook,
}

impl RedTeamRunner {
    /// Create a new red-team runner
    pub fn new(config: AttackConfig) -> anyhow::Result<Self> {
        let playbook = if let Some(ref path) = config.custom_playbook {
            AttackPlaybook::from_yaml_file(path)?
        } else {
            AttackPlaybook::builtin()?
        };

        Ok(Self { config, playbook })
    }

    /// Run all attacks in the playbook
    pub async fn run_all_attacks(&self) -> anyhow::Result<SecurityReport> {
        let mut report = SecurityReport::new(self.config.profile.clone());

        for attack in self.playbook.attacks() {
            if self.config.verbose {
                tracing::info!("Running attack: {}", attack.name());
            }

            let result = self.run_attack(attack).await?;
            report.add_result(result);
        }

        report.finalize();
        Ok(report)
    }

    /// Run a single attack
    pub async fn run_attack(&self, attack: Arc<dyn Attack>) -> anyhow::Result<AttackResult> {
        let start = chrono::Utc::now();

        let status = match attack.execute().await {
            Ok(blocked) => {
                if blocked {
                    AttackStatus::Blocked
                } else {
                    AttackStatus::Evaded
                }
            }
            Err(e) => AttackStatus::Error(e.to_string()),
        };

        let duration = chrono::Utc::now() - start;

        Ok(AttackResult {
            attack_name: attack.name().to_string(),
            status,
            duration_ms: duration.num_milliseconds() as u64,
            details: attack.details().clone(),
        })
    }

    /// Run in regression mode (replay previous attacks from report)
    pub async fn run_regression(
        &self,
        previous_report: &SecurityReport,
    ) -> anyhow::Result<SecurityReport> {
        let mut report = SecurityReport::new(format!("{}-regression", self.config.profile));

        for previous_result in previous_report.results() {
            // Find the attack in the current playbook
            if let Some(attack) = self.playbook.find_attack(&previous_result.attack_name) {
                let result = self.run_attack(attack).await?;
                report.add_regression_result(result, previous_result);
            }
        }

        report.finalize();
        Ok(report)
    }

    /// Run in CI mode (non-interactive, fail if score below threshold)
    pub async fn run_ci_mode(&self) -> anyhow::Result<SecurityReport> {
        let report = self.run_all_attacks().await?;

        if let Some(min_score) = self.config.min_score {
            let score = report.score();
            if score.value() < min_score {
                anyhow::bail!(
                    "Security score {} below threshold {}",
                    score.value(),
                    min_score
                );
            }
        }

        Ok(report)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_attack_config_default() {
        let config = AttackConfig::default();
        assert_eq!(config.profile, "default");
        assert!(config.duration.is_some());
        assert!(!config.regression_mode);
    }

    #[test]
    fn test_attack_config_builder() {
        let config = AttackConfig::new()
            .with_duration(Duration::from_secs(600))
            .with_profile("prod".to_string())
            .with_min_score(95)
            .with_verbose(true);

        assert_eq!(config.profile, "prod");
        assert_eq!(config.duration, Some(Duration::from_secs(600)));
        assert_eq!(config.min_score, Some(95));
        assert!(config.verbose);
    }

    #[tokio::test]
    async fn test_security_report_creation() {
        let report = SecurityReport::new("test".to_string());
        assert_eq!(report.profile(), "test");
        assert!(!report.is_finalized());
    }

    #[tokio::test]
    async fn test_builtin_playbook() {
        let playbook = AttackPlaybook::builtin().unwrap();
        assert!(!playbook.attacks().is_empty());
    }
}
