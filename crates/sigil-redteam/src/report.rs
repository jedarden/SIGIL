//! Security report generation
//!
//! Generates comprehensive security reports with scoring.

use crate::attack::{AttackResult, AttackStatus};
use serde::{Deserialize, Serialize};
use std::fmt;

/// Security report from red-team testing
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityReport {
    /// Profile that was tested
    profile: String,
    /// When the report was generated
    generated_at: chrono::DateTime<chrono::Utc>,
    /// When testing started
    started_at: chrono::DateTime<chrono::Utc>,
    /// When testing ended
    ended_at: Option<chrono::DateTime<chrono::Utc>>,
    /// Total duration in seconds
    duration_secs: u64,
    /// Attack results
    results: Vec<AttackResult>,
    /// Previous results for regression
    previous_results: Vec<AttackResult>,
    /// Whether the report is finalized
    finalized: bool,
}

impl SecurityReport {
    /// Create a new security report
    pub fn new(profile: String) -> Self {
        let now = chrono::Utc::now();
        Self {
            profile,
            generated_at: now,
            started_at: now,
            ended_at: None,
            duration_secs: 0,
            results: Vec::new(),
            previous_results: Vec::new(),
            finalized: false,
        }
    }

    /// Add an attack result
    pub fn add_result(&mut self, result: AttackResult) {
        self.results.push(result);
    }

    /// Add a regression result (with previous result for comparison)
    pub fn add_regression_result(&mut self, result: AttackResult, previous: &AttackResult) {
        self.previous_results.push(previous.clone());
        self.results.push(result);
    }

    /// Finalize the report
    pub fn finalize(&mut self) {
        self.ended_at = Some(chrono::Utc::now());
        self.duration_secs = if let Some(end) = self.ended_at {
            (end - self.started_at).num_seconds() as u64
        } else {
            0
        };
        self.finalized = true;
    }

    /// Check if the report is finalized
    pub fn is_finalized(&self) -> bool {
        self.finalized
    }

    /// Get the profile name
    pub fn profile(&self) -> &str {
        &self.profile
    }

    /// Get all attack results
    pub fn results(&self) -> &[AttackResult] {
        &self.results
    }

    /// Calculate the security score
    pub fn score(&self) -> SecurityScore {
        if self.results.is_empty() {
            return SecurityScore::A;
        }

        let blocked = self
            .results
            .iter()
            .filter(|r| r.was_blocked() || matches!(r.status, AttackStatus::Detected))
            .count();

        let total = self.results.len();
        let block_rate = (blocked as f64 / total as f64) * 100.0;

        // Check for any evaded critical attacks
        let has_evaded_critical = self.results.iter().any(|r| {
            r.was_evaded() && r.details.get("severity").and_then(|s| s.as_str()) == Some("Critical")
        });

        SecurityScore::from_block_rate(block_rate, has_evaded_critical)
    }

    /// Get the number of blocked attacks
    pub fn blocked_count(&self) -> usize {
        self.results.iter().filter(|r| r.was_blocked()).count()
    }

    /// Get the number of evaded attacks
    pub fn evaded_count(&self) -> usize {
        self.results.iter().filter(|r| r.was_evaded()).count()
    }

    /// Get the number of detected attacks
    pub fn detected_count(&self) -> usize {
        self.results
            .iter()
            .filter(|r| matches!(r.status, AttackStatus::Detected))
            .count()
    }

    /// Get the number of errors
    pub fn error_count(&self) -> usize {
        self.results.iter().filter(|r| r.had_error()).count()
    }

    /// Get total attack count
    pub fn total_count(&self) -> usize {
        self.results.len()
    }

    /// Get regression status (for regression mode)
    pub fn regression_status(&self) -> RegressionStatus {
        if self.previous_results.is_empty() {
            return RegressionStatus::NoBaseline;
        }

        let mut improved = 0;
        let mut regressed = 0;
        let mut same = 0;

        // Compare current vs previous for each attack
        for (current, previous) in self.results.iter().zip(self.previous_results.iter()) {
            let current_blocked =
                current.was_blocked() || matches!(current.status, AttackStatus::Detected);
            let previous_blocked =
                previous.was_blocked() || matches!(previous.status, AttackStatus::Detected);

            if current_blocked && !previous_blocked {
                improved += 1;
            } else if !current_blocked && previous_blocked {
                regressed += 1;
            } else {
                same += 1;
            }
        }

        if regressed == 0 {
            RegressionStatus::Improved { improved, same }
        } else {
            RegressionStatus::Regressed {
                regressed,
                improved,
                same,
            }
        }
    }

    /// Format the report as a human-readable string
    pub fn format(&self) -> String {
        let mut output = String::new();

        output.push_str(&format!(
            "SIGIL Red-Team Report — {}\n",
            self.generated_at.format("%Y-%m-%d %H:%M:%S")
        ));
        output.push_str(&format!("Profile: {}\n", self.profile));

        if let Some(end) = self.ended_at {
            let duration = end - self.started_at;
            output.push_str(&format!(
                "Duration: {} minutes, {} seconds\n",
                duration.num_minutes(),
                duration.num_seconds() % 60
            ));
        }

        output.push_str(&format!("Total attacks: {}\n", self.total_count()));

        let blocked = self.blocked_count();
        let detected = self.detected_count();
        let evaded = self.evaded_count();
        let errors = self.error_count();

        output.push_str(&format!(
            "BLOCKED:  {} ({:.1}%)\n",
            blocked + detected,
            ((blocked + detected) as f64 / self.total_count() as f64) * 100.0
        ));
        output.push_str(&format!("DETECTED:  {} (canary triggers)\n", detected));
        output.push_str(&format!("EVADED:   {}\n", evaded));
        output.push_str(&format!("ERRORS:   {}\n", errors));

        output.push_str(&format!("\nSecurity Score: {}\n", self.score()));

        if !self.results.is_empty() {
            output.push_str("\nAttack Results:\n");
            for result in &self.results {
                let status = match result.status {
                    AttackStatus::Blocked => "BLOCKED",
                    AttackStatus::Evaded => "EVADED",
                    AttackStatus::Detected => "DETECTED",
                    AttackStatus::Error(_) => "ERROR",
                };
                output.push_str(&format!(
                    "  [{:8}] {} ({}ms)\n",
                    status, result.attack_name, result.duration_ms
                ));
            }
        }

        // Show known evasion methods
        if evaded > 0 {
            output.push_str("\nKnown Limitations:\n");
            for result in &self.results {
                if result.was_evaded() {
                    if let Some(evasion) = result.details.get("evasion_method") {
                        if let Some(method) = evasion.as_str() {
                            output.push_str(&format!("  - {}\n", method));
                        }
                    }
                }
            }
        }

        output
    }

    /// Export the report as JSON
    pub fn to_json(&self) -> anyhow::Result<String> {
        serde_json::to_string_pretty(self).map_err(Into::into)
    }

    /// Export the report as YAML
    pub fn to_yaml(&self) -> anyhow::Result<String> {
        serde_yaml::to_string(self).map_err(Into::into)
    }
}

/// Security score (A-F grading)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SecurityScore {
    /// Excellent: 95-100% block rate, no critical evasions
    A,
    /// Good: 85-94% block rate, no critical evasions
    B,
    /// Fair: 70-84% block rate
    C,
    /// Poor: 50-69% block rate
    D,
    /// Fail: < 50% block rate or critical evasions
    F,
}

impl SecurityScore {
    /// Get the numeric value of the score
    pub fn value(&self) -> u8 {
        match self {
            SecurityScore::A => 95,
            SecurityScore::B => 85,
            SecurityScore::C => 70,
            SecurityScore::D => 50,
            SecurityScore::F => 0,
        }
    }

    /// Create a score from block rate and critical evasion status
    pub fn from_block_rate(rate: f64, has_critical_evasion: bool) -> Self {
        if has_critical_evasion {
            return SecurityScore::F;
        }

        if rate >= 95.0 {
            SecurityScore::A
        } else if rate >= 85.0 {
            SecurityScore::B
        } else if rate >= 70.0 {
            SecurityScore::C
        } else if rate >= 50.0 {
            SecurityScore::D
        } else {
            SecurityScore::F
        }
    }
}

impl fmt::Display for SecurityScore {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let (grade, description) = match self {
            SecurityScore::A => ("A (97/100)", "Excellent"),
            SecurityScore::B => ("B (85/100)", "Good"),
            SecurityScore::C => ("C (70/100)", "Fair"),
            SecurityScore::D => ("D (50/100)", "Poor"),
            SecurityScore::F => ("F (0/100)", "Fail"),
        };
        write!(f, "{} ({})", grade, description)
    }
}

/// Regression status for regression mode
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RegressionStatus {
    /// No baseline to compare against
    NoBaseline,
    /// Security improved (attacks now blocked that weren't before)
    Improved {
        /// Number of attacks that improved
        improved: usize,
        /// Number of attacks with same status
        same: usize,
    },
    /// Security regressed (attacks now evading that were blocked before)
    Regressed {
        /// Number of attacks that regressed
        regressed: usize,
        /// Number of attacks that improved
        improved: usize,
        /// Number of attacks with same status
        same: usize,
    },
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::attack::AttackStatus;

    #[test]
    fn test_security_report_creation() {
        let report = SecurityReport::new("test".to_string());
        assert_eq!(report.profile(), "test");
        assert!(!report.is_finalized());
        assert_eq!(report.total_count(), 0);
    }

    #[test]
    fn test_security_score() {
        assert_eq!(SecurityScore::A.value(), 95);
        assert_eq!(SecurityScore::B.value(), 85);
        assert_eq!(SecurityScore::C.value(), 70);
        assert_eq!(SecurityScore::D.value(), 50);
        assert_eq!(SecurityScore::F.value(), 0);
    }

    #[test]
    fn test_score_from_block_rate() {
        assert!(matches!(
            SecurityScore::from_block_rate(98.0, false),
            SecurityScore::A
        ));
        assert!(matches!(
            SecurityScore::from_block_rate(90.0, false),
            SecurityScore::B
        ));
        assert!(matches!(
            SecurityScore::from_block_rate(75.0, false),
            SecurityScore::C
        ));
        assert!(matches!(
            SecurityScore::from_block_rate(60.0, false),
            SecurityScore::D
        ));
        assert!(matches!(
            SecurityScore::from_block_rate(40.0, false),
            SecurityScore::F
        ));
        assert!(matches!(
            SecurityScore::from_block_rate(98.0, true),
            SecurityScore::F
        ));
    }

    #[test]
    fn test_report_formatting() {
        let mut report = SecurityReport::new("test".to_string());

        report.add_result(AttackResult {
            attack_name: "test_attack".to_string(),
            status: AttackStatus::Blocked,
            duration_ms: 100,
            details: std::collections::HashMap::new(),
        });

        report.finalize();

        let formatted = report.format();
        assert!(formatted.contains("SIGIL Red-Team Report"));
        assert!(formatted.contains("test_attack"));
        assert!(formatted.contains("BLOCKED"));
    }

    #[test]
    fn test_regression_status() {
        let mut report = SecurityReport::new("test".to_string());

        // Add previous result (blocked)
        let prev_result = AttackResult {
            attack_name: "test".to_string(),
            status: AttackStatus::Blocked,
            duration_ms: 100,
            details: std::collections::HashMap::new(),
        };

        // Add current result (evaded - regression)
        let curr_result = AttackResult {
            attack_name: "test".to_string(),
            status: AttackStatus::Evaded,
            duration_ms: 100,
            details: std::collections::HashMap::new(),
        };

        report.add_regression_result(curr_result, &prev_result);

        let status = report.regression_status();
        assert!(matches!(status, RegressionStatus::Regressed { .. }));
    }
}
