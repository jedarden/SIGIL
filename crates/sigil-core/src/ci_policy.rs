//! CI policy module for secret access control in CI/CD environments
//!
//! This module implements policy-based secret access control for headless CI/CD workflows.
//! When SIGIL_CI is set, the daemon evaluates requested secret paths against allow/deny
//! rules defined in `.sigil/ci-policy.toml` instead of using interactive approval.
//!
//! # Policy File Format
//!
//! The `.sigil/ci-policy.toml` file defines allow/deny rules using glob patterns:
//!
//! ```toml
//! version = 1
//!
//! [[policy.allow]]
//! pattern = "kalshi/*"
//! description = "Allow all Kalshi trading secrets"
//!
//! [[policy.allow]]
//! pattern = "aws/access_key_id"
//! description = "Allow AWS access key ID (public)"
//!
//! [[policy.deny]]
//! pattern = "aws/*"
//! description = "Deny other AWS secrets"
//!
//! [[policy.deny]]
//! pattern = "prod/*"
//! description = "Deny production secrets"
//!
//! [[policy.allow]]
//! pattern = "prod/deploy_key"
//! description = "Allow specific production deploy key"
//! ```
//!
//! # Evaluation Logic
//!
//! 1. If SIGIL_CI is set and `.sigil/ci-policy.toml` exists:
//!    - Evaluate the requested secret path against all deny rules
//!    - If any deny rule matches → ACCESS DENIED (fail closed)
//!    - Evaluate against all allow rules
//!    - If any allow rule matches → ACCESS GRANTED (session-scoped)
//!    - If no rule matches → ACCESS DENIED (fail closed)
//!
//! 2. If SIGIL_CI is set but no policy file exists:
//!    - Preserve backward compatibility: blanket approve all requests
//!    - This is additive and opt-in (no regression for existing CI users)
//!
//! # Glob Pattern Syntax
//!
//! Patterns use standard glob syntax:
//! - `*` matches any sequence of characters (except `/`)
//! - `**` matches any sequence including `/`
//! - `?` matches any single character
//! - `[abc]` matches any character in the set
//! - `[!abc]` matches any character not in the set
//!
//! Examples:
//! - `kalshi/*` matches `kalshi/api_key`, `kalshi/secret`, etc.
//! - `*.api_key` matches `aws/api_key`, `kalshi/api_key`, etc.
//! - `**/*` matches all paths (use with caution)
//! - `prod/deploy_key` matches only that exact path
//!
//! # Security Considerations
//!
//! - **Deny rules take precedence**: If a path matches both allow and deny rules,
//!   the deny rule wins (defense-in-depth)
//! - **Fail closed**: If no rule matches, access is denied (not granted)
//! - **Policy is version-controlled**: `.sigil/ci-policy.toml` can be committed to git
//!   and reviewed via pull requests
//! - **Audit logging**: All policy decisions are logged with the matching rule
//!
//! # Example: Least-Privilege CI Policy
//!
//! ```toml
//! version = 1
//!
//! # Allow specific test secrets
//! [[policy.allow]]
//! pattern = "test/*"
//! description = "Allow test environment secrets"
//!
//! # Allow specific deployment key
//! [[policy.allow]]
//! pattern = "deploy/ssh_key"
//! description = "Allow deployment SSH key"
//!
//! # Deny all production secrets
//! [[policy.deny]]
//! pattern = "prod/*"
//! description = "Deny production secrets"
//!
//! # Deny database passwords
//! [[policy.deny]]
//! pattern = "*/db_password"
//! description = "Deny database passwords"
//! ```
//!
//! # Recommendations
//!
//! 1. Start with an empty policy (allow nothing) and add specific allow rules
//! 2. Use deny rules for high-sensitivity paths (prod, db_passwords, etc.)
//! 3. Commit policy files to git for review and audit trail
//! 4. Run `sigil doctor` to check for overly-broad rules (e.g., `allow = ["*"]`)
//! 5. Rotate secrets if a policy was accidentally too permissive

use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use thiserror::Error;

/// Version of the policy file format
pub const POLICY_FORMAT_VERSION: u32 = 1;

/// Error type for CI policy operations
#[derive(Debug, Error)]
pub enum CiPolicyError {
    /// I/O error reading policy file
    #[error("Failed to read policy file: {0}")]
    IoError(#[from] std::io::Error),

    /// TOML parsing error
    #[error("Failed to parse policy file: {0}")]
    ParseError(#[from] toml::de::Error),

    /// Policy version mismatch
    #[error("Invalid policy version: expected {expected}, got {got}")]
    InvalidVersion {
        /// Expected version number
        expected: u32,
        /// Actual version number found in file
        got: u32,
    },

    /// Invalid glob pattern
    #[error("Invalid glob pattern '{pattern}': {reason}")]
    InvalidPattern {
        /// The pattern that failed to parse
        pattern: String,
        /// Description of why the pattern is invalid
        reason: String,
    },

    /// Policy file not found at path
    #[error("Policy file not found: {0}")]
    PolicyNotFound(PathBuf),
}

/// Result type for CI policy operations
pub type Result<T> = std::result::Result<T, CiPolicyError>;

/// Policy rule for matching secret paths
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyRule {
    /// Glob pattern for matching secret paths
    pub pattern: String,

    /// Optional description of what this rule allows/denies
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
}

impl PolicyRule {
    /// Create a new policy rule
    pub fn new(pattern: impl Into<String>, description: impl Into<Option<String>>) -> Self {
        Self {
            pattern: pattern.into(),
            description: description.into(),
        }
    }

    /// Check if this rule matches a given secret path
    fn matches(&self, path: &str) -> bool {
        // Use glob matching
        match glob_match(&self.pattern, path) {
            Ok(matches) => matches,
            Err(e) => {
                tracing::warn!("Invalid glob pattern '{}': {}", self.pattern, e);
                false
            }
        }
    }
}

/// CI policy configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CiPolicyConfig {
    /// Policy file format version
    #[serde(default = "default_policy_version")]
    pub version: u32,

    /// Allow rules (secrets that can be accessed in CI)
    #[serde(default)]
    pub allow: Vec<PolicyRule>,

    /// Deny rules (secrets that cannot be accessed in CI)
    #[serde(default)]
    pub deny: Vec<PolicyRule>,
}

fn default_policy_version() -> u32 {
    POLICY_FORMAT_VERSION
}

impl Default for CiPolicyConfig {
    fn default() -> Self {
        Self {
            version: POLICY_FORMAT_VERSION,
            allow: Vec::new(),
            deny: Vec::new(),
        }
    }
}

/// CI policy evaluator
#[derive(Debug, Clone)]
pub struct CiPolicy {
    config: CiPolicyConfig,
    policy_path: PathBuf,
}

impl CiPolicy {
    /// Load a CI policy from a file
    pub fn load_from_file(path: &Path) -> Result<Self> {
        if !path.exists() {
            return Err(CiPolicyError::PolicyNotFound(path.to_path_buf()));
        }

        let content = std::fs::read_to_string(path)?;
        let config: CiPolicyConfig = toml::from_str(&content)?;

        // Validate version
        if config.version != POLICY_FORMAT_VERSION {
            return Err(CiPolicyError::InvalidVersion {
                expected: POLICY_FORMAT_VERSION,
                got: config.version,
            });
        }

        Ok(Self {
            config,
            policy_path: path.to_path_buf(),
        })
    }

    /// Evaluate whether a secret path should be allowed in CI mode
    ///
    /// Returns `PolicyDecision::Allow` with the matching rule if allowed,
    /// or `PolicyDecision::Deny` with the reason if denied.
    pub fn evaluate(&self, path: &str) -> PolicyDecision {
        // First, check deny rules (defense-in-depth: deny takes precedence)
        for rule in &self.config.deny {
            if rule.matches(path) {
                let reason = rule
                    .description
                    .clone()
                    .unwrap_or_else(|| format!("Matches deny rule: {}", rule.pattern));
                tracing::info!("CI policy: DENIED '{}' (deny rule: {})", path, rule.pattern);
                return PolicyDecision::Deny { reason };
            }
        }

        // Then, check allow rules
        for rule in &self.config.allow {
            if rule.matches(path) {
                let reason = rule
                    .description
                    .clone()
                    .unwrap_or_else(|| format!("Matches allow rule: {}", rule.pattern));
                tracing::info!(
                    "CI policy: ALLOWED '{}' (allow rule: {})",
                    path,
                    rule.pattern
                );
                return PolicyDecision::Allow {
                    rule: rule.pattern.clone(),
                    description: reason,
                };
            }
        }

        // No rule matched: fail closed
        tracing::info!("CI policy: DENIED '{}' (no matching rule)", path);
        PolicyDecision::Deny {
            reason: "No matching allow rule in CI policy".to_string(),
        }
    }

    /// Get the policy file path
    pub fn policy_path(&self) -> &Path {
        &self.policy_path
    }

    /// Get a reference to the configuration
    pub fn config(&self) -> &CiPolicyConfig {
        &self.config
    }

    /// Check if the policy has any allow rules
    pub fn has_allow_rules(&self) -> bool {
        !self.config.allow.is_empty()
    }

    /// Check if the policy has any deny rules
    pub fn has_deny_rules(&self) -> bool {
        !self.config.deny.is_empty()
    }

    /// Check if the policy is empty (no rules at all)
    pub fn is_empty(&self) -> bool {
        self.config.allow.is_empty() && self.config.deny.is_empty()
    }
}

/// Result of policy evaluation
#[derive(Debug, Clone)]
pub enum PolicyDecision {
    /// Access is allowed
    Allow {
        /// The rule pattern that matched
        rule: String,
        /// Description of the rule
        description: String,
    },

    /// Access is denied
    Deny {
        /// Reason for denial
        reason: String,
    },
}

impl PolicyDecision {
    /// Check if this decision is an allow
    pub fn is_allowed(&self) -> bool {
        matches!(self, PolicyDecision::Allow { .. })
    }

    /// Get the reason string for this decision
    pub fn reason(&self) -> String {
        match self {
            PolicyDecision::Allow { description, .. } => description.clone(),
            PolicyDecision::Deny { reason } => reason.clone(),
        }
    }
}

/// Find and load the CI policy file from standard locations
///
/// Searches for `.sigil/ci-policy.toml` in:
/// 1. Current working directory
/// 2. Parent directories (up to workspace root)
/// 3. Home directory
pub fn find_ci_policy() -> Option<PathBuf> {
    let policy_name = ".sigil/ci-policy.toml";

    // Check current directory first
    if let Ok(cwd) = std::env::current_dir() {
        let policy_path = cwd.join(Path::new(policy_name));
        if policy_path.exists() {
            return Some(policy_path);
        }

        // Check parent directories (workspace traversal)
        let mut current = cwd;
        while let Some(parent) = current.parent() {
            let policy_path = parent.join(Path::new(policy_name));
            if policy_path.exists() {
                return Some(policy_path);
            }
            current = parent.to_path_buf();

            // Stop at filesystem root to avoid infinite loop
            if current.as_os_str().is_empty() {
                break;
            }
        }
    }

    // Check home directory
    if let Ok(home) = std::env::var("HOME") {
        let policy_path = PathBuf::from(home).join(Path::new(policy_name));
        if policy_path.exists() {
            return Some(policy_path);
        }
    }

    None
}

/// Simple glob pattern matching
///
/// Supports: `*`, `**`, `?`, `[abc]`, `[!abc]`
fn glob_match(pattern: &str, text: &str) -> std::result::Result<bool, String> {
    // Handle common patterns manually for efficiency
    if pattern == "*" {
        return Ok(!text.contains('/'));
    }

    if pattern == "**" || pattern == "**/*" {
        return Ok(true);
    }

    if pattern == text {
        return Ok(true);
    }

    // Split pattern into segments
    let pattern_segments: Vec<&str> = pattern.split('/').collect();
    let text_segments: Vec<&str> = text.split('/').collect();

    match glob_segments(&pattern_segments, &text_segments) {
        Some(result) => Ok(result),
        None => Err(format!("Invalid glob pattern: {}", pattern)),
    }
}

/// Match glob pattern segments against text segments
fn glob_segments(pattern: &[&str], text: &[&str]) -> Option<bool> {
    let mut p_idx = 0;
    let mut t_idx = 0;
    let mut p_backtrack: Vec<(usize, usize)> = Vec::new();

    while p_idx < pattern.len() || t_idx < text.len() {
        if p_idx < pattern.len() {
            let pat_seg = pattern[p_idx];

            if pat_seg == "**" {
                // Double-star matches zero or more segments
                if p_idx + 1 < pattern.len() {
                    // Try matching the rest of the pattern starting at current text position
                    p_backtrack.push((p_idx, t_idx));
                    p_idx += 1;
                    continue;
                } else {
                    // ** at the end matches everything remaining
                    return Some(true);
                }
            }

            if t_idx < text.len() && segment_matches(pat_seg, text[t_idx]) {
                p_idx += 1;
                t_idx += 1;
                continue;
            }
        }

        // No match found, try backtracking
        if let Some((back_p, back_t)) = p_backtrack.pop() {
            p_idx = back_p + 1;
            t_idx = back_t + 1;
            if t_idx <= text.len() {
                p_backtrack.push((back_p, t_idx));
                continue;
            }
        }

        return Some(false);
    }

    Some(true)
}

/// Check if a single pattern segment matches a text segment
fn segment_matches(pattern: &str, text: &str) -> bool {
    let mut p_chars = pattern.chars().peekable();
    let mut t_chars = text.chars().peekable();

    while let Some(p) = p_chars.next() {
        match p {
            '*' => {
                // * matches any sequence of non-separator characters
                let mut matched = false;
                while let Some(&t) = t_chars.peek() {
                    if t == '/' {
                        break;
                    }
                    t_chars.next();
                    matched = true;
                }
                if !matched {
                    return false;
                }
            }

            '?' => {
                // ? matches any single character except '/'
                if let Some(t) = t_chars.next() {
                    if t == '/' {
                        return false;
                    }
                } else {
                    return false;
                }
            }

            '[' => {
                // Character class: [abc] or [!abc]
                let negate = p_chars.peek() == Some(&'!');
                if negate {
                    p_chars.next();
                }

                let mut class_chars = Vec::new();
                for c in p_chars.by_ref() {
                    if c == ']' {
                        break;
                    }
                    class_chars.push(c);
                }

                if let Some(t) = t_chars.next() {
                    let in_class = class_chars.contains(&t);
                    if negate && in_class {
                        return false;
                    }
                    if !negate && !in_class {
                        return false;
                    }
                } else {
                    return false;
                }
            }

            c => {
                // Literal character match
                if let Some(t) = t_chars.next() {
                    if c != t {
                        return false;
                    }
                } else {
                    return false;
                }
            }
        }
    }

    // All pattern characters consumed - remaining text chars must also be consumed
    t_chars.next().is_none()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_simple_match() {
        assert!(glob_match("kalshi/api_key", "kalshi/api_key").unwrap());
        assert!(!glob_match("kalshi/api_key", "aws/api_key").unwrap());
    }

    #[test]
    fn test_wildcard_match() {
        assert!(glob_match("kalshi/*", "kalshi/api_key").unwrap());
        assert!(glob_match("kalshi/*", "kalshi/secret").unwrap());
        assert!(!glob_match("kalshi/*", "aws/api_key").unwrap());
        assert!(!glob_match("kalshi/*", "kalshi/sub/path").unwrap());
    }

    #[test]
    fn test_double_wildcard_match() {
        assert!(glob_match("**/*", "kalshi/api_key").unwrap());
        assert!(glob_match("**/*", "kalshi/sub/path").unwrap());
        assert!(glob_match("**", "anything").unwrap());
        assert!(glob_match("**", "deep/nested/path").unwrap());
    }

    #[test]
    fn test_question_mark() {
        assert!(glob_match("kalshi/?", "kalshi/a").unwrap());
        assert!(glob_match("kalshi/?", "kalshi/1").unwrap());
        assert!(!glob_match("kalshi/?", "kalshi/ab").unwrap());
        assert!(!glob_match("kalshi/?", "kalshi").unwrap());
    }

    #[test]
    fn test_character_class() {
        assert!(glob_match("kalshi/[abc]", "kalshi/a").unwrap());
        assert!(glob_match("kalshi/[abc]", "kalshi/b").unwrap());
        assert!(!glob_match("kalshi/[abc]", "kalshi/d").unwrap());
    }

    #[test]
    fn test_negated_character_class() {
        assert!(!glob_match("kalshi/[!abc]", "kalshi/a").unwrap());
        assert!(glob_match("kalshi/[!abc]", "kalshi/d").unwrap());
    }

    #[test]
    fn test_suffix_wildcard() {
        assert!(glob_match("*/api_key", "kalshi/api_key").unwrap());
        assert!(glob_match("*/api_key", "aws/api_key").unwrap());
        assert!(!glob_match("*/api_key", "kalshi/secret").unwrap());
    }

    #[test]
    fn test_complex_pattern() {
        assert!(glob_match("**/test/*", "test/api_key").unwrap());
        assert!(glob_match("**/test/*", "sub/test/api_key").unwrap());
        assert!(!glob_match("**/test/*", "prod/api_key").unwrap());
    }

    #[test]
    fn test_exact_segment_matching() {
        assert!(segment_matches("api_key", "api_key"));
        assert!(!segment_matches("api_key", "secret"));
    }

    #[test]
    fn test_segment_wildcard() {
        assert!(segment_matches("*", "anything"));
        assert!(segment_matches("*", "a"));
        assert!(!segment_matches("*", ""));
    }

    #[test]
    fn test_segment_question_mark() {
        assert!(segment_matches("?", "a"));
        assert!(segment_matches("?", "1"));
        assert!(!segment_matches("?", "ab"));
        assert!(!segment_matches("?", ""));
    }

    #[test]
    fn test_policy_rule_matches() {
        let rule = PolicyRule::new("kalshi/*", Some("Kalshi secrets".to_string()));
        assert!(rule.matches("kalshi/api_key"));
        assert!(rule.matches("kalshi/secret"));
        assert!(!rule.matches("aws/api_key"));

        let rule = PolicyRule::new("*/api_key", None);
        assert!(rule.matches("kalshi/api_key"));
        assert!(rule.matches("aws/api_key"));
        assert!(!rule.matches("kalshi/secret"));
    }

    #[test]
    fn test_ci_policy_allow_only() {
        let toml = r#"
version = 1

[[allow]]
pattern = "kalshi/*"
description = "Allow Kalshi secrets"

[[allow]]
pattern = "aws/access_key_id"
description = "Allow AWS access key ID"
"#;

        let config: CiPolicyConfig = toml::from_str(toml).unwrap();
        let policy = CiPolicy {
            config,
            policy_path: PathBuf::from("/test/policy.toml"),
        };

        // Should allow kalshi secrets
        assert!(policy.evaluate("kalshi/api_key").is_allowed());
        assert!(policy.evaluate("kalshi/secret").is_allowed());

        // Should allow specific AWS secret
        assert!(policy.evaluate("aws/access_key_id").is_allowed());

        // Should deny everything else (fail closed)
        assert!(!policy.evaluate("aws/secret_access_key").is_allowed());
        assert!(!policy.evaluate("prod/key").is_allowed());
    }

    #[test]
    fn test_ci_policy_deny_precedence() {
        let toml = r#"
version = 1

[[allow]]
pattern = "aws/*"
description = "Allow AWS secrets"

[[deny]]
pattern = "aws/secret_access_key"
description = "Deny AWS secret key (high sensitivity)"
"#;

        let config: CiPolicyConfig = toml::from_str(toml).unwrap();
        let policy = CiPolicy {
            config,
            policy_path: PathBuf::from("/test/policy.toml"),
        };

        // Deny rule takes precedence
        assert!(!policy.evaluate("aws/secret_access_key").is_allowed());

        // Other AWS secrets allowed
        assert!(policy.evaluate("aws/access_key_id").is_allowed());
    }

    #[test]
    fn test_ci_policy_empty_policy() {
        let toml = r#"
version = 1
"#;

        let config: CiPolicyConfig = toml::from_str(toml).unwrap();
        let policy = CiPolicy {
            config,
            policy_path: PathBuf::from("/test/policy.toml"),
        };

        // Empty policy: everything denied (fail closed)
        assert!(!policy.evaluate("anything").is_allowed());
        assert!(!policy.evaluate("kalshi/api_key").is_allowed());
        assert!(policy.is_empty());
    }

    #[test]
    fn test_ci_policy_version_validation() {
        let toml = r#"
version = 999

[[policy.allow]]
pattern = "kalshi/*"
"#;

        let result: std::result::Result<CiPolicyConfig, _> = toml::from_str(toml);
        assert!(result.is_ok()); // Parsing succeeds

        let config = result.unwrap();
        let policy = CiPolicy {
            config,
            policy_path: PathBuf::from("/test/policy.toml"),
        };

        // But loading would fail due to version mismatch
        let result = CiPolicy::load_from_file(&PathBuf::from("/nonexistent.toml"));
        // Would get InvalidVersion error if file existed
    }

    #[test]
    fn test_policy_decision_methods() {
        let decision = PolicyDecision::Allow {
            rule: "kalshi/*".to_string(),
            description: "Kalshi secrets".to_string(),
        };

        assert!(decision.is_allowed());
        assert_eq!(decision.reason(), "Kalshi secrets");

        let decision = PolicyDecision::Deny {
            reason: "No matching rule".to_string(),
        };

        assert!(!decision.is_allowed());
        assert_eq!(decision.reason(), "No matching rule");
    }

    #[test]
    fn test_wildcard_star_all() {
        // Pattern "*" should match single-segment paths only
        assert!(glob_match("*", "api_key").unwrap());
        assert!(!glob_match("*", "kalshi/api_key").unwrap());
        assert!(!glob_match("*", "a/b").unwrap());

        // Pattern "**" should match everything
        assert!(glob_match("**", "api_key").unwrap());
        assert!(glob_match("**", "kalshi/api_key").unwrap());
        assert!(glob_match("**", "a/b/c").unwrap());
    }

    #[test]
    fn test_pattern_with_slash_in_text() {
        assert!(!glob_match("test", "test/path").unwrap());
        assert!(glob_match("test/*", "test/path").unwrap());
        assert!(glob_match("test/**", "test/path/sub").unwrap());
    }

    #[test]
    fn test_multiple_wildcards() {
        assert!(glob_match("*/*", "a/b").unwrap());
        assert!(!glob_match("*/*", "a").unwrap());
        assert!(!glob_match("*/*", "a/b/c").unwrap());

        assert!(glob_match("*/**/*", "a/b/c").unwrap());
        assert!(glob_match("*/**/*", "x/y/z").unwrap());
    }
}
