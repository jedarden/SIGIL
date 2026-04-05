//! Proxy configuration types

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::SocketAddr;

/// Proxy configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProxyConfig {
    /// Listen address (use ":0" for random port)
    #[serde(default = "default_listen")]
    pub listen: String,

    /// Proxy rules
    #[serde(default)]
    pub rules: Vec<ProxyRule>,

    /// Whether to enable default-deny for domains
    #[serde(default = "default_allowlist_only")]
    pub allowlist_only: bool,

    /// Whether to enable audit logging
    #[serde(default = "default_audit_logging")]
    pub audit_logging: bool,

    /// Timeout for upstream connections (seconds)
    #[serde(default = "default_timeout")]
    pub timeout_secs: u64,
}

fn default_listen() -> String {
    "127.0.0.1:0".to_string()
}

fn default_allowlist_only() -> bool {
    true
}

fn default_audit_logging() -> bool {
    true
}

fn default_timeout() -> u64 {
    30
}

impl Default for ProxyConfig {
    fn default() -> Self {
        Self {
            listen: default_listen(),
            rules: Vec::new(),
            allowlist_only: default_allowlist_only(),
            audit_logging: default_audit_logging(),
            timeout_secs: default_timeout(),
        }
    }
}

impl ProxyConfig {
    /// Parse proxy config from TOML
    pub fn from_toml(toml: &str) -> Result<Self, toml::de::Error> {
        toml::from_str(toml)
    }

    /// Convert to TOML
    pub fn to_toml(&self) -> Result<String, toml::ser::Error> {
        toml::to_string_pretty(self)
    }

    /// Get the listen address as a SocketAddr
    pub fn listen_addr(&self) -> Result<SocketAddr, crate::ProxyError> {
        self.listen
            .parse()
            .map_err(|e| crate::ProxyError::InvalidConfig(format!("invalid listen address: {}", e)))
    }

    /// Find a rule that matches the given domain
    pub fn find_rule_for_domain(&self, domain: &str) -> Option<&ProxyRule> {
        self.rules.iter().find(|rule| rule.matches_domain(domain))
    }

    /// Check if a domain is allowed (in allowlist mode)
    pub fn is_domain_allowed(&self, domain: &str) -> bool {
        if !self.allowlist_only {
            return true;
        }
        self.rules.iter().any(|rule| rule.matches_domain(domain))
    }
}

/// A single proxy rule for injecting authentication
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProxyRule {
    /// Domain pattern (e.g., "api.example.com" or "*.amazonaws.com")
    pub domain: String,

    /// Rule type
    #[serde(flatten)]
    pub rule_type: ProxyRuleType,
}

impl ProxyRule {
    /// Check if this rule matches the given domain
    pub fn matches_domain(&self, domain: &str) -> bool {
        match_domain(&self.domain, domain)
    }
}

/// Types of proxy rules
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum ProxyRuleType {
    /// Simple header injection
    #[serde(rename = "header")]
    Header {
        /// Header name
        header: String,
        /// Header value (may contain {{secret:...}} placeholders)
        value: String,
    },

    /// Bearer token injection
    #[serde(rename = "bearer")]
    Bearer {
        /// Secret path for the token
        secret: String,
    },

    /// AWS SigV4 signing
    #[serde(rename = "aws_sigv4")]
    AwsSigV4 {
        /// Secret path for access key ID
        access_key: String,
        /// Secret path for secret access key
        secret_key: String,
        /// AWS region
        region: String,
        /// AWS service (default: "execute-api")
        #[serde(default = "default_aws_service")]
        service: String,
    },

    /// Basic auth
    #[serde(rename = "basic")]
    Basic {
        /// Secret path for username
        username: String,
        /// Secret path for password
        password: String,
    },

    /// Custom auth (multi-header)
    #[serde(rename = "custom")]
    Custom {
        /// Map of header names to secret paths or values
        headers: HashMap<String, String>,
    },
}

fn default_aws_service() -> String {
    "execute-api".to_string()
}

/// Match a domain pattern against a target domain
///
/// Patterns:
/// - "example.com" matches exactly "example.com"
/// - "*.example.com" matches "foo.example.com" but not "example.com"
/// - "api.*.example.com" matches "api.foo.example.com"
pub fn match_domain(pattern: &str, target: &str) -> bool {
    if pattern == "*" {
        return true;
    }

    if !pattern.contains('*') {
        return pattern == target;
    }

    // Split by wildcard and check each part
    let parts: Vec<&str> = pattern.split('*').collect();
    if parts.is_empty() {
        return false;
    }

    let mut target_idx = 0;

    for (i, part) in parts.iter().enumerate() {
        if part.is_empty() {
            continue;
        }

        if i == 0 && !pattern.starts_with('*') {
            // First part must match at the start
            if !target.starts_with(part) {
                return false;
            }
            target_idx += part.len();
        } else if i == parts.len() - 1 && !pattern.ends_with('*') {
            // Last part must match at the end
            if !target.ends_with(part) {
                return false;
            }
        } else {
            // Middle parts must be found in order
            if let Some(pos) = target[target_idx..].find(part) {
                target_idx += pos + part.len();
            } else {
                return false;
            }
        }
    }

    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_match_domain_exact() {
        assert!(match_domain("example.com", "example.com"));
        assert!(!match_domain("example.com", "foo.example.com"));
        assert!(!match_domain("example.com", "example.org"));
    }

    #[test]
    fn test_match_domain_wildcard() {
        assert!(match_domain("*.example.com", "foo.example.com"));
        assert!(match_domain("*.example.com", "bar.example.com"));
        assert!(!match_domain("*.example.com", "example.com"));
        assert!(match_domain("*.example.com", "api.foo.example.com")); // Multi-level
    }

    #[test]
    fn test_match_domain_wildcard_any() {
        assert!(match_domain("*", "anything"));
        assert!(match_domain("*", "example.com"));
    }

    #[test]
    fn test_parse_proxy_config() {
        let toml = r#"
            listen = "127.0.0.1:8080"
            allowlist_only = true

            [[rules]]
            domain = "api.example.com"
            type = "bearer"
            secret = "example/api_key"

            [[rules]]
            domain = "*.amazonaws.com"
            type = "aws_sigv4"
            access_key = "aws/access_key_id"
            secret_key = "aws/secret_access_key"
            region = "us-east-1"
        "#;

        let config = ProxyConfig::from_toml(toml).unwrap();
        assert_eq!(config.listen, "127.0.0.1:8080");
        assert_eq!(config.rules.len(), 2);
        assert!(config.is_domain_allowed("api.example.com"));
        assert!(!config.is_domain_allowed("unknown.com"));
    }

    #[test]
    fn test_proxy_rule_matches() {
        let rule = ProxyRule {
            domain: "*.amazonaws.com".to_string(),
            rule_type: ProxyRuleType::Header {
                header: "Authorization".to_string(),
                value: "Bearer test".to_string(),
            },
        };

        assert!(rule.matches_domain("s3.amazonaws.com"));
        assert!(rule.matches_domain("ec2.us-east-1.amazonaws.com"));
        assert!(!rule.matches_domain("amazonaws.com"));
        assert!(!rule.matches_domain("example.com"));
    }
}
