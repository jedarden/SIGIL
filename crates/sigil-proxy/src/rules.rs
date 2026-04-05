//! Rule matching and secret resolution

use crate::config::ProxyRule;
use std::collections::HashMap;

/// A matched rule with resolved secret values
#[derive(Debug, Clone)]
pub struct MatchedRule {
    /// The original rule
    pub rule: ProxyRule,
    /// Resolved headers to inject
    pub headers: HashMap<String, String>,
    /// Secret paths that were accessed
    pub secret_paths: Vec<String>,
}

impl MatchedRule {
    /// Create a new matched rule from a proxy rule
    pub fn new(
        rule: ProxyRule,
        headers: HashMap<String, String>,
        secret_paths: Vec<String>,
    ) -> Self {
        Self {
            rule,
            headers,
            secret_paths,
        }
    }

    /// Get all headers as an iterator
    pub fn iter_headers(&self) -> impl Iterator<Item = (&str, &str)> {
        self.headers.iter().map(|(k, v)| (k.as_str(), v.as_str()))
    }
}

// DomainMatcher was removed - ProxyConfig implements matching directly
// via find_rule_for_domain() and is_domain_allowed() methods.

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::ProxyRuleType;

    fn create_test_rules() -> Vec<ProxyRule> {
        vec![
            ProxyRule {
                domain: "api.example.com".to_string(),
                rule_type: ProxyRuleType::Header {
                    header: "Authorization".to_string(),
                    value: "Bearer test".to_string(),
                },
            },
            ProxyRule {
                domain: "*.amazonaws.com".to_string(),
                rule_type: ProxyRuleType::AwsSigV4 {
                    access_key: "aws/access_key_id".to_string(),
                    secret_key: "aws/secret_access_key".to_string(),
                    region: "us-east-1".to_string(),
                    service: "s3".to_string(),
                },
            },
        ]
    }

    #[test]
    fn test_matched_rule_creation() {
        let rule = create_test_rules().remove(0);
        let mut headers = std::collections::HashMap::new();
        headers.insert("Authorization".to_string(), "Bearer test".to_string());

        let matched = MatchedRule::new(rule, headers, vec!["test/path".to_string()]);

        assert_eq!(matched.secret_paths.len(), 1);
        assert_eq!(matched.secret_paths[0], "test/path");
    }

    #[test]
    fn test_matched_rule_iter_headers() {
        let mut headers = std::collections::HashMap::new();
        headers.insert("Authorization".to_string(), "Bearer xyz".to_string());
        headers.insert("X-Custom".to_string(), "value".to_string());

        let rule = create_test_rules().remove(0);
        let matched = MatchedRule::new(rule, headers, vec![]);

        let header_vec: Vec<(&str, &str)> = matched.iter_headers().collect();
        assert_eq!(header_vec.len(), 2);
    }
}
