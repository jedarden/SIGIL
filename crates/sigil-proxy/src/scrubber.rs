//! Response body scrubbing for leaked credentials

use aho_corasick::{AhoCorasick, MatchKind, PatternID};
use regex::Regex;
use std::collections::HashSet;

/// Context for scrubbing responses
#[derive(Debug, Clone)]
pub struct ScrubContext {
    /// Secret values that should be scrubbed
    pub secrets: Vec<String>,
    /// Additional patterns to scrub
    pub patterns: Vec<String>,
}

impl ScrubContext {
    /// Create a new scrub context
    pub fn new() -> Self {
        Self {
            secrets: Vec::new(),
            patterns: Vec::new(),
        }
    }

    /// Add a secret value to scrub
    pub fn add_secret(&mut self, secret: String) {
        self.secrets.push(secret);
    }

    /// Add a pattern to scrub
    pub fn add_pattern(&mut self, pattern: String) {
        self.patterns.push(pattern);
    }

    /// Check if empty
    pub fn is_empty(&self) -> bool {
        self.secrets.is_empty() && self.patterns.is_empty()
    }
}

impl Default for ScrubContext {
    fn default() -> Self {
        Self::new()
    }
}

/// Response scrubber for removing leaked credentials
pub struct ResponseScrubber {
    /// Compiled Aho-Corasick automaton for literal secret matching
    ac: AhoCorasick,
    /// Pattern IDs that are secrets (vs generic patterns)
    secret_ids: HashSet<PatternID>,
    /// Compiled regex patterns for pattern-based matching
    regex_patterns: Vec<Regex>,
}

impl ResponseScrubber {
    /// Create a new scrubber from a context
    pub fn new(ctx: &ScrubContext) -> Result<Self, crate::ProxyError> {
        if ctx.is_empty() {
            // Create a no-op scrubber with a single dummy pattern
            return Ok(Self {
                ac: AhoCorasick::builder()
                    .match_kind(MatchKind::LeftmostLongest)
                    .build(["__SIGIL_NOOP_PATTERN__"])?,
                secret_ids: HashSet::new(),
                regex_patterns: Vec::new(),
            });
        }

        let mut secret_patterns = Vec::new();
        let mut secret_ids = HashSet::new();
        let mut regex_patterns = Vec::new();

        // Add secrets as literal patterns (fast aho-corasick matching)
        for (i, secret) in ctx.secrets.iter().enumerate() {
            secret_patterns.push(secret.clone());
            secret_ids.insert(PatternID::new(i).unwrap());
        }

        // Add patterns as regex (for pattern-based matching)
        for pattern in &ctx.patterns {
            match Regex::new(pattern) {
                Ok(re) => regex_patterns.push(re),
                Err(e) => {
                    tracing::warn!("Invalid regex pattern '{}': {}", pattern, e);
                    // Continue with other patterns
                }
            }
        }

        // Build aho-corasick for literal secret matching
        let ac = if secret_patterns.is_empty() {
            // No secrets, create a no-op automaton
            AhoCorasick::builder()
                .match_kind(MatchKind::LeftmostLongest)
                .build(["__SIGIL_NOOP_PATTERN__"])?
        } else {
            AhoCorasick::builder()
                .match_kind(MatchKind::LeftmostLongest)
                .build(&secret_patterns)?
        };

        Ok(Self {
            ac,
            secret_ids,
            regex_patterns,
        })
    }

    /// Scrub a response body
    pub fn scrub(&self, body: &str) -> String {
        if self.regex_patterns.is_empty() && self.secret_ids.is_empty() {
            return body.to_string();
        }

        let mut result = body.to_string();

        // First, use aho-corasick for fast literal secret matching
        if !self.secret_ids.is_empty() {
            let replacements: Vec<&str> = vec!["***"; self.ac.patterns_len()];
            result = self.ac.replace_all(&result, &replacements);
        }

        // Then, apply regex patterns
        for regex in &self.regex_patterns {
            result = regex.replace_all(&result, "***").to_string();
        }

        result
    }

    /// Scrub with different replacement for secrets vs patterns
    pub fn scrub_with_replacements(
        &self,
        body: &str,
        secret_repl: &str,
        pattern_repl: &str,
    ) -> String {
        if self.regex_patterns.is_empty() && self.secret_ids.is_empty() {
            return body.to_string();
        }

        let mut result = body.to_string();

        // First, use aho-corasick for fast literal secret matching
        if !self.secret_ids.is_empty() {
            let replacements: Vec<&str> = vec![secret_repl; self.ac.patterns_len()];
            result = self.ac.replace_all(&result, &replacements);
        }

        // Then, apply regex patterns with pattern replacement
        for regex in &self.regex_patterns {
            result = regex.replace_all(&result, pattern_repl).to_string();
        }

        result
    }
}

/// Default patterns for common credential formats
pub fn default_credential_patterns() -> Vec<String> {
    vec![
        // AWS keys
        r"(?i)AKIA[0-9A-Z]{16}".to_string(),
        // GitHub tokens
        r"(?i)ghp_[a-zA-Z0-9]{36}".to_string(),
        r"(?i)gho_[a-zA-Z0-9]{36}".to_string(),
        r"(?i)ghu_[a-zA-Z0-9]{36}".to_string(),
        r"(?i)ghs_[a-zA-Z0-9]{36}".to_string(),
        r"(?i)ghr_[a-zA-Z0-9]{36}".to_string(),
        // Stripe keys
        r"(?i)sk_live_[a-zA-Z0-9]{24}".to_string(),
        r"(?i)sk_test_[a-zA-Z0-9]{24}".to_string(),
        // Slack tokens
        r"xox[pbar]-[a-zA-Z0-9-]+".to_string(),
        // Bearer tokens (generic)
        r"(?i)Bearer\s+[a-zA-Z0-9_\-\.=]+".to_string(),
        // API keys (generic)
        r"(?i)api[_-]?key\s*[:=]\s*[a-zA-Z0-9_\-\.=]+".to_string(),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_scrub_no_secrets() {
        let ctx = ScrubContext::new();
        let scrubber = ResponseScrubber::new(&ctx).unwrap();
        let body = "This is a normal response";
        assert_eq!(scrubber.scrub(body), body);
    }

    #[test]
    fn test_scrub_with_secret() {
        let mut ctx = ScrubContext::new();
        ctx.add_secret("secret123".to_string());
        let scrubber = ResponseScrubber::new(&ctx).unwrap();

        let body = "The secret is secret123 and here's more text";
        let scrubbed = scrubber.scrub(body);
        assert!(scrubbed.contains("***"));
        assert!(!scrubbed.contains("secret123"));
    }

    #[test]
    fn test_scrub_with_aws_key() {
        let ctx = ScrubContext {
            secrets: vec![],
            patterns: vec![r"(?i)AKIA[0-9A-Z]{16}".to_string()],
        };
        let scrubber = ResponseScrubber::new(&ctx).unwrap();

        let body = r#"{"access_key": "AKIAIOSFODNN7EXAMPLE", "user": "test"}"#;
        let scrubbed = scrubber.scrub(body);
        assert!(!scrubbed.contains("AKIAIOSFODNN7EXAMPLE"));
        assert!(scrubbed.contains("***"));
    }

    #[test]
    fn test_scrub_with_multiple_secrets() {
        let mut ctx = ScrubContext::new();
        ctx.add_secret("password123".to_string());
        ctx.add_secret("token_abc".to_string());
        let scrubber = ResponseScrubber::new(&ctx).unwrap();

        let body = "password=token_abc&secret=password123";
        let scrubbed = scrubber.scrub(body);
        assert!(!scrubbed.contains("password123"));
        assert!(!scrubbed.contains("token_abc"));
        // Should have replaced both
        assert!(scrubbed.matches("***").count() >= 2);
    }

    #[test]
    fn test_default_patterns() {
        let patterns = default_credential_patterns();
        assert!(patterns.iter().any(|p| p.contains("AKIA")));
        assert!(patterns.iter().any(|p| p.contains("ghp_")));
        assert!(patterns.iter().any(|p| p.contains("sk_live_")));
    }

    #[test]
    fn test_scrub_with_replacements() {
        let mut ctx = ScrubContext::new();
        ctx.add_secret("secret123".to_string());
        ctx.add_pattern(r"(?i)AKIA[0-9A-Z]{16}".to_string());
        let scrubber = ResponseScrubber::new(&ctx).unwrap();

        let body = "Key: AKIAIOSFODNN7EXAMPLE, Token: secret123";
        let scrubbed = scrubber.scrub_with_replacements(body, "[REDACTED]", "[MASKED]");
        assert!(scrubbed.contains("[REDACTED]")); // secret
        assert!(scrubbed.contains("[MASKED]")); // pattern
        assert!(!scrubbed.contains("secret123"));
        assert!(!scrubbed.contains("AKIAIOSFODNN7EXAMPLE"));
    }
}
