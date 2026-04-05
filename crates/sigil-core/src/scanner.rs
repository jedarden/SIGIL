//! Project Scanner - Detects potential secret patterns in project files
//!
//! This module provides functionality to scan project files for common secret
//! patterns and suggest entries for the .sigil.toml manifest.

use crate::{SecretPath, SecretType};
use anyhow::Result;
use std::collections::HashMap;
use std::fs;
use std::path::Path;

/// Detected secret suggestion from scanning
#[derive(Debug, Clone)]
pub struct SecretSuggestion {
    /// Suggested secret path
    pub path: SecretPath,
    /// Suggested secret type
    pub secret_type: SecretType,
    /// Source file where pattern was found
    pub source_file: String,
    /// Pattern that matched
    pub pattern: String,
    /// Suggested description
    pub description: String,
}

/// Scan configuration
#[derive(Debug, Clone)]
pub struct ScanConfig {
    /// Maximum file size to scan (bytes)
    pub max_file_size: usize,
    /// Whether to scan node_modules
    pub scan_node_modules: bool,
    /// Whether to scan target directories
    pub scan_target: bool,
}

impl Default for ScanConfig {
    fn default() -> Self {
        Self {
            max_file_size: 1024 * 1024, // 1MB
            scan_node_modules: false,
            scan_target: false,
        }
    }
}

/// Project scanner for detecting secret patterns
pub struct ProjectScanner {
    config: ScanConfig,
    patterns: Vec<PatternRule>,
}

/// Pattern matching rule
#[derive(Debug, Clone)]
struct PatternRule {
    /// Pattern name/identifier
    name: &'static str,
    /// Suggested secret path template
    path_template: &'static str,
    /// Secret type for this pattern
    secret_type: SecretType,
    /// Regex pattern to match
    regex: regex::Regex,
    /// File patterns to scan (glob-style)
    file_patterns: Vec<&'static str>,
    /// Suggested description
    description: &'static str,
}

impl ProjectScanner {
    /// Create a new project scanner with default patterns
    pub fn new() -> Result<Self> {
        Self::with_config(ScanConfig::default())
    }

    /// Create a new project scanner with custom configuration
    pub fn with_config(config: ScanConfig) -> Result<Self> {
        let patterns = Self::builtin_patterns()?;
        Ok(Self { config, patterns })
    }

    /// Get built-in pattern rules
    fn builtin_patterns() -> Result<Vec<PatternRule>> {
        Ok(vec![
            // AWS credentials
            PatternRule {
                name: "aws_access_key_id",
                path_template: "aws/access_key_id",
                secret_type: SecretType::ApiKey,
                regex: regex::Regex::new(
                    r#"(?i)(aws_access_key_id|AWS_ACCESS_KEY_ID)\s*=\s*["']?([A-Z0-9]{20})["']?"#,
                )?,
                file_patterns: vec![".env", ".env.*", "config/*.env", "*.conf"],
                description: "AWS Access Key ID",
            },
            PatternRule {
                name: "aws_secret_access_key",
                path_template: "aws/secret_access_key",
                secret_type: SecretType::ApiKey,
                regex: regex::Regex::new(
                    r#"(?i)(aws_secret_access_key|AWS_SECRET_ACCESS_KEY)\s*=\s*["']?([A-Za-z0-9/+=]{40})["']?"#,
                )?,
                file_patterns: vec![".env", ".env.*", "config/*.env", "*.conf"],
                description: "AWS Secret Access Key",
            },
            // Database URLs
            PatternRule {
                name: "database_url",
                path_template: "db/{name}_url",
                secret_type: SecretType::DatabaseUrl,
                regex: regex::Regex::new(
                    r#"(?i)(database_url|db_url|mongodb_uri|redis_url)\s*=\s*["']?([a-z]+://[^"'\s]+)["']?"#,
                )?,
                file_patterns: vec![".env", ".env.*", "config/*.env", "*.toml"],
                description: "Database connection URL",
            },
            // API keys
            PatternRule {
                name: "api_key_generic",
                path_template: "api/{service}_key",
                secret_type: SecretType::ApiKey,
                regex: regex::Regex::new(
                    r#"(?i)(api_key|apikey|api-key)\s*=\s*["']?([A-Za-z0-9_\-]{16,})["']?"#,
                )?,
                file_patterns: vec![".env", ".env.*", "config/*.env"],
                description: "API key",
            },
            // GitHub tokens
            PatternRule {
                name: "github_token",
                path_template: "github/token",
                secret_type: SecretType::ApiKey,
                regex: regex::Regex::new(r"(?i)(ghp_|gho_|ghu_|ghs_|ghr_)[A-Za-z0-9]{36}")?,
                file_patterns: vec![".env", ".env.*", "*.sh", "*.yml", "*.yaml"],
                description: "GitHub personal access token",
            },
            // Stripe keys
            PatternRule {
                name: "stripe_key",
                path_template: "stripe/{env}_key",
                secret_type: SecretType::ApiKey,
                regex: regex::Regex::new(r"(?i)sk_(live|test)_[A-Za-z0-9]{24}")?,
                file_patterns: vec![".env", ".env.*", "*.env.example"],
                description: "Stripe API key",
            },
            // Slack tokens
            PatternRule {
                name: "slack_token",
                path_template: "slack/bot_token",
                secret_type: SecretType::ApiKey,
                regex: regex::Regex::new(r"xox[pbar]-[A-Za-z0-9\-]{10,}")?,
                file_patterns: vec![".env", ".env.*", "*.yml", "*.yaml"],
                description: "Slack bot token",
            },
            // JWT tokens
            PatternRule {
                name: "jwt_token",
                path_template: "auth/jwt",
                secret_type: SecretType::ApiKey,
                regex: regex::Regex::new(r"eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+")?,
                file_patterns: vec![".env", ".env.*", "*.json"],
                description: "JWT token",
            },
            // OpenAI API keys
            PatternRule {
                name: "openai_key",
                path_template: "openai/api_key",
                secret_type: SecretType::ApiKey,
                regex: regex::Regex::new(r"(?i)sk-[a-zA-Z0-9]{48}")?,
                file_patterns: vec![".env", ".env.*", "*.env.example"],
                description: "OpenAI API key",
            },
            // Docker registry tokens
            PatternRule {
                name: "docker_token",
                path_template: "docker/{registry}_token",
                secret_type: SecretType::ApiKey,
                regex: regex::Regex::new(
                    r#"(?i)docker.*auth\s*=\s*["']?([A-Za-z0-9_\-]{20,})["']?"#,
                )?,
                file_patterns: vec!["~/.docker/config.json", "*docker*.json"],
                description: "Docker registry token",
            },
            // npm tokens
            PatternRule {
                name: "npm_token",
                path_template: "npm/token",
                secret_type: SecretType::ApiKey,
                regex: regex::Regex::new(
                    r#"(?i)_authToken\s*=\s*["']?([A-Za-z0-9_\-]{20,})["']?"#,
                )?,
                file_patterns: vec![".npmrc", "~/.npmrc"],
                description: "npm authentication token",
            },
            // SSH keys (file-based)
            PatternRule {
                name: "ssh_key_file",
                path_template: "ssh/{name}_key",
                secret_type: SecretType::SshKey,
                regex: regex::Regex::new(r"-----BEGIN ([A-Z]+ )?PRIVATE KEY-----")?,
                file_patterns: vec!["*.pem", "*.key", "id_*", "*_rsa", "*_ed25519"],
                description: "SSH private key",
            },
            // PEM certificates
            PatternRule {
                name: "pem_certificate",
                path_template: "tls/{name}_cert",
                secret_type: SecretType::Certificate,
                regex: regex::Regex::new(r"-----BEGIN CERTIFICATE-----")?,
                file_patterns: vec!["*.pem", "*.crt", "*.cert"],
                description: "PEM certificate",
            },
        ])
    }

    /// Scan a project directory for secret patterns
    pub fn scan_project(&self, project_dir: &Path) -> Result<Vec<SecretSuggestion>> {
        let mut suggestions = Vec::new();
        let mut seen = HashMap::new(); // Deduplicate by pattern name and file

        self.scan_directory(project_dir, &mut suggestions, &mut seen, 0)?;

        // Sort by source file and pattern name
        suggestions.sort_by(|a, b| {
            a.source_file
                .cmp(&b.source_file)
                .then_with(|| a.pattern.cmp(&b.pattern))
        });

        Ok(suggestions)
    }

    /// Recursively scan a directory
    fn scan_directory(
        &self,
        dir: &Path,
        suggestions: &mut Vec<SecretSuggestion>,
        seen: &mut HashMap<(String, String), ()>,
        depth: usize,
    ) -> Result<()> {
        // Limit recursion depth
        if depth > 10 {
            return Ok(());
        }

        let entries = match fs::read_dir(dir) {
            Ok(e) => e,
            Err(_) => return Ok(()), // Skip unreadable directories
        };

        for entry in entries.flatten() {
            let path = entry.path();
            let file_name = match path.file_name().and_then(|n| n.to_str()) {
                Some(n) => n.to_string(),
                None => continue,
            };

            // Skip certain directories
            if path.is_dir() {
                if self.should_skip_directory(&file_name) {
                    continue;
                }
                self.scan_directory(&path, suggestions, seen, depth + 1)?;
                continue;
            }

            // Check if file should be scanned
            if !self.should_scan_file(&file_name, &path) {
                continue;
            }

            // Scan the file
            if let Ok(file_suggestions) = self.scan_file(&path) {
                for suggestion in file_suggestions {
                    let key = (suggestion.pattern.clone(), suggestion.source_file.clone());
                    if let std::collections::hash_map::Entry::Vacant(e) = seen.entry(key) {
                        e.insert(());
                        suggestions.push(suggestion);
                    }
                }
            }
        }

        Ok(())
    }

    /// Check if a directory should be skipped
    fn should_skip_directory(&self, name: &str) -> bool {
        matches!(
            name,
            "node_modules"
                | "target"
                | "vendor"
                | ".git"
                | ".svn"
                | ".hg"
                | "dist"
                | "build"
                | ".venv"
                | "venv"
                | "__pycache__"
                | ".pytest_cache"
                | "cache"
                | ".cache"
        ) || (name == "node_modules" && !self.config.scan_node_modules)
            || (name == "target" && !self.config.scan_target)
    }

    /// Check if a file should be scanned
    fn should_scan_file(&self, name: &str, path: &Path) -> bool {
        // Skip lock files
        if name.ends_with(".lock") || name == "Cargo.lock" || name == "package-lock.json" {
            return false;
        }

        // Skip binary files
        if matches!(
            path.extension().and_then(|e| e.to_str()),
            Some(
                "png"
                    | "jpg"
                    | "jpeg"
                    | "gif"
                    | "ico"
                    | "pdf"
                    | "zip"
                    | "tar"
                    | "gz"
                    | "so"
                    | "dylib"
                    | "dll"
            )
        ) {
            return false;
        }

        // Check if any pattern matches
        for pattern in &self.patterns {
            for file_pattern in &pattern.file_patterns {
                if self.matches_glob(name, file_pattern) {
                    return true;
                }
            }
        }

        // Default: scan common config file types
        matches!(
            path.extension().and_then(|e| e.to_str()),
            Some(
                "env"
                    | "toml"
                    | "yaml"
                    | "yml"
                    | "json"
                    | "conf"
                    | "ini"
                    | "sh"
                    | "rs"
                    | "js"
                    | "ts"
                    | "py"
            )
        )
    }

    /// Simple glob matching (supports * and ? wildcards)
    fn matches_glob(&self, text: &str, pattern: &str) -> bool {
        // Handle ~ prefix for home directory
        let pattern = pattern.strip_prefix("~/").unwrap_or(pattern);

        // Convert glob to regex
        let mut regex_pattern = String::new();
        let chars = pattern.chars().peekable();

        for c in chars {
            match c {
                '*' => regex_pattern.push_str("[^/]*"),
                '?' => regex_pattern.push('.'),
                '.' | '+' | '(' | ')' | '[' | ']' | '{' | '}' | '|' | '^' | '$' => {
                    regex_pattern.push('\\');
                    regex_pattern.push(c);
                }
                _ => regex_pattern.push(c),
            }
        }

        if let Ok(re) = regex::Regex::new(&format!("^{}$", regex_pattern)) {
            re.is_match(text)
        } else {
            false
        }
    }

    /// Scan a single file for secret patterns
    fn scan_file(&self, path: &Path) -> Result<Vec<SecretSuggestion>> {
        let content = match fs::read(path) {
            Ok(bytes) => bytes,
            Err(_) => return Ok(Vec::new()),
        };

        // Skip files that are too large
        if content.len() > self.config.max_file_size {
            return Ok(Vec::new());
        }

        let text = match String::from_utf8(content) {
            Ok(s) => s,
            Err(_) => return Ok(Vec::new()), // Skip binary files
        };

        let source_file = path
            .strip_prefix(Path::new("."))
            .unwrap_or(path)
            .to_string_lossy()
            .to_string();

        let mut suggestions = Vec::new();

        for pattern in &self.patterns {
            for captures in pattern.regex.captures_iter(&text) {
                let matched_text = captures.get(0).map(|m| m.as_str()).unwrap_or("");

                // Skip obvious example values
                if self.is_example_value(matched_text) {
                    continue;
                }

                // Extract service name from pattern if available
                let path = self.format_path(pattern, &captures, &text);

                suggestions.push(SecretSuggestion {
                    path: SecretPath::new(&path)?,
                    secret_type: pattern.secret_type,
                    source_file: source_file.clone(),
                    pattern: pattern.name.to_string(),
                    description: pattern.description.to_string(),
                });
            }
        }

        Ok(suggestions)
    }

    /// Check if a matched value is an example placeholder
    fn is_example_value(&self, value: &str) -> bool {
        let lower = value.to_lowercase();
        lower.contains("example")
            || lower.contains("placeholder")
            || lower.contains("your_")
            || lower.contains("replace")
            || lower.contains("xxx")
            || lower.contains("...value")
    }

    /// Format the secret path from pattern and captures
    fn format_path(
        &self,
        pattern: &PatternRule,
        captures: &regex::Captures,
        _text: &str,
    ) -> String {
        let mut path = pattern.path_template.to_string();

        // Try to extract a specific name from the match
        if let Some(name_capture) = captures.get(2) {
            let name = name_capture.as_str();
            // Use a short identifier from the matched value
            if name.len() > 3 && name.len() < 50 {
                // For env-based patterns, try to extract the service name
                if let Some(env_match) = captures.get(1) {
                    let env_var = env_match.as_str().to_lowercase();
                    if env_var.contains("production") || env_var.contains("prod") {
                        path = path.replace("{env}", "prod");
                    } else if env_var.contains("staging") || env_var.contains("stage") {
                        path = path.replace("{env}", "staging");
                    } else if env_var.contains("development") || env_var.contains("dev") {
                        path = path.replace("{env}", "dev");
                    } else if env_var.contains("test") {
                        path = path.replace("{env}", "test");
                    }
                }
            }
        }

        // Replace {name} placeholder
        if path.contains("{name}") {
            path = path.replace("{name}", "default");
        }

        // Replace {env} placeholder if not already replaced
        if path.contains("{env}") {
            path = path.replace("{env}", "production");
        }

        // Replace {service} placeholder
        if path.contains("{service}") {
            path = path.replace("{service}", "api");
        }

        path
    }
}

impl Default for ProjectScanner {
    fn default() -> Self {
        Self::new().expect("failed to create project scanner")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_scanner_creation() {
        let scanner = ProjectScanner::new();
        assert!(scanner.is_ok());
    }

    #[test]
    fn test_pattern_matching() {
        let scanner = ProjectScanner::new().unwrap();

        // Test AWS key pattern
        let aws_key_regex = &scanner.patterns[0].regex;
        assert!(aws_key_regex.is_match("AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE"));
        assert!(aws_key_regex.is_match("aws_access_key_id = 'AKIAIOSFODNN7EXAMPLE'"));
    }

    #[test]
    fn test_glob_matching() {
        let scanner = ProjectScanner::new().unwrap();
        assert!(scanner.matches_glob(".env", ".env"));
        assert!(scanner.matches_glob(".env.local", ".env.*"));
        assert!(scanner.matches_glob(".env", "*.env"));
        assert!(scanner.matches_glob("config.env", "*.env"));
        assert!(!scanner.matches_glob(".env", "*.toml"));
        assert!(scanner.matches_glob("id_rsa", "id_*"));
        assert!(scanner.matches_glob("id_ed25519", "id_*"));
        assert!(!scanner.matches_glob("other_file", "id_*"));
    }

    #[test]
    fn test_example_detection() {
        let scanner = ProjectScanner::new().unwrap();
        assert!(scanner.is_example_value("YOUR_API_KEY_HERE"));
        assert!(scanner.is_example_value("replace_with_real_key"));
        assert!(scanner.is_example_value("sk-example-key-placeholder-123"));
        assert!(!scanner.is_example_value("sk_live_abc123xyz789"));
    }

    #[test]
    fn test_should_skip_directory() {
        let config = ScanConfig::default();
        let scanner = ProjectScanner::with_config(config).unwrap();

        assert!(scanner.should_skip_directory("node_modules"));
        assert!(scanner.should_skip_directory("target"));
        assert!(scanner.should_skip_directory(".git"));
        assert!(!scanner.should_skip_directory("src"));
        assert!(!scanner.should_skip_directory("config"));
    }

    #[test]
    fn test_should_scan_file() {
        let scanner = ProjectScanner::new().unwrap();
        let path = Path::new(".env");

        assert!(scanner.should_scan_file(".env", path));
        assert!(scanner.should_scan_file("config.prod.env", Path::new("config.prod.env")));
        assert!(!scanner.should_scan_file("Cargo.lock", Path::new("Cargo.lock")));
        assert!(!scanner.should_scan_file("image.png", Path::new("image.png")));
    }

    #[test]
    fn test_path_formatting() {
        let scanner = ProjectScanner::new().unwrap();
        let pattern = &scanner.patterns[0];

        // Create a mock capture
        let re =
            regex::Regex::new(r#"(?i)(AWS_ACCESS_KEY_ID)\s*=\s*["']?([A-Z0-9]{20})["']?"#).unwrap();
        let captures = re
            .captures("AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE")
            .unwrap();

        let path = scanner.format_path(pattern, &captures, "");
        assert_eq!(path, "aws/access_key_id");
    }
}
