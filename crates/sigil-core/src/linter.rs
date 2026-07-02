//! Secret linting and detection module.
//!
//! Provides shared logic for detecting potential secret leaks in source code,
//! used by both CLI and daemon.

use crate::ipc::SecretFinding;
use regex::Regex;
use std::path::Path;

/// Secret pattern definition
#[derive(Debug, Clone, Copy)]
pub struct SecretPattern {
    /// Regex pattern to match the secret
    pub pattern: &'static str,
    /// Human-readable type name
    pub secret_type: &'static str,
    /// Suggested vault path prefix
    pub vault_path: &'static str,
}

/// Default secret patterns for linting
pub fn default_patterns() -> &'static [SecretPattern] {
    &[
        SecretPattern {
            pattern: r#"(?i)api[_-]?key\s*=\s*["']?([a-zA-Z0-9]{20,})["']?"#,
            secret_type: "API Key",
            vault_path: "api_key",
        },
        SecretPattern {
            pattern: r#"(?i)database[_-]?url\s*=\s*["']?([a-zA-Z0-9+]+://[^\s"']+)["']?"#,
            secret_type: "Database URL",
            vault_path: "database_url",
        },
        SecretPattern {
            pattern: r#"(?i)jwt[_-]?token\s*=\s*[']?([a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+)[']?"#,
            secret_type: "JWT Token",
            vault_path: "jwt_token",
        },
        SecretPattern {
            pattern: r#"(?i)password\s*=\s*[']?([^\s']{8,})[']?"#,
            secret_type: "Password",
            vault_path: "password",
        },
        SecretPattern {
            pattern: r#"(?i)secret[_-]?token\s*=\s*[']?([a-zA-Z0-9]{20,})[']?"#,
            secret_type: "Secret Token",
            vault_path: "secret_token",
        },
        SecretPattern {
            pattern: r#"(?i)aws[_-]?(access[_-]?key[_-]?id)\s*=\s*[']?([A-Z0-9]{20})[']?"#,
            secret_type: "AWS Access Key",
            vault_path: "aws_access_key_id",
        },
        SecretPattern {
            pattern: r#"(?i)aws[_-]?(secret[_-]?access[_-]?key)\s*=\s*[']?([a-zA-Z0-9/+]{40})[']?"#,
            secret_type: "AWS Secret Key",
            vault_path: "aws_secret_access_key",
        },
        SecretPattern {
            pattern: r#"(?i)(github|gitlab)[_-]?token\s*=\s*[']?([a-zA-Z0-9]{20,})[']?"#,
            secret_type: "Git Token",
            vault_path: "git_token",
        },
    ]
}

/// Linter configuration
#[derive(Debug, Clone, Default)]
pub struct LinterConfig {
    /// Custom patterns (if None, uses default patterns)
    pub patterns: Option<Vec<SecretPattern>>,
}

/// Secret linter for detecting potential secret leaks
pub struct SecretLinter {
    _config: LinterConfig,
}

impl SecretLinter {
    /// Create a new linter with default configuration
    pub fn new() -> Self {
        Self::with_config(LinterConfig::default())
    }

    /// Create a new linter with custom configuration
    pub fn with_config(config: LinterConfig) -> Self {
        Self { _config: config }
    }

    /// Get the patterns to use (default or custom)
    fn patterns(&self) -> &'static [SecretPattern] {
        // Always use default patterns for now
        // Custom pattern support can be added later with a different design
        default_patterns()
    }

    /// Detect a secret in a single line of text
    ///
    /// Returns `None` if no secret is detected, or `Some(SecretFinding)` if a secret is found.
    pub fn detect_secret(&self, line: &str, file: &str, line_num: usize) -> Option<SecretFinding> {
        for pattern_def in self.patterns() {
            if let Ok(re) = Regex::new(pattern_def.pattern) {
                if let Some(caps) = re.captures(line) {
                    // Get the matched value (last capture group)
                    if caps.len() > 0 {
                        let value = caps.get(caps.len() - 1).map(|m| m.as_str()).unwrap_or("");

                        // Skip obvious false positives
                        if value.len() < 8
                            || value == "***"
                            || value == "****"
                            || value.contains('<')
                        {
                            continue;
                        }

                        return Some(SecretFinding {
                            secret_type: pattern_def.secret_type.to_string(),
                            file: file.to_string(),
                            line: line_num,
                            line_content: line.to_string(),
                            placeholder: Some(format!(
                                "{}=***",
                                pattern_def.secret_type.to_lowercase().replace(' ', "_")
                            )),
                            suggested_vault_path: Some(pattern_def.vault_path.to_string()),
                        });
                    }
                }
            }
        }

        None
    }

    /// Scan a single file for secret patterns
    ///
    /// Returns a vector of findings, or an error if the file cannot be read.
    pub fn scan_file(&self, path: &Path) -> Result<Vec<SecretFinding>, std::io::Error> {
        let content = std::fs::read_to_string(path)?;
        let file_name = path.display().to_string();
        let mut findings = Vec::new();

        // Scan line by line
        for (line_num, line) in content.lines().enumerate() {
            if let Some(finding) = self.detect_secret(line, &file_name, line_num + 1) {
                findings.push(finding);
            }
        }

        Ok(findings)
    }

    /// Scan multiple files for secret patterns
    ///
    /// Returns a vector of all findings across all files.
    pub fn scan_files(&self, paths: &[&Path]) -> Vec<SecretFinding> {
        let mut all_findings = Vec::new();

        for path in paths {
            if let Ok(metadata) = std::fs::metadata(path) {
                if metadata.is_file() {
                    if let Ok(file_findings) = self.scan_file(path) {
                        all_findings.extend(file_findings);
                    }
                }
            }
        }

        all_findings
    }
}

impl Default for SecretLinter {
    fn default() -> Self {
        Self::new()
    }
}

/// Get list of staged files from git
///
/// Returns files that are staged for commit (added, copied, or modified).
pub fn get_staged_files() -> Result<Vec<std::path::PathBuf>, anyhow::Error> {
    use std::process::Command;

    let output = Command::new("git")
        .args(["diff", "--cached", "--name-only", "--diff-filter=ACM"])
        .output()?;

    if !output.status.success() {
        anyhow::bail!("Failed to get staged files. Is this a git repository?");
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    let mut files = Vec::new();

    for line in stdout.lines() {
        if !line.is_empty() {
            files.push(std::path::PathBuf::from(line));
        }
    }

    Ok(files)
}

/// Collect all files in a directory recursively
///
/// Skips hidden directories and common non-source directories (node_modules, target, vendor, .git, etc.).
/// Only scans text files with common extensions.
pub fn collect_files_in_directory(
    dir: &std::path::Path,
) -> Result<Vec<std::path::PathBuf>, anyhow::Error> {
    use std::fs;

    let mut files = Vec::new();
    let entries = fs::read_dir(dir)?;

    for entry in entries {
        let entry = entry?;
        let path = entry.path();

        if path.is_dir() {
            // Skip hidden directories and common non-source directories
            if let Some(name) = path.file_name() {
                let name_str = name.to_string_lossy();
                if name_str.starts_with('.')
                    || [
                        "node_modules",
                        "target",
                        "vendor",
                        ".git",
                        "dist",
                        "build",
                        ".venv",
                        "venv",
                        "__pycache__",
                        ".pytest_cache",
                        "cache",
                        ".cache",
                    ]
                    .contains(&name_str.as_ref())
                {
                    continue;
                }
                files.extend(collect_files_in_directory(&path)?);
            }
        } else if path.is_file() {
            // Only scan text files
            if let Some(ext) = path.extension() {
                let ext_str = ext.to_string_lossy();
                if [
                    "env", "txt", "md", "json", "yaml", "yml", "toml", "ini", "conf", "sh", "bash",
                    "rs", "py", "js", "ts", "tsx", "jsx", "go", "java", "php", "rb", "cs", "cpp",
                    "c", "h", "hpp", "swift", "kt", "scala",
                ]
                .contains(&ext_str.as_ref())
                {
                    files.push(path);
                }
            }
        }
    }

    Ok(files)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_detect_api_key() {
        let linter = SecretLinter::new();
        let line = r#"api_key = "a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6""#;
        let result = linter.detect_secret(line, "test.env", 1);
        assert!(result.is_some());
        let finding = result.unwrap();
        assert_eq!(finding.secret_type, "API Key");
        assert_eq!(finding.line, 1);
    }

    #[test]
    fn test_ignore_false_positives() {
        let linter = SecretLinter::new();

        // Too short
        assert!(linter
            .detect_secret(r#"api_key = "short""#, "test.env", 1)
            .is_none());

        // Masked values
        assert!(linter
            .detect_secret(r#"api_key = "***""#, "test.env", 1)
            .is_none());
        assert!(linter
            .detect_secret(r#"api_key = "****""#, "test.env", 1)
            .is_none());

        // HTML/HTML-like
        assert!(linter
            .detect_secret(r#"api_key = "<div>""#, "test.env", 1)
            .is_none());
    }

    #[test]
    fn test_detect_database_url() {
        let linter = SecretLinter::new();
        let line = r#"database_url = "postgresql://user:pass@localhost/db""#;
        let result = linter.detect_secret(line, "config.toml", 1);
        assert!(result.is_some());
        assert_eq!(result.unwrap().secret_type, "Database URL");
    }
}
