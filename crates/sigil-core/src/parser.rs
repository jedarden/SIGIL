//! Command parser for extracting {{secret:path}} placeholders
//!
//! This module provides functionality to parse commands and extract
//! secret placeholders with their injection modes.

use crate::{Result, SigilError};
use regex::Regex;
use serde::{Deserialize, Serialize};

lazy_static::lazy_static! {
    /// Regex for matching {{secret:path}} placeholders with optional injection mode
    /// Format: {{secret:path[:mode[:arg]]}}
    static ref SECRET_PLACEHOLDER_REGEX: Regex = Regex::new(
        r"\{\{secret:([a-zA-Z0-9_/.-]+)(?::([a-z_]+)(?::([^\}]+))?)?\}\}"
    ).expect("Failed to compile regex");
}

/// Injection mode for a secret placeholder
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum InjectionMode {
    /// Inline substitution (default)
    Inline,
    /// Inject as environment variable
    Env,
    /// Write to tmpfs and substitute with file path
    File {
        /// Optional target path (defaults to /tmp/sigil_<sanitized_path>)
        path: Option<String>,
    },
    /// Pipe to command's stdin
    Stdin,
}

/// A placeholder for a secret in a command
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SecretPlaceholder {
    /// Full placeholder text (e.g., "{{secret:api/key}}")
    pub full_text: String,
    /// Path of the secret
    pub path: String,
    /// Injection mode
    pub mode: InjectionMode,
    /// Position in the original command (start, end)
    pub position: (usize, usize),
}

impl SecretPlaceholder {
    /// Create a new secret placeholder
    fn new(full_text: String, path: String, mode: InjectionMode, position: (usize, usize)) -> Self {
        Self {
            full_text,
            path,
            mode,
            position,
        }
    }
}

/// A resolved command with all injection instructions
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResolvedCommand {
    /// The original command string
    pub original: String,
    /// All secret placeholders found in the command
    pub placeholders: Vec<SecretPlaceholder>,
    /// The command with placeholders resolved (for execution)
    pub resolved: String,
    /// Environment variables to inject (name -> secret_path)
    pub env_injections: Vec<(String, String)>,
    /// File injections (secret_path -> target_path)
    pub file_injections: Vec<(String, String)>,
    /// Whether to use stdin injection
    pub use_stdin: bool,
    /// The secret to pipe to stdin
    pub stdin_secret: Option<String>,
}

impl ResolvedCommand {
    /// Create a new resolved command
    pub fn new(
        original: String,
        placeholders: Vec<SecretPlaceholder>,
        resolved: String,
        env_injections: Vec<(String, String)>,
        file_injections: Vec<(String, String)>,
        use_stdin: bool,
        stdin_secret: Option<String>,
    ) -> Self {
        Self {
            original,
            placeholders,
            resolved,
            env_injections,
            file_injections,
            use_stdin,
            stdin_secret,
        }
    }

    /// Check if the command has any secret placeholders
    pub fn has_secrets(&self) -> bool {
        !self.placeholders.is_empty()
    }

    /// Get all unique secret paths referenced in the command
    pub fn secret_paths(&self) -> Vec<String> {
        let mut paths = std::collections::HashSet::new();
        for placeholder in &self.placeholders {
            paths.insert(placeholder.path.clone());
        }
        paths.into_iter().collect()
    }
}

/// Parse injection mode from regex capture groups
fn parse_injection_mode(mode: Option<&str>, arg: Option<&str>) -> Result<InjectionMode> {
    match mode {
        None => Ok(InjectionMode::Inline),
        Some("env") => Ok(InjectionMode::Env),
        Some("file") => Ok(InjectionMode::File {
            path: arg.map(|s| s.to_string()),
        }),
        Some("stdin") => Ok(InjectionMode::Stdin),
        Some(unknown) => Err(SigilError::InvalidConfig(format!(
            "Unknown injection mode: {}",
            unknown
        ))),
    }
}

/// Command parser for extracting and resolving secret placeholders
pub struct CommandParser;

impl CommandParser {
    /// Extract all secret placeholders from a command string
    pub fn extract_placeholders(command: &str) -> Result<Vec<SecretPlaceholder>> {
        let mut placeholders = Vec::new();

        for capture in SECRET_PLACEHOLDER_REGEX.captures_iter(command) {
            let full_match = capture.get(0).unwrap();
            let path = capture.get(1).unwrap().as_str().to_string();
            let mode = capture.get(2).map(|m| m.as_str());
            let arg = capture.get(3).map(|m| m.as_str());

            let injection_mode = parse_injection_mode(mode, arg)?;

            placeholders.push(SecretPlaceholder::new(
                full_match.as_str().to_string(),
                path,
                injection_mode,
                (full_match.start(), full_match.end()),
            ));
        }

        Ok(placeholders)
    }

    /// Resolve a command by processing all secret placeholders
    pub fn resolve_command(command: &str) -> Result<ResolvedCommand> {
        let placeholders = Self::extract_placeholders(command)?;

        let mut env_injections = Vec::new();
        let mut file_injections = Vec::new();
        let mut use_stdin = false;
        let mut stdin_secret = None;
        let mut resolved = command.to_string();

        // Process placeholders in reverse order to preserve string positions
        let mut sorted_placeholders = placeholders.clone();
        sorted_placeholders.sort_by_key(|p| std::cmp::Reverse(p.position));

        for placeholder in &sorted_placeholders {
            match &placeholder.mode {
                InjectionMode::Inline => {
                    // For inline mode, replace with a placeholder that will be substituted later
                    // In a real implementation, this would be replaced with the actual secret value
                    let replacement =
                        format!("${{{}}}", Self::sanitize_env_name(&placeholder.path));
                    resolved.replace_range(
                        placeholder.position.0..placeholder.position.1,
                        &replacement,
                    );
                }
                InjectionMode::Env => {
                    // Generate a safe environment variable name from the path
                    let env_name = Self::sanitize_env_name(&placeholder.path);
                    env_injections.push((env_name.clone(), placeholder.path.clone()));
                    let replacement = format!("${}", env_name);
                    resolved.replace_range(
                        placeholder.position.0..placeholder.position.1,
                        &replacement,
                    );
                }
                InjectionMode::File { path } => {
                    let target_path = path.clone().unwrap_or_else(|| {
                        format!("/tmp/sigil_{}", Self::sanitize_path(&placeholder.path))
                    });
                    file_injections.push((placeholder.path.clone(), target_path.clone()));
                    let replacement = target_path.clone();
                    resolved.replace_range(
                        placeholder.position.0..placeholder.position.1,
                        &replacement,
                    );
                }
                InjectionMode::Stdin => {
                    if use_stdin {
                        return Err(SigilError::InvalidConfig(
                            "Cannot use multiple stdin injections".to_string(),
                        ));
                    }
                    use_stdin = true;
                    stdin_secret = Some(placeholder.path.clone());
                    // Remove the placeholder from the command
                    resolved.replace_range(placeholder.position.0..placeholder.position.1, "");
                }
            }
        }

        // Sort placeholders back by position for storage
        let mut placeholders = placeholders;
        placeholders.sort_by_key(|p| p.position);

        Ok(ResolvedCommand::new(
            command.to_string(),
            placeholders,
            resolved,
            env_injections,
            file_injections,
            use_stdin,
            stdin_secret,
        ))
    }

    /// Sanitize a secret path for use as an environment variable name
    fn sanitize_env_name(path: &str) -> String {
        let sanitized: String = path
            .chars()
            .map(|c| {
                if c.is_alphanumeric() || c == '_' {
                    c.to_ascii_uppercase()
                } else {
                    '_'
                }
            })
            .collect();

        // Ensure it doesn't start with a digit (invalid for env vars)
        let trimmed = sanitized.trim_start_matches('_');

        if trimmed.is_empty() {
            "SIGIL".to_string()
        } else if trimmed.chars().next().is_some_and(|c| c.is_numeric()) {
            format!("SIGIL_{}", trimmed)
        } else {
            trimmed.to_string()
        }
    }

    /// Sanitize a secret path for use as a file path
    fn sanitize_path(path: &str) -> String {
        path.chars()
            .map(|c| {
                if c.is_alphanumeric() || c == '_' || c == '-' || c == '.' {
                    c
                } else {
                    '_'
                }
            })
            .collect()
    }

    /// Validate that a command doesn't have dangerous combinations
    pub fn validate_command(command: &str) -> Result<()> {
        // Check for piped commands with inline substitutions
        if command.contains('|') {
            let placeholders = Self::extract_placeholders(command)?;
            for placeholder in &placeholders {
                if placeholder.mode == InjectionMode::Inline {
                    return Err(SigilError::InvalidConfig(
                        "Cannot use inline substitution in piped commands. Use :env mode instead."
                            .to_string(),
                    ));
                }
            }
        }

        // Check for heredocs with placeholders (basic check)
        if command.contains("<<") {
            // Heredocs with placeholders can be tricky, warn about it
            // In a production implementation, this would need more sophisticated handling
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_inline_placeholder() {
        let command = "curl https://api.example.com -H 'Authorization: {{secret:api/key}}'";
        let placeholders = CommandParser::extract_placeholders(command).unwrap();

        assert_eq!(placeholders.len(), 1);
        assert_eq!(placeholders[0].path, "api/key");
        assert_eq!(placeholders[0].mode, InjectionMode::Inline);
        assert_eq!(placeholders[0].full_text, "{{secret:api/key}}");
    }

    #[test]
    fn test_extract_env_placeholder() {
        let command = "curl https://api.example.com -H 'Authorization: {{secret:api/key:env}}'";
        let placeholders = CommandParser::extract_placeholders(command).unwrap();

        assert_eq!(placeholders.len(), 1);
        assert_eq!(placeholders[0].path, "api/key");
        assert_eq!(placeholders[0].mode, InjectionMode::Env);
    }

    #[test]
    fn test_extract_file_placeholder() {
        let command = "command --config {{secret:config/file:file}}";
        let placeholders = CommandParser::extract_placeholders(command).unwrap();

        assert_eq!(placeholders.len(), 1);
        assert_eq!(placeholders[0].path, "config/file");
        assert_eq!(placeholders[0].mode, InjectionMode::File { path: None });
    }

    #[test]
    fn test_extract_file_with_path_placeholder() {
        let command = "command --cert {{secret:certs/client:file:/etc/ssl/cert.pem}}";
        let placeholders = CommandParser::extract_placeholders(command).unwrap();

        assert_eq!(placeholders.len(), 1);
        assert_eq!(placeholders[0].path, "certs/client");
        assert_eq!(
            placeholders[0].mode,
            InjectionMode::File {
                path: Some("/etc/ssl/cert.pem".to_string())
            }
        );
    }

    #[test]
    fn test_extract_stdin_placeholder() {
        let command = "decrypt {{secret:data/key:stdin}}";
        let placeholders = CommandParser::extract_placeholders(command).unwrap();

        assert_eq!(placeholders.len(), 1);
        assert_eq!(placeholders[0].path, "data/key");
        assert_eq!(placeholders[0].mode, InjectionMode::Stdin);
    }

    #[test]
    fn test_extract_multiple_placeholders() {
        let command = "curl -H 'X-Api-Key: {{secret:api/key}}' -H 'X-Auth: {{secret:auth/token}}'";
        let placeholders = CommandParser::extract_placeholders(command).unwrap();

        assert_eq!(placeholders.len(), 2);
        assert_eq!(placeholders[0].path, "api/key");
        assert_eq!(placeholders[1].path, "auth/token");
    }

    #[test]
    fn test_resolve_inline_command() {
        let command = "echo {{secret:test/path}}";
        let resolved = CommandParser::resolve_command(command).unwrap();

        assert!(resolved.has_secrets());
        assert_eq!(resolved.placeholders.len(), 1);
        assert_eq!(resolved.secret_paths(), vec!["test/path"]);
    }

    #[test]
    fn test_resolve_env_command() {
        let command = "curl -H 'Auth: {{secret:api/key:env}}'";
        let resolved = CommandParser::resolve_command(command).unwrap();

        assert_eq!(resolved.env_injections.len(), 1);
        assert_eq!(resolved.env_injections[0].0, "API_KEY"); // Sanitized name
        assert_eq!(resolved.env_injections[0].1, "api/key");
    }

    #[test]
    fn test_resolve_stdin_command() {
        let command = "decrypt {{secret:data:stdin}}";
        let resolved = CommandParser::resolve_command(command).unwrap();

        assert!(resolved.use_stdin);
        assert_eq!(resolved.stdin_secret, Some("data".to_string()));
    }

    #[test]
    fn test_validate_piped_command_inline_fails() {
        let command = "echo {{secret:test}} | sha256sum";
        let result = CommandParser::validate_command(command);

        assert!(result.is_err());
    }

    #[test]
    fn test_validate_piped_command_env_passes() {
        let command = "echo {{secret:test:env}} | sha256sum";
        let result = CommandParser::validate_command(command);

        assert!(result.is_ok());
    }

    #[test]
    fn test_sanitize_env_name() {
        assert_eq!(CommandParser::sanitize_env_name("api/key"), "API_KEY");
        assert_eq!(CommandParser::sanitize_env_name("test-path"), "TEST_PATH");
        assert_eq!(CommandParser::sanitize_env_name("my.secret"), "MY_SECRET");
    }

    #[test]
    fn test_unknown_injection_mode_fails() {
        let command = "echo {{secret:test:unknown}}";
        let result = CommandParser::extract_placeholders(command);

        assert!(result.is_err());
    }
}
