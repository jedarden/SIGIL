//! Signature configuration types and TOML parsing
//!
//! Defines the structure for command signatures including:
//! - Match patterns (regex)
//! - Injection types (env, file, header)
//! - Secret path mappings
//! - Optional flags

use regex::Regex;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::Path;

/// Signature configuration loaded from TOML files
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct SignatureConfig {
    /// Signature definitions indexed by name
    #[serde(default)]
    pub signatures: HashMap<String, Signature>,
}

impl SignatureConfig {
    /// Create an empty signature config
    pub fn new() -> Self {
        Self {
            signatures: HashMap::new(),
        }
    }

    /// Add a signature to the config
    pub fn add_signature(&mut self, name: String, signature: Signature) {
        self.signatures.insert(name, signature);
    }

    /// Load signature config from a TOML file
    pub fn from_file<P: AsRef<Path>>(path: P) -> sigil_core::Result<Self> {
        let content = std::fs::read_to_string(path.as_ref()).map_err(|e| {
            sigil_core::SigilError::IoError(format!("Failed to read signature file: {}", e))
        })?;

        let config: SignaturesToml = toml::from_str(&content).map_err(|e| {
            sigil_core::SigilError::InvalidConfig(format!("Failed to parse signature TOML: {}", e))
        })?;

        Ok(config.into())
    }

    /// Merge another signature config into this one
    ///
    /// Existing signatures are replaced by the incoming config.
    pub fn merge(&mut self, other: SignatureConfig) {
        for (name, signature) in other.signatures {
            self.signatures.insert(name, signature);
        }
    }

    /// Get all signatures
    pub fn get_all(&self) -> Vec<(String, Signature)> {
        self.signatures
            .iter()
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect()
    }
}

impl Default for SignatureConfig {
    fn default() -> Self {
        Self::new()
    }
}

/// Root TOML structure for signatures files
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct SignaturesToml {
    /// Signature definitions
    pub signatures: HashMap<String, Signature>,
}

impl From<SignaturesToml> for SignatureConfig {
    fn from(toml: SignaturesToml) -> Self {
        Self {
            signatures: toml.signatures,
        }
    }
}

/// A single command signature
///
/// Defines how to match a command and what secrets to inject.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Signature {
    /// Regex pattern to match the command
    pub match_pattern: String,

    /// List of injections to perform when this signature matches
    #[serde(default)]
    pub inject: Vec<InjectionConfig>,

    /// Optional description of what this signature does
    #[serde(default)]
    pub description: Option<String>,

    /// Whether this signature is enabled
    #[serde(default = "default_enabled")]
    pub enabled: bool,
}

fn default_enabled() -> bool {
    true
}

impl Signature {
    /// Get the compiled regex for this signature
    pub fn regex(&self) -> sigil_core::Result<Regex> {
        Regex::new(&self.match_pattern).map_err(|e| {
            sigil_core::SigilError::InvalidConfig(format!(
                "Invalid regex pattern '{}': {}",
                self.match_pattern, e
            ))
        })
    }

    /// Check if this signature matches a command string
    pub fn matches(&self, command: &str) -> sigil_core::Result<bool> {
        Ok(self.regex()?.is_match(command))
    }
}

/// Configuration for a single injection
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct InjectionConfig {
    /// Type of injection (env, file, header)
    #[serde(flatten)]
    pub injection_type: InjectionType,

    /// Secret path in the vault (e.g., "aws/access_key_id")
    pub secret: String,

    /// Whether this injection is optional (skip if secret doesn't exist)
    #[serde(default)]
    pub optional: bool,

    /// Whether to clean up temporary files after execution
    #[serde(default)]
    pub cleanup: bool,
}

/// Type of injection to perform
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(tag = "type")]
pub enum InjectionType {
    /// Environment variable injection
    /// ```toml
    /// { type = "env", name = "API_KEY", secret = "api/key" }
    /// ```
    Env {
        /// Environment variable name
        name: String,
    },

    /// File injection
    /// ```toml
    /// { type = "file", path = "/tmp/kubeconfig", secret = "k8s/kubeconfig" }
    /// ```
    File {
        /// File path where the secret will be written
        path: String,
    },

    /// HTTP header injection (for curl, httpie, etc.)
    /// ```toml
    /// { type = "header", name = "Authorization", secret = "api/token", format = "Bearer {value}" }
    /// ```
    Header {
        /// Header name
        name: String,
        /// Format string with {value} placeholder
        #[serde(default = "default_header_format")]
        format: String,
    },
}

fn default_header_format() -> String {
    "{value}".to_string()
}

impl InjectionType {
    /// Get a descriptive name for this injection type
    pub fn type_name(&self) -> &str {
        match self {
            InjectionType::Env { .. } => "env",
            InjectionType::File { .. } => "file",
            InjectionType::Header { .. } => "header",
        }
    }

    /// Get the target name/path for this injection
    pub fn target(&self) -> String {
        match self {
            InjectionType::Env { name } => name.clone(),
            InjectionType::File { path } => path.clone(),
            InjectionType::Header { name, .. } => name.clone(),
        }
    }

    /// Format the secret value for this injection type
    pub fn format_value(&self, value: &str) -> String {
        match self {
            InjectionType::Env { .. } => value.to_string(),
            InjectionType::File { .. } => value.to_string(),
            InjectionType::Header { format, .. } => format.replace("{value}", value),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_signature_config_new() {
        let config = SignatureConfig::new();
        assert!(config.signatures.is_empty());
    }

    #[test]
    fn test_signature_config_add() {
        let mut config = SignatureConfig::new();
        let signature = Signature {
            match_pattern: "^aws\\s".to_string(),
            inject: vec![],
            description: None,
            enabled: true,
        };
        config.add_signature("aws".to_string(), signature);
        assert_eq!(config.signatures.len(), 1);
    }

    #[test]
    fn test_signature_matches() {
        let signature = Signature {
            match_pattern: "^aws\\s".to_string(),
            inject: vec![],
            description: None,
            enabled: true,
        };

        assert!(signature.matches("aws s3 ls").unwrap());
        assert!(signature.matches("aws ec2 describe-instances").unwrap());
        assert!(!signature.matches("echo aws").unwrap());
        assert!(!signature.matches("kubectl").unwrap());
    }

    #[test]
    fn test_injection_type_target() {
        let env = InjectionType::Env {
            name: "API_KEY".to_string(),
        };
        assert_eq!(env.target(), "API_KEY");

        let file = InjectionType::File {
            path: "/tmp/kubeconfig".to_string(),
        };
        assert_eq!(file.target(), "/tmp/kubeconfig");

        let header = InjectionType::Header {
            name: "Authorization".to_string(),
            format: "Bearer {value}".to_string(),
        };
        assert_eq!(header.target(), "Authorization");
    }

    #[test]
    fn test_injection_type_format_value() {
        let env = InjectionType::Env {
            name: "API_KEY".to_string(),
        };
        assert_eq!(env.format_value("secret123"), "secret123");

        let header = InjectionType::Header {
            name: "Authorization".to_string(),
            format: "Bearer {value}".to_string(),
        };
        assert_eq!(header.format_value("token123"), "Bearer token123");

        let basic_auth = InjectionType::Header {
            name: "Authorization".to_string(),
            format: "Basic {value}".to_string(),
        };
        assert_eq!(basic_auth.format_value("creds"), "Basic creds");
    }
}
