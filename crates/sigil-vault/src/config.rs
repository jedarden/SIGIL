//! SIGIL project configuration
//!
//! This module provides project-level configuration for SIGIL vaults.
//! The configuration file (.sigil/config.toml) contains non-secret metadata
//! that can be committed to git and shared across a team.

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};

/// Current config format version
pub const CONFIG_FORMAT_VERSION: u16 = 1;

/// SIGIL project configuration
///
/// This configuration file contains non-secret vault metadata that can be
/// safely committed to version control. It includes format version, KDF
/// parameters (algorithm name and parameter values, not keys), and auth
/// factors (which factors are required).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SigilConfig {
    /// Config format version
    pub format_version: u16,

    /// Vault configuration
    #[serde(default)]
    pub vault: VaultConfig,

    /// Project-specific settings
    #[serde(default)]
    pub project: ProjectConfig,
}

impl Default for SigilConfig {
    fn default() -> Self {
        Self {
            format_version: CONFIG_FORMAT_VERSION,
            vault: VaultConfig::default(),
            project: ProjectConfig::default(),
        }
    }
}

/// Vault configuration section
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VaultConfig {
    /// Path to the vault file (relative to project root)
    pub path: String,

    /// KDF configuration
    #[serde(default)]
    pub kdf_params: KdfParams,

    /// Auth factors required to unseal the vault
    #[serde(default)]
    pub auth_factors: AuthFactorsConfig,
}

impl Default for VaultConfig {
    fn default() -> Self {
        Self {
            path: ".sigil/vault.sealed".to_string(),
            kdf_params: KdfParams::default(),
            auth_factors: AuthFactorsConfig::default(),
        }
    }
}

/// KDF (Key Derivation Function) parameters
///
/// These parameters describe the KDF algorithm and its settings.
/// The actual keys are NOT stored here - only the algorithm name
/// and parameter values.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KdfParams {
    /// KDF algorithm (e.g., "argon2id")
    pub algorithm: String,

    /// Memory cost in bytes
    pub memory_cost: u32,

    /// Number of iterations
    pub iterations: u32,

    /// Parallelism factor
    pub parallelism: u32,

    /// Salt length in bytes
    pub salt_length: u32,
}

impl Default for KdfParams {
    fn default() -> Self {
        Self {
            algorithm: "argon2id".to_string(),
            memory_cost: 1_073_741_824, // 1 GiB
            iterations: 3,
            parallelism: 4,
            salt_length: 32,
        }
    }
}

/// Auth factors configuration
///
/// This describes which authentication factors are required to unseal the vault.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthFactorsConfig {
    /// Passphrase is required
    #[serde(default)]
    pub passphrase: bool,

    /// Device key is required
    #[serde(default)]
    pub device: bool,

    /// TOTP is required
    #[serde(default)]
    pub totp: bool,

    /// FIDO2 hmac-secret is required
    #[serde(default)]
    pub fido2: bool,
}

impl Default for AuthFactorsConfig {
    fn default() -> Self {
        Self {
            passphrase: true,
            device: true,
            totp: false,
            fido2: false,
        }
    }
}

impl AuthFactorsConfig {
    /// Get the auth factors as a bitmask
    pub fn as_bitmask(&self) -> u8 {
        let mut mask = 0;
        if self.passphrase {
            mask |= 0x01;
        }
        if self.device {
            mask |= 0x02;
        }
        if self.totp {
            mask |= 0x04;
        }
        if self.fido2 {
            mask |= 0x08;
        }
        mask
    }

    /// Create from bitmask
    pub fn from_bitmask(mask: u8) -> Self {
        Self {
            passphrase: mask & 0x01 != 0,
            device: mask & 0x02 != 0,
            totp: mask & 0x04 != 0,
            fido2: mask & 0x08 != 0,
        }
    }
}

/// Project-specific configuration
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ProjectConfig {
    /// Project name
    #[serde(default)]
    pub name: Option<String>,

    /// Project description
    #[serde(default)]
    pub description: Option<String>,

    /// Signature mappings for transparent command recognition
    #[serde(default)]
    pub signature_mappings: Vec<SignatureMapping>,
}

/// Signature mapping for transparent command recognition
///
/// This maps command patterns to secret paths for auto-injection.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignatureMapping {
    /// Unique identifier for this mapping
    pub id: String,

    /// Command pattern (regex)
    pub pattern: String,

    /// Secret path to inject
    pub secret_path: String,

    /// Injection type (env, file, header)
    #[serde(default = "default_injection_type")]
    pub injection_type: String,

    /// Target (e.g., environment variable name, file path, header name)
    pub target: String,

    /// Whether this secret is optional
    #[serde(default)]
    pub optional: bool,
}

fn default_injection_type() -> String {
    "env".to_string()
}

/// SIGIL project configuration manager
pub struct SigilConfigManager {
    /// Path to the config file
    config_path: PathBuf,
}

impl SigilConfigManager {
    /// Create a new config manager for the given directory
    pub fn new(project_dir: &Path) -> Self {
        let config_path = project_dir.join(".sigil").join("config.toml");
        Self { config_path }
    }

    /// Load the configuration from the project directory
    pub fn load(&self) -> Result<Option<SigilConfig>> {
        if !self.config_path.exists() {
            return Ok(None);
        }

        let content = fs::read_to_string(&self.config_path)
            .with_context(|| format!("Failed to read {}", self.config_path.display()))?;

        let config: SigilConfig = toml::from_str(&content)
            .with_context(|| format!("Failed to parse {}", self.config_path.display()))?;

        Ok(Some(config))
    }

    /// Save the configuration to the project directory
    pub fn save(&self, config: &SigilConfig) -> Result<()> {
        // Ensure the .sigil directory exists
        if let Some(parent) = self.config_path.parent() {
            fs::create_dir_all(parent)
                .with_context(|| format!("Failed to create {}", parent.display()))?;
        }

        // Serialize to TOML
        let content =
            toml::to_string_pretty(config).context("Failed to serialize config to TOML")?;

        // Write to file
        fs::write(&self.config_path, content)
            .with_context(|| format!("Failed to write {}", self.config_path.display()))?;

        Ok(())
    }

    /// Get the config file path
    pub fn config_path(&self) -> &Path {
        &self.config_path
    }

    /// Initialize a new config file with defaults
    pub fn init(&self) -> Result<SigilConfig> {
        let config = SigilConfig::default();
        self.save(&config)?;
        Ok(config)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_config_default() {
        let config = SigilConfig::default();
        assert_eq!(config.format_version, CONFIG_FORMAT_VERSION);
        assert_eq!(config.vault.path, ".sigil/vault.sealed");
        assert!(config.vault.auth_factors.passphrase);
        assert!(config.vault.auth_factors.device);
    }

    #[test]
    fn test_kdf_params_default() {
        let params = KdfParams::default();
        assert_eq!(params.algorithm, "argon2id");
        assert_eq!(params.memory_cost, 1_073_741_824);
        assert_eq!(params.iterations, 3);
        assert_eq!(params.parallelism, 4);
    }

    #[test]
    fn test_auth_factors_bitmask() {
        let factors = AuthFactorsConfig::default();
        let mask = factors.as_bitmask();
        assert_eq!(mask, 0x03); // passphrase + device

        let restored = AuthFactorsConfig::from_bitmask(mask);
        assert!(restored.passphrase);
        assert!(restored.device);
        assert!(!restored.totp);
        assert!(!restored.fido2);
    }

    #[test]
    fn test_signature_mapping() {
        let mapping = SignatureMapping {
            id: "aws-cred".to_string(),
            pattern: "^aws\\s".to_string(),
            secret_path: "aws/access_key_id".to_string(),
            injection_type: "env".to_string(),
            target: "AWS_ACCESS_KEY_ID".to_string(),
            optional: false,
        };

        assert_eq!(mapping.id, "aws-cred");
        assert_eq!(mapping.injection_type, "env");
    }

    #[test]
    fn test_config_serialize() {
        let config = SigilConfig::default();
        let toml_str = toml::to_string_pretty(&config).unwrap();
        assert!(toml_str.contains("format_version"));
        assert!(toml_str.contains("kdf_params"));
        assert!(toml_str.contains("auth_factors"));
    }

    #[test]
    fn test_config_deserialize() {
        let toml_str = r#"
format_version = 1

[vault]
path = ".sigil/vault.sealed"

[vault.kdf_params]
algorithm = "argon2id"
memory_cost = 1073741824
iterations = 3
parallelism = 4
salt_length = 32

[vault.auth_factors]
passphrase = true
device = true
totp = false
fido2 = false
"#;

        let config: SigilConfig = toml::from_str(toml_str).unwrap();
        assert_eq!(config.format_version, 1);
        assert_eq!(config.vault.kdf_params.algorithm, "argon2id");
        assert!(config.vault.auth_factors.passphrase);
    }
}
