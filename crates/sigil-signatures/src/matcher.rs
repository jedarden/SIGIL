//! Signature matching logic
//!
//! The matcher combines built-in and user-defined signatures to find
//! appropriate injections for any command.

use crate::builtins::BUILTIN_SIGNATURES;
use crate::config::SignatureConfig;
use sigil_core::{Result, SecretPath, SigilError};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tracing::{debug, trace, warn};

/// A matched signature with resolved injections
#[derive(Debug, Clone)]
pub struct MatchedSignature {
    /// Name of the signature that matched
    pub signature_name: String,

    /// The original match pattern
    pub pattern: String,

    /// Injections to perform
    pub injections: Vec<MatchedInjection>,
}

/// A single matched injection ready to be applied
#[derive(Debug, Clone)]
pub struct MatchedInjection {
    /// Secret path in the vault
    pub secret_path: SecretPath,

    /// Type of injection
    pub injection_type: InjectionType,

    /// Whether this injection is optional
    pub optional: bool,

    /// Whether to cleanup after execution
    pub cleanup: bool,
}

/// Type of injection for a matched signature
#[derive(Debug, Clone)]
pub enum InjectionType {
    /// Environment variable: name
    Env(String),

    /// File: path
    File(PathBuf),

    /// HTTP header: name, format string
    Header(String, String),
}

/// The main signature matcher
///
/// Combines built-in signatures with user-defined signatures from
/// global and project-specific configuration files.
pub struct SignatureMatcher {
    /// Combined signature configuration
    config: Arc<SignatureConfig>,

    /// Project directory for project-specific signatures
    project_dir: Option<PathBuf>,
}

impl SignatureMatcher {
    /// Create a new signature matcher with all default signatures
    pub fn new() -> Result<Self> {
        Self::with_project_dir(None)
    }

    /// Create a signature matcher with a specific project directory
    pub fn with_project_dir(project_dir: Option<PathBuf>) -> Result<Self> {
        let mut config = SignatureConfig::new();

        // Load built-in signatures
        debug!("Loading built-in signatures...");
        let builtin = BUILTIN_SIGNATURES.get_config()?;
        config.merge(builtin);

        // Load global user signatures
        if let Some(global_dir) = Self::get_global_signatures_dir() {
            if global_dir.exists() {
                debug!("Loading global signatures from: {:?}", global_dir);
                Self::load_signatures_from_dir(&mut config, &global_dir)?;
            }
        }

        // Load project-specific signatures
        if let Some(ref project_dir) = project_dir {
            let project_file = project_dir.join(crate::PROJECT_SIGNATURES_FILE);
            if project_file.exists() {
                debug!("Loading project signatures from: {:?}", project_file);
                match SignatureConfig::from_file(&project_file) {
                    Ok(project_config) => {
                        config.merge(project_config);
                    }
                    Err(e) => {
                        warn!("Failed to load project signatures: {}", e);
                    }
                }
            }

            let project_sig_dir = project_dir.join(crate::USER_SIGNATURES_DIR);
            if project_sig_dir.exists() {
                debug!("Loading project signatures from dir: {:?}", project_sig_dir);
                Self::load_signatures_from_dir(&mut config, &project_sig_dir)?;
            }
        }

        debug!("Loaded {} total signatures", config.get_all().len());

        Ok(Self {
            config: Arc::new(config),
            project_dir,
        })
    }

    /// Get the global signatures directory path
    fn get_global_signatures_dir() -> Option<PathBuf> {
        if let Ok(home) = std::env::var("HOME") {
            Some(PathBuf::from(home).join(".sigil").join("signatures.d"))
        } else {
            None
        }
    }

    /// Load all TOML files from a directory
    fn load_signatures_from_dir(config: &mut SignatureConfig, dir: &Path) -> Result<()> {
        let toml_files = glob::glob(&format!("{}/*.toml", dir.display()))
            .map_err(|e| SigilError::InvalidConfig(format!("Invalid glob pattern: {}", e)))?;

        for entry in toml_files.flatten() {
            match SignatureConfig::from_file(&entry) {
                Ok(file_config) => {
                    debug!("Loaded signatures from: {:?}", entry);
                    config.merge(file_config);
                }
                Err(e) => {
                    warn!("Failed to load signatures from {:?}: {}", entry, e);
                }
            }
        }

        Ok(())
    }

    /// Match a command against all known signatures
    ///
    /// Returns injections for all matching signatures, or an empty vector
    /// if no signatures match.
    pub fn match_command(&self, command: &str) -> Vec<MatchedSignature> {
        let mut results = Vec::new();

        for (name, signature) in self.config.get_all() {
            if !signature.enabled {
                trace!("Skipping disabled signature: {}", name);
                continue;
            }

            match signature.matches(command) {
                Ok(true) => {
                    debug!("Command '{}' matched signature '{}'", command, name);
                    let injections: Vec<MatchedInjection> = signature
                        .inject
                        .iter()
                        .filter_map(|inject| self.to_matched_injection(inject).ok())
                        .collect();

                    if !injections.is_empty() {
                        results.push(MatchedSignature {
                            signature_name: name,
                            pattern: signature.match_pattern.clone(),
                            injections,
                        });
                    }
                }
                Ok(false) => {
                    trace!("Command '{}' did not match signature '{}'", command, name);
                }
                Err(e) => {
                    warn!("Error checking signature '{}': {}", name, e);
                }
            }
        }

        results
    }

    /// Convert an InjectionConfig to a MatchedInjection
    fn to_matched_injection(
        &self,
        inject: &crate::config::InjectionConfig,
    ) -> Result<MatchedInjection> {
        let secret_path = SecretPath::new(inject.secret.clone())?;

        let injection_type = match &inject.injection_type {
            crate::config::InjectionType::Env { name } => InjectionType::Env(name.clone()),
            crate::config::InjectionType::File { path } => InjectionType::File(PathBuf::from(path)),
            crate::config::InjectionType::Header { name, format } => {
                InjectionType::Header(name.clone(), format.clone())
            }
        };

        Ok(MatchedInjection {
            secret_path,
            injection_type,
            optional: inject.optional,
            cleanup: inject.cleanup,
        })
    }

    /// Reload signatures from disk
    pub fn reload(&mut self) -> Result<()> {
        *self = Self::with_project_dir(self.project_dir.clone())?;
        Ok(())
    }

    /// Get the number of loaded signatures
    pub fn signature_count(&self) -> usize {
        self.config.get_all().len()
    }

    /// List all signature names
    pub fn list_signatures(&self) -> Vec<String> {
        self.config
            .get_all()
            .into_iter()
            .map(|(name, _)| name)
            .collect()
    }
}

impl Default for SignatureMatcher {
    fn default() -> Self {
        Self::new().expect("Failed to create default signature matcher")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{InjectionConfig, InjectionType};

    #[test]
    fn test_matcher_creation() {
        let matcher = SignatureMatcher::new().unwrap();
        assert!(matcher.signature_count() > 0);
    }

    #[test]
    fn test_match_aws_command() {
        let matcher = SignatureMatcher::new().unwrap();
        let results = matcher.match_command("aws s3 ls");

        // Should match the AWS signature
        assert!(!results.is_empty());
        let aws_match = results.iter().find(|m| m.signature_name == "aws");
        assert!(aws_match.is_some());
    }

    #[test]
    fn test_match_kubectl_command() {
        let matcher = SignatureMatcher::new().unwrap();
        let results = matcher.match_command("kubectl get pods");

        // Should match the kubectl signature
        assert!(!results.is_empty());
    }

    #[test]
    fn test_no_match_for_echo() {
        let matcher = SignatureMatcher::new().unwrap();
        let results = matcher.match_command("echo hello");

        // echo should not match any signature
        assert!(results.is_empty());
    }

    #[test]
    fn test_injection_type_conversion() {
        let inject_env = InjectionConfig {
            injection_type: InjectionType::Env {
                name: "API_KEY".to_string(),
            },
            secret: "api/key".to_string(),
            optional: false,
            cleanup: false,
        };

        let matcher = SignatureMatcher::new().unwrap();
        let matched = matcher.to_matched_injection(&inject_env).unwrap();

        assert_eq!(matched.secret_path.as_str(), "api/key");
        assert!(!matched.optional);
        assert!(!matched.cleanup);
    }
}
