//! Project Manifest (.sigil.toml) support
//!
//! This module provides types and functions for working with SIGIL project manifests.
//! A project manifest is a declarative TOML file that defines which secrets a project uses,
//! custom signatures, and inline sealed operations. It is committed to version control.

use crate::SecretType;
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};

/// Project manifest (.sigil.toml)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProjectManifest {
    /// Project metadata
    #[serde(default)]
    pub project: ProjectMetadata,
    /// Secrets declared by this project
    #[serde(default)]
    pub secrets: Vec<SecretDeclaration>,
    /// Custom signatures for this project
    #[serde(default)]
    pub signatures: Vec<SignatureRule>,
    /// Sealed operations for this project
    #[serde(default)]
    pub operations: Vec<OperationDeclaration>,
}

/// Project metadata
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ProjectMetadata {
    /// Project name
    pub name: Option<String>,
    /// Minimum SIGIL version required
    pub min_sigil_version: Option<String>,
}

/// Secret declaration in the manifest
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecretDeclaration {
    /// Secret path (e.g., "kalshi/api_key")
    pub path: String,
    /// Secret type
    #[serde(default = "default_secret_type")]
    pub secret_type: SecretType,
    /// Whether this secret is required
    #[serde(default)]
    pub required: bool,
    /// Description of the secret
    pub description: Option<String>,
    /// Injection mode (env or file)
    #[serde(default = "default_inject_mode")]
    pub inject: InjectMode,
    /// Environment variable name (when inject=env)
    pub env_var: Option<String>,
}

fn default_secret_type() -> SecretType {
    SecretType::Generic
}

fn default_inject_mode() -> InjectMode {
    InjectMode::Env
}

/// Injection mode for secrets
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum InjectMode {
    /// Inject as environment variable
    #[default]
    Env,
    /// Inject as file path
    File,
}

/// Signature rule for automatic secret injection
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignatureRule {
    /// Signature name
    pub name: String,
    /// Regex pattern to match commands
    pub match_pattern: String,
    /// Secret injection rules
    pub inject: Vec<InjectionRule>,
}

/// Secret injection rule
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InjectionRule {
    /// Header format (e.g., "Authorization: Bearer")
    #[serde(default)]
    pub header: Option<String>,
    /// Secret path to inject
    pub secret: String,
}

/// Operation declaration in the manifest
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OperationDeclaration {
    /// Operation name/ID
    pub name: String,
    /// Operation description
    pub description: Option<String>,
    /// Command to execute (may contain {{secret:path}} placeholders)
    pub command: String,
    /// Secrets this operation uses
    #[serde(default)]
    pub secrets: Vec<String>,
    /// Output filter mode
    #[serde(default)]
    pub output_filter: OutputFilter,
    /// Whether this operation requires approval
    #[serde(default = "default_require_approval")]
    pub require_approval: bool,
    /// Timeout in seconds
    pub timeout_seconds: Option<u64>,
    /// Summary extraction regex
    pub summary_regex: Option<String>,
}

fn default_require_approval() -> bool {
    true
}

/// Output filter mode for operations
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum OutputFilter {
    /// Only show exit code
    #[default]
    ExitCode,
    /// Show summary with exit code and duration
    Summary,
    /// Show full output (scrubbed)
    FullScrubbed,
    /// No output (for operations that only care about side effects)
    None,
}

/// Result of validating a manifest against the vault
#[derive(Debug, Clone)]
pub struct ManifestValidationResult {
    /// Secrets in manifest that exist in vault
    pub valid: Vec<String>,
    /// Required secrets in manifest that are missing from vault
    pub missing_required: Vec<String>,
    /// Optional secrets in manifest that are missing from vault
    pub missing_optional: Vec<String>,
    /// Secrets in vault used by project but not declared in manifest
    pub undeclared: Vec<String>,
    /// Whether validation passed (no required secrets missing)
    pub passed: bool,
}

impl ProjectManifest {
    /// Load a project manifest from a file
    pub fn load(path: &Path) -> Result<Self> {
        let content = fs::read_to_string(path)
            .with_context(|| format!("Failed to read manifest file: {}", path.display()))?;

        let manifest: ProjectManifest = toml::from_str(&content)
            .with_context(|| format!("Failed to parse manifest file: {}", path.display()))?;

        Ok(manifest)
    }

    /// Save a project manifest to a file
    pub fn save(&self, path: &Path) -> Result<()> {
        let content = toml::to_string_pretty(self).context("Failed to serialize manifest")?;

        fs::write(path, content)
            .with_context(|| format!("Failed to write manifest file: {}", path.display()))?;

        Ok(())
    }

    /// Create a new empty manifest
    pub fn new() -> Self {
        Self {
            project: ProjectMetadata::default(),
            secrets: Vec::new(),
            signatures: Vec::new(),
            operations: Vec::new(),
        }
    }

    /// Create a manifest from suggestions
    pub fn from_suggestions(
        project_name: String,
        suggestions: &[crate::scanner::SecretSuggestion],
    ) -> Self {
        let mut secrets = Vec::new();

        for suggestion in suggestions {
            secrets.push(SecretDeclaration {
                path: suggestion.path.as_str().to_string(),
                secret_type: suggestion.secret_type,
                required: false, // Don't auto-mark as required
                description: Some(suggestion.description.clone()),
                inject: InjectMode::Env,
                env_var: None,
            });
        }

        Self {
            project: ProjectMetadata {
                name: Some(project_name),
                min_sigil_version: Some("0.1.0".to_string()),
            },
            secrets,
            signatures: Vec::new(),
            operations: Vec::new(),
        }
    }

    /// Add a secret declaration
    pub fn add_secret(&mut self, secret: SecretDeclaration) {
        // Remove existing declaration with same path
        self.secrets.retain(|s| s.path != secret.path);
        self.secrets.push(secret);
    }

    /// Add a signature rule
    pub fn add_signature(&mut self, signature: SignatureRule) {
        // Remove existing signature with same name
        self.signatures.retain(|s| s.name != signature.name);
        self.signatures.push(signature);
    }

    /// Add an operation declaration
    pub fn add_operation(&mut self, operation: OperationDeclaration) {
        // Remove existing operation with same name
        self.operations.retain(|o| o.name != operation.name);
        self.operations.push(operation);
    }

    /// Get secret declaration by path
    pub fn get_secret(&self, path: &str) -> Option<&SecretDeclaration> {
        self.secrets.iter().find(|s| s.path == path)
    }

    /// Get operation declaration by name
    pub fn get_operation(&self, name: &str) -> Option<&OperationDeclaration> {
        self.operations.iter().find(|o| o.name == name)
    }

    /// Validate this manifest against available secrets in the vault
    pub fn validate(&self, available_secrets: &[String]) -> ManifestValidationResult {
        let mut valid = Vec::new();
        let mut missing_required = Vec::new();
        let mut missing_optional = Vec::new();
        let mut undeclared = Vec::new();

        // Check manifest secrets against vault
        for secret in &self.secrets {
            if available_secrets.contains(&secret.path) {
                valid.push(secret.path.clone());
            } else if secret.required {
                missing_required.push(secret.path.clone());
            } else {
                missing_optional.push(secret.path.clone());
            }
        }

        // Check for vault secrets not in manifest
        for available in available_secrets {
            if !self.secrets.iter().any(|s| &s.path == available) {
                undeclared.push(available.clone());
            }
        }

        let passed = missing_required.is_empty();

        ManifestValidationResult {
            valid,
            missing_required,
            missing_optional,
            undeclared,
            passed,
        }
    }

    /// Generate a template manifest for a new project
    pub fn template(project_name: &str) -> Self {
        Self {
            project: ProjectMetadata {
                name: Some(project_name.to_string()),
                min_sigil_version: Some("0.1.0".to_string()),
            },
            secrets: vec![SecretDeclaration {
                path: "api/production_key".to_string(),
                secret_type: SecretType::ApiKey,
                required: true,
                description: Some("Production API key".to_string()),
                inject: InjectMode::Env,
                env_var: Some("API_KEY".to_string()),
            }],
            signatures: vec![SignatureRule {
                name: "api-deploy".to_string(),
                match_pattern: "kubectl.*apply".to_string(),
                inject: vec![InjectionRule {
                    header: Some("Authorization: Bearer".to_string()),
                    secret: "api/production_key".to_string(),
                }],
            }],
            operations: vec![OperationDeclaration {
                name: "deploy".to_string(),
                description: Some("Deploy to production".to_string()),
                command: "kubectl apply -f manifests/".to_string(),
                secrets: vec!["api/production_key".to_string()],
                output_filter: OutputFilter::Summary,
                require_approval: true,
                timeout_seconds: Some(300),
                summary_regex: None,
            }],
        }
    }

    /// Merge this manifest with another (operations.toml takes precedence on name collision)
    pub fn merge(&mut self, other: ProjectManifest) {
        // Merge operations - other takes precedence on name collision
        for op in other.operations {
            self.operations.retain(|o| o.name != op.name);
            self.operations.push(op);
        }

        // Merge signatures - other takes precedence on name collision
        for sig in other.signatures {
            self.signatures.retain(|s| s.name != sig.name);
            self.signatures.push(sig);
        }

        // Merge secrets - keep unique paths, other takes precedence
        for secret in other.secrets {
            self.secrets.retain(|s| s.path != secret.path);
            self.secrets.push(secret);
        }

        // Update project metadata if other has it
        if other.project.name.is_some() {
            self.project.name = other.project.name;
        }
        if other.project.min_sigil_version.is_some() {
            self.project.min_sigil_version = other.project.min_sigil_version;
        }
    }
}

impl Default for ProjectManifest {
    fn default() -> Self {
        Self::new()
    }
}

/// Find the project manifest file in the current directory or parent directories
pub fn find_manifest(start_dir: &Path) -> Option<PathBuf> {
    let mut current = Some(start_dir);

    while let Some(dir) = current {
        let manifest_path = dir.join(".sigil.toml");
        if manifest_path.exists() {
            return Some(manifest_path);
        }

        // Move to parent directory
        current = dir.parent();
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_manifest_creation() {
        let manifest = ProjectManifest::new();
        assert_eq!(manifest.secrets.len(), 0);
        assert_eq!(manifest.operations.len(), 0);
    }

    #[test]
    fn test_manifest_template() {
        let manifest = ProjectManifest::template("test-project");
        assert_eq!(manifest.project.name.as_deref(), Some("test-project"));
        assert!(!manifest.secrets.is_empty());
        assert!(!manifest.operations.is_empty());
    }

    #[test]
    fn test_add_secret() {
        let mut manifest = ProjectManifest::new();
        manifest.add_secret(SecretDeclaration {
            path: "test/key".to_string(),
            secret_type: SecretType::ApiKey,
            required: true,
            description: None,
            inject: InjectMode::Env,
            env_var: None,
        });

        assert_eq!(manifest.secrets.len(), 1);
        assert_eq!(manifest.secrets[0].path, "test/key");

        // Adding same path should replace
        manifest.add_secret(SecretDeclaration {
            path: "test/key".to_string(),
            secret_type: SecretType::Password,
            required: false,
            description: Some("Updated".to_string()),
            inject: InjectMode::File,
            env_var: None,
        });

        assert_eq!(manifest.secrets.len(), 1);
        assert_eq!(manifest.secrets[0].secret_type, SecretType::Password);
    }

    #[test]
    fn test_validate_manifest() {
        let mut manifest = ProjectManifest::new();
        manifest.add_secret(SecretDeclaration {
            path: "required_secret".to_string(),
            secret_type: SecretType::ApiKey,
            required: true,
            description: None,
            inject: InjectMode::Env,
            env_var: None,
        });
        manifest.add_secret(SecretDeclaration {
            path: "optional_secret".to_string(),
            secret_type: SecretType::ApiKey,
            required: false,
            description: None,
            inject: InjectMode::Env,
            env_var: None,
        });

        // Both secrets missing
        let result = manifest.validate(&[]);
        assert!(!result.passed);
        assert_eq!(result.missing_required.len(), 1);
        assert_eq!(result.missing_optional.len(), 1);

        // Only required secret present
        let result = manifest.validate(&["required_secret".to_string()]);
        assert!(result.passed);
        assert_eq!(result.valid.len(), 1);
        assert_eq!(result.missing_optional.len(), 1);
        assert_eq!(result.undeclared.len(), 0);

        // Both secrets present
        let result =
            manifest.validate(&["required_secret".to_string(), "optional_secret".to_string()]);
        assert!(result.passed);
        assert_eq!(result.valid.len(), 2);

        // Undeclared secret in vault
        let result = manifest.validate(&[
            "required_secret".to_string(),
            "undeclared_secret".to_string(),
        ]);
        assert!(result.passed);
        assert_eq!(result.undeclared.len(), 1);
        assert_eq!(result.undeclared[0], "undeclared_secret");
    }

    #[test]
    fn test_serialize_deserialize() {
        let manifest = ProjectManifest::template("test");

        let toml_str = toml::to_string_pretty(&manifest).unwrap();
        let deserialized: ProjectManifest = toml::from_str(&toml_str).unwrap();

        assert_eq!(manifest.project.name, deserialized.project.name);
        assert_eq!(manifest.secrets.len(), deserialized.secrets.len());
    }

    #[test]
    fn test_merge_manifests() {
        let mut base = ProjectManifest::new();
        base.add_secret(SecretDeclaration {
            path: "base_secret".to_string(),
            secret_type: SecretType::ApiKey,
            required: true,
            description: Some("Base".to_string()),
            inject: InjectMode::Env,
            env_var: None,
        });
        base.add_operation(OperationDeclaration {
            name: "base_op".to_string(),
            description: None,
            command: "echo base".to_string(),
            secrets: vec![],
            output_filter: OutputFilter::ExitCode,
            require_approval: false,
            timeout_seconds: None,
            summary_regex: None,
        });

        let mut other = ProjectManifest::new();
        other.add_secret(SecretDeclaration {
            path: "other_secret".to_string(),
            secret_type: SecretType::ApiKey,
            required: false,
            description: Some("Other".to_string()),
            inject: InjectMode::Env,
            env_var: None,
        });
        other.add_operation(OperationDeclaration {
            name: "other_op".to_string(),
            description: None,
            command: "echo other".to_string(),
            secrets: vec![],
            output_filter: OutputFilter::ExitCode,
            require_approval: false,
            timeout_seconds: None,
            summary_regex: None,
        });
        // Override operation from base
        other.add_operation(OperationDeclaration {
            name: "base_op".to_string(),
            description: Some("Overridden".to_string()),
            command: "echo overridden".to_string(),
            secrets: vec![],
            output_filter: OutputFilter::Summary,
            require_approval: true,
            timeout_seconds: Some(60),
            summary_regex: None,
        });

        base.merge(other);

        assert_eq!(base.secrets.len(), 2);
        assert_eq!(base.operations.len(), 2);
        assert_eq!(
            base.get_operation("base_op").unwrap().description,
            Some("Overridden".to_string())
        );
    }
}
