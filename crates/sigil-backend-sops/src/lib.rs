//! SOPS backend for SIGIL
//!
//! This backend provides secret access from SOPS-encrypted YAML/JSON files.
//! SOPS (Secrets OPerationS) is an editor of encrypted files that supports
//! YAML, JSON, ENV, INI and BIN formats.
//!
//! # Security Considerations
//!
//! - **Age encryption**: SOPS files must use age encryption (compatible with
//!   SIGIL's existing age backend)
//! - **No secret caching**: Secrets are fetched on-demand from SOPS files
//! - **Read-only access**: The backend only reads secrets, never writes
//! - **No passphrase storage**: Passphrases are not stored; decryption uses
//!   the SIGIL vault's age identity
//!
//! # Configuration
//!
//! Add to `~/.sigil/config.toml`:
//!
//! ```toml
//! [backends.sops]
//! type = "sops"
//! # Directory containing SOPS files (default: .sops/)
//! directory = ".sops"
//! # File pattern to match (default: "*.yaml", "*.yml", "*.json")
//! patterns = ["*.yaml", "*.yml", "*.json"]
//! ```
//!
//! # SOPS File Format
//!
//! SOPS files have a specific structure:
//! ```yaml
//! sops:
//!     kms: []
//!     gcp_kms: []
//!     azure_kv: []
//!     hc_vault: []
//!     age: <encrypted age key>
//!     lastmodified: "2024-01-01T00:00:00Z"
//!     mac: <HMAC>
//!     pgp: []
//!     unencrypted_suffix: "_unencrypted"
//!     version: "3.8.0"
//! myapp:
//!     database:
//!         password: <encrypted value>
//! ```

#![warn(missing_docs)]
#![warn(clippy::all)]

use async_trait::async_trait;
use sigil_core::{
    Result, SecretBackend, SecretMetadata, SecretPath, SecretType, SecretValue, SigilError,
};
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};

/// SOPS backend configuration
#[derive(Debug, Clone)]
pub struct SopsBackendConfig {
    /// Directory containing SOPS files
    pub directory: PathBuf,
    /// File patterns to match (default: ["*.yaml", "*.yml", "*.json"])
    pub patterns: Vec<String>,
}

impl Default for SopsBackendConfig {
    fn default() -> Self {
        Self {
            directory: PathBuf::from(".sops"),
            patterns: vec![
                "*.yaml".to_string(),
                "*.yml".to_string(),
                "*.json".to_string(),
            ],
        }
    }
}

/// SOPS backend for SIGIL
///
/// Reads secrets from SOPS-encrypted YAML/JSON files. This backend is designed
/// for teams using SOPS to manage encrypted secrets in version control.
#[allow(dead_code)]
pub struct SopsBackend {
    /// Directory containing SOPS files
    directory: PathBuf,
    /// File patterns to match
    patterns: Vec<String>,
    /// Cached metadata for all secrets
    metadata: HashMap<String, SecretMetadata>,
    /// Cached file contents (lazy loaded)
    files: HashMap<String, SopsFile>,
}

/// Parsed SOPS file
#[derive(Debug, Clone)]
#[allow(dead_code)]
struct SopsFile {
    /// SOPS metadata
    sops_metadata: SopsMetadata,
    /// Decrypted data (nested key-value pairs)
    data: serde_yaml::Value,
}

/// SOPS metadata from the file header
#[derive(Debug, Clone)]
#[allow(dead_code)]
struct SopsMetadata {
    /// Age key (encrypted)
    age_key: Option<String>,
    /// MAC for verification
    mac: Option<String>,
    /// Last modified timestamp
    last_modified: Option<String>,
    /// SOPS version
    version: Option<String>,
}

impl SopsBackend {
    /// Create a new SOPS backend
    ///
    /// # Arguments
    /// * `config` - Backend configuration
    ///
    /// # Returns
    /// A new SopsBackend instance with loaded secret metadata
    pub fn new(config: SopsBackendConfig) -> Result<Self> {
        let directory = config.directory;

        if !directory.exists() {
            // Directory doesn't exist yet, return empty backend
            return Ok(Self {
                directory,
                patterns: config.patterns,
                metadata: HashMap::new(),
                files: HashMap::new(),
            });
        }

        // Discover and parse SOPS files
        let (files, metadata) = Self::discover_files(&directory, &config.patterns)?;

        tracing::info!(
            "Loaded {} secrets from {} SOPS file(s) in {}",
            metadata.len(),
            files.len(),
            directory.display()
        );

        Ok(Self {
            directory,
            patterns: config.patterns,
            metadata,
            files,
        })
    }

    /// Discover and parse SOPS files in the directory
    fn discover_files(
        directory: &Path,
        patterns: &[String],
    ) -> Result<(HashMap<String, SopsFile>, HashMap<String, SecretMetadata>)> {
        let mut files = HashMap::new();
        let mut metadata = HashMap::new();

        // Find all matching files
        let entries = fs::read_dir(directory)
            .map_err(|e| SigilError::IoError(format!("Failed to read SOPS directory: {}", e)))?;

        for entry in entries {
            let entry = entry.map_err(|e| {
                SigilError::IoError(format!("Failed to read directory entry: {}", e))
            })?;
            let path = entry.path();

            if !path.is_file() {
                continue;
            }

            // Check if file matches pattern
            let file_name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");

            let matches = patterns
                .iter()
                .any(|pattern| Self::matches_pattern(file_name, pattern));

            if !matches {
                continue;
            }

            // Try to parse as SOPS file
            match Self::parse_sops_file(&path) {
                Ok((sops_file, secrets)) => {
                    let file_key = path.to_string_lossy().to_string();
                    files.insert(file_key.clone(), sops_file);

                    // Add all secrets from this file
                    for (secret_path, secret_meta) in secrets {
                        metadata.insert(secret_path, secret_meta);
                    }
                }
                Err(e) => {
                    tracing::warn!("Failed to parse SOPS file {}: {}", path.display(), e);
                    // Continue with other files
                }
            }
        }

        Ok((files, metadata))
    }

    /// Check if a filename matches a pattern (simple glob)
    fn matches_pattern(filename: &str, pattern: &str) -> bool {
        if pattern == "*" {
            return true;
        }

        if let Some(ext) = pattern.strip_prefix("*.") {
            return filename.ends_with(ext);
        }

        filename == pattern
    }

    /// Parse a SOPS file and extract secrets
    fn parse_sops_file(path: &Path) -> Result<(SopsFile, HashMap<String, SecretMetadata>)> {
        let content = fs::read_to_string(path).map_err(|e| {
            SigilError::IoError(format!("Failed to read file {}: {}", path.display(), e))
        })?;

        let value: serde_yaml::Value = serde_yaml::from_str(&content)
            .map_err(|e| SigilError::IoError(format!("Failed to parse YAML/JSON: {}", e)))?;

        // Extract SOPS metadata
        let sops_metadata = value
            .get("sops")
            .and_then(|v| v.as_mapping())
            .ok_or_else(|| {
                SigilError::IoError("Invalid SOPS file: missing 'sops' key".to_string())
            })?;

        let age_key = sops_metadata
            .get("age")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string());

        let mac = sops_metadata
            .get("mac")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string());

        let last_modified = sops_metadata
            .get("lastmodified")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string());

        let version = sops_metadata
            .get("version")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string());

        let metadata = SopsMetadata {
            age_key,
            mac,
            last_modified,
            version,
        };

        // Extract all secrets from the file (excluding 'sops' key)
        let mut secrets = HashMap::new();
        if let Some(mapping) = value.as_mapping() {
            for (key, value) in mapping {
                if let Some(key_str) = key.as_str() {
                    if key_str == "sops" {
                        continue; // Skip SOPS metadata
                    }

                    // Recursively extract secrets from nested structures
                    Self::extract_nested_secrets(value, key_str, &mut secrets, path);
                }
            }
        }

        let sops_file = SopsFile {
            sops_metadata: metadata,
            data: value,
        };

        Ok((sops_file, secrets))
    }

    /// Recursively extract secrets from nested YAML structures
    fn extract_nested_secrets(
        value: &serde_yaml::Value,
        prefix: &str,
        secrets: &mut HashMap<String, SecretMetadata>,
        file_path: &Path,
    ) {
        match value {
            serde_yaml::Value::Mapping(mapping) => {
                for (key, value) in mapping {
                    if let Some(key_str) = key.as_str() {
                        let new_prefix = if prefix.is_empty() {
                            key_str.to_string()
                        } else {
                            format!("{}/{}", prefix, key_str)
                        };

                        // Check if this is a leaf value (string or number)
                        match value {
                            serde_yaml::Value::String(_)
                            | serde_yaml::Value::Number(_)
                            | serde_yaml::Value::Bool(_) => {
                                // This is a leaf value, treat it as a secret
                                let secret_type = Self::infer_secret_type(&new_prefix);
                                secrets.insert(
                                    new_prefix.clone(),
                                    SecretMetadata {
                                        path: SecretPath::new(&new_prefix).unwrap(),
                                        secret_type,
                                        tags: vec!["sops".to_string()],
                                        notes: Some(format!(
                                            "From SOPS file: {}",
                                            file_path.display()
                                        )),
                                        created_at: chrono::Utc::now(),
                                        updated_at: chrono::Utc::now(),
                                        expires_at: None,
                                    },
                                );
                            }
                            serde_yaml::Value::Mapping(_) | serde_yaml::Value::Sequence(_) => {
                                // Continue recursing
                                Self::extract_nested_secrets(
                                    value,
                                    &new_prefix,
                                    secrets,
                                    file_path,
                                );
                            }
                            serde_yaml::Value::Null => {
                                // Skip null values
                            }
                            _ => {}
                        }
                    }
                }
            }
            serde_yaml::Value::Sequence(sequence) => {
                for (i, value) in sequence.iter().enumerate() {
                    let new_prefix = format!("{}[{}]", prefix, i);
                    Self::extract_nested_secrets(value, &new_prefix, secrets, file_path);
                }
            }
            _ => {
                // Leaf value (already handled above)
            }
        }
    }

    /// Infer secret type from path
    fn infer_secret_type(path: &str) -> SecretType {
        let path_lower = path.to_lowercase();

        if path_lower.contains("ssh") || path_lower.contains("private_key") {
            SecretType::SshKey
        } else if path_lower.contains("api")
            || path_lower.contains("key")
            || path_lower.contains("token")
        {
            SecretType::ApiKey
        } else if path_lower.contains("cert") || path_lower.contains("certificate") {
            SecretType::Certificate
        } else if path_lower.contains("pass") || path_lower.contains("password") {
            SecretType::Password
        } else {
            SecretType::Generic
        }
    }

    /// Get the directory containing SOPS files
    pub fn directory(&self) -> &Path {
        &self.directory
    }
}

#[async_trait]
impl SecretBackend for SopsBackend {
    /// Get a secret value by path
    ///
    /// The path is the dot-notation path to the secret in the SOPS file.
    /// For example, "myapp.database.password" maps to:
    /// ```yaml
    /// myapp:
    ///     database:
    ///         password: <value>
    /// ```
    async fn get(&self, path: &SecretPath) -> Result<SecretValue> {
        let path_str = path.as_str();

        // Strip "sops/" prefix if present
        let sops_path = if let Some(stripped) = path_str.strip_prefix("sops/") {
            stripped
        } else {
            path_str
        };

        // Search through all loaded files for this path
        for sops_file in self.files.values() {
            if let Some(value) = Self::get_nested_value(&sops_file.data, sops_path) {
                // Convert value to string
                let string_value = match value {
                    serde_yaml::Value::String(s) => s.clone(),
                    serde_yaml::Value::Number(n) => n.to_string(),
                    serde_yaml::Value::Bool(b) => b.to_string(),
                    _ => {
                        return Err(SigilError::IoError(format!(
                            "Secret at path '{}' is not a scalar value",
                            sops_path
                        )));
                    }
                };

                return Ok(SecretValue::new(string_value.as_bytes().to_vec()));
            }
        }

        Err(SigilError::SecretNotFound(path_str.to_string()))
    }

    /// Get secret metadata by path
    async fn get_metadata(&self, path: &SecretPath) -> Result<SecretMetadata> {
        let path_str = path.as_str();

        // Try direct lookup first
        if let Some(meta) = self.metadata.get(path_str) {
            return Ok(meta.clone());
        }

        // Try with "sops/" prefix
        let prefixed = format!("sops/{}", path_str);
        if let Some(meta) = self.metadata.get(&prefixed) {
            return Ok(meta.clone());
        }

        Err(SigilError::SecretNotFound(path_str.to_string()))
    }

    /// Set a secret value (not supported for SOPS backend)
    async fn set(
        &self,
        _path: &SecretPath,
        _value: &SecretValue,
        _meta: &SecretMetadata,
    ) -> Result<()> {
        // SOPS backend is read-only for security (SOPS files should be managed via SOPS CLI)
        Err(SigilError::IoError(
            "SOPS backend is read-only. Use 'sops' CLI to edit encrypted files.".to_string(),
        ))
    }

    /// Delete a secret (not supported for SOPS backend)
    async fn delete(&self, path: &SecretPath) -> Result<()> {
        // SOPS backend is read-only
        Err(SigilError::IoError(format!(
            "Cannot delete secret '{}' from SOPS backend (read-only)",
            path.as_str()
        )))
    }

    /// List all available secrets
    ///
    /// Returns all secret paths from all loaded SOPS files.
    async fn list(&self, prefix: &str) -> Result<Vec<SecretMetadata>> {
        let mut secrets = Vec::new();

        for (path, metadata) in &self.metadata {
            // Filter by prefix if specified
            if prefix.is_empty() || path.starts_with(prefix) {
                secrets.push(metadata.clone());
            }
        }

        Ok(secrets)
    }

    /// Get the backend type
    fn backend_type(&self) -> &str {
        "sops"
    }
}

impl SopsBackend {
    /// Get a nested value from YAML using dot notation
    fn get_nested_value(data: &serde_yaml::Value, path: &str) -> Option<serde_yaml::Value> {
        let parts: Vec<&str> = path.split('/').collect();

        let mut current = data;
        for part in parts {
            match current {
                serde_yaml::Value::Mapping(mapping) => {
                    current = mapping.get(serde_yaml::Value::String(part.to_string()))?;
                }
                _ => return None,
            }
        }

        Some(current.clone())
    }
}

/// Implement BackendFromConfig for SopsBackend
///
/// This allows the backend factory to create SopsBackend instances
/// from BackendEntry configurations loaded from the SIGIL config file.
impl sigil_core::backend::BackendFromConfig for SopsBackend {
    fn from_config(entry: &sigil_core::backend::BackendEntry) -> std::result::Result<Self, String> {
        // Extract directory from config
        let directory = entry
            .config
            .get("directory")
            .cloned()
            .unwrap_or_else(|| ".sops".to_string());

        // Extract patterns from config
        let patterns = entry
            .config
            .get("patterns")
            .map(|p| {
                // Parse comma-separated patterns
                p.split(',')
                    .map(|s| s.trim().to_string())
                    .collect::<Vec<_>>()
            })
            .unwrap_or_else(|| {
                vec![
                    "*.yaml".to_string(),
                    "*.yml".to_string(),
                    "*.json".to_string(),
                ]
            });

        let config = SopsBackendConfig {
            directory: std::path::PathBuf::from(directory),
            patterns,
        };

        SopsBackend::new(config).map_err(|e| format!("Failed to create SOPS backend: {:?}", e))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn test_sops_backend_config_default() {
        let config = SopsBackendConfig::default();
        assert_eq!(config.directory, PathBuf::from(".sops"));
        assert_eq!(config.patterns, vec!["*.yaml", "*.yml", "*.json"]);
    }

    #[test]
    fn test_matches_pattern() {
        assert!(SopsBackend::matches_pattern("test.yaml", "*.yaml"));
        assert!(SopsBackend::matches_pattern("test.yml", "*.yml"));
        assert!(SopsBackend::matches_pattern("test.json", "*.json"));
        assert!(!SopsBackend::matches_pattern("test.txt", "*.yaml"));
        assert!(SopsBackend::matches_pattern("test", "*"));
    }

    #[test]
    fn test_infer_secret_type() {
        assert_eq!(
            SopsBackend::infer_secret_type("ssh/key"),
            SecretType::SshKey
        );
        assert_eq!(
            SopsBackend::infer_secret_type("api/token"),
            SecretType::ApiKey
        );
        assert_eq!(
            SopsBackend::infer_secret_type("tls/cert"),
            SecretType::Certificate
        );
        assert_eq!(
            SopsBackend::infer_secret_type("db/password"),
            SecretType::Password
        );
        assert_eq!(
            SopsBackend::infer_secret_type("generic"),
            SecretType::Generic
        );
    }

    #[test]
    fn test_sops_backend_empty_directory() {
        let temp_dir = TempDir::new().unwrap();
        let config = SopsBackendConfig {
            directory: temp_dir.path().to_path_buf(),
            ..Default::default()
        };

        let backend = SopsBackend::new(config).unwrap();
        assert_eq!(backend.metadata.len(), 0);
        assert_eq!(backend.files.len(), 0);
    }

    #[test]
    fn test_get_nested_value() {
        let yaml = r#"
sops:
    version: "3.8.0"
myapp:
    database:
        password: "secret123"
"#;

        let value: serde_yaml::Value = serde_yaml::from_str(yaml).unwrap();
        let result = SopsBackend::get_nested_value(&value, "myapp/database/password");

        assert!(result.is_some());
        assert_eq!(
            result.unwrap(),
            serde_yaml::Value::String("secret123".to_string())
        );
    }

    // Behavioral tests for SecretBackend trait methods

    #[test]
    fn test_sops_backend_creates_from_valid_yaml() {
        let temp_dir = TempDir::new().unwrap();
        let sops_file = temp_dir.path().join("test.yaml");

        // Write a valid SOPS YAML file
        let yaml_content = r#"
sops:
    version: "3.8.0"
    age: age1test123456789
    mac: ABCDEF1234567890
    lastmodified: "2024-01-01T00:00:00Z"
myapp:
    api_key: sk_live_12345
    database:
        password: secret_password
"#;
        fs::write(&sops_file, yaml_content).unwrap();

        let config = SopsBackendConfig {
            directory: temp_dir.path().to_path_buf(),
            ..Default::default()
        };

        let backend = SopsBackend::new(config);
        assert!(backend.is_ok());
        let backend = backend.unwrap();

        // Verify metadata was loaded
        assert_eq!(backend.metadata.len(), 2);
    }

    #[tokio::test]
    async fn test_sops_backend_get_success() {
        let temp_dir = TempDir::new().unwrap();
        let sops_file = temp_dir.path().join("test.yaml");

        // Write a valid SOPS YAML file
        let yaml_content = r#"
sops:
    version: "3.8.0"
    age: age1test123456789
    mac: ABCDEF1234567890
    lastmodified: "2024-01-01T00:00:00Z"
myapp:
    api_key: sk_live_12345
"#;
        fs::write(&sops_file, yaml_content).unwrap();

        let config = SopsBackendConfig {
            directory: temp_dir.path().to_path_buf(),
            ..Default::default()
        };

        let backend = SopsBackend::new(config).unwrap();

        // Test get operation
        let path = SecretPath::new("myapp/api_key").unwrap();
        let result = backend.get(&path).await;

        assert!(result.is_ok());
        let value = result.unwrap();
        let exposed = value.expose(|v| String::from_utf8(v.to_vec()).unwrap());
        assert_eq!(exposed, "sk_live_12345");
    }

    #[tokio::test]
    async fn test_sops_backend_get_nested_secret() {
        let temp_dir = TempDir::new().unwrap();
        let sops_file = temp_dir.path().join("test.yaml");

        // Write a SOPS file with nested secrets
        let yaml_content = r#"
sops:
    version: "3.8.0"
    age: age1test123456789
    mac: ABCDEF1234567890
    lastmodified: "2024-01-01T00:00:00Z"
production:
    database:
        password: prod_secret_123
        username: admin_user
"#;
        fs::write(&sops_file, yaml_content).unwrap();

        let config = SopsBackendConfig {
            directory: temp_dir.path().to_path_buf(),
            ..Default::default()
        };

        let backend = SopsBackend::new(config).unwrap();

        // Test get operation with nested path
        let path = SecretPath::new("production/database/password").unwrap();
        let result = backend.get(&path).await;

        assert!(result.is_ok());
        let value = result.unwrap();
        let exposed = value.expose(|v| String::from_utf8(v.to_vec()).unwrap());
        assert_eq!(exposed, "prod_secret_123");
    }

    #[tokio::test]
    async fn test_sops_backend_get_not_found() {
        let temp_dir = TempDir::new().unwrap();
        let sops_file = temp_dir.path().join("test.yaml");

        // Write a minimal SOPS file
        let yaml_content = r#"
sops:
    version: "3.8.0"
    age: age1test123456789
    mac: ABCDEF1234567890
myapp:
    api_key: sk_live_12345
"#;
        fs::write(&sops_file, yaml_content).unwrap();

        let config = SopsBackendConfig {
            directory: temp_dir.path().to_path_buf(),
            ..Default::default()
        };

        let backend = SopsBackend::new(config).unwrap();

        // Test get operation for non-existent secret
        let path = SecretPath::new("nonexistent/secret").unwrap();
        let result = backend.get(&path).await;

        assert!(result.is_err());
        match result {
            Err(SigilError::SecretNotFound(p)) => {
                assert!(p.contains("nonexistent/secret"));
            }
            Err(e) => panic!("Expected SecretNotFound error, got: {:?}", e),
            Ok(_) => panic!("Expected error, got Ok"),
        }
    }

    #[tokio::test]
    async fn test_sops_backend_list_all() {
        let temp_dir = TempDir::new().unwrap();
        let sops_file = temp_dir.path().join("test.yaml");

        // Write a SOPS file with multiple secrets
        let yaml_content = r#"
sops:
    version: "3.8.0"
    age: age1test123456789
    mac: ABCDEF1234567890
myapp:
    api_key: sk_live_12345
    database:
        password: db_password
        username: admin
other:
    token: xyz789
"#;
        fs::write(&sops_file, yaml_content).unwrap();

        let config = SopsBackendConfig {
            directory: temp_dir.path().to_path_buf(),
            ..Default::default()
        };

        let backend = SopsBackend::new(config).unwrap();

        // Test list operation
        let result = backend.list("").await;

        assert!(result.is_ok());
        let secrets = result.unwrap();
        assert_eq!(secrets.len(), 4);

        // Verify paths
        let paths: Vec<String> = secrets
            .iter()
            .map(|s| s.path.as_str().to_string())
            .collect();
        assert!(paths.contains(&"myapp/api_key".to_string()));
        assert!(paths.contains(&"myapp/database/password".to_string()));
        assert!(paths.contains(&"myapp/database/username".to_string()));
        assert!(paths.contains(&"other/token".to_string()));
    }

    #[tokio::test]
    async fn test_sops_backend_list_with_prefix() {
        let temp_dir = TempDir::new().unwrap();
        let sops_file = temp_dir.path().join("test.yaml");

        // Write a SOPS file with multiple secrets
        let yaml_content = r#"
sops:
    version: "3.8.0"
    age: age1test123456789
    mac: ABCDEF1234567890
production:
    api_key: prod_key
    database:
        password: prod_password
staging:
    api_key: stag_key
"#;
        fs::write(&sops_file, yaml_content).unwrap();

        let config = SopsBackendConfig {
            directory: temp_dir.path().to_path_buf(),
            ..Default::default()
        };

        let backend = SopsBackend::new(config).unwrap();

        // Test list operation with prefix
        let result = backend.list("production").await;

        assert!(result.is_ok());
        let secrets = result.unwrap();
        assert_eq!(secrets.len(), 2);

        // Verify all secrets have the production prefix
        for secret in &secrets {
            assert!(secret.path.as_str().starts_with("production"));
        }
    }

    #[tokio::test]
    async fn test_sops_backend_get_metadata() {
        let temp_dir = TempDir::new().unwrap();
        let sops_file = temp_dir.path().join("test.yaml");

        // Write a SOPS file
        let yaml_content = r#"
sops:
    version: "3.8.0"
    age: age1test123456789
    mac: ABCDEF1234567890
myapp:
    api_key: sk_live_12345
"#;
        fs::write(&sops_file, yaml_content).unwrap();

        let config = SopsBackendConfig {
            directory: temp_dir.path().to_path_buf(),
            ..Default::default()
        };

        let backend = SopsBackend::new(config).unwrap();

        // Test get_metadata operation
        let path = SecretPath::new("myapp/api_key").unwrap();
        let result = backend.get_metadata(&path).await;

        assert!(result.is_ok());
        let metadata = result.unwrap();
        assert_eq!(metadata.path.as_str(), "myapp/api_key");
        assert_eq!(metadata.secret_type, SecretType::ApiKey);
        assert!(metadata.tags.contains(&"sops".to_string()));
    }

    #[tokio::test]
    async fn test_sops_backend_set_not_supported() {
        let temp_dir = TempDir::new().unwrap();
        let sops_file = temp_dir.path().join("test.yaml");

        // Write a minimal SOPS file
        let yaml_content = r#"
sops:
    version: "3.8.0"
    age: age1test123456789
    mac: ABCDEF1234567890
myapp:
    api_key: sk_live_12345
"#;
        fs::write(&sops_file, yaml_content).unwrap();

        let config = SopsBackendConfig {
            directory: temp_dir.path().to_path_buf(),
            ..Default::default()
        };

        let backend = SopsBackend::new(config).unwrap();

        // Test set operation (should fail - read-only backend)
        let path = SecretPath::new("new/secret").unwrap();
        let value = SecretValue::from_string("test_value".to_string());
        let metadata = SecretMetadata::new(path.clone());

        let result = backend.set(&path, &value, &metadata).await;
        assert!(result.is_err());

        match result {
            Err(SigilError::IoError(msg)) => {
                assert!(msg.contains("read-only"));
            }
            Err(e) => panic!("Expected IoError with read-only message, got: {:?}", e),
            Ok(_) => panic!("Expected error, got Ok"),
        }
    }

    #[tokio::test]
    async fn test_sops_backend_delete_not_supported() {
        let temp_dir = TempDir::new().unwrap();
        let sops_file = temp_dir.path().join("test.yaml");

        // Write a minimal SOPS file
        let yaml_content = r#"
sops:
    version: "3.8.0"
    age: age1test123456789
    mac: ABCDEF1234567890
myapp:
    api_key: sk_live_12345
"#;
        fs::write(&sops_file, yaml_content).unwrap();

        let config = SopsBackendConfig {
            directory: temp_dir.path().to_path_buf(),
            ..Default::default()
        };

        let backend = SopsBackend::new(config).unwrap();

        // Test delete operation (should fail - read-only backend)
        let path = SecretPath::new("myapp/api_key").unwrap();
        let result = backend.delete(&path).await;

        assert!(result.is_err());
        match result {
            Err(SigilError::IoError(msg)) => {
                assert!(msg.contains("read-only"));
            }
            Err(e) => panic!("Expected IoError with read-only message, got: {:?}", e),
            Ok(_) => panic!("Expected error, got Ok"),
        }
    }

    #[test]
    fn test_sops_backend_backend_type() {
        let temp_dir = TempDir::new().unwrap();
        let config = SopsBackendConfig {
            directory: temp_dir.path().to_path_buf(),
            ..Default::default()
        };

        let backend = SopsBackend::new(config).unwrap();
        assert_eq!(backend.backend_type(), "sops");
    }

    #[tokio::test]
    async fn test_sops_backend_multiple_files() {
        let temp_dir = TempDir::new().unwrap();

        // Write first SOPS file
        let file1 = temp_dir.path().join("app1.yaml");
        let yaml1 = r#"
sops:
    version: "3.8.0"
    age: age1test123456789
    mac: ABCDEF1234567890
app1:
    api_key: key1
"#;
        fs::write(&file1, yaml1).unwrap();

        // Write second SOPS file
        let file2 = temp_dir.path().join("app2.yaml");
        let yaml2 = r#"
sops:
    version: "3.8.0"
    age: age1test123456789
    mac: ABCDEF1234567890
app2:
    api_key: key2
"#;
        fs::write(&file2, yaml2).unwrap();

        let config = SopsBackendConfig {
            directory: temp_dir.path().to_path_buf(),
            ..Default::default()
        };

        let backend = SopsBackend::new(config).unwrap();

        // Test list operation - should have secrets from both files
        let result = backend.list("").await;
        assert!(result.is_ok());
        let secrets = result.unwrap();
        assert_eq!(secrets.len(), 2);

        // Test get operation from both files
        let path1 = SecretPath::new("app1/api_key").unwrap();
        let value1 = backend.get(&path1).await.unwrap();
        let exposed1 = value1.expose(|v| String::from_utf8(v.to_vec()).unwrap());
        assert_eq!(exposed1, "key1");

        let path2 = SecretPath::new("app2/api_key").unwrap();
        let value2 = backend.get(&path2).await.unwrap();
        let exposed2 = value2.expose(|v| String::from_utf8(v.to_vec()).unwrap());
        assert_eq!(exposed2, "key2");
    }

    #[tokio::test]
    async fn test_sops_backend_get_non_scalar_value() {
        let temp_dir = TempDir::new().unwrap();
        let sops_file = temp_dir.path().join("test.yaml");

        // Write a SOPS file with a nested structure (not a scalar leaf value)
        let yaml_content = r#"
sops:
    version: "3.8.0"
    age: age1test123456789
    mac: ABCDEF1234567890
myapp:
    config:
        nested: value
"#;
        fs::write(&sops_file, yaml_content).unwrap();

        let config = SopsBackendConfig {
            directory: temp_dir.path().to_path_buf(),
            ..Default::default()
        };

        let backend = SopsBackend::new(config).unwrap();

        // Test get operation on a path that points to a mapping (not a scalar)
        let path = SecretPath::new("myapp/config").unwrap();
        let result = backend.get(&path).await;

        // Should fail because config is not a scalar value
        assert!(result.is_err());
        match result {
            Err(SigilError::IoError(msg)) => {
                assert!(msg.contains("not a scalar value"));
            }
            Err(e) => panic!("Expected IoError about non-scalar value, got: {:?}", e),
            Ok(_) => panic!("Expected error, got Ok"),
        }
    }
}
