//! SIGIL Git Credential Helper
//!
//! This crate implements the Git credential helper protocol for SIGIL.
//!
//! Git invokes credential helpers with stdin containing key-value pairs
//! and expects a response with key-value pairs or a non-zero exit status.
//!
//! # Protocol
//!
//! Input (git -> helper):
//! ```text
//! protocol=https
//! host=github.com
//! path=jedarden/sigil.git
//! ```
//!
//! Output (helper -> git):
//! ```text
//! username=token
//! password=ghp_xxx
//! ```
//!
//! # Subcommands
//!
//! - `get`: Retrieve credentials for a given host
//! - `store`: Store credentials (not implemented, uses vault)
//! - `erase`: Erase credentials (not implemented, uses vault)

#![warn(missing_docs)]
#![warn(clippy::all)]

use anyhow::{Context, Result};
use sigil_core::{SecretBackend, SecretPath};
use sigil_vault::LocalVault;
use std::collections::HashMap;
use std::fs;
use std::io::{self, BufRead, BufReader, Write};
use std::path::PathBuf;

/// Default mapping of git hosts to vault secret paths
const DEFAULT_HOST_MAPPINGS: &[(&str, &str)] = &[
    ("github.com", "github/token"),
    ("gitlab.com", "gitlab/token"),
    ("bitbucket.org", "bitbucket/token"),
    ("gitea.com", "gitea/token"),
    ("codeberg.org", "codeberg/token"),
];

/// Git credential request
#[derive(Debug, Clone)]
pub struct CredentialRequest {
    /// Protocol (http, https, ssh, git)
    pub protocol: Option<String>,
    /// Host (e.g., github.com)
    pub host: Option<String>,
    /// Path (e.g., jedarden/sigil.git)
    pub path: Option<String>,
    /// Username (if provided by git)
    pub username: Option<String>,
    /// Password (if provided by git, for store/erase)
    pub password: Option<String>,
    /// All other fields
    pub extra: HashMap<String, String>,
}

/// Git credential response
#[derive(Debug, Clone)]
pub struct CredentialResponse {
    /// Username
    pub username: Option<String>,
    /// Password/token
    pub password: Option<String>,
    /// All other fields
    pub extra: HashMap<String, String>,
}

impl CredentialResponse {
    /// Write the response to stdout in git credential protocol format
    pub fn write_to(&self, mut writer: impl Write) -> Result<()> {
        if let Some(username) = &self.username {
            writeln!(writer, "username={}", username)?;
        }
        if let Some(password) = &self.password {
            writeln!(writer, "password={}", password)?;
        }
        for (key, value) in &self.extra {
            writeln!(writer, "{}={}", key, value)?;
        }
        writeln!(writer)?;
        Ok(())
    }
}

/// Configuration for git credential mappings
#[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
pub struct GitCredentialConfig {
    /// Mapping of host patterns to secret paths
    #[serde(default)]
    pub host_mappings: HashMap<String, String>,
}

impl Default for GitCredentialConfig {
    fn default() -> Self {
        Self {
            host_mappings: DEFAULT_HOST_MAPPINGS
                .iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect(),
        }
    }
}

impl GitCredentialConfig {
    /// Load config from .sigil/git-credentials.toml if it exists
    pub fn load_from_project() -> Result<Option<Self>> {
        let config_path = Self::project_config_path()?;
        if !config_path.exists() {
            return Ok(None);
        }

        let content = fs::read_to_string(&config_path)
            .with_context(|| format!("Failed to read {}", config_path.display()))?;

        toml::from_str(&content)
            .with_context(|| format!("Failed to parse {}", config_path.display()))
            .map(Some)
    }

    /// Load config, falling back to defaults if no project config exists
    pub fn load() -> Result<Self> {
        Ok(Self::load_from_project()?.unwrap_or_default())
    }

    /// Get the path to the project-specific git-credentials.toml
    fn project_config_path() -> Result<PathBuf> {
        let current_dir = std::env::current_dir()?;
        Ok(current_dir.join(".sigil").join("git-credentials.toml"))
    }

    /// Find the secret path for a given host
    pub fn find_secret_path(&self, host: &str) -> Option<String> {
        // Try exact match first
        if let Some(path) = self.host_mappings.get(host) {
            return Some(path.clone());
        }

        // Try wildcard match (*.domain.com)
        for (pattern, path) in &self.host_mappings {
            if let Some(base) = pattern.strip_prefix("*.") {
                if host.ends_with(base) {
                    return Some(path.clone());
                }
            }
        }

        None
    }
}

/// Git credential helper
pub struct GitCredentialHelper {
    config: GitCredentialConfig,
    vault_dir: PathBuf,
    identity_path: PathBuf,
}

impl GitCredentialHelper {
    /// Create a new credential helper
    pub fn new() -> Result<Self> {
        let vault_dir = dirs::home_dir()
            .ok_or_else(|| anyhow::anyhow!("Cannot determine home directory"))?
            .join(".sigil");

        let identity_path = vault_dir.join("identity.age");

        let config = GitCredentialConfig::load()?;

        Ok(Self {
            config,
            vault_dir,
            identity_path,
        })
    }

    /// Run the credential helper for the given subcommand
    pub fn run(subcommand: &str) -> Result<()> {
        let helper = Self::new()?;

        match subcommand {
            "get" => helper.get(),
            "store" => helper.store(),
            "erase" => helper.erase(),
            _ => Err(anyhow::anyhow!("Unknown subcommand: {}", subcommand)),
        }
    }

    /// Handle the `get` subcommand - retrieve credentials
    fn get(&self) -> Result<()> {
        // Read request from stdin
        let request = Self::read_request()?;

        // Find the host
        let host = request
            .host
            .as_ref()
            .context("Missing host in credential request")?;

        // Map host to secret path
        let secret_path = self
            .config
            .find_secret_path(host)
            .with_context(|| anyhow::anyhow!("No secret path configured for host: {}", host))?;

        // Prompt for passphrase
        eprint!("Enter vault passphrase (leave empty if no passphrase): ");
        io::stdout().flush()?;
        let mut passphrase = String::new();
        io::stdin().read_line(&mut passphrase)?;
        let passphrase = if passphrase.trim().is_empty() {
            None
        } else {
            Some(passphrase.trim().to_string())
        };

        // Create and load the vault
        let mut vault = LocalVault::new(self.vault_dir.join("vault"), self.identity_path.clone())?;
        vault
            .load(passphrase.as_deref())
            .context("Failed to unlock vault")?;

        // Use tokio runtime for async get operation
        let rt = tokio::runtime::Runtime::new().context("Failed to create async runtime")?;
        let secret_path_obj = SecretPath::new(&secret_path)?;
        let secret_value = rt
            .block_on(vault.get(&secret_path_obj))
            .context("Failed to get secret from vault")?;

        // Copy the secret bytes to an owned Vec for conversion
        let secret_bytes = secret_value.expose(|v| v.to_vec());
        let token =
            std::str::from_utf8(&secret_bytes).context("Secret value is not valid UTF-8")?;

        // Build response
        let response = CredentialResponse {
            username: Some("git".to_string()), // Git uses "git" as username for token auth
            password: Some(token.to_string()),
            extra: HashMap::new(),
        };

        // Write response to stdout
        response.write_to(io::stdout())?;

        Ok(())
    }

    /// Handle the `store` subcommand - credentials are stored in the vault, not via git
    fn store(&self) -> Result<()> {
        // Read request but don't store - credentials should be added via `sigil add`
        Self::read_request()?;

        // Exit with success but do nothing
        // (users should use `sigil add github/token` to store credentials)
        Ok(())
    }

    /// Handle the `erase` subcommand - credentials are removed from the vault, not via git
    fn erase(&self) -> Result<()> {
        // Read request but don't erase - credentials should be removed via `sigil rm`
        Self::read_request()?;

        // Exit with success but do nothing
        // (users should use `sigil rm github/token` to remove credentials)
        Ok(())
    }

    /// Read a credential request from stdin
    fn read_request() -> Result<CredentialRequest> {
        let stdin = io::stdin();
        let reader = BufReader::new(stdin.lock());

        let mut protocol = None;
        let mut host = None;
        let mut path = None;
        let mut username = None;
        let mut password = None;
        let mut extra = HashMap::new();

        for line in reader.lines() {
            let line = line?;
            if line.is_empty() {
                break; // Empty line marks end of input
            }

            if let Some((key, value)) = line.split_once('=') {
                match key {
                    "protocol" => protocol = Some(value.to_string()),
                    "host" => host = Some(value.to_string()),
                    "path" => path = Some(value.to_string()),
                    "username" => username = Some(value.to_string()),
                    "password" => password = Some(value.to_string()),
                    _ => {
                        extra.insert(key.to_string(), value.to_string());
                    }
                }
            }
        }

        Ok(CredentialRequest {
            protocol,
            host,
            path,
            username,
            password,
            extra,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_mappings() {
        let config = GitCredentialConfig::default();
        assert_eq!(
            config.find_secret_path("github.com"),
            Some("github/token".to_string())
        );
        assert_eq!(
            config.find_secret_path("gitlab.com"),
            Some("gitlab/token".to_string())
        );
        assert!(config.find_secret_path("unknown.com").is_none());
    }

    #[test]
    fn test_wildcard_mappings() {
        let mut config = GitCredentialConfig::default();
        config
            .host_mappings
            .insert("*.example.com".to_string(), "example/token".to_string());

        assert_eq!(
            config.find_secret_path("api.example.com"),
            Some("example/token".to_string())
        );
        assert_eq!(
            config.find_secret_path("foo.example.com"),
            Some("example/token".to_string())
        );
    }

    #[test]
    fn test_response_write() {
        let response = CredentialResponse {
            username: Some("git".to_string()),
            password: Some("ghp_token".to_string()),
            extra: {
                let mut map = HashMap::new();
                map.insert("key".to_string(), "value".to_string());
                map
            },
        };

        let mut output = Vec::new();
        response.write_to(&mut output).unwrap();

        let output_str = String::from_utf8(output).unwrap();
        assert!(output_str.contains("username=git"));
        assert!(output_str.contains("password=ghp_token"));
        assert!(output_str.contains("key=value"));
    }
}
