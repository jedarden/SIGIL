//! Canary types and core structures

use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use zeroize::Zeroize;

/// Kind of canary secret
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum CanaryKind {
    /// AWS credentials file (~/.aws/credentials)
    AwsCredentials,
    /// SSH private key (~/.ssh/id_sigil_canary)
    SshKey,
    /// GitHub CLI config (~/.config/gh/hosts.yml)
    GitHubToken,
    /// Environment file (.env in project root)
    EnvFile,
    /// Stripe API key
    StripeKey,
    /// JWT token
    JwtToken,
    /// PEM certificate
    PemCertificate,
    /// Generic canary
    Generic,
}

impl CanaryKind {
    /// Get the default file path for this canary kind
    pub fn default_path(&self) -> PathBuf {
        match self {
            CanaryKind::AwsCredentials => PathBuf::from(".aws/credentials"),
            CanaryKind::SshKey => PathBuf::from(".ssh/id_sigil_canary"),
            CanaryKind::GitHubToken => PathBuf::from(".config/gh/hosts.yml"),
            CanaryKind::EnvFile => PathBuf::from(".env"),
            CanaryKind::StripeKey => PathBuf::from(".sigil/canaries/stripe_key"),
            CanaryKind::JwtToken => PathBuf::from(".sigil/canaries/jwt_token"),
            CanaryKind::PemCertificate => PathBuf::from(".sigil/canaries/cert.pem"),
            CanaryKind::Generic => PathBuf::from(".sigil-canary"),
        }
    }
}

impl std::fmt::Display for CanaryKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CanaryKind::AwsCredentials => write!(f, "aws_credentials"),
            CanaryKind::SshKey => write!(f, "ssh_key"),
            CanaryKind::GitHubToken => write!(f, "github_token"),
            CanaryKind::EnvFile => write!(f, "env_file"),
            CanaryKind::StripeKey => write!(f, "stripe_key"),
            CanaryKind::JwtToken => write!(f, "jwt_token"),
            CanaryKind::PemCertificate => write!(f, "pem_certificate"),
            CanaryKind::Generic => write!(f, "generic"),
        }
    }
}

/// A canary secret that detects unauthorized access
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CanarySecret {
    /// Unique identifier for this canary
    pub id: String,
    /// Kind of canary
    pub kind: CanaryKind,
    /// The fake secret value (in memory only)
    #[serde(skip)]
    value: Vec<u8>,
    /// File path where this canary is "placed" (relative to home)
    pub path: PathBuf,
    /// When this canary was created
    pub created_at: chrono::DateTime<chrono::Utc>,
    /// Whether this canary has been triggered (accessed)
    pub triggered: bool,
    /// When this canary was triggered (if applicable)
    pub triggered_at: Option<chrono::DateTime<chrono::Utc>>,
}

impl CanarySecret {
    /// Create a new canary secret
    pub fn new(kind: CanaryKind, value: Vec<u8>, path: PathBuf) -> Self {
        use rand::Rng;
        let id: String = rand::thread_rng()
            .sample_iter(&rand::distributions::Alphanumeric)
            .take(16)
            .map(char::from)
            .collect();

        Self {
            id,
            kind,
            value,
            path,
            created_at: chrono::Utc::now(),
            triggered: false,
            triggered_at: None,
        }
    }

    /// Get the canary value (exposing it securely)
    pub fn value(&self) -> &[u8] {
        &self.value
    }

    /// Get the path relative to home directory
    pub fn relative_path(&self) -> PathBuf {
        self.path.clone()
    }

    /// Get the full path in the sandbox overlay
    pub fn sandbox_path(&self, sandbox_overlay: &std::path::Path) -> PathBuf {
        sandbox_overlay.join(&self.path)
    }

    /// Mark this canary as triggered
    pub fn mark_triggered(&mut self) {
        self.triggered = true;
        self.triggered_at = Some(chrono::Utc::now());
    }

    /// Check if this canary has been triggered
    pub fn is_triggered(&self) -> bool {
        self.triggered
    }
}

impl Drop for CanarySecret {
    fn drop(&mut self) {
        // Zeroize the secret value on drop
        self.value.zeroize();
    }
}

/// A canary file that exists in the sandbox overlay
#[derive(Debug, Clone)]
pub struct CanaryFile {
    /// The underlying canary secret
    pub secret: CanarySecret,
    /// Full path to the canary file in the overlay
    pub overlay_path: PathBuf,
}

impl CanaryFile {
    /// Create a new canary file
    pub fn new(secret: CanarySecret, overlay_path: PathBuf) -> Self {
        Self {
            secret,
            overlay_path,
        }
    }

    /// Write the canary file to the overlay (in-memory/tmpfs only)
    pub fn write_to_overlay(&self) -> anyhow::Result<()> {
        // Ensure parent directory exists
        if let Some(parent) = self.overlay_path.parent() {
            std::fs::create_dir_all(parent)?;
        }

        std::fs::write(&self.overlay_path, self.secret.value())?;
        tracing::debug!("Wrote canary file: {:?}", self.overlay_path);

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_canary_kind_paths() {
        assert_eq!(
            CanaryKind::AwsCredentials.default_path(),
            PathBuf::from(".aws/credentials")
        );
        assert_eq!(
            CanaryKind::SshKey.default_path(),
            PathBuf::from(".ssh/id_sigil_canary")
        );
        assert_eq!(
            CanaryKind::GitHubToken.default_path(),
            PathBuf::from(".config/gh/hosts.yml")
        );
        assert_eq!(CanaryKind::EnvFile.default_path(), PathBuf::from(".env"));
    }

    #[test]
    fn test_canary_secret_creation() {
        let secret = CanarySecret::new(
            CanaryKind::AwsCredentials,
            b"fake aws credentials".to_vec(),
            PathBuf::from(".aws/credentials"),
        );

        assert!(!secret.is_triggered());
        assert_eq!(secret.kind, CanaryKind::AwsCredentials);
        assert_eq!(secret.value(), b"fake aws credentials");
        assert!(!secret.id.is_empty());
    }

    #[test]
    fn test_canary_secret_trigger() {
        let mut secret = CanarySecret::new(
            CanaryKind::GitHubToken,
            b"fake github token".to_vec(),
            PathBuf::from(".config/gh/hosts.yml"),
        );

        assert!(!secret.is_triggered());
        assert!(secret.triggered_at.is_none());

        secret.mark_triggered();

        assert!(secret.is_triggered());
        assert!(secret.triggered_at.is_some());
    }

    #[test]
    fn test_canary_file_overlay_path() {
        let secret = CanarySecret::new(
            CanaryKind::EnvFile,
            b"FAKE_KEY=fake_value".to_vec(),
            PathBuf::from(".env"),
        );

        let overlay = PathBuf::from("/tmp/sigil-overlay");
        assert_eq!(
            secret.sandbox_path(&overlay),
            PathBuf::from("/tmp/sigil-overlay/.env")
        );
    }
}
