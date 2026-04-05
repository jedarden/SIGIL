//! Canary secret generator
//!
//! Generates realistic-looking fake credentials for canary files.

use rand::Rng;
use std::path::PathBuf;

use crate::canary::{CanaryKind, CanarySecret};

/// Base64 URL-safe encoding (no padding)
fn base64_url_encode(data: &[u8]) -> String {
    use base64::prelude::*;
    BASE64_URL_SAFE_NO_PAD.encode(data)
}

/// Generates canary secrets
#[derive(Debug, Clone)]
pub struct CanaryGenerator;

impl CanaryGenerator {
    /// Create a new generator
    pub fn new() -> Self {
        Self
    }

    /// Generate an AWS credentials file canary
    ///
    /// Format:
    /// ```text
    /// [default]
    /// aws_access_key_id = AKIAIOSFODNN7EXAMPLE
    /// aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
    /// ```
    pub fn generate_aws_credentials(&self) -> CanarySecret {
        let access_key = format!("AKIA{}", self.random_alphanumeric(16));
        let secret_key = self.random_alphanumeric(40);

        let content = format!(
            "[default]\naws_access_key_id = {}\naws_secret_access_key = {}\n",
            access_key, secret_key
        );

        CanarySecret::new(
            CanaryKind::AwsCredentials,
            content.into_bytes(),
            CanaryKind::AwsCredentials.default_path(),
        )
    }

    /// Generate an SSH private key canary
    ///
    /// Creates a fake PEM-encoded RSA key (looks like a real expired key)
    pub fn generate_ssh_key(&self) -> CanarySecret {
        // Generate a realistic-looking fake PEM file
        // NO identifying comments - agent cannot distinguish from real expired key
        let pem_header = format!(
            "-----BEGIN RSA PRIVATE KEY-----\n\
             {}\n\
             {}\
             -----END RSA PRIVATE KEY-----\n",
            self.random_base64(10),
            self.random_base64(20)
        );

        CanarySecret::new(
            CanaryKind::SshKey,
            pem_header.into_bytes(),
            CanaryKind::SshKey.default_path(),
        )
    }

    /// Generate a GitHub CLI config canary
    ///
    /// Format:
    /// ```text
    /// github.com:
    ///   oauth_token: ghp_exampletoken123456789012345678901234567890
    ///   user: sigil-canary-user
    /// ```
    pub fn generate_github_token(&self) -> CanarySecret {
        let token = format!("ghp_{}", self.random_alphanumeric(36));

        let content = format!(
            "github.com:\n  oauth_token: {}\n  user: sigil-canary-user\n",
            token
        );

        CanarySecret::new(
            CanaryKind::GitHubToken,
            content.into_bytes(),
            CanaryKind::GitHubToken.default_path(),
        )
    }

    /// Generate a Stripe API key canary
    ///
    /// Format: `sk_live_` + 24 alphanumeric (looks like a real expired key)
    pub fn generate_stripe_key(&self) -> CanarySecret {
        let key = format!("sk_live_{}", self.random_alphanumeric(24));

        CanarySecret::new(
            CanaryKind::StripeKey,
            key.into_bytes(),
            CanaryKind::StripeKey.default_path(),
        )
    }

    /// Generate a JWT token canary
    ///
    /// Format: valid header.payload.signature structure with garbage content
    /// The token looks real but will fail verification
    pub fn generate_jwt_token(&self) -> CanarySecret {
        // JWT header (algorithm: HS256, type: JWT)
        let header = base64_url_encode(b"{\"alg\":\"HS256\",\"typ\":\"JWT\"}");

        // JWT payload (random claims that look real but are garbage)
        let payload = base64_url_encode(
            format!(
                "{{\"sub\":\"user{}\",\"exp\":{},\"iat\":{}}}",
                self.random_alphanumeric(8),
                // Expired timestamp (1 day ago)
                chrono::Utc::now().timestamp() - 86400,
                // Issued at timestamp (2 days ago)
                chrono::Utc::now().timestamp() - 172800
            )
            .as_bytes(),
        );

        // JWT signature (random garbage that won't verify)
        let signature = self.random_alphanumeric(43);

        let token = format!("{}.{}.{}", header, payload, signature);

        CanarySecret::new(
            CanaryKind::JwtToken,
            token.into_bytes(),
            CanaryKind::JwtToken.default_path(),
        )
    }

    /// Generate a PEM certificate canary
    ///
    /// Format: valid but self-signed, expired certificate
    /// Looks like a real cert that's just expired
    pub fn generate_pem_certificate(&self) -> CanarySecret {
        // Generate a realistic-looking PEM certificate structure
        // This looks like a real cert but is expired and self-signed
        let cert = format!(
            "-----BEGIN CERTIFICATE-----\n\
             {}\n\
             {}\n\
             -----END CERTIFICATE-----\n",
            self.random_base64(20),
            self.random_base64(20)
        );

        CanarySecret::new(
            CanaryKind::PemCertificate,
            cert.into_bytes(),
            CanaryKind::PemCertificate.default_path(),
        )
    }

    /// Generate a .env file canary
    ///
    /// Contains several fake environment variables (looks like a real .env file)
    pub fn generate_env_file(&self) -> CanarySecret {
        let api_key = self.random_alphanumeric(32);
        let db_password = self.random_alphanumeric(24);
        let secret_key = self.random_alphanumeric(64);

        // NO identifying comments - agent cannot distinguish from real .env file
        let content = format!(
            "API_KEY=sk_{}\n\
             DB_PASSWORD={}\n\
             SECRET_KEY={}\n",
            api_key, db_password, secret_key
        );

        CanarySecret::new(
            CanaryKind::EnvFile,
            content.into_bytes(),
            PathBuf::from(".env"),
        )
    }

    /// Generate all standard canaries
    pub fn generate_all(&self) -> Vec<CanarySecret> {
        vec![
            self.generate_aws_credentials(),
            self.generate_ssh_key(),
            self.generate_github_token(),
            self.generate_env_file(),
            self.generate_stripe_key(),
            self.generate_jwt_token(),
            self.generate_pem_certificate(),
        ]
    }

    /// Generate a random alphanumeric string
    fn random_alphanumeric(&self, len: usize) -> String {
        rand::thread_rng()
            .sample_iter(&rand::distributions::Alphanumeric)
            .take(len)
            .map(char::from)
            .collect()
    }

    /// Generate a random base64 string
    fn random_base64(&self, lines: usize) -> String {
        (0..lines)
            .map(|_| {
                let bytes: Vec<u8> = (0..64).map(|_| rand::random::<u8>()).collect();
                use base64::prelude::*;
                BASE64_STANDARD.encode(&bytes)
            })
            .collect::<Vec<_>>()
            .join("\n")
    }
}

impl Default for CanaryGenerator {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_aws_credentials() {
        let gen = CanaryGenerator::new();
        let canary = gen.generate_aws_credentials();

        assert_eq!(canary.kind, CanaryKind::AwsCredentials);
        let content = String::from_utf8_lossy(canary.value());
        assert!(content.contains("aws_access_key_id"));
        assert!(content.contains("AKIA"));
    }

    #[test]
    fn test_generate_ssh_key() {
        let gen = CanaryGenerator::new();
        let canary = gen.generate_ssh_key();

        assert_eq!(canary.kind, CanaryKind::SshKey);
        let content = String::from_utf8_lossy(canary.value());
        // Should look like a real RSA private key
        assert!(content.contains("BEGIN RSA PRIVATE KEY"));
        assert!(content.contains("END RSA PRIVATE KEY"));
        // Should NOT contain identifying comments
        assert!(!content.contains("SIGIL CANARY"));
    }

    #[test]
    fn test_generate_github_token() {
        let gen = CanaryGenerator::new();
        let canary = gen.generate_github_token();

        assert_eq!(canary.kind, CanaryKind::GitHubToken);
        let content = String::from_utf8_lossy(canary.value());
        assert!(content.contains("ghp_"));
        assert!(content.contains("oauth_token"));
    }

    #[test]
    fn test_generate_env_file() {
        let gen = CanaryGenerator::new();
        let canary = gen.generate_env_file();

        assert_eq!(canary.kind, CanaryKind::EnvFile);
        let content = String::from_utf8_lossy(canary.value());
        assert!(content.contains("API_KEY="));
        assert!(content.contains("DB_PASSWORD="));
        assert!(content.contains("SECRET_KEY="));
        // .env file should start with sk_ for API key (looks like real Stripe/Secret key)
        assert!(content.contains("sk_"));
    }

    #[test]
    fn test_generate_all() {
        let gen = CanaryGenerator::new();
        let canaries = gen.generate_all();

        assert_eq!(canaries.len(), 7);
        assert!(canaries
            .iter()
            .any(|c| c.kind == CanaryKind::AwsCredentials));
        assert!(canaries.iter().any(|c| c.kind == CanaryKind::SshKey));
        assert!(canaries.iter().any(|c| c.kind == CanaryKind::GitHubToken));
        assert!(canaries.iter().any(|c| c.kind == CanaryKind::EnvFile));
        assert!(canaries.iter().any(|c| c.kind == CanaryKind::StripeKey));
        assert!(canaries.iter().any(|c| c.kind == CanaryKind::JwtToken));
        assert!(canaries
            .iter()
            .any(|c| c.kind == CanaryKind::PemCertificate));
    }

    #[test]
    fn test_generate_stripe_key() {
        let gen = CanaryGenerator::new();
        let canary = gen.generate_stripe_key();

        assert_eq!(canary.kind, CanaryKind::StripeKey);
        let content = String::from_utf8_lossy(canary.value());
        assert!(content.starts_with("sk_live_"));
        // Should be 31 characters (7 + 24) plus newline
        let trimmed = content.trim();
        assert!(
            trimmed.len() >= 31,
            "Stripe key should be at least 31 characters, got {}",
            trimmed.len()
        );
        assert!(
            trimmed.len() <= 32,
            "Stripe key should be at most 32 characters, got {}",
            trimmed.len()
        );
    }

    #[test]
    fn test_generate_jwt_token() {
        let gen = CanaryGenerator::new();
        let canary = gen.generate_jwt_token();

        assert_eq!(canary.kind, CanaryKind::JwtToken);
        let content = String::from_utf8_lossy(canary.value());

        // JWT should have 3 parts separated by dots
        let parts: Vec<&str> = content.split('.').collect();
        assert_eq!(parts.len(), 3);

        // Header should decode to JWT header
        let header = base64_url_decode(parts[0]);
        assert!(header.contains("\"alg\""));
        assert!(header.contains("\"typ\""));
    }

    #[test]
    fn test_generate_pem_certificate() {
        let gen = CanaryGenerator::new();
        let canary = gen.generate_pem_certificate();

        assert_eq!(canary.kind, CanaryKind::PemCertificate);
        let content = String::from_utf8_lossy(canary.value());
        assert!(content.contains("BEGIN CERTIFICATE"));
        assert!(content.contains("END CERTIFICATE"));
    }

    #[test]
    fn test_decoy_has_no_identifying_comments() {
        let gen = CanaryGenerator::new();

        // .env file should not have "SIGIL CANARY" or "canary_" prefix
        let env_canary = gen.generate_env_file();
        let env_content = String::from_utf8_lossy(env_canary.value());
        assert!(!env_content.contains("SIGIL CANARY"));
        assert!(!env_content.contains("canary_"));

        // SSH key should not have identifying comments
        let ssh_canary = gen.generate_ssh_key();
        let ssh_content = String::from_utf8_lossy(ssh_canary.value());
        assert!(!ssh_content.contains("SIGIL CANARY"));
        assert!(!ssh_content.contains("DO NOT USE"));
    }

    /// Base64 URL-safe decoding (no padding)
    fn base64_url_decode(data: &str) -> String {
        use base64::prelude::*;
        let decoded = BASE64_URL_SAFE_NO_PAD.decode(data).unwrap_or_default();
        String::from_utf8_lossy(&decoded).to_string()
    }
}
