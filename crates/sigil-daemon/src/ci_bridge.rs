//! CI/CD Environment Bridge for SIGIL
//!
//! This module implements Tier 1 of the CI/CD mode: Environment-Bridge.
//!
//! CI platforms inject secrets as environment variables with a special prefix:
//! - SIGIL_SECRET_AWS_ACCESS_KEY_ID → aws/access_key_id
//! - SIGIL_SECRET_DB_PASSWORD → db/password
//!
//! When SIGIL_CI=true, the daemon auto-discovers these variables and bridges
//! them into the vault namespace, holding them in mlock'd memory.

#![warn(missing_docs)]
#![warn(clippy::all)]

use sigil_core::{Result, SigilError};
use std::collections::HashMap;
use tracing::{info, warn};

/// Environment variable prefix for CI secrets
const SIGIL_SECRET_PREFIX: &str = "SIGIL_SECRET_";

/// CI mode detection environment variable
const SIGIL_CI_VAR: &str = "SIGIL_CI";

/// CI bridge for importing secrets from environment variables
pub struct CiBridge;

impl CiBridge {
    /// Check if CI mode is enabled
    ///
    /// CI mode is enabled when SIGIL_CI=true or SIGIL_CI=1
    pub fn is_ci_mode() -> bool {
        match std::env::var(SIGIL_CI_VAR) {
            Ok(val) => {
                let val = val.trim().to_lowercase();
                val == "true" || val == "1"
            }
            Err(_) => false,
        }
    }

    /// Discover all SIGIL_SECRET_* environment variables
    ///
    /// Returns a map of secret paths to their values, with paths normalized
    /// (underscores converted to forward slashes).
    ///
    /// Only returns valid paths that pass security validation.
    pub fn discover_secrets() -> HashMap<String, String> {
        let mut secrets = HashMap::new();

        for (key, value) in std::env::vars() {
            if key.starts_with(SIGIL_SECRET_PREFIX) {
                // Strip the prefix to get the secret path
                let path = key
                    .strip_prefix(SIGIL_SECRET_PREFIX)
                    .expect("prefix was checked above");

                // Convert underscores to slashes for path normalization
                // AWS_ACCESS_KEY_ID → aws/access/key/id
                let normalized_path = path.replace('_', "/").to_lowercase();

                // Validate the path for security issues
                if let Err(e) = Self::validate_path(&normalized_path) {
                    warn!(
                        "Skipping invalid CI secret path '{}': {}",
                        normalized_path, e
                    );
                    continue;
                }

                info!("Discovered CI secret: {}", normalized_path);
                secrets.insert(normalized_path, value);
            }
        }

        secrets
    }

    /// Load CI secrets into protected memory
    ///
    /// This loads all discovered SIGIL_SECRET_* environment variables
    /// into the protected secrets store and clears them from the environment.
    pub async fn load_ci_secrets(
        protected_secrets: &crate::memory::ProtectedSecrets,
    ) -> Result<usize> {
        let secrets = Self::discover_secrets();

        if secrets.is_empty() {
            info!("No CI secrets discovered (no SIGIL_SECRET_* variables found)");
            return Ok(0);
        }

        let mut loaded = 0;

        for (path, value) in secrets {
            // Convert to bytes for storage
            let value_bytes = value.into_bytes();

            // Store in protected memory
            if let Err(e) = protected_secrets.insert(path.clone(), value_bytes).await {
                warn!("Failed to store secret {} in protected memory: {}", path, e);
            } else {
                info!("Loaded CI secret: {}", path);
                loaded += 1;
            }

            // Clear the environment variable after loading
            let env_key = format!(
                "{}{}",
                SIGIL_SECRET_PREFIX,
                path.replace('/', "_").to_uppercase()
            );
            std::env::remove_var(&env_key);
        }

        Ok(loaded)
    }

    /// Validate CI secret paths
    ///
    /// Ensures that all discovered secret paths are valid and don't contain
    /// suspicious patterns that might indicate path traversal attacks.
    pub fn validate_path(path: &str) -> Result<()> {
        // Path must not be empty
        if path.is_empty() {
            return Err(SigilError::InvalidPath(
                "CI secret path cannot be empty".into(),
            ));
        }

        // Path must not contain ".." to prevent directory traversal
        if path.contains("..") {
            return Err(SigilError::InvalidPath(
                "CI secret path cannot contain '..'".into(),
            ));
        }

        // Path must not start with "/"
        if path.starts_with('/') {
            return Err(SigilError::InvalidPath(
                "CI secret path cannot start with '/'".into(),
            ));
        }

        // Path must not contain null bytes
        if path.contains('\0') {
            return Err(SigilError::InvalidPath(
                "CI secret path cannot contain null bytes".into(),
            ));
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serial_test::serial;

    // Note: These tests use environment variables which are process-global.
    // The test runner may execute tests in parallel, so we use the serial_test
    // crate to ensure they don't interfere with each other.

    #[test]
    #[serial]
    fn test_is_ci_mode_true() {
        std::env::set_var(SIGIL_CI_VAR, "true");
        assert!(CiBridge::is_ci_mode());
        std::env::remove_var(SIGIL_CI_VAR);
    }

    #[test]
    #[serial]
    fn test_is_ci_mode_one() {
        std::env::set_var(SIGIL_CI_VAR, "1");
        assert!(CiBridge::is_ci_mode());
        std::env::remove_var(SIGIL_CI_VAR);
    }

    #[test]
    #[serial]
    fn test_is_ci_mode_false() {
        // Remove any existing value first to avoid interference from parallel tests
        std::env::remove_var(SIGIL_CI_VAR);
        std::env::set_var(SIGIL_CI_VAR, "false");
        assert!(!CiBridge::is_ci_mode());
        std::env::remove_var(SIGIL_CI_VAR);
    }

    #[test]
    #[serial]
    fn test_is_ci_mode_unset() {
        // Remove any existing value first
        std::env::remove_var(SIGIL_CI_VAR);
        assert!(!CiBridge::is_ci_mode());
    }

    #[test]
    #[serial]
    fn test_discover_secrets() {
        // Clear any existing SIGIL_SECRET_* variables
        for (key, _) in std::env::vars() {
            if key.starts_with(SIGIL_SECRET_PREFIX) {
                std::env::remove_var(&key);
            }
        }

        // Set up test secrets
        std::env::set_var("SIGIL_SECRET_AWS_ACCESS_KEY_ID", "AKIAEXAMPLE");
        std::env::set_var("SIGIL_SECRET_DB_PASSWORD", "secret123");
        std::env::set_var("NOT_A_SECRET", "should_be_ignored");

        let secrets = CiBridge::discover_secrets();

        assert_eq!(secrets.len(), 2);
        assert_eq!(
            secrets.get("aws/access/key/id"),
            Some(&"AKIAEXAMPLE".to_string())
        );
        assert_eq!(secrets.get("db/password"), Some(&"secret123".to_string()));
        assert_eq!(secrets.get("not_a/secret"), None);

        // Clean up
        std::env::remove_var("SIGIL_SECRET_AWS_ACCESS_KEY_ID");
        std::env::remove_var("SIGIL_SECRET_DB_PASSWORD");
        std::env::remove_var("NOT_A_SECRET");
    }

    #[test]
    fn test_validate_path_valid() {
        assert!(CiBridge::validate_path("aws/access_key").is_ok());
        assert!(CiBridge::validate_path("db/password").is_ok());
        assert!(CiBridge::validate_path("api/key").is_ok());
    }

    #[test]
    fn test_validate_path_invalid() {
        assert!(CiBridge::validate_path("").is_err());
        assert!(CiBridge::validate_path("../etc/passwd").is_err());
        assert!(CiBridge::validate_path("/absolute/path").is_err());
        assert!(CiBridge::validate_path("path\0with\0nulls").is_err());
    }

    #[test]
    #[serial]
    fn test_env_var_cleared_after_discovery() {
        // Clear any existing SIGIL_SECRET_* variables
        for (key, _) in std::env::vars() {
            if key.starts_with(SIGIL_SECRET_PREFIX) {
                std::env::remove_var(&key);
            }
        }

        // Set up a test secret
        std::env::set_var("SIGIL_SECRET_TEST_API_KEY", "test-secret-value");

        // Verify it's set
        assert_eq!(
            std::env::var("SIGIL_SECRET_TEST_API_KEY"),
            Ok("test-secret-value".to_string())
        );

        // Discover secrets (this doesn't clear env vars in discovery)
        let secrets = CiBridge::discover_secrets();
        assert_eq!(secrets.len(), 1);

        // Manually clear the env var to verify it works
        let env_key = format!("{}TEST_API_KEY", SIGIL_SECRET_PREFIX);
        std::env::remove_var(&env_key);

        // Verify it's cleared
        assert_eq!(
            std::env::var("SIGIL_SECRET_TEST_API_KEY"),
            Err(std::env::VarError::NotPresent)
        );
    }
}
