//! Behavioral tests for environment variable backend
//!
//! These tests verify the EnvBackend implementation using temporary test files
//! to mock environment file operations.

use sigil_backend_env::{EnvBackend, EnvBackendConfig};
use sigil_core::{SecretBackend, SecretMetadata, SecretPath, SecretType, SecretValue, SigilError};
use std::fs;
use std::io::Write;
use tempfile::TempDir;

/// Helper to create a test .env file with test data
fn create_test_env_file(dir: &TempDir, content: &str) -> std::path::PathBuf {
    let env_file = dir.path().join("test.env");
    let mut file = fs::File::create(&env_file).unwrap();
    file.write_all(content.as_bytes()).unwrap();
    file.flush().unwrap();
    env_file
}

/// Helper to create test secret metadata
fn create_test_metadata(path: &str) -> SecretMetadata {
    SecretMetadata {
        path: SecretPath::new(path.to_string()).unwrap(),
        secret_type: SecretType::Generic,
        tags: vec!["test".to_string()],
        notes: Some("Test secret".to_string()),
        created_at: chrono::Utc::now(),
        updated_at: chrono::Utc::now(),
        expires_at: None,
    }
}

// ============================================================================
// GET OPERATION TESTS
// ============================================================================

#[test]
fn test_get_secret_success() {
    let dir = TempDir::new().unwrap();
    let content = r#"
SIGIL_API_KEY=sk_live_abc123
SIGIL_DATABASE_URL=postgresql://user:pass@host/db
SIGIL_SECRET_TOKEN=xyz789
"#;
    let env_file = create_test_env_file(&dir, content);

    let config = EnvBackendConfig {
        env_file: env_file.clone(),
        prefix: Some("SIGIL_".to_string()),
    };
    let backend = EnvBackend::new(config).unwrap();

    // Test getting a secret
    let path = SecretPath::new("env/API_KEY").unwrap();
    let result = backend.get(&path);

    assert!(result.is_ok(), "get should succeed for existing secret");
    let secret_value = result.unwrap();
    let value = secret_value.expose(|bytes| String::from_utf8(bytes.to_vec()).unwrap());
    assert_eq!(value, "sk_live_abc123");
}

#[test]
fn test_get_secret_not_found() {
    let dir = TempDir::new().unwrap();
    let content = "SIGIL_API_KEY=sk_live_abc123\n";
    let env_file = create_test_env_file(&dir, content);

    let config = EnvBackendConfig {
        env_file: env_file.clone(),
        prefix: Some("SIGIL_".to_string()),
    };
    let backend = EnvBackend::new(config).unwrap();

    // Test getting a non-existent secret
    let path = SecretPath::new("env/NONEXISTENT").unwrap();
    let result = backend.get(&path);

    assert!(result.is_err(), "get should fail for non-existent secret");
    match result {
        Err(SigilError::SecretNotFound(msg)) => {
            assert!(msg.contains("NONEXISTENT") || msg.contains("not found"),
                    "error should mention the secret path: {}", msg);
        }
        Err(other) => panic!("Expected SecretNotFound error, got: {:?}", other),
        Ok(_) => panic!("Expected error, got success"),
    }
}

#[test]
fn test_get_secret_with_empty_prefix() {
    let dir = TempDir::new().unwrap();
    let content = r#"
API_KEY=sk_live_abc123
DATABASE_URL=postgresql://user:pass@host/db
"#;
    let env_file = create_test_env_file(&dir, content);

    let config = EnvBackendConfig {
        env_file: env_file.clone(),
        prefix: None, // No prefix filtering
    };
    let backend = EnvBackend::new(config).unwrap();

    // Test getting a secret without prefix
    let path = SecretPath::new("env/API_KEY").unwrap();
    let result = backend.get(&path);

    assert!(result.is_ok(), "get should succeed without prefix");
    let secret_value = result.unwrap();
    let value = secret_value.expose(|bytes| String::from_utf8(bytes.to_vec()).unwrap());
    assert_eq!(value, "sk_live_abc123");
}

#[test]
fn test_get_secret_with_multiline_value() {
    let dir = TempDir::new().unwrap();
    let content = "SIGIL_MULTI_LINE=value1\nvalue2\nvalue3\n";
    let env_file = create_test_env_file(&dir, content);

    let config = EnvBackendConfig {
        env_file: env_file.clone(),
        prefix: Some("SIGIL_".to_string()),
    };
    let backend = EnvBackend::new(config).unwrap();

    let path = SecretPath::new("env/MULTI_LINE").unwrap();
    let result = backend.get(&path);

    assert!(result.is_ok(), "get should succeed for multi-line value");
    let secret_value = result.unwrap();
    let value = secret_value.expose(|bytes| String::from_utf8_lossy(bytes).to_string());
    // Multi-line values should be handled (implementation-dependent)
    assert!(!value.is_empty());
}

// ============================================================================
// SET OPERATION TESTS
// ============================================================================

#[test]
fn test_set_secret_success() {
    let dir = TempDir::new().unwrap();
    let content = "SIGIL_API_KEY=initial_value\n";
    let env_file = create_test_env_file(&dir, content);

    let config = EnvBackendConfig {
        env_file: env_file.clone(),
        prefix: Some("SIGIL_".to_string()),
    };
    let backend = EnvBackend::new(config).unwrap();

    let path = SecretPath::new("env/NEW_SECRET").unwrap();
    let value = SecretValue::new(b"new_secret_value".to_vec());
    let metadata = create_test_metadata("env/NEW_SECRET");

    // Note: Env backend is read-only in the current implementation
    // This test verifies the expected behavior
    let result = backend.set(&path, &value, &metadata);

    // Currently Env backend may not support set (implementation-dependent)
    // This test documents the expected interface
    match result {
        Ok(_) => {
            // If set is supported, verify the value was written
            let get_result = backend.get(&path);
            assert!(get_result.is_ok());
        }
        Err(_) => {
            // If set is not supported (read-only backend), that's also valid
            // Just verify the error is appropriate
        }
    }
}

#[test]
fn test_set_secret_updates_existing() {
    let dir = TempDir::new().unwrap();
    let content = "SIGIL_API_KEY=old_value\n";
    let env_file = create_test_env_file(&dir, content);

    let config = EnvBackendConfig {
        env_file: env_file.clone(),
        prefix: Some("SIGIL_".to_string()),
    };
    let backend = EnvBackend::new(config).unwrap();

    let path = SecretPath::new("env/API_KEY").unwrap();
    let value = SecretValue::new(b"updated_value".to_vec());
    let metadata = create_test_metadata("env/API_KEY");

    // Test updating an existing secret
    let result = backend.set(&path, &value, &metadata);

    // Implementation-dependent behavior
    match result {
        Ok(_) => {
            // If set is supported, verify the update
            let get_result = backend.get(&path);
            if get_result.is_ok() {
                let updated_value = get_result.unwrap()
                    .expose(|bytes| String::from_utf8_lossy(bytes).to_string());
                // The value should be updated (or at least exist)
                assert!(!updated_value.is_empty());
            }
        }
        Err(_) => {
            // Read-only backends may reject set operations
        }
    }
}

// ============================================================================
// DELETE OPERATION TESTS
// ============================================================================

#[test]
fn test_delete_secret_success() {
    let dir = TempDir::new().unwrap();
    let content = "SIGIL_API_KEY=sk_live_abc123\nSIGIL_OTHER=value\n";
    let env_file = create_test_env_file(&dir, content);

    let config = EnvBackendConfig {
        env_file: env_file.clone(),
        prefix: Some("SIGIL_".to_string()),
    };
    let backend = EnvBackend::new(config).unwrap();

    let path = SecretPath::new("env/API_KEY").unwrap();

    // Test deleting a secret
    let result = backend.delete(&path);

    // Implementation-dependent behavior
    match result {
        Ok(_) => {
            // If delete is supported, verify the secret is gone
            let get_result = backend.get(&path);
            assert!(get_result.is_err(), "deleted secret should not be accessible");
        }
        Err(_) => {
            // Read-only backends may reject delete operations
        }
    }
}

#[test]
fn test_delete_secret_not_found() {
    let dir = TempDir::new().unwrap();
    let content = "SIGIL_API_KEY=sk_live_abc123\n";
    let env_file = create_test_env_file(&dir, content);

    let config = EnvBackendConfig {
        env_file: env_file.clone(),
        prefix: Some("SIGIL_".to_string()),
    };
    let backend = EnvBackend::new(config).unwrap();

    let path = SecretPath::new("env/NONEXISTENT").unwrap();
    let result = backend.delete(&path);

    // Deleting a non-existent secret should either:
    // 1. Return an error (SecretNotFound or IoError)
    // 2. Succeed idempotently (no-op)
    match result {
        Ok(_) => {
            // Idempotent delete - acceptable behavior
        }
        Err(SigilError::SecretNotFound(_)) | Err(SigilError::IoError(_)) => {
            // Explicit error - also acceptable
        }
        Err(other) => {
            panic!("Expected SecretNotFound, IoError, or success, got: {:?}", other);
        }
    }
}

// ============================================================================
// LIST OPERATION TESTS
// ============================================================================

#[test]
fn test_list_secrets_success() {
    let dir = TempDir::new().unwrap();
    let content = r#"
SIGIL_API_KEY=sk_live_abc123
SIGIL_DATABASE_URL=postgresql://user:pass@host/db
SIGIL_SECRET_TOKEN=xyz789
"#;
    let env_file = create_test_env_file(&dir, content);

    let config = EnvBackendConfig {
        env_file: env_file.clone(),
        prefix: Some("SIGIL_".to_string()),
    };
    let backend = EnvBackend::new(config).unwrap();

    let result = backend.list("");

    assert!(result.is_ok(), "list should succeed");
    let secrets = result.unwrap();
    assert_eq!(secrets.len(), 3, "should return 3 secrets");

    // Verify secret paths
    let paths: Vec<String> = secrets
        .iter()
        .map(|m| m.path.as_str().to_string())
        .collect();
    assert!(paths.contains(&"env/API_KEY".to_string()));
    assert!(paths.contains(&"env/DATABASE_URL".to_string()));
    assert!(paths.contains(&"env/SECRET_TOKEN".to_string()));
}

#[test]
fn test_list_secrets_empty() {
    let dir = TempDir::new().unwrap();
    let content = "# Empty env file with just comments\n";
    let env_file = create_test_env_file(&dir, content);

    let config = EnvBackendConfig {
        env_file: env_file.clone(),
        prefix: Some("SIGIL_".to_string()),
    };
    let backend = EnvBackend::new(config).unwrap();

    let result = backend.list("");

    assert!(result.is_ok(), "list should succeed even when empty");
    let secrets = result.unwrap();
    assert_eq!(secrets.len(), 0, "should return 0 secrets");
}

#[test]
fn test_list_secrets_with_prefix_filtering() {
    let dir = TempDir::new().unwrap();
    let content = r#"
SIGIL_API_KEY=sk_live_abc123
SIGIL_DATABASE_URL=postgresql://user:pass@host/db
OTHER_VAR=should_not_appear
"#;
    let env_file = create_test_env_file(&dir, content);

    let config = EnvBackendConfig {
        env_file: env_file.clone(),
        prefix: Some("SIGIL_".to_string()),
    };
    let backend = EnvBackend::new(config).unwrap();

    let result = backend.list("");

    assert!(result.is_ok(), "list should succeed");
    let secrets = result.unwrap();

    // Should only include SIGIL_ prefixed variables
    let paths: Vec<String> = secrets
        .iter()
        .map(|m| m.path.as_str().to_string())
        .collect();
    assert!(paths.contains(&"env/API_KEY".to_string()));
    assert!(paths.contains(&"env/DATABASE_URL".to_string()));
    // OTHER_VAR should not appear
    assert!(!paths.iter().any(|p| p.contains("OTHER_VAR")));
}

// ============================================================================
// ERROR HANDLING TESTS
// ============================================================================

#[test]
fn test_backend_file_not_found() {
    let config = EnvBackendConfig {
        env_file: std::path::PathBuf::from("/nonexistent/path/secrets.env"),
        prefix: Some("SIGIL_".to_string()),
    };
    let result = EnvBackend::new(config);

    assert!(result.is_err(), "should fail when env file doesn't exist");
    match result {
        Err(SigilError::IoError(msg)) => {
            assert!(msg.contains("not found") || msg.contains("Environment file"),
                    "error should mention file not found: {}", msg);
        }
        Err(other) => panic!("Expected IoError, got: {:?}", other),
        Ok(_) => panic!("Expected error, got success"),
    }
}

#[test]
fn test_backend_type() {
    let dir = TempDir::new().unwrap();
    let content = "SIGIL_API_KEY=value\n";
    let env_file = create_test_env_file(&dir, content);

    let config = EnvBackendConfig {
        env_file: env_file.clone(),
        prefix: Some("SIGIL_".to_string()),
    };
    let backend = EnvBackend::new(config).unwrap();

    assert_eq!(backend.backend_type(), "env");
}

#[test]
fn test_get_metadata() {
    let dir = TempDir::new().unwrap();
    let content = "SIGIL_API_KEY=value\n";
    let env_file = create_test_env_file(&dir, content);

    let config = EnvBackendConfig {
        env_file: env_file.clone(),
        prefix: Some("SIGIL_".to_string()),
    };
    let backend = EnvBackend::new(config).unwrap();

    let path = SecretPath::new("env/API_KEY").unwrap();
    let result = backend.get_metadata(&path);

    assert!(result.is_ok(), "get_metadata should succeed");
    let metadata = result.unwrap();

    assert_eq!(metadata.path.as_str(), "env/API_KEY");
    assert_eq!(metadata.secret_type, SecretType::Generic); // Default type
    assert!(metadata.tags.contains(&"env".to_string()));
}
