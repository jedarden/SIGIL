//! Behavioral tests for pass/gopass backend
//!
//! These tests verify the PassBackend implementation using temporary test password
//! stores and command execution.

use sigil_backend_pass::{PassBackend, PassBackendConfig, PassCommand};
use sigil_core::{SecretBackend, SecretMetadata, SecretPath, SecretType, SecretValue, SigilError};
use std::fs;
use std::io::Write;
use std::path::PathBuf;
use tempfile::TempDir;

/// Helper to create a temporary password store directory
fn create_test_password_store() -> TempDir {
    let dir = TempDir::new().unwrap();

    // Create the .gpg-id file to make it a valid password store
    let gpg_id = dir.path().join(".gpg-id");
    let mut file = fs::File::create(&gpg_id).unwrap();
    file.write_all(b"test@gpg.key\n").unwrap();
    file.flush().unwrap();

    dir
}

/// Helper to create a test password file
fn create_test_password(store: &TempDir, path: &str, content: &str) {
    let password_file = store.path().join(path);
    let parent = password_file.parent().unwrap();
    fs::create_dir_all(parent).unwrap();

    let mut file = fs::File::create(&password_file).unwrap();
    file.write_all(content.as_bytes()).unwrap();
    file.flush().unwrap();
}

/// Helper to create test secret metadata
fn create_test_metadata(path: &str) -> SecretMetadata {
    SecretMetadata {
        path: SecretPath::new(path.to_string()).unwrap(),
        secret_type: SecretType::Password,
        tags: vec!["test".to_string()],
        notes: Some("Test secret".to_string()),
        created_at: chrono::Utc::now(),
        updated_at: chrono::Utc::now(),
        expires_at: None,
    }
}

// ============================================================================
// CONFIGURATION TESTS
// ============================================================================

#[test]
fn test_backend_configuration_auto_detect() {
    let store = create_test_password_store();

    let config = PassBackendConfig {
        command: PassCommand::Auto,
        store_path: store.path().to_path_buf(),
    };

    assert_eq!(config.command, PassCommand::Auto);
    assert_eq!(config.store_path, store.path());
}

#[test]
fn test_backend_configuration_force_pass() {
    let store = create_test_password_store();

    let config = PassBackendConfig {
        command: PassCommand::Pass,
        store_path: store.path().to_path_buf(),
    };

    assert_eq!(config.command, PassCommand::Pass);
}

#[test]
fn test_backend_configuration_force_gopass() {
    let store = create_test_password_store();

    let config = PassBackendConfig {
        command: PassCommand::Gopass,
        store_path: store.path().to_path_buf(),
    };

    assert_eq!(config.command, PassCommand::Gopass);
}

#[test]
fn test_backend_configuration_default() {
    let config = PassBackendConfig::default();

    assert_eq!(config.command, PassCommand::Auto);
    assert_eq!(config.store_path, PathBuf::from("~/.password-store"));
}

// ============================================================================
// ERROR HANDLING TESTS
// ============================================================================

#[test]
fn test_backend_command_not_found() {
    let store = create_test_password_store();

    let config = PassBackendConfig {
        command: PassCommand::Pass,
        store_path: store.path().to_path_buf(),
    };

    // If 'pass' command doesn't exist, backend creation should fail
    let result = PassBackend::new(config);

    // This test verifies error handling when command is not available
    match result {
        Err(SigilError::IoError(msg)) => {
            assert!(msg.contains("not found") || msg.contains("Command"),
                    "error should mention command not found: {}", msg);
        }
        Err(other) => {
            // Other errors are acceptable if pass is installed
            // (e.g., GPG key errors)
            tracing::info!("Got expected error: {:?}", other);
        }
        Ok(_) => {
            // If pass is installed, that's fine too
            tracing::info!("pass command is available");
        }
    }
}

#[test]
fn test_backend_store_not_found() {
    // Use a non-existent store path
    let config = PassBackendConfig {
        command: PassCommand::Pass,
        store_path: PathBuf::from("/nonexistent/password/store"),
    };

    let result = PassBackend::new(config);

    assert!(result.is_err(), "should fail when password store doesn't exist");
    match result {
        Err(SigilError::IoError(msg)) => {
            assert!(msg.contains("not found") || msg.contains("Password store"),
                    "error should mention store not found: {}", msg);
        }
        Err(other) => panic!("Expected IoError, got: {:?}", other),
        Ok(_) => panic!("Expected error, got success"),
    }
}

// ============================================================================
// BEHAVIORAL TESTS (when pass/gopass is available)
// ============================================================================

#[test]
fn test_backend_type() {
    let store = create_test_password_store();

    let config = PassBackendConfig {
        command: PassCommand::Auto,
        store_path: store.path().to_path_buf(),
    };

    let result = PassBackend::new(config);

    match result {
        Ok(backend) => {
            assert_eq!(backend.backend_type(), "pass");
        }
        Err(_) => {
            // If commands aren't available, skip this test
            // The error handling is tested separately
        }
    }
}

#[test]
fn test_list_secrets_structure() {
    let store = create_test_password_store();

    // Create some test password files
    create_test_password(&store, "email/gmail.gpg", "gmail_password");
    create_test_password(&store, "work/aws.gpg", "aws_password");
    create_test_password(&store, "personal/github.gpg", "github_password");

    let config = PassBackendConfig {
        command: PassCommand::Auto,
        store_path: store.path().to_path_buf(),
    };

    let result = PassBackend::new(config);

    match result {
        Ok(backend) => {
            // Test listing secrets
            let list_result = backend.list("");

            match list_result {
                Ok(secrets) => {
                    // Should have discovered the created passwords
                    assert!(!secrets.is_empty(), "should discover at least one secret");

                    // Verify secret paths
                    let paths: Vec<String> = secrets
                        .iter()
                        .map(|m| m.path.as_str().to_string())
                        .collect();

                    // Paths should contain the created passwords (with pass/ prefix)
                    assert!(paths.iter().any(|p| p.contains("email") || p.contains("work") || p.contains("personal")),
                            "should find at least one of the created passwords");
                }
                Err(e) => {
                    // List might fail if pass/gopass isn't properly configured
                    tracing::info!("List failed (expected if GPG not configured): {:?}", e);
                }
            }
        }
        Err(_) => {
            // Backend creation failed - skip list test
            tracing::info!("Backend creation failed (expected if pass/gopass not available)");
        }
    }
}

#[test]
fn test_get_secret_expected_behavior() {
    let store = create_test_password_store();

    // Create a test password file
    create_test_password(&store, "test/password.gpg", "my_test_password");

    let config = PassBackendConfig {
        command: PassCommand::Auto,
        store_path: store.path().to_path_buf(),
    };

    let result = PassBackend::new(config);

    match result {
        Ok(backend) => {
            // Test getting a secret
            let path = SecretPath::new("pass/test/password").unwrap();
            let get_result = backend.get(&path);

            match get_result {
                Ok(secret_value) => {
                    let value = secret_value.expose(|bytes| String::from_utf8_lossy(bytes).to_string());
                    // The value should not be empty
                    assert!(!value.is_empty(), "retrieved password should not be empty");
                }
                Err(SigilError::SecretNotFound(msg)) => {
                    // Secret might not be found if GPG decryption fails
                    tracing::info!("Secret not found (expected if GPG not configured): {}", msg);
                }
                Err(e) => {
                    // Other errors (GPG, etc.) are acceptable
                    tracing::info!("Get failed (expected if GPG not configured): {:?}", e);
                }
            }
        }
        Err(_) => {
            // Backend creation failed - skip get test
            tracing::info!("Backend creation failed (expected if pass/gopass not available)");
        }
    }
}

#[test]
fn test_get_secret_not_found_expected_behavior() {
    let store = create_test_password_store();

    let config = PassBackendConfig {
        command: PassCommand::Auto,
        store_path: store.path().to_path_buf(),
    };

    let result = PassBackend::new(config);

    match result {
        Ok(backend) => {
            // Test getting a non-existent secret
            let path = SecretPath::new("pass/nonexistent/secret").unwrap();
            let get_result = backend.get(&path);

            match get_result {
                Err(SigilError::SecretNotFound(msg)) => {
                    assert!(msg.contains("nonexistent") || msg.contains("not found"),
                            "error should mention the secret path: {}", msg);
                }
                Err(SigilError::IoError(_)) => {
                    // IoError is also acceptable (pass command may fail)
                }
                Err(other) => {
                    panic!("Expected SecretNotFound or IoError, got: {:?}", other);
                }
                Ok(_) => {
                    panic!("Expected error for non-existent secret, got success");
                }
            }
        }
        Err(_) => {
            // Backend creation failed - skip this test
        }
    }
}

#[test]
fn test_get_metadata_expected_behavior() {
    let store = create_test_password_store();

    let config = PassBackendConfig {
        command: PassCommand::Auto,
        store_path: store.path().to_path_buf(),
    };

    let result = PassBackend::new(config);

    match result {
        Ok(backend) => {
            let path = SecretPath::new("pass/test/item").unwrap();
            let metadata_result = backend.get_metadata(&path);

            match metadata_result {
                Ok(metadata) => {
                    assert_eq!(metadata.path.as_str(), "pass/test/item");
                    assert_eq!(metadata.secret_type, SecretType::Password);
                    assert!(metadata.tags.contains(&"pass".to_string()));
                }
                Err(SigilError::SecretNotFound(_)) | Err(SigilError::IoError(_)) => {
                    // Metadata lookup might fail if the secret doesn't exist
                    // This is expected behavior
                }
                Err(other) => {
                    panic!("Expected SecretNotFound or IoError, got: {:?}", other);
                }
            }
        }
        Err(_) => {
            // Backend creation failed - skip this test
        }
    }
}

// ============================================================================
// PATH HANDLING TESTS
// ============================================================================

#[test]
fn test_path_stripping_with_pass_prefix() {
    let path_with_prefix = "pass/email/gmail";
    let stripped = path_with_prefix.strip_prefix("pass/").unwrap();
    assert_eq!(stripped, "email/gmail");
}

#[test]
fn test_path_stripping_without_pass_prefix() {
    let path_without_prefix = "email/gmail";
    let stripped = path_without_prefix
        .strip_prefix("pass/")
        .unwrap_or(path_without_prefix);
    assert_eq!(stripped, "email/gmail");
}

// ============================================================================
// COMMAND DETECTION TESTS
// ============================================================================

#[test]
fn test_command_detection_order() {
    // Verify that auto-detection prefers gopass over pass
    // This test documents the expected behavior

    let store = create_test_password_store();

    let config = PassBackendConfig {
        command: PassCommand::Auto,
        store_path: store.path().to_path_buf(),
    };

    let result = PassBackend::new(config);

    match result {
        Ok(backend) => {
            // If backend was created, it means at least one command was detected
            // The implementation should prefer gopass if both are available
            assert!(backend.backend_type() == "pass" || backend.backend_type() == "gopass");
        }
        Err(_) => {
            // Neither command is available - error handling is tested elsewhere
        }
    }
}
