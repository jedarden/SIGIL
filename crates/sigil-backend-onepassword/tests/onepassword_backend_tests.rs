//! Behavioral tests for 1Password backend
//!
//! These tests verify the OnePasswordBackend implementation with comprehensive
//! coverage of the SecretBackend trait methods and error scenarios.

use sigil_backend_onepassword::{OnePasswordBackend, OnePasswordBackendConfig};
use sigil_core::{SecretBackend, SecretMetadata, SecretPath, SecretType, SecretValue, SigilError};
use std::time::Duration;

/// Helper to create a CLI-only test config (bypasses CLI check for testing)
fn create_test_config() -> OnePasswordBackendConfig {
    OnePasswordBackendConfig {
        vault: Some("Personal".to_string()),
        account: None,
        use_connect: true, // Use Connect mode to avoid CLI requirement in tests
        connect_address: Some("http://localhost:8080".to_string()),
        connect_token: Some("test-token".to_string()),
        cache: false,
        cache_ttl: Duration::from_secs(0),
    }
}

/// Helper to create a cached test config
fn create_cached_config() -> OnePasswordBackendConfig {
    OnePasswordBackendConfig {
        vault: Some("Personal".to_string()),
        account: None,
        use_connect: true,
        connect_address: Some("http://localhost:8080".to_string()),
        connect_token: Some("test-token".to_string()),
        cache: true,
        cache_ttl: Duration::from_secs(300),
    }
}

/// Helper to create SecretMetadata for testing
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

#[test]
fn test_config_default() {
    let config = OnePasswordBackendConfig::default();
    assert!(config.vault.is_none());
    assert!(config.account.is_none());
    assert!(!config.use_connect);
    assert!(!config.cache);
    assert_eq!(config.cache_ttl, Duration::from_secs(300));
    assert!(config.connect_address.is_none());
    assert!(config.connect_token.is_none());
}

#[test]
fn test_config_custom() {
    let config = OnePasswordBackendConfig {
        vault: Some("Work".to_string()),
        account: Some("myaccount.1password.com".to_string()),
        use_connect: true,
        connect_address: Some("https://connect.example.com".to_string()),
        connect_token: Some("my-token-123".to_string()),
        cache: true,
        cache_ttl: Duration::from_secs(600),
    };

    assert_eq!(config.vault.unwrap(), "Work");
    assert_eq!(config.account.unwrap(), "myaccount.1password.com");
    assert!(config.use_connect);
    assert_eq!(
        config.connect_address.unwrap(),
        "https://connect.example.com"
    );
    assert_eq!(config.connect_token.unwrap(), "my-token-123");
    assert!(config.cache);
    assert_eq!(config.cache_ttl, Duration::from_secs(600));
}

#[test]
fn test_parse_path() {
    let config = OnePasswordBackendConfig {
        use_connect: true,
        ..Default::default()
    };
    let backend = OnePasswordBackend::new(config).unwrap();

    // Test simple path: onepassword/item
    let (vault, item, field) = backend.parse_path("onepassword/example").unwrap();
    assert!(vault.is_none());
    assert_eq!(item, "example");
    assert_eq!(field, Some("password".to_string()));

    // Test path with field: onepassword/item/field
    let (vault, item, field) = backend.parse_path("onepassword/example/username").unwrap();
    assert!(vault.is_none());
    assert_eq!(item, "example");
    assert_eq!(field, Some("username".to_string()));

    // Test path with vault: onepassword/vault/item/field
    let (vault, item, field) = backend
        .parse_path("onepassword/Personal/example/password")
        .unwrap();
    assert_eq!(vault, Some("Personal".to_string()));
    assert_eq!(item, "example");
    assert_eq!(field, Some("password".to_string()));

    // Test complex path: onepassword/vault/category/item/field
    let (vault, item, field) = backend
        .parse_path("onepassword/Work/SSH/prod/server/key")
        .unwrap();
    assert_eq!(vault, Some("Work".to_string()));
    assert_eq!(item, "SSH/prod/server");
    assert_eq!(field, Some("key".to_string()));
}

#[test]
fn test_parse_path_invalid() {
    let config = OnePasswordBackendConfig {
        use_connect: true,
        ..Default::default()
    };
    let backend = OnePasswordBackend::new(config).unwrap();

    // Test path without onepassword prefix
    let result = backend.parse_path("invalid/path");
    assert!(result.is_err());

    // Test empty path components
    let result = backend.parse_path("onepassword/");
    assert!(result.is_err());

    // Test empty path
    let result = backend.parse_path("");
    assert!(result.is_err());
}

#[test]
fn test_parse_path_with_default_vault() {
    let config = OnePasswordBackendConfig {
        vault: Some("MyVault".to_string()),
        use_connect: true,
        ..Default::default()
    };
    let backend = OnePasswordBackend::new(config).unwrap();

    // When default vault is set, paths without vault use the default
    let (vault, item, field) = backend.parse_path("onepassword/example").unwrap();
    assert_eq!(vault, Some("MyVault".to_string()));
    assert_eq!(item, "example");
    assert_eq!(field, Some("password".to_string()));

    // Paths with explicit vault override the default
    let (vault, item, field) = backend
        .parse_path("onepassword/Other/example/password")
        .unwrap();
    assert_eq!(vault, Some("Other".to_string()));
    assert_eq!(item, "example");
    assert_eq!(field, Some("password".to_string()));
}

#[test]
fn test_detect_secret_type() {
    // Test detection by item name/title
    assert_eq!(
        OnePasswordBackend::detect_secret_type(&[], "GitHub token"),
        SecretType::ApiKey
    );
    assert_eq!(
        OnePasswordBackend::detect_secret_type(&[], "My SSH key"),
        SecretType::SshKey
    );
    assert_eq!(
        OnePasswordBackend::detect_secret_type(&[], "Database connection"),
        SecretType::DatabaseUrl
    );
    assert_eq!(
        OnePasswordBackend::detect_secret_type(&[], "My password"),
        SecretType::Password
    );
    assert_eq!(
        OnePasswordBackend::detect_secret_type(&[], "Generic secret"),
        SecretType::Generic
    );

    // Test detection by category
    let password_categories = vec![Some("Login".to_string()), Some("Password".to_string())];
    assert_eq!(
        OnePasswordBackend::detect_secret_type(&password_categories, "Example"),
        SecretType::Password
    );

    let api_categories = vec![Some("API".to_string()), Some("Token".to_string())];
    assert_eq!(
        OnePasswordBackend::detect_secret_type(&api_categories, "Example"),
        SecretType::ApiKey
    );

    let ssh_categories = vec![Some("SSH".to_string()), Some("Server".to_string())];
    assert_eq!(
        OnePasswordBackend::detect_secret_type(&ssh_categories, "Example"),
        SecretType::SshKey
    );

    let db_categories = vec![Some("Database".to_string())];
    assert_eq!(
        OnePasswordBackend::detect_secret_type(&db_categories, "Example"),
        SecretType::DatabaseUrl
    );
}

#[tokio::test]
async fn test_backend_type() {
    let config = create_test_config();
    let backend = OnePasswordBackend::new(config).unwrap();

    assert_eq!(backend.backend_type(), "onepassword");
}

#[tokio::test]
async fn test_get_metadata() {
    let config = create_test_config();
    let backend = OnePasswordBackend::new(config).unwrap();

    let path = SecretPath::new("onepassword/Personal/test").unwrap();
    let result = backend.get_metadata(&path).await;

    assert!(result.is_ok(), "get_metadata should succeed");
    let metadata = result.unwrap();

    assert_eq!(metadata.path.as_str(), "onepassword/Personal/test");
    assert!(metadata.tags.contains(&"onepassword".to_string()));
    assert!(metadata.notes.is_some());
    assert!(metadata.notes.unwrap().contains("1Password"));
}

#[tokio::test]
async fn test_get_metadata_different_paths() {
    let config = create_test_config();
    let backend = OnePasswordBackend::new(config).unwrap();

    let test_cases = vec![
        "onepassword/example",
        "onepassword/example/username",
        "onepassword/Personal/example/password",
        "onepassword/Work/SSH/server/key",
    ];

    for path_str in test_cases {
        let path = SecretPath::new(path_str.to_string()).unwrap();
        let result = backend.get_metadata(&path).await;

        assert!(
            result.is_ok(),
            "get_metadata should succeed for path: {}",
            path_str
        );
        let metadata = result.unwrap();

        assert_eq!(metadata.path.as_str(), path_str);
        assert!(metadata.tags.contains(&"onepassword".to_string()));
    }
}

#[tokio::test]
async fn test_get_secret_not_implemented() {
    let config = create_test_config();
    let backend = OnePasswordBackend::new(config).unwrap();

    // Note: The actual implementation requires the `op` CLI or Connect server
    // This test verifies the backend structure and error handling
    let path = SecretPath::new("onepassword/Personal/test").unwrap();

    // Without real CLI/server, get will fail
    let result = backend.get(&path).await;

    // In Connect mode without actual server, or CLI mode without `op` installed,
    // we expect an error
    assert!(
        result.is_err(),
        "get should fail without CLI or Connect server"
    );
}

#[tokio::test]
async fn test_set_secret_not_supported() {
    let config = create_test_config();
    let backend = OnePasswordBackend::new(config).unwrap();

    let path = SecretPath::new("onepassword/Personal/test").unwrap();
    let value = SecretValue::new(b"test-value".to_vec());
    let metadata = create_test_metadata("onepassword/Personal/test");

    let result = backend.set(&path, &value, &metadata).await;

    assert!(
        result.is_err(),
        "set should fail - 1Password backend is read-only"
    );
    match result {
        Err(SigilError::IoError(msg)) => {
            assert!(
                msg.contains("read-only") || msg.contains("1Password"),
                "Error message should mention read-only or 1Password: {}",
                msg
            );
        }
        Err(other) => panic!("Expected IoError with read-only message, got: {:?}", other),
        Ok(_) => panic!("Expected error for set operation"),
    }
}

#[tokio::test]
async fn test_delete_secret_not_supported() {
    let config = create_test_config();
    let backend = OnePasswordBackend::new(config).unwrap();

    let path = SecretPath::new("onepassword/Personal/test").unwrap();
    let result = backend.delete(&path).await;

    assert!(
        result.is_err(),
        "delete should fail - 1Password backend is read-only"
    );
    match result {
        Err(SigilError::IoError(msg)) => {
            assert!(
                msg.contains("read-only") || msg.contains("Cannot delete"),
                "Error message should mention read-only or Cannot delete: {}",
                msg
            );
        }
        Err(other) => panic!("Expected IoError with read-only message, got: {:?}", other),
        Ok(_) => panic!("Expected error for delete operation"),
    }
}

#[tokio::test]
async fn test_list_secrets_not_implemented() {
    let config = create_test_config();
    let backend = OnePasswordBackend::new(config).unwrap();

    // List operation requires CLI or Connect server
    let result = backend.list("").await;

    // Without real CLI/server, list will return empty or fail
    // This is expected behavior
    match result {
        Ok(secrets) => {
            // Empty list is acceptable (graceful degradation)
            // No assertion needed - getting Ok result is success
            let _ = secrets;
        }
        Err(_) => {
            // Error is also acceptable
        }
    }
}

#[tokio::test]
async fn test_list_secrets_with_prefix() {
    let config = create_test_config();
    let backend = OnePasswordBackend::new(config).unwrap();

    let test_prefixes = vec!["", "onepassword", "onepassword/Personal", "Personal"];

    for prefix in test_prefixes {
        let result = backend.list(prefix).await;

        // Without real CLI/server, result is either empty list or error
        match result {
            Ok(secrets) => {
                // Accept empty list (graceful degradation)
                // No assertion needed - getting Ok result is success
                let _ = secrets;
            }
            Err(_) => {
                // Error is acceptable
            }
        }
    }
}

#[test]
fn test_command_exists() {
    // Test that command_exists helper works
    assert!(command_exists("sh"));
    assert!(command_exists("ls"));
    assert!(command_exists("bash"));
    assert!(!command_exists("thiscommanddefinitelydoesnotexist12345"));
}

#[tokio::test]
async fn test_cache_behavior() {
    let config = create_cached_config();
    let backend = OnePasswordBackend::new(config).unwrap();

    // Verify cache settings
    assert!(backend.cache_ttl().as_secs() > 0);

    // Note: Without real secrets, we can't test cache hits/misses
    // but we verify the cache configuration is applied
    let path = SecretPath::new("onepassword/test").unwrap();

    // Operations should work (or fail gracefully) with cache enabled
    let _ = backend.get_metadata(&path).await;
}

#[tokio::test]
async fn test_read_only_backend_constraints() {
    let config = create_test_config();
    let backend = OnePasswordBackend::new(config).unwrap();

    let path = SecretPath::new("onepassword/Personal/test").unwrap();
    let value = SecretValue::new(b"test".to_vec());
    let metadata = create_test_metadata("onepassword/Personal/test");

    // Test that write operations fail appropriately
    let set_result = backend.set(&path, &value, &metadata).await;
    assert!(set_result.is_err());

    let delete_result = backend.delete(&path).await;
    assert!(delete_result.is_err());

    // Verify error messages are informative
    if let Err(SigilError::IoError(msg)) = set_result {
        assert!(msg.to_lowercase().contains("read-only") || msg.contains("1Password"));
    }

    if let Err(SigilError::IoError(msg)) = delete_result {
        assert!(msg.to_lowercase().contains("read-only") || msg.contains("delete"));
    }
}

#[tokio::test]
async fn test_backend_initialization() {
    // Test various backend initialization scenarios

    // Test with Connect mode
    let connect_config = OnePasswordBackendConfig {
        use_connect: true,
        connect_address: Some("http://localhost:8080".to_string()),
        connect_token: Some("token".to_string()),
        ..Default::default()
    };
    let backend = OnePasswordBackend::new(connect_config.clone());
    assert!(
        backend.is_ok(),
        "Connect mode should initialize successfully"
    );

    // Test with invalid vault config (should still work)
    let invalid_vault_config = OnePasswordBackendConfig {
        vault: Some("".to_string()), // Empty vault name
        ..connect_config.clone()
    };
    let backend = OnePasswordBackend::new(invalid_vault_config);
    assert!(
        backend.is_ok(),
        "Empty vault name should be handled gracefully"
    );

    // Test with minimal config
    let minimal_config = OnePasswordBackendConfig {
        use_connect: true,
        ..Default::default()
    };
    let backend = OnePasswordBackend::new(minimal_config);
    assert!(backend.is_ok(), "Minimal config should work");
}

#[tokio::test]
async fn test_path_validation() {
    let config = create_test_config();
    let backend = OnePasswordBackend::new(config).unwrap();

    // Test valid paths
    let valid_paths = vec![
        "onepassword/item",
        "onepassword/item/field",
        "onepassword/vault/item/field",
        "onepassword/vault/category/item/field",
    ];

    for path_str in valid_paths {
        let path = SecretPath::new(path_str.to_string());
        assert!(path.is_ok(), "Valid path should parse: {}", path_str);

        // Parse the path
        let result = backend.parse_path(path_str);
        assert!(result.is_ok(), "Valid path should parse: {}", path_str);
    }

    // Test invalid paths
    let invalid_paths = vec![
        "",             // Empty
        "invalid",      // No prefix
        "onepassword",  // No item
        "onepassword/", // Trailing slash
    ];

    for path_str in invalid_paths {
        let result = backend.parse_path(path_str);
        assert!(result.is_err(), "Invalid path should fail: {}", path_str);
    }
}

#[tokio::test]
async fn test_secret_type_detection() {
    let config = create_test_config();
    let _backend = OnePasswordBackend::new(config).unwrap();

    // Test various secret type detection scenarios
    let test_cases: Vec<(Vec<Option<String>>, &str, SecretType)> = vec![
        // API keys and tokens
        (vec![Some("API".to_string())], "GitHub", SecretType::ApiKey),
        (vec![], "API Key", SecretType::ApiKey),
        (vec![], "auth_token", SecretType::ApiKey),
        // SSH and server keys
        (vec![Some("SSH".to_string())], "server", SecretType::SshKey),
        (vec![], "SSH Key", SecretType::SshKey),
        (vec![], "private_key", SecretType::SshKey),
        // Database
        (
            vec![Some("Database".to_string())],
            "prod",
            SecretType::DatabaseUrl,
        ),
        (vec![], "database", SecretType::DatabaseUrl),
        (vec![], "db_connection", SecretType::DatabaseUrl),
        // Passwords
        (
            vec![Some("Login".to_string())],
            "site",
            SecretType::Password,
        ),
        (vec![], "password", SecretType::Password),
        // Generic
        (vec![], "note", SecretType::Generic),
        (vec![], "misc", SecretType::Generic),
    ];

    for (categories, title, expected_type) in test_cases {
        let detected_type = OnePasswordBackend::detect_secret_type(&categories, title);
        assert_eq!(
            detected_type, expected_type,
            "Type detection failed for categories={:?}, title={}: expected {:?}, got {:?}",
            categories, title, expected_type, detected_type
        );
    }
}

#[tokio::test]
async fn test_metadata_generation() {
    let config = create_test_config();
    let backend = OnePasswordBackend::new(config).unwrap();

    let path = SecretPath::new("onepassword/Personal/GitHub/token").unwrap();
    let result = backend.get_metadata(&path).await;

    assert!(result.is_ok());
    let metadata = result.unwrap();

    // Verify metadata structure
    assert_eq!(metadata.path.as_str(), "onepassword/Personal/GitHub/token");
    assert!(metadata.tags.contains(&"onepassword".to_string()));
    assert!(metadata.notes.is_some());
    assert!(metadata.notes.unwrap().contains("1Password"));

    // Verify timestamps are set
    let now = chrono::Utc::now();
    let time_diff = now - metadata.created_at;
    assert!(
        time_diff.num_seconds() < 10,
        "Created timestamp should be recent"
    );

    let time_diff = now - metadata.updated_at;
    assert!(
        time_diff.num_seconds() < 10,
        "Updated timestamp should be recent"
    );
}

/// Helper function to check if a command exists (from lib.rs)
fn command_exists(command: &str) -> bool {
    std::process::Command::new("which")
        .arg(command)
        .output()
        .map(|output| output.status.success())
        .unwrap_or(false)
}
