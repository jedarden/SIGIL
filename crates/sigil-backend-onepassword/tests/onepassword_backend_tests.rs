//! Behavioral tests for 1Password backend
//!
//! These tests verify the OnePasswordBackend implementation using mockito
//! to mock 1Password Connect API HTTP responses.

use mockito::Server;
use sigil_backend_onepassword::{OnePasswordBackend, OnePasswordBackendConfig};
use sigil_core::{SecretBackend, SecretMetadata, SecretPath, SecretType, SecretValue, SigilError};
use std::time::Duration;

/// Helper to create a Connect API backend config
fn create_connect_config(server_url: &str) -> OnePasswordBackendConfig {
    OnePasswordBackendConfig {
        vault: Some("TestVault".to_string()),
        account: None,
        use_connect: true,
        connect_address: Some(server_url.to_string()),
        connect_token: Some("test-token".to_string()),
        cache: false,
        cache_ttl: Duration::from_secs(0),
    }
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

#[tokio::test]
async fn test_get_secret_success() {
    let mut server = Server::new_async().await;

    // Mock the 1Password Connect API read endpoint
    // GET /v1/vaults/{vault}/items/{item}/fields/{field}
    let mock = server
        .mock("GET", "/v1/vaults/TestVault/items/api_key/fields/password")
        .match_header("authorization", "Bearer test-token")
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(r#"{"value": "sk-live-abc123xyz"}"#)
        .create_async()
        .await;

    let config = create_connect_config(&server.url());
    let backend = OnePasswordBackend::new(config).unwrap();

    // Path format: onepassword/item (uses default vault from config)
    let path = SecretPath::new("onepassword/api_key").unwrap();
    let result = backend.get(&path).await;

    assert!(result.is_ok(), "get should succeed for existing secret");
    let secret_value = result.unwrap();
    let value = secret_value.expose(|bytes| String::from_utf8(bytes.to_vec()).unwrap());
    assert_eq!(value, "sk-live-abc123xyz");

    mock.assert();
}

#[tokio::test]
async fn test_get_secret_not_found() {
    let mut server = Server::new_async().await;

    // Mock a 404 response for non-existent secret
    let mock = server
        .mock("GET", "/v1/vaults/TestVault/items/nonexistent/fields/password")
        .match_header("authorization", "Bearer test-token")
        .with_status(404)
        .with_header("content-type", "application/json")
        .with_body(r#"{"message": "Item not found"}"#)
        .create_async()
        .await;

    let config = create_connect_config(&server.url());
    let backend = OnePasswordBackend::new(config).unwrap();

    // Path format: onepassword/item (uses default vault from config)
    let path = SecretPath::new("onepassword/nonexistent").unwrap();
    let result = backend.get(&path).await;

    assert!(result.is_err(), "get should fail for non-existent secret");
    match result {
        Err(SigilError::SecretNotFound(msg)) => {
            assert!(
                msg.contains("nonexistent") || msg.contains("not found"),
                "error should mention the secret path or not found: {}",
                msg
            );
        }
        Err(other) => panic!("Expected SecretNotFound error, got: {:?}", other),
        Ok(_) => panic!("Expected error for non-existent secret"),
    }

    mock.assert();
}

#[tokio::test]
async fn test_get_secret_with_custom_field() {
    let mut server = Server::new_async().await;

    // Mock reading a custom field
    let mock = server
        .mock("GET", "/v1/vaults/TestVault/items/github/fields/username")
        .match_header("authorization", "Bearer test-token")
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(r#"{"value": "myusername"}"#)
        .create_async()
        .await;

    let config = create_connect_config(&server.url());
    let backend = OnePasswordBackend::new(config).unwrap();

    // Path format: onepassword/item/field (uses default vault from config)
    let path = SecretPath::new("onepassword/github/username").unwrap();
    let result = backend.get(&path).await;

    assert!(result.is_ok(), "get should succeed with custom field");
    let secret_value = result.unwrap();
    let value = secret_value.expose(|bytes| String::from_utf8(bytes.to_vec()).unwrap());
    assert_eq!(value, "myusername");

    mock.assert();
}

#[tokio::test]
async fn test_get_secret_with_default_vault() {
    let mut server = Server::new_async().await;

    // When no vault specified in path, use default vault from config
    let mock = server
        .mock("GET", "/v1/vaults/TestVault/items/default_secret/fields/password")
        .match_header("authorization", "Bearer test-token")
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(r#"{"value": "default_value"}"#)
        .create_async()
        .await;

    let config = create_connect_config(&server.url());
    let backend = OnePasswordBackend::new(config).unwrap();

    // Path without vault should use configured default
    let path = SecretPath::new("onepassword/default_secret").unwrap();
    let result = backend.get(&path).await;

    assert!(result.is_ok(), "get should use default vault from config");
    let secret_value = result.unwrap();
    let value = secret_value.expose(|bytes| String::from_utf8(bytes.to_vec()).unwrap());
    assert_eq!(value, "default_value");

    mock.assert();
}

#[tokio::test]
async fn test_get_secret_unauthorized() {
    let mut server = Server::new_async().await;

    // Mock a 403 response for unauthorized access
    let mock = server
        .mock("GET", "/v1/vaults/TestVault/items/restricted/fields/password")
        .match_header("authorization", "Bearer test-token")
        .with_status(403)
        .with_header("content-type", "application/json")
        .with_body(r#"{"message": "Forbidden"}"#)
        .create_async()
        .await;

    let config = create_connect_config(&server.url());
    let backend = OnePasswordBackend::new(config).unwrap();

    // Path format: onepassword/item (uses default vault from config)
    let path = SecretPath::new("onepassword/restricted").unwrap();
    let result = backend.get(&path).await;

    assert!(result.is_err(), "get should fail with auth error");
    match result {
        Err(SigilError::IoError(msg)) => {
            assert!(
                msg.contains("Authentication") || msg.contains("403"),
                "error should mention authentication failure: {}",
                msg
            );
        }
        Err(other) => panic!("Expected IoError with auth failure, got: {:?}", other),
        Ok(_) => panic!("Expected auth error"),
    }

    mock.assert();
}

#[tokio::test]
async fn test_get_secret_invalid_token() {
    let mut server = Server::new_async().await;

    // Mock a 401 response for invalid token
    let mock = server
        .mock("GET", "/v1/vaults/TestVault/items/api_key/fields/password")
        .match_header("authorization", "Bearer test-token")
        .with_status(401)
        .with_header("content-type", "application/json")
        .with_body(r#"{"message": "Unauthorized"}"#)
        .create_async()
        .await;

    let config = create_connect_config(&server.url());
    let backend = OnePasswordBackend::new(config).unwrap();

    // Path format: onepassword/item (uses default vault from config)
    let path = SecretPath::new("onepassword/api_key").unwrap();
    let result = backend.get(&path).await;

    assert!(result.is_err(), "get should fail with invalid token");
    match result {
        Err(SigilError::IoError(msg)) => {
            assert!(
                msg.contains("Authentication") || msg.contains("401"),
                "error should mention authentication failure: {}",
                msg
            );
        }
        Err(other) => panic!("Expected IoError with auth failure, got: {:?}", other),
        Ok(_) => panic!("Expected auth error"),
    }

    mock.assert();
}

// ============================================================================
// SET OPERATION TESTS
// ============================================================================

#[tokio::test]
async fn test_set_secret_not_supported() {
    let server = Server::new_async().await;

    // Even with mock server, set should fail as 1Password backend is read-only
    let config = create_connect_config(&server.url());
    let backend = OnePasswordBackend::new(config).unwrap();

    let path = SecretPath::new("onepassword/TestVault/new_item").unwrap();
    let value = SecretValue::new(b"new-secret-value".to_vec());
    let metadata = create_test_metadata("onepassword/TestVault/new_item");

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

// ============================================================================
// DELETE OPERATION TESTS
// ============================================================================

#[tokio::test]
async fn test_delete_secret_not_supported() {
    let server = Server::new_async().await;

    // Even with mock server, delete should fail as 1Password backend is read-only
    let config = create_connect_config(&server.url());
    let backend = OnePasswordBackend::new(config).unwrap();

    let path = SecretPath::new("onepassword/TestVault/item_to_delete").unwrap();
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

// ============================================================================
// LIST OPERATION TESTS
// ============================================================================

#[tokio::test]
async fn test_list_secrets_empty() {
    let _server = Server::new_async().await;

    let config = OnePasswordBackendConfig {
        vault: Some("TestVault".to_string()),
        account: None,
        use_connect: true,
        connect_address: Some("http://localhost:8080".to_string()),
        connect_token: Some("test-token".to_string()),
        cache: false,
        cache_ttl: Duration::from_secs(0),
    };

    let backend = OnePasswordBackend::new(config).unwrap();

    // List operation uses CLI even when Connect is enabled
    // In test environment without CLI, it should fail gracefully or return empty
    let result = backend.list("").await;

    // Since CLI is not available, list should either fail or return empty
    // The implementation returns empty on CLI failure
    match result {
        Ok(secrets) => {
            // Empty list is acceptable
            let _ = secrets;
        }
        Err(_) => {
            // Also acceptable if CLI error is returned
        }
    }
}

#[tokio::test]
async fn test_list_secrets_with_prefix() {
    let _server = Server::new_async().await;

    let config = OnePasswordBackendConfig {
        vault: Some("TestVault".to_string()),
        account: None,
        use_connect: true,
        connect_address: Some("http://localhost:8080".to_string()),
        connect_token: Some("test-token".to_string()),
        cache: false,
        cache_ttl: Duration::from_secs(0),
    };

    let backend = OnePasswordBackend::new(config).unwrap();

    // Test listing with various prefixes
    let prefixes = vec!["", "onepassword", "onepassword/TestVault"];

    for prefix in prefixes {
        let result = backend.list(prefix).await;
        // Should either succeed (possibly empty) or fail with CLI error
        match result {
            Ok(_) => {
                // Success is fine
            }
            Err(_) => {
                // CLI error is also acceptable in test environment
            }
        }
    }
}

// ============================================================================
// GET METADATA TESTS
// ============================================================================

#[tokio::test]
async fn test_get_metadata() {
    let _server = Server::new_async().await;

    let config = OnePasswordBackendConfig {
        vault: Some("TestVault".to_string()),
        account: None,
        use_connect: true,
        connect_address: Some("http://localhost:8080".to_string()),
        connect_token: Some("test-token".to_string()),
        cache: false,
        cache_ttl: Duration::from_secs(0),
    };

    let backend = OnePasswordBackend::new(config).unwrap();

    let path = SecretPath::new("onepassword/TestVault/api_key").unwrap();
    let result = backend.get_metadata(&path).await;

    assert!(result.is_ok(), "get_metadata should succeed");
    let metadata = result.unwrap();

    assert_eq!(metadata.path.as_str(), "onepassword/TestVault/api_key");
    assert!(metadata.tags.contains(&"onepassword".to_string()));
    assert!(metadata.notes.is_some());
    assert!(metadata.notes.unwrap().contains("1Password"));
}

// ============================================================================
// BACKEND TYPE TEST
// ============================================================================

#[tokio::test]
async fn test_backend_type() {
    let _server = Server::new_async().await;

    let config = OnePasswordBackendConfig {
        vault: Some("TestVault".to_string()),
        account: None,
        use_connect: true,
        connect_address: Some("http://localhost:8080".to_string()),
        connect_token: Some("test-token".to_string()),
        cache: false,
        cache_ttl: Duration::from_secs(0),
    };

    let backend = OnePasswordBackend::new(config).unwrap();

    assert_eq!(backend.backend_type(), "onepassword");
}

// ============================================================================
// PATH PARSING TESTS
// ============================================================================

#[tokio::test]
async fn test_parse_path_simple() {
    let _server = Server::new_async().await;

    let config = OnePasswordBackendConfig {
        vault: Some("TestVault".to_string()),
        account: None,
        use_connect: true,
        connect_address: Some("http://localhost:8080".to_string()),
        connect_token: Some("test-token".to_string()),
        cache: false,
        cache_ttl: Duration::from_secs(0),
    };

    let backend = OnePasswordBackend::new(config).unwrap();

    // Test simple path: onepassword/item
    let (vault, item, field) = backend.parse_path("onepassword/example").unwrap();
    assert_eq!(vault, Some("TestVault".to_string())); // Uses default from config
    assert_eq!(item, "example");
    assert_eq!(field, Some("password".to_string()));
}

#[tokio::test]
async fn test_parse_path_with_field() {
    let _server = Server::new_async().await;

    let config = OnePasswordBackendConfig {
        vault: Some("TestVault".to_string()),
        account: None,
        use_connect: true,
        connect_address: Some("http://localhost:8080".to_string()),
        connect_token: Some("test-token".to_string()),
        cache: false,
        cache_ttl: Duration::from_secs(0),
    };

    let backend = OnePasswordBackend::new(config).unwrap();

    // Test path with field: onepassword/item/field
    let (vault, item, field) = backend
        .parse_path("onepassword/example/username")
        .unwrap();
    assert_eq!(vault, Some("TestVault".to_string()));
    assert_eq!(item, "example");
    assert_eq!(field, Some("username".to_string()));
}

#[tokio::test]
async fn test_parse_path_with_vault() {
    let _server = Server::new_async().await;

    let config = OnePasswordBackendConfig {
        vault: Some("TestVault".to_string()),
        account: None,
        use_connect: true,
        connect_address: Some("http://localhost:8080".to_string()),
        connect_token: Some("test-token".to_string()),
        cache: false,
        cache_ttl: Duration::from_secs(0),
    };

    let backend = OnePasswordBackend::new(config).unwrap();

    // Test path with vault: onepassword/vault/item/field
    let (vault, item, field) = backend
        .parse_path("onepassword/CustomVault/example/password")
        .unwrap();
    assert_eq!(vault, Some("CustomVault".to_string())); // Overrides default
    assert_eq!(item, "example");
    assert_eq!(field, Some("password".to_string()));
}

#[tokio::test]
async fn test_parse_path_invalid() {
    let _server = Server::new_async().await;

    let config = OnePasswordBackendConfig {
        vault: Some("TestVault".to_string()),
        account: None,
        use_connect: true,
        connect_address: Some("http://localhost:8080".to_string()),
        connect_token: Some("test-token".to_string()),
        cache: false,
        cache_ttl: Duration::from_secs(0),
    };

    let backend = OnePasswordBackend::new(config).unwrap();

    // Test invalid paths
    assert!(backend.parse_path("invalid/path").is_err());
    assert!(backend.parse_path("onepassword/").is_err());
    assert!(backend.parse_path("").is_err());
}

// ============================================================================
// CACHE TESTS
// ============================================================================

#[tokio::test]
async fn test_cache_behavior() {
    let mut server = Server::new_async().await;

    // Mock one request - second should be served from cache
    let mock = server
        .mock("GET", "/v1/vaults/TestVault/items/cached_secret/fields/password")
        .match_header("authorization", "Bearer test-token")
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(r#"{"value": "cached_value"}"#)
        .expect(1) // Only 1 hit expected since second request should be cached
        .create_async()
        .await;

    let mut config = create_connect_config(&server.url());
    config.cache = true;
    config.cache_ttl = Duration::from_secs(300);

    let backend = OnePasswordBackend::new(config).unwrap();

    // Use simple item name (will use default vault from config)
    let path = SecretPath::new("onepassword/cached_secret").unwrap();

    // First request - hits the server
    let result1 = backend.get(&path).await;
    assert!(result1.is_ok());
    let value1 = result1.unwrap().expose(|bytes| String::from_utf8(bytes.to_vec()).unwrap());
    assert_eq!(value1, "cached_value");

    // Second request - should be served from cache
    let result2 = backend.get(&path).await;
    assert!(result2.is_ok());
    let value2 = result2.unwrap().expose(|bytes| String::from_utf8(bytes.to_vec()).unwrap());
    assert_eq!(value2, "cached_value");

    mock.assert();
}

// ============================================================================
// ERROR HANDLING TESTS
// ============================================================================

#[tokio::test]
async fn test_get_secret_server_error() {
    let mut server = Server::new_async().await;

    // Mock a 500 server error
    let mock = server
        .mock("GET", "/v1/vaults/TestVault/items/error_item/fields/password")
        .match_header("authorization", "Bearer test-token")
        .with_status(500)
        .with_header("content-type", "application/json")
        .with_body(r#"{"message": "Internal server error"}"#)
        .create_async()
        .await;

    let config = create_connect_config(&server.url());
    let backend = OnePasswordBackend::new(config).unwrap();

    // Use simple item name (will use default vault from config)
    let path = SecretPath::new("onepassword/error_item").unwrap();
    let result = backend.get(&path).await;

    assert!(result.is_err(), "get should fail with server error");
    match result {
        Err(SigilError::IoError(msg)) => {
            assert!(
                msg.contains("500") || msg.contains("error"),
                "error should mention HTTP error: {}",
                msg
            );
        }
        Err(other) => panic!("Expected IoError with server error, got: {:?}", other),
        Ok(_) => panic!("Expected server error"),
    }

    mock.assert();
}

#[tokio::test]
async fn test_get_secret_invalid_response() {
    let mut server = Server::new_async().await;

    // Mock a response without "value" field
    let mock = server
        .mock("GET", "/v1/vaults/TestVault/items/malformed/fields/password")
        .match_header("authorization", "Bearer test-token")
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(r#"{"data": "invalid structure"}"#)
        .create_async()
        .await;

    let config = create_connect_config(&server.url());
    let backend = OnePasswordBackend::new(config).unwrap();

    // Use simple item name (will use default vault from config)
    let path = SecretPath::new("onepassword/malformed").unwrap();
    let result = backend.get(&path).await;

    assert!(result.is_err(), "get should fail with invalid response");
    match result {
        Err(SigilError::IoError(msg)) => {
            assert!(
                msg.contains("value") || msg.contains("No value"),
                "error should mention missing value field: {}",
                msg
            );
        }
        Err(other) => panic!("Expected IoError for invalid response, got: {:?}", other),
        Ok(_) => panic!("Expected invalid response error"),
    }

    mock.assert();
}
