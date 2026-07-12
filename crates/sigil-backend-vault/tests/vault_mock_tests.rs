//! Behavioral tests for Vault backend using mockito
//!
//! These tests mock Vault HTTP API responses to verify the VaultBackend
//! implementation without requiring a real Vault server.

use mockito::Matcher;
use sigil_backend_vault::{VaultAuth, VaultBackend, VaultBackendConfig, VaultToken};
use sigil_core::{SecretBackend, SecretMetadata, SecretPath, SecretType, SecretValue, SigilError};
use std::time::Duration;

/// Helper to create a test Vault backend config
fn create_test_config(server_url: &str) -> VaultBackendConfig {
    VaultBackendConfig {
        address: server_url.to_string(),
        auth: VaultAuth::Token {
            token: VaultToken::Direct("test-token".to_string()),
        },
        mount: "secret".to_string(),
        namespace: None,
        cache_ttl: Duration::from_secs(60),
        verify_tls: false, // Disable TLS for mock server tests
    }
}

/// Helper to create a KV v2 secret response
fn create_kv_v2_response(value: &str) -> serde_json::Value {
    serde_json::json!({
        "data": {
            "data": {
                "value": value
            },
            "metadata": {
                "created_time": "2024-01-01T00:00:00Z",
                "updated_time": "2024-01-01T00:00:00Z",
                "version": 1
            }
        }
    })
}

/// Helper to create a list response
fn create_list_response(keys: Vec<&str>) -> serde_json::Value {
    serde_json::json!({
        "data": {
            "keys": keys
        }
    })
}

#[tokio::test]
async fn test_get_secret_success() {
    let mut server = mockito::Server::new_async().await;

    // Mock the Vault KV v2 read endpoint
    let mock = server
        .mock("GET", "/v1/secret/data/test/api_key")
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(create_kv_v2_response("sk-live-abc123").to_string())
        .create_async()
        .await;

    let config = create_test_config(&server.url());
    let backend = VaultBackend::new(config).await.unwrap();

    let path = SecretPath::new("vault/test/api_key").unwrap();
    let result = backend.get(&path).await;

    assert!(result.is_ok(), "get should succeed for existing secret");
    let secret_value = result.unwrap();
    let value = secret_value.expose(|bytes| String::from_utf8(bytes.to_vec()).unwrap());
    assert_eq!(value, "sk-live-abc123");

    mock.assert();
}

#[tokio::test]
async fn test_get_secret_not_found() {
    let mut server = mockito::Server::new_async().await;

    // Mock a 404 response for non-existent secret
    let mock = server
        .mock("GET", "/v1/secret/data/nonexistent")
        .with_status(404)
        .with_header("content-type", "application/json")
        .with_body(r#"{"errors": []}"#)
        .create_async()
        .await;

    let config = create_test_config(&server.url());
    let backend = VaultBackend::new(config).await.unwrap();

    let path = SecretPath::new("vault/nonexistent").unwrap();
    let result = backend.get(&path).await;

    assert!(result.is_err(), "get should fail for non-existent secret");
    match result {
        Err(SigilError::SecretNotFound(msg)) => {
            assert!(
                msg.contains("nonexistent"),
                "error should mention the secret path"
            );
        }
        Err(other) => panic!("Expected SecretNotFound error, got: {:?}", other),
        Ok(_) => panic!("Expected error, got success"),
    }

    mock.assert();
}

#[tokio::test]
async fn test_get_secret_without_vault_prefix() {
    let mut server = mockito::Server::new_async().await;

    // Mock the Vault KV v2 read endpoint
    let mock = server
        .mock("GET", "/v1/secret/data/simple/path")
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(create_kv_v2_response("my-secret-value").to_string())
        .create_async()
        .await;

    let config = create_test_config(&server.url());
    let backend = VaultBackend::new(config).await.unwrap();

    // Test without the "vault/" prefix
    let path = SecretPath::new("simple/path").unwrap();
    let result = backend.get(&path).await;

    assert!(result.is_ok(), "get should work without vault/ prefix");
    let secret_value = result.unwrap();
    let value = secret_value.expose(|bytes| String::from_utf8(bytes.to_vec()).unwrap());
    assert_eq!(value, "my-secret-value");

    mock.assert();
}

#[tokio::test]
async fn test_get_secret_unauthorized() {
    let mut server = mockito::Server::new_async().await;

    // Mock a 403 response for unauthorized access
    let mock = server
        .mock("GET", "/v1/secret/data/restricted")
        .with_status(403)
        .with_header("content-type", "application/json")
        .with_body(r#"{"errors": ["permission denied"]}"#)
        .create_async()
        .await;

    let config = create_test_config(&server.url());
    let backend = VaultBackend::new(config).await.unwrap();

    let path = SecretPath::new("vault/restricted").unwrap();
    let result = backend.get(&path).await;

    assert!(result.is_err(), "get should fail for unauthorized access");
    match result {
        Err(SigilError::IoError(msg)) => {
            assert!(
                msg.contains("Access denied") || msg.contains("Vault API error"),
                "error should mention access denial: {}",
                msg
            );
        }
        Err(other) => panic!("Expected IoError, got: {:?}", other),
        Ok(_) => panic!("Expected error, got success"),
    }

    mock.assert();
}

#[tokio::test]
async fn test_set_secret_success() {
    let mut server = mockito::Server::new_async().await;

    // Mock the Vault KV v2 write endpoint
    let mock = server
        .mock("POST", "/v1/secret/data/new_secret")
        .match_body(Matcher::JsonString(r#"{"data":{"value":"my-new-value","metadata":{"tags":[],"custom_metadata":{"notes":""}}}}"#.to_string()))
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(r#"{"data":{}}"#)
        .create_async()
        .await;

    let config = create_test_config(&server.url());
    let backend = VaultBackend::new(config).await.unwrap();

    let path = SecretPath::new("vault/new_secret").unwrap();
    let value = SecretValue::new(b"my-new-value".to_vec());
    let metadata = SecretMetadata {
        path: SecretPath::new("vault/new_secret").unwrap(),
        secret_type: SecretType::Generic,
        tags: vec![],
        notes: None,
        created_at: chrono::Utc::now(),
        updated_at: chrono::Utc::now(),
        expires_at: None,
    };

    let result = backend.set(&path, &value, &metadata).await;

    assert!(result.is_ok(), "set should succeed for valid secret");

    mock.assert();
}

#[tokio::test]
async fn test_set_secret_unauthorized() {
    let mut server = mockito::Server::new_async().await;

    // Mock a 403 response for unauthorized write
    let mock = server
        .mock("POST", "/v1/secret/data/restricted")
        .with_status(403)
        .with_header("content-type", "application/json")
        .with_body(r#"{"errors": ["permission denied"]}"#)
        .create_async()
        .await;

    let config = create_test_config(&server.url());
    let backend = VaultBackend::new(config).await.unwrap();

    let path = SecretPath::new("vault/restricted").unwrap();
    let value = SecretValue::new(b"some-value".to_vec());
    let metadata = SecretMetadata {
        path: SecretPath::new("vault/restricted").unwrap(),
        secret_type: SecretType::Generic,
        tags: vec![],
        notes: None,
        created_at: chrono::Utc::now(),
        updated_at: chrono::Utc::now(),
        expires_at: None,
    };

    let result = backend.set(&path, &value, &metadata).await;

    assert!(result.is_err(), "set should fail for unauthorized access");
    match result {
        Err(SigilError::IoError(msg)) => {
            assert!(
                msg.contains("Access denied") || msg.contains("Vault API error"),
                "error should mention access denial: {}",
                msg
            );
        }
        Err(other) => panic!("Expected IoError, got: {:?}", other),
        Ok(_) => panic!("Expected error, got success"),
    }

    mock.assert();
}

#[tokio::test]
async fn test_delete_secret_success() {
    let mut server = mockito::Server::new_async().await;

    // Mock the Vault KV v2 delete endpoint
    let mock = server
        .mock("DELETE", "/v1/secret/metadata/old_secret")
        .with_status(204) // Vault returns 204 No Content on successful deletion
        .create_async()
        .await;

    let config = create_test_config(&server.url());
    let backend = VaultBackend::new(config).await.unwrap();

    let path = SecretPath::new("vault/old_secret").unwrap();
    let result = backend.delete(&path).await;

    assert!(result.is_ok(), "delete should succeed for existing secret");

    mock.assert();
}

#[tokio::test]
async fn test_delete_secret_not_found() {
    let mut server = mockito::Server::new_async().await;

    // Mock a 404 response for deleting non-existent secret
    // Vault returns 404 but deletion is idempotent, so this should still succeed
    let mock = server
        .mock("DELETE", "/v1/secret/metadata/nonexistent")
        .with_status(404)
        .create_async()
        .await;

    let config = create_test_config(&server.url());
    let backend = VaultBackend::new(config).await.unwrap();

    let path = SecretPath::new("vault/nonexistent").unwrap();
    let result = backend.delete(&path).await;

    assert!(
        result.is_ok(),
        "delete should succeed even for non-existent secret (idempotent)"
    );

    mock.assert();
}

#[tokio::test]
async fn test_delete_secret_unauthorized() {
    let mut server = mockito::Server::new_async().await;

    // Mock a 403 response for unauthorized delete
    let mock = server
        .mock("DELETE", "/v1/secret/metadata/restricted")
        .with_status(403)
        .with_header("content-type", "application/json")
        .with_body(r#"{"errors": ["permission denied"]}"#)
        .create_async()
        .await;

    let config = create_test_config(&server.url());
    let backend = VaultBackend::new(config).await.unwrap();

    let path = SecretPath::new("vault/restricted").unwrap();
    let result = backend.delete(&path).await;

    assert!(
        result.is_err(),
        "delete should fail for unauthorized access"
    );
    match result {
        Err(SigilError::IoError(msg)) => {
            assert!(
                msg.contains("Access denied") || msg.contains("Vault API error"),
                "error should mention access denial: {}",
                msg
            );
        }
        Err(other) => panic!("Expected IoError, got: {:?}", other),
        Ok(_) => panic!("Expected error, got success"),
    }

    mock.assert();
}

#[tokio::test]
async fn test_list_secrets_success() {
    let mut server = mockito::Server::new_async().await;

    // Mock the Vault list endpoint
    let mock = server
        .mock("GET", "/v1/secret/metadata?list=true")
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(create_list_response(vec!["api_key", "db_password", "ssh_key"]).to_string())
        .create_async()
        .await;

    let config = create_test_config(&server.url());
    let backend = VaultBackend::new(config).await.unwrap();

    let result = backend.list("").await;

    assert!(result.is_ok(), "list should succeed");
    let secrets = result.unwrap();
    assert_eq!(secrets.len(), 3, "should return 3 secrets");

    // Verify secret paths
    let paths: Vec<String> = secrets
        .iter()
        .map(|m| m.path.as_str().to_string())
        .collect();
    assert!(paths.contains(&"vault/api_key".to_string()));
    assert!(paths.contains(&"vault/db_password".to_string()));
    assert!(paths.contains(&"vault/ssh_key".to_string()));

    mock.assert();
}

#[tokio::test]
async fn test_list_secrets_empty() {
    let mut server = mockito::Server::new_async().await;

    // Mock an empty list response
    let mock = server
        .mock("GET", "/v1/secret/metadata?list=true")
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(create_list_response(vec![]).to_string())
        .create_async()
        .await;

    let config = create_test_config(&server.url());
    let backend = VaultBackend::new(config).await.unwrap();

    let result = backend.list("").await;

    assert!(result.is_ok(), "list should succeed even when empty");
    let secrets = result.unwrap();
    assert_eq!(secrets.len(), 0, "should return 0 secrets");

    mock.assert();
}

#[tokio::test]
async fn test_list_secrets_with_prefix() {
    let mut server = mockito::Server::new_async().await;

    // Mock the Vault list endpoint with a subpath
    let mock = server
        .mock("GET", "/v1/secret/metadata/prod?list=true")
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(create_list_response(vec!["db_url", "redis_url"]).to_string())
        .create_async()
        .await;

    let config = create_test_config(&server.url());
    let backend = VaultBackend::new(config).await.unwrap();

    let result = backend.list("vault/prod").await;

    assert!(result.is_ok(), "list with prefix should succeed");
    let secrets = result.unwrap();
    assert_eq!(secrets.len(), 2, "should return 2 secrets");

    // Verify secret paths include the prefix
    let paths: Vec<String> = secrets
        .iter()
        .map(|m| m.path.as_str().to_string())
        .collect();
    assert!(paths.contains(&"vault/prod/db_url".to_string()));
    assert!(paths.contains(&"vault/prod/redis_url".to_string()));

    mock.assert();
}

#[tokio::test]
async fn test_list_secrets_unauthorized() {
    let mut server = mockito::Server::new_async().await;

    // Mock a 403 response for unauthorized list
    let mock = server
        .mock("GET", "/v1/secret/metadata?list=true")
        .with_status(403)
        .with_header("content-type", "application/json")
        .with_body(r#"{"errors": ["permission denied"]}"#)
        .create_async()
        .await;

    let config = create_test_config(&server.url());
    let backend = VaultBackend::new(config).await.unwrap();

    let result = backend.list("").await;

    assert!(result.is_err(), "list should fail for unauthorized access");
    match result {
        Err(SigilError::IoError(msg)) => {
            assert!(
                msg.contains("Access denied") || msg.contains("Vault API error"),
                "error should mention access denial: {}",
                msg
            );
        }
        Err(other) => panic!("Expected IoError, got: {:?}", other),
        Ok(_) => panic!("Expected error, got success"),
    }

    mock.assert();
}

#[tokio::test]
async fn test_cache_behavior() {
    let mut server = mockito::Server::new_async().await;

    // Create a mock that will be called only once (second hit should be cached)
    let mock = server
        .mock("GET", "/v1/secret/data/cached")
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(create_kv_v2_response("cached-value").to_string())
        .expect(1) // Should only be called once
        .create_async()
        .await;

    let config = create_test_config(&server.url());
    let backend = VaultBackend::new(config).await.unwrap();

    let path = SecretPath::new("vault/cached").unwrap();

    // First call - should hit the API
    let result1 = backend.get(&path).await;
    assert!(result1.is_ok());
    let value1 = result1
        .unwrap()
        .expose(|bytes| String::from_utf8(bytes.to_vec()).unwrap());
    assert_eq!(value1, "cached-value");

    // Second call - should use cache (no additional API call)
    let result2 = backend.get(&path).await;
    assert!(result2.is_ok());
    let value2 = result2
        .unwrap()
        .expose(|bytes| String::from_utf8(bytes.to_vec()).unwrap());
    assert_eq!(value2, "cached-value");

    // Verify the mock was called only once
    mock.assert();
}

#[tokio::test]
async fn test_cache_invalidation_on_set() {
    let mut server = mockito::Server::new_async().await;

    // Mock get endpoint
    let get_mock = server
        .mock("GET", "/v1/secret/data/cache_test")
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(create_kv_v2_response("initial-value").to_string())
        .expect(2) // Will be called twice due to cache invalidation
        .create_async()
        .await;

    // Mock set endpoint
    let set_mock = server
        .mock("POST", "/v1/secret/data/cache_test")
        .match_body(Matcher::JsonString(r#"{"data":{"value":"new-value","metadata":{"tags":[],"custom_metadata":{"notes":""}}}}"#.to_string()))
        .with_status(200)
        .create_async()
        .await;

    let config = create_test_config(&server.url());
    let backend = VaultBackend::new(config).await.unwrap();

    let path = SecretPath::new("vault/cache_test").unwrap();

    // First get - caches the value
    let result1 = backend.get(&path).await.unwrap();
    let value1 = result1.expose(|bytes| String::from_utf8(bytes.to_vec()).unwrap());
    assert_eq!(value1, "initial-value");

    // Set new value - should invalidate cache
    let metadata = SecretMetadata {
        path: SecretPath::new("vault/cache_test").unwrap(),
        secret_type: SecretType::Generic,
        tags: vec![],
        notes: None,
        created_at: chrono::Utc::now(),
        updated_at: chrono::Utc::now(),
        expires_at: None,
    };
    backend
        .set(&path, &SecretValue::new(b"new-value".to_vec()), &metadata)
        .await
        .unwrap();

    // Second get - should fetch from Vault (cache was invalidated)
    let result2 = backend.get(&path).await.unwrap();
    let value2 = result2.expose(|bytes| String::from_utf8(bytes.to_vec()).unwrap());
    assert_eq!(value2, "initial-value");

    get_mock.assert();
    set_mock.assert();
}

#[tokio::test]
async fn test_cache_invalidation_on_delete() {
    let mut server = mockito::Server::new_async().await;

    // Mock get endpoint
    let get_mock = server
        .mock("GET", "/v1/secret/data/delete_test")
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(create_kv_v2_response("value-to-delete").to_string())
        .expect(1) // Will be called once
        .create_async()
        .await;

    // Mock delete endpoint
    let delete_mock = server
        .mock("DELETE", "/v1/secret/metadata/delete_test")
        .with_status(204)
        .create_async()
        .await;

    let config = create_test_config(&server.url());
    let backend = VaultBackend::new(config).await.unwrap();

    let path = SecretPath::new("vault/delete_test").unwrap();

    // Get to populate cache
    let result1 = backend.get(&path).await.unwrap();
    let value1 = result1.expose(|bytes| String::from_utf8(bytes.to_vec()).unwrap());
    assert_eq!(value1, "value-to-delete");

    // Delete - should invalidate cache
    backend.delete(&path).await.unwrap();

    // Verify mocks were called
    get_mock.assert();
    delete_mock.assert();
}

#[tokio::test]
async fn test_backend_type() {
    let server = mockito::Server::new_async().await;
    let config = create_test_config(&server.url());
    let backend = VaultBackend::new(config).await.unwrap();

    assert_eq!(backend.backend_type(), "vault");
}

#[tokio::test]
async fn test_get_metadata() {
    let mut server = mockito::Server::new_async().await;

    // Mock the Vault KV v2 read endpoint
    let mock = server
        .mock("GET", "/v1/secret/data/test/api_key")
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(create_kv_v2_response("secret-value").to_string())
        .create_async()
        .await;

    let config = create_test_config(&server.url());
    let backend = VaultBackend::new(config).await.unwrap();

    let path = SecretPath::new("vault/test/api_key").unwrap();
    let result = backend.get_metadata(&path).await;

    assert!(result.is_ok(), "get_metadata should succeed");
    let metadata = result.unwrap();

    assert_eq!(metadata.path.as_str(), "vault/test/api_key");
    assert_eq!(metadata.secret_type, SecretType::ApiKey); // Contains "key" keyword
    assert!(metadata.tags.contains(&"vault".to_string()));
    assert!(metadata.notes.is_some());

    mock.assert();
}
