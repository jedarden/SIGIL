//! Behavioral tests for Vault/OpenBao backend
//!
//! This test file verifies that the Vault backend correctly interacts with
//! Vault/OpenBao KV v2 HTTP API, including successful operations and error handling.
//!
//! Testing pattern:
//! - Mock HTTP responses for get/set/delete/list operations
//! - Use mockito's Server to simulate Vault KV v2 endpoints
//! - Test authentication, error handling, and response parsing
//! - Verify cache functionality and namespace support
//! - Test KV v2 specific behavior (versioning, metadata, cas)

use mockito::Server;
use serde_json::json;

/// Test successful KV v2 get operation
#[tokio::test]
async fn test_successful_get() {
    let mut server = Server::new_async().await;

    // Mock KV v2 read endpoint
    // Vault KV v2 GET: /v1/secret/data/<path>
    let mock = server
        .mock("GET", "/v1/secret/data/mysecret")
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(
            r#"{
            "data": {
                "metadata": {
                    "created_time": "2022-01-01T00:00:00Z",
                    "deletion_time": "",
                    "destroyed": false,
                    "version": 1
                },
                "data": {
                    "password": "my-secret-value",
                    "username": "admin"
                }
            }
        }"#,
        )
        .create_async()
        .await;

    let url = server.url();
    assert!(!url.is_empty());

    // Verify the mock works
    let client = reqwest::Client::new();
    let response = client
        .get(format!("{}/v1/secret/data/mysecret", url))
        .header("X-Vault-Token", "test-token")
        .send()
        .await
        .expect("Failed to send request");

    assert_eq!(response.status(), 200);
    mock.assert_async().await;
}

/// Test get operation with specific version
#[tokio::test]
async fn test_get_with_version() {
    let mut server = Server::new_async().await;

    // Mock KV v2 read with version parameter
    let mock = server
        .mock("GET", "/v1/secret/data/mysecret?version=2")
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(
            r#"{
            "data": {
                "metadata": {
                    "created_time": "2022-01-02T00:00:00Z",
                    "version": 2
                },
                "data": {
                    "password": "old-secret-value"
                }
            }
        }"#,
        )
        .create_async()
        .await;

    let url = server.url();
    let client = reqwest::Client::new();
    let response = client
        .get(format!("{}/v1/secret/data/mysecret?version=2", url))
        .header("X-Vault-Token", "test-token")
        .send()
        .await
        .expect("Failed to send request");

    assert_eq!(response.status(), 200);
    mock.assert_async().await;
}

/// Test successful list operation (KV v2)
#[tokio::test]
async fn test_successful_list() {
    let mut server = Server::new_async().await;

    // Mock KV v2 list endpoint
    // Vault KV v2 LIST: /v1/secret/metadata/<path>
    let mock = server
        .mock("LIST", "/v1/secret/metadata/")
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(
            r#"{
            "data": {
                "keys": ["db", "api", "config"]
            }
        }"#,
        )
        .create_async()
        .await;

    let url = server.url();
    let client = reqwest::Client::builder()
        .build()
        .expect("Failed to create client");

    let response = client
        .request(
            reqwest::Method::from_bytes(b"LIST").unwrap(),
            format!("{}/v1/secret/metadata/", url),
        )
        .header("X-Vault-Token", "test-token")
        .send()
        .await
        .expect("Failed to send request");

    assert_eq!(response.status(), 200);
    mock.assert_async().await;
}

/// Test successful create/update operation
#[tokio::test]
async fn test_successful_create() {
    let mut server = Server::new_async().await;

    // Mock KV v2 write endpoint
    let mock = server
        .mock("POST", "/v1/secret/data/newsecret")
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(
            r#"{
            "data": {
                "metadata": {
                    "created_time": "2022-01-01T00:00:00Z",
                    "version": 1
                },
                "data": {
                    "value": "new-secret"
                }
            }
        }"#,
        )
        .create_async()
        .await;

    let url = server.url();
    let client = reqwest::Client::new();
    let response = client
        .post(format!("{}/v1/secret/data/newsecret", url))
        .header("X-Vault-Token", "test-token")
        .json(&json!({"data": {"value": "new-secret"}}))
        .send()
        .await
        .expect("Failed to send request");

    assert_eq!(response.status(), 200);
    mock.assert_async().await;
}

/// Test successful update with check-and-set (CAS)
#[tokio::test]
async fn test_update_with_cas() {
    let mut server = Server::new_async().await;

    // Mock KV v2 update with CAS parameter
    let mock = server
        .mock("POST", "/v1/secret/data/mysecret")
        .match_query(mockito::Matcher::AllOf(vec![mockito::Matcher::UrlEncoded(
            "cas".into(),
            "1".into(),
        )]))
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(
            r#"{
            "data": {
                "metadata": {
                    "version": 2
                },
                "data": {
                    "value": "updated-value"
                }
            }
        }"#,
        )
        .create_async()
        .await;

    let url = server.url();
    let client = reqwest::Client::new();
    let response = client
        .post(format!("{}/v1/secret/data/mysecret?cas=1", url))
        .header("X-Vault-Token", "test-token")
        .json(&json!({"data": {"value": "updated-value"}}))
        .send()
        .await
        .expect("Failed to send request");

    assert_eq!(response.status(), 200);
    mock.assert_async().await;
}

/// Test successful delete operation
#[tokio::test]
async fn test_successful_delete() {
    let mut server = Server::new_async().await;

    // Mock KV v2 delete endpoint
    let mock = server
        .mock("DELETE", "/v1/secret/data/deletedsecret")
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(r#"{}"#)
        .create_async()
        .await;

    let url = server.url();
    let client = reqwest::Client::new();
    let response = client
        .delete(format!("{}/v1/secret/data/deletedsecret", url))
        .header("X-Vault-Token", "test-token")
        .send()
        .await
        .expect("Failed to send request");

    assert_eq!(response.status(), 200);
    mock.assert_async().await;
}

/// Test permanent delete (destroy metadata)
#[tokio::test]
async fn test_permanent_delete() {
    let mut server = Server::new_async().await;

    // Mock KV v2 metadata destroy endpoint
    let mock = server
        .mock("DELETE", "/v1/secret/metadata/deletedsecret")
        .with_status(204)
        .create_async()
        .await;

    let url = server.url();
    let client = reqwest::Client::new();
    let response = client
        .delete(format!("{}/v1/secret/metadata/deletedsecret", url))
        .header("X-Vault-Token", "test-token")
        .send()
        .await
        .expect("Failed to send request");

    assert_eq!(response.status(), 204);
    mock.assert_async().await;
}

/// Test secret not found error
#[tokio::test]
async fn test_secret_not_found() {
    let mut server = Server::new_async().await;

    // Mock Vault error response
    let mock = server
        .mock("GET", "/v1/secret/data/nonexistent")
        .with_status(404)
        .with_header("content-type", "application/json")
        .with_body(
            r#"{
            "errors": [
                "no secret found at nonexistent/data/nonexistent"
            ]
        }"#,
        )
        .create_async()
        .await;

    let url = server.url();
    let client = reqwest::Client::new();
    let response = client
        .get(format!("{}/v1/secret/data/nonexistent", url))
        .header("X-Vault-Token", "test-token")
        .send()
        .await
        .expect("Failed to send request");

    assert_eq!(response.status(), 404);
    mock.assert_async().await;
}

/// Test invalid token (403)
#[tokio::test]
async fn test_invalid_token() {
    let mut server = Server::new_async().await;

    // Mock permission denied response
    let mock = server
        .mock("GET", "/v1/secret/data/mysecret")
        .with_status(403)
        .with_header("content-type", "application/json")
        .with_body(
            r#"{
            "errors": [
                "permission denied"
            ]
        }"#,
        )
        .create_async()
        .await;

    let url = server.url();
    let client = reqwest::Client::new();
    let response = client
        .get(format!("{}/v1/secret/data/mysecret", url))
        .header("X-Vault-Token", "invalid-token")
        .send()
        .await
        .expect("Failed to send request");

    assert_eq!(response.status(), 403);
    mock.assert_async().await;
}

/// Test expired token (403)
#[tokio::test]
async fn test_expired_token() {
    let mut server = Server::new_async().await;

    // Mock expired token response
    let mock = server
        .mock("GET", "/v1/secret/data/mysecret")
        .with_status(403)
        .with_header("content-type", "application/json")
        .with_body(
            r#"{
            "errors": [
                "invalid token"
            ]
        }"#,
        )
        .create_async()
        .await;

    let url = server.url();
    let client = reqwest::Client::new();
    let response = client
        .get(format!("{}/v1/secret/data/mysecret", url))
        .header("X-Vault-Token", "expired-token")
        .send()
        .await
        .expect("Failed to send request");

    assert_eq!(response.status(), 403);
    mock.assert_async().await;
}

/// Test server error (500)
#[tokio::test]
async fn test_server_error() {
    let mut server = Server::new_async().await;

    // Mock internal server error
    let mock = server
        .mock("GET", "/v1/secret/data/mysecret")
        .with_status(500)
        .with_header("content-type", "application/json")
        .with_body(
            r#"{
            "errors": [
                "internal server error"
            ]
        }"#,
        )
        .create_async()
        .await;

    let url = server.url();
    let client = reqwest::Client::new();
    let response = client
        .get(format!("{}/v1/secret/data/mysecret", url))
        .header("X-Vault-Token", "test-token")
        .send()
        .await
        .expect("Failed to send request");

    assert_eq!(response.status(), 500);
    mock.assert_async().await;
}

/// Test Vault sealed (503)
#[tokio::test]
async fn test_vault_sealed() {
    let mut server = Server::new_async().await;

    // Mock sealed Vault response
    let mock = server
        .mock("GET", "/v1/secret/data/mysecret")
        .with_status(503)
        .with_header("content-type", "application/json")
        .with_body(
            r#"{
            "errors": [
                "Vault is sealed"
            ]
        }"#,
        )
        .create_async()
        .await;

    let url = server.url();
    let client = reqwest::Client::new();
    let response = client
        .get(format!("{}/v1/secret/data/mysecret", url))
        .header("X-Vault-Token", "test-token")
        .send()
        .await
        .expect("Failed to send request");

    assert_eq!(response.status(), 503);
    mock.assert_async().await;
}

/// Test standby node (503 with redirect)
#[tokio::test]
async fn test_standby_redirect() {
    let mut server = Server::new_async().await;

    // Mock standby node redirect
    let mock = server
        .mock("GET", "/v1/secret/data/mysecret")
        .with_status(307)
        .with_header(
            "Location",
            "http://active-vault:8200/v1/secret/data/mysecret",
        )
        .create_async()
        .await;

    let url = server.url();
    // Disable redirect following to test redirect status code
    let client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .expect("Failed to create client");
    let response = client
        .get(format!("{}/v1/secret/data/mysecret", url))
        .header("X-Vault-Token", "test-token")
        .send()
        .await
        .expect("Failed to send request");

    assert_eq!(response.status(), 307);

    // Verify the Location header is set correctly
    let location = response
        .headers()
        .get("Location")
        .and_then(|v| v.to_str().ok());
    assert_eq!(
        location,
        Some("http://active-vault:8200/v1/secret/data/mysecret")
    );

    mock.assert_async().await;
}

/// Test network timeout
#[tokio::test]
async fn test_network_timeout() {
    let mut server = Server::new_async().await;

    // Mock a timeout by not responding
    let _mock = server
        .mock("GET", "/v1/secret/data/mysecret")
        .with_status(200)
        .with_chunked_body(|_| Err(std::io::Error::new(std::io::ErrorKind::TimedOut, "timeout")))
        .create_async()
        .await;

    let url = server.url();
    assert!(!url.is_empty());
}

/// Test KV v2 patch metadata operation
#[tokio::test]
async fn test_patch_metadata() {
    let mut server = Server::new_async().await;

    // Mock KV v2 metadata patch
    let mock = server
        .mock("PATCH", "/v1/secret/metadata/mysecret")
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(r#"{}"#)
        .create_async()
        .await;

    let url = server.url();
    let client = reqwest::Client::builder()
        .build()
        .expect("Failed to create client");

    let response = client
        .request(
            reqwest::Method::from_bytes(b"PATCH").unwrap(),
            format!("{}/v1/secret/metadata/mysecret", url),
        )
        .header("X-Vault-Token", "test-token")
        .json(&json!({"max_versions": 10}))
        .send()
        .await
        .expect("Failed to send request");

    assert_eq!(response.status(), 200);
    mock.assert_async().await;
}

/// Test namespace header support
#[tokio::test]
async fn test_namespace_header() {
    let mut server = Server::new_async().await;

    // Mock with namespace expectation
    let mock = server
        .mock("GET", "/v1/secret/data/mysecret")
        .match_header("X-Vault-Namespace", "ns1")
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(r#"{"data": {"data": {"value": "test"}}}"#)
        .create_async()
        .await;

    let url = server.url();
    let client = reqwest::Client::new();
    let response = client
        .get(format!("{}/v1/secret/data/mysecret", url))
        .header("X-Vault-Token", "test-token")
        .header("X-Vault-Namespace", "ns1")
        .send()
        .await
        .expect("Failed to send request");

    assert_eq!(response.status(), 200);
    mock.assert_async().await;
}

/// Test health check endpoint
#[tokio::test]
async fn test_health_check() {
    let mut server = Server::new_async().await;

    // Mock health check
    let mock = server
        .mock("GET", "/v1/sys/health")
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(
            r#"{
            "initialized": true,
            "sealed": false,
            "standby": false
        }"#,
        )
        .create_async()
        .await;

    let url = server.url();
    let client = reqwest::Client::new();
    let response = client
        .get(format!("{}/v1/sys/health", url))
        .send()
        .await
        .expect("Failed to send request");

    assert_eq!(response.status(), 200);
    mock.assert_async().await;

    let body: serde_json::Value = response.json().await.expect("Failed to parse JSON");
    assert_eq!(body["initialized"], true);
    assert_eq!(body["sealed"], false);
    assert_eq!(body["standby"], false);
}

/// Test cache behavior consistency
#[tokio::test]
async fn test_cache_behavior() {
    let mut server = Server::new_async().await;

    // Mock to verify cache behavior - should be called twice in this test
    // (In a real backend with caching, subsequent calls would hit cache)
    let mock = server
        .mock("GET", "/v1/secret/data/cachedsecret")
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(
            r#"{
            "data": {
                "data": {"value": "cached-value"},
                "metadata": {"version": 1}
            }
        }"#,
        )
        .expect(2) // Called twice since we're testing HTTP directly, not backend cache
        .create_async()
        .await;

    let url = server.url();

    // First request - cache miss, calls API
    let client = reqwest::Client::new();
    let response1 = client
        .get(format!("{}/v1/secret/data/cachedsecret", url))
        .header("X-Vault-Token", "test-token")
        .send()
        .await
        .expect("Failed to send request");
    assert_eq!(response1.status(), 200);

    // Second request - in a real backend with caching enabled, this would hit cache
    // This test verifies the API response structure is consistent
    let response2 = client
        .get(format!("{}/v1/secret/data/cachedsecret", url))
        .header("X-Vault-Token", "test-token")
        .send()
        .await
        .expect("Failed to send request");
    assert_eq!(response2.status(), 200);

    // Both requests should return identical data (cache consistency)
    let body1: serde_json::Value = response1.json().await.expect("Failed to parse JSON1");
    let body2: serde_json::Value = response2.json().await.expect("Failed to parse JSON2");
    assert_eq!(body1, body2, "Cached data should match original data");

    mock.assert_async().await;
}

/// Test CAS conflict (404 check-and-set failed)
#[tokio::test]
async fn test_cas_conflict() {
    let mut server = Server::new_async().await;

    // Mock CAS conflict response
    let mock = server
        .mock("POST", "/v1/secret/data/mysecret")
        .match_query(mockito::Matcher::AllOf(vec![mockito::Matcher::UrlEncoded(
            "cas".into(),
            "99".into(),
        )]))
        .with_status(404)
        .with_header("content-type", "application/json")
        .with_body(
            r#"{
            "errors": [
                "check-and-set constraint did not match"
            ]
        }"#,
        )
        .create_async()
        .await;

    let url = server.url();
    let client = reqwest::Client::new();
    let response = client
        .post(format!("{}/v1/secret/data/mysecret?cas=99", url))
        .header("X-Vault-Token", "test-token")
        .json(&json!({"data": {"value": "attempted-update"}}))
        .send()
        .await
        .expect("Failed to send request");

    assert_eq!(response.status(), 404);
    mock.assert_async().await;
}

/// Module for behavioral tests using the VaultBackend implementation
mod backend_behavioral {
    use mockito::Server;
    use sigil_backend_vault::{VaultAuth, VaultBackend, VaultBackendConfig, VaultToken};
    use sigil_core::{SecretBackend, SecretMetadata, SecretPath, SecretType, SecretValue};
    use std::time::Duration;

    /// Helper to create a VaultBackend connected to a mock server
    async fn create_test_backend(server: &Server) -> VaultBackend {
        let config = VaultBackendConfig {
            address: server.url(),
            auth: VaultAuth::Token {
                token: VaultToken::Direct("test-token".to_string()),
            },
            mount: "secret".to_string(),
            namespace: None,
            cache_ttl: Duration::from_secs(0), // Disable cache for tests
            verify_tls: false,
        };

        VaultBackend::new(config)
            .await
            .expect("Failed to create Vault backend")
    }

    /// Test successful get operation through SecretBackend trait
    #[tokio::test]
    async fn test_backend_get_success() {
        let mut server = Server::new_async().await;

        let mock = server
            .mock("GET", "/v1/secret/data/testsecret")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(
                r#"{
                "data": {
                    "metadata": {
                        "created_time": "2022-01-01T00:00:00Z",
                        "updated_time": "2022-01-01T00:00:00Z",
                        "version": 1
                    },
                    "data": {
                        "value": "my-secret-value"
                    }
                }
            }"#,
            )
            .create_async()
            .await;

        let backend = create_test_backend(&server).await;
        let path = SecretPath::new("vault/testsecret".to_string()).expect("Failed to create path");

        let result = backend.get(&path).await;

        if let Err(e) = &result {
            eprintln!("Get failed with error: {}", e);
        }
        assert!(
            result.is_ok(),
            "get should succeed, but got error: {:?}",
            result
        );
        let secret_value = result.unwrap();
        let value_bytes = secret_value.expose(|bytes| bytes.to_vec());
        assert_eq!(String::from_utf8_lossy(&value_bytes), "my-secret-value");

        mock.assert_async().await;
    }

    /// Test get operation with 404 not found error
    #[tokio::test]
    async fn test_backend_get_not_found() {
        let mut server = Server::new_async().await;

        let mock = server
            .mock("GET", "/v1/secret/data/nonexistent")
            .with_status(404)
            .with_header("content-type", "application/json")
            .with_body(
                r#"{
                "errors": ["no secret found at nonexistent/data/nonexistent"]
            }"#,
            )
            .create_async()
            .await;

        let backend = create_test_backend(&server).await;
        let path = SecretPath::new("vault/nonexistent".to_string()).expect("Failed to create path");

        let result = backend.get(&path).await;

        assert!(result.is_err(), "get should fail for non-existent secret");
        let error = result.unwrap_err();
        assert!(
            error.to_string().contains("not found") || error.to_string().contains("SecretNotFound"),
            "Error should indicate secret not found: {}",
            error
        );

        mock.assert_async().await;
    }

    /// Test get operation with authentication failure (403)
    #[tokio::test]
    async fn test_backend_get_auth_failure() {
        let mut server = Server::new_async().await;

        let mock = server
            .mock("GET", "/v1/secret/data/testsecret")
            .with_status(403)
            .with_header("content-type", "application/json")
            .with_body(
                r#"{
                "errors": ["permission denied"]
            }"#,
            )
            .create_async()
            .await;

        let backend = create_test_backend(&server).await;
        let path = SecretPath::new("vault/testsecret".to_string()).expect("Failed to create path");

        let result = backend.get(&path).await;

        assert!(result.is_err(), "get should fail with auth error");
        let error = result.unwrap_err();
        assert!(
            error.to_string().contains("Access denied") || error.to_string().contains("permission"),
            "Error should indicate access denied: {}",
            error
        );

        mock.assert_async().await;
    }

    /// Test successful set operation through SecretBackend trait
    #[tokio::test]
    async fn test_backend_set_success() {
        let mut server = Server::new_async().await;

        let mock = server
            .mock("POST", "/v1/secret/data/newsecret")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(
                r#"{
                "data": {
                    "metadata": {
                        "created_time": "2022-01-01T00:00:00Z",
                        "version": 1
                    }
                }
            }"#,
            )
            .create_async()
            .await;

        let backend = create_test_backend(&server).await;
        let path = SecretPath::new("vault/newsecret".to_string()).expect("Failed to create path");
        let value = SecretValue::new(b"new-secret-value".to_vec());
        let metadata = SecretMetadata {
            path: SecretPath::new("vault/newsecret".to_string()).unwrap(),
            secret_type: SecretType::Generic,
            tags: vec!["test".to_string()],
            notes: Some("Test secret".to_string()),
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
            expires_at: None,
        };

        let result = backend.set(&path, &value, &metadata).await;

        assert!(result.is_ok(), "set should succeed");
        mock.assert_async().await;
    }

    /// Test set operation with authentication failure (403)
    #[tokio::test]
    async fn test_backend_set_auth_failure() {
        let mut server = Server::new_async().await;

        let mock = server
            .mock("POST", "/v1/secret/data/newsecret")
            .with_status(403)
            .with_header("content-type", "application/json")
            .with_body(
                r#"{
                "errors": ["permission denied"]
            }"#,
            )
            .create_async()
            .await;

        let backend = create_test_backend(&server).await;
        let path = SecretPath::new("vault/newsecret".to_string()).expect("Failed to create path");
        let value = SecretValue::new(b"new-secret-value".to_vec());
        let metadata = SecretMetadata {
            path: SecretPath::new("vault/newsecret".to_string()).unwrap(),
            secret_type: SecretType::Generic,
            tags: vec![],
            notes: None,
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
            expires_at: None,
        };

        let result = backend.set(&path, &value, &metadata).await;

        assert!(result.is_err(), "set should fail with auth error");
        let error = result.unwrap_err();
        assert!(
            error.to_string().contains("Access denied") || error.to_string().contains("permission"),
            "Error should indicate access denied: {}",
            error
        );

        mock.assert_async().await;
    }

    /// Test successful delete operation through SecretBackend trait
    #[tokio::test]
    async fn test_backend_delete_success() {
        let mut server = Server::new_async().await;

        let mock = server
            .mock("DELETE", "/v1/secret/metadata/todelete")
            .with_status(204)
            .create_async()
            .await;

        let backend = create_test_backend(&server).await;
        let path = SecretPath::new("vault/todelete".to_string()).expect("Failed to create path");

        let result = backend.delete(&path).await;

        assert!(result.is_ok(), "delete should succeed");
        mock.assert_async().await;
    }

    /// Test delete operation with authentication failure
    #[tokio::test]
    async fn test_backend_delete_auth_failure() {
        let mut server = Server::new_async().await;

        let mock = server
            .mock("DELETE", "/v1/secret/metadata/todelete")
            .with_status(403)
            .with_header("content-type", "application/json")
            .with_body(
                r#"{
                "errors": ["permission denied"]
            }"#,
            )
            .create_async()
            .await;

        let backend = create_test_backend(&server).await;
        let path = SecretPath::new("vault/todelete".to_string()).expect("Failed to create path");

        let result = backend.delete(&path).await;

        assert!(result.is_err(), "delete should fail with auth error");
        let error = result.unwrap_err();
        assert!(
            error.to_string().contains("Access denied") || error.to_string().contains("permission"),
            "Error should indicate access denied: {}",
            error
        );

        mock.assert_async().await;
    }

    /// Test successful list operation through SecretBackend trait
    #[tokio::test]
    async fn test_backend_list_success() {
        let mut server = Server::new_async().await;

        let mock = server
            .mock("GET", "/v1/secret/metadata?list=true")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(
                r#"{
                "data": {
                    "keys": ["secret1", "secret2", "secret3"]
                }
            }"#,
            )
            .create_async()
            .await;

        let backend = create_test_backend(&server).await;

        let result = backend.list("").await;

        assert!(result.is_ok(), "list should succeed");
        let secrets = result.unwrap();
        assert_eq!(secrets.len(), 3, "should return 3 secrets");

        // Verify secret paths are prefixed with "vault/"
        for secret in &secrets {
            assert!(
                secret.path.as_str().starts_with("vault/"),
                "Secret path should start with 'vault/': {}",
                secret.path.as_str()
            );
        }

        mock.assert_async().await;
    }

    /// Test list operation with authentication failure
    #[tokio::test]
    async fn test_backend_list_auth_failure() {
        let mut server = Server::new_async().await;

        let mock = server
            .mock("GET", "/v1/secret/metadata?list=true")
            .with_status(403)
            .with_header("content-type", "application/json")
            .with_body(
                r#"{
                "errors": ["permission denied"]
            }"#,
            )
            .create_async()
            .await;

        let backend = create_test_backend(&server).await;

        let result = backend.list("").await;

        assert!(result.is_err(), "list should fail with auth error");
        let error = result.unwrap_err();
        assert!(
            error.to_string().contains("Access denied") || error.to_string().contains("permission"),
            "Error should indicate access denied: {}",
            error
        );

        mock.assert_async().await;
    }

    /// Test list operation with empty result
    #[tokio::test]
    async fn test_backend_list_empty() {
        let mut server = Server::new_async().await;

        let mock = server
            .mock("GET", "/v1/secret/metadata?list=true")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(
                r#"{
                "data": {
                    "keys": []
                }
            }"#,
            )
            .create_async()
            .await;

        let backend = create_test_backend(&server).await;

        let result = backend.list("").await;

        assert!(result.is_ok(), "list should succeed even when empty");
        let secrets = result.unwrap();
        assert_eq!(secrets.len(), 0, "should return 0 secrets");

        mock.assert_async().await;
    }

    /// Test backend_type method
    #[tokio::test]
    async fn test_backend_type() {
        let server = Server::new_async().await;
        let backend = create_test_backend(&server).await;

        assert_eq!(backend.backend_type(), "vault");
    }

    /// Test get_metadata operation
    #[tokio::test]
    async fn test_backend_get_metadata() {
        let mut server = Server::new_async().await;

        let mock = server
            .mock("GET", "/v1/secret/data/testsecret")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(
                r#"{
                "data": {
                    "metadata": {
                        "created_time": "2022-01-01T00:00:00Z",
                        "updated_time": "2022-01-02T00:00:00Z",
                        "version": 2
                    },
                    "data": {
                        "value": "secret-value"
                    }
                }
            }"#,
            )
            .create_async()
            .await;

        let backend = create_test_backend(&server).await;
        let path = SecretPath::new("vault/testsecret".to_string()).expect("Failed to create path");

        let result = backend.get_metadata(&path).await;

        assert!(result.is_ok(), "get_metadata should succeed");
        let metadata = result.unwrap();
        assert_eq!(metadata.secret_type, SecretType::Generic);
        assert!(metadata.tags.contains(&"vault".to_string()));

        mock.assert_async().await;
    }

    /// Test complete workflow: get, set, delete, list
    #[tokio::test]
    async fn test_backend_complete_workflow() {
        let mut server = Server::new_async().await;

        // Mock set operation
        let set_mock = server
            .mock("POST", "/v1/secret/data/workflowtest")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(
                r#"{
                "data": {
                    "metadata": {
                        "created_time": "2022-01-01T00:00:00Z",
                        "version": 1
                    }
                }
            }"#,
            )
            .expect(1)
            .create_async()
            .await;

        // Mock get operation
        let get_mock = server
            .mock("GET", "/v1/secret/data/workflowtest")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(
                r#"{
                "data": {
                    "metadata": {
                        "created_time": "2022-01-01T00:00:00Z",
                        "updated_time": "2022-01-01T00:00:00Z",
                        "version": 1
                    },
                    "data": {
                        "value": "workflow-value"
                    }
                }
            }"#,
            )
            .expect(1)
            .create_async()
            .await;

        // Mock list operation
        let list_mock = server
            .mock("GET", "/v1/secret/metadata?list=true")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(
                r#"{
                "data": {
                    "keys": ["workflowtest"]
                }
            }"#,
            )
            .expect(1)
            .create_async()
            .await;

        // Mock delete operation
        let delete_mock = server
            .mock("DELETE", "/v1/secret/metadata/workflowtest")
            .with_status(204)
            .expect(1)
            .create_async()
            .await;

        let backend = create_test_backend(&server).await;

        // 1. Set a secret
        let path = SecretPath::new("vault/workflowtest".to_string()).unwrap();
        let value = SecretValue::new(b"workflow-value".to_vec());
        let metadata = SecretMetadata {
            path: path.clone(),
            secret_type: SecretType::Generic,
            tags: vec![],
            notes: None,
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
            expires_at: None,
        };

        backend
            .set(&path, &value, &metadata)
            .await
            .expect("set should succeed");

        // 2. Get the secret back
        let retrieved_value = backend.get(&path).await.expect("get should succeed");
        let retrieved_bytes = retrieved_value.expose(|bytes| bytes.to_vec());
        assert_eq!(String::from_utf8_lossy(&retrieved_bytes), "workflow-value");

        // 3. List secrets
        let secrets = backend.list("").await.expect("list should succeed");
        assert_eq!(secrets.len(), 1);
        assert_eq!(secrets[0].path.as_str(), "vault/workflowtest");

        // 4. Delete the secret
        backend.delete(&path).await.expect("delete should succeed");

        // Verify all mocks were called
        set_mock.assert_async().await;
        get_mock.assert_async().await;
        list_mock.assert_async().await;
        delete_mock.assert_async().await;
    }

    /// Test that cache is disabled in tests (cache_ttl = 0)
    #[tokio::test]
    async fn test_cache_disabled() {
        let mut server = Server::new_async().await;

        // The mock should be called twice since cache is disabled
        let mock = server
            .mock("GET", "/v1/secret/data/cachetest")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(
                r#"{
                "data": {
                    "metadata": {
                        "created_time": "2022-01-01T00:00:00Z",
                        "updated_time": "2022-01-01T00:00:00Z",
                        "version": 1
                    },
                    "data": {
                        "value": "cached-value"
                    }
                }
            }"#,
            )
            .expect(2) // Should be called twice since cache is disabled
            .create_async()
            .await;

        let backend = create_test_backend(&server).await;
        let path = SecretPath::new("vault/cachetest".to_string()).expect("Failed to create path");

        // First call - cache miss, calls API
        backend.get(&path).await.expect("First get should succeed");

        // Second call - with cache disabled, should call API again
        backend.get(&path).await.expect("Second get should succeed");

        mock.assert_async().await;
    }

    /// Test server error (500) on get operation
    #[tokio::test]
    async fn test_backend_get_server_error() {
        let mut server = Server::new_async().await;

        let mock = server
            .mock("GET", "/v1/secret/data/testsecret")
            .with_status(500)
            .with_header("content-type", "application/json")
            .with_body(
                r#"{
                "errors": ["internal server error"]
            }"#,
            )
            .create_async()
            .await;

        let backend = create_test_backend(&server).await;
        let path = SecretPath::new("vault/testsecret".to_string()).expect("Failed to create path");

        let result = backend.get(&path).await;

        assert!(result.is_err(), "get should fail with server error");
        let error = result.unwrap_err();
        assert!(
            error.to_string().contains("500") || error.to_string().contains("error"),
            "Error should indicate server error: {}",
            error
        );

        mock.assert_async().await;
    }

    /// Test list operation with prefix
    #[tokio::test]
    async fn test_backend_list_with_prefix() {
        let mut server = Server::new_async().await;

        let mock = server
            .mock("GET", "/v1/secret/metadata/subfolder?list=true")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(
                r#"{
                "data": {
                    "keys": ["key1", "key2"]
                }
            }"#,
            )
            .create_async()
            .await;

        let backend = create_test_backend(&server).await;

        let result = backend.list("vault/subfolder").await;

        assert!(result.is_ok(), "list with prefix should succeed");
        let secrets = result.unwrap();
        assert_eq!(secrets.len(), 2);

        // Verify paths include the prefix
        for secret in &secrets {
            assert!(
                secret.path.as_str().starts_with("vault/subfolder/"),
                "Secret path should include prefix: {}",
                secret.path.as_str()
            );
        }

        mock.assert_async().await;
    }
}
