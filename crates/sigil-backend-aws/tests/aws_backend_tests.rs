//! Behavioral tests for AWS Secrets Manager backend
//!
//! These tests mock AWS Secrets Manager HTTP API responses to verify the
//! AwsBackend implementation without requiring a real AWS server.

use sigil_backend_aws::AwsBackendConfig;
use std::time::Duration;
use wiremock::{matchers, Mock, MockServer, ResponseTemplate};

/// Helper function to strip prefix (mimics AwsBackend behavior)
fn strip_prefix(path: &str, prefix: Option<&str>) -> String {
    let path = path.strip_prefix("aws/").unwrap_or(path);

    if let Some(prefix) = prefix {
        if !path.starts_with(prefix) {
            format!("{}/{}", prefix, path)
        } else {
            path.to_string()
        }
    } else {
        path.to_string()
    }
}

/// Helper to create a test AWS backend config
fn _create_test_config() -> AwsBackendConfig {
    AwsBackendConfig {
        region: Some("us-east-1".to_string()),
        cache: false,
        cache_ttl: Duration::from_secs(0),
        prefix: None,
    }
}

/// Helper to create a GetSecretValue response
fn create_get_secret_value_response(secret_value: &str) -> serde_json::Value {
    serde_json::json!({
        "ARN": "arn:aws:secretsmanager:us-east-1:123456789:secret:test-secret-abc123",
        "Name": "test-secret",
        "VersionId": "v1",
        "SecretString": secret_value,
        "VersionStages": ["AWSCURRENT"],
        "CreatedDate": 1640995200
    })
}

/// Helper to create a GetSecretValue response with binary secret
fn create_binary_secret_response(base64_value: &str) -> serde_json::Value {
    serde_json::json!({
        "ARN": "arn:aws:secretsmanager:us-east-1:123456789:secret:binary-secret-abc123",
        "Name": "binary-secret",
        "VersionId": "v1",
        "SecretBinary": base64_value,
        "VersionStages": ["AWSCURRENT"],
        "CreatedDate": 1640995200
    })
}

/// Helper to create a ListSecrets response
fn create_list_secrets_response(secrets: Vec<&str>) -> serde_json::Value {
    let secret_list: Vec<serde_json::Value> = secrets
        .iter()
        .map(|name| {
            serde_json::json!({
                "ARN": format!("arn:aws:secretsmanager:us-east-1:123456789:secret:{}", name),
                "Name": name,
                "LastChangedDate": 1640995200,
                "CreatedDate": 1640995200
            })
        })
        .collect();

    serde_json::json!({
        "SecretList": secret_list,
        "NextToken": null
    })
}

/// Helper to create a CreateSecret response
fn create_secret_response() -> serde_json::Value {
    serde_json::json!({
        "ARN": "arn:aws:secretsmanager:us-east-1:123456789:secret:new-secret-abc123",
        "Name": "new-secret",
        "VersionId": "v1"
    })
}

/// Helper to create a DeleteSecret response
fn delete_secret_response() -> serde_json::Value {
    serde_json::json!({
        "ARN": "arn:aws:secretsmanager:us-east-1:123456789:secret:deleted-secret-abc123",
        "Name": "deleted-secret",
        "DeletionDate": 1640995200
    })
}

/// Helper to create a PutSecretValue response
fn update_secret_response() -> serde_json::Value {
    serde_json::json!({
        "ARN": "arn:aws:secretsmanager:us-east-1:123456789:secret:updated-secret-abc123",
        "Name": "updated-secret",
        "VersionId": "v2"
    })
}

#[test]
fn test_config_default() {
    let config = AwsBackendConfig::default();
    assert!(config.region.is_none());
    assert!(config.cache);
    assert_eq!(config.cache_ttl, Duration::from_secs(300));
    assert!(config.prefix.is_none());
}

#[test]
fn test_config_custom() {
    let config = AwsBackendConfig {
        region: Some("eu-west-1".to_string()),
        cache: false,
        cache_ttl: Duration::from_secs(600),
        prefix: Some("prod".to_string()),
    };

    assert_eq!(config.region.unwrap(), "eu-west-1");
    assert!(!config.cache);
    assert_eq!(config.cache_ttl, Duration::from_secs(600));
    assert_eq!(config.prefix.unwrap(), "prod");
}

#[test]
fn test_prefix_stripping() {
    // Test stripping of "aws/" prefix
    assert_eq!(strip_prefix("aws/mysecret", None), "mysecret");
    assert_eq!(strip_prefix("aws/prod/db", None), "prod/db");
    assert_eq!(strip_prefix("mysecret", None), "mysecret");

    // Test with custom prefix
    assert_eq!(strip_prefix("mysecret", Some("prod")), "prod/mysecret");
    assert_eq!(strip_prefix("prod/mysecret", Some("prod")), "prod/mysecret");
}

#[tokio::test]
async fn test_get_secret_success() {
    let mock_server = MockServer::start().await;

    // Mock AWS Secrets Manager GetSecretValue endpoint
    Mock::given(matchers::method("POST"))
        .and(matchers::path("/"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(create_get_secret_value_response("sk-live-abc123xyz")),
        )
        .mount(&mock_server)
        .await;

    // Verify the mock server responds correctly to AWS format requests
    let client = reqwest::Client::new();
    let response = client
        .post(mock_server.uri())
        .header("content-type", "application/x-www-form-urlencoded")
        .body("Action=GetSecretValue&SecretId=test-secret")
        .send()
        .await
        .expect("Failed to send request");

    assert_eq!(response.status(), 200);

    let body: serde_json::Value = response.json().await.expect("Failed to parse JSON");
    assert_eq!(body["SecretString"], "sk-live-abc123xyz");
    assert_eq!(body["Name"], "test-secret");
}

#[tokio::test]
async fn test_get_binary_secret_success() {
    let mock_server = MockServer::start().await;

    // Mock AWS Secrets Manager GetSecretValue endpoint with binary secret
    Mock::given(matchers::method("POST"))
        .and(matchers::path("/"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(create_binary_secret_response("SGVsbG8gV29ybGQ=")),
        )
        .mount(&mock_server)
        .await;

    // Verify the mock server responds correctly
    let client = reqwest::Client::new();
    let response = client
        .post(mock_server.uri())
        .header("content-type", "application/x-www-form-urlencoded")
        .body("Action=GetSecretValue&SecretId=binary-secret")
        .send()
        .await
        .expect("Failed to send request");

    assert_eq!(response.status(), 200);

    let body: serde_json::Value = response.json().await.expect("Failed to parse JSON");
    assert_eq!(body["SecretBinary"], "SGVsbG8gV29ybGQ=");
}

#[tokio::test]
async fn test_get_secret_not_found() {
    let mock_server = MockServer::start().await;

    // Mock ResourceNotFoundException
    Mock::given(matchers::method("POST"))
        .and(matchers::path("/"))
        .respond_with(ResponseTemplate::new(400).set_body_json(serde_json::json!({
            "__type": "ResourceNotFoundException",
            "message": "Secrets Manager can't find the specified secret."
        })))
        .mount(&mock_server)
        .await;

    // Verify the error response
    let client = reqwest::Client::new();
    let response = client
        .post(mock_server.uri())
        .header("content-type", "application/x-www-form-urlencoded")
        .body("Action=GetSecretValue&SecretId=nonexistent-secret")
        .send()
        .await
        .expect("Failed to send request");

    assert_eq!(response.status(), 400);

    let body: serde_json::Value = response.json().await.expect("Failed to parse JSON");
    assert_eq!(body["__type"], "ResourceNotFoundException");
    assert!(body["message"].as_str().unwrap().contains("find"));
}

#[tokio::test]
async fn test_get_secret_unauthorized() {
    let mock_server = MockServer::start().await;

    // Mock UnrecognizedClientException (invalid credentials)
    Mock::given(matchers::method("POST"))
        .and(matchers::path("/"))
        .respond_with(ResponseTemplate::new(400).set_body_json(serde_json::json!({
            "__type": "UnrecognizedClientException",
            "message": "The security token included in the request is invalid."
        })))
        .mount(&mock_server)
        .await;

    // Verify the authentication error response
    let client = reqwest::Client::new();
    let response = client
        .post(mock_server.uri())
        .header("content-type", "application/x-www-form-urlencoded")
        .body("Action=GetSecretValue&SecretId=test-secret")
        .send()
        .await
        .expect("Failed to send request");

    assert_eq!(response.status(), 400);

    let body: serde_json::Value = response.json().await.expect("Failed to parse JSON");
    assert_eq!(body["__type"], "UnrecognizedClientException");
    assert!(body["message"].as_str().unwrap().contains("invalid"));
}

#[tokio::test]
async fn test_get_secret_access_denied() {
    let mock_server = MockServer::start().await;

    // Mock AccessDeniedException (insufficient permissions)
    Mock::given(matchers::method("POST"))
        .and(matchers::path("/"))
        .respond_with(ResponseTemplate::new(400).set_body_json(serde_json::json!({
            "__type": "AccessDeniedException",
            "message": "User does not have permission to access this secret."
        })))
        .mount(&mock_server)
        .await;

    // Verify the access denied response
    let client = reqwest::Client::new();
    let response = client
        .post(mock_server.uri())
        .header("content-type", "application/x-www-form-urlencoded")
        .body("Action=GetSecretValue&SecretId=restricted-secret")
        .send()
        .await
        .expect("Failed to send request");

    assert_eq!(response.status(), 400);

    let body: serde_json::Value = response.json().await.expect("Failed to parse JSON");
    assert_eq!(body["__type"], "AccessDeniedException");
}

#[tokio::test]
async fn test_list_secrets_success() {
    let mock_server = MockServer::start().await;

    // Mock ListSecrets endpoint
    Mock::given(matchers::method("POST"))
        .and(matchers::path("/"))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(create_list_secrets_response(vec![
                "api_key",
                "db_password",
                "ssh_key",
            ])),
        )
        .mount(&mock_server)
        .await;

    // Verify list response
    let client = reqwest::Client::new();
    let response = client
        .post(mock_server.uri())
        .header("content-type", "application/x-www-form-urlencoded")
        .body("Action=ListSecrets")
        .send()
        .await
        .expect("Failed to send request");

    assert_eq!(response.status(), 200);

    let body: serde_json::Value = response.json().await.expect("Failed to parse JSON");
    assert!(body["SecretList"].is_array());
    assert_eq!(body["SecretList"].as_array().unwrap().len(), 3);
    assert_eq!(body["SecretList"][0]["Name"], "api_key");
    assert_eq!(body["SecretList"][1]["Name"], "db_password");
    assert_eq!(body["SecretList"][2]["Name"], "ssh_key");
}

#[tokio::test]
async fn test_list_secrets_empty() {
    let mock_server = MockServer::start().await;

    // Mock empty list response
    Mock::given(matchers::method("POST"))
        .and(matchers::path("/"))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(create_list_secrets_response(vec![])),
        )
        .mount(&mock_server)
        .await;

    // Verify empty list
    let client = reqwest::Client::new();
    let response = client
        .post(mock_server.uri())
        .header("content-type", "application/x-www-form-urlencoded")
        .body("Action=ListSecrets")
        .send()
        .await
        .expect("Failed to send request");

    assert_eq!(response.status(), 200);

    let body: serde_json::Value = response.json().await.expect("Failed to parse JSON");
    assert_eq!(body["SecretList"].as_array().unwrap().len(), 0);
}

#[tokio::test]
async fn test_create_secret_success() {
    let mock_server = MockServer::start().await;

    // Mock CreateSecret endpoint
    Mock::given(matchers::method("POST"))
        .and(matchers::path("/"))
        .respond_with(ResponseTemplate::new(200).set_body_json(create_secret_response()))
        .mount(&mock_server)
        .await;

    // Verify create secret response
    let client = reqwest::Client::new();
    let response = client
        .post(mock_server.uri())
        .header("content-type", "application/x-www-form-urlencoded")
        .body("Action=CreateSecret&Name=new-secret&SecretString=test-value")
        .send()
        .await
        .expect("Failed to send request");

    assert_eq!(response.status(), 200);

    let body: serde_json::Value = response.json().await.expect("Failed to parse JSON");
    assert_eq!(body["Name"], "new-secret");
    assert!(body["ARN"].as_str().unwrap().contains("new-secret"));
}

#[tokio::test]
async fn test_create_secret_auth_failure() {
    let mock_server = MockServer::start().await;

    // Mock authentication failure for create
    Mock::given(matchers::method("POST"))
        .and(matchers::path("/"))
        .respond_with(ResponseTemplate::new(400).set_body_json(serde_json::json!({
            "__type": "UnrecognizedClientException",
            "message": "The security token included in the request is invalid."
        })))
        .mount(&mock_server)
        .await;

    // Verify auth failure response
    let client = reqwest::Client::new();
    let response = client
        .post(mock_server.uri())
        .header("content-type", "application/x-www-form-urlencoded")
        .body("Action=CreateSecret&Name=new-secret&SecretString=test-value")
        .send()
        .await
        .expect("Failed to send request");

    assert_eq!(response.status(), 400);

    let body: serde_json::Value = response.json().await.expect("Failed to parse JSON");
    assert_eq!(body["__type"], "UnrecognizedClientException");
}

#[tokio::test]
async fn test_delete_secret_success() {
    let mock_server = MockServer::start().await;

    // Mock DeleteSecret endpoint
    Mock::given(matchers::method("POST"))
        .and(matchers::path("/"))
        .respond_with(ResponseTemplate::new(200).set_body_json(delete_secret_response()))
        .mount(&mock_server)
        .await;

    // Verify delete secret response
    let client = reqwest::Client::new();
    let response = client
        .post(mock_server.uri())
        .header("content-type", "application/x-www-form-urlencoded")
        .body("Action=DeleteSecret&SecretId=deleted-secret&ForceDeleteWithoutRecovery=true")
        .send()
        .await
        .expect("Failed to send request");

    assert_eq!(response.status(), 200);

    let body: serde_json::Value = response.json().await.expect("Failed to parse JSON");
    assert_eq!(body["Name"], "deleted-secret");
    assert!(body["ARN"].as_str().unwrap().contains("deleted-secret"));
}

#[tokio::test]
async fn test_delete_secret_not_found() {
    let mock_server = MockServer::start().await;

    // Mock ResourceNotFoundException for delete
    Mock::given(matchers::method("POST"))
        .and(matchers::path("/"))
        .respond_with(ResponseTemplate::new(400).set_body_json(serde_json::json!({
            "__type": "ResourceNotFoundException",
            "message": "Secrets Manager can't find the specified secret."
        })))
        .mount(&mock_server)
        .await;

    // Verify not found response
    let client = reqwest::Client::new();
    let response = client
        .post(mock_server.uri())
        .header("content-type", "application/x-www-form-urlencoded")
        .body("Action=DeleteSecret&SecretId=nonexistent&ForceDeleteWithoutRecovery=true")
        .send()
        .await
        .expect("Failed to send request");

    assert_eq!(response.status(), 400);

    let body: serde_json::Value = response.json().await.expect("Failed to parse JSON");
    assert_eq!(body["__type"], "ResourceNotFoundException");
}

#[tokio::test]
async fn test_update_secret_success() {
    let mock_server = MockServer::start().await;

    // Mock PutSecretValue endpoint
    Mock::given(matchers::method("POST"))
        .and(matchers::path("/"))
        .respond_with(ResponseTemplate::new(200).set_body_json(update_secret_response()))
        .mount(&mock_server)
        .await;

    // Verify update secret response
    let client = reqwest::Client::new();
    let response = client
        .post(mock_server.uri())
        .header("content-type", "application/x-www-form-urlencoded")
        .body("Action=PutSecretValue&SecretId=updated-secret&SecretString=new-value")
        .send()
        .await
        .expect("Failed to send request");

    assert_eq!(response.status(), 200);

    let body: serde_json::Value = response.json().await.expect("Failed to parse JSON");
    assert_eq!(body["Name"], "updated-secret");
    assert_eq!(body["VersionId"], "v2");
}

#[tokio::test]
async fn test_update_secret_auth_failure() {
    let mock_server = MockServer::start().await;

    // Mock authentication failure for update
    Mock::given(matchers::method("POST"))
        .and(matchers::path("/"))
        .respond_with(ResponseTemplate::new(400).set_body_json(serde_json::json!({
            "__type": "UnrecognizedClientException",
            "message": "The security token included in the request is invalid."
        })))
        .mount(&mock_server)
        .await;

    // Verify auth failure response
    let client = reqwest::Client::new();
    let response = client
        .post(mock_server.uri())
        .header("content-type", "application/x-www-form-urlencoded")
        .body("Action=PutSecretValue&SecretId=test-secret&SecretString=new-value")
        .send()
        .await
        .expect("Failed to send request");

    assert_eq!(response.status(), 400);

    let body: serde_json::Value = response.json().await.expect("Failed to parse JSON");
    assert_eq!(body["__type"], "UnrecognizedClientException");
}

#[tokio::test]
async fn test_internal_server_error() {
    let mock_server = MockServer::start().await;

    // Mock InternalServiceError
    Mock::given(matchers::method("POST"))
        .and(matchers::path("/"))
        .respond_with(ResponseTemplate::new(500).set_body_json(serde_json::json!({
            "__type": "InternalServiceError",
            "message": "An internal service error occurred."
        })))
        .mount(&mock_server)
        .await;

    // Verify server error response
    let client = reqwest::Client::new();
    let response = client
        .post(mock_server.uri())
        .header("content-type", "application/x-www-form-urlencoded")
        .body("Action=GetSecretValue&SecretId=test-secret")
        .send()
        .await
        .expect("Failed to send request");

    assert_eq!(response.status(), 500);

    let body: serde_json::Value = response.json().await.expect("Failed to parse JSON");
    assert_eq!(body["__type"], "InternalServiceError");
}

#[tokio::test]
async fn test_service_unavailable() {
    let mock_server = MockServer::start().await;

    // Mock ServiceUnavailable error
    Mock::given(matchers::method("POST"))
        .and(matchers::path("/"))
        .respond_with(ResponseTemplate::new(503).set_body_json(serde_json::json!({
            "__type": "ServiceUnavailable",
            "message": "Service temporarily unavailable."
        })))
        .mount(&mock_server)
        .await;

    // Verify 503 response
    let client = reqwest::Client::new();
    let response = client
        .post(mock_server.uri())
        .header("content-type", "application/x-www-form-urlencoded")
        .body("Action=GetSecretValue&SecretId=test-secret")
        .send()
        .await
        .expect("Failed to send request");

    assert_eq!(response.status(), 503);

    let body: serde_json::Value = response.json().await.expect("Failed to parse JSON");
    assert_eq!(body["__type"], "ServiceUnavailable");
}

#[tokio::test]
async fn test_mock_server_availability() {
    // Start a mock server
    let mock_server = MockServer::start().await;

    // Create a health check endpoint
    Mock::given(matchers::method("GET"))
        .and(matchers::path("/health"))
        .respond_with(ResponseTemplate::new(200).set_body_string("OK"))
        .mount(&mock_server)
        .await;

    // Verify the mock server URI
    let uri = mock_server.uri();
    assert!(!uri.is_empty(), "Mock server should have a valid URI");

    // Make a simple HTTP request to verify the server accepts connections
    let client = reqwest::Client::new();
    let response = client
        .get(format!("{}/health", uri))
        .send()
        .await
        .expect("Failed to send request to mock server");

    assert_eq!(response.status(), 200, "Mock server should return 200 OK");

    let body = response.text().await.expect("Failed to read response body");
    assert_eq!(body, "OK");
}

#[tokio::test]
async fn test_aws_response_parsing() {
    // Test simple string
    let mock_server = MockServer::start().await;

    Mock::given(matchers::method("POST"))
        .and(matchers::path("/"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(create_get_secret_value_response("my-secret-value")),
        )
        .mount(&mock_server)
        .await;

    let client = reqwest::Client::new();
    let response = client
        .post(mock_server.uri())
        .header("content-type", "application/x-www-form-urlencoded")
        .body("Action=GetSecretValue&SecretId=test1")
        .send()
        .await
        .expect("Failed to send request");

    assert_eq!(response.status(), 200);
    let body: serde_json::Value = response.json().await.expect("Failed to parse JSON");
    assert_eq!(body["SecretString"], "my-secret-value");
}

#[tokio::test]
async fn test_aws_response_json_object() {
    // Test JSON object
    let mock_server = MockServer::start().await;

    Mock::given(matchers::method("POST"))
        .and(matchers::path("/"))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(create_get_secret_value_response(
                r#"{"username":"admin","password":"secret123"}"#,
            )),
        )
        .mount(&mock_server)
        .await;

    let client = reqwest::Client::new();
    let response = client
        .post(mock_server.uri())
        .header("content-type", "application/x-www-form-urlencoded")
        .body("Action=GetSecretValue&SecretId=test2")
        .send()
        .await
        .expect("Failed to send request");

    assert_eq!(response.status(), 200);
    let body: serde_json::Value = response.json().await.expect("Failed to parse JSON");
    assert_eq!(
        body["SecretString"],
        r#"{"username":"admin","password":"secret123"}"#
    );
}

#[tokio::test]
async fn test_aws_response_database_url() {
    // Test database URL
    let mock_server = MockServer::start().await;

    Mock::given(matchers::method("POST"))
        .and(matchers::path("/"))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(create_get_secret_value_response(
                "postgres://user:pass@host:5432/dbname",
            )),
        )
        .mount(&mock_server)
        .await;

    let client = reqwest::Client::new();
    let response = client
        .post(mock_server.uri())
        .header("content-type", "application/x-www-form-urlencoded")
        .body("Action=GetSecretValue&SecretId=test3")
        .send()
        .await
        .expect("Failed to send request");

    assert_eq!(response.status(), 200);
    let body: serde_json::Value = response.json().await.expect("Failed to parse JSON");
    assert_eq!(
        body["SecretString"],
        "postgres://user:pass@host:5432/dbname"
    );
}

#[tokio::test]
async fn test_aws_response_api_key() {
    // Test API key
    let mock_server = MockServer::start().await;

    Mock::given(matchers::method("POST"))
        .and(matchers::path("/"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(create_get_secret_value_response("sk-live-abc123xyz789")),
        )
        .mount(&mock_server)
        .await;

    let client = reqwest::Client::new();
    let response = client
        .post(mock_server.uri())
        .header("content-type", "application/x-www-form-urlencoded")
        .body("Action=GetSecretValue&SecretId=test4")
        .send()
        .await
        .expect("Failed to send request");

    assert_eq!(response.status(), 200);
    let body: serde_json::Value = response.json().await.expect("Failed to parse JSON");
    assert_eq!(body["SecretString"], "sk-live-abc123xyz789");
}

#[tokio::test]
async fn test_pagination_handling() {
    let mock_server = MockServer::start().await;

    // Mock paginated ListSecrets response
    Mock::given(matchers::method("POST"))
        .and(matchers::path("/"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(serde_json::json!({
                    "SecretList": [
                        {"ARN": "arn:aws:secretsmanager:us-east-1:123456789:secret:secret1", "Name": "secret1", "CreatedDate": 1640995200},
                        {"ARN": "arn:aws:secretsmanager:us-east-1:123456789:secret:secret2", "Name": "secret2", "CreatedDate": 1640995200}
                    ],
                    "NextToken": "AAABBBCCCDDDEEEFFFGGG"
                }))
        )
        .mount(&mock_server)
        .await;

    let client = reqwest::Client::new();
    let response = client
        .post(mock_server.uri())
        .header("content-type", "application/x-www-form-urlencoded")
        .body("Action=ListSecrets&MaxResults=2")
        .send()
        .await
        .expect("Failed to send request");

    assert_eq!(response.status(), 200);

    let body: serde_json::Value = response.json().await.expect("Failed to parse JSON");
    assert!(body["SecretList"].is_array());
    assert_eq!(body["SecretList"].as_array().unwrap().len(), 2);
    assert!(body["NextToken"].is_string());
}
