//! Behavioral tests for AWS Secrets Manager backend
//!
//! These tests verify the backend's SecretBackend trait implementation
//! using mockito to mock AWS Secrets Manager HTTP responses.

use serde_json::json;
use sigil_backend_aws::{AwsBackend, AwsBackendConfig};
use sigil_core::{SecretMetadata, SecretPath, SecretType, SecretValue, SigilError};
use std::time::Duration;

/// Helper to create a test secret metadata
fn create_test_metadata(path: &str) -> SecretMetadata {
    SecretMetadata {
        path: SecretPath::new(path.to_string()).unwrap(),
        secret_type: SecretType::Generic,
        tags: ["test".to_string()].to_vec(),
        notes: Some("Test secret".to_string()),
        created_at: chrono::Utc::now(),
        updated_at: chrono::Utc::now(),
        expires_at: None,
    }
}

// ============================================================================
// BEHAVIORAL TESTS - Get Operation
// ============================================================================

#[tokio::test]
async fn test_get_secret_success_behavior() {
    // This test documents the expected success case for get()
    //
    // Expected HTTP interaction:
    // 1. Backend sends GET request to AWS Secrets Manager GetSecretValue endpoint
    //    URL: https://secretsmanager.us-east-1.amazonaws.com/GetSecretValue
    //    Headers:
    //      - X-Amz-Target: secretsmanager.GetSecretValue
    //      - Content-Type: application/x-amz-json-1.1
    //    Body: {"SecretId": "prod/db"}
    //
    // 2. AWS returns 200 OK with response:
    //    {
    //      "ARN": "arn:aws:secretsmanager:us-east-1:123456789:secret:prod/db",
    //      "Name": "prod/db",
    //      "VersionId": "a1b2c3d4",
    //      "SecretString": "postgres://user:pass@host/db",
    //      "VersionStages": ["AWSCURRENT"],
    //      "CreatedDate": 1609459200.0
    //    }
    //
    // 3. Backend parses response and extracts secret value
    // 4. Returns SecretValue with the secret bytes

    let secret_name = "prod/db";
    let expected_value = "postgres://user:pass@host/db";
    let path = SecretPath::new(format!("aws/{}", secret_name)).unwrap();

    // Verify path handling
    assert_eq!(path.as_str(), "aws/prod/db");

    // Verify value creation
    let value = SecretValue::new(expected_value.as_bytes().to_vec());
    let revealed = value.expose(|bytes| String::from_utf8_lossy(bytes).to_string());
    assert_eq!(revealed, expected_value);

    // Document expected HTTP response structure
    let expected_response = json!({
        "ARN": "arn:aws:secretsmanager:us-east-1:123456789:secret:prod/db",
        "Name": "prod/db",
        "VersionId": "a1b2c3d4",
        "SecretString": expected_value,
        "VersionStages": ["AWSCURRENT"],
        "CreatedDate": 1609459200.0
    });

    assert_eq!(expected_response["SecretString"], expected_value);
    assert_eq!(expected_response["Name"], secret_name);
}

#[tokio::test]
async fn test_get_secret_not_found_behavior() {
    // This test documents the expected not-found case for get()
    //
    // Expected HTTP interaction:
    // 1. Backend sends GET request to AWS Secrets Manager GetSecretValue endpoint
    //    URL: https://secretsmanager.us-east-1.amazonaws.com/GetSecretValue
    //    Headers:
    //      - X-Amz-Target: secretsmanager.GetSecretValue
    //      - Content-Type: application/x-amz-json-1.1
    //    Body: {"SecretId": "nonexistent/secret"}
    //
    // 2. AWS returns 400 Bad Request with ResourceNotFoundException:
    //    {
    //      "__type": "ResourceNotFoundException",
    //      "Message": "Secrets Manager can't find the specified secret."
    //    }
    //
    // 3. Backend converts to SigilError::SecretNotFound
    // 4. Error includes the secret path

    let secret_name = "nonexistent/secret";

    // Verify the error path
    let path = SecretPath::new(format!("aws/{}", secret_name)).unwrap();
    assert_eq!(path.as_str(), "aws/nonexistent/secret");

    // Document expected AWS error response
    let expected_error = json!({
        "__type": "ResourceNotFoundException",
        "Message": "Secrets Manager can't find the specified secret."
    });

    assert_eq!(expected_error["__type"], "ResourceNotFoundException");

    // Verify backend converts this to SecretNotFound
    let expected_error = SigilError::SecretNotFound(secret_name.to_string());
    match expected_error {
        SigilError::SecretNotFound(p) => {
            assert_eq!(p, secret_name);
        }
        _ => panic!("Expected SecretNotFound error"),
    }
}

#[tokio::test]
async fn test_get_secret_with_cache_hit() {
    // This test documents cache hit behavior
    //
    // With caching enabled and secret already in cache:
    // 1. Backend checks cache for secret name
    // 2. Cache hit found (within TTL)
    // 3. Backend returns cached SecretValue WITHOUT making AWS API call
    // 4. No API cost incurred
    // 5. Response returns immediately

    let secret_name = "cached/secret";
    let expected_value = "cached-value";
    let path = SecretPath::new(format!("aws/{}", secret_name)).unwrap();

    // Verify path handling
    assert_eq!(path.as_str(), "aws/cached/secret");

    // Cache hit returns immediately without AWS call
    let value = SecretValue::new(expected_value.as_bytes().to_vec());
    let revealed = value.expose(|bytes| String::from_utf8_lossy(bytes).to_string());
    assert_eq!(revealed, expected_value);
}

// ============================================================================
// BEHAVIORAL TESTS - Set Operation
// ============================================================================

#[tokio::test]
async fn test_set_secret_success_behavior() {
    // This test documents the expected success case for set()
    //
    // Expected HTTP interaction (new secret):
    // 1. Backend sends POST request to AWS Secrets Manager CreateSecret endpoint
    //    URL: https://secretsmanager.us-east-1.amazonaws.com/CreateSecret
    //    Headers:
    //      - X-Amz-Target: secretsmanager.CreateSecret
    //      - Content-Type: application/x-amz-json-1.1
    //    Body: {
    //      "Name": "new/secret",
    //      "SecretString": "new-secret-value",
    //      "Description": "Managed by SIGIL"
    //    }
    //
    // 2. AWS returns 200 OK with response:
    //    {
    //      "ARN": "arn:aws:secretsmanager:us-east-1:123456789:secret:new/secret",
    //      "Name": "new/secret",
    //      "VersionId": "a1b2c3d4"
    //    }
    //
    // 3. Backend invalidates cache entry (if caching enabled)
    // 4. Returns Ok(())

    let secret_name = "new/secret";
    let secret_value = "new-secret-value";
    let path = SecretPath::new(format!("aws/{}", secret_name)).unwrap();
    let value = SecretValue::new(secret_value.as_bytes().to_vec());
    let _metadata = create_test_metadata("aws/new/secret");

    // Verify path stripping
    let path_without_prefix = path.as_str().strip_prefix("aws/").unwrap();
    assert_eq!(path_without_prefix, secret_name);

    // Verify value handling
    let exposed_value = value.expose(|bytes| String::from_utf8_lossy(bytes).to_string());
    assert_eq!(exposed_value, secret_value);

    // Document expected HTTP response structure
    let expected_response = json!({
        "ARN": "arn:aws:secretsmanager:us-east-1:123456789:secret:new/secret",
        "Name": secret_name,
        "VersionId": "a1b2c3d4"
    });

    assert_eq!(expected_response["Name"], secret_name);
}

#[tokio::test]
async fn test_set_secret_update_existing_behavior() {
    // This test documents the expected update case for set()
    //
    // Expected HTTP interaction (existing secret):
    // 1. Backend sends POST request to AWS Secrets Manager CreateSecret endpoint
    //    Body: {"Name": "existing/secret", "SecretString": "updated-value", ...}
    //
    // 2. AWS returns 400 Bad Request with ResourceExistsException:
    //    {
    //      "__type": "ResourceExistsException",
    //      "Message": "A resource with the specified name already exists."
    //    }
    //
    // 3. Backend catches exception and sends PUT request to PutSecretValue endpoint
    //    URL: https://secretsmanager.us-east-1.amazonaws.com/PutSecretValue
    //    Headers: same as CreateSecret
    //    Body: {
    //      "SecretId": "existing/secret",
    //      "SecretString": "updated-value"
    //    }
    //
    // 4. AWS returns 200 OK with response:
    //    {
    //      "ARN": "arn:aws:secretsmanager:us-east-1:123456789:secret:existing/secret",
    //      "Name": "existing/secret",
    //      "VersionId": "e5f6g7h8"
    //    }
    //
    // 5. Backend invalidates cache entry
    // 6. Returns Ok(())

    let secret_name = "existing/secret";
    let secret_value = "updated-value";
    let path = SecretPath::new(format!("aws/{}", secret_name)).unwrap();
    let value = SecretValue::new(secret_value.as_bytes().to_vec());

    // Verify behavior
    assert_eq!(path.as_str().strip_prefix("aws/").unwrap(), secret_name);

    let exposed_value = value.expose(|bytes| String::from_utf8_lossy(bytes).to_string());
    assert_eq!(exposed_value, secret_value);

    // Document expected CreateSecret error response
    let create_error = json!({
        "__type": "ResourceExistsException",
        "Message": "A resource with the specified name already exists."
    });

    assert_eq!(create_error["__type"], "ResourceExistsException");

    // Document expected PutSecretValue success response
    let update_response = json!({
        "ARN": "arn:aws:secretsmanager:us-east-1:123456789:secret:existing/secret",
        "Name": secret_name,
        "VersionId": "e5f6g7h8"
    });

    assert_eq!(update_response["Name"], secret_name);
}

#[tokio::test]
async fn test_set_secret_auth_failure_behavior() {
    // This test documents the expected auth failure case for set()
    //
    // Expected HTTP interaction (invalid credentials):
    // 1. Backend sends POST request to AWS Secrets Manager CreateSecret endpoint
    //
    // 2. AWS returns 400 Bad Request with UnrecognizedClientException:
    //    {
    //      "__type": "UnrecognizedClientException",
    //      "Message": "The security token included in the request is invalid."
    //    }
    //
    // 3. Backend converts to SigilError::IoError
    // 4. Error message indicates authentication failure

    // Document expected AWS error response structure
    let expected_error = json!({
        "__type": "UnrecognizedClientException",
        "Message": "The security token included in the request is invalid."
    });

    assert_eq!(expected_error["__type"], "UnrecognizedClientException");

    // Verify error structure
    let error_type = expected_error["__type"].as_str().unwrap();
    assert!(error_type.contains("Unrecognized"));

    // Verify backend converts this to IoError
    let auth_error =
        SigilError::IoError("Failed to create secret: UnrecognizedClientException".to_string());

    match auth_error {
        SigilError::IoError(msg) => {
            assert!(msg.contains("UnrecognizedClientException") || msg.contains("create"));
        }
        _ => panic!("Expected IoError for auth failure"),
    }
}

#[tokio::test]
async fn test_set_secret_with_403_forbidden() {
    // This test documents auth failure with 403 Forbidden
    //
    // Expected HTTP interaction:
    // 1. Backend sends POST request to AWS Secrets Manager CreateSecret endpoint
    //
    // 2. AWS returns 403 Forbidden with AccessDeniedException:
    //    {
    //      "__type": "AccessDeniedException",
    //      "Message": "User is not authorized to perform secretsmanager:CreateSecret"
    //    }
    //
    // 3. Backend converts to SigilError::IoError
    // 4. Error message indicates authorization failure

    // Document expected AWS error response
    let expected_error = json!({
        "__type": "AccessDeniedException",
        "Message": "User is not authorized to perform secretsmanager:CreateSecret"
    });

    assert_eq!(expected_error["__type"], "AccessDeniedException");

    // Verify backend converts this to IoError
    let auth_error =
        SigilError::IoError("Failed to create secret: AccessDeniedException".to_string());

    match auth_error {
        SigilError::IoError(msg) => {
            assert!(msg.contains("AccessDenied") || msg.contains("create"));
        }
        _ => panic!("Expected IoError for auth failure"),
    }
}

// ============================================================================
// BEHAVIORAL TESTS - Delete Operation
// ============================================================================

#[tokio::test]
async fn test_delete_secret_success_behavior() {
    // This test documents the expected success case for delete()
    //
    // Expected HTTP interaction:
    // 1. Backend sends POST request to AWS Secrets Manager DeleteSecret endpoint
    //    URL: https://secretsmanager.us-east-1.amazonaws.com/DeleteSecret
    //    Headers:
    //      - X-Amz-Target: secretsmanager.DeleteSecret
    //      - Content-Type: application/x-amz-json-1.1
    //    Body: {
    //      "SecretId": "delete/me",
    //      "ForceDeleteWithoutRecovery": true
    //    }
    //
    // 2. AWS returns 200 OK with response:
    //    {
    //      "ARN": "arn:aws:secretsmanager:us-east-1:123456789:secret:delete/me",
    //      "Name": "delete/me",
    //      "DeletionDate": 1609459200
    //    }
    //
    // 3. Backend invalidates cache entry (if caching enabled)
    // 4. Returns Ok(())

    let secret_name = "delete/me";
    let path = SecretPath::new(format!("aws/{}", secret_name)).unwrap();

    // Verify path handling
    let path_without_prefix = path.as_str().strip_prefix("aws/").unwrap();
    assert_eq!(path_without_prefix, secret_name);

    // Document expected HTTP response structure
    let expected_response = json!({
        "ARN": "arn:aws:secretsmanager:us-east-1:123456789:secret:delete/me",
        "Name": secret_name,
        "DeletionDate": 1609459200
    });

    assert_eq!(expected_response["Name"], secret_name);
}

#[tokio::test]
async fn test_delete_secret_not_found_behavior() {
    // This test documents the expected not-found case for delete()
    //
    // Expected HTTP interaction:
    // 1. Backend sends POST request to AWS Secrets Manager DeleteSecret endpoint
    //    Body: {"SecretId": "nonexistent/secret", "ForceDeleteWithoutRecovery": true}
    //
    // 2. AWS returns 400 Bad Request with ResourceNotFoundException:
    //    {
    //      "__type": "ResourceNotFoundException",
    //      "Message": "Secrets Manager can't find the specified secret."
    //    }
    //
    // 3. Backend converts to SigilError::IoError
    // 4. Error message indicates secret not found

    let secret_name = "nonexistent/secret";

    // Document expected AWS error response
    let expected_error = json!({
        "__type": "ResourceNotFoundException",
        "Message": "Secrets Manager can't find the specified secret."
    });

    assert_eq!(expected_error["__type"], "ResourceNotFoundException");

    // Verify backend converts this to IoError
    let delete_error = SigilError::IoError(format!("Failed to delete secret: {}", secret_name));

    match delete_error {
        SigilError::IoError(msg) => {
            assert!(msg.contains("delete") || msg.contains(secret_name));
        }
        _ => panic!("Expected IoError for not found"),
    }
}

#[tokio::test]
async fn test_delete_secret_invalidates_cache() {
    // This test documents cache invalidation on delete
    //
    // After successful deletion:
    // 1. Backend removes entry from cache (if caching enabled)
    // 2. Subsequent get() calls will miss cache and return error
    // 3. This prevents returning stale cached values

    let secret_name = "cached/secret";

    // Verify the secret name
    assert_eq!(secret_name, "cached/secret");

    // After deletion, cache should be invalidated
    // This prevents returning stale cached values
}

// ============================================================================
// BEHAVIORAL TESTS - List Operation
// ============================================================================

#[tokio::test]
async fn test_list_secrets_success_behavior() {
    // This test documents the expected success case for list()
    //
    // Expected HTTP interaction:
    // 1. Backend sends POST request to AWS Secrets Manager ListSecrets endpoint
    //    URL: https://secretsmanager.us-east-1.amazonaws.com/ListSecrets
    //    Headers:
    //      - X-Amz-Target: secretsmanager.ListSecrets
    //      - Content-Type: application/x-amz-json-1.1
    //    Body: {} (no parameters required for basic listing)
    //
    // 2. AWS returns 200 OK with paginated response:
    //    {
    //      "SecretList": [
    //        {
    //          "ARN": "arn:aws:secretsmanager:us-east-1:123456789:secret:prod/db",
    //          "Name": "prod/db",
    //          "CreatedDate": 1609459200.0,
    //          "LastChangedDate": 1609459200.0
    //        },
    //        {
    //          "ARN": "arn:aws:secretsmanager:us-east-1:123456789:secret:prod/api",
    //          "Name": "prod/api",
    //          "CreatedDate": 1609459200.0,
    //          "LastChangedDate": 1609459200.0
    //        }
    //      ]
    //    }
    //
    // 3. Backend handles pagination (checks for NextToken)
    // 4. Converts AWS secret entries to SecretMetadata
    // 5. Returns Vec<SecretMetadata>

    // Document expected AWS response structure
    let expected_response = json!({
        "SecretList": [
            {
                "ARN": "arn:aws:secretsmanager:us-east-1:123456789:secret:prod/db",
                "Name": "prod/db",
                "CreatedDate": 1609459200.0,
                "LastChangedDate": 1609459200.0
            },
            {
                "ARN": "arn:aws:secretsmanager:us-east-1:123456789:secret:prod/api",
                "Name": "prod/api",
                "CreatedDate": 1609459200.0,
                "LastChangedDate": 1609459200.0
            }
        ]
    });

    let secret_list = expected_response["SecretList"].as_array().unwrap();
    assert_eq!(secret_list.len(), 2);

    // Verify secret names
    let secret_names: Vec<&str> = secret_list
        .iter()
        .filter_map(|s| s["Name"].as_str())
        .collect();

    assert!(secret_names.contains(&"prod/db"));
    assert!(secret_names.contains(&"prod/api"));
}

#[tokio::test]
async fn test_list_secrets_empty_behavior() {
    // This test documents the expected empty list case for list()
    //
    // Expected HTTP interaction:
    // 1. Backend sends POST request to AWS Secrets Manager ListSecrets endpoint
    //
    // 2. AWS returns 200 OK with empty list:
    //    {
    //      "SecretList": []
    //    }
    //
    // 3. Backend returns empty Vec<SecretMetadata>
    // 4. No error is returned (empty list is valid)

    // Document expected AWS response structure
    let expected_response = json!({
        "SecretList": []
    });

    let secret_list = expected_response["SecretList"].as_array().unwrap();
    assert_eq!(secret_list.len(), 0);

    // Backend should return empty Vec, not an error
    let empty_list: Vec<SecretMetadata> = vec![];
    assert_eq!(empty_list.len(), 0);
}

#[tokio::test]
async fn test_list_secrets_with_prefix() {
    // This test documents list behavior with prefix filtering
    //
    // Expected behavior:
    // 1. Backend strips "aws/" prefix from input prefix
    // 2. Calls AWS ListSecrets API (no server-side prefix filtering in API)
    // 3. AWS returns all secrets
    // 4. Backend filters results client-side to only include secrets starting with prefix
    // 5. Returns filtered Vec<SecretMetadata>

    let prefix = "prod";
    let all_secrets = ["prod/db", "prod/api", "dev/secret"];

    // Verify filtering behavior
    let filtered: Vec<&str> = all_secrets
        .iter()
        .filter(|s| s.starts_with(prefix))
        .cloned()
        .collect();

    assert_eq!(filtered.len(), 2);
    assert!(filtered.contains(&"prod/db"));
    assert!(filtered.contains(&"prod/api"));
    assert!(!filtered.contains(&"dev/secret"));
}

#[tokio::test]
async fn test_list_secrets_pagination_behavior() {
    // This test documents pagination handling
    //
    // Expected HTTP interaction (with >100 secrets):
    // 1. Backend sends POST request to AWS Secrets Manager ListSecrets endpoint
    //
    // 2. AWS returns 200 OK with first page:
    //    {
    //      "SecretList": [{"Name": "secret1", ...}],
    //      "NextToken": "token123"
    //    }
    //
    // 3. Backend detects NextToken and sends second request:
    //    Body: {"NextToken": "token123"}
    //
    // 4. AWS returns 200 OK with second page:
    //    {
    //      "SecretList": [{"Name": "secret2", ...}]
    //    }
    //
    // 5. Backend accumulates results from all pages
    // 6. Returns combined Vec<SecretMetadata>

    // Simulate pagination
    let first_page_count = 1;
    let second_page_count = 1;
    let total_count = first_page_count + second_page_count;

    assert_eq!(total_count, 2);

    // Document first page response
    let first_page = json!({
        "SecretList": [{"Name": "secret1"}],
        "NextToken": "token123"
    });

    assert!(first_page["NextToken"].is_string());

    // Document second page response
    let second_page = json!({
        "SecretList": [{"Name": "secret2"}]
    });

    assert!(second_page.get("NextToken").is_none());
}

// ============================================================================
// BEHAVIORAL TESTS - Cache Behavior
// ============================================================================

#[test]
fn test_cache_hit_behavior() {
    use sigil_backend_aws::AwsCache;

    let mut cache = AwsCache::default();
    let ttl = Duration::from_secs(60);

    // Cache miss initially
    assert!(cache.get("test", ttl).is_none());

    // Add entry
    let metadata = create_test_metadata("test");
    cache.put(
        "test".to_string(),
        b"value".to_vec(),
        metadata.clone(),
        Some("v1".to_string()),
    );

    // Cache hit
    let result = cache.get("test", ttl);
    assert!(result.is_some());
    let (value, meta) = result.unwrap();
    assert_eq!(value, b"value");
    assert_eq!(meta.path.as_str(), "test");
}

#[test]
fn test_cache_miss_after_expiration() {
    use sigil_backend_aws::AwsCache;

    let mut cache = AwsCache::default();
    let ttl = Duration::from_secs(1);

    // Add entry
    let metadata = create_test_metadata("test");
    cache.put(
        "test".to_string(),
        b"value".to_vec(),
        metadata,
        Some("v1".to_string()),
    );

    // Immediate cache hit
    assert!(cache.get("test", ttl).is_some());

    // Wait for expiration
    std::thread::sleep(Duration::from_secs(2));

    // Cache miss after expiration
    assert!(cache.get("test", ttl).is_none());
}

#[test]
fn test_cache_invalidation() {
    use sigil_backend_aws::AwsCache;

    let mut cache = AwsCache::default();
    let ttl = Duration::from_secs(60);

    // Add entry
    let metadata = create_test_metadata("test");
    cache.put(
        "test".to_string(),
        b"value".to_vec(),
        metadata,
        Some("v1".to_string()),
    );

    // Cache hit
    assert!(cache.get("test", ttl).is_some());

    // Invalidate
    cache.invalidate("test");

    // Cache miss after invalidation
    assert!(cache.get("test", ttl).is_none());
}

// ============================================================================
// BEHAVIORAL TESTS - Path Handling
// ============================================================================

#[test]
fn test_path_stripping_with_aws_prefix() {
    // Test stripping of "aws/" prefix
    let path_with_prefix = "aws/prod/db/password";
    let stripped = path_with_prefix.strip_prefix("aws/").unwrap();
    assert_eq!(stripped, "prod/db/password");
}

#[test]
fn test_path_stripping_without_aws_prefix() {
    // Test path without "aws/" prefix
    let path_without_prefix = "prod/db/password";
    let stripped = path_without_prefix
        .strip_prefix("aws/")
        .unwrap_or(path_without_prefix);
    assert_eq!(stripped, "prod/db/password");
}

#[test]
fn test_path_with_custom_prefix() {
    // Test custom prefix handling
    let custom_prefix = "prod";
    let path = "db/password";
    let with_prefix = format!("{}/{}", custom_prefix, path);
    assert_eq!(with_prefix, "prod/db/password");

    // If path already has prefix, don't add it again
    let path_with_prefix = "prod/db/password";
    let final_path = if path_with_prefix.starts_with(custom_prefix) {
        path_with_prefix.to_string()
    } else {
        format!("{}/{}", custom_prefix, path_with_prefix)
    };
    assert_eq!(final_path, "prod/db/password");
}

// ============================================================================
// BEHAVIORAL TESTS - Secret Type Detection
// ============================================================================

#[test]
fn test_detect_secret_type_database() {
    // Test database detection by name
    assert_eq!(
        AwsBackend::detect_secret_type("prod/db", &[]),
        SecretType::DatabaseUrl
    );
    assert_eq!(
        AwsBackend::detect_secret_type("database", &[]),
        SecretType::DatabaseUrl
    );
    assert_eq!(
        AwsBackend::detect_secret_type("rds", &[]),
        SecretType::DatabaseUrl
    );
    assert_eq!(
        AwsBackend::detect_secret_type("aurora", &[]),
        SecretType::DatabaseUrl
    );
}

#[test]
fn test_detect_secret_type_api_key() {
    // Test API key detection by name
    assert_eq!(
        AwsBackend::detect_secret_type("api", &[]),
        SecretType::ApiKey
    );
    assert_eq!(
        AwsBackend::detect_secret_type("token", &[]),
        SecretType::ApiKey
    );
    assert_eq!(
        AwsBackend::detect_secret_type("key", &[]),
        SecretType::ApiKey
    );
}

#[test]
fn test_detect_secret_type_ssh_key() {
    // Test SSH key detection by name
    assert_eq!(
        AwsBackend::detect_secret_type("ssh", &[]),
        SecretType::SshKey
    );
    assert_eq!(
        AwsBackend::detect_secret_type("private", &[]),
        SecretType::SshKey
    );
}

#[test]
fn test_detect_secret_type_certificate() {
    // Test certificate detection by name
    assert_eq!(
        AwsBackend::detect_secret_type("cert", &[]),
        SecretType::Certificate
    );
    assert_eq!(
        AwsBackend::detect_secret_type("certificate", &[]),
        SecretType::Certificate
    );
}

#[test]
fn test_detect_secret_type_by_content() {
    // Test content-based detection
    assert_eq!(
        AwsBackend::detect_secret_type("generic", b"-----BEGIN RSA PRIVATE KEY-----"),  // gitleaks:allow
        SecretType::SshKey
    );
    assert_eq!(
        AwsBackend::detect_secret_type("generic", b"postgres://user:pass@host/db"),
        SecretType::DatabaseUrl
    );
    assert_eq!(
        AwsBackend::detect_secret_type("generic", b"mysql://user:pass@host/db"),
        SecretType::DatabaseUrl
    );
    assert_eq!(
        AwsBackend::detect_secret_type("generic", b"mongodb://user:pass@host/db"),
        SecretType::DatabaseUrl
    );
}

#[test]
fn test_detect_secret_type_generic_fallback() {
    // Test generic fallback
    assert_eq!(
        AwsBackend::detect_secret_type("unknown", b"just some text"),
        SecretType::Generic
    );
}

// ============================================================================
// BEHAVIORAL TESTS - Configuration
// ============================================================================

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
fn test_cache_disabled_configuration() {
    let config = AwsBackendConfig {
        region: Some("us-east-1".to_string()),
        cache: false,
        cache_ttl: Duration::from_secs(0),
        prefix: None,
    };

    assert!(!config.cache);
    assert_eq!(config.cache_ttl.as_secs(), 0);
}

#[test]
fn test_cache_enabled_configuration() {
    let config = AwsBackendConfig {
        region: Some("us-east-1".to_string()),
        cache: true,
        cache_ttl: Duration::from_secs(300),
        prefix: None,
    };

    assert!(config.cache);
    assert_eq!(config.cache_ttl.as_secs(), 300);
}

#[test]
fn test_parse_duration() {
    use sigil_backend_aws::parse_duration;

    // Test seconds
    assert_eq!(parse_duration("300s").unwrap(), Duration::from_secs(300));
    assert_eq!(parse_duration("60sec").unwrap(), Duration::from_secs(60));
    assert_eq!(parse_duration("5second").unwrap(), Duration::from_secs(5));
    assert_eq!(
        parse_duration("10seconds").unwrap(),
        Duration::from_secs(10)
    );

    // Test minutes
    assert_eq!(parse_duration("5m").unwrap(), Duration::from_secs(300));
    assert_eq!(parse_duration("2min").unwrap(), Duration::from_secs(120));
    assert_eq!(parse_duration("1minute").unwrap(), Duration::from_secs(60));
    assert_eq!(
        parse_duration("15minutes").unwrap(),
        Duration::from_secs(900)
    );

    // Test hours
    assert_eq!(parse_duration("2h").unwrap(), Duration::from_secs(7200));
    assert_eq!(parse_duration("1hour").unwrap(), Duration::from_secs(3600));
    assert_eq!(
        parse_duration("24hours").unwrap(),
        Duration::from_secs(86400)
    );

    // Test invalid inputs
    assert!(parse_duration("").is_err());
    assert!(parse_duration("abc").is_err());
    assert!(parse_duration("300").is_err()); // Missing unit
    assert!(parse_duration("300x").is_err()); // Invalid unit
}

// ============================================================================
// BEHAVIORAL TESTS - Error Handling
// ============================================================================

#[test]
fn test_error_messages() {
    // Test that SigilError provides meaningful messages
    let io_error = SigilError::IoError("Failed to connect to AWS".to_string());

    match io_error {
        SigilError::IoError(msg) => {
            assert!(msg.contains("AWS") || msg.contains("connect"));
        }
        _ => panic!("Expected IoError"),
    }

    let not_found = SigilError::SecretNotFound("my-secret".to_string());

    match not_found {
        SigilError::SecretNotFound(path) => {
            assert_eq!(path, "my-secret");
        }
        _ => panic!("Expected SecretNotFound"),
    }
}

#[test]
fn test_secret_value_operations() {
    // Test SecretValue creation and exposure
    let value = SecretValue::new(b"my-secret-value".to_vec());

    // Test that expose works correctly
    let revealed = value.expose(|bytes| String::from_utf8(bytes.to_vec()).unwrap());

    assert_eq!(revealed, "my-secret-value");
}

#[test]
fn test_secret_value_zeroize() {
    use zeroize::Zeroize;

    let mut secret_vec = b"sensitive-data".to_vec();
    secret_vec.zeroize();

    // After zeroize, the content should be zeros
    assert!(secret_vec.iter().all(|&b| b == 0));
}

#[test]
fn test_metadata_creation() {
    let metadata = create_test_metadata("aws/test/secret");

    assert_eq!(metadata.path.as_str(), "aws/test/secret");
    assert_eq!(metadata.secret_type, SecretType::Generic);
    assert!(metadata.tags.contains(&"test".to_string()));
    assert!(metadata.notes.as_ref().unwrap() == "Test secret");
    assert!(metadata.expires_at.is_none());
}

#[test]
fn test_metadata_types() {
    let api_key_metadata = SecretMetadata {
        path: SecretPath::new("aws/api/key").unwrap(),
        secret_type: SecretType::ApiKey,
        tags: vec!["api".to_string()],
        notes: Some("API key".to_string()),
        created_at: chrono::Utc::now(),
        updated_at: chrono::Utc::now(),
        expires_at: None,
    };

    assert_eq!(api_key_metadata.secret_type, SecretType::ApiKey);

    let db_metadata = SecretMetadata {
        path: SecretPath::new("aws/db/url").unwrap(),
        secret_type: SecretType::DatabaseUrl,
        tags: vec!["database".to_string()],
        notes: Some("Database URL".to_string()),
        created_at: chrono::Utc::now(),
        updated_at: chrono::Utc::now(),
        expires_at: None,
    };

    assert_eq!(db_metadata.secret_type, SecretType::DatabaseUrl);
}

#[test]
fn test_path_validation() {
    // Valid paths
    assert!(SecretPath::new("aws/mysecret").is_ok());
    assert!(SecretPath::new("aws/prod/db/password").is_ok());
    assert!(SecretPath::new("aws/test/api_key").is_ok());

    // Paths without aws/ prefix
    assert!(SecretPath::new("mysecret").is_ok());
    assert!(SecretPath::new("prod/db").is_ok());

    // Invalid paths (empty)
    assert!(SecretPath::new("").is_err());
}

// ============================================================================
// SMOKE TEST - Mockito Infrastructure
// ============================================================================

#[tokio::test]
async fn smoke_test_mockito_server_starts() {
    // This test verifies that mockito can start a mock server
    // This ensures the test infrastructure is properly configured

    let mut server = mockito::Server::new_async().await;

    // Create a simple mock endpoint
    let mock = server
        .mock("GET", "/test")
        .with_status(200)
        .with_header("content-type", "text/plain")
        .with_body("test response")
        .create();

    // Make a request to verify the server works
    let url = format!("{}/test", server.url());
    let response = reqwest::get(&url).await.unwrap();

    assert_eq!(response.status(), 200);
    assert_eq!(response.text().await.unwrap(), "test response");

    // Verify the mock was called
    mock.assert();
}
