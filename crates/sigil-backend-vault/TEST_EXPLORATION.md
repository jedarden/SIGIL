# Vault Backend Test Exploration

## Date: 2025-01-11

## Overview
This document summarizes the exploration of the `sigil-backend-vault` crate implementation and existing test infrastructure.

## Main Implementation: `crates/sigil-backend-vault/src/lib.rs`

### Architecture
- **VaultBackend** struct implements the `SecretBackend` trait
- Supports HashiCorp Vault and OpenBao (community fork)
- Uses KV v2 secrets engine
- HTTP client via `reqwest` with rustls TLS
- In-memory caching with configurable TTL (default: 5 minutes)
- Token stored in protected memory using `secrecy::SecretString`

### Authentication Methods Supported
1. **Token** - Direct token, env var (VAULT_TOKEN), or file (~/.vault-token)
2. **AppRole** - Role ID + Secret ID
3. **Kubernetes** - Service account JWT with role
4. **JWT** - For GitLab CI (CI_JOB_JWT_V2) or custom JWT providers

### Key Components

#### Path Handling
- Strips "vault/" prefix from incoming paths via `strip_prefix()`
- Routes to Vault KV v2: `/v1/{mount}/data/{path}`
- List operations use: `/v1/{mount}/metadata?list=true`

#### Caching
- `VaultCache` struct with `HashMap<String, CacheEntry>`
- Cache entries have: value, metadata, cached_at timestamp
- TTL-based expiration (check: `age.to_std().ok()? < ttl`)
- Invalidation on set/delete operations

#### Secret Type Detection
Heuristic-based detection from path:
- `ssh` or `private_key` → `SshKey`
- `api`, `token`, or `key` → `ApiKey`
- `cert` or `certificate` → `Certificate`
- `db`, `database`, `postgres`, `mysql` → `DatabaseUrl`
- Default → `Generic`

## SecretBackend Trait Methods (from `sigil-core/src/types.rs`)

All methods are async and return `Result<T>`:

1. **get** - Get secret value by path
2. **get_metadata** - Get secret metadata by path  
3. **set** - Set secret value with metadata
4. **delete** - Delete secret by path
5. **list** - List all secrets matching prefix
6. **backend_type** - Get backend identifier ("vault")

## Existing Test Infrastructure

### Test Files

#### 1. `tests/vault_backend_tests.rs` (60+ tests)
**Purpose**: Direct HTTP API interaction tests using mockito

**Coverage**:
- HTTP endpoint mocking (GET, POST, DELETE, LIST, PATCH)
- Vault KV v2 specific operations
- Error handling (404, 403, 500, 503)
- Authentication scenarios
- CAS (Check-and-Set) operations
- Namespace header support
- Health check endpoint
- Network timeout scenarios
- Cache behavior consistency

**Key Test Patterns**:
```rust
let mut server = Server::new_async().await;
let mock = server
    .mock("GET", "/v1/secret/data/mysecret")
    .with_status(200)
    .with_header("content-type", "application/json")
    .with_body(r#"{"data": {"data": {"value": "secret"}}}"#)
    .create_async()
    .await;
```

#### 2. `tests/vault_mock_tests.rs` (22 tests)  
**Purpose**: High-level backend behavior tests through SecretBackend trait

**Coverage**:
- SecretBackend trait method testing
- Success and failure cases for all operations
- Cache behavior (hit/miss/invalidation)
- Error type validation (SigilError variants)
- Complete workflow testing (get, set, delete, list)
- Prefix-based listing

**Key Test Patterns**:
```rust
let config = VaultBackendConfig { ... };
let backend = VaultBackend::new(config).await.unwrap();
let path = SecretPath::new("vault/secret").unwrap();
let result = backend.get(&path).await;
assert!(result.is_ok());
```

#### 3. Unit tests in `src/lib.rs` (lines 1079-1208)
**Purpose**: Basic type and logic tests

**Coverage**:
- Configuration defaults
- Secret type detection heuristics
- Path prefix stripping
- Cache operations (get/put/clear)
- Clone trait implementations for auth types

## Mockito Dependency

**Status**: ✅ Confirmed in `Cargo.toml`

```toml
[dev-dependencies]
mockito = "1.5"
```

## Vault HTTP API Structure

### Request Format

#### Headers
```
X-Vault-Token: s.{token}
X-Vault-Namespace: {namespace}  # Enterprise only
```

#### Endpoints

| Operation | Method | Path | Purpose |
|-----------|--------|------|---------|
| Get | GET | `/v1/{mount}/data/{path}` | Read secret value |
| Set | POST | `/v1/{mount}/data/{path}` | Write secret value |
| Delete | DELETE | `/v1/{mount}/metadata/{path}` | Delete secret |
| List | GET | `/v1/{mount}/metadata?list=true` | List secrets |
| Health | GET | `/v1/sys/health` | Check Vault status |

### Response Format (KV v2)

#### Get Response
```json
{
  "data": {
    "metadata": {
      "created_time": "2022-01-01T00:00:00Z",
      "updated_time": "2022-01-01T00:00:00Z",
      "version": 1,
      "deletion_time": "",
      "destroyed": false
    },
    "data": {
      "value": "secret-value",
      "username": "admin",
      "password": "pass123"
    }
  }
}
```

#### List Response
```json
{
  "data": {
    "keys": ["secret1", "secret2", "secret3"]
  }
}
```

#### Authentication Response (AppRole/Kubernetes/JWT)
```json
{
  "auth": {
    "client_token": "s.{token}"
  }
}
```

### Error Responses

| Status | Meaning | Example |
|--------|---------|---------|
| 200 | Success | Secret read/written successfully |
| 204 | No Content | Delete succeeded |
| 403 | Forbidden | Permission denied |
| 404 | Not Found | Secret doesn't exist |
| 500 | Internal Error | Vault server error |
| 503 | Service Unavailable | Vault sealed or standby |

## Test Helper Functions

### In `tests/vault_mock_tests.rs`:

```rust
fn create_test_config(server_url: &str) -> VaultBackendConfig {
    VaultBackendConfig {
        address: server_url.to_string(),
        auth: VaultAuth::Token { token: VaultToken::Direct("test-token".to_string()) },
        mount: "secret".to_string(),
        namespace: None,
        cache_ttl: Duration::from_secs(60),
        verify_tls: false,
    }
}

fn create_kv_v2_response(value: &str) -> serde_json::Value {
    serde_json::json!({
        "data": {
            "data": { "value": value },
            "metadata": {
                "created_time": "2024-01-01T00:00:00Z",
                "updated_time": "2024-01-01T00:00:00Z",
                "version": 1
            }
        }
    })
}

fn create_list_response(keys: Vec<&str>) -> serde_json::Value {
    serde_json::json!({
        "data": { "keys": keys }
    })
}
```

### In `tests/vault_backend_tests.rs` (backend_behavioral module):

```rust
async fn create_test_backend(server: &Server) -> VaultBackend {
    let config = VaultBackendConfig {
        address: server.url(),
        auth: VaultAuth::Token { token: VaultToken::Direct("test-token".to_string()) },
        mount: "secret".to_string(),
        namespace: None,
        cache_ttl: Duration::from_secs(0), // Disable cache for tests
        verify_tls: false,
    };
    VaultBackend::new(config).await.expect("Failed to create Vault backend")
}
```

## Test Coverage Summary

### Currently Tested

✅ **SecretBackend Trait Methods**:
- get() - success, not_found, unauthorized, server_error
- set() - success, unauthorized
- delete() - success, not_found (idempotent), unauthorized
- list() - success, empty, prefix, unauthorized
- get_metadata() - success
- backend_type() - returns "vault"

✅ **HTTP Layer**:
- All Vault KV v2 endpoints
- Headers (X-Vault-Token, X-Vault-Namespace)
- Status codes (200, 204, 403, 404, 500, 503)
- Request/response parsing

✅ **Caching**:
- Cache hit/miss behavior
- Cache invalidation on set/delete
- Cache disabled for tests (TTL = 0)

✅ **Authentication** (HTTP layer only):
- Token auth success/failure
- AppRole, Kubernetes, JWT endpoints mocked

✅ **Vault-Specific Features**:
- KV v2 data structure
- CAS (Check-and-Set) operations
- List operations with ?list=true
- Metadata patch operations
- Health check endpoint

### NOT Currently Tested (Opportunities)

❌ **Authentication Flows**:
- No integration tests for AppRole authentication
- No integration tests for Kubernetes authentication  
- No integration tests for JWT authentication
- Token file reading (~/.vault-token)
- Environment variable fallbacks

❌ **Cache Behavior Details**:
- Cache TTL expiration (only basic hit/miss tested)
- Cache entry aging
- Cache with non-zero TTL in real backend

❌ **Error Recovery**:
- Network retry logic (if added)
- Token refresh/rotation
- Standby node redirect handling (307)

❌ **Edge Cases**:
- Very long secret values
- Binary secret data
- Special characters in paths
- Empty secret values
- Unicode in secret values

❌ **Concurrency**:
- Concurrent get operations
- Cache thread safety
- Token refresh during concurrent operations

## Recommendations

### 1. Test Organization is Excellent
- Clear separation: HTTP layer tests vs. backend behavior tests
- Good helper functions for common patterns
- Comprehensive coverage of Vault KV v2 API

### 2. Existing Tests are Robust
- 80+ tests covering main functionality
- Both success and failure cases
- Mock-based (no real Vault required)
- Fast and deterministic

### 3. Potential Improvements

#### High Priority
- Add integration tests for authentication flows (AppRole, Kubernetes, JWT)
- Add cache TTL expiration tests
- Add concurrent access tests
- Add edge case tests (empty values, binary data, special characters)

#### Medium Priority  
- Add network retry tests
- Add token refresh tests
- Add standby redirect tests
- Add performance benchmarks

#### Low Priority
- Add stress tests (many concurrent operations)
- Add fuzzing for path validation
- Add real Vault integration tests (optional, in CI)

### 4. Test Utility Improvements

Consider adding:
```rust
// Helper to create a complete backend with all auth methods
async fn create_backend_with_auth(auth: VaultAuth, server: &Server) -> VaultBackend {
    VaultBackend::new(VaultBackendConfig {
        address: server.url(),
        auth,
        ..Default::default()
    }).await.unwrap()
}

// Helper for common secret data
fn test_secret_data() -> (SecretValue, SecretMetadata) {
    let value = SecretValue::new(b"test-value".to_vec());
    let metadata = SecretMetadata {
        path: SecretPath::new("test/path").unwrap(),
        secret_type: SecretType::Generic,
        tags: vec!["test".to_string()],
        notes: Some("Test note".to_string()),
        created_at: chrono::Utc::now(),
        updated_at: chrono::Utc::now(),
        expires_at: None,
    };
    (value, metadata)
}
```

## Conclusion

The Vault backend has a **solid test foundation** with 80+ tests covering the main functionality through mockito. The implementation is well-structured with proper separation of concerns (HTTP layer, caching, authentication).

The testing strategy is **comprehensive for the current implementation** but could be enhanced with:
1. Authentication flow integration tests
2. Cache TTL and concurrency tests  
3. Edge case and error recovery tests
4. Optional real Vault integration tests

The existing test infrastructure provides a **good template for other backend implementations** (AWS, 1Password, pass, SOPS, env).
