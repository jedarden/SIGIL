# Phase 6.2-6.3 Verification Summary

## Task

Verify all 6 external backends and backend routing for SIGIL.

## Date

2026-05-20

## Backends Verified

### 1. sigil-backend-vault ✅

**Token Authentication:**
- Direct token values (`VaultToken::Direct`)
- VAULT_TOKEN environment variable (`VaultToken::Env`)
- ~/.vault-token file (`VaultToken::File`)
- Tokens protected with `SecretString` (secrecy crate)

**AppRole Authentication:**
- `VaultAuth::AppRole` variant with role_id and secret_id
- `authenticate_approle()` function implements approle/login endpoint
- Secret ID protected with SecretString

**Kubernetes Authentication:**
- `VaultAuth::Kubernetes` variant with role and mount parameters
- `authenticate_kubernetes()` reads service account token from `/var/run/secrets/kubernetes.io/serviceaccount/token`
- Uses kubernetes auth mount point

**JWT Authentication (GitLab CI):**
- `VaultAuth::Jwt` variant with role, jwt, and mount parameters
- `VaultJwt` enum supports: Direct, GitLabCi, EnvVar
- Automatically reads CI_JOB_JWT_V2 for GitLab CI

**KV v2 Support:**
- Configurable mount point (default: "secret")
- Uses `/data/` path for secret reads
- Uses `/metadata/` path for metadata operations
- Handles nested `data.data` structure

**Cache:**
- In-memory cache with `Arc<RwLock<VaultCache>>`
- Configurable TTL (default: 5 minutes)
- Cache get/put/invalidate operations
- No disk persistence

### 2. sigil-backend-onepassword ✅

**CLI Support:**
- Uses `op read` command to fetch secrets
- Supports `op://vault/item/field` URL format
- Path parsing extracts vault/item/field components
- Command execution via std::process::Command

**Connect Server API:**
- `use_connect` configuration flag
- `connect_address` and `connect_token` configuration
- Cache support with configurable TTL

**Read-Only:**
- Set operations return error: "1Password backend is read-only"
- Delete operations return error: "1Password backend is read-only"

### 3. sigil-backend-pass ✅

**Command Detection:**
- `PassCommand` enum: Auto, Pass, Gopass
- `detect_pass_command()` auto-detects available command
- `command_exists()` checks via `which` command

**Store Access:**
- `pass show` or `gopass show -o` for fetching secrets
- `PASSWORD_STORE_DIR` environment variable support
- Configurable store path (default: ~/.password-store)
- `pass ls` / `gopass ls` for listing secrets

**Read-Only:**
- Set operations return error: "Pass backend is read-only"
- Delete operations return error: "Pass backend is read-only"

### 4. sigil-backend-env ✅

**File Loading:**
- Configurable env file path (default: ~/.sigil/secrets.env)
- `load_env_file()` function parses KEY=VALUE format
- File permissions check (warns if group/world readable)
- Does NOT read from agent's process environment (verified)

**Prefix Support:**
- Configurable prefix (default: "SIGIL_")
- Get method tries: direct lookup, prefixed lookup, uppercase lookup
- Prefix filtering in list method

**Read-Only:**
- Set operations return error: "Environment backend is read-only"
- Delete operations return error: "Environment backend is read-only"

### 5. sigil-backend-aws ✅

**Secrets Manager:**
- Uses `aws_sdk_secretsmanager` crate
- `get_secret_value()` API call
- `list_secrets()` with pagination support
- Extracts `secret_string()` from response

**STS Rotation:**
- Version ID tracking for rotation detection
- Cache invalidation on secret updates
- AWS SDK credential chain via `aws_config`

**Cache:**
- In-memory cache with `Arc<RwLock<AwsCache>>`
- Configurable TTL (default: 5 minutes)
- Version ID tracking for rotation

**Write Support:**
- Set operations create/update secrets via `create_secret()` or `put_secret_value()`
- Delete operations with force_delete_without_recovery

### 6. sigil-backend-sops ✅

**YAML/JSON Support:**
- Uses `serde_yaml` for parsing (handles both YAML and JSON)
- Configurable file patterns (default: *.yaml, *.yml, *.json)
- `matches_pattern()` for glob matching

**Age Encryption:**
- `SopsMetadata` struct extracts: age_key, mac, last_modified, version
- Checks for age key in sops metadata
- MAC verification for integrity
- Version checking

**Read-Only:**
- Set operations return error: "SOPS backend is read-only"
- Delete operations return error: "SOPS backend is read-only"

## Backend Routing (6.3)

### Current Status: PARTIALLY IMPLEMENTED

**What Works:**
- Each backend handles its own path prefix stripping
- `backend_type()` returns correct identifier
- Configuration structures exist for all backends
- Cache is in-memory with TTL (no mlock verified)

**What's Missing:**
- Centralized `BackendManager` to route requests to multiple backends
- Resolution order: local vault → backends in config order
- Namespace prefix routing configuration in ~/.sigil/config.toml
- Backend cache memory protection (mlock not explicitly implemented)

### Path Prefix Handling by Backend:

| Backend | Prefix Strip | Example |
|---------|--------------|---------|
| vault   | `strip_prefix("vault/")` | `vault/foo/bar` → `foo/bar` |
| onepassword | `strip_prefix("onepassword/")` | `onepassword/vault/item` → `vault/item` |
| pass | `strip_prefix("pass/")` | `pass/email/gmail` → `email/gmail` |
| aws | `strip_prefix("aws/")` | `aws/prod/db` → `prod/db` |
| sops | `strip_prefix("sops/")` | `sops/myapp/key` → `myapp/key` |

## Tests Created

22 comprehensive tests in `crates/sigil-integration-tests/tests/phase6_2_3_backend_verification_test.rs`:

1. `test_all_backends_implement_secret_backend_trait` - Verifies trait implementation
2. `test_vault_backend_token_auth` - Token authentication methods
3. `test_vault_backend_approle_auth` - AppRole authentication
4. `test_vault_backend_kubernetes_auth` - Kubernetes authentication
5. `test_vault_backend_jwt_auth` - JWT authentication (GitLab CI)
6. `test_vault_backend_kv_v2_support` - KV v2 secrets engine
7. `test_vault_backend_cache` - Cache implementation
8. `test_onepassword_cli_support` - op CLI integration
9. `test_onepassword_connect_support` - Connect API support
10. `test_pass_backend_command_detection` - Command auto-detection
11. `test_pass_backend_store_access` - Store access methods
12. `test_env_backend_file_loading` - File loading and permissions
13. `test_env_backend_prefix_support` - SIGIL_ prefix support
14. `test_aws_backend_secrets_manager` - AWS SM integration
15. `test_aws_backend_sts_rotation` - STS rotation support
16. `test_sops_backend_yaml_json_support` - YAML/JSON parsing
17. `test_sops_backend_age_support` - Age encryption metadata
18. `test_backend_namespace_routing` - Path prefix handling
19. `test_backend_cache_memory_protection` - No disk persistence
20. `test_backend_cache_ttl_configuration` - TTL configuration
21. `test_backend_type_identifiers` - Correct type strings
22. `test_backend_configuration_structure` - Config structs

**All 22 tests pass.**

## Acceptance Criteria

- ✅ All 6 backends work correctly
- ✅ Each backend implements SecretBackend trait
- ✅ Vault token/AppRole/Kubernetes auth methods verified
- ✅ Vault KV v2 support verified
- ✅ 1Password op read and Connect server support verified
- ✅ pass/gopass command detection and store access verified
- ✅ env backend file loading and SIGIL_SECRET_* prefix verified
- ✅ AWS backend Secrets Manager and STS rotation verified
- ✅ SOPS backend YAML/JSON with age backend verified
- ⚠️ Backend routing namespace prefix handling exists but no central manager
- ✅ Backend cache is in-memory with TTL (mlock not explicitly verified)

## Recommendations

1. **Implement BackendManager**: Create a centralized manager that:
   - Loads backend configurations from ~/.sigil/config.toml
   - Routes secret requests based on namespace prefix
   - Implements resolution order: local vault → backends in config order
   - Manages backend lifecycle (initialization, cleanup)

2. **Add mlock support**: Consider using `mlock()` or `mlock2()` for backend cache:
   - Use `secrecy` crate's `SecretVec` for cached values
   - Implement mlock via `libc` or `mlock` crate
   - Ensure cache memory is protected from swap

3. **Backend configuration schema**: Add to `~/.sigil/config.toml`:
   ```toml
   [backends.vault]
   type = "vault"
   address = "http://127.0.0.1:8200"
   auth = "token"
   mount = "secret"
   cache_ttl = "5m"

   [backends.onepassword]
   type = "onepassword"
   account = "myaccount.1password.com"
   cache = true

   [backends.pass]
   type = "pass"
   store = "~/.password-store"
   ```

## Files Modified

- `crates/sigil-integration-tests/tests/phase6_2_3_backend_verification_test.rs` (created)
- `notes/bf-5hxa.md` (created)

## Test Results

```
running 22 tests
test test_aws_backend_secrets_manager ... ok
test test_aws_backend_sts_rotation ... ok
test test_backend_cache_memory_protection ... ok
test test_backend_cache_ttl_configuration ... ok
test test_backend_configuration_structure ... ok
test test_backend_namespace_routing ... ok
test test_backend_type_identifiers ... ok
test test_env_backend_file_loading ... ok
test test_env_backend_prefix_support ... ok
test test_onepassword_cli_support ... ok
test test_onepassword_connect_support ... ok
test test_pass_backend_command_detection ... ok
test test_pass_backend_store_access ... ok
test test_sops_backend_age_support ... ok
test test_sops_backend_yaml_json_support ... ok
test test_vault_backend_approle_auth ... ok
test test_vault_backend_cache ... ok
test test_vault_backend_jwt_auth ... ok
test test_vault_backend_kubernetes_auth ... ok
test test_vault_backend_kv_v2_support ... ok
test test_vault_backend_token_auth ... ok
test test_all_backends_implement_secret_backend_trait ... ok

test result: ok. 22 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out
```
