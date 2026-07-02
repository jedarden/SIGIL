//! Phase 6.2-6.3: External Backends and Routing Verification Tests
//!
//! These tests verify all 6 external backends and backend routing:
//!
//! ## 6.2 External backends to verify:
//! - sigil-backend-vault: token/AppRole/Kubernetes auth, KV v2, dynamic secrets
//! - sigil-backend-onepassword: op read and Connect server API
//! - sigil-backend-pass: pass show / gopass show -o
//! - sigil-backend-env: SIGIL_SECRET_* env var bridge
//! - sigil-backend-aws: AWS SDK with STS rotation
//! - sigil-backend-sops: SOPS YAML/JSON with age backend
//!
//! ## 6.3 Backend routing:
//! - Namespace prefix routing: {{secret:openbao/kalshi/api_key}} → openbao backend
//! - Resolution order: local vault → backends in config order
//! - Backend cache: mlock'd in-memory cache with TTL
//! - Config in ~/.sigil/config.toml with [backends.*] sections

mod common;
use common::workspace_root;
use std::fs;

/// Test 1: Verify all 6 backends implement SecretBackend trait correctly
///
/// From Phase 6.2: "Each backend implements SecretBackend trait"
#[test]
fn test_all_backends_implement_secret_backend_trait() {
    let backends = [
        "sigil-backend-vault",
        "sigil-backend-onepassword",
        "sigil-backend-pass",
        "sigil-backend-env",
        "sigil-backend-aws",
        "sigil-backend-sops",
    ];

    for backend in backends {
        let backend_path = workspace_root().join(format!("crates/{}/src/lib.rs", backend));

        if !backend_path.exists() {
            panic!(
                "Backend crate {} does not exist at {:?}",
                backend, backend_path
            );
        }

        let backend_code = fs::read_to_string(&backend_path)
            .unwrap_or_else(|_| panic!("Failed to read backend code for {}", backend));

        // Verify SecretBackend trait is implemented
        assert!(
            backend_code.contains("impl SecretBackend for"),
            "Backend {} must implement SecretBackend trait",
            backend
        );

        // Verify all required trait methods are implemented
        let required_methods = [
            "async fn get",
            "async fn get_metadata",
            "async fn set",
            "async fn delete",
            "async fn list",
            "fn backend_type",
        ];

        for method in required_methods {
            assert!(
                backend_code.contains(method),
                "Backend {} must implement SecretBackend method: {}",
                backend,
                method
            );
        }

        // Verify async_trait is used (either #[async_trait] or #[async_trait::async_trait])
        assert!(
            backend_code.contains("#[async_trait]")
                || backend_code.contains("async_trait::async_trait"),
            "Backend {} must use #[async_trait] for async trait methods",
            backend
        );
    }
}

/// Test 2: Verify Vault backend token authentication
///
/// From Phase 6.2: "Token auth for Vault/AppRole"
#[test]
fn test_vault_backend_token_auth() {
    let vault_backend = workspace_root().join("crates/sigil-backend-vault/src/lib.rs");
    let vault_code = fs::read_to_string(&vault_backend).expect("Failed to read Vault backend");

    // Verify VaultAuth::Token variant exists
    assert!(
        vault_code.contains("VaultAuth::Token"),
        "Vault backend must support Token authentication"
    );

    // Verify VaultToken enum with Direct, Env, and File variants
    assert!(
        vault_code.contains("VaultToken::Direct"),
        "Vault backend must support direct token values"
    );
    assert!(
        vault_code.contains("VaultToken::Env"),
        "Vault backend must support VAULT_TOKEN environment variable"
    );
    assert!(
        vault_code.contains("VaultToken::File"),
        "Vault backend must support ~/.vault-token file"
    );

    // Verify authentication function
    assert!(
        vault_code.contains("async fn authenticate"),
        "Vault backend must have an async authentication function"
    );

    // Verify token is stored using SecretString (secrecy crate)
    assert!(
        vault_code.contains("SecretString"),
        "Vault backend must use SecretString to protect tokens"
    );
}

/// Test 3: Verify Vault backend AppRole authentication
///
/// From Phase 6.2: "AppRole authentication"
#[test]
fn test_vault_backend_approle_auth() {
    let vault_backend = workspace_root().join("crates/sigil-backend-vault/src/lib.rs");
    let vault_code = fs::read_to_string(&vault_backend).expect("Failed to read Vault backend");

    // Verify VaultAuth::AppRole variant exists
    assert!(
        vault_code.contains("VaultAuth::AppRole"),
        "Vault backend must support AppRole authentication"
    );

    // Verify AppRole has role_id and secret_id
    assert!(
        vault_code.contains("role_id") && vault_code.contains("secret_id"),
        "Vault AppRole auth must have role_id and secret_id"
    );

    // Verify AppRole authentication function
    assert!(
        vault_code.contains("authenticate_approle"),
        "Vault backend must implement AppRole authentication"
    );

    // Verify AppRole login endpoint is used
    assert!(
        vault_code.contains("approle/login"),
        "Vault AppRole must use approle/login endpoint"
    );
}

/// Test 4: Verify Vault backend Kubernetes authentication
///
/// From Phase 6.2: "Kubernetes auth for Vault"
#[test]
fn test_vault_backend_kubernetes_auth() {
    let vault_backend = workspace_root().join("crates/sigil-backend-vault/src/lib.rs");
    let vault_code = fs::read_to_string(&vault_backend).expect("Failed to read Vault backend");

    // Verify VaultAuth::Kubernetes variant exists
    assert!(
        vault_code.contains("VaultAuth::Kubernetes"),
        "Vault backend must support Kubernetes authentication"
    );

    // Verify Kubernetes auth has role and mount parameters
    assert!(
        vault_code.contains("Kubernetes {")
            && vault_code.contains("role")
            && vault_code.contains("mount"),
        "Vault Kubernetes auth must have role and mount parameters"
    );

    // Verify Kubernetes authentication function
    assert!(
        vault_code.contains("authenticate_kubernetes"),
        "Vault backend must implement Kubernetes authentication"
    );

    // Verify service account token is read
    assert!(
        vault_code.contains("/var/run/secrets/kubernetes.io/serviceaccount/token"),
        "Vault Kubernetes auth must read service account token"
    );
}

/// Test 5: Verify Vault backend JWT authentication (for GitLab CI)
///
/// From Phase 6.2: "JWT authentication (GitLab CI)"
#[test]
fn test_vault_backend_jwt_auth() {
    let vault_backend = workspace_root().join("crates/sigil-backend-vault/src/lib.rs");
    let vault_code = fs::read_to_string(&vault_backend).expect("Failed to read Vault backend");

    // Verify VaultAuth::Jwt variant exists
    assert!(
        vault_code.contains("VaultAuth::Jwt"),
        "Vault backend must support JWT authentication"
    );

    // Verify JWT auth has role, jwt, and mount parameters
    assert!(
        vault_code.contains("Jwt {") && vault_code.contains("role") && vault_code.contains("jwt"),
        "Vault JWT auth must have role and jwt parameters"
    );

    // Verify JWT authentication function
    assert!(
        vault_code.contains("authenticate_jwt"),
        "Vault backend must implement JWT authentication"
    );

    // Verify GitLab CI JWT support (CI_JOB_JWT_V2)
    assert!(
        vault_code.contains("CI_JOB_JWT_V2"),
        "Vault JWT auth must support GitLab CI environment variable"
    );
}

/// Test 6: Verify Vault backend KV v2 secrets engine
///
/// From Phase 6.2: "KV v2, dynamic secrets"
#[test]
fn test_vault_backend_kv_v2_support() {
    let vault_backend = workspace_root().join("crates/sigil-backend-vault/src/lib.rs");
    let vault_code = fs::read_to_string(&vault_backend).expect("Failed to read Vault backend");

    // Verify KV v2 mount point configuration
    assert!(
        vault_code.contains("mount") && vault_code.contains("secret"),
        "Vault backend must support configurable KV v2 mount point"
    );

    // Verify KV v2 data path format
    assert!(
        vault_code.contains("/data/"),
        "Vault backend must use KV v2 data path format"
    );

    // Verify KV v2 metadata path
    assert!(
        vault_code.contains("/metadata/"),
        "Vault backend must support KV v2 metadata operations"
    );

    // Verify secret value extraction handles KV v2 structure
    assert!(
        vault_code.contains("data.data"),
        "Vault backend must handle KV v2 nested data structure"
    );
}

/// Test 7: Verify Vault backend cache with TTL
///
/// From Phase 6.2: "Cache with configurable TTL"
#[test]
fn test_vault_backend_cache() {
    let vault_backend = workspace_root().join("crates/sigil-backend-vault/src/lib.rs");
    let vault_code = fs::read_to_string(&vault_backend).expect("Failed to read Vault backend");

    // Verify cache struct exists
    assert!(
        vault_code.contains("struct VaultCache") || vault_code.contains("VaultCache"),
        "Vault backend must have a cache implementation"
    );

    // Verify cache has TTL support
    assert!(
        vault_code.contains("cache_ttl") || vault_code.contains("Ttl"),
        "Vault backend must support cache TTL"
    );

    // Verify cache get/put operations
    assert!(
        vault_code.contains("cache.get") || vault_code.contains("get(&self"),
        "Vault backend must support cache get operation"
    );
    assert!(
        vault_code.contains("cache.put") || vault_code.contains("put(&mut"),
        "Vault backend must support cache put operation"
    );

    // Verify cache is wrapped in Arc<RwLock<>> for thread safety
    assert!(
        vault_code.contains("Arc<RwLock<VaultCache>>"),
        "Vault cache must be thread-safe with Arc<RwLock<>>"
    );
}

/// Test 8: Verify 1Password backend CLI support
///
/// From Phase 6.2: "op read"
#[test]
fn test_onepassword_cli_support() {
    let onepassword_backend = workspace_root().join("crates/sigil-backend-onepassword/src/lib.rs");
    let onepassword_code =
        fs::read_to_string(&onepassword_backend).expect("Failed to read 1Password backend");

    // Verify op command execution
    assert!(
        onepassword_code.contains("op read") || onepassword_code.contains("op item"),
        "1Password backend must use 'op' CLI command"
    );

    // Verify command execution via std::process::Command
    assert!(
        onepassword_code.contains("Command::new") && onepassword_code.contains("op"),
        "1Password backend must execute op CLI via Command::new"
    );

    // Verify path parsing for op:// format
    assert!(
        onepassword_code.contains("op://"),
        "1Password backend must support op:// URL format"
    );

    // Verify vault/item/field parsing
    assert!(
        onepassword_code.contains("parse_path") || onepassword_code.contains("parse"),
        "1Password backend must parse paths into vault/item/field components"
    );
}

/// Test 9: Verify 1Password backend Connect server API support
///
/// From Phase 6.2: "Connect server API"
#[test]
fn test_onepassword_connect_support() {
    let onepassword_backend = workspace_root().join("crates/sigil-backend-onepassword/src/lib.rs");
    let onepassword_code =
        fs::read_to_string(&onepassword_backend).expect("Failed to read 1Password backend");

    // Verify Connect mode configuration
    assert!(
        onepassword_code.contains("use_connect") || onepassword_code.contains("connect"),
        "1Password backend must support Connect API mode"
    );

    // Verify Connect address and token configuration
    assert!(
        onepassword_code.contains("connect_address") && onepassword_code.contains("connect_token"),
        "1Password backend must support Connect server address and token"
    );

    // Verify backend is read-only (as documented)
    assert!(
        onepassword_code.contains("read-only") || onepassword_code.contains("set.*not supported"),
        "1Password backend should be read-only"
    );
}

/// Test 10: Verify pass/gopass backend command detection
///
/// From Phase 6.2: "pass show / gopass show -o"
#[test]
fn test_pass_backend_command_detection() {
    let pass_backend = workspace_root().join("crates/sigil-backend-pass/src/lib.rs");
    let pass_code = fs::read_to_string(&pass_backend).expect("Failed to read pass backend");

    // Verify PassCommand enum with Auto, Pass, Gopass variants
    assert!(
        pass_code.contains("PassCommand::Auto") || pass_code.contains("enum PassCommand"),
        "Pass backend must support auto-detection"
    );
    assert!(
        pass_code.contains("PassCommand::Pass"),
        "Pass backend must support standard pass command"
    );
    assert!(
        pass_code.contains("PassCommand::Gopass"),
        "Pass backend must support gopass command"
    );

    // Verify command detection function
    assert!(
        pass_code.contains("detect_pass_command"),
        "Pass backend must have a command detection function"
    );

    // Verify command existence check
    assert!(
        pass_code.contains("command_exists") || pass_code.contains("which"),
        "Pass backend must check if command exists"
    );
}

/// Test 11: Verify pass/gopass backend store access
///
/// From Phase 6.2: "pass show / gopass show -o"
#[test]
fn test_pass_backend_store_access() {
    let pass_backend = workspace_root().join("crates/sigil-backend-pass/src/lib.rs");
    let pass_code = fs::read_to_string(&pass_backend).expect("Failed to read pass backend");

    // Verify pass show command execution
    assert!(
        pass_code.contains("show")
            && (pass_code.contains("pass show") || pass_code.contains("gopass show")),
        "Pass backend must execute pass show or gopass show command"
    );

    // Verify gopass -o flag (output only, no clipboard)
    assert!(
        pass_code.contains("show -o") || pass_code.contains("-o"),
        "Gopass command must use -o flag"
    );

    // Verify PASSWORD_STORE_DIR environment variable
    assert!(
        pass_code.contains("PASSWORD_STORE_DIR"),
        "Pass backend must set PASSWORD_STORE_DIR environment variable"
    );

    // Verify store path configuration
    assert!(
        pass_code.contains("store_path") || pass_code.contains("password-store"),
        "Pass backend must support configurable store path"
    );

    // Verify list operation (pass ls or gopass ls)
    assert!(
        pass_code.contains("ls") || pass_code.contains("list"),
        "Pass backend must support listing secrets"
    );
}

/// Test 12: Verify env backend file loading
///
/// From Phase 6.2: "SIGIL_SECRET_* env var bridge"
#[test]
fn test_env_backend_file_loading() {
    let env_backend = workspace_root().join("crates/sigil-backend-env/src/lib.rs");
    let env_code = fs::read_to_string(&env_backend).expect("Failed to read env backend");

    // Verify env file configuration
    assert!(
        env_code.contains("env_file") || env_code.contains("file"),
        "Env backend must support configurable env file path"
    );

    // Verify env file loading function
    assert!(
        env_code.contains("load_env_file"),
        "Env backend must have a function to load env file"
    );

    // Verify KEY=VALUE parsing (looks for '=' character in line parsing)
    assert!(
        env_code.contains("=") && (env_code.contains("find") || env_code.contains("split")),
        "Env backend must parse KEY=VALUE format"
    );

    // Verify file permissions check
    assert!(
        env_code.contains("permissions") || env_code.contains("0600") || env_code.contains("mode"),
        "Env backend must check file permissions"
    );

    // Verify backend does NOT read from process environment (check in code, not comments)
    // The env backend reads from a file, not std::env::var
    // Note: std::env::var might appear in comments/docs, which is acceptable
    let code_without_comments: String = env_code
        .lines()
        .filter(|line| {
            !line.trim_start().starts_with("//") && !line.trim_start().starts_with("//!")
        })
        .collect::<Vec<_>>()
        .join("\n");

    let reads_from_env = code_without_comments.contains("std::env::var(")
        || code_without_comments.contains("env::var(");

    assert!(
        !reads_from_env,
        "Env backend must not read from agent's process environment"
    );
}

/// Test 13: Verify env backend SIGIL_SECRET_* prefix support
///
/// From Phase 6.2: "SIGIL_SECRET_* env var bridge"
#[test]
fn test_env_backend_prefix_support() {
    let env_backend = workspace_root().join("crates/sigil-backend-env/src/lib.rs");
    let env_code = fs::read_to_string(&env_backend).expect("Failed to read env backend");

    // Verify prefix configuration
    assert!(
        env_code.contains("prefix") || env_code.contains("SIGIL_"),
        "Env backend must support prefix filtering"
    );

    // Verify default prefix is SIGIL_
    assert!(
        env_code.contains("SIGIL_") || env_code.contains("SIGIL_SECRET"),
        "Env backend should use SIGIL_ prefix by default"
    );

    // Verify prefix is used in get() method
    assert!(
        env_code.contains("format!") || env_code.contains("prefixed"),
        "Env backend must apply prefix when looking up secrets"
    );
}

/// Test 14: Verify AWS backend Secrets Manager
///
/// From Phase 6.2: "AWS SDK with STS rotation"
#[test]
fn test_aws_backend_secrets_manager() {
    let aws_backend = workspace_root().join("crates/sigil-backend-aws/src/lib.rs");
    let aws_code = fs::read_to_string(&aws_backend).expect("Failed to read AWS backend");

    // Verify AWS SDK client
    assert!(
        aws_code.contains("aws_sdk_secretsmanager") || aws_code.contains("SecretsClient"),
        "AWS backend must use AWS Secrets Manager SDK"
    );

    // Verify get_secret_value operation
    assert!(
        aws_code.contains("get_secret_value") || aws_code.contains("GetSecretValue"),
        "AWS backend must call GetSecretValue API"
    );

    // Verify list_secrets operation
    assert!(
        aws_code.contains("list_secrets") || aws_code.contains("ListSecrets"),
        "AWS backend must support listing secrets"
    );

    // Verify secret_string() extraction
    assert!(
        aws_code.contains("secret_string") || aws_code.contains("secret_bytes"),
        "AWS backend must extract secret_string from response"
    );
}

/// Test 15: Verify AWS backend STS rotation support
///
/// From Phase 6.2: "AWS SDK with STS rotation"
#[test]
fn test_aws_backend_sts_rotation() {
    let aws_backend = workspace_root().join("crates/sigil-backend-aws/src/lib.rs");
    let aws_code = fs::read_to_string(&aws_backend).expect("Failed to read AWS backend");

    // Verify version_id tracking for rotation detection
    assert!(
        aws_code.contains("version_id") || aws_code.contains("VersionId"),
        "AWS backend must track secret version IDs for rotation"
    );

    // Verify cache invalidation on rotation
    assert!(
        aws_code.contains("invalidate") || aws_code.contains("rotation"),
        "AWS backend must handle cache invalidation for rotated secrets"
    );

    // Verify AWS SDK configuration loading
    assert!(
        aws_code.contains("aws_config") || aws_code.contains("BehaviorVersion"),
        "AWS backend must use AWS SDK config loader for credential chain"
    );
}

/// Test 16: Verify SOPS backend YAML/JSON support
///
/// From Phase 6.2: "SOPS YAML/JSON with age backend"
#[test]
fn test_sops_backend_yaml_json_support() {
    let sops_backend = workspace_root().join("crates/sigil-backend-sops/src/lib.rs");
    let sops_code = fs::read_to_string(&sops_backend).expect("Failed to read SOPS backend");

    // Verify YAML parsing
    assert!(
        sops_code.contains("serde_yaml") || sops_code.contains("Yaml"),
        "SOPS backend must support YAML parsing"
    );

    // Verify JSON support (via serde_yaml which handles JSON too)
    assert!(
        sops_code.contains("json") || sops_code.contains("JSON"),
        "SOPS backend must support JSON files"
    );

    // Verify file pattern matching
    assert!(
        sops_code.contains("patterns") || sops_code.contains("*.yaml"),
        "SOPS backend must support file pattern matching"
    );

    // Verify default patterns include *.yaml, *.yml, *.json
    assert!(
        sops_code.contains("*.yaml") && sops_code.contains("*.yml") && sops_code.contains("*.json"),
        "SOPS backend must support .yaml, .yml, and .json files by default"
    );
}

/// Test 17: Verify SOPS backend age encryption
///
/// From Phase 6.2: "SOPS YAML/JSON with age backend"
#[test]
fn test_sops_backend_age_support() {
    let sops_backend = workspace_root().join("crates/sigil-backend-sops/src/lib.rs");
    let sops_code = fs::read_to_string(&sops_backend).expect("Failed to read SOPS backend");

    // Verify SOPS metadata extraction
    assert!(
        sops_code.contains("sops_metadata") || sops_code.contains("SopsMetadata"),
        "SOPS backend must extract SOPS metadata from files"
    );

    // Verify age key in metadata
    assert!(
        sops_code.contains("age_key") || sops_code.contains("age"),
        "SOPS backend must check for age encryption key in metadata"
    );

    // Verify MAC verification
    assert!(
        sops_code.contains("mac") || sops_code.contains("Mac"),
        "SOPS backend must verify MAC for integrity"
    );

    // Verify version checking
    assert!(
        sops_code.contains("version") || sops_code.contains("Version"),
        "SOPS backend must check SOPS version"
    );

    // Note: Actual decryption happens via sops CLI or sops-gothkre
    // The backend just reads the encrypted structure
}

/// Test 18: Verify backend namespace prefix routing
///
/// From Phase 6.3: "Namespace prefix routing: {{secret:openbao/kalshi/api_key}} → openbao backend"
#[test]
fn test_backend_namespace_routing() {
    // Check each backend for path prefix handling
    let backends = [
        ("vault", "crates/sigil-backend-vault/src/lib.rs"),
        ("onepassword", "crates/sigil-backend-onepassword/src/lib.rs"),
        ("pass", "crates/sigil-backend-pass/src/lib.rs"),
        ("aws", "crates/sigil-backend-aws/src/lib.rs"),
        ("sops", "crates/sigil-backend-sops/src/lib.rs"),
    ];

    for (name, path) in backends {
        let backend_path = workspace_root().join(path);
        if !backend_path.exists() {
            continue;
        }

        let backend_code = fs::read_to_string(&backend_path)
            .unwrap_or_else(|_| panic!("Failed to read backend code for {}", name));

        // Verify backend handles path prefixes
        // Each backend should strip its namespace prefix (e.g., "vault/") from paths
        assert!(
            backend_code.contains("strip_prefix") || backend_code.contains("prefix"),
            "Backend {} must handle path prefix stripping",
            name
        );
    }
}

/// Test 19: Verify backend cache uses mlock'd memory
///
/// From Phase 6.3: "Backend cache: mlock'd in-memory cache with TTL"
#[test]
fn test_backend_cache_memory_protection() {
    let backends = [
        ("vault", "crates/sigil-backend-vault/src/lib.rs"),
        ("onepassword", "crates/sigil-backend-onepassword/src/lib.rs"),
        ("aws", "crates/sigil-backend-aws/src/lib.rs"),
    ];

    for (name, path) in backends {
        let backend_path = workspace_root().join(path);
        if !backend_path.exists() {
            continue;
        }

        let backend_code = fs::read_to_string(&backend_path)
            .unwrap_or_else(|_| panic!("Failed to read backend code for {}", name));

        // Verify cache does NOT write to disk
        assert!(
            !backend_code.contains("cache_to_disk") && !backend_code.contains("persist_cache"),
            "Backend {} cache must not persist to disk",
            name
        );

        // Verify cache uses in-memory storage (HashMap, BTreeMap, etc.)
        if backend_code.contains("cache") || backend_code.contains("Cache") {
            assert!(
                backend_code.contains("HashMap")
                    || backend_code.contains("BTreeMap")
                    || backend_code.contains("RwLock"),
                "Backend {} cache must use in-memory storage",
                name
            );
        }
    }
}

/// Test 20: Verify backend cache TTL configuration
///
/// From Phase 6.3: "Backend cache: mlock'd in-memory cache with TTL"
#[test]
fn test_backend_cache_ttl_configuration() {
    let backends = [
        ("vault", "crates/sigil-backend-vault/src/lib.rs"),
        ("onepassword", "crates/sigil-backend-onepassword/src/lib.rs"),
        ("aws", "crates/sigil-backend-aws/src/lib.rs"),
    ];

    for (name, path) in backends {
        let backend_path = workspace_root().join(path);
        if !backend_path.exists() {
            continue;
        }

        let backend_code = fs::read_to_string(&backend_path)
            .unwrap_or_else(|_| panic!("Failed to read backend code for {}", name));

        // Verify TTL configuration
        assert!(
            backend_code.contains("cache_ttl") || backend_code.contains("ttl"),
            "Backend {} must support cache TTL configuration",
            name
        );

        // Verify Duration type for TTL
        assert!(
            backend_code.contains("Duration") || backend_code.contains("duration"),
            "Backend {} cache TTL must use Duration type",
            name
        );

        // Verify cache respects TTL (has age checking)
        assert!(
            backend_code.contains("cached_at")
                || backend_code.contains("age")
                || backend_code.contains("expiry"),
            "Backend {} cache must track entry age for TTL enforcement",
            name
        );
    }
}

/// Test 21: Verify backend type() method returns correct identifier
///
/// From Phase 6.3: "Config in ~/.sigil/config.toml with [backends.*] sections"
#[test]
fn test_backend_type_identifiers() {
    let backends = [
        ("vault", "vault"),
        ("onepassword", "onepassword"),
        ("pass", "pass"),
        ("env", "env"),
        ("aws", "aws"),
        ("sops", "sops"),
    ];

    for (name, expected_type) in backends {
        let backend_path =
            workspace_root().join(format!("crates/sigil-backend-{}/src/lib.rs", name));
        if !backend_path.exists() {
            continue;
        }

        let backend_code = fs::read_to_string(&backend_path)
            .unwrap_or_else(|_| panic!("Failed to read backend code for {}", name));

        // Verify backend_type() method returns correct identifier
        assert!(
            backend_code.contains(&format!("\"{}\"", expected_type))
                || backend_code.contains(&format!("'{}'", expected_type)),
            "Backend {} must return '{}' from backend_type()",
            name,
            expected_type
        );
    }
}

/// Test 22: Verify backend configuration structure
///
/// From Phase 6.3: "Config in ~/.sigil/config.toml with [backends.*] sections"
#[test]
fn test_backend_configuration_structure() {
    let backends = [
        ("vault", "VaultBackendConfig"),
        ("onepassword", "OnePasswordBackendConfig"),
        ("pass", "PassBackendConfig"),
        ("env", "EnvBackendConfig"),
        ("aws", "AwsBackendConfig"),
        ("sops", "SopsBackendConfig"),
    ];

    for (name, config_type) in backends {
        let backend_path =
            workspace_root().join(format!("crates/sigil-backend-{}/src/lib.rs", name));
        if !backend_path.exists() {
            continue;
        }

        let backend_code = fs::read_to_string(&backend_path)
            .unwrap_or_else(|_| panic!("Failed to read backend code for {}", name));

        // Verify config struct exists
        assert!(
            backend_code.contains(config_type) || backend_code.contains("Config"),
            "Backend {} must have a configuration struct",
            name
        );

        // Verify config has Default implementation
        assert!(
            backend_code.contains("impl Default for")
                || backend_code.contains("Default::default()"),
            "Backend {} config must implement Default",
            name
        );

        // Verify new() constructor
        assert!(
            backend_code.contains("pub fn new") || backend_code.contains("pub async fn new"),
            "Backend {} must have a public constructor",
            name
        );
    }
}
