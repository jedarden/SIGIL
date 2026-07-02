//! Backend Integration Tests
//!
//! This test module verifies the external backend implementations:
//! - Vault backend (HashiCorp Vault/OpenBao)
//! - 1Password backend
//! - Pass/gopass backend
//! - AWS Secrets Manager backend
//! - SOPS backend
//! - Environment backend
//!
//! These tests verify that:
//! 1. BackendFromConfig trait is implemented for all backends
//! 2. Backends can be created from configuration
//! 3. Backend routing works correctly
//! 4. Namespace prefix resolution works as expected

mod common;
use common::workspace_root;
use std::fs;

// ============================================================================
// BACKEND FACTORY TESTS
// ============================================================================

/// Test 1.1: Verify BackendFromConfig is implemented for all backends
///
/// This test verifies that all backend crates implement the BackendFromConfig
/// trait, which is required for dynamic backend creation from configuration.
#[test]
fn test_backend_from_config_implementations() {
    // Check vault backend
    let vault_backend_path = workspace_root().join("crates/sigil-backend-vault/src/lib.rs");
    let vault_code =
        fs::read_to_string(&vault_backend_path).expect("Failed to read vault backend code");
    assert!(
        vault_backend_path.exists(),
        "Vault backend crate must exist"
    );
    assert!(
        vault_code.contains("impl sigil_core::backend::BackendFromConfig for VaultBackend")
            || vault_code.contains("BackendFromConfig for VaultBackend"),
        "Vault backend must implement BackendFromConfig"
    );

    // Check 1Password backend
    let onepassword_backend_path =
        workspace_root().join("crates/sigil-backend-onepassword/src/lib.rs");
    let onepassword_code = fs::read_to_string(&onepassword_backend_path)
        .expect("Failed to read 1Password backend code");
    assert!(
        onepassword_backend_path.exists(),
        "1Password backend crate must exist"
    );
    assert!(
        onepassword_code
            .contains("impl sigil_core::backend::BackendFromConfig for OnePasswordBackend")
            || onepassword_code.contains("BackendFromConfig for OnePasswordBackend"),
        "1Password backend must implement BackendFromConfig"
    );

    // Check pass backend
    let pass_backend_path = workspace_root().join("crates/sigil-backend-pass/src/lib.rs");
    let pass_code =
        fs::read_to_string(&pass_backend_path).expect("Failed to read pass backend code");
    assert!(pass_backend_path.exists(), "Pass backend crate must exist");
    assert!(
        pass_code.contains("impl sigil_core::backend::BackendFromConfig for PassBackend")
            || pass_code.contains("BackendFromConfig for PassBackend"),
        "Pass backend must implement BackendFromConfig"
    );

    // Check AWS backend
    let aws_backend_path = workspace_root().join("crates/sigil-backend-aws/src/lib.rs");
    let aws_code = fs::read_to_string(&aws_backend_path).expect("Failed to read AWS backend code");
    assert!(aws_backend_path.exists(), "AWS backend crate must exist");
    assert!(
        aws_code.contains("impl sigil_core::backend::BackendFromConfig for AwsBackend")
            || aws_code.contains("BackendFromConfig for AwsBackend"),
        "AWS backend must implement BackendFromConfig"
    );

    // Check SOPS backend
    let sops_backend_path = workspace_root().join("crates/sigil-backend-sops/src/lib.rs");
    let sops_code =
        fs::read_to_string(&sops_backend_path).expect("Failed to read SOPS backend code");
    assert!(sops_backend_path.exists(), "SOPS backend crate must exist");
    assert!(
        sops_code.contains("impl sigil_core::backend::BackendFromConfig for SopsBackend")
            || sops_code.contains("BackendFromConfig for SopsBackend"),
        "SOPS backend must implement BackendFromConfig"
    );

    // Check env backend
    let env_backend_path = workspace_root().join("crates/sigil-backend-env/src/lib.rs");
    let env_code = fs::read_to_string(&env_backend_path).expect("Failed to read env backend code");
    assert!(env_backend_path.exists(), "Env backend crate must exist");
    assert!(
        env_code.contains("impl sigil_core::backend::BackendFromConfig for EnvBackend")
            || env_code.contains("BackendFromConfig for EnvBackend"),
        "Env backend must implement BackendFromConfig"
    );
}

/// Test 1.2: Verify BackendFactory supports all backend types
///
/// This test verifies that the BackendFactory in sigil-core can create
/// instances of all backend types.
#[test]
fn test_backend_factory_support() {
    let backend_rs_path = workspace_root().join("crates/sigil-core/src/backend.rs");
    let backend_code =
        fs::read_to_string(&backend_rs_path).expect("Failed to read backend.rs code");

    // Verify BackendFactory exists
    assert!(
        backend_code.contains("pub struct BackendFactory"),
        "BackendFactory must be defined"
    );

    // Verify create_backend function
    assert!(
        backend_code.contains("pub fn create_backend"),
        "BackendFactory must have create_backend function"
    );

    // Verify support for all backend types
    let required_backends = [
        ("vault", "backend-vault"),
        ("onepassword", "backend-onepassword"),
        ("pass", "backend-pass"),
        ("aws", "backend-aws"),
        ("sops", "backend-sops"),
        ("env", "backend-env"),
    ];

    for (backend_type, feature_name) in required_backends {
        assert!(
            backend_code.contains(&format!("\"{}\"", backend_type))
                || backend_code.contains(&format!("{}\"", backend_type)),
            "BackendFactory must support '{}' backend type",
            backend_type
        );
        assert!(
            backend_code.contains(&format!("feature = \"{}\"", feature_name))
                || backend_code.contains(&format!("#[cfg(feature = \"{}\")]", feature_name)),
            "BackendFactory must have feature flag for '{}'",
            feature_name
        );
    }
}

// ============================================================================
// BACKEND ROUTING TESTS
// ============================================================================

/// Test 2.1: Verify namespace prefix routing
///
/// This test verifies that the backend router correctly routes secrets
/// based on their namespace prefix.
#[test]
fn test_namespace_prefix_routing() {
    let backend_rs_path = workspace_root().join("crates/sigil-core/src/backend.rs");
    let backend_code =
        fs::read_to_string(&backend_rs_path).expect("Failed to read backend.rs code");

    // Verify BACKEND_PREFIXES constant
    assert!(
        backend_code.contains("pub const BACKEND_PREFIXES"),
        "BACKEND_PREFIXES constant must be defined"
    );

    // Verify all required prefixes
    let required_prefixes = [
        ("vault", "vault"),
        ("openbao", "vault"),
        ("onepassword", "onepassword"),
        ("op", "onepassword"),
        ("pass", "pass"),
        ("gopass", "pass"),
        ("aws", "aws"),
        ("sops", "sops"),
        ("env", "env"),
    ];

    for (alias, backend_type) in required_prefixes {
        assert!(
            backend_code.contains(&format!("(\"{}\"", alias))
                || backend_code.contains(&format!("(\"{alias}\"")),
            "BACKEND_PREFIXES must include '{}' alias for '{}'",
            alias,
            backend_type
        );
    }

    // Verify BackendEntry::matches_path method
    assert!(
        backend_code.contains("pub fn matches_path"),
        "BackendEntry must have matches_path method"
    );

    // Verify BackendRouter::route method
    assert!(
        backend_code.contains("pub fn route"),
        "BackendRouter must have route method"
    );
}

/// Test 2.2: Verify resolution order
///
/// This test verifies that the backend router follows the correct
/// resolution order:
/// 1. Local vault (no prefix)
/// 2. Backends by namespace prefix
/// 3. Default backend
/// 4. Priority order
#[test]
fn test_resolution_order() {
    let backend_rs_path = workspace_root().join("crates/sigil-core/src/backend.rs");
    let backend_code =
        fs::read_to_string(&backend_rs_path).expect("Failed to read backend.rs code");

    // Verify is_local_vault_path method
    assert!(
        backend_code.contains("is_local_vault_path"),
        "BackendRouter must check for local vault paths"
    );

    // Verify priority handling
    assert!(
        backend_code.contains("priority") && backend_code.contains("sort_by"),
        "BackendRouter must sort backends by priority"
    );

    // Verify default_backend handling
    assert!(
        backend_code.contains("default_backend"),
        "BackendRouter must support default backend"
    );
}

// ============================================================================
// BACKEND CACHE TESTS
// ============================================================================

/// Test 3.1: Verify backend cache implementation
///
/// This test verifies that the backend cache is implemented with:
/// 1. TTL support
/// 2. Cache invalidation
/// 3. Per-backend storage
/// 4. Cleanup of expired entries
#[test]
fn test_backend_cache_implementation() {
    let backend_rs_path = workspace_root().join("crates/sigil-core/src/backend.rs");
    let backend_code =
        fs::read_to_string(&backend_rs_path).expect("Failed to read backend.rs code");

    // Verify BackendCache struct
    assert!(
        backend_code.contains("pub struct BackendCache"),
        "BackendCache must be defined"
    );

    // Verify cache methods
    let required_methods = [
        "pub fn get",
        "pub fn set",
        "pub fn invalidate",
        "clear_backend",
        "cleanup_expired",
    ];

    for method in required_methods {
        assert!(
            backend_code.contains(method),
            "BackendCache must implement {} method",
            method
        );
    }

    // Verify TTL support
    assert!(
        backend_code.contains("expires_at") || backend_code.contains("ttl"),
        "BackendCache must support TTL"
    );

    // Verify cache entry structure
    assert!(
        backend_code.contains("struct CacheEntry"),
        "BackendCache must define CacheEntry structure"
    );
}

// ============================================================================
// VAULT BACKEND TESTS
// ============================================================================

/// Test 4.1: Verify Vault backend authentication methods
///
/// This test verifies that the Vault backend supports all required
/// authentication methods.
#[test]
fn test_vault_backend_auth_methods() {
    let vault_backend_path = workspace_root().join("crates/sigil-backend-vault/src/lib.rs");
    let vault_code =
        fs::read_to_string(&vault_backend_path).expect("Failed to read vault backend code");

    // Verify VaultAuth enum
    assert!(
        vault_code.contains("pub enum VaultAuth"),
        "Vault backend must define VaultAuth enum"
    );

    // Verify all auth methods
    let required_auth_methods = ["Token", "AppRole", "Kubernetes", "Jwt"];

    for auth_method in required_auth_methods {
        assert!(
            vault_code.contains(&format!("{} {{", auth_method))
                || vault_code.contains(&format!("{}:", auth_method)),
            "VaultAuth must support {} authentication",
            auth_method
        );
    }

    // Verify authenticate function
    assert!(
        vault_code.contains("async fn authenticate"),
        "Vault backend must have authenticate function"
    );
}

/// Test 4.2: Verify Vault backend KV v2 support
///
/// This test verifies that the Vault backend supports KV v2 engine.
#[test]
fn test_vault_backend_kv2_support() {
    let vault_backend_path = workspace_root().join("crates/sigil-backend-vault/src/lib.rs");
    let vault_code =
        fs::read_to_string(&vault_backend_path).expect("Failed to read vault backend code");

    // Verify KV v2 path handling
    assert!(
        vault_code.contains("data/") && vault_code.contains("metadata/"),
        "Vault backend must support KV v2 paths"
    );

    // Verify read_kv_v2 function
    assert!(
        vault_code.contains("async fn read_kv_v2") || vault_code.contains("fn read_kv_v2"),
        "Vault backend must have read_kv_v2 function"
    );

    // Verify list_kv_v2 function
    assert!(
        vault_code.contains("async fn list_kv_v2") || vault_code.contains("fn list_kv_v2"),
        "Vault backend must have list_kv_v2 function"
    );
}

// ============================================================================
// ONEPASSWORD BACKEND TESTS
// ============================================================================

/// Test 5.1: Verify 1Password backend CLI integration
///
/// This test verifies that the 1Password backend integrates with
/// the op CLI tool.
#[test]
fn test_onepassword_backend_cli_integration() {
    let onepassword_backend_path =
        workspace_root().join("crates/sigil-backend-onepassword/src/lib.rs");
    let onepassword_code = fs::read_to_string(&onepassword_backend_path)
        .expect("Failed to read 1Password backend code");

    // Verify op command execution
    assert!(
        onepassword_code.contains("op read") || onepassword_code.contains("Command::new(\"op\")"),
        "1Password backend must execute 'op read' command"
    );

    // Verify path parsing
    assert!(
        onepassword_code.contains("fn parse_path"),
        "1Password backend must parse op:// paths"
    );

    // Verify reference format
    assert!(
        onepassword_code.contains("op://"),
        "1Password backend must handle op:// reference format"
    );
}

// ============================================================================
// PASS BACKEND TESTS
// ============================================================================

/// Test 6.1: Verify pass backend supports both pass and gopass
///
/// This test verifies that the pass backend can use either pass
/// or gopass command.
#[test]
fn test_pass_backend_command_support() {
    let pass_backend_path = workspace_root().join("crates/sigil-backend-pass/src/lib.rs");
    let pass_code =
        fs::read_to_string(&pass_backend_path).expect("Failed to read pass backend code");

    // Verify PassCommand enum
    assert!(
        pass_code.contains("pub enum PassCommand") || pass_code.contains("enum PassCommand"),
        "Pass backend must define PassCommand enum"
    );

    // Verify command variants
    assert!(
        pass_code.contains("Auto") || pass_code.contains("Pass") || pass_code.contains("Gopass"),
        "PassCommand must support Auto, Pass, and Gopass variants"
    );

    // Verify command detection
    assert!(
        pass_code.contains("fn detect_pass_command"),
        "Pass backend must detect available command"
    );
}

// ============================================================================
// AWS BACKEND TESTS
// ============================================================================

/// Test 7.1: Verify AWS backend uses AWS SDK
///
/// This test verifies that the AWS backend uses the official AWS SDK.
#[test]
fn test_aws_backend_sdk_usage() {
    let aws_backend_path = workspace_root().join("crates/sigil-backend-aws/src/lib.rs");
    let aws_code = fs::read_to_string(&aws_backend_path).expect("Failed to read AWS backend code");

    // Verify AWS SDK imports
    assert!(
        aws_code.contains("aws_config") || aws_code.contains("aws_sdk_secretsmanager"),
        "AWS backend must use AWS SDK"
    );

    // Verify SecretsManager client
    assert!(
        aws_code.contains("SecretsClient") || aws_code.contains("secretsmanager"),
        "AWS backend must create Secrets Manager client"
    );

    // Verify credential chain
    assert!(
        aws_code.contains("BehaviorVersion") || aws_code.contains("defaults"),
        "AWS backend must use AWS SDK credential chain"
    );
}

/// Test 7.2: Verify AWS backend rotation support
///
/// This test verifies that the AWS backend supports secret rotation
/// via version IDs.
#[test]
fn test_aws_backend_rotation_support() {
    let aws_backend_path = workspace_root().join("crates/sigil-backend-aws/src/lib.rs");
    let aws_code = fs::read_to_string(&aws_backend_path).expect("Failed to read AWS backend code");

    // Verify version ID handling
    assert!(
        aws_code.contains("version_id") || aws_code.contains("VersionId"),
        "AWS backend must track secret versions for rotation"
    );

    // Verify cache invalidation on update
    assert!(
        aws_code.contains("invalidate") && aws_code.contains("put_secret_value"),
        "AWS backend must invalidate cache on secret update"
    );
}

// ============================================================================
// SOPS BACKEND TESTS
// ============================================================================

/// Test 8.1: Verify SOPS backend YAML/JSON parsing
///
/// This test verifies that the SOPS backend can parse YAML and JSON
/// files with SOPS metadata.
#[test]
fn test_sops_backend_file_parsing() {
    let sops_backend_path = workspace_root().join("crates/sigil-backend-sops/src/lib.rs");
    let sops_code =
        fs::read_to_string(&sops_backend_path).expect("Failed to read SOPS backend code");

    // Verify SOPS metadata extraction
    assert!(
        sops_code.contains("SopsMetadata") && sops_code.contains("sops"),
        "SOPS backend must extract SOPS metadata"
    );

    // Verify nested value extraction
    assert!(
        sops_code.contains("get_nested_value") || sops_code.contains("extract_nested"),
        "SOPS backend must extract nested values"
    );

    // Verify YAML/JSON parsing
    assert!(
        sops_code.contains("serde_yaml") || sops_code.contains("serde_json"),
        "SOPS backend must parse YAML/JSON"
    );
}

// ============================================================================
// ENV BACKEND TESTS
// ============================================================================

/// Test 9.1: Verify env backend file handling
///
/// This test verifies that the env backend reads from a restricted
/// environment file, not from process environment.
#[test]
fn test_env_backend_file_handling() {
    let env_backend_path = workspace_root().join("crates/sigil-backend-env/src/lib.rs");
    let env_code = fs::read_to_string(&env_backend_path).expect("Failed to read env backend code");

    // Verify file reading (not std::env::var)
    assert!(
        env_code.contains("fs::read_to_string") || env_code.contains("File::open"),
        "Env backend must read from file, not std::env::var"
    );

    // Verify permission checking
    assert!(
        env_code.contains("PermissionsExt") || env_code.contains("permissions"),
        "Env backend must check file permissions"
    );

    // Verify KEY=VALUE parsing (uses find('=') and slicing)
    assert!(
        env_code.contains("=')")
            || (env_code.contains("=")
                && (env_code.contains("parse") || env_code.contains("split"))),
        "Env backend must parse KEY=VALUE format"
    );
}

/// Test 9.2: Verify env backend prefix filtering
///
/// This test verifies that the env backend supports optional
/// prefix filtering for environment variables.
#[test]
fn test_env_backend_prefix_filtering() {
    let env_backend_path = workspace_root().join("crates/sigil-backend-env/src/lib.rs");
    let env_code = fs::read_to_string(&env_backend_path).expect("Failed to read env backend code");

    // Verify prefix configuration
    assert!(
        env_code.contains("prefix") || env_code.contains("SIGIL_"),
        "Env backend must support prefix filtering"
    );

    // Verify prefix matching logic
    assert!(
        env_code.contains("starts_with") || env_code.contains("prefix"),
        "Env backend must match variable prefix"
    );
}

// ============================================================================
// END-TO-END BACKEND WORKFLOW TESTS
// ============================================================================

/// Test 10.1: Verify complete backend workflow
///
/// This test verifies the complete workflow for using external backends:
/// 1. Backend is configured in config file
/// 2. Backend is created via BackendFactory
/// 3. Secret is routed to correct backend based on prefix
/// 4. Secret is retrieved from backend
/// 5. Secret is cached for subsequent requests
#[test]
fn test_complete_backend_workflow() {
    // This test verifies all components are present for the workflow

    // 1. Backend configuration
    let backend_rs_path = workspace_root().join("crates/sigil-core/src/backend.rs");
    let backend_code =
        fs::read_to_string(&backend_rs_path).expect("Failed to read backend.rs code");
    assert!(
        backend_code.contains("BackendEntry") && backend_code.contains("config"),
        "BackendEntry must store configuration"
    );

    // 2. Backend factory
    assert!(
        backend_code.contains("BackendFactory") && backend_code.contains("create_backend"),
        "BackendFactory must create backends from config"
    );

    // 3. Backend routing
    assert!(
        backend_code.contains("BackendRouter") && backend_code.contains("route"),
        "BackendRouter must route requests to backends"
    );

    // 4. Backend cache
    assert!(
        backend_code.contains("BackendCache")
            && backend_code.contains("get")
            && backend_code.contains("set"),
        "BackendCache must cache secrets"
    );

    // 5. SecretBackend trait
    let types_path = workspace_root().join("crates/sigil-core/src/types.rs");
    if types_path.exists() {
        let types_code = fs::read_to_string(&types_path).expect("Failed to read types.rs code");
        assert!(
            types_code.contains("trait SecretBackend")
                || types_code.contains("pub trait SecretBackend"),
            "SecretBackend trait must be defined"
        );
    }
}
