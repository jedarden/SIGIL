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
//! 3. Backend objects can be instantiated successfully

mod common;
use common::workspace_root;

// ============================================================================
// BACKEND FACTORY TESTS
// ============================================================================

/// Test: Verify BackendFromConfig is implemented for all backends
///
/// This is a behavioral test that actually creates backend instances
/// from configuration, verifying that:
/// - All backend crates implement the BackendFromConfig trait
/// - Backends can be instantiated from BackendEntry configuration
/// - Configuration validation works correctly
///
/// Note: This is NOT marked as #[tokio::test] because the backends
/// create their own tokio runtimes internally when needed.
#[test]
fn test_backend_from_config_implementations() {
    use sigil_core::backend::{BackendEntry, BackendFromConfig};
    use std::collections::HashMap;

    // Helper function to create a minimal BackendEntry
    fn create_backend_entry(
        backend_type: &str,
        prefix: &str,
        config: serde_json::Value,
    ) -> BackendEntry {
        let mut config_map = HashMap::new();
        if let Ok(obj) =
            serde_json::from_value::<serde_json::Map<String, serde_json::Value>>(config.clone())
        {
            for (key, value) in obj {
                if let Ok(str_val) = serde_json::to_string(&value) {
                    config_map.insert(key, str_val);
                }
            }
        }

        BackendEntry {
            id: format!("test-{}", backend_type),
            backend_type: backend_type.to_string(),
            prefix: prefix.to_string(),
            priority: 100,
            config: config_map,
            enabled: true,
        }
    }

    // Test Vault backend
    let vault_config = serde_json::json!({
        "address": "http://127.0.0.1:8200",
        "auth": "token",
        "token": "s.test-token",
        "mount": "secret",
        "namespace": null,
        "cache_ttl": 300,
        "verify_tls": false
    });
    let vault_entry = create_backend_entry("vault", "vault", vault_config);
    let vault_result = sigil_backend_vault::VaultBackend::from_config(&vault_entry);
    assert!(
        vault_result.is_ok(),
        "Vault backend should be created from config: {}",
        vault_result.unwrap_err()
    );
    let _vault_backend = vault_result.unwrap();

    // Test 1Password backend (use Connect mode to bypass CLI check)
    let onepassword_config = serde_json::json!({
        "vault": null,
        "account": null,
        "connect": true,
        "address": "http://localhost:8080",
        "token": "test-token",
        "cache": false,
        "cache_ttl": 300
    });
    let onepassword_entry = create_backend_entry("onepassword", "onepassword", onepassword_config);
    let onepassword_result =
        sigil_backend_onepassword::OnePasswordBackend::from_config(&onepassword_entry);
    assert!(
        onepassword_result.is_ok(),
        "1Password backend should be created from config: {}",
        onepassword_result.unwrap_err()
    );
    let _onepassword_backend = onepassword_result.unwrap();

    // Test Pass backend (skip if commands not available)
    let pass_config = serde_json::json!({
        "command": "auto",
        "store": "~/.password-store",
        "cache": false,
        "cache_ttl": 300
    });
    let pass_entry = create_backend_entry("pass", "pass", pass_config);
    let pass_result = sigil_backend_pass::PassBackend::from_config(&pass_entry);
    if let Err(e) = &pass_result {
        // Check if the error is about missing commands
        if e.to_string().contains("Neither 'pass' nor 'gopass' command found") {
            println!("Skipping Pass backend test - commands not available");
        } else {
            assert!(
                pass_result.is_ok(),
                "Pass backend should be created from config: {}",
                pass_result.unwrap_err()
            );
        }
    } else {
        let _pass_backend = pass_result.unwrap();
    }

    // Test AWS backend
    let aws_config = serde_json::json!({
        "region": null,
        "endpoint_url": null,
        "cache": true,
        "cache_ttl": 300,
        "prefix": null
    });
    let aws_entry = create_backend_entry("aws", "aws", aws_config);
    let aws_result = sigil_backend_aws::AwsBackend::from_config(&aws_entry);
    assert!(
        aws_result.is_ok(),
        "AWS backend should be created from config: {}",
        aws_result.unwrap_err()
    );
    let _aws_backend = aws_result.unwrap();

    // Test SOPS backend
    let sops_config = serde_json::json!({
        "directory": "/tmp/sops",
        "patterns": ["*.yaml", "*.yml", "*.json"],
        "cache": false,
        "cache_ttl": 300
    });
    let sops_entry = create_backend_entry("sops", "sops", sops_config);
    let sops_result = sigil_backend_sops::SopsBackend::from_config(&sops_entry);
    assert!(
        sops_result.is_ok(),
        "SOPS backend should be created from config: {}",
        sops_result.unwrap_err()
    );
    let _sops_backend = sops_result.unwrap();

    // Test Env backend (skip if file doesn't exist)
    let env_config = serde_json::json!({
        "file": "/tmp/test.env",
        "prefix": "SIGIL_"
    });
    let env_entry = create_backend_entry("env", "env", env_config);
    let env_result = sigil_backend_env::EnvBackend::from_config(&env_entry);
    if let Err(e) = &env_result {
        // Check if the error is about missing file
        if e.to_string().contains("Environment file not found") {
            println!("Skipping Env backend test - file not available");
        } else {
            assert!(
                env_result.is_ok(),
                "Env backend should be created from config: {}",
                env_result.unwrap_err()
            );
        }
    } else {
        let _env_backend = env_result.unwrap();
    }
}
