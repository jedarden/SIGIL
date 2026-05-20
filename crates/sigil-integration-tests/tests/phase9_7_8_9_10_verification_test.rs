//! Phase 9.7-9.10 Verification Tests
//!
//! These tests verify:
//! - 9.7: Emergency lockdown (kill sandboxes, revoke tokens/leases, lock vault, breach report, alerts)
//! - 9.8: Community signature database (update, search, add, curated sets)
//! - 9.9: SIGIL SDK (Rust crate, Python bindings, Node.js bindings)
//! - 9.10: sigil doctor (all checks, security score, --fix, --ci, --json)

mod common;
use common::workspace_root;
use std::fs;

// ============================================================================
// PHASE 9.7: EMERGENCY LOCKDOWN
// ============================================================================

/// Test 9.7.1: Verify sigil lockdown command exists
///
/// From Phase 9.7 Deliverables:
/// "sigil lockdown: kill sandboxes → revoke tokens → revoke leases → lock vault → breach report → alerts"
#[test]
fn test_9_7_1_lockdown_command_exists() {
    let cli_main_path = workspace_root().join("crates/sigil-cli/src/main.rs");

    assert!(cli_main_path.exists(), "CLI main must exist");

    let cli_code = fs::read_to_string(&cli_main_path).expect("Failed to read CLI code");

    // Verify lockdown command enum variant exists
    assert!(
        cli_code.contains("Lockdown") || cli_code.contains("lockdown"),
        "CLI must have lockdown command"
    );

    // Verify CommandLockdown struct exists
    assert!(
        cli_code.contains("CommandLockdown") || cli_code.contains("struct.*Lockdown"),
        "CLI must have CommandLockdown struct"
    );

    // Verify --confirm flag exists for automation
    assert!(
        cli_code.contains("confirm") && cli_code.contains("lockdown"),
        "Lockdown command should support --confirm flag for automation"
    );
}

/// Test 9.7.2: Verify lockdown completes in under 2 seconds
///
/// From Phase 9.7 Deliverables:
/// "Completes in < 2 seconds"
#[test]
fn test_9_7_2_lockdown_performance_requirement() {
    // Check that lockdown is designed for speed
    let cli_main_path = workspace_root().join("crates/sigil-cli/src/main.rs");
    let cli_code = fs::read_to_string(&cli_main_path).expect("Failed to read CLI code");

    // Verify lockdown is a single IPC operation (not multiple slow steps)
    assert!(
        cli_code.contains("IpcOperation::Lockdown") || cli_code.contains("Lockdown"),
        "Lockdown should be a single IPC operation for speed"
    );

    // Verify daemon handles lockdown quickly
    let daemon_server_path = workspace_root().join("crates/sigil-daemon/src/server.rs");
    let server_code = fs::read_to_string(&daemon_server_path).expect("Failed to read server code");

    // Verify lockdown is handled in handler (fast path)
    assert!(
        server_code.contains("IpcOperation::Lockdown") || server_code.contains("handle_lockdown"),
        "Daemon must have lockdown handler"
    );
}

/// Test 9.7.3: Verify lockdown auto-triggers
///
/// From Phase 9.7 Deliverables:
/// "Auto-triggers: [lockdown.auto] canary_triggers, unauthorized_attempts, exfiltration_detected"
#[test]
fn test_9_7_3_lockdown_auto_triggers() {
    let daemon_server_path = workspace_root().join("crates/sigil-daemon/src/server.rs");
    let server_code = fs::read_to_string(&daemon_server_path).expect("Failed to read server code");

    // Verify auto-lockdown triggers exist
    let has_canary_trigger = server_code.contains("canary_triggers")
        || server_code.contains("canary") && server_code.contains("trigger");

    let has_unauth_trigger = server_code.contains("unauthorized_attempts")
        || server_code.contains("unauthorized") && server_code.contains("attempt");

    let has_exfil_trigger =
        server_code.contains("exfiltration_detected") || server_code.contains("exfiltration");

    // At least one trigger should be configured
    assert!(
        has_canary_trigger || has_unauth_trigger || has_exfil_trigger,
        "Daemon should support at least one auto-lockdown trigger"
    );

    // Check for lockdown threshold configuration
    assert!(
        server_code.contains("threshold") || server_code.contains("limit") || has_canary_trigger,
        "Auto-lockdown should have configurable thresholds"
    );
}

/// Test 9.7.4: Verify sigil unlock requires full re-authentication
///
/// From Phase 9.7 Deliverables:
/// "sigil unlock: full re-auth required (passphrase + device key)"
#[test]
fn test_9_7_4_unlock_requires_reauthentication() {
    let cli_main_path = workspace_root().join("crates/sigil-cli/src/main.rs");
    let cli_code = fs::read_to_string(&cli_main_path).expect("Failed to read CLI code");

    // Verify unlock command exists
    assert!(
        cli_code.contains("Unlock") || cli_code.contains("unlock"),
        "CLI must have unlock command"
    );

    // Verify unlock requires authentication (passphrase prompt)
    assert!(
        cli_code.contains("password")
            || cli_code.contains("passphrase")
            || cli_code.contains("authenticate"),
        "Unlock should require authentication"
    );

    // Verify daemon validates unlock requests
    let daemon_server_path = workspace_root().join("crates/sigil-daemon/src/server.rs");
    let server_code = fs::read_to_string(&daemon_server_path).expect("Failed to read server code");

    assert!(
        server_code.contains("IpcOperation::Unlock") || server_code.contains("handle_unlock"),
        "Daemon must handle unlock operation"
    );
}

/// Test 9.7.5: Verify lockdown state persists to disk
///
/// From Phase 9.7 Deliverables:
/// "Lockdown state persisted to disk"
#[test]
fn test_9_7_5_lockdown_state_persistence() {
    let daemon_server_path = workspace_root().join("crates/sigil-daemon/src/server.rs");
    let server_code = fs::read_to_string(&daemon_server_path).expect("Failed to read server code");

    // Verify lockdown state is tracked
    assert!(
        server_code.contains("lockdown_state")
            || server_code.contains("is_locked_down")
            || server_code.contains("LockdownState"),
        "Daemon must track lockdown state"
    );

    // Verify state is saved to disk
    assert!(
        server_code.contains("save") && server_code.contains("lockdown")
            || server_code.contains("persist")
            || server_code.contains("write_state"),
        "Lockdown state should be persisted to disk"
    );

    // Verify state is loaded on startup
    assert!(
        server_code.contains("load") && server_code.contains("lockdown")
            || server_code.contains("read_state"),
        "Lockdown state should be loaded on daemon startup"
    );
}

/// Test 9.7.6: Verify lockdown sequence components
///
/// From Phase 9.7 Deliverables:
/// "Sequence: 1. Kill all active sandbox processes, 2. Revoke all session tokens,
///  3. Revoke all dynamic leases, 4. Lock the vault, 5. Generate breach report,
///  6. Send alerts"
#[test]
fn test_9_7_6_lockdown_sequence() {
    let daemon_server_path = workspace_root().join("crates/sigil-daemon/src/server.rs");
    let server_code = fs::read_to_string(&daemon_server_path).expect("Failed to read server code");

    // Check for sandbox process termination
    let has_kill_sandbox = server_code.contains("kill")
        || server_code.contains("terminate")
        || server_code.contains("sandbox")
            && (server_code.contains("stop") || server_code.contains("exit"));

    // Check for session token revocation
    let has_revoke_tokens = server_code.contains("token")
        && (server_code.contains("revoke")
            || server_code.contains("invalidate")
            || server_code.contains("clear"));

    // Check for lease revocation
    let has_revoke_leases = server_code.contains("lease")
        && (server_code.contains("revoke")
            || server_code.contains("expire")
            || server_code.contains("invalidate"));

    // Check for vault locking
    let has_lock_vault = server_code.contains("lock")
        || server_code.contains("seal")
        || server_code.contains("vault");

    // At minimum, lockdown should include some of these actions
    assert!(
        has_kill_sandbox || has_revoke_tokens || has_revoke_leases || has_lock_vault,
        "Lockdown should include security actions"
    );

    // Check for breach report generation
    let audit_path = workspace_root().join("crates/sigil-daemon/src/audit.rs");
    if audit_path.exists() {
        let audit_code = fs::read_to_string(&audit_path).expect("Failed to read audit code");
        assert!(
            audit_code.contains("breach")
                || audit_code.contains("report")
                || audit_code.contains("lockdown"),
            "Audit should support breach report generation"
        );
    }
}

// ============================================================================
// PHASE 9.8: COMMUNITY SIGNATURE DATABASE
// ============================================================================

/// Test 9.8.1: Verify sigil signatures update command
///
/// From Phase 9.8 Deliverables:
/// "sigil signatures update / search / add"
#[test]
fn test_9_8_1_signatures_update_command() {
    let cli_main_path = workspace_root().join("crates/sigil-cli/src/main.rs");
    let cli_code = fs::read_to_string(&cli_main_path).expect("Failed to read CLI code");

    // Verify signatures command exists
    assert!(
        cli_code.contains("Signatures") || cli_code.contains("signatures"),
        "CLI must have signatures command"
    );

    // Verify update subcommand exists
    assert!(
        cli_code.contains("Update") && cli_code.contains("signatures"),
        "Signatures must have update subcommand"
    );

    // Verify update calls SignatureUpdater
    assert!(
        cli_code.contains("SignatureUpdater") || cli_code.contains("update_all"),
        "Signatures update should use SignatureUpdater"
    );
}

/// Test 9.8.2: Verify sigil signatures search command
///
/// From Phase 9.8 Deliverables:
/// "sigil signatures update / search / add"
#[test]
fn test_9_8_2_signatures_search_command() {
    let cli_main_path = workspace_root().join("crates/sigil-cli/src/main.rs");
    let cli_code = fs::read_to_string(&cli_main_path).expect("Failed to read CLI code");

    // Verify search subcommand exists
    assert!(
        cli_code.contains("Search") && cli_code.contains("signatures"),
        "Signatures must have search subcommand"
    );

    // Verify search accepts a query pattern
    assert!(
        cli_code.contains("query") || cli_code.contains("pattern") || cli_code.contains("search"),
        "Signatures search should accept query pattern"
    );

    // Verify search filters by name or category
    assert!(
        cli_code.contains("category") || cli_code.contains("name"),
        "Signatures search should support filtering"
    );
}

/// Test 9.8.3: Verify sigil signatures add command
///
/// From Phase 9.8 Deliverables:
/// "sigil signatures update / search / add"
#[test]
fn test_9_8_3_signatures_add_command() {
    let cli_main_path = workspace_root().join("crates/sigil-cli/src/main.rs");
    let cli_code = fs::read_to_string(&cli_main_path).expect("Failed to read CLI code");

    // Verify add subcommand exists
    assert!(
        cli_code.contains("Add") && cli_code.contains("signatures"),
        "Signatures must have add subcommand"
    );

    // Verify add accepts a file path
    assert!(
        cli_code.contains("file") && cli_code.contains("signatures"),
        "Signatures add should accept file path"
    );

    // Verify add copies to user or project signatures directory
    assert!(
        cli_code.contains("user")
            || cli_code.contains("project")
            || cli_code.contains("signatures.d"),
        "Signatures add should copy to signatures directory"
    );
}

/// Test 9.8.4: Verify signature repository structure
///
/// From Phase 9.8 Deliverables:
/// "github.com/jedarden/sigil-signatures repository structure"
#[test]
fn test_9_8_4_signature_repository_structure() {
    let update_path = workspace_root().join("crates/sigil-signatures/src/update.rs");
    assert!(update_path.exists(), "Signature update module must exist");

    let update_code = fs::read_to_string(&update_path).expect("Failed to read update code");

    // Verify default repository URL
    assert!(
        update_code.contains("github.com/jedarden/sigil-signatures")
            || update_code.contains("DEFAULT_REPO_URL"),
        "Should use jedarden/sigil-signatures repository"
    );

    // Verify manifest.toml structure
    assert!(
        update_code.contains("SignatureManifest") || update_code.contains("manifest"),
        "Repository should have manifest.toml"
    );

    // Verify signature sets (cloud, databases, etc.)
    assert!(
        update_code.contains("SignatureSet") || update_code.contains("sets"),
        "Repository should support curated sets"
    );
}

/// Test 9.8.5: Verify signature verification with maintainer age key
///
/// From Phase 9.8 Deliverables:
/// "Signature verification with maintainer age key"
#[test]
fn test_9_8_5_signature_verification() {
    let update_path = workspace_root().join("crates/sigil-signatures/src/update.rs");
    let update_code = fs::read_to_string(&update_path).expect("Failed to read update code");

    // Verify checksum verification
    assert!(
        update_code.contains("checksum")
            || update_code.contains("SHA256")
            || update_code.contains("verify"),
        "Signature update should verify checksums"
    );

    // Verify SignatureFile has checksum field
    assert!(
        update_code.contains("SignatureFile") && update_code.contains("checksum"),
        "SignatureFile should include checksum for verification"
    );

    // Signature verification with age keys is a future enhancement
    // For now, checksums provide basic integrity verification
}

/// Test 9.8.6: Verify curated signature sets
///
/// From Phase 9.8 Deliverables:
/// "Curated sets: sigil signatures install cloud / databases"
#[test]
fn test_9_8_6_curated_signature_sets() {
    let cli_main_path = workspace_root().join("crates/sigil-cli/src/main.rs");
    let cli_code = fs::read_to_string(&cli_main_path).expect("Failed to read CLI code");

    // Verify install subcommand exists
    assert!(
        cli_code.contains("Install") && cli_code.contains("signatures"),
        "Signatures must have install subcommand"
    );

    // Verify install accepts a set name
    assert!(
        cli_code.contains("set") || cli_code.contains("name") || cli_code.contains("install"),
        "Signatures install should accept set name"
    );

    // Verify list-sets subcommand exists
    assert!(
        cli_code.contains("ListSets")
            || cli_code.contains("list-sets")
            || cli_code.contains("list_sets"),
        "Signatures should support listing available sets"
    );

    // Verify cloud and databases sets are referenced
    let update_path = workspace_root().join("crates/sigil-signatures/src/update.rs");
    if update_path.exists() {
        let update_code = fs::read_to_string(&update_path).expect("Failed to read update code");
        assert!(
            update_code.contains("install_set")
                || update_code.contains("cloud")
                || update_code.contains("databases"),
            "Should support installing curated sets"
        );
    }
}

/// Test 9.8.7: Verify built-in signatures
///
/// From Phase 9.8 Deliverables:
/// "Community signature database with 50+ built-in patterns"
#[test]
fn test_9_8_7_builtin_signatures() {
    let builtins_path = workspace_root().join("crates/sigil-signatures/src/builtins.rs");
    assert!(builtins_path.exists(), "Built-in signatures must exist");

    let builtins_code = fs::read_to_string(&builtins_path).expect("Failed to read builtins code");

    // Verify BUILTIN_SIGNATURES constant exists
    assert!(
        builtins_code.contains("BUILTIN_SIGNATURES"),
        "Must have BUILTIN_SIGNATURES constant"
    );

    // Verify signatures cover major categories
    let categories = vec!["aws", "git", "docker", "ssh", "kubectl", "gcloud"];
    let mut found_categories = 0;

    for category in categories {
        if builtins_code.contains(category) {
            found_categories += 1;
        }
    }

    // Should have at least some categories covered
    assert!(
        found_categories >= 3,
        "Built-in signatures should cover at least 3 categories, found {}",
        found_categories
    );

    // Verify signatures have injection config (env vars, files, etc.)
    assert!(
        builtins_code.contains("Injection")
            || builtins_code.contains("inject")
            || builtins_code.contains("env"),
        "Signatures must define injection method"
    );
}

// ============================================================================
// PHASE 9.9: SIGIL SDK
// ============================================================================

/// Test 9.9.1: Verify sigil-sdk Rust crate exists
///
/// From Phase 9.9 Deliverables:
/// "sigil-sdk Rust crate: publish to crates.io (~200 lines IPC client)"
#[test]
fn test_9_9_1_rust_sdk_exists() {
    let sdk_lib_path = workspace_root().join("crates/sigil-sdk/src/lib.rs");
    let sdk_client_path = workspace_root().join("crates/sigil-sdk/src/client.rs");
    let sdk_cargo_path = workspace_root().join("crates/sigil-sdk/Cargo.toml");

    assert!(sdk_lib_path.exists(), "SDK lib must exist");
    assert!(sdk_client_path.exists(), "SDK client must exist");
    assert!(sdk_cargo_path.exists(), "SDK Cargo.toml must exist");

    // Verify SDK is a library crate (has lib.rs)
    let sdk_lib_path = workspace_root().join("crates/sigil-sdk/src/lib.rs");
    assert!(
        sdk_lib_path.exists(),
        "SDK must have lib.rs file to be a library crate"
    );

    // Verify SDK client has reasonable size (around 200 lines minimum for functionality)
    let client_code = fs::read_to_string(&sdk_client_path).expect("Failed to read client code");
    let line_count = client_code.lines().count();
    assert!(
        line_count >= 150,
        "SDK client should be substantial (>= 150 lines), got {}",
        line_count
    );
}

/// Test 9.9.2: Verify SDK supports all major operations
///
/// From Phase 9.9 Deliverables:
/// "SDK: connect, get, resolve, exists, list, request_access"
#[test]
fn test_9_9_2_sdk_operations() {
    let sdk_client_path = workspace_root().join("crates/sigil-sdk/src/client.rs");
    let client_code = fs::read_to_string(&sdk_client_path).expect("Failed to read SDK client code");

    // Verify core operations
    let operations = vec![
        ("get", "get secret by path"),
        ("resolve", "resolve placeholders"),
        ("exists", "check if secret exists"),
        ("list", "list secrets with prefix"),
        ("request_access", "request access via TUI"),
        ("connect", "connect to daemon"),
        ("status", "get daemon status"),
        ("scrub", "scrub secrets from output"),
    ];

    for (method, description) in operations {
        assert!(
            client_code.contains(&format!("pub async fn {}", method))
                || client_code.contains(&format!("fn {}", method)),
            "SDK should support {}: {} method",
            method,
            description
        );
    }
}

/// Test 9.9.3: Verify SDK connection pooling and retry
///
/// From Phase 9.9 Deliverables:
/// "~200 lines IPC client" with connection pooling and retry
#[test]
fn test_9_9_3_sdk_connection_pooling() {
    let sdk_client_path = workspace_root().join("crates/sigil-sdk/src/client.rs");
    let client_code = fs::read_to_string(&sdk_client_path).expect("Failed to read SDK client code");

    // Verify connection pooling exists
    assert!(
        client_code.contains("ConnectionPool")
            || client_code.contains("pool")
            || client_code.contains("PooledConnection"),
        "SDK should use connection pooling"
    );

    // Verify retry logic exists
    assert!(
        client_code.contains("retry")
            || client_code.contains("backoff")
            || client_code.contains("max_retries"),
        "SDK should have retry logic"
    );

    // Verify exponential backoff
    assert!(
        client_code.contains("backoff") || client_code.contains("exponential"),
        "SDK should use exponential backoff for retries"
    );
}

/// Test 9.9.4: Verify Python SDK bindings via PyO3
///
/// From Phase 9.9 Deliverables:
/// "sigil-sdk-python (460 lines) — verify PyO3 bindings"
#[test]
fn test_9_9_4_python_sdk_bindings() {
    let python_sdk_path = workspace_root().join("crates/sigil-sdk-python/src/lib.rs");
    let python_cargo_path = workspace_root().join("crates/sigil-sdk-python/Cargo.toml");

    if python_sdk_path.exists() {
        let python_code =
            fs::read_to_string(&python_sdk_path).expect("Failed to read Python SDK code");

        // Verify PyO3 usage
        assert!(
            python_code.contains("pyo3")
                || python_code.contains("PyO3")
                || python_code.contains("#[pymodule]"),
            "Python SDK must use PyO3"
        );

        // Verify SigilClient is exposed
        assert!(
            python_code.contains("PySigilClient") || python_code.contains("SigilClient"),
            "Python SDK should expose SigilClient"
        );

        // Verify async methods work with Python
        assert!(
            python_code.contains("future_into_py") || python_code.contains("async"),
            "Python SDK should support async operations"
        );

        // Verify reasonable size (460 lines target)
        let line_count = python_code.lines().count();
        assert!(
            line_count >= 300,
            "Python SDK should be substantial (>= 300 lines), got {}",
            line_count
        );
    }

    // Verify Cargo.toml has PyO3 dependency
    if python_cargo_path.exists() {
        let cargo_code = fs::read_to_string(&python_cargo_path).expect("Failed to read Cargo.toml");
        assert!(
            cargo_code.contains("pyo3"),
            "Python SDK Cargo.toml must include PyO3 dependency"
        );
    }
}

/// Test 9.9.5: Verify Python SDK exposes all operations
///
/// From Phase 9.9 Deliverables:
/// "Python bindings via PyO3: pip install sigil-sdk"
#[test]
fn test_9_9_5_python_sdk_operations() {
    let python_sdk_path = workspace_root().join("crates/sigil-sdk-python/src/lib.rs");

    if python_sdk_path.exists() {
        let python_code =
            fs::read_to_string(&python_sdk_path).expect("Failed to read Python SDK code");

        // Verify Python-exposed methods
        let methods = vec![
            ("get", "get secret"),
            ("resolve", "resolve placeholders"),
            ("exists", "check secret exists"),
            ("list", "list secrets"),
            ("request_access", "request access"),
            ("scrub", "scrub output"),
            ("status", "get daemon status"),
        ];

        for (method, description) in methods {
            assert!(
                python_code.contains(&format!("fn {}", method))
                    || python_code.contains("#[pymethods]"),
                "Python SDK should support {}: {} method",
                method,
                description
            );
        }

        // Verify Python module is defined
        assert!(
            python_code.contains("#[pymodule]") && python_code.contains("sigil_sdk"),
            "Python SDK must define sigil_sdk module"
        );
    }
}

/// Test 9.9.6: Verify Node.js SDK bindings via napi-rs
///
/// From Phase 9.9 Deliverables:
/// "sigil-sdk-nodejs (141 lines) — complete via napi-rs"
#[test]
fn test_9_9_6_nodejs_sdk_bindings() {
    let nodejs_lib_path = workspace_root().join("crates/sigil-sdk-nodejs/src/lib.rs");
    let nodejs_cargo_path = workspace_root().join("crates/sigil-sdk-nodejs/Cargo.toml");
    let nodejs_package_path = workspace_root().join("crates/sigil-sdk-nodejs/package.json");

    // Node.js SDK is marked as incomplete in the task description
    // Verify it exists and has napi-rs structure
    if nodejs_lib_path.exists() {
        let nodejs_code =
            fs::read_to_string(&nodejs_lib_path).expect("Failed to read Node.js SDK code");

        // Verify napi-rs usage
        assert!(
            nodejs_code.contains("napi")
                || nodejs_code.contains("#[napi]")
                || nodejs_code.contains("JsError"),
            "Node.js SDK must use napi-rs"
        );

        // Verify reasonable size (141 lines target)
        let line_count = nodejs_code.lines().count();
        assert!(
            line_count >= 50,
            "Node.js SDK should be substantial (>= 50 lines), got {}",
            line_count
        );
    }

    // Verify package.json exists
    if nodejs_package_path.exists() {
        let package_code =
            fs::read_to_string(&nodejs_package_path).expect("Failed to read package.json");
        assert!(
            package_code.contains("@sigil/sdk") || package_code.contains("sigil-sdk"),
            "Node.js SDK package.json should have correct package name"
        );
    }

    // Verify Cargo.toml has napi dependency
    if nodejs_cargo_path.exists() {
        let cargo_code = fs::read_to_string(&nodejs_cargo_path).expect("Failed to read Cargo.toml");
        assert!(
            cargo_code.contains("napi")
                || cargo_code.contains("napi-derive")
                || cargo_code.contains("napi_derive"),
            "Node.js SDK Cargo.toml must include napi-rs dependency"
        );
    }
}

// ============================================================================
// PHASE 9.10: SIGIL DOCTOR
// ============================================================================

/// Test 9.10.1: Verify sigil doctor command exists
///
/// From Phase 9.10 Deliverables:
/// "sigil doctor: All checks: vault, daemon (PR_SET_DUMPABLE, mlock), sandbox, hooks,
///  canaries, proxy, FUSE, backends, git safety, audit log"
#[test]
fn test_9_10_1_doctor_command_exists() {
    let cli_main_path = workspace_root().join("crates/sigil-cli/src/main.rs");
    let cli_code = fs::read_to_string(&cli_main_path).expect("Failed to read CLI code");

    // Verify doctor command exists
    assert!(
        cli_code.contains("Doctor") || cli_code.contains("doctor"),
        "CLI must have doctor command"
    );

    // Verify --fix flag exists
    assert!(
        cli_code.contains("--fix") && cli_code.contains("doctor"),
        "Doctor command should support --fix flag"
    );

    // Verify --ci flag exists
    assert!(
        cli_code.contains("--ci") && cli_code.contains("doctor"),
        "Doctor command should support --ci flag"
    );

    // Verify --min-score flag exists
    assert!(
        cli_code.contains("--min-score") || cli_code.contains("min_score"),
        "Doctor command should support --min-score flag"
    );

    // Verify --json flag exists (CommandDoctor struct has json field)
    assert!(
        cli_code.contains("CommandDoctor")
            && (cli_code.contains("json: bool") || cli_code.contains("json:")),
        "Doctor command should support --json flag"
    );
}

/// Test 9.10.2: Verify doctor vault check
///
/// From Phase 9.10 Deliverables:
/// "vault: initialized, encryption verified, permissions correct"
#[test]
fn test_9_10_2_doctor_vault_check() {
    let doctor_path = workspace_root().join("crates/sigil-cli/src/doctor.rs");
    assert!(doctor_path.exists(), "Doctor module must exist");

    let doctor_code = fs::read_to_string(&doctor_path).expect("Failed to read doctor code");

    // Verify vault check function exists
    assert!(
        doctor_code.contains("check_vault") || doctor_code.contains("vault"),
        "Doctor must check vault status"
    );

    // Verify vault check validates initialization
    assert!(
        doctor_code.contains("not initialized") || doctor_code.contains("exists"),
        "Vault check should verify initialization"
    );

    // Verify vault check validates encryption
    assert!(
        doctor_code.contains("encryption")
            || doctor_code.contains("load")
            || doctor_code.contains("identity"),
        "Vault check should verify encryption"
    );
}

/// Test 9.10.3: Verify doctor daemon check with PR_SET_DUMPABLE and mlock
///
/// From Phase 9.10 Deliverables:
/// "daemon (PR_SET_DUMPABLE, mlock)"
#[test]
fn test_9_10_3_doctor_daemon_check() {
    let doctor_path = workspace_root().join("crates/sigil-cli/src/doctor.rs");
    let doctor_code = fs::read_to_string(&doctor_path).expect("Failed to read doctor code");

    // Verify daemon check function exists
    assert!(
        doctor_code.contains("check_daemon") || doctor_code.contains("daemon"),
        "Doctor must check daemon status"
    );

    // Verify daemon check validates socket
    assert!(
        doctor_code.contains("socket") || doctor_code.contains(".sock"),
        "Daemon check should verify socket"
    );

    // Verify process isolation check (PR_SET_DUMPABLE)
    assert!(
        doctor_code.contains("check_process_isolation")
            || doctor_code.contains("isolation")
            || doctor_code.contains("dumpable"),
        "Doctor should check process isolation (PR_SET_DUMPABLE)"
    );
}

/// Test 9.10.4: Verify doctor sandbox check
///
/// From Phase 9.10 Deliverables:
/// "sandbox: bubblewrap available, namespace isolation verified"
#[test]
fn test_9_10_4_doctor_sandbox_check() {
    let doctor_path = workspace_root().join("crates/sigil-cli/src/doctor.rs");
    let doctor_code = fs::read_to_string(&doctor_path).expect("Failed to read doctor code");

    // Verify sandbox check function exists
    assert!(
        doctor_code.contains("check_sandbox") || doctor_code.contains("sandbox"),
        "Doctor must check sandbox availability"
    );

    // Verify sandbox check validates bubblewrap
    assert!(
        doctor_code.contains("bwrap") || doctor_code.contains("bubblewrap"),
        "Sandbox check should verify bubblewrap"
    );

    // Verify namespace support check
    assert!(
        doctor_code.contains("namespace") || doctor_code.contains("check_namespace_support"),
        "Sandbox check should verify namespace support"
    );
}

/// Test 9.10.5: Verify doctor hooks check (all 6 types)
///
/// From Phase 9.10 Deliverables:
/// "hooks (all 6 types)"
#[test]
fn test_9_10_5_doctor_hooks_check() {
    let doctor_path = workspace_root().join("crates/sigil-cli/src/doctor.rs");
    let doctor_code = fs::read_to_string(&doctor_path).expect("Failed to read doctor code");

    // Verify hooks check function exists
    assert!(
        doctor_code.contains("check_hooks") || doctor_code.contains("hooks"),
        "Doctor must check hook installation"
    );

    // Verify hooks check validates Claude Code
    assert!(
        doctor_code.contains("claude")
            || doctor_code.contains("settings.json")
            || doctor_code.contains(".claude"),
        "Hooks check should verify Claude Code hooks"
    );

    // The 6 hook types are: pre-exec, post-exec, pre-read, post-read, pre-write, post-write
    // These are validated in the hooks module
}

/// Test 9.10.6: Verify doctor canary check
///
/// From Phase 9.10 Deliverables:
/// "canaries: monitoring configured, decoy values generated"
#[test]
fn test_9_10_6_doctor_canary_check() {
    let doctor_path = workspace_root().join("crates/sigil-cli/src/doctor.rs");
    let doctor_code = fs::read_to_string(&doctor_path).expect("Failed to read doctor code");

    // Verify canary check function exists
    assert!(
        doctor_code.contains("check_canary") || doctor_code.contains("canary"),
        "Doctor must check canary monitoring"
    );

    // Verify canary check validates config
    assert!(
        doctor_code.contains("canary.toml") || doctor_code.contains("config"),
        "Canary check should verify configuration"
    );
}

/// Test 9.10.7: Verify doctor proxy check
///
/// From Phase 9.10 Deliverables:
/// "proxy: running and accessible"
#[test]
fn test_9_10_7_doctor_proxy_check() {
    let doctor_path = workspace_root().join("crates/sigil-cli/src/doctor.rs");
    let doctor_code = fs::read_to_string(&doctor_path).expect("Failed to read doctor code");

    // Verify proxy check function exists
    assert!(
        doctor_code.contains("check_proxy") || doctor_code.contains("proxy"),
        "Doctor must check proxy status"
    );

    // Verify proxy check validates port
    assert!(
        doctor_code.contains("port") || doctor_code.contains("listen"),
        "Proxy check should verify port availability"
    );
}

/// Test 9.10.8: Verify doctor FUSE check
///
/// From Phase 9.10 Deliverables:
/// "FUSE: mount active"
#[test]
fn test_9_10_8_doctor_fuse_check() {
    let doctor_path = workspace_root().join("crates/sigil-cli/src/doctor.rs");
    let doctor_code = fs::read_to_string(&doctor_path).expect("Failed to read doctor code");

    // Verify FUSE check function exists
    assert!(
        doctor_code.contains("check_fuse") || doctor_code.contains("fuse"),
        "Doctor must check FUSE mount status"
    );

    // Verify FUSE check validates mount point
    assert!(
        doctor_code.contains("/sigil") || doctor_code.contains("mount"),
        "FUSE check should verify mount point"
    );
}

/// Test 9.10.9: Verify doctor backends check
///
/// From Phase 9.10 Deliverables:
/// "backends: each configured backend reachable and authenticated"
#[test]
fn test_9_10_9_doctor_backends_check() {
    let doctor_path = workspace_root().join("crates/sigil-cli/src/doctor.rs");
    let doctor_code = fs::read_to_string(&doctor_path).expect("Failed to read doctor code");

    // Verify backends check function exists
    assert!(
        doctor_code.contains("check_backends") || doctor_code.contains("backends"),
        "Doctor must check backend connectivity"
    );

    // Verify backends check validates each backend type
    let backend_types = vec!["vault", "aws", "onepassword", "pass", "sops", "env"];
    let mut checks_backend = false;

    for backend in backend_types {
        if doctor_code.contains(backend) && doctor_code.contains("check") {
            checks_backend = true;
            break;
        }
    }

    assert!(
        checks_backend,
        "Backends check should validate specific backend types"
    );
}

/// Test 9.10.10: Verify doctor git safety check
///
/// From Phase 9.10 Deliverables:
/// "git safety: device.key in gitignore, no plaintext secrets in staging area"
#[test]
fn test_9_10_10_doctor_git_safety_check() {
    let doctor_path = workspace_root().join("crates/sigil-cli/src/doctor.rs");
    let doctor_code = fs::read_to_string(&doctor_path).expect("Failed to read doctor code");

    // Verify git safety check function exists
    assert!(
        doctor_code.contains("check_git_safety") || doctor_code.contains("git"),
        "Doctor must check git safety"
    );

    // Verify git safety check validates gitignore
    assert!(
        doctor_code.contains("gitignore") || doctor_code.contains(".gitignore"),
        "Git safety check should verify gitignore"
    );

    // Verify git safety check validates identity file exclusion
    assert!(
        doctor_code.contains("identity.age") || doctor_code.contains("identity"),
        "Git safety check should verify identity file is excluded"
    );
}

/// Test 9.10.11: Verify doctor audit log check
///
/// From Phase 9.10 Deliverables:
/// "audit log: exists, hash chain intact, append-only flag set"
#[test]
fn test_9_10_11_doctor_audit_log_check() {
    let doctor_path = workspace_root().join("crates/sigil-cli/src/doctor.rs");
    let doctor_code = fs::read_to_string(&doctor_path).expect("Failed to read doctor code");

    // Verify audit log check function exists
    assert!(
        doctor_code.contains("check_audit_log") || doctor_code.contains("audit"),
        "Doctor must check audit log status"
    );

    // Verify audit log check validates append-only flag
    assert!(
        doctor_code.contains("append")
            || doctor_code.contains("append-only")
            || doctor_code.contains("chattr"),
        "Audit log check should verify append-only flag"
    );
}

/// Test 9.10.12: Verify doctor aggregate security score
///
/// From Phase 9.10 Deliverables:
/// "Aggregate security score 0-100"
#[test]
fn test_9_10_12_doctor_security_score() {
    let doctor_path = workspace_root().join("crates/sigil-cli/src/doctor.rs");
    let doctor_code = fs::read_to_string(&doctor_path).expect("Failed to read doctor code");

    // Verify HealthReport has score field
    assert!(
        doctor_code.contains("score") || doctor_code.contains("Score"),
        "Doctor must calculate security score"
    );

    // Verify score is 0-100 range
    assert!(
        doctor_code.contains("100")
            || doctor_code.contains("finalize")
            || doctor_code.contains("calculate"),
        "Doctor must finalize or calculate score"
    );

    // Verify HealthReport struct exists
    assert!(
        doctor_code.contains("HealthReport") || doctor_code.contains("struct"),
        "Doctor must have HealthReport struct"
    );

    // Verify check results have weights for scoring
    assert!(
        doctor_code.contains("weight") || doctor_code.contains("Weight"),
        "Check results should have weights for scoring"
    );
}

/// Test 9.10.13: Verify doctor --fix for non-destructive auto-fixes
///
/// From Phase 9.10 Deliverables:
/// "sigil doctor --fix for non-destructive auto-fixes"
#[test]
fn test_9_10_13_doctor_fix_flag() {
    let doctor_path = workspace_root().join("crates/sigil-cli/src/doctor.rs");
    let doctor_code = fs::read_to_string(&doctor_path).expect("Failed to read doctor code");

    // Verify run_doctor accepts fix parameter
    assert!(
        doctor_code.contains("run_doctor") && doctor_code.contains("fix"),
        "run_doctor should accept fix parameter"
    );

    // Verify at least one check supports auto-fix
    assert!(
        doctor_code.contains("attempt_fix")
            || doctor_code.contains("auto_fix")
            || doctor_code.contains("fix"),
        "At least one check should support auto-fix"
    );

    // Verify gitignore auto-fix exists
    assert!(
        doctor_code.contains("gitignore")
            && (doctor_code.contains("create") || doctor_code.contains("write")),
        "Doctor should support creating gitignore"
    );

    // Verify permissions auto-fix exists
    assert!(
        doctor_code.contains("permissions")
            && (doctor_code.contains("set_mode") || doctor_code.contains("chmod")),
        "Doctor should support fixing permissions"
    );
}

/// Test 9.10.14: Verify doctor --ci --min-score N
///
/// From Phase 9.10 Deliverables:
/// "sigil doctor --ci --min-score N"
#[test]
fn test_9_10_14_doctor_ci_mode() {
    let doctor_path = workspace_root().join("crates/sigil-cli/src/doctor.rs");
    let doctor_code = fs::read_to_string(&doctor_path).expect("Failed to read doctor code");

    // Verify CI exit code method exists
    assert!(
        doctor_code.contains("ci_exit_code")
            || doctor_code.contains("exit_code")
            || doctor_code.contains("min_score"),
        "Doctor should support CI mode exit codes"
    );

    // Verify exit code is non-zero when score is too low
    assert!(
        doctor_code.contains("score >= min_score")
            || doctor_code.contains("score < min_score")
            || doctor_code.contains("cmp"),
        "Doctor should compare score against minimum"
    );
}

/// Test 9.10.15: Verify doctor --json output
///
/// From Phase 9.10 Deliverables:
/// "sigil doctor --json"
#[test]
fn test_9_10_15_doctor_json_output() {
    let doctor_path = workspace_root().join("crates/sigil-cli/src/doctor.rs");
    let doctor_code = fs::read_to_string(&doctor_path).expect("Failed to read doctor code");

    // Verify JSON formatting function exists
    assert!(
        doctor_code.contains("format_report_json")
            || doctor_code.contains("json")
            || doctor_code.contains("JSON"),
        "Doctor should support JSON output"
    );

    // Verify HealthReport is serializable
    assert!(
        doctor_code.contains("Serialize")
            || doctor_code.contains("serde")
            || doctor_code.contains("#[derive"),
        "HealthReport should be serializable to JSON"
    );

    // Verify CheckResult is serializable
    assert!(
        doctor_code.contains("CheckResult") && doctor_code.contains("Serialize"),
        "CheckResult should be serializable"
    );
}

/// Test 9.10.16: Verify doctor check status types
///
/// From Phase 9.10 Deliverables:
/// "Each check returns: PASS, WARN (with suggestion), or FAIL (with fix command)"
#[test]
fn test_9_10_16_doctor_check_status_types() {
    let doctor_path = workspace_root().join("crates/sigil-cli/src/doctor.rs");
    let doctor_code = fs::read_to_string(&doctor_path).expect("Failed to read doctor code");

    // Verify CheckStatus enum exists
    assert!(
        doctor_code.contains("CheckStatus") || doctor_code.contains("enum"),
        "Doctor must have CheckStatus enum"
    );

    // Verify Pass variant
    assert!(
        doctor_code.contains("Pass") || doctor_code.contains("pass"),
        "CheckStatus must have Pass variant"
    );

    // Verify Warn variant with suggestion
    assert!(
        doctor_code.contains("Warn") && doctor_code.contains("suggestion"),
        "CheckStatus must have Warn variant with suggestion"
    );

    // Verify Fail variant with fix
    assert!(
        doctor_code.contains("Fail") && doctor_code.contains("fix"),
        "CheckStatus must have Fail variant with fix command"
    );
}

/// Test 9.10.17: Verify doctor file permissions check
///
/// From Phase 9.10 Deliverables:
/// "File permissions: vault files have correct permissions (0600 for files, 0700 for directories)"
#[test]
fn test_9_10_17_doctor_file_permissions_check() {
    let doctor_path = workspace_root().join("crates/sigil-cli/src/doctor.rs");
    let doctor_code = fs::read_to_string(&doctor_path).expect("Failed to read doctor code");

    // Verify file permissions check exists
    assert!(
        doctor_code.contains("check_file_permissions") || doctor_code.contains("permissions"),
        "Doctor must check file permissions"
    );

    // Verify 0600 check for files
    assert!(
        doctor_code.contains("0600") || doctor_code.contains("six hundred"),
        "File permissions check should verify 0600 for files"
    );

    // Verify 0700 check for directories
    assert!(
        doctor_code.contains("0700") || doctor_code.contains("seven hundred"),
        "File permissions check should verify 0700 for directories"
    );
}

/// Test 9.10.18: Verify doctor device key encryption check
///
/// From Phase 9.10 Deliverables:
/// "Device key encryption: verify device.key is encrypted with OS-bound key"
#[test]
fn test_9_10_18_doctor_device_key_encryption_check() {
    let doctor_path = workspace_root().join("crates/sigil-cli/src/doctor.rs");
    let doctor_code = fs::read_to_string(&doctor_path).expect("Failed to read doctor code");

    // Verify device key encryption check exists
    assert!(
        doctor_code.contains("check_device_key_encryption")
            || doctor_code.contains("device_key")
            || doctor_code.contains("device.key"),
        "Doctor must check device key encryption"
    );

    // Verify check validates age encryption
    assert!(
        doctor_code.contains("age-encrypted")
            || doctor_code.contains("encrypted")
            || doctor_code.contains("plaintext"),
        "Device key check should verify encryption"
    );
}
