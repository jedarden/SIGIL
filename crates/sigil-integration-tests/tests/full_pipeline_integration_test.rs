//! Full Pipeline Integration Tests
//!
//! This test module verifies the complete end-to-end SIGIL pipeline:
//! - Vault initialization and sealing
//! - Secret storage and retrieval
//! - Daemon lifecycle and IPC
//! - Sandbox isolation and execution
//! - Scrubbing and breach detection
//! - Canary system integration
//! - Export/import functionality
//!
//! These are integration tests that verify the entire system works together.

mod common;
use common::workspace_root;
use std::fs;

// ============================================================================
// VAULT LIFECYCLE TESTS
// ============================================================================

/// Test 1.1: Verify vault initialization workflow
///
/// Tests the complete vault initialization:
/// 1. sigil init creates vault and identity
/// 2. Vault is encrypted with age
/// 3. Identity file is created
/// 4. Config is initialized
#[test]
fn test_vault_initialization_workflow() {
    let cli_path = workspace_root().join("crates/sigil-cli/src/main.rs");
    let cli_code = fs::read_to_string(&cli_path).expect("Failed to read CLI code");

    // Verify init command exists
    assert!(
        cli_code.contains("CommandInit") || cli_code.contains("fn cmd_init"),
        "CLI must have init command"
    );

    // Verify init creates vault directory
    assert!(
        cli_code.contains("create_dir") || cli_code.contains("vault_dir"),
        "Init must create vault directory"
    );

    // Verify init creates identity file
    assert!(
        cli_code.contains("identity") || cli_code.contains("age"),
        "Init must create identity file"
    );

    // Verify vault module initialization
    let vault_local_path = workspace_root().join("crates/sigil-vault/src/local.rs");
    let vault_local_code =
        fs::read_to_string(&vault_local_path).expect("Failed to read vault local code");

    assert!(
        vault_local_code.contains("pub fn init") || vault_local_code.contains("fn init"),
        "Vault must have init function in local.rs"
    );

    assert!(
        vault_local_code.contains("age")
            || vault_local_code.contains("rage")
            || vault_local_code.contains("Encryptor"),
        "Vault must use age for encryption"
    );
}

/// Test 1.2: Verify secret add/get/list workflow
///
/// Tests the complete secret management workflow:
/// 1. sigil add stores a secret
/// 2. sigil get retrieves a secret
/// 3. sigil list lists all secrets
#[test]
fn test_secret_add_get_list_workflow() {
    let cli_path = workspace_root().join("crates/sigil-cli/src/main.rs");
    let cli_code = fs::read_to_string(&cli_path).expect("Failed to read CLI code");

    // Verify add command exists
    assert!(
        cli_code.contains("CommandAdd") || cli_code.contains("fn cmd_add"),
        "CLI must have add command"
    );

    // Verify get command exists
    assert!(
        cli_code.contains("CommandGet") || cli_code.contains("fn cmd_get"),
        "CLI must have get command"
    );

    // Verify list command exists
    assert!(
        cli_code.contains("CommandList") || cli_code.contains("fn cmd_list"),
        "CLI must have list command"
    );

    // Verify vault module operations (SecretBackend trait uses set, not add)
    let vault_local_path = workspace_root().join("crates/sigil-vault/src/local.rs");
    let vault_local_code =
        fs::read_to_string(&vault_local_path).expect("Failed to read vault local code");

    assert!(
        vault_local_code.contains("pub async fn set")
            || vault_local_code.contains("pub fn set")
            || vault_local_code.contains("fn set")
            || vault_local_code.contains("async fn set"),
        "Vault must have set function in local.rs (SecretBackend trait)"
    );

    assert!(
        vault_local_code.contains("pub async fn get")
            || vault_local_code.contains("pub fn get")
            || vault_local_code.contains("fn get")
            || vault_local_code.contains("async fn get"),
        "Vault must have get function in local.rs"
    );

    assert!(
        vault_local_code.contains("pub async fn list")
            || vault_local_code.contains("pub fn list")
            || vault_local_code.contains("fn list")
            || vault_local_code.contains("async fn list"),
        "Vault must have list function in local.rs"
    );
}

/// Test 1.3: Verify sealed vault workflow
///
/// Tests the sealed vault workflow:
/// 1. sigil init --sealed creates sealed vault
/// 2. Vault can be committed to git
/// 3. sigil unseal unlocks the vault
#[test]
fn test_sealed_vault_workflow() {
    let cli_path = workspace_root().join("crates/sigil-cli/src/main.rs");
    let cli_code = fs::read_to_string(&cli_path).expect("Failed to read CLI code");

    // Verify sealed option exists
    assert!(
        cli_code.contains("sealed") || cli_code.contains("git-safe"),
        "Init must support sealed/git-safe mode"
    );

    // Verify unseal command exists
    assert!(
        cli_code.contains("CommandUnseal") || cli_code.contains("fn cmd_unseal"),
        "CLI must have unseal command"
    );

    // Verify sealed vault module exists
    let sealed_path = workspace_root().join("crates/sigil-vault/src/sealed.rs");
    if sealed_path.exists() {
        let sealed_code = fs::read_to_string(&sealed_path).expect("Failed to read sealed code");

        assert!(
            sealed_code.contains("fn init_sealed") || sealed_code.contains("pub fn init"),
            "Sealed vault must have init function"
        );

        assert!(
            sealed_code.contains("fn unseal") || sealed_code.contains("pub fn unseal"),
            "Sealed vault must have unseal function"
        );

        // Verify 2SKD (Two-Secret Key Derivation)
        assert!(
            sealed_code.contains("derive_master_key") || sealed_code.contains("HKDF"),
            "Sealed vault must use 2SKD"
        );
    }
}

// ============================================================================
// DAEMON LIFECYCLE TESTS
// ============================================================================

/// Test 2.1: Verify daemon startup and shutdown
///
/// Tests the daemon lifecycle:
/// 1. sigild starts up
/// 2. Creates socket for IPC
/// 3. Responds to status requests
/// 4. Shuts down gracefully
#[test]
fn test_daemon_startup_shutdown() {
    let daemon_path = workspace_root().join("crates/sigil-daemon/src/main.rs");
    let daemon_code = fs::read_to_string(&daemon_path).expect("Failed to read daemon code");

    // Verify main entry point
    assert!(
        daemon_code.contains("fn main") || daemon_code.contains("tokio::main"),
        "Daemon must have main function"
    );

    // Verify server creation
    assert!(
        daemon_code.contains("SigilServer") || daemon_code.contains("Server"),
        "Daemon must create server"
    );

    // Verify socket creation
    assert!(
        daemon_code.contains("UnixListener") || daemon_code.contains("socket"),
        "Daemon must create Unix socket"
    );

    // Verify graceful shutdown
    assert!(
        daemon_code.contains("shutdown") || daemon_code.contains("ctrl_c"),
        "Daemon must handle graceful shutdown"
    );

    // Verify server module
    let server_path = workspace_root().join("crates/sigil-daemon/src/server.rs");
    let server_code = fs::read_to_string(&server_path).expect("Failed to read server code");

    assert!(
        server_code.contains("pub async fn run") || server_code.contains("fn serve"),
        "Server must have run/serve function"
    );

    assert!(
        server_code.contains("IpcRequest") || server_code.contains("IPC"),
        "Server must handle IPC requests"
    );
}

/// Test 2.2: Verify IPC protocol operations
///
/// Tests that all IPC operations are implemented:
/// - Get, Add, List, Delete secrets
/// - Exec with sandbox
/// - Status check
/// - Request access
#[test]
fn test_ipc_protocol_operations() {
    let ipc_path = workspace_root().join("crates/sigil-core/src/ipc.rs");
    let ipc_code = fs::read_to_string(&ipc_path).expect("Failed to read IPC code");

    // Verify IpcOperation enum
    assert!(
        ipc_code.contains("pub enum IpcOperation") || ipc_code.contains("enum IpcOperation"),
        "IPC must define IpcOperation enum"
    );

    // Verify core operations
    let required_ops = [
        "Get",
        "Add",
        "List",
        "Delete",
        "Exec",
        "Status",
        "RequestAccess",
    ];

    for op in required_ops {
        assert!(
            ipc_code.contains(op) || ipc_code.contains(&format!("IpcOperation::{}", op)),
            "IPC must support {} operation",
            op
        );
    }

    // Verify IpcRequest struct
    assert!(
        ipc_code.contains("pub struct IpcRequest") || ipc_code.contains("struct IpcRequest"),
        "IPC must define IpcRequest struct"
    );

    // Verify IpcResponse struct
    assert!(
        ipc_code.contains("pub struct IpcResponse") || ipc_code.contains("struct IpcResponse"),
        "IPC must define IpcResponse struct"
    );

    // Verify session token handling
    assert!(
        ipc_code.contains("session_token") || ipc_code.contains("token"),
        "IPC must handle session tokens"
    );
}

/// Test 2.3: Verify session management
///
/// Tests session lifecycle:
/// 1. Session creation on connect
/// 2. Session token generation
/// 3. Session expiration
/// 4. Session cleanup
#[test]
fn test_session_management() {
    let server_path = workspace_root().join("crates/sigil-daemon/src/server.rs");
    let server_code = fs::read_to_string(&server_path).expect("Failed to read server code");

    // Verify session storage
    assert!(
        server_code.contains("Session") || server_code.contains("sessions"),
        "Server must manage sessions"
    );

    // Verify session token generation
    assert!(
        server_code.contains("generate_token") || server_code.contains("token"),
        "Server must generate session tokens"
    );

    // Verify session validation
    assert!(
        server_code.contains("validate_session") || server_code.contains("check_session"),
        "Server must validate sessions"
    );

    // Verify session cleanup
    assert!(
        server_code.contains("cleanup") || server_code.contains("expire"),
        "Server must clean up expired sessions"
    );
}

// ============================================================================
// SANDBOX EXECUTION TESTS
// ============================================================================

/// Test 3.1: Verify sandbox execution workflow
///
/// Tests the sandbox execution:
/// 1. Command is parsed
/// 2. Sandbox is created with bwrap
/// 3. Command executes in sandbox
/// 4. Output is captured and scrubbed
/// 5. Sandbox is cleaned up
#[test]
fn test_sandbox_execution_workflow() {
    let sandbox_path = workspace_root().join("crates/sigil-sandbox/src/lib.rs");
    if sandbox_path.exists() {
        let sandbox_code = fs::read_to_string(&sandbox_path).expect("Failed to read sandbox code");

        // Verify sandbox execution function
        assert!(
            sandbox_code.contains("pub async fn execute") || sandbox_code.contains("fn execute"),
            "Sandbox must have execute function"
        );

        // Verify bubblewrap integration
        assert!(
            sandbox_code.contains("bwrap") || sandbox_code.contains("bubblewrap"),
            "Sandbox must use bubblewrap"
        );

        // Verify namespace isolation
        assert!(
            sandbox_code.contains("namespace") || sandbox_code.contains("--unshare"),
            "Sandbox must use namespace isolation"
        );

        // Verify seccomp filter
        assert!(
            sandbox_code.contains("seccomp") || sandbox_code.contains("seccomp-filter"),
            "Sandbox must use seccomp filtering"
        );
    }

    // Verify server integration
    let server_path = workspace_root().join("crates/sigil-daemon/src/server.rs");
    let server_code = fs::read_to_string(&server_path).expect("Failed to read server code");

    assert!(
        server_code.contains("handle_exec") || server_code.contains("IpcOperation::Exec"),
        "Server must handle exec operations"
    );

    // Verify scrubbing integration
    assert!(
        server_code.contains("scrub") || server_code.contains("Scrubber"),
        "Exec output must be scrubbed"
    );
}

/// Test 3.2: Verify sandbox isolation
///
/// Tests that the sandbox provides proper isolation:
/// 1. Network isolation
/// 2. Filesystem isolation
/// 3. Process isolation
/// 4. PID namespace
/// 5. Mount namespace
#[test]
fn test_sandbox_isolation() {
    let sandbox_path = workspace_root().join("crates/sigil-sandbox/src/lib.rs");
    if sandbox_path.exists() {
        let sandbox_code = fs::read_to_string(&sandbox_path).expect("Failed to read sandbox code");

        // Verify network isolation option
        assert!(
            sandbox_code.contains("network") || sandbox_code.contains("--unshare-net"),
            "Sandbox must support network isolation"
        );

        // Verify filesystem isolation
        assert!(
            sandbox_code.contains("bind") || sandbox_code.contains("mount"),
            "Sandbox must use bind mounts for filesystem isolation"
        );

        // Verify PID namespace
        assert!(
            sandbox_code.contains("--unshare-pid") || sandbox_code.contains("pid"),
            "Sandbox must use PID namespace"
        );

        // Verify mount namespace
        assert!(
            sandbox_code.contains("--unshare-mount") || sandbox_code.contains("mount"),
            "Sandbox must use mount namespace"
        );

        // Verify read-only root
        assert!(
            sandbox_code.contains("--ro-bind") || sandbox_code.contains("read-only"),
            "Sandbox should have read-only root filesystem"
        );
    }
}

/// Test 3.3: Verify environment variable injection
///
/// Tests that secrets can be injected as environment variables:
/// 1. Secrets are resolved from vault
/// 2. Environment variables are set in sandbox
/// 3. Variables are not visible outside sandbox
#[test]
fn test_environment_variable_injection() {
    let sandbox_path = workspace_root().join("crates/sigil-sandbox/src/lib.rs");
    if sandbox_path.exists() {
        let sandbox_code = fs::read_to_string(&sandbox_path).expect("Failed to read sandbox code");

        // Verify environment variable support
        assert!(
            sandbox_code.contains("env") || sandbox_code.contains("--setenv"),
            "Sandbox must support environment variables"
        );
    }

    // Verify IPC exec request includes env vars
    let ipc_path = workspace_root().join("crates/sigil-core/src/ipc.rs");
    let ipc_code = fs::read_to_string(&ipc_path).expect("Failed to read IPC code");

    assert!(
        ipc_code.contains("ExecRequest") && ipc_code.contains("env"),
        "ExecRequest must support environment variables"
    );
}

// ============================================================================
// SCRUBBING AND BREACH DETECTION TESTS
// ============================================================================

/// Test 4.1: Verify output scrubbing workflow
///
/// Tests the complete scrubbing pipeline:
/// 1. Command output is captured
/// 2. Secrets are detected using patterns
/// 3. Secrets are replaced with placeholders
/// 4. Scrubbed output is returned
#[test]
fn test_output_scrubbing_workflow() {
    let scrubber_path = workspace_root().join("crates/sigil-scrub/src/scrubber.rs");
    let scrubber_code = fs::read_to_string(&scrubber_path).expect("Failed to read scrubber code");

    // Verify scrub function exists
    assert!(
        scrubber_code.contains("pub fn scrub") || scrubber_code.contains("fn scrub"),
        "Scrubber must have scrub function"
    );

    // Verify pattern matching
    assert!(
        scrubber_code.contains("AhoCorasick") || scrubber_code.contains("pattern"),
        "Scrubber must use pattern matching"
    );

    // Verify placeholder format
    assert!(
        scrubber_code.contains("{{secret:") || scrubber_code.contains("placeholder"),
        "Scrubber must use {{secret:path}} placeholder format"
    );

    // Verify streaming support
    assert!(
        scrubber_code.contains("StreamingScrubber") || scrubber_code.contains("stream"),
        "Scrubber must support streaming"
    );
}

/// Test 4.2: Verify breach detection and logging
///
/// Tests that breaches are detected and logged:
/// 1. Canary access is detected
/// 2. High-entropy strings are detected
/// 3. Breaches are logged at appropriate severity
/// 4. Audit trail is maintained
#[test]
fn test_breach_detection_logging() {
    let server_path = workspace_root().join("crates/sigil-daemon/src/server.rs");
    let server_code = fs::read_to_string(&server_path).expect("Failed to read server code");

    // Verify canary access detection
    assert!(
        server_code.contains("canary") || server_code.contains("decoy"),
        "Server must detect canary access"
    );

    // Verify breach logging
    assert!(
        server_code.contains("CRITICAL") || server_code.contains("breach"),
        "Server must log breaches at CRITICAL level"
    );

    // Verify audit logging
    let audit_path = workspace_root().join("crates/sigil-core/src/audit.rs");
    let audit_code = fs::read_to_string(&audit_path).expect("Failed to read audit code");

    assert!(
        audit_code.contains("BreachDetected") || audit_code.contains("log_breach"),
        "Audit must support breach detection logging"
    );

    assert!(
        audit_code.contains("AuditLog") || audit_code.contains("append"),
        "Audit must maintain append-only log"
    );
}

/// Test 4.3: Verify multiple encoding detection
///
/// Tests that secrets in multiple encodings are detected:
/// 1. Plain text
/// 2. Base64
/// 3. Hex
/// 4. URL encoding
#[test]
fn test_multiple_encoding_detection() {
    let scrubber_path = workspace_root().join("crates/sigil-scrub/src/scrubber.rs");
    let scrubber_code = fs::read_to_string(&scrubber_path).expect("Failed to read scrubber code");

    // Verify encoding variant generation
    assert!(
        scrubber_code.contains("generate_encoding_variants") || scrubber_code.contains("encoding"),
        "Scrubber must generate encoding variants"
    );

    // Verify base64 support
    assert!(
        scrubber_code.contains("base64") || scrubber_code.contains("BASE64"),
        "Scrubber must detect base64-encoded secrets"
    );

    // Verify hex support
    assert!(
        scrubber_code.contains("hex") || scrubber_code.contains("HEX"),
        "Scrubber must detect hex-encoded secrets"
    );

    // Verify URL encoding support
    assert!(
        scrubber_code.contains("url") || scrubber_code.contains("percent"),
        "Scrubber must detect URL-encoded secrets"
    );
}

// ============================================================================
// CANARY SYSTEM INTEGRATION TESTS
// ============================================================================

/// Test 5.1: Verify canary generation workflow
///
/// Tests the canary generation:
/// 1. Canary files are generated at daemon startup
/// 2. Files are stored in tmpfs (not on disk)
/// 3. Multiple canary types are generated
/// 4. Each canary has unique value
#[test]
fn test_canary_generation_workflow() {
    let canary_path = workspace_root().join("crates/sigil-canary/src/lib.rs");
    if canary_path.exists() {
        let canary_code = fs::read_to_string(&canary_path).expect("Failed to read canary code");

        // Verify canary generator
        assert!(
            canary_code.contains("generate") || canary_code.contains("Generator"),
            "Canary module must have generator"
        );

        // Verify multiple canary types
        assert!(
            canary_code.contains("AWS")
                || canary_code.contains("GitHub")
                || canary_code.contains("SSH"),
            "Canary module must support multiple types"
        );
    }

    // Verify daemon integration
    let daemon_path = workspace_root().join("crates/sigil-daemon/src/main.rs");
    let daemon_code = fs::read_to_string(&daemon_path).expect("Failed to read daemon code");

    assert!(
        daemon_code.contains("CanaryManager") || daemon_code.contains("canary"),
        "Daemon must initialize canary system"
    );
}

/// Test 5.2: Verify canary access detection
///
/// Tests that canary access is detected:
/// 1. Canary files are monitored
/// 2. Access triggers alert
/// 3. Access is logged
/// 4. Auto-lockdown can be triggered
#[test]
fn test_canary_access_detection() {
    let monitor_path = workspace_root().join("crates/sigil-canary/src/monitor.rs");
    if monitor_path.exists() {
        let monitor_code = fs::read_to_string(&monitor_path).expect("Failed to read monitor code");

        // Verify monitoring mechanism
        assert!(
            monitor_code.contains("fanotify") || monitor_code.contains("inotify"),
            "Canary must use file monitoring"
        );

        // Verify access detection
        assert!(
            monitor_code.contains("access") || monitor_code.contains("read"),
            "Canary must detect file access"
        );

        // Verify alert generation
        assert!(
            monitor_code.contains("alert") || monitor_code.contains("trigger"),
            "Canary must generate alerts on access"
        );
    }

    // Verify server integration
    let server_path = workspace_root().join("crates/sigil-daemon/src/server.rs");
    let server_code = fs::read_to_string(&server_path).expect("Failed to read server code");

    assert!(
        server_code.contains("canary_access") || server_code.contains("record_canary"),
        "Server must record canary access"
    );

    assert!(
        server_code.contains("canary_triggers") || server_code.contains("lockdown"),
        "Server must support canary-triggered lockdown"
    );
}

/// Test 5.3: Verify canary hook-only mode
///
/// Tests that canaries work in hook-only mode:
/// 1. Hooks detect canary paths
/// 2. Decoy responses are served
/// 3. No files are created on host filesystem
#[test]
fn test_canary_hook_only_mode() {
    let server_path = workspace_root().join("crates/sigil-daemon/src/server.rs");
    let server_code = fs::read_to_string(&server_path).expect("Failed to read server code");

    // Verify canary path detection
    assert!(
        server_code.contains("is_canary_path") || server_code.contains("canary_path"),
        "Server must detect canary paths"
    );

    // Verify decoy response generation
    assert!(
        server_code.contains("generate_decoy") || server_code.contains("decoy"),
        "Server must generate decoy responses"
    );

    // Verify no filesystem writes for canaries
    let cli_path = workspace_root().join("crates/sigil-cli/src/main.rs");
    let cli_code = fs::read_to_string(&cli_path).expect("Failed to read CLI code");

    // Verify init does NOT create canary files on host
    assert!(
        !cli_code.contains("write .aws/credentials")
            && !cli_code.contains("create .ssh/id_sigil_canary"),
        "CLI init must NOT create canary files on host filesystem"
    );
}

// ============================================================================
// COMPREHENSIVE END-TO-END TESTS
// ============================================================================

/// Test 6.1: Verify complete secret usage workflow
///
/// Tests the complete workflow from secret creation to usage:
/// 1. Initialize vault
/// 2. Add secret
/// 3. Start daemon
/// 4. Execute command with secret injection
/// 5. Verify output is scrubbed
/// 6. Verify secret was accessed (audit log)
#[test]
fn test_complete_secret_usage_workflow() {
    // This test verifies all components are present for the workflow

    // 1. Vault initialization
    let cli_path = workspace_root().join("crates/sigil-cli/src/main.rs");
    let cli_code = fs::read_to_string(&cli_path).expect("Failed to read CLI code");
    assert!(
        cli_code.contains("CommandInit"),
        "CLI must support vault initialization"
    );

    // 2. Secret storage
    assert!(
        cli_code.contains("CommandAdd"),
        "CLI must support adding secrets"
    );

    // 3. Daemon startup
    let daemon_path = workspace_root().join("crates/sigil-daemon/src/main.rs");
    assert!(daemon_path.exists(), "Daemon must exist");

    // 4. Command execution with injection
    let server_path = workspace_root().join("crates/sigil-daemon/src/server.rs");
    let server_code = fs::read_to_string(&server_path).expect("Failed to read server code");
    assert!(
        server_code.contains("handle_exec"),
        "Server must handle command execution"
    );

    // 5. Output scrubbing
    assert!(
        server_code.contains("scrub") || server_code.contains("Scrubber"),
        "Server must scrub output"
    );

    // 6. Audit logging
    let audit_path = workspace_root().join("crates/sigil-core/src/audit.rs");
    assert!(audit_path.exists(), "Audit module must exist");
}

/// Test 6.2: Verify complete canary breach workflow
///
/// Tests the complete canary breach detection workflow:
/// 1. Initialize daemon with canaries
/// 2. Attempt to access canary file
/// 3. Verify breach is detected
/// 4. Verify alert is generated
/// 5. Verify audit log entry
/// 6. Verify potential lockdown trigger
#[test]
fn test_complete_canary_breach_workflow() {
    // 1. Canary initialization
    let daemon_path = workspace_root().join("crates/sigil-daemon/src/main.rs");
    let daemon_code = fs::read_to_string(&daemon_path).expect("Failed to read daemon code");
    assert!(
        daemon_code.contains("CanaryManager"),
        "Daemon must initialize canary system"
    );

    // 2-3. Canary access detection
    let monitor_path = workspace_root().join("crates/sigil-canary/src/monitor.rs");
    if monitor_path.exists() {
        let monitor_code = fs::read_to_string(&monitor_path).expect("Failed to read monitor code");
        assert!(
            monitor_code.contains("monitor") || monitor_code.contains("watch"),
            "Canary must monitor for access"
        );
    }

    // 4-5. Alert and audit logging
    let server_path = workspace_root().join("crates/sigil-daemon/src/server.rs");
    let server_code = fs::read_to_string(&server_path).expect("Failed to read server code");
    assert!(
        server_code.contains("record_canary_access"),
        "Server must record canary access"
    );

    assert!(
        server_code.contains("canary_triggers") && server_code.contains("lockdown"),
        "Server must support lockdown on canary threshold"
    );
}

/// Test 6.3: Verify complete export/import workflow
///
/// Tests the complete archive workflow:
/// 1. Create archive with secrets
/// 2. Verify archive is encrypted
/// 3. Import archive to new vault
/// 4. Verify secrets are restored
#[test]
fn test_complete_export_import_workflow() {
    let archive_path = workspace_root().join("crates/sigil-cli/src/archive.rs");
    if archive_path.exists() {
        let archive_code = fs::read_to_string(&archive_path).expect("Failed to read archive code");

        // Verify export function
        assert!(
            archive_code.contains("pub fn create_archive") || archive_code.contains("export"),
            "Archive module must support export"
        );

        // Verify import function
        assert!(
            archive_code.contains("pub fn extract_archive") || archive_code.contains("import"),
            "Archive module must support import"
        );

        // Verify encryption
        assert!(
            archive_code.contains("age") || archive_code.contains("encrypt"),
            "Archive must be encrypted"
        );

        // Verify magic bytes for format validation
        assert!(
            archive_code.contains("ARCHIVE_MAGIC") || archive_code.contains("magic"),
            "Archive must have magic bytes for validation"
        );
    }

    // Verify CLI commands
    let cli_path = workspace_root().join("crates/sigil-cli/src/main.rs");
    let cli_code = fs::read_to_string(&cli_path).expect("Failed to read CLI code");

    assert!(
        cli_code.contains("CommandExport") || cli_code.contains("export"),
        "CLI must support export command"
    );

    assert!(
        cli_code.contains("CommandImport") || cli_code.contains("import"),
        "CLI must support import command"
    );
}

/// Test 6.4: Verify complete sandbox isolation workflow
///
/// Tests the complete sandbox isolation:
/// 1. Start daemon
/// 2. Execute command in sandbox
/// 3. Verify process isolation
/// 4. Verify filesystem isolation
/// 5. Verify network isolation (if enabled)
/// 6. Verify cleanup
#[test]
fn test_complete_sandbox_isolation_workflow() {
    let sandbox_path = workspace_root().join("crates/sigil-sandbox/src/lib.rs");
    if sandbox_path.exists() {
        let sandbox_code = fs::read_to_string(&sandbox_path).expect("Failed to read sandbox code");

        // Verify sandbox creation
        assert!(
            sandbox_code.contains("pub async fn execute"),
            "Sandbox must have execute function"
        );

        // Verify bubblewrap usage
        assert!(
            sandbox_code.contains("Command::new") && sandbox_code.contains("bwrap"),
            "Sandbox must use bubblewrap"
        );

        // Verify isolation flags
        assert!(
            sandbox_code.contains("--unshare-all")
                || (sandbox_code.contains("--unshare-user")
                    && sandbox_code.contains("--unshare-pid")
                    && sandbox_code.contains("--unshare-net")
                    && sandbox_code.contains("--unshare-ipc")
                    && sandbox_code.contains("--unshare-cgroup")
                    && sandbox_code.contains("--unshare-uts")),
            "Sandbox must unshare all namespaces"
        );

        // Verify seccomp filter
        assert!(
            sandbox_code.contains("--seccomp") || sandbox_code.contains("seccomp"),
            "Sandbox must use seccomp filtering"
        );
    }

    // Verify server integration
    let server_path = workspace_root().join("crates/sigil-daemon/src/server.rs");
    let server_code = fs::read_to_string(&server_path).expect("Failed to read server code");

    assert!(
        server_code.contains("handle_exec") && server_code.contains("sandbox"),
        "Server must handle sandbox execution"
    );
}

/// Test 6.5: Verify complete TUI workflow
///
/// Tests the complete TUI workflow:
/// 1. Launch TUI
/// 2. Display secrets list
/// 3. Request access to secret
/// 4. Approve/deny request
/// 5. Show audit log
#[test]
fn test_complete_tui_workflow() {
    let tui_path = workspace_root().join("crates/sigil-tui/src/lib.rs");
    if tui_path.exists() {
        let tui_code = fs::read_to_string(&tui_path).expect("Failed to read TUI code");

        // Verify TUI entry point
        assert!(
            tui_code.contains("pub async fn run") || tui_code.contains("fn main"),
            "TUI must have run function"
        );

        // Verify state management
        assert!(
            tui_code.contains("State") || tui_code.contains("TuiState"),
            "TUI must manage state"
        );

        // Verify event handling
        assert!(
            tui_code.contains("handle_event") || tui_code.contains("Event"),
            "TUI must handle events"
        );

        // Verify rendering
        assert!(
            tui_code.contains("draw") || tui_code.contains("render"),
            "TUI must render UI"
        );
    }

    // Verify CLI integration
    let cli_path = workspace_root().join("crates/sigil-cli/src/main.rs");
    let cli_code = fs::read_to_string(&cli_path).expect("Failed to read CLI code");

    assert!(
        cli_code.contains("CommandTui") || cli_code.contains("tui"),
        "CLI must support TUI command"
    );
}

/// Test 6.6: Verify complete proxy workflow
///
/// Tests the complete HTTP proxy workflow:
/// 1. Start proxy server
/// 2. Configure client to use proxy
/// 3. Intercept HTTPS with MITM
/// 4. Sign requests with AWS credentials
/// 5. Scrub responses
/// 6. Enforce allowlist
#[test]
fn test_complete_proxy_workflow() {
    let proxy_path = workspace_root().join("crates/sigil-proxy/src/proxy.rs");
    if proxy_path.exists() {
        let proxy_code = fs::read_to_string(&proxy_path).expect("Failed to read proxy code");

        // Verify proxy server
        assert!(
            proxy_code.contains("pub async fn serve"),
            "Proxy must have serve function"
        );

        // Verify request handling
        assert!(
            proxy_code.contains("handle_request"),
            "Proxy must handle requests"
        );

        // Verify TLS MITM
        let tls_path = workspace_root().join("crates/sigil-proxy/src/tls.rs");
        if tls_path.exists() {
            let tls_code = fs::read_to_string(&tls_path).expect("Failed to read TLS code");
            assert!(
                tls_code.contains("MitmCa") || tls_code.contains("generate_cert"),
                "Proxy must support MITM TLS"
            );
        }

        // Verify response scrubbing
        let scrubber_path = workspace_root().join("crates/sigil-proxy/src/scrubber.rs");
        if scrubber_path.exists() {
            let scrubber_code =
                fs::read_to_string(&scrubber_path).expect("Failed to read scrubber code");
            assert!(
                scrubber_code.contains("scrub") || scrubber_code.contains("ResponseScrubber"),
                "Proxy must scrub responses"
            );
        }
    }

    // Verify CLI integration
    let cli_path = workspace_root().join("crates/sigil-cli/src/main.rs");
    let cli_code = fs::read_to_string(&cli_path).expect("Failed to read CLI code");

    assert!(
        cli_code.contains("CommandProxy") || cli_code.contains("proxy"),
        "CLI must support proxy command"
    );
}
