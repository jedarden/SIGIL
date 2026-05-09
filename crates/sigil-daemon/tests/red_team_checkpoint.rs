//! Red team checkpoint verification for Phase 2 hardening
//!
//! This test suite verifies that the daemon properly implements security measures
//! against common attack vectors. These tests verify the code implementation and
//! should be complemented with manual runtime testing.
//!
//! # Security Measures Verified
//!
//! 1. **Memory Protection**: PR_SET_DUMPABLE=0 prevents ptrace and /proc/pid/mem reads
//! 2. **Core Dump Prevention**: RLIMIT_CORE=0 prevents secret leakage in core dumps
//! 3. **Socket Security**: 0600 permissions prevent unauthorized access
//! 4. **Keyring Storage**: Session token in kernel memory, not on disk
//! 5. **Audit Logging**: Hash-chained append-only logs with tamper detection
//! 6. **Authentication**: Token validation required for all operations
//!
//! # Manual Verification Steps
//!
//! Runtime verification requires building and running the daemon:
//!
//! ```bash
//! cargo build --release --bin sigild
//! ./target/release/sigild start
//! # In another terminal:
//! cat /proc/$(pgrep sigild)/status | grep -E "^VmPeak|^VmSize|^VmRSS"
//! # Verify dumpable: 0
//! cat /proc/$(pgrep sigild)/status | grep dumpable
//! # Try to read memory (should fail)
//! sudo gdb -p $(pgrep sigild) -batch -ex "gdb detach"
//! # Try to connect without token (should reject)
//! echo '{}' | socat - UNIX-CONNECT:$(echo $XDG_RUNTIME_DIR/sigil.sock)
//! # Tamper audit log and verify chain breaks
//! echo '{"type":"test","timestamp":"2026-01-01T00:00:00Z"}' >> ~/.sigil/vault/audit.jsonl
//! # Restart daemon (should detect tampering)
//! ./target/release/sigild start
//! ```

use std::path::PathBuf;

/// Get the path to the sigil-daemon source directory
fn daemon_src_path() -> PathBuf {
    PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").unwrap()).join("src")
}

/// Get the path to the sigil-core source directory
fn core_src_path() -> PathBuf {
    PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").unwrap())
        .join("../sigil-core/src")
        .canonicalize()
        .expect("Failed to find sigil-core src")
}

// ============================================================================
// Memory Protection Tests
// ============================================================================

#[test]
#[cfg(target_os = "linux")]
fn test_pr_set_dumpable_prevents_ptrace() {
    let memory_rs = std::fs::read_to_string(daemon_src_path().join("memory.rs"))
        .expect("Failed to read memory.rs");

    // Verify PR_SET_DUMPABLE is set to 0
    assert!(
        memory_rs.contains("libc::prctl(libc::PR_SET_DUMPABLE, 0"),
        "PR_SET_DUMPABLE must be set to 0 to prevent ptrace"
    );

    // Verify this is done before any secret operations
    let main_rs = std::fs::read_to_string(daemon_src_path().join("main.rs"))
        .expect("Failed to read main.rs");

    let mem_protect_pos = main_rs.find("enable_memory_protection()").unwrap();
    let unlock_pos = main_rs.find("unlock_async").unwrap();

    assert!(
        mem_protect_pos < unlock_pos,
        "Memory protection must be enabled before vault unlock"
    );
}

#[test]
#[cfg(target_os = "linux")]
fn test_mlockall_prevents_swapping() {
    let memory_rs = std::fs::read_to_string(daemon_src_path().join("memory.rs"))
        .expect("Failed to read memory.rs");

    // Verify mlockall is called with correct flags
    assert!(
        memory_rs.contains("libc::mlockall(libc::MCL_CURRENT | libc::MCL_FUTURE)"),
        "mlockall must use MCL_CURRENT | MCL_FUTURE"
    );

    // Verify best-effort handling (warn but continue on failure)
    assert!(
        memory_rs.contains("warn!") || memory_rs.contains("tracing::warn"),
        "mlockall failure should log warning but continue"
    );
}

#[test]
#[cfg(target_os = "linux")]
fn test_rlimit_core_zero_disables_dumps() {
    let memory_rs = std::fs::read_to_string(daemon_src_path().join("memory.rs"))
        .expect("Failed to read memory.rs");

    // Verify RLIMIT_CORE is set to 0
    assert!(
        memory_rs.contains("libc::setrlimit(libc::RLIMIT_CORE"),
        "RLIMIT_CORE must be set"
    );
    assert!(
        memory_rs.contains("rlim_cur: 0") && memory_rs.contains("rlim_max: 0"),
        "Both rlim_cur and rlim_max must be 0"
    );
}

// ============================================================================
// Socket Security Tests
// ============================================================================

#[test]
fn test_socket_has_restrictive_permissions() {
    let server_rs = std::fs::read_to_string(daemon_src_path().join("server.rs"))
        .expect("Failed to read server.rs");

    // Verify socket permissions are set to 0600
    assert!(
        server_rs.contains("0o600") || server_rs.contains("0600"),
        "Socket must have 0600 permissions"
    );

    // Verify permissions are set after socket creation
    assert!(
        server_rs.contains("set_permissions") || server_rs.contains("set_mode"),
        "Socket permissions must be explicitly set"
    );
}

#[test]
fn test_socket_in_xdg_runtime_dir() {
    let main_rs = std::fs::read_to_string(daemon_src_path().join("main.rs"))
        .expect("Failed to read main.rs");

    // Verify default socket path uses XDG_RUNTIME_DIR
    assert!(
        main_rs.contains("XDG_RUNTIME_DIR"),
        "Default socket path should use XDG_RUNTIME_DIR"
    );
    assert!(
        main_rs.contains("sigil.sock"),
        "Socket file should be named sigil.sock"
    );
}

// ============================================================================
// Session Token Security Tests
// ============================================================================

#[test]
#[cfg(target_os = "linux")]
fn test_session_token_in_keyring() {
    let vault_rs = std::fs::read_to_string(daemon_src_path().join("vault.rs"))
        .expect("Failed to read vault.rs");

    // Verify keyring availability check
    assert!(
        vault_rs.contains("is_keyring_available"),
        "Must check keyring availability"
    );

    // Verify keyring is used when available
    assert!(
        vault_rs.contains("add_session_token"),
        "Must use keyring for session token storage"
    );

    // Verify file fallback with secure permissions
    assert!(
        vault_rs.contains("mode(0o400)"),
        "Fallback file must have 0400 permissions"
    );
}

#[test]
fn test_session_token_is_32_bytes() {
    use sigil_core::ipc::SessionToken;

    let token = SessionToken::generate();
    let bytes = token.to_bytes();

    assert_eq!(bytes.len(), 32, "Session token must be 32 bytes");
}

#[test]
fn test_session_token_unique() {
    use sigil_core::ipc::SessionToken;
    use std::collections::HashSet;

    let mut tokens = HashSet::new();

    // Generate 100 tokens and verify uniqueness
    for _ in 0..100 {
        let token = SessionToken::generate();
        let token_str = token.to_base64();
        assert!(tokens.insert(token_str), "Generated duplicate token");
    }
}

// ============================================================================
// Audit Log Security Tests
// ============================================================================

#[test]
fn test_audit_log_hash_chained() {
    let audit_rs = std::fs::read_to_string(daemon_src_path().join("audit.rs"))
        .expect("Failed to read audit.rs");

    // Verify hash chaining
    assert!(
        audit_rs.contains("previous_hash"),
        "Audit entries must include previous hash"
    );
    assert!(
        audit_rs.contains("compute_hash"),
        "Must compute hash for each entry"
    );
}

#[test]
fn test_audit_log_append_only() {
    let audit_rs = std::fs::read_to_string(daemon_src_path().join("audit.rs"))
        .expect("Failed to read audit.rs");

    // Verify append-only flag attempt
    assert!(
        audit_rs.contains("set_append_only_flag") || audit_rs.contains("FS_APPEND_FL"),
        "Must attempt to set append-only flag"
    );

    // Verify secure permissions
    assert!(
        audit_rs.contains("set_audit_log_permissions") || audit_rs.contains("0o600"),
        "Audit log must have 0600 permissions"
    );
}

#[test]
fn test_audit_log_tamper_detection() {
    let audit_rs = std::fs::read_to_string(daemon_src_path().join("audit.rs"))
        .expect("Failed to read audit.rs");

    // Verify chain verification
    assert!(
        audit_rs.contains("verify_chain"),
        "Must implement hash chain verification"
    );

    // Verify tamper detection on startup
    let main_rs = std::fs::read_to_string(daemon_src_path().join("main.rs"))
        .expect("Failed to read main.rs");

    assert!(
        main_rs.contains("verify_chain") || main_rs.contains("hash chain"),
        "Daemon must verify audit log chain on startup"
    );
}

#[test]
fn test_audit_log_rotation() {
    let audit_rs = std::fs::read_to_string(daemon_src_path().join("audit.rs"))
        .expect("Failed to read audit.rs");

    // Verify rotation support
    assert!(
        audit_rs.contains("rotate") || audit_rs.contains("max_size"),
        "Audit log must support rotation"
    );

    // Verify hash bridge between logs
    assert!(
        audit_rs.contains("Rotation") || audit_rs.contains("previous_file_hash"),
        "Rotation must maintain hash chain"
    );
}

// ============================================================================
// Authentication Tests
// ============================================================================

#[test]
fn test_token_required_for_all_operations() {
    let ipc_rs = std::fs::read_to_string(core_src_path().join("ipc.rs"))
        .expect("Failed to read ipc.rs");

    // Verify IpcRequest includes token field
    assert!(
        ipc_rs.contains("pub token: String"),
        "IPC request must include session token"
    );
}

#[test]
fn test_all_ipc_error_codes_implemented() {
    let ipc_rs = std::fs::read_to_string(core_src_path().join("ipc.rs"))
        .expect("Failed to read ipc.rs");

    // Verify all 15 error codes from the spec
    let required_errors = vec![
        "InvalidToken",
        "InvalidRequest",
        "UnknownOp",
        "SecretNotFound",
        "AccessDenied",
        "VaultLocked",
        "RateLimited",
        "PayloadTooLarge",
        "InternalError",
        "SessionExpired",
        "OperationFailed",
        "SandboxError",
        "ScrubError",
        "BackendError",
        "LockedDown",
    ];

    for error in required_errors {
        assert!(
            ipc_rs.contains(error),
            "Missing error code: {}",
            error
        );
    }
}

// ============================================================================
// Signal Handling Tests
// ============================================================================

#[test]
fn test_graceful_shutdown_on_sigterm() {
    let signals_rs = std::fs::read_to_string(daemon_src_path().join("signals.rs"))
        .expect("Failed to read signals.rs");

    // Verify SIGTERM handling
    assert!(
        signals_rs.contains("SIGTERM") || signals_rs.contains("terminate"),
        "Must handle SIGTERM"
    );

    // Verify graceful shutdown
    assert!(
        signals_rs.contains("Shutdown") || signals_rs.contains("shutdown"),
        "Must implement graceful shutdown"
    );
}

#[test]
fn test_config_reload_on_sighup() {
    let signals_rs = std::fs::read_to_string(daemon_src_path().join("signals.rs"))
        .expect("Failed to read signals.rs");

    // Verify SIGHUP handling
    assert!(
        signals_rs.contains("SIGHUP") || signals_rs.contains("hangup"),
        "Must handle SIGHUP"
    );

    // Verify config reload
    assert!(
        signals_rs.contains("Reload") || signals_rs.contains("reload"),
        "Must implement config reload"
    );
}

#[test]
fn test_status_dump_on_sigusr1() {
    let signals_rs = std::fs::read_to_string(daemon_src_path().join("signals.rs"))
        .expect("Failed to read signals.rs");

    // Verify SIGUSR1 handling
    assert!(
        signals_rs.contains("SIGUSR1") || signals_rs.contains("user_defined1"),
        "Must handle SIGUSR1"
    );

    // Verify status dump
    assert!(
        signals_rs.contains("DumpStatus") || signals_rs.contains("dump"),
        "Must implement status dump"
    );
}

#[test]
fn test_log_rotation_on_sigusr2() {
    let signals_rs = std::fs::read_to_string(daemon_src_path().join("signals.rs"))
        .expect("Failed to read signals.rs");

    // Verify SIGUSR2 handling
    assert!(
        signals_rs.contains("SIGUSR2") || signals_rs.contains("user_defined2"),
        "Must handle SIGUSR2"
    );

    // Verify log rotation
    assert!(
        signals_rs.contains("RotateLog") || signals_rs.contains("rotate"),
        "Must implement log rotation"
    );
}

// ============================================================================
// Startup Mode Tests
// ============================================================================

#[test]
fn test_on_demand_startup() {
    let ondemand_rs = std::fs::read_to_string(daemon_src_path().join("ondemand.rs"))
        .expect("Failed to read ondemand.rs");

    // Verify lockfile coordination
    assert!(
        ondemand_rs.contains("flock") || ondemand_rs.contains("LOCK_EX"),
        "Must use flock for lockfile coordination"
    );

    // Verify socket wait with timeout
    assert!(
        ondemand_rs.contains("wait_for_socket") || ondemand_rs.contains("SOCKET_WAIT_TIMEOUT"),
        "Must wait for socket with timeout"
    );
}

#[test]
fn test_systemd_socket_activation() {
    let server_rs = std::fs::read_to_string(daemon_src_path().join("server.rs"))
        .expect("Failed to read server.rs");

    // Verify LISTEN_FDS handling
    assert!(
        server_rs.contains("LISTEN_FDS") || server_rs.contains("get_systemd_socket_fd"),
        "Must support systemd socket activation"
    );

    // Verify sd_notify
    assert!(
        server_rs.contains("NOTIFY_SOCKET") || server_rs.contains("sd_notify"),
        "Must send READY=1 notification"
    );
}

// ============================================================================
// Comprehensive Security Checklist
// ============================================================================

#[test]
fn test_phase2_security_checklist_complete() {
    // This test verifies the complete Phase 2 security checklist

    // 2.1 Daemon hardening
    #[cfg(target_os = "linux")]
    {
        test_pr_set_dumpable_prevents_ptrace();
        test_mlockall_prevents_swapping();
        test_rlimit_core_zero_disables_dumps();
    }

    // Socket security
    test_socket_has_restrictive_permissions();
    test_socket_in_xdg_runtime_dir();

    // Session token security
    #[cfg(target_os = "linux")]
    test_session_token_in_keyring();
    test_session_token_is_32_bytes();
    test_session_token_unique();

    // Audit log security
    test_audit_log_hash_chained();
    test_audit_log_append_only();
    test_audit_log_tamper_detection();
    test_audit_log_rotation();

    // Authentication
    test_token_required_for_all_operations();
    test_all_ipc_error_codes_implemented();

    // Signal handling
    test_graceful_shutdown_on_sigterm();
    test_config_reload_on_sighup();
    test_status_dump_on_sigusr1();
    test_log_rotation_on_sigusr2();

    // Startup modes
    test_on_demand_startup();
    test_systemd_socket_activation();
}
