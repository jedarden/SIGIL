//! Integration tests for daemon hardening measures
//!
//! These tests verify that the daemon properly implements security hardening:
//! - PR_SET_DUMPABLE=0 to prevent ptrace/memory reads
//! - RLIMIT_CORE=0 to disable core dumps
//! - Socket with 0600 permissions
//! - Session token stored in kernel keyring (not on disk)

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

/// Test that the daemon sets PR_SET_DUMPABLE=0
///
/// This test verifies the code contains prctl with PR_SET_DUMPABLE
#[test]
#[cfg(target_os = "linux")]
fn test_pr_set_dumpable() {
    assert_dumpable_zero_in_code();
}

/// Test that the daemon sets RLIMIT_CORE=0
#[test]
#[cfg(target_os = "linux")]
fn test_rlimit_core_zero() {
    assert_rlimit_core_zero_in_code();
}

/// Test that the daemon socket has 0600 permissions
#[test]
fn test_socket_permissions() {
    assert_socket_0600_in_code();
}

/// Test that session token is stored in kernel keyring (not on disk)
#[test]
#[cfg(target_os = "linux")]
fn test_session_token_keyring() {
    assert_keyring_usage_in_code();
}

/// Helper: Verify PR_SET_DUMPABLE=0 in code
#[cfg(target_os = "linux")]
fn assert_dumpable_zero_in_code() {
    let memory_rs = std::fs::read_to_string(daemon_src_path().join("memory.rs"))
        .expect("Failed to read memory.rs");

    assert!(
        memory_rs.contains("PR_SET_DUMPABLE"),
        "memory.rs should contain PR_SET_DUMPABLE"
    );
    assert!(
        memory_rs.contains("prctl"),
        "memory.rs should contain prctl syscall"
    );

    // Verify it's called with 0
    assert!(
        memory_rs.contains("libc::prctl(libc::PR_SET_DUMPABLE, 0"),
        "memory.rs should call prctl with PR_SET_DUMPABLE and 0"
    );
}

/// Helper: Verify RLIMIT_CORE=0 in code
#[cfg(target_os = "linux")]
fn assert_rlimit_core_zero_in_code() {
    let memory_rs = std::fs::read_to_string(daemon_src_path().join("memory.rs"))
        .expect("Failed to read memory.rs");

    assert!(
        memory_rs.contains("RLIMIT_CORE"),
        "memory.rs should contain RLIMIT_CORE"
    );
    assert!(
        memory_rs.contains("setrlimit"),
        "memory.rs should contain setrlimit syscall"
    );
    assert!(
        memory_rs.contains("rlim_cur: 0") && memory_rs.contains("rlim_max: 0"),
        "memory.rs should set both rlim_cur and rlim_max to 0"
    );
}

/// Helper: Verify socket 0600 permissions in code
fn assert_socket_0600_in_code() {
    let server_rs = std::fs::read_to_string(daemon_src_path().join("server.rs"))
        .expect("Failed to read server.rs");

    assert!(
        server_rs.contains("0o600") || server_rs.contains("0600"),
        "server.rs should set socket permissions to 0600"
    );
    assert!(
        server_rs.contains("set_permissions") || server_rs.contains("set_mode"),
        "server.rs should call set_permissions or set_mode"
    );
}

/// Helper: Verify keyring usage in code
#[cfg(target_os = "linux")]
fn assert_keyring_usage_in_code() {
    let vault_rs = std::fs::read_to_string(daemon_src_path().join("vault.rs"))
        .expect("Failed to read vault.rs");

    assert!(
        vault_rs.contains("keyring") || vault_rs.contains("keyctl"),
        "vault.rs should use kernel keyring"
    );

    // Verify it checks for keyring availability
    assert!(
        vault_rs.contains("is_keyring_available"),
        "vault.rs should check keyring availability"
    );

    // Verify sigil-core has keyring support
    let keyring_rs = std::fs::read_to_string(core_src_path().join("keyring.rs"))
        .expect("Failed to read keyring.rs");

    assert!(
        keyring_rs.contains("add_session_token"),
        "keyring.rs should have add_session_token function"
    );
    assert!(
        keyring_rs.contains("KEY_SPEC_SESSION_KEYRING"),
        "keyring.rs should use KEY_SPEC_SESSION_KEYRING"
    );
}

/// Verify the startup sequence order
#[test]
fn test_startup_sequence_order() {
    let main_rs = std::fs::read_to_string(daemon_src_path().join("main.rs"))
        .expect("Failed to read main.rs");

    // Verify enable_memory_protection is called before vault unlock
    let mem_protect_pos = main_rs.find("enable_memory_protection()")
        .expect("main.rs should call enable_memory_protection");

    let unlock_pos = main_rs.find("unlock_async")
        .expect("main.rs should call unlock_async");

    assert!(
        mem_protect_pos < unlock_pos,
        "enable_memory_protection should be called before vault unlock"
    );
}

/// Verify mlockall is called
#[test]
#[cfg(target_os = "linux")]
fn test_mlockall_called() {
    let memory_rs = std::fs::read_to_string(daemon_src_path().join("memory.rs"))
        .expect("Failed to read memory.rs");

    assert!(
        memory_rs.contains("mlockall"),
        "memory.rs should contain mlockall"
    );
    assert!(
        memory_rs.contains("MCL_CURRENT") && memory_rs.contains("MCL_FUTURE"),
        "memory.rs should use MCL_CURRENT | MCL_FUTURE"
    );
}

/// Comprehensive hardening verification
#[test]
fn test_all_hardening_measures_present() {
    // This is a comprehensive test that verifies all hardening measures
    // are present in the codebase

    // 1. PR_SET_DUMPABLE=0
    #[cfg(target_os = "linux")]
    assert_dumpable_zero_in_code();

    // 2. RLIMIT_CORE=0
    #[cfg(target_os = "linux")]
    assert_rlimit_core_zero_in_code();

    // 3. Socket 0600 permissions
    assert_socket_0600_in_code();

    // 4. Kernel keyring for session token
    #[cfg(target_os = "linux")]
    assert_keyring_usage_in_code();

    // 5. mlockall
    #[cfg(target_os = "linux")]
    test_mlockall_called();

    // 6. Startup sequence order
    test_startup_sequence_order();
}
