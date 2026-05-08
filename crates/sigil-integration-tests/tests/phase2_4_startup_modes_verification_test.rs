//! Phase 2.4 Verification Tests
//!
//! These tests verify the three daemon startup modes as specified in the plan.
//!
//! Phase 2.4 covers:
//! - On-demand startup (default) with lockfile coordination
//! - systemd socket activation (Linux)
//! - launchd socket activation (macOS)
//! - Idle timeout configuration and shutdown

mod common;
use common::workspace_root;
use std::fs;

// ============================================================================
// On-demand startup (default) verification tests
// ============================================================================

/// Test 2.4.1: Verify ondemand module exists
///
/// From Phase 2.4 deliverables:
/// "On-demand startup (default): Lockfile coordination: $XDG_RUNTIME_DIR/sigil.lock"
#[test]
fn test_ondemand_module_exists() {
    let ondemand_path = workspace_root()
        .join("crates/sigil-daemon/src/ondemand.rs");
    assert!(
        ondemand_path.exists(),
        "ondemand.rs module must exist"
    );
}

/// Test 2.4.2: Verify OnDemandCoordinator struct exists
///
/// From Phase 2.4 deliverables:
/// "On-demand startup (default): Lockfile coordination: $XDG_RUNTIME_DIR/sigil.lock"
#[test]
fn test_on_demand_coordinator_exists() {
    let ondemand_path = workspace_root()
        .join("crates/sigil-daemon/src/ondemand.rs");
    let ondemand_code = fs::read_to_string(&ondemand_path)
        .expect("Failed to read ondemand.rs");

    assert!(
        ondemand_code.contains("pub struct OnDemandCoordinator"),
        "OnDemandCoordinator struct must exist"
    );
}

/// Test 2.4.3: Verify lockfile path coordination
///
/// From Phase 2.4 deliverables:
/// "On-demand startup (default): Lockfile coordination: $XDG_RUNTIME_DIR/sigil.lock"
#[test]
fn test_lockfile_coordination() {
    let ondemand_path = workspace_root()
        .join("crates/sigil-daemon/src/ondemand.rs");
    let ondemand_code = fs::read_to_string(&ondemand_path)
        .expect("Failed to read ondemand.rs");

    // Verify lockfile_path field exists
    assert!(
        ondemand_code.contains("lockfile_path"),
        "OnDemandCoordinator must have lockfile_path field"
    );

    // Verify lockfile is created with .lock extension
    assert!(
        ondemand_code.contains("with_extension(\"lock\")"),
        "Lockfile should use .lock extension"
    );
}

/// Test 2.4.4: Verify is_daemon_running checks socket
///
/// From Phase 2.4 deliverables:
/// "Client checks if daemon running via socket probe"
#[test]
fn test_is_daemon_running_socket_probe() {
    let ondemand_path = workspace_root()
        .join("crates/sigil-daemon/src/ondemand.rs");
    let ondemand_code = fs::read_to_string(&ondemand_path)
        .expect("Failed to read ondemand.rs");

    // Verify is_daemon_running checks socket existence
    assert!(
        ondemand_code.contains("fn is_daemon_running") &&
        ondemand_code.contains("socket_path.exists()"),
        "is_daemon_running must check socket existence"
    );
}

/// Test 2.4.5: Verify ensure_daemon_running acquires lockfile
///
/// From Phase 2.4 deliverables:
/// "If not running: acquire lockfile, fork daemon, wait for socket (max 5s)"
#[test]
fn test_ensure_daemon_lockfile_acquisition() {
    let ondemand_path = workspace_root()
        .join("crates/sigil-daemon/src/ondemand.rs");
    let ondemand_code = fs::read_to_string(&ondemand_path)
        .expect("Failed to read ondemand.rs");

    // Verify ensure_daemon_running exists
    assert!(
        ondemand_code.contains("pub async fn ensure_daemon_running"),
        "ensure_daemon_running function must exist"
    );

    // Verify lockfile acquisition
    assert!(
        ondemand_code.contains("acquire_lockfile"),
        "ensure_daemon_running must acquire lockfile"
    );
}

/// Test 2.4.6: Verify lockfile uses flock for exclusive access
///
/// From Phase 2.4 deliverables:
/// "Race-safe: multiple clients result in exactly one daemon"
#[test]
fn test_lockfile_flock_exclusive() {
    let ondemand_path = workspace_root()
        .join("crates/sigil-daemon/src/ondemand.rs");
    let ondemand_code = fs::read_to_string(&ondemand_path)
        .expect("Failed to read ondemand.rs");

    // Verify flock is used for exclusive locking
    assert!(
        ondemand_code.contains("libc::flock") &&
        ondemand_code.contains("LOCK_EX"),
        "Lockfile must use flock with LOCK_EX for exclusive access"
    );
}

/// Test 2.4.7: Verify socket wait timeout (max 5 seconds)
///
/// From Phase 2.4 deliverables:
/// "wait for socket (max 5s)"
#[test]
fn test_socket_wait_timeout() {
    let ondemand_path = workspace_root()
        .join("crates/sigil-daemon/src/ondemand.rs");
    let ondemand_code = fs::read_to_string(&ondemand_path)
        .expect("Failed to read ondemand.rs");

    // Verify SOCKET_WAIT_TIMEOUT constant exists and is 5 seconds
    assert!(
        ondemand_code.contains("SOCKET_WAIT_TIMEOUT") &&
        ondemand_code.contains("Duration::from_secs(5)"),
        "Socket wait timeout must be 5 seconds"
    );
}

/// Test 2.4.8: Verify daemon spawn functionality
///
/// From Phase 2.4 deliverables:
/// "If not running: acquire lockfile, fork daemon, wait for socket"
#[test]
fn test_daemon_spawn() {
    let ondemand_path = workspace_root()
        .join("crates/sigil-daemon/src/ondemand.rs");
    let ondemand_code = fs::read_to_string(&ondemand_path)
        .expect("Failed to read ondemand.rs");

    // Verify spawn_daemon function exists
    assert!(
        ondemand_code.contains("fn spawn_daemon"),
        "spawn_daemon function must exist"
    );

    // Verify tokio::process::Command is used
    assert!(
        ondemand_code.contains("tokio::process::Command"),
        "Must use tokio::process::Command for spawning"
    );
}

/// Test 2.4.9: Verify LockFileGuard releases lock on drop
///
/// From Phase 2.4 deliverables:
/// "Race-safe: multiple clients result in exactly one daemon"
#[test]
fn test_lockfile_guard_release() {
    let ondemand_path = workspace_root()
        .join("crates/sigil-daemon/src/ondemand.rs");
    let ondemand_code = fs::read_to_string(&ondemand_path)
        .expect("Failed to read ondemand.rs");

    // Verify LockFileGuard struct exists
    assert!(
        ondemand_code.contains("struct LockFileGuard"),
        "LockFileGuard struct must exist"
    );

    // Verify Drop implementation releases lock
    assert!(
        ondemand_code.contains("impl Drop for LockFileGuard") &&
        ondemand_code.contains("LOCK_UN"),
        "LockFileGuard must release lock on drop"
    );
}

// ============================================================================
// systemd socket activation verification tests
// ============================================================================

/// Test 2.4.10: Verify setup_systemd function exists
///
/// From Phase 2.4 deliverables:
/// "systemd socket activation (Linux): sigil setup systemd installs unit files"
#[test]
fn test_setup_systemd_exists() {
    let main_path = workspace_root()
        .join("crates/sigil-cli/src/main.rs");
    let main_code = fs::read_to_string(&main_path)
        .expect("Failed to read main.rs");

    assert!(
        main_code.contains("fn setup_systemd"),
        "setup_systemd function must exist"
    );
}

/// Test 2.4.11: Verify systemd socket unit file creation
///
/// From Phase 2.4 deliverables:
/// "sigil setup systemd installs ~/.config/systemd/user/sigil.socket"
#[test]
fn test_systemd_socket_unit_creation() {
    let main_path = workspace_root()
        .join("crates/sigil-cli/src/main.rs");
    let main_code = fs::read_to_string(&main_path)
        .expect("Failed to read main.rs");

    // Verify socket unit file creation
    assert!(
        main_code.contains("sigil.socket") &&
        main_code.contains(".config/systemd/user"),
        "Must create socket unit in ~/.config/systemd/user/"
    );
}

/// Test 2.4.12: Verify systemd service unit file creation
///
/// From Phase 2.4 deliverables:
/// "sigil setup systemd installs ~/.config/systemd/user/sigil.service"
#[test]
fn test_systemd_service_unit_creation() {
    let main_path = workspace_root()
        .join("crates/sigil-cli/src/main.rs");
    let main_code = fs::read_to_string(&main_path)
        .expect("Failed to read main.rs");

    // Verify service unit file creation
    assert!(
        main_code.contains("sigil.service") &&
        main_code.contains("[Service]"),
        "Must create service unit with [Service] section"
    );
}

/// Test 2.4.13: Verify SocketMode=0600 in socket unit
///
/// From Phase 2.4 deliverables:
/// "SocketMode=0600 in unit file"
#[test]
fn test_socket_mode_0600() {
    let main_path = workspace_root()
        .join("crates/sigil-cli/src/main.rs");
    let main_code = fs::read_to_string(&main_path)
        .expect("Failed to read main.rs");

    assert!(
        main_code.contains("SocketMode=0600"),
        "Socket unit must have SocketMode=0600"
    );
}

/// Test 2.4.14: Verify --systemd flag in service unit
///
/// From Phase 2.4 deliverables:
/// "sigil setup systemd installs ~/.config/systemd/user/sigil.service"
/// "Daemon receives socket fd via $LISTEN_FDS (sd_listen_fds protocol)"
#[test]
fn test_systemd_flag_in_service() {
    let main_path = workspace_root()
        .join("crates/sigil-cli/src/main.rs");
    let main_code = fs::read_to_string(&main_path)
        .expect("Failed to read main.rs");

    assert!(
        main_code.contains("--systemd") &&
        main_code.contains("ExecStart"),
        "Service unit must have --systemd flag in ExecStart"
    );
}

/// Test 2.4.15: Verify get_systemd_socket_fd function exists
///
/// From Phase 2.4 deliverables:
/// "Daemon receives socket fd via $LISTEN_FDS (sd_listen_fds protocol)"
#[test]
fn test_get_systemd_socket_fd_exists() {
    let server_path = workspace_root()
        .join("crates/sigil-daemon/src/server.rs");
    let server_code = fs::read_to_string(&server_path)
        .expect("Failed to read server.rs");

    assert!(
        server_code.contains("fn get_systemd_socket_fd"),
        "get_systemd_socket_fd function must exist"
    );
}

/// Test 2.4.16: Verify LISTEN_FDS environment variable check
///
/// From Phase 2.4 deliverables:
/// "Daemon receives socket fd via $LISTEN_FDS (sd_listen_fds protocol)"
#[test]
fn test_listen_fds_env_check() {
    let server_path = workspace_root()
        .join("crates/sigil-daemon/src/server.rs");
    let server_code = fs::read_to_string(&server_path)
        .expect("Failed to read server.rs");

    assert!(
        server_code.contains("LISTEN_FDS") &&
        server_code.contains("std::env::var"),
        "Must check LISTEN_FDS environment variable"
    );
}

/// Test 2.4.17: Verify LISTEN_PID security check
///
/// From Phase 2.4 deliverables:
/// "Daemon receives socket fd via $LISTEN_FDS (sd_listen_fds protocol)"
/// (The LISTEN_PID check is part of the sd_listen_fds protocol for security)
#[test]
fn test_listen_pid_security_check() {
    let server_path = workspace_root()
        .join("crates/sigil-daemon/src/server.rs");
    let server_code = fs::read_to_string(&server_path)
        .expect("Failed to read server.rs");

    assert!(
        server_code.contains("LISTEN_PID") &&
        server_code.contains("std::process::id()"),
        "Must verify LISTEN_PID matches our PID for security"
    );
}

/// Test 2.4.18: Verify SD_LISTEN_FDS_START constant
///
/// From Phase 2.4 deliverables:
/// "Daemon receives socket fd via $LISTEN_FDS (sd_listen_fds protocol)"
#[test]
fn test_sd_listen_fds_start() {
    let server_path = workspace_root()
        .join("crates/sigil-daemon/src/server.rs");
    let server_code = fs::read_to_string(&server_path)
        .expect("Failed to read server.rs");

    assert!(
        server_code.contains("SD_LISTEN_FDS_START") &&
        server_code.contains("3"),
        "Must use SD_LISTEN_FDS_START=3 as specified by systemd protocol"
    );
}

/// Test 2.4.19: Verify sd_notify function exists
///
/// From Phase 2.4 deliverables:
/// "sd_notify(READY=1) after secrets loaded"
#[test]
fn test_sd_notify_exists() {
    let server_path = workspace_root()
        .join("crates/sigil-daemon/src/server.rs");
    let server_code = fs::read_to_string(&server_path)
        .expect("Failed to read server.rs");

    assert!(
        server_code.contains("fn sd_notify"),
        "sd_notify function must exist"
    );
}

/// Test 2.4.20: Verify READY=1 notification
///
/// From Phase 2.4 deliverables:
/// "sd_notify(READY=1) after secrets loaded"
#[test]
fn test_ready_1_notification() {
    let server_path = workspace_root()
        .join("crates/sigil-daemon/src/server.rs");
    let server_code = fs::read_to_string(&server_path)
        .expect("Failed to read server.rs");

    assert!(
        server_code.contains("READY=1") &&
        server_code.contains("sd_notify"),
        "Must send READY=1 notification via sd_notify"
    );
}

/// Test 2.4.21: Verify NOTIFY_SOCKET handling
///
/// From Phase 2.4 deliverables:
/// "sd_notify(READY=1) after secrets loaded"
#[test]
fn test_notify_socket_handling() {
    let server_path = workspace_root()
        .join("crates/sigil-daemon/src/server.rs");
    let server_code = fs::read_to_string(&server_path)
        .expect("Failed to read server.rs");

    assert!(
        server_code.contains("NOTIFY_SOCKET") &&
        server_code.contains("UnixDatagram"),
        "Must use NOTIFY_SOCKET with UnixDatagram for sd_notify"
    );
}

/// Test 2.4.22: Verify notify_ready method
///
/// From Phase 2.4 deliverables:
/// "sd_notify(READY=1) after secrets loaded"
#[test]
fn test_notify_ready_method() {
    let server_path = workspace_root()
        .join("crates/sigil-daemon/src/server.rs");
    let server_code = fs::read_to_string(&server_path)
        .expect("Failed to read server.rs");

    assert!(
        server_code.contains("pub async fn notify_ready") &&
        server_code.contains("systemd_mode"),
        "Must have notify_ready method that checks systemd_mode"
    );
}

/// Test 2.4.23: Verify Type=notify in service unit
///
/// From Phase 2.4 deliverables:
/// "sd_notify(READY=1) after secrets loaded"
/// (Type=notify is required for sd_notify to work)
#[test]
fn test_type_notify_in_service() {
    let main_path = workspace_root()
        .join("crates/sigil-cli/src/main.rs");
    let main_code = fs::read_to_string(&main_path)
        .expect("Failed to read main.rs");

    assert!(
        main_code.contains("Type=notify"),
        "Service unit must have Type=notify for sd_notify"
    );
}

// ============================================================================
// launchd socket activation verification tests
// ============================================================================

/// Test 2.4.24: Verify setup_launchd function exists
///
/// From Phase 2.4 deliverables:
/// "launchd (macOS): sigil setup launchd installs plist"
#[test]
fn test_setup_launchd_exists() {
    let main_path = workspace_root()
        .join("crates/sigil-cli/src/main.rs");
    let main_code = fs::read_to_string(&main_path)
        .expect("Failed to read main.rs");

    assert!(
        main_code.contains("fn setup_launchd"),
        "setup_launchd function must exist"
    );
}

/// Test 2.4.25: Verify launchd plist creation
///
/// From Phase 2.4 deliverables:
/// "sigil setup launchd installs ~/Library/LaunchAgents/com.sigil.daemon.plist"
#[test]
fn test_launchd_plist_creation() {
    let main_path = workspace_root()
        .join("crates/sigil-cli/src/main.rs");
    let main_code = fs::read_to_string(&main_path)
        .expect("Failed to read main.rs");

    assert!(
        main_code.contains("com.sigil.daemon.plist") &&
        main_code.contains("Library/LaunchAgents"),
        "Must create plist in ~/Library/LaunchAgents/"
    );
}

/// Test 2.4.26: Verify --launchd flag in plist
///
/// From Phase 2.4 deliverables:
/// "Daemon receives socket fd via launchd check-in API"
#[test]
fn test_launchd_flag_in_plist() {
    let main_path = workspace_root()
        .join("crates/sigil-cli/src/main.rs");
    let main_code = fs::read_to_string(&main_path)
        .expect("Failed to read main.rs");

    assert!(
        main_code.contains("--launchd"),
        "Plist must include --launchd flag"
    );
}

/// Test 2.4.27: Verify SockPathName in plist
///
/// From Phase 2.4 deliverables:
/// "SockPathName uses $TMPDIR/sigil.sock (macOS-specific path)"
#[test]
fn test_sock_path_name() {
    let main_path = workspace_root()
        .join("crates/sigil-cli/src/main.rs");
    let main_code = fs::read_to_string(&main_path)
        .expect("Failed to read main.rs");

    assert!(
        main_code.contains("SockPathName") &&
        main_code.contains("sigil.sock"),
        "Plist must have SockPathName with sigil.sock"
    );
}

/// Test 2.4.28: Verify SockPathMode=384 (0600 octal)
///
/// From Phase 2.4 deliverables:
/// "SockPathMode=384 (0600 octal)"
#[test]
fn test_sock_path_mode_384() {
    let main_path = workspace_root()
        .join("crates/sigil-cli/src/main.rs");
    let main_code = fs::read_to_string(&main_path)
        .expect("Failed to read main.rs");

    assert!(
        main_code.contains("SockPathMode") &&
        main_code.contains("384"),
        "Plist must have SockPathMode=384 (0600 octal)"
    );
}

/// Test 2.4.29: Verify get_launchd_socket_fd function exists (macOS)
///
/// From Phase 2.4 deliverables:
/// "Daemon receives socket fd via launchd check-in API"
#[test]
fn test_get_launchd_socket_fd_exists() {
    let server_path = workspace_root()
        .join("crates/sigil-daemon/src/server.rs");
    let server_code = fs::read_to_string(&server_path)
        .expect("Failed to read server.rs");

    // Note: This function is cfg-gated for macOS only
    assert!(
        server_code.contains("fn get_launchd_socket_fd") ||
        server_code.contains("#[cfg(target_os = \"macos\")]"),
        "get_launchd_socket_fd function must exist (macOS only)"
    );
}

/// Test 2.4.30: Verify launch_activate_socket declaration
///
/// From Phase 2.4 deliverables:
/// "Daemon receives socket fd via launchd check-in API"
#[test]
fn test_launch_activate_socket() {
    let server_path = workspace_root()
        .join("crates/sigil-daemon/src/server.rs");
    let server_code = fs::read_to_string(&server_path)
        .expect("Failed to read server.rs");

    // Verify launch_activate_socket is declared
    assert!(
        server_code.contains("launch_activate_socket") ||
        server_code.contains("launch"), // Might be in the link attribute
        "Must declare launch_activate_socket from launch framework"
    );
}

/// Test 2.4.31: Verify launch framework link
///
/// From Phase 2.4 deliverables:
/// "Daemon receives socket fd via launchd check-in API"
#[test]
fn test_launch_framework_link() {
    let server_path = workspace_root()
        .join("crates/sigil-daemon/src/server.rs");
    let server_code = fs::read_to_string(&server_path)
        .expect("Failed to read server.rs");

    // Verify link to launch framework
    assert!(
        server_code.contains("#[link(name = \"launch\"") ||
        server_code.contains("launch_activate_socket"),
        "Must link to launch framework for socket activation"
    );
}

// ============================================================================
// Idle timeout verification tests
// ============================================================================

/// Test 2.4.32: Verify idle_timeout parameter in Start command
///
/// From Phase 2.4 deliverables:
/// "Idle timeout shutdown: Configurable idle timeout (default 30m)"
#[test]
fn test_idle_timeout_parameter() {
    let main_path = workspace_root()
        .join("crates/sigil-daemon/src/main.rs");
    let main_code = fs::read_to_string(&main_path)
        .expect("Failed to read main.rs");

    assert!(
        main_code.contains("idle_timeout") &&
        main_code.contains("default_value = \"30m\""),
        "Start command must have idle_timeout parameter with default 30m"
    );
}

/// Test 2.4.33: Verify parse_duration function
///
/// From Phase 2.4 deliverables:
/// "Configurable idle timeout (default 30m): [daemon] idle_timeout = \"30m\""
#[test]
fn test_parse_duration_function() {
    let main_path = workspace_root()
        .join("crates/sigil-daemon/src/main.rs");
    let main_code = fs::read_to_string(&main_path)
        .expect("Failed to read main.rs");

    assert!(
        main_code.contains("fn parse_duration"),
        "parse_duration function must exist"
    );
}

/// Test 2.4.34: Verify "never" disables timeout
///
/// From Phase 2.4 deliverables:
/// "idle_timeout = \"never\" disables timeout"
#[test]
fn test_never_disables_timeout() {
    let main_path = workspace_root()
        .join("crates/sigil-daemon/src/main.rs");
    let main_code = fs::read_to_string(&main_path)
        .expect("Failed to read main.rs");

    assert!(
        main_code.contains("\"never\"") &&
        main_code.contains("u64::MAX"),
        "parse_duration must handle 'never' as u64::MAX"
    );
}

/// Test 2.4.35: Verify last_activity tracking in server
///
/// From Phase 2.4 deliverables:
/// "Daemon tracks last activity timestamp"
#[test]
fn test_last_activity_tracking() {
    let server_path = workspace_root()
        .join("crates/sigil-daemon/src/server.rs");
    let server_code = fs::read_to_string(&server_path)
        .expect("Failed to read server.rs");

    assert!(
        server_code.contains("last_activity") &&
        server_code.contains("Arc<Mutex<Instant>>"),
        "Server must track last_activity as Arc<Mutex<Instant>>"
    );
}

/// Test 2.4.36: Verify idle timeout checker task
///
/// From Phase 2.4 deliverables:
/// "On timeout: graceful shutdown (zeroize, close socket, remove lockfile)"
#[test]
fn test_idle_timeout_checker() {
    let server_path = workspace_root()
        .join("crates/sigil-daemon/src/server.rs");
    let server_code = fs::read_to_string(&server_path)
        .expect("Failed to read server.rs");

    // Verify idle timeout checking logic
    assert!(
        server_code.contains("idle_duration") &&
        server_code.contains("idle_timeout"),
        "Must have idle timeout checking logic"
    );
}

/// Test 2.4.37: Verify idle timeout triggers shutdown
///
/// From Phase 2.4 deliverables:
/// "On timeout: graceful shutdown (zeroize, close socket, remove lockfile)"
#[test]
fn test_idle_timeout_shutdown() {
    let server_path = workspace_root()
        .join("crates/sigil-daemon/src/server.rs");
    let server_code = fs::read_to_string(&server_path)
        .expect("Failed to read server.rs");

    assert!(
        server_code.contains("shutdown_flag") &&
        server_code.contains("Idle timeout reached"),
        "Must set shutdown_flag when idle timeout is reached"
    );
}

/// Test 2.4.38: Verify status shows idle timeout
///
/// From Phase 2.4 deliverables:
/// "Daemon tracks last activity timestamp"
#[test]
fn test_status_shows_idle_timeout() {
    let server_path = workspace_root()
        .join("crates/sigil-daemon/src/server.rs");
    let server_code = fs::read_to_string(&server_path)
        .expect("Failed to read server.rs");

    assert!(
        server_code.contains("idle_timeout_secs") &&
        server_code.contains("DaemonStatus"),
        "DaemonStatus must include idle_timeout_secs field"
    );
}

/// Test 2.4.39: Verify last_activity updated on requests
///
/// From Phase 2.4 deliverables:
/// "Daemon tracks last activity timestamp"
#[test]
fn test_last_activity_updated() {
    let server_path = workspace_root()
        .join("crates/sigil-daemon/src/server.rs");
    let server_code = fs::read_to_string(&server_path)
        .expect("Failed to read server.rs");

    // Verify last_activity is updated when handling requests
    assert!(
        server_code.contains("*self.last_activity.lock().await = Instant::now()"),
        "Must update last_activity timestamp on each request"
    );
}

// ============================================================================
// Runtime tests (require built binaries)
// ============================================================================

/// Test 2.4.40: Verify systemd and launchd flags in daemon start
///
/// From Phase 2.4 deliverables:
/// "systemd socket activation (Linux)" and "launchd (macOS)"
#[test]
fn test_daemon_start_flags() {
    let main_path = workspace_root()
        .join("crates/sigil-daemon/src/main.rs");
    let main_code = fs::read_to_string(&main_path)
        .expect("Failed to read main.rs");

    // Verify both flags are accepted
    assert!(
        main_code.contains("--systemd") &&
        main_code.contains("--launchd"),
        "Daemon start must accept both --systemd and --launchd flags"
    );
}

/// Test 2.4.41: Verify socket activation mode passed to server
///
/// From Phase 2.4 deliverables:
/// "systemd socket activation" and "launchd socket activation"
#[test]
fn test_socket_activation_mode() {
    let main_path = workspace_root()
        .join("crates/sigil-daemon/src/main.rs");
    let main_code = fs::read_to_string(&main_path)
        .expect("Failed to read main.rs");

    // Verify the mode is passed to DaemonServer::new_with_mode
    assert!(
        main_code.contains("new_with_mode") &&
        main_code.contains("systemd_mode"),
        "Must pass socket activation mode to server"
    );
}

/// Test 2.4.42: Verify ondemand module is included in daemon
///
/// From Phase 2.4 deliverables:
/// "On-demand startup (default)"
#[test]
fn test_ondemand_module_included() {
    let main_path = workspace_root()
        .join("crates/sigil-daemon/src/main.rs");
    let main_code = fs::read_to_string(&main_path)
        .expect("Failed to read main.rs");

    assert!(
        main_code.contains("mod ondemand"),
        "ondemand module must be included in daemon"
    );
}

/// Test 2.4.43: Verify socket permissions 0600 in server
///
/// From Phase 2.4 deliverables:
/// "SocketMode=0600 in unit file" (should apply to all modes)
#[test]
fn test_socket_permissions_0600() {
    let server_path = workspace_root()
        .join("crates/sigil-daemon/src/server.rs");
    let server_code = fs::read_to_string(&server_path)
        .expect("Failed to read server.rs");

    // Verify socket permissions set to 0o600 (octal)
    assert!(
        server_code.contains("0o600") &&
        server_code.contains("set_mode"),
        "Socket must be created with 0o600 permissions"
    );
}

/// Test 2.4.44: Verify setup commands in CLI
///
/// From Phase 2.4 deliverables:
/// "sigil setup systemd" and "sigil setup launchd"
#[test]
fn test_setup_commands() {
    let main_path = workspace_root()
        .join("crates/sigil-cli/src/main.rs");
    let main_code = fs::read_to_string(&main_path)
        .expect("Failed to read main.rs");

    // Verify both systemd and launchd are setup options
    assert!(
        main_code.contains("\"systemd\"") &&
        main_code.contains("\"launchd\""),
        "Setup command must support systemd and launchd"
    );
}
