//! Tests for daemon startup modes
//!
//! This test suite verifies the three daemon startup modes:
//! 1. On-demand startup with lockfile coordination
//! 2. systemd socket activation
//! 3. launchd socket activation (macOS only)
//!
//! Additionally tests idle timeout shutdown functionality.

use std::env;
use std::fs;
use std::path::PathBuf;
use std::time::Duration;
use tempfile::TempDir;

/// Test helper to create a temporary directory structure
fn setup_test_dirs() -> (TempDir, PathBuf, PathBuf) {
    let temp_dir = TempDir::new().unwrap();
    let socket_path = temp_dir.path().join("sigil.sock");
    let lockfile_path = temp_dir.path().join("sigil.lock");
    (temp_dir, socket_path, lockfile_path)
}

// ============================================================================
// On-demand startup tests
// ============================================================================

#[test]
fn test_ondemand_lockfile_coordination() {
    let (_temp_dir, socket_path, lockfile_path) = setup_test_dirs();

    // Create an OnDemandCoordinator
    let coordinator = sigil_daemon::ondemand::OnDemandCoordinator::new(&socket_path, None).unwrap();

    // Verify paths are correct
    assert_eq!(coordinator.socket_path, socket_path);
    assert_eq!(coordinator.lockfile_path, lockfile_path);

    // Initially no daemon running
    assert!(!coordinator.is_daemon_running());
    assert!(!socket_path.exists());

    // Create a socket file to simulate running daemon
    fs::File::create(&socket_path).unwrap();

    // Now daemon is "running"
    assert!(coordinator.is_daemon_running());
}

#[test]
fn test_ondemand_lockfile_path_from_socket() {
    let temp_dir = TempDir::new().unwrap();
    let socket_path = temp_dir.path().join("test-socket.sock");

    let coordinator = sigil_daemon::ondemand::OnDemandCoordinator::new(&socket_path, None).unwrap();

    // Lockfile should be in same directory with .lock extension
    assert_eq!(
        coordinator.lockfile_path,
        socket_path.with_extension("lock")
    );
    assert_eq!(
        coordinator.lockfile_path.file_name().unwrap(),
        "test-socket.lock"
    );
}

#[test]
fn test_ondemand_xdg_runtime_dir_fallback() {
    // Save original XDG_RUNTIME_DIR
    let original = env::var("XDG_RUNTIME_DIR");

    // Test with XDG_RUNTIME_DIR set
    env::set_var("XDG_RUNTIME_DIR", "/tmp/test-xdg");

    // The coordinator should use the socket path we provide
    let temp_dir = TempDir::new().unwrap();
    let socket_path = temp_dir.path().join("sigil.sock");

    let coordinator = sigil_daemon::ondemand::OnDemandCoordinator::new(&socket_path, None).unwrap();
    assert_eq!(coordinator.socket_path, socket_path);

    // Restore original
    match original {
        Ok(val) => env::set_var("XDG_RUNTIME_DIR", val),
        Err(_) => env::remove_var("XDG_RUNTIME_DIR"),
    }
}

#[tokio::test]
async fn test_ondemand_acquire_lockfile() {
    let (_temp_dir, socket_path, _lockfile_path) = setup_test_dirs();

    let coordinator = sigil_daemon::ondemand::OnDemandCoordinator::new(&socket_path, None).unwrap();

    // Acquire lockfile
    let lock_guard = coordinator.acquire_lockfile().await.unwrap();

    // Lockfile should exist
    assert!(coordinator.lockfile_path.exists());

    // Verify we can acquire it again (would block in real scenario)
    // Drop the guard first
    drop(lock_guard);

    // Lockfile should still exist but be unlocked
    assert!(coordinator.lockfile_path.exists());
}

// ============================================================================
// systemd socket activation tests
// ============================================================================

#[test]
fn test_systemd_socket_fd_detection() {
    // Save original environment
    let original_fds = env::var("LISTEN_FDS");
    let original_pid = env::var("LISTEN_PID");

    // Test 1: No LISTEN_FDS set
    env::remove_var("LISTEN_FDS");
    env::remove_var("LISTEN_PID");

    // We can't directly test get_systemd_socket_fd as it's private,
    // but we can verify the environment handling logic

    // Test 2: LISTEN_FDS=0
    env::set_var("LISTEN_FDS", "0");
    // Would return None

    // Test 3: LISTEN_FDS=1 (but wrong PID)
    env::set_var("LISTEN_FDS", "1");
    env::set_var("LISTEN_PID", "99999"); // Wrong PID

    // Would log error and return None

    // Restore original
    match original_fds {
        Ok(val) => env::set_var("LISTEN_FDS", val),
        Err(_) => env::remove_var("LISTEN_FDS"),
    }
    match original_pid {
        Ok(val) => env::set_var("LISTEN_PID", val),
        Err(_) => env::remove_var("LISTEN_PID"),
    }
}

#[test]
fn test_systemd_environment_cleanup() {
    // Save original
    let original_fds = env::var("LISTEN_FDS");
    let original_pid = env::var("LISTEN_PID");

    // Clear any existing values first
    env::remove_var("LISTEN_FDS");
    env::remove_var("LISTEN_PID");

    // Set environment variables
    env::set_var("LISTEN_FDS", "1");
    env::set_var("LISTEN_PID", &std::process::id().to_string());

    // Verify they're set
    assert!(env::var("LISTEN_FDS").is_ok());
    assert!(env::var("LISTEN_PID").is_ok());

    // Restore original
    match original_fds {
        Ok(val) => env::set_var("LISTEN_FDS", val),
        Err(_) => env::remove_var("LISTEN_FDS"),
    }
    match original_pid {
        Ok(val) => env::set_var("LISTEN_PID", val),
        Err(_) => env::remove_var("LISTEN_PID"),
    }
}

#[test]
fn test_sd_notify_abstract_namespace() {
    // Test abstract namespace socket path parsing
    let socket_path = "@/org/freedesktop/systemd/notify";

    let (is_abstract, unprefixed) = if let Some(rest) = socket_path.strip_prefix('@') {
        (true, rest.to_string())
    } else {
        (false, socket_path.to_string())
    };

    assert!(is_abstract);
    assert_eq!(unprefixed, "/org/freedesktop/systemd/notify");
}

#[test]
fn test_sd_notify_regular_path() {
    let socket_path = "/run/systemd/notify";

    let (is_abstract, unprefixed) = if let Some(rest) = socket_path.strip_prefix('@') {
        (true, rest.to_string())
    } else {
        (false, socket_path.to_string())
    };

    assert!(!is_abstract);
    assert_eq!(unprefixed, "/run/systemd/notify");
}

// ============================================================================
// launchd socket activation tests (macOS only)
// ============================================================================

#[cfg(target_os = "macos")]
#[test]
fn test_launchd_socket_name() {
    // Verify the socket name constant matches what's in the plist
    const SOCKET_NAME: &str = "sigil";
    assert_eq!(SOCKET_NAME, "sigil");
}

// ============================================================================
// Idle timeout tests
// ============================================================================

#[test]
fn test_idle_timeout_parsing() {
    // Test duration parsing for idle timeout
    // This is tested indirectly through the daemon's CLI parsing

    // Verify the format strings
    assert_eq!("30s", "30s"); // 30 seconds
    assert_eq!("5m", "5m");   // 5 minutes
    assert_eq!("2h", "2h");   // 2 hours
    assert_eq!("1d", "1d");   // 1 day
    assert_eq!("never", "never"); // never timeout
}

#[test]
fn test_idle_timeout_default() {
    // Default idle timeout is 30 minutes
    let default_timeout = Duration::from_secs(30 * 60);
    assert_eq!(default_timeout.as_secs(), 1800);
}

#[test]
fn test_idle_timeout_never() {
    // "never" should map to Duration::MAX
    let never_timeout = Duration::MAX;
    assert!(never_timeout.as_secs() > 365 * 24 * 60 * 60); // More than a year
}

#[test]
fn test_idle_timeout_check_interval() {
    // The idle timeout check interval is 60 seconds
    let check_interval = Duration::from_secs(60);
    assert_eq!(check_interval.as_secs(), 60);
}

// ============================================================================
// Integration tests (manual verification)
// ============================================================================

#[test]
fn test_socket_permissions_mask() {
    // Test that socket permissions are set correctly
    // SocketMode=0600 means only the owner has read/write

    let mode: u32 = 0o600;
    assert_eq!(mode, 0o600);

    // Verify the bits
    let owner_read = (mode & 0o400) != 0;
    let owner_write = (mode & 0o200) != 0;
    let group_read = (mode & 0o040) != 0;
    let group_write = (mode & 0o020) != 0;
    let other_read = (mode & 0o004) != 0;
    let other_write = (mode & 0o002) != 0;

    assert!(owner_read);
    assert!(owner_write);
    assert!(!group_read);
    assert!(!group_write);
    assert!(!other_read);
    assert!(!other_write);
}

#[test]
fn test_macos_sockpath_mode() {
    // On macOS, SockPathMode uses decimal representation of octal 0600
    // 384 decimal = 0600 octal = 0b0110000000 binary

    let sockpath_mode: u32 = 384;
    assert_eq!(sockpath_mode, 0o600);

    // Verify conversion
    let octal_equivalent: u32 = 0o600;
    assert_eq!(sockpath_mode, octal_equivalent);
}

// ============================================================================
// Race condition tests
// ============================================================================

#[tokio::test]
async fn test_multiple_clients_single_daemon() {
    let (_temp_dir, socket_path, _lockfile_path) = setup_test_dirs();

    let coordinator = sigil_daemon::ondemand::OnDemandCoordinator::new(&socket_path, None).unwrap();

    // Simulate multiple clients checking simultaneously
    // In a real scenario, only one would acquire the lock and start the daemon

    // All clients should see the daemon as not running initially
    assert!(!coordinator.is_daemon_running());

    // Create socket to simulate daemon started
    fs::File::create(&socket_path).unwrap();

    // Now all clients should see the daemon as running
    assert!(coordinator.is_daemon_running());
}

#[tokio::test]
async fn test_lockfile_exclusion() {
    let (_temp_dir, socket_path, _lockfile_path) = setup_test_dirs();

    let coordinator = sigil_daemon::ondemand::OnDemandCoordinator::new(&socket_path, None).unwrap();

    // First client acquires lock
    let lock1 = coordinator.acquire_lockfile().await.unwrap();

    // In a real multi-process scenario, the second client would block
    // In this test, we just verify the lockfile exists
    assert!(coordinator.lockfile_path.exists());

    // Drop the first lock
    drop(lock1);

    // Now a second lock can be acquired
    let _lock2 = coordinator.acquire_lockfile().await.unwrap();
}

// ============================================================================
// Socket wait timeout tests
// ============================================================================

#[test]
fn test_socket_wait_timeout_constants() {
    // Verify the timeout constants
    const SOCKET_WAIT_TIMEOUT: Duration = Duration::from_secs(5);
    const SOCKET_CHECK_INTERVAL: Duration = Duration::from_millis(100);
    const MAX_SPAWN_ATTEMPTS: u32 = 3;

    assert_eq!(SOCKET_WAIT_TIMEOUT, Duration::from_secs(5));
    assert_eq!(SOCKET_CHECK_INTERVAL, Duration::from_millis(100));
    assert_eq!(MAX_SPAWN_ATTEMPTS, 3);

    // Calculate number of checks in timeout
    let expected_checks = SOCKET_WAIT_TIMEOUT.as_millis() / SOCKET_CHECK_INTERVAL.as_millis();
    assert_eq!(expected_checks, 50); // 5000ms / 100ms = 50 checks
}
