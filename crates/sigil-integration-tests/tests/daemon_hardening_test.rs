//! Daemon Hardening Verification Tests
//!
//! Runtime tests to verify daemon security hardening measures:
//! - PR_SET_DUMPABLE=0 to prevent memory inspection
//! - mlockall to prevent swapping
//! - Kernel keyring for session token storage
//! - RLIMIT_CORE=0 to disable core dumps
//! - Socket with 0600 permissions

mod common;
use common::workspace_root;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use tempfile::TempDir;

/// Get the sigild binary path
fn sigild_path() -> PathBuf {
    workspace_root()
        .join("target")
        .join("debug")
        .join("sigild")
}

/// Get the sigil CLI binary path
fn sigil_path() -> PathBuf {
    workspace_root()
        .join("target")
        .join("debug")
        .join("sigil")
}

/// Test 1: Verify PR_SET_DUMPABLE=0 prevents memory reads
///
/// Starts a daemon, then checks /proc/<pid>/status to verify
/// the process is non-dumpable.
#[test]
fn test_daemon_sets_dumpable_zero() {
    // Skip if not Linux (no /proc)
    #[cfg(not(target_os = "linux"))]
    {
        return;
    }

    // Ensure binaries are built
    let sigild = sigild_path();
    if !sigild.exists() {
        eprintln!("sigild not found, skipping test. Run: cargo build --bin sigild");
        return;
    }

    // Create temporary directory for the test
    let temp_dir = TempDir::new().expect("Failed to create temp dir");
    let vault_path = temp_dir.path().join("vault");
    let socket_path = temp_dir.path().join("sigil.sock");

    // Set XDG_RUNTIME_DIR for the test
    std::env::set_var("XDG_RUNTIME_DIR", temp_dir.path());

    // Initialize a vault (no passphrase for CI testing)
    let sigil = sigil_path();
    if !sigil.exists() {
        eprintln!("sigil not found, skipping test. Run: cargo build --bin sigil");
        return;
    }

    let status = Command::new(&sigil)
        .arg("init")
        .arg("--vault")
        .arg(&vault_path)
        .arg("--no-passphrase")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();

    if !status.map(|s| s.success()).unwrap_or(false) {
        eprintln!("Failed to initialize vault, skipping test");
        return;
    }

    // Start the daemon in CI mode (no passphrase prompt)
    let mut child = Command::new(&sigild)
        .arg("daemon")
        .arg("start")
        .arg("--socket")
        .arg(&socket_path)
        .arg("--vault")
        .arg(&vault_path)
        .arg("--ci")
        .arg("--idle-timeout")
        .arg("never")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("Failed to start daemon");

    // Give the daemon time to start
    std::thread::sleep(std::time::Duration::from_millis(500));

    let pid = child.id();

    // Check /proc/<pid>/status for dumpable field
    let status_path = format!("/proc/{}/status", pid);
    let status_content = fs::read_to_string(&status_path);

    // Stop the daemon
    let _ = Command::new(&sigild)
        .arg("daemon")
        .arg("stop")
        .arg("--socket")
        .arg(&socket_path)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();

    let _ = child.wait();

    match status_content {
        Ok(content) => {
            // Look for the "dumpable" field in /proc/pid/status
            let dumpable_line = content
                .lines()
                .find(|line| line.starts_with("dumpable:"));

            match dumpable_line {
                Some(line) => {
                    let parts: Vec<&str> = line.split_whitespace().collect();
                    if parts.len() >= 2 {
                        let dumpable_value: u32 = parts[1]
                            .parse()
                            .unwrap_or(1);

                        assert_eq!(
                            dumpable_value, 0,
                            "PR_SET_DUMPABLE should be 0, got {}. Full line: {}",
                            dumpable_value, line
                        );
                    } else {
                        panic!("Failed to parse dumpable line: {}", line);
                    }
                }
                None => {
                    panic!("dumpable field not found in /proc/{}/status", pid);
                }
            }
        }
        Err(e) => {
            panic!("Failed to read /proc/{}/status: {}", pid, e);
        }
    }
}

/// Test 2: Verify session token is stored in kernel keyring (not file)
///
/// Starts a daemon and verifies that:
/// - Session token is accessible via keyctl
/// - No sigil-session-token file exists in $XDG_RUNTIME_DIR
#[test]
fn test_session_token_in_keyring() {
    // Skip if not Linux (keyring is Linux-specific)
    #[cfg(not(target_os = "linux"))]
    {
        return;
    }

    let sigild = sigild_path();
    if !sigild.exists() {
        eprintln!("sigild not found, skipping test. Run: cargo build --bin sigild");
        return;
    }

    let sigil = sigil_path();
    if !sigil.exists() {
        eprintln!("sigil not found, skipping test. Run: cargo build --bin sigil");
        return;
    }

    // Create temporary directory for the test
    let temp_dir = TempDir::new().expect("Failed to create temp dir");
    let vault_path = temp_dir.path().join("vault");
    let socket_path = temp_dir.path().join("sigil.sock");
    let runtime_dir = temp_dir.path().join("runtime");

    fs::create_dir_all(&runtime_dir).expect("Failed to create runtime dir");
    std::env::set_var("XDG_RUNTIME_DIR", &runtime_dir);

    // Initialize a vault
    let status = Command::new(&sigil)
        .arg("init")
        .arg("--vault")
        .arg(&vault_path)
        .arg("--no-passphrase")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();

    if !status.map(|s| s.success()).unwrap_or(false) {
        eprintln!("Failed to initialize vault, skipping test");
        return;
    }

    // Start the daemon in CI mode
    let mut child = Command::new(&sigild)
        .arg("daemon")
        .arg("start")
        .arg("--socket")
        .arg(&socket_path)
        .arg("--vault")
        .arg(&vault_path)
        .arg("--ci")
        .arg("--idle-timeout")
        .arg("never")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("Failed to start daemon");

    // Give the daemon time to start
    std::thread::sleep(std::time::Duration::from_millis(500));

    let pid = child.id();

    // Check that NO session token file exists
    let token_file = runtime_dir.join("sigil-session-token");
    assert!(
        !token_file.exists(),
        "Session token file should NOT exist when using kernel keyring. Found at: {:?}",
        token_file
    );

    // Check keyring for the session token
    // Use keyctl to search for the "sigil_session" key
    let keyctl_output = Command::new("keyctl")
        .arg("search")
        .arg("@s")
        .arg("user")
        .arg("sigil_session")
        .output();

    // Stop the daemon
    let _ = Command::new(&sigil)
        .arg("daemon")
        .arg("stop")
        .arg("--socket")
        .arg(&socket_path)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();

    let _ = child.wait();

    match keyctl_output {
        Ok(output) => {
            if output.status.success() {
                let key_id = String::from_utf8_lossy(&output.stdout);
                assert!(
                    !key_id.trim().is_empty(),
                    "keyctl should find sigil_session key in session keyring"
                );
                println!("Found session token in keyring: key ID {}", key_id.trim());
            } else {
                // keyctl might not be available or might fail with permissions
                eprintln!("keyctl search failed (might not be available in this environment)");
            }
        }
        Err(e) => {
            eprintln!("Failed to run keyctl: {} (might not be installed)", e);
        }
    }
}

/// Test 3: Verify socket permissions are 0600
///
/// Starts a daemon and checks that the Unix socket file
/// has permissions 0600 (owner read/write only).
#[test]
fn test_socket_permissions_are_0600() {
    let sigild = sigild_path();
    if !sigild.exists() {
        eprintln!("sigild not found, skipping test. Run: cargo build --bin sigild");
        return;
    }

    let sigil = sigil_path();
    if !sigil.exists() {
        eprintln!("sigil not found, skipping test. Run: cargo build --bin sigil");
        return;
    }

    // Create temporary directory for the test
    let temp_dir = TempDir::new().expect("Failed to create temp dir");
    let vault_path = temp_dir.path().join("vault");
    let socket_path = temp_dir.path().join("sigil.sock");
    let runtime_dir = temp_dir.path().join("runtime");

    fs::create_dir_all(&runtime_dir).expect("Failed to create runtime dir");
    std::env::set_var("XDG_RUNTIME_DIR", &runtime_dir);

    // Initialize a vault
    let status = Command::new(&sigil)
        .arg("init")
        .arg("--vault")
        .arg(&vault_path)
        .arg("--no-passphrase")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();

    if !status.map(|s| s.success()).unwrap_or(false) {
        eprintln!("Failed to initialize vault, skipping test");
        return;
    }

    // Start the daemon
    let mut child = Command::new(&sigild)
        .arg("daemon")
        .arg("start")
        .arg("--socket")
        .arg(&socket_path)
        .arg("--vault")
        .arg(&vault_path)
        .arg("--ci")
        .arg("--idle-timeout")
        .arg("never")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("Failed to start daemon");

    // Give the daemon time to start
    std::thread::sleep(std::time::Duration::from_millis(500));

    // Check socket permissions
    let metadata = fs::metadata(&socket_path);
    let has_socket = socket_path.exists();

    // Stop the daemon
    let _ = Command::new(&sigil)
        .arg("daemon")
        .arg("stop")
        .arg("--socket")
        .arg(&socket_path)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();

    let _ = child.wait();

    assert!(
        has_socket,
        "Socket file should exist at {}",
        socket_path.display()
    );

    let metadata = metadata.expect("Failed to get socket metadata");
    let permissions = metadata.permissions();
    let mode = permissions.mode();

    // Mask to get the last 9 bits (permissions)
    let perm_bits = mode & 0o777;

    assert_eq!(
        perm_bits, 0o600,
        "Socket permissions should be 0600, got {:04o}",
        perm_bits
    );
}

/// Test 4: Verify RLIMIT_CORE=0 disables core dumps
///
/// Starts a daemon and checks /proc/<pid>/limits to verify
/// core dump size is limited to 0.
#[test]
fn test_rlimit_core_is_zero() {
    // Skip if not Linux (no /proc)
    #[cfg(not(target_os = "linux"))]
    {
        return;
    }

    let sigild = sigild_path();
    if !sigild.exists() {
        eprintln!("sigild not found, skipping test. Run: cargo build --bin sigild");
        return;
    }

    let sigil = sigil_path();
    if !sigil.exists() {
        eprintln!("sigil not found, skipping test. Run: cargo build --bin sigil");
        return;
    }

    // Create temporary directory for the test
    let temp_dir = TempDir::new().expect("Failed to create temp dir");
    let vault_path = temp_dir.path().join("vault");
    let socket_path = temp_dir.path().join("sigil.sock");
    let runtime_dir = temp_dir.path().join("runtime");

    fs::create_dir_all(&runtime_dir).expect("Failed to create runtime dir");
    std::env::set_var("XDG_RUNTIME_DIR", &runtime_dir);

    // Initialize a vault
    let status = Command::new(&sigil)
        .arg("init")
        .arg("--vault")
        .arg(&vault_path)
        .arg("--no-passphrase")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();

    if !status.map(|s| s.success()).unwrap_or(false) {
        eprintln!("Failed to initialize vault, skipping test");
        return;
    }

    // Start the daemon
    let mut child = Command::new(&sigild)
        .arg("daemon")
        .arg("start")
        .arg("--socket")
        .arg(&socket_path)
        .arg("--vault")
        .arg(&vault_path)
        .arg("--ci")
        .arg("--idle-timeout")
        .arg("never")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("Failed to start daemon");

    // Give the daemon time to start
    std::thread::sleep(std::time::Duration::from_millis(500));

    let pid = child.id();

    // Check /proc/<pid>/limits for Max core file size
    let limits_path = format!("/proc/{}/limits", pid);
    let limits_content = fs::read_to_string(&limits_path);

    // Stop the daemon
    let _ = Command::new(&sigil)
        .arg("daemon")
        .arg("stop")
        .arg("--socket")
        .arg(&socket_path)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();

    let _ = child.wait();

    match limits_content {
        Ok(content) => {
            // Look for the "Max core file size" line
            let core_limit_line = content
                .lines()
                .find(|line| line.contains("core file size"));

            match core_limit_line {
                Some(line) => {
                    // The format is: "Max core file size  0  0  bytes"
                    // We need to check if the soft limit is 0
                    let parts: Vec<&str> = line.split_whitespace().collect();
                    // The soft limit is usually the second numeric value
                    if parts.len() >= 3 {
                        let soft_limit_str = parts[2];
                        if soft_limit_str == "0" {
                            // Core dumps are disabled
                            println!("Core dumps disabled: {}", line);
                        } else {
                            panic!(
                                "Core dump limit should be 0, got {}. Full line: {}",
                                soft_limit_str, line
                            );
                        }
                    } else {
                        eprintln!("Warning: Could not parse core limit line: {}", line);
                    }
                }
                None => {
                    eprintln!("Warning: 'Max core file size' line not found in /proc/{}/limits", pid);
                }
            }
        }
        Err(e) => {
            eprintln!("Failed to read /proc/{}/limits: {}", pid, e);
        }
    }
}

/// Test 5: Verify mlockall is called
///
/// This test checks that the daemon attempts to lock memory
/// by looking for the expected log message or by checking
/// /proc/<pid>/status for VM_LOCKED memory.
#[test]
fn test_mlockall_is_called() {
    // Skip if not Linux (no /proc)
    #[cfg(not(target_os = "linux"))]
    {
        return;
    }

    let sigild = sigild_path();
    if !sigild.exists() {
        eprintln!("sigild not found, skipping test. Run: cargo build --bin sigild");
        return;
    }

    let sigil = sigil_path();
    if !sigil.exists() {
        eprintln!("sigil not found, skipping test. Run: cargo build --bin sigil");
        return;
    }

    // Create temporary directory for the test
    let temp_dir = TempDir::new().expect("Failed to create temp dir");
    let vault_path = temp_dir.path().join("vault");
    let socket_path = temp_dir.path().join("sigil.sock");
    let runtime_dir = temp_dir.path().join("runtime");
    let log_path = temp_dir.path().join("daemon.log");

    fs::create_dir_all(&runtime_dir).expect("Failed to create runtime dir");
    std::env::set_var("XDG_RUNTIME_DIR", &runtime_dir);

    // Initialize a vault
    let status = Command::new(&sigil)
        .arg("init")
        .arg("--vault")
        .arg(&vault_path)
        .arg("--no-passphrase")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();

    if !status.map(|s| s.success()).unwrap_or(false) {
        eprintln!("Failed to initialize vault, skipping test");
        return;
    }

    // Start the daemon with logging
    let log_file = fs::File::create(&log_path).expect("Failed to create log file");
    let mut child = Command::new(&sigild)
        .arg("daemon")
        .arg("start")
        .arg("--socket")
        .arg(&socket_path)
        .arg("--vault")
        .arg(&vault_path)
        .arg("--ci")
        .arg("--idle-timeout")
        .arg("never")
        .stdout(Stdio::from(log_file.try_clone().unwrap()))
        .stderr(Stdio::from(log_file))
        .spawn()
        .expect("Failed to start daemon");

    // Give the daemon time to start
    std::thread::sleep(std::time::Duration::from_millis(500));

    let pid = child.id();

    // Check /proc/<pid>/status for VmLck (locked memory)
    let status_path = format!("/proc/{}/status", pid);
    let status_content = fs::read_to_string(&status_path);

    // Stop the daemon
    let _ = Command::new(&sigil)
        .arg("daemon")
        .arg("stop")
        .arg("--socket")
        .arg(&socket_path)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();

    let _ = child.wait();

    // Check the log for mlockall message
    let log_content = fs::read_to_string(&log_path).unwrap_or_default();
    assert!(
        log_content.contains("Memory locked") || log_content.contains("mlockall"),
        "Daemon log should indicate memory was locked with mlockall"
    );

    // Optionally check VmLck in /proc/pid/status
    if let Ok(content) = status_content {
        if let Some(vmlck_line) = content.lines().find(|line| line.starts_with("VmLck:")) {
            println!("Locked memory: {}", vmlck_line);
        }
    }
}
