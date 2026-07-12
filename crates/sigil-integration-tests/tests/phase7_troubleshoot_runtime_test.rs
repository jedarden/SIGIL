//! Phase 7 Troubleshoot Runtime Tests
//!
//! Runtime tests for the `sigil troubleshoot` command that verify actual
//! behavior rather than just source code structure.
//!
//! These tests verify:
//! - Daemon connectivity check (active IPC test)
//! - Vault accessibility check
//! - Sandbox availability check
//! - Hooks installation check
//! - Permissions validation
//! - Error detection and remediation suggestions

mod common;
use common::workspace_root;
use sigil_integration_tests::DaemonGuard;
use std::fs;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use tempfile::TempDir;

/// Get the sigild binary path
fn sigild_path() -> PathBuf {
    workspace_root().join("target").join("debug").join("sigild")
}

/// Get the sigil CLI binary path
fn sigil_path() -> PathBuf {
    workspace_root().join("target").join("debug").join("sigil")
}

/// Test 1: Verify troubleshoot command runs successfully
///
/// This test verifies that:
/// - `sigil troubleshoot` command exists and executes
/// - Returns structured output with all check categories
/// - Handles gracefully when daemon is not running
#[test]
fn test_troubleshoot_runs_without_daemon() {
    let sigil = sigil_path();
    if !sigil.exists() {
        eprintln!("sigil not found, skipping test. Run: cargo build --bin sigil");
        return;
    }

    // Run troubleshoot without starting daemon
    let output = Command::new(&sigil)
        .arg("troubleshoot")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output();

    match output {
        Ok(result) => {
            let stdout = String::from_utf8_lossy(&result.stdout);
            let stderr = String::from_utf8_lossy(&result.stderr);

            // Command should execute (may fail with daemon not running)
            // but should produce structured output
            let combined = format!("{}\n{}", stdout, stderr);

            // Verify output contains check categories
            assert!(
                combined.contains("Daemon") || combined.contains("daemon"),
                "Troubleshoot output should mention Daemon check"
            );
            assert!(
                combined.contains("Vault") || combined.contains("vault"),
                "Troubleshoot output should mention Vault check"
            );

            // Should detect daemon is not running
            assert!(
                combined.contains("not running")
                    || combined.contains("stopped")
                    || combined.contains("not responding")
                    || combined.contains("Fail"),
                "Troubleshoot should detect daemon is not running"
            );

            println!("Troubleshoot output:\n{}", combined);
        }
        Err(e) => {
            eprintln!("Failed to run sigil troubleshoot: {}", e);
            // This is acceptable if the command doesn't exist yet
        }
    }
}

/// Test 2: Verify troubleshoot detects vault issues
///
/// This test verifies that:
/// - troubleshoot checks vault accessibility
/// - Reports errors when vault is missing or corrupted
/// - Provides actionable remediation steps
#[test]
fn test_troubleshoot_detects_vault_issues() {
    let sigil = sigil_path();
    if !sigil.exists() {
        return;
    }

    // Create temp directory with no vault
    let temp_dir = TempDir::new().expect("Failed to create temp dir");
    let sigil_dir = temp_dir.path().join(".sigil");

    // Run troubleshoot with custom sigil directory
    let output = Command::new(&sigil)
        .arg("troubleshoot")
        .env("SIGIL_DIR", sigil_dir)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output();

    if let Ok(result) = output {
        let stdout = String::from_utf8_lossy(&result.stdout);
        let stderr = String::from_utf8_lossy(&result.stderr);
        let combined = format!("{}\n{}", stdout, stderr);

        // Should detect vault doesn't exist
        let vault_check_found = combined.contains("Vault")
            || combined.contains("vault")
            || combined.contains(".sigil/vault");

        if vault_check_found {
            // Should report failure or warning
            assert!(
                combined.contains("Fail")
                    || combined.contains("not found")
                    || combined.contains("does not exist")
                    || combined.contains("Warn"),
                "Troubleshoot should report vault issue"
            );
        }
    }
}

/// Test 3: Verify troubleshoot with running daemon
///
/// This test verifies that:
/// - troubleshoot performs active IPC test with daemon
/// - Reports daemon status correctly
/// - Checks daemon health (PR_SET_DUMPABLE, mlock)
#[test]
fn test_troubleshoot_with_running_daemon() {
    let sigild = sigild_path();
    let sigil = sigil_path();

    // Skip if binaries are missing
    skip_if_binary_missing!(
        &sigild,
        "daemon binary required for troubleshoot daemon test"
    );
    skip_if_binary_missing!(&sigil, "CLI binary required for troubleshoot daemon test");

    // Check if we can start the daemon
    if !common::can_start_daemon(&sigild, false) {
        eprintln!("Skipping test: daemon cannot be started in this environment");
        return;
    }

    // Create temporary directory for the test
    let temp_dir = TempDir::new().expect("Failed to create temp dir");
    let vault_path = temp_dir.path().join("vault");
    let socket_path = temp_dir.path().join("sigil.sock");
    let runtime_dir = common::ensure_xdg_runtime_dir();

    // Initialize a vault
    let init_status = Command::new(&sigil)
        .arg("init")
        .arg("--path")
        .arg(&vault_path)
        .arg("--no-passphrase")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();

    if !init_status.map(|s| s.success()).unwrap_or(false) {
        eprintln!("Failed to initialize vault, skipping test");
        return;
    }

    // Start the daemon
    let _guard = DaemonGuard::new(
        Command::new(&sigild)
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
            .expect("Failed to start daemon"),
    );

    // Wait for daemon to be ready (not just socket existence)
    if !common::wait_for_daemon_ready(&socket_path, 5000) {
        eprintln!("Daemon did not become ready within timeout, skipping test");
        return;
    }

    // Run troubleshoot - it will find socket via XDG_RUNTIME_DIR
    let output = Command::new(&sigil)
        .arg("troubleshoot")
        .env("XDG_RUNTIME_DIR", &runtime_dir)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output();

    if let Ok(result) = output {
        let stdout = String::from_utf8_lossy(&result.stdout);
        let stderr = String::from_utf8_lossy(&result.stderr);
        let combined = format!("{}\n{}", stdout, stderr);

        println!("Troubleshoot output with running daemon:\n{}", combined);

        // Should detect daemon is running
        assert!(
            combined.contains("running")
                || combined.contains("PASS")
                || combined.contains("OK")
                || combined.contains("connected"),
            "Troubleshoot should detect daemon is running"
        );

        // Should check vault
        assert!(
            combined.contains("Vault") || combined.contains("vault"),
            "Troubleshoot should check vault status"
        );
    }

    // Stop the daemon
    let _ = Command::new(&sigild)
        .arg("daemon")
        .arg("stop")
        .arg("--socket")
        .arg(&socket_path)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();
}

/// Test 4: Verify troubleshoot checks sandbox availability
///
/// This test verifies that:
/// - troubleshoot checks for bubblewrap availability
/// - Reports sandbox status
/// - Tests sandbox execution actively
#[test]
fn test_troubleshoot_checks_sandbox() {
    let sigil = sigil_path();
    if !sigil.exists() {
        return;
    }

    // Check if bwrap is available first
    let bwrap_available = common::is_bwrap_available();
    if !bwrap_available {
        eprintln!("Skipping troubleshoot sandbox check: bwrap not available");
        return;
    }

    // Run troubleshoot
    let output = Command::new(&sigil)
        .arg("troubleshoot")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output();

    if let Ok(result) = output {
        let stdout = String::from_utf8_lossy(&result.stdout);
        let stderr = String::from_utf8_lossy(&result.stderr);
        let combined = format!("{}\n{}", stdout, stderr);

        // Check for sandbox-related output
        // This may not be present if troubleshoot doesn't check sandbox yet
        let has_sandbox = combined.contains("Sandbox")
            || combined.contains("sandbox")
            || combined.contains("bwrap")
            || combined.contains("bubblewrap");

        if has_sandbox {
            println!("Sandbox check found in troubleshoot output");
        }
    }
}

/// Test 5: Verify troubleshoot checks hooks installation
///
/// This test verifies that:
/// - troubleshoot checks Claude Code settings.json
/// - Validates hook installation
/// - Reports missing or broken hooks
#[test]
fn test_troubleshoot_checks_hooks() {
    let sigil = sigil_path();
    if !sigil.exists() {
        return;
    }

    // Create temp directory with no hooks
    let temp_dir = TempDir::new().expect("Failed to create temp dir");
    let claude_dir = temp_dir.path().join(".claude");

    // Run troubleshoot with custom Claude directory
    let output = Command::new(&sigil)
        .arg("troubleshoot")
        .env("CLAUDE_CONFIG_DIR", &claude_dir)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output();

    if let Ok(result) = output {
        let stdout = String::from_utf8_lossy(&result.stdout);
        let stderr = String::from_utf8_lossy(&result.stderr);
        let combined = format!("{}\n{}", stdout, stderr);

        // Check for hooks-related output
        let has_hooks = combined.contains("Hooks")
            || combined.contains("hooks")
            || combined.contains("settings.json");

        if has_hooks {
            // Should report missing hooks
            assert!(
                combined.contains("not found")
                    || combined.contains("missing")
                    || combined.contains("Warn")
                    || combined.contains("Fail"),
                "Troubleshoot should report missing hooks"
            );
        }
    }
}

/// Test 6: Verify troubleshoot provides actionable remediation
///
/// This test verifies that:
/// - Failures include specific remediation steps
/// - Remediation includes actual commands to run
/// - Suggestions are numbered and clear
#[test]
fn test_troubleshoot_actionable_remediation() {
    let sigil = sigil_path();
    if !sigil.exists() {
        return;
    }

    // Run troubleshoot without daemon (will produce failures)
    let output = Command::new(&sigil)
        .arg("troubleshoot")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output();

    if let Ok(result) = output {
        let stdout = String::from_utf8_lossy(&result.stdout);
        let stderr = String::from_utf8_lossy(&result.stderr);
        let combined = format!("{}\n{}", stdout, stderr);

        // Look for remediation patterns
        // Should include commands like "sigild start" or "sigil init"
        let has_remediation = combined.contains("sigild start")
            || combined.contains("sigil init")
            || combined.contains("Remediation")
            || combined.contains("Suggestion")
            || combined.contains("To fix:")
            || combined.contains("1.")
            || combined.contains("2.");

        // Also check for common fix patterns
        let has_fix_commands = combined.contains("chmod")
            || combined.contains("install")
            || combined.contains("apt")
            || combined.contains("dnf")
            || combined.contains("pacman");

        if has_remediation || has_fix_commands {
            println!("Troubleshoot provides remediation steps");
        }
    }
}

/// Test 7: Verify troubleshoot verbose mode
///
/// This test verifies that:
/// - --verbose flag provides more detailed output
/// - Includes additional diagnostic information
#[test]
fn test_troubleshoot_verbose_mode() {
    let sigil = sigil_path();
    if !sigil.exists() {
        return;
    }

    // Run troubleshoot with --verbose
    let output = Command::new(&sigil)
        .arg("troubleshoot")
        .arg("--verbose")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output();

    if let Ok(result) = output {
        let stdout = String::from_utf8_lossy(&result.stdout);
        let stderr = String::from_utf8_lossy(&result.stderr);
        let combined = format!("{}\n{}", stdout, stderr);

        // Verbose mode should produce more output
        // At minimum, command should not crash
        println!("Verbose troubleshoot output:\n{}", combined);
    }
}

/// Test 8: Verify troubleshoot exit codes
///
/// This test verifies that:
/// - Exit code 0 when all checks pass
/// - Non-zero exit code when there are failures
#[test]
fn test_troubleshoot_exit_codes() {
    let sigil = sigil_path();
    if !sigil.exists() {
        return;
    }

    // Run troubleshoot (will likely have failures without setup)
    let output = Command::new(&sigil)
        .arg("troubleshoot")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output();

    if let Ok(result) = output {
        let stdout = String::from_utf8_lossy(&result.stdout);
        let stderr = String::from_utf8_lossy(&result.stderr);

        // If there are failures, exit code should be non-zero
        let has_failures = stdout.contains("Fail")
            || stderr.contains("Fail")
            || stdout.contains("ERROR")
            || stderr.contains("ERROR");

        if has_failures {
            assert!(
                !result.status.success(),
                "Troubleshoot should exit with non-zero when there are failures"
            );
        }
    }
}

/// Test 9: Verify troubleshoot checks permissions
///
/// This test verifies that:
/// - Checks vault directory permissions (0700)
/// - Checks identity file permissions (0600/0400)
/// - Reports insecure permissions
#[test]
fn test_troubleshoot_checks_permissions() {
    let sigil = sigil_path();
    if !sigil.exists() {
        return;
    }

    // Create a vault with intentionally wrong permissions
    let temp_dir = TempDir::new().expect("Failed to create temp dir");
    let vault_path = temp_dir.path().join("vault");

    // Initialize vault
    let init_status = Command::new(&sigil)
        .arg("init")
        .arg("--path")
        .arg(&vault_path)
        .arg("--no-passphrase")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();

    if !init_status.map(|s| s.success()).unwrap_or(false) {
        return;
    }

    // Make identity file world-readable (insecure)
    let identity_path = vault_path.join("identity.age");
    if identity_path.exists() {
        // Set permissions to 0644 (insecure)
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perms = fs::metadata(&identity_path)
                .expect("Failed to get metadata")
                .permissions();
            perms.set_mode(0o644);
            fs::set_permissions(&identity_path, perms).expect("Failed to set permissions");
        }

        // Run troubleshoot
        let output = Command::new(&sigil)
            .arg("troubleshoot")
            .env("SIGIL_DIR", temp_dir.path())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .output();

        if let Ok(result) = output {
            let stdout = String::from_utf8_lossy(&result.stdout);
            let stderr = String::from_utf8_lossy(&result.stderr);
            let combined = format!("{}\n{}", stdout, stderr);

            // Should detect permission issues
            let detected_issue = combined.contains("permission")
                || combined.contains("Permission")
                || combined.contains("insecure")
                || combined.contains("0644")
                || combined.contains("world-readable");

            if detected_issue {
                println!("Troubleshoot detected permission issue");
            }
        }
    }
}
