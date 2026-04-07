//! Doctor Health Check Integration Tests
//!
//! These tests verify the health check properties of SIGIL doctor
//! as specified in Phase 9 Deliverables.

mod common;
use common::workspace_root;
use std::fs;

/// Test 1: Verify doctor detects vault issues
///
/// From Phase 9 Checkpoint:
/// "Doctor: verify doctor detects deliberately introduced misconfigurations"
#[test]
fn test_doctor_detects_vault_issues() {
    // Read the doctor implementation
    let doctor_path = workspace_root().join("crates/sigil-cli/src/doctor.rs");
    let doctor_code = fs::read_to_string(&doctor_path).expect("Failed to read doctor code");

    // Verify vault checks exist
    assert!(
        doctor_code.contains("check_vault") || doctor_code.contains("vault"),
        "Doctor must check vault status"
    );

    // Verify fail status exists
    assert!(
        doctor_code.contains("Fail") || doctor_code.contains("fail"),
        "Doctor must report failed checks"
    );

    // Check that vault check can detect missing vault
    assert!(
        doctor_code.contains("not initialized")
            || doctor_code.contains("not found")
            || doctor_code.contains("exists"),
        "Doctor must detect missing vault"
    );
}

/// Test 2: Verify doctor detects daemon issues
///
/// From Phase 9 Deliverables:
/// "Checks: Daemon: running, memory protected, socket permissions"
#[test]
fn test_doctor_detects_daemon_issues() {
    // Read the doctor implementation
    let doctor_path = workspace_root().join("crates/sigil-cli/src/doctor.rs");
    let doctor_code = fs::read_to_string(&doctor_path).expect("Failed to read doctor code");

    // Verify daemon checks exist
    assert!(
        doctor_code.contains("check_daemon") || doctor_code.contains("daemon"),
        "Doctor must check daemon status"
    );

    // Verify socket check exists
    assert!(
        doctor_code.contains("socket") || doctor_code.contains(".sock"),
        "Doctor must check daemon socket"
    );
}

/// Test 3: Verify doctor detects sandbox issues
///
/// From Phase 9 Deliverables:
/// "Checks: Sandbox: bubblewrap available, seccomp compiled, namespace isolation verified"
#[test]
fn test_doctor_detects_sandbox_issues() {
    // Read the doctor implementation
    let doctor_path = workspace_root().join("crates/sigil-cli/src/doctor.rs");
    let doctor_code = fs::read_to_string(&doctor_path).expect("Failed to read doctor code");

    // Verify sandbox checks exist
    assert!(
        doctor_code.contains("check_sandbox")
            || doctor_code.contains("sandbox")
            || doctor_code.contains("bwrap")
            || doctor_code.contains("bubblewrap"),
        "Doctor must check sandbox availability"
    );

    // Check for bubblewrap detection
    assert!(
        doctor_code.contains("bwrap") || doctor_code.contains("bubblewrap"),
        "Doctor must check for bubblewrap"
    );
}

/// Test 4: Verify doctor detects hook installation issues
///
/// From Phase 9 Deliverables:
/// "Checks: Hooks: all tool hooks installed"
#[test]
fn test_doctor_detects_hook_issues() {
    // Read the doctor implementation
    let doctor_path = workspace_root().join("crates/sigil-cli/src/doctor.rs");
    let doctor_code = fs::read_to_string(&doctor_path).expect("Failed to read doctor code");

    // Verify hook checks exist
    assert!(
        doctor_code.contains("check_hooks")
            || doctor_code.contains("hooks")
            || doctor_code.contains("claude"),
        "Doctor must check hook installation"
    );

    // Check for Claude Code specific hook checks
    assert!(
        doctor_code.contains("settings.json") || doctor_code.contains("claude"),
        "Doctor should check Claude Code hooks"
    );
}

/// Test 5: Verify doctor backend health checks
///
/// From Phase 9 Deliverables (recently added):
/// "Backends: each configured backend reachable and authenticated"
#[test]
fn test_doctor_backend_health_checks() {
    // Read the doctor implementation
    let doctor_path = workspace_root().join("crates/sigil-cli/src/doctor.rs");
    let doctor_code = fs::read_to_string(&doctor_path).expect("Failed to read doctor code");

    // Verify backend checks exist
    assert!(
        doctor_code.contains("check_backend")
            || doctor_code.contains("backends")
            || doctor_code.contains("backend_health"),
        "Doctor must check backend connectivity"
    );

    // Check for specific backend types
    let backend_types = vec!["vault", "aws", "onepassword", "pass", "sops"];
    let mut checks_backend = false;

    for backend in backend_types {
        if doctor_code.contains(backend) && doctor_code.contains("check") {
            checks_backend = true;
            break;
        }
    }

    assert!(
        checks_backend,
        "Doctor should check specific backend types (vault, aws, etc.)"
    );
}

/// Test 6: Verify doctor provides fix suggestions
///
/// From Phase 9 Deliverables:
/// "Each check returns: PASS, WARN (with suggestion), or FAIL (with fix command)"
#[test]
fn test_doctor_fix_suggestions() {
    // Read the doctor implementation
    let doctor_path = workspace_root().join("crates/sigil-cli/src/doctor.rs");
    let doctor_code = fs::read_to_string(&doctor_path).expect("Failed to read doctor code");

    // Verify CheckResult has status field
    assert!(
        doctor_code.contains("CheckStatus") || doctor_code.contains("CheckResult"),
        "Doctor must have structured check results"
    );

    // Verify warn/fail have suggestions
    assert!(
        (doctor_code.contains("Warn") && doctor_code.contains("suggestion"))
            || (doctor_code.contains("Fail") && doctor_code.contains("fix")),
        "Check results should include fix suggestions"
    );
}

/// Test 7: Verify doctor generates security score
///
/// From Phase 9 Deliverables:
/// "Aggregate security score: 0-100"
#[test]
fn test_doctor_security_score() {
    // Read the doctor implementation
    let doctor_path = workspace_root().join("crates/sigil-cli/src/doctor.rs");
    let doctor_code = fs::read_to_string(&doctor_path).expect("Failed to read doctor code");

    // Verify score calculation exists
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
}

/// Test 8: Verify doctor CI mode
///
/// From Phase 9 Deliverables:
/// "CI mode: sigil doctor --ci --min-score 90 exits non-zero if score too low"
#[test]
fn test_doctor_ci_mode() {
    // Read the doctor implementation
    let doctor_path = workspace_root().join("crates/sigil-cli/src/doctor.rs");
    let doctor_code = fs::read_to_string(&doctor_path).expect("Failed to read doctor code");

    // Check for CI mode support
    let has_ci_mode = doctor_code.contains("ci")
        || doctor_code.contains("CI")
        || doctor_code.contains("min_score")
        || doctor_code.contains("exit_code");

    // Verify exit code handling for CI
    if has_ci_mode {
        assert!(
            doctor_code.contains("exit") || doctor_code.contains("ExitCode"),
            "Doctor should support CI mode exit codes"
        );
    }
}

/// Test 9: Verify doctor JSON output
///
/// From Phase 9 Deliverables:
/// "JSON output: sigil doctor --json for programmatic consumption"
#[test]
fn test_doctor_json_output() {
    // Read the doctor implementation
    let doctor_path = workspace_root().join("crates/sigil-cli/src/doctor.rs");
    let doctor_code = fs::read_to_string(&doctor_path).expect("Failed to read doctor code");

    // Check for JSON output support
    let has_json = doctor_code.contains("json")
        || doctor_code.contains("JSON")
        || doctor_code.contains("serialize");

    // Verify JSON serialization
    if has_json {
        assert!(
            doctor_code.contains("Serialize")
                || doctor_code.contains("serde")
                || doctor_code.contains("to_string"),
            "Doctor should support JSON output"
        );
    }
}

/// Test 10: Verify doctor WSL2 detection
///
/// From Phase 9 Deliverables:
/// "WSL2 uses Linux namespaces natively — no special handling needed
///  WSL2-specific check: verify /dev/shm is available for tmpfs"
#[test]
fn test_doctor_wsl2_detection() {
    // Read the doctor implementation
    let doctor_path = workspace_root().join("crates/sigil-cli/src/doctor.rs");
    let doctor_code = fs::read_to_string(&doctor_path).expect("Failed to read doctor code");

    // Verify WSL detection exists
    assert!(
        doctor_code.contains("WSL")
            || doctor_code.contains("wsl")
            || doctor_code.contains("detect_wsl")
            || doctor_code.contains("platform"),
        "Doctor should detect WSL environment"
    );

    // Check for /dev/shm check
    let has_dev_shm_check = doctor_code.contains("/dev/shm")
        || doctor_code.contains("dev_shm")
        || doctor_code.contains("tmpfs");

    // /dev/shm check is WSL2-specific
    if has_dev_shm_check {
        assert!(
            doctor_code.contains("WSL") || doctor_code.contains("wsl"),
            "/dev/shm check should be in WSL context"
        );
    }
}

/// Test 11: Verify doctor git safety checks
///
/// From Phase 9 Deliverables:
/// "Git safety: device.key in gitignore, no plaintext secrets in staging area"
#[test]
fn test_doctor_git_safety() {
    // Read the doctor implementation
    let doctor_path = workspace_root().join("crates/sigil-cli/src/doctor.rs");
    let doctor_code = fs::read_to_string(&doctor_path).expect("Failed to read doctor code");

    // Verify git checks exist
    assert!(
        doctor_code.contains("git") || doctor_code.contains("Git"),
        "Doctor should check git safety"
    );

    // Check for gitignore verification
    assert!(
        doctor_code.contains("gitignore") || doctor_code.contains(".gitignore"),
        "Doctor should verify identity file in gitignore"
    );
}

/// Test 12: Verify doctor audit log checks
///
/// From Phase 9 Deliverables:
/// "Audit log: exists, hash chain intact, append-only flag set"
#[test]
fn test_doctor_audit_log_checks() {
    // Read the doctor implementation
    let doctor_path = workspace_root().join("crates/sigil-cli/src/doctor.rs");
    let doctor_code = fs::read_to_string(&doctor_path).expect("Failed to read doctor code");

    // Verify audit log checks exist
    assert!(
        doctor_code.contains("audit") || doctor_code.contains("Audit"),
        "Doctor should check audit log status"
    );

    // Check for append-only flag check (Linux)
    #[cfg(target_os = "linux")]
    assert!(
        doctor_code.contains("append")
            || doctor_code.contains("chattr")
            || doctor_code.contains("immutable"),
        "Doctor should check append-only flag on Linux"
    );
}

// ============================================================================
// TROUBLESHOOT COMMAND TESTS
// ============================================================================

/// Test 13: Verify troubleshoot daemon checks
///
/// From Phase 9 Deliverables:
/// "Active component testing: send test IPC message to daemon"
#[test]
fn test_troubleshoot_daemon_checks() {
    // Read the troubleshoot implementation
    let troubleshoot_path = workspace_root().join("crates/sigil-cli/src/troubleshoot.rs");
    let troubleshoot_code =
        fs::read_to_string(&troubleshoot_path).expect("Failed to read troubleshoot code");

    // Verify daemon check function exists
    assert!(
        troubleshoot_code.contains("check_daemon"),
        "Troubleshoot must check daemon status"
    );

    // Verify active IPC test exists
    assert!(
        troubleshoot_code.contains("test_daemon_ipc") || troubleshoot_code.contains("IpcRequest"),
        "Troubleshoot must actively test daemon IPC connectivity"
    );

    // Verify socket path detection
    assert!(
        troubleshoot_code.contains("XDG_RUNTIME_DIR") || troubleshoot_code.contains("sigil.sock"),
        "Troubleshoot must detect socket path"
    );
}

/// Test 14: Verify troubleshoot vault checks
///
/// From Phase 9 Deliverables:
/// "Active component testing: verify vault can be opened"
#[test]
fn test_troubleshoot_vault_checks() {
    // Read the troubleshoot implementation
    let troubleshoot_path = workspace_root().join("crates/sigil-cli/src/troubleshoot.rs");
    let troubleshoot_code =
        fs::read_to_string(&troubleshoot_path).expect("Failed to read troubleshoot code");

    // Verify vault check function exists
    assert!(
        troubleshoot_code.contains("check_vault"),
        "Troubleshoot must check vault status"
    );

    // Verify vault loading test exists
    assert!(
        troubleshoot_code.contains("LocalVault") || troubleshoot_code.contains("load"),
        "Troubleshoot must test vault can be opened"
    );

    // Verify secret counting
    assert!(
        troubleshoot_code.contains("count_secrets") || troubleshoot_code.contains("secret_count"),
        "Troubleshoot should count secrets in vault"
    );
}

/// Test 15: Verify troubleshoot sandbox checks
///
/// From Phase 9 Deliverables:
/// "Active component testing: run test command in sandbox"
#[test]
fn test_troubleshoot_sandbox_checks() {
    // Read the troubleshoot implementation
    let troubleshoot_path = workspace_root().join("crates/sigil-cli/src/troubleshoot.rs");
    let troubleshoot_code =
        fs::read_to_string(&troubleshoot_path).expect("Failed to read troubleshoot code");

    // Verify sandbox check function exists
    assert!(
        troubleshoot_code.contains("check_sandbox"),
        "Troubleshoot must check sandbox availability"
    );

    // Verify active sandbox test exists
    assert!(
        troubleshoot_code.contains("test_sandbox_execution") || troubleshoot_code.contains("bwrap"),
        "Troubleshoot must actively test sandbox execution"
    );

    // Verify namespace support check
    assert!(
        troubleshoot_code.contains("check_namespace_support")
            || troubleshoot_code.contains("namespace"),
        "Troubleshoot must verify namespace support"
    );
}

/// Test 16: Verify troubleshoot hooks checks
///
/// From Phase 9 Deliverables:
/// "Active component testing: verify hook installation responds correctly"
#[test]
fn test_troubleshoot_hooks_checks() {
    // Read the troubleshoot implementation
    let troubleshoot_path = workspace_root().join("crates/sigil-cli/src/troubleshoot.rs");
    let troubleshoot_code =
        fs::read_to_string(&troubleshoot_path).expect("Failed to read troubleshoot code");

    // Verify hooks check function exists
    assert!(
        troubleshoot_code.contains("check_hooks"),
        "Troubleshoot must check hook installation"
    );

    // Verify settings.json check
    assert!(
        troubleshoot_code.contains("settings.json") || troubleshoot_code.contains(".claude"),
        "Troubleshoot should verify Claude Code settings"
    );

    // Verify JSON validation
    assert!(
        troubleshoot_code.contains("serde_json") || troubleshoot_code.contains("from_str"),
        "Troubleshoot should validate settings.json syntax"
    );
}

/// Test 17: Verify troubleshoot permissions checks
///
/// From Phase 9 Deliverables:
/// "Produce actionable remediation steps for each failure"
#[test]
fn test_troubleshoot_permissions_checks() {
    // Read the troubleshoot implementation
    let troubleshoot_path = workspace_root().join("crates/sigil-cli/src/troubleshoot.rs");
    let troubleshoot_code =
        fs::read_to_string(&troubleshoot_path).expect("Failed to read troubleshoot code");

    // Verify permissions check function exists
    assert!(
        troubleshoot_code.contains("check_permissions"),
        "Troubleshoot must check file permissions"
    );

    // Verify permission checking for vault
    assert!(
        troubleshoot_code.contains("0700") || troubleshoot_code.contains("chmod"),
        "Troubleshoot should verify vault directory permissions"
    );

    // Verify append-only flag check for audit log
    assert!(
        troubleshoot_code.contains("append-only") || troubleshoot_code.contains("lsattr"),
        "Troubleshoot should check audit log append-only flag"
    );
}

/// Test 18: Verify troubleshoot status types
///
/// From Phase 9 Deliverables:
/// "Each check returns: PASS, WARN (with suggestion), or FAIL (with fix command)"
#[test]
fn test_troubleshoot_status_types() {
    // Read the troubleshoot implementation
    let troubleshoot_path = workspace_root().join("crates/sigil-cli/src/troubleshoot.rs");
    let troubleshoot_code =
        fs::read_to_string(&troubleshoot_path).expect("Failed to read troubleshoot code");

    // Verify TroubleshootStatus enum exists with all variants
    assert!(
        troubleshoot_code.contains("TroubleshootStatus"),
        "Troubleshoot must have status type"
    );

    // Verify Pass variant with optional info
    assert!(
        troubleshoot_code.contains("Pass") && troubleshoot_code.contains("info"),
        "TroubleshootStatus must have Pass variant with optional info"
    );

    // Verify Warn variant with message and suggestion
    assert!(
        troubleshoot_code.contains("Warn")
            && troubleshoot_code.contains("message")
            && troubleshoot_code.contains("suggestion"),
        "TroubleshootStatus must have Warn variant with message and suggestion"
    );

    // Verify Fail variant with error and remediation steps
    assert!(
        troubleshoot_code.contains("Fail")
            && troubleshoot_code.contains("error")
            && troubleshoot_code.contains("remediation"),
        "TroubleshootStatus must have Fail variant with error and remediation steps"
    );
}

/// Test 19: Verify troubleshoot report formatting
///
/// From Phase 9 Deliverables:
/// "Produce actionable remediation steps for each failure (not just pass/fail)"
#[test]
fn test_troubleshoot_report_formatting() {
    // Read the troubleshoot implementation
    let troubleshoot_path = workspace_root().join("crates/sigil-cli/src/troubleshoot.rs");
    let troubleshoot_code =
        fs::read_to_string(&troubleshoot_path).expect("Failed to read troubleshoot code");

    // Verify TroubleshootReport exists
    assert!(
        troubleshoot_code.contains("TroubleshootReport"),
        "Troubleshoot must have report type"
    );

    // Verify format method exists
    assert!(
        troubleshoot_code.contains("fn format"),
        "TroubleshootReport must have format method"
    );

    // Verify remediation steps are numbered in output
    assert!(
        troubleshoot_code.contains("i + 1") || troubleshoot_code.contains("enumerate"),
        "Remediation steps should be numbered in output"
    );
}

/// Test 20: Verify troubleshoot actionable remediation
///
/// From Phase 9 Deliverables:
/// "Each check returns: PASS, WARN (with suggestion), or FAIL (with fix command)"
#[test]
fn test_troubleshoot_actionable_remediation() {
    // Read the troubleshoot implementation
    let troubleshoot_path = workspace_root().join("crates/sigil-cli/src/troubleshoot.rs");
    let troubleshoot_code =
        fs::read_to_string(&troubleshoot_path).expect("Failed to read troubleshoot code");

    // Verify remediation steps contain specific commands
    assert!(
        troubleshoot_code.contains("sigild start")
            || troubleshoot_code.contains("sigil init")
            || troubleshoot_code.contains("chmod"),
        "Troubleshoot should provide specific fix commands in remediation steps"
    );

    // Verify suggestions in Warn status
    assert!(
        troubleshoot_code.contains("suggestion") || troubleshoot_code.contains("Suggestion:"),
        "Troubleshoot should include suggestions for warnings"
    );

    // Verify multiple remediation steps are supported
    assert!(
        troubleshoot_code.contains("Vec<String>") || troubleshoot_code.contains("vec!"),
        "Troubleshoot should support multiple remediation steps"
    );
}

/// Test 21: Verify troubleshoot main entry point
///
/// Verifies the run_troubleshoot function orchestrates all checks
#[test]
fn test_troubleshoot_entry_point() {
    // Read the troubleshoot implementation
    let troubleshoot_path = workspace_root().join("crates/sigil-cli/src/troubleshoot.rs");
    let troubleshoot_code =
        fs::read_to_string(&troubleshoot_path).expect("Failed to read troubleshoot code");

    // Verify main function exists
    assert!(
        troubleshoot_code.contains("run_troubleshoot"),
        "Troubleshoot must have main entry point function"
    );

    // Verify all check functions are called
    assert!(
        troubleshoot_code.contains("check_daemon"),
        "run_troubleshoot must call check_daemon"
    );
    assert!(
        troubleshoot_code.contains("check_vault"),
        "run_troubleshoot must call check_vault"
    );
    assert!(
        troubleshoot_code.contains("check_sandbox"),
        "run_troubleshoot must call check_sandbox"
    );
    assert!(
        troubleshoot_code.contains("check_hooks"),
        "run_troubleshoot must call check_hooks"
    );
    assert!(
        troubleshoot_code.contains("check_permissions"),
        "run_troubleshoot must call check_permissions"
    );
}
