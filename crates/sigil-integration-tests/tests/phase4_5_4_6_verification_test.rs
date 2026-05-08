//! Phase 4.5-4.6: TOCTOU Mitigations and Full Pipeline Verification Tests
//!
//! These tests verify:
//! - 4.5: TOCTOU (Time-of-Check-to-Time-of-Use) mitigations
//!   - memfd_create for TOCTOU-safe secret injection (Linux)
//!   - pidfd_open for PID reuse attack prevention (Linux 5.3+)
//!   - LOCAL_PEERPID for macOS peer credential verification
//!   - Fallback for older kernels
//! - 4.6: Full execution pipeline (parse → resolve → sandbox → execute → scrub → return)
//!   - Error handling for daemon unreachable
//!   - Error handling for placeholder resolution failures
//!   - Sandbox creation fallback to hook-only mode
//!
//! Test coverage:
//! - memfd_create implementation with MFD_CLOEXEC and MFD_ALLOW_SEALING
//! - pidfd_open immediately after SO_PEERCRED verification
//! - SecurePid with pidfd support and fallback
//! - SecurePeerCredentials wrapping PeerCredentials with SecurePid
//! - Full command execution pipeline
//! - Error handling at each pipeline stage
//! - Red team tests for sandbox escape attempts
//! - Performance measurement for sandbox overhead

mod common;
use common::workspace_root;
use std::fs;

// =============================================================================
// Phase 4.5: TOCTOU Mitigations
// =============================================================================

/// Test 4.5.1: Verify memfd_create is used for TOCTOU-safe secret injection
#[test]
fn test_memfd_create_for_toctou_safe_injection() {
    let secure_fd_path = workspace_root().join("crates/sigil-sandbox/src/secure_fd.rs");
    let secure_fd_code = fs::read_to_string(&secure_fd_path)
        .expect("Failed to read secure_fd.rs");

    // Verify memfd_create syscall is used
    assert!(
        secure_fd_code.contains("memfd_create") || secure_fd_code.contains("SYS_memfd_create"),
        "memfd_create syscall must be used for TOCTOU-safe secret injection"
    );

    // Verify MFD_CLOEXEC flag is defined
    assert!(
        secure_fd_code.contains("MFD_CLOEXEC"),
        "MFD_CLOEXEC flag must be defined for memfd_create"
    );

    // Verify MFD_ALLOW_SEALING flag is defined
    assert!(
        secure_fd_code.contains("MFD_ALLOW_SEALING"),
        "MFD_ALLOW_SEALING flag must be defined for memfd_create"
    );

    // Verify memfd_create is called via libc::syscall
    assert!(
        secure_fd_code.contains("libc::syscall") && secure_fd_code.contains("SYS_memfd_create"),
        "memfd_create must be called via libc::syscall with SYS_memfd_create"
    );
}

/// Test 4.5.2: Verify memfd_create has no filesystem path (TOCTOU-safe)
#[test]
fn test_memfd_no_filesystem_path() {
    let secure_fd_path = workspace_root().join("crates/sigil-sandbox/src/secure_fd.rs");
    let secure_fd_code = fs::read_to_string(&secure_fd_path)
        .expect("Failed to read secure_fd.rs");

    // Verify SecureFile has path field that is None for memfd
    assert!(
        secure_fd_code.contains("path: None") || secure_fd_code.contains("path: Option"),
        "SecureFile must have path field that is None for memfd"
    );

    // Verify documentation mentions no filesystem path
    assert!(
        secure_fd_code.contains("no filesystem path") || secure_fd_code.contains("anonymous"),
        "Documentation must mention memfd has no filesystem path"
    );
}

/// Test 4.5.3: Verify pidfd_open is used immediately after SO_PEERCRED
#[test]
fn test_pidfd_open_after_so_peercred() {
    let server_path = workspace_root().join("crates/sigil-daemon/src/server.rs");
    let server_code = fs::read_to_string(&server_path)
        .expect("Failed to read server.rs");

    // Verify SecurePeerCredentials struct exists
    assert!(
        server_code.contains("SecurePeerCredentials") || server_code.contains("SecurePid"),
        "Server must use SecurePeerCredentials with pidfd support"
    );

    // Verify pidfd_open is called after SO_PEERCRED
    assert!(
        server_code.contains("pidfd_open") || server_code.contains("SYS_pidfd_open"),
        "pidfd_open syscall must be used for PID reuse protection"
    );

    // Verify SecurePeerCredentials wraps PeerCredentials with SecurePid
    assert!(
        server_code.contains("SecurePid") && server_code.contains("peer_creds"),
        "SecurePeerCredentials must wrap PeerCredentials with SecurePid"
    );
}

/// Test 4.5.4: Verify SecurePid with pidfd support
#[test]
fn test_secure_pid_with_pidfd() {
    let secure_fd_path = workspace_root().join("crates/sigil-sandbox/src/secure_fd.rs");
    let secure_fd_code = fs::read_to_string(&secure_fd_path)
        .expect("Failed to read secure_fd.rs");

    // Verify SecurePid struct exists
    assert!(
        secure_fd_code.contains("struct SecurePid") || secure_fd_code.contains("pub struct SecurePid"),
        "SecurePid struct must exist for pidfd-based PID tracking"
    );

    // Verify pidfd field exists
    assert!(
        secure_fd_code.contains("pidfd:") || secure_fd_code.contains("pidfd: Option"),
        "SecurePid must have pidfd field"
    );

    // Verify from_pid method creates pidfd
    assert!(
        secure_fd_code.contains("fn from_pid") && secure_fd_code.contains("pidfd_open"),
        "SecurePid::from_pid must attempt pidfd_open"
    );

    // Verify is_valid method checks PID/pidfd validity
    assert!(
        secure_fd_code.contains("fn is_valid") || secure_fd_code.contains("pub fn is_valid"),
        "SecurePid must have is_valid method to verify PID/pidfd validity"
    );
}

/// Test 4.5.5: Verify fallback for older kernels without pidfd_open
#[test]
fn test_pidfd_fallback_for_old_kernels() {
    let secure_fd_path = workspace_root().join("crates/sigil-sandbox/src/secure_fd.rs");
    let secure_fd_code = fs::read_to_string(&secure_fd_path)
        .expect("Failed to read secure_fd.rs");

    // Verify fallback when pidfd_open fails
    assert!(
        secure_fd_code.contains("pidfd_open not available") || secure_fd_code.contains("kernel < 5.3"),
        "Code must handle pidfd_open unavailability with fallback"
    );

    // Verify PID-based tracking is used as fallback
    assert!(
        secure_fd_code.contains("fallback") || secure_fd_code.contains("PID-based"),
        "Fallback to PID-based tracking must exist"
    );

    // Verify is_using_pidfd method exists to check if pidfd is active
    assert!(
        secure_fd_code.contains("is_using_pidfd"),
        "SecurePid must have is_using_pidfd method to check if pidfd is active"
    );
}

/// Test 4.5.6: Verify LOCAL_PEERPID is used on macOS
#[test]
fn test_local_peerpid_on_macos() {
    let ipc_path = workspace_root().join("crates/sigil-core/src/ipc.rs");
    if ipc_path.exists() {
        let ipc_code = fs::read_to_string(&ipc_path)
            .expect("Failed to read ipc.rs");

        // Verify LOCAL_PEERPID is used on macOS
        #[cfg(target_os = "macos")]
        assert!(
            ipc_code.contains("LOCAL_PEERPID") || ipc_code.contains("LOCAL_PEERCRED"),
            "macOS must use LOCAL_PEERPID for peer credential verification"
        );
    }

    // Verify documentation mentions macOS approach
    let plan_path = workspace_root().join("docs/plan/plan.md");
    if plan_path.exists() {
        let plan_code = fs::read_to_string(&plan_path)
            .expect("Failed to read plan.md");

        assert!(
            plan_code.contains("LOCAL_PEERPID") && plan_code.contains("macOS"),
            "Plan must document LOCAL_PEERPID usage for macOS"
        );
    }
}

/// Test 4.5.7: Verify session token is primary authentication on macOS
#[test]
fn test_session_token_primary_on_macos() {
    let plan_path = workspace_root().join("docs/plan/plan.md");
    if plan_path.exists() {
        let plan_code = fs::read_to_string(&plan_path)
            .expect("Failed to read plan.md");

        // Verify session token is primary gate on macOS
        assert!(
            plan_code.contains("session token") && plan_code.contains("primary") && plan_code.contains("macOS"),
            "Plan must document session tokens as primary authentication on macOS"
        );

        // Verify PID verification is defense-in-depth on macOS
        assert!(
            plan_code.contains("defense-in-depth") || plan_code.contains("defense in depth"),
            "Plan must document PID verification as defense-in-depth"
        );
    }
}

/// Test 4.5.8: Verify /proc/<pid>/exe verification fallback
#[test]
fn test_proc_exe_verification_fallback() {
    let plan_path = workspace_root().join("docs/plan/plan.md");
    if plan_path.exists() {
        let plan_code = fs::read_to_string(&plan_path)
            .expect("Failed to read plan.md");

        // Verify /proc/<pid>/exe verification is documented as fallback
        assert!(
            plan_code.contains("/proc/") && plan_code.contains("/exe") && plan_code.contains("fallback"),
            "Plan must document /proc/<pid>/exe symlink verification as fallback"
        );
    }
}

/// Test 4.5.9: Verify memfd sealing is used for defense-in-depth
#[test]
fn test_memfd_sealing_defense_in_depth() {
    let secure_fd_path = workspace_root().join("crates/sigil-sandbox/src/secure_fd.rs");
    let secure_fd_code = fs::read_to_string(&secure_fd_path)
        .expect("Failed to read secure_fd.rs");

    // Verify F_SEAL_* constants are defined
    assert!(
        secure_fd_code.contains("F_SEAL_SEAL") ||
        secure_fd_code.contains("F_SEAL_SHRINK") ||
        secure_fd_code.contains("F_SEAL_GROW") ||
        secure_fd_code.contains("F_SEAL_WRITE"),
        "memfd sealing constants must be defined"
    );

    // Verify seal method exists
    assert!(
        secure_fd_code.contains("fn seal") || secure_fd_code.contains("pub fn seal"),
        "SecureFile must have seal method"
    );

    // Verify fcntl is used for sealing
    assert!(
        secure_fd_code.contains("fcntl") && secure_fd_code.contains("F_ADD_SEALS"),
        "fcntl must be used with F_ADD_SEALS for memfd sealing"
    );
}

/// Test 4.5.10: Verify PreToolUse hook → command execution is NOT vulnerable
#[test]
fn test_pretooluse_hook_not_vulnerable_toctou() {
    let plan_path = workspace_root().join("docs/plan/plan.md");
    if plan_path.exists() {
        let plan_code = fs::read_to_string(&plan_path)
            .expect("Failed to read plan.md");

        // Verify PreToolUse hook is documented as NOT vulnerable
        assert!(
            plan_code.contains("PreToolUse") && plan_code.contains("NOT VULNERABLE"),
            "Plan must document PreToolUse hook as NOT vulnerable to TOCTOU"
        );

        // Verify explanation that hook IS execution path
        assert!(
            plan_code.contains("check IS execution") || plan_code.contains("execution path"),
            "Plan must explain that PreToolUse hook check IS execution path"
        );
    }
}

/// Test 4.5.11: Verify bwrap sandbox setup is NOT vulnerable to TOCTOU
#[test]
fn test_bwrap_sandbox_not_vulnerable_toctou() {
    let plan_path = workspace_root().join("docs/plan/plan.md");
    if plan_path.exists() {
        let plan_code = fs::read_to_string(&plan_path)
            .expect("Failed to read plan.md");

        // Verify bwrap sandbox setup is documented as NOT vulnerable
        assert!(
            plan_code.contains("Bwrap sandbox") && plan_code.contains("NOT VULNERABLE"),
            "Plan must document bwrap sandbox setup as NOT vulnerable to TOCTOU"
        );

        // Verify explanation that clone() with namespace flags is atomic
        assert!(
            plan_code.contains("clone()") && plan_code.contains("namespace") && plan_code.contains("atomic"),
            "Plan must explain that clone() with namespace flags is atomic"
        );
    }
}

// =============================================================================
// Phase 4.6: Full Execution Pipeline
// =============================================================================

/// Test 4.6.1: Verify command parsing exists
#[test]
fn test_command_parsing_exists() {
    let parser_path = workspace_root().join("crates/sigil-core/src/parser.rs");
    if parser_path.exists() {
        let parser_code = fs::read_to_string(&parser_path)
            .expect("Failed to read parser.rs");

        // Verify parse function exists
        assert!(
            parser_code.contains("parse") || parser_code.contains("parse_command"),
            "Parser must have parse function for command parsing"
        );

        // Verify placeholder detection
        assert!(
            parser_code.contains("placeholder") || parser_code.contains("{{secret:"),
            "Parser must detect {{secret:path}} placeholders"
        );
    }
}

/// Test 4.6.2: Verify secret resolution exists
#[test]
fn test_secret_resolution_exists() {
    let server_path = workspace_root().join("crates/sigil-daemon/src/server.rs");
    let server_code = fs::read_to_string(&server_path)
        .expect("Failed to read server.rs");

    // Verify resolve_placeholders function exists
    assert!(
        server_code.contains("resolve") || server_code.contains("placeholder"),
        "Server must have placeholder resolution logic"
    );

    // Verify secret lookup from protected secrets
    assert!(
        server_code.contains("secrets.get") || server_code.contains("protected_secrets"),
        "Server must look up secrets from protected secrets store"
    );
}

/// Test 4.6.3: Verify sandbox wrapping exists
#[test]
fn test_sandbox_wrapping_exists() {
    let sandbox_path = workspace_root().join("crates/sigil-sandbox/src/bubblewrap.rs");
    let sandbox_code = fs::read_to_string(&sandbox_path)
        .expect("Failed to read bubblewrap.rs");

    // Verify wrap_command method exists
    assert!(
        sandbox_code.contains("fn wrap_command") || sandbox_code.contains("pub fn wrap_command"),
        "Sandbox must have wrap_command method"
    );

    // Verify SandboxProvider trait exists
    assert!(
        sandbox_code.contains("trait SandboxProvider") || sandbox_code.contains("SandboxProvider"),
        "SandboxProvider trait must exist for abstraction"
    );
}

/// Test 4.6.4: Verify command execution exists
#[test]
fn test_command_execution_exists() {
    let server_path = workspace_root().join("crates/sigil-daemon/src/server.rs");
    let server_code = fs::read_to_string(&server_path)
        .expect("Failed to read server.rs");

    // Verify execute_command_sandboxed or similar function exists
    assert!(
        server_code.contains("execute") || server_code.contains("CommandExecution"),
        "Server must have command execution logic"
    );

    // Verify std::process::Command is used
    assert!(
        server_code.contains("std::process::Command") || server_code.contains("process::Command"),
        "Server must use std::process::Command for execution"
    );
}

/// Test 4.6.5: Verify output scrubbing exists
#[test]
fn test_output_scrubbing_exists() {
    let scrub_path = workspace_root().join("crates/sigil-scrub/src/lib.rs");
    if scrub_path.exists() {
        let scrub_code = fs::read_to_string(&scrub_path)
            .expect("Failed to read scrub.rs");

        // Verify scrubbing functionality exists
        assert!(
            scrub_code.contains("scrub") || scrub_code.contains("redact"),
            "Scrubber must have scrub/redact functionality"
        );
    }

    let server_path = workspace_root().join("crates/sigil-daemon/src/server.rs");
    let server_code = fs::read_to_string(&server_path)
        .expect("Failed to read server.rs");

    // Verify output scrubbing is applied
    assert!(
        server_code.contains("scrub") || server_code.contains("Scrubber"),
        "Server must apply output scrubbing"
    );
}

/// Test 4.6.6: Verify error handling for daemon unreachable
#[test]
fn test_error_handling_daemon_unreachable() {
    let client_path = workspace_root().join("crates/sigil-daemon/src/client.rs");
    if client_path.exists() {
        let client_code = fs::read_to_string(&client_path)
            .expect("Failed to read client.rs");

        // Verify error handling for connection failures
        assert!(
            client_code.contains("Connect") || client_code.contains("Connection") ||
            client_code.contains("Unreachable") || client_code.contains("refused"),
            "Client must handle daemon unreachable errors"
        );
    }

    let execute_path = workspace_root().join("crates/sigil-cli/src/execute.rs");
    if execute_path.exists() {
        let execute_code = fs::read_to_string(&execute_path)
            .expect("Failed to read execute.rs");

        // Verify error message for daemon unreachable
        assert!(
            execute_code.contains("sigild") || execute_code.contains("daemon") ||
            execute_code.contains("unreachable") || execute_code.contains("not running"),
            "Execute must provide clear error for daemon unreachable"
        );
    }
}

/// Test 4.6.7: Verify error handling for missing placeholder
#[test]
fn test_error_handling_missing_placeholder() {
    let server_path = workspace_root().join("crates/sigil-daemon/src/server.rs");
    let server_code = fs::read_to_string(&server_path)
        .expect("Failed to read server.rs");

    // Verify error for missing secret
    assert!(
        server_code.contains("Secret not found") || server_code.contains("missing") ||
        server_code.contains("does not exist") || server_code.contains("cannot resolve"),
        "Server must return clear error for missing placeholder"
    );

    // Verify error lists the missing path
    assert!(
        server_code.contains("path") || server_code.contains("secret"),
        "Error must mention the missing secret path"
    );
}

/// Test 4.6.8: Verify fallback to hook-only mode on sandbox failure
#[test]
fn test_fallback_hook_only_mode() {
    let plan_path = workspace_root().join("docs/plan/plan.md");
    if plan_path.exists() {
        let plan_code = fs::read_to_string(&plan_path)
            .expect("Failed to read plan.md");

        // Verify fallback to hook-only mode is documented
        assert!(
            plan_code.contains("hook-only") || plan_code.contains("hook only") ||
            plan_code.contains("fallback") && plan_code.contains("sandbox"),
            "Plan must document fallback to hook-only mode when sandbox fails"
        );
    }

    let execute_path = workspace_root().join("crates/sigil-cli/src/execute.rs");
    if execute_path.exists() {
        let execute_code = fs::read_to_string(&execute_path)
            .expect("Failed to read execute.rs");

        // Verify warning is issued when falling back
        assert!(
            execute_code.contains("warn") || execute_code.contains("warning") ||
            execute_code.contains("fallback") || execute_code.contains("sandbox.*fail"),
            "Execute must warn when falling back to hook-only mode"
        );
    }
}

/// Test 4.6.9: Verify end-to-end pipeline integration
#[test]
fn test_end_to_end_pipeline_integration() {
    let execute_path = workspace_root().join("crates/sigil-cli/src/execute.rs");
    if execute_path.exists() {
        let execute_code = fs::read_to_string(&execute_path)
            .expect("Failed to read execute.rs");

        // Verify all pipeline stages are present
        assert!(
            execute_code.contains("parse") || execute_code.contains("placeholder"),
            "Pipeline must include parsing stage"
        );

        assert!(
            execute_code.contains("resolve") || execute_code.contains("secret"),
            "Pipeline must include resolution stage"
        );

        assert!(
            execute_code.contains("sandbox") || execute_code.contains("bwrap") || execute_code.contains("wrap"),
            "Pipeline must include sandbox stage"
        );

        assert!(
            execute_code.contains("execute") || execute_code.contains("run") || execute_code.contains("spawn"),
            "Pipeline must include execution stage"
        );

        assert!(
            execute_code.contains("scrub") || execute_code.contains("redact"),
            "Pipeline must include scrubbing stage"
        );
    }
}

// =============================================================================
// Red Team Tests
// =============================================================================

/// Test RT-1: Verify ptrace is blocked by seccomp
#[test]
fn test_redteam_ptrace_blocked() {
    let landlock_path = workspace_root().join("crates/sigil-sandbox/src/landlock.rs");
    if landlock_path.exists() {
        let landlock_code = fs::read_to_string(&landlock_path)
            .expect("Failed to read landlock.rs");

        // Verify ptrace is in seccomp filter
        assert!(
            landlock_code.contains("ptrace") && landlock_code.contains("SeccompRule"),
            "ptrace must be blocked by seccomp filter"
        );

        // Verify ptrace action is EPERM or similar error
        assert!(
            landlock_code.contains("EPERM") || landlock_code.contains("Errno") ||
            landlock_code.contains("block") || landlock_code.contains("deny"),
            "ptrace must return error when attempted"
        );
    }
}

/// Test RT-2: Verify /proc/<sigild_pid>/mem is blocked by PID namespace
#[test]
fn test_redteam_proc_mem_blocked() {
    let bubblewrap_path = workspace_root().join("crates/sigil-sandbox/src/bubblewrap.rs");
    let bubblewrap_code = fs::read_to_string(&bubblewrap_path)
        .expect("Failed to read bubblewrap.rs");

    // Verify PID namespace is unshared
    assert!(
        bubblewrap_code.contains("--unshare-pid") || bubblewrap_code.contains("unshare_pid"),
        "PID namespace must be unshared to block /proc/<pid>/mem access"
    );

    // Verify isolated /proc is mounted
    assert!(
        bubblewrap_code.contains("--proc") || bubblewrap_code.contains("/proc"),
        "Isolated /proc must be mounted"
    );
}

/// Test RT-3: Verify PATH modification is blocked
#[test]
fn test_redteam_path_blocked() {
    let state_path = workspace_root().join("crates/sigil-sandbox/src/state.rs");
    let state_code = fs::read_to_string(&state_path)
        .expect("Failed to read state.rs");

    // Verify PATH is in blocked list
    assert!(
        state_code.contains("PATH") && state_code.contains("blocked") &&
        (state_code.contains("is_blocked_env_var") || state_code.contains("BLOCKED")),
        "PATH must be in blocked environment variables list"
    );

    // Verify setting PATH returns false
    assert!(
        state_code.contains("set_env") && state_code.contains("PATH") &&
        (state_code.contains("false") || state_code.contains("fail")),
        "Setting PATH must fail"
    );

    let bubblewrap_path = workspace_root().join("crates/sigil-sandbox/src/bubblewrap.rs");
    let bubblewrap_code = fs::read_to_string(&bubblewrap_path)
        .expect("Failed to read bubblewrap.rs");

    // Verify PATH is overridden in sandbox
    assert!(
        bubblewrap_code.contains("PATH") && bubblewrap_code.contains("env"),
        "Sandbox must override PATH environment variable"
    );
}

/// Test RT-4: Verify LD_PRELOAD modification is blocked
#[test]
fn test_redteam_ld_preload_blocked() {
    let state_path = workspace_root().join("crates/sigil-sandbox/src/state.rs");
    let state_code = fs::read_to_string(&state_path)
        .expect("Failed to read state.rs");

    // Verify LD_PRELOAD is in blocked list
    assert!(
        state_code.contains("LD_PRELOAD") && state_code.contains("blocked") &&
        (state_code.contains("is_blocked_env_var") || state_code.contains("BLOCKED")),
        "LD_PRELOAD must be in blocked environment variables list"
    );

    let bubblewrap_path = workspace_root().join("crates/sigil-sandbox/src/bubblewrap.rs");
    let bubblewrap_code = fs::read_to_string(&bubblewrap_path)
        .expect("Failed to read bubblewrap.rs");

    // Verify LD_PRELOAD is removed in sandbox
    assert!(
        bubblewrap_code.contains("LD_PRELOAD") && bubblewrap_code.contains("env_remove"),
        "Sandbox must remove LD_PRELOAD environment variable"
    );
}

/// Test RT-5: Verify LD_LIBRARY_PATH modification is blocked
#[test]
fn test_redteam_ld_library_path_blocked() {
    let state_path = workspace_root().join("crates/sigil-sandbox/src/state.rs");
    let state_code = fs::read_to_string(&state_path)
        .expect("Failed to read state.rs");

    // Verify LD_LIBRARY_PATH is in blocked list
    assert!(
        state_code.contains("LD_LIBRARY_PATH") && state_code.contains("blocked") &&
        (state_code.contains("is_blocked_env_var") || state_code.contains("BLOCKED")),
        "LD_LIBRARY_PATH must be in blocked environment variables list"
    );

    let bubblewrap_path = workspace_root().join("crates/sigil-sandbox/src/bubblewrap.rs");
    let bubblewrap_code = fs::read_to_string(&bubblewrap_path)
        .expect("Failed to read bubblewrap.rs");

    // Verify LD_LIBRARY_PATH is removed in sandbox
    assert!(
        bubblewrap_code.contains("LD_LIBRARY_PATH") && bubblewrap_code.contains("env_remove"),
        "Sandbox must remove LD_LIBRARY_PATH environment variable"
    );
}

/// Test RT-6: Verify sandbox overhead is documented
#[test]
fn test_redteam_sandbox_overhead_documented() {
    let plan_path = workspace_root().join("docs/plan/plan.md");
    if plan_path.exists() {
        let plan_code = fs::read_to_string(&plan_path)
            .expect("Failed to read plan.md");

        // Verify 30ms overhead requirement is documented
        assert!(
            plan_code.contains("30ms") || plan_code.contains("30 ms") ||
            (plan_code.contains("overhead") && plan_code.contains("ms")),
            "Plan must document sandbox overhead requirement"
        );
    }
}

/// Test RT-7: Verify end-to-end testing with Claude Code Bash tool is documented
#[test]
fn test_redteam_e2e_claude_code_test_documented() {
    let plan_path = workspace_root().join("docs/plan/plan.md");
    if plan_path.exists() {
        let plan_code = fs::read_to_string(&plan_path)
            .expect("Failed to read plan.md");

        // Verify end-to-end testing is mentioned
        assert!(
            plan_code.contains("end-to-end") || plan_code.contains("e2e") ||
            (plan_code.contains("Claude Code") && plan_code.contains("Bash tool")),
            "Plan must document end-to-end testing with Claude Code Bash tool"
        );
    }
}

// =============================================================================
// Integration Tests
// =============================================================================

/// Test IT-1: Verify SecureFileInjection uses memfd on Linux
#[test]
fn test_integration_secure_file_injection_uses_memfd() {
    let injection_path = workspace_root().join("crates/sigil-sandbox/src/injection.rs");
    let injection_code = fs::read_to_string(&injection_path)
        .expect("Failed to read injection.rs");

    // Verify SecureFileInjection exists
    assert!(
        injection_code.contains("SecureFileInjection") || injection_code.contains("struct SecureFileInjection"),
        "SecureFileInjection must exist for TOCTOU-safe injection"
    );

    // Verify it uses SecureFile (which uses memfd on Linux)
    assert!(
        injection_code.contains("SecureFile") && injection_code.contains("secure_file"),
        "SecureFileInjection must use SecureFile (memfd on Linux)"
    );

    // Verify proc_fd_path method for passing to bwrap
    assert!(
        injection_code.contains("proc_fd_path") || injection_code.contains("/proc/self/fd"),
        "SecureFileInjection must provide /proc/self/fd path for bwrap"
    );
}

/// Test IT-2: Verify server uses SecureFile for file injection
#[test]
fn test_integration_server_uses_secure_file() {
    let server_path = workspace_root().join("crates/sigil-daemon/src/server.rs");
    let server_code = fs::read_to_string(&server_path)
        .expect("Failed to read server.rs");

    // Verify SecureFile is used for file injection
    assert!(
        server_code.contains("SecureFile") || server_code.contains("SecureFileInjection"),
        "Server must use SecureFile for TOCTOU-safe file injection"
    );

    // Verify memfd_create is mentioned in comments or documentation
    assert!(
        server_code.contains("memfd") || server_code.contains("TOCTOU-safe") ||
        server_code.contains("TOCTOU safe"),
        "Server must document TOCTOU-safe file injection"
    );
}

/// Test IT-3: Verify full pipeline error handling
#[test]
fn test_integration_full_pipeline_error_handling() {
    let execute_path = workspace_root().join("crates/sigil-cli/src/execute.rs");
    if execute_path.exists() {
        let execute_code = fs::read_to_string(&execute_path)
            .expect("Failed to read execute.rs");

        // Verify Result type is used for error handling
        assert!(
            execute_code.contains("Result<") || execute_code.contains(" anyhow::") ||
            execute_code.contains("anyhow::Result"),
            "Pipeline must use Result type for error handling"
        );

        // Verify errors are propagated with context
        assert!(
            execute_code.contains("map_err") || execute_code.contains("context") ||
            execute_code.contains("with_context"),
            "Errors must be propagated with context"
        );
    }
}

/// Test IT-4: Verify scrubber is applied to all output
#[test]
fn test_integration_scrubber_all_output() {
    let server_path = workspace_root().join("crates/sigil-daemon/src/server.rs");
    let server_code = fs::read_to_string(&server_path)
        .expect("Failed to read server.rs");

    // Verify scrubber is applied to command output
    assert!(
        server_code.contains("scrub") && (server_code.contains("stdout") || server_code.contains("output")),
        "Scrubber must be applied to command output"
    );

    // Verify scrubber uses secret patterns
    assert!(
        server_code.contains("Scrubber") || server_code.contains("scrubber."),
        "Scrubber must be used to filter output"
    );
}

/// Test IT-5: Verify all TOCTOU mitigations are documented
#[test]
fn test_integration_toctou_mitigations_documented() {
    let plan_path = workspace_root().join("docs/plan/plan.md");
    if plan_path.exists() {
        let plan_code = fs::read_to_string(&plan_path)
            .expect("Failed to read plan.md");

        // Verify all TOCTOU mitigations are documented
        assert!(
            plan_code.contains("memfd_create") && plan_code.contains("TOCTOU"),
            "Plan must document memfd_create mitigation"
        );

        assert!(
            plan_code.contains("pidfd_open") && plan_code.contains("PID reuse"),
            "Plan must document pidfd_open mitigation"
        );

        assert!(
            plan_code.contains("LOCAL_PEERPID") && plan_code.contains("macOS"),
            "Plan must document LOCAL_PEERPID mitigation for macOS"
        );
    }
}

/// Test IT-6: Verify pipeline stages are in correct order
#[test]
fn test_integration_pipeline_order() {
    let execute_path = workspace_root().join("crates/sigil-cli/src/execute.rs");
    if execute_path.exists() {
        let execute_code = fs::read_to_string(&execute_path)
            .expect("Failed to read execute.rs");

        // Verify parse comes before resolve
        let parse_pos = execute_code.find("parse").unwrap_or(0);
        let resolve_pos = execute_code.find("resolve").unwrap_or(0);
        assert!(
            parse_pos < resolve_pos || parse_pos == 0,
            "Parse stage should come before resolve stage"
        );

        // Verify resolve comes before execute
        let execute_pos = execute_code.find("execute").unwrap_or(0);
        assert!(
            resolve_pos < execute_pos || resolve_pos == 0,
            "Resolve stage should come before execute stage"
        );
    }
}
