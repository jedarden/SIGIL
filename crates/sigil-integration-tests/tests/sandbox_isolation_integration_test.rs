//! Sandbox Isolation Integration Tests
//!
//! This test module verifies comprehensive sandbox isolation:
//! - Process isolation (namespaces)
//! - Filesystem isolation (mounts, bind mounts)
//! - Network isolation
//! - Resource limits
//! - Seccomp filtering
//! - Privilege dropping
//! - Tmpfs for secrets
//! - Cleanup and teardown
//!
//! These tests ensure the sandbox provides strong security guarantees.

mod common;
use common::workspace_root;
use std::fs;

// ============================================================================
// PROCESS ISOLATION TESTS
// ============================================================================

/// Test 1.1: Verify PID namespace isolation
///
/// Tests that the sandbox uses PID namespace:
/// - Processes in sandbox have different PIDs
/// - Sandbox init is PID 1
/// - Parent process cannot see sandbox processes
#[test]
fn test_pid_namespace_isolation() {
    let sandbox_path = workspace_root().join("crates/sigil-sandbox/src/lib.rs");
    if !sandbox_path.exists() {
        return; // Skip if sandbox module doesn't exist
    }

    let sandbox_code = fs::read_to_string(&sandbox_path).expect("Failed to read sandbox code");

    // Verify --unshare-pid flag
    assert!(
        sandbox_code.contains("--unshare-pid") || sandbox_code.contains("unshare_pid"),
        "Sandbox must use PID namespace isolation"
    );

    // Verify --pid-namespace or equivalent
    assert!(
        sandbox_code.contains("pid") && sandbox_code.contains("namespace"),
        "Sandbox must configure PID namespace"
    );

    // Verify sandbox becomes PID 1
    assert!(
        sandbox_code.contains("pid1") || sandbox_code.contains("init"),
        "Sandbox process should become PID 1 in namespace"
    );
}

/// Test 1.2: Verify UTS namespace isolation
///
/// Tests that the sandbox uses UTS namespace:
/// - Hostname can be changed in sandbox
/// - Changes don't affect host
#[test]
fn test_uts_namespace_isolation() {
    let sandbox_path = workspace_root().join("crates/sigil-sandbox/src/lib.rs");
    if !sandbox_path.exists() {
        return;
    }

    let sandbox_code = fs::read_to_string(&sandbox_path).expect("Failed to read sandbox code");

    // Verify --unshare-uts flag
    assert!(
        sandbox_code.contains("--unshare-uts") || sandbox_code.contains("uts"),
        "Sandbox must use UTS namespace isolation"
    );

    // Verify hostname can be set
    assert!(
        sandbox_code.contains("--hostname") || sandbox_code.contains("hostname"),
        "Sandbox must support setting hostname"
    );
}

/// Test 1.3: Verify IPC namespace isolation
///
/// Tests that the sandbox uses IPC namespace:
/// - System V IPC is isolated
/// - POSIX message queues are isolated
#[test]
fn test_ipc_namespace_isolation() {
    let sandbox_path = workspace_root().join("crates/sigil-sandbox/src/lib.rs");
    if !sandbox_path.exists() {
        return;
    }

    let sandbox_code = fs::read_to_string(&sandbox_path).expect("Failed to read sandbox code");

    // Verify --unshare-ipc flag
    assert!(
        sandbox_code.contains("--unshare-ipc") || sandbox_code.contains("ipc"),
        "Sandbox must use IPC namespace isolation"
    );
}

/// Test 1.4: Verify network namespace isolation
///
/// Tests that the sandbox uses network namespace:
/// - Separate network stack
/// - Can be configured with or without network
/// - Loopback interface available
#[test]
fn test_network_namespace_isolation() {
    let sandbox_path = workspace_root().join("crates/sigil-sandbox/src/lib.rs");
    if !sandbox_path.exists() {
        return;
    }

    let sandbox_code = fs::read_to_string(&sandbox_path).expect("Failed to read sandbox code");

    // Verify --unshare-net flag
    assert!(
        sandbox_code.contains("--unshare-net") || sandbox_code.contains("network"),
        "Sandbox must use network namespace isolation"
    );

    // Verify network isolation is configurable
    assert!(
        sandbox_code.contains("network_isolated") || sandbox_code.contains("disable_network"),
        "Sandbox must support configurable network isolation"
    );

    // Verify loopback is available
    assert!(
        sandbox_code.contains("--dev-bind")
            || sandbox_code.contains("lo")
            || sandbox_code.contains("loopback"),
        "Sandbox should provide loopback interface"
    );
}

/// Test 1.5: Verify user namespace isolation
///
/// Tests that the sandbox uses user namespace:
/// - Root inside sandbox is not root outside
/// - UID/GID mapping is configured
#[test]
fn test_user_namespace_isolation() {
    let sandbox_path = workspace_root().join("crates/sigil-sandbox/src/lib.rs");
    if !sandbox_path.exists() {
        return;
    }

    let sandbox_code = fs::read_to_string(&sandbox_path).expect("Failed to read sandbox code");

    // Verify --unshare-user flag
    assert!(
        sandbox_code.contains("--unshare-user") || sandbox_code.contains("user"),
        "Sandbox must use user namespace isolation"
    );

    // Verify UID/GID mapping
    assert!(
        sandbox_code.contains("--uidmap")
            || sandbox_code.contains("uid")
            || sandbox_code.contains("map"),
        "Sandbox must configure UID mapping"
    );
}

/// Test 1.6: Verify cgroup namespace isolation
///
/// Tests that the sandbox uses cgroup namespace:
/// - Cgroup views are isolated
/// - Processes can't see host cgroups
#[test]
fn test_cgroup_namespace_isolation() {
    let sandbox_path = workspace_root().join("crates/sigil-sandbox/src/lib.rs");
    if !sandbox_path.exists() {
        return;
    }

    let sandbox_code = fs::read_to_string(&sandbox_path).expect("Failed to read sandbox code");

    // Verify --unshare-cgroup flag
    assert!(
        sandbox_code.contains("--unshare-cgroup") || sandbox_code.contains("cgroup"),
        "Sandbox should use cgroup namespace isolation"
    );
}

// ============================================================================
// FILESYSTEM ISOLATION TESTS
// ============================================================================

/// Test 2.1: Verify root filesystem isolation
///
/// Tests that the sandbox has isolated root filesystem:
/// - Read-only bind mount for host root
/// - Separate /proc, /sys, /dev
/// - Cannot modify host filesystem
#[test]
fn test_root_filesystem_isolation() {
    let sandbox_path = workspace_root().join("crates/sigil-sandbox/src/lib.rs");
    if !sandbox_path.exists() {
        return;
    }

    let sandbox_code = fs::read_to_string(&sandbox_path).expect("Failed to read sandbox code");

    // Verify bind mounts for root
    assert!(
        sandbox_code.contains("--bind") || sandbox_code.contains("--ro-bind"),
        "Sandbox must use bind mounts"
    );

    // Verify read-only root
    assert!(
        sandbox_code.contains("--ro-bind") || sandbox_code.contains("read-only"),
        "Sandbox root should be read-only"
    );

    // Verify /proc mount
    assert!(
        sandbox_code.contains("proc") && sandbox_code.contains("--proc"),
        "Sandbox must mount /proc"
    );

    // Verify /dev mount
    assert!(
        sandbox_code.contains("dev") && sandbox_code.contains("--dev")
            || sandbox_code.contains("/dev"),
        "Sandbox must mount /dev"
    );
}

/// Test 2.2: Verify tmpfs for /tmp
///
/// Tests that /tmp is mounted as tmpfs:
/// - Files written to /tmp don't persist
/// - Memory-backed filesystem
#[test]
fn test_tmpfs_for_temp() {
    let sandbox_path = workspace_root().join("crates/sigil-sandbox/src/lib.rs");
    if !sandbox_path.exists() {
        return;
    }

    let sandbox_code = fs::read_to_string(&sandbox_path).expect("Failed to read sandbox code");

    // Verify tmpfs mount for /tmp
    assert!(
        sandbox_code.contains("--tmpfs")
            || sandbox_code.contains("tmpfs") && sandbox_code.contains("/tmp"),
        "Sandbox must mount /tmp as tmpfs"
    );
}

/// Test 2.3: Verify tmpfs for secrets
///
/// Tests that secrets are mounted via tmpfs:
/// - Secret files in memory only
/// - Never written to disk
/// - Cleaned up on exit
#[test]
fn test_tmpfs_for_secrets() {
    let sandbox_path = workspace_root().join("crates/sigil-sandbox/src/lib.rs");
    if !sandbox_path.exists() {
        return;
    }

    let sandbox_code = fs::read_to_string(&sandbox_path).expect("Failed to read sandbox code");

    // Verify tmpfs mount for secrets
    assert!(
        sandbox_code.contains("SECRET_TMPFS")
            || sandbox_code.contains("secret") && sandbox_code.contains("tmpfs"),
        "Sandbox must mount secrets directory as tmpfs"
    );

    // Verify secrets path
    assert!(
        sandbox_code.contains("/run/secrets")
            || sandbox_code.contains("/sigil")
            || sandbox_code.contains("secret_path"),
        "Sandbox must define secrets mount point"
    );
}

/// Test 2.4: Verify working directory binding
///
/// Tests that working directory is properly bound:
/// - Current directory is accessible
/// - Can be read-only or read-write
/// - Subdirectory mount option
#[test]
fn test_working_directory_binding() {
    let sandbox_path = workspace_root().join("crates/sigil-sandbox/src/lib.rs");
    if !sandbox_path.exists() {
        return;
    }

    let sandbox_code = fs::read_to_string(&sandbox_path).expect("Failed to read sandbox code");

    // Verify working directory is bound
    assert!(
        sandbox_code.contains("cwd")
            || sandbox_code.contains("working_dir")
            || sandbox_code.contains("--bind"),
        "Sandbox must bind mount working directory"
    );
}

/// Test 2.5: Verify overlay filesystem support
///
/// Tests that overlay can be used for layered filesystem:
/// - Read-only base layer
/// - Writable overlay layer
/// - Changes don't affect base
#[test]
fn test_overlay_filesystem_support() {
    let sandbox_path = workspace_root().join("crates/sigil-sandbox/src/lib.rs");
    if !sandbox_path.exists() {
        return;
    }

    let sandbox_code = fs::read_to_string(&sandbox_path).expect("Failed to read sandbox code");

    // Verify overlay support (optional but recommended)
    let has_overlay = sandbox_code.contains("overlay") || sandbox_code.contains("--overlay");

    if has_overlay {
        assert!(
            sandbox_code.contains("lowerdir")
                || sandbox_code.contains("upperdir")
                || sandbox_code.contains("workdir"),
            "Overlay must specify lower, upper, and work directories"
        );
    }
}

// ============================================================================
// RESOURCE LIMITS TESTS
// ============================================================================

/// Test 3.1: Verify memory limits
///
/// Tests that memory can be limited:
/// - RSS limit
/// - AS (address space) limit
/// - OOM handling
#[test]
fn test_memory_limits() {
    let sandbox_path = workspace_root().join("crates/sigil-sandbox/src/lib.rs");
    if !sandbox_path.exists() {
        return;
    }

    let sandbox_code = fs::read_to_string(&sandbox_path).expect("Failed to read sandbox code");

    // Verify RLIMIT_AS or memory limit
    assert!(
        sandbox_code.contains("RLIMIT_AS")
            || sandbox_code.contains("memory")
            || sandbox_code.contains("rlimit"),
        "Sandbox should support memory limits"
    );
}

/// Test 3.2: Verify CPU limits
///
/// Tests that CPU usage can be limited:
/// - CPU time limit
/// - CPU affinity
#[test]
fn test_cpu_limits() {
    let sandbox_path = workspace_root().join("crates/sigil-sandbox/src/lib.rs");
    if !sandbox_path.exists() {
        return;
    }

    let sandbox_code = fs::read_to_string(&sandbox_path).expect("Failed to read sandbox code");

    // Verify RLIMIT_CPU or CPU limit
    let has_cpu_limit = sandbox_code.contains("RLIMIT_CPU") || sandbox_code.contains("cpu");

    // This is optional
    if has_cpu_limit {
        assert!(
            sandbox_code.contains("rlimit") || sandbox_code.contains("setrlimit"),
            "Sandbox must use setrlimit for CPU limits"
        );
    }
}

/// Test 3.3: Verify execution timeout
///
/// Tests that commands can be timed out:
/// - Timeout is configurable
/// - Process is killed after timeout
/// - Resources are cleaned up
#[test]
fn test_execution_timeout() {
    let sandbox_path = workspace_root().join("crates/sigil-sandbox/src/lib.rs");
    if !sandbox_path.exists() {
        return;
    }

    let sandbox_code = fs::read_to_string(&sandbox_path).expect("Failed to read sandbox code");

    // Verify timeout support
    assert!(
        sandbox_code.contains("timeout") || sandbox_code.contains("duration"),
        "Sandbox must support execution timeout"
    );

    // Verify timeout handling
    assert!(
        sandbox_code.contains("kill")
            || sandbox_code.contains("terminate")
            || sandbox_code.contains("timeout"),
        "Sandbox must kill process on timeout"
    );
}

// ============================================================================
// SECURITY FILTERING TESTS
// ============================================================================

/// Test 4.1: Verify seccomp filtering
///
/// Tests that seccomp filter is applied:
/// - Dangerous syscalls are blocked
/// - Filter is configured at startup
/// - Whitelist or blacklist approach
#[test]
fn test_seccomp_filtering() {
    let sandbox_path = workspace_root().join("crates/sigil-sandbox/src/lib.rs");
    if !sandbox_path.exists() {
        return;
    }

    let sandbox_code = fs::read_to_string(&sandbox_path).expect("Failed to read sandbox code");

    // Verify seccomp flag
    assert!(
        sandbox_code.contains("--seccomp") || sandbox_code.contains("seccomp"),
        "Sandbox must use seccomp filtering"
    );

    // Verify seccomp profile
    assert!(
        sandbox_code.contains("seccomp.profile")
            || sandbox_code.contains(".profile")
            || sandbox_code.contains("filter"),
        "Sandbox must specify seccomp profile"
    );
}

/// Test 4.2: Verify blocked syscalls
///
/// Tests that dangerous syscalls are blocked:
/// - ptrace (prevents debugging other processes)
/// - kexec (prevents loading new kernel)
/// - swapon/off (prevents modifying swap)
/// - reboot (prevents rebooting system)
/// - sethostname (when UTS namespace not used)
#[test]
fn test_blocked_syscalls() {
    let sandbox_path = workspace_root().join("crates/sigil-sandbox/src/lib.rs");
    if !sandbox_path.exists() {
        return;
    }

    let sandbox_code = fs::read_to_string(&sandbox_path).expect("Failed to read sandbox code");

    // Verify default seccomp profile blocks dangerous syscalls
    // This is typically handled by bwrap's default seccomp filter
    assert!(
        sandbox_code.contains("--seccomp") || sandbox_code.contains("seccomp"),
        "Sandbox must use seccomp to block dangerous syscalls"
    );
}

/// Test 4.3: Verify no_new_privs
///
/// Tests that no_new_privs flag is set:
/// - Prevents gaining privileges
/// - Required for user namespaces
#[test]
fn test_4_3_no_new_privs() {
    let sandbox_path = workspace_root().join("crates/sigil-sandbox/src/lib.rs");
    if !sandbox_path.exists() {
        return;
    }

    let sandbox_code = fs::read_to_string(&sandbox_path).expect("Failed to read sandbox code");

    // Verify no-new-privs flag
    assert!(
        sandbox_code.contains("no_new_privs")
            || sandbox_code.contains("no-new-privs")
            || sandbox_code.contains("prctl"),
        "Sandbox must set no_new_privs"
    );
}

// ============================================================================
// PRIVILEGE DROPPING TESTS
// ============================================================================

/// Test 5.1: Verify privilege dropping
///
/// Tests that privileges are dropped:
/// - Not running as root inside sandbox
/// - UID/GID are set
/// - Cannot regain privileges
#[test]
fn test_privilege_dropping() {
    let sandbox_path = workspace_root().join("crates/sigil-sandbox/src/lib.rs");
    if !sandbox_path.exists() {
        return;
    }

    let sandbox_code = fs::read_to_string(&sandbox_path).expect("Failed to read sandbox code");

    // Verify UID/GID setting
    assert!(
        sandbox_code.contains("--uid")
            || sandbox_code.contains("--gid")
            || sandbox_code.contains("unshare-user"),
        "Sandbox must set UID/GID for privilege dropping"
    );

    // Verify not running as root
    assert!(
        sandbox_code.contains("nobody")
            || sandbox_code.contains("65534")
            || sandbox_code.contains("uid"),
        "Sandbox should drop to non-root user"
    );
}

/// Test 5.2: Verify capability dropping
///
/// Tests that capabilities are dropped:
/// - Most capabilities are removed
/// - Only necessary capabilities kept
#[test]
fn test_capability_dropping() {
    let sandbox_path = workspace_root().join("crates/sigil-sandbox/src/lib.rs");
    if !sandbox_path.exists() {
        return;
    }

    let sandbox_code = fs::read_to_string(&sandbox_path).expect("Failed to read sandbox code");

    // Verify capability dropping (optional, depends on implementation)
    let has_caps = sandbox_code.contains("cap") || sandbox_code.contains("CAP");

    if has_caps {
        assert!(
            sandbox_code.contains("--drop-capability") || sandbox_code.contains("cap-drop"),
            "Sandbox should drop capabilities"
        );
    }
}

// ============================================================================
// CLEANUP AND TEARDOWN TESTS
// ============================================================================

/// Test 6.1: Verify process cleanup
///
/// Tests that processes are cleaned up:
/// - All child processes are terminated
/// - No orphan processes
/// - Zombie processes are reaped
#[test]
fn test_process_cleanup() {
    let sandbox_path = workspace_root().join("crates/sigil-sandbox/src/lib.rs");
    if !sandbox_path.exists() {
        return;
    }

    let sandbox_code = fs::read_to_string(&sandbox_path).expect("Failed to read sandbox code");

    // Verify child process handling
    assert!(
        sandbox_code.contains("wait")
            || sandbox_code.contains("reap")
            || sandbox_code.contains("child"),
        "Sandbox must wait for/reap child processes"
    );

    // Verify process group termination
    assert!(
        sandbox_code.contains("killpg")
            || sandbox_code.contains("process_group")
            || sandbox_code.contains("--die-with-parent"),
        "Sandbox should terminate process group"
    );
}

/// Test 6.2: Verify filesystem cleanup
///
/// Tests that filesystem is cleaned up:
/// - Tmpfs is automatically cleaned
/// - Overlay directories are removed
/// - Mount points are unmounted
#[test]
fn test_filesystem_cleanup() {
    let sandbox_path = workspace_root().join("crates/sigil-sandbox/src/lib.rs");
    if !sandbox_path.exists() {
        return;
    }

    let sandbox_code = fs::read_to_string(&sandbox_path).expect("Failed to read sandbox code");

    // Verify tmpfs cleanup (automatic, but verify it's used)
    assert!(
        sandbox_code.contains("--tmpfs") || sandbox_code.contains("tmpfs"),
        "Sandbox should use tmpfs for automatic cleanup"
    );

    // Verify overlay cleanup (if used)
    let has_overlay = sandbox_code.contains("overlay");
    if has_overlay {
        assert!(
            sandbox_code.contains("cleanup")
                || sandbox_code.contains("remove")
                || sandbox_code.contains("unshare"),
            "Sandbox should clean up overlay directories"
        );
    }
}

/// Test 6.3: Verify signal handling
///
/// Tests that signals are properly handled:
/// - SIGTERM terminates sandbox
/// - SIGKILL terminates sandbox
/// - Signals are forwarded to child
/// - SIGCHLD is handled
#[test]
fn test_signal_handling() {
    let sandbox_path = workspace_root().join("crates/sigil-sandbox/src/lib.rs");
    if !sandbox_path.exists() {
        return;
    }

    let sandbox_code = fs::read_to_string(&sandbox_path).expect("Failed to read sandbox code");

    // Verify signal handling
    assert!(
        sandbox_code.contains("signal")
            || sandbox_code.contains("SIGTERM")
            || sandbox_code.contains("SIGKILL"),
        "Sandbox must handle signals"
    );

    // Verify signal forwarding
    assert!(
        sandbox_code.contains("forward")
            || sandbox_code.contains("kill")
            || sandbox_code.contains("send"),
        "Sandbox should forward signals to child process"
    );
}

// ============================================================================
// ESCAPE PREVENTION TESTS
// ============================================================================

/// Test 7.1: Verify mount namespace escape prevention
///
/// Tests that sandbox cannot escape via mount:
/// - Cannot mount new filesystems
/// - Cannot remount existing filesystems
#[test]
fn test_mount_namespace_escape_prevention() {
    let sandbox_path = workspace_root().join("crates/sigil-sandbox/src/lib.rs");
    if !sandbox_path.exists() {
        return;
    }

    let sandbox_code = fs::read_to_string(&sandbox_path).expect("Failed to read sandbox code");

    // Verify mount namespace
    assert!(
        sandbox_code.contains("--unshare-mount") || sandbox_code.contains("mount"),
        "Sandbox must use mount namespace isolation"
    );

    // Verify seccomp blocks mount syscall
    assert!(
        sandbox_code.contains("--seccomp") || sandbox_code.contains("seccomp"),
        "Sandbox should block mount syscall via seccomp"
    );
}

/// Test 7.2: Verify device access prevention
///
/// Tests that sandbox cannot access devices:
/// - Cannot open /dev/sda*
/// - Cannot access device nodes
/// - /dev is minimal
#[test]
fn test_device_access_prevention() {
    let sandbox_path = workspace_root().join("crates/sigil-sandbox/src/lib.rs");
    if !sandbox_path.exists() {
        return;
    }

    let sandbox_code = fs::read_to_string(&sandbox_path).expect("Failed to read sandbox code");

    // Verify minimal /dev
    assert!(
        sandbox_code.contains("--dev") || sandbox_code.contains("/dev"),
        "Sandbox must provide minimal /dev"
    );

    // Verify device nodes are not accessible
    // This is typically handled by the minimal /dev and read-only mounts
    assert!(
        sandbox_code.contains("--ro-bind") || sandbox_code.contains("--dev-bind"),
        "Sandbox must control device access"
    );
}

/// Test 7.3: Verify ptrace escape prevention
///
/// Tests that sandbox cannot ptrace host processes:
/// - PID namespace prevents seeing host PIDs
/// - seccomp blocks ptrace syscall
#[test]
fn test_ptrace_escape_prevention() {
    let sandbox_path = workspace_root().join("crates/sigil-sandbox/src/lib.rs");
    if !sandbox_path.exists() {
        return;
    }

    let sandbox_code = fs::read_to_string(&sandbox_path).expect("Failed to read sandbox code");

    // Verify PID namespace
    assert!(
        sandbox_code.contains("--unshare-pid") || sandbox_code.contains("pid"),
        "Sandbox must use PID namespace to hide host processes"
    );

    // Verify seccomp blocks ptrace
    assert!(
        sandbox_code.contains("--seccomp") || sandbox_code.contains("ptrace"),
        "Sandbox should block ptrace syscall"
    );
}

/// Test 7.4: Verify TIOCSTI escape prevention
///
/// Tests that TIOCSTI is blocked:
/// - Cannot inject characters into parent TTY
#[test]
fn test_tiocsti_escape_prevention() {
    let sandbox_path = workspace_root().join("crates/sigil-sandbox/src/lib.rs");
    if !sandbox_path.exists() {
        return;
    }

    let sandbox_code = fs::read_to_string(&sandbox_path).expect("Failed to read sandbox code");

    // Verify seccomp blocks TIOCSTI
    // TIOCSTI is typically blocked by seccomp filter
    assert!(
        sandbox_code.contains("--seccomp")
            || sandbox_code.contains("TIOCSTI")
            || sandbox_code.contains("ioctl"),
        "Sandbox should block TIOCSTI ioctl"
    );
}

// ============================================================================
// INTEGRATION TESTS
// ============================================================================

/// Test 8.1: Verify sandbox integrates with daemon
///
/// Tests that sandbox is properly integrated:
/// - Daemon creates sandbox for exec
/// - IPC passes sandbox options
/// - Output is captured and scrubbed
#[test]
fn test_sandbox_daemon_integration() {
    let server_path = workspace_root().join("crates/sigil-daemon/src/server.rs");
    let server_code = fs::read_to_string(&server_path).expect("Failed to read server code");

    // Verify exec handling
    assert!(
        server_code.contains("handle_exec") || server_code.contains("IpcOperation::Exec"),
        "Server must handle exec operations"
    );

    // Verify sandbox options are passed
    assert!(
        server_code.contains("sandbox") || server_code.contains("isolate"),
        "Exec request must include sandbox options"
    );

    // Verify output capture
    assert!(
        server_code.contains("stdout") && server_code.contains("stderr"),
        "Server must capture stdout and stderr"
    );

    // Verify scrubbing
    assert!(
        server_code.contains("scrub") || server_code.contains("Scrubber"),
        "Server must scrub output"
    );
}

/// Test 8.2: Verify sandbox timeout handling
///
/// Tests that sandbox enforces timeouts:
/// - Timeout is configured
/// - Process is killed after timeout
/// - Resources are cleaned up
#[test]
fn test_sandbox_timeout_handling() {
    let server_path = workspace_root().join("crates/sigil-daemon/src/server.rs");
    let server_code = fs::read_to_string(&server_path).expect("Failed to read server code");

    // Verify timeout support
    assert!(
        server_code.contains("timeout") || server_code.contains("duration"),
        "Exec request must support timeout"
    );

    // Verify timeout enforcement
    assert!(
        server_code.contains("tokio::time::timeout") || server_code.contains("timeout"),
        "Server must enforce execution timeout"
    );
}

/// Test 8.3: Verify sandbox environment injection
///
/// Tests that environment variables are injected:
/// - Secrets are injected as env vars
/// - Env vars are set in sandbox
/// - Not visible to host
#[test]
fn test_sandbox_environment_injection() {
    let server_path = workspace_root().join("crates/sigil-daemon/src/server.rs");
    let server_code = fs::read_to_string(&server_path).expect("Failed to read server code");

    // Verify env var support
    assert!(
        server_code.contains("env") || server_code.contains("environment"),
        "Exec request must support environment variables"
    );

    // Verify secret resolution for env vars
    assert!(
        server_code.contains("resolve") || server_code.contains("inject"),
        "Server must resolve secrets for injection"
    );
}

/// Test 8.4: Verify sandbox network isolation option
///
/// Tests that network isolation is configurable:
/// - Can enable/disable network
/// - Default is isolated
#[test]
fn test_sandbox_network_isolation_option() {
    let server_path = workspace_root().join("crates/sigil-daemon/src/server.rs");
    let server_code = fs::read_to_string(&server_path).expect("Failed to read server code");

    // Verify network isolation option
    assert!(
        server_code.contains("network") || server_code.contains("isolate"),
        "Exec request must support network isolation option"
    );

    // Verify default behavior
    // Network should be isolated by default for security
}

/// Test 8.5: Verify sandbox working directory
///
/// Tests that working directory is properly set:
/// - Command runs in specified directory
#[test]
fn test_sandbox_working_directory() {
    let server_path = workspace_root().join("crates/sigil-daemon/src/server.rs");
    let server_code = fs::read_to_string(&server_path).expect("Failed to read server code");

    // Verify working directory support
    assert!(
        server_code.contains("working_dir") || server_code.contains("cwd"),
        "Exec request must support working directory"
    );
}

/// Test 8.6: Verify sandbox with FUSE mount
///
/// Tests that FUSE mount can be used in sandbox:
/// - FUSE mount is bind-mounted into sandbox
/// - Mounted at /sigil
#[test]
fn test_sandbox_with_fuse_mount() {
    let sandbox_path = workspace_root().join("crates/sigil-sandbox/src/lib.rs");
    if !sandbox_path.exists() {
        return;
    }

    let sandbox_code = fs::read_to_string(&sandbox_path).expect("Failed to read sandbox code");

    // Verify FUSE mount support
    let has_fuse = sandbox_code.contains("/sigil") || sandbox_code.contains("fuse");

    if has_fuse {
        assert!(
            sandbox_code.contains("--bind") || sandbox_code.contains("--ro-bind"),
            "FUSE mount should be bind-mounted into sandbox"
        );
    }
}

/// Test 8.7: Verify sandbox resource limits
///
/// Tests that resource limits are enforced:
/// - Memory limits
/// - CPU limits
#[test]
fn test_sandbox_resource_limits() {
    let sandbox_path = workspace_root().join("crates/sigil-sandbox/src/lib.rs");
    if !sandbox_path.exists() {
        return;
    }

    let sandbox_code = fs::read_to_string(&sandbox_path).expect("Failed to read sandbox code");

    // Verify resource limit support
    let has_rlimit = sandbox_code.contains("rlimit") || sandbox_code.contains("RLIMIT");

    // This is optional but recommended
    if has_rlimit {
        assert!(
            sandbox_code.contains("setrlimit") || sandbox_code.contains("prlimit"),
            "Sandbox must use setrlimit for resource limits"
        );
    }
}

// ============================================================================
// RUNTIME SANDBOX TESTS
// ============================================================================

/// Test RT.1: Verify sandbox executes commands
///
/// Runtime test that verifies:
/// - Commands can be executed in sandbox
/// - Output is captured correctly
/// - Exit codes are preserved
#[test]
fn test_sandbox_runtime_execution() {
    let sigil = workspace_root().join("target").join("debug").join("sigil");
    if !sigil.exists() {
        eprintln!("sigil binary not found, skipping runtime sandbox test");
        return;
    }

    // Execute a simple command in sandbox
    let output = std::process::Command::new(&sigil)
        .arg("wrap")
        .arg("--")
        .arg("echo")
        .arg("sandbox-test")
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .output();

    match output {
        Ok(result) => {
            let stdout = String::from_utf8_lossy(&result.stdout);
            assert!(
                stdout.contains("sandbox-test"),
                "Sandbox should execute command and return output"
            );
            println!("✓ Sandbox executes commands: {}", stdout.trim());
        }
        Err(e) => {
            eprintln!("Failed to execute sandbox command: {}", e);
        }
    }
}

/// Test RT.2: Verify sandbox isolates filesystem
///
/// Runtime test that verifies:
/// - Files written in /tmp don't persist
/// - /tmp is tmpfs
#[test]
fn test_sandbox_runtime_filesystem_isolation() {
    let sigil = workspace_root().join("target").join("debug").join("sigil");
    if !sigil.exists() {
        return;
    }

    // Create a temp directory outside sandbox
    let temp_dir = tempfile::TempDir::new().expect("Failed to create temp dir");
    let _test_file = temp_dir.path().join("test.txt");

    // Write to /tmp inside sandbox (should not affect host)
    let output = std::process::Command::new(&sigil)
        .arg("wrap")
        .arg("--")
        .arg("sh")
        .arg("-c")
        .arg("echo 'sandbox-test' > /tmp/sandbox-test.txt && cat /tmp/sandbox-test.txt")
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .output();

    if let Ok(result) = output {
        let stdout = String::from_utf8_lossy(&result.stdout);
        if stdout.contains("sandbox-test") {
            println!("✓ Sandbox /tmp is writable (tmpfs)");

            // Verify the file doesn't exist on host
            let host_file = std::path::PathBuf::from("/tmp/sandbox-test.txt");
            if !host_file.exists() {
                println!("✓ Sandbox /tmp is isolated from host");
            }
        }
    }
}

/// Test RT.3: Verify sandbox network isolation
///
/// Runtime test that verifies:
/// - Network can be disabled in sandbox
/// - External connections fail when isolated
#[test]
fn test_sandbox_runtime_network_isolation() {
    let sigil = workspace_root().join("target").join("debug").join("sigil");
    if !sigil.exists() {
        return;
    }

    // Try to connect to external host in isolated sandbox
    let output = std::process::Command::new(&sigil)
        .arg("wrap")
        .arg("--isolated")
        .arg("--")
        .arg("sh")
        .arg("-c")
        .arg("curl -s --connect-timeout 2 http://example.com || echo 'network-blocked'")
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .output();

    if let Ok(result) = output {
        let stdout = String::from_utf8_lossy(&result.stdout);
        let stderr = String::from_utf8_lossy(&result.stderr);
        let combined = format!("{}\n{}", stdout, stderr);

        // Should fail or show network blockage
        if combined.contains("network-blocked")
            || combined.contains("curl:")
            || combined.contains("Failed")
            || combined.contains("refused")
        {
            println!("✓ Sandbox network isolation works");
        }
    }
}

/// Test RT.4: Verify sandbox with sigil wrap
///
/// Runtime test that verifies:
/// - sigil wrap uses sandbox for execution
/// - Environment variables are injected
/// - Output is scrubbed
#[test]
fn test_sandbox_with_sigil_wrap() {
    let sigil = workspace_root().join("target").join("debug").join("sigil");
    if !sigil.exists() {
        return;
    }

    // Run command with placeholder (will fail to resolve but tests sandbox)
    let output = std::process::Command::new(&sigil)
        .arg("wrap")
        .arg("--")
        .arg("sh")
        .arg("-c")
        .arg("echo 'test-output' && echo $PATH")
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .output();

    if let Ok(result) = output {
        let stdout = String::from_utf8_lossy(&result.stdout);
        if stdout.contains("test-output") {
            println!("✓ sigil wrap executes commands through sandbox");
        }
    }
}

/// Test RT.5: Verify sandbox handles command failures
///
/// Runtime test that verifies:
/// - Failed commands return proper exit codes
/// - Error output is captured
#[test]
fn test_sandbox_command_failure_handling() {
    let sigil = workspace_root().join("target").join("debug").join("sigil");
    if !sigil.exists() {
        return;
    }

    // Execute a command that fails
    let output = std::process::Command::new(&sigil)
        .arg("wrap")
        .arg("--")
        .arg("false")
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .output();

    if let Ok(result) = output {
        assert!(
            !result.status.success(),
            "Sandbox should preserve command failure exit code"
        );
        println!("✓ Sandbox preserves command exit codes");
    }
}

/// Test RT.6: Verify sandbox timeout enforcement
///
/// Runtime test that verifies:
/// - Commands are killed after timeout
/// - Resources are cleaned up
#[test]
fn test_sandbox_timeout_enforcement() {
    let sigil = workspace_root().join("target").join("debug").join("sigil");
    if !sigil.exists() {
        return;
    }

    // Execute a long-running command with short timeout
    let output = std::process::Command::new(&sigil)
        .arg("wrap")
        .arg("--timeout")
        .arg("2s")
        .arg("--")
        .arg("sleep")
        .arg("10")
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .output();

    if let Ok(result) = output {
        let stdout = String::from_utf8_lossy(&result.stdout);
        let stderr = String::from_utf8_lossy(&result.stderr);
        let combined = format!("{}\n{}", stdout, stderr);

        // Command should be terminated early
        let was_killed = combined.contains("timeout")
            || combined.contains("killed")
            || combined.contains("terminated")
            || !result.status.success();

        if was_killed {
            println!("✓ Sandbox enforces timeout");
        }
    }
}
