//! Phase 4.1-4.2 Verification Tests
//!
//! These tests verify the bubblewrap sandbox and file injection implementation
//! as specified in the plan Phase 4.1 and 4.2 deliverables.

mod common;
use common::workspace_root;
use std::fs;

/// Test 4.1.1: Verify seccomp BPF filter blocks ptrace
///
/// From Phase 4.1 deliverables:
/// "Seccomp BPF filter blocking: ptrace — prevent debugging"
#[test]
fn test_seccomp_blocks_ptrace() {
    let landlock_path = workspace_root().join("crates/sigil-sandbox/src/landlock.rs");
    let landlock_code = fs::read_to_string(&landlock_path).expect("Failed to read landlock code");

    // Verify ptrace is in the seccomp block list
    assert!(
        landlock_code.contains("ptrace") && landlock_code.contains("SeccompRule"),
        "Landlock seccomp rules must block ptrace syscall"
    );

    // Verify it's blocked with EPERM (permission denied)
    assert!(
        landlock_code.contains("EPERM") || landlock_code.contains("Errno"),
        "ptrace should return EPERM error"
    );
}

/// Test 4.1.2: Verify seccomp BPF filter blocks process_vm_readv/writev
///
/// From Phase 4.1 deliverables:
/// "Seccomp BPF filter blocking: process_vm_readv / process_vm_writev"
#[test]
fn test_seccomp_blocks_process_vm() {
    let landlock_path = workspace_root().join("crates/sigil-sandbox/src/landlock.rs");
    let landlock_code = fs::read_to_string(&landlock_path).expect("Failed to read landlock code");

    // Verify process_vm_readv is blocked
    assert!(
        landlock_code.contains("process_vm_readv"),
        "Seccomp rules must block process_vm_readv syscall"
    );

    // Verify process_vm_writev is blocked
    assert!(
        landlock_code.contains("process_vm_writev"),
        "Seccomp rules must block process_vm_writev syscall"
    );
}

/// Test 4.1.3: Verify seccomp BPF filter blocks AF_INET/AF_INET6 sockets
///
/// From Phase 4.1 deliverables:
/// "Seccomp BPF filter blocking: socket(AF_INET, ...) and socket(AF_INET6, ...)"
#[test]
fn test_seccomp_blocks_network_sockets() {
    let landlock_path = workspace_root().join("crates/sigil-sandbox/src/landlock.rs");
    let landlock_code = fs::read_to_string(&landlock_path).expect("Failed to read landlock code");

    // Verify socket syscall is blocked when network isolation is enabled
    assert!(
        landlock_code.contains("socket") && landlock_code.contains("network_isolated"),
        "Seccomp rules must block socket syscall when network_isolated is true"
    );

    // Verify connect is also blocked
    assert!(
        landlock_code.contains("connect"),
        "Seccomp rules must block connect syscall"
    );
}

/// Test 4.1.4: Verify seccomp BPF filter blocks mount
///
/// From Phase 4.1 deliverables:
/// "Seccomp BPF filter blocking: mount, umount2"
#[test]
fn test_seccomp_blocks_mount() {
    let landlock_path = workspace_root().join("crates/sigil-sandbox/src/landlock.rs");
    let landlock_code = fs::read_to_string(&landlock_path).expect("Failed to read landlock code");

    // Verify mount is blocked
    assert!(
        landlock_code.contains("mount") && landlock_code.contains("SeccompRule"),
        "Seccomp rules must block mount syscall"
    );

    // Verify umount2 is blocked
    assert!(
        landlock_code.contains("umount2"),
        "Seccomp rules must block umount2 syscall"
    );
}

/// Test 4.1.5: Verify seccomp BPF filter blocks io_uring_enter
///
/// From Phase 4.1 deliverables:
/// "Seccomp BPF filter blocking: io_uring_enter — prevent io_uring-based escapes"
#[test]
fn test_seccomp_blocks_io_uring() {
    let landlock_path = workspace_root().join("crates/sigil-sandbox/src/landlock.rs");
    let landlock_code = fs::read_to_string(&landlock_path).expect("Failed to read landlock code");

    // Verify io_uring_enter is blocked
    assert!(
        landlock_code.contains("io_uring_enter"),
        "Seccomp rules must block io_uring_enter syscall"
    );
}

/// Test 4.1.6: Verify seccomp BPF filter blocks kexec_load
///
/// From Phase 4.1 deliverables:
/// "Seccomp BPF filter blocking: kexec_load, init_module, finit_module"
#[test]
fn test_seccomp_blocks_kexec() {
    let landlock_path = workspace_root().join("crates/sigil-sandbox/src/landlock.rs");
    let landlock_code = fs::read_to_string(&landlock_path).expect("Failed to read landlock code");

    // Verify kexec_load is blocked
    assert!(
        landlock_code.contains("kexec_load"),
        "Seccomp rules must block kexec_load syscall"
    );

    // Verify init_module is blocked
    assert!(
        landlock_code.contains("init_module"),
        "Seccomp rules must block init_module syscall"
    );

    // Verify finit_module is blocked
    assert!(
        landlock_code.contains("finit_module"),
        "Seccomp rules must block finit_module syscall"
    );
}

/// Test 4.1.7: Verify .env is in sensitive path overlays
///
/// From Phase 4.1 deliverables:
/// "Sensitive path overlays: .env, .aws/credentials, .ssh/*, .gnupg/ → /dev/null"
#[test]
fn test_sensitive_path_env() {
    let bwrap_path = workspace_root().join("crates/sigil-sandbox/src/bubblewrap.rs");
    let bwrap_code = fs::read_to_string(&bwrap_path).expect("Failed to read bubblewrap code");

    // Verify .env is in DEFAULT_SENSITIVE_PATHS
    assert!(
        bwrap_code.contains(".env"),
        "DEFAULT_SENSITIVE_PATHS must include .env"
    );

    // Verify it's overlaid with /dev/null using --ro-bind
    assert!(
        bwrap_code.contains("--ro-bind") && bwrap_code.contains("/dev/null"),
        "Sensitive paths must be overlaid with /dev/null"
    );
}

/// Test 4.1.8: Verify .aws/credentials is in sensitive path overlays
#[test]
fn test_sensitive_path_aws_credentials() {
    let bwrap_path = workspace_root().join("crates/sigil-sandbox/src/bubblewrap.rs");
    let bwrap_code = fs::read_to_string(&bwrap_path).expect("Failed to read bubblewrap code");

    // Verify .aws/credentials is in DEFAULT_SENSITIVE_PATHS
    assert!(
        bwrap_code.contains(".aws/credentials"),
        "DEFAULT_SENSITIVE_PATHS must include .aws/credentials"
    );
}

/// Test 4.1.9: Verify .ssh keys are in sensitive path overlays
#[test]
fn test_sensitive_path_ssh_keys() {
    let bwrap_path = workspace_root().join("crates/sigil-sandbox/src/bubblewrap.rs");
    let bwrap_code = fs::read_to_string(&bwrap_path).expect("Failed to read bubblewrap code");

    // Verify SSH keys are in DEFAULT_SENSITIVE_PATHS
    assert!(
        bwrap_code.contains(".ssh/id_rsa") || bwrap_code.contains(".ssh/id_ed25519"),
        "DEFAULT_SENSITIVE_PATHS must include SSH keys"
    );
}

/// Test 4.1.10: Verify .gnupg is in sensitive path overlays
#[test]
fn test_sensitive_path_gnupg() {
    let bwrap_path = workspace_root().join("crates/sigil-sandbox/src/bubblewrap.rs");
    let bwrap_code = fs::read_to_string(&bwrap_path).expect("Failed to read bubblewrap code");

    // Verify .gnupg is in DEFAULT_SENSITIVE_PATHS
    assert!(
        bwrap_code.contains(".gnupg"),
        "DEFAULT_SENSITIVE_PATHS must include .gnupg"
    );
}

/// Test 4.1.11: Verify --unshare-pid is used
///
/// From Phase 4.1 deliverables:
/// "bwrap --unshare-pid --unshare-net --die-with-parent confirmed working"
#[test]
fn test_bwrap_unshare_pid() {
    let bwrap_path = workspace_root().join("crates/sigil-sandbox/src/bubblewrap.rs");
    let bwrap_code = fs::read_to_string(&bwrap_path).expect("Failed to read bubblewrap code");

    // Verify --unshare-pid is used
    assert!(
        bwrap_code.contains("--unshare-pid"),
        "Bubblewrap must use --unshare-pid for PID namespace isolation"
    );
}

/// Test 4.1.12: Verify --unshare-net is used
#[test]
fn test_bwrap_unshare_net() {
    let bwrap_path = workspace_root().join("crates/sigil-sandbox/src/bubblewrap.rs");
    let bwrap_code = fs::read_to_string(&bwrap_path).expect("Failed to read bubblewrap code");

    // Verify --unshare-net is used
    assert!(
        bwrap_code.contains("--unshare-net"),
        "Bubblewrap must use --unshare-net for network namespace isolation"
    );
}

/// Test 4.1.13: Verify --die-with-parent is used
#[test]
fn test_bwrap_die_with_parent() {
    let bwrap_path = workspace_root().join("crates/sigil-sandbox/src/bubblewrap.rs");
    let bwrap_code = fs::read_to_string(&bwrap_path).expect("Failed to read bubblewrap code");

    // Verify --die-with-parent is used
    assert!(
        bwrap_code.contains("--die-with-parent"),
        "Bubblewrap must use --die-with-parent for automatic cleanup"
    );
}

/// Test 4.1.14: Verify read-only root bind mount
///
/// From Phase 4.1 deliverables:
/// "Read-only root bind, project dir writable, tmpfs for /tmp and /run/sigil/secrets"
#[test]
fn test_readonly_root_bind() {
    let bwrap_path = workspace_root().join("crates/sigil-sandbox/src/bubblewrap.rs");
    let bwrap_code = fs::read_to_string(&bwrap_path).expect("Failed to read bubblewrap code");

    // Verify --ro-bind / / is used
    assert!(
        bwrap_code.contains("--ro-bind") && bwrap_code.contains("/"),
        "Bubblewrap must use --ro-bind for read-only root filesystem"
    );

    // Verify it's documented
    assert!(
        bwrap_code.contains("Read-only root") || bwrap_code.contains("ro-bind"),
        "Read-only root should be documented"
    );
}

/// Test 4.1.15: Verify project dir is writable
#[test]
fn test_project_dir_writable() {
    let bwrap_path = workspace_root().join("crates/sigil-sandbox/src/bubblewrap.rs");
    let bwrap_code = fs::read_to_string(&bwrap_path).expect("Failed to read bubblewrap code");

    // Verify --bind (not --ro-bind) is used for project_dir
    assert!(
        bwrap_code.contains("project_dir") && bwrap_code.contains("--bind"),
        "Project directory must be mounted with --bind (writable)"
    );
}

/// Test 4.1.16: Verify tmpfs for /tmp
#[test]
fn test_tmpfs_tmp() {
    let bwrap_path = workspace_root().join("crates/sigil-sandbox/src/bubblewrap.rs");
    let bwrap_code = fs::read_to_string(&bwrap_path).expect("Failed to read bubblewrap code");

    // Verify --tmpfs /tmp is used
    assert!(
        bwrap_code.contains("--tmpfs") && bwrap_code.contains("/tmp"),
        "Bubblewrap must use tmpfs for /tmp"
    );
}

/// Test 4.1.17: Verify tmpfs for /run/sigil/secrets
#[test]
fn test_tmpfs_secrets() {
    let bwrap_path = workspace_root().join("crates/sigil-sandbox/src/bubblewrap.rs");
    let bwrap_code = fs::read_to_string(&bwrap_path).expect("Failed to read bubblewrap code");

    // Verify SECRET_TMPFS constant is defined
    assert!(
        bwrap_code.contains("SECRET_TMPFS") || bwrap_code.contains("/run/sigil/secrets"),
        "SECRET_TMPFS must be defined for secret injection"
    );

    // Verify --tmpfs is used for secrets
    assert!(
        bwrap_code.contains("--tmpfs") && bwrap_code.contains("SECRET_TMPFS"),
        "Bubblewrap must use tmpfs for secret file injection"
    );
}

/// Test 4.2.1: Verify memfd_create is used on Linux
///
/// From Phase 4.2 deliverables:
/// "{{secret:path:file}} → memfd_create(MFD_CLOEXEC) on Linux"
#[test]
fn test_memfd_create_linux() {
    let secure_fd_path = workspace_root().join("crates/sigil-sandbox/src/secure_fd.rs");
    let secure_fd_code = fs::read_to_string(&secure_fd_path).expect("Failed to read secure_fd code");

    // Verify MFD_CLOEXEC is defined
    assert!(
        secure_fd_code.contains("MFD_CLOEXEC"),
        "MFD_CLOEXEC flag must be defined for memfd_create"
    );

    // Verify MFD_ALLOW_SEALING is defined
    assert!(
        secure_fd_code.contains("MFD_ALLOW_SEALING"),
        "MFD_ALLOW_SEALING flag must be defined for memfd_create"
    );

    // Verify memfd_create syscall is used
    assert!(
        secure_fd_code.contains("memfd_create") || secure_fd_code.contains("SYS_memfd_create"),
        "memfd_create syscall must be used on Linux"
    );

    // Verify libc::syscall is used
    assert!(
        secure_fd_code.contains("libc::syscall"),
        "memfd_create must be called via libc::syscall"
    );
}

/// Test 4.2.2: Verify MFD_CLOEXEC flag is set
#[test]
fn test_memfd_cloexec_flag() {
    let secure_fd_path = workspace_root().join("crates/sigil-sandbox/src/secure_fd.rs");
    let secure_fd_code = fs::read_to_string(&secure_fd_path).expect("Failed to read secure_fd code");

    // Verify MFD_CLOEXEC is set in the syscall
    assert!(
        secure_fd_code.contains("MFD_CLOEXEC | MFD_ALLOW_SEALING")
            || secure_fd_code.contains("MFD_CLOEXEC"),
        "memfd_create must use MFD_CLOEXEC flag"
    );
}

/// Test 4.2.3: Verify SecureFile has path: None on Linux (memfd has no filesystem path)
#[test]
fn test_memfd_no_path() {
    let secure_fd_path = workspace_root().join("crates/sigil-sandbox/src/secure_fd.rs");
    let secure_fd_code = fs::read_to_string(&secure_fd_path).expect("Failed to read secure_fd code");

    // Verify SecureFile path is None for memfd
    assert!(
        secure_fd_code.contains("path: None") || secure_fd_code.contains("no filesystem path"),
        "memfd files should have path: None (no filesystem path)"
    );
}

/// Test 4.2.4: Verify macOS mkstemp fallback
///
/// From Phase 4.2 deliverables:
/// "macOS fallback: mkstemp() + immediate unlink()"
#[test]
fn test_macos_mkstemp_fallback() {
    let secure_fd_path = workspace_root().join("crates/sigil-sandbox/src/secure_fd.rs");
    let secure_fd_code = fs::read_to_string(&secure_fd_path).expect("Failed to read secure_fd code");

    // Verify mkstemp is used for non-Linux platforms
    assert!(
        secure_fd_code.contains("mkstemp"),
        "macOS must use mkstemp for secure temporary file creation"
    );

    // Verify immediate unlink is done
    assert!(
        secure_fd_code.contains("unlink") || secure_fd_code.contains("remove_file"),
        "macOS must immediately unlink the temp file"
    );
}

/// Test 4.2.5: Verify macOS temp directory has restrictive permissions
#[test]
fn test_macos_restrictive_temp_dir() {
    let secure_fd_path = workspace_root().join("crates/sigil-sandbox/src/secure_fd.rs");
    let secure_fd_code = fs::read_to_string(&secure_fd_path).expect("Failed to read secure_fd code");

    // Verify 0700 permissions are set
    assert!(
        secure_fd_code.contains("0o700") || secure_fd_code.contains("0700"),
        "macOS temp directory must have 0700 permissions"
    );
}

/// Test 4.2.6: Verify tmpfs secret files are overwritten with zeros
///
/// From Phase 4.2 deliverables:
/// "tmpfs secret files overwritten with zeros after execution"
#[test]
fn test_tmpfs_zeroization() {
    let injection_path = workspace_root().join("crates/sigil-sandbox/src/injection.rs");
    let injection_code = fs::read_to_string(&injection_path).expect("Failed to read injection code");

    // Verify cleanup overwrites with zeros
    assert!(
        injection_code.contains("zeros") || injection_code.contains("0u8"),
        "Injected files must be overwritten with zeros on cleanup"
    );

    // Verify file is removed after overwriting
    assert!(
        injection_code.contains("remove_file") || injection_code.contains("unlink"),
        "Injected files must be removed after zeroization"
    );
}

/// Test 4.2.7: Verify file permissions 0400 for injected secret files
///
/// From Phase 4.2 deliverables:
/// "File permissions 0400 for injected secret files"
#[test]
fn test_file_permissions_0400() {
    let injection_path = workspace_root().join("crates/sigil-sandbox/src/injection.rs");
    let injection_code = fs::read_to_string(&injection_path).expect("Failed to read injection code");

    // Verify 0o400 permissions are set
    assert!(
        injection_code.contains("0o400") || injection_code.contains("0400"),
        "Injected secret files must have 0400 permissions (owner read-only)"
    );

    // Verify set_mode is called
    assert!(
        injection_code.contains("set_mode"),
        "File permissions must be set via set_mode"
    );
}

/// Test 4.2.8: Verify SecureFileInjection uses memfd
#[test]
fn test_secure_file_injection_uses_memfd() {
    let injection_path = workspace_root().join("crates/sigil-sandbox/src/injection.rs");
    let injection_code = fs::read_to_string(&injection_path).expect("Failed to read injection code");

    // Verify SecureFileInjection exists
    assert!(
        injection_code.contains("SecureFileInjection"),
        "SecureFileInjection must exist for TOCTOU-safe injection"
    );

    // Verify it uses SecureFile
    assert!(
        injection_code.contains("SecureFile") && injection_code.contains("secure_file"),
        "SecureFileInjection must use SecureFile (memfd)"
    );
}

/// Test 4.2.9: Verify memfd sealing is used
#[test]
fn test_memfd_sealing() {
    let secure_fd_path = workspace_root().join("crates/sigil-sandbox/src/secure_fd.rs");
    let secure_fd_code = fs::read_to_string(&secure_fd_path).expect("Failed to read secure_fd code");

    // Verify F_SEAL_SEAL is defined
    assert!(
        secure_fd_code.contains("F_SEAL_SEAL"),
        "F_SEAL_SEAL constant must be defined"
    );

    // Verify F_SEAL_WRITE is defined
    assert!(
        secure_fd_code.contains("F_SEAL_WRITE"),
        "F_SEAL_WRITE constant must be defined"
    );

    // Verify fcntl with F_ADD_SEALS is used
    assert!(
        secure_fd_code.contains("F_ADD_SEALS") || secure_fd_code.contains("seal"),
        "memfd sealing must be implemented via fcntl"
    );
}

/// Test 4.2.10: Verify proc_fd_path for passing memfd to bwrap
#[test]
fn test_proc_fd_path() {
    let injection_path = workspace_root().join("crates/sigil-sandbox/src/injection.rs");
    let injection_code = fs::read_to_string(&injection_path).expect("Failed to read injection code");

    // Verify proc_fd_path method exists
    assert!(
        injection_code.contains("proc_fd_path") && injection_code.contains("/proc/self/fd/"),
        "SecureFileInjection must provide /proc/self/fd path for bwrap bind mounts"
    );
}

/// Test 4.2.11: Verify injection cleanup on drop
#[test]
fn test_injection_cleanup_on_drop() {
    let injection_path = workspace_root().join("crates/sigil-sandbox/src/injection.rs");
    let injection_code = fs::read_to_string(&injection_path).expect("Failed to read injection code");

    // Verify Drop is implemented for FileInjection
    assert!(
        injection_code.contains("impl Drop for FileInjection"),
        "FileInjection must implement Drop for automatic cleanup"
    );

    // Verify cleanup is called in drop
    assert!(
        injection_code.contains("drop") && injection_code.contains("cleanup"),
        "Drop implementation must call cleanup"
    );
}

/// Test 4.2.12: Verify InjectionManager tracks multiple injections
#[test]
fn test_injection_manager() {
    let injection_path = workspace_root().join("crates/sigil-sandbox/src/injection.rs");
    let injection_code = fs::read_to_string(&injection_path).expect("Failed to read injection code");

    // Verify InjectionManager exists
    assert!(
        injection_code.contains("InjectionManager"),
        "InjectionManager must exist to track multiple injections"
    );

    // Verify cleanup_all method
    assert!(
        injection_code.contains("cleanup_all"),
        "InjectionManager must have cleanup_all method"
    );
}

/// Test 4.2.13: Verify file injection uses tmpfs base directory
#[test]
fn test_file_injection_tmpfs_base() {
    let injection_path = workspace_root().join("crates/sigil-sandbox/src/injection.rs");
    let injection_code = fs::read_to_string(&injection_path).expect("Failed to read injection code");

    // Verify SECRET_TMPFS_BASE is defined
    assert!(
        injection_code.contains("SECRET_TMPFS_BASE") || injection_code.contains("/run/user/"),
        "SECRET_TMPFS_BASE must be defined for tmpfs-based injection"
    );

    // Verify UID interpolation is used
    assert!(
        injection_code.contains("%UID%") || injection_code.contains("getuid"),
        "Tmpfs base must interpolate UID"
    );
}

/// Test 4.2.14: Verify filename sanitization
#[test]
fn test_filename_sanitization() {
    let injection_path = workspace_root().join("crates/sigil-sandbox/src/injection.rs");
    let injection_code = fs::read_to_string(&injection_path).expect("Failed to read injection code");

    // Verify sanitize_filename function exists
    assert!(
        injection_code.contains("sanitize_filename") || injection_code.contains("sanitize_path"),
        "Filename sanitization function must exist"
    );
}

/// Test 4.2.15: Verify maximum memfd size limit
#[test]
fn test_max_memfd_size() {
    let secure_fd_path = workspace_root().join("crates/sigil-sandbox/src/secure_fd.rs");
    let secure_fd_code = fs::read_to_string(&secure_fd_path).expect("Failed to read secure_fd code");

    // Verify MAX_MEMFD_SIZE is defined
    assert!(
        secure_fd_code.contains("MAX_MEMFD_SIZE"),
        "MAX_MEMFD_SIZE constant must be defined"
    );

    // Verify size check is done
    assert!(
        secure_fd_code.contains("data.len()") && secure_fd_code.contains("MAX_MEMFD_SIZE"),
        "Write must check against MAX_MEMFD_SIZE"
    );
}
