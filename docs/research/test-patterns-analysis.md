# SIGIL Test Patterns and Fixtures Analysis

## Overview

SIGIL uses a comprehensive integration testing framework with consistent patterns across all test files. This analysis documents the fixtures, patterns, and utilities used to enable easy test creation and maintenance.

---

## Test File Structure

### Standard Module Declaration
All test files begin with:
```rust
mod common;
use common::workspace_root;
```

This provides access to shared utilities from `common.rs` including:
- Path resolution (`workspace_root()`)
- Daemon lifecycle management
- Environment detection
- Socket waiting utilities
- Test directory management

### Test Organization Pattern
Tests are organized by phase and functionality:
- `phase1_5_6_7_verification_test.rs` - Phase-specific verification
- `phase2_audit_ipc_signals_test.rs` - Audit and IPC testing  
- `full_pipeline_integration_test.rs` - End-to-end testing
- `runtime_framework.rs` - Daemon lifecycle and runtime testing

---

## Core Fixtures

### 1. Binary Path Fixtures

```rust
/// Get the sigil CLI binary path
fn sigil_path() -> PathBuf {
    workspace_root().join("target").join("debug").join("sigil")
}

/// Get both sigil and sigild binaries
pub struct Binaries {
    pub sigil: PathBuf,
    pub sigild: PathBuf,
}

impl Binaries {
    pub fn get() -> Option<Self> {
        let workspace = workspace_root();
        let sigil = workspace.join("target").join("debug").join("sigil");
        let sigild = workspace.join("target").join("debug").join("sigild");
        
        if sigil.exists() && sigild.exists() {
            Some(Self { sigil, sigild })
        } else {
            None
        }
    }
}
```

**Usage Pattern:**
```rust
let sigil = sigil_path();
if !sigil.exists() {
    eprintln!("sigil not found, skipping test. Run: cargo build");
    return;
}
```

### 2. Directory Fixtures

```rust
/// Create a unique temporary runtime directory for a test
pub fn create_test_runtime_dir(test_name: &str) -> PathBuf {
    let temp_runtime = std::env::temp_dir().join(format!(
        "sigil-test-{}-{}-{}",
        test_name,
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
    ));
    
    fs::create_dir_all(&temp_runtime).expect("Failed to create test runtime dir");
    
    // Set permissions to 0700 for security
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = fs::metadata(&temp_runtime)
            .expect("Failed to get test runtime dir metadata")
            .permissions();
        perms.set_mode(0o700);
        fs::set_permissions(&temp_runtime, perms)
            .expect("Failed to set test runtime dir permissions");
    }
    
    temp_runtime
}
```

**Usage Pattern:**
```rust
let temp_dir = TempDir::new().expect("Failed to create temp dir");
let home_dir = temp_dir.path();
let sigil_dir = home_dir.join(".sigil");
```

### 3. Daemon Guard Fixture

```rust
/// Guard for a daemon process - kills and waits on drop
pub struct DaemonGuard(std::process::Child);

impl DaemonGuard {
    pub fn new(child: std::process::Child) -> Self {
        Self(child)
    }
    
    pub fn pid(&self) -> u32 {
        self.0.id()
    }
}

impl Drop for DaemonGuard {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}
```

**Usage Pattern:**
```rust
pub struct TestEnv {
    pub daemon: Option<DaemonGuard>,
    // ... other fields
}

// Automatic cleanup on test completion
```

---

## Setup/Teardown Patterns

### 1. Test Environment Setup

```rust
pub struct TestEnv {
    pub temp_dir: TempDir,
    pub vault_path: PathBuf,
    pub socket_path: PathBuf,
    pub runtime_dir: PathBuf,
    pub binaries: Binaries,
    pub daemon: Option<DaemonGuard>,
}

impl TestEnv {
    pub fn new() -> std::io::Result<Self> {
        let temp_dir = TempDir::new()?;
        let vault_path = temp_dir.path().join("vault");
        let socket_path = temp_dir.path().join("sigil.sock");
        
        let runtime_dir = ensure_xdg_runtime_dir().map_err(|e| {
            std::io::Error::other(format!("Failed to ensure XDG_RUNTIME_DIR: {}", e))
        })?;
        
        let binaries = Binaries::get().ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::NotFound,
                "sigil/sigild binaries not found. Run: cargo build",
            )
        })?;
        
        Ok(Self {
            temp_dir,
            vault_path,
            socket_path,
            runtime_dir,
            binaries,
            daemon: None,
        })
    }
}
```

### 2. Vault Initialization Pattern

```rust
pub fn init_vault(&self) -> bool {
    let output = Command::new(&self.binaries.sigil)
        .arg("init")
        .arg("--path")
        .arg(&self.vault_path)
        .arg("--no-passphrase")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();
    
    output.map(|s| s.success()).unwrap_or(false)
}
```

### 3. Daemon Startup Pattern

```rust
pub fn start_daemon(&mut self) -> bool {
    self.start_daemon_with_opts(true, false)
}

pub fn start_daemon_with_opts(&mut self, ci_mode: bool, require_bwrap: bool) -> bool {
    if !can_start_daemon(&self.binaries.sigild, require_bwrap) {
        eprintln!("Skipping daemon start: preflight checks failed");
        return false;
    }
    
    let mut cmd = Command::new(&self.binaries.sigild);
    cmd.arg("start")
        .arg("--socket")
        .arg(&self.socket_path)
        .arg("--vault")
        .arg(&self.vault_path)
        .arg("--idle-timeout")
        .arg("never")
        .env("XDG_RUNTIME_DIR", &self.runtime_dir)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    
    if ci_mode {
        cmd.arg("--ci");
    }
    
    match cmd.spawn() {
        Ok(child) => {
            self.daemon = Some(DaemonGuard::new(child));
            wait_for_daemon_ready(&self.socket_path, 5000)
        }
        Err(_) => false,
    }
}
```

---

## Test Function Patterns

### 1. Synchronous Test Pattern

```rust
#[test]
fn test_audit_log_size_based_rotation() {
    let temp_dir = TempDir::new().expect("Failed to create temp dir");
    let log_path = temp_dir.path().join("audit.jsonl");
    
    // Create audit logger with small max_size for testing
    let config = AuditConfig {
        max_size: 1024, // 1KB for testing
        ..Default::default()
    };
    
    // Test implementation...
    assert!(metadata.len() as usize > config.max_size);
}
```

### 2. Async Test Pattern

```rust
#[tokio::test]
async fn test_archive_format_structure() {
    let temp_dir = TempDir::new().expect("Failed to create temp dir");
    let home_dir = temp_dir.path();
    
    let sigil = sigil_path();
    if !sigil.exists() {
        eprintln!("sigil not found, skipping test. Run: cargo build --bin sigil");
        return;
    }
    
    // Async test implementation...
}
```

### 3. Conditional Test Pattern

```rust
#[test]
fn test_sealed_vault_workflow() {
    let cli_path = workspace_root().join("crates/sigil-cli/src/main.rs");
    let cli_code = fs::read_to_string(&cli_path).expect("Failed to read CLI code");
    
    // Verify implementation exists
    assert!(
        cli_code.contains("sealed") || cli_code.contains("git-safe"),
        "Init must support sealed/git-safe mode"
    );
}
```

---

## Helper Functions and Test Utilities

### 1. Socket Waiting Utilities

```rust
/// Wait for a Unix domain socket to appear and be ready for connections
pub fn wait_for_socket(socket_path: &Path, timeout_ms: u64) -> bool {
    let start = std::time::Instant::now();
    let timeout = Duration::from_millis(timeout_ms);
    let poll_interval = Duration::from_millis(100);
    
    while start.elapsed() < timeout {
        if socket_path.exists() {
            thread::sleep(Duration::from_millis(100));
            
            if let Ok(metadata) = fs::metadata(socket_path) {
                #[cfg(unix)]
                {
                    use std::os::unix::fs::FileTypeExt;
                    if metadata.file_type().is_socket() {
                        return true;
                    }
                }
                thread::sleep(poll_interval);
                continue;
            }
        }
        thread::sleep(poll_interval);
    }
    
    false
}

/// Wait for daemon to be ready by testing socket connectivity
pub fn wait_for_daemon_ready(socket_path: &Path, timeout_ms: u64) -> bool {
    let start = std::time::Instant::now();
    let timeout = Duration::from_millis(timeout_ms);
    
    while start.elapsed() < timeout {
        if socket_path.exists() {
            #[cfg(unix)]
            {
                use std::os::unix::net::UnixStream;
                if UnixStream::connect(socket_path).is_ok() {
                    return true;
                }
            }
            thread::sleep(Duration::from_millis(100));
        } else {
            thread::sleep(Duration::from_millis(100));
        }
    }
    
    false
}
```

### 2. Environment Detection Helpers

```rust
/// Check if bubblewrap is available on the system
pub fn is_bwrap_available() -> bool {
    detect_bwrap()
}

/// Ensure XDG_RUNTIME_DIR is set and usable
pub fn ensure_xdg_runtime_dir() -> PathBuf {
    lib_ensure_xdg_runtime_dir()
        .expect("Failed to ensure XDG_RUNTIME_DIR is set and usable")
}

/// Check if daemon startup is likely to succeed
pub fn can_start_daemon(daemon_path: &Path, require_bwrap: bool) -> bool {
    if !daemon_path.exists() {
        eprintln!("Cannot start daemon: binary not found at {:?}", daemon_path);
        return false;
    }
    
    if require_bwrap && !is_bwrap_available() {
        eprintln!("Cannot start daemon: bwrap not available (install bubblewrap)");
        return false;
    }
    
    true
}
```

### 3. Conditional Skip Macros

```rust
/// Skip test if bwrap is not available
#[macro_export]
macro_rules! skip_if_no_bwrap {
    () => {
        sigil_integration_tests::env_detect::skip::if_no_bwrap();
    };
    ($($arg:tt)*) => {
        sigil_integration_tests::env_detect::skip::if_no_bwrap_with(&format!($($arg)*));
    };
}

/// Skip test if running in CI environment
#[macro_export]
macro_rules! skip_if_ci {
    () => {
        sigil_integration_tests::env_detect::skip::if_ci();
    };
    ($($arg:tt)*) => {
        sigil_integration_tests::env_detect::skip::if_ci_with(&format!($($arg)*));
    };
}

/// Skip test if the binary does not exist
#[macro_export]
macro_rules! skip_if_binary_missing {
    ($binary_path:expr) => {
        sigil_integration_tests::env_detect::skip::if_binary_missing($binary_path);
    };
    ($binary_path:expr, $reason:expr) => {
        sigil_integration_tests::env_detect::skip::if_binary_missing_with($binary_path, $reason);
    };
}
```

---

## How to Add New Tests

### 1. Basic Integration Test Template

```rust
//! Test Description
//!
//! Detailed explanation of what this test verifies.

mod common;
use common::workspace_root;
use std::process::{Command, Stdio};
use tempfile::TempDir;

/// Get the sigil CLI binary path
fn sigil_path() -> PathBuf {
    workspace_root().join("target").join("debug").join("sigil")
}

#[test]
fn test_feature_description() {
    let temp_dir = TempDir::new().expect("Failed to create temp dir");
    let home_dir = temp_dir.path();
    
    let sigil = sigil_path();
    if !sigil.exists() {
        eprintln!("sigil not found, skipping test. Run: cargo build --bin sigil");
        return;
    }
    
    // Initialize test vault
    let status = Command::new(&sigil)
        .arg("init")
        .arg("--path")
        .arg(home_dir.join(".sigil"))
        .arg("--no-passphrase")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();
    
    if !status.map(|s| s.success()).unwrap_or(false) {
        eprintln!("Failed to initialize vault, skipping test");
        return;
    }
    
    // Test implementation...
    assert!(true, "Test assertion");
}
```

### 2. Daemon Integration Test Template

```rust
//! Daemon Test Description

mod common;
use common::workspace_root;
use sigil_integration_tests::DaemonGuard;
use std::process::{Command, Stdio};
use tempfile::TempDir;

#[tokio::test]
async fn test_daemon_feature() {
    let temp_dir = TempDir::new().expect("Failed to create temp dir");
    
    // Setup binaries
    let workspace = workspace_root();
    let sigil = workspace.join("target").join("debug").join("sigil");
    let sigild = workspace.join("target").join("debug").join("sigild");
    
    if !sigil.exists() || !sigild.exists() {
        eprintln!("Binaries not found, skipping test");
        return;
    }
    
    // Initialize vault
    let vault_path = temp_dir.path().join("vault");
    let socket_path = temp_dir.path().join("sigil.sock");
    
    let _ = Command::new(&sigil)
        .arg("init")
        .arg("--path")
        .arg(&vault_path)
        .arg("--no-passphrase")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();
    
    // Start daemon
    let mut cmd = Command::new(&sigild);
    cmd.arg("start")
        .arg("--socket")
        .arg(&socket_path)
        .arg("--vault")
        .arg(&vault_path)
        .arg("--idle-timeout")
        .arg("never")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    
    let daemon_guard = match cmd.spawn() {
        Ok(child) => DaemonGuard::new(child),
        Err(_) => {
            eprintln!("Failed to start daemon, skipping test");
            return;
        }
    };
    
    // Wait for daemon readiness
    let _ready = wait_for_daemon_ready(&socket_path, 5000);
    
    // Test implementation...
    // DaemonGuard automatically kills process when dropped
}
```

### 3. Unit Test Pattern (in lib.rs)

```rust
#[cfg(test)]
mod feature_tests {
    use sigil_core::FeatureToTest;
    
    #[test]
    fn test_specific_aspect() {
        let input = "test_data";
        let result = FeatureToTest::process(input);
        
        assert!(result.is_ok(), "Should process successfully");
        assert_eq!(result.unwrap(), expected);
    }
    
    #[test]
    fn test_error_handling() {
        let invalid_input = "invalid";
        let result = FeatureToTest::process(invalid_input);
        
        assert!(result.is_err(), "Should reject invalid input");
    }
}
```

---

## Assertion and Verification Patterns

### 1. Command Output Verification

```rust
let output = Command::new(&sigil)
    .arg("list")
    .stdout(Stdio::piped())
    .stderr(Stdio::piped())
    .output()
    .unwrap();

if output.status.success() {
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("expected_text"), "Should show expected content");
}
```

### 2. File Content Verification

```rust
let file_content = fs::read_to_string(&file_path)
    .expect("Failed to read file");

assert!(
    file_content.contains("expected_content"),
    "File should contain expected content"
);
```

### 3. Exit Code Verification

```rust
let status = Command::new(&sigil)
    .arg("command")
    .status()
    .unwrap();

assert!(
    status.success(),
    "Command should succeed"
);
```

---

## Cleanup and Resource Management

### 1. Automatic Cleanup with RAII

```rust
// TempDir automatically cleans up when dropped
let temp_dir = TempDir::new().expect("Failed to create temp dir");
// ... use temp_dir
// Automatic cleanup when temp_dir goes out of scope

// DaemonGuard automatically kills process when dropped
let daemon_guard = DaemonGuard::new(child);
// ... daemon runs
// Automatic kill when daemon_guard goes out of scope
```

### 2. Manual Cleanup Pattern

```rust
pub fn cleanup_test_runtime_dir(runtime_dir: &Path) {
    // Ignore errors during cleanup
    let _ = fs::remove_dir_all(runtime_dir);
}
```

---

## Common Testing Scenarios

### 1. Command Execution with Secrets

```rust
// Add secret
let mut add_child = Command::new(&sigil)
    .arg("add")
    .arg("test/secret")
    .arg("--from-stdin")
    .stdin(Stdio::piped())
    .stdout(Stdio::null())
    .stderr(Stdio::null())
    .spawn()
    .unwrap();

{
    let stdin = add_child.stdin.as_mut().expect("Failed to open stdin");
    stdin.write_all(b"secret-value").unwrap();
}
let _ = add_child.wait_with_output();

// Retrieve secret
let output = Command::new(&sigil)
    .arg("get")
    .arg("test/secret")
    .output()
    .unwrap();
```

### 2. Archive Format Verification

```rust
// Export archive
let output = Command::new(&sigil)
    .arg("export")
    .arg("--output")
    .arg(&export_file)
    .arg("--passphrase")
    .arg("")
    .output()
    .unwrap();

// Verify format
let archive_data = fs::read(&export_file).unwrap();

assert!(
    archive_data.starts_with(b"SIGIL\x00"),
    "Archive should start with magic bytes"
);

let version_bytes = &archive_data[6..8];
let version = u16::from_be_bytes([version_bytes[0], version_bytes[1]]);
assert_eq!(version, 1, "Archive version should be 1");
```

---

## Test Configuration and Constants

### 1. Default Configuration

```rust
pub struct TestConfig {
    pub sigil_bin: PathBuf,
    pub sigild_bin: PathBuf,
    pub sigil_proxy_bin: Option<PathBuf>,
    pub vault_dir: PathBuf,
    pub runtime_dir: PathBuf,
}

impl Default for TestConfig {
    fn default() -> Self {
        Self {
            sigil_bin: PathBuf::from("target/debug/sigil"),
            sigild_bin: PathBuf::from("target/debug/sigild"),
            sigil_proxy_bin: Some(PathBuf::from("target/debug/sigil-proxy")),
            vault_dir: PathBuf::from("/tmp/sigil-test-vault"),
            runtime_dir: PathBuf::from("/tmp/sigil-test-runtime"),
        }
    }
}
```

### 2. Common Timeout Values

```rust
const DAEMON_STARTUP_TIMEOUT_MS: u64 = 5000;
const SOCKET_POLL_INTERVAL_MS: u64 = 100;
const COMMAND_EXECUTION_TIMEOUT_MS: u64 = 10000;
```

---

## Integration with Test Frameworks

### 1. Tokio Async Runtime

```rust
#[tokio::test]
async fn async_test_function() {
    // Async operations here
    let result = some_async_function().await;
    assert!(result.is_ok());
}
```

### 2. Property-Based Testing

```rust
#[test]
fn test_property() {
    let mut scrubber = Scrubber::new();
    
    // Test with multiple inputs
    let test_cases = vec![
        ("input1", "expected1"),
        ("input2", "expected2"),
    ];
    
    for (input, expected) in test_cases {
        let result = scrubber.scrub(input);
        assert!(result.contains(expected));
    }
}
```

---

## Summary of Key Testing Patterns

| Pattern Type | Implementation | Usage Scenario |
|--------------|----------------|----------------|
| **Binary Path Resolution** | `workspace_root().join("target/debug/sigil")` | Locating test binaries |
| **Temp Directory Creation** | `TempDir::new()` | Isolated test environments |
| **Daemon Lifecycle** | `DaemonGuard` RAII pattern | Automatic process cleanup |
| **Socket Waiting** | `wait_for_daemon_ready()` | Daemon readiness checks |
| **Conditional Testing** | `skip_if_*` macros | Platform-dependent tests |
| **Command Execution** | `Command::new().args().output()` | CLI integration testing |
| **File Verification** | `fs::read_to_string()` + asserts | Output validation |
| **Secret Management** | stdin piping with `--from-stdin` | Vault operations testing |

---

## Best Practices Identified

1. **Always check binary existence** before running tests that require compiled binaries
2. **Use RAII patterns** for automatic cleanup (TempDir, DaemonGuard)
3. **Provide clear error messages** in assertions with expected vs actual values
4. **Use conditional returns** for tests that may skip due to missing dependencies
5. **Leverage shared utilities** from `common.rs` rather than duplicating code
6. **Include timeout mechanisms** for daemon startup and socket operations
7. **Use proper environment isolation** with temp directories and XDG_RUNTIME_DIR
8. **Document test purposes** with module-level comments explaining what's being tested
9. **Handle platform differences** with `#[cfg(unix)]` and platform-specific code
10. **Provide helpful skip messages** when tests can't run due to missing dependencies

This comprehensive testing framework enables robust integration testing while maintaining code reusability and clear test organization.