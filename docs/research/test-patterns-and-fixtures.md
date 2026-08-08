# SIGIL Test Patterns and Fixtures Analysis

## Overview

This document analyzes the test patterns, fixtures, and conventions used throughout the SIGIL codebase to guide new test development and maintain consistency across the project.

## Test Architecture

SIGIL uses a multi-layered testing approach:

1. **Unit Tests** - Individual crate-level tests in `#[cfg(test)]` modules
2. **Integration Tests** - Cross-crate tests in `crates/sigil-integration-tests/`
3. **Property-Based Tests** - Proptest tests for invariant verification
4. **Verification Tests** - Implementation verification against plan deliverables
5. **Red Team Tests** - Security-focused adversarial testing

## Common Test Infrastructure

### Location: `crates/sigil-integration-tests/`

The integration test crate provides shared utilities and patterns for all testing:

#### Key Modules:
- `common.rs` - Shared test utilities and helpers
- `binary_fixture.rs` - Test binary creation and management
- `env_detect.rs` - Environment detection and conditional test execution
- `thread_util.rs` - Thread management for concurrent tests
- `concurrent_tests.rs` - Multi-threaded test patterns

## Test Fixtures and Their Purposes

### 1. Binary Fixture System (`binary_fixture.rs`)

**Purpose:** Create temporary test binaries with specific permissions for security testing

**Key Fixtures:**
- `create_executable_binary(name, content)` - Regular executable (0o755)
- `create_setuid_binary(name, content)` - Setuid executable (0o4755)
- `create_setgid_binary(name, content)` - Setgid executable (0o2755)
- `create_setuid_setgid_binary(name, content)` - Both bits set (0o6755)

**RAII Guards:**
```rust
let _guard = BinaryFixtureGuard::new(); // Auto-cleanup on drop
let _path_guard = add_to_path(&binary_path); // Restore PATH on drop
```

**Usage Pattern:**
```rust
#[test]
fn test_sandbox_blocks_setuid() {
    let setuid_bin = create_setuid_binary("test_suid", b"#!/bin/sh\nid\n").unwrap();
    let _guard = add_binary_to_path(&setuid_bin).unwrap();
    
    // Test sandbox detection...
    assert!(sandbox_detects_setuid(&setuid_bin));
}
```

### 2. Environment Detection (`env_detect.rs`)

**Purpose:** Detect system capabilities and conditionally run tests

**Key Detection Functions:**
- `detect_bwrap()` - Check if bubblewrap is available
- `detect_systemd()` - Check for systemd socket activation
- `detect_launchd()` - Check for macOS launchd
- `detect_ci()` - Detect CI environment

**Skip Patterns:**
```rust
// Function version (with installation hints)
skip::if_no_bwrap();

// Function version with custom message
skip::if_no_bwrap_with("Network isolation tests require bwrap");

// Macro version (compile-time checking)
skip_if_no_bwrap!(); // In common.rs
skip_if_ci!("Interactive test not suitable for CI");
skip_if_binary_missing!("/path/to/binary");
```

### 3. Common Test Utilities (`common.rs`)

**Purpose:** Shared helper functions for all integration tests

**Key Functions:**

#### Path Navigation
```rust
workspace_root() // Returns /home/coding/SIGIL
crate_source_path(crate_name, file) // e.g., "sigil-sandbox", "lib.rs"
```

#### Socket/Daemon Management
```rust
wait_for_socket(socket_path, timeout_ms) // Poll for socket existence
wait_for_daemon_ready(socket_path, timeout_ms) // Test connectivity
socket_wait_helper(socket_path, timeout_ms) // Combined wait + health check
daemon_health_check(socket_path) // Comprehensive validation
```

#### Runtime Directory Management
```rust
ensure_xdg_runtime_dir() // Set up XDG_RUNTIME_DIR if missing
create_test_runtime_dir(test_name) // Isolated temp directory per test
cleanup_test_runtime_dir(runtime_dir) // Remove test directory
```

#### Daemon Startup
```rust
can_start_daemon(daemon_path, require_bwrap) // Preflight checks
is_bwrap_available() // Check sandbox availability
```

## Test Patterns by Type

### Pattern 1: Code Verification Tests

**Purpose:** Verify implementation matches plan specifications

**File Example:** `phase4_1_4_2_verification_test.rs`

**Pattern:**
```rust
/// Test 4.1.1: Verify seccomp BPF filter blocks ptrace
///
/// From Phase 4.1 deliverables:
/// "Seccomp BPF filter blocking: ptrace — prevent debugging"
#[test]
fn test_seccomp_blocks_ptrace() {
    let landlock_path = workspace_root().join("crates/sigil-sandbox/src/landlock.rs");
    let landlock_code = fs::read_to_string(&landlock_path)
        .expect("Failed to read landlock code");

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
```

**Key Characteristics:**
- Test name references plan deliverable (e.g., "4.1.1")
- Docstring cites plan requirement
- Reads source code as text
- Uses string containment checks for verification
- Provides clear assertion messages

### Pattern 2: Property-Based Tests

**Purpose:** Verify invariants across wide input ranges

**File Example:** `proptest_parser.rs`

**Pattern:**
```rust
proptest! {
    #[test]
    fn prop_parser_never_panics(command in ".{0,1000}") {
        let _ = CommandParser::extract_placeholders(&command);
        let _ = CommandParser::resolve_command(&command);
        let _ = CommandParser::validate_command(&command);
    }
}
```

**Key Characteristics:**
- Uses `proptest!` macro
- Generates random inputs with constraints
- Tests should never panic
- Tests maintain invariants (ordering, bounds, uniqueness)
- Uses `prop_assert!` for proptest-specific assertions

### Pattern 3: Async Unit Tests

**Purpose:** Test async functionality in individual crates

**File Example:** `memory.rs` (in `sigil-daemon/src/`)

**Pattern:**
```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_protected_secrets_creation() {
        let secrets = ProtectedSecrets::new().unwrap();
        let store = secrets.inner().read().await;
        assert!(store.is_empty());
    }

    #[tokio::test]
    async fn test_protected_secrets_insert() {
        let secrets = ProtectedSecrets::new().unwrap();
        secrets.insert("test/path".to_string(), b"test_value".to_vec())
            .await
            .unwrap();

        let store = secrets.inner().read().await;
        assert_eq!(store.len(), 1);
    }
}
```

**Key Characteristics:**
- Uses `#[cfg(test)]` module
- Uses `#[tokio::test]` for async tests
- Tests individual functions in isolation
- Directly tests internal logic

### Pattern 4: Red Team Tests

**Purpose:** Security-focused adversarial testing

**File Example:** `phase6_redteam_test.rs`

**Pattern:**
```rust
/// Test 1: Verify TUI runs on separate PTY
///
/// From Phase 6 Red Team Checkpoint:
/// "From the agent's terminal, attempt to observe the TUI:
///  cat /dev/pts/* — should fail (different PTY, permissions)"
#[test]
fn test_tui_separate_pty() {
    let tui_path = workspace_root().join("crates/sigil-tui/src/main.rs");
    let tui_code = fs::read_to_string(&tui_path).expect("Failed to read TUI code");

    // Verify PTY allocation exists
    assert!(
        tui_code.contains("openpty") || tui_code.contains("PTY") || tui_code.contains("pts"),
        "TUI must allocate a separate PTY for isolation"
    );

    // Verify process isolation is enabled
    assert!(
        tui_code.contains("PR_SET_DUMPABLE") || 
        tui_code.contains("set_dumpable") || 
        tui_code.contains("process_isolation"),
        "TUI must enable process isolation to prevent memory reads"
    );
}
```

**Key Characteristics:**
- Focuses on security properties
- Tests adversarial scenarios
- Verifies defense mechanisms
- Often cross-references threat model

## Setup/Teardown Patterns

### Pattern 1: RAII Guards for Automatic Cleanup

**Setup:** Create guard in test
**Teardown:** Automatic when guard drops

```rust
#[test]
fn test_with_auto_cleanup() {
    // Setup: RAII guard creates temporary directory
    let _guard = BinaryFixtureGuard::new();
    
    let test_bin = create_executable_binary("test", b"test").unwrap();
    
    // Test code...
    assert!(test_bin.exists());
    
} // Teardown: Guard dropped here, directory removed
```

### Pattern 2: Manual Setup/Teardown

```rust
#[test]
fn test_with_manual_cleanup() {
    // Setup
    let runtime_dir = create_test_runtime_dir("my_test").unwrap();
    let socket_path = runtime_dir.join("sigil.sock");
    
    // Test code...
    assert!(socket_path.parent().unwrap().exists());
    
    // Teardown
    cleanup_test_runtime_dir(&runtime_dir).unwrap();
}
```

### Pattern 3: Conditional Test Execution

```rust
#[test]
fn test_sandbox_feature() {
    // Setup: Check prerequisites
    skip_if_no_bwrap!("This test requires bubblewrap for sandbox isolation");
    
    let runtime_dir = create_test_runtime_dir("sandbox_test").unwrap();
    
    // Test code that requires bwrap...
    let result = run_sandbox_command();
    assert!(result.is_ok());
    
    // Teardown
    cleanup_test_runtime_dir(&runtime_dir).unwrap();
}
```

## Helper Functions and Test Utilities

### From `common.rs`:

#### Path Utilities
- `workspace_root()` - Navigate to project root
- `crate_source_path()` - Navigate to specific crate files

#### Socket/Daemon Utilities
- `wait_for_socket()` - Poll for socket file appearance
- `wait_for_daemon_ready()` - Verify daemon accepting connections
- `daemon_health_check()` - Comprehensive health validation
- `socket_wait_helper()` - Combined wait + health check

#### Environment Setup
- `ensure_xdg_runtime_dir()` - Set up XDG runtime directory
- `create_test_runtime_dir()` - Create isolated test directory
- `cleanup_test_runtime_dir()` - Remove test directory
- `is_bwrap_available()` - Check for sandbox availability

#### Async Runtime
- `create_blocking_runtime()` - Create tokio runtime for async in sync tests

### From `binary_fixture.rs`:

#### Binary Creation
- `create_test_binary()` - Generic binary creation
- `create_executable_binary()` - Regular executable
- `create_setuid_binary()` - Setuid executable
- `create_setgid_binary()` - Setgid executable
- `create_setuid_setgid_binary()` - Both setuid + setgid

#### Binary Verification
- `is_setuid()` - Check if binary has setuid bit
- `is_setgid()` - Check if binary has setgid bit

#### PATH Management
- `add_to_path()` - Add directory to PATH with auto-restore
- `add_binary_to_path()` - Add binary's parent directory to PATH

#### Cleanup
- `cleanup_test_binaries()` - Remove all test binaries
- `cleanup_setuid_fixtures()` - Alias for cleanup_test_binaries()

### From `env_detect.rs`:

#### Detection Functions
- `detect_bwrap()` - Check for bubblewrap
- `detect_systemd()` - Check for systemd
- `detect_launchd()` - Check for launchd (macOS)
- `detect_ci()` - Check if running in CI

#### Skip Functions
- `skip::if_no_bwrap()` - Skip if bwrap unavailable (with hints)
- `skip::if_no_bwrap_with()` - Skip with custom message (with hints)
- `skip::if_ci()` - Skip in CI environment
- `skip::if_binary_missing()` - Skip if binary not built

## Naming Conventions

### Test Functions
- Verification tests: `test_<phase>_<deliverable>` (e.g., `test_seccomp_blocks_ptrace`)
- Property tests: `prop_<invariant_name>` (e.g., `prop_parser_never_panics`)
- Unit tests: `test_<functionality>` (e.g., `test_protected_secrets_creation`)
- Red team tests: `test_<security_property>` (e.g., `test_tui_separate_pty`)

### Test Files
- Integration tests: `phase<N>_<topic>_test.rs`
- Property tests: `proptest_<module>.rs`
- Red team tests: `phase<N>_redteam_test.rs`
- Unit tests: Inline in source files under `#[cfg(test)]`

### Fixtures
- Binary fixtures: `create_<type>_binary()` (e.g., `create_setuid_binary`)
- Test directories: `create_test_runtime_dir()` / `cleanup_test_runtime_dir()`
- Guards: `<Purpose>Guard` (e.g., `BinaryFixtureGuard`, `PathGuard`)

## Common Assertions

### String/Code Verification
```rust
assert!(code.contains("pattern"), "Error message");
assert!(code.contains("pattern1") && code.contains("pattern2"), "Error");
assert_ne!(code.find("forbidden"), None, "Should not contain pattern");
```

### File System
```rust
assert!(path.exists(), "File should exist");
assert!(path.is_file(), "Should be a file");
assert!(path.is_dir(), "Should be a directory");
```

### Permissions (Unix)
```rust
let mode = metadata.permissions.mode();
assert_eq!(mode & 0o755, 0o755, "Should have executable permissions");
assert_ne!(mode & 0o4000, 0, "Should have setuid bit");
```

### Proptest
```rust
prop_assert!(condition);
prop_assert_eq!(left, right);
prop_assert_ne!(value, expected);
```

## Adding New Tests

### Step 1: Determine Test Type

**Verification Test:** Implementation matches plan specification
- Use code verification pattern
- Name it `test_<phase>_<deliverable>`
- Add to `crates/sigil-integration-tests/tests/`

**Property Test:** Invariant across input space
- Use proptest pattern
- Name it `prop_<invariant>`
- Add to `crates/<crate>/tests/proptest_<module>.rs`

**Unit Test:** Individual function/crate behavior
- Use async unit test pattern
- Add to `#[cfg(test)]` module in source file

**Red Team Test:** Security property verification
- Use red team pattern
- Name it `test_<security_property>`
- Add to `crates/sigil-integration-tests/tests/phase<N>_redteam_test.rs`

### Step 2: Include Common Module

For integration tests:
```rust
mod common;
use common::workspace_root;
```

### Step 3: Set Up Prerequisites

```rust
#[test]
fn test_my_feature() {
    // Check environment
    skip_if_no_bwrap!("This test requires sandbox");
    
    // Set up test directory
    let runtime_dir = create_test_runtime_dir("my_test").unwrap();
    
    // Test code...
    
    // Cleanup
    cleanup_test_runtime_dir(&runtime_dir).unwrap();
}
```

### Step 4: Use Appropriate Fixtures

**For binaries:**
```rust
let test_bin = create_executable_binary("mytest", b"#!/bin/sh\necho test\n").unwrap();
let _path_guard = add_binary_to_path(&test_bin).unwrap();
```

**For automatic cleanup:**
```rust
let _guard = BinaryFixtureGuard::new();
```

**For socket/daemon tests:**
```rust
socket_wait_helper(&socket_path, 5000).unwrap();
```

## Test Organization

### Directory Structure
```
crates/
├── sigil-core/
│   └── tests/
│       └── proptest_parser.rs
├── sigil-daemon/
│   ├── src/memory.rs (contains #[cfg(test)])
│   └── tests/
│       ├── hardening_test.rs
│       └── startup_modes.rs
├── sigil-integration-tests/
│   ├── src/
│   │   ├── binary_fixture.rs
│   │   ├── env_detect.rs
│   │   └── common.rs (also tests/common.rs)
│   └── tests/
│       ├── phase4_1_4_2_verification_test.rs
│       ├── phase6_redteam_test.rs
│       └── phase2_audit_ipc_signals_test.rs
```

### Import Patterns

**Verification tests:**
```rust
mod common;
use common::workspace_root;
use std::fs;
```

**Property tests:**
```rust
use proptest::prelude::*;
use sigil_core::parser::CommandParser;
```

**Unit tests:**
```rust
#[cfg(test)]
mod tests {
    use super::*;
    // test functions here
}
```

## Best Practices

### 1. Use RAII Guards for Cleanup
Prefer `BinaryFixtureGuard` over manual cleanup to ensure cleanup even on panic.

### 2. Provide Clear Assertion Messages
Include descriptive messages in all assertions for debugging.

### 3. Check Prerequisites Early
Use skip helpers at the start of tests to fail fast when dependencies are missing.

### 4. Make Tests Independent
Each test should set up and clean up its own state (don't rely on test order).

### 5. Use Platform-Specific Conditions
```rust
#[cfg(target_os = "linux")]
assert!(linux_specific_condition);

#[cfg(target_os = "macos")]
assert!(macos_specific_condition);
```

### 6. Test Error Messages
Verify not just that errors occur, but that they have appropriate messages:
```rust
assert!(result.is_err());
let err_msg = result.unwrap_err().to_string();
assert!(err_msg.contains("expected substring"));
```

### 7. Property Test Edge Cases
Include property tests for edge cases and boundary conditions.

### 8. Document Security Assumptions
In red team tests, clearly document what security property is being tested.

## Test Execution Patterns

### Running All Tests
```bash
cargo test --workspace
```

### Running Specific Test Types
```bash
# Unit tests only
cargo test --lib

# Integration tests only  
cargo test --test sigil_integration_tests

# Property tests only
cargo test --test proptest_parser
```

### Running with Output
```bash
# Show test output
cargo test -- --nocapture

# Show test output but only for failed tests
cargo test -- --show-output
```

### Conditional Test Execution
Tests automatically skip when prerequisites are missing (bwrap, systemd, etc.), printing clear messages.

## Summary

SIGIL's test architecture emphasizes:

1. **Verification over validation** - Tests verify implementation matches plan
2. **Security-first testing** - Red team tests validate security properties
3. **Property-based testing** - Proptest ensures invariants across input space
4. **Clean test isolation** - Each test sets up and tears down its own environment
5. **Conditional execution** - Tests gracefully skip when dependencies unavailable
6. **Comprehensive fixtures** - Binary, path, and environment fixtures simplify common operations

When adding new tests, identify the test type first, then follow the corresponding patterns for setup, execution, and teardown. Use the common utilities and fixtures to maintain consistency across the codebase.