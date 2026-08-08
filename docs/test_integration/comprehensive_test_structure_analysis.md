# SIGIL Test File Structure Analysis

## Executive Summary

This document provides a comprehensive analysis of SIGIL's test file structure, patterns, and organization for integrating new tests and assertions. The analysis covers both unit tests embedded in source files and integration tests in dedicated test modules.

## Test Organization Overview

SIGIL uses a multi-tier testing approach:

### 1. **Unit Tests** (Embedded in Source Files)
- Location: Inside implementation files using `#[cfg(test)]` modules
- Example: `crates/sigil-core/src/thread_utils/result_collector.rs` (contains 193+ tests)
- Purpose: Test individual functions, structs, and internal logic
- Execution: `cargo test` runs all unit tests automatically

### 2. **Integration Tests** (Dedicated Test Modules)
- Location: `crates/sigil-integration-tests/tests/`
- Example: `phase1_5_6_7_verification_test.rs`
- Purpose: Test cross-component interactions and CLI commands
- Execution: `cargo test --test <test_name>`

### 3. **Common Test Utilities** (Shared Infrastructure)
- Location: `crates/sigil-integration-tests/tests/common.rs`
- Purpose: Shared helper functions, fixtures, and test setup
- Usage: Imported via `mod common;` in integration tests

## Detailed Test Structure Analysis

### Unit Test Structure Pattern

#### File Organization
```rust
// In implementation file (e.g., result_collector.rs)

//! Module documentation

// Implementation code...

#[cfg(test)]
mod tests {
    use super::*;
    
    // ===== Test Categories =====
    
    // Basic functionality tests
    #[test]
    fn test_basic_functionality() {
        // Test implementation
    }
    
    // Comprehensive validation tests
    #[test]
    fn test_comprehensive_validation() {
        // Test implementation
    }
    
    // Edge case and error tests
    #[test]
    fn test_error_cases() {
        // Test implementation
    }
}
```

#### Key Unit Test Features
1. **Inline Organization**: Tests live directly beside the code they test
2. **Private Access**: Can test private functions via `use super::*`
3. **Fast Execution**: No external dependencies, minimal setup
4. **Focused Scope**: Each test validates a specific behavior

### Integration Test Structure Pattern

#### File Organization
```rust
// In integration test file (e.g., phase1_5_6_7_verification_test.rs)

//! Phase X.X Verification Tests
//!
//! Runtime tests to verify Phase X.X deliverables

mod common;
use common::workspace_root;
use std::fs;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use tempfile::TempDir;

/// Helper function to get sigil binary path
fn sigil_path() -> PathBuf {
    workspace_root().join("target").join("debug").join("sigil")
}

// ===== Test Groups =====

#[tokio::test]
async fn test_feature_name() {
    let temp_dir = TempDir::new().expect("Failed to create temp dir");
    
    // Test implementation using Command to run sigil CLI
}

#[test]
fn test_sync_feature() {
    // Synchronous test
}
```

#### Key Integration Test Features
1. **CLI Testing**: Tests run actual `sigil` commands via `std::process::Command`
2. **Isolation**: Each test uses temporary directories (`tempfile::TempDir`)
3. **Async Support**: Uses `#[tokio::test]` for async operations
4. **Real Environment**: Tests actual behavior, not mocked components

## Test Fixtures and Setup Patterns

### 1. **TempDir Pattern** (Primary Fixture)
```rust
#[tokio::test]
async fn test_with_isolation() {
    let temp_dir = TempDir::new().expect("Failed to create temp dir");
    let home_dir = temp_dir.path();
    let sigil_dir = home_dir.join(".sigil");
    
    fs::create_dir_all(&sigil_dir).unwrap();
    
    // Test implementation with isolated environment
    
    // Cleanup is automatic when temp_dir is dropped
}
```

**Purpose**: Complete filesystem isolation for each test

### 2. **Binary Path Pattern**
```rust
fn sigil_path() -> PathBuf {
    workspace_root().join("target").join("debug").join("sigil")
}

fn daemon_path() -> PathBuf {
    workspace_root().join("target").join("debug").join("sigild")
}
```

**Purpose**: Consistent binary path resolution across tests

### 3. **Command Execution Pattern**
```rust
let output = Command::new(&sigil)
    .arg("init")
    .arg("--path")
    .arg(&sigil_dir)
    .arg("--no-passphrase")
    .env("HOME", home_dir)
    .stdout(Stdio::piped())
    .stderr(Stdio::piped())
    .output()
    .unwrap();
```

**Purpose**: Execute CLI commands with controlled environment

### 4. **Setup-Execute-Assert Pattern**
```rust
#[tokio::test]
async fn test_standard_pattern() {
    // ===== SETUP =====
    let temp_dir = TempDir::new().expect("Failed to create temp dir");
    let home_dir = temp_dir.path();
    let sigil = sigil_path();
    
    // ===== EXECUTE =====
    let output = Command::new(&sigil)
        .arg("command")
        .env("HOME", home_dir)
        .output()
        .unwrap();
    
    // ===== ASSERT =====
    assert!(output.status.success(), "Command should succeed");
    
    // Cleanup is automatic
}
```

## Assertion Patterns

### 1. **Standard Assertion Pattern**
```rust
#[test]
fn test_standard_assertions() {
    let collector = StreamingResultCollector::<i32>::new();
    
    // Pre-condition assertions
    let count_before = collector.sender_count();
    assert_eq!(count_before, 1, "Initial count should be 1");
    assert!(count_before > 0, "Count should be non-zero");
    
    // Operation
    let clone = collector.clone();
    
    // Post-condition assertions
    let count_after = collector.sender_count();
    assert_eq!(count_after, 2, "Count should increment by 1");
    assert!(count_after > count_before, "Count should increase");
}
```

### 2. **Comprehensive Validation Pattern** (Before/During/After)
```rust
#[test]
fn test_comprehensive_validation() {
    let collector = StreamingResultCollector::<i32>::new();
    
    // === BEFORE STATE CAPTURE ===
    let count_before = validate_sender_count_before_clone(&collector)
        .expect("Pre-clone validation should pass");
    
    // === OPERATION ===
    let clone = collector.clone();
    
    // === POST-CONDITION VALIDATION ===
    validate_sender_count_after_clone(&collector, &clone, count_before + 1)
        .expect("Post-clone validation should pass");
    
    // === CONSISTENCY CHECK ===
    assert_eq!(collector.sender_count(), clone.sender_count(), 
        "All instances should see same count");
}
```

### 3. **Stability Testing Pattern**
```rust
#[test]
fn test_stability_pattern() {
    let collector = StreamingResultCollector::<i32>::new();
    
    // Multiple reads to verify stability
    let count1 = collector.sender_count();
    let count2 = collector.sender_count();
    let count3 = collector.sender_count();
    
    let max_count = count1.max(count2).max(count3);
    let min_count = count1.min(count2).min(count3);
    let variation = max_count - min_count;
    
    assert_eq!(variation, 0, "Values should be stable: variation={}", variation);
}
```

## Common Test Utilities

### Helper Functions in `common.rs`

#### 1. **Path Resolution**
```rust
pub fn workspace_root() -> PathBuf
pub fn crate_source_path(crate_name: &str, file: &str) -> PathBuf
```

#### 2. **Environment Detection**
```rust
pub fn is_bwrap_available() -> bool
pub fn ensure_xdg_runtime_dir() -> PathBuf
pub fn can_start_daemon(daemon_path: &Path, require_bwrap: bool) -> bool
```

#### 3. **Socket/Process Testing**
```rust
pub fn wait_for_socket(socket_path: &Path, timeout_ms: u64) -> bool
pub fn wait_for_daemon_ready(socket_path: &Path, timeout_ms: u64) -> bool
pub fn daemon_health_check(socket_path: &Path) -> Result<(), String>
pub fn socket_wait_helper(socket_path: &Path, timeout_ms: u64) -> Result<(), String>
```

#### 4. **Test Directory Management**
```rust
pub fn create_test_runtime_dir(test_name: &str) -> PathBuf
pub fn cleanup_test_runtime_dir(runtime_dir: &Path)
```

#### 5. **Skip Macros**
```rust
skip_if_no_bwrap!()
skip_if_ci!()
skip_if_binary_missing!($binary_path)
```

### Assertion Helper Functions (in unit tests)

```rust
fn validate_sender_count_before_clone<T>(collector: &StreamingResultCollector<T>) -> Result<usize, String>
fn validate_sender_count_after_clone<T>(collector: &StreamingResultCollector<T>, clone: &StreamingResultCollector<T>, expected_count: usize) -> Result<(), String>
fn validate_sender_count_stability<T>(collector: &StreamingResultCollector<T>, allowed_variation: usize) -> Result<(), String>
fn validate_comprehensive_sender_count<T>(...) -> Result<(), String>
```

## Pattern for Adding New Tests

### Step 1: Choose Test Type
- **Unit Test**: For testing individual functions/structs
- **Integration Test**: For testing CLI commands or cross-component interactions

### Step 2: Follow Naming Convention

**Unit Tests:**
```rust
fn test_<component>_<feature>_<scenario>()
```

Examples:
- `test_streaming_collector_sender_count_tracking`
- `test_streaming_collector_sender_count_stability_during_clone`

**Integration Tests:**
```rust
fn test_phase<phase_number>_<subsection>_<feature>()
```

Examples:
- `test_archive_format_structure`
- `test_migrate_dry_run`
- `test_uninstall_purge_requires_confirmation`

### Step 3: Use Standard Test Structure

```rust
/// Test <feature description>
///
/// This test verifies that:
/// - <expectation 1>
/// - <expectation 2>
/// - <expectation 3>
#[test]
fn test_<descriptive_name>() {
    // 1. SETUP: Create test environment
    let collector = StreamingResultCollector::<i32>::new();
    
    // 2. CAPTURE: Record initial state
    let count_before = collector.sender_count();
    
    // 3. VALIDATE: Check preconditions
    assert!(count_before > 0, "Precondition failed");
    
    // 4. EXECUTE: Perform operation
    let clone = collector.clone();
    
    // 5. VERIFY: Check postconditions
    let count_after = collector.sender_count();
    assert_eq!(count_after, count_before + 1, "Postcondition failed");
    
    // 6. CLEANUP: Ensure proper resource management
    drop(clone);
    assert_eq!(collector.sender_count(), 1, "Final state incorrect");
}
```

### Step 4: Add Comprehensive Documentation

```rust
/// Test sender_count stability during rapid sequential clone operations
///
/// This test verifies that sender_count remains stable and consistent
/// when multiple clone operations occur in quick succession, without
/// any intervening operations that could affect the count.
///
/// # Verification Points
/// 1. Initial count is 1 for newly created collector
/// 2. Count increases by exactly 1 after each clone
/// 3. No count decreases occur during cloning
/// 4. All instances (original + clones) see the same count
///
/// # Test Coverage
/// - Basic clone operations
/// - Count stability across multiple reads
/// - Cross-instance consistency
#[test]
fn test_streaming_collector_sender_count_rapid_sequential_clones() {
    // Implementation
}
```

### Step 5: Use Appropriate Assertion Level

**Basic Assertions:**
```rust
assert_eq!(expected, actual, "Message");
assert!(condition, "Message");
```

**Comprehensive Validations:**
```rust
validate_sender_count_before_clone(&collector)
    .expect("Validation should pass");
```

**Custom Validations:**
```rust
let result = some_operation();
if let Err(e) = result {
    panic!("Operation failed: {}", e);
}
```

## Test Categories by Phase

SIGIL organizes tests by implementation phase:

### Phase 1 Tests (Core Vault and CLI)
- `phase1_3_verification_test.rs` - Command parser and output scrubber
- `phase1_3_1_verification_test.rs` - Specific parser features
- `phase1_4_cli_docs_verification_test.rs` - CLI documentation
- `phase1_5_6_7_verification_test.rs` - Export/import, versioning, lifecycle
- `phase1_redteam_test.rs` - Security validation

### Phase 2 Tests (Daemon and IPC)
- `phase2_audit_ipc_signals_test.rs` - Audit logging and IPC
- `phase2_audit_lifecycle_test.rs` - Audit log lifecycle
- `phase2_client_audit_test.rs` - Client audit integration
- `phase2_ipc_protocol_test.rs` - IPC protocol validation
- `phase2_signal_handling_test.rs` - Signal processing
- `phase2_redteam_test.rs` - Adversarial validation

### Phase 3 Tests (Parser and Scrubber)
- `phase3_3_3_4_verification_test.rs` - Command parser and scrubber
- `phase3_3_cli_integration_test.rs` - CLI integration
- `phase3_redteam_test.rs` - Scrubber evasion testing

### Phase 4 Tests (Sandbox Execution)
- `phase4_1_4_2_sandbox_verification_test.rs` - Sandbox isolation
- `phase4_1_4_2_verification_test.rs` - Sandbox features
- `phase4_3_4_4_verification_test.rs` - macOS sandbox
- `phase4_5_4_6_verification_test.rs` - Full execution pipeline
- `phase4_redteam_test.rs` - Sandbox escape testing

### Phase 5 Tests (Agent Integration)
- `phase5_1_claude_code_hook_verification_test.rs` - Claude Code hooks
- `phase5_2_non_bash_tool_hooks_test.rs` - Non-Bash tool integration
- `phase5_3_5_4_verification_test.rs` - Shell wrapper and MCP
- `phase5_redteam_test.rs` - Agent bypass testing

### Phases 6-9 Tests
- Similar pattern for TUI, backends, breach detection, advanced features, and platform features

## Best Practices Summary

### 1. **Test Isolation**
- Each test should be independent
- Use `TempDir` for filesystem operations
- Clean up resources in `drop` implementations

### 2. **Clear Assertions**
- Use descriptive assertion messages
- Follow before/during/after pattern
- Validate preconditions and postconditions

### 3. **Comprehensive Coverage**
- Test both success and failure cases
- Include edge cases and boundary conditions
- Test error paths explicitly

### 4. **Documentation**
- Add doc comments explaining test purpose
- Document verification points
- Reference specific plan requirements

### 5. **Consistent Structure**
- Follow established patterns for test organization
- Use common utilities where appropriate
- Maintain naming conventions

### 6. **Async Testing**
- Use `#[tokio::test]` for async operations
- Handle timeouts appropriately
- Test both success and error cases

## Running Tests

### Run All Tests
```bash
cargo test
```

### Run Specific Test File
```bash
cargo test --test phase1_5_6_7_verification_test
```

### Run Specific Test
```bash
cargo test test_archive_format_structure
```

### Run Tests with Output
```bash
cargo test -- --nocapture
```

### Run Tests in Specific Crate
```bash
cargo test -p sigil-core
```

## Conclusion

SIGIL's test structure is well-organized with clear patterns for adding new tests. The combination of unit tests embedded in source files and integration tests in dedicated modules provides comprehensive coverage. The common utilities and assertion helpers make it easy to write consistent, maintainable tests.

When adding new tests, follow the established patterns:
1. Use descriptive test names
2. Follow the setup-execute-assert pattern
3. Add comprehensive documentation
4. Leverage common utilities
5. Test both success and failure cases

This structure ensures tests are maintainable, readable, and provide good coverage of SIGIL's functionality.