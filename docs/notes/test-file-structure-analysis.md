# SIGIL Test File Structure Analysis

## Overview

SIGIL uses a comprehensive multi-level testing strategy with integration tests organized primarily in `crates/sigil-integration-tests/` and unit tests distributed across individual crates.

## Test Organization Structure

### Main Integration Test Suite
```
crates/sigil-integration-tests/
├── src/
│   ├── lib.rs                    # Shared utilities and test infrastructure
│   ├── binary_fixture.rs         # Test binary creation with specific permissions
│   ├── concurrent_tests.rs       # Concurrent testing infrastructure
│   ├── env_detect.rs            # Environment detection and skip macros
│   ├── socket_util.rs           # Socket availability and connection utilities
│   └── thread_util.rs          # Thread testing utilities
└── tests/
    ├── common.rs                # Common test utilities and helpers
    ├── phase1_*.rs             # Phase 1 verification tests
    ├── phase2_*.rs             # Phase 2 verification tests
    ├── phase3_*.rs             # Phase 3 verification tests
    ├── ... (phases 4-9)
    └── runtime_framework.rs    # Runtime testing framework
```

### Individual Crate Tests
Each crate has its own `tests/` directory:
```
crates/{crate-name}/tests/
├── {specific_tests}.rs
└── proptest_*.rs               # Property-based tests
```

## Test Module Patterns

### 1. Integration Test Modules

**Location:** `crates/sigil-integration-tests/tests/`

**Structure:**
```rust
//! Module documentation describing what phase/features are tested

mod common;
use common::{workspace_root, other_helpers};

/// Helper function to get binary paths
fn binary_path() -> PathBuf {
    workspace_root().join("target").join("debug").join("binary-name")
}

/// Test 1: Specific feature verification
///
/// This test verifies that:
/// - Feature A works correctly
/// - Feature B integrates properly
#[test] // or #[tokio::test] for async tests
fn test_specific_feature() {
    // Setup: Create test environment
    let temp_dir = TempDir::new().expect("Failed to create temp dir");
    
    // Exercise: Call the code being tested
    let result = function_under_test();
    
    // Verify: Check expected behavior
    assert!(result.is_ok(), "Should succeed");
}
```

**Key Characteristics:**
- Each test file corresponds to a specific phase or feature
- Tests use `mod common;` to import shared utilities
- Helper functions provide binary paths and environment setup
- Comprehensive doc comments explain what each test verifies
- Use of `#[tokio::test]` for async operations

### 2. Unit Test Modules

**Location:** Individual crate `tests/` directories or inline in `src/`

**Structure:**
```rust
//! Feature-specific test documentation

#[cfg(test)]
mod feature_tests {
    use super::*;
    
    #[test]
    fn test_unit_behavior() {
        let result = function_to_test();
        assert_eq!(result, expected);
    }
}
```

## Setup Patterns and Fixtures

### 1. Test Configuration
**Location:** `crates/sigil-integration-tests/src/lib.rs`

```rust
pub struct TestConfig {
    pub sigil_bin: PathBuf,
    pub sigild_bin: PathBuf,
    pub vault_dir: PathBuf,
    pub runtime_dir: PathBuf,
}

impl Default for TestConfig {
    fn default() -> Self {
        Self {
            sigil_bin: PathBuf::from("target/debug/sigil"),
            sigild_bin: PathBuf::from("target/debug/sigild"),
            // ...
        }
    }
}
```

### 2. Process Guards
**Location:** `crates/sigil-integration-tests/src/lib.rs`

```rust
pub struct DaemonGuard(std::process::Child);

impl DaemonGuard {
    pub fn new(child: std::process::Child) -> Self {
        Self(child)
    }
}

impl Drop for DaemonGuard {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}
```

### 3. Common Utilities
**Location:** `crates/sigil-integration-tests/tests/common.rs`

**Key utilities:**
- `workspace_root()` - Finds repository root
- `wait_for_socket_sync()` - Waits for daemon socket with timeout
- `daemon_health_check()` - Validates daemon is running correctly
- `create_test_runtime_dir()` - Creates isolated test environments
- Skip macros: `skip_if_no_bwrap!()`, `skip_if_ci!()`, etc.

### 4. Environment Detection
**Location:** `crates/sigil-integration-tests/src/env_detect.rs`

**Capabilities:**
- `detect_bwrap()` - Checks for bubblewrap availability
- `ensure_xdg_runtime_dir()` - Sets up runtime directory
- Skip conditions for different environments

## Test Naming Conventions

### Integration Tests
- `phase{N}_{feature}_verification_test.rs` - Phase-specific verification
- `phase{N}_redteam_test.rs` - Security/adversarial testing
- `{feature}_integration_test.rs` - Cross-feature integration tests
- `{feature}_security_test.rs` - Security-focused tests

### Unit Tests
- `proptest_{feature}.rs` - Property-based tests
- `{feature}_tests.rs` - Standard unit tests

## Test Documentation Patterns

### Comprehensive Doc Comments
```rust
/// Test 1: Verify specific feature behavior
///
/// This test verifies that:
/// - Requirement 1 is met
/// - Requirement 2 is met
/// - Edge case handling works correctly
///
/// # Example
/// The test simulates this scenario:
/// 1. Create test environment
/// 2. Execute operation
/// 3. Verify expected outcome
#[tokio::test]
async fn test_comprehensive_feature() {
    // Test implementation
}
```

## Async vs Sync Tests

### Async Tests (using tokio)
```rust
#[tokio::test]
async fn test_async_operation() {
    let result = async_function().await;
    assert!(result.is_ok());
}
```

### Sync Tests
```rust
#[test]
fn test_sync_operation() {
    let result = sync_function();
    assert!(result.is_ok());
}
```

## Common Test Scenarios

### 1. Daemon Startup Tests
- Create temporary directory structure
- Initialize vault with `sigil init`
- Start daemon with `sigild start`
- Verify socket creation and connectivity
- Use `DaemonGuard` for cleanup

### 2. CLI Operation Tests
- Execute CLI commands via `std::process::Command`
- Capture stdout/stderr for verification
- Check exit codes and output content

### 3. Vault Operation Tests
- Create temporary vault with `LocalVault::new()`
- Add/retrieve/delete secrets
- Verify encryption and file structure
- Test version history and rollback

### 4. Security Verification Tests
- Verify file permissions (0600 for files, 0700 for directories)
- Test memory protection (PR_SET_DUMPABLE, mlock)
- Validate socket permissions and access control
- Run red-team scenarios

## How to Add New Tests

### 1. Choose Test Location
- **Integration test:** Add to `crates/sigil-integration-tests/tests/`
- **Unit test:** Add to specific crate's `tests/` directory or inline in `src/`

### 2. Follow Naming Convention
- Use descriptive names following the pattern: `test_{what_is_being_tested}`
- For phase-specific tests: `phase{N}_{feature}_verification_test.rs`

### 3. Import Required Modules
```rust
mod common;
use common::{workspace_root, other_helpers};
```

### 4. Create Helper Functions
```rust
fn binary_path() -> PathBuf {
    workspace_root().join("target").join("debug").join("binary-name")
}
```

### 5. Write Test Function
```rust
#[tokio::test]
async fn test_new_feature() {
    // Setup
    let temp_dir = TempDir::new().expect("Failed to create temp dir");
    
    // Exercise
    let result = feature_under_test().await;
    
    // Verify
    assert!(result.is_ok(), "Feature should work correctly");
    
    // Cleanup is automatic via Drop traits
}
```

### 6. Add Comprehensive Documentation
```rust
/// Test new feature behavior
///
/// This test verifies that:
/// - Feature works correctly in normal conditions
/// - Edge cases are handled properly
/// - Error conditions return appropriate errors
#[tokio::test]
async fn test_new_feature() {
    // Implementation
}
```

## Property-Based Testing

SIGIL uses proptest for property-based testing:

```rust
proptest! {
    #[test]
    fn prop_never_panics(input in ".{0,1000}") {
        // Test that code never panics on any input
        let _ = function_under_test(input);
    }
}
```

## Test Skipping Mechanisms

For environment-dependent tests:

```rust
// Skip if bubblewrap not available
skip_if_no_bwrap!("This test requires bubblewrap");

// Skip if running in CI
skip_if_ci!("Interactive test not suitable for CI");

// Skip if binary missing
skip_if_binary_missing!(binary_path, "Build the binary first");
```

## Test Isolation and Cleanup

### Automatic Cleanup
- Use `TempDir` for temporary directories
- Use `DaemonGuard` for process cleanup
- Rely on Rust's RAII patterns via `Drop` trait

### Manual Cleanup
```rust
fn cleanup_test_env(config: &TestConfig) {
    let _ = fs::remove_dir_all(&config.vault_dir);
    let _ = fs::remove_dir_all(&config.runtime_dir);
}
```

## Summary

SIGIL's test structure follows these key principles:

1. **Organized by Phase/Feature** - Tests grouped by implementation phase
2. **Shared Infrastructure** - Common utilities in `src/lib.rs` and `tests/common.rs`
3. **Comprehensive Documentation** - Each test has clear doc comments
4. **Isolated Execution** - Each test uses temporary directories and cleanup guards
5. **Environment Awareness** - Tests can skip based on environment capabilities
6. **Async Support** - First-class support for async operations via tokio
7. **Property Testing** - Proptest for invariant verification across input space
8. **Security Focus** - Dedicated red-team and security verification tests

This structure ensures tests are maintainable, reliable, and provide comprehensive coverage of SIGIL's security-critical functionality.