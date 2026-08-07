# Test Assertion Patterns and Naming Conventions

This document describes the test assertion patterns, naming conventions, and error message formats used throughout the SIGIL codebase. These patterns ensure consistency, maintainability, and clear failure messages across all test suites.

## Table of Contents

- [Overview](#overview)
- [Test Naming Conventions](#test-naming-conventions)
- [Assertion Pattern Categories](#assertion-pattern-categories)
- [Property-Based Testing Patterns](#property-based-testing-patterns)
- [Integration Test Patterns](#integration-test-patterns)
- [Custom Assertion Helpers](#custom-assertion-helpers)
- [Error Message Format Conventions](#error-message-format-conventions)
- [Phase Verification Test Patterns](#phase-verification-test-patterns)
- [Best Practices](#best-practices)

---

## Overview

SIGIL uses multiple testing approaches to ensure comprehensive coverage:

- **Property-based testing** with `proptest` for invariant verification
- **Integration testing** for end-to-end functionality
- **Unit testing** for individual components
- **Hardening testing** for security measures
- **Phase verification testing** tied to implementation plan checkpoints

All tests follow consistent naming conventions and assertion patterns to make the codebase maintainable and test failures easy to diagnose.

---

## Test Naming Conventions

### Standard Test Function Names

Tests use descriptive, verb-based names that clearly indicate what is being tested:

```rust
// Format: test_{component}_{aspect}_{condition}
fn test_shell_state_struct_fields() { }
fn test_blocked_env_vars() { }
fn test_socket_permissions() { }
```

### Property-Based Test Names

Property tests use the `prop_` prefix and describe the invariant being tested:

```rust
// Format: prop_{invariant_description}
proptest! {
    #[test]
    fn prop_scrubber_removes_secret(...) { }
    
    #[test]
    fn prop_parser_never_panics(...) { }
}
```

### Phase Verification Test Names

Tests tied to plan phases use explicit phase numbering:

```rust
// Format: test_{phase}_{subsection}_{requirement}
fn test_4_3_shell_state_tracking() { }
fn test_phase_4_3_4_4_seatbelt_implementation() { }
```

### Hardening Test Names

Security/hardening tests explicitly name the security measure:

```rust
fn test_pr_set_dumpable() { }
fn test_rlimit_core_zero() { }
fn test_mlockall_called() { }
```

### Custom Assertion Helper Names

Custom assertion helpers use the `assert_{condition}` pattern:

```rust
fn assert_dumpable_zero_in_code() { }
fn assert_socket_0600_in_code() { }
fn assert_keyring_usage_in_code() { }
```

---

## Assertion Pattern Categories

### 1. Basic Assertions

Standard Rust assertions are used for simple checks:

```rust
// Equality checks
assert_eq!(result, expected);
assert_eq!(store.len(), 1);

// Inequality checks  
assert_ne!(value, unexpected);

// Boolean conditions
assert!(condition);
assert!(result.is_ok());
assert!(!error_msg.contains("pipe"));
```

### 2. Conditional Assertions with Context

Assertions that provide additional context when they fail:

```rust
assert!(
    result.is_ok(),
    "Vault backend should be created from config: {}",
    result.unwrap_err()
);

assert_eq!(
    token.to_bytes().len(), 
    32, 
    "Session token must be 32 bytes"
);
```

### 3. Multi-Step Verification Patterns

Tests that verify multiple aspects of a condition:

```rust
// Verify all required fields exist
assert_eq!(state.cwd(), &PathBuf::from("."));
assert!(state.env_vars().is_empty());
assert!(state.options().is_empty());
assert!(state.last_exit_code().is_none());
```

### 4. Before/After State Validation

Tests that verify state changes:

```rust
// Before state
let store = secrets.inner().read().await;
assert!(store.is_empty());

// Action
secrets.insert("test/path".to_string(), b"test_value".to_vec()).await.unwrap();

// After state
let store = secrets.inner().read().await;
assert_eq!(store.len(), 1);
```

### 5. Error Handling Verification

Tests that verify proper error handling:

```rust
// Should fail
assert!(result.is_err());
assert!(!state.set_env("PATH".to_string(), "/malicious".to_string()));

// Should succeed  
assert!(result.is_ok());
assert!(state.set_env("MY_VAR".to_string(), "value".to_string()));
```

---

## Property-Based Testing Patterns

Property-based tests use `proptest` to verify invariants across a wide range of inputs.

### Property Test Structure

```rust
proptest! {
    #[test]
    fn prop_{invariant_name}(input in "{strategy}") {
        // Setup
        let mut system = System::new();
        
        // Action (using generated input)
        let result = system.process(&input);
        
        // Assert invariant holds
        prop_assert!(invariant_holds);
    }
}
```

### Common Property Patterns

#### 1. Round-Trip Properties

Verify that operations preserve data:

```rust
proptest! {
    #[test]
    fn prop_valid_secret_path_roundtrip(path in "[a-zA-Z0-9_./-]{1,100}") {
        let command = format!("echo {{{{secret:{}}}}}", path);
        let result = CommandParser::extract_placeholders(&command);
        
        if let Ok(placeholders) = result {
            if !placeholders.is_empty() {
                prop_assert_eq!(&placeholders[0].path, &path);
            }
        }
    }
}
```

#### 2. Never-Panic Properties

Verify robustness against arbitrary input:

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

#### 3. Idempotence Properties

Verify that repeated operations produce the same result:

```rust
proptest! {
    #[test]
    fn prop_scrubber_is_idempotent(...) {
        let scrubbed_once = scrubber.scrub(&output);
        let scrubbed_twice = scrubber.scrub(&scrubbed_once);
        
        prop_assert_eq!(scrubbed_once, scrubbed_twice);
    }
}
```

#### 4. Bounds-Checking Properties

Verify that values stay within expected ranges:

```rust
proptest! {
    #[test]
    fn prop_placeholder_positions_in_bounds(command in ".{0,1000}") {
        for placeholder in &placeholders {
            prop_assert!(placeholder.position.0 < command.len());
            prop_assert!(placeholder.position.1 <= command.len());
            prop_assert!(placeholder.position.0 < placeholder.position.1);
        }
    }
}
```

#### 5. Ordering Properties

Verify that operations maintain expected order:

```rust
proptest! {
    #[test]
    fn prop_placeholders_maintain_order(...) {
        if placeholders.len() >= 2 {
            prop_assert!(placeholders[0].position.0 < placeholders[1].position.0);
        }
    }
}
```

### Proptest Assertions

Property tests use special assertion macros:

```rust
// Property-specific assertions
prop_assert!(condition);
prop_assert_eq!(left, right);
prop_assert_ne!(left, right);
```

---

## Integration Test Patterns

Integration tests verify end-to-end functionality and often involve multiple components.

### Structure Pattern

```rust
//! Module documentation describing what is being tested

mod common;
use sigil_module::{Type, AnotherType};

// =============================================================================
// Section Header
// =============================================================================

/// Test description explaining what is being verified
#[test]
fn test_specific_functionality() {
    // Setup
    
    // Action
    
    // Verification
}
```

### Backend Integration Pattern

```rust
/// Test: Verify BackendFromConfig is implemented for all backends
///
/// This is a behavioral test that actually creates backend instances
/// from configuration, verifying that:
/// - All backend crates implement the BackendFromConfig trait
/// - Backends can be instantiated from BackendEntry configuration
/// - Configuration validation works correctly
#[test]
fn test_backend_from_config_implementations() {
    use sigil_core::backend::{BackendEntry, BackendFromConfig};
    
    // Create configuration
    let config = serde_json::json!({ /* ... */ });
    let entry = create_backend_entry("vault", "vault", config);
    
    // Test backend creation
    let result = VaultBackend::from_config(&entry);
    assert!(
        result.is_ok(),
        "Vault backend should be created from config: {}",
        result.unwrap_err()
    );
}
```

### Common Module Pattern

Tests often share common setup code through a `common` module:

```rust
mod common;

#[test]
fn test_with_common_setup() {
    // Use common setup utilities
    let daemon = common::setup_test_daemon().await;
    // ... test code
}
```

---

## Custom Assertion Helpers

Custom assertion helpers encapsulate complex verification logic and provide reusable test utilities.

### Code Verification Assertions

These helpers verify that specific code patterns exist in the codebase:

```rust
/// Helper: Verify PR_SET_DUMPABLE=0 in code
#[cfg(target_os = "linux")]
fn assert_dumpable_zero_in_code() {
    let memory_rs = std::fs::read_to_string(daemon_src_path().join("memory.rs"))
        .expect("Failed to read memory.rs");

    assert!(
        memory_rs.contains("PR_SET_DUMPABLE"),
        "memory.rs should contain PR_SET_DUMPABLE"
    );
    assert!(
        memory_rs.contains("libc::prctl(libc::PR_SET_DUMPABLE, 0"),
        "memory.rs should call prctl with PR_SET_DUMPABLE and 0"
    );
}
```

### Pattern for Code Verification

```rust
fn assert_{pattern}_in_code() {
    let source_file = std::fs::read_to_string(path).expect("Failed to read file");
    
    // Check for required patterns
    assert!(source_file.contains("PATTERN"), "Error message");
    
    // Check for specific implementations
    assert!(source_file.contains("specific_call"), "Error message");
}
```

### Generic Assertion Helpers

```rust
/// Helper: Verify sandbox provider is available
fn assert_sandbox_provider<T: SandboxProvider>(_: T) {
    // Type-level assertion that T implements SandboxProvider
}
```

---

## Error Message Format Conventions

### Assertion Error Messages

Error messages follow the pattern: `{what should happen}: {why it failed} {context}`

```rust
assert!(
    condition,
    "{expected outcome}: {actual outcome}",
    additional_context
);
```

### Examples of Error Messages

```rust
// Simple assertion with context
assert!(
    memory_rs.contains("PR_SET_DUMPABLE"),
    "memory.rs should contain PR_SET_DUMPABLE"
);

// Assertion with error details
assert!(
    result.is_ok(),
    "Vault backend should be created from config: {}",
    result.unwrap_err()
);

// Assertion with explanation
assert_eq!(
    token.to_bytes().len(),
    32,
    "Session token must be 32 bytes"
);
```

### Error Message Patterns

1. **Should contain**: "File should contain X"
2. **Should be**: "Value should be X"
3. **Expected**: "Expected X, got Y"
4. **Must**: "Value must X"

---

## Phase Verification Test Patterns

Tests that verify plan checkpoints use explicit phase references and comprehensive verification.

### Phase Test Structure

```rust
//! Phase X.Y: Feature Description Verification Tests
//!
//! These tests verify:
//! - Requirement 1
//! - Requirement 2
//! - Requirement 3

mod common;
use sigil_module::{Type1, Type2};

// =============================================================================
// Phase X.Y: Specific Feature Tests  
// =============================================================================

/// Test X.Y.1: Verify specific requirement
#[test]
fn test_{phase}_{subsection}_{requirement}() {
    // Verification code
}
```

### Comprehensive Verification Pattern

```rust
/// Comprehensive hardening verification
#[test]
fn test_all_hardening_measures_present() {
    // 1. PR_SET_DUMPABLE=0
    #[cfg(target_os = "linux")]
    assert_dumpable_zero_in_code();

    // 2. RLIMIT_CORE=0
    #[cfg(target_os = "linux")]
    assert_rlimit_core_zero_in_code();

    // 3. Socket 0600 permissions
    assert_socket_0600_in_code();

    // 4. Kernel keyring for session token
    #[cfg(target_os = "linux")]
    assert_keyring_usage_in_code();

    // 5. mlockall
    #[cfg(target_os = "linux")]
    test_mlockall_called();

    // 6. Startup sequence order
    test_startup_sequence_order();
}
```

---

## Best Practices

### 1. Test Documentation

Every test file should have module-level documentation:

```rust
//! Clear description of what this test module verifies
//!
//! These tests verify:
//! - Specific feature 1
//! - Specific feature 2
//! - Specific feature 3
```

### 2. Test Function Documentation

Test functions should include documentation explaining what is being tested:

```rust
/// Test: Clear description of what is being verified
///
/// This test verifies that:
/// - Condition 1 holds
/// - Condition 2 holds
/// - Condition 3 holds
#[test]
fn test_descriptive_name() {
    // Test code
}
```

### 3. Setup/Teardown

Use consistent patterns for test setup and teardown:

```rust
#[tokio::test]
async fn test_with_setup() {
    // Setup
    let system = setup_test_system().await;
    
    // Test
    let result = system.do_something().await;
    
    // Verification
    assert!(result.is_ok());
    
    // Teardown (implicit via Drop)
}
```

### 4. Platform-Specific Tests

Use conditional compilation for platform-specific tests:

```rust
#[test]
#[cfg(target_os = "linux")]
fn test_linux_specific() {
    // Linux-specific test code
}

#[test]
#[cfg(target_os = "macos")]
fn test_macos_specific() {
    // macOS-specific test code
}
```

### 5. Assertions vs. Expectations

- Use `assert!` for test-critical conditions
- Use `expect!` only in test code (never in production code per project conventions)

### 6. Error Messages

Always provide clear error messages with assertions:

```rust
// Good
assert_eq!(result, expected, "Result should equal expected");

// Less clear
assert_eq!(result, expected);
```

### 7. Property Test Strategies

Use appropriate proptest strategies for input generation:

```rust
// Alphanumeric paths
path in "[a-zA-Z0-9_./-]{1,100}"

// Commands (any character)
command in ".{0,1000}"

// Unicode strings
s in "\\PC{0,1000}"

// Special characters
special in "[!@#$%^&*()\\-_=+\\[\\]{}|;:'\",.<>?/`~]{0,20}"
```

### 8. Test Independence

Ensure tests are independent and can run in any order:

```rust
#[test]
fn test_first() {
    // Should not depend on test_second running first
    let state = create_fresh_state();
    // Test code
}
```

---

## Summary

SIGIL's test assertion patterns and naming conventions provide:

- **Consistency**: Uniform naming and structure across all test suites
- **Clarity**: Descriptive test names and error messages
- **Maintainability**: Reusable patterns and helpers
- **Comprehensiveness**: Multiple testing approaches for different scenarios
- **Clear Failures**: Detailed error messages for easy debugging

Following these patterns ensures that tests are easy to write, understand, and maintain throughout the SIGIL codebase.