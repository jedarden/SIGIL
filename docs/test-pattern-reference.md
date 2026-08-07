# SIGIL Test Pattern Reference

Comprehensive reference documentation for test assertion patterns used throughout the SIGIL codebase.

## Table of Contents

- [Overview](#overview)
- [Quick Reference Guide](#quick-reference-guide)
- [Basic Assertion Patterns](#basic-assertion-patterns)
- [Structured Assertion Patterns](#structured-assertion-patterns)
- [State Change Verification](#state-change-verification)
- [Property-Based Testing](#property-based-testing)
- [Custom Assertion Helpers](#custom-assertion-helpers)
- [Test Organization](#test-organization)
- [Naming Conventions](#naming-conventions)
- [Error Message Standards](#error-message-standards)
- [Specialized Testing Patterns](#specialized-testing-patterns)
- [Integration Testing Framework](#integration-testing-framework)
- [Security Testing Patterns](#security-testing-patterns)
- [Best Practices](#best-practices)

---

## Overview

SIGIL employs multiple testing approaches to ensure comprehensive coverage:

- **Unit testing** within modules via `#[cfg(test)]`
- **Property-based testing** with `proptest`
- **Integration testing** for cross-component functionality
- **Security hardening testing** for attack surface validation
- **Phase verification testing** tied to implementation plan checkpoints

All tests follow consistent naming conventions, assertion patterns, and error message formats to maintain code quality and enable easy debugging.

### Design Principles

1. **Descriptive Failures**: Every assertion includes clear context about what went wrong
2. **State Verification**: Before/after patterns validate expected changes
3. **Consistency Checking**: Cross-instance verification for clones and related objects
4. **Stability Assurance**: Values remain stable when they shouldn't change
5. **Monotonic Validation**: Counters and sequences follow expected ordering

---

## Quick Reference Guide

### Most Common Patterns

```rust
// 1. Basic equality with context
assert_eq!(actual, expected, "Context: expected={}, got={}", expected, actual);

// 2. Boolean condition with message
assert!(condition, "Condition should be true: context={}", context);

// 3. Before/after state change
let before = system.get_state();
system.perform_operation();
let after = system.get_state();
assert!(after > before, "Value should increase: before={}, after={}", before, after);

// 4. Consistency across instances
assert_eq!(original.value(), clone.value(), "Instances should match");

// 5. Stability verification
let val1 = system.value();
let val2 = system.value();
assert_eq!(val1, val2, "Value should remain stable");
```

### Key Locations

- **Unit tests**: `#[cfg(test)]` modules within source files
- **Integration tests**: `crates/sigil-integration-tests/tests/`
- **Security tests**: `crates/sigil-daemon/tests/hardening_test.rs`
- **Property tests**: `crates/sigil-core/tests/proptest_*.rs`
- **sender_count tests**: `crates/sigil-core/src/thread_utils/result_collector.rs`

---

## Basic Assertion Patterns

### Equality Assertions

**Pattern**: `assert_eq!(left, right, message)`

```rust
// Simple equality
assert_eq!(result, expected);

// With context message
assert_eq!(
    collector.sender_count(), 
    2, 
    "New collector should have count of 2"
);

// Multiple field verification
assert_eq!(coordinator.socket_path, socket_path);
assert_eq!(coordinator.lockfile_path, lockfile_path);
```

### Conditional Assertions

**Pattern**: `assert!(condition, message)`

```rust
// Basic boolean assertion
assert!(result.is_ok());

// Negated condition
assert!(!collector.is_empty());

// With detailed message
assert!(
    memory_rs.contains("PR_SET_DUMPABLE"),
    "memory.rs should contain PR_SET_DUMPABLE"
);
```

### Non-Zero/Non-Empty Checks

```rust
// Non-zero verification
assert!(count > 0, "Count should be non-zero: got={}", count);

// Non-empty collection
assert!(!results.is_empty(), "Results should not be empty");

// Collection size verification
assert_eq!(
    results.len(), 
    expected_count, 
    "Expected {} results, got {}", 
    expected_count, 
    results.len()
);
```

---

## Structured Assertion Patterns

### Multi-Part Assertions

```rust
assert!(
    count_after_clone >= count_before_clone,
    "sender_count should not decrease during clone operation: before={}, after={}",
    count_before_clone,
    count_after_clone
);
```

**Structure**:
1. **What should happen**: Clear expectation description
2. **What was wrong**: Actual values that caused failure
3. **Context**: Enough information to debug without re-running

### Comprehensive Verification Pattern

```rust
// Verify multiple aspects of a condition
assert_eq!(state.cwd(), &PathBuf::from("."));
assert!(state.env_vars().is_empty());
assert!(state.options().is_empty());
assert!(state.last_exit_code().is_none());
```

### Error Handling Verification

```rust
// Should fail
assert!(result.is_err());
assert!(!state.set_env("PATH".to_string(), "/malicious".to_string()));

// Should succeed  
assert!(result.is_ok());
assert!(state.set_env("MY_VAR".to_string(), "value".to_string()));
```

---

## State Change Verification

### Before/After Pattern

**Primary pattern for validating state changes:**

```rust
// 1. Capture initial state
let before = system.get_state();

// 2. Perform the operation being tested
system.perform_operation();

// 3. Verify state changed as expected
let after = system.get_state();
assert_eq!(
    after, 
    expected_after, 
    "State should change: before={}, after={}", 
    before, 
    after
);
```

### Clone State Verification Pattern

```rust
let count_before_clone = collector.sender_count();
assert_eq!(count_before_clone, 1, "Count should be 1 before clone");

let clone = collector.clone();
let count_after_clone = collector.sender_count();
assert_eq!(count_after_clone, 2, "Count should be 2 after clone");

// Verify monotonic behavior
assert!(
    count_after_clone >= count_before_clone,
    "Count should not decrease: before={}, after={}",
    count_before_clone,
    count_after_clone
);
```

### Lifecycle Testing Pattern

```rust
// Setup
let collector = StreamingResultCollector::<i32>::new();
let clone1 = collector.clone();
let clone2 = collector.clone();

// Verify initial state
assert_eq!(collector.sender_count(), 3);

// Verify cleanup
drop(clone1);
assert_eq!(collector.sender_count(), 2);

drop(clone2);
assert_eq!(collector.sender_count(), 1);
```

---

## Property-Based Testing

SIGIL uses `proptest` for invariant verification across generated inputs.

### Basic Property Test Structure

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

#### Round-Trip Properties

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

#### Never-Panic Properties

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

#### Idempotence Properties

```rust
proptest! {
    #[test]
    fn prop_scrubber_is_idempotent(output in ".{0,10000}") {
        let scrubber = Scrubber::new();
        let scrubbed_once = scrubber.scrub(&output);
        let scrubbed_twice = scrubber.scrub(&scrubbed_once);
        
        prop_assert_eq!(scrubbed_once, scrubbed_twice);
    }
}
```

### Proptest Strategy Examples

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

---

## Custom Assertion Helpers

SIGIL uses custom validation functions to encapsulate complex assertion patterns.

### Validation Helper Pattern

```rust
pub fn validate_sender_count_after_clone<T>(
    collector: &StreamingResultCollector<T>,
    clone: &StreamingResultCollector<T>,
    expected_count: usize,
) -> Result<(), String>
where
    T: Send + 'static,
{
    let original_count = collector.sender_count();
    if original_count != expected_count {
        return Err(format!(
            "Original collector sender_count mismatch: expected={}, got={}",
            expected_count, original_count
        ));
    }

    let cloned_count = clone.sender_count();
    if cloned_count != expected_count {
        return Err(format!(
            "Cloned collector sender_count mismatch: expected={}, got={}",
            expected_count, cloned_count
        ));
    }

    if original_count != cloned_count {
        return Err(format!(
            "sender_count consistency check failed: original={}, cloned={}",
            original_count, cloned_count
        ));
    }

    Ok(())
}
```

### Comprehensive Validation Pattern

```rust
pub fn validate_comprehensive_sender_count<T>(
    collector: &StreamingResultCollector<T>,
    clone: &StreamingResultCollector<T>,
    pre_clone_count: usize,
    expected_post_clone_count: usize,
) -> Result<(), String>
where
    T: Send + 'static,
{
    // Validation 1: Pre-clone baseline
    if pre_clone_count == 0 {
        return Err("Pre-clone sender_count is zero, invalid baseline".to_string());
    }

    // Validation 2: Post-clone consistency
    validate_sender_count_after_clone(collector, clone, expected_post_clone_count)
        .map_err(|e| format!("Post-clone validation failed: {}", e))?;

    // Validation 3: Verify count increased
    let actual_post_count = collector.sender_count();
    if actual_post_count <= pre_clone_count {
        return Err(format!(
            "sender_count did not increase after clone: pre_clone={}, post_clone={}",
            pre_clone_count, actual_post_count
        ));
    }

    // Additional validations...
    Ok(())
}
```

### Available Helper Functions

**Location**: `crates/sigil-core/src/thread_utils/result_collector_sender_count_assertions.rs`

1. **`validate_sender_count_after_clone`**: Validates consistency after clone operation
2. **`validate_monotonic_sender_count`**: Ensures count never decreases
3. **`validate_sender_count_stability`**: Verifies count remains stable across reads
4. **`validate_comprehensive_sender_count`**: Combines all validation patterns

---

## Test Organization

### Module-Level Tests

```rust
#[cfg(test)]
mod tests {
    use super::*;

    // Basic functionality
    #[test]
    fn test_basic_functionality() { }
    
    // Lifecycle tests
    #[test]
    fn test_lifecycle_behavior() { }
    
    // Error handling
    #[test]
    fn test_error_handling() { }
    
    // Concurrent behavior
    #[test]
    fn test_concurrent_access() { }
}
```

### Integration Test Files

```rust
// crates/sigil-integration-tests/tests/backend_integration_test.rs

#[test]
fn test_backend_from_config_implementations() {
    let vault_result = sigil_backend_vault::VaultBackend::from_config(&vault_entry);
    assert!(
        vault_result.is_ok(),
        "Vault backend should be created from config: {}",
        vault_result.unwrap_err()
    );
}
```

### Test File Locations

```
/home/coding/SIGIL/
├── crates/
│   ├── sigil-integration-tests/tests/
│   │   ├── phase{N}_{subphase}_*.rs              # Phase-based integration tests
│   │   ├── backend_integration_test.rs           # Backend integration tests
│   │   └── *_verification_test.rs                # Verification tests
│   ├── sigil-daemon/tests/
│   │   └── hardening_test.rs                     # Security hardening tests
│   ├── sigil-backend-{backend}/tests/            # Backend-specific tests
│   │   └── {backend}_backend_tests.rs
│   └── */src/
│       └── #[cfg(test)] modules                  # Unit tests embedded in source
```

---

## Naming Conventions

### Test Function Names

**Pattern**: `test_{component}_{scenario}_{expected}`

**Examples**:
- `test_streaming_collector_new` - Basic creation
- `test_streaming_collector_clone_independently` - Clone independence
- `test_streaming_collector_sender_count_tracking` - sender_count behavior
- `test_pr_set_dumpable` - Security measure verification
- `test_4_3_shell_state_tracking` - Phase-based test

### Property-Based Test Names

**Pattern**: `prop_{invariant_description}`

```rust
proptest! {
    #[test]
    fn prop_scrubber_removes_secret(...) { }
    
    #[test]
    fn prop_parser_never_panics(...) { }
}
```

### Helper Function Names

**Pattern**: `{verb}_{noun}_for_{purpose}` or `validate_{aspect}`

**Examples**:
- `validate_sender_count_after_clone()`
- `validate_monotonic_sender_count()`
- `assert_dumpable_zero_in_code()`
- `setup_test_daemon()`

### Variable Names in Tests

**Pattern**: `{entity}_{state}` or `{entity}_{description}`

**Examples**:
- `count_before_clone`
- `count_after_clone`
- `collector_clone`
- `original_count`
- `cloned_count`

---

## Error Message Standards

### Format Structure

```
"{what_should_happen}: {context}={value}"
```

### Examples

**Good messages**:
```rust
"sender_count should not decrease during clone operation: before={}, after={}"
"Count should be 2 after first clone"
"Vault backend should be created from config: {}"
"Session token must be 32 bytes"
```

**Poor messages**:
```rust
"failed"                 // No context
"wrong count"            // What was wrong?
"assertion failed"       // Which assertion?
```

### Message Guidelines

1. **Be Specific**: Describe exactly what should happen
2. **Include Context**: Show relevant values when they help debugging
3. **Avoid Ambiguity**: Use clear language
4. **Maintain Consistency**: Use similar phrasing for similar checks
5. **Provide Values**: Include actual vs expected values

### Error Message Templates

```rust
// Equality checks
"{} should match: expected={}, got={}", field_name, expected, actual

// State changes
"{} should increase: before={}, after={}", field_name, before, after

// Consistency checks
"{} should be consistent across instances: expected={}, got={}", 
    description, expected, actual

// Stability checks
"{} should remain stable: expected={}, got={}", field_name, expected, actual
```

---

## Specialized Testing Patterns

### sender_count Specific Patterns

**Primary Location**: `crates/sigil-core/src/thread_utils/result_collector.rs`

#### Basic sender_count Test Pattern

```rust
#[test]
fn test_streaming_collector_sender_count_after_single_clone() {
    let collector = StreamingResultCollector::<i32>::new();
    let initial_count = collector.sender_count();
    assert_eq!(initial_count, 1);

    let count_before_clone = collector.sender_count();
    assert_eq!(count_before_clone, 1, "Count should be 1 before clone");

    let clone = collector.clone();
    let count_after_clone = collector.sender_count();
    assert_eq!(count_after_clone, 2, "Count should be 2 after clone");
    assert_eq!(clone.sender_count(), 2, "Clone should see count as 2");

    // Critical assertion: sender_count stays consistent
    assert!(
        count_after_clone >= count_before_clone,
        "sender_count should not decrease during clone operation: before={}, after={}",
        count_before_clone,
        count_after_clone
    );
}
```

#### Lifecycle Testing Pattern

```rust
#[test]
fn test_streaming_collector_sender_count_decreases_to_zero() {
    let collector = StreamingResultCollector::<i32>::new();
    let clone1 = collector.clone();
    let clone2 = collector.clone();
    
    assert_eq!(collector.sender_count(), 3);

    drop(clone1);
    assert_eq!(collector.sender_count(), 2);

    drop(clone2);
    assert_eq!(collector.sender_count(), 1);
}
```

#### Consistency Verification Pattern

```rust
#[test]
fn test_streaming_collector_sender_count_consistency() {
    let collector = StreamingResultCollector::<i32>::new();
    let count_before_clone = collector.sender_count();
    
    let clone = collector.clone();
    let count_after_clone = collector.sender_count();
    
    assert_eq!(count_after_clone, 2, "Count should be 2 after clone");
    assert_eq!(clone.sender_count(), 2, "Clone should see count as 2");

    assert!(
        count_after_clone >= count_before_clone,
        "sender_count should not decrease during clone operation: before={}, after={}",
        count_before_clone,
        count_after_clone
    );
}
```

### Where to Add sender_count Assertions

#### Primary Location
**File**: `crates/sigil-core/src/thread_utils/result_collector.rs`
**Module**: `#[cfg(test)]` test module within the file

#### Supporting File
**File**: `crates/sigil-core/src/thread_utils/result_collector_sender_count_assertions.rs`
**Module**: `#[cfg(test)] mod sender_count_assertions`
**Purpose**: Reusable validation functions for sender_count operations

#### Integration Points
1. **Clone Operations**: Verify count increments correctly
2. **Drop Operations**: Verify count decrements appropriately
3. **Concurrent Access**: Verify count remains consistent under thread stress
4. **Error Recovery**: Verify count remains valid after error conditions
5. **Lifecycle Operations**: Verify count reaches zero when all instances dropped

---

## Integration Testing Framework

### Test Configuration Structure

```rust
pub struct TestConfig {
    pub sigil_bin: PathBuf,
    pub sigild_bin: PathBuf,
    pub vault_dir: PathBuf,
    pub runtime_dir: PathBuf,
}

impl Default for TestConfig {
    fn default() -> Self {
        TestConfig {
            sigil_bin: find_binary("sigil"),
            sigild_bin: find_binary("sigild"),
            vault_dir: TempDir::new().unwrap().into_path(),
            runtime_dir: TempDir::new().unwrap().into_path(),
        }
    }
}
```

### Environment Setup

```rust
pub fn setup_test_env() -> TestConfig {
    let config = TestConfig::default();
    
    // Ensure clean environment
    std::env::set_var("SIGIL_TEST", "1");
    std::env::set_var("SIGIL_VAULT_PATH", config.vault_dir.to_string_lossy().as_ref());
    
    config
}
```

### RAII Guards for Resource Management

```rust
pub struct DaemonGuard(std::process::Child);

impl Drop for DaemonGuard {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

// Usage
#[test]
fn test_with_daemon_cleanup() {
    let config = setup_test_env();
    let daemon = start_sigild(&config).expect("Failed to start daemon");
    let _guard = DaemonGuard(daemon);  // Auto-cleanup on drop
    
    // Test implementation - daemon cleaned up automatically
}
```

---

## Security Testing Patterns

### Code Verification Assertions

```rust
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

### Binary Fixture Creation for Security Testing

```rust
pub fn create_setuid_fixture(name: &str, content: &[u8]) -> Result<PathBuf> {
    let bin_path = test_bin_dir().join(name);
    fs::write(&bin_path, content)?;
    
    // Set permissions including setuid bit
    let mut perms = fs::metadata(&bin_path)?.permissions();
    perms.set_mode(0o4755);  // setuid + executable
    fs::set_permissions(&bin_path, perms)?;
    
    Ok(bin_path)
}
```

### Memory Security Testing

```rust
#[test]
fn test_memory_clearing() {
    let mut buf = b"sensitive_data".to_vec();
    secure_clear(&mut buf);
    
    assert!(
        buf.iter().all(|&b| b == 0),
        "Memory should be zeroed after secure_clear"
    );
}

#[test]
fn test_secret_value_zeroize() {
    let secret = SecretValue::new(b"secret_data".to_vec());
    drop(secret);
    // Value is zeroized on drop - verification through memory inspection
}
```

---

## Best Practices

### DO ✅

- Use `assert_eq!` for value comparisons
- Include descriptive messages in assertions
- Follow before/after pattern for state changes
- Use custom validation functions for complex checks
- Name tests descriptively: `test_{what}_{scenario}_{expected}`
- Verify both success and failure paths
- Test edge cases (empty collections, single items, limits)
- Include security-specific tests for sensitive operations
- Document test purposes with comments

### DON'T ❌

- Use vague assertion messages like "failed" or "error"
- Skip testing cleanup/lifecycle behavior
- Assume thread safety without concurrent tests
- Forget to document security assumptions
- Mix multiple assertions in one test without clear separation
- Use `unwrap()` or `expect()` in non-test production code
- Test internal implementation details unnecessarily
- Write brittle tests that break with refactoring

### Test Documentation

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

### Platform-Specific Tests

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

---

## Summary

SIGIL's test assertion patterns provide:

- **Consistency**: Uniform naming and structure across all test suites
- **Clarity**: Descriptive test names and error messages
- **Maintainability**: Reusable patterns and helpers
- **Comprehensiveness**: Multiple testing approaches for different scenarios
- **Clear Failures**: Detailed error messages for easy debugging

Following these patterns ensures that tests are easy to write, understand, and maintain throughout the SIGIL codebase.

### Key Files Reference

- **Basic patterns**: This document
- **Implementation examples**: `crates/sigil-core/src/thread_utils/result_collector.rs`
- **Helper functions**: `crates/sigil-core/src/thread_utils/result_collector_sender_count_assertions.rs`
- **Integration tests**: `crates/sigil-integration-tests/tests/`
- **Security tests**: `crates/sigil-daemon/tests/hardening_test.rs`
- **Test utilities**: `crates/sigil-integration-tests/src/lib.rs`

### Quick Reference Card

```rust
// Basic assertions
assert_eq!(actual, expected, "message");
assert!(condition, "message");

// Before/after pattern
let before = state();
action();
assert!(state() > before, "message");

// Consistency check
assert_eq!(original.value(), clone.value(), "message");

// Helper usage
validate_helper(&obj, &clone, expected).expect("message");

// Test structure
#[test]
fn test_component_scenario_expected() {
    // Setup
    // Action
    // Verify
}
```
