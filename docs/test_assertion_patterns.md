# SIGIL Test Assertion Patterns

This document catalogs the existing test assertion patterns in the SIGIL codebase and serves as a reference for writing new tests that follow established conventions.

## Table of Contents
- [Overview](#overview)
- [Basic Assertion Patterns](#basic-assertion-patterns)
- [Error Message Format](#error-message-format)
- [Before/After Check Patterns](#beforeafter-check-patterns)
- [Consistency Assertions](#consistency-assertions)
- [Stability Verification](#stability-verification)
- [Monotonic Behavior Testing](#monotonic-behavior-testing)
- [Helper Functions](#helper-functions)
- [sender_count Specific Patterns](#sender_count-specific-patterns)
- [Test File Structure](#test-file-structure)
- [Async Testing Patterns](#async-testing-patterns)

## Overview

SIGIL tests follow a consistent assertion pattern that emphasizes:
- **Descriptive error messages** that explain what went wrong and why
- **Before/after verification** to validate state changes
- **Consistency checks** across related objects
- **Stability verification** to ensure values don't fluctuate unexpectedly
- **Monotonic behavior validation** for counters and sequences

## Basic Assertion Patterns

### Equality Checks

```rust
// Simple equality with context message
assert_eq!(actual_value, expected_value, "Context message: expected={}, got={}", expected_value, actual_value);

// Example from startup_modes.rs:47
assert_eq!(coordinator.socket_path, socket_path);
assert_eq!(coordinator.lockfile_path, lockfile_path);
```

### Boolean Checks

```rust
// Boolean assertions with descriptive context
assert!(condition, "Condition should be true: {}", context);
assert!(!should_be_false, "Value should be false: {}", should_be_false);

// Example from canary monitor tests
assert!(!monitor.is_active().await);
assert!(!monitor.has_breaches().await);
```

### Non-Zero/Non-Empty Checks

```rust
// Verify non-zero values
assert!(count > 0, "Count should be non-zero: got={}", count);

// Verify non-empty collections
assert!(!results.is_empty(), "Results should not be empty");
assert_eq!(results.len(), expected_count, "Expected {} results, got {}", expected_count, results.len());
```

## Error Message Format

SIGIL uses a consistent error message format that includes:
1. **What** should happen
2. **What** was expected
3. **What** was actually found
4. **Why** it matters (context)

```rust
// Format: "Description: expected={}, got={}, context={}"
assert_eq!(
    actual, expected,
    "Field name should match: expected={}, got={}, in context '{}'",
    expected, actual, context_description
);

// Example from sender_count assertions
assert!(
    count_after_clone >= count_before_clone,
    "sender_count should not decrease during clone operation: before={}, after={}",
    count_before_clone,
    count_after_clone
);
```

## Before/After Check Patterns

This is SIGIL's primary pattern for validating state changes:

### Pattern 1: Capture, Act, Verify

```rust
// 1. Capture initial state
let before = system.get_state();

// 2. Perform the operation being tested
system.perform_operation();

// 3. Verify state changed as expected
let after = system.get_state();
assert_eq!(after, expected_after, "State should change: before={}, after={}", before, after);
```

### Pattern 2: Clone State Verification

```rust
// Example from result_collector.rs
let count_before_clone = collector.sender_count();
assert_eq!(count_before_clone, 1, "Count should be 1 before clone");

let clone = collector.clone();
let count_after_clone = collector.sender_count();
assert_eq!(count_after_clone, 2, "Count should be 2 after clone");

// Verify monotonic behavior
assert!(count_after_clone >= count_before_clone, "Count should not decrease");
```

## Consistency Assertions

### Cross-Instance Consistency

When testing clones or related objects, verify they all report consistent values:

```rust
// Verify all instances see the same value
assert_eq!(
    original.sender_count(),
    clone.sender_count(),
    "Clone should see same count as original: expected={}, got={}",
    original.sender_count(),
    clone.sender_count()
);
```

### Multi-Verification Pattern

```rust
// Verify consistency across all collectors
for (idx, existing_clone) in clones.iter().enumerate() {
    assert_eq!(
        existing_clone.sender_count(),
        current_count,
        "Clone {} should see current count: expected={}, got={}",
        idx,
        current_count,
        existing_clone.sender_count()
    );
}
```

## Stability Verification

SIGIL tests verify that values remain stable when they shouldn't change:

### Immediate Stability Check

```rust
// Verify value remains stable immediately after an operation
let verify_stability = collector.sender_count();
assert_eq!(
    verify_stability, expected_value,
    "Value should remain stable immediately after operation: expected={}, got={}",
    expected_value, verify_stability
);
```

### Multiple Read Stability

```rust
// Verify stability across multiple consecutive reads
let count1 = collector.sender_count();
let count2 = collector.sender_count();
let count3 = collector.sender_count();

let max_count = count1.max(count2).max(count3);
let min_count = count1.min(count2).min(count3);
let variation = max_count - min_count;

assert!(
    variation <= threshold,
    "Value should remain stable: variation={} exceeds threshold={}, values=[{}, {}, {}]",
    variation, threshold, count1, count2, count3
);
```

## Monotonic Behavior Testing

For counters and sequences that should only increase:

### Simple Monotonic Check

```rust
assert!(
    after_value >= before_value,
    "Value should be monotonically non-decreasing: before={}, after={}",
    before_value, after_value
);
```

### Sequence Monotonic Verification

```rust
// Verify monotonic behavior across a sequence
for (i, window) in counts.windows(2).enumerate() {
    assert!(
        window[1] >= window[0],
        "Value decreased at position {}: from {} to {}",
        i + 1,
        window[0],
        window[1]
    );
}
```

### Increment Verification

```rust
// Verify count increased by exactly expected amount
assert_eq!(
    count_after,
    count_before + expected_increment,
    "Count should increment by {}: before={}, after={}",
    expected_increment,
    count_before,
    count_after
);
```

## Helper Functions

SIGIL uses helper functions to encapsulate common assertion patterns:

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

    // ... additional validations

    Ok(())
}
```

## sender_count Specific Patterns

The SIGIL codebase has extensive patterns for testing `sender_count` in `StreamingResultCollector`:

### Verification Point Pattern

Each clone operation includes multiple verification points:

```rust
fn clone(&self) -> Self {
    // === VERIFICATION POINT 1: Before any clone operations ===
    let count_before_clone = self.sender_count.load(std::sync::atomic::Ordering::Relaxed);

    // === VERIFICATION POINT 2: Increment sender count ===
    let count_after_increment = self.sender_count.fetch_add(1, std::sync::atomic::Ordering::Relaxed);

    debug_assert!(
        count_after_increment >= count_before_clone,
        "sender_count decreased during clone operation (after increment): before={}, after={}",
        count_before_clone,
        count_after_increment
    );

    // === VERIFICATION POINT 3: Verify stability before Arc::clone ===
    let count_before_arc_clone = self.sender_count.load(std::sync::atomic::Ordering::Relaxed);
    debug_assert!(/* ... */);

    // Continue with additional verification points...
}
```

### Test-Level sender_count Assertions

Tests for sender_count follow this pattern:

```rust
#[test]
fn test_streaming_collector_sender_count_after_single_clone() {
    let collector = StreamingResultCollector::<i32>::new();
    let initial_count = collector.sender_count();
    assert_eq!(initial_count, 1);

    // Capture count before clone to verify stability
    let count_before_clone = collector.sender_count();
    assert_eq!(count_before_clone, 1, "Count should be 1 before clone");

    // Clone once and verify sender_count increases
    let clone = collector.clone();
    let count_after_clone = collector.sender_count();
    assert_eq!(count_after_clone, 2, "Count should be 2 after clone");
    assert_eq!(clone.sender_count(), 2, "Clone should see count as 2");

    // Critical assertion: sender_count stays consistent after clone operation
    assert!(
        count_after_clone >= count_before_clone,
        "sender_count should not decrease during clone operation: before={}, after={}",
        count_before_clone,
        count_after_clone
    );

    // Verify count is stable immediately after clone (no fluctuations)
    let count_verify_stability = collector.sender_count();
    assert_eq!(
        count_verify_stability, 2,
        "sender_count should remain stable immediately after clone: expected=2, got={}",
        count_verify_stability
    );

    // Verify clone sees same count (consistency across all instances)
    assert_eq!(
        clone.sender_count(),
        2,
        "Clone should see consistent sender_count: expected=2, got={}",
        clone.sender_count()
    );

    // Verify monotonic increase
    assert!(
        count_after_clone > initial_count,
        "sender_count should increase monotonically after clone: initial={}, after={}",
        initial_count,
        count_after_clone
    );

    // Verify both collectors work correctly
    let _ = collector.stream_add(42).unwrap();
    let _ = clone.stream_add(24).unwrap();

    let mut results = collector.stream_collect_blocking();
    results.sort();
    assert_eq!(results, vec![24, 42]);
}
```

### Where to Add sender_count Assertions

Based on the git history and existing patterns, sender_count assertions should be added in:

1. **`crates/sigil-core/src/thread_utils/result_collector.rs`**
   - Primary location for sender_count test assertions
   - Tests are in the `#[cfg(test)]` module at the end of the file
   - Look for existing test functions starting with `test_streaming_collector_sender_count_`

2. **Specific test functions where assertions are needed:**
   - `test_streaming_collector_sender_count_after_single_clone` - Basic clone behavior
   - `test_streaming_collector_sender_count_stability_during_clone` - Stability verification
   - `test_streaming_collector_sender_count_tracking` - General tracking behavior
   - `test_streaming_collector_sender_count_decreases_to_zero` - Drop behavior
   - Any new tests that verify sender_count consistency

3. **Helper module location:**
   - `crates/sigil-core/src/thread_utils/result_collector_sender_count_assertions.rs`
   - Contains reusable assertion helper functions
   - Follows the pattern established in existing code

## Test File Structure

### Module-Level Tests

Tests are typically in a `#[cfg(test)]` module at the end of the file:

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_basic_functionality() {
        // Test code here
    }

    #[tokio::test]
    async fn test_async_functionality() {
        // Async test code here
    }
}
```

### Integration Test Files

Integration tests are in separate `tests/` directories:

```rust
// crates/sigil-daemon/tests/startup_modes.rs
#[test]
fn test_ondemand_lockfile_coordination() {
    let (_temp_dir, socket_path, lockfile_path) = setup_test_dirs();

    let coordinator = sigil_daemon::ondemand::OnDemandCoordinator::new(&socket_path, None).unwrap();

    assert_eq!(coordinator.socket_path, socket_path);
    assert_eq!(coordinator.lockfile_path, lockfile_path);
}
```

## Async Testing Patterns

### Basic Async Test

```rust
#[tokio::test]
async fn test_async_operation() {
    let result = async_function().await.unwrap();
    assert_eq!(result, expected_value);
}
```

### Async Assertion Patterns

```rust
#[tokio::test]
async fn test_canary_monitor_creation() {
    let overlay = tempfile::tempdir().unwrap();
    let monitor = CanaryMonitor::new(overlay.path().to_path_buf());

    assert!(!monitor.is_active().await);
    assert!(!monitor.has_breaches().await);
}
```

## Naming Conventions

### Test Function Names

- **Unit tests**: `test_<functionality>` or `test_<component>_<behavior>`
  - `test_canary_monitor_creation`
  - `test_ondemand_lockfile_coordination`

- **Sender count tests**: `test_streaming_collector_sender_count_<specific_behavior>`
  - `test_streaming_collector_sender_count_after_single_clone`
  - `test_streaming_collector_sender_count_stability_during_clone`

### Assertion Messages

- Use present tense: "should" not "shall"
- Include relevant values: "expected=X, got=Y"
- Provide context: what was being tested, why it matters

```rust
// Good
assert_eq!(actual, expected, "Field name should match: expected={}, got={}", expected, actual);

// Less good
assert_eq!(actual, expected); // No context on failure
```

## Summary

SIGIL's test assertion patterns emphasize:
1. **Descriptive error messages** that include expected and actual values
2. **Before/after verification** for state changes
3. **Consistency checks** across related objects
4. **Stability verification** for values that shouldn't change
5. **Monotonic behavior validation** for counters and sequences
6. **Helper functions** for common assertion patterns

For sender_count specifically:
- Tests are in `crates/sigil-core/src/thread_utils/result_collector.rs`
- Follow existing test naming: `test_streaming_collector_sender_count_<behavior>`
- Use the comprehensive assertion patterns in existing tests
- Helper functions are available in `result_collector_sender_count_assertions.rs`

When adding new sender_count assertions:
1. Follow the before/after pattern
2. Include descriptive error messages with values
3. Verify stability and consistency
4. Check monotonic behavior
5. Use helper functions where appropriate
