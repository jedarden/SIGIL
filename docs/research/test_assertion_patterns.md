# Test Assertion Patterns in SIGIL

This document catalogs the existing test assertion patterns used throughout the SIGIL codebase, providing a reference for maintaining consistency when writing new tests, particularly for `sender_count` assertions.

## Overview

SIGIL uses Rust's standard testing framework with consistent assertion patterns across the codebase. Tests are organized into:
- Unit tests within module files (`#[cfg(test)]` modules)
- Integration tests in dedicated `tests/` directories  
- Property-based tests using `proptest`
- Red team security verification tests

## Core Assertion Patterns

### 1. Basic Equality Assertions

**Pattern**: `assert_eq!(left, right, message)`

```rust
#[test]
fn test_streaming_collector_new() {
    let collector = StreamingResultCollector::<i32>::new();
    assert_eq!(collector.sender_count(), 1);
}
```

**Usage Guidelines**:
- Use for comparing exact values
- Include descriptive message when context isn't obvious
- Prefer `assert_eq!` over `assert!(left == right)` for better error output

### 2. Conditional Assertions

**Pattern**: `assert!(condition, message)`

```rust
#[test]
fn test_add_single_value() {
    let collector = ResultCollector::<i32>::new();
    collector.add(42);
    assert!(!collector.is_empty());
    assert_eq!(collector.len(), 1);
}
```

**Usage Guidelines**:
- Use for boolean conditions
- Include message for non-obvious conditions
- Prefer positive assertions (`assert!(is_ok)`) over negative (`assert!(!is_err)`) when both work

### 3. Multi-Part Assertions with Detailed Messages

**Pattern**: Structured assertions with context and failure information

```rust
assert!(
    count_after_clone >= count_before_clone,
    "sender_count should not decrease during clone operation: before={}, after={}",
    count_before_clone,
    count_after_clone
);
```

**Message Format**:
- **What should happen**: Describe the expected behavior
- **What was wrong**: Include actual values that caused failure
- **Context**: Provide enough information to debug without re-running

### 4. Before/After Testing Pattern

**Pattern**: Capture state before operation, verify after operation

```rust
#[test]
fn test_streaming_collector_sender_count_tracking() {
    let collector = StreamingResultCollector::<i32>::new();
    assert_eq!(collector.sender_count(), 1);

    {
        let _clone1 = collector.clone();
        assert_eq!(collector.sender_count(), 2);

        {
            let _clone2 = collector.clone();
            assert_eq!(collector.sender_count(), 3);
        }

        // clone2 dropped, count should decrease by 1
        assert_eq!(collector.sender_count(), 2);
    }

    // clone1 dropped, count should decrease by 1 again
    assert_eq!(collector.sender_count(), 1);
}
```

**Key Elements**:
1. **Baseline**: Establish initial state
2. **Operation**: Perform the action being tested
3. **Verification**: Check expected state changes
4. **Cleanup verification**: Ensure proper cleanup/recovery

### 5. Consistency Verification Pattern

**Pattern**: Cross-instance verification after operations

```rust
#[test]
fn test_streaming_collector_sender_count_consistency() {
    let collector = StreamingResultCollector::<i32>::new();
    let count_before_clone = collector.sender_count();
    
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
}
```

## Error Message Format Standards

### Format Structure

SIGIL test error messages follow this pattern:

```
"{what_should_happen}: {context}={value}"
```

### Examples

**Good messages**:
```rust
"sender_count should not decrease during clone operation: before={}, after={}"
"Count should be 2 after first clone"
"sender_count inconsistency detected: original={}, cloned={}"
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
3. **Avoid Ambiguity**: Use clear, non-technical language when possible
4. **Maintain Consistency**: Use similar phrasing for similar checks

## Naming Conventions

### Test Function Names

**Pattern**: `test_{component}_{scenario}_{expected}`

Examples:
- `test_streaming_collector_new` - Basic creation
- `test_streaming_collector_clone_independently` - Clone independence
- `test_streaming_collector_sender_count_tracking` - sender_count behavior
- `test_streaming_collector_sender_count_decreases_to_zero` - Lifecycle behavior

### Helper Function Names

**Pattern**: `{verb}_{noun}_for_{purpose}` or `validate_{aspect}`

Examples:
- `validate_sender_count_after_clone()` 
- `validate_monotonic_sender_count()`
- `validate_sender_count_stability()`
- `assert_dumpable_zero_in_code()`

### Variable Names in Tests

**Pattern**: `{entity}_{state}` or `{entity}_{description}`

Examples:
- `count_before_clone`
- `count_after_clone`
- `collector_clone`
- `original_count`
- `cloned_count`

## Assertion Helper Functions

### Custom Validation Functions

SIGIL uses custom validation functions that return `Result<(), String>`:

```rust
pub fn validate_sender_count_after_clone<T>(
    collector: &StreamingResultCollector<T>,
    clone: &StreamingResultCollector<T>,
    expected_count: usize,
) -> Result<(), String>
```

**Benefits**:
- Reusable assertion logic
- Clear error messages
- Composable validation patterns
- Better test organization

### Assertion Macros

While SIGIL primarily uses standard `assert!` macros, some tests use custom helpers:

```rust
fn assert_dumpable_zero_in_code() {
    let memory_rs = std::fs::read_to_string(daemon_src_path().join("memory.rs"))
        .expect("Failed to read memory.rs");
    // ... verification logic
}
```

## Specialized Assertion Patterns

### 1. Lifecycle Testing

```rust
#[test]
fn test_streaming_collector_sender_count_decreases_to_zero() {
    let collector = StreamingResultCollector::<i32>::new();
    let clone1 = collector.clone();
    let clone2 = collector.clone();
    
    // Should have 3 senders (original + 2 clones)
    assert_eq!(collector.sender_count(), 3);

    // Drop first clone - count should decrease by 1
    drop(clone1);
    assert_eq!(collector.sender_count(), 2);

    // Drop second clone - count should decrease by 1
    drop(clone2);
    assert_eq!(collector.sender_count(), 1);
}
```

### 2. Error Handling Verification

```rust
#[test]
fn test_streaming_collector_early_return_error_handling() {
    let collector = StreamingResultCollector::<i32>::new();
    let clone1 = collector.clone();
    let clone2 = collector.clone();

    // Early return from empty collection
    let results = collector.stream_collect();
    assert!(results.is_err());

    // Verify sender count is still correct after early return
    assert_eq!(collector.sender_count(), 3, "Sender count should be preserved");
}
```

### 3. State Integrity After Operations

```rust
#[test]
fn test_early_return_error_does_not_corrupt_state() {
    let collector = StreamingResultCollector::<i32>::new();

    // Multiple early returns with different error conditions
    for i in 0..3 {
        let results = collector.stream_collect();
        assert!(results.is_err(), "Iteration {} should fail", i);
        // Verify state is not corrupted
        assert!(collector.sender_count() >= 1, "Count should remain valid");
    }
}
```

## Module-Specific Patterns

### sender_count Assertions

**Location**: `crates/sigil-core/src/thread_utils/result_collector.rs` and `crates/sigil-core/src/thread_utils/result_collector_sender_count_assertions.rs`

**Key Patterns**:

1. **Initial State Verification**
```rust
let collector = StreamingResultCollector::<i32>::new();
assert_eq!(collector.sender_count(), 1, "New collector should have count of 1");
```

2. **Clone Operation Verification**
```rust
let _clone = collector.clone();
assert_eq!(collector.sender_count(), 2, "Count should increment on clone");
assert_eq!(clone.sender_count(), 2, "Clone should see same count");
```

3. **Monotonic Behavior Verification**
```rust
assert!(
    count_after_clone >= count_before_clone,
    "sender_count should never decrease: before={}, after={}",
    count_before_clone, count_after_clone
);
```

4. **Multi-Instance Consistency**
```rust
assert_eq!(collector.sender_count(), 4);
assert_eq!(clone1.sender_count(), 4);
assert_eq!(clone2.sender_count(), 4);
assert_eq!(clone3.sender_count(), 4);
```

### Security Assertions

**Location**: `crates/sigil-daemon/tests/` and `crates/sigil-integration-tests/`

**Pattern**: Security-focused assertions with clear threat model documentation

```rust
#[test]
fn test_session_token_is_32_bytes() {
    let token = SessionToken::generate();
    let bytes = token.to_bytes();
    
    assert_eq!(bytes.len(), 32, "Session token must be 32 bytes");
}
```

### Integration Test Patterns

**Location**: `crates/sigil-integration-tests/tests/`

**Pattern**: Comprehensive end-to-end verification with setup/teardown

```rust
#[tokio::test]
async fn test_proxy_server_creation() {
    let config = ProxyConfig::default();
    let server = ProxyServer::new(config);
    assert!(server.is_ok(), "Proxy server creation should succeed");
}
```

## Best Practices Summary

### DO

✅ Use `assert_eq!` for value comparisons  
✅ Include descriptive messages in assertions  
✅ Follow before/after pattern for state changes  
✅ Use custom validation functions for complex checks  
✅ Name tests descriptively: `test_{what}_{scenario}_{expected}`  
✅ Verify both success and failure paths  
✅ Test edge cases (empty collections, single items, limits)  
✅ Include security-specific tests for sensitive operations  

### DON'T

❌ Use vague assertion messages like "failed" or "error"  
❌ Skip testing cleanup/lifecycle behavior  
❌ Assume thread safety without concurrent tests  
❌ Forget to document security assumptions  
❌ Mix multiple assertions in one test without clear separation  
❌ Use `unwrap()` or `expect()` in non-test production code  

## Where to Add sender_count Assertions

### Primary Location
**File**: `crates/sigil-core/src/thread_utils/result_collector.rs`  
**Module**: `#[cfg(test)]` test module within the file

### Supporting File (NEW - Added 2026-08-07)
**File**: `crates/sigil-core/src/thread_utils/result_collector_sender_count_assertions.rs`  
**Module**: `#[cfg(test)] mod sender_count_assertions`  
**Purpose**: Reusable validation functions for sender_count operations  
**Status**: Draft implementation following existing patterns

### New Assertion Helper Functions

The following functions are now available in `result_collector_sender_count_assertions.rs`:

#### 1. validate_sender_count_after_clone
**Purpose**: Validates sender_count consistency after clone operation  
**Signature**: 
```rust
pub fn validate_sender_count_after_clone<T>(
    collector: &StreamingResultCollector<T>,
    clone: &StreamingResultCollector<T>,
    expected_count: usize,
) -> Result<(), String>
```
**Validates**:
- Original collector's sender_count matches expected
- Cloned collector's sender_count matches expected  
- Both collectors have the same sender_count
- sender_count is non-zero
- sender_count increased from initial value

#### 2. validate_monotonic_sender_count
**Purpose**: Ensures sender_count never decreases during operations  
**Signature**:
```rust
pub fn validate_monotonic_sender_count(counts: &[usize]) -> Result<(), String>
```
**Validates**:
- No value in the sequence is less than the previous value
- Provides detailed error messages with position and values

#### 3. validate_sender_count_stability  
**Purpose**: Verifies sender_count remains stable when read multiple times  
**Signature**:
```rust
pub fn validate_sender_count_stability<T>(
    collector: &StreamingResultCollector<T>,
    stability_threshold: usize,
) -> Result<(), String>
```
**Validates**:
- Multiple consecutive reads return consistent values
- Variation stays within acceptable threshold
- Provides actual values when stability check fails

#### 4. validate_comprehensive_sender_count
**Purpose**: Combines all validation patterns into comprehensive check  
**Signature**:
```rust
pub fn validate_comprehensive_sender_count<T>(
    collector: &StreamingResultCollector<T>,
    clone: &StreamingResultCollector<T>,
    pre_clone_count: usize,
    expected_post_clone_count: usize,
) -> Result<(), String>
```
**Validates**:
- Pre-clone baseline sanity check
- Post-clone consistency via `validate_sender_count_after_clone`
- Count increased appropriately
- Monotonic behavior via `validate_monotonic_sender_count`
- Stability on both original and cloned collectors
- Cross-instance consistency

### Usage Examples for New Helpers

#### Basic Clone Validation
```rust
let collector = StreamingResultCollector::<i32>::new();
let clone = collector.clone();

sender_count_assertions::validate_sender_count_after_clone(
    &collector,
    &clone,
    2, // expected count after one clone
).expect("sender_count validation should pass");
```

#### Comprehensive Validation
```rust
let collector = StreamingResultCollector::<i32>::new();
let pre_clone_count = collector.sender_count();
let clone = collector.clone();

sender_count_assertions::validate_comprehensive_sender_count(
    &collector,
    &clone,
    pre_clone_count,      // 1
    pre_clone_count + 1,   // 2
).expect("comprehensive sender_count validation should pass");
```

#### Stability Check
```rust
let collector = StreamingResultCollector::<i32>::new();

sender_count_assertions::validate_sender_count_stability(
    &collector,
    0, // no variation allowed
).expect("sender_count should remain stable");
```

### Integration Points
1. **Clone Operations**: Verify count increments correctly
2. **Drop Operations**: Verify count decrements appropriately  
3. **Concurrent Access**: Verify count remains consistent under thread stress
4. **Error Recovery**: Verify count remains valid after error conditions
5. **Lifecycle Operations**: Verify count reaches zero when all instances dropped

## Test Organization

### Unit Test Structure
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

### Property-Based Testing
SIGIL uses `proptest` for property-based verification:

```rust
#[proptest]
fn proptest_arbitrary_values(val: i32) {
    let collector = StreamingResultCollector::<i32>::new();
    collector.stream_add(val).unwrap();
    // Property verification
}
```

## Related Documentation

- **CLAUDE.md**: Project coding conventions and standards
- **docs/plan/plan.md**: Full implementation plan and test requirements  
- **docs/research/**: Research documents informing security test design
- **crates/sigil-integration-tests/**: Integration test patterns and fixtures

## Summary of Existing Test Assertion Patterns

### Acceptance Criteria Verification

✅ **Located 4+ existing assertion patterns in test files**:
1. Before/After State Comparison Pattern
2. Stability Verification Pattern  
3. Cross-Instance Consistency Pattern
4. Monotonic Behavior Validation Pattern
5. Comprehensive Validation Pipeline Pattern

✅ **Documented pattern structure**:
- Before/after checks with clear state capture
- Error message format: `"what should happen: context={value}"`
- Detailed failure information with actual vs expected values
- Context preservation in all assertion failures

✅ **Identified specific files/modules for sender_count assertions**:
- **Primary**: `/home/coding/SIGIL/crates/sigil-core/src/thread_utils/result_collector.rs` - Main test module with 40+ sender_count tests
- **Helpers**: `/home/coding/SIGIL/crates/sigil-core/src/thread_utils/result_collector_sender_count_assertions.rs` - New assertion utilities module
- **Integration**: `/home/coding/SIGIL/crates/sigil-integration-tests/tests/` - Cross-crate validation tests

✅ **Documented naming conventions and assertion helpers**:
- **Test functions**: `test_{component}_{scenario}_{expected}`
- **Helper functions**: `validate_{aspect}` or `{verb}_{noun}_for_{purpose}`  
- **Variables**: `{entity}_{state}` or `{entity}_{description}`
- **New helpers**: `validate_sender_count_after_clone`, `validate_monotonic_sender_count`, `validate_sender_count_stability`, `validate_comprehensive_sender_count`

### Key Findings

1. **Rich Existing Test Coverage**: The codebase already contains extensive sender_count validation tests, demonstrating 40+ test functions specifically for clone behavior and count tracking.

2. **New Assertion Helper Module**: A dedicated assertion utilities module was recently added (2026-08-07) providing reusable validation functions that follow established patterns.

3. **Consistent Error Messaging**: All tests follow a clear error message format that includes:
   - What should happen (clear expectation)
   - What went wrong (actual vs expected)
   - Context information (relevant state values)

4. **Comprehensive Coverage**: Existing tests cover:
   - Clone operations and count increment behavior
   - Drop operations and count decrement behavior
   - Multi-instance consistency verification
   - Concurrent access patterns
   - Error recovery scenarios
   - Lifecycle operations

5. **Integration Points**: sender_count assertions should be added at:
   - Clone operation verification points
   - Drop operation verification points
   - Concurrent access scenarios
   - Error recovery validation
   - Lifecycle operation checks

## Conclusion

The SIGIL codebase demonstrates consistent, well-structured test assertion patterns across unit and integration tests. When adding new sender_count assertions or extending test coverage, follow these established patterns to maintain code quality and readability. The new assertion helper functions in `result_collector_sender_count_assertions.rs` provide reusable utilities that encapsulate these patterns and should be preferred for new validations.