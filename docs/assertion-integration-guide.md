# sender_count Assertion Integration Guide

## Overview

This document identifies where and how the `sender_count` assertions should be integrated into the SIGIL codebase. It provides the specific locations, import patterns, and fixture requirements for adding new assertion tests.

## Current Status

### ✅ Already Integrated (Inline Assertions)
The main `result_collector.rs` file contains comprehensive inline assertion checks within the `Clone` implementation (lines 1102-1198):
- **VERIFICATION POINT 1**: Pre-clone sender_count validation (lines 1100-1107)
- **VERIFICATION POINT 2**: Post-increment validation (lines 1126-1136)
- **VERIFICATION POINT 3**: Pre-Arc::clone stability (lines 1139-1145)
- **VERIFICATION POINT 4**: Arc::clone execution (line 1148)
- **VERIFICATION POINT 5**: Post-Arc::clone stability (lines 1151-1157)
- **VERIFICATION POINT 6**: Pre-sender.clone stability (lines 1160-1167)
- **VERIFICATION POINT 7**: Sender clone execution (line 1170)
- **VERIFICATION POINT 8**: Post-sender.clone stability (lines 1173-1178)
- **VERIFICATION POINT 9**: Final pre-return validation (lines 1182-1188)

### ✅ Already Integrated (Test Utilities)
Comprehensive test assertion utilities are already integrated in the test module (lines 7343-7552):
- `validate_sender_count_before_clone<T>()` - Pre-clone baseline validation
- `validate_sender_count_after_clone<T>()` - Post-clone consistency validation  
- `validate_monotonic_sender_count()` - Monotonic behavior validation
- `validate_sender_count_stability<T>()` - Stability validation
- `validate_comprehensive_sender_count<T>()` - Combined comprehensive validation

### ✅ Already Integrated (Test Cases)
Four comprehensive test cases using the assertion utilities (lines 7556-7650+):
- `test_streaming_collector_sender_count_comprehensive_validation`
- `test_streaming_collector_sender_count_stability_after_clone`
- `test_streaming_collector_sender_count_monotonic_multiple_clones`
- `test_streaming_collector_sender_count_assertion_helpers`

## Integration Points for New Assertions

### 1. Specific Test Module to Extend

**Location**: `crates/sigil-core/src/thread_utils/result_collector.rs`
**Module**: `#[cfg(test)] mod tests` (starting at line 1228)
**Section**: "Comprehensive Sender Count Tests" (starting at line 7553)

**How to Extend**: Add new test functions after line 7650 (after existing sender_count tests) following the established pattern:

```rust
#[test]
fn test_streaming_collector_<new_aspect>() {
    let collector = StreamingResultCollector::<i32>::new();
    
    // Use existing assertion utilities
    let pre_clone_count = validate_sender_count_before_clone(&collector)
        .expect("Pre-clone validation should pass");
    
    // Test your new aspect here
    // ...
    
    // Validate results
    validate_comprehensive_sender_count(
        &collector,
        &clone,
        pre_clone_count,
        expected_count,
    ).expect("Validation should pass");
}
```

### 2. Exact Location for Assertion Code

**For New Test Functions**: Add after line 7650 in the test module
**For New Assertion Utilities**: Add after line 7551 (before the "Comprehensive Sender Count Tests" section)

**Location Pattern**:
```rust
// Line 7551: End of existing assertion utilities
    }

// ===== Comprehensive Sender Count Tests =====  // Line 7553
// Add new assertion utilities here (if needed)

// ===== New Assertion Utilities =====  // Add new section here if creating new utilities
#[test]
fn test_streaming_collector_your_new_test() {
    // Your test code here
}
```

### 3. Import Pattern Needed

**Standard Test Imports** (already present in the test module at line 1229-1231):
```rust
#[cfg(test)]
mod tests {
    use super::*;      // Import parent module items
    use std::thread;   // For thread-based tests
    
    // Your test functions here
}
```

**For Assertion Utilities**: No additional imports needed - they're defined within the same test module and use only:
- Standard library types (`usize`, `vec`, etc.)
- The `StreamingResultCollector<T>` type (via `use super::*`)
- Result types (`Result<(), String>`, `Result<usize, String>`)

**No External Imports Required** - The assertion utilities are self-contained within the test module.

### 4. Fixtures Needed for Assertions

**No Special Fixtures Required** - The sender_count assertions use simple instantiation:

```rust
// Standard fixture pattern
let collector = StreamingResultCollector::<i32>::new();

// With specific types as needed
let collector = StreamingResultCollector::<YourType>::new();

// For capacity testing
let collector = StreamingResultCollector::<i32>::with_capacity(100);
```

**Optional Fixtures** (for advanced testing only):
- **Thread Handles**: For concurrent testing (if needed):
  ```rust
  let handle = thread::spawn(move || {
      collector_clone.stream_add(42).unwrap()
  });
  handle.join().unwrap();
  ```

- **Clone Chains**: For testing complex clone scenarios (already present in existing tests):
  ```rust
  let clone1 = collector.clone();
  let clone2 = clone1.clone();
  let clone3 = clone2.clone();
  ```

**No Binary Fixtures, Path Fixtures, or Runtime Fixtures Required** - Unlike integration tests in `crates/sigil-integration-tests/`, the sender_count assertions are pure unit tests that don't require:
- Binary fixtures (`create_executable_binary`, etc.)
- Path manipulation (`workspace_root`, `crate_source_path`)
- Socket/daemon management (`wait_for_socket`, `daemon_health_check`)
- Environment detection (`detect_bwrap`, `skip_if_no_bwrap`)

## How to Add New sender_count Assertions

### Step 1: Identify Assertion Type

**For New Test Cases**: Add new test functions in the "Comprehensive Sender Count Tests" section
**For New Validation Logic**: Add new assertion utility functions before line 7553

### Step 2: Use Established Patterns

**Pattern A: Comprehensive Test** (recommended for most cases)
```rust
#[test]
fn test_streaming_collector_sender_count_<new_scenario>() {
    let collector = StreamingResultCollector::<i32>::new();
    
    // Pre-clone validation
    let pre_clone_count = validate_sender_count_before_clone(&collector)
        .expect("Pre-clone validation should pass");
    
    // Perform your test operations
    let clone = collector.clone();
    // ... additional operations ...
    
    // Comprehensive validation
    validate_comprehensive_sender_count(
        &collector,
        &clone,
        pre_clone_count,
        expected_count,
    ).expect("Comprehensive validation should pass");
}
```

**Pattern B: Utility Function** (for new validation patterns)
```rust
/// Validate <new aspect> of sender_count
///
/// This function validates that sender_count:
/// - <condition 1>
/// - <condition 2>
fn validate_sender_count_<new_aspect<T>(
    collector: &StreamingResultCollector<T>,
    additional_param: SomeType,
) -> Result<(), String>
where
    T: Send + 'static,
{
    // Validation logic
    if <condition> {
        return Err(format!(
            "<what_should_happen>: <context>={value}",
            context = value
        ));
    }
    
    Ok(())
}
```

### Step 3: Follow Naming Conventions

**Test Functions**: `test_streaming_collector_sender_count_<aspect>`
**Validation Functions**: `validate_sender_count_<aspect>`
**Error Messages**: Follow pattern `{what_should_happen}: {context}={value}`

### Step 4: Use Existing Utilities Before Creating New Ones

The existing assertion utilities cover most common scenarios:
- ✅ Pre-clone validation: `validate_sender_count_before_clone()`
- ✅ Post-clone validation: `validate_sender_count_after_clone()`
- ✅ Monotonic behavior: `validate_monotonic_sender_count()`
- ✅ Stability checks: `validate_sender_count_stability()`
- ✅ Comprehensive validation: `validate_comprehensive_sender_count()`

Only create new utilities if you need to validate aspects not covered by these functions.

## Integration Checklist

When adding new sender_count assertions:

- [ ] Add test function after line 7650 in the test module
- [ ] Use existing assertion utilities where possible
- [ ] Follow naming convention: `test_streaming_collector_sender_count_<aspect>`
- [ ] Include descriptive error messages with context
- [ ] Return `Result<(), String>` from validation functions
- [ ] Use `.expect()` with clear messages when calling validation functions
- [ ] Add functional verification alongside assertion validation
- [ ] Run tests with: `cargo test test_streaming_collector_sender_count`
- [ ] Ensure no new fixtures or imports are needed

## Example: Adding a New Assertion

```rust
// Add after line 7650 in the test module
#[test]
fn test_streaming_collector_sender_count_high_concurrency_stability() {
    let collector = StreamingResultCollector::<i32>::new();
    let pre_clone_count = validate_sender_count_before_clone(&collector)
        .expect("Pre-clone validation should pass");

    // Create many concurrent clones
    let mut handles = Vec::new();
    for i in 0..10 {
        let collector_clone = collector.clone();
        let handle = thread::spawn(move || {
            // Each thread does some work
            let _ = collector_clone.stream_add(i).unwrap();
            collector_clone.sender_count()
        });
        handles.push(handle);
    }

    // Verify monotonic behavior across all operations
    let mut counts = vec![pre_clone_count];
    for handle in handles {
        counts.push(handle.join().unwrap());
    }
    
    validate_monotonic_sender_count(&counts)
        .expect("sender_count should remain monotonic under high concurrency");

    // Final comprehensive validation
    let final_count = collector.sender_count();
    assert_eq!(final_count, 11, "Should have 11 total collectors (1 original + 10 threads)");
}
```

## Summary

The `sender_count` assertions are **fully integrated** into the SIGIL codebase:

1. **Test Module**: Extended in `#[cfg(test)] mod tests` at line 1228
2. **Location**: "Comprehensive Sender Count Tests" section starting at line 7553
3. **Imports**: Standard test imports only (`use super::*`, `use std::thread`)
4. **Fixtures**: None required - pure unit tests with simple instantiation

New assertions can be added by:
1. Creating new test functions following established patterns
2. Using existing assertion utilities where possible
3. Following naming conventions and error message patterns
4. Running tests with standard `cargo test` commands

The integration is complete and ready for extension. No additional setup, fixtures, or imports are required.