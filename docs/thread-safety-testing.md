# Thread Safety Testing in SIGIL

This document describes the thread safety testing infrastructure available in SIGIL and how to use it for concurrent/parallel testing.

## Overview

SIGIL includes comprehensive thread safety testing infrastructure in `crates/sigil-integration-tests/`. The testing framework provides:

- Thread spawning with configurable counts
- Barrier synchronization for coordinated testing
- Result collection from concurrent operations
- Thread-safe state management helpers
- High-concurrency stress testing utilities
- Race condition detection patterns

## Available Dependencies

### Standard Library (No External Dependencies Required)

Most thread testing can use Rust's standard library:

- `std::thread` - Thread spawning and management
- `std::sync::{Arc, Mutex, RwLock}` - Thread-safe shared state
- `std::sync::atomic` - Atomic operations for lock-free concurrency
- `std::sync::Barrier` - Coordinated thread execution

All primitives are available without any additional dependencies.

### Workspace Dependencies

The following dependencies are available in the workspace for thread safety testing:

#### `parking_lot` (v0.12)
- **Purpose**: Faster mutex/rwlock implementations for testing
- **When to use**: Performance-critical tests or when you need fairness guarantees
- **Features**: `const_mut` mutations, deadlock detection, stats tracking

```toml
parking_lot = "0.12"
```

#### `tokio` (v1.40, features: ["full"])
- **Purpose**: Async runtime for concurrent async testing
- **When to use**: Testing async operations, futures, concurrent I/O
- **Features**: Multi-threaded runtime, timers, I/O utilities

```toml
tokio = { version = "1.40", features = ["full"] }
```

#### `serial_test` (v3.1)
- **Purpose**: Sequential test execution for tests that cannot run in parallel
- **When to use**: Tests that share global state or resources
- **Note**: Already available in integration tests

```toml
serial_test = "3.1"
```

## Thread Testing Infrastructure

### Core Utilities Module

Located in `crates/sigil-integration-tests/src/thread_util.rs`, this module provides:

#### Thread Count Detection

```rust
use sigil_integration_tests::thread_util::*;

// Get appropriate thread count for testing (capped at 8 for CI)
let count = get_test_thread_count();

// Get thread count with custom bounds
let count = get_test_thread_count_bounded(2, 4); // Between 2 and 4 threads

// Get available parallelism (uncapped)
let parallelism = available_parallelism_count();
```

#### Thread Spawning

```rust
use sigil_integration_tests::thread_util::*;

// Spawn threads with error handling
let handles = spawn_test_threads(4, || {
    // Thread logic here
    42
}).expect("Failed to spawn threads");

// Wait for all threads
for handle in handles {
    handle.join().expect("Thread panicked");
}
```

#### Barrier Coordination

```rust
use sigil_integration_tests::thread_util::*;

// Create a barrier for coordinated execution
let barrier = create_barrier(4);

// Execute with barrier coordination (all threads start simultaneously)
let results = coordinate_then_execute(4, || {
    // This runs after all threads are ready
    expensive_operation()
}).expect("Failed to coordinate");
```

#### Result Collection

```rust
use sigil_integration_tests::thread_util::*;

// Collect results (unordered)
let results = collect_thread_results(4, || {
    42
}).expect("Failed to collect");

// Collect results (ordered by thread ID)
let results = collect_thread_results_ordered(4, |thread_id| {
    thread_id * 2
}).expect("Failed to collect");

// Collect results with error handling
let collection = collect_thread_results_with_result(4, || {
    Ok(42)
}).expect("Failed to collect");

// Successes and errors are separated
println!("Successes: {:?}", collection.successes);
println!("Errors: {:?}", collection.errors);
```

### Concurrent Tests Module

Located in `crates/sigil-integration-tests/src/concurrent_tests.rs`, this module provides:

#### High-Level Concurrent Testing

```rust
use sigil_integration_tests::concurrent_tests::*;

// Basic concurrent test
let results = spawn_and_collect(4, |thread_id| {
    thread_id * 2
});
assert_eq!(results.len(), 4);

// Coordinated concurrent execution
let results = execute_with_barrier(8, |thread_id| {
    // All threads start simultaneously
    expensive_operation(thread_id)
});

// Verify thread safety
let safe = verify_thread_safe(100, || {
    // Function should not panic under concurrent access
    Environment::get()
});
assert!(safe);

// Stress test with timeout
let iterations = stress_test_concurrent(
    8,
    Duration::from_secs(5),
    || {
        // Return true to continue, false to stop early
        true
    }
);
println!("Completed {} iterations", iterations);

// Collect memory addresses for singleton verification
let addrs = collect_concurrent_addrs(10, || {
    Environment::get() as *const Environment as usize
});
// All addresses should be identical (singleton pattern)
assert!(addrs.iter().all(|&addr| addr == addrs[0]));
```

#### Concurrent Test Template

```rust
use sigil_integration_tests::concurrent_tests::*;

// Use template for consistent test configuration
let results = ConcurrentTestTemplate::new()
    .with_thread_count(8)
    .with_barrier(true)
    .run(|thread_id| {
        // Your test logic here
        perform_concurrent_operation(thread_id)
    });
```

## Usage Examples

### Example 1: Testing Thread Safety of a Singleton

```rust
use sigil_integration_tests::concurrent_tests::*;
use std::sync::Arc;

#[test]
fn test_singleton_thread_safety() {
    // Verify that get() is thread-safe
    let safe = verify_thread_safe(100, || {
        let _env = Environment::get();
    });
    assert!(safe);
    
    // Verify that all threads get the same instance
    let addrs = collect_concurrent_addrs(10, || {
        Environment::get() as *const Environment as usize
    });
    assert!(addrs.iter().all(|&addr| addr == addrs[0]));
}
```

### Example 2: Testing Concurrent Vault Access

```rust
use sigil_integration_tests::concurrent_tests::*;
use sigil_core::SecretBackend;

#[test]
fn test_concurrent_vault_reads() {
    let vault = Arc::new(TestVault::new());
    let vault_ref = Arc::clone(&vault);
    
    let results = execute_with_barrier(8, move |thread_id| {
        // All threads attempt to read simultaneously
        let secret = vault_ref.get(&format!("secret{}", thread_id % 3));
        secret.is_ok()
    });
    
    // All operations should succeed
    assert!(results.iter().all(|&success| success));
}
```

### Example 3: Stress Testing with Timeout

```rust
use sigil_integration_tests::concurrent_tests::*;
use std::time::Duration;

#[test]
fn test_scrubber_under_load() {
    let iterations = stress_test_concurrent(
        4,
        Duration::from_secs(10),
        || {
            // Repeatedly scrub output
            let output = "secret value";
            let _ = scrubber.scrub(output);
            true // Continue testing
        }
    );
    
    println!("Scrubber completed {} iterations", iterations);
    assert!(iterations > 1000, "Should complete many iterations");
}
```

### Example 4: Testing Race Conditions

```rust
use sigil_integration_tests::thread_util::*;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

#[test]
fn test_race_condition_protection() {
    let counter = Arc::new(AtomicUsize::new(0));
    let counter_ref = Arc::clone(&counter);
    
    let results = coordinate_then_execute(8, move || {
        // All threads increment simultaneously
        counter_ref.fetch_add(1, Ordering::SeqCst)
    }).expect("Failed to coordinate");
    
    // All increments should be captured (no race conditions)
    assert_eq!(results.iter().sum::<usize>(), 28); // 0+1+2+3+4+5+6+7
}
```

## Async Thread Testing

For async operations, use the `tokio::test` macro:

```rust
use tokio::test;

#[test]
async fn test_async_concurrent_operations() {
    // Spawn multiple concurrent async tasks
    let handles: Vec<_> = (0..10)
        .map(|i| {
            tokio::spawn(async move {
                // Async operation here
                perform_async_operation(i).await
            })
        })
        .collect();
    
    // Wait for all tasks to complete
    let results: Vec<_> = futures::future::join_all(handles)
        .await
        .into_iter()
        .map(|r| r.unwrap())
        .collect();
    
    assert_eq!(results.len(), 10);
}
```

## Performance Considerations

### Thread Count Selection

- **Development**: Use `get_test_thread_count()` to auto-detect appropriate thread count
- **CI**: Capped at 8 threads to avoid overwhelming CI systems
- **Stress testing**: Use higher counts (16-32) for detecting race conditions
- **Resource-intensive tests**: Use `get_test_thread_count_with_max(4)` to limit threads

### Barrier vs No Barrier

- **Use barriers** when testing race conditions or need simultaneous execution
- **Skip barriers** for general concurrent testing (less overhead)
- **Template pattern**: Use `ConcurrentTestTemplate::new().with_barrier(true)`

### Result Collection

- **Unordered**: `collect_thread_results` - Faster, simpler
- **Ordered**: `collect_thread_results_ordered` - When thread ID matters
- **With errors**: `collect_thread_results_with_result` - For fallible operations

## Best Practices

1. **Always verify thread safety** for singleton-like functions using `verify_thread_safe`
2. **Use barriers** to maximize chance of detecting race conditions
3. **Test with various thread counts** (1, 2, 4, 8) to catch different failure modes
4. **Include stress tests** for high-contention scenarios
5. **Use parking_lot** for performance-critical synchronization in tests
6. **Document concurrent behavior** in test comments
7. **Clean up resources** in test teardown to avoid state leakage

## Existing Tests

SIGIL includes extensive concurrent tests:

- `crates/sigil-integration-tests/tests/env_detect_concurrent_test.rs` - Environment detection thread safety
- `crates/sigil-integration-tests/tests/phase6_2_3_backend_verification_test.rs` - Backend concurrent access
- Various `*_concurrent_test.rs` files throughout the codebase

These tests serve as examples for how to write effective concurrent tests.

## Troubleshooting

### Tests Failing on CI But Passing Locally

- **Cause**: Race conditions or timing issues
- **Fix**: Use `get_test_thread_count_with_max(4)` to limit thread count on CI
- **Alternative**: Use barriers to ensure deterministic execution

### Thread Panics

- **Cause**: Unhandled panic in a thread
- **Fix**: Use `std::panic::catch_unwind` to catch panics, check error returns
- **Prevention**: Verify all thread operations are infallible

### Deadlocks

- **Cause**: Lock ordering issues or missing unlocks
- **Fix**: Use timeout variants (`with_timeout`), use `parking_lot` with deadlock detection
- **Prevention**: Always acquire locks in consistent order

### Resource Exhaustion

- **Cause**: Too many threads for system resources
- **Fix**: Limit thread count with `get_test_thread_count_with_max()`
- **Monitoring**: Watch for thread spawn failures (`ThreadSpawnError`)

## Documentation References

- `thread_util.rs` module documentation (comprehensive doc comments)
- `concurrent_tests.rs` module documentation (usage examples and patterns)
- Rust standard library docs for `std::thread` and `std::sync`

## Conclusion

SIGIL provides a robust foundation for thread safety testing. The infrastructure uses primarily standard library primitives, with optional dependencies like `parking_lot` for enhanced performance and debugging. Start with the high-level utilities in `concurrent_tests` and drop down to `thread_util` when you need more control.
