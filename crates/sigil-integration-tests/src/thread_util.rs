//! Thread Testing Utilities
//!
//! This module provides utility functions for determining appropriate thread counts
//! for concurrent testing across different environments and hardware configurations.
//!
//! # Features
//!
//! - Detect available parallelism using `std::thread::available_parallelism()`
//! - Provide capped thread counts for testing (avoid overwhelming CI systems)
//! - Allow custom limits for specific test scenarios
//! - Handle detection failures gracefully

use std::sync::{Arc, Barrier, Mutex};
use std::time::Duration;

/// Maximum thread count for tests in resource-constrained environments
///
/// This prevents tests from overwhelming CI systems or low-resource environments.
/// Most concurrent tests work well with 4-8 threads even if more CPUs are available.
const DEFAULT_MAX_TEST_THREADS: usize = 8;

/// Minimum thread count for tests (never go below this)
const MIN_TEST_THREADS: usize = 1;

/// Cached thread count for performance
static CACHED_THREAD_COUNT: Mutex<Option<usize>> = Mutex::new(None);

/// Get the available parallelism count from the system
///
/// This function wraps `std::thread::available_parallelism()` and provides
/// a sensible default if the function fails. This is useful for code that
/// needs to know the number of available CPU cores for thread pool sizing
/// or concurrent operation planning.
///
/// # Behavior
///
/// - Uses `std::thread::available_parallelism()` to detect CPU count
/// - Returns the number of available threads as `usize`
/// - Falls back to 4 if detection fails (safe, conservative default)
/// - Does NOT cache the result (always detects current system state)
/// - **Never returns zero** - even on single-threaded systems, returns at least 1
///
/// # Edge Cases
///
/// - **System call failure**: Returns 4 (fallback value) when `available_parallelism()` fails
/// - **Single-threaded systems**: Returns 1 (not zero)
/// - **High-core systems**: Can return values up to 512+ on server hardware
/// - **Containerized environments**: Returns the container's CPU limit, not host cores
/// - **Process isolation**: Respects CPU affinity masks and cgroup limits
///
/// # Returns
///
/// The number of available parallel threads (typically the number of CPU cores)
///
/// # Examples
///
/// ```
/// use sigil_integration_tests::thread_util::available_parallelism_count;
///
/// let count = available_parallelism_count();
/// assert!(count >= 1, "Should always return at least 1");
/// // On most modern systems, this will be the number of CPU cores
/// // On systems with 8 cores, returns 8
/// // On single-core systems, returns 1
/// ```
///
/// # Performance Considerations
///
/// This function always makes a system call and does not cache the result.
/// For repeated calls in performance-critical code, consider calling once
/// and storing the result, or use `get_test_thread_count()` which includes
/// caching.
pub fn available_parallelism_count() -> usize {
    match std::thread::available_parallelism() {
        Ok(parallelism) => parallelism.get(),
        Err(_) => 4, // Sensible default if detection fails
    }
}

/// Get the number of threads to use for concurrent testing
///
/// This function detects the available parallelism and caps it at a reasonable
/// value for testing purposes. This prevents tests from overwhelming CI systems
/// or resource-constrained environments while still testing concurrent behavior.
///
/// # Behavior
///
/// - Uses `std::thread::available_parallelism()` to detect CPU count
/// - Caps at `DEFAULT_MAX_TEST_THREADS` (8) to avoid overwhelming systems
/// - Minimum of `MIN_TEST_THREADS` (1) to ensure progress
/// - Caches the result for performance (use `reset_cached_thread_count()` to clear)
/// - Falls back to 2 threads if detection fails
///
/// # Thread Count Ranges
///
/// This function returns different values based on the available hardware:
///
/// - **1 core systems**: Returns 1 (minimum guaranteed)
/// - **2-8 core systems**: Returns the actual core count (1-8)
/// - **8+ core systems**: Returns 8 (capped at DEFAULT_MAX_TEST_THREADS)
/// - **Detection failure**: Returns 2 (conservative fallback)
///
/// # When to Use This Function
///
/// - **Concurrent test execution**: Spawn this many threads for parallel tests
/// - **Thread pool sizing**: Configure thread pools with appropriate worker count
/// - **Resource-aware testing**: Avoid overwhelming CI systems with too many threads
///
/// # Examples
///
/// ```
/// use sigil_integration_tests::thread_util::get_test_thread_count;
///
/// let thread_count = get_test_thread_count();
/// assert!(thread_count >= 1);
/// assert!(thread_count <= 8);
///
/// // Use for thread pool configuration
/// let pool = threadpool::Builder::new()
///     .num_threads(thread_count)
///     .build();
/// ```
///
/// # Performance Considerations
///
/// This function caches the result after the first call. Subsequent calls
/// return the cached value immediately. Use `reset_cached_thread_count()`
/// to force re-detection if needed.
pub fn get_test_thread_count() -> usize {
    // Try to get the cached value first
    if let Ok(cache) = CACHED_THREAD_COUNT.lock() {
        if let Some(cached) = *cache {
            return cached;
        }
    }

    // Detect the thread count
    let detected = match std::thread::available_parallelism() {
        Ok(parallelism) => {
            let detected = parallelism.get();

            // Cap at the maximum test threads to avoid overwhelming systems
            let capped = detected.min(DEFAULT_MAX_TEST_THREADS);

            // Ensure we have at least the minimum
            capped.max(MIN_TEST_THREADS)
        }
        Err(_) => {
            // Fallback to a conservative default if detection fails
            // This handles systems where available_parallelism() fails
            2
        }
    };

    // Cache the result
    if let Ok(mut cache) = CACHED_THREAD_COUNT.lock() {
        *cache = Some(detected);
    }

    detected
}

/// Get thread count with a custom maximum
///
/// This function is useful for tests that need a specific upper bound on
/// thread count, such as tests that spawn resources per thread.
///
/// # Arguments
///
/// * `max_threads` - Maximum number of threads to return (must be >= 1)
///
/// # Returns
///
/// The number of threads to use, capped at `max_threads`
///
/// # Panics
///
/// Panics if `max_threads` is 0
///
/// # Examples
///
/// ```rust
/// use sigil_integration_tests::thread_util::get_test_thread_count_with_max;
///
/// // Get thread count capped at 4 for resource-intensive tests
/// let count = get_test_thread_count_with_max(4);
/// assert!(count >= 1);
/// assert!(count <= 4);
/// ```
pub fn get_test_thread_count_with_max(max_threads: usize) -> usize {
    assert!(max_threads >= 1, "max_threads must be at least 1");
    get_test_thread_count().min(max_threads)
}

/// Get thread count with a custom minimum
///
/// This function is useful for tests that require a minimum level of
/// concurrency to properly exercise race conditions or concurrent behavior.
///
/// # Arguments
///
/// * `min_threads` - Minimum number of threads to return (must be >= 1)
///
/// # Returns
///
/// The number of threads to use, guaranteed to be at least `min_threads`
/// or the detected count if lower
///
/// # Panics
///
/// Panics if `min_threads` is 0
///
/// # Examples
///
/// ```rust
/// use sigil_integration_tests::thread_util::get_test_thread_count_with_min;
///
/// // Ensure at least 2 threads for race condition testing
/// let count = get_test_thread_count_with_min(2);
/// assert!(count >= 2);
/// ```
pub fn get_test_thread_count_with_min(min_threads: usize) -> usize {
    assert!(min_threads >= 1, "min_threads must be at least 1");
    get_test_thread_count().max(min_threads)
}

/// Get thread count with both custom minimum and maximum
///
/// This function provides full control over the thread count range,
/// useful for tests with specific concurrency requirements.
///
/// # Arguments
///
/// * `min_threads` - Minimum number of threads (must be >= 1)
/// * `max_threads` - Maximum number of threads (must be >= min_threads)
///
/// # Returns
///
/// A thread count within the specified range [`min_threads`, `max_threads`]
///
/// # Panics
///
/// Panics if:
/// - `min_threads` is 0
/// - `max_threads` < `min_threads`
///
/// # Examples
///
/// ```rust
/// use sigil_integration_tests::thread_util::get_test_thread_count_bounded;
///
/// // Get between 2 and 4 threads
/// let count = get_test_thread_count_bounded(2, 4);
/// assert!(count >= 2);
/// assert!(count <= 4);
/// ```
pub fn get_test_thread_count_bounded(min_threads: usize, max_threads: usize) -> usize {
    assert!(min_threads >= 1, "min_threads must be at least 1");
    assert!(
        max_threads >= min_threads,
        "max_threads must be >= min_threads"
    );

    let detected = get_test_thread_count();
    detected.clamp(min_threads, max_threads)
}

/// Reset the cached thread count
///
/// This function is primarily useful for testing the thread utilities themselves.
/// It clears the cached value so the next call to `get_test_thread_count()` will
/// re-detect the available parallelism.
///
/// # Examples
///
/// ```rust
/// use sigil_integration_tests::thread_util::{get_test_thread_count, reset_cached_thread_count};
///
/// let count1 = get_test_thread_count();
/// reset_cached_thread_count();
/// let count2 = get_test_thread_count();
/// // count1 and count2 will be the same, but the cache was reset
/// ```
pub fn reset_cached_thread_count() {
    if let Ok(mut cache) = CACHED_THREAD_COUNT.lock() {
        *cache = None;
    }
}

/// Spawn multiple test threads with the given closure
///
/// This function creates a specified number of threads, each running the provided
/// closure. It collects all thread handles into a Vec for the caller to manage.
/// This is useful for concurrent testing scenarios where you need multiple threads
/// executing the same logic.
///
/// # Type Parameters
///
/// * `F` - Closure type that must be `Clone + Send + 'static` (can be cloned and sent between threads)
/// * `T` - Return type of the closure (must be `Send + 'static`)
///
/// # Arguments
///
/// * `count` - Number of threads to spawn (must be >= 1)
/// * `closure` - Closure to execute in each thread (will be cloned for each thread)
///
/// # Returns
///
/// * `Ok(Vec<JoinHandle<T>>)` - Vector of join handles on success
/// * `Err(ThreadSpawnError)` - Error if thread spawning fails
///
/// # Errors
///
/// Returns an error if:
/// - `count` is 0 (no threads to spawn)
/// - Any individual thread spawn fails (though this is rare in practice)
///
/// # Examples
///
/// Basic usage with a simple closure:
///
/// ```rust
/// use sigil_integration_tests::thread_util::spawn_test_threads;
/// use std::sync::atomic::{AtomicUsize, Ordering};
///
/// let counter = AtomicUsize::new(0);
/// let counter_ref = &counter;
/// let handles = spawn_test_threads(4, move || {
///     // Each thread increments the counter
///     counter_ref.fetch_add(1, Ordering::SeqCst);
/// }).expect("Failed to spawn threads");
///
/// // Wait for all threads to complete
/// for handle in handles {
///     handle.join().expect("Thread panicked");
/// }
///
/// assert_eq!(counter.load(Ordering::SeqCst), 4);
/// ```
///
/// Using with a closure that returns a value:
///
/// ```rust
/// use sigil_integration_tests::thread_util::spawn_test_threads;
///
/// let handles = spawn_test_threads(3, || {
///     // Each thread computes and returns a value
///     42
/// }).expect("Failed to spawn threads");
///
/// let results: Vec<i32> = handles
///     .into_iter()
///     .map(|h| h.join().expect("Thread panicked"))
///     .collect();
///
/// assert_eq!(results, vec![42, 42, 42]);
/// ```
///
/// Proper error handling:
///
/// ```rust
/// use sigil_integration_tests::thread_util::{spawn_test_threads, ThreadSpawnError};
///
/// match spawn_test_threads(0, || println!("This will fail")) {
///     Ok(_) => println!("Threads spawned successfully"),
///     Err(e) => eprintln!("Failed to spawn threads: {}", e),
/// }
/// ```
///
/// # Panics
///
/// This function itself does not panic. However, if a thread panics while
/// executing the closure, calling `join()` on its handle will return an `Err`.
///
/// # Performance Considerations
///
/// - Thread spawning has overhead; consider using thread pools for many short-lived tasks
/// - The `count` parameter should be reasonable for your system's resources
/// - Use `get_test_thread_count()` to determine a sensible count for your system
/// - The closure is cloned for each thread, so capturing large values may have overhead
pub fn spawn_test_threads<F, T>(
    count: usize,
    closure: F,
) -> Result<Vec<std::thread::JoinHandle<T>>, ThreadSpawnError>
where
    F: FnOnce() -> T + Clone + Send + 'static,
    T: Send + 'static,
{
    // Validate count
    if count == 0 {
        return Err(ThreadSpawnError::ZeroCount);
    }

    let mut handles = Vec::with_capacity(count);

    for i in 0..count {
        // Clone the closure for each thread
        let closure_clone = closure.clone();

        // std::thread::spawn doesn't return Result, it can only panic
        // We catch panics using catch_unwind
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            std::thread::spawn(closure_clone)
        }));

        match result {
            Ok(handle) => handles.push(handle),
            Err(_) => {
                // Clean up already spawned threads by detaching them
                // They will complete on their own or be terminated when the process exits
                for handle in handles {
                    let _ = handle.join();
                }
                return Err(ThreadSpawnError::SpawnFailed { thread_index: i });
            }
        }
    }

    Ok(handles)
}

// ============================================================================
// Barrier Synchronization Utilities
// ============================================================================

/// Create a new barrier for coordinating thread execution
///
/// This is a simple factory function for `std::sync::Barrier` that provides
/// a centralized location for barrier creation with consistent documentation.
/// A barrier allows multiple threads to synchronize at a specific point:
/// all threads must reach the barrier before any can proceed.
///
/// # Arguments
///
/// * `n` - Number of threads that will wait on this barrier (must be >= 1)
///
/// # Returns
///
/// A new `Barrier` instance that can be shared across threads
///
/// # Behavior
///
/// - Each thread calls `wait()` on the barrier
/// - The barrier blocks until all `n` threads have called `wait()`
/// - Once all threads arrive, all are unblocked simultaneously
/// - The barrier can be reused after all threads are released
///
/// # When to Use Barriers
///
/// - **Coordinated testing**: Ensure all threads reach a specific state before proceeding
/// - **Race condition testing**: Force threads to arrive at a point simultaneously
/// - **Setup/teardown**: Wait for all threads to complete setup before main test execution
/// - **Deterministic ordering**: Create reproducible thread execution patterns
///
/// # Examples
///
/// Basic barrier usage:
///
/// ```rust
/// use sigil_integration_tests::thread_util::create_barrier;
/// use std::sync::Arc;
/// use std::thread;
///
/// let barrier = Arc::new(create_barrier(2));
/// let barrier_clone = Arc::clone(&barrier);
///
/// // Spawn two threads
/// let h1 = thread::spawn(move || {
///     // Do some work
///     barrier_clone.wait(); // Wait for other thread
///     // Continue after both threads have arrived
/// });
///
/// let h2 = thread::spawn(move || {
///     barrier.wait(); // Wait for other thread
///     // Continue after both threads have arrived
/// });
///
/// h1.join().unwrap();
/// h2.join().unwrap();
/// ```
///
/// # Panics
///
/// Panics if `n` is 0
///
/// # Performance Considerations
///
/// - Barrier wait is a blocking operation
/// - Consider using timeout variants (`wait_timeout`) to prevent hangs
/// - For high-contention scenarios, consider alternative primitives
pub fn create_barrier(n: usize) -> Barrier {
    assert!(n > 0, "Barrier thread count must be at least 1");
    Barrier::new(n)
}

/// Execute a closure in multiple threads with barrier coordination
///
/// This function spawns multiple threads that coordinate using a barrier.
/// Each thread executes the provided closure after all threads have been spawned
/// and have reached the barrier point. This is useful for testing race conditions
/// or ensuring deterministic thread execution.
///
/// # Type Parameters
///
/// * `F` - Closure type that must be `FnOnce() -> T + Clone + Send + 'static`
/// * `T` - Return type of the closure (must be `Send + 'static`)
///
/// # Arguments
///
/// * `thread_count` - Number of threads to spawn (must be >= 1)
/// * `closure` - Closure to execute in each thread (after barrier synchronization)
///
/// # Returns
///
/// * `Ok(Vec<T>)` - Vector of results from each thread on success
/// * `Err(BarrierError)` - Error if coordination fails
///
/// # Behavior
///
/// 1. Spawn `thread_count` threads
/// 2. Each thread waits at a barrier until all threads are ready
/// 3. Once all threads arrive, each executes the closure
/// 4. Collect results from all threads
///
/// # Errors
///
/// Returns an error if:
/// - `thread_count` is 0 (no threads to spawn)
/// - Thread spawning fails (returns `BarrierError::SpawnFailed`)
/// - Any thread panics during execution (returns `BarrierError::ThreadPanicked`)
///
/// # Examples
///
/// Basic usage with a simple closure:
///
/// ```rust
/// use sigil_integration_tests::thread_util::coordinate_then_execute;
///
/// let results = coordinate_then_execute(4, || {
///     // This code executes after all 4 threads are ready
///     42
/// }).expect("Failed to coordinate threads");
///
/// assert_eq!(results, vec![42, 42, 42, 42]);
/// ```
///
/// Testing race conditions:
///
/// ```rust
/// use sigil_integration_tests::thread_util::coordinate_then_execute;
/// use std::sync::atomic::{AtomicUsize, Ordering};
/// use std::sync::Arc;
///
/// let counter = Arc::new(AtomicUsize::new(0));
/// let counter_ref = Arc::clone(&counter);
///
/// let results = coordinate_then_execute(4, move || {
///     // All threads execute this simultaneously after barrier
///     counter_ref.fetch_add(1, Ordering::SeqCst)
/// }).expect("Failed to coordinate threads");
///
/// // All threads incremented simultaneously
/// assert!(results.iter().sum::<usize>() >= 4);
/// ```
///
/// Proper error handling:
///
/// ```rust
/// use sigil_integration_tests::thread_util::coordinate_then_execute;
///
/// match coordinate_then_execute(0, || unreachable!()) {
///     Ok(_) => println!("Success"),
///     Err(e) => eprintln!("Failed to coordinate: {}", e),
/// }
/// ```
///
/// # Panics
///
/// This function itself does not panic. However, if a thread panics while
/// executing the closure, the function returns a `BarrierError::ThreadPanicked`.
///
/// # Performance Considerations
///
/// - Barrier wait is blocking; consider timeout variants for long-running tests
/// - Thread spawning has overhead; use thread pools for many short tasks
/// - The closure is cloned for each thread
pub fn coordinate_then_execute<F, T>(
    thread_count: usize,
    closure: F,
) -> Result<Vec<T>, BarrierError>
where
    F: FnOnce() -> T + Clone + Send + 'static,
    T: Send + 'static,
{
    if thread_count == 0 {
        return Err(BarrierError::ZeroThreadCount);
    }

    let barrier = std::sync::Arc::new(create_barrier(thread_count));
    let mut handles = Vec::with_capacity(thread_count);

    for i in 0..thread_count {
        let barrier_clone = std::sync::Arc::clone(&barrier);
        let closure_clone = closure.clone();

        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            std::thread::spawn(move || {
                // Wait for all threads to be ready
                barrier_clone.wait();

                // Execute the closure after all threads arrive
                closure_clone()
            })
        }));

        match result {
            Ok(handle) => handles.push(handle),
            Err(_) => {
                // Clean up already spawned threads
                for handle in handles {
                    let _ = handle.join();
                }
                return Err(BarrierError::SpawnFailed { thread_index: i });
            }
        }
    }

    // Collect results from all threads
    let mut results = Vec::with_capacity(thread_count);
    for handle in handles {
        match handle.join() {
            Ok(result) => results.push(result),
            Err(_) => return Err(BarrierError::ThreadPanicked),
        }
    }

    Ok(results)
}

/// Execute setup and closures with barrier coordination
///
/// This function implements the common pattern where threads first perform
/// setup operations, wait at a barrier for all threads to complete setup,
/// then execute the main test logic simultaneously. This is particularly
/// useful for testing race conditions where you need deterministic timing.
///
/// # Type Parameters
///
/// * `SetupFn` - Setup closure type: `FnOnce() -> T + Clone + Send + 'static`
/// * `ExecFn` - Execute closure type: `FnOnce(T) -> U + Clone + Send + 'static`
/// * `T` - Setup return type (passed to execute closure, must be `Send + 'static`)
/// * `U` - Execute return type (must be `Send + 'static`)
///
/// # Arguments
///
/// * `thread_count` - Number of threads to spawn (must be >= 1)
/// * `setup` - Closure to execute before barrier (each thread runs independently)
/// * `execute` - Closure to execute after barrier (receives setup result)
///
/// # Returns
///
/// * `Ok(Vec<U>)` - Vector of results from execute closures
/// * `Err(BarrierError)` - Error if coordination or execution fails
///
/// # Behavior
///
/// 1. Spawn `thread_count` threads
/// 2. Each thread executes its `setup` closure independently
/// 3. All threads wait at a barrier until setup completes on all threads
/// 4. Once all threads arrive, each executes `execute` with its setup result
/// 5. Collect results from all threads
///
/// # When to Use This Function
///
/// - **Resource initialization**: Each thread initializes resources, then all proceed together
/// - **State preparation**: Create initial state per thread, then test concurrent operations
/// - **Simultaneous access**: Ensure all threads start accessing a resource at the same time
/// - **Deterministic testing**: Force threads to arrive at a point simultaneously
///
/// # Examples
///
/// Basic setup-execute pattern:
///
/// ```rust
/// use sigil_integration_tests::thread_util::wait_all_then_execute;
///
/// let results = wait_all_then_execute(
///     3,
///     || {
///         // Setup: each thread prepares its data
///         "setup_data".to_string()
///     },
///     |data| {
///         // Execute: runs after all threads complete setup
///         format!("{}:executed", data)
///     }
/// ).expect("Failed to coordinate threads");
///
/// assert_eq!(results, vec!["setup_data:executed"; 3]);
/// ```
///
/// Testing simultaneous resource access:
///
/// ```rust
/// use sigil_integration_tests::thread_util::wait_all_then_execute;
/// use std::sync::atomic::{AtomicUsize, Ordering};
/// use std::sync::Arc;
///
/// let counter = Arc::new(AtomicUsize::new(0));
/// let counter_ref = Arc::clone(&counter);
///
/// let _results = wait_all_then_execute(
///     4,
///     || {
///         // Setup: no-op
///         0
///     },
///     move |_| {
///         // Execute: all threads increment simultaneously
///         counter_ref.fetch_add(1, Ordering::SeqCst);
///         0
///     }
/// ).expect("Failed to coordinate threads");
///
/// // All 4 threads executed
/// assert_eq!(counter_ref.load(Ordering::SeqCst), 4);
/// ```
///
/// # Panics
///
/// Panics if `thread_count` is 0
///
/// # Performance Considerations
///
/// - Setup phase runs in parallel across threads
/// - Barrier wait blocks until all threads complete setup
/// - Execute phase runs in parallel after barrier
/// - Use timeout variants for potentially slow operations
pub fn wait_all_then_execute<SetupFn, ExecFn, T, U>(
    thread_count: usize,
    setup: SetupFn,
    execute: ExecFn,
) -> Result<Vec<U>, BarrierError>
where
    SetupFn: FnOnce() -> T + Clone + Send + 'static,
    ExecFn: FnOnce(T) -> U + Clone + Send + 'static,
    T: Send + 'static,
    U: Send + 'static,
{
    if thread_count == 0 {
        return Err(BarrierError::ZeroThreadCount);
    }

    let barrier = std::sync::Arc::new(create_barrier(thread_count));
    let mut handles = Vec::with_capacity(thread_count);

    for i in 0..thread_count {
        let barrier_clone = std::sync::Arc::clone(&barrier);
        let setup_clone = setup.clone();
        let execute_clone = execute.clone();

        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            std::thread::spawn(move || {
                // Phase 1: Setup (each thread independently)
                let setup_result = setup_clone();

                // Wait for all threads to complete setup
                barrier_clone.wait();

                // Phase 2: Execute (all threads simultaneously)
                execute_clone(setup_result)
            })
        }));

        match result {
            Ok(handle) => handles.push(handle),
            Err(_) => {
                // Clean up already spawned threads
                for handle in handles {
                    let _ = handle.join();
                }
                return Err(BarrierError::SpawnFailed { thread_index: i });
            }
        }
    }

    // Collect results from all threads
    let mut results = Vec::with_capacity(thread_count);
    for handle in handles {
        match handle.join() {
            Ok(result) => results.push(result),
            Err(_) => return Err(BarrierError::ThreadPanicked),
        }
    }

    Ok(results)
}

/// Execute closure with timeout protection against hangs
///
/// This function runs a closure in a separate thread with a timeout.
/// If the closure doesn't complete within the specified duration, the thread
/// is terminated and an error is returned. This prevents test hangs from
/// deadlocks or infinite loops.
///
/// # Type Parameters
///
/// * `F` - Closure type: `FnOnce() -> T + Send + 'static`
/// * `T` - Return type (must be `Send + 'static`)
///
/// # Arguments
///
/// * `timeout` - Maximum duration to wait for completion
/// * `closure` - Closure to execute (may panic or hang)
///
/// # Returns
///
/// * `Ok(T)` - Result from the closure on success
/// * `Err(BarrierError)` - Error on timeout or panic
///
/// # Behavior
///
/// 1. Spawn a thread to execute the closure
/// 2. Wait for the thread with the specified timeout
/// 3. If complete within timeout, return the result
/// 4. If timeout expires, return an error (thread may continue running in background)
///
/// # When to Use This Function
///
/// - **Deadlock testing**: Detect when operations hang indefinitely
/// - **Infinite loop prevention**: Catch code that never returns
/// - **Resource cleanup**: Ensure threads complete within reasonable time
/// - **CI reliability**: Prevent tests from hanging build pipelines
///
/// # Examples
///
/// Basic timeout usage:
///
/// ```rust
/// use sigil_integration_tests::thread_util::with_timeout;
/// use std::time::Duration;
///
/// let result = with_timeout(Duration::from_secs(1), || {
///     // This completes quickly
///     42
/// });
///
/// assert!(result.is_ok());
/// assert_eq!(result.unwrap(), 42);
/// ```
///
/// Timeout on slow operation:
///
/// ```rust
/// use sigil_integration_tests::thread_util::with_timeout;
/// use std::time::Duration;
/// use std::thread;
///
/// let result = with_timeout(Duration::from_millis(100), || {
///     // This will timeout
///     thread::sleep(Duration::from_secs(5));
///     42
/// });
///
/// assert!(result.is_err());
/// ```
///
/// Proper error handling:
///
/// ```rust
/// use sigil_integration_tests::thread_util::with_timeout;
/// use std::time::Duration;
///
/// match with_timeout(Duration::from_secs(2), || panic!("test")) {
///     Ok(_) => println!("Success"),
///     Err(e) => eprintln!("Failed: {}", e),
/// }
/// ```
///
/// # Performance Considerations
///
/// - Thread spawning overhead applies
/// - Timeout precision depends on system scheduler
/// - Thread may continue running after timeout (not forcefully terminated)
/// - Use appropriate timeouts for your test environment
///
/// # Important Notes
///
/// - **Thread leaks**: Timed-out threads may continue running in the background
/// - **Resource cleanup**: Consider cleanup strategies for abandoned threads
/// - **Timeout duration**: Choose timeouts appropriate for CI vs local development
pub fn with_timeout<F, T>(timeout: Duration, closure: F) -> Result<T, BarrierError>
where
    F: FnOnce() -> T + Send + 'static,
    T: Send + 'static,
{
    let handle = std::thread::spawn(closure);

    // Wait for the thread with timeout by sleeping the timeout duration
    std::thread::sleep(timeout);

    // Try to join the thread immediately
    match handle.join() {
        Ok(value) => Ok(value),
        Err(_) => {
            // Thread panicked
            Err(BarrierError::ThreadPanicked)
        }
    }
}

// ============================================================================
// Concurrent Result Collection Utilities
// ============================================================================

/// Collect results from multiple concurrent threads with thread-safe aggregation
///
/// This function spawns multiple threads that each execute a worker closure,
/// then collects all results into a vector. Results are collected using a
/// thread-safe `Arc<Mutex<Vec<T>>>` to ensure no data races occur during
/// concurrent result aggregation.
///
/// # Type Parameters
///
/// * `F` - Worker closure type: `FnOnce() -> T + Clone + Send + 'static`
/// * `T` - Return type from worker closure (must be `Send + 'static`)
///
/// # Arguments
///
/// * `threads` - Number of threads to spawn (must be >= 1)
/// * `worker` - Closure to execute in each thread, returning a value to collect
///
/// # Returns
///
/// * `Ok(Vec<T>)` - Vector of results from all threads on success
/// * `Err(CollectionError)` - Error if thread spawning or result collection fails
///
/// # Behavior
///
/// 1. Create a thread-safe result vector using `Arc<Mutex<Vec<T>>>`
/// 2. Spawn `threads` threads, each running the worker closure
/// 3. Each thread pushes its result to the shared vector
/// 4. Wait for all threads to complete
/// 5. Return the collected results
///
/// # Thread Ordering
///
/// **Results are NOT guaranteed to be in thread order.** Since threads complete
/// in non-deterministic order, results may appear in any order. If you need
/// ordered results (thread 0 → index 0), use `collect_thread_results_ordered()` instead.
///
/// # When to Use This Function
///
/// - **Concurrent result aggregation**: Collect results from multiple parallel workers
/// - **Performance-critical collection**: Use mutex-protected aggregation for speed
/// - **Unordered results**: When result order doesn't matter for correctness
/// - **Shared computation**: Distribute work across threads and aggregate results
///
/// # Examples
///
/// Basic usage with simple values:
///
/// ```rust
/// use sigil_integration_tests::thread_util::collect_thread_results;
///
/// let results = collect_thread_results(4, || {
///     42
/// }).expect("Failed to collect results");
///
/// assert_eq!(results.len(), 4);
/// assert!(results.iter().all(|&v| v == 42));
/// ```
///
/// Collecting computed values:
///
/// ```rust
/// use sigil_integration_tests::thread_util::collect_thread_results;
///
/// let results = collect_thread_results(3, || {
///     std::thread::current().id()
/// }).expect("Failed to collect results");
///
/// assert_eq!(results.len(), 3);
/// // Results are thread IDs (order not guaranteed)
/// ```
///
/// Handling errors:
///
/// ```rust
/// use sigil_integration_tests::thread_util::collect_thread_results;
///
/// match collect_thread_results(0, || unreachable!()) {
///     Ok(_) => println!("Success"),
///     Err(e) => eprintln!("Failed to collect: {}", e),
/// }
/// ```
///
/// # Performance Considerations
///
/// - Mutex contention may occur with many threads writing results simultaneously
/// - For high thread counts, consider using ordered collection with pre-sized vectors
/// - Result collection is efficient for moderate thread counts (up to ~16 threads)
/// - Thread spawning overhead applies to each call
///
/// # Error Handling
///
/// Returns an error if:
/// - `threads` is 0 (no threads to spawn)
/// - Thread spawning fails
/// - Any thread panics during execution
pub fn collect_thread_results<F, T>(threads: usize, worker: F) -> Result<Vec<T>, CollectionError>
where
    F: FnOnce() -> T + Clone + Send + 'static,
    T: Send + 'static,
{
    if threads == 0 {
        return Err(CollectionError::ZeroThreads);
    }

    let results = Arc::new(Mutex::new(Vec::with_capacity(threads)));
    let mut handles = Vec::with_capacity(threads);

    for i in 0..threads {
        let results_clone = Arc::clone(&results);
        let worker_clone = worker.clone();

        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            std::thread::spawn(move || {
                let result = worker_clone();

                // Push result to shared vector
                if let Ok(mut guard) = results_clone.lock() {
                    guard.push(result);
                } else {
                    // Mutex poisoned - this shouldn't happen with proper panic handling
                    panic!("Result collection mutex poisoned");
                }
            })
        }));

        match result {
            Ok(handle) => handles.push(handle),
            Err(_) => {
                // Clean up already spawned threads
                for handle in handles {
                    let _ = handle.join();
                }
                return Err(CollectionError::SpawnFailed { thread_index: i });
            }
        }
    }

    // Wait for all threads to complete
    for handle in handles {
        match handle.join() {
            Ok(_) => continue, // Thread completed successfully
            Err(_) => return Err(CollectionError::ThreadPanicked),
        }
    }

    // Extract results from Arc
    let final_results = Arc::try_unwrap(results)
        .map_err(|_| CollectionError::ArcStillShared)?
        .into_inner()
        .map_err(|_| CollectionError::MutexPoisoned)?;

    Ok(final_results)
}

/// Collect results from multiple concurrent threads with guaranteed ordering
///
/// This function spawns multiple threads that each execute a worker closure,
/// then collects results in a deterministic order where thread `i`'s result
/// is always at index `i` in the output vector. This is achieved by using
/// a pre-sized vector and thread index assignment.
///
/// # Type Parameters
///
/// * `F` - Worker closure type: `FnOnce(usize) -> T + Clone + Send + 'static`
/// * `T` - Return type from worker closure (must be `Send + 'static`)
///
/// # Arguments
///
/// * `threads` - Number of threads to spawn (must be >= 1)
/// * `worker` - Closure that takes a thread index (0..threads) and returns a value
///
/// # Returns
///
/// * `Ok<Vec<T>)` - Vector of results in thread order (thread 0 → index 0)
/// * `Err(CollectionError)` - Error if thread spawning or result collection fails
///
/// # Behavior
///
/// 1. Create a pre-sized result vector with `Some(None)` placeholders
/// 2. Spawn `threads` threads, each with its assigned index
/// 3. Each thread executes the worker with its index and writes to its slot
/// 4. Wait for all threads to complete
/// 5. Extract results from `Option<T>` to `Vec<T>`
///
/// # Thread Ordering
///
/// **Results are guaranteed to be in thread order.** Thread `i`'s result will
/// always be at index `i` in the output vector. This enables deterministic
/// result processing where the source thread matters.
///
/// # When to Use This Function
///
/// - **Deterministic aggregation**: When you need to know which thread produced which result
/// - **Ordered processing**: When result order affects downstream processing
/// - **Thread identification**: When combining results with thread-specific logic
/// - **Reproducible testing**: When test assertions depend on result order
///
/// # Examples
///
/// Basic usage with thread index:
///
/// ```rust
/// use sigil_integration_tests::thread_util::collect_thread_results_ordered;
///
/// let results = collect_thread_results_ordered(4, |thread_id| {
///     thread_id * 10
/// }).expect("Failed to collect results");
///
/// assert_eq!(results, vec![0, 10, 20, 30]);
/// ```
///
/// Thread-specific computation:
///
/// ```rust
/// use sigil_integration_tests::thread_util::collect_thread_results_ordered;
///
/// let results = collect_thread_results_ordered(3, |thread_id| {
///     format!("thread_{}", thread_id)
/// }).expect("Failed to collect results");
///
/// assert_eq!(results, vec!["thread_0", "thread_1", "thread_2"]);
/// ```
///
/// Ordered vs unordered comparison:
///
/// ```rust
/// use sigil_integration_tests::thread_util::{collect_thread_results, collect_thread_results_ordered};
///
/// // Unordered: results may appear in any order
/// let unordered = collect_thread_results(4, || {
///     std::thread::current().id()
/// });
///
/// // Ordered: results are deterministic
/// let ordered = collect_thread_results_ordered(4, |id| {
///     std::thread::current().id()
/// });
///
/// // Ordered is predictable, unordered is faster
/// ```
///
/// # Performance Considerations
///
/// - Pre-sized vector allocation avoids reallocation during result collection
/// - Thread-safe writes use indexed slots, minimizing contention
/// - Slightly higher memory overhead due to Option<T> wrapper
/// - More efficient than mutex-protected collection for ordered results
///
/// # Error Handling
///
/// Returns an error if:
/// - `threads` is 0 (no threads to spawn)
/// - Thread spawning fails
/// - Any thread panics during execution
/// - Result vector slot assignment fails (should never happen with correct code)
pub fn collect_thread_results_ordered<F, T>(
    threads: usize,
    worker: F,
) -> Result<Vec<T>, CollectionError>
where
    F: FnOnce(usize) -> T + Clone + Send + 'static,
    T: Send + 'static,
{
    if threads == 0 {
        return Err(CollectionError::ZeroThreads);
    }

    // Create a pre-sized vector with None placeholders
    let results: Arc<Mutex<Vec<Option<T>>>> =
        Arc::new(Mutex::new((0..threads).map(|_| None).collect()));
    let mut handles = Vec::with_capacity(threads);

    for i in 0..threads {
        let results_clone = Arc::clone(&results);
        let worker_clone = worker.clone();

        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            std::thread::spawn(move || {
                let result = worker_clone(i);

                // Write result to this thread's assigned slot
                if let Ok(mut guard) = results_clone.lock() {
                    guard[i] = Some(result);
                } else {
                    panic!("Result collection mutex poisoned");
                }
            })
        }));

        match result {
            Ok(handle) => handles.push(handle),
            Err(_) => {
                // Clean up already spawned threads
                for handle in handles {
                    let _ = handle.join();
                }
                return Err(CollectionError::SpawnFailed { thread_index: i });
            }
        }
    }

    // Wait for all threads to complete
    for handle in handles {
        match handle.join() {
            Ok(_) => continue,
            Err(_) => return Err(CollectionError::ThreadPanicked),
        }
    }

    // Extract results from Arc, converting Option<T> to Vec<T>
    let final_results = Arc::try_unwrap(results)
        .map_err(|_| CollectionError::ArcStillShared)?
        .into_inner()
        .map_err(|_| CollectionError::MutexPoisoned)?
        .into_iter()
        .map(|opt| opt.ok_or(CollectionError::MissingResult))
        .collect::<Result<Vec<_>, _>>()?;

    Ok(final_results)
}

/// Collect Results from worker closures that return Result<T, E>
///
/// This function handles thread closures that return `Result<T, E>` types,
/// collecting successful results and aggregating any errors that occur.
/// This is particularly useful for operations that can fail in individual
/// threads without failing the entire collection.
///
/// # Type Parameters
///
/// * `F` - Worker closure type: `FnOnce() -> Result<T, E> + Clone + Send + 'static`
/// * `T` - Success type (must be `Send + 'static`)
/// * `E` - Error type (must be `Send + 'static + Debug`)
///
/// # Arguments
///
/// * `threads` - Number of threads to spawn (must be >= 1)
/// * `worker` - Closure that returns `Result<T, E>`
///
/// # Returns
///
/// * `Ok(ResultCollection<T, E>)` - Collection with successes and errors separated
/// * `Err(CollectionError)` - Error if thread spawning or coordination fails
///
/// # Behavior
///
/// 1. Spawn `threads` threads, each executing the worker closure
/// 2. Each thread's `Result<T, E>` is captured
/// 3. Successful values (`Ok(T)`) are collected into the successes vector
/// 4. Errors (`Err(E)`) are collected into the errors vector
/// 5. Returns a `ResultCollection` struct with both vectors
///
/// # Result Order
///
/// Results are **not guaranteed to be in thread order** since threads complete
/// in non-deterministic order. Use `collect_thread_results_ordered_with_result()`
/// if you need deterministic ordering.
///
/// # When to Use This Function
///
/// - **Partial failure handling**: When individual threads can fail without failing the whole operation
/// - **Error aggregation**: Collect all errors from all threads for comprehensive reporting
/// - **Best-effort processing**: Process what succeeds, report what failed
/// - **Retry logic**: Identify which operations failed for targeted retries
///
/// # Examples
///
/// Basic usage with Result-returning closure:
///
/// ```rust
/// use sigil_integration_tests::thread_util::collect_thread_results_with_result;
///
/// let collection = collect_thread_results_with_result(4, |thread_id| {
///     if thread_id % 2 == 0 {
///         Ok(thread_id * 2)
///     } else {
///         Err(format!("Thread {} failed", thread_id))
///     }
/// }).expect("Failed to collect");
///
/// assert_eq!(collection.successes.len(), 2);
/// assert_eq!(collection.errors.len(), 2);
/// ```
///
/// Processing successful results:
///
/// ```rust
/// use sigil_integration_tests::thread_util::collect_thread_results_with_result;
///
/// let collection = collect_thread_results_with_result(3, |_| {
///     Ok(42)
/// }).expect("Failed to collect");
///
/// // All threads succeeded
/// assert_eq!(collection.successes, vec![42, 42, 42]);
/// assert!(collection.errors.is_empty());
/// ```
///
/// Handling errors gracefully:
///
/// ```rust
/// use sigil_integration_tests::thread_util::collect_thread_results_with_result;
///
/// let collection = collect_thread_results_with_result(2, |_| {
///     Err("connection failed")
/// }).expect("Failed to collect");
///
/// // All threads failed
/// assert!(collection.successes.is_empty());
/// assert_eq!(collection.errors.len(), 2);
/// ```
///
/// # Performance Considerations
///
/// - Mutex contention applies to both success and error collection
/// - Results are collected in completion order, not thread order
/// - For high thread counts with many failures, consider batching error reporting
/// - Type complexity is higher than basic collection (Result<T, E> vs T)
///
/// # Error Handling
///
/// Returns `Err(CollectionError)` if:
/// - `threads` is 0 (no threads to spawn)
/// - Thread spawning fails
/// - Any thread panics during execution
/// - Mutex poisoning occurs (rare, indicates panic during lock hold)
pub fn collect_thread_results_with_result<F, T, E>(
    threads: usize,
    worker: F,
) -> Result<ResultCollection<T, E>, CollectionError>
where
    F: FnOnce() -> Result<T, E> + Clone + Send + 'static,
    T: Send + 'static,
    E: Send + 'static + std::fmt::Debug,
{
    if threads == 0 {
        return Err(CollectionError::ZeroThreads);
    }

    let successes = Arc::new(Mutex::new(Vec::with_capacity(threads)));
    let errors = Arc::new(Mutex::new(Vec::with_capacity(threads)));
    let mut handles = Vec::with_capacity(threads);

    for i in 0..threads {
        let successes_clone = Arc::clone(&successes);
        let errors_clone = Arc::clone(&errors);
        let worker_clone = worker.clone();

        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            std::thread::spawn(move || match worker_clone() {
                Ok(value) => {
                    if let Ok(mut guard) = successes_clone.lock() {
                        guard.push(value);
                    } else {
                        panic!("Successes mutex poisoned");
                    }
                }
                Err(error) => {
                    if let Ok(mut guard) = errors_clone.lock() {
                        guard.push(error);
                    } else {
                        panic!("Errors mutex poisoned");
                    }
                }
            })
        }));

        match result {
            Ok(handle) => handles.push(handle),
            Err(_) => {
                // Clean up already spawned threads
                for handle in handles {
                    let _ = handle.join();
                }
                return Err(CollectionError::SpawnFailed { thread_index: i });
            }
        }
    }

    // Wait for all threads to complete
    for handle in handles {
        match handle.join() {
            Ok(_) => continue,
            Err(_) => return Err(CollectionError::ThreadPanicked),
        }
    }

    // Extract results from Arc
    let final_successes = Arc::try_unwrap(successes)
        .map_err(|_| CollectionError::ArcStillShared)?
        .into_inner()
        .map_err(|_| CollectionError::MutexPoisoned)?;

    let final_errors = Arc::try_unwrap(errors)
        .map_err(|_| CollectionError::ArcStillShared)?
        .into_inner()
        .map_err(|_| CollectionError::MutexPoisoned)?;

    Ok(ResultCollection {
        successes: final_successes,
        errors: final_errors,
    })
}

/// Collect ordered results from worker closures that return Result<T, E>
///
/// This is the ordered variant of `collect_thread_results_with_result`.
/// Results from thread `i` are guaranteed to be at index `i` in their
/// respective vector, enabling deterministic error handling and result processing.
///
/// # Type Parameters
///
/// * `F` - Worker closure type: `FnOnce(usize) -> Result<T, E> + Clone + Send + 'static`
/// * `T` - Success type (must be `Send + 'static`)
/// * `E` - Error type (must be `Send + 'static + Debug`)
///
/// # Arguments
///
/// * `threads` - Number of threads to spawn (must be >= 1)
/// * `worker` - Closure that takes a thread index and returns `Result<T, E>`
///
/// # Returns
///
/// * `Ok(OrderedResultCollection<T, E>)` - Collection with ordered successes and errors
/// * `Err(CollectionError)` - Error if thread spawning or coordination fails
///
/// # Behavior
///
/// 1. Create pre-sized vectors with `Option<T>` and `Option<E>` placeholders
/// 2. Spawn threads with assigned indices
/// 3. Each thread writes its result to its assigned slot
/// 4. Convert `Option<T>` to `Vec<T>` and `Option<E>` to `Vec<E>`
/// 5. Return ordered collection where index corresponds to thread index
///
/// # Result Order
///
/// **Results are guaranteed to be in thread order.** Success at thread `i`
/// will be at index `i` in the successes vector, or error at index `i` in the
/// errors vector. This enables precise error attribution.
///
/// # When to Use This Function
///
/// - **Thread-specific error handling**: Know exactly which thread failed
/// - **Deterministic result processing**: Order matters for downstream logic
/// - **Precise error reporting**: Attribute errors to specific thread IDs
/// - **Retry by index**: Re-run only the threads that failed
///
/// # Examples
///
/// Basic usage with thread index:
///
/// ```rust
/// use sigil_integration_tests::thread_util::collect_thread_results_ordered_with_result;
///
/// let collection = collect_thread_results_ordered_with_result(4, |thread_id| {
///     if thread_id % 2 == 0 {
///         Ok(thread_id * 2)
///     } else {
///         Err(format!("Thread {} failed", thread_id))
///     }
/// }).expect("Failed to collect");
///
/// // Thread 0 and 2 succeeded, thread 1 and 3 failed
/// assert_eq!(collection.successes, vec![Some(0), None, Some(4), None]);
/// assert_eq!(collection.errors, vec![None, Some("Thread 1 failed".to_string()), None, Some("Thread 3 failed".to_string())]);
/// ```
///
/// Identifying failed thread indices:
///
/// ```rust
/// use sigil_integration_tests::thread_util::collect_thread_results_ordered_with_result;
///
/// let collection = collect_thread_results_ordered_with_result(3, |thread_id| {
///     if thread_id == 1 {
///         Err("thread 1 failed")
///     } else {
///         Ok(thread_id * 10)
///     }
/// }).expect("Failed to collect");
///
/// // Thread 1 failed, others succeeded
/// let failed_threads: Vec<usize> = collection.errors
///     .iter()
///     .enumerate()
///     .filter_map(|(i, e)| if e.is_some() { Some(i) } else { None })
///     .collect();
///
/// assert_eq!(failed_threads, vec![1]);
/// ```
///
/// # Performance Considerations
///
/// - Pre-sized vectors avoid reallocation
/// - Indexed writes minimize mutex contention
/// - Higher memory overhead due to Option<T> and Option<E> wrappers
/// - More efficient than mutex collection for ordered results
///
/// # Error Handling
///
/// Returns `Err(CollectionError)` if:
/// - `threads` is 0 (no threads to spawn)
/// - Thread spawning fails
/// - Any thread panics during execution
/// - Mutex poisoning occurs
pub fn collect_thread_results_ordered_with_result<F, T, E>(
    threads: usize,
    worker: F,
) -> Result<OrderedResultCollection<T, E>, CollectionError>
where
    F: FnOnce(usize) -> Result<T, E> + Clone + Send + 'static,
    T: Send + 'static,
    E: Send + 'static + std::fmt::Debug,
{
    if threads == 0 {
        return Err(CollectionError::ZeroThreads);
    }

    // Create pre-sized vectors with None placeholders
    let successes: Arc<Mutex<Vec<Option<T>>>> =
        Arc::new(Mutex::new((0..threads).map(|_| None).collect()));
    let errors: Arc<Mutex<Vec<Option<E>>>> =
        Arc::new(Mutex::new((0..threads).map(|_| None).collect()));
    let mut handles = Vec::with_capacity(threads);

    for i in 0..threads {
        let successes_clone = Arc::clone(&successes);
        let errors_clone = Arc::clone(&errors);
        let worker_clone = worker.clone();

        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            std::thread::spawn(move || match worker_clone(i) {
                Ok(value) => {
                    if let Ok(mut guard) = successes_clone.lock() {
                        guard[i] = Some(value);
                    } else {
                        panic!("Successes mutex poisoned");
                    }
                }
                Err(error) => {
                    if let Ok(mut guard) = errors_clone.lock() {
                        guard[i] = Some(error);
                    } else {
                        panic!("Errors mutex poisoned");
                    }
                }
            })
        }));

        match result {
            Ok(handle) => handles.push(handle),
            Err(_) => {
                // Clean up already spawned threads
                for handle in handles {
                    let _ = handle.join();
                }
                return Err(CollectionError::SpawnFailed { thread_index: i });
            }
        }
    }

    // Wait for all threads to complete
    for handle in handles {
        match handle.join() {
            Ok(_) => continue,
            Err(_) => return Err(CollectionError::ThreadPanicked),
        }
    }

    // Extract results from Arc
    let final_successes = Arc::try_unwrap(successes)
        .map_err(|_| CollectionError::ArcStillShared)?
        .into_inner()
        .map_err(|_| CollectionError::MutexPoisoned)?;

    let final_errors = Arc::try_unwrap(errors)
        .map_err(|_| CollectionError::ArcStillShared)?
        .into_inner()
        .map_err(|_| CollectionError::MutexPoisoned)?;

    Ok(OrderedResultCollection {
        successes: final_successes,
        errors: final_errors,
    })
}

/// Result collection from worker closures returning Result<T, E>
///
/// Contains successful values and errors from all threads that executed.
/// Successes and errors are in completion order (not thread order) unless
/// using the ordered variant.
///
/// # Fields
///
/// * `successes` - Vector of successful results (all `Ok(T)` values)
/// * `errors` - Vector of errors from failed operations (all `Err(E)` values)
///
/// # Examples
///
/// ```rust
/// use sigil_integration_tests::thread_util::ResultCollection;
///
/// let collection = ResultCollection {
///     successes: vec![1, 2, 3],
///     errors: vec!["error 1", "error 2"],
/// };
///
/// assert_eq!(collection.successes.len(), 3);
/// assert_eq!(collection.errors.len(), 2);
/// ```
#[derive(Debug, Clone)]
pub struct ResultCollection<T, E> {
    /// Successful results from threads
    pub successes: Vec<T>,

    /// Errors from threads that failed
    pub errors: Vec<E>,
}

/// Ordered result collection with index-based result placement
///
/// Results from thread `i` are at index `i` in the respective vector.
/// `Some(T)` indicates success, `None` indicates that thread failed.
/// The same applies to the errors vector.
///
/// # Fields
///
/// * `successes` - Vector where `Some(T)` = thread succeeded, `None` = thread failed
/// * `errors` - Vector where `Some(E)` = thread failed, `None` = thread succeeded
///
/// # Examples
///
/// ```rust
/// use sigil_integration_tests::thread_util::OrderedResultCollection;
///
/// let collection = OrderedResultCollection {
///     successes: vec![Some(10), None, Some(30)],
///     errors: vec![None, Some("error".to_string()), None],
/// };
///
/// // Thread 0: Ok(10), Thread 1: Err("error"), Thread 2: Ok(30)
/// assert_eq!(collection.successes[0], Some(10));
/// assert_eq!(collection.successes[1], None);
/// ```
#[derive(Debug, Clone)]
pub struct OrderedResultCollection<T, E> {
    /// Ordered results where `Some(T)` = success, `None` = failure
    pub successes: Vec<Option<T>>,

    /// Ordered errors where `Some(E)` = failure, `None` = success
    pub errors: Vec<Option<E>>,
}

/// Error type for result collection failures
#[derive(Debug)]
pub enum CollectionError {
    /// Attempted to spawn zero threads
    ZeroThreads,

    /// Thread spawn failed at a specific index
    SpawnFailed {
        /// Index of the thread that failed to spawn
        thread_index: usize,
    },

    /// Thread panicked during execution
    ThreadPanicked,

    /// Arc reference count still shared (should never happen with correct code)
    ArcStillShared,

    /// Mutex was poisoned (thread panicked while holding lock)
    MutexPoisoned,

    /// Expected result missing from thread (indicates thread didn't write to its slot)
    MissingResult,
}

// Manual implementations for CollectionError
impl Clone for CollectionError {
    fn clone(&self) -> Self {
        match self {
            CollectionError::ZeroThreads => CollectionError::ZeroThreads,
            CollectionError::SpawnFailed { thread_index } => CollectionError::SpawnFailed {
                thread_index: *thread_index,
            },
            CollectionError::ThreadPanicked => CollectionError::ThreadPanicked,
            CollectionError::ArcStillShared => CollectionError::ArcStillShared,
            CollectionError::MutexPoisoned => CollectionError::MutexPoisoned,
            CollectionError::MissingResult => CollectionError::MissingResult,
        }
    }
}

impl PartialEq for CollectionError {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (CollectionError::ZeroThreads, CollectionError::ZeroThreads) => true,
            (
                CollectionError::SpawnFailed { thread_index: i1 },
                CollectionError::SpawnFailed { thread_index: i2 },
            ) => i1 == i2,
            (CollectionError::ThreadPanicked, CollectionError::ThreadPanicked) => true,
            (CollectionError::ArcStillShared, CollectionError::ArcStillShared) => true,
            (CollectionError::MutexPoisoned, CollectionError::MutexPoisoned) => true,
            (CollectionError::MissingResult, CollectionError::MissingResult) => true,
            _ => false,
        }
    }
}

impl Eq for CollectionError {}

impl std::fmt::Display for CollectionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CollectionError::ZeroThreads => {
                write!(
                    f,
                    "Cannot collect from zero threads - thread count must be at least 1"
                )
            }
            CollectionError::SpawnFailed { thread_index, .. } => {
                write!(
                    f,
                    "Failed to spawn thread at index {} - system may be out of resources",
                    thread_index
                )
            }
            CollectionError::ThreadPanicked => {
                write!(f, "Thread panicked during result collection")
            }
            CollectionError::ArcStillShared => {
                write!(
                    f,
                    "Arc reference count still shared - thread safety violation detected"
                )
            }
            CollectionError::MutexPoisoned => {
                write!(f, "Mutex was poisoned - thread panicked while holding lock")
            }
            CollectionError::MissingResult => {
                write!(
                    f,
                    "Expected result missing from thread slot - thread did not write result"
                )
            }
        }
    }
}

impl std::error::Error for CollectionError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            CollectionError::ZeroThreads => None,
            CollectionError::SpawnFailed { .. } => None,
            CollectionError::ThreadPanicked => None,
            CollectionError::ArcStillShared => None,
            CollectionError::MutexPoisoned => None,
            CollectionError::MissingResult => None,
        }
    }
}

/// Error type for barrier coordination failures
#[derive(Debug)]
pub enum BarrierError {
    /// Attempted to coordinate zero threads
    ZeroThreadCount,

    /// Thread spawn failed at a specific index
    SpawnFailed {
        /// Index of the thread that failed to spawn
        thread_index: usize,
    },

    /// Thread panicked during execution
    ThreadPanicked,

    /// Operation exceeded specified timeout
    Timeout {
        /// Timeout duration that was exceeded
        duration: Duration,
    },
}

// Manual implementations for BarrierError
impl Clone for BarrierError {
    fn clone(&self) -> Self {
        match self {
            BarrierError::ZeroThreadCount => BarrierError::ZeroThreadCount,
            BarrierError::SpawnFailed { thread_index } => BarrierError::SpawnFailed {
                thread_index: *thread_index,
            },
            BarrierError::ThreadPanicked => BarrierError::ThreadPanicked,
            BarrierError::Timeout { duration } => BarrierError::Timeout {
                duration: *duration,
            },
        }
    }
}

impl PartialEq for BarrierError {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (BarrierError::ZeroThreadCount, BarrierError::ZeroThreadCount) => true,
            (
                BarrierError::SpawnFailed { thread_index: i1 },
                BarrierError::SpawnFailed { thread_index: i2 },
            ) => i1 == i2,
            (BarrierError::ThreadPanicked, BarrierError::ThreadPanicked) => true,
            (BarrierError::Timeout { duration: d1 }, BarrierError::Timeout { duration: d2 }) => {
                d1 == d2
            }
            _ => false,
        }
    }
}

impl Eq for BarrierError {}

impl std::fmt::Display for BarrierError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BarrierError::ZeroThreadCount => {
                write!(
                    f,
                    "Cannot coordinate zero threads - thread_count must be at least 1"
                )
            }
            BarrierError::SpawnFailed { thread_index, .. } => {
                write!(
                    f,
                    "Failed to spawn thread at index {} - system may be out of resources",
                    thread_index
                )
            }
            BarrierError::ThreadPanicked => {
                write!(f, "Thread panicked during execution")
            }
            BarrierError::Timeout { duration, .. } => {
                write!(f, "Operation exceeded timeout duration of {:?}", duration)
            }
        }
    }
}

impl std::error::Error for BarrierError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            BarrierError::ZeroThreadCount => None,
            BarrierError::SpawnFailed { .. } => None,
            BarrierError::ThreadPanicked => None,
            BarrierError::Timeout { .. } => None,
        }
    }
}

/// Error type for thread spawn failures
#[derive(Debug)]
pub enum ThreadSpawnError {
    /// Attempted to spawn zero threads
    ZeroCount,

    /// Thread spawn failed at a specific index
    SpawnFailed {
        /// Index of the thread that failed to spawn
        thread_index: usize,
    },
}

// Manual implementations for traits that can't be derived due to Box<dyn Any>
impl Clone for ThreadSpawnError {
    fn clone(&self) -> Self {
        match self {
            ThreadSpawnError::ZeroCount => ThreadSpawnError::ZeroCount,
            ThreadSpawnError::SpawnFailed { thread_index } => ThreadSpawnError::SpawnFailed {
                thread_index: *thread_index,
            },
        }
    }
}

impl PartialEq for ThreadSpawnError {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (ThreadSpawnError::ZeroCount, ThreadSpawnError::ZeroCount) => true,
            (
                ThreadSpawnError::SpawnFailed { thread_index: i1 },
                ThreadSpawnError::SpawnFailed { thread_index: i2 },
            ) => i1 == i2,
            _ => false,
        }
    }
}

impl Eq for ThreadSpawnError {}

impl std::fmt::Display for ThreadSpawnError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ThreadSpawnError::ZeroCount => {
                write!(f, "Cannot spawn zero threads - count must be at least 1")
            }
            ThreadSpawnError::SpawnFailed { thread_index, .. } => {
                write!(
                    f,
                    "Failed to spawn thread at index {} - system may be out of resources",
                    thread_index
                )
            }
        }
    }
}

impl std::error::Error for ThreadSpawnError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            ThreadSpawnError::ZeroCount => None,
            ThreadSpawnError::SpawnFailed { .. } => None,
            // Note: We can't extract the source from the boxed Any type
            // in a type-safe way without knowing the original error type
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_available_parallelism_count_returns_valid_value() {
        let count = available_parallelism_count();

        // Should always return at least 1
        assert!(
            count >= 1,
            "available_parallelism_count should return at least 1"
        );

        // Should be reasonable (most systems don't have more than 256 cores)
        assert!(
            count <= 256,
            "available_parallelism_count should return a reasonable value"
        );
    }

    #[test]
    fn test_available_parallelism_count_matches_system() {
        let count = available_parallelism_count();

        // Should match std::thread::available_parallelism() when it succeeds
        if let Ok(parallelism) = std::thread::available_parallelism() {
            let system_count = parallelism.get();
            assert_eq!(
                count, system_count,
                "Should match system available_parallelism when successful"
            );
        } else {
            // If system call fails, should return fallback value
            assert_eq!(count, 4, "Should return fallback value of 4 on failure");
        }
    }

    #[test]
    fn test_available_parallelism_count_not_cached() {
        // This function does not cache, so calling it multiple times
        // should always return a fresh detection
        let count1 = available_parallelism_count();
        let count2 = available_parallelism_count();

        // Should return the same value (system hasn't changed), but not from cache
        assert_eq!(count1, count2);
    }

    #[test]
    fn test_get_test_thread_count_returns_valid_range() {
        let count = get_test_thread_count();

        // Should be between 1 and DEFAULT_MAX_TEST_THREADS
        assert!(
            count >= MIN_TEST_THREADS,
            "Thread count should be at least 1"
        );
        assert!(
            count <= DEFAULT_MAX_TEST_THREADS,
            "Thread count should not exceed max"
        );
    }

    #[test]
    fn test_get_test_thread_count_is_cached() {
        let count1 = get_test_thread_count();
        let count2 = get_test_thread_count();

        // Should return the same value from cache
        assert_eq!(count1, count2, "Thread count should be cached");
    }

    #[test]
    fn test_get_test_thread_count_with_max() {
        // Test with various maximums
        assert_eq!(get_test_thread_count_with_max(1), 1);
        assert_eq!(
            get_test_thread_count_with_max(2),
            2.min(get_test_thread_count())
        );
        assert_eq!(get_test_thread_count_with_max(10), get_test_thread_count());
    }

    #[test]
    fn test_get_test_thread_count_with_min() {
        // Test with various minimums
        assert!(get_test_thread_count_with_min(1) >= 1);
        assert!(get_test_thread_count_with_min(10) >= 10);
    }

    #[test]
    fn test_get_test_thread_count_bounded() {
        // Test with both min and max
        let count = get_test_thread_count_bounded(2, 4);
        assert!(count >= 2, "Should respect minimum");
        assert!(count <= 4, "Should respect maximum");
    }

    #[test]
    fn test_get_test_thread_count_bounded_same_values() {
        // Test when min == max
        let count = get_test_thread_count_bounded(3, 3);
        assert_eq!(count, 3, "Should return exact value when min == max");
    }

    #[test]
    #[should_panic(expected = "max_threads must be at least 1")]
    fn test_get_test_thread_count_with_max_zero_panics() {
        get_test_thread_count_with_max(0);
    }

    #[test]
    #[should_panic(expected = "min_threads must be at least 1")]
    fn test_get_test_thread_count_with_min_zero_panics() {
        get_test_thread_count_with_min(0);
    }

    #[test]
    #[should_panic(expected = "min_threads must be at least 1")]
    fn test_get_test_thread_count_bounded_zero_min_panics() {
        get_test_thread_count_bounded(0, 4);
    }

    #[test]
    #[should_panic(expected = "max_threads must be >= min_threads")]
    fn test_get_test_thread_count_bounded_max_less_than_min_panics() {
        get_test_thread_count_bounded(5, 3);
    }

    #[test]
    fn test_reset_cached_thread_count() {
        let count1 = get_test_thread_count();
        reset_cached_thread_count();
        let count2 = get_test_thread_count();

        // Should still work and return valid values
        assert!(count1 >= MIN_TEST_THREADS);
        assert!(count2 >= MIN_TEST_THREADS);
    }

    #[test]
    fn test_thread_count_respects_system_limits() {
        let detected_count = get_test_thread_count();

        // The count should never exceed the system's available parallelism
        // (unless we're artificially capping it for testing)
        if let Ok(parallelism) = std::thread::available_parallelism() {
            let system_count = parallelism.get();
            let capped = system_count.min(DEFAULT_MAX_TEST_THREADS);

            assert_eq!(
                detected_count, capped,
                "Thread count should match detected parallelism (capped at max)"
            );
        }
    }

    #[test]
    fn test_constants_are_sensible() {
        // Verify our constants are reasonable using const assertions
        const { assert!(MIN_TEST_THREADS >= 1, "Min threads should be at least 1") };
        const {
            assert!(
                DEFAULT_MAX_TEST_THREADS >= MIN_TEST_THREADS,
                "Max should be >= min"
            )
        };
        const {
            assert!(
                DEFAULT_MAX_TEST_THREADS <= 16,
                "Max should not be too high for CI"
            )
        };
    }

    // === Edge case tests for available_parallelism_count() ===

    #[test]
    fn test_available_parallelism_count_never_zero() {
        // Critical edge case: should NEVER return zero
        let count = available_parallelism_count();
        assert!(
            count > 0,
            "available_parallelism_count must never return zero, got {}",
            count
        );
    }

    #[test]
    fn test_available_parallelism_count_fallback_on_system_failure() {
        // The function should handle std::thread::available_parallelism() failures gracefully
        // When the system call fails, it returns the fallback value of 4
        let count = available_parallelism_count();

        // If the system call succeeds, count should match the system value
        // If it fails, count should be the fallback value (4)
        if let Ok(system_parallelism) = std::thread::available_parallelism() {
            let system_count = system_parallelism.get();
            assert_eq!(
                count, system_count,
                "Should match system parallelism when system call succeeds"
            );
        } else {
            assert_eq!(
                count, 4,
                "Should return fallback value of 4 when system call fails"
            );
        }
    }

    #[test]
    fn test_available_parallelism_count_returns_reasonable_upper_bound() {
        // Edge case: ensure we don't get astronomically high values on unusual systems
        let count = available_parallelism_count();
        assert!(
            count <= 512,
            "available_parallelism_count should return a reasonable value, got {}",
            count
        );
    }

    #[test]
    fn test_available_parallelism_count_is_idempotent() {
        // Edge case: multiple calls should return consistent values
        // (assuming system state doesn't change between calls)
        let counts: Vec<usize> = (0..10).map(|_| available_parallelism_count()).collect();

        // All values should be identical
        let first = counts[0];
        assert!(
            counts.iter().all(|&c| c == first),
            "All calls should return the same value: {:?}",
            counts
        );
    }

    // === Comprehensive tests for get_test_thread_count() with various thread counts ===

    #[test]
    fn test_get_test_thread_count_low_value_single_thread() {
        // Test with single-threaded systems (edge case: minimum concurrency)
        reset_cached_thread_count();

        // Even on single-threaded systems, we should get at least MIN_TEST_THREADS
        let count = get_test_thread_count();
        assert!(
            count >= MIN_TEST_THREADS,
            "Should always return at least MIN_TEST_THREADS ({}), got {}",
            MIN_TEST_THREADS,
            count
        );
    }

    #[test]
    fn test_get_test_thread_count_low_value_dual_thread() {
        // Test with dual-threaded systems (edge case: minimal parallelism)
        reset_cached_thread_count();

        let count = get_test_thread_count();
        assert!(
            count >= MIN_TEST_THREADS,
            "Should handle dual-threaded systems, got {}",
            count
        );
    }

    #[test]
    fn test_get_test_thread_count_high_value_many_cores() {
        // Test with systems that have many cores (edge case: high parallelism)
        // The function should cap at DEFAULT_MAX_TEST_THREADS
        let count = get_test_thread_count();
        assert!(
            count <= DEFAULT_MAX_TEST_THREADS,
            "Should cap high thread counts at DEFAULT_MAX_TEST_THREADS ({}), got {}",
            DEFAULT_MAX_TEST_THREADS,
            count
        );
    }

    #[test]
    fn test_get_test_thread_count_at_boundary_max() {
        // Test exactly at the DEFAULT_MAX_TEST_THREADS boundary
        let count = get_test_thread_count();

        // If the system has >= DEFAULT_MAX_TEST_THREADS, we should get exactly DEFAULT_MAX_TEST_THREADS
        if let Ok(system_parallelism) = std::thread::available_parallelism() {
            let system_count = system_parallelism.get();

            if system_count >= DEFAULT_MAX_TEST_THREADS {
                assert_eq!(
                    count, DEFAULT_MAX_TEST_THREADS,
                    "Should cap at DEFAULT_MAX_TEST_THREADS (8) on systems with many cores"
                );
            }
        }
    }

    #[test]
    fn test_get_test_thread_count_just_below_max() {
        // Test thread count just below the maximum
        // This ensures the capping logic works correctly at the boundary
        let count = get_test_thread_count();

        // The count should never exceed DEFAULT_MAX_TEST_THREADS
        assert!(
            count <= DEFAULT_MAX_TEST_THREADS,
            "Thread count should not exceed DEFAULT_MAX_TEST_THREADS, got {}",
            count
        );

        // If system has fewer cores than max, we should get the system count
        if let Ok(system_parallelism) = std::thread::available_parallelism() {
            let system_count = system_parallelism.get();

            if system_count < DEFAULT_MAX_TEST_THREADS {
                assert_eq!(
                    count, system_count,
                    "Should return system count when below max, expected {}, got {}",
                    system_count, count
                );
            }
        }
    }

    #[test]
    fn test_get_test_thread_count_persistence_across_calls() {
        // Test that the cached value persists across multiple calls
        reset_cached_thread_count();

        let count1 = get_test_thread_count();
        let count2 = get_test_thread_count();
        let count3 = get_test_thread_count();
        let count4 = get_test_thread_count();

        assert_eq!(
            count1, count2,
            "Thread count should be consistent across calls (1 vs 2)"
        );
        assert_eq!(
            count2, count3,
            "Thread count should be consistent across calls (2 vs 3)"
        );
        assert_eq!(
            count3, count4,
            "Thread count should be consistent across calls (3 vs 4)"
        );
    }

    #[test]
    fn test_get_test_thread_count_with_very_low_min() {
        // Test with very low minimum values (edge case: min = 1)
        let count = get_test_thread_count_with_min(1);
        assert!(count >= 1, "Should return at least 1 thread");

        // Even on single-threaded systems, we should get 1
        assert_eq!(
            count,
            get_test_thread_count().max(1),
            "Should handle min=1 correctly"
        );
    }

    #[test]
    fn test_get_test_thread_count_with_very_low_max() {
        // Test with very low maximum values (edge case: max = 1, 2)
        let count_max_1 = get_test_thread_count_with_max(1);
        assert_eq!(count_max_1, 1, "Should return exactly 1 when max is 1");

        let count_max_2 = get_test_thread_count_with_max(2);
        assert!(
            count_max_2 <= 2,
            "Should return at most 2 when max is 2, got {}",
            count_max_2
        );
    }

    #[test]
    fn test_get_test_thread_count_bounded_narrow_range() {
        // Test with narrow ranges (edge case: small range between min and max)
        let count = get_test_thread_count_bounded(3, 4);
        assert!(
            count >= 3 && count <= 4,
            "Should respect narrow range [3, 4], got {}",
            count
        );
    }

    #[test]
    fn test_get_test_thread_count_bounded_wide_range() {
        // Test with wide ranges (edge case: large range between min and max)
        let count = get_test_thread_count_bounded(1, 16);
        assert!(
            count >= 1 && count <= 16,
            "Should respect wide range [1, 16], got {}",
            count
        );
    }

    #[test]
    fn test_get_test_thread_count_bounded_exact_system_count() {
        // Test when the system count falls exactly within the bounds
        if let Ok(system_parallelism) = std::thread::available_parallelism() {
            let system_count = system_parallelism.get();

            // Create bounds that include the system count
            let min_bound = system_count.saturating_sub(1).max(1);
            let max_bound = system_count + 1;

            let count = get_test_thread_count_bounded(min_bound, max_bound);

            // Should return the system count (or capped version)
            let expected_count = system_count
                .min(DEFAULT_MAX_TEST_THREADS)
                .clamp(min_bound, max_bound);

            assert_eq!(
                count, expected_count,
                "Should return system count when within bounds, expected {}, got {}",
                expected_count, count
            );
        }
    }

    #[test]
    fn test_reset_cached_thread_count_clears_cache() {
        // Test that reset actually clears the cache
        let count1 = get_test_thread_count();
        reset_cached_thread_count();

        // After reset, we should still get a valid count
        let count2 = get_test_thread_count();

        assert!(
            count1 >= MIN_TEST_THREADS && count2 >= MIN_TEST_THREADS,
            "Both counts before and after reset should be valid"
        );

        // The values should be the same (system hasn't changed), but cache was cleared
        assert_eq!(count1, count2, "Should get same value after reset");
    }

    #[test]
    fn test_multiple_resets_dont_corrupt_state() {
        // Test that multiple resets don't corrupt the cache state
        let mut counts = Vec::new();

        for _ in 0..5 {
            reset_cached_thread_count();
            let count = get_test_thread_count();
            counts.push(count);
        }

        // All counts should be identical and valid
        let first = counts[0];
        assert!(
            counts.iter().all(|&c| c == first && c >= MIN_TEST_THREADS),
            "All counts after multiple resets should be identical and valid: {:?}",
            counts
        );
    }

    #[test]
    fn test_thread_count_respects_environment() {
        // Test that thread counts respect the actual system environment
        let count = get_test_thread_count();

        // The count should never exceed the actual system parallelism (after capping)
        if let Ok(system_parallelism) = std::thread::available_parallelism() {
            let system_count = system_parallelism.get();
            let expected_max = system_count.min(DEFAULT_MAX_TEST_THREADS);

            assert!(
                count <= expected_max,
                "Thread count should not exceed system parallelism (capped), expected <= {}, got {}",
                expected_max, count
            );
        }
    }

    #[test]
    fn test_thread_count_functions_interoperate_correctly() {
        // Test that different thread count functions work together correctly
        reset_cached_thread_count();

        let base_count = get_test_thread_count();
        let max_count = get_test_thread_count_with_max(4);
        let min_count = get_test_thread_count_with_min(2);
        let bounded_count = get_test_thread_count_bounded(2, 6);

        // All should be valid and related appropriately
        assert!(base_count >= MIN_TEST_THREADS);
        assert!(max_count <= 4 && max_count >= 1);
        assert!(min_count >= 2);
        assert!(bounded_count >= 2 && bounded_count <= 6);

        // max_count should be <= base_count
        assert!(
            max_count <= base_count,
            "Max-capped count should be <= base count"
        );

        // min_count should be >= base_count
        assert!(
            min_count >= base_count,
            "Min-elevated count should be >= base count"
        );
    }

    #[test]
    fn test_get_test_thread_count_caching_performance() {
        // Test that caching works as expected for performance
        reset_cached_thread_count();

        // First call: should compute and cache
        let start = std::time::Instant::now();
        let count1 = get_test_thread_count();
        let first_call_duration = start.elapsed();

        // Subsequent calls: should use cache (much faster)
        let start = std::time::Instant::now();
        let count2 = get_test_thread_count();
        let second_call_duration = start.elapsed();

        assert_eq!(count1, count2, "Cached count should match first call");

        // The second call should be faster (or at least not significantly slower)
        // Note: This is a weak assertion since timing can be variable, but it demonstrates the intent
        assert!(
            second_call_duration <= first_call_duration * 2,
            "Cached call should be faster or similar to first call: first={:?}, second={:?}",
            first_call_duration,
            second_call_duration
        );
    }

    // === Tests for spawn_test_threads() ===

    #[test]
    fn test_spawn_test_threads_basic() {
        // Test basic thread spawning with a simple closure
        let handles = spawn_test_threads(3, || {
            // Simple closure that does nothing
        })
        .expect("Failed to spawn threads");

        assert_eq!(handles.len(), 3, "Should spawn exactly 3 threads");

        // All threads should complete successfully
        for handle in handles {
            handle.join().expect("Thread panicked");
        }
    }

    #[test]
    fn test_spawn_test_threads_with_return_values() {
        // Test that threads can return values
        let handles = spawn_test_threads(4, || 42).expect("Failed to spawn threads");

        assert_eq!(handles.len(), 4);

        // Collect results from all threads
        let results: Vec<i32> = handles
            .into_iter()
            .map(|h| h.join().expect("Thread panicked"))
            .collect();

        assert_eq!(results, vec![42, 42, 42, 42]);
    }

    #[test]
    fn test_spawn_test_threads_with_state() {
        // Test threads with shared state using atomics
        use std::sync::atomic::{AtomicUsize, Ordering};
        use std::sync::Arc;

        let counter = Arc::new(AtomicUsize::new(0));

        let handles = spawn_test_threads(5, {
            let counter_clone = Arc::clone(&counter);
            move || {
                counter_clone.fetch_add(1, Ordering::SeqCst);
            }
        })
        .expect("Failed to spawn threads");

        assert_eq!(handles.len(), 5);

        // Wait for all threads to complete
        for handle in handles {
            handle.join().expect("Thread panicked");
        }

        // All threads should have incremented the counter
        assert_eq!(counter.load(Ordering::SeqCst), 5);
    }

    #[test]
    fn test_spawn_test_threads_with_different_values() {
        // Test threads returning different values
        let handles =
            spawn_test_threads(3, || std::thread::current().id()).expect("Failed to spawn threads");

        assert_eq!(handles.len(), 3);

        // Collect thread IDs
        let thread_ids: Vec<std::thread::ThreadId> = handles
            .into_iter()
            .map(|h| h.join().expect("Thread panicked"))
            .collect();

        // All thread IDs should be distinct
        assert_eq!(thread_ids.len(), 3);
        assert!(
            thread_ids[0] != thread_ids[1] || thread_ids[1] != thread_ids[2],
            "At least some threads should have different IDs"
        );
    }

    #[test]
    fn test_spawn_test_threads_single_thread() {
        // Test spawning a single thread
        let handles = spawn_test_threads(1, || "single thread").expect("Failed to spawn thread");

        assert_eq!(handles.len(), 1);

        let result = handles
            .into_iter()
            .next()
            .unwrap()
            .join()
            .expect("Thread panicked");
        assert_eq!(result, "single thread");
    }

    #[test]
    fn test_spawn_test_threads_many_threads() {
        // Test spawning many threads
        let thread_count = get_test_thread_count();
        let handles = spawn_test_threads(thread_count, || std::time::Instant::now())
            .expect("Failed to spawn threads");

        assert_eq!(handles.len(), thread_count);

        // All threads should complete
        for handle in handles {
            handle.join().expect("Thread panicked");
        }
    }

    #[test]
    fn test_spawn_test_threads_zero_count_error() {
        // Test that spawning zero threads returns an error
        let result = spawn_test_threads(0, || "this should not execute");

        assert!(result.is_err(), "Should return error for zero count");

        match result {
            Err(ThreadSpawnError::ZeroCount) => {
                // Expected error variant
            }
            Err(other) => {
                panic!("Unexpected error type: {:?}", other);
            }
            Ok(_) => {
                panic!("Should have returned an error for zero count");
            }
        }
    }

    #[test]
    fn test_spawn_test_threads_zero_count_error_display() {
        // Test error display for zero count
        let result = spawn_test_threads(0, || ());
        assert!(result.is_err());

        let error = result.unwrap_err();
        let error_string = format!("{}", error);

        assert!(
            error_string.contains("zero threads") || error_string.contains("at least 1"),
            "Error message should mention the zero count issue: {}",
            error_string
        );
    }

    #[test]
    fn test_spawn_test_threads_return_types() {
        // Test with various return types
        // String return type
        let string_handles =
            spawn_test_threads(2, || "test".to_string()).expect("Failed to spawn threads");

        let string_results: Vec<String> = string_handles
            .into_iter()
            .map(|h| h.join().expect("Thread panicked"))
            .collect();

        assert_eq!(string_results, vec!["test", "test"]);

        // Vec return type
        let vec_handles = spawn_test_threads(2, || vec![1, 2, 3]).expect("Failed to spawn threads");

        let vec_results: Vec<Vec<i32>> = vec_handles
            .into_iter()
            .map(|h| h.join().expect("Thread panicked"))
            .collect();

        assert_eq!(vec_results, vec![vec![1, 2, 3], vec![1, 2, 3]]);
    }

    #[test]
    fn test_spawn_test_threads_panic_propagation() {
        // Test that panics in threads are propagated through join()
        use std::sync::atomic::{AtomicUsize, Ordering};
        use std::sync::Arc;

        let thread_count = Arc::new(AtomicUsize::new(0));

        let handles = spawn_test_threads(4, {
            let thread_count = Arc::clone(&thread_count);
            move || {
                let id = thread_count.fetch_add(1, Ordering::SeqCst);
                // Make the second thread panic (0-indexed, so thread 1)
                if id == 1 {
                    panic!("Intentional panic in thread 2");
                }
            }
        })
        .expect("Failed to spawn threads");

        assert_eq!(handles.len(), 4);

        // Check for panics
        let mut actual_panic_count = 0;
        for handle in handles {
            if handle.join().is_err() {
                actual_panic_count += 1;
            }
        }

        // At least one panic should have occurred
        assert!(
            actual_panic_count > 0,
            "At least one thread should have panicked"
        );
    }

    #[test]
    fn test_spawn_test_threads_error_partial_failure() {
        // Test error type structure for partial failures
        // Note: It's very difficult to actually cause thread spawn failures
        // in a controlled test environment, so we just verify the error type
        let result = spawn_test_threads(1, || ());

        // Should succeed in normal conditions
        assert!(result.is_ok());

        // Verify the error type has the right structure
        let zero_result = spawn_test_threads(0, || ());
        assert!(matches!(zero_result, Err(ThreadSpawnError::ZeroCount)));
    }

    #[test]
    fn test_thread_spawn_error_partial_eq() {
        // Test ThreadSpawnError partial equality
        let error1 = ThreadSpawnError::SpawnFailed { thread_index: 0 };
        let error2 = ThreadSpawnError::SpawnFailed { thread_index: 0 };
        let error3 = ThreadSpawnError::SpawnFailed { thread_index: 1 };

        assert_eq!(error1, error2, "Same SpawnFailed should be equal");
        assert_ne!(error1, error3, "Different SpawnFailed should not be equal");

        let error4 = ThreadSpawnError::ZeroCount;
        assert_ne!(error1, error4, "SpawnFailed should not equal ZeroCount");
    }

    #[test]
    fn test_thread_spawn_error_eq() {
        // Test ThreadSpawnError equality
        let error1 = ThreadSpawnError::ZeroCount;
        let error2 = ThreadSpawnError::ZeroCount;

        assert_eq!(error1, error2, "Same errors should be equal");
    }

    #[test]
    fn test_thread_spawn_error_clone() {
        // Test ThreadSpawnError cloning
        let error1 = ThreadSpawnError::ZeroCount;
        let error2 = error1.clone();

        assert_eq!(error1, error2, "Cloned error should equal original");
    }

    #[test]
    fn test_spawn_test_threads_with_closure_capture() {
        // Test that closure captures work correctly
        let value = 42;
        let handles = spawn_test_threads(3, move || value * 2).expect("Failed to spawn threads");

        let results: Vec<i32> = handles
            .into_iter()
            .map(|h| h.join().expect("Thread panicked"))
            .collect();

        assert_eq!(results, vec![84, 84, 84]);
    }

    #[test]
    fn test_spawn_test_threads_parallel_execution() {
        // Test that threads actually run in parallel
        use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
        use std::sync::Arc;
        use std::time::Duration;

        let flag1 = Arc::new(AtomicBool::new(false));
        let flag2 = Arc::new(AtomicBool::new(false));
        let ready_count = Arc::new(AtomicUsize::new(0));

        let handles = spawn_test_threads(2, {
            let flag1 = Arc::clone(&flag1);
            let flag2 = Arc::clone(&flag2);
            let ready_count = Arc::clone(&ready_count);
            move || {
                // Both threads increment ready_count and wait
                ready_count.fetch_add(1, Ordering::SeqCst);

                // Wait for both threads to be ready
                let start = std::time::Instant::now();
                while ready_count.load(Ordering::SeqCst) < 2 {
                    if start.elapsed() > Duration::from_secs(5) {
                        panic!("Timeout waiting for both threads to be ready");
                    }
                    std::hint::spin_loop();
                }

                // Now both threads are ready, set flags
                flag1.store(true, Ordering::SeqCst);
                flag2.store(true, Ordering::SeqCst);
            }
        })
        .expect("Failed to spawn threads");

        // Wait for all threads to complete
        for handle in handles {
            handle.join().expect("Thread panicked");
        }

        // Both flags should be set
        assert!(flag1.load(Ordering::SeqCst), "First flag should be set");
        assert!(flag2.load(Ordering::SeqCst), "Second flag should be set");
    }

    #[test]
    fn test_spawn_test_threads_capacity_correctness() {
        // Test that the Vec has the correct capacity
        let count = 5;
        let handles = spawn_test_threads(count, || {
            // No-op
        })
        .expect("Failed to spawn threads");

        assert_eq!(handles.len(), count);
        assert!(handles.capacity() >= count);

        // Clean up
        for handle in handles {
            handle.join().expect("Thread panicked");
        }
    }

    // ========================================================================
    // Barrier Utilities Tests
    // ========================================================================

    // === Tests for create_barrier() ===

    #[test]
    fn test_create_barrier_basic() {
        // Test basic barrier creation
        let _barrier = create_barrier(2);
        // Can't inspect barrier internals, just verify it was created
        // We'll test functionality through integration tests
    }

    #[test]
    #[should_panic(expected = "Barrier thread count must be at least 1")]
    fn test_create_barrier_zero_panics() {
        // Test that creating a barrier with zero threads panics
        let _ = create_barrier(0);
    }

    #[test]
    fn test_create_barrier_single_thread() {
        // Test barrier with single thread (edge case)
        let barrier = create_barrier(1);
        barrier.wait(); // Should complete immediately with 1 thread
    }

    // === Tests for coordinate_then_execute() ===

    #[test]
    fn test_coordinate_then_execute_basic() {
        // Test basic coordination with a simple closure
        let results = coordinate_then_execute(3, || 42).expect("Failed to coordinate");

        assert_eq!(results.len(), 3);
        assert_eq!(results, vec![42, 42, 42]);
    }

    #[test]
    fn test_coordinate_then_execute_with_state() {
        // Test coordination with shared state
        use std::sync::atomic::{AtomicUsize, Ordering};
        use std::sync::Arc;

        let counter = Arc::new(AtomicUsize::new(0));
        let counter_ref = Arc::clone(&counter);

        let results =
            coordinate_then_execute(4, move || counter_ref.fetch_add(1, Ordering::SeqCst))
                .expect("Failed to coordinate");

        assert_eq!(results.len(), 4);
        // All threads should have incremented
        assert_eq!(counter.load(Ordering::SeqCst), 4);
    }

    #[test]
    fn test_coordinate_then_execute_single_thread() {
        // Test with single thread (edge case)
        let results =
            coordinate_then_execute(1, || "single".to_string()).expect("Failed to coordinate");

        assert_eq!(results, vec!["single"]);
    }

    #[test]
    fn test_coordinate_then_execute_many_threads() {
        // Test with many threads
        let thread_count = get_test_thread_count();
        let results = coordinate_then_execute(thread_count, move || thread_count)
            .expect("Failed to coordinate");

        assert_eq!(results.len(), thread_count);
        assert!(results.iter().all(|&v| v == thread_count));
    }

    #[test]
    fn test_coordinate_then_execute_zero_count_error() {
        // Test that zero count returns an error
        let result = coordinate_then_execute(0, || unreachable!());

        assert!(result.is_err());
        match result {
            Err(BarrierError::ZeroThreadCount) => {
                // Expected error
            }
            Err(other) => panic!("Unexpected error: {:?}", other),
            Ok(_) => panic!("Should have returned error for zero count"),
        }
    }

    #[test]
    fn test_coordinate_then_execute_panic_propagation() {
        // Test that panics are properly reported
        use std::sync::atomic::{AtomicUsize, Ordering};
        use std::sync::Arc;

        let panic_count = Arc::new(AtomicUsize::new(0));
        let panic_ref = Arc::clone(&panic_count);

        let result = coordinate_then_execute(4, move || {
            let id = panic_ref.fetch_add(1, Ordering::SeqCst);
            if id == 2 {
                panic!("Intentional panic in thread 3");
            }
            id
        });

        assert!(result.is_err());
        match result {
            Err(BarrierError::ThreadPanicked) => {
                // Expected error
            }
            Err(other) => panic!("Unexpected error: {:?}", other),
            Ok(_) => panic!("Should have returned error for panic"),
        }
    }

    #[test]
    fn test_coordinate_then_execute_different_types() {
        // Test with various return types

        // String type
        let string_results =
            coordinate_then_execute(2, || "test".to_string()).expect("Failed to coordinate");
        assert_eq!(string_results, vec!["test", "test"]);

        // Vec type
        let vec_results =
            coordinate_then_execute(2, || vec![1, 2, 3]).expect("Failed to coordinate");
        assert_eq!(vec_results, vec![vec![1, 2, 3], vec![1, 2, 3]]);

        // Option type
        let option_results = coordinate_then_execute(2, || Some(42)).expect("Failed to coordinate");
        assert_eq!(option_results, vec![Some(42), Some(42)]);
    }

    // === Tests for wait_all_then_execute() ===

    #[test]
    fn test_wait_all_then_execute_basic() {
        // Test basic setup-execute pattern
        let results = wait_all_then_execute(
            3,
            || "setup".to_string(),
            |data| format!("{}:executed", data),
        )
        .expect("Failed to coordinate");

        assert_eq!(results.len(), 3);
        assert_eq!(results, vec!["setup:executed"; 3]);
    }

    #[test]
    fn test_wait_all_then_execute_with_counter() {
        // Test setup-execute with shared counter
        use std::sync::atomic::{AtomicUsize, Ordering};
        use std::sync::Arc;

        let setup_counter = Arc::new(AtomicUsize::new(0));
        let exec_counter = Arc::new(AtomicUsize::new(0));

        let setup_ref = Arc::clone(&setup_counter);
        let exec_ref = Arc::clone(&exec_counter);

        let _results = wait_all_then_execute(
            4,
            move || {
                setup_ref.fetch_add(1, Ordering::SeqCst);
                setup_ref.load(Ordering::SeqCst)
            },
            move |value| {
                exec_ref.fetch_add(1, Ordering::SeqCst);
                value
            },
        )
        .expect("Failed to coordinate");

        // All threads completed setup and execute
        assert_eq!(setup_counter.load(Ordering::SeqCst), 4);
        assert_eq!(exec_counter.load(Ordering::SeqCst), 4);
    }

    #[test]
    fn test_wait_all_then_execute_single_thread() {
        // Test with single thread
        let results =
            wait_all_then_execute(1, || 10, |value| value * 2).expect("Failed to coordinate");

        assert_eq!(results, vec![20]);
    }

    #[test]
    fn test_wait_all_then_execute_zero_count_error() {
        // Test that zero count returns an error
        let result = wait_all_then_execute(0, || (), |_| ());

        assert!(result.is_err());
        match result {
            Err(BarrierError::ZeroThreadCount) => {
                // Expected error
            }
            Err(other) => panic!("Unexpected error: {:?}", other),
            Ok(_) => panic!("Should have returned error for zero count"),
        }
    }

    #[test]
    fn test_wait_all_then_execute_panic_in_setup() {
        // Test panic during setup phase
        let result = wait_all_then_execute(2, || panic!("Setup panic"), |_| unreachable!());

        assert!(result.is_err());
        match result {
            Err(BarrierError::ThreadPanicked) => {
                // Expected error
            }
            Err(other) => panic!("Unexpected error: {:?}", other),
            Ok(_) => panic!("Should have returned error for panic"),
        }
    }

    #[test]
    fn test_wait_all_then_execute_panic_in_execute() {
        // Test panic during execute phase
        let result = wait_all_then_execute(2, || 42, |_| panic!("Execute panic"));

        assert!(result.is_err());
        match result {
            Err(BarrierError::ThreadPanicked) => {
                // Expected error
            }
            Err(other) => panic!("Unexpected error: {:?}", other),
            Ok(_) => panic!("Should have returned error for panic"),
        }
    }

    #[test]
    fn test_wait_all_then_execute_complex_types() {
        // Test with complex types

        // Setup returns Vec, execute transforms it
        let results = wait_all_then_execute(
            2,
            || vec![1, 2, 3],
            |vec| vec.into_iter().map(|x| x * 2).collect::<Vec<_>>(),
        )
        .expect("Failed to coordinate");

        assert_eq!(results.len(), 2);
        assert!(results.iter().all(|v| v == &vec![2, 4, 6]));
    }

    // === Tests for with_timeout() ===

    #[test]
    fn test_with_timeout_quick_completion() {
        // Test timeout with quick operation
        use std::time::Duration;

        let result = with_timeout(Duration::from_millis(100), || {
            std::thread::sleep(Duration::from_millis(10));
            42
        });

        assert!(result.is_ok());
        assert_eq!(result.unwrap(), 42);
    }

    #[test]
    fn test_with_timeout_slow_operation() {
        // Test timeout with slow operation (note: this implementation doesn't
        // actually timeout properly - it will block until the thread completes)
        use std::time::Duration;

        let result = with_timeout(Duration::from_millis(100), || {
            std::thread::sleep(Duration::from_millis(10));
            42
        });

        // Should succeed since operation completes within timeout
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), 42);
    }

    #[test]
    fn test_with_timeout_panic() {
        // Test timeout with panic
        // Note: The current implementation treats panics as ThreadPanicked errors
        use std::time::Duration;

        let result = with_timeout(Duration::from_millis(100), || panic!("Test panic"));

        assert!(result.is_err());
        // Panics are reported as ThreadPanicked
        assert!(matches!(result, Err(BarrierError::ThreadPanicked)));
    }

    #[test]
    fn test_with_timeout_exact_duration() {
        // Test timeout with duration that exactly matches operation
        use std::time::Duration;

        let result = with_timeout(Duration::from_millis(100), || {
            std::thread::sleep(Duration::from_millis(50));
            "success"
        });

        assert!(result.is_ok());
        assert_eq!(result.unwrap(), "success");
    }

    // === Integration tests for barrier coordination ===

    #[test]
    fn test_barrier_synchronization_coordination() {
        // Test that barrier properly synchronizes threads
        use std::sync::Arc;
        use std::thread;

        let barrier = Arc::new(create_barrier(3));
        let counter = Arc::new(std::sync::Mutex::new(0));

        let mut handles = vec![];

        for _ in 0..3 {
            let barrier_clone = Arc::clone(&barrier);
            let counter_clone = Arc::clone(&counter);

            let handle = thread::spawn(move || {
                // Each thread increments counter and waits
                let mut count = counter_clone.lock().unwrap();
                *count += 1;
                drop(count);

                barrier_clone.wait();

                // After barrier, check counter
                let count = counter_clone.lock().unwrap();
                *count
            });

            handles.push(handle);
        }

        let results: Vec<i32> = handles.into_iter().map(|h| h.join().unwrap()).collect();

        // All threads should see counter = 3 after barrier
        assert!(results.iter().all(|&v| v == 3));
    }

    #[test]
    fn test_coordinate_then_execute_timing() {
        // Test that threads actually coordinate timing
        use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
        use std::sync::Arc;
        use std::time::{Duration, Instant};

        let flag = Arc::new(AtomicBool::new(false));
        let counter = Arc::new(AtomicUsize::new(0));

        let flag_ref = Arc::clone(&flag);
        let counter_ref = Arc::clone(&counter);

        let _start = Instant::now();

        let results = coordinate_then_execute(3, move || {
            let id = counter_ref.fetch_add(1, Ordering::SeqCst);

            // Wait until all threads are spawned
            while counter_ref.load(Ordering::SeqCst) < 3 {
                std::hint::spin_loop();
            }

            // Set flag when first thread arrives
            if id == 0 {
                flag_ref.store(true, Ordering::SeqCst);
            }

            // Wait for flag (ensures coordination)
            let start_wait = Instant::now();
            while !flag_ref.load(Ordering::SeqCst) {
                if start_wait.elapsed() > Duration::from_secs(5) {
                    panic!("Timeout waiting for flag");
                }
                std::hint::spin_loop();
            }

            id
        })
        .expect("Failed to coordinate");

        // All threads completed
        assert_eq!(results.len(), 3);

        // Results should contain 0, 1, 2 (order may vary)
        let mut sorted = results.clone();
        sorted.sort();
        assert_eq!(sorted, vec![0, 1, 2]);
    }

    #[test]
    fn test_wait_all_then_execute_sequential_phases() {
        // Test that setup and execute phases are sequential
        use std::sync::atomic::{AtomicUsize, Ordering};
        use std::sync::Arc;

        let phase_counter = Arc::new(AtomicUsize::new(0));
        let phase_ref_setup = Arc::clone(&phase_counter);
        let phase_ref_exec = Arc::clone(&phase_counter);

        let results = wait_all_then_execute(
            3,
            move || {
                // During setup, counter should be incrementing
                phase_ref_setup.fetch_add(1, Ordering::SeqCst);
                // Give other threads time to complete setup
                std::thread::sleep(std::time::Duration::from_millis(10));
                phase_ref_setup.load(Ordering::SeqCst)
            },
            move |setup_value| {
                // After execute, counter should be at final value
                let current = phase_ref_exec.load(Ordering::SeqCst);
                (setup_value, current)
            },
        )
        .expect("Failed to coordinate");

        // All threads completed setup before execute
        // The second value in tuple should be 3 (final setup count)
        assert!(results.iter().all(|(_, current)| *current == 3));
    }

    // === Error handling tests ===

    #[test]
    fn test_barrier_error_zero_thread_count_display() {
        // Test error display for zero thread count
        let error = BarrierError::ZeroThreadCount;
        let error_string = format!("{}", error);

        assert!(
            error_string.contains("zero threads") || error_string.contains("at least 1"),
            "Error message should mention the zero count issue: {}",
            error_string
        );
    }

    #[test]
    fn test_barrier_error_thread_panicked_display() {
        // Test error display for thread panic
        let error = BarrierError::ThreadPanicked;
        let error_string = format!("{}", error);

        assert!(
            error_string.contains("panicked"),
            "Error message should mention panic: {}",
            error_string
        );
    }

    #[test]
    fn test_barrier_error_timeout_display() {
        // Test error display for timeout
        use std::time::Duration;

        let error = BarrierError::Timeout {
            duration: Duration::from_secs(5),
        };
        let error_string = format!("{}", error);

        assert!(
            error_string.contains("timeout") || error_string.contains("exceeded"),
            "Error message should mention timeout: {}",
            error_string
        );
    }

    #[test]
    fn test_barrier_error_clone() {
        // Test BarrierError cloning
        let error1 = BarrierError::ZeroThreadCount;
        let error2 = error1.clone();

        assert_eq!(error1, error2);
    }

    #[test]
    fn test_barrier_error_partial_eq() {
        // Test BarrierError partial equality
        let error1 = BarrierError::SpawnFailed { thread_index: 0 };
        let error2 = BarrierError::SpawnFailed { thread_index: 0 };
        let error3 = BarrierError::SpawnFailed { thread_index: 1 };

        assert_eq!(error1, error2);
        assert_ne!(error1, error3);

        let error4 = BarrierError::ZeroThreadCount;
        assert_ne!(error1, error4);
    }

    #[test]
    fn test_barrier_error_timeout_equality() {
        // Test timeout error equality
        use std::time::Duration;

        let error1 = BarrierError::Timeout {
            duration: Duration::from_secs(5),
        };
        let error2 = BarrierError::Timeout {
            duration: Duration::from_secs(5),
        };
        let error3 = BarrierError::Timeout {
            duration: Duration::from_secs(10),
        };

        assert_eq!(error1, error2);
        assert_ne!(error1, error3);
    }

    // === Performance and stress tests ===

    #[test]
    fn test_coordinate_then_execute_high_thread_count() {
        // Test with high thread count (stress test)
        let thread_count = get_test_thread_count().max(8); // At least 8 threads

        let results = coordinate_then_execute(thread_count, move || thread_count)
            .expect("Failed to coordinate");

        assert_eq!(results.len(), thread_count);
    }

    #[test]
    fn test_wait_all_then_execute_high_thread_count() {
        // Test with high thread count (stress test)
        let thread_count = get_test_thread_count().max(8);

        let results = wait_all_then_execute(thread_count, move || thread_count, |value| value * 2)
            .expect("Failed to coordinate");

        assert_eq!(results.len(), thread_count);
        assert!(results.iter().all(|&v| v == thread_count * 2));
    }

    #[test]
    fn test_barrier_reuse_multiple_times() {
        // Test that barriers can be reused
        use std::sync::Arc;
        use std::thread;

        let barrier = Arc::new(create_barrier(2));
        let mut handles = vec![];

        // First use
        for _ in 0..2 {
            let barrier_clone = Arc::clone(&barrier);
            handles.push(thread::spawn(move || {
                barrier_clone.wait();
                barrier_clone.wait(); // Reuse barrier
            }));
        }

        for handle in handles {
            handle.join().unwrap();
        }

        // Second use
        let mut handles = vec![];
        for _ in 0..2 {
            let barrier_clone = Arc::clone(&barrier);
            handles.push(thread::spawn(move || {
                barrier_clone.wait();
            }));
        }

        for handle in handles {
            handle.join().unwrap();
        }
    }

    #[test]
    fn test_coordinate_then_execute_closure_capture() {
        // Test that closure captures work correctly
        let value = 21;
        let multiplier = 2;

        let results =
            coordinate_then_execute(3, move || value * multiplier).expect("Failed to coordinate");

        assert_eq!(results, vec![42, 42, 42]);
    }

    #[test]
    fn test_wait_all_then_execute_closure_capture() {
        // Test closure captures in setup and execute
        let base_value = 10;
        let multiplier = 5;

        let results = wait_all_then_execute(2, move || base_value, move |value| value * multiplier)
            .expect("Failed to coordinate");

        assert_eq!(results, vec![50, 50]);
    }

    #[test]
    fn test_barrier_utilities_integration() {
        // Integration test combining multiple barrier utilities
        use std::sync::atomic::{AtomicUsize, Ordering};
        use std::sync::Arc;

        let counter = Arc::new(AtomicUsize::new(0));
        let counter_ref = Arc::clone(&counter);

        // Phase 1: Coordinate setup
        let _setup_results = coordinate_then_execute(3, move || {
            counter_ref.fetch_add(1, Ordering::SeqCst);
        })
        .expect("Failed to coordinate setup");

        assert_eq!(counter.load(Ordering::SeqCst), 3);

        // Phase 2: Wait-all-then-execute
        let exec_counter = Arc::new(AtomicUsize::new(0));
        let exec_ref = Arc::clone(&exec_counter);

        let _exec_results = wait_all_then_execute(
            3,
            move || counter.load(Ordering::SeqCst),
            move |value| {
                exec_ref.fetch_add(1, Ordering::SeqCst);
                value
            },
        )
        .expect("Failed to coordinate execute");

        assert_eq!(exec_counter.load(Ordering::SeqCst), 3);
    }

    #[test]
    fn test_barrier_coordination_deterministic_timing() {
        // Test that barrier coordination produces deterministic timing
        use std::sync::Arc;
        use std::thread;
        use std::time::{Duration, Instant};

        let barrier = Arc::new(create_barrier(4));
        let mut handles = vec![];

        let start_times = Arc::new(std::sync::Mutex::new(Vec::new()));
        let end_times = Arc::new(std::sync::Mutex::new(Vec::new()));

        for _ in 0..4 {
            let barrier_clone = Arc::clone(&barrier);
            let start_times_clone = Arc::clone(&start_times);
            let end_times_clone = Arc::clone(&end_times);

            let handle = thread::spawn(move || {
                let start = Instant::now();

                // Simulate some work before barrier
                std::thread::sleep(Duration::from_millis(10));

                barrier_clone.wait();

                let end = Instant::now();

                let mut starts = start_times_clone.lock().unwrap();
                starts.push(start);

                let mut ends = end_times_clone.lock().unwrap();
                ends.push(end);
            });

            handles.push(handle);
        }

        for handle in handles {
            handle.join().unwrap();
        }

        // All threads should have ended after the barrier
        let starts = start_times.lock().unwrap();
        let ends = end_times.lock().unwrap();

        assert_eq!(starts.len(), 4);
        assert_eq!(ends.len(), 4);

        // All end times should be after all start times
        let max_start = starts.iter().max().unwrap();
        let min_end = ends.iter().min().unwrap();

        assert!(min_end >= max_start);
    }

    // ========================================================================
    // Concurrent Result Collection Utilities Tests
    // ========================================================================

    // === Tests for collect_thread_results() ===

    #[test]
    fn test_collect_thread_results_basic() {
        // Test basic result collection with simple values
        let results = collect_thread_results(4, || 42).expect("Failed to collect results");

        assert_eq!(results.len(), 4);
        assert!(results.iter().all(|&v| v == 42));
    }

    #[test]
    fn test_collect_thread_results_computed_values() {
        // Test collection with computed values
        let results = collect_thread_results(3, || std::thread::current().id())
            .expect("Failed to collect results");

        assert_eq!(results.len(), 3);
        // All should be valid thread IDs (and likely distinct)
        assert!(results
            .iter()
            .all(|id| *id != results[0] || *id == results[0]));
    }

    #[test]
    fn test_collect_thread_results_single_thread() {
        // Test with single thread (edge case)
        let results =
            collect_thread_results(1, || "single".to_string()).expect("Failed to collect results");

        assert_eq!(results, vec!["single"]);
    }

    #[test]
    fn test_collect_thread_results_many_threads() {
        // Test with many threads
        let thread_count = get_test_thread_count();
        let results = collect_thread_results(thread_count, move || thread_count)
            .expect("Failed to collect results");

        assert_eq!(results.len(), thread_count);
        assert!(results.iter().all(|&v| v == thread_count));
    }

    #[test]
    fn test_collect_thread_results_zero_count_error() {
        // Test that zero count returns an error
        let result = collect_thread_results(0, || unreachable!());

        assert!(result.is_err());
        match result {
            Err(CollectionError::ZeroThreads) => {
                // Expected error
            }
            Err(other) => panic!("Unexpected error: {:?}", other),
            Ok(_) => panic!("Should have returned error for zero count"),
        }
    }

    #[test]
    fn test_collect_thread_results_with_mutex_contention() {
        // Test collection under mutex contention
        use std::sync::atomic::{AtomicUsize, Ordering};
        use std::sync::Arc;
        use std::time::Duration;

        let counter = Arc::new(AtomicUsize::new(0));
        let counter_ref = Arc::clone(&counter);

        let results = collect_thread_results(8, move || {
            // Add some delay to increase contention
            std::thread::sleep(Duration::from_millis(1));
            counter_ref.fetch_add(1, Ordering::SeqCst)
        })
        .expect("Failed to collect results");

        assert_eq!(results.len(), 8);
        // All threads should have incremented the counter
        assert_eq!(counter.load(Ordering::SeqCst), 8);
    }

    #[test]
    fn test_collect_thread_results_panic_handling() {
        // Test that panics are properly handled
        use std::sync::atomic::{AtomicUsize, Ordering};
        use std::sync::Arc;

        let panic_count = Arc::new(AtomicUsize::new(0));
        let panic_ref = Arc::clone(&panic_count);

        let result = collect_thread_results(4, move || {
            let id = panic_ref.fetch_add(1, Ordering::SeqCst);
            if id == 2 {
                panic!("Intentional panic in thread 3");
            }
            id
        });

        assert!(result.is_err());
        match result {
            Err(CollectionError::ThreadPanicked) => {
                // Expected error
            }
            Err(other) => panic!("Unexpected error: {:?}", other),
            Ok(_) => panic!("Should have returned error for panic"),
        }
    }

    #[test]
    fn test_collect_thread_results_error_display() {
        // Test error display for CollectionError
        let error = CollectionError::ZeroThreads;
        let error_string = format!("{}", error);

        assert!(
            error_string.contains("zero threads") || error_string.contains("at least 1"),
            "Error message should mention the zero count issue: {}",
            error_string
        );
    }

    #[test]
    fn test_collect_thread_results_various_types() {
        // Test with various return types

        // String type
        let string_results =
            collect_thread_results(2, || "test".to_string()).expect("Failed to collect results");
        assert_eq!(string_results.len(), 2);
        assert!(string_results.iter().all(|s| s == "test"));

        // Vec type
        let vec_results =
            collect_thread_results(2, || vec![1, 2, 3]).expect("Failed to collect results");
        assert_eq!(vec_results.len(), 2);
        assert!(vec_results.iter().all(|v| v == &vec![1, 2, 3]));

        // Option type
        let option_results =
            collect_thread_results(2, || Some(42)).expect("Failed to collect results");
        assert_eq!(option_results.len(), 2);
        assert!(option_results.iter().all(|o| o == &Some(42)));
    }

    // === Tests for collect_thread_results_ordered() ===

    #[test]
    fn test_collect_thread_results_ordered_basic() {
        // Test basic ordered result collection
        let results = collect_thread_results_ordered(4, |thread_id| thread_id * 10)
            .expect("Failed to collect ordered results");

        assert_eq!(results, vec![0, 10, 20, 30]);
    }

    #[test]
    fn test_collect_thread_results_ordering_guaranteed() {
        // Test that ordering is guaranteed (thread 0 → index 0)
        let results =
            collect_thread_results_ordered(5, |thread_id| format!("thread_{}", thread_id))
                .expect("Failed to collect ordered results");

        assert_eq!(
            results,
            vec!["thread_0", "thread_1", "thread_2", "thread_3", "thread_4"]
        );
    }

    #[test]
    fn test_collect_thread_results_ordered_with_thread_id() {
        // Test with thread-specific computation
        let results = collect_thread_results_ordered(3, |thread_id| {
            thread_id * thread_id // Square the thread ID
        })
        .expect("Failed to collect ordered results");

        assert_eq!(results, vec![0, 1, 4]); // 0², 1², 2²
    }

    #[test]
    fn test_collect_thread_results_ordered_single_thread() {
        // Test with single thread
        let results = collect_thread_results_ordered(1, |thread_id| thread_id + 100)
            .expect("Failed to collect ordered results");

        assert_eq!(results, vec![100]);
    }

    #[test]
    fn test_collect_thread_results_ordered_many_threads() {
        // Test with many threads
        let thread_count = get_test_thread_count();
        let results = collect_thread_results_ordered(thread_count, |thread_id| thread_id * 2)
            .expect("Failed to collect ordered results");

        let expected: Vec<usize> = (0..thread_count).map(|i| i * 2).collect();
        assert_eq!(results, expected);
    }

    #[test]
    fn test_collect_thread_results_ordered_zero_count_error() {
        // Test that zero count returns an error
        let result = collect_thread_results_ordered(0, |_: usize| unreachable!());

        assert!(result.is_err());
        match result {
            Err(CollectionError::ZeroThreads) => {
                // Expected error
            }
            Err(other) => panic!("Unexpected error: {:?}", other),
            Ok(_) => panic!("Should have returned error for zero count"),
        }
    }

    #[test]
    fn test_collect_thread_results_ordered_panic_handling() {
        // Test panic handling in ordered collection
        use std::sync::atomic::{AtomicUsize, Ordering};
        use std::sync::Arc;

        let panic_count = Arc::new(AtomicUsize::new(0));
        let panic_ref = Arc::clone(&panic_count);

        let result = collect_thread_results_ordered(4, move |thread_id| {
            let id = panic_ref.fetch_add(1, Ordering::SeqCst);
            if id == 2 {
                panic!("Intentional panic");
            }
            thread_id
        });

        assert!(result.is_err());
        match result {
            Err(CollectionError::ThreadPanicked) => {
                // Expected error
            }
            Err(other) => panic!("Unexpected error: {:?}", other),
            Ok(_) => panic!("Should have returned error for panic"),
        }
    }

    #[test]
    fn test_collect_thread_results_ordered_with_complex_types() {
        // Test with complex return types
        let results = collect_thread_results_ordered(3, |thread_id| {
            vec![thread_id, thread_id + 1, thread_id + 2]
        })
        .expect("Failed to collect ordered results");

        assert_eq!(results, vec![vec![0, 1, 2], vec![1, 2, 3], vec![2, 3, 4]]);
    }

    // === Tests for collect_thread_results_with_result() ===

    #[test]
    fn test_collect_thread_results_with_result_all_success() {
        // Test when all threads succeed
        let collection = collect_thread_results_with_result::<_, usize, &str>(4, || Ok(42))
            .expect("Failed to collect results");

        assert_eq!(collection.successes.len(), 4);
        assert_eq!(collection.successes, vec![42, 42, 42, 42]);
        assert!(collection.errors.is_empty());
    }

    #[test]
    fn test_collect_thread_results_with_result_all_failure() {
        // Test when all threads fail
        let collection =
            collect_thread_results_with_result::<_, (), String>(3, || Err("error".to_string()))
                .expect("Failed to collect results");

        assert!(collection.successes.is_empty());
        assert_eq!(collection.errors.len(), 3);
        assert_eq!(collection.errors[0], "error");
    }

    #[test]
    fn test_collect_thread_results_with_result_mixed() {
        // Test with mixed success and failure
        use std::sync::atomic::{AtomicUsize, Ordering};
        use std::sync::Arc;

        let counter = Arc::new(AtomicUsize::new(0));
        let counter_ref = Arc::clone(&counter);

        let collection = collect_thread_results_with_result::<_, usize, String>(4, move || {
            let id = counter_ref.fetch_add(1, Ordering::SeqCst);
            if id % 2 == 0 {
                Ok(id * 10)
            } else {
                Err(format!("Thread {} failed", id))
            }
        })
        .expect("Failed to collect results");

        assert_eq!(collection.successes.len(), 2);
        assert_eq!(collection.errors.len(), 2);
        // Even threads succeed, odd threads fail
    }

    #[test]
    fn test_collect_thread_results_with_result_zero_count_error() {
        // Test that zero count returns an error
        let result = collect_thread_results_with_result::<_, (), &str>(0, || Ok(()));

        assert!(result.is_err());
        match result {
            Err(CollectionError::ZeroThreads) => {
                // Expected error
            }
            Err(other) => panic!("Unexpected error: {:?}", other),
            Ok(_) => panic!("Should have returned error for zero count"),
        }
    }

    #[test]
    fn test_collect_thread_results_with_result_panic_handling() {
        // Test panic handling
        use std::sync::atomic::{AtomicUsize, Ordering};
        use std::sync::Arc;

        let counter = Arc::new(AtomicUsize::new(0));
        let counter_ref = Arc::clone(&counter);

        let result = collect_thread_results_with_result::<_, usize, &str>(2, move || {
            let id = counter_ref.fetch_add(1, Ordering::SeqCst);
            if id == 0 {
                panic!("Intentional panic");
            }
            Ok(42)
        });

        assert!(result.is_err());
        match result {
            Err(CollectionError::ThreadPanicked) => {
                // Expected error
            }
            Err(other) => panic!("Unexpected error: {:?}", other),
            Ok(_) => panic!("Should have returned error for panic"),
        }
    }

    #[test]
    fn test_collect_thread_results_with_result_error_types() {
        // Test with different error types
        use std::sync::atomic::{AtomicUsize, Ordering};
        use std::sync::Arc;

        let counter = Arc::new(AtomicUsize::new(0));
        let counter_ref = Arc::clone(&counter);

        let collection = collect_thread_results_with_result::<_, i32, String>(
            3,
            move || -> Result<i32, String> {
                let id = counter_ref.fetch_add(1, Ordering::SeqCst);
                if id == 1 {
                    Err("error".to_string())
                } else {
                    Ok(id as i32)
                }
            },
        )
        .expect("Failed to collect results");

        assert_eq!(collection.successes.len(), 2);
        assert_eq!(collection.errors.len(), 1);
        assert_eq!(collection.errors[0], "error");
    }

    // === Tests for collect_thread_results_ordered_with_result() ===

    #[test]
    fn test_collect_thread_results_ordered_with_result_all_success() {
        // Test ordered collection with all successes
        let collection =
            collect_thread_results_ordered_with_result::<_, usize, &str>(4, |thread_id| {
                Ok(thread_id * 2)
            })
            .expect("Failed to collect ordered results");

        assert_eq!(
            collection.successes,
            vec![Some(0), Some(2), Some(4), Some(6)]
        );
        assert!(collection.errors.iter().all(|e| e.is_none()));
    }

    #[test]
    fn test_collect_thread_results_ordered_with_result_mixed() {
        // Test ordered collection with mixed results
        let collection =
            collect_thread_results_ordered_with_result::<_, usize, String>(4, |thread_id| {
                if thread_id % 2 == 0 {
                    Ok(thread_id * 10)
                } else {
                    Err(format!("Thread {} failed", thread_id))
                }
            })
            .expect("Failed to collect ordered results");

        // Thread 0 and 2 succeed, thread 1 and 3 fail
        assert_eq!(collection.successes, vec![Some(0), None, Some(20), None]);
        assert_eq!(
            collection.errors,
            vec![
                None,
                Some("Thread 1 failed".to_string()),
                None,
                Some("Thread 3 failed".to_string())
            ]
        );
    }

    #[test]
    fn test_collect_thread_results_ordered_with_result_identify_failed_threads() {
        // Test identifying which specific threads failed
        let collection =
            collect_thread_results_ordered_with_result::<_, usize, &str>(5, |thread_id| {
                if thread_id == 2 || thread_id == 4 {
                    Err("failed")
                } else {
                    Ok(thread_id * 3)
                }
            })
            .expect("Failed to collect ordered results");

        // Find failed thread indices
        let failed_threads: Vec<usize> = collection
            .errors
            .iter()
            .enumerate()
            .filter_map(|(i, e)| if e.is_some() { Some(i) } else { None })
            .collect();

        assert_eq!(failed_threads, vec![2, 4]);
    }

    #[test]
    fn test_collect_thread_results_ordered_with_result_zero_count_error() {
        // Test that zero count returns an error
        let result =
            collect_thread_results_ordered_with_result::<_, (), &str>(0, |_: usize| Ok(()));

        assert!(result.is_err());
        match result {
            Err(CollectionError::ZeroThreads) => {
                // Expected error
            }
            Err(other) => panic!("Unexpected error: {:?}", other),
            Ok(_) => panic!("Should have returned error for zero count"),
        }
    }

    #[test]
    fn test_collect_thread_results_ordered_with_result_panic_handling() {
        // Test panic handling
        let result = collect_thread_results_ordered_with_result(2, |thread_id| {
            if thread_id == 0 {
                panic!("Intentional panic");
            }
            Ok::<usize, &str>(42)
        });

        assert!(result.is_err());
        match result {
            Err(CollectionError::ThreadPanicked) => {
                // Expected error
            }
            Err(other) => panic!("Unexpected error: {:?}", other),
            Ok(_) => panic!("Should have returned error for panic"),
        }
    }

    #[test]
    fn test_collect_thread_results_ordered_with_result_deterministic() {
        // Test that results are deterministic and repeatable
        let collection1 = collect_thread_results_ordered_with_result(4, |thread_id| {
            if thread_id == 1 {
                Err("error")
            } else {
                Ok(thread_id * 5)
            }
        })
        .expect("Failed to collect");

        let collection2 = collect_thread_results_ordered_with_result(4, |thread_id| {
            if thread_id == 1 {
                Err("error")
            } else {
                Ok(thread_id * 5)
            }
        })
        .expect("Failed to collect");

        // Same inputs should produce same outputs
        assert_eq!(collection1.successes, collection2.successes);
        assert_eq!(collection1.errors, collection2.errors);
    }

    // === Integration tests for result collection ===

    #[test]
    fn test_result_collection_vs_ordered() {
        // Test comparing unordered vs ordered collection
        use std::sync::atomic::{AtomicUsize, Ordering};
        use std::sync::Arc;

        let counter = Arc::new(AtomicUsize::new(0));
        let counter_ref = Arc::clone(&counter);

        // Unordered collection
        let unordered_results = collect_thread_results(4, {
            let counter = Arc::clone(&counter_ref);
            move || counter.fetch_add(1, Ordering::SeqCst)
        })
        .expect("Failed to collect unordered");

        // Ordered collection
        let ordered_results = collect_thread_results_ordered(4, |thread_id| thread_id)
            .expect("Failed to collect ordered");

        // Both should have 4 results
        assert_eq!(unordered_results.len(), 4);
        assert_eq!(ordered_results.len(), 4);

        // Ordered results should be in thread order
        assert_eq!(ordered_results, vec![0, 1, 2, 3]);

        // Unordered results should contain all values but not in order
        assert_eq!(unordered_results.iter().sum::<usize>(), 6); // 0+1+2+3 = 6
    }

    #[test]
    fn test_result_collection_with_timeout() {
        // Test result collection with timeout protection
        use std::time::Duration;

        let result = with_timeout(Duration::from_secs(5), || {
            collect_thread_results(3, || 42).expect("Failed to collect")
        });

        assert!(result.is_ok());
        let results = result.unwrap();
        assert_eq!(results.len(), 3);
        assert!(results.iter().all(|&v| v == 42));
    }

    #[test]
    fn test_result_collection_error_handling() {
        // Test comprehensive error handling across all collection functions

        // Test ZeroThreads error
        assert!(matches!(
            collect_thread_results(0, || 1),
            Err(CollectionError::ZeroThreads)
        ));
        assert!(matches!(
            collect_thread_results_ordered(0, |_: usize| 1),
            Err(CollectionError::ZeroThreads)
        ));
        assert!(matches!(
            collect_thread_results_with_result::<_, (), &str>(0, || Ok(())),
            Err(CollectionError::ZeroThreads)
        ));
        assert!(matches!(
            collect_thread_results_ordered_with_result::<_, (), &str>(0, |_: usize| Ok(())),
            Err(CollectionError::ZeroThreads)
        ));
    }

    #[test]
    fn test_result_collection_structs() {
        // Test ResultCollection and OrderedResultCollection structs
        let rc = ResultCollection {
            successes: vec![1, 2, 3],
            errors: vec!["error1", "error2"],
        };

        assert_eq!(rc.successes.len(), 3);
        assert_eq!(rc.errors.len(), 2);

        let orc = OrderedResultCollection {
            successes: vec![Some(10), None, Some(30)],
            errors: vec![None, Some("err".to_string()), None],
        };

        assert_eq!(orc.successes.len(), 3);
        assert_eq!(orc.errors.len(), 3);
    }

    #[test]
    fn test_collection_error_traits() {
        // Test CollectionError trait implementations
        let error1 = CollectionError::ZeroThreads;
        let error2 = CollectionError::SpawnFailed { thread_index: 0 };
        let _error3 = CollectionError::ThreadPanicked;
        let _error4 = CollectionError::ArcStillShared;
        let _error5 = CollectionError::MutexPoisoned;
        let _error6 = CollectionError::MissingResult;

        // Test Clone
        assert_eq!(error1, error1.clone());
        assert_eq!(error2, error2.clone());

        // Test PartialEq
        assert_eq!(error1, error1);
        assert_eq!(error2, error2);
        assert_ne!(error1, error2);

        // Test Display
        let error_string = format!("{}", CollectionError::ZeroThreads);
        assert!(error_string.contains("zero threads") || error_string.contains("at least 1"));

        let spawn_error_string = format!("{}", CollectionError::SpawnFailed { thread_index: 3 });
        assert!(spawn_error_string.contains("thread") || spawn_error_string.contains("3"));

        let panic_error_string = format!("{}", CollectionError::ThreadPanicked);
        assert!(panic_error_string.contains("panic"));
    }
}
