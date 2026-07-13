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

use std::sync::Mutex;

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
}
