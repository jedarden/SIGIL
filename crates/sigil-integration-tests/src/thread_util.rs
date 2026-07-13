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
/// - Caches the result for performance
/// - Falls back to 2 threads if detection fails
///
/// # Returns
///
/// The number of threads to use for testing (1-8)
///
/// # Examples
///
/// ```rust
/// use sigil_integration_tests::thread_util::get_test_thread_count;
///
/// let thread_count = get_test_thread_count();
/// assert!(thread_count >= 1);
/// assert!(thread_count <= 8);
/// ```
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

#[cfg(test)]
mod tests {
    use super::*;

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
}
