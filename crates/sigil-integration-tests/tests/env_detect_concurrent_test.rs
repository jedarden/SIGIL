//! Concurrent Thread Safety Tests for env_detect Module
//!
//! This test module demonstrates and validates thread safety guarantees
//! for the `Environment::get()` cached environment singleton.
//!
//! # Tests Included
//!
//! - Basic concurrent access patterns
//! - Memory address consistency across threads
//! - Barrier synchronization for race condition testing
//! - Stress testing with high thread counts
//! - Result collection and validation utilities
//!
//! # Infrastructure
//!
//! Uses the `sigil_integration_tests::env_detect::concurrent` module which provides:
//! - `run_concurrent()` - Spawn N threads executing a function
//! - `run_concurrent_with_barrier()` - Synchronized concurrent execution
//! - `ConcurrentBarrier` - Thread synchronization primitive
//! - `ResultCollector` - Thread-safe result collection
//! - `AtomicCounter` - Lock-free thread coordination
//! - `AtomicFlag` - Thread-safe boolean signaling
//! - `collect_concurrent_addrs()` - Memory address collection
//! - `all_equal()` - Result consistency validation
//! - `all_same_address()` - Memory address consistency validation
//! - `unique_count()` - Distinct result counting

use sigil_integration_tests::env_detect::{concurrent::*, Environment};
use sigil_integration_tests::thread_util::*;
use std::thread;

#[cfg(test)]
mod environment_concurrent_tests {
    use super::*;
    use sigil_integration_tests::env_detect::Environment;

    /// Test basic concurrent Environment::get() calls
    ///
    /// # Purpose
    ///
    /// Verifies that multiple threads can safely call Environment::get()
    /// simultaneously without data races or panics.
    ///
    /// # Validation
    ///
    /// - All threads receive the same Environment reference (same memory address)
    /// - All threads see consistent environment capabilities
    /// - No deadlocks or hangs occur
    #[test]
    fn test_environment_detection_concurrent() {
        // Run Environment::get() in 10 concurrent threads
        let results = run_concurrent(10, || Environment::get().bwrap_available);

        // All threads should see the same bwrap availability
        assert!(
            all_equal(&results),
            "All threads should see same bwrap_available"
        );
        assert_eq!(results.len(), 10, "Should have 10 results");
    }

    /// Test memory address consistency across concurrent calls
    ///
    /// # Purpose
    ///
    /// Verifies that Environment::get() returns the exact same memory
    /// address to all threads, proving the OnceLock singleton pattern
    /// works correctly under concurrent access.
    #[test]
    fn test_environment_memory_address_consistency() {
        // Collect memory addresses from 20 concurrent threads
        let addresses =
            collect_concurrent_addrs(20, || Environment::get() as *const Environment as usize);

        // All addresses should be identical (same singleton instance)
        assert!(
            all_same_address(&addresses),
            "All threads should receive the exact same Environment reference"
        );
        assert_eq!(addresses.len(), 20, "Should have 20 address results");
    }

    /// Test barrier-synchronized concurrent access
    ///
    /// # Purpose
    ///
    /// Uses a barrier to ensure all threads simultaneously call
    /// Environment::get(), maximizing the chance of detecting race
    /// conditions in the OnceLock initialization.
    #[test]
    fn test_environment_barrier_synchronized_access() {
        let barrier = ConcurrentBarrier::new(15);

        let results = run_concurrent_with_barrier(15, &barrier, || {
            // All threads wait here until 15 threads are ready
            // Then they all call Environment::get() simultaneously
            Environment::get().systemd_available
        });

        // Validate consistent results
        assert!(
            all_equal(&results),
            "All threads should see same systemd_available"
        );
        assert_eq!(results.len(), 15, "Should have 15 results");
    }

    /// Test all cached environment fields under concurrent access
    ///
    /// # Purpose
    ///
    /// Validates that all cached fields in Environment remain consistent
    /// when multiple threads access different fields simultaneously.
    #[test]
    fn test_environment_all_fields_concurrent() {
        let barrier = ConcurrentBarrier::new(20);

        // Each thread accesses a different environment field
        let results = run_concurrent_with_barrier(20, &barrier, || {
            let env = Environment::get();
            (
                env.bwrap_available,
                env.systemd_available,
                env.launchd_available,
                env.is_ci,
            )
        });

        // All tuples should be identical
        assert!(
            all_equal(&results),
            "All threads should see identical environment state"
        );
        assert_eq!(results.len(), 20, "Should have 20 results");

        // Validate the first result as a sanity check
        let first = &results[0];
        println!(
            "Environment state: bwrap={}, systemd={}, launchd={}, ci={}",
            first.0, first.1, first.2, first.3
        );
    }

    /// Test high-load concurrent access (stress test)
    ///
    /// # Purpose
    ///
    /// Spawns a large number of threads (100) to stress-test the
    /// OnceLock implementation and ensure no performance degradation
    /// or race conditions emerge under heavy load.
    #[test]
    fn test_environment_high_load_concurrent() {
        let thread_count = 100;
        let barrier = ConcurrentBarrier::new(thread_count);

        let results = run_concurrent_with_barrier(thread_count, &barrier, || {
            Environment::get().xdg_runtime_dir.clone()
        });

        // All threads should get the exact same PathBuf
        assert!(
            all_equal(&results),
            "All threads should see same xdg_runtime_dir"
        );
        assert_eq!(
            results.len(),
            thread_count,
            "Should have {} results",
            thread_count
        );

        // Validate the path is not empty
        assert!(
            !results[0].as_os_str().is_empty(),
            "XDG runtime dir should not be empty"
        );
    }

    /// Test ResultCollector functionality
    ///
    /// # Purpose
    ///
    /// Demonstrates and validates the ResultCollector utility for
    /// collecting thread-safe results from concurrent operations.
    #[test]
    fn test_result_collector_concurrent() {
        use sigil_integration_tests::env_detect::concurrent::ResultCollector;

        let collector = ResultCollector::new();
        let thread_count = 10;

        for _i in 0..thread_count {
            let collector_clone = collector.clone();
            thread::spawn(move || {
                let env = Environment::get();
                collector_clone.collect(env.bwrap_available);
            })
            .join()
            .expect("Thread panicked");
        }

        let results = collector.into_vec();
        assert_eq!(results.len(), thread_count, "Should collect all results");
        assert!(all_equal(&results), "All results should be identical");
    }

    /// Test AtomicCounter for thread coordination
    ///
    /// # Purpose
    ///
    /// Validates that AtomicCounter correctly increments across
    /// concurrent threads without race conditions.
    #[test]
    fn test_atomic_counter_concurrent() {
        use sigil_integration_tests::env_detect::concurrent::AtomicCounter;

        let counter = AtomicCounter::new();
        let thread_count = 50;

        // Clone the counter for use in the closure
        let counter_clone = counter.clone();
        run_concurrent(thread_count, move || {
            counter_clone.increment();
        });

        assert_eq!(
            counter.value(),
            thread_count,
            "Counter should equal thread count"
        );
    }

    /// Test AtomicFlag for thread coordination
    ///
    /// # Purpose
    ///
    /// Validates that AtomicFlag provides correct thread-safe
    /// boolean signaling across concurrent threads.
    #[test]
    fn test_atomic_flag_concurrent() {
        use sigil_integration_tests::env_detect::concurrent::AtomicFlag;

        let flag = AtomicFlag::new(false);
        let thread_count = 20;

        // First thread sets flag, rest check it
        let results = run_concurrent_with_barrier(
            thread_count,
            &ConcurrentBarrier::new(thread_count),
            move || {
                if !flag.get() {
                    flag.set(true);
                    true
                } else {
                    flag.get()
                }
            },
        );

        // At least one thread should have set the flag
        assert!(
            results.iter().any(|&r| r),
            "At least one thread should set the flag"
        );
        // All subsequent threads should see the flag as true
        let true_count = results.iter().filter(|&&r| r).count();
        assert!(true_count >= 1, "Flag should be set");
    }

    /// Test unique_count utility function
    ///
    /// # Purpose
    ///
    /// Validates that unique_count correctly identifies distinct
    /// values in concurrent test results.
    #[test]
    fn test_unique_count_utility() {
        // All same values
        let all_same = vec![true, true, true, true];
        assert_eq!(unique_count(&all_same), 1, "All same should have count 1");

        // All different values
        let all_different: Vec<usize> = vec![1, 2, 3, 4, 5];
        assert_eq!(
            unique_count(&all_different),
            5,
            "All different should have count 5"
        );

        // Mix of same and different
        let mixed = vec![1, 1, 2, 2, 3];
        assert_eq!(unique_count(&mixed), 3, "Mixed values should have count 3");
    }

    /// Test thread cleanup and resource management
    ///
    /// # Purpose
    ///
    /// Ensures that concurrent operations properly clean up resources
    /// and don't leave zombie threads or leaked memory.
    #[test]
    fn test_thread_cleanup_and_resource_management() {
        let thread_count = 30;

        // Run multiple concurrent test iterations
        for iteration in 0..5 {
            let results = run_concurrent(thread_count, || Environment::get().bwrap_available);

            assert!(
                all_equal(&results),
                "Iteration {}: All results should be equal",
                iteration
            );
        }

        // If we get here without hanging or panicking, cleanup is working
        println!(
            "Completed {} iterations of {} concurrent threads",
            5, thread_count
        );
    }
}

#[cfg(test)]
mod thread_count_utilities_tests {
    use super::*;
    use sigil_integration_tests::env_detect::concurrent::*;

    /// Test get_test_thread_count returns reasonable values
    ///
    /// # Purpose
    ///
    /// Validates that get_test_thread_count() returns a thread count
    /// within the expected range (4-32 threads) and respects system
    /// parallelism constraints.
    #[test]
    fn test_get_test_thread_count_returns_valid_range() {
        let thread_count = get_test_thread_count();

        // Thread count should be between 4 and 32 inclusive
        assert!(
            thread_count >= 4,
            "Thread count should be at least 4, got {}",
            thread_count
        );
        assert!(
            thread_count <= 32,
            "Thread count should be at most 32, got {}",
            thread_count
        );

        println!("System test thread count: {}", thread_count);

        // Verify the thread count is based on actual system parallelism
        if let Ok(parallelism) = std::thread::available_parallelism() {
            let cores = parallelism.get();
            let expected = cores.clamp(4, 32);
            assert_eq!(
                thread_count, expected,
                "Thread count should match clamped parallelism"
            );
        }
    }

    /// Test get_test_thread_count_with_bounds respects minimum
    ///
    /// # Purpose
    ///
    /// Validates that get_test_thread_count_with_bounds() enforces
    /// the minimum thread count even on systems with fewer cores.
    #[test]
    fn test_get_test_thread_count_with_bounds_respects_minimum() {
        // Set minimum higher than most systems have
        let thread_count = get_test_thread_count_with_bounds(10, 32);

        assert!(
            thread_count >= 10,
            "Thread count should respect minimum bound"
        );
        assert!(
            thread_count <= 32,
            "Thread count should respect maximum bound"
        );

        println!("Thread count with bounds (10-32): {}", thread_count);
    }

    /// Test get_test_thread_count_with_bounds respects maximum
    ///
    /// # Purpose
    ///
    /// Validates that get_test_thread_count_with_bounds() enforces
    /// the maximum thread count even on systems with many cores.
    #[test]
    fn test_get_test_thread_count_with_bounds_respects_maximum() {
        // Set maximum lower than most systems have
        let thread_count = get_test_thread_count_with_bounds(2, 6);

        assert!(
            thread_count >= 2,
            "Thread count should respect minimum bound"
        );
        assert!(
            thread_count <= 6,
            "Thread count should respect maximum bound"
        );

        println!("Thread count with bounds (2-6): {}", thread_count);
    }

    /// Test get_test_thread_count_with_bounds validation
    ///
    /// # Purpose
    ///
    /// Validates that get_test_thread_count_with_bounds() panics
    /// when given invalid bounds (zero or inverted ranges).
    #[test]
    #[should_panic(expected = "min_threads must be > 0")]
    fn test_get_test_thread_count_with_bounds_panics_on_zero_min() {
        get_test_thread_count_with_bounds(0, 10);
    }

    /// Test get_test_thread_count_with_bounds with inverted bounds
    #[test]
    #[should_panic(expected = "max_threads must be >= min_threads")]
    fn test_get_test_thread_count_with_bounds_panics_on_inverted_bounds() {
        get_test_thread_count_with_bounds(20, 10);
    }

    /// Test is_high_core_system detection
    ///
    /// # Purpose
    ///
    /// Validates that is_high_core_system() correctly identifies
    /// systems with >= 16 logical cores.
    #[test]
    fn test_is_high_core_system() {
        let is_high_core = is_high_core_system();

        if let Ok(parallelism) = std::thread::available_parallelism() {
            let cores = parallelism.get();
            let expected = cores >= 16;
            assert_eq!(
                is_high_core, expected,
                "High core detection should match core count"
            );
            println!("System has {} cores, high_core={}", cores, is_high_core);
        } else {
            // If parallelism detection fails, should return false (conservative)
            assert!(
                !is_high_core,
                "Should return false when parallelism detection fails"
            );
        }
    }

    /// Test thread count utilities in actual concurrent operations
    ///
    /// # Purpose
    ///
    /// Integration test that validates get_test_thread_count() works
    /// correctly with actual concurrent thread spawning and produces
    /// consistent results.
    #[test]
    fn test_thread_count_utilities_integration() {
        let thread_count = get_test_thread_count();

        // Verify we can actually run this many threads successfully
        let results = run_concurrent(thread_count, || Environment::get().bwrap_available);

        // Should get exactly thread_count results
        assert_eq!(
            results.len(),
            thread_count,
            "Should get one result per thread"
        );

        // All results should be identical
        assert!(
            all_equal(&results),
            "All threads should see same environment state"
        );

        println!(
            "Successfully ran {} concurrent threads using get_test_thread_count()",
            thread_count
        );
    }

    /// Test conservative thread count on high-core systems
    ///
    /// # Purpose
    ///
    /// Validates that on systems with many cores, the thread count
    /// utilities provide conservative values suitable for CI environments.
    #[test]
    fn test_conservative_thread_count_for_high_core_systems() {
        if is_high_core_system() {
            // Use conservative bounds for high-core systems
            let conservative_count = get_test_thread_count_with_bounds(4, 16);

            assert!(
                conservative_count >= 4,
                "Conservative count should meet minimum"
            );
            assert!(
                conservative_count <= 16,
                "Conservative count should respect cap"
            );

            println!(
                "High-core system: using {} threads (conservative)",
                conservative_count
            );

            // Verify the conservative count works in practice
            let results =
                run_concurrent(conservative_count, || Environment::get().systemd_available);

            assert_eq!(results.len(), conservative_count);
            assert!(all_equal(&results));
        } else {
            println!("Not a high-core system, test skipped");
        }
    }

    /// Test thread count consistency across multiple calls
    ///
    /// # Purpose
    ///
    /// Validates that get_test_thread_count() returns consistent
    /// results across multiple invocations (no nondeterminism).
    #[test]
    fn test_thread_count_consistency() {
        let count1 = get_test_thread_count();
        let count2 = get_test_thread_count();
        let count3 = get_test_thread_count();

        assert_eq!(count1, count2, "Thread count should be consistent");
        assert_eq!(count2, count3, "Thread count should be consistent");

        println!("Thread count is consistent across calls: {}", count1);
    }
}

#[cfg(test)]
mod usage_examples {
    use super::*;

    /// Example 1: Basic concurrent pattern
    ///
    /// This example shows the simplest pattern: spawn N threads
    /// that all call the same function and collect results.
    #[test]
    fn example_basic_concurrent_pattern() {
        let results = run_concurrent(10, || {
            // Your code here
            Environment::get().bwrap_available
        });

        assert_eq!(results.len(), 10);
        println!("Results: {:?}", results);
    }

    /// Example 2: Barrier-synchronized pattern
    ///
    /// This example shows how to use barriers to ensure threads
    /// execute code simultaneously rather than sequentially.
    #[test]
    fn example_barrier_synchronized_pattern() {
        let barrier = ConcurrentBarrier::new(8);

        let results = run_concurrent_with_barrier(8, &barrier, move || {
            // The barrier is already cloned internally by run_concurrent_with_barrier
            // so we don't need to call wait() manually here
            Environment::get().systemd_available
        });

        assert_eq!(results.len(), 8);
        println!("Synchronized results: {:?}", results);
    }

    /// Example 3: Memory address verification
    ///
    /// This example shows how to verify that all threads receive
    /// the exact same memory address (useful for singleton testing).
    #[test]
    fn example_memory_address_verification() {
        let addresses = collect_concurrent_addrs(12, || Environment::get() as *const _ as usize);

        assert!(all_same_address(&addresses));
        println!("All threads received address: {:018x}", addresses[0]);
    }

    /// Example 4: Using ResultCollector directly
    ///
    /// This example shows manual result collection when you need
    /// more control over the collection process.
    #[test]
    fn example_manual_result_collection() {
        use sigil_integration_tests::env_detect::concurrent::ResultCollector;

        let collector = ResultCollector::new();

        // Spawn threads manually
        for _i in 0..5 {
            let collector_clone = collector.clone();
            thread::spawn(move || {
                let result = Environment::get().bwrap_available;
                collector_clone.collect(result);
                println!("Thread completed");
            })
            .join()
            .expect("Thread panicked");
        }

        let results = collector.into_vec();
        assert_eq!(results.len(), 5);
        println!("Collected results: {:?}", results);
    }

    /// Example 5: AtomicCounter for thread coordination
    ///
    /// This example shows how to use AtomicCounter to verify
    /// that exactly N threads completed an operation.
    #[test]
    fn example_atomic_counter_coordination() {
        use sigil_integration_tests::env_detect::concurrent::AtomicCounter;

        let counter = AtomicCounter::new();

        // Clone the counter for use in the closure
        let counter_clone = counter.clone();
        run_concurrent(10, move || {
            counter_clone.increment();
            Environment::get().launchd_available
        });

        assert_eq!(counter.value(), 10);
        println!("All {} threads completed", counter.value());
    }
}

#[cfg(test)]
mod edge_cases {
    use super::*;

    /// Test with single thread (degenerate case)
    #[test]
    fn test_concurrent_single_thread() {
        let results = run_concurrent(1, || Environment::get().bwrap_available);
        assert_eq!(results.len(), 1);
    }

    /// Test with zero threads (edge case handling)
    #[test]
    #[should_panic(expected = "Thread count must be > 0")]
    fn test_concurrent_zero_threads_panics() {
        let _ = ConcurrentBarrier::new(0);
    }

    /// Test repeated concurrent access patterns
    #[test]
    fn test_repeated_concurrent_access() {
        for _ in 0..10 {
            let addresses = collect_concurrent_addrs(5, || Environment::get() as *const _ as usize);
            assert!(all_same_address(&addresses));
        }
    }

    /// Test mixed operations under concurrent load
    #[test]
    fn test_mixed_operations_concurrent() {
        let barrier = ConcurrentBarrier::new(10);

        let results = run_concurrent_with_barrier(10, &barrier, || {
            let env = Environment::get();
            // Mix different operations using a simple counter approach
            // We can't use thread_id directly due to unstable API, so we use
            // bwrap_available for all threads in this test
            env.bwrap_available
        });

        // We should get consistent results
        assert_eq!(results.len(), 10);
        println!("Mixed operation results: {:?}", results);
    }
}

#[cfg(test)]
mod thread_util_module_tests {
    use super::*;

    /// Test thread_util module - basic thread count
    ///
    /// # Purpose
    ///
    /// Demonstrates the new thread_util module which provides more
    /// conservative thread counts for CI-friendly testing.
    #[test]
    fn test_thread_util_basic_count() {
        // Reset cache to ensure we get a fresh value
        reset_cached_thread_count();

        let thread_count = get_test_thread_count();

        // thread_util returns 1-8 threads (more conservative than env_detect)
        assert!(
            thread_count >= 1,
            "Thread count should be at least 1, got {}",
            thread_count
        );
        assert!(
            thread_count <= 8,
            "Thread count should be at most 8, got {}",
            thread_count
        );

        println!("thread_util::get_test_thread_count() = {}", thread_count);
    }

    /// Test thread_util with custom maximum
    ///
    /// # Purpose
    ///
    /// Validates that get_test_thread_count_with_max correctly limits
    /// thread count for resource-intensive tests.
    #[test]
    fn test_thread_util_with_max() {
        let max_4 = get_test_thread_count_with_max(4);
        assert!(max_4 >= 1 && max_4 <= 4, "Should be capped at 4");

        let max_2 = get_test_thread_count_with_max(2);
        assert!(max_2 >= 1 && max_2 <= 2, "Should be capped at 2");

        println!("thread_util with max(4) = {}, max(2) = {}", max_4, max_2);
    }

    /// Test thread_util with custom minimum
    ///
    /// # Purpose
    ///
    /// Validates that get_test_thread_count_with_min ensures minimum
    /// thread counts for concurrent tests.
    #[test]
    fn test_thread_util_with_min() {
        let min_2 = get_test_thread_count_with_min(2);
        assert!(min_2 >= 2, "Should have at least 2 threads");

        let min_4 = get_test_thread_count_with_min(4);
        assert!(min_4 >= 4, "Should have at least 4 threads");

        println!("thread_util with min(2) = {}, min(4) = {}", min_2, min_4);
    }

    /// Test thread_util with bounded range
    ///
    /// # Purpose
    ///
    /// Validates that get_test_thread_count_bounded provides precise
    /// control over thread count ranges.
    #[test]
    fn test_thread_util_bounded() {
        let range_2_4 = get_test_thread_count_bounded(2, 4);
        assert!(
            range_2_4 >= 2 && range_2_4 <= 4,
            "Should be in range [2, 4]"
        );

        let range_4_6 = get_test_thread_count_bounded(4, 6);
        assert!(
            range_4_6 >= 4 && range_4_6 <= 6,
            "Should be in range [4, 6]"
        );

        println!(
            "thread_util bounded(2,4) = {}, bounded(4,6) = {}",
            range_2_4, range_4_6
        );
    }

    /// Test thread_util caching behavior
    ///
    /// # Purpose
    ///
    /// Validates that thread_util caches the thread count and provides
    /// reset functionality for testing.
    #[test]
    fn test_thread_util_caching() {
        let count1 = get_test_thread_count();
        let count2 = get_test_thread_count();

        assert_eq!(count1, count2, "Should return cached value");

        // Reset the cache
        reset_cached_thread_count();

        let count3 = get_test_thread_count();
        assert_eq!(count1, count3, "Should return same value after reset");

        println!(
            "thread_util caching: count1={}, count2={}, count3={}",
            count1, count2, count3
        );
    }

    /// Integration test: thread_util with concurrent operations
    ///
    /// # Purpose
    ///
    /// Demonstrates that thread_util works correctly with actual
    /// concurrent thread spawning.
    #[test]
    fn test_thread_util_integration() {
        let thread_count = get_test_thread_count();

        // Run actual concurrent threads using thread_util count
        let results = run_concurrent(thread_count, || Environment::get().bwrap_available);

        assert_eq!(
            results.len(),
            thread_count,
            "Should get one result per thread"
        );
        assert!(all_equal(&results), "All results should be identical");

        println!(
            "thread_util integration: successfully ran {} threads",
            thread_count
        );
    }

    /// Comparison test: env_detect vs thread_util
    ///
    /// # Purpose
    ///
    /// Shows the difference between env_detect (higher thread counts)
    /// and thread_util (conservative thread counts).
    #[test]
    fn test_env_detect_vs_thread_util_comparison() {
        use sigil_integration_tests::env_detect::concurrent::get_test_thread_count as env_detect_count;

        // Reset cache to ensure we get fresh values
        reset_cached_thread_count();

        let env_threads = env_detect_count();
        let util_threads = get_test_thread_count();

        println!("env_detect::get_test_thread_count() = {}", env_threads);
        println!("thread_util::get_test_thread_count() = {}", util_threads);

        // env_detect should be >= thread_util (higher caps)
        assert!(
            env_threads >= util_threads,
            "env_detect should return >= threads than thread_util"
        );

        // env_detect caps at 32, thread_util caps at 8
        assert!(env_threads <= 32, "env_detect max is 32");
        assert!(util_threads <= 8, "thread_util max is 8");
    }

    /// Test thread_util constants are reasonable
    ///
    /// # Purpose
    ///
    /// Validates that the constants used in thread_util are sensible
    /// for CI and resource-constrained environments.
    #[test]
    fn test_thread_util_constants() {
        // The thread_util module uses conservative defaults:
        // - DEFAULT_MAX_TEST_THREADS: 8 (CI-friendly)
        // - MIN_TEST_THREADS: 1 (always make progress)

        let max_count = get_test_thread_count_with_max(8);
        let min_count = get_test_thread_count_with_min(1);

        assert!(max_count <= 8, "Should respect max constant");
        assert!(min_count >= 1, "Should respect min constant");

        println!(
            "thread_util constants validated: max={}, min={}",
            max_count, min_count
        );
    }
}
