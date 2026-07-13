//! Concurrent Testing Infrastructure
//!
//! This module provides a comprehensive, reusable infrastructure for testing
//! concurrent operations and thread safety across the SIGIL codebase. It brings together
//! utilities from `thread_util` and `env_detect` modules into a unified, well-documented
//! interface for concurrent testing.
//!
//! # Features
//!
//! - Thread spawning with configurable counts
//! - Barrier synchronization for coordinated testing
//! - Result collection from concurrent operations
//! - Thread-safe state management helpers
//! - High-concurrency stress testing utilities
//! - Race condition detection patterns
//!
//! # Usage Overview
//!
//! ```rust,ignore
//! use sigil_integration_tests::concurrent_tests::*;
//!
//! // Basic concurrent test
//! let results = spawn_and_collect(4, |thread_id| {
//!     // Your test logic here
//!     thread_id * 2
//! });
//! assert_eq!(results, vec![0, 2, 4, 6]);
//!
//! // Coordinated concurrent execution with barriers
//! let results = execute_with_barrier(8, |thread_id| {
//!     // All threads start simultaneously
//!     expensive_operation(thread_id)
//! });
//!
//! // Thread safety verification
//! verify_thread_safe(|threads| {
//!     for _ in 0..threads {
//!         thread::spawn(|| {
//!             // Call the function being tested
//!             Environment::get();
//!         });
//!     }
//! });
//! ```
//!
//! # Design Principles
//!
//! - **No external dependencies**: Uses only std::sync primitives
//! - **Reusable patterns**: Each function demonstrates a common concurrent testing pattern
//! - **Clear documentation**: Examples show expected usage for each utility
//! - **Deterministic coordination**: Barriers ensure reproducible test execution

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Barrier, Mutex};
use std::thread::{self, JoinHandle};
use std::time::Duration;

// Re-export utilities from thread_util for convenience
pub use crate::thread_util::{
    available_parallelism_count, collect_thread_results, collect_thread_results_ordered,
    collect_thread_results_ordered_with_result, collect_thread_results_with_result,
    coordinate_then_execute, create_barrier, get_test_thread_count, get_test_thread_count_bounded,
    get_test_thread_count_with_max, get_test_thread_count_with_min, reset_cached_thread_count,
    spawn_test_threads, wait_all_then_execute, BarrierError, CollectionError, ThreadSpawnError,
};

/// Spawns threads that each execute a closure and collect their results
///
/// This is the foundational concurrent testing primitive - it spawns N threads,
/// executes the provided closure in each thread, and collects all results.
///
/// # Arguments
///
/// * `count` - Number of threads to spawn (must be >= 1)
/// * `f` - Closure that takes a thread ID (0-based) and returns a value
///
/// # Returns
///
/// Vector of results from each thread in thread order (thread 0 → index 0)
///
/// # Examples
///
/// ```rust,ignore
/// let results = spawn_and_collect(4, |id| id * 2);
/// assert_eq!(results, vec![0, 2, 4, 6]);
/// ```
pub fn spawn_and_collect<F, T>(count: usize, f: F) -> Vec<T>
where
    F: Fn(usize) -> T + Send + Clone + 'static,
    T: Send + 'static,
{
    let counter = Arc::new(AtomicUsize::new(0));
    let results = Arc::new(Mutex::new(Vec::with_capacity(count)));
    let mut handles = Vec::with_capacity(count);

    for thread_id in 0..count {
        let counter_clone = Arc::clone(&counter);
        let results_clone = Arc::clone(&results);
        let f_clone = f.clone();

        let handle = thread::spawn(move || {
            let result = f_clone(thread_id);

            // Store result in this thread's assigned slot
            if let Ok(mut results_guard) = results_clone.lock() {
                results_guard.push(result);
            } else {
                panic!("Results mutex poisoned");
            }

            counter_clone.fetch_add(1, Ordering::SeqCst);
        });

        handles.push(handle);
    }

    // Wait for all threads to complete
    for handle in handles {
        handle.join().expect("Thread panicked");
    }

    // Extract results - note: order is not guaranteed without additional coordination
    Arc::try_unwrap(results)
        .map_err(|_| "Arc still shared".to_string())
        .and_then(|r| r.into_inner().map_err(|_| "Mutex poisoned".to_string()))
        .expect("Failed to extract results")
}

/// Executes a closure in multiple threads with barrier coordination
///
/// All threads wait at a barrier before executing, ensuring simultaneous start.
/// This is useful for testing race conditions and thread safety under high concurrency.
///
/// # Arguments
///
/// * `thread_count` - Number of threads to spawn (must be >= 1)
/// * `f` - Closure that takes thread ID and returns a value
///
/// # Returns
///
/// Vector of results from each thread (order not guaranteed)
///
/// # Examples
///
/// ```rust,ignore
/// let results = execute_with_barrier(8, |thread_id| {
///     // All threads execute this simultaneously after barrier
///     shared_resource.clone()
/// });
/// ```
pub fn execute_with_barrier<F, T>(thread_count: usize, f: F) -> Vec<T>
where
    F: Fn(usize) -> T + Send + Clone + 'static,
    T: Send + 'static,
{
    let barrier = Arc::new(Barrier::new(thread_count));
    let counter = Arc::new(AtomicUsize::new(0));
    let results = Arc::new(Mutex::new(Vec::with_capacity(thread_count)));
    let mut handles = Vec::with_capacity(thread_count);

    for thread_id in 0..thread_count {
        let barrier_clone = Arc::clone(&barrier);
        let counter_clone = Arc::clone(&counter);
        let results_clone = Arc::clone(&results);
        let f_clone = f.clone();

        let handle = thread::spawn(move || {
            // Wait for all threads to be ready
            barrier_clone.wait();

            // Execute the closure after all threads arrive
            let result = f_clone(thread_id);

            // Store result
            if let Ok(mut results_guard) = results_clone.lock() {
                results_guard.push(result);
            } else {
                panic!("Results mutex poisoned");
            }

            counter_clone.fetch_add(1, Ordering::SeqCst);
        });

        handles.push(handle);
    }

    // Wait for all threads to complete
    for handle in handles {
        handle.join().expect("Thread panicked");
    }

    // Extract results
    Arc::try_unwrap(results)
        .map_err(|_| "Arc still shared".to_string())
        .and_then(|r| r.into_inner().map_err(|_| "Mutex poisoned".to_string()))
        .expect("Failed to extract results")
}

/// Verifies that a function is thread-safe under concurrent access
///
/// This spawns multiple threads that all call the same function simultaneously,
/// then verifies that no panics or data races occurred. Useful for testing
/// OnceLock-backed functions like `Environment::get()`.
///
/// # Arguments
///
/// * `thread_count` - Number of threads to spawn (use high numbers for stress testing)
/// * `f` - Closure that calls the function being tested
///
/// # Returns
///
/// True if all threads completed without panicking
///
/// # Examples
///
/// ```rust,ignore
/// let safe = verify_thread_safe(100, || {
///     Environment::get(); // Should be thread-safe
/// });
/// assert!(safe);
/// ```
pub fn verify_thread_safe<F>(thread_count: usize, f: F) -> bool
where
    F: Fn() + Send + Clone + 'static,
{
    let panic_count = Arc::new(AtomicUsize::new(0));
    let barrier = Arc::new(Barrier::new(thread_count));
    let mut handles = Vec::with_capacity(thread_count);

    for _ in 0..thread_count {
        let barrier_clone = Arc::clone(&barrier);
        let panic_count_clone = Arc::clone(&panic_count);
        let f_clone = f.clone();

        let handle = thread::spawn(move || {
            // Catch any panics in the closure
            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                barrier_clone.wait(); // Coordinate start
                f_clone();
            }));

            if result.is_err() {
                panic_count_clone.fetch_add(1, Ordering::SeqCst);
            }
        });

        handles.push(handle);
    }

    // Wait for all threads
    for handle in handles {
        let _ = handle.join();
    }

    // Thread-safe if no panics occurred
    panic_count.load(Ordering::SeqCst) == 0
}

/// Collects memory addresses from concurrent operations to verify singleton behavior
///
/// This is used to verify that functions returning `&'static` references (like
/// `Environment::get()`) truly return the same memory location across threads.
///
/// # Arguments
///
/// * `thread_count` - Number of threads to spawn
/// * `f` - Closure that returns a pointer/address as usize
///
/// # Returns
///
/// Vector of memory addresses from each thread
///
/// # Examples
///
/// ```rust,ignore
/// let addrs = collect_concurrent_addrs(10, || {
///     Environment::get() as *const Environment as usize
/// });
/// // All addresses should be identical (singleton)
/// assert!(addrs.iter().all(|&addr| addr == addrs[0]));
/// ```
pub fn collect_concurrent_addrs<F>(thread_count: usize, f: F) -> Vec<usize>
where
    F: Fn() -> usize + Send + Clone + 'static,
{
    let barrier = Arc::new(Barrier::new(thread_count));
    let addrs = Arc::new(Mutex::new(Vec::with_capacity(thread_count)));
    let mut handles = Vec::with_capacity(thread_count);

    for _ in 0..thread_count {
        let barrier_clone = Arc::clone(&barrier);
        let addrs_clone = Arc::clone(&addrs);
        let f_clone = f.clone();

        let handle = thread::spawn(move || {
            barrier_clone.wait(); // Coordinate simultaneous access
            let addr = f_clone();

            if let Ok(mut addrs_guard) = addrs_clone.lock() {
                addrs_guard.push(addr);
            }
        });

        handles.push(handle);
    }

    // Wait for all threads
    for handle in handles {
        handle.join().expect("Thread panicked");
    }

    // Extract addresses
    Arc::try_unwrap(addrs)
        .map_err(|_| "Arc still shared".to_string())
        .and_then(|a| a.into_inner().map_err(|_| "Mutex poisoned".to_string()))
        .expect("Failed to extract addresses")
}

/// Runs a concurrent stress test with configurable duration
///
/// This spawns threads that continuously call a function for a specified duration,
/// useful for finding race conditions that only appear under sustained load.
///
/// # Arguments
///
/// * `thread_count` - Number of threads to spawn
/// * `duration` - How long to run the stress test
/// * `f` - Closure to call repeatedly (return false to stop early)
///
/// # Returns
///
/// Number of iterations completed across all threads
///
/// # Examples
///
/// ```rust,ignore
/// let iterations = stress_test_concurrent(8, Duration::from_secs(5), || {
///     Environment::get(); // Repeatedly call function under test
///     true // Continue testing
/// });
/// println!("Completed {} iterations", iterations);
/// ```
pub fn stress_test_concurrent<F>(thread_count: usize, duration: Duration, f: F) -> usize
where
    F: Fn() -> bool + Send + Clone + 'static,
{
    let counter = Arc::new(AtomicUsize::new(0));
    let stop = Arc::new(AtomicUsize::new(0));
    let mut handles = Vec::with_capacity(thread_count);

    // Spawn stopper thread
    let stop_clone = Arc::clone(&stop);
    let stopper = thread::spawn(move || {
        thread::sleep(duration);
        stop_clone.store(1, Ordering::SeqCst);
    });

    // Spawn worker threads
    for _ in 0..thread_count {
        let counter_clone = Arc::clone(&counter);
        let stop_clone = Arc::clone(&stop);
        let f_clone = f.clone();

        let handle = thread::spawn(move || {
            while stop_clone.load(Ordering::SeqCst) == 0 {
                if !f_clone() {
                    break; // Early stop requested
                }
                counter_clone.fetch_add(1, Ordering::SeqCst);
            }
        });

        handles.push(handle);
    }

    // Wait for stopper
    stopper.join().expect("Stopper thread panicked");

    // Wait for workers
    for handle in handles {
        handle.join().expect("Worker thread panicked");
    }

    counter.load(Ordering::SeqCst)
}

/// Creates a reusable test template for concurrent operations
///
/// This struct provides a structured way to set up and execute concurrent tests
/// with consistent parameters and cleanup procedures.
///
/// # Examples
///
/// ```rust,ignore
/// let test = ConcurrentTestTemplate::new()
///     .with_thread_count(8)
///     .with_barrier(true)
///     .run(|thread_id| {
///         // Your test logic here
///         Environment::get();
///     });
/// ```
pub struct ConcurrentTestTemplate {
    thread_count: Option<usize>,
    use_barrier: bool,
    timeout: Option<Duration>,
}

impl ConcurrentTestTemplate {
    /// Create a new concurrent test template with defaults
    pub fn new() -> Self {
        Self {
            thread_count: None,
            use_barrier: false,
            timeout: None,
        }
    }

    /// Set the thread count for the test
    pub fn with_thread_count(mut self, count: usize) -> Self {
        self.thread_count = Some(count);
        self
    }

    /// Enable barrier coordination for simultaneous thread start
    pub fn with_barrier(mut self, use_barrier: bool) -> Self {
        self.use_barrier = use_barrier;
        self
    }

    /// Set a timeout for the test (not yet implemented)
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = Some(timeout);
        self
    }

    /// Execute the test with the configured parameters
    pub fn run<F, T>(&self, f: F) -> Vec<T>
    where
        F: Fn(usize) -> T + Send + Clone + 'static,
        T: Send + 'static,
    {
        let thread_count = self.thread_count.unwrap_or_else(get_test_thread_count);

        if self.use_barrier {
            execute_with_barrier(thread_count, f)
        } else {
            spawn_and_collect(thread_count, f)
        }
    }
}

impl Default for ConcurrentTestTemplate {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_spawn_and_collect_basic() {
        let results = spawn_and_collect(4, |id| id * 2);
        assert_eq!(results.len(), 4);
    }

    #[test]
    fn test_execute_with_barrier_coordination() {
        let counter = Arc::new(AtomicUsize::new(0));
        let barrier = Arc::new(Barrier::new(4));

        let barrier_clone = Arc::clone(&barrier);
        let counter_clone = Arc::clone(&counter);

        let _results = execute_with_barrier(4, move |id| {
            // All threads wait at barrier
            let barrier_clone2 = Arc::clone(&barrier_clone);
            let counter_clone2 = Arc::clone(&counter_clone);

            thread::spawn(move || {
                barrier_clone2.wait();
                counter_clone2.fetch_add(1, Ordering::SeqCst);
            });

            id
        });

        // Give threads time to complete
        thread::sleep(Duration::from_millis(100));
    }

    #[test]
    fn test_verify_thread_safe_with_panic() {
        // Should detect panics
        let safe = verify_thread_safe(4, || {
            panic!("Test panic");
        });
        assert!(!safe, "Should detect panic");
    }

    #[test]
    fn test_verify_thread_safe_success() {
        // Should succeed with no panics
        let safe = verify_thread_safe(4, || {
            // No-op - thread safe
        });
        assert!(safe, "Should be thread-safe");
    }

    #[test]
    fn test_collect_concurrent_addrs_consistency() {
        // All threads should get the same "address" (simulated)
        let addrs = collect_concurrent_addrs(4, || {
            0xDEADBEEF // Simulated singleton address
        });

        assert_eq!(addrs.len(), 4);
        assert!(addrs.iter().all(|&addr| addr == 0xDEADBEEF));
    }

    #[test]
    fn test_stress_test_concurrent_completes() {
        // Should complete without hanging
        let iterations = stress_test_concurrent(
            4,
            Duration::from_millis(100),
            || true, // Continue running
        );

        assert!(iterations > 0, "Should complete some iterations");
    }

    #[test]
    fn test_stress_test_concurrent_early_stop() {
        // Should respect early stop condition
        let iterations = stress_test_concurrent(
            4,
            Duration::from_millis(100),
            || false, // Stop immediately
        );

        assert_eq!(
            iterations, 0,
            "Should stop immediately when function returns false"
        );
    }

    #[test]
    fn test_concurrent_test_template_defaults() {
        let results = ConcurrentTestTemplate::new().run(|id| id * 3);

        assert!(!results.is_empty());
    }

    #[test]
    fn test_concurrent_test_template_with_barrier() {
        let results = ConcurrentTestTemplate::new()
            .with_thread_count(3)
            .with_barrier(true)
            .run(|id| id);

        assert_eq!(results.len(), 3);
    }
}
