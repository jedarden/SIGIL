//! Thread spawn helper utilities for testing and concurrent operations
//!
//! This module provides reusable helper functions for spawning multiple threads
//! with proper error handling and resource management, plus barrier synchronization
//! utilities for coordinating concurrent test execution.

use std::fmt;
use std::io;
use std::sync::{Arc, Barrier};
use std::thread;
use std::time::Duration;

/// Error type for thread spawn failures
#[derive(Debug)]
pub enum ThreadSpawnError {
    /// Thread spawn failed due to system resource limits
    SpawnFailed(io::Error),
    /// Thread count exceeds available parallelism
    TooManyThreads { requested: usize, available: usize },
}

impl fmt::Display for ThreadSpawnError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ThreadSpawnError::SpawnFailed(e) => {
                write!(f, "Failed to spawn thread: {}", e)
            }
            ThreadSpawnError::TooManyThreads {
                requested,
                available,
            } => {
                write!(
                    f,
                    "Requested {} threads but only {} parallel threads are available",
                    requested, available
                )
            }
        }
    }
}

impl std::error::Error for ThreadSpawnError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            ThreadSpawnError::SpawnFailed(e) => Some(e),
            ThreadSpawnError::TooManyThreads { .. } => None,
        }
    }
}

impl From<io::Error> for ThreadSpawnError {
    fn from(err: io::Error) -> Self {
        ThreadSpawnError::SpawnFailed(err)
    }
}

/// Result type for thread operations
pub type ThreadResult<T> = std::result::Result<T, ThreadSpawnError>;

/// Get the number of available parallel threads on the system
///
/// This uses `std::thread::available_parallelism` which returns the number
/// of CPU threads available to the process. This is the recommended way to
/// determine the optimal thread count for parallel operations.
///
/// # Example
///
/// ```no_run
/// use sigil_core::thread_utils::available_parallelism;
///
/// let num_threads = available_parallelism();
/// println!("Available parallel threads: {}", num_threads);
/// ```
pub fn available_parallelism() -> usize {
    thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(1) // Fallback to 1 if unavailable
}

/// Spawn N threads, each running the provided closure
///
/// This function spawns exactly `count` threads, each executing the closure `f`.
/// The closure is called with the thread index (0..count) as its parameter.
///
/// # Parameters
///
/// * `count` - Number of threads to spawn
/// * `f` - Closure to execute in each thread, receives thread index as parameter
///
/// # Returns
///
/// * `Ok(Vec<thread::JoinHandle<()>>)` - Vector of join handles for all spawned threads
/// * `Err(ThreadSpawnError)` - If thread spawn fails or count exceeds available parallelism
///
/// # Example
///
/// ```
/// use sigil_core::thread_utils::spawn_threads;
///
/// let handles = spawn_threads(4, |i| {
///     println!("Thread {} running", i);
///     // Do work here
/// }).unwrap();
///
/// // Wait for all threads to complete
/// for handle in handles {
///     handle.join().unwrap();
/// }
/// ```
pub fn spawn_threads<F>(count: usize, f: F) -> ThreadResult<Vec<thread::JoinHandle<()>>>
where
    F: FnOnce(usize) + Send + Clone + 'static,
{
    let available = available_parallelism();

    if count > available {
        return Err(ThreadSpawnError::TooManyThreads {
            requested: count,
            available,
        });
    }

    let mut handles = Vec::with_capacity(count);

    for i in 0..count {
        let f_clone = f.clone();
        let handle = thread::Builder::new()
            .name(format!("sigil-worker-{}", i))
            .spawn(move || f_clone(i))?;
        handles.push(handle);
    }

    Ok(handles)
}

/// Spawn N threads and wait for all to complete, returning their results
///
/// This is a convenience function that spawns threads and automatically joins them,
/// collecting the results into a vector. The results are returned in thread index order.
///
/// # Parameters
///
/// * `count` - Number of threads to spawn
/// * `f` - Closure to execute in each thread, receives thread index and returns a value
///
/// # Returns
///
/// * `Ok(Vec<T>)` - Vector of results from all threads, in index order
/// * `Err(ThreadSpawnError)` - If thread spawn fails or count exceeds available parallelism
///
/// # Example
///
/// ```
/// use sigil_core::thread_utils::spawn_and_collect;
///
/// let results = spawn_and_collect(4, |i| i * 2).unwrap();
/// assert_eq!(results, vec![0, 2, 4, 6]);
/// ```
pub fn spawn_and_collect<F, T>(count: usize, f: F) -> ThreadResult<Vec<T>>
where
    F: FnOnce(usize) -> T + Send + Clone + 'static,
    T: Send + Clone + 'static,
{
    use std::sync::mpsc;

    let (sender, receiver) = mpsc::channel();
    let mut handles = Vec::with_capacity(count);
    let available = available_parallelism();

    if count > available {
        return Err(ThreadSpawnError::TooManyThreads {
            requested: count,
            available,
        });
    }

    for i in 0..count {
        let f_clone = f.clone();
        let sender_clone = sender.clone();
        let handle = thread::Builder::new()
            .name(format!("sigil-worker-{}", i))
            .spawn(move || {
                let result = f_clone(i);
                // Send result with index for ordering
                sender_clone.send((i, result)).unwrap();
            })?;
        handles.push(handle);
    }

    // Drop the original sender so the channel closes when all threads finish
    drop(sender);

    // Join all threads first to propagate any panics
    for handle in handles {
        handle.join().map_err(|e| {
            ThreadSpawnError::SpawnFailed(io::Error::new(
                io::ErrorKind::Other,
                format!("Thread panicked: {:?}", e),
            ))
        })?;
    }

    // Collect results in order
    let mut results: Vec<Option<T>> = Vec::with_capacity(count);
    results.resize_with(count, || None);
    for (index, result) in receiver {
        results[index] = Some(result);
    }

    // Convert None to Some (should never happen if logic is correct)
    let results = results.into_iter().map(|r| r.unwrap()).collect();
    Ok(results)
}

/// Join all thread handles, propagating panics and errors
///
/// This function joins all handles in the vector. If any thread panicked,
/// the panic is propagated. Returns success only if all threads completed
/// without panicking.
///
/// # Parameters
///
/// * `handles` - Vector of thread join handles
///
/// # Returns
///
/// * `Ok(())` - All threads completed successfully
/// * `Err(ThreadSpawnError)` - Any thread panicked or failed to join
///
/// # Example
///
/// ```
/// use sigil_core::thread_utils::{spawn_threads, join_all};
///
/// let handles = spawn_threads(4, |i| {
///     println!("Thread {} working", i);
/// }).unwrap();
///
/// join_all(handles).unwrap();
/// ```
pub fn join_all(handles: Vec<thread::JoinHandle<()>>) -> ThreadResult<()> {
    for handle in handles {
        handle.join().map_err(|e| {
            ThreadSpawnError::SpawnFailed(io::Error::new(
                io::ErrorKind::Other,
                format!("Thread panicked: {:?}", e),
            ))
        })?;
    }
    Ok(())
}

// ============================================================================
// Barrier Synchronization Utilities
// ============================================================================

/// Error type for barrier synchronization failures
#[derive(Debug, Clone, PartialEq, Eq)]
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

impl fmt::Display for BarrierError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
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
/// ```no_run
/// use sigil_core::thread_utils::create_barrier;
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

/// Test-friendly barrier wrapper with timeout support
///
/// `TestBarrier` wraps `std::sync::Barrier` to provide a test-friendly API
/// for coordinating concurrent thread execution with deadlock prevention
/// through timeout handling.
///
/// # Overview
///
/// A barrier allows multiple threads to synchronize at a specific point:
/// all threads must reach the barrier before any can proceed. This is
/// particularly useful in testing for:
///
/// - **Coordinated testing**: Ensure all threads reach a specific state simultaneously
/// - **Race condition testing**: Force threads to arrive at a point at the same time
/// - **Setup/teardown**: Wait for all threads to complete setup before main test execution
/// - **Deterministic ordering**: Create reproducible thread execution patterns
///
/// # Timeout Protection
///
/// Unlike `std::sync::Barrier`, `TestBarrier` provides timeout-based waiting
/// to prevent test hangs from deadlocks or stuck threads. If threads don't
/// reach the barrier within the specified timeout, an error is returned.
///
/// # Examples
///
/// Basic barrier coordination:
///
/// ```no_run
/// use sigil_core::thread_utils::TestBarrier;
/// use std::sync::Arc;
/// use std::thread;
///
/// let barrier = Arc::new(TestBarrier::new(2));
/// let barrier_clone = Arc::clone(&barrier);
///
/// // Spawn two threads that coordinate
/// let h1 = thread::spawn(move || {
///     // Do some work
///     barrier_clone.wait().expect("Barrier wait failed");
///     // Continue after both threads arrive
/// });
///
/// let h2 = thread::spawn(move || {
///     barrier.wait().expect("Barrier wait failed");
///     // Continue after both threads arrive
/// });
///
/// h1.join().unwrap();
/// h2.join().unwrap();
/// ```
///
/// Barrier with timeout protection:
///
/// ```no_run
/// use sigil_core::thread_utils::TestBarrier;
/// use std::sync::Arc;
/// use std::thread;
/// use std::time::Duration;
///
/// let barrier = Arc::new(TestBarrier::new(2));
/// let barrier_clone = Arc::clone(&barrier);
///
/// let h1 = thread::spawn(move || {
///     // This will timeout if the other thread doesn't reach the barrier
///     match barrier_clone.wait_timeout(Duration::from_secs(5)) {
///         Ok(_) => println!("Both threads arrived"),
///         Err(e) => eprintln!("Barrier timeout: {}", e),
///     }
/// });
///
/// let h2 = thread::spawn(move || {
///     barrier.wait().expect("Barrier wait failed");
/// });
///
/// h1.join().unwrap();
/// h2.join().unwrap();
/// ```
///
/// # Thread Count
///
/// The barrier requires exactly `n` threads to call `wait()` before any
/// thread can proceed. If fewer than `n` threads reach the barrier, the
/// remaining threads will block indefinitely (or until timeout expires).
///
/// # Reusability
///
/// The barrier can be reused after all threads are released. Each call to
/// `wait()` or `wait_timeout()` resets the barrier for the next synchronization
/// point.
#[derive(Debug, Clone)]
pub struct TestBarrier {
    /// The underlying std::sync::Barrier wrapped in Arc for sharing
    inner: Arc<Barrier>,
    /// Number of threads this barrier coordinates
    thread_count: usize,
}

impl TestBarrier {
    /// Create a new `TestBarrier` for coordinating `n` threads
    ///
    /// # Arguments
    ///
    /// * `n` - Number of threads that will wait on this barrier (must be >= 1)
    ///
    /// # Returns
    ///
    /// A new `TestBarrier` instance
    ///
    /// # Panics
    ///
    /// Panics if `n` is 0
    ///
    /// # Examples
    ///
    /// ```
    /// use sigil_core::thread_utils::TestBarrier;
    ///
    /// let barrier = TestBarrier::new(3);
    /// // Coordinates 3 threads
    /// ```
    pub fn new(n: usize) -> Self {
        assert!(n > 0, "Barrier thread count must be at least 1");
        Self {
            inner: Arc::new(Barrier::new(n)),
            thread_count: n,
        }
    }

    /// Get the number of threads this barrier coordinates
    ///
    /// # Returns
    ///
    /// The number of threads required to synchronize at this barrier
    ///
    /// # Examples
    ///
    /// ```
    /// use sigil_core::thread_utils::TestBarrier;
    ///
    /// let barrier = TestBarrier::new(4);
    /// assert_eq!(barrier.thread_count(), 4);
    /// ```
    #[must_use]
    pub const fn thread_count(&self) -> usize {
        self.thread_count
    }

    /// Synchronize with all other threads waiting at this barrier
    ///
    /// This call blocks until all `n` threads have called `wait()`. Once all
    /// threads arrive, all are unblocked simultaneously and the barrier is
    /// reset for the next synchronization.
    ///
    /// # Behavior
    ///
    /// - Blocks the current thread until all `n` threads have called `wait()`
    /// - Returns a boolean indicating if this thread is the "leader" (last to arrive)
    /// - The barrier is reusable after all threads are released
    ///
    /// # Returns
    ///
    /// * `Ok(true)` - This thread was the last to arrive (is the "leader")
    /// * `Ok(false)` - Other threads are still waiting
    /// * `Err(BarrierError)` - Synchronization error
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use sigil_core::thread_utils::TestBarrier;
    /// use std::sync::Arc;
    /// use std::thread;
    ///
    /// let barrier = Arc::new(TestBarrier::new(2));
    /// let barrier_clone = Arc::clone(&barrier);
    ///
    /// let h1 = thread::spawn(move || {
    ///     let is_leader = barrier_clone.wait().expect("Failed to wait");
    ///     println!("Thread 1: is_leader = {}", is_leader);
    /// });
    ///
    /// let h2 = thread::spawn(move || {
    ///     let is_leader = barrier.wait().expect("Failed to wait");
    ///     println!("Thread 2: is_leader = {}", is_leader);
    /// });
    ///
    /// h1.join().unwrap();
    /// h2.join().unwrap();
    /// ```
    ///
    /// # Errors
    ///
    /// Returns `BarrierError` if synchronization fails
    pub fn wait(&self) -> Result<bool, BarrierError> {
        let is_leader = self.inner.wait();
        Ok(is_leader.is_leader())
    }

    /// Synchronize with timeout protection against deadlocks
    ///
    /// This method provides the same synchronization as `wait()` but with
    /// a timeout to prevent test hangs. If the specified timeout expires
    /// before all threads reach the barrier, an error is returned.
    ///
    /// # Arguments
    ///
    /// * `timeout` - Maximum duration to wait for all threads to arrive
    ///
    /// # Behavior
    ///
    /// 1. Spawn a watcher thread that waits for the barrier
    /// 2. Wait for the watcher thread with the specified timeout using a channel
    /// 3. If complete within timeout, return the leader status
    /// 4. If timeout expires, return an error
    ///
    /// # Returns
    ///
    /// * `Ok(true)` - This thread is the leader (last to arrive)
    /// * `Ok(false)` - Other threads are still waiting
    /// * `Err(BarrierError)` - Timeout or synchronization error
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use sigil_core::thread_utils::TestBarrier;
    /// use std::time::Duration;
    ///
    /// let barrier = TestBarrier::new(2);
    ///
    /// match barrier.wait_timeout(Duration::from_secs(5)) {
    ///     Ok(is_leader) => println!("Synchronized, leader: {}", is_leader),
    ///     Err(e) => eprintln!("Timeout: {}", e),
    /// }
    /// ```
    ///
    /// # Timeout Behavior
    ///
    /// - **Timeout expires**: Returns `BarrierError::Timeout` even if threads would eventually arrive
    /// - **Thread continues**: Timed-out threads may continue running in the background
    /// - **Not forceful**: This does not forcefully terminate stuck threads
    ///
    /// # When to Use Timeouts
    ///
    /// - **Deadlock testing**: Detect when operations hang indefinitely
    /// - **CI reliability**: Prevent tests from hanging build pipelines
    /// - **Resource cleanup**: Ensure threads complete within reasonable time
    /// - **Infinite loop prevention**: Catch code that never returns
    pub fn wait_timeout(&self, timeout: Duration) -> Result<bool, BarrierError> {
        use std::sync::mpsc::{self as mpsc, Receiver, Sender};

        let (tx, rx): (
            Sender<Result<bool, BarrierError>>,
            Receiver<Result<bool, BarrierError>>,
        ) = mpsc::channel();
        let barrier_clone = self.clone();

        std::thread::spawn(move || {
            let is_leader = barrier_clone.wait();
            // Ignore send errors if receiver was dropped due to timeout
            let _ = tx.send(is_leader);
        });

        // Wait for result with timeout
        match rx.recv_timeout(timeout) {
            Ok(Ok(is_leader)) => Ok(is_leader),
            Ok(Err(e)) => Err(e),
            Err(_) => Err(BarrierError::Timeout { duration: timeout }),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;
    use std::time::Duration;

    #[test]
    fn test_available_parallelism() {
        let parallelism = available_parallelism();
        assert!(parallelism >= 1, "At least one thread should be available");
    }

    #[test]
    fn test_spawn_threads_basic() {
        let counter = Arc::new(AtomicUsize::new(0));
        let num_threads = available_parallelism().min(4);

        let handles = spawn_threads(num_threads, {
            let counter = Arc::clone(&counter);
            move |i| {
                counter.fetch_add(1, Ordering::SeqCst);
                println!("Thread {} executing", i);
            }
        })
        .unwrap();

        join_all(handles).unwrap();

        assert_eq!(counter.load(Ordering::SeqCst), num_threads);
    }

    #[test]
    fn test_spawn_threads_single() {
        let handles = spawn_threads(1, |i| {
            assert_eq!(i, 0);
        })
        .unwrap();

        join_all(handles).unwrap();
    }

    #[test]
    fn test_spawn_and_collect() {
        let num_threads = available_parallelism().min(4);
        let results = spawn_and_collect(num_threads, |i| i * 2).unwrap();
        let expected: Vec<usize> = (0..num_threads).map(|i| i * 2).collect();
        assert_eq!(results, expected);
    }

    #[test]
    fn test_spawn_and_collect_string() {
        let num_threads = available_parallelism().min(3);
        let results = spawn_and_collect(num_threads, |i| format!("thread-{}", i)).unwrap();
        let expected: Vec<String> = (0..num_threads).map(|i| format!("thread-{}", i)).collect();
        assert_eq!(results, expected);
    }

    #[test]
    fn test_spawn_threads_exceeds_parallelism() {
        let available = available_parallelism().min(2); // Ensure at least 2 threads for this test

        let result = spawn_threads(available + 1, |_| {});
        assert!(
            result.is_err(),
            "Should error when requesting too many threads"
        );

        match result {
            Err(ThreadSpawnError::TooManyThreads {
                requested,
                available: avail,
            }) => {
                assert_eq!(requested, available + 1);
                assert_eq!(avail, available);
            }
            _ => panic!("Expected TooManyThreads error"),
        }
    }

    #[test]
    fn test_join_all_propagates_panic() {
        let handles = spawn_threads(2, |_i| {
            panic!("Intentional panic in thread 1");
        })
        .unwrap();

        let result = join_all(handles);
        assert!(result.is_err(), "Should propagate thread panic");
    }

    #[test]
    fn test_spawn_threads_named() {
        let handles = spawn_threads(2, |_i| {
            let current = thread::current();
            let name = current.name().unwrap_or("");
            assert!(
                name.starts_with("sigil-worker-"),
                "Thread should have sigil-worker- prefix"
            );
        })
        .unwrap();

        join_all(handles).unwrap();
    }

    #[test]
    fn test_thread_spawn_error_display() {
        let err = ThreadSpawnError::TooManyThreads {
            requested: 8,
            available: 4,
        };
        let display = format!("{}", err);
        assert!(display.contains("8 threads") && display.contains("4 parallel"));
    }

    #[test]
    fn test_spawn_and_collect_with_complex_type() {
        #[derive(Debug, PartialEq, Clone)]
        struct Point {
            x: i32,
            y: i32,
        }

        let num_threads = available_parallelism().min(3);
        let results = spawn_and_collect(num_threads, |i| Point {
            x: i as i32,
            y: i as i32 * 2,
        })
        .unwrap();
        let expected: Vec<Point> = (0..num_threads)
            .map(|i| Point {
                x: i as i32,
                y: i as i32 * 2,
            })
            .collect();
        assert_eq!(results, expected);
    }

    // === Barrier Synchronization Tests ===

    #[test]
    fn test_create_barrier() {
        let _barrier = create_barrier(2);
        // Just verify it creates successfully
        // Real usage requires multiple threads
    }

    #[test]
    #[should_panic(expected = "Barrier thread count must be at least 1")]
    fn test_create_barrier_zero_panics() {
        create_barrier(0);
    }

    #[test]
    fn test_test_barrier_new() {
        let barrier = TestBarrier::new(3);
        assert_eq!(barrier.thread_count(), 3);
    }

    #[test]
    #[should_panic(expected = "Barrier thread count must be at least 1")]
    fn test_test_barrier_new_zero_panics() {
        TestBarrier::new(0);
    }

    #[test]
    fn test_test_barrier_thread_count() {
        let barrier = TestBarrier::new(5);
        assert_eq!(barrier.thread_count(), 5);
    }

    #[test]
    fn test_test_barrier_wait_two_threads() {
        let barrier = Arc::new(TestBarrier::new(2));
        let barrier_clone = Arc::clone(&barrier);

        let counter = Arc::new(AtomicUsize::new(0));
        let counter_clone1 = Arc::clone(&counter);
        let counter_clone2 = Arc::clone(&counter);

        let h1 = thread::spawn(move || {
            counter_clone1.fetch_add(1, Ordering::SeqCst);
            barrier_clone.wait().unwrap();
            counter_clone1.fetch_add(10, Ordering::SeqCst);
        });

        let barrier_clone2 = Arc::clone(&barrier);
        let h2 = thread::spawn(move || {
            counter_clone2.fetch_add(1, Ordering::SeqCst);
            barrier_clone2.wait().unwrap();
            counter_clone2.fetch_add(10, Ordering::SeqCst);
        });

        h1.join().unwrap();
        h2.join().unwrap();

        // Both threads should have completed: 2 (initial) + 20 (after barrier)
        assert_eq!(counter.load(Ordering::SeqCst), 22);
    }

    #[test]
    fn test_test_barrier_wait_leader_detection() {
        let barrier = Arc::new(TestBarrier::new(2));
        let barrier_clone = Arc::clone(&barrier);

        let leader1 = Arc::new(AtomicUsize::new(0));
        let leader2 = Arc::new(AtomicUsize::new(0));
        let leader1_clone = Arc::clone(&leader1);
        let leader2_clone = Arc::clone(&leader2);
        let leader2_assert = Arc::clone(&leader2);

        let h1 = thread::spawn(move || {
            if barrier_clone.wait().unwrap() {
                leader1_clone.fetch_add(1, Ordering::SeqCst);
            }
        });

        let barrier_clone2 = Arc::clone(&barrier);
        let h2 = thread::spawn(move || {
            if barrier_clone2.wait().unwrap() {
                leader2_clone.fetch_add(1, Ordering::SeqCst);
            }
        });

        h1.join().unwrap();
        h2.join().unwrap();

        // Exactly one thread should be the leader
        let total_leaders = leader1.load(Ordering::SeqCst) + leader2_assert.load(Ordering::SeqCst);
        assert_eq!(total_leaders, 1, "Exactly one thread should be the leader");
    }

    #[test]
    fn test_test_barrier_wait_multiple_threads() {
        let num_threads = 4;
        let barrier = Arc::new(TestBarrier::new(num_threads));
        let counter = Arc::new(AtomicUsize::new(0));

        let mut handles = Vec::new();

        for _i in 0..num_threads {
            let barrier_clone = Arc::clone(&barrier);
            let counter_clone = Arc::clone(&counter);

            let handle = thread::spawn(move || {
                // Each thread increments before barrier
                counter_clone.fetch_add(1, Ordering::SeqCst);

                // Wait for all threads
                barrier_clone.wait().unwrap();

                // Each thread increments after barrier
                counter_clone.fetch_add(10, Ordering::SeqCst);
            });

            handles.push(handle);
        }

        // Wait for all threads
        for handle in handles {
            handle.join().unwrap();
        }

        // All threads should have completed: 4 (initial) + 40 (after barrier)
        assert_eq!(counter.load(Ordering::SeqCst), 44);
    }

    #[test]
    fn test_test_barrier_wait_timeout_success() {
        let barrier = Arc::new(TestBarrier::new(2));
        let barrier_clone = Arc::clone(&barrier);

        let h1 = thread::spawn(move || {
            // This should succeed within timeout
            match barrier_clone.wait_timeout(Duration::from_secs(5)) {
                Ok(_) => true,
                Err(_) => false,
            }
        });

        let barrier_clone2 = Arc::clone(&barrier);
        let h2 = thread::spawn(move || {
            // Reach the barrier quickly
            thread::sleep(Duration::from_millis(10));
            barrier_clone2.wait().unwrap();
            true
        });

        let r1 = h1.join().unwrap();
        let r2 = h2.join().unwrap();

        assert!(r1, "Thread 1 should complete successfully");
        assert!(r2, "Thread 2 should complete successfully");
    }

    #[test]
    fn test_test_barrier_wait_timeout_expired() {
        let barrier = Arc::new(TestBarrier::new(2));
        let barrier_clone = Arc::clone(&barrier);

        let h1 = thread::spawn(move || {
            // This will timeout because thread 2 never reaches the barrier
            match barrier_clone.wait_timeout(Duration::from_millis(100)) {
                Ok(_) => false, // Should not succeed
                Err(e) => {
                    matches!(e, BarrierError::Timeout { .. })
                }
            }
        });

        // Thread 2 never calls wait() - simulating a deadlock
        let h2 = thread::spawn(move || {
            thread::sleep(Duration::from_secs(1));
            true
        });

        let r1 = h1.join().unwrap();
        let r2 = h2.join().unwrap();

        assert!(r1, "Thread 1 should detect timeout");
        assert!(
            r2,
            "Thread 2 should complete (though it never reached barrier)"
        );
    }

    #[test]
    fn test_test_barrier_reusability() {
        let barrier = Arc::new(TestBarrier::new(2));
        let counter = Arc::new(AtomicUsize::new(0));
        let counter_clone1 = Arc::clone(&counter);
        let counter_clone2 = Arc::clone(&counter);

        // First synchronization
        let barrier_clone1 = Arc::clone(&barrier);
        let h1 = thread::spawn(move || {
            barrier_clone1.wait().unwrap();
            counter_clone1.fetch_add(1, Ordering::SeqCst);
        });

        let barrier_clone2 = Arc::clone(&barrier);
        let h2 = thread::spawn(move || {
            barrier_clone2.wait().unwrap();
            counter_clone2.fetch_add(1, Ordering::SeqCst);
        });

        h1.join().unwrap();
        h2.join().unwrap();

        assert_eq!(counter.load(Ordering::SeqCst), 2);

        // Second synchronization - reuse the same barrier
        let counter_clone3 = Arc::clone(&counter);
        let counter_clone4 = Arc::clone(&counter);
        let barrier_clone3 = Arc::clone(&barrier);
        let h3 = thread::spawn(move || {
            barrier_clone3.wait().unwrap();
            counter_clone3.fetch_add(10, Ordering::SeqCst);
        });

        let barrier_clone4 = Arc::clone(&barrier);
        let h4 = thread::spawn(move || {
            barrier_clone4.wait().unwrap();
            counter_clone4.fetch_add(10, Ordering::SeqCst);
        });

        h3.join().unwrap();
        h4.join().unwrap();

        assert_eq!(counter.load(Ordering::SeqCst), 22); // 2 + 20
    }

    #[test]
    fn test_barrier_error_display() {
        let err = BarrierError::ZeroThreadCount;
        assert!(format!("{}", err).contains("Cannot coordinate zero threads"));

        let err2 = BarrierError::Timeout {
            duration: Duration::from_secs(5),
        };
        assert!(format!("{}", err2).contains("exceeded timeout"));
    }

    #[test]
    fn test_barrier_error_clone() {
        let err1 = BarrierError::ZeroThreadCount;
        let err2 = err1.clone();
        assert_eq!(err1, err2);

        let err3 = BarrierError::SpawnFailed { thread_index: 3 };
        let err4 = err3.clone();
        assert_eq!(err3, err4);
    }

    #[test]
    fn test_barrier_error_equality() {
        assert_eq!(BarrierError::ZeroThreadCount, BarrierError::ZeroThreadCount);
        assert_eq!(
            BarrierError::SpawnFailed { thread_index: 1 },
            BarrierError::SpawnFailed { thread_index: 1 }
        );
        assert_ne!(
            BarrierError::SpawnFailed { thread_index: 1 },
            BarrierError::SpawnFailed { thread_index: 2 }
        );
    }

    #[test]
    fn test_test_barrier_debug_clone() {
        let barrier = TestBarrier::new(3);
        let barrier_clone = barrier.clone();

        assert_eq!(barrier.thread_count(), barrier_clone.thread_count());

        // Debug output should be valid
        let debug_str = format!("{:?}", barrier);
        assert!(debug_str.contains("TestBarrier"));
    }
}
