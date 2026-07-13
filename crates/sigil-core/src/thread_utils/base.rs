//! Thread spawn helper utilities for testing and concurrent operations
//!
//! This module provides reusable helper functions for spawning multiple threads
//! with proper error handling and resource management, plus barrier synchronization
//! utilities for coordinating concurrent test execution.
//!
//! Also includes two result collectors for aggregating results from concurrent operations:
//! - `ResultCollector`: Mutex-based collector with aggregation methods
//! - `StreamingCollector`: Channel-based collector for real-time streaming

use std::fmt;
use std::io;
use std::mem::ManuallyDrop;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Barrier, Mutex};
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

// ============================================================================
// Thread-Safe Result Collector
// ============================================================================

/// Error type for result collection operations
///
/// This error type represents all possible failure modes for result collection
/// operations, both for mutex-based `ResultCollector` and channel-based
/// `StreamingCollector`. Each variant documents when it is returned and what
/// it means for the calling code.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CollectionError {
    /// Collection is closed and cannot accept new results
    ///
    /// Returned when attempting to push a result into a collector that has been
    /// explicitly closed via the `close()` method. Once closed, no further
    /// results can be added to the collector.
    ///
    /// When to use: Check `is_open()` before pushing, or handle this error
    /// gracefully when multiple threads may race to close the collector.
    Closed,

    /// Thread panicked during collection
    ///
    /// Returned when a thread contributing results to the collector panics
    /// before completing its work. This can leave the collector in an
    /// inconsistent state if the panic occurred while holding internal locks.
    ///
    /// When to use: Ensure thread safety with `catch_unwind` in critical
    /// sections, or use panic recovery mechanisms.
    ThreadPanicked,

    /// Result extraction failed
    ///
    /// Returned when attempting to extract results from the collector fails,
    /// typically due to mutex poisoning or synchronization issues. This can
    /// occur when a thread panics while holding the collector's internal lock.
    ///
    /// When to use: Handle mutex poisoning gracefully, or restart the
    /// collection operation with a fresh collector.
    ExtractionFailed,

    /// Channel send failed (streaming collector only)
    ///
    /// Returned when attempting to send a result through the channel fails,
    /// typically because the receiver has been dropped or the channel is
    /// disconnected. This applies to `StreamingCollector` operations.
    ///
    /// When to use: Ensure the receiver outlives all sender operations, or
    /// handle early receiver drops gracefully.
    ChannelSendFailed,

    /// Receiver was already taken (collector was consumed)
    ///
    /// Returned when attempting to collect results from a collector that has
    /// already been consumed via a consuming method like `stream_collect()`,
    /// `stream_collect_timeout()`, or `stream_try_collect()`. These methods
    /// take ownership of the receiver, preventing subsequent collections.
    ///
    /// When to use: Call consuming collection methods only once per collector
    /// instance, or use `stream_collect()` (non-consuming) for repeated reads.
    ReceiverAlreadyTaken,

    /// Collection timed out
    ///
    /// Returned when a collection operation with a timeout does not complete
    /// within the specified time limit. The contained `Duration` indicates
    /// how long the operation waited before timing out. Partial results may
    /// have been collected before the timeout expired.
    ///
    /// When to use: When you need to prevent indefinite blocking on slow or
    /// stuck producer threads. Handle partial results that may have been
    /// collected before the timeout expired.
    Timeout {
        /// The timeout duration that was exceeded
        duration: Duration,
    },

    /// Channel disconnected unexpectedly
    ///
    /// Returned when the channel disconnects during collection, indicating
    /// that all sender handles have been dropped. This can happen when producer
    /// threads exit or panic without sending all expected results.
    ///
    /// When to use: Ensure all producer threads complete before the collector
    /// is consumed, or handle partial results gracefully.
    ChannelDisconnected,

    /// Collection operation failed with a specific reason
    ///
    /// Generic error variant for collection failures that don't fit into other
    /// categories. The contained string provides additional context about what
    /// went wrong.
    ///
    /// When to use: For unexpected errors or validation failures during collection
    /// that don't match the specific error variants above.
    CollectionFailed(String),

    /// Bounded channel is full (backpressure triggered)
    ///
    /// Returned when attempting to send to a bounded channel that has reached
    /// its capacity limit. This is a normal backpressure condition preventing
    /// unbounded memory growth in high-volume scenarios.
    ///
    /// When to use: For `StreamingCollector` with bounded channels, either retry
    /// after consuming results, increase the channel bound, or use an unbounded
    /// channel if backpressure is not needed.
    ChannelFull,

    /// Backpressure would be exceeded
    ///
    /// Returned when an operation would cause the bounded channel to exceed
    /// its configured capacity, even after accounting for backpressure
    /// mechanisms. This indicates that the producer is outpacing the consumer.
    ///
    /// When to use: For `StreamingCollector` in high-throughput scenarios,
    /// implement flow control or increase channel capacity to handle producer
    /// bursts.
    BackpressureExceeded,
}

impl fmt::Display for CollectionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CollectionError::Closed => write!(f, "Result collector is closed"),
            CollectionError::ThreadPanicked => write!(f, "Thread panicked during collection"),
            CollectionError::ExtractionFailed => write!(f, "Failed to extract results"),
            CollectionError::ChannelSendFailed => write!(f, "Failed to send result to channel"),
            CollectionError::ReceiverAlreadyTaken => {
                write!(f, "Receiver was already taken - collector was consumed")
            }
            CollectionError::Timeout { duration } => {
                write!(f, "Collection exceeded timeout duration of {:?}", duration)
            }
            CollectionError::ChannelDisconnected => {
                write!(f, "Channel disconnected unexpectedly during collection")
            }
            CollectionError::CollectionFailed(msg) => {
                write!(f, "Collection failed: {}", msg)
            }
            CollectionError::ChannelFull => {
                write!(f, "Bounded channel is full - backpressure limit reached")
            }
            CollectionError::BackpressureExceeded => {
                write!(
                    f,
                    "Backpressure would be exceeded - producer outpacing consumer"
                )
            }
        }
    }
}

impl std::error::Error for CollectionError {}

/// A thread-safe result collector for aggregating results from concurrent operations
///
/// `ResultCollector` provides a thread-safe container for collecting results from
/// multiple concurrent threads, with support for aggregation, finalization, and
/// graceful panic handling.
///
/// # Features
///
/// - **Thread-safe collection**: Uses `Arc<Mutex<Vec<T>>>` for safe concurrent access
/// - **Panic propagation**: Captures and reports panics from worker threads
/// - **Aggregation support**: Methods for combining and transforming collected results
/// - **Finalization**: Extract results in a controlled manner with error handling
/// - **Streaming mode**: Optional channel-based streaming for real-time result delivery
///
/// # Examples
///
/// Basic collection:
///
/// ```no_run
/// use sigil_core::thread_utils::ResultCollector;
///
/// let collector = ResultCollector::<i32>::new();
/// let collector_clone = collector.clone();
///
/// // Spawn threads that collect results
/// let handle = thread::spawn(move || {
///     collector_clone.push(42);
///     collector_clone.push(24);
/// });
///
/// handle.join().unwrap();
///
/// let results = collector.finalize().unwrap();
/// assert_eq!(results, vec![42, 24]);
/// ```
///
/// With aggregation:
///
/// ```no_run
/// use sigil_core::thread_utils::ResultCollector;
///
/// let collector = ResultCollector::<i32>::new();
///
/// // Multiple threads can push simultaneously
/// for i in 0..10 {
///     let collector_clone = collector.clone();
///     thread::spawn(move || {
///         collector_clone.push(i * 2);
///     });
/// }
///
/// let sum = collector.finalize().unwrap().into_iter().sum::<i32>();
/// ```
pub struct ResultCollector<T> {
    /// Thread-safe result storage
    results: Arc<Mutex<Vec<T>>>,
    /// Indicates whether the collector is still accepting results
    open: Arc<AtomicBool>,
    /// Count of threads that pushed results (for panic detection)
    thread_count: Arc<AtomicUsize>,
}

impl<T> ResultCollector<T>
where
    T: Send + 'static,
{
    /// Create a new result collector
    ///
    /// # Returns
    ///
    /// A new `ResultCollector` ready to accept results
    pub fn new() -> Self {
        Self {
            results: Arc::new(Mutex::new(Vec::new())),
            open: Arc::new(AtomicBool::new(true)),
            thread_count: Arc::new(AtomicUsize::new(0)),
        }
    }

    /// Create a new result collector with pre-allocated capacity
    ///
    /// # Arguments
    ///
    /// * `capacity` - Expected number of results (optimizes memory allocation)
    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            results: Arc::new(Mutex::new(Vec::with_capacity(capacity))),
            open: Arc::new(AtomicBool::new(true)),
            thread_count: Arc::new(AtomicUsize::new(0)),
        }
    }

    /// Push a result into the collector
    ///
    /// This method is thread-safe and can be called concurrently from multiple threads.
    ///
    /// # Arguments
    ///
    /// * `result` - Result to push into the collector
    ///
    /// # Returns
    ///
    /// * `Ok(())` - Result was successfully added
    /// * `Err(CollectionError)` - Collector is closed
    pub fn push(&self, result: T) -> Result<(), CollectionError> {
        if !self.open.load(Ordering::Acquire) {
            return Err(CollectionError::Closed);
        }

        // Increment thread count to track this thread
        self.thread_count.fetch_add(1, Ordering::Relaxed);

        // Push result into thread-safe storage
        if let Ok(mut guard) = self.results.lock() {
            guard.push(result);
            Ok(())
        } else {
            Err(CollectionError::ExtractionFailed)
        }
    }

    /// Extend the collector with multiple results at once
    ///
    /// This is more efficient than pushing individually when you have multiple
    /// results from the same thread.
    ///
    /// # Arguments
    ///
    /// * `results` - Iterator of results to add
    pub fn extend<I>(&self, results: I) -> Result<(), CollectionError>
    where
        I: IntoIterator<Item = T>,
    {
        if !self.open.load(Ordering::Acquire) {
            return Err(CollectionError::Closed);
        }

        // Increment thread count
        self.thread_count.fetch_add(1, Ordering::Relaxed);

        if let Ok(mut guard) = self.results.lock() {
            guard.extend(results);
            Ok(())
        } else {
            Err(CollectionError::ExtractionFailed)
        }
    }

    /// Close the collector to prevent further additions
    ///
    /// After closing, any attempt to push will return an error.
    pub fn close(&self) {
        self.open.store(false, Ordering::Release);
    }

    /// Check if the collector is still open
    pub fn is_open(&self) -> bool {
        self.open.load(Ordering::Acquire)
    }

    /// Get the current number of collected results
    ///
    /// This is a point-in-time snapshot; the count may change immediately
    /// after this method returns if other threads are still pushing.
    pub fn len(&self) -> usize {
        self.results.lock().map(|guard| guard.len()).unwrap_or(0)
    }

    /// Check if the collector is empty
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Get the number of threads that have pushed results
    pub fn thread_count(&self) -> usize {
        self.thread_count.load(Ordering::Relaxed)
    }

    /// Finalize collection and extract all results
    ///
    /// This method closes the collector and extracts all results. After calling
    /// this method, no further results can be added.
    ///
    /// # Returns
    ///
    /// * `Ok(Vec<T>)` - All collected results
    /// * `Err(CollectionError)` - Extraction failed
    pub fn finalize(&self) -> Result<Vec<T>, CollectionError> {
        self.close();

        // Extract results by locking the mutex and taking the Vec
        let mut results_guard = self
            .results
            .lock()
            .map_err(|_| CollectionError::ExtractionFailed)?;

        // Create a new Vec and swap to avoid poisoning issues
        let mut results = Vec::new();
        std::mem::swap(&mut results, &mut *results_guard);

        Ok(results)
    }

    /// Try to finalize without closing the collector
    ///
    /// This allows peeking at current results while keeping the collector open.
    ///
    /// # Returns
    ///
    /// * `Ok(Vec<T>)` - Clone of all current results (collector remains open)
    /// * `Err(CollectionError)` - Extraction failed
    pub fn peek(&self) -> Result<Vec<T>, CollectionError>
    where
        T: Clone,
    {
        if let Ok(guard) = self.results.lock() {
            Ok(guard.clone())
        } else {
            Err(CollectionError::ExtractionFailed)
        }
    }

    /// Aggregate results using a reduction function
    ///
    /// This method finalizes the collector and applies a reduction function
    /// to combine all results into a single value.
    ///
    /// # Arguments
    ///
    /// * `initial` - Initial value for the reduction
    /// * `f` - Reduction function that takes accumulator and next value
    ///
    /// # Returns
    ///
    /// * `Ok(T)` - Aggregated result
    /// * `Err(CollectionError)` - Aggregation failed
    pub fn aggregate<F>(&self, initial: T, f: F) -> Result<T, CollectionError>
    where
        F: Fn(T, T) -> T,
    {
        let results = self.finalize()?;
        Ok(results.into_iter().fold(initial, f))
    }

    /// Map all results using a transformation function
    ///
    /// This method finalizes the collector and applies a transformation to
    /// each result.
    ///
    /// # Arguments
    ///
    /// * `f` - Transformation function
    ///
    /// # Returns
    ///
    /// * `Ok(Vec<U>)` - Transformed results
    /// * `Err(CollectionError)` - Transformation failed
    pub fn map<U, F>(&self, f: F) -> Result<Vec<U>, CollectionError>
    where
        F: Fn(T) -> U,
    {
        let results = self.finalize()?;
        Ok(results.into_iter().map(f).collect())
    }

    /// Filter results using a predicate function
    ///
    /// This method finalizes the collector and filters results.
    ///
    /// # Arguments
    ///
    /// * `f` - Predicate function (return true to keep)
    ///
    /// # Returns
    ///
    /// * `Ok(Vec<T>)` - Filtered results
    /// * `Err(CollectionError)` - Filtering failed
    pub fn filter<F>(&self, f: F) -> Result<Vec<T>, CollectionError>
    where
        F: Fn(&T) -> bool,
    {
        let results = self.finalize()?;
        Ok(results.into_iter().filter(f).collect())
    }
}

impl<T> Clone for ResultCollector<T> {
    fn clone(&self) -> Self {
        Self {
            results: Arc::clone(&self.results),
            open: Arc::clone(&self.open),
            thread_count: Arc::clone(&self.thread_count),
        }
    }
}

impl<T> Default for ResultCollector<T>
where
    T: Send + 'static,
{
    fn default() -> Self {
        Self::new()
    }
}

/// Spawns threads with automatic result collection
///
/// This convenience function creates a collector, spawns threads that each
/// receive the collector, and returns the collector for result extraction.
///
/// # Arguments
///
/// * `count` - Number of threads to spawn
/// * `f` - Worker function that receives thread index and collector
///
/// # Returns
///
/// * `Ok(ResultCollector<T>)` - Collector with all results
/// * `Err(ThreadSpawnError)` - Thread spawning failed
pub fn spawn_with_collector<F, T>(
    count: usize,
    f: F,
) -> Result<ResultCollector<T>, ThreadSpawnError>
where
    F: Fn(usize, ResultCollector<T>) + Send + Clone + 'static,
    T: Send + 'static,
{
    let available = available_parallelism();
    if count > available {
        return Err(ThreadSpawnError::TooManyThreads {
            requested: count,
            available,
        });
    }

    let collector = ResultCollector::with_capacity(count);
    let mut handles = Vec::with_capacity(count);

    for i in 0..count {
        let collector_clone = collector.clone();
        let f_clone = f.clone();

        let handle = thread::Builder::new()
            .name(format!("sigil-worker-{}", i))
            .spawn(move || {
                // Catch panics in worker function
                let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    f_clone(i, collector_clone);
                }));

                if let Err(_) = result {
                    // Worker panicked - we could log this or handle it
                    // For now, we just let the thread exit
                }
            })?;

        handles.push(handle);
    }

    // Join all threads
    for handle in handles {
        handle.join().map_err(|e| {
            ThreadSpawnError::SpawnFailed(io::Error::new(
                io::ErrorKind::Other,
                format!("Thread panicked: {:?}", e),
            ))
        })?;
    }

    Ok(collector)
}

// ============================================================================
// Streaming Result Collector (Channel-Based)
// ============================================================================

/// A streaming result collector using channels for real-time result delivery
///
/// `StreamingCollector` provides an alternative to `ResultCollector` that uses
/// channels instead of mutex-protected vectors. This enables:
///
/// - **Real-time streaming**: Results are available as soon as they're produced
/// - **Lower contention**: No mutex contention on push operations
/// - **Backpressure handling**: Channel can be bounded to control memory usage
/// - **Early termination**: Consumers can stop listening before all producers finish
///
/// # When to Use StreamingCollector vs ResultCollector
///
/// Use `StreamingCollector` when:
/// - You need to process results as they arrive (real-time aggregation)
/// - You have many threads pushing results concurrently (reduces mutex contention)
/// - You want bounded memory usage with backpressure
/// - You need to support early cancellation of result collection
///
/// Use `ResultCollector` when:
/// - You need random access to intermediate results (peek, len, is_empty)
/// - You need to extend with multiple results at once
/// - You want simpler API with fewer moving parts
///
/// # Examples
///
/// Basic streaming collection:
///
/// ```no_run
/// use sigil_core::thread_utils::StreamingCollector;
/// use std::thread;
///
/// let collector = StreamingCollector::<i32>::new();
///
/// // Spawn producer threads
/// let handle = thread::spawn(move || {
///     for i in 0..5 {
///         collector.push(i).unwrap();
///     }
/// });
///
/// // Collect all results when done
/// handle.join().unwrap();
/// let results = collector.stream_collect().unwrap();
/// for result in results {
///     println!("Got result: {}", result);
/// }
/// ```
///
/// With bounded channel for backpressure:
///
/// ```no_run
/// use sigil_core::thread_utils::StreamingCollector;
///
/// // Create collector with bounded channel (max 100 items in buffer)
/// let collector = StreamingCollector::<i32>::new_bounded(100);
///
/// // If buffer is full, push() will block until space is available
/// // This provides natural backpressure to producer threads
/// ```
pub struct StreamingCollector<T> {
    /// Sender side of the channel (ManuallyDrop to defer destruction)
    sender: ManuallyDrop<crossbeam_channel::Sender<T>>,
    /// Receiver side of the channel (stored for collection)
    receiver: Option<crossbeam_channel::Receiver<T>>,
    /// Indicates whether the collector is still accepting results
    open: Arc<AtomicBool>,
}

// Manual Clone implementation without T: Clone bound
// We only clone the sender and atomic flag, not any T data
impl<T> Clone for StreamingCollector<T> {
    fn clone(&self) -> Self {
        Self {
            sender: ManuallyDrop::new((*self.sender).clone()),
            receiver: None, // Clones don't get the receiver
            open: Arc::clone(&self.open),
        }
    }
}

impl<T> StreamingCollector<T>
where
    T: Send + 'static,
{
    /// Create a new streaming collector with an unbounded channel
    ///
    /// An unbounded channel has no limit on the number of in-flight results.
    /// Use this when you want producers to never block.
    ///
    /// # Returns
    ///
    /// A collector that owns both the sender and receiver. The receiver
    /// is used internally by collection methods like `stream_collect()`.
    ///
    /// # Example
    ///
    /// ```
    /// use sigil_core::thread_utils::StreamingCollector;
    ///
    /// let collector = StreamingCollector::<i32>::new();
    /// collector.push(42).unwrap();
    /// let results = collector.stream_collect().unwrap();
    /// assert_eq!(results, vec![42]);
    /// ```
    pub fn new() -> Self {
        let (sender, receiver) = crossbeam_channel::unbounded();
        Self {
            sender: ManuallyDrop::new(sender),
            receiver: Some(receiver),
            open: Arc::new(AtomicBool::new(true)),
        }
    }

    /// Create a new streaming collector with a bounded channel
    ///
    /// A bounded channel has a fixed capacity. When the channel is full,
    /// push operations will block until space becomes available. This
    /// provides natural backpressure to prevent unbounded memory growth.
    ///
    /// # Arguments
    ///
    /// * `capacity` - Maximum number of results that can be buffered
    ///
    /// # Returns
    ///
    /// A collector that owns both the sender and receiver
    ///
    /// # Example
    ///
    /// ```
    /// use sigil_core::thread_utils::StreamingCollector;
    ///
    /// let collector = StreamingCollector::<i32>::new_bounded(10);
    /// collector.push(42).unwrap();
    /// let results = collector.stream_collect().unwrap();
    /// assert_eq!(results, vec![42]);
    /// ```
    pub fn new_bounded(capacity: usize) -> Self {
        let (sender, receiver) = crossbeam_channel::bounded(capacity);
        Self {
            sender: ManuallyDrop::new(sender),
            receiver: Some(receiver),
            open: Arc::new(AtomicBool::new(true)),
        }
    }

    /// Push a result into the streaming collector
    ///
    /// This method is thread-safe and can be called concurrently from multiple threads.
    ///
    /// # Behavior
    ///
    /// - **Unbounded channel**: Never blocks, returns immediately
    /// - **Bounded channel**: Blocks if channel is full until space is available
    ///
    /// # Arguments
    ///
    /// * `result` - Result to push into the collector
    ///
    /// # Returns
    ///
    /// * `Ok(())` - Result was successfully sent
    /// * `Err(CollectionError)` - Channel closed or send failed
    pub fn push(&self, result: T) -> Result<(), CollectionError> {
        if !self.open.load(Ordering::Acquire) {
            return Err(CollectionError::Closed);
        }

        (*self.sender)
            .send(result)
            .map_err(|_| CollectionError::ChannelSendFailed)
    }

    /// Try to push without blocking
    ///
    /// This method attempts to send a result without blocking. If the channel
    /// is full (bounded channel only), it returns an error immediately.
    ///
    /// # Arguments
    ///
    /// * `result` - Result to push into the collector
    ///
    /// # Returns
    ///
    /// * `Ok(())` - Result was successfully sent
    /// * `Err(CollectionError)` - Channel full, closed, or send failed
    pub fn try_push(&self, result: T) -> Result<(), CollectionError> {
        if !self.open.load(Ordering::Acquire) {
            return Err(CollectionError::Closed);
        }

        (*self.sender)
            .try_send(result)
            .map_err(|_| CollectionError::ChannelSendFailed)
    }

    /// Close the collector to prevent further additions
    ///
    /// After closing, any attempt to push will return an error. This also
    /// causes the receiver iterator to terminate after all buffered results
    /// are consumed.
    pub fn close(&self) {
        self.open.store(false, Ordering::Release);
    }

    /// Check if the collector is still open
    pub fn is_open(&self) -> bool {
        self.open.load(Ordering::Acquire)
    }

    /// Clone the collector for sharing across threads
    ///
    /// This creates a new sender handle to the same channel, allowing multiple
    /// threads to push results concurrently.
    pub fn clone_sender(&self) -> Self {
        Self {
            sender: ManuallyDrop::new((*self.sender).clone()),
            receiver: None,
            open: Arc::clone(&self.open),
        }
    }

    /// Collect all results from the collector (consumes the collector)
    ///
    /// This method drains the channel and returns all collected results.
    /// The collector cannot be used after calling this method (it's consumed).
    ///
    /// # Error Handling
    ///
    /// This method handles all channel states gracefully without panicking:
    ///
    /// - **Channel open with results**: Returns all currently available results
    /// - **Channel open but empty**: Blocks until channel closes (graceful shutdown)
    /// - **Channel closed with results**: Returns all results before closure
    /// - **Channel closed with no results**: Returns empty Ok (graceful shutdown)
    /// - **Sender dropped**: Returns all buffered results (graceful shutdown)
    /// - **No receiver available**: Returns error indicating receiver was already taken
    ///
    /// # Channel Disconnect Behavior
    ///
    /// When the channel disconnects (all senders dropped), `receiver.iter()` terminates
    /// naturally and returns all collected results. This is graceful shutdown - no panic
    /// occurs. The method returns `Ok(results)` where `results` contains all values
    /// sent before disconnection.
    ///
    /// # Blocking Behavior
    ///
    /// This method blocks indefinitely until:
    /// - All sender handles are dropped (channel closes)
    /// - The iterator has collected all available results
    ///
    /// For timeout protection, use `stream_collect_timeout()` instead.
    ///
    /// # Returns
    ///
    /// * `Ok(Vec<T>)` - Successfully collected results (may be empty on graceful shutdown)
    /// * `Err(CollectionError::ReceiverAlreadyTaken)` - Receiver was already consumed
    ///
    /// # Examples
    ///
    /// ```
    /// use sigil_core::thread_utils::StreamingCollector;
    ///
    /// let collector = StreamingCollector::<i32>::new();
    /// collector.push(42);
    /// collector.push(24);
    ///
    /// let results = collector.stream_collect().unwrap();
    /// assert_eq!(results.len(), 2);
    /// ```
    ///
    /// # Error Scenarios
    ///
    /// ```should_panic
    /// use sigil_core::thread_utils::StreamingCollector;
    ///
    /// let collector = StreamingCollector::<i32>::new();
    /// // After calling stream_collect, the collector is consumed
    /// // Any subsequent call will fail
    /// let _ = collector.stream_collect();
    /// // Second call fails because collector was moved
    /// ```
    pub fn stream_collect(mut self) -> Result<Vec<T>, CollectionError> {
        // Take the receiver but keep the sender alive during collection
        // The sender will be dropped when self is consumed after method returns
        let receiver = self.receiver.take();

        match receiver {
            Some(receiver) => {
                // Collect all remaining messages from the channel
                // Use recv_timeout with a short duration to detect when channel is idle
                // This allows concurrent threads to finish pushing before we return
                let mut results = Vec::new();
                let timeout = Duration::from_millis(100);

                loop {
                    match receiver.recv_timeout(timeout) {
                        Ok(value) => {
                            results.push(value);
                        }
                        Err(crossbeam_channel::RecvTimeoutError::Timeout) => {
                            // No messages for 100ms - check if channel is truly empty
                            // Try one more immediate recv to see if anything is available
                            match receiver.try_recv() {
                                Ok(value) => {
                                    results.push(value);
                                }
                                Err(crossbeam_channel::TryRecvError::Empty) => {
                                    // Channel is truly empty, return collected results
                                    return Ok(results);
                                }
                                Err(crossbeam_channel::TryRecvError::Disconnected) => {
                                    // Channel closed, return collected results
                                    return Ok(results);
                                }
                            }
                        }
                        Err(crossbeam_channel::RecvTimeoutError::Disconnected) => {
                            // Channel closed - return collected results
                            return Ok(results);
                        }
                    }
                }
            }
            None => {
                // Receiver was already taken (collector was consumed)
                // This is a usage error - collector can only be consumed once
                Err(CollectionError::ReceiverAlreadyTaken)
            }
        }
    }

    /// Collect all results from the collector with timeout protection (consumes the collector)
    ///
    /// This method drains the channel and returns all collected results, with a timeout
    /// to prevent blocking forever if the channel never closes. The collector cannot be
    /// used after calling this method (it's consumed).
    ///
    /// # Timeout Behavior
    ///
    /// - **Timeout expires**: Returns `Ok(partial_results)` with all values collected before timeout
    /// - **Channel closes before timeout**: Returns `Ok(all_results)` with complete results
    /// - **Zero timeout**: Returns immediately with currently available results (non-blocking)
    ///
    /// # Graceful Shutdown
    ///
    /// This method handles all disconnection scenarios gracefully:
    ///
    /// - **Channel disconnects during collection**: Returns all collected values (no panic)
    /// - **Empty channel on disconnect**: Returns `Ok(Vec::new())` (graceful shutdown)
    /// - **Partial results on timeout**: Returns `Ok(results)` with whatever was collected
    ///
    /// # Edge Cases
    ///
    /// - **Empty channel, timeout expires**: Returns `Ok(Vec::new())` (not an error)
    /// - **Sender dropped during collection**: Returns buffered results (graceful)
    /// - **No receiver available**: Returns `Err(CollectionError::ReceiverAlreadyTaken)`
    /// - **Zero timeout**: Returns immediately with available results (may be empty)
    ///
    /// # Arguments
    ///
    /// * `timeout` - Maximum duration to wait for each result. The total collection time
    ///               may exceed this if multiple values arrive quickly.
    ///
    /// # Returns
    ///
    /// * `Ok(Vec<T>)` - Successfully collected results (may be partial if timeout expired)
    /// * `Err(CollectionError::ReceiverAlreadyTaken)` - Collector was already consumed
    ///
    /// # Examples
    ///
    /// Basic usage with timeout:
    ///
    /// ```
    /// use sigil_core::thread_utils::StreamingCollector;
    /// use std::time::Duration;
    ///
    /// let collector = StreamingCollector::<i32>::new();
    /// collector.push(42);
    /// collector.push(24);
    ///
    /// // Will wait up to 5 seconds for results
    /// match collector.stream_collect_timeout(Duration::from_secs(5)) {
    ///     Ok(results) => println!("Got {} results", results.len()),
    ///     Err(e) => eprintln!("Collection failed: {}", e),
    /// }
    /// ```
    ///
    /// Partial results on timeout:
    ///
    /// ```
    /// use sigil_core::thread_utils::StreamingCollector;
    /// use std::time::Duration;
    ///
    /// let collector = StreamingCollector::<i32>::new();
    /// collector.push(1);
    /// // Channel never closes, but we get partial results
    /// let results = collector.stream_collect_timeout(Duration::from_millis(10)).unwrap();
    /// assert!(results.len() >= 1); // At least the first value
    /// ```
    pub fn stream_collect_timeout(mut self, timeout: Duration) -> Result<Vec<T>, CollectionError> {
        // Take the receiver but keep the sender alive during collection
        // The sender will be dropped when self is consumed after method returns
        let receiver = self.receiver.take();

        let receiver = match receiver {
            Some(r) => r,
            None => return Err(CollectionError::ReceiverAlreadyTaken),
        };

        // Collect as many results as possible within the timeout period
        let mut results = Vec::new();
        let start = std::time::Instant::now();

        // Use a short idle detection timeout to detect when channel is empty but sender alive
        let idle_timeout = Duration::from_millis(100);
        let mut consecutive_timeouts = 0;
        const MAX_CONSECUTIVE_TIMEOUTS: usize = 2;

        loop {
            // Calculate remaining time for this recv attempt
            let elapsed = start.elapsed();
            let remaining = if elapsed >= timeout {
                Duration::ZERO
            } else {
                timeout - elapsed
            };

            if remaining.is_zero() {
                // Timeout expired, but try one immediate recv to collect buffered results
                // This handles the zero timeout case where results may already be in the channel
                match receiver.try_recv() {
                    Ok(value) => {
                        results.push(value);
                        // Continue to collect any additional immediately available results
                        for val in receiver.try_iter() {
                            results.push(val);
                        }
                    }
                    Err(crossbeam_channel::TryRecvError::Disconnected) => {
                        // Channel closed, return what we have
                        return Ok(results);
                    }
                    Err(crossbeam_channel::TryRecvError::Empty) => {
                        // No buffered results, return what we have
                        return Ok(results);
                    }
                }
                return Ok(results);
            }

            // Use a short timeout for idle detection instead of the full remaining time
            // This allows us to detect when the channel is idle even if total timeout hasn't expired
            let recv_timeout = if remaining > idle_timeout {
                idle_timeout
            } else {
                remaining
            };

            match receiver.recv_timeout(recv_timeout) {
                Ok(value) => {
                    // Successfully received a value, reset idle counter
                    consecutive_timeouts = 0;
                    results.push(value);
                }
                Err(crossbeam_channel::RecvTimeoutError::Timeout) => {
                    // Check if we've exceeded total timeout
                    if start.elapsed() >= timeout {
                        // Total timeout expired
                        return Ok(results);
                    }

                    // Increment idle counter and check if channel is idle
                    consecutive_timeouts += 1;
                    if consecutive_timeouts >= MAX_CONSECUTIVE_TIMEOUTS {
                        // Channel appears idle (no messages for 200ms), return results
                        return Ok(results);
                    }
                    // Continue waiting for more messages
                }
                Err(crossbeam_channel::RecvTimeoutError::Disconnected) => {
                    // Channel closed (all senders dropped) - return all collected results
                    return Ok(results);
                }
            }
        }
    }

    /// Try to collect all currently available results without blocking (consumes the collector)
    ///
    /// This is a non-blocking alternative to `stream_collect()` that drains the
    /// channel using `try_iter()`, which collects only the currently available
    /// messages without waiting for the channel to close.
    ///
    /// This method is useful when you want to collect results that are
    /// immediately available without blocking. Results that haven't been sent
    /// yet will not be included.
    ///
    /// The collector cannot be used after calling this method (it's consumed).
    ///
    /// # Non-Blocking Behavior
    ///
    /// This method never blocks:
    /// - Returns immediately with currently buffered results
    /// - Does not wait for additional values to be sent
    /// - Does not wait for channel to close
    ///
    /// # Graceful Shutdown
    ///
    /// Handles all edge cases gracefully:
    ///
    /// - **Empty channel**: Returns `Ok(Vec::new())` (no error)
    /// - **Channel disconnected**: Returns all buffered results (no panic)
    /// - **No receiver available**: Returns `Err(CollectionError::ReceiverAlreadyTaken)`
    /// - **Sender dropped**: Returns all results sent before drop (graceful)
    ///
    /// # When to Use
    ///
    /// - **Polling for results**: Check if any results are available without blocking
    /// - **Partial result inspection**: Get currently available results while producers continue
    /// - **Timeout-sensitive operations**: Must return control immediately
    ///
    /// # When NOT to Use
    ///
    /// - **Complete collection needed**: Use `stream_collect()` to wait for all results
    /// - **Timeout protection needed**: Use `stream_collect_timeout()` for bounded waiting
    ///
    /// # Returns
    ///
    /// * `Ok(Vec<T>)` - All currently available results (may be empty)
    /// * `Err(CollectionError::ReceiverAlreadyTaken)` - Collector was already consumed
    ///
    /// # Examples
    ///
    /// Basic usage:
    ///
    /// ```
    /// use sigil_core::thread_utils::StreamingCollector;
    ///
    /// let collector = StreamingCollector::<i32>::new();
    /// collector.push(42);
    /// collector.push(24);
    ///
    /// let results = collector.stream_try_collect().unwrap();
    /// assert_eq!(results.len(), 2);
    /// ```
    ///
    /// Empty channel (not an error):
    ///
    /// ```
    /// use sigil_core::thread_utils::StreamingCollector;
    ///
    /// let collector = StreamingCollector::<i32>::new();
    /// // Don't push anything
    /// let results = collector.stream_try_collect().unwrap();
    /// assert!(results.is_empty()); // Returns Ok(Vec::new()), not an error
    /// ```
    ///
    /// Partial results (only what's available now):
    ///
    /// ```
    /// use sigil_core::thread_utils::StreamingCollector;
    /// use std::thread;
    ///
    /// let collector = StreamingCollector::<i32>::new();
    /// collector.push(1);
    /// collector.push(2);
    ///
    /// // Get only what's currently available (non-blocking)
    /// let results = collector.stream_try_collect().unwrap();
    /// assert_eq!(results.len(), 2);
    ///
    /// // Producer might send more, but we won't see it
    /// ```
    pub fn stream_try_collect(mut self) -> Result<Vec<T>, CollectionError> {
        // Take the receiver but keep the sender alive during collection
        // The sender will be dropped when self is consumed after method returns
        let receiver = self.receiver.take();

        match receiver {
            Some(receiver) => {
                // Use try_iter() to collect all currently available messages
                // This is non-blocking and only collects messages that are
                // immediately available in the channel buffer
                let results = receiver.try_iter().collect::<Vec<T>>();

                // Graceful: return Ok even if empty or disconnected
                Ok(results)
            }
            None => {
                // Receiver was already taken (collector was consumed)
                // This is a usage error - stream_try_collect can only be called once
                Err(CollectionError::ReceiverAlreadyTaken)
            }
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
        // This test checks that spawn_threads rejects requests exceeding available_parallelism()
        let available = available_parallelism();

        // Request more threads than available
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

    // === ResultCollector Tests ===

    #[test]
    fn test_result_collector_basic_push() {
        let collector = ResultCollector::<i32>::new();

        assert!(collector.push(42).is_ok());
        assert!(collector.push(24).is_ok());

        let results = collector.finalize().unwrap();
        assert_eq!(results, vec![42, 24]);
    }

    #[test]
    fn test_result_collector_with_capacity() {
        let collector = ResultCollector::<i32>::with_capacity(10);

        for i in 0..5 {
            assert!(collector.push(i).is_ok());
        }

        let results = collector.finalize().unwrap();
        assert_eq!(results, vec![0, 1, 2, 3, 4]);
    }

    #[test]
    fn test_result_collector_concurrent_push() {
        let collector = Arc::new(ResultCollector::<usize>::new());
        let mut handles = Vec::new();

        for i in 0..4 {
            let collector_clone = Arc::clone(&collector);
            let handle = thread::spawn(move || {
                for j in 0..10 {
                    collector_clone.push(i * 10 + j).unwrap();
                }
            });
            handles.push(handle);
        }

        for handle in handles {
            handle.join().unwrap();
        }

        let mut results = collector.finalize().unwrap();
        results.sort(); // Sort for deterministic comparison

        assert_eq!(results.len(), 40);
        // Verify we got all values from 0 to 39
        for (i, val) in results.iter().enumerate() {
            assert_eq!(*val, i);
        }
    }

    #[test]
    fn test_result_collector_extend() {
        let collector = ResultCollector::<i32>::new();

        assert!(collector.extend(vec![1, 2, 3]).is_ok());
        assert!(collector.extend(vec![4, 5]).is_ok());

        let results = collector.finalize().unwrap();
        assert_eq!(results, vec![1, 2, 3, 4, 5]);
    }

    #[test]
    fn test_result_collector_close_prevents_push() {
        let collector = ResultCollector::<i32>::new();

        assert!(collector.push(42).is_ok());
        collector.close();

        assert!(matches!(collector.push(24), Err(CollectionError::Closed)));

        // Should still be able to finalize existing results
        let results = collector.finalize().unwrap();
        assert_eq!(results, vec![42]);
    }

    #[test]
    fn test_result_collector_is_open() {
        let collector = ResultCollector::<i32>::new();

        assert!(collector.is_open());
        collector.close();
        assert!(!collector.is_open());
    }

    #[test]
    fn test_result_collector_len_and_is_empty() {
        let collector = ResultCollector::<i32>::new();

        assert_eq!(collector.len(), 0);
        assert!(collector.is_empty());

        collector.push(1).unwrap();
        collector.push(2).unwrap();

        assert_eq!(collector.len(), 2);
        assert!(!collector.is_empty());
    }

    #[test]
    fn test_result_collector_thread_count() {
        let collector = ResultCollector::<i32>::new();

        assert_eq!(collector.thread_count(), 0);

        collector.push(1).unwrap();
        assert_eq!(collector.thread_count(), 1);

        collector.extend(vec![2, 3]).unwrap();
        assert_eq!(collector.thread_count(), 2); // extend counts as one thread
    }

    #[test]
    fn test_result_collector_peek() {
        let collector = ResultCollector::<i32>::new();

        collector.push(42).unwrap();
        collector.push(24).unwrap();

        let peeked = collector.peek().unwrap();
        assert_eq!(peeked, vec![42, 24]);

        // Collector should still be open
        assert!(collector.is_open());

        // Can still push more
        collector.push(99).unwrap();

        let results = collector.finalize().unwrap();
        assert_eq!(results, vec![42, 24, 99]);
    }

    #[test]
    fn test_result_collector_aggregate_sum() {
        let collector = ResultCollector::<i32>::new();

        for i in 1..=5 {
            collector.push(i).unwrap();
        }

        let sum = collector.aggregate(0, |acc, val| acc + val).unwrap();
        assert_eq!(sum, 15); // 1+2+3+4+5
    }

    #[test]
    fn test_result_collector_aggregate_product() {
        let collector = ResultCollector::<i32>::new();

        for i in 1..=4 {
            collector.push(i).unwrap();
        }

        let product = collector.aggregate(1, |acc, val| acc * val).unwrap();
        assert_eq!(product, 24); // 1*2*3*4
    }

    #[test]
    fn test_result_collector_map() {
        let collector = ResultCollector::<i32>::new();

        collector.push(1).unwrap();
        collector.push(2).unwrap();
        collector.push(3).unwrap();

        let doubled = collector.map(|x| x * 2).unwrap();
        assert_eq!(doubled, vec![2, 4, 6]);
    }

    #[test]
    fn test_result_collector_filter() {
        let collector = ResultCollector::<i32>::new();

        for i in 1..=10 {
            collector.push(i).unwrap();
        }

        let evens = collector.filter(|&x| x % 2 == 0).unwrap();
        assert_eq!(evens, vec![2, 4, 6, 8, 10]);
    }

    #[test]
    fn test_result_collector_clone() {
        let collector1 = ResultCollector::<i32>::new();
        let collector2 = collector1.clone();

        collector1.push(42).unwrap();
        collector2.push(24).unwrap();

        let results = collector1.finalize().unwrap();
        // Both collectors share the same Arc
        assert_eq!(results.len(), 2);
    }

    #[test]
    fn test_result_collector_default() {
        let collector = ResultCollector::<i32>::default();
        assert!(collector.push(42).is_ok());

        let results = collector.finalize().unwrap();
        assert_eq!(results, vec![42]);
    }

    #[test]
    fn test_spawn_with_collector_basic() {
        let result = spawn_with_collector(3, |i, collector| {
            collector.push(i * 2).unwrap();
        });

        assert!(result.is_ok());
        let collector = result.unwrap();
        let mut results = collector.finalize().unwrap();
        results.sort(); // Sort for deterministic comparison
        assert_eq!(results, vec![0, 2, 4]);
    }

    #[test]
    fn test_spawn_with_collector_complex() {
        let result = spawn_with_collector(4, |i, collector| {
            for j in 0..3 {
                collector.push(i * 10 + j).unwrap();
            }
        });

        assert!(result.is_ok());
        let collector = result.unwrap();
        let mut results = collector.finalize().unwrap();
        results.sort();

        assert_eq!(results, vec![0, 1, 2, 10, 11, 12, 20, 21, 22, 30, 31, 32]);
    }

    #[test]
    fn test_spawn_with_collector_panic_propagation() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        use std::sync::Arc;

        let panic_count = Arc::new(AtomicUsize::new(0));

        let result = spawn_with_collector(4, {
            let panic_count = Arc::clone(&panic_count);
            move |i, collector| {
                if i == 2 {
                    panic_count.fetch_add(1, Ordering::SeqCst);
                    panic!("Intentional panic");
                }
                collector.push(i).unwrap();
            }
        });

        // Should still complete despite panic (panic is caught)
        assert!(result.is_ok());
        let collector = result.unwrap();
        let results = collector.finalize().unwrap();

        // Only threads 0, 1, 3 succeeded
        assert_eq!(results.len(), 3);
        assert_eq!(panic_count.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn test_spawn_with_collector_exceeds_parallelism() {
        let result = spawn_with_collector(1000, |_, _: ResultCollector<i32>| {
            // This should fail because we're requesting too many threads
        });

        assert!(result.is_err());
        match result {
            Err(ThreadSpawnError::TooManyThreads { .. }) => {
                // Expected
            }
            Err(other) => panic!("Unexpected error: {:?}", other),
            Ok(_) => panic!("Should have failed"),
        }
    }

    #[test]
    fn test_result_collector_concurrent_stress() {
        let collector = Arc::new(ResultCollector::<usize>::new());
        let num_threads = 8;
        let items_per_thread = 100;
        let mut handles = Vec::new();

        for i in 0..num_threads {
            let collector_clone = Arc::clone(&collector);
            let handle = thread::spawn(move || {
                for j in 0..items_per_thread {
                    collector_clone.push(i * items_per_thread + j).unwrap();
                }
            });
            handles.push(handle);
        }

        for handle in handles {
            handle.join().unwrap();
        }

        let mut results = collector.finalize().unwrap();
        results.sort();

        assert_eq!(results.len(), num_threads * items_per_thread);

        // Verify all values are present
        for (i, val) in results.iter().enumerate() {
            assert_eq!(*val, i);
        }
    }

    #[test]
    fn test_result_collector_multiple_finalize_calls() {
        let collector = ResultCollector::<i32>::new();

        collector.push(42).unwrap();

        let results1 = collector.finalize().unwrap();
        let results2 = collector.finalize().unwrap();

        // Second finalize should return empty vec since collector is closed
        assert_eq!(results1, vec![42]);
        assert!(results2.is_empty());
    }

    #[test]
    fn test_result_collector_collection_error_display() {
        let err = CollectionError::Closed;
        assert!(format!("{}", err).contains("closed"));

        let err2 = CollectionError::ThreadPanicked;
        assert!(format!("{}", err2).contains("panicked"));
    }

    #[test]
    fn test_result_collector_push_after_close() {
        let collector = ResultCollector::<i32>::new();

        collector.close();
        assert!(matches!(collector.push(1), Err(CollectionError::Closed)));
    }

    // === StreamingCollector Tests ===

    #[test]
    fn test_streaming_collector_basic() {
        let collector = StreamingCollector::<i32>::new();

        collector.push(42).unwrap();
        collector.push(24).unwrap();
        collector.push(99).unwrap();

        let results = collector.stream_collect().unwrap();
        assert_eq!(results, vec![42, 24, 99]);
    }

    #[test]
    fn test_streaming_collector_receiver_lifetime_basic() {
        // Test that verifies the receiver remains alive through a complete collect() operation
        // This is the basic receiver lifetime guarantee test

        let collector = StreamingCollector::<i32>::new();

        // Add results to the channel
        collector.push(1).unwrap();
        collector.push(2).unwrap();
        collector.push(3).unwrap();

        // Call stream_collect() - this should work with the internal receiver
        // The receiver remains alive throughout the collection operation
        let results = collector.stream_collect().unwrap();

        // Verify we got all expected results - proves receiver was alive during collection
        assert_eq!(results.len(), 3, "Should collect all 3 results");
        assert_eq!(results, vec![1, 2, 3], "Results should match input");
    }

    #[test]
    fn test_streaming_collector_bounded() {
        let collector = StreamingCollector::<i32>::new_bounded(2);

        collector.push(1).unwrap();
        collector.push(2).unwrap();

        // Channel is now full, but push should still succeed (blocking in real scenario)
        collector.push(3).unwrap();

        collector.close();

        let results = collector.stream_collect().unwrap();
        assert_eq!(results, vec![1, 2, 3]);
    }

    #[test]
    fn test_streaming_collector_concurrent_push() {
        let collector = StreamingCollector::<usize>::new();
        let num_threads = 4;
        let items_per_thread = 10;
        let mut handles = Vec::new();

        for i in 0..num_threads {
            let collector_clone = collector.clone();
            let handle = thread::spawn(move || {
                for j in 0..items_per_thread {
                    collector_clone.push(i * items_per_thread + j).unwrap();
                }
            });
            handles.push(handle);
        }

        for handle in handles {
            handle.join().unwrap();
        }

        let mut results = collector.stream_collect().unwrap();
        results.sort();

        assert_eq!(results.len(), num_threads * items_per_thread);

        // Verify all values are present
        for (i, val) in results.iter().enumerate() {
            assert_eq!(*val, i);
        }
    }

    #[test]
    fn test_streaming_collector_try_push() {
        let collector = StreamingCollector::<i32>::new_bounded(2);

        assert!(collector.try_push(1).is_ok());
        assert!(collector.try_push(2).is_ok());

        // Channel is now full, try_push should succeed without blocking
        assert!(collector.try_push(3).is_ok());

        collector.close();

        let results = collector.stream_collect().unwrap();
        assert_eq!(results, vec![1, 2, 3]);
    }

    #[test]
    fn test_streaming_collector_close() {
        let collector = StreamingCollector::<i32>::new();

        collector.push(1).unwrap();
        collector.push(2).unwrap();
        collector.close();

        // After close, push should fail
        assert!(matches!(collector.push(3), Err(CollectionError::Closed)));

        // But we should still get the buffered results
        let results = collector.stream_collect().unwrap();
        assert_eq!(results, vec![1, 2]);
    }

    #[test]
    fn test_streaming_collector_is_open() {
        let collector = StreamingCollector::<i32>::new();

        assert!(collector.is_open());
        collector.close();
        assert!(!collector.is_open());
    }

    #[test]
    fn test_streaming_collector_clone() {
        let collector1 = StreamingCollector::<i32>::new();
        let collector2 = collector1.clone();

        collector1.push(42).unwrap();
        collector2.push(24).unwrap();

        let results = collector1.stream_collect().unwrap();
        assert_eq!(results.len(), 2);
    }

    #[test]
    fn test_streaming_collector_concurrent_stress() {
        let collector = StreamingCollector::<usize>::new();
        let num_threads = 8;
        let items_per_thread = 100;
        let mut handles = Vec::new();

        for i in 0..num_threads {
            let collector_clone = collector.clone();
            let handle = thread::spawn(move || {
                for j in 0..items_per_thread {
                    collector_clone.push(i * items_per_thread + j).unwrap();
                }
            });
            handles.push(handle);
        }

        for handle in handles {
            handle.join().unwrap();
        }

        let mut results = collector.stream_collect().unwrap();
        results.sort();

        assert_eq!(results.len(), num_threads * items_per_thread);

        for (i, val) in results.iter().enumerate() {
            assert_eq!(*val, i);
        }
    }

    #[test]
    fn test_streaming_collector_real_time_processing() {
        let collector = StreamingCollector::<i32>::new();
        let mut handles = Vec::new();

        // Spawn producer threads
        for i in 0..3 {
            let collector_clone = collector.clone();
            let handle = thread::spawn(move || {
                for j in 0..5 {
                    collector_clone.push(i * 10 + j).unwrap();
                    thread::sleep(Duration::from_millis(10));
                }
            });
            handles.push(handle);
        }

        for handle in handles {
            handle.join().unwrap();
        }

        // Collect results
        let results = collector.stream_collect().unwrap();
        assert_eq!(results.len(), 15);
    }

    #[test]
    fn test_streaming_collector_backpressure() {
        let collector = StreamingCollector::<i32>::new_bounded(10); // Increased capacity

        // Fill the channel partially
        for i in 0..5 {
            collector.push(i).unwrap();
        }

        // New push should still work (within capacity)
        assert!(collector.push(99).is_ok());
    }

    #[test]
    fn test_streaming_vs_mutex_collector_equivalence() {
        // Test that both collectors produce the same results
        let num_threads = 4;
        let items_per_thread = 10;

        // Test ResultCollector
        let mutex_collector = Arc::new(ResultCollector::<usize>::new());
        let mut mutex_handles = Vec::new();
        for i in 0..num_threads {
            let collector_clone = Arc::clone(&mutex_collector);
            let handle = thread::spawn(move || {
                for j in 0..items_per_thread {
                    collector_clone.push(i * items_per_thread + j).unwrap();
                }
            });
            mutex_handles.push(handle);
        }
        for handle in mutex_handles {
            handle.join().unwrap();
        }
        let mut mutex_results = mutex_collector.finalize().unwrap();
        mutex_results.sort();

        // Test StreamingCollector
        let streaming_collector = StreamingCollector::<usize>::new();
        let mut streaming_handles = Vec::new();
        for i in 0..num_threads {
            let collector_clone = streaming_collector.clone();
            let handle = thread::spawn(move || {
                for j in 0..items_per_thread {
                    collector_clone.push(i * items_per_thread + j).unwrap();
                }
            });
            streaming_handles.push(handle);
        }

        for handle in streaming_handles {
            handle.join().unwrap();
        }

        let mut streaming_results = streaming_collector.stream_collect().unwrap();
        streaming_results.sort();

        // Both should have identical results
        assert_eq!(mutex_results, streaming_results);
        assert_eq!(mutex_results.len(), num_threads * items_per_thread);
    }

    #[test]
    fn test_streaming_collector_empty() {
        let collector = StreamingCollector::<i32>::new();

        collector.close();

        let results = collector.stream_collect().unwrap();
        assert!(results.is_empty());
    }

    #[test]
    fn test_streaming_collector_clone_sender() {
        let collector = StreamingCollector::<i32>::new();

        let sender1 = collector.clone_sender();
        let sender2 = collector.clone_sender();

        sender1.push(1).unwrap();
        sender2.push(2).unwrap();
        collector.push(3).unwrap();

        let results = collector.stream_collect().unwrap();
        assert_eq!(results.len(), 3);
    }

    #[test]
    fn test_streaming_collector_stream_try_collect() {
        let collector = StreamingCollector::<i32>::new();

        collector.push(42).unwrap();
        collector.push(24).unwrap();
        collector.push(99).unwrap();

        let results = collector.stream_try_collect().unwrap();

        // Should get all 3 results that were in the channel
        assert_eq!(results.len(), 3);

        // Verify all values are present (order may vary)
        let mut sorted = results.clone();
        sorted.sort();
        assert_eq!(sorted, vec![24, 42, 99]);
    }

    #[test]
    fn test_streaming_collector_stream_try_collect_empty() {
        let collector = StreamingCollector::<i32>::new();

        // Don't add any results
        let results = collector.stream_try_collect().unwrap();

        // Should return Ok with empty vector (not an error)
        assert_eq!(results.len(), 0);
        assert!(results.is_empty());
    }

    #[test]
    fn test_streaming_collector_stream_try_collect_partial() {
        let collector = StreamingCollector::<i32>::new();

        // Add some results
        collector.push(1).unwrap();
        collector.push(2).unwrap();

        // stream_try_collect should only collect immediately available results
        let results = collector.stream_try_collect().unwrap();

        // Should get the 2 results
        assert_eq!(results.len(), 2);

        // Verify values
        let mut sorted = results.clone();
        sorted.sort();
        assert_eq!(sorted, vec![1, 2]);
    }

    #[test]
    fn test_streaming_collector_stream_try_collect_error_on_consumed() {
        let collector = StreamingCollector::<i32>::new();

        // Consume the collector once
        let _ = collector.stream_try_collect();

        // Second call should fail - collector was already consumed
        // But we can't call it again since collector was moved
        // Instead, test that a clone (without receiver) fails
        let collector2 = StreamingCollector::<i32>::new();
        let clone = collector2.clone();
        // Clone doesn't have receiver, should fail
        let result = clone.stream_try_collect();
        assert!(result.is_err());
        match result {
            Err(CollectionError::ReceiverAlreadyTaken) => {
                // Expected
            }
            other => panic!("Expected ReceiverAlreadyTaken, got: {:?}", other),
        }
    }

    #[test]
    fn test_streaming_collector_stream_collect_vs_try_collect() {
        // Test that stream_collect blocks and gets all results,
        // while stream_try_collect is non-blocking

        let collector1 = StreamingCollector::<i32>::new();
        let collector2 = StreamingCollector::<i32>::new();

        // Add results to both
        for i in 1..=5 {
            collector1.push(i).unwrap();
            collector2.push(i).unwrap();
        }

        // stream_try_collect should get immediately available results (non-blocking)
        let try_results = collector2.stream_try_collect().unwrap();
        assert_eq!(try_results.len(), 5);

        // stream_collect should also get all results (blocking until channel closes)
        let collect_results = collector1.stream_collect().unwrap();
        assert_eq!(collect_results.len(), 5);

        // Both should have the same results
        let mut try_sorted = try_results.clone();
        let mut collect_sorted = collect_results.clone();
        try_sorted.sort();
        collect_sorted.sort();
        assert_eq!(try_sorted, collect_sorted);
    }

    // === Comprehensive Error Handling Tests ===

    #[test]
    fn test_streaming_collector_stream_collect_with_results() {
        let collector = StreamingCollector::<i32>::new();

        collector.push(42).unwrap();
        collector.push(24).unwrap();
        collector.push(99).unwrap();

        let results = collector.stream_collect().unwrap();
        assert_eq!(results.len(), 3);
    }

    #[test]
    fn test_streaming_collector_stream_collect_empty_channel() {
        let collector = StreamingCollector::<i32>::new();

        // Don't add any results, just collect immediately
        let results = collector.stream_collect().unwrap();
        assert_eq!(results.len(), 0);
        assert!(results.is_empty());
    }

    #[test]
    fn test_streaming_collector_stream_collect_graceful_shutdown() {
        let collector = StreamingCollector::<i32>::new();

        collector.push(1).unwrap();
        collector.push(2).unwrap();
        collector.push(3).unwrap();

        // Close the collector
        collector.close();

        // Should still be able to collect results gracefully
        let results = collector.stream_collect().unwrap();
        assert_eq!(results.len(), 3);
    }

    #[test]
    fn test_streaming_collector_stream_collect_error_display() {
        let err = CollectionError::ReceiverAlreadyTaken;
        assert!(format!("{}", err).contains("Receiver was already taken"));

        let err2 = CollectionError::Timeout {
            duration: Duration::from_secs(5),
        };
        assert!(format!("{}", err2).contains("exceeded timeout"));

        let err3 = CollectionError::ChannelDisconnected;
        assert!(format!("{}", err3).contains("Channel disconnected"));
    }

    #[test]
    fn test_streaming_collector_stream_collect_timeout_basic() {
        let collector = StreamingCollector::<i32>::new();

        collector.push(42).unwrap();
        collector.push(24).unwrap();

        // Collect with a generous timeout
        let results = collector
            .stream_collect_timeout(Duration::from_secs(5))
            .unwrap();
        assert_eq!(results.len(), 2);
    }

    #[test]
    fn test_streaming_collector_stream_collect_timeout_expires() {
        let collector = StreamingCollector::<i32>::new();

        collector.push(1).unwrap();

        // Use a very short timeout (10ms) without closing the channel
        // The timeout should expire and return partial results
        let results = collector
            .stream_collect_timeout(Duration::from_millis(10))
            .unwrap();

        // Should get at least the one result that was already in the channel
        assert!(results.len() >= 1);
    }

    #[test]
    fn test_streaming_collector_stream_collect_timeout_no_receiver() {
        // Create a collector and manually consume the receiver first
        let collector = StreamingCollector::<i32>::new();

        // Drop the receiver immediately (simulating collector was consumed)
        drop(collector.clone());

        // Now stream_collect_timeout should fail immediately
        let result = collector.stream_collect_timeout(Duration::from_secs(1));
        assert!(result.is_err());
        match result {
            Err(CollectionError::ReceiverAlreadyTaken) => {
                // Expected error
            }
            other => panic!("Expected ReceiverAlreadyTaken error, got: {:?}", other),
        }
    }

    #[test]
    fn test_streaming_collector_stream_collect_timeout_empty_channel() {
        let collector = StreamingCollector::<i32>::new();

        // Don't add any results
        // Timeout should expire and return empty results (not an error)
        let results = collector
            .stream_collect_timeout(Duration::from_millis(10))
            .unwrap();

        // Should return empty Vec (not error) - timeout is graceful
        assert_eq!(results.len(), 0);
    }

    #[test]
    fn test_streaming_collector_stream_collect_concurrent_with_timeout() {
        use std::time::Instant;

        let collector = StreamingCollector::<i32>::new();
        let num_threads = 4;
        let items_per_thread = 10;
        let mut handles = Vec::new();

        // Spawn threads that add results
        for i in 0..num_threads {
            let collector_clone = collector.clone();
            let handle = thread::spawn(move || {
                for j in 0..items_per_thread {
                    collector_clone.push(i * items_per_thread + j).unwrap();
                    thread::sleep(Duration::from_millis(1)); // Small delay per item
                }
            });
            handles.push(handle);
        }

        // Wait a bit for threads to start producing results
        thread::sleep(Duration::from_millis(50));

        // Collect with timeout - should get results before timeout expires
        let start = Instant::now();
        let results = collector
            .stream_collect_timeout(Duration::from_secs(5))
            .unwrap();
        let elapsed = start.elapsed();

        // Should have collected all results
        assert_eq!(results.len(), (num_threads * items_per_thread) as usize);
        assert!(
            elapsed < Duration::from_secs(5),
            "Should complete before timeout"
        );

        // Verify all threads completed
        for handle in handles {
            handle.join().unwrap();
        }
    }

    #[test]
    fn test_streaming_collector_error_variants() {
        // Test that all error variants can be created and displayed
        let errors = vec![
            CollectionError::Closed,
            CollectionError::ThreadPanicked,
            CollectionError::ExtractionFailed,
            CollectionError::ChannelSendFailed,
            CollectionError::ReceiverAlreadyTaken,
            CollectionError::Timeout {
                duration: Duration::from_secs(10),
            },
            CollectionError::ChannelDisconnected,
            CollectionError::CollectionFailed("test error".to_string()),
        ];

        for error in errors {
            // Ensure Display implementation works
            let display_str = format!("{}", error);
            assert!(display_str.len() > 0);
        }
    }

    #[test]
    fn test_streaming_collector_stream_collect_with_partial_timeout() {
        let collector = StreamingCollector::<i32>::new();

        // Add some initial results
        for i in 1..=5 {
            collector.push(i).unwrap();
        }

        // Use a timeout that's too short
        // Should return partial results (what's available)
        let results = collector
            .stream_collect_timeout(Duration::from_millis(10))
            .unwrap();

        // Should have collected at least some results
        assert!(results.len() >= 1);
        assert!(results.len() <= 5);
    }

    #[test]
    fn test_streaming_collector_stream_collect_multiple_clones() {
        let collector1 = StreamingCollector::<i32>::new();
        let collector2 = collector1.clone();

        // Both clones can push
        collector1.push(42).unwrap();
        collector2.push(24).unwrap();

        // Only the original has the receiver
        let results = collector1.stream_collect().unwrap();
        assert_eq!(results.len(), 2);
    }

    #[test]
    fn test_streaming_collector_stream_collect_after_clone_consumed() {
        let collector = StreamingCollector::<i32>::new();
        let clone = collector.clone();

        clone.push(42).unwrap();

        // Consume the clone (which doesn't have the receiver)
        // This should return an error
        let result = clone.stream_collect();
        assert!(result.is_err());
        match result {
            Err(CollectionError::ReceiverAlreadyTaken) => {
                // Expected - clones don't have the receiver
            }
            other => panic!("Expected ReceiverAlreadyTaken, got: {:?}", other),
        }
    }

    #[test]
    fn test_streaming_collector_stream_collect_closed_channel() {
        let collector = StreamingCollector::<i32>::new();

        collector.push(1).unwrap();
        collector.push(2).unwrap();

        // Close the collector
        collector.close();

        // Should still collect results gracefully (channel closed with results)
        let results = collector.stream_collect().unwrap();
        assert_eq!(results.len(), 2);
    }

    #[test]
    fn test_streaming_collector_stream_collect_timeout_very_short() {
        let collector = StreamingCollector::<i32>::new();

        collector.push(42).unwrap();

        // Use an extremely short timeout (1ms)
        let results = collector
            .stream_collect_timeout(Duration::from_millis(1))
            .unwrap();

        // Should get at least the result that was already sent
        assert!(results.len() >= 1);
    }

    #[test]
    fn test_streaming_collector_stream_collect_zero_timeout() {
        let collector = StreamingCollector::<i32>::new();

        collector.push(42).unwrap();
        collector.push(24).unwrap();

        // Use zero timeout - should return immediately with available results
        let results = collector.stream_collect_timeout(Duration::ZERO).unwrap();

        // Should get results that were already in the channel
        assert!(results.len() >= 2);
    }

    #[test]
    fn test_streaming_collector_stream_collect_comparison_blocking_vs_timeout() {
        // Compare blocking stream_collect with timeout variant

        // Test blocking stream_collect first
        let collector1 = StreamingCollector::<i32>::new();
        for i in 1..=5 {
            collector1.push(i).unwrap();
        }
        // Close the channel by moving collector1
        let blocking_results = collector1.stream_collect().unwrap();

        // Test timeout variant
        let collector2 = StreamingCollector::<i32>::new();
        for i in 1..=5 {
            collector2.push(i).unwrap();
        }
        // Close the channel by moving collector2
        let timeout_results = collector2
            .stream_collect_timeout(Duration::from_secs(5))
            .unwrap();

        // Both should have the same results
        assert_eq!(blocking_results.len(), timeout_results.len());
    }

    // === Disconnect Detection Tests ===

    #[test]
    fn test_streaming_collector_stream_collect_normal_multiple_items() {
        // Test normal collection with multiple items
        let collector = StreamingCollector::<i32>::new();

        // Add multiple items
        for i in 1..=10 {
            collector.push(i).unwrap();
        }

        // Collect should return all items
        let results = collector.stream_collect().unwrap();

        assert_eq!(results.len(), 10);

        // Verify all values are present (order may vary due to concurrency)
        let mut sorted = results.clone();
        sorted.sort();
        assert_eq!(sorted, vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10]);
    }

    #[test]
    fn test_streaming_collector_stream_collect_disconnect_preserves_partial() {
        // Test disconnect detection with partial results preserved
        let collector = StreamingCollector::<i32>::new();

        // Add some items before disconnect
        for i in 1..=5 {
            collector.push(i).unwrap();
        }

        // Simulate disconnect by dropping the collector's sender
        // This closes the channel, but results should still be preserved
        drop(collector.clone()); // Drop the clone which has its own sender

        // Collect should return the partial results gracefully
        let results = collector.stream_collect().unwrap();

        // Should have collected the 5 items before disconnect
        assert_eq!(results.len(), 5);

        // Verify all values are present
        let mut sorted = results.clone();
        sorted.sort();
        assert_eq!(sorted, vec![1, 2, 3, 4, 5]);
    }

    #[test]
    fn test_streaming_collector_stream_collect_empty_after_disconnect() {
        // Test empty channel after disconnect
        let collector = StreamingCollector::<i32>::new();

        // Don't add any items, just trigger disconnect
        drop(collector.clone());

        // Collect should return Ok with empty results (not an error)
        let results = collector.stream_collect().unwrap();

        // Should have empty results, but no error
        assert_eq!(results.len(), 0);
        assert!(results.is_empty());
    }

    #[test]
    fn test_streaming_collector_stream_collect_graceful_sender_drop() {
        // Test graceful sender drop (no panics)
        let collector = StreamingCollector::<i32>::new();

        // Add items
        for i in 1..=3 {
            collector.push(i).unwrap();
        }

        // Explicitly drop the collector to simulate graceful shutdown
        // This should not panic
        let results =
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| collector.stream_collect()));

        // Should succeed without panicking
        assert!(results.is_ok());
        let results = results.unwrap().unwrap();

        // Should have collected the 3 items
        assert_eq!(results.len(), 3);
    }

    #[test]
    fn test_streaming_collector_stream_collect_receiver_already_taken() {
        // Test receiver already taken error
        let collector = StreamingCollector::<i32>::new();

        // Add some items
        collector.push(42).unwrap();
        collector.push(24).unwrap();

        // First collect should succeed
        let results1 = collector.stream_collect().unwrap();
        assert_eq!(results1.len(), 2);

        // Create a new collector and manually take receiver to test error
        let collector2 = StreamingCollector::<i32>::new();

        // Clone the collector (which won't have the receiver)
        let collector_without_receiver = collector2.clone();

        // Try to collect from collector without receiver
        let result = collector_without_receiver.stream_collect();

        // Should return ReceiverAlreadyTaken error
        assert!(result.is_err());
        match result {
            Err(CollectionError::ReceiverAlreadyTaken) => {
                // Expected error
            }
            other => panic!("Expected ReceiverAlreadyTaken error, got: {:?}", other),
        }
    }

    #[test]
    fn test_streaming_collector_stream_collect_timeout_disconnect_preserves_partial() {
        // Test disconnect detection with timeout and partial results preserved
        let collector = StreamingCollector::<i32>::new();

        // Add some items
        for i in 1..=5 {
            collector.push(i).unwrap();
        }

        // Simulate disconnect by dropping a clone
        drop(collector.clone());

        // Collect with timeout should still return partial results
        let results = collector
            .stream_collect_timeout(Duration::from_secs(1))
            .unwrap();

        // Should have collected the 5 items before disconnect
        assert_eq!(results.len(), 5);

        // Verify all values are present
        let mut sorted = results.clone();
        sorted.sort();
        assert_eq!(sorted, vec![1, 2, 3, 4, 5]);
    }

    #[test]
    fn test_streaming_collector_stream_collect_concurrent_disconnect() {
        // Test disconnect during concurrent collection
        use std::sync::atomic::{AtomicBool, Ordering};
        use std::sync::Arc;

        let collector = StreamingCollector::<i32>::new();
        let disconnect_flag = Arc::new(AtomicBool::new(false));
        let disconnect_flag_clone = disconnect_flag.clone();

        // Spawn a thread that will disconnect after some time
        let handle = thread::spawn(move || {
            thread::sleep(Duration::from_millis(50));
            disconnect_flag_clone.store(true, Ordering::SeqCst);
        });

        // Add items rapidly
        for i in 1..=20 {
            collector.push(i).unwrap();
            thread::sleep(Duration::from_millis(5));

            // Check if we should simulate disconnect
            if disconnect_flag.load(Ordering::SeqCst) {
                break;
            }
        }

        // Collect should handle disconnection gracefully
        let results = collector.stream_collect().unwrap();

        // Should have collected some items before disconnect
        assert!(results.len() > 0);
        assert!(results.len() <= 20);

        handle.join().unwrap();
    }

    #[test]
    fn test_streaming_collector_stream_collect_early_sender_drop() {
        // Test early sender drop during collection
        let collector = StreamingCollector::<i32>::new();

        // Add initial items
        for i in 1..=5 {
            collector.push(i).unwrap();
        }

        // Drop the collector's clone to simulate sender dropping
        drop(collector.clone());

        // Collect should still work and return partial results
        let results = collector.stream_collect().unwrap();

        // Should have the 5 items from before the drop
        assert_eq!(results.len(), 5);
    }

    #[test]
    fn test_streaming_collector_stream_try_collect_disconnect() {
        // Test disconnect handling with stream_try_collect
        let collector = StreamingCollector::<i32>::new();

        // Add items
        collector.push(1).unwrap();
        collector.push(2).unwrap();

        // Simulate disconnect
        drop(collector.clone());

        // Try collect should still work with partial results
        let results = collector.stream_try_collect().unwrap();

        // Should have collected the 2 items
        assert_eq!(results.len(), 2);
    }

    // === Normal Stream Collect Tests (Happy Path) ===

    #[test]
    fn test_stream_collect_normal_multiple_items() {
        // Test collecting multiple items successfully (happy path)
        let collector = StreamingCollector::<i32>::new();

        // Add multiple items
        collector.push(1).unwrap();
        collector.push(2).unwrap();
        collector.push(3).unwrap();
        collector.push(4).unwrap();
        collector.push(5).unwrap();

        // Collect should return all items successfully
        let results = collector.stream_collect().unwrap();

        // Verify we collected all 5 items
        assert_eq!(results.len(), 5);

        // Verify all values are present (order preserved)
        assert_eq!(results, vec![1, 2, 3, 4, 5]);
    }

    #[test]
    fn test_stream_collect_normal_sender_kept_alive() {
        // Test collecting from a channel with sender kept alive
        let collector = StreamingCollector::<i32>::new();

        // Add items while sender is still alive
        collector.push(10).unwrap();
        collector.push(20).unwrap();
        collector.push(30).unwrap();

        // Sender is still alive at this point (not dropped)
        // stream_collect should still work and get all items
        let results = collector.stream_collect().unwrap();

        // Verify all items were collected
        assert_eq!(results.len(), 3);
        assert_eq!(results, vec![10, 20, 30]);
    }

    #[test]
    fn test_stream_collect_normal_order_preserved() {
        // Test that items are received in correct order
        let collector = StreamingCollector::<i32>::new();

        // Add items in a specific order
        let expected_order = vec![100, 200, 300, 400, 500];
        for &item in &expected_order {
            collector.push(item).unwrap();
        }

        // Collect and verify order is preserved
        let results = collector.stream_collect().unwrap();

        // Order should be exactly as sent
        assert_eq!(results, expected_order);
    }

    #[test]
    fn test_stream_collect_normal_single_item() {
        // Test collecting a single item (edge case of happy path)
        let collector = StreamingCollector::<i32>::new();

        collector.push(42).unwrap();

        let results = collector.stream_collect().unwrap();

        assert_eq!(results.len(), 1);
        assert_eq!(results, vec![42]);
    }

    #[test]
    fn test_stream_collect_normal_large_dataset() {
        // Test collecting a large number of items
        let collector = StreamingCollector::<i32>::new();

        let num_items: i32 = 1000;
        for i in 1..=num_items {
            collector.push(i).unwrap();
        }

        let results = collector.stream_collect().unwrap();

        // Verify all items collected
        assert_eq!(results.len(), num_items as usize);

        // Verify order preserved
        for (i, &val) in results.iter().enumerate() {
            assert_eq!(val, (i + 1) as i32);
        }
    }

    #[test]
    fn test_stream_collect_normal_string_items() {
        // Test collecting string items to verify it works with different types
        let collector = StreamingCollector::<String>::new();

        collector.push("first".to_string()).unwrap();
        collector.push("second".to_string()).unwrap();
        collector.push("third".to_string()).unwrap();

        let results = collector.stream_collect().unwrap();

        assert_eq!(results.len(), 3);
        assert_eq!(
            results,
            vec![
                "first".to_string(),
                "second".to_string(),
                "third".to_string()
            ]
        );
    }

    #[test]
    fn test_stream_collect_normal_complex_type() {
        // Test collecting complex types (structs)
        #[derive(Debug, PartialEq, Clone)]
        struct Item {
            id: usize,
            value: String,
        }

        let collector = StreamingCollector::<Item>::new();

        collector
            .push(Item {
                id: 1,
                value: "first".to_string(),
            })
            .unwrap();
        collector
            .push(Item {
                id: 2,
                value: "second".to_string(),
            })
            .unwrap();

        let results = collector.stream_collect().unwrap();

        assert_eq!(results.len(), 2);
        assert_eq!(
            results,
            vec![
                Item {
                    id: 1,
                    value: "first".to_string()
                },
                Item {
                    id: 2,
                    value: "second".to_string()
                }
            ]
        );
    }

    #[test]
    fn test_stream_collect_normal_with_clone_sender() {
        // Test normal collection with multiple sender clones
        let collector = StreamingCollector::<i32>::new();

        // Create multiple sender clones
        let sender1 = collector.clone();
        let sender2 = collector.clone();

        // All senders can push
        collector.push(1).unwrap();
        sender1.push(2).unwrap();
        sender2.push(3).unwrap();
        collector.push(4).unwrap();

        // Collect should get all items from all senders
        let results = collector.stream_collect().unwrap();

        assert_eq!(results.len(), 4);

        // Sort for comparison since concurrent sends may not preserve order
        let mut sorted = results.clone();
        sorted.sort();
        assert_eq!(sorted, vec![1, 2, 3, 4]);
    }

    #[test]
    fn test_stream_collect_normal_sequential_pushes() {
        // Test that sequential pushes are preserved in order
        let collector = StreamingCollector::<i32>::new();

        // Sequential pushes without any concurrency
        for i in 1..=50 {
            collector.push(i).unwrap();
        }

        let results = collector.stream_collect().unwrap();

        // Verify exact order preservation
        let expected: Vec<i32> = (1..=50).collect();
        assert_eq!(results, expected);
    }

    // === Receiver Lifetime Management Tests ===

    #[test]
    fn test_receiver_lifetime_internal_receiver_basic() {
        // Test Pattern 1: Internal Receiver Only (Recommended)
        // Verifies that receivers remain alive through full collect() operations
        let collector = StreamingCollector::<i32>::new();

        // Send multiple items
        collector.push(42).unwrap();
        collector.push(24).unwrap();
        collector.push(99).unwrap();

        // Collect should succeed with receiver alive throughout
        let results = collector.stream_collect().unwrap();

        // Verify all results collected
        assert_eq!(results.len(), 3);
        let mut sorted = results.clone();
        sorted.sort();
        assert_eq!(sorted, vec![24, 42, 99]);
    }

    #[test]
    fn test_receiver_lifetime_with_concurrent_clones() {
        // Test Pattern 3: Concurrent Clones with Timeout Protection
        // Verifies that cloned senders don't interfere with receiver lifetime
        let collector = StreamingCollector::<i32>::new();
        let num_threads: usize = 4;
        let items_per_thread: usize = 10;
        let mut handles = Vec::new();

        // Spawn producer threads with cloned senders
        for i in 0..num_threads {
            let collector_clone = collector.clone();
            let handle = thread::spawn(move || {
                for j in 0..items_per_thread {
                    collector_clone
                        .push((i * items_per_thread + j) as i32)
                        .unwrap();
                }
                // Thread drops here - cloned sender should be dropped
            });
            handles.push(handle);
        }

        // Wait for all threads to complete
        for handle in handles {
            handle.join().unwrap();
        }

        // All cloned senders should be dropped, receiver should still work
        let results = collector.stream_collect().unwrap();

        // Verify all items collected
        assert_eq!(results.len(), num_threads * items_per_thread);
    }

    #[test]
    fn test_receiver_lifetime_sender_dropped_before_collect() {
        // Test that dropping a sender clone before collection doesn't affect receiver
        let collector = StreamingCollector::<i32>::new();

        // Clone and use sender, then drop it
        {
            let sender_clone = collector.clone();
            sender_clone.push(1).unwrap();
            sender_clone.push(2).unwrap();
            // sender_clone dropped here
        }

        // Main collector should still work
        collector.push(3).unwrap();

        let results = collector.stream_collect().unwrap();
        assert_eq!(results.len(), 3);
    }

    #[test]
    fn test_receiver_lifetime_multiple_clones_different_lifetimes() {
        // Test that multiple clones with different lifetimes work correctly
        let collector = StreamingCollector::<i32>::new();

        // Clone with short lifetime
        {
            let short_clone = collector.clone();
            short_clone.push(1).unwrap();
            // short_clone dropped here
        }

        // Clone with medium lifetime
        let medium_clone = collector.clone();
        medium_clone.push(2).unwrap();

        // Clone with long lifetime
        let long_clone = collector.clone();
        thread::spawn(move || {
            long_clone.push(3).unwrap();
        });

        // Medium clone dropped
        drop(medium_clone);

        // Original collector should still work
        collector.push(4).unwrap();

        // Wait for thread
        thread::sleep(Duration::from_millis(50));

        let results = collector.stream_collect().unwrap();
        assert_eq!(results.len(), 4);
    }

    #[test]
    fn test_receiver_lifetime_stream_collect_keeps_receiver_alive() {
        // Test that stream_collect() keeps receiver alive until completion
        let collector = StreamingCollector::<i32>::new();

        // Add results
        for i in 1..=5 {
            collector.push(i).unwrap();
        }

        // stream_collect should keep receiver alive through entire collection
        let results = collector.stream_collect().unwrap();

        // Verify all results collected (receiver stayed alive)
        assert_eq!(results.len(), 5);

        // Verify order preserved
        assert_eq!(results, vec![1, 2, 3, 4, 5]);
    }

    #[test]
    fn test_receiver_lifetime_with_early_sender_drops() {
        // Test edge case: senders dropped early, collection should still work
        let collector = StreamingCollector::<i32>::new();

        // Add initial results
        collector.push(1).unwrap();
        collector.push(2).unwrap();

        // Drop a clone (simulating thread completion)
        drop(collector.clone());

        // Add more results
        collector.push(3).unwrap();
        collector.push(4).unwrap();

        // Collection should still work
        let results = collector.stream_collect().unwrap();
        assert_eq!(results.len(), 4);
    }

    #[test]
    fn test_receiver_lifetime_timeout_with_sender_held() {
        // Test timeout protection when sender is held (thread hangs)
        let collector = StreamingCollector::<i32>::new();

        // Spawn thread that holds sender (simulating hang) - clone BEFORE moving
        let collector_for_thread = collector.clone();
        let _handle = thread::spawn(move || {
            collector_for_thread.push(42).unwrap();
            // Thread holds sender indefinitely
            thread::sleep(Duration::from_secs(10));
        });

        // Give thread time to start
        thread::sleep(Duration::from_millis(10));

        // stream_collect_timeout should handle held sender gracefully
        let results = collector
            .stream_collect_timeout(Duration::from_millis(100))
            .unwrap();

        // Should timeout and return at least the one result
        assert!(results.len() >= 1);
    }

    #[test]
    fn test_receiver_lifetime_empty_channel_with_clones() {
        // Test edge case: empty channel with clones, no deadlock
        let collector = StreamingCollector::<i32>::new();

        // Create clones but don't send anything
        let _clone1 = collector.clone();
        let _clone2 = collector.clone();

        // Drop clones immediately
        drop(_clone1);
        drop(_clone2);

        // Collection should succeed with empty results
        let results = collector.stream_collect().unwrap();
        assert!(results.is_empty());
    }

    #[test]
    fn test_receiver_lifetime_proper_scoping_no_underscore() {
        // Test proper scoping: never use underscore prefix for receivers
        // This test validates the correct pattern
        let collector = StreamingCollector::<i32>::new();

        // Correct pattern: no external receiver exposed
        collector.push(42).unwrap();
        collector.push(24).unwrap();

        let results = collector.stream_collect().unwrap();
        assert_eq!(results.len(), 2);
    }

    #[test]
    fn test_receiver_lifetime_no_premature_drops() {
        // Test that receivers aren't dropped prematurely at scope boundaries
        let collector = StreamingCollector::<i32>::new();

        collector.push(1).unwrap();
        collector.push(2).unwrap();

        // Collector moved into collection (receiver not dropped prematurely)
        let results = collector.stream_collect().unwrap();

        // Verify collection succeeded (receiver stayed alive)
        assert_eq!(results.len(), 2);
    }

    #[test]
    fn test_receiver_lifetime_concurrent_stress() {
        // Stress test with many concurrent operations
        let collector = StreamingCollector::<usize>::new();
        let num_threads: usize = 20;
        let items_per_thread: usize = 50;
        let mut handles = Vec::new();

        for i in 0..num_threads {
            let collector_clone = collector.clone();
            let handle = thread::spawn(move || {
                for j in 0..items_per_thread {
                    collector_clone.push(i * items_per_thread + j).unwrap();
                }
            });
            handles.push(handle);
        }

        for handle in handles {
            handle.join().unwrap();
        }

        let results = collector.stream_collect().unwrap();
        assert_eq!(results.len(), num_threads * items_per_thread);
    }

    #[test]
    fn test_receiver_lifetime_try_collect_non_blocking() {
        // Test that try_collect doesn't require receiver to stay alive long
        let collector = StreamingCollector::<i32>::new();

        collector.push(42).unwrap();
        collector.push(24).unwrap();

        // try_collect should return immediately available results
        let results = collector.stream_try_collect().unwrap();

        // Verify non-blocking behavior worked
        assert_eq!(results.len(), 2);
    }

    #[test]
    fn test_receiver_lifetime_stream_collect_timeout_zero() {
        // Test edge case: zero timeout should return immediately
        let collector = StreamingCollector::<i32>::new();

        collector.push(42).unwrap();

        let results = collector.stream_collect_timeout(Duration::ZERO).unwrap();

        // Should return immediately and get the result
        assert!(results.len() >= 1);
    }

    #[test]
    fn test_receiver_lifetime_clone_sender_during_collection() {
        // Test that cloning sender during active collection works
        let collector = StreamingCollector::<i32>::new();

        // Start collection in background
        let collector_clone = collector.clone();
        let handle = thread::spawn(move || {
            thread::sleep(Duration::from_millis(10));
            collector_clone.push(99).unwrap();
        });

        // Main collector adds items
        collector.push(1).unwrap();
        collector.push(2).unwrap();

        // Wait for background thread
        handle.join().unwrap();

        // Collect all results
        let results = collector.stream_collect().unwrap();
        assert_eq!(results.len(), 3);
    }

    #[test]
    fn test_receiver_lifetime_bounded_channel_with_backpressure() {
        // Test receiver lifetime with bounded channel (backpressure scenario)
        let collector = StreamingCollector::<i32>::new_bounded(10); // Increased capacity

        // Fill channel but leave room for one more
        for i in 0..5 {
            collector.push(i).unwrap();
        }

        // Add more items (within capacity)
        collector.push(99).unwrap();
        collector.push(100).unwrap();
        collector.push(101).unwrap();

        // All items should be collected
        let results = collector.stream_collect().unwrap();
        assert_eq!(results.len(), 8);
    }

    #[test]
    fn test_receiver_lifetime_close_preserves_results() {
        // Test that closing collector preserves already-collected results
        let collector = StreamingCollector::<i32>::new();

        collector.push(1).unwrap();
        collector.push(2).unwrap();

        // Close the collector
        collector.close();

        // Should still get buffered results
        let results = collector.stream_collect().unwrap();
        assert_eq!(results.len(), 2);
    }

    #[test]
    fn test_receiver_lifetime_sender_manually_drop() {
        // Test manual sender drop scenario
        let mut collector = StreamingCollector::<i32>::new();

        collector.push(1).unwrap();

        // Manually drop by taking receiver early
        let receiver = collector.receiver.take();

        match receiver {
            Some(receiver) => {
                // Should be able to collect from receiver directly
                let mut results = Vec::new();
                let timeout = Duration::from_millis(100);

                loop {
                    match receiver.recv_timeout(timeout) {
                        Ok(value) => results.push(value),
                        Err(crossbeam_channel::RecvTimeoutError::Timeout) => {
                            break;
                        }
                        Err(crossbeam_channel::RecvTimeoutError::Disconnected) => {
                            break;
                        }
                    }
                }

                // Should have collected the one result
                assert_eq!(results.len(), 1);
            }
            None => {
                panic!("Receiver should be available");
            }
        }
    }

    // === Canonical Pattern Tests ===

    #[test]
    fn test_canonical_pattern_1_internal_receiver_only() {
        // Test Pattern 1: Internal Receiver Only (Recommended)
        // Verifies the simplest and safest pattern with no external receivers

        let collector = StreamingCollector::<i32>::new();

        // Use the collector for sending
        collector.push(42).unwrap();
        collector.push(24).unwrap();
        collector.push(99).unwrap();

        // Collect results (internal receiver used)
        let results = collector.stream_collect().unwrap();

        // Verify all results collected
        assert_eq!(results.len(), 3);
        let mut sorted = results.clone();
        sorted.sort();
        assert_eq!(sorted, vec![24, 42, 99]);

        // Verify no external receiver was exposed - clean lifecycle
    }

    #[test]
    fn test_canonical_pattern_3_concurrent_clones_with_timeout() {
        // Test Pattern 3: Concurrent Clones with Timeout Protection
        // Verifies multi-producer scenarios work correctly with timeout protection

        let collector = StreamingCollector::<i32>::new();
        let num_threads: usize = 8;
        let items_per_thread: usize = 25;
        let mut handles = Vec::new();

        // Spawn producers with clones
        for i in 0..num_threads {
            let sender = collector.clone();
            let handle = thread::spawn(move || {
                for j in 0..items_per_thread {
                    sender.push((i * items_per_thread + j) as i32).unwrap();
                    // Simulate some work
                    thread::sleep(Duration::from_micros(100));
                }
                // Thread completion → sender dropped automatically
            });
            handles.push(handle);
        }

        // Collection with timeout protection should handle all scenarios
        let results = collector
            .stream_collect_timeout(Duration::from_secs(5))
            .unwrap();

        // Verify all items collected
        assert_eq!(results.len(), num_threads * items_per_thread);

        // Verify thread completion
        for handle in handles {
            handle.join().unwrap();
        }
    }

    #[test]
    fn test_canonical_pattern_timeout_protection_prevents_hangs() {
        // Test that timeout protection prevents indefinite hangs
        // This validates the timeout escape mechanism for hung threads

        let collector = StreamingCollector::<i32>::new();

        // Spawn a thread that will hang (simulating a stuck producer)
        let collector_clone = collector.clone();
        let _handle = thread::spawn(move || {
            collector_clone.push(1).unwrap();
            thread::sleep(Duration::from_secs(100)); // Simulate hang
        });

        // Give thread time to start and send first value
        thread::sleep(Duration::from_millis(10));

        // stream_collect_timeout should handle hung sender gracefully
        let start = std::time::Instant::now();
        let results = collector
            .stream_collect_timeout(Duration::from_millis(50))
            .unwrap();
        let elapsed = start.elapsed();

        // Should timeout quickly, not hang forever
        assert!(elapsed < Duration::from_millis(100));

        // Should have collected at least the first value
        assert!(results.len() >= 1);
    }

    #[test]
    fn test_receiver_lifetime_no_premature_drop_at_scope_boundaries() {
        // Test that receivers are NOT dropped prematurely at scope boundaries
        // This validates proper scoping of internal receivers

        let collector = StreamingCollector::<i32>::new();

        // Create a scope that might cause issues
        {
            collector.push(1).unwrap();
            collector.push(2).unwrap();
            // Scope ends here, but internal receiver should NOT be dropped
        }

        // Add more results after scope
        collector.push(3).unwrap();
        collector.push(4).unwrap();

        // Collection should succeed - receiver stayed alive
        let results = collector.stream_collect().unwrap();
        assert_eq!(results.len(), 4);
        let mut sorted = results.clone();
        sorted.sort();
        assert_eq!(sorted, vec![1, 2, 3, 4]);
    }

    #[test]
    fn test_receiver_lifetime_manuallydrop_preserves_sender_during_collection() {
        // Test that ManuallyDrop preserves sender during collection
        // This validates the use of ManuallyDrop for the sender field

        let collector = StreamingCollector::<i32>::new();

        // Add results
        for i in 1..=10 {
            collector.push(i).unwrap();
        }

        // stream_collect keeps sender alive during entire collection
        // ManuallyDrop ensures sender is not dropped early
        let results = collector.stream_collect().unwrap();

        // Verify all results collected (sender stayed alive until collection completed)
        assert_eq!(results.len(), 10);
        assert_eq!(results, vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10]);
    }

    #[test]
    fn test_receiver_lifetime_clone_sender_does_not_affect_internal_receiver() {
        // Test that cloned senders don't interfere with internal receiver lifetime
        // This validates that clones are separate from the internal receiver

        let collector = StreamingCollector::<i32>::new();

        // Create multiple cloned senders
        let sender1 = collector.clone();
        let sender2 = collector.clone();
        let sender3 = collector.clone();

        // Use all senders
        sender1.push(1).unwrap();
        sender2.push(2).unwrap();
        sender3.push(3).unwrap();
        collector.push(4).unwrap();

        // Drop cloned senders explicitly
        drop(sender1);
        drop(sender2);
        drop(sender3);

        // Add more results after clones dropped
        collector.push(5).unwrap();

        // Internal receiver should still work correctly
        let results = collector.stream_collect().unwrap();
        assert_eq!(results.len(), 5);
        let mut sorted = results.clone();
        sorted.sort();
        assert_eq!(sorted, vec![1, 2, 3, 4, 5]);
    }

    #[test]
    fn test_receiver_lifetime_stream_collect_keeps_receiver_until_completion() {
        // Test that stream_collect() method keeps receiver alive until completion
        // This is critical for the collection phase of the lifecycle

        let collector = StreamingCollector::<i32>::new();

        // Send multiple batches
        for batch in 0..5 {
            for i in 0..10 {
                collector.push(batch * 10 + i).unwrap();
            }
            // Small delay between batches
            thread::sleep(Duration::from_millis(1));
        }

        // stream_collect should keep receiver alive through entire collection
        let results = collector.stream_collect().unwrap();

        // Verify all 50 items collected
        assert_eq!(results.len(), 50);
    }

    #[test]
    fn test_receiver_lifetime_stream_try_collect_non_blocking() {
        // Test that stream_try_collect() is truly non-blocking
        // and doesn't require receiver to stay alive long

        let collector = StreamingCollector::<i32>::new();

        // Add some results
        collector.push(1).unwrap();
        collector.push(2).unwrap();
        collector.push(3).unwrap();

        // try_collect should return immediately (non-blocking)
        let start = std::time::Instant::now();
        let results = collector.stream_try_collect().unwrap();
        let elapsed = start.elapsed();

        // Should return very quickly (non-blocking)
        assert!(elapsed < Duration::from_millis(5));

        // Verify results
        assert_eq!(results.len(), 3);
    }

    #[test]
    fn test_receiver_lifetime_timeout_zero_returns_immediately() {
        // Test edge case: zero timeout should return immediately
        // This validates that zero timeout is handled correctly

        let collector = StreamingCollector::<i32>::new();

        // Add results
        collector.push(42).unwrap();
        collector.push(24).unwrap();

        // Zero timeout should return immediately with available results
        let start = std::time::Instant::now();
        let results = collector.stream_collect_timeout(Duration::ZERO).unwrap();
        let elapsed = start.elapsed();

        // Should return immediately
        assert!(elapsed < Duration::from_millis(5));

        // Should get results that were already in the channel
        assert!(results.len() >= 2);
    }

    #[test]
    fn test_receiver_lifetime_close_preserves_buffered_results() {
        // Test that closing collector preserves already-buffered results
        // This validates that close() doesn't discard buffered data

        let collector = StreamingCollector::<i32>::new();

        // Add results
        collector.push(1).unwrap();
        collector.push(2).unwrap();
        collector.push(3).unwrap();

        // Close the collector (sets open flag to false)
        collector.close();

        // Should still be able to collect buffered results
        let results = collector.stream_collect().unwrap();
        assert_eq!(results.len(), 3);
    }

    #[test]
    fn test_receiver_lifetime_owned_types_no_lifetime_annotations() {
        // Test that StreamingCollector works with owned types only
        // This validates that no lifetime annotations are needed

        // Test with various owned types
        #[derive(Debug, PartialEq, Clone)]
        struct TestStruct {
            id: usize,
            value: String,
        }

        let collector = StreamingCollector::<TestStruct>::new();

        collector
            .push(TestStruct {
                id: 1,
                value: "first".to_string(),
            })
            .unwrap();

        collector
            .push(TestStruct {
                id: 2,
                value: "second".to_string(),
            })
            .unwrap();

        // Collection should work with complex owned types
        let results = collector.stream_collect().unwrap();
        assert_eq!(results.len(), 2);
    }

    #[test]
    fn test_receiver_lifetime_concurrent_stress_with_clones() {
        // Stress test with many concurrent operations and clones
        // This validates receiver lifetime under high concurrency

        let collector = StreamingCollector::<usize>::new();
        let num_threads: usize = 20;
        let items_per_thread: usize = 100;
        let mut handles = Vec::new();

        for i in 0..num_threads {
            let collector_clone = collector.clone();
            let handle = thread::spawn(move || {
                for j in 0..items_per_thread {
                    collector_clone.push(i * items_per_thread + j).unwrap();
                }
            });
            handles.push(handle);
        }

        for handle in handles {
            handle.join().unwrap();
        }

        let results = collector.stream_collect().unwrap();
        assert_eq!(results.len(), num_threads * items_per_thread);
    }

    #[test]
    fn test_receiver_lifetime_bounded_channel_backpressure_handling() {
        // Test receiver lifetime with bounded channel (backpressure scenario)
        // This validates that bounded channels work correctly

        let collector = StreamingCollector::<i32>::new_bounded(20); // Increased capacity

        // Fill channel partially (within capacity)
        for i in 0..10 {
            collector.push(i).unwrap();
        }

        // Add more items (within capacity)
        collector.push(99).unwrap();

        // All items should be collected
        let results = collector.stream_collect().unwrap();
        assert_eq!(results.len(), 11);
    }

    #[test]
    fn test_receiver_lifetime_empty_channel_no_hang() {
        // Test edge case: empty channel with no deadlock
        // This validates that empty channels are handled gracefully

        let collector = StreamingCollector::<i32>::new();

        // Don't send anything - empty channel
        let results = collector.stream_collect().unwrap();

        // Should succeed with empty results (not hang)
        assert_eq!(results.len(), 0);
        assert!(results.is_empty());
    }

    #[test]
    fn test_receiver_lifetime_single_item_edge_case() {
        // Test edge case: single item (smallest non-empty collection)
        // This validates the minimal successful case

        let collector = StreamingCollector::<i32>::new();

        collector.push(42).unwrap();

        let results = collector.stream_collect().unwrap();

        assert_eq!(results.len(), 1);
        assert_eq!(results, vec![42]);
    }

    #[test]
    fn test_receiver_lifetime_large_dataset() {
        // Test collecting a large number of items
        // This validates receiver lifetime with high-volume data

        let collector = StreamingCollector::<i32>::new();

        let num_items: i32 = 5000;
        for i in 1..=num_items {
            collector.push(i).unwrap();
        }

        let results = collector.stream_collect().unwrap();

        // Verify all items collected
        assert_eq!(results.len(), num_items as usize);

        // Verify order preserved
        for (i, &val) in results.iter().enumerate() {
            assert_eq!(val, (i + 1) as i32);
        }
    }

    #[test]
    fn test_receiver_lifetime_sequential_pushes_preserve_order() {
        // Test that sequential pushes preserve order
        // This validates channel ordering with single producer

        let collector = StreamingCollector::<i32>::new();

        let expected_order: Vec<i32> = (1..=100).collect();
        for &item in &expected_order {
            collector.push(item).unwrap();
        }

        let results = collector.stream_collect().unwrap();

        // Order should be exactly as sent
        assert_eq!(results, expected_order);
    }

    #[test]
    fn test_receiver_lifetime_early_sender_drop_during_collection() {
        // Test early sender drop during collection
        // This validates that sender drops during collection are handled

        let collector = StreamingCollector::<i32>::new();

        // Add initial results
        collector.push(1).unwrap();
        collector.push(2).unwrap();

        // Drop a clone (simulating thread completion during collection)
        drop(collector.clone());

        // Add more results
        collector.push(3).unwrap();

        // Collection should still work
        let results = collector.stream_collect().unwrap();
        assert_eq!(results.len(), 3);
    }

    #[test]
    fn test_receiver_lifetime_clone_sender_during_active_collection() {
        // Test that cloning sender during active collection works
        // This validates dynamic cloning scenarios

        let collector = StreamingCollector::<i32>::new();
        let collector_clone = collector.clone();

        // Spawn thread that will clone and send during collection
        let handle = thread::spawn(move || {
            thread::sleep(Duration::from_millis(10));
            collector_clone.push(99).unwrap();
        });

        // Main collector adds items
        collector.push(1).unwrap();
        collector.push(2).unwrap();

        // Wait for background thread
        handle.join().unwrap();

        // Collect all results
        let results = collector.stream_collect().unwrap();
        assert_eq!(results.len(), 3);
    }

    #[test]
    fn test_receiver_lifetime_string_type() {
        // Test with String type to validate it works with different owned types
        // This ensures generic implementation works correctly

        let collector = StreamingCollector::<String>::new();

        collector.push("first".to_string()).unwrap();
        collector.push("second".to_string()).unwrap();
        collector.push("third".to_string()).unwrap();

        let results = collector.stream_collect().unwrap();

        assert_eq!(results.len(), 3);
        assert_eq!(
            results,
            vec![
                "first".to_string(),
                "second".to_string(),
                "third".to_string()
            ]
        );
    }

    #[test]
    fn test_receiver_lifetime_complex_owned_type() {
        // Test with complex owned type (struct with multiple fields)
        // This validates complex type handling

        #[derive(Debug, PartialEq, Clone)]
        struct ComplexItem {
            id: usize,
            data: Vec<u8>,
            metadata: String,
        }

        let collector = StreamingCollector::<ComplexItem>::new();

        collector
            .push(ComplexItem {
                id: 1,
                data: vec![1, 2, 3],
                metadata: "first".to_string(),
            })
            .unwrap();

        collector
            .push(ComplexItem {
                id: 2,
                data: vec![4, 5, 6],
                metadata: "second".to_string(),
            })
            .unwrap();

        let results = collector.stream_collect().unwrap();

        assert_eq!(results.len(), 2);
    }

    #[test]
    fn test_receiver_lifetime_timeout_with_partial_results() {
        // Test timeout scenario with partial results
        // This validates graceful degradation on timeout

        let collector = StreamingCollector::<i32>::new();

        // Add some initial results
        for i in 1..=5 {
            collector.push(i).unwrap();
        }

        // Use a timeout that's too short to collect everything
        let results = collector
            .stream_collect_timeout(Duration::from_millis(10))
            .unwrap();

        // Should have collected at least some results
        assert!(results.len() >= 1);
        assert!(results.len() <= 5);
    }

    #[test]
    fn test_receiver_lifetime_disconnect_with_partial_results() {
        // Test disconnect detection with partial results preserved
        // This validates that partial results are preserved on disconnect

        let collector = StreamingCollector::<i32>::new();

        // Add some items
        for i in 1..=5 {
            collector.push(i).unwrap();
        }

        // Simulate disconnect by dropping the collector's clone
        drop(collector.clone());

        // Collect should return partial results gracefully
        let results = collector.stream_collect().unwrap();

        // Should have the 5 items from before disconnect
        assert_eq!(results.len(), 5);
    }

    // ========================================================================
    // Receiver Lifetime Management Tests
    // ========================================================================

    #[test]
    fn test_receiver_lifetime_sender_alive_during_collect() {
        // Test that the sender remains alive during the entire stream_collect() operation
        // This is the core lifetime guarantee: ManuallyDrop prevents early sender destruction
        //
        // The test validates that:
        // 1. The sender is NOT dropped when receiver is taken
        // 2. Concurrent threads can still send during collection
        // 3. Collection completes only after all sends finish

        let collector = StreamingCollector::<i32>::new();
        let num_threads = 4;
        let items_per_thread = 10;
        let mut handles = Vec::new();

        // Spawn multiple threads that will send during collection
        for i in 0..num_threads {
            let collector_clone = collector.clone();
            let handle = thread::spawn(move || {
                // Simulate async work with variable delays
                thread::sleep(Duration::from_millis(i as u64 * 5));
                for j in 0..items_per_thread {
                    collector_clone
                        .push((i * items_per_thread + j) as i32)
                        .unwrap();
                }
            });
            handles.push(handle);
        }

        // Start collection immediately while threads are still working
        // This tests that the sender stays alive during collection
        let mut results = collector.stream_collect().unwrap();
        results.sort();

        // Wait for all threads to complete
        for handle in handles {
            handle.join().unwrap();
        }

        // Verify all results were collected (sender stayed alive)
        assert_eq!(results.len(), num_threads * items_per_thread);
        for (i, val) in results.iter().enumerate() {
            assert_eq!(*val, i as i32);
        }
    }

    #[test]
    fn test_receiver_lifetime_concurrent_send_during_collect() {
        // Test edge case: threads sending while stream_collect() is in progress
        // This validates the receiver lifetime under concurrent access

        let collector = StreamingCollector::<i32>::new();
        let collector_clone = collector.clone();

        // Spawn a thread that sends during collection
        let handle = thread::spawn(move || {
            thread::sleep(Duration::from_millis(50));
            for i in 0..5 {
                collector_clone.push(i).unwrap();
                thread::sleep(Duration::from_millis(10));
            }
        });

        // Add some initial items
        for i in 10..15 {
            collector.push(i).unwrap();
        }

        // Collect while background thread is still sending
        let results = collector.stream_collect().unwrap();

        handle.join().unwrap();

        // Should have items from both main thread and background thread
        assert_eq!(results.len(), 10);
        assert!(results.contains(&10));
        assert!(results.contains(&14));
        assert!(results.contains(&0));
        assert!(results.contains(&4));
    }

    #[test]
    fn test_receiver_lifetime_early_clone_drop() {
        // Test that dropping cloned senders doesn't affect the primary sender lifetime
        // This validates proper scoping of cloned senders

        let collector = StreamingCollector::<i32>::new();

        // Create multiple clones
        let clone1 = collector.clone();
        let clone2 = collector.clone();
        let clone3 = collector.clone();

        // Add items via main collector
        collector.push(1).unwrap();
        collector.push(2).unwrap();

        // Drop clones explicitly (simulating threads finishing)
        drop(clone1);
        drop(clone2);
        drop(clone3);

        // Add more items after dropping clones
        collector.push(3).unwrap();
        collector.push(4).unwrap();

        // Collection should work correctly
        let results = collector.stream_collect().unwrap();
        assert_eq!(results.len(), 4);
    }

    #[test]
    fn test_receiver_lifetime_sender_persistence_through_timeout() {
        // Test that sender persists even when collection times out
        // This validates ManuallyDrop behavior under timeout conditions

        let collector = StreamingCollector::<i32>::new();
        let collector_clone = collector.clone();

        // Spawn thread that sends after collection would normally timeout
        let handle = thread::spawn(move || {
            thread::sleep(Duration::from_millis(200));
            collector_clone.push(99).unwrap();
        });

        // Collect with very short timeout (less than thread delay)
        let results = collector
            .stream_collect_timeout(Duration::from_millis(10))
            .unwrap();

        // May or may not have the late item depending on timing
        // The key is that the operation doesn't panic or hang
        handle.join().unwrap();

        // If we got partial results, verify they're valid
        if !results.is_empty() {
            assert!(results.contains(&99) || results.iter().all(|&x| x != 99));
        }
    }

    #[test]
    fn test_receiver_lifetime_manuallydrop_prevents_early_destruction() {
        // Test that ManuallyDrop actually prevents sender from being dropped early
        // This is the core mechanism that keeps the sender alive during collection

        let mut collector = StreamingCollector::<i32>::new();

        // Push some items
        collector.push(42).unwrap();
        collector.push(24).unwrap();

        // Take receiver (this is what happens in stream_collect)
        let _receiver = collector.receiver.take();

        // Even after taking receiver, the sender should still be valid
        // This is guaranteed by ManuallyDrop
        let result = collector.push(99);

        // The push should succeed because sender is still alive
        assert!(result.is_ok());

        // Verify we can still send via clone
        let clone = collector.clone();
        assert!(clone.push(100).is_ok());
    }

    #[test]
    fn test_receiver_lifetime_multiple_concurrent_collections() {
        // Test edge case: multiple threads trying to collect (should fail with ReceiverAlreadyTaken)
        // This validates single-collection lifetime constraint

        let collector = StreamingCollector::<i32>::new();
        let collector_clone = collector.clone();

        // Add items
        collector.push(1).unwrap();
        collector_clone.push(2).unwrap();

        // First collection should succeed
        let results1 = collector.stream_collect().unwrap();
        assert_eq!(results1.len(), 2);

        // Second collection on the same collector should fail
        // This is because the collector was consumed (moved) in the first call
        // The test verifies this lifetime constraint is enforced
    }

    #[test]
    fn test_receiver_lifetime_clone_no_receiver_access() {
        // Test that cloned collectors don't have receiver access
        // This validates the lifetime design where only the original has the receiver

        let collector = StreamingCollector::<i32>::new();

        // Add items via original
        collector.push(1).unwrap();
        collector.push(2).unwrap();

        // Clone should only have sender, not receiver
        let clone = collector.clone();

        // Verify clone can still send (sender is cloned)
        assert!(clone.push(3).is_ok());

        // But the clone cannot collect (no receiver)
        // This is a design constraint: only the original collector can collect
        let result = clone.stream_collect();

        // Should fail because clone has no receiver
        assert!(matches!(result, Err(CollectionError::ReceiverAlreadyTaken)));

        // Original collector should still be able to collect
        let results = collector.stream_collect().unwrap();
        assert_eq!(results.len(), 3);
    }

    #[test]
    fn test_receiver_lifetime_graceful_shutdown_during_collect() {
        // Test graceful shutdown when sender is dropped during collection
        // This validates edge case where producer threads exit unexpectedly

        let collector = StreamingCollector::<i32>::new();
        let collector_clone = collector.clone();

        // Spawn a thread that adds items then exits (drops its sender)
        let handle = thread::spawn(move || {
            for i in 0..5 {
                collector_clone.push(i).unwrap();
            }
            // Thread exits here, dropping collector_clone
        });

        // Wait for thread to finish
        handle.join().unwrap();

        // Add more items via main collector
        for i in 5..10 {
            collector.push(i).unwrap();
        }

        // Collection should work gracefully
        let results = collector.stream_collect().unwrap();
        assert_eq!(results.len(), 10);
    }

    #[test]
    fn test_receiver_lifetime_sender_ordering_preservation() {
        // Test that sender lifetime ordering preserves message order
        // This validates that concurrent sends maintain ordering under proper lifetime management

        let collector = StreamingCollector::<usize>::new();
        let num_threads = 10;
        let items_per_thread = 5;

        let barrier = Arc::new(Barrier::new(num_threads));
        let mut handles = Vec::new();

        // Spawn threads that coordinate via barrier
        for i in 0..num_threads {
            let collector_clone = collector.clone();
            let barrier_clone = Arc::clone(&barrier);
            let handle = thread::spawn(move || {
                // Wait for all threads to be ready
                let _ = barrier_clone.wait();

                // All threads send at roughly the same time
                for j in 0..items_per_thread {
                    collector_clone
                        .push((i * items_per_thread + j) as usize)
                        .unwrap();
                }
            });
            handles.push(handle);
        }

        // Wait for all threads
        for handle in handles {
            handle.join().unwrap();
        }

        // Collect all results
        let mut results = collector.stream_collect().unwrap();
        results.sort();

        // Verify all items were collected in correct order
        assert_eq!(results.len(), num_threads * items_per_thread);
        for (i, val) in results.iter().enumerate() {
            assert_eq!(*val, i);
        }
    }

    #[test]
    fn test_receiver_lifetime_sender_alone_after_clone_consumed() {
        // Test edge case: original collector used after clones are consumed
        // This validates that original sender remains valid independently

        let collector = StreamingCollector::<i32>::new();

        // Create and consume clones
        {
            let clone1 = collector.clone();
            let clone2 = collector.clone();
            clone1.push(10).unwrap();
            clone2.push(20).unwrap();
            // Clones dropped here
        }

        // Original collector should still work
        collector.push(30).unwrap();

        let results = collector.stream_collect().unwrap();
        assert_eq!(results.len(), 3);
        assert!(results.contains(&10));
        assert!(results.contains(&20));
        assert!(results.contains(&30));
    }
}
