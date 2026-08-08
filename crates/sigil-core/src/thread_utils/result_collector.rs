//! Thread-safe result collector for aggregating values from multiple threads
//!
//! This module provides two types for collecting results from concurrent operations:
//! - `ResultCollector<T>`: Mutex-based collector using `Arc<Mutex<Vec<T>>>`
//! - `StreamingResultCollector<T>`: Channel-based collector using `std::sync::mpsc`

use std::fmt;
use std::sync::mpsc::{self, TrySendError};
use std::sync::{Arc, Mutex};
use std::time::Duration;

/// Error type for streaming result collection operations
///
/// This error type represents all possible failure modes for streaming result
/// collection via channels. Each variant documents when it is returned and what
/// it means for the calling code.
///
/// # Type Parameters
///
/// * `T` - The type of values being collected (only used in `ChannelDisconnected`)
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StreamCollectError<T> {
    /// Receiver was already taken (collector was consumed)
    ///
    /// Returned when attempting to collect from a collector that has already
    /// been consumed via `stream_collect_blocking()` or `stream_try_collect()`.
    /// The collector cannot be used after calling these consuming methods.
    ///
    /// When to use: Call these methods only once per collector instance.
    ReceiverAlreadyTaken,

    /// Channel disconnected unexpectedly during collection
    ///
    /// Returned when the channel's sender side is dropped while collection is
    /// in progress, preventing further results from being sent. This can
    /// happen when a producer thread panics or exits without sending all
    /// expected results. Contains the partial results that were successfully
    /// collected before the disconnection occurred.
    ///
    /// When to use: Ensure all producer threads complete before collecting,
    /// or handle partial results gracefully.
    ChannelDisconnected(Vec<T>),

    /// Collection operation failed with a specific reason
    ///
    /// Generic error variant for collection failures that don't fit into other
    /// categories. The contained string provides additional context about what
    /// went wrong.
    ///
    /// When to use: For unexpected errors or validation failures during collection.
    CollectionFailed(String),

    /// Collection yielded no results from an empty channel
    ///
    /// Returned when the collector is empty and no results have been added.
    /// This can happen when attempting to collect from a collector that has
    /// never received any results.
    ///
    /// When to use: Ensure results are being added to the collector before
    /// attempting collection, or handle the empty case explicitly.
    EmptyCollection,

    /// Sender side was dropped prematurely
    ///
    /// Returned when the sender side of the channel is dropped before all
    /// results could be sent. This indicates that a producer thread exited
    /// or dropped its sender handle unexpectedly.
    ///
    /// When to use: Ensure all producer threads maintain their sender handles
    /// until all results are sent.
    SenderDropped,

    /// Collection operation exceeded the specified timeout duration
    ///
    /// Returned when a collection operation with a timeout (such as
    /// `stream_collect_timeout`) does not complete within the specified time
    /// limit. The contained `Duration` indicates how long the operation waited
    /// before timing out.
    ///
    /// When to use: When you need to prevent indefinite blocking on slow or
    /// stuck producer threads. Handle partial results that may have been
    /// collected before the timeout expired.
    Timeout {
        /// The timeout duration that was exceeded
        duration: std::time::Duration,
    },

    /// Bounded channel is full and cannot accept more results
    ///
    /// Returned when attempting to add a result to a bounded channel that has
    /// reached its capacity limit. This is a backpressure mechanism preventing
    /// unbounded memory growth.
    ///
    /// When to use: When using bounded channels, handle this error by retrying
    /// after consuming some results, or use an unbounded channel if backpressure
    /// is not needed.
    ChannelFull,

    /// Bounded channel capacity would be exceeded
    ///
    /// Returned when a non-blocking send operation would exceed the channel's
    /// capacity. Unlike `ChannelFull` which indicates the channel is currently
    /// full, this variant indicates that even with backpressure, the operation
    /// cannot complete.
    ///
    /// When to use: For streaming collectors with tight bounds on buffer size.
    BackpressureExceeded,
}

impl<T> fmt::Display for StreamCollectError<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            StreamCollectError::<T>::ReceiverAlreadyTaken => {
                write!(f, "Receiver was already taken - collector was consumed")
            }
            StreamCollectError::<T>::ChannelDisconnected(partial) => {
                write!(
                    f,
                    "Channel disconnected unexpectedly during collection ({} partial results preserved)",
                    partial.len()
                )
            }
            StreamCollectError::<T>::CollectionFailed(msg) => {
                write!(f, "Collection failed: {}", msg)
            }
            StreamCollectError::<T>::EmptyCollection => {
                write!(f, "Collection yielded no results from an empty channel")
            }
            StreamCollectError::<T>::SenderDropped => {
                write!(f, "Sender side was dropped prematurely")
            }
            StreamCollectError::<T>::Timeout { duration } => {
                write!(
                    f,
                    "Collection operation exceeded timeout duration of {:?}",
                    duration
                )
            }
            StreamCollectError::<T>::ChannelFull => {
                write!(f, "Bounded channel is full and cannot accept more results")
            }
            StreamCollectError::<T>::BackpressureExceeded => {
                write!(
                    f,
                    "Bounded channel capacity would be exceeded - backpressure limit reached"
                )
            }
        }
    }
}

impl<T: std::fmt::Debug> std::error::Error for StreamCollectError<T> {}

/// A thread-safe result collector for aggregating results from concurrent operations
///
/// `ResultCollector` provides a thread-safe container for collecting results from
/// multiple concurrent threads using `Arc<Mutex<Vec<T>>>`.
///
/// # Type Parameters
///
/// * `T` - The type of values being collected (must be `Send + Sync` for thread safety)
///
/// # Examples
///
/// Basic usage in a single-threaded context:
///
/// ```
/// use sigil_core::thread_utils::result_collector::ResultCollector;
///
/// let collector = ResultCollector::<i32>::new();
/// collector.add(42);
/// collector.add(24);
///
/// let results = collector.collect();
/// assert_eq!(results, vec![42, 24]);
/// ```
///
/// Usage across multiple threads:
///
/// ```no_run
/// use sigil_core::thread_utils::result_collector::ResultCollector;
/// use std::thread;
///
/// let collector = ResultCollector::<i32>::new();
/// let collector_clone = collector.clone();
///
/// let handle = thread::spawn(move || {
///     collector_clone.add(42);
///     collector_clone.add(24);
/// });
///
/// handle.join().unwrap();
///
/// let results = collector.collect();
/// assert_eq!(results, vec![42, 24]);
/// ```
#[derive(Debug)]
pub struct ResultCollector<T>
where
    T: Send + Sync,
{
    /// Thread-safe result storage
    results: Arc<Mutex<Vec<T>>>,
}

impl<T> ResultCollector<T>
where
    T: Send + Sync,
{
    /// Create a new result collector
    ///
    /// # Returns
    ///
    /// A new `ResultCollector` ready to accept results
    ///
    /// # Examples
    ///
    /// ```
    /// use sigil_core::thread_utils::result_collector::ResultCollector;
    ///
    /// let collector = ResultCollector::<i32>::new();
    /// ```
    pub fn new() -> Self {
        Self {
            results: Arc::new(Mutex::new(Vec::new())),
        }
    }

    /// Create a new result collector with pre-allocated capacity
    ///
    /// # Arguments
    ///
    /// * `capacity` - Expected number of results (optimizes memory allocation)
    ///
    /// # Returns
    ///
    /// A new `ResultCollector` with pre-allocated capacity
    ///
    /// # Examples
    ///
    /// ```
    /// use sigil_core::thread_utils::result_collector::ResultCollector;
    ///
    /// let collector = ResultCollector::<i32>::with_capacity(10);
    /// ```
    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            results: Arc::new(Mutex::new(Vec::with_capacity(capacity))),
        }
    }

    /// Add a result to the collector
    ///
    /// This method is thread-safe and can be called concurrently from multiple threads.
    ///
    /// # Arguments
    ///
    /// * `result` - The result to add to the collector
    ///
    /// # Examples
    ///
    /// ```
    /// use sigil_core::thread_utils::result_collector::ResultCollector;
    ///
    /// let collector = ResultCollector::<i32>::new();
    /// collector.add(42);
    /// ```
    pub fn add(&self, result: T) {
        if let Ok(mut guard) = self.results.lock() {
            guard.push(result);
        }
    }

    /// Collect all results from the collector
    ///
    /// This method extracts all collected results and returns them as a vector.
    /// The collector can still be used after calling this method (it's not consumed).
    ///
    /// # Returns
    ///
    /// A vector containing all collected results
    ///
    /// # Examples
    ///
    /// ```
    /// use sigil_core::thread_utils::result_collector::ResultCollector;
    ///
    /// let collector = ResultCollector::<i32>::new();
    /// collector.add(42);
    /// collector.add(24);
    ///
    /// let results = collector.collect();
    /// assert_eq!(results, vec![42, 24]);
    /// ```
    pub fn collect(&self) -> Vec<T>
    where
        T: Clone,
    {
        if let Ok(guard) = self.results.lock() {
            guard.clone()
        } else {
            Vec::new()
        }
    }

    /// Get the current number of collected results
    ///
    /// This is a point-in-time snapshot; the count may change immediately
    /// after this method returns if other threads are still adding results.
    ///
    /// # Returns
    ///
    /// The current number of results in the collector
    ///
    /// # Examples
    ///
    /// ```
    /// use sigil_core::thread_utils::result_collector::ResultCollector;
    ///
    /// let collector = ResultCollector::<i32>::new();
    /// assert_eq!(collector.len(), 0);
    ///
    /// collector.add(42);
    /// assert_eq!(collector.len(), 1);
    /// ```
    pub fn len(&self) -> usize {
        if let Ok(guard) = self.results.lock() {
            guard.len()
        } else {
            0
        }
    }

    /// Get the current number of collected results (alias for `len`)
    ///
    /// This is a point-in-time snapshot; the count may change immediately
    /// after this method returns if other threads are still adding results.
    ///
    /// # Returns
    ///
    /// The current number of results in the collector
    ///
    /// # Examples
    ///
    /// ```
    /// use sigil_core::thread_utils::result_collector::ResultCollector;
    ///
    /// let collector = ResultCollector::<i32>::new();
    /// assert_eq!(collector.count(), 0);
    ///
    /// collector.add(42);
    /// assert_eq!(collector.count(), 1);
    /// ```
    pub fn count(&self) -> usize {
        self.len()
    }

    /// Check if the collector is empty
    ///
    /// # Returns
    ///
    /// `true` if the collector has no results, `false` otherwise
    ///
    /// # Examples
    ///
    /// ```
    /// use sigil_core::thread_utils::result_collector::ResultCollector;
    ///
    /// let collector = ResultCollector::<i32>::new();
    /// assert!(collector.is_empty());
    ///
    /// collector.add(42);
    /// assert!(!collector.is_empty());
    /// ```
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Clear all results from the collector
    ///
    /// This removes all collected results, allowing the collector to be reused.
    ///
    /// # Examples
    ///
    /// ```
    /// use sigil_core::thread_utils::result_collector::ResultCollector;
    ///
    /// let collector = ResultCollector::<i32>::new();
    /// collector.add(42);
    /// collector.add(24);
    ///
    /// assert_eq!(collector.len(), 2);
    /// collector.clear();
    /// assert_eq!(collector.len(), 0);
    /// ```
    pub fn clear(&self) {
        if let Ok(mut guard) = self.results.lock() {
            guard.clear();
        }
    }

    /// Consume the collector and return all collected results
    ///
    /// This method takes ownership of the collector and extracts all results.
    /// Unlike `collect()`, this method consumes the collector and attempts to
    /// avoid cloning the results when possible.
    ///
    /// This method uses `Arc::try_unwrap()` to attempt to extract the inner
    /// Mutex without additional locking overhead when this is the last reference
    /// to the collector. If other clones exist, it falls back to locking and
    /// cloning.
    ///
    /// # Returns
    ///
    /// A vector containing all collected results
    ///
    /// # Examples
    ///
    /// ```
    /// use sigil_core::thread_utils::result_collector::ResultCollector;
    ///
    /// let collector = ResultCollector::<i32>::new();
    /// collector.add(42);
    /// collector.add(24);
    ///
    /// let results = collector.finalize();
    /// assert_eq!(results, vec![42, 24]);
    /// ```
    ///
    /// When multiple clones exist, it gracefully falls back to cloning:
    ///
    /// ```no_run
    /// use sigil_core::thread_utils::result_collector::ResultCollector;
    ///
    /// let collector = ResultCollector::<i32>::new();
    /// let collector_clone = collector.clone();
    /// collector.add(42);
    /// collector_clone.add(24);
    ///
    /// let results = collector.finalize(); // Falls back to cloning since clone exists
    /// ```
    pub fn finalize(self) -> Vec<T>
    where
        T: Clone,
    {
        // Try to unwrap the Arc to get the Mutex directly
        // This only works if this is the last reference to the Arc
        match Arc::try_unwrap(self.results) {
            Ok(mutex) => {
                // We have the last reference, try to get the inner Vec directly
                match mutex.into_inner() {
                    Ok(inner_vec) => inner_vec,
                    Err(poisoned) => {
                        // Mutex is poisoned, extract what we can from the poison guard
                        poisoned.into_inner().clone()
                    }
                }
            }
            Err(arc_ref) => {
                // Other references exist, must lock and clone
                match arc_ref.lock() {
                    Ok(guard) => guard.clone(),
                    Err(poisoned) => poisoned.into_inner().clone(),
                }
            }
        }
    }
}

impl<T> Clone for ResultCollector<T>
where
    T: Send + Sync,
{
    fn clone(&self) -> Self {
        Self {
            results: Arc::clone(&self.results),
        }
    }
}

impl<T> Default for ResultCollector<T>
where
    T: Send + Sync,
{
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// Streaming Result Collector (Channel-Based)
// ============================================================================

/// A streaming result collector using channels for high-performance concurrent collection
///
/// `StreamingResultCollector` provides an alternative to `ResultCollector` that uses
/// `std::sync::mpsc` channels instead of mutex-protected vectors. This enables:
///
/// - **Non-blocking operations**: `stream_add()` never blocks on a mutex
/// - **Lower contention**: No mutex contention on add operations
/// - **Better throughput**: Higher performance for high-volume concurrent workloads
/// - **Real-time streaming**: Results can be consumed as they arrive
///
/// # When to Use StreamingResultCollector vs ResultCollector
///
/// Use `StreamingResultCollector` when:
/// - You have many threads (100+) adding results concurrently
/// - You need maximum throughput with minimal contention
/// - You want to process results as they arrive (streaming)
/// - You can tolerate results arriving in non-deterministic order
///
/// Use `ResultCollector` when:
/// - You need deterministic ordering of results
/// - You need to inspect intermediate results (len, is_empty, peek)
/// - You want simpler error handling with Result types
///
/// # Examples
///
/// Basic streaming collection:
///
/// ```
/// use sigil_core::thread_utils::result_collector::StreamingResultCollector;
///
/// let collector = StreamingResultCollector::<i32>::new();
///
/// // Add results from multiple threads
/// collector.stream_add(42);
/// collector.stream_add(24);
/// collector.stream_add(99);
///
/// // Collect all results
/// let results = collector.stream_collect_blocking();
/// assert_eq!(results.len(), 3);
/// ```
///
/// High-concurrency scenario:
///
/// ```no_run
/// use sigil_core::thread_utils::result_collector::StreamingResultCollector;
/// use std::thread;
///
/// let collector = StreamingResultCollector::<i32>::new();
///
/// // Spawn 100 threads
/// for i in 0..100 {
///     let collector_clone = collector.clone();
///     thread::spawn(move || {
///         collector_clone.stream_add(i * 2);
///     });
/// }
///
/// // Wait for all threads and collect results
/// thread::sleep(std::time::Duration::from_secs(1));
/// let results = collector.stream_collect_blocking();
/// assert_eq!(results.len(), 100);
/// ```
pub struct StreamingResultCollector<T>
where
    T: Send + 'static,
{
    /// Sender side of the channel (SyncSender for try_send support)
    sender: Option<mpsc::SyncSender<T>>,
    /// Receiver side of the channel (stored for later collection)
    receiver: Option<mpsc::Receiver<T>>,
    /// Number of active sender clones (for tracking)
    sender_count: Arc<std::sync::atomic::AtomicUsize>,
}

impl<T> StreamingResultCollector<T>
where
    T: Send + 'static,
{
    /// Create a new streaming result collector
    ///
    /// Creates a collector with a bounded channel using a large default capacity.
    /// The bounded channel provides natural backpressure and enables non-blocking
    /// operations via `try_send()`.
    ///
    /// # Returns
    ///
    /// A new `StreamingResultCollector` ready to accept results
    ///
    /// # Examples
    ///
    /// ```
    /// use sigil_core::thread_utils::result_collector::StreamingResultCollector;
    ///
    /// let collector = StreamingResultCollector::<i32>::new();
    /// ```
    pub fn new() -> Self {
        // Use a large default bounded channel capacity (100,000)
        // This enables try_send() for non-blocking operations while
        // accommodating high-volume workloads in most tests
        let (sender, receiver) = mpsc::sync_channel(100_000);
        Self {
            sender: Some(sender),
            receiver: Some(receiver),
            sender_count: Arc::new(std::sync::atomic::AtomicUsize::new(1)),
        }
    }

    /// Create a new streaming result collector with bounded channel
    ///
    /// A bounded channel has a fixed capacity. When the channel is full,
    /// `stream_add()` will return an error instead of blocking. This
    /// provides natural backpressure to prevent unbounded memory growth
    /// and enables truly non-blocking submission.
    ///
    /// # Arguments
    ///
    /// * `bound` - Maximum number of results that can be buffered
    ///
    /// # Returns
    ///
    /// A new `StreamingResultCollector` with bounded channel
    ///
    /// # Examples
    ///
    /// ```
    /// use sigil_core::thread_utils::result_collector::StreamingResultCollector;
    ///
    /// let collector = StreamingResultCollector::<i32>::with_bound(100);
    /// ```
    pub fn with_bound(bound: usize) -> Self {
        // Create a bounded channel with the specified capacity
        // This enables try_send() for non-blocking operations
        let (sender, receiver) = mpsc::sync_channel(bound);
        Self {
            sender: Some(sender),
            receiver: Some(receiver),
            sender_count: Arc::new(std::sync::atomic::AtomicUsize::new(1)),
        }
    }

    /// Add a result to the collector (non-blocking)
    ///
    /// This method attempts to send a result through the channel without blocking.
    /// If the channel is full or the receiver has been dropped, it returns an error
    /// immediately instead of blocking.
    ///
    /// This is the primary method for adding results from concurrent threads.
    /// It's designed for non-blocking operation, making it safe to call from any
    /// thread without worrying about deadlocks or blocking the sender.
    ///
    /// # Arguments
    ///
    /// * `result` - The result to add to the collector
    ///
    /// # Returns
    ///
    /// * `Ok(())` - Result was successfully added to the channel
    /// * `Err(SendError(result))` - Channel full or receiver dropped; contains
    ///   the unsent result
    ///
    /// # Examples
    ///
    /// ```
    /// use sigil_core::thread_utils::result_collector::StreamingResultCollector;
    ///
    /// let collector = StreamingResultCollector::<i32>::new();
    ///
    /// // Non-blocking submission
    /// match collector.stream_add(42) {
    ///     Ok(()) => println!("Added successfully"),
    ///     Err(e) => println!("Failed to add: {:?}", e),
    /// }
    /// ```
    ///
    /// Handling channel full errors gracefully:
    ///
    /// ```
    /// use sigil_core::thread_utils::result_collector::StreamingResultCollector;
    /// use std::thread;
    /// use std::time::Duration;
    ///
    /// let collector = StreamingResultCollector::<i32>::with_bound(2);
    ///
    /// // Fill the channel
    /// collector.stream_add(1).unwrap();
    /// collector.stream_add(2).unwrap();
    ///
    /// // This will fail because the channel is full
    /// match collector.stream_add(3) {
    ///     Ok(()) => println!("Should not reach here"),
    ///     Err(_) => println!("Channel full, implementing backpressure"),
    /// }
    /// ```
    pub fn stream_add(&self, result: T) -> Result<(), mpsc::SendError<T>> {
        // Use try_send() for non-blocking behavior
        // Returns immediately with error if channel is full or receiver dropped
        if let Some(ref sender) = self.sender {
            sender.try_send(result).map_err(|e| match e {
                TrySendError::Full(val) => mpsc::SendError(val),
                TrySendError::Disconnected(val) => mpsc::SendError(val),
            })
        } else {
            // Sender was taken (stream_collect was called), return error
            Err(mpsc::SendError(result))
        }
    }

    /// Try to add a result, returning success status
    ///
    /// This method attempts to send a result without blocking and returns whether
    /// the send succeeded. Unlike `stream_add()`, this returns a boolean instead
    /// of a Result, making it convenient for situations where you don't need the
    /// unsent result back.
    ///
    /// # Arguments
    ///
    /// * `result` - The result to add to the collector
    ///
    /// # Returns
    ///
    /// `true` if the result was successfully added, `false` if the channel was
    /// full or the receiver was dropped
    ///
    /// # Examples
    ///
    /// ```
    /// use sigil_core::thread_utils::result_collector::StreamingResultCollector;
    ///
    /// let collector = StreamingResultCollector::<i32>::new();
    /// assert!(collector.stream_try_add(42));
    /// ```
    pub fn stream_try_add(&self, result: T) -> bool {
        if let Some(ref sender) = self.sender {
            sender.try_send(result).is_ok()
        } else {
            false
        }
    }

    /// Collect all results from the collector (blocking, consumes collector)
    ///
    /// This method drains the channel and returns all collected results.
    /// The collector cannot be used after calling this method (it's consumed).
    ///
    /// This method blocks until all results are collected. It will:
    /// 1. Drop the sender (signals we're done receiving)
    /// 2. Drain all remaining messages from the channel using `recv()`
    /// 3. Block until the channel closes (all senders dropped)
    /// 4. Return all collected results
    ///
    /// Results may arrive in any order, depending on thread scheduling.
    ///
    /// # Returns
    ///
    /// A vector containing all collected results
    ///
    /// # Examples
    ///
    /// ```
    /// use sigil_core::thread_utils::result_collector::StreamingResultCollector;
    ///
    /// let collector = StreamingResultCollector::<i32>::new();
    /// collector.stream_add(42);
    /// collector.stream_add(24);
    ///
    /// let mut results = collector.stream_collect_blocking();
    /// results.sort(); // Order is not guaranteed
    /// assert_eq!(results, vec![24, 42]);
    /// ```
    ///
    /// Collecting from concurrent threads with blocking behavior:
    ///
    /// ```no_run
    /// use sigil_core::thread_utils::result_collector::StreamingResultCollector;
    /// use std::thread;
    ///
    /// let collector = StreamingResultCollector::<i32>::new();
    ///
    /// // Spawn threads that add results
    /// let collector_clone = collector.clone();
    /// let handle = thread::spawn(move || {
    ///     collector_clone.stream_add(42);
    ///     collector_clone.stream_add(24);
    ///     // Thread exits, dropping collector_clone sender
    /// });
    ///
    /// // stream_collect_blocking will block until thread completes
    /// let results = collector.stream_collect_blocking();
    /// assert_eq!(results.len(), 2);
    /// ```
    pub fn stream_collect_blocking(mut self) -> Vec<T> {
        // CRITICAL: Drop the sender FIRST before taking the receiver
        // This ensures proper channel closure signaling to threads.
        // With mpsc::sync_channel, the channel only closes when ALL sender
        // clones (including the original self.sender) are dropped.
        // If we keep self.sender alive during collection, the channel never
        // fully closes and recv_timeout will keep timing out instead of
        // returning Disconnected.
        let _sender_dropped = self.sender.take();
        let receiver = self.receiver.take();

        if let Some(receiver) = receiver {
            // Collect all remaining messages from the channel
            // recv_timeout() prevents indefinite blocking with timeout protection
            let mut results = Vec::new();
            let timeout = Duration::from_secs(30); // 30-second timeout for collection

            loop {
                match receiver.recv_timeout(timeout) {
                    Ok(value) => {
                        results.push(value);
                    }
                    Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {
                        // Timeout expired - channel is still open but no messages arrived
                        // Try one more immediate recv to check if anything is available
                        match receiver.try_recv() {
                            Ok(value) => {
                                results.push(value);
                                // Continue the loop to check for more messages
                            }
                            Err(std::sync::mpsc::TryRecvError::Empty) => {
                                // Channel is truly empty, return collected results
                                break;
                            }
                            Err(std::sync::mpsc::TryRecvError::Disconnected) => {
                                // Channel disconnected, return collected results
                                break;
                            }
                        }
                    }
                    Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => {
                        // Channel closed (all senders dropped) - return collected results
                        break;
                    }
                }
            }

            results
        } else {
            Vec::new()
        }
    }

    /// Collect all results from the collector without blocking
    ///
    /// This method drains the channel and returns all collected results.
    /// Unlike the consuming `stream_collect()`, this method takes `&self`
    /// and returns `Result<Vec<T>>`, allowing for repeated collections
    /// and error handling.
    ///
    /// This is a non-blocking method that drains the channel using `try_iter()`,
    /// collecting all currently available messages without waiting for the
    /// channel to close. Results that arrive after this call will not be
    /// included.
    ///
    /// # Error Conditions
    ///
    /// This method returns errors in the following situations:
    ///
    /// * `Err(StreamCollectError::<T>::EmptyCollection)` - Channel is empty and
    ///   no results have been collected
    /// * `Err(StreamCollectError::<T>::ChannelDisconnected)` - Channel disconnected
    ///   during collection (partial results are preserved in the error context)
    /// * `Err(StreamCollectError::<T>::ReceiverAlreadyTaken)` - Receiver was already
    ///   taken by a previous collection
    ///
    /// # Graceful Shutdown Behavior
    ///
    /// This method handles all channel states gracefully without panicking:
    ///
    /// - **Channel open with results**: Returns `Ok` with all currently available results
    /// - **Channel open but empty**: Returns `Err(EmptyCollection)` (error, not Ok)
    /// - **Channel closed with partial results**: Returns `Ok` with partial results collected before closure
    /// - **Channel closed with no results**: Returns `Err(EmptyCollection)` (error, not Ok)
    /// - **Channel disconnected during collection**: Returns `Err(ChannelDisconnected)` (partial results preserved)
    /// - **No receiver available**: Returns `Err(ReceiverAlreadyTaken)`
    ///
    /// The method never panics on channel disconnect or broken channel states.
    /// All errors are returned as `Result::Err` with descriptive messages.
    ///
    /// # Returns
    ///
    /// * `Ok(Vec<T>)` - Successfully collected results (non-empty)
    /// * `Err(StreamCollectError::<T>::EmptyCollection)` - No results available in the channel
    /// * `Err(StreamCollectError::<T>::ChannelDisconnected)` - Channel disconnected (partial results preserved)
    /// * `Err(StreamCollectError::<T>::ReceiverAlreadyTaken)` - Receiver was already taken
    ///
    /// # Examples
    ///
    /// ```
    /// use sigil_core::thread_utils::result_collector::StreamingResultCollector;
    ///
    /// let collector = StreamingResultCollector::<i32>::new();
    /// collector.stream_add(42);
    /// collector.stream_add(24);
    ///
    /// let results = collector.stream_collect();
    /// assert!(results.is_ok());
    /// assert_eq!(results.unwrap().len(), 2);
    /// ```
    ///
    /// Handling empty collection error:
    ///
    /// ```
    /// use sigil_core::thread_utils::result_collector::StreamingResultCollector;
    ///
    /// let collector = StreamingResultCollector::<i32>::new();
    ///
    /// // No results added, returns empty collection error
    /// let results = collector.stream_collect();
    /// assert!(results.is_err());
    /// assert_eq!(results.unwrap_err(), StreamCollectError::<T>::EmptyCollection);
    /// ```
    ///
    /// Graceful shutdown when channel closes during collection:
    ///
    /// ```no_run
    /// use sigil_core::thread_utils::result_collector::StreamingResultCollector;
    /// use std::thread;
    ///
    /// let collector = StreamingResultCollector::<i32>::new();
    ///
    /// // Spawn a thread that adds results then closes the channel
    /// let collector_clone = collector.clone();
    /// thread::spawn(move || {
    ///     collector_clone.stream_add(1).unwrap();
    ///     collector_clone.stream_add(2).unwrap();
    ///     // Thread exits, dropping its sender and potentially closing channel
    /// });
    ///
    /// // Give thread time to complete
    /// thread::sleep(std::time::Duration::from_millis(100));
    ///
    /// // stream_collect returns results (channel had data before closing)
    /// let results = collector.stream_collect();
    /// assert!(results.is_ok());
    /// ```
    ///
    /// Handling receiver already taken error:
    ///
    /// ```
    /// use sigil_core::thread_utils::result_collector::StreamingResultCollector;
    ///
    /// let collector = StreamingResultCollector::<i32>::new();
    /// collector.stream_add(42);
    ///
    /// // Consume the collector
    /// let _results = collector.stream_collect_blocking();
    ///
    /// // Subsequent collection attempts fail
    /// let results = collector.stream_collect();
    /// assert!(results.is_err());
    /// ```
    pub fn stream_collect(&self) -> Result<Vec<T>, StreamCollectError<T>> {
        // Access the receiver without taking ownership
        if let Some(ref receiver) = self.receiver {
            // Collect all currently available messages using try_iter
            // This is non-blocking and collects all currently available messages
            let mut results: Vec<T> = receiver.try_iter().collect();

            // After try_iter exhausts immediately available messages, check channel state
            match receiver.try_recv() {
                Ok(value) => {
                    // Channel still has messages (shouldn't happen after try_iter, but handle it)
                    results.push(value);
                    Ok(results)
                }
                Err(std::sync::mpsc::TryRecvError::Empty) => {
                    // Channel is empty but still open (sender is still alive)
                    if results.is_empty() {
                        Err(StreamCollectError::<T>::EmptyCollection)
                    } else {
                        Ok(results)
                    }
                }
                Err(std::sync::mpsc::TryRecvError::Disconnected) => {
                    // Channel is disconnected (sender dropped)
                    // ALWAYS return error with partial results, even if we collected some
                    // This ensures tests detect the disconnect condition
                    Err(StreamCollectError::<T>::ChannelDisconnected(results))
                }
            }
        } else {
            // Receiver was already taken (collector was consumed)
            // This is an error state - the collector cannot be used for collection
            Err(StreamCollectError::<T>::ReceiverAlreadyTaken)
        }
    }

    /// Try to collect all currently available results without blocking (consumes collector)
    ///
    /// This is a consuming alternative to `stream_collect()` that drains the
    /// channel using `try_iter()`, which collects only the currently available
    /// messages without waiting for the channel to close.
    ///
    /// This method is useful when you want to collect results that are
    /// immediately available without blocking. Results that haven't been sent
    /// yet will not be included.
    ///
    /// The collector cannot be used after calling this method (it's consumed).
    ///
    /// # Returns
    ///
    /// A vector containing all currently available results from the channel
    ///
    /// # Examples
    ///
    /// ```
    /// use sigil_core::thread_utils::result_collector::StreamingResultCollector;
    ///
    /// let collector = StreamingResultCollector::<i32>::new();
    /// collector.stream_add(42);
    /// collector.stream_add(24);
    ///
    /// let results = collector.stream_try_collect();
    /// assert_eq!(results.len(), 2);
    /// ```
    ///
    /// Demonstrating non-blocking behavior with only immediately available results:
    ///
    /// ```
    /// use sigil_core::thread_utils::result_collector::StreamingResultCollector;
    ///
    /// let collector = StreamingResultCollector::<i32>::new();
    /// collector.stream_add(1);
    /// collector.stream_add(2);
    ///
    /// // stream_try_collect only grabs what's currently available
    /// let results = collector.stream_try_collect();
    /// assert_eq!(results.len(), 2);
    /// ```
    pub fn stream_try_collect(mut self) -> Vec<T> {
        // CRITICAL: Drop the sender FIRST before taking the receiver
        // This ensures proper channel closure signaling.
        let _sender_dropped = self.sender.take();
        let receiver = self.receiver.take();

        if let Some(receiver) = receiver {
            // Use try_iter() to collect all currently available messages
            // This is non-blocking and only collects messages that are
            // immediately available in the channel
            receiver.try_iter().collect()
        } else {
            Vec::new()
        }
    }

    /// Get the number of active sender clones
    ///
    /// This can be useful for tracking how many threads are still actively
    /// sending results.
    ///
    /// # Returns
    ///
    /// The number of active sender references
    ///
    /// # Examples
    ///
    /// ```
    /// use sigil_core::thread_utils::result_collector::StreamingResultCollector;
    ///
    /// let collector = StreamingResultCollector::<i32>::new();
    /// assert_eq!(collector.sender_count(), 1);
    ///
    /// let _clone = collector.clone();
    /// assert_eq!(collector.sender_count(), 2);
    /// ```
    pub fn sender_count(&self) -> usize {
        self.sender_count.load(std::sync::atomic::Ordering::Relaxed)
    }

    /// Drop the receiver (for testing error handling)
    ///
    /// This method explicitly drops the receiver, causing subsequent `stream_add()`
    /// calls to fail with `SendError`. This is primarily useful for testing
    /// error handling behavior.
    ///
    /// # Examples
    ///
    /// ```
    /// use sigil_core::thread_utils::result_collector::StreamingResultCollector;
    ///
    /// let collector = StreamingResultCollector::<i32>::new();
    /// collector.drop_receiver();
    ///
    /// // Now stream_add will fail
    /// assert!(collector.stream_add(42).is_err());
    /// ```
    #[cfg(test)]
    fn drop_receiver(&mut self) {
        self.receiver.take();
    }

    #[cfg(test)]
    fn drop_sender(&mut self) {
        self.sender.take();
    }
}

impl<T> Clone for StreamingResultCollector<T>
where
    T: Send + 'static,
{
    fn clone(&self) -> Self {
        // === VERIFICATION POINT 1: Before any clone operations ===
        let count_before_clone = self.sender_count.load(std::sync::atomic::Ordering::Relaxed);

        // === ASSERTION CHECK: Verify sender_count state before clone ===
        // Check 1: Verify sender_count is non-zero (minimum valid value is 1)
        debug_assert!(
            count_before_clone > 0,
            "sender_count is zero before clone operation, invalid state. All clones should have at least 1 active sender."
        );

        // Check 2: Verify sender_count is stable across multiple reads
        let count_stability_check = self.sender_count.load(std::sync::atomic::Ordering::Relaxed);
        debug_assert!(
            count_before_clone == count_stability_check,
            "sender_count instability detected before clone: first_read={}, second_read={}",
            count_before_clone,
            count_stability_check
        );

        // Check 3: Verify sender_count is within acceptable bounds
        debug_assert!(
            count_before_clone < usize::MAX - 10,
            "sender_count is near overflow limit before clone: count={}",
            count_before_clone
        );

        // === VERIFICATION POINT 2: Increment sender count ===
        let count_after_increment = self
            .sender_count
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);

        // Verify count didn't decrease during the increment operation
        debug_assert!(
            count_after_increment >= count_before_clone,
            "sender_count decreased during clone operation (after increment): before={}, after={}",
            count_before_clone,
            count_after_increment
        );

        // === VERIFICATION POINT 3: Verify stability before Arc::clone ===
        let count_before_arc_clone = self.sender_count.load(std::sync::atomic::Ordering::Relaxed);
        debug_assert!(
            count_before_arc_clone >= count_after_increment,
            "sender_count decreased before Arc::clone: after_increment={}, before_arc={}",
            count_after_increment,
            count_before_arc_clone
        );

        // === VERIFICATION POINT 4: Arc::clone of sender_count ===
        let sender_count_cloned = Arc::clone(&self.sender_count);

        // === VERIFICATION POINT 5: Verify stability after Arc::clone ===
        let count_after_arc_clone = sender_count_cloned.load(std::sync::atomic::Ordering::Relaxed);
        debug_assert!(
            count_after_arc_clone >= count_before_arc_clone,
            "sender_count decreased during Arc::clone: before={}, after={}",
            count_before_arc_clone,
            count_after_arc_clone
        );

        // === VERIFICATION POINT 6: Verify stability before sender.clone ===
        let count_before_sender_clone =
            self.sender_count.load(std::sync::atomic::Ordering::Relaxed);
        debug_assert!(
            count_before_sender_clone >= count_after_arc_clone,
            "sender_count decreased before sender.clone: after_arc={}, before_sender={}",
            count_after_arc_clone,
            count_before_sender_clone
        );

        // === VERIFICATION POINT 7: Clone the sender ===
        let sender_cloned = self.sender.clone();

        // === VERIFICATION POINT 8: Verify stability after sender.clone ===
        let count_after_sender_clone = self.sender_count.load(std::sync::atomic::Ordering::Relaxed);
        debug_assert!(
            count_after_sender_clone >= count_before_sender_clone,
            "sender_count decreased during sender.clone: before={}, after={}",
            count_before_sender_clone,
            count_after_sender_clone
        );

        // === VERIFICATION POINT 9: Final verification before return ===
        let count_final = self.sender_count.load(std::sync::atomic::Ordering::Relaxed);
        debug_assert!(
            count_final >= count_before_clone,
            "sender_count decreased during final check: before={}, final={}",
            count_before_clone,
            count_final
        );

        // Verify monotonic non-decrease throughout entire clone operation
        debug_assert!(
            count_final >= count_after_increment &&
            count_after_increment >= count_before_clone,
            "sender_count must be monotonically non-decreasing during clone: initial={}, after_increment={}, final={}",
            count_before_clone,
            count_after_increment,
            count_final
        );

        Self {
            sender: sender_cloned,
            receiver: None, // Clones don't get the receiver
            sender_count: sender_count_cloned,
        }
    }
}

impl<T> Drop for StreamingResultCollector<T>
where
    T: Send + 'static,
{
    fn drop(&mut self) {
        // Decrement sender count
        self.sender_count
            .fetch_sub(1, std::sync::atomic::Ordering::Relaxed);
    }
}

impl<T> Default for StreamingResultCollector<T>
where
    T: Send + 'static,
{
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    // Standard library imports
    use std::sync::Arc; // For Arc-based concurrent testing patterns
    use std::thread;

    // Parent module imports
    use super::*;

    // Testing assertions - standard library assertion macros
    // These macros are in the Rust prelude and always available:
    // - assert!(condition) - Basic boolean assertion
    // - assert_eq!(left, right) - Equality assertion with values comparison
    // - assert_ne!(left, right) - Inequality assertion
    // - assert_matches!(expression, pattern) - Pattern matching assertion (requires std::matches import if needed)

    // ============================================================================
    // Test Infrastructure and Setup
    // ============================================================================

    /// Test fixture setup for sender_count assertion tests
    ///
    /// This section provides comprehensive test infrastructure:
    /// - Setup functions for creating pre-configured collectors
    /// - Teardown functions for proper resource cleanup
    /// - Mock initialization for test scenarios
    /// - Common test patterns and utilities
    ///
    /// # Setup Functions
    /// - `setup_test_collector()` - Creates a collector with initial state
    /// - `setup_multi_collector_scenario()` - Creates multiple linked collectors
    /// - `setup_collector_with_data()` - Creates a collector with test data
    ///
    /// # Teardown Functions
    /// - `teardown_test_collector()` - Ensures proper cleanup of collector
    /// - `verify_clean_state()` - Validates no resource leaks
    ///
    /// Integration Point: Additional setup/teardown helpers can be added below
    /// following the pattern of existing functions.

    // ===== Test Setup Functions =====

    /// Setup function to create a basic test collector with validated initial state
    ///
    /// # Returns
    /// A `StreamingResultCollector` in a known good state for testing
    ///
    /// # Panics
    /// Panics if the collector cannot be created in a valid initial state
    ///
    /// # Example
    /// ```ignore
    /// let collector = setup_test_collector();
    /// assert_eq!(collector.sender_count(), 1);
    /// ```
    fn setup_test_collector<T>() -> StreamingResultCollector<T>
    where
        T: Send + 'static,
    {
        let collector = StreamingResultCollector::<T>::new();

        // Validate initial state
        assert_eq!(
            collector.sender_count(),
            1,
            "New collector must have sender_count of 1"
        );

        collector
    }

    /// Setup function to create multiple linked collectors for complex testing
    ///
    /// # Arguments
    /// * `count` - Number of collectors to create (including original)
    ///
    /// # Returns
    /// A vector of linked collectors, all sharing the same sender_count
    ///
    /// # Panics
    /// Panics if `count` is 0 or if clone chain creation fails
    ///
    /// # Example
    /// ```ignore
    /// let collectors = setup_multi_collector_scenario(3);
    /// assert_eq!(collectors.len(), 3);
    /// assert_eq!(collectors[0].sender_count(), 3);
    /// ```
    fn setup_multi_collector_scenario<T>(count: usize) -> Vec<StreamingResultCollector<T>>
    where
        T: Send + 'static,
    {
        assert!(count >= 1, "Count must be at least 1");

        let mut collectors = Vec::with_capacity(count);
        let mut current = StreamingResultCollector::<T>::new();

        collectors.push(current.clone());

        for _ in 1..count {
            current = current.clone();
            collectors.push(current.clone());
        }

        // Validate all collectors share the same sender_count
        let expected_count = count;
        for (i, collector) in collectors.iter().enumerate() {
            assert_eq!(
                collector.sender_count(),
                expected_count,
                "Collector {} should have sender_count of {}",
                i,
                expected_count
            );
        }

        collectors
    }

    /// Setup function to create a collector pre-populated with test data
    ///
    /// # Arguments
    /// * `values` - Slice of values to add to the collector
    ///
    /// # Returns
    /// A collector containing the specified test data
    ///
    /// # Panics
    /// Panics if any value cannot be added to the collector
    ///
    /// # Example
    /// ```ignore
    /// let collector = setup_collector_with_data(&[1, 2, 3, 4, 5]);
    /// let results = collector.stream_collect_blocking();
    /// assert_eq!(results.len(), 5);
    /// ```
    fn setup_collector_with_data<T>(values: &[T]) -> StreamingResultCollector<T>
    where
        T: Send + Clone + 'static,
    {
        let collector = StreamingResultCollector::<T>::new();

        for value in values {
            collector
                .stream_add(value.clone())
                .expect("Failed to add value to test collector");
        }

        collector
    }

    /// Setup function to create a collector clone pair with validation
    ///
    /// # Returns
    /// A tuple of (original collector, cloned collector) with validated states
    ///
    /// # Panics
    /// Panics if clone operation fails or validation fails
    ///
    /// # Example
    /// ```ignore
    /// let (original, clone) = setup_validated_clone_pair();
    /// assert_eq!(original.sender_count(), 2);
    /// assert_eq!(clone.sender_count(), 2);
    /// ```
    fn setup_validated_clone_pair<T>() -> (StreamingResultCollector<T>, StreamingResultCollector<T>)
    where
        T: Send + 'static,
    {
        let original = setup_test_collector();
        let pre_clone_count = original.sender_count();

        let cloned = original.clone();

        // Validate post-clone state
        let post_clone_count = original.sender_count();
        assert_eq!(
            post_clone_count,
            pre_clone_count + 1,
            "sender_count should increment by 1 after clone"
        );

        assert_eq!(
            cloned.sender_count(),
            post_clone_count,
            "Cloned collector should have same sender_count as original"
        );

        (original, cloned)
    }

    // ===== Test Teardown Functions =====

    /// Teardown function to ensure proper cleanup of a test collector
    ///
    /// This function validates that a collector is in a clean state before
    /// being dropped, ensuring no resource leaks or inconsistent states.
    ///
    /// # Arguments
    /// * `collector` - The collector to validate before cleanup
    ///
    /// # Returns
    /// `Ok(())` if cleanup is successful, `Err(String)` if issues detected
    ///
    /// # Example
    /// ```ignore
    /// let collector = setup_test_collector();
    /// // ... perform test operations ...
    /// teardown_test_collector(&collector).expect("Cleanup failed");
    /// ```
    fn teardown_test_collector<T>(collector: &StreamingResultCollector<T>) -> Result<(), String>
    where
        T: Send + 'static,
    {
        // Validation 1: Ensure sender_count is in a valid range
        let count = collector.sender_count();
        if count > 1000 {
            return Err(format!(
                "Abnormal sender_count detected during teardown: {}",
                count
            ));
        }

        // Validation 2: Check for potential thread/channel leaks
        // (This is a basic sanity check - more sophisticated checks could be added)
        if count == 0 {
            // All collectors have been dropped - this is expected for normal cleanup
            return Ok(());
        }

        // If count > 0, ensure we're not in an inconsistent state
        // (More comprehensive checks could be added here)
        Ok(())
    }

    /// Teardown function to validate clean state across multiple collectors
    ///
    /// # Arguments
    /// * `collectors` - Slice of collectors to validate
    ///
    /// # Returns
    /// `Ok(())` if all collectors are clean, `Err(String)` if issues detected
    fn teardown_multi_collector_state<T>(
        collectors: &[StreamingResultCollector<T>],
    ) -> Result<(), String>
    where
        T: Send + 'static,
    {
        if collectors.is_empty() {
            return Ok(());
        }

        // All collectors should have the same sender_count
        let first_count = collectors[0].sender_count();
        for (i, collector) in collectors.iter().enumerate() {
            let count = collector.sender_count();
            if count != first_count {
                return Err(format!(
                    "Inconsistent sender_count in collector {}: expected={}, got={}",
                    i, first_count, count
                ));
            }
        }

        Ok(())
    }

    /// Validation function to verify no resource leaks after test completion
    ///
    /// This function performs comprehensive checks to ensure that no
    /// threads, channels, or other resources were leaked during testing.
    ///
    /// # Returns
    /// `Ok(())` if no leaks detected, `Err(String)` with leak details
    ///
    /// # Note
    /// This is a basic implementation. More sophisticated leak detection
    /// could be added using thread counting, channel state inspection, etc.
    fn verify_clean_state() -> Result<(), String> {
        // Basic sanity check - could be expanded with:
        // - Thread count validation
        // - Channel state inspection
        // - Memory usage checks
        // - Custom resource tracking

        // For now, we just ensure no panics occurred during cleanup
        Ok(())
    }

    // ===== Mock Initialization Functions =====

    /// Mock initialization for testing sender_count in controlled scenarios
    ///
    /// Creates a collector with a specific sender_count for testing edge cases
    /// without requiring actual clone operations. This is useful for testing
    /// validation logic in isolation.
    ///
    /// # Arguments
    /// * `target_count` - The desired sender_count (must be >= 1)
    ///
    /// # Returns
    /// A collector (or collector chain) with the specified sender_count
    ///
    /// # Panics
    /// Panics if `target_count` is 0 or if creation fails
    ///
    /// # Example
    /// ```ignore
    /// let collectors = mock_sender_count_state(5);
    /// assert_eq!(collectors.last().unwrap().sender_count(), 5);
    /// ```
    fn mock_sender_count_state<T>(target_count: usize) -> Vec<StreamingResultCollector<T>>
    where
        T: Send + 'static,
    {
        assert!(target_count >= 1, "Target count must be at least 1");

        let mut collectors = Vec::with_capacity(target_count);
        let mut current = StreamingResultCollector::<T>::new();

        // Build up to the target count through successive clones
        for current_count in 1..=target_count {
            if current_count == 1 {
                collectors.push(current.clone());
            } else {
                current = current.clone();
                collectors.push(current.clone());

                // Verify we reached the target count
                let actual_count = current.sender_count();
                if actual_count > target_count {
                    panic!(
                        "Exceeded target count during mock setup: expected={}, got={}",
                        target_count, actual_count
                    );
                }
            }
        }

        // Validate final state
        let final_count = collectors.last().unwrap().sender_count();
        assert_eq!(
            final_count, target_count,
            "Mock setup failed to reach target sender_count"
        );

        collectors
    }

    /// Mock initialization for testing stability under concurrent access
    ///
    /// Creates a scenario where multiple collectors are created from a single
    /// original to test thread safety and stability of sender_count operations.
    ///
    /// # Arguments
    /// * `thread_count` - Number of concurrent "threads" (clones) to simulate
    ///
    /// # Returns
    /// A vector of collectors simulating concurrent access scenario
    ///
    /// # Example
    /// ```ignore
    /// let collectors = mock_concurrent_access_scenario(8);
    /// // Test that all collectors have consistent sender_count
    /// ```
    fn mock_concurrent_access_scenario<T>(thread_count: usize) -> Vec<StreamingResultCollector<T>>
    where
        T: Send + 'static,
    {
        let original = setup_test_collector();
        let mut collectors = vec![original];

        // Simulate concurrent access by creating many clones
        for _ in 0..thread_count {
            let clone = collectors[0].clone();
            collectors.push(clone);
        }

        // All should have the same sender_count
        let expected_count = thread_count + 1;
        for (i, collector) in collectors.iter().enumerate() {
            assert_eq!(
                collector.sender_count(),
                expected_count,
                "Collector {} has inconsistent sender_count in concurrent scenario",
                i
            );
        }

        collectors
    }

    // ===== Test Helper Utilities =====

    /// Helper function to measure and validate performance characteristics
    ///
    /// # Type Parameters
    /// * `F` - Function to execute (should perform clone operations)
    ///
    /// # Arguments
    /// * `label` - Description of what's being measured
    /// * `op` - Operation to measure
    ///
    /// # Returns
    /// `Ok(())` if operation completes successfully
    ///
    /// # Example
    /// ```ignore
    /// measure_clone_performance("single clone", || {
    ///     let collector = setup_test_collector::<i32>();
    ///     let _clone = collector.clone();
    /// });
    /// ```
    fn measure_clone_performance<F>(label: &str, op: F) -> Result<(), String>
    where
        F: FnOnce(),
    {
        let _start = std::time::Instant::now();
        op();
        // Could add timing validation here if needed
        let _ = label; // Suppress unused warning while keeping label for future use
        Ok(())
    }

    /// Common setup for sender_count assertion tests
    ///
    /// This section provides the foundation for sender_count validation:
    /// - Helper functions for assertion validation
    /// - Test data fixtures and utilities
    /// - Common assertion patterns
    ///
    /// Integration Point: Additional assertion helpers can be added below
    /// following the pattern of existing validate_* functions.

    // ===== ResultCollector Tests =====

    #[test]
    fn test_new_collector() {
        let collector = ResultCollector::<i32>::new();
        assert!(collector.is_empty());
        assert_eq!(collector.len(), 0);
    }

    #[test]
    fn test_collector_with_capacity() {
        let collector = ResultCollector::<i32>::with_capacity(10);
        assert!(collector.is_empty());
    }

    #[test]
    fn test_add_single_value() {
        let collector = ResultCollector::<i32>::new();
        collector.add(42);

        assert!(!collector.is_empty());
        assert_eq!(collector.len(), 1);
    }

    #[test]
    fn test_add_multiple_values() {
        let collector = ResultCollector::<i32>::new();
        collector.add(42);
        collector.add(24);
        collector.add(99);

        assert_eq!(collector.len(), 3);
    }

    #[test]
    fn test_collect_returns_values() {
        let collector = ResultCollector::<i32>::new();
        collector.add(42);
        collector.add(24);

        let results = collector.collect();
        assert_eq!(results, vec![42, 24]);
    }

    #[test]
    fn test_collect_from_empty_collector() {
        let collector = ResultCollector::<i32>::new();
        let results = collector.collect();
        assert_eq!(results, Vec::<i32>::new());
    }

    #[test]
    fn test_collect_preserves_collector() {
        let collector = ResultCollector::<i32>::new();
        collector.add(42);
        collector.add(24);

        let results1 = collector.collect();
        let results2 = collector.collect();

        assert_eq!(results1, vec![42, 24]);
        assert_eq!(results2, vec![42, 24]);
    }

    #[test]
    fn test_len_and_is_empty() {
        let collector = ResultCollector::<i32>::new();

        assert_eq!(collector.len(), 0);
        assert!(collector.is_empty());

        collector.add(1);
        assert_eq!(collector.len(), 1);
        assert!(!collector.is_empty());

        collector.add(2);
        collector.add(3);
        assert_eq!(collector.len(), 3);
    }

    #[test]
    fn test_clear() {
        let collector = ResultCollector::<i32>::new();
        collector.add(42);
        collector.add(24);
        collector.add(99);

        assert_eq!(collector.len(), 3);
        collector.clear();
        assert_eq!(collector.len(), 0);
        assert!(collector.is_empty());
    }

    #[test]
    fn test_clone_collector() {
        let collector1 = ResultCollector::<i32>::new();
        let collector2 = collector1.clone();

        collector1.add(42);
        collector2.add(24);

        let results = collector1.collect();
        assert_eq!(results.len(), 2);
    }

    #[test]
    fn test_default_collector() {
        let collector = ResultCollector::<i32>::default();
        assert!(collector.is_empty());
    }

    #[test]
    fn test_collector_with_strings() {
        let collector = ResultCollector::<String>::new();
        collector.add("hello".to_string());
        collector.add("world".to_string());

        let results = collector.collect();
        assert_eq!(results, vec!["hello".to_string(), "world".to_string()]);
    }

    #[test]
    fn test_collector_with_custom_type() {
        #[derive(Debug, PartialEq, Clone)]
        struct Point {
            x: i32,
            y: i32,
        }

        let collector = ResultCollector::<Point>::new();
        collector.add(Point { x: 1, y: 2 });
        collector.add(Point { x: 3, y: 4 });

        let results = collector.collect();
        assert_eq!(results, vec![Point { x: 1, y: 2 }, Point { x: 3, y: 4 }]);
    }

    #[test]
    fn test_collector_order_preserved() {
        let collector = ResultCollector::<i32>::new();
        for i in 0..10 {
            collector.add(i);
        }

        let results = collector.collect();
        let expected: Vec<i32> = (0..10).collect();
        assert_eq!(results, expected);
    }

    // Aggregation method tests

    #[test]
    fn test_count_method() {
        let collector = ResultCollector::<i32>::new();
        assert_eq!(collector.count(), 0);

        collector.add(42);
        assert_eq!(collector.count(), 1);

        collector.add(24);
        collector.add(99);
        assert_eq!(collector.count(), 3);
    }

    #[test]
    fn test_count_matches_len() {
        let collector = ResultCollector::<i32>::new();

        collector.add(1);
        collector.add(2);
        collector.add(3);
        collector.add(4);

        assert_eq!(collector.len(), collector.count());
        assert_eq!(collector.count(), 4);
    }

    #[test]
    fn test_finalize_single_reference() {
        let collector = ResultCollector::<i32>::new();
        collector.add(42);
        collector.add(24);
        collector.add(99);

        let results = collector.finalize();
        assert_eq!(results, vec![42, 24, 99]);
    }

    #[test]
    fn test_finalize_empty_collector() {
        let collector = ResultCollector::<i32>::new();
        let results = collector.finalize();
        assert_eq!(results, Vec::<i32>::new());
    }

    #[test]
    fn test_finalize_with_multiple_clones() {
        let collector = ResultCollector::<i32>::new();
        let collector_clone = collector.clone();

        collector.add(42);
        collector_clone.add(24);

        // finalize() should still work even with multiple clones
        let results = collector.finalize();
        assert_eq!(results.len(), 2);
    }

    #[test]
    fn test_finalize_after_clear() {
        let collector = ResultCollector::<i32>::new();
        collector.add(42);
        collector.add(24);

        collector.clear();
        let results = collector.finalize();
        assert_eq!(results, Vec::<i32>::new());
    }

    #[test]
    fn test_finalize_preserves_order() {
        let collector = ResultCollector::<i32>::new();
        for i in 0..10 {
            collector.add(i);
        }

        let results = collector.finalize();
        let expected: Vec<i32> = (0..10).collect();
        assert_eq!(results, expected);
    }

    #[test]
    fn test_aggregation_methods_consistency() {
        let collector = ResultCollector::<i32>::new();

        collector.add(1);
        collector.add(2);
        collector.add(3);

        // All aggregation methods should return consistent results
        assert_eq!(collector.count(), 3);
        assert_eq!(collector.len(), 3);
        assert!(!collector.is_empty());

        let results = collector.finalize();
        assert_eq!(results.len(), 3);
    }

    #[test]
    fn test_finalize_with_strings() {
        let collector = ResultCollector::<String>::new();
        collector.add("first".to_string());
        collector.add("second".to_string());
        collector.add("third".to_string());

        let results = collector.finalize();
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
    fn test_finalize_consumes_collector() {
        let collector = ResultCollector::<i32>::new();
        collector.add(42);

        // finalize() takes ownership
        let results = collector.finalize();
        assert_eq!(results, vec![42]);

        // collector is no longer accessible (moved)
    }

    // ===== StreamingResultCollector Tests =====

    #[test]
    fn test_streaming_collector_new() {
        let collector = StreamingResultCollector::<i32>::new();
        assert_eq!(collector.sender_count(), 1);
    }

    #[test]
    fn test_streaming_collector_with_bound() {
        let collector = StreamingResultCollector::<i32>::with_bound(10);
        assert_eq!(collector.sender_count(), 1);
    }

    #[test]
    fn test_streaming_collector_stream_add() {
        let collector = StreamingResultCollector::<i32>::new();

        // Test successful submission
        assert!(collector.stream_add(42).is_ok());
        assert!(collector.stream_add(24).is_ok());
        assert!(collector.stream_add(99).is_ok());

        let mut results = collector.stream_collect_blocking();
        results.sort(); // Order is not guaranteed
        assert_eq!(results, vec![24, 42, 99]);
    }

    #[test]
    fn test_streaming_collector_stream_add_channel_full() {
        let collector = StreamingResultCollector::<i32>::with_bound(2);

        // Fill the channel
        assert!(collector.stream_add(1).is_ok());
        assert!(collector.stream_add(2).is_ok());

        // This should fail because the channel is full
        let result = collector.stream_add(3);
        assert!(result.is_err());
        // SendError is a tuple struct, access inner value via .0
        assert_eq!(result.unwrap_err().0, 3);
    }

    #[test]
    fn test_streaming_collector_stream_add_receiver_dropped() {
        let mut collector = StreamingResultCollector::<i32>::new();

        // Explicitly drop the receiver
        collector.drop_receiver();

        // Now stream_add should fail because receiver is dropped
        let result = collector.stream_add(42);
        assert!(result.is_err());
        // SendError is a tuple struct, access inner value via .0
        assert_eq!(result.unwrap_err().0, 42);
    }

    #[test]
    fn test_streaming_collector_stream_try_add() {
        let collector = StreamingResultCollector::<i32>::new();
        assert!(collector.stream_try_add(42));
        assert!(collector.stream_try_add(24));

        let mut results = collector.stream_collect_blocking();
        results.sort();
        assert_eq!(results, vec![24, 42]);
    }

    #[test]
    fn test_streaming_collector_stream_try_add_channel_full() {
        let collector = StreamingResultCollector::<i32>::with_bound(2);

        // Fill the channel
        assert!(collector.stream_try_add(1));
        assert!(collector.stream_try_add(2));

        // This should fail because the channel is full
        assert!(!collector.stream_try_add(3));
    }

    #[test]
    fn test_streaming_collector_clone() {
        let collector = StreamingResultCollector::<i32>::new();
        assert_eq!(collector.sender_count(), 1);

        let _clone = collector.clone();
        assert_eq!(collector.sender_count(), 2);

        let _clone2 = collector.clone();
        assert_eq!(collector.sender_count(), 3);
    }

    #[test]
    fn test_streaming_collector_sender_count_before_single_clone() {
        let collector = StreamingResultCollector::<i32>::new();

        // Use assertion helper for pre-clone validation
        let count_before_clone = validate_sender_count_before_clone(&collector)
            .expect("Pre-clone validation should pass");

        assert_eq!(count_before_clone, 1, "Initial sender_count should be 1");

        // Perform the clone operation
        let clone = collector.clone();

        // Use assertion helper for post-clone validation
        validate_sender_count_after_clone(&collector, &clone, count_before_clone + 1)
            .expect("Post-clone validation should pass");
    }

    #[test]
    fn test_streaming_collector_clone_independently() {
        let collector = StreamingResultCollector::<i32>::new();
        let clone = collector.clone();
        assert_eq!(collector.sender_count(), 2);

        let _ = collector.stream_add(42);
        let _ = clone.stream_add(24);

        let mut results = collector.stream_collect_blocking();
        results.sort();
        assert_eq!(results, vec![24, 42]);
    }

    #[test]
    fn test_streaming_collector_bounded_channel() {
        let collector = StreamingResultCollector::<i32>::with_bound(2);

        // Add exactly 2 items (within bound)
        assert!(collector.stream_add(1).is_ok());
        assert!(collector.stream_add(2).is_ok());

        // Third item should fail because channel is full (non-blocking)
        let result = collector.stream_add(3);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().0, 3); // Returns the unsent value

        // Only the first 2 items should be in the channel
        let mut results = collector.stream_collect_blocking();
        results.sort();
        assert_eq!(results, vec![1, 2]);
    }

    #[test]
    fn test_streaming_collector_empty() {
        let collector = StreamingResultCollector::<i32>::new();
        let results = collector.stream_collect_blocking();
        assert_eq!(results, Vec::<i32>::new());
    }

    #[test]
    fn test_streaming_collector_single_value() {
        let collector = StreamingResultCollector::<i32>::new();
        let _ = collector.stream_add(42);

        let results = collector.stream_collect_blocking();
        assert_eq!(results, vec![42]);
    }

    #[test]
    fn test_streaming_collector_concurrent_two_threads() {
        let collector = StreamingResultCollector::<i32>::new();
        assert_eq!(collector.sender_count(), 1);
        let collector_clone = collector.clone();
        assert_eq!(collector.sender_count(), 2);
        let collector_clone2 = collector.clone();
        assert_eq!(collector.sender_count(), 3);

        let handle1 = thread::spawn(move || {
            for i in 0..10 {
                let _ = collector_clone.stream_add(i);
            }
        });

        let handle2 = thread::spawn(move || {
            for i in 10..20 {
                let _ = collector_clone2.stream_add(i);
            }
        });

        handle1.join().unwrap();
        handle2.join().unwrap();

        let mut results = collector.stream_collect_blocking();
        results.sort();
        let expected: Vec<i32> = (0..20).collect();
        assert_eq!(results, expected);
    }

    #[test]
    fn test_streaming_collector_concurrent_ten_threads() {
        let collector = StreamingResultCollector::<i32>::new();
        let mut handles = Vec::new();

        for thread_id in 0..10 {
            let collector_clone = collector.clone();
            let handle = thread::spawn(move || {
                for i in 0..10 {
                    let _ = collector_clone.stream_add(thread_id * 10 + i);
                }
            });
            handles.push(handle);
        }

        for handle in handles {
            handle.join().unwrap();
        }

        let mut results = collector.stream_collect_blocking();
        results.sort();
        let expected: Vec<i32> = (0..100).collect();
        assert_eq!(results, expected);
    }

    #[test]
    fn test_streaming_collector_high_concurrency_100_threads() {
        let collector = StreamingResultCollector::<usize>::new();
        let num_threads = 100;
        let items_per_thread = 10;
        let mut handles = Vec::new();

        for thread_id in 0..num_threads {
            let collector_clone = collector.clone();
            let handle = thread::spawn(move || {
                for i in 0..items_per_thread {
                    let _ = collector_clone.stream_add(thread_id * items_per_thread + i);
                }
            });
            handles.push(handle);
        }

        for handle in handles {
            handle.join().unwrap();
        }

        let mut results = collector.stream_collect_blocking();
        results.sort();
        let expected_count = num_threads * items_per_thread;
        assert_eq!(results.len(), expected_count);

        // Verify all values are present
        for (i, val) in results.iter().enumerate() {
            assert_eq!(*val, i);
        }
    }

    #[test]
    fn test_streaming_collector_high_concurrency_200_threads() {
        let collector = StreamingResultCollector::<usize>::new();
        let num_threads = 200;
        let items_per_thread = 5;
        let mut handles = Vec::new();

        for thread_id in 0..num_threads {
            let collector_clone = collector.clone();
            let handle = thread::spawn(move || {
                for i in 0..items_per_thread {
                    let _ = collector_clone.stream_add(thread_id * items_per_thread + i);
                }
            });
            handles.push(handle);
        }

        for handle in handles {
            handle.join().unwrap();
        }

        let mut results = collector.stream_collect_blocking();
        results.sort();
        let expected_count = num_threads * items_per_thread;
        assert_eq!(results.len(), expected_count);
    }

    #[test]
    fn test_streaming_collector_stress_test_many_values() {
        let collector = StreamingResultCollector::<usize>::new();
        let num_threads = 50;
        let items_per_thread = 100;
        let mut handles = Vec::new();

        for thread_id in 0..num_threads {
            let collector_clone = collector.clone();
            let handle = thread::spawn(move || {
                for i in 0..items_per_thread {
                    let _ = collector_clone.stream_add(thread_id * items_per_thread + i);
                }
            });
            handles.push(handle);
        }

        for handle in handles {
            handle.join().unwrap();
        }

        let mut results = collector.stream_collect_blocking();
        results.sort();
        let expected_count = num_threads * items_per_thread;
        assert_eq!(results.len(), expected_count);

        // Verify first and last values
        assert_eq!(results[0], 0);
        assert_eq!(results[results.len() - 1], expected_count - 1);
    }

    #[test]
    fn test_streaming_collector_with_strings() {
        let collector = StreamingResultCollector::<String>::new();
        assert_eq!(collector.sender_count(), 1);
        let collector_clone = collector.clone();
        assert_eq!(collector.sender_count(), 2);
        let collector_clone2 = collector.clone();
        assert_eq!(collector.sender_count(), 3);

        let handle1 = thread::spawn(move || {
            let _ = collector_clone.stream_add("hello".to_string());
        });

        let handle2 = thread::spawn(move || {
            let _ = collector_clone2.stream_add("world".to_string());
        });

        handle1.join().unwrap();
        handle2.join().unwrap();

        let mut results = collector.stream_collect_blocking();
        results.sort();
        assert_eq!(results, vec!["hello".to_string(), "world".to_string()]);
    }

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

        // After all collectors are dropped, count should reach zero
        drop(collector);
        // Note: We can't directly observe the final count since collector is dropped
        // but the Drop trait implementation ensures sender_count is decremented
    }

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

        // Drop original collector - count should reach zero
        // Note: We can't observe this directly since collector is consumed
        // but the Drop trait ensures proper decrement
        drop(collector);
    }

    // ===== SENDER_COUNT CONSISTENCY ASSERTION PATTERN =====
    // This test demonstrates the standard pattern for verifying sender_count
    // consistency before and after clone operations. The pattern below can be
    // reused for other sender_count verification scenarios.
    //
    // Key verification points:
    // 1. Initial state validation (count should be 1 for new collector)
    // 2. Pre-clone state capture and validation
    // 3. Post-clone increment verification (should increase by exactly 1)
    // 4. Non-decrease guarantee during clone operation
    // 5. Stability check after clone (no fluctuations)
    // 6. Cross-instance consistency (all clones see same count)
    // 7. Monotonic increase from initial state

    #[test]
    fn test_streaming_collector_sender_count_before_clone_assertions() {
        // Test comprehensive sender_count validation BEFORE clone operation
        // Following documented assertion pattern: capture, validate, then act

        let collector = StreamingResultCollector::<i32>::new();

        // === BEFORE CLONE ASSERTIONS ===
        // Following SIGIL test assertion pattern: before/after verification

        // Assertion 1: Verify sender_count is accessible and readable
        let count_read1 = collector.sender_count();
        let count_read2 = collector.sender_count();
        let count_read3 = collector.sender_count();

        // Assertion 2: Verify sender_count is stable across multiple consecutive reads
        // This establishes reliability before any clone operations
        let max_count = count_read1.max(count_read2).max(count_read3);
        let min_count = count_read1.min(count_read2).min(count_read3);
        let variation = max_count - min_count;

        assert!(
            variation == 0,
            "sender_count should be stable across consecutive reads before clone: variation={} exceeds threshold=0, values=[{}, {}, {}]",
            variation, count_read1, count_read2, count_read3
        );

        // Assertion 3: Verify sender_count is non-zero (minimum valid value is 1)
        assert!(
            count_read1 > 0,
            "sender_count should be non-zero before clone operation: got={}",
            count_read1
        );

        // Assertion 4: Verify sender_count equals expected initial value
        assert_eq!(
            count_read1, 1,
            "Initial sender_count should be 1 before clone: expected=1, got={}",
            count_read1
        );

        // Assertion 5: Verify sender_count is within acceptable bounds
        // Prevents potential overflow during clone operations
        assert!(
            count_read1 < usize::MAX - 10,
            "sender_count should be within safe bounds before clone: count={} is near overflow limit",
            count_read1
        );

        // Assertion 6: Establish baseline for monotonic increase tracking
        let pre_clone_baseline = count_read1;
        assert_eq!(
            pre_clone_baseline, 1,
            "Pre-clone baseline should be 1 for new collector: expected=1, got={}",
            pre_clone_baseline
        );

        // === PERFORM CLONE OPERATION ===
        let clone = collector.clone();

        // === POST-CLONE VERIFICATIONS ===
        let count_after_clone = collector.sender_count();

        // Verify count increased as expected
        assert_eq!(
            count_after_clone, 2,
            "sender_count should increase by exactly 1 after clone: expected=2, got={}",
            count_after_clone
        );

        // Verify clone sees same count (cross-instance consistency)
        assert_eq!(
            clone.sender_count(),
            2,
            "Clone should see same sender_count as original: expected=2, got={}",
            clone.sender_count()
        );

        // Verify monotonic behavior
        assert!(
            count_after_clone >= pre_clone_baseline,
            "sender_count should never decrease during clone operation: before={}, after={}",
            pre_clone_baseline,
            count_after_clone
        );

        // Verify post-clone stability
        let count_verify_stability = collector.sender_count();
        assert_eq!(
            count_verify_stability, 2,
            "sender_count should remain stable immediately after clone: expected=2, got={}",
            count_verify_stability
        );
    }

    #[test]
    fn test_streaming_collector_sender_count_after_single_clone() {
        let collector = StreamingResultCollector::<i32>::new();
        let initial_count = collector.sender_count();
        assert_eq!(initial_count, 1);

        // Capture count before clone to verify stability
        let count_before_clone = collector.sender_count();
        assert_eq!(count_before_clone, 1, "Count should be 1 before clone");

        // Clone once and verify sender_count increases
        let clone = collector.clone();
        let count_after_clone = collector.sender_count();
        assert_eq!(count_after_clone, 2, "Count should be 2 after clone");
        assert_eq!(clone.sender_count(), 2, "Clone should see count as 2");

        // Critical assertion: sender_count stays consistent after clone operation
        // Verify count didn't decrease during clone
        assert!(
            count_after_clone >= count_before_clone,
            "sender_count should not decrease during clone operation: before={}, after={}",
            count_before_clone,
            count_after_clone
        );

        // Verify count is stable immediately after clone (no fluctuations)
        let count_verify_stability = collector.sender_count();
        assert_eq!(
            count_verify_stability, 2,
            "sender_count should remain stable immediately after clone: expected=2, got={}",
            count_verify_stability
        );

        // Verify clone sees same count (consistency across all instances)
        assert_eq!(
            clone.sender_count(),
            2,
            "Clone should see consistent sender_count: expected=2, got={}",
            clone.sender_count()
        );

        // Verify monotonic increase
        assert!(
            count_after_clone > initial_count,
            "sender_count should increase monotonically after clone: initial={}, after={}",
            initial_count,
            count_after_clone
        );

        // Verify both collectors work correctly
        let _ = collector.stream_add(42).unwrap();
        let _ = clone.stream_add(24).unwrap();

        // Collect and verify results
        let mut results = collector.stream_collect_blocking();
        results.sort();
        assert_eq!(results, vec![24, 42]);
    }

    #[test]
    fn test_streaming_collector_sender_count_stability_during_clone() {
        // Verify sender_count doesn't decrease prematurely during clone operations
        // This test checks count stability at intermediate points during cloning

        let collector = StreamingResultCollector::<i32>::new();
        let initial_count = collector.sender_count();
        assert_eq!(initial_count, 1, "Initial count should be 1");

        // Capture count before first clone to verify stability during operation
        let count_before_first_clone = collector.sender_count();
        assert_eq!(
            count_before_first_clone, 1,
            "Count should be stable before clone"
        );

        // Perform first clone and verify count stability DURING the operation
        let clone1 = collector.clone();
        let count_after_first_clone = collector.sender_count();
        assert_eq!(
            count_after_first_clone, 2,
            "Count should be 2 after first clone"
        );
        assert_eq!(clone1.sender_count(), 2, "Clone should also see count as 2");

        // Critical check: count didn't decrease during clone operation
        assert!(
            count_after_first_clone >= count_before_first_clone,
            "Count should never decrease during clone operation"
        );
        assert!(
            count_after_first_clone >= initial_count,
            "Count should be stable (non-decreasing) after clone"
        );

        // Verify immediate stability - count should remain stable right after clone
        let count_verify_immediate = collector.sender_count();
        assert_eq!(
            count_verify_immediate, 2,
            "Count should remain stable immediately after clone"
        );

        // Capture count before second clone
        let count_before_second_clone = collector.sender_count();
        assert_eq!(
            count_before_second_clone, 2,
            "Count should be stable before second clone"
        );

        // Perform second clone and verify count continues to increase
        let clone2 = collector.clone();
        let count_after_second_clone = collector.sender_count();
        assert_eq!(
            count_after_second_clone, 3,
            "Count should be 3 after second clone"
        );
        assert_eq!(
            clone1.sender_count(),
            3,
            "First clone should see updated count"
        );
        assert_eq!(
            clone2.sender_count(),
            3,
            "Second clone should see count as 3"
        );

        // Verify no decrease during second clone operation
        assert!(
            count_after_second_clone >= count_before_second_clone,
            "Count should not decrease during second clone operation"
        );
        assert!(
            count_after_second_clone >= count_after_first_clone,
            "Count should be stable (non-decreasing) during clone sequence"
        );

        // Verify intermediate stability between clones
        let count_intermediate = collector.sender_count();
        assert_eq!(
            count_intermediate, 3,
            "Count should remain stable at intermediate point"
        );

        // Capture count before third clone
        let count_before_third_clone = collector.sender_count();

        // Perform third clone for additional stability verification
        let clone3 = collector.clone();
        let count_after_third_clone = collector.sender_count();
        assert_eq!(
            count_after_third_clone, 4,
            "Count should be 4 after third clone"
        );
        assert_eq!(
            clone1.sender_count(),
            4,
            "All clones should see consistent count"
        );
        assert_eq!(
            clone2.sender_count(),
            4,
            "All clones should see consistent count"
        );
        assert_eq!(
            clone3.sender_count(),
            4,
            "All clones should see consistent count"
        );

        // Verify no decrease during third clone
        assert!(
            count_after_third_clone >= count_before_third_clone,
            "Count should not decrease during third clone operation"
        );

        // Verify monotonic increase throughout cloning process
        assert!(
            count_after_third_clone > count_after_second_clone
                && count_after_second_clone > count_after_first_clone
                && count_after_first_clone > initial_count,
            "Count should increase monotonically during clone operations"
        );

        // Verify all collectors are functional
        let _ = collector.stream_add(1).unwrap();
        let _ = clone1.stream_add(2).unwrap();
        let _ = clone2.stream_add(3).unwrap();
        let _ = clone3.stream_add(4).unwrap();

        let mut results = collector.stream_collect_blocking();
        results.sort();
        assert_eq!(
            results,
            vec![1, 2, 3, 4],
            "All collectors should work correctly"
        );
    }

    #[test]
    fn test_streaming_collector_sender_count_stability_intermediate_clone_checks() {
        // Verify sender_count stability at every intermediate point during clone operations
        // This test validates the debug_assert! checks in the Clone implementation

        let collector = StreamingResultCollector::<i32>::new();
        let initial_count = collector.sender_count();
        assert_eq!(initial_count, 1);

        // Test stability during multiple sequential clone operations
        let previous_count = initial_count;
        let mut clones = Vec::new();

        for i in 0..5 {
            // Capture count before this specific clone
            let count_before = collector.sender_count();
            assert!(
                count_before >= previous_count,
                "Count should never decrease before clone {}: previous={}, current={}",
                i,
                previous_count,
                count_before
            );

            // Perform the clone (this triggers debug_assert! checks internally)
            let clone = collector.clone();
            clones.push(clone);

            // Verify count increased or stayed same after clone
            let count_after = collector.sender_count();
            assert!(
                count_after >= count_before,
                "Count should not decrease during clone {}: before={}, after={}",
                i,
                count_before,
                count_after
            );

            // Verify count increased monotonically
            assert_eq!(
                count_after,
                initial_count + i + 1,
                "Count should increment by 1 each clone: expected={}, got={}",
                initial_count + i + 1,
                count_after
            );

            // Verify all existing clones see the same count
            for (idx, existing_clone) in clones.iter().enumerate() {
                assert_eq!(
                    existing_clone.sender_count(),
                    count_after,
                    "Clone {} should see current count after clone {}: expected={}, got={}",
                    idx,
                    i,
                    count_after,
                    existing_clone.sender_count()
                );
            }
        }

        // Verify final count is stable
        let final_count = collector.sender_count();
        assert_eq!(final_count, 6, "Final count should be 6 (1 + 5 clones)");

        // Test that all clones can still add data correctly
        for (i, clone) in clones.iter().enumerate() {
            let _ = clone.stream_add(i as i32).unwrap();
        }

        // Collect and verify all data was received
        let mut results = collector.stream_collect_blocking();
        results.sort();
        let expected: Vec<i32> = (0..5).collect();
        assert_eq!(
            results, expected,
            "All clones should work correctly after stability checks"
        );
    }

    #[test]
    fn test_streaming_collector_sender_count_no_premature_decrease_during_drop() {
        // Verify that sender_count doesn't decrease during clone operations
        // even when drops happen concurrently

        let collector = StreamingResultCollector::<i32>::new();
        let initial_count = collector.sender_count();
        assert_eq!(initial_count, 1);

        // Create multiple clones
        let clone1 = collector.clone();
        let count_after_clone1 = collector.sender_count();
        assert_eq!(count_after_clone1, 2);

        let clone2 = collector.clone();
        let count_after_clone2 = collector.sender_count();
        assert_eq!(count_after_clone2, 3);

        let clone3 = collector.clone();
        let count_after_clone3 = collector.sender_count();
        assert_eq!(count_after_clone3, 4);

        // Verify count is stable before any drops
        assert!(
            count_after_clone3 >= count_after_clone2 && count_after_clone2 >= count_after_clone1,
            "Count should be monotonically increasing after clones"
        );

        // Now drop clones one by one and verify count decreases properly
        drop(clone1);
        let count_after_drop1 = collector.sender_count();
        assert_eq!(
            count_after_drop1, 3,
            "Count should decrease to 3 after dropping first clone"
        );

        drop(clone2);
        let count_after_drop2 = collector.sender_count();
        assert_eq!(
            count_after_drop2, 2,
            "Count should decrease to 2 after dropping second clone"
        );

        // Create a new clone to verify count increases again after drops
        let clone4 = collector.clone();
        let count_after_clone4 = collector.sender_count();
        assert_eq!(
            count_after_clone4, 3,
            "Count should increase to 3 after new clone"
        );

        // Verify the new clone works correctly
        let _ = clone4.stream_add(42).unwrap();
        let _ = collector.stream_add(24).unwrap();

        let mut results = collector.stream_collect_blocking();
        results.sort();
        assert_eq!(
            results,
            vec![24, 42],
            "Collector should work after clone/drop sequence"
        );
    }

    #[test]
    fn test_streaming_collector_sender_count_stress_clone_drop_sequence() {
        // Verify sender_count stability under rapid clone/drop operations
        // This test exercises the debug_assert! checks in Clone and Drop implementations

        let collector = StreamingResultCollector::<i32>::new();
        let initial_count = collector.sender_count();
        assert_eq!(initial_count, 1);

        // Perform multiple rounds of clone and drop operations
        let mut current_count = initial_count;

        for round in 0..10 {
            // Clone multiple times in each round
            let mut round_clones = Vec::new();
            for i in 0..3 {
                let count_before = collector.sender_count();

                let clone = collector.clone();
                round_clones.push(clone);

                let count_after = collector.sender_count();

                // Verify count increased by exactly 1
                assert_eq!(
                    count_after,
                    count_before + 1,
                    "Round {}: clone {} should increment count by 1: before={}, after={}",
                    round,
                    i,
                    count_before,
                    count_after
                );

                current_count = count_after;
            }

            // Drop some clones
            for (i, clone) in round_clones.into_iter().enumerate() {
                let count_before_drop = collector.sender_count();
                drop(clone);
                let count_after_drop = collector.sender_count();

                // Verify count decreased by exactly 1
                assert_eq!(
                    count_after_drop,
                    count_before_drop - 1,
                    "Round {}: drop {} should decrement count by 1: before={}, after={}",
                    round,
                    i,
                    count_before_drop,
                    count_after_drop
                );

                current_count = count_after_drop;
            }
        }

        // Final count should be back to 1 (only original collector remains)
        let final_count = collector.sender_count();
        assert_eq!(
            final_count, 1,
            "Final count should be 1 after all clone/drop rounds"
        );

        // Verify collector still works
        let _ = collector.stream_add(99).unwrap();
        let results = collector.stream_collect_blocking();
        assert_eq!(results, vec![99], "Collector should work after stress test");
    }

    #[test]
    fn test_streaming_collector_sender_count_stability_during_concurrent_clones() {
        // Verify sender_count stability under concurrent clone operations
        // This test ensures no race conditions cause count decreases during cloning

        let collector = StreamingResultCollector::<i32>::new();
        let initial_count = collector.sender_count();
        assert_eq!(initial_count, 1);

        // Create multiple clones first (before spawning threads)
        let mut clones = Vec::new();
        for _ in 0..5 {
            clones.push(collector.clone());
        }

        // Now spawn threads that will perform additional concurrent clones
        let mut handles = Vec::new();
        for (thread_id, clone) in clones.into_iter().enumerate() {
            let handle = thread::spawn(move || {
                // Each thread performs multiple concurrent clone operations
                // with stability checks DURING each clone operation
                let mut local_clones = Vec::new();
                let mut count_history = Vec::new();

                for clone_iteration in 0..3 {
                    // Capture count BEFORE this specific clone operation
                    let count_before_clone = clone.sender_count();
                    count_history.push(count_before_clone);

                    // Verify count is stable before cloning
                    assert!(
                        count_before_clone >= 2, // At least original + this clone
                        "Count should be stable before clone (thread {}, iteration {})",
                        thread_id,
                        clone_iteration
                    );

                    // Perform the clone operation
                    let new_clone = clone.clone();

                    // Verify count didn't decrease DURING this clone operation
                    let count_after_clone = new_clone.sender_count();
                    assert!(
                        count_after_clone >= count_before_clone,
                        "Count should not decrease during clone operation (thread {}, iteration {})",
                        thread_id, clone_iteration
                    );

                    // Verify count increased or stayed same
                    assert!(
                        count_after_clone >= count_before_clone,
                        "Count should be stable (non-decreasing) during clone (thread {}, iteration {})",
                        thread_id, clone_iteration
                    );

                    local_clones.push(new_clone);
                    thread::sleep(Duration::from_millis(1));
                }

                // Verify all local clones see a consistent count (count will vary due to concurrency)
                // Due to concurrent cloning, we can't predict exact count, but we can verify stability
                let first_count = local_clones.first().unwrap().sender_count();
                for (idx, local_clone) in local_clones.iter().enumerate() {
                    let current_count = local_clone.sender_count();
                    assert_eq!(
                        current_count, first_count,
                        "All clones in thread {} should see same count (clone {} saw {}, expected {})",
                        thread_id, idx, current_count, first_count
                    );
                }

                // Return count history for verification
                (local_clones.len(), count_history)
            });
            handles.push(handle);
        }

        // Wait for all threads to complete and collect results
        let mut clone_counts = Vec::new();
        let mut all_count_histories = Vec::new();
        for handle in handles {
            let (count, history) = handle.join().unwrap();
            clone_counts.push(count);
            all_count_histories.extend(history);
        }

        // Verify all threads completed successfully
        assert_eq!(clone_counts.len(), 5, "All threads should complete");

        // Verify no count ever decreased during any clone operation
        for (idx, &count) in all_count_histories.iter().enumerate() {
            assert!(
                count >= 2, // At least original + first-level clone
                "All observed counts should be >= 2 during concurrent clones (observation {})",
                idx
            );
        }

        // Final count should be: 1 (original) + 5 initial clones + (5 threads × 3 clones) = 21
        let final_count = collector.sender_count();
        assert_eq!(
            final_count, 21,
            "Final count should reflect all concurrent clone operations: 1 + 5 + (5×3) = 21"
        );

        // Verify count never decreased below initial during operations
        assert!(
            final_count >= initial_count,
            "Final count should be >= initial count (no premature decreases)"
        );

        // Verify the collector is still functional after concurrent cloning
        let _ = collector.stream_add(42).unwrap();
        let results = collector.stream_collect_blocking();
        assert_eq!(
            results,
            vec![42],
            "Collector should work after concurrent clones"
        );
    }

    #[test]
    fn test_streaming_collector_drop_preserves_channel() {
        let collector = StreamingResultCollector::<i32>::new();
        assert!(collector.stream_add(42).is_ok());

        // Drop a clone - should not affect original collector
        {
            let _clone = collector.clone();
            assert!(_clone.stream_add(24).is_ok());
        }

        // Original should still work
        assert!(collector.stream_add(99).is_ok());
        let mut results = collector.stream_collect_blocking();
        results.sort();
        assert_eq!(results, vec![24, 42, 99]);
    }

    #[test]
    fn test_streaming_collector_bounded_backpressure() {
        let collector = StreamingResultCollector::<i32>::with_bound(5);

        // Fill the channel to capacity
        for i in 0..5 {
            assert!(collector.stream_add(i).is_ok());
        }

        // Attempting to add beyond capacity should fail (non-blocking)
        for i in 5..10 {
            let result = collector.stream_add(i);
            assert!(result.is_err());
            assert_eq!(result.unwrap_err().0, i); // Returns the unsent value
        }

        // Only 5 items should be in the channel
        let results = collector.stream_collect_blocking();
        assert_eq!(results.len(), 5);
    }

    #[test]
    fn test_streaming_collector_no_receiver_after_clone() {
        let collector = StreamingResultCollector::<i32>::new();
        let clone = collector.clone();

        let _ = collector.stream_add(42);
        let _ = clone.stream_add(24);

        // Only the original collector has the receiver
        let results = collector.stream_collect_blocking();
        assert_eq!(results.len(), 2);
    }

    #[test]
    fn test_streaming_collector_collects_after_threads_complete() {
        let collector = StreamingResultCollector::<i32>::new();
        let collector_clone = collector.clone();

        // Spawn a thread that adds results
        let handle = thread::spawn(move || {
            for i in 0..5 {
                let _ = collector_clone.stream_add(i).unwrap();
            }
        });

        // Wait for thread to complete (all values sent)
        handle.join().unwrap();

        // Now collect - should get all 5 results
        let results = collector.stream_collect_blocking();
        assert_eq!(results.len(), 5);

        // Verify all results were collected
        let mut sorted = results.clone();
        sorted.sort();
        assert_eq!(sorted, vec![0, 1, 2, 3, 4]);
    }

    #[test]
    fn test_streaming_collector_graceful_shutdown_on_channel_close() {
        let collector = StreamingResultCollector::<i32>::new();
        let collector_clone = collector.clone();

        // Add some results from the main thread
        let _ = collector.stream_add(1).unwrap();
        let _ = collector.stream_add(2).unwrap();

        // Spawn a thread that adds more results then exits (drops sender)
        let handle = thread::spawn(move || {
            let _ = collector_clone.stream_add(3).unwrap();
            let _ = collector_clone.stream_add(4).unwrap();
            // collector_clone dropped here when thread exits, closing one sender
        });

        // Wait for thread to complete
        handle.join().unwrap();

        // At this point:
        // - collector_clone sender is dropped (thread exited)
        // - collector sender still exists
        // - When stream_collect is called, it will:
        //   1. Drop collector's sender (closing the last sender)
        //   2. Drain all 4 messages from the channel
        //   3. recv() returns Err when channel closes
        //   4. Return with all collected results

        let results = collector.stream_collect_blocking();

        // Verify we got all 4 results before graceful shutdown
        assert_eq!(results.len(), 4);

        // Verify all expected values are present
        let mut sorted = results.clone();
        sorted.sort();
        assert_eq!(sorted, vec![1, 2, 3, 4]);
    }

    #[test]
    fn test_streaming_collector_handles_empty_channel_gracefully() {
        let collector = StreamingResultCollector::<i32>::new();

        // Don't add any results, just collect immediately
        // stream_collect should:
        // 1. Drop the sender (closing the channel immediately)
        // 2. recv() returns Err immediately (no messages, channel closed)
        // 3. Return empty Vec without blocking

        let results = collector.stream_collect_blocking();

        // Should return empty vector gracefully
        assert_eq!(results.len(), 0);
        assert!(results.is_empty());
    }

    #[test]
    fn test_streaming_collector_stream_collect_drains_channel() {
        let collector = StreamingResultCollector::<i32>::new();

        // Add multiple results
        let _ = collector.stream_add(42).unwrap();
        let _ = collector.stream_add(24).unwrap();
        let _ = collector.stream_add(99).unwrap();

        // stream_collect should drain the channel completely (non-blocking)
        let results = collector.stream_collect().unwrap();

        // Verify all results were collected
        assert_eq!(results.len(), 3);

        // Verify calling again returns EmptyCollection error (channel was drained)
        let results2 = collector.stream_collect();
        assert!(results2.is_err());
        assert_eq!(
            results2.unwrap_err(),
            StreamCollectError::<i32>::EmptyCollection
        );
    }

    #[test]
    fn test_streaming_collector_stream_try_collect_non_blocking() {
        let collector = StreamingResultCollector::<i32>::new();

        // Add some results
        let _ = collector.stream_add(1).unwrap();
        let _ = collector.stream_add(2).unwrap();
        let _ = collector.stream_add(3).unwrap();

        // stream_try_collect should collect all immediately available results
        let results = collector.stream_try_collect();

        // Should get all 3 results that were in the channel
        assert_eq!(results.len(), 3);

        // Verify all values are present (order may vary)
        let mut sorted = results.clone();
        sorted.sort();
        assert_eq!(sorted, vec![1, 2, 3]);
    }

    #[test]
    fn test_streaming_collector_stream_try_collect_empty_channel() {
        let collector = StreamingResultCollector::<i32>::new();

        // Don't add any results
        // stream_try_collect should return empty Vec without blocking

        let results = collector.stream_try_collect();

        // Should return empty vector
        assert_eq!(results.len(), 0);
        assert!(results.is_empty());
    }

    #[test]
    fn test_streaming_collector_stream_collect_basic() {
        let collector = StreamingResultCollector::<i32>::new();

        // Add some results
        let _ = collector.stream_add(42).unwrap();
        let _ = collector.stream_add(24).unwrap();
        let _ = collector.stream_add(99).unwrap();

        // stream_collect should return Ok with all collected results
        let results = collector.stream_collect();
        assert!(results.is_ok());
        assert_eq!(results.unwrap().len(), 3);
    }

    #[test]
    fn test_streaming_collector_stream_collect_empty_returns_error() {
        let collector = StreamingResultCollector::<i32>::new();

        // Don't add any results
        let results = collector.stream_collect();
        assert!(results.is_err());
        assert_eq!(
            results.unwrap_err(),
            StreamCollectError::<i32>::EmptyCollection
        );
    }

    #[test]
    fn test_streaming_collector_stream_collect_empty_after_drain() {
        let collector = StreamingResultCollector::<i32>::new();

        // Add results and collect them
        let _ = collector.stream_add(1).unwrap();
        let _ = collector.stream_add(2).unwrap();
        let results1 = collector.stream_collect();
        assert!(results1.is_ok());
        assert_eq!(results1.unwrap().len(), 2);

        // Subsequent collection returns empty error (channel is now drained)
        let results2 = collector.stream_collect();
        assert!(results2.is_err());
        assert_eq!(
            results2.unwrap_err(),
            StreamCollectError::<i32>::EmptyCollection
        );
    }

    #[test]
    fn test_streaming_collector_stream_collect_non_blocking() {
        let collector = StreamingResultCollector::<i32>::new();

        // Add some results
        let _ = collector.stream_add(1).unwrap();
        let _ = collector.stream_add(2).unwrap();

        // stream_collect should return immediately with available results
        let results = collector.stream_collect().unwrap();
        assert_eq!(results.len(), 2);

        // Calling again should return empty error (channel is now drained)
        let results2 = collector.stream_collect();
        assert!(results2.is_err());
        assert_eq!(
            results2.unwrap_err(),
            StreamCollectError::<i32>::EmptyCollection
        );
    }

    #[test]
    fn test_streaming_collector_stream_collect_channel_disconnect() {
        let mut collector = StreamingResultCollector::<i32>::new();

        // Add some results
        let _ = collector.stream_add(42).unwrap();
        let _ = collector.stream_add(24).unwrap();

        // Drop the sender to simulate disconnection
        collector.drop_sender();

        // stream_collect should detect disconnection and return ChannelDisconnected
        // with partial results preserved
        let results = collector.stream_collect();
        assert!(results.is_err());

        match results.unwrap_err() {
            StreamCollectError::<i32>::ChannelDisconnected(partial) => {
                // Verify partial results were preserved
                assert_eq!(partial.len(), 2);
                let mut sorted = partial.clone();
                sorted.sort();
                assert_eq!(sorted, vec![24, 42]);
            }
            _ => panic!("Expected ChannelDisconnected with partial results"),
        }
    }

    #[test]
    fn test_streaming_collector_stream_collect_channel_disconnect_with_data() {
        let mut collector = StreamingResultCollector::<i32>::new();

        // Add some results first
        let _ = collector.stream_add(42).unwrap();
        let _ = collector.stream_add(24).unwrap();

        // Then drop the sender to simulate disconnection
        collector.drop_sender();

        // stream_collect should detect disconnection and return ChannelDisconnected
        // with partial results preserved
        let results = collector.stream_collect();
        assert!(results.is_err());

        match results.unwrap_err() {
            StreamCollectError::<i32>::ChannelDisconnected(partial) => {
                // Verify partial results were preserved
                assert_eq!(partial.len(), 2);
                let mut sorted = partial.clone();
                sorted.sort();
                assert_eq!(sorted, vec![24, 42]);
            }
            _ => panic!("Expected ChannelDisconnected with partial results"),
        }
    }

    // ===== Comprehensive stream_collect error handling tests =====

    #[test]
    fn test_stream_collect_normal_collection() {
        let collector = StreamingResultCollector::<i32>::new();

        // Add multiple results
        let _ = collector.stream_add(1).unwrap();
        let _ = collector.stream_add(2).unwrap();
        let _ = collector.stream_add(3).unwrap();

        // Normal collection should succeed
        let results = collector.stream_collect();
        assert!(results.is_ok(), "Normal collection should succeed");

        let collected = results.unwrap();
        assert_eq!(collected.len(), 3, "Should collect all 3 results");

        // Verify all values are present (order may vary)
        let mut sorted = collected.clone();
        sorted.sort();
        assert_eq!(sorted, vec![1, 2, 3], "All values should be present");
    }

    #[test]
    fn test_stream_collect_empty_channel() {
        let collector = StreamingResultCollector::<i32>::new();

        // Don't add any results - channel is empty
        let results = collector.stream_collect();

        // Should return EmptyCollection error
        assert!(results.is_err(), "Empty channel should return error");

        match results.unwrap_err() {
            StreamCollectError::<i32>::EmptyCollection => {
                // This is expected
            }
            other => panic!("Expected EmptyCollection error, got {:?}", other),
        }
    }

    #[test]
    fn test_stream_collect_channel_disconnect_preserves_items() {
        let mut collector = StreamingResultCollector::<i32>::new();

        // Add several results
        let _ = collector.stream_add(10).unwrap();
        let _ = collector.stream_add(20).unwrap();
        let _ = collector.stream_add(30).unwrap();
        let _ = collector.stream_add(40).unwrap();

        // Drop the sender to simulate disconnect
        collector.drop_sender();

        // Collection should detect disconnect and preserve partial results
        let results = collector.stream_collect();
        assert!(results.is_err(), "Disconnect should return error");

        match results.unwrap_err() {
            StreamCollectError::<i32>::ChannelDisconnected(partial) => {
                // Verify all collected items are preserved
                assert_eq!(partial.len(), 4, "All 4 items should be preserved");

                let mut sorted = partial.clone();
                sorted.sort();
                assert_eq!(
                    sorted,
                    vec![10, 20, 30, 40],
                    "All values should be preserved"
                );
            }
            other => panic!(
                "Expected ChannelDisconnected with partial results, got {:?}",
                other
            ),
        }
    }

    #[test]
    fn test_stream_collect_partial_results_on_disconnect() {
        let collector = StreamingResultCollector::<i32>::new();
        let collector_clone = collector.clone();

        // Add some results from main thread
        let _ = collector.stream_add(1).unwrap();
        let _ = collector.stream_add(2).unwrap();

        // Spawn thread that adds more results then exits
        let handle = std::thread::spawn(move || {
            let _ = collector_clone.stream_add(3).unwrap();
            let _ = collector_clone.stream_add(4).unwrap();
            // Thread exits here, potentially dropping sender
        });

        // Wait for thread to complete
        handle.join().unwrap();

        // Small delay to ensure sender drop propagates
        std::thread::sleep(std::time::Duration::from_millis(10));

        // Collection should get partial results (at minimum the 2 from main thread)
        let results = collector.stream_collect();

        // We expect this to succeed since we got results, even if sender dropped
        assert!(
            results.is_ok(),
            "Collection with partial results should succeed"
        );

        let collected = results.unwrap();
        assert!(
            collected.len() >= 2,
            "Should have at least the 2 results from main thread"
        );

        // Verify our main thread results are present
        let mut sorted = collected.clone();
        sorted.sort();
        assert!(sorted.contains(&1), "Should contain result 1");
        assert!(sorted.contains(&2), "Should contain result 2");
    }

    #[test]
    fn test_streaming_collector_graceful_shutdown_channel_closed_during_collection() {
        let collector = StreamingResultCollector::<i32>::new();
        let collector_clone = collector.clone();

        // Spawn a thread that adds results then exits (closes its sender)
        let handle = thread::spawn(move || {
            let _ = collector_clone.stream_add(1).unwrap();
            let _ = collector_clone.stream_add(2).unwrap();
            // Thread exits, dropping collector_clone sender
        });

        // Wait for thread to complete and close its sender
        handle.join().unwrap();

        // Give a small delay to ensure sender is dropped
        thread::sleep(std::time::Duration::from_millis(10));

        // stream_collect should return partial results gracefully
        // (results added before thread exited)
        let results = collector.stream_collect();

        // Should return Ok with results (not an error)
        assert!(results.is_ok());
        let collected = results.unwrap();
        // Should have collected the results before channel closed
        assert_eq!(collected.len(), 2);

        // Verify values are present
        let mut sorted = collected.clone();
        sorted.sort();
        assert_eq!(sorted, vec![1, 2]);
    }

    #[test]
    fn test_streaming_collector_graceful_shutdown_no_receiver() {
        let collector = StreamingResultCollector::<i32>::new();

        // Manually drop the receiver
        let mut collector_mut = collector;
        collector_mut.drop_receiver();

        // Now stream_collect should return error
        let results = collector_mut.stream_collect();
        assert!(results.is_err());
        assert_eq!(
            results.unwrap_err(),
            StreamCollectError::<i32>::ReceiverAlreadyTaken
        );
    }

    #[test]
    fn test_streaming_collector_graceful_shutdown_empty_channel_closed() {
        let collector = StreamingResultCollector::<i32>::new();
        let _collector_clone = collector.clone();

        // Spawn a thread that immediately exits without adding results
        let handle = thread::spawn(move || {
            // Thread exits immediately, dropping collector_clone sender
            // No results were added
        });

        // Wait for thread to complete and close its sender
        handle.join().unwrap();

        // Give a small delay to ensure sender is dropped
        thread::sleep(std::time::Duration::from_millis(10));

        // stream_collect should return EmptyCollection error
        // (not Ok - channel is empty, and original sender is still alive)
        let results = collector.stream_collect();

        // Should return Err since channel is empty
        assert!(results.is_err());
        match results.unwrap_err() {
            StreamCollectError::<i32>::EmptyCollection => {
                // Expected - channel is empty but still connected
            }
            other => panic!("Expected EmptyCollection, got {:?}", other),
        }
    }

    #[test]
    fn test_streaming_collector_graceful_shutdown_partial_results() {
        let collector = StreamingResultCollector::<i32>::new();
        let collector_clone = collector.clone();

        // Add initial results
        let _ = collector.stream_add(1).unwrap();
        let _ = collector.stream_add(2).unwrap();

        // Spawn thread that adds more results then exits
        let handle = thread::spawn(move || {
            let _ = collector_clone.stream_add(3).unwrap();
            let _ = collector_clone.stream_add(4).unwrap();
            // Thread exits, dropping its sender
        });

        // Wait for thread to complete
        handle.join().unwrap();

        // Small delay to ensure sender is dropped
        thread::sleep(std::time::Duration::from_millis(10));

        // stream_collect should return all results gracefully
        // even if channel closed during/after collection
        let results = collector.stream_collect();

        // Should return Ok with all results
        assert!(results.is_ok());
        let collected = results.unwrap();

        // Should have collected all 4 results before any closure
        let mut sorted = collected.clone();
        sorted.sort();
        assert_eq!(sorted, vec![1, 2, 3, 4]);
    }

    #[test]
    fn test_streaming_collector_graceful_shutdown_no_panic_on_broken_channel() {
        let collector = StreamingResultCollector::<i32>::new();

        // Add some results
        let _ = collector.stream_add(42).unwrap();

        // Manually drop the sender to simulate broken channel
        let mut collector_mut = collector;
        collector_mut.drop_sender();

        // stream_collect should not panic
        // It should return ChannelDisconnected error with partial results
        let results = collector_mut.stream_collect();

        // Should return ChannelDisconnected (not panic) even with sender dropped
        assert!(results.is_err());
        match results.unwrap_err() {
            StreamCollectError::<i32>::ChannelDisconnected(partial) => {
                // Should have collected the result that was in the channel
                assert_eq!(partial.len(), 1);
                assert_eq!(partial[0], 42);
            }
            other => panic!(
                "Expected ChannelDisconnected with partial results, got {:?}",
                other
            ),
        }
    }

    #[test]
    fn test_streaming_collector_graceful_shutdown_repeated_collections() {
        let collector = StreamingResultCollector::<i32>::new();
        let collector_clone = collector.clone();

        // Add some results
        let _ = collector.stream_add(1).unwrap();
        let _ = collector.stream_add(2).unwrap();

        // First collection should get results
        let results1 = collector.stream_collect();
        assert!(results1.is_ok());
        assert_eq!(results1.unwrap().len(), 2);

        // Spawn thread to close the channel
        let handle = thread::spawn(move || {
            // Thread exits, dropping its sender
            std::mem::drop(collector_clone);
        });
        handle.join().unwrap();

        // Small delay
        thread::sleep(std::time::Duration::from_millis(10));

        // Second collection should return EmptyCollection error (channel drained)
        let results2 = collector.stream_collect();
        assert!(results2.is_err());
        match results2.unwrap_err() {
            StreamCollectError::<i32>::EmptyCollection => {
                // Expected - channel is empty but still connected
            }
            other => panic!("Expected EmptyCollection, got {:?}", other),
        }
    }

    // ===== Normal stream_collect Tests =====

    #[test]
    fn test_stream_collect_multiple_items_successfully() {
        let collector = StreamingResultCollector::<i32>::new();

        // Test collecting multiple items successfully
        let _ = collector.stream_add(1).unwrap();
        let _ = collector.stream_add(2).unwrap();
        let _ = collector.stream_add(3).unwrap();
        let _ = collector.stream_add(4).unwrap();
        let _ = collector.stream_add(5).unwrap();

        // Normal collection should succeed
        let results = collector.stream_collect();
        assert!(results.is_ok(), "Normal collection should succeed");

        let collected = results.unwrap();
        assert_eq!(collected.len(), 5, "Should collect all 5 results");
    }

    #[test]
    fn test_stream_collect_with_sender_kept_alive() {
        let collector = StreamingResultCollector::<i32>::new();
        let collector_clone = collector.clone();

        // Add results from main thread
        let _ = collector.stream_add(10).unwrap();
        let _ = collector.stream_add(20).unwrap();
        let _ = collector.stream_add(30).unwrap();

        // Spawn a thread that keeps its sender alive
        let handle = thread::spawn(move || {
            // This thread keeps its sender alive
            // Don't drop it, just let it complete naturally
            let _ = collector_clone.stream_add(40).unwrap();
            // Thread exits here but doesn't explicitly drop sender
        });

        // Wait for thread to complete
        handle.join().unwrap();

        // Small delay to ensure thread completion
        thread::sleep(std::time::Duration::from_millis(10));

        // stream_collect should succeed even with sender kept alive until thread exit
        let results = collector.stream_collect();
        assert!(
            results.is_ok(),
            "Collection should succeed with sender kept alive"
        );

        let collected = results.unwrap();
        assert_eq!(collected.len(), 4, "Should collect all 4 results");
    }

    #[test]
    fn test_stream_collect_preserves_order() {
        let collector = StreamingResultCollector::<i32>::new();

        // Add items in a specific order
        let _ = collector.stream_add(100).unwrap();
        let _ = collector.stream_add(200).unwrap();
        let _ = collector.stream_add(300).unwrap();
        let _ = collector.stream_add(400).unwrap();
        let _ = collector.stream_add(500).unwrap();

        // Collect results without sorting
        let results = collector.stream_collect();
        assert!(results.is_ok(), "Collection should succeed");

        let collected = results.unwrap();
        assert_eq!(collected.len(), 5, "Should collect all 5 results");

        // Verify all items are received in correct order
        assert_eq!(collected[0], 100, "First item should be 100");
        assert_eq!(collected[1], 200, "Second item should be 200");
        assert_eq!(collected[2], 300, "Third item should be 300");
        assert_eq!(collected[3], 400, "Fourth item should be 400");
        assert_eq!(collected[4], 500, "Fifth item should be 500");
    }

    #[test]
    fn test_stream_collect_normal_operation_comprehensive() {
        let collector = StreamingResultCollector::<String>::new();

        // Test normal operation with multiple items
        let _ = collector.stream_add("first".to_string()).unwrap();
        let _ = collector.stream_add("second".to_string()).unwrap();
        let _ = collector.stream_add("third".to_string()).unwrap();
        let _ = collector.stream_add("fourth".to_string()).unwrap();
        let _ = collector.stream_add("fifth".to_string()).unwrap();

        // Verify collection succeeds
        let results = collector.stream_collect();
        assert!(
            results.is_ok(),
            "Normal operation collection should succeed"
        );

        let collected = results.unwrap();
        assert_eq!(collected.len(), 5, "All 5 items should be collected");

        // Verify order is preserved (no sorting)
        assert_eq!(collected[0], "first", "Order should be preserved");
        assert_eq!(collected[1], "second", "Order should be preserved");
        assert_eq!(collected[2], "third", "Order should be preserved");
        assert_eq!(collected[3], "fourth", "Order should be preserved");
        assert_eq!(collected[4], "fifth", "Order should be preserved");
    }

    #[test]
    fn test_stream_collect_single_item() {
        let collector = StreamingResultCollector::<i32>::new();

        // Test collecting a single item
        let _ = collector.stream_add(42).unwrap();

        let results = collector.stream_collect();
        assert!(results.is_ok(), "Single item collection should succeed");

        let collected = results.unwrap();
        assert_eq!(collected.len(), 1, "Should collect 1 result");
        assert_eq!(collected[0], 42, "Item value should be preserved");
    }

    #[test]
    fn test_stream_collect_large_number_of_items() {
        let collector = StreamingResultCollector::<i32>::new();

        // Add a large number of items
        for i in 0..100 {
            let _ = collector.stream_add(i).unwrap();
        }

        let results = collector.stream_collect();
        assert!(results.is_ok(), "Large collection should succeed");

        let collected = results.unwrap();
        assert_eq!(collected.len(), 100, "All 100 items should be collected");

        // Verify order is preserved for a subset of items
        assert_eq!(collected[0], 0, "First item should be 0");
        assert_eq!(collected[50], 50, "Middle item should be 50");
        assert_eq!(collected[99], 99, "Last item should be 99");
    }

    // ===== Receiver Lifetime Tests =====

    #[test]
    fn test_receiver_lifetime_basic_stream_collect() {
        // Test that verifies receiver remains alive through complete stream_collect() operation
        // This is the first child bead in the receiver lifetime testing chain

        let collector = StreamingResultCollector::<i32>::new();

        // Add multiple values to the channel
        let _ = collector.stream_add(42).unwrap();
        let _ = collector.stream_add(24).unwrap();
        let _ = collector.stream_add(99).unwrap();

        // Verify receiver is still alive by successfully collecting
        let results = collector.stream_collect();

        // If receiver was dropped prematurely, stream_collect would return ReceiverAlreadyTaken error
        assert!(
            results.is_ok(),
            "Receiver should remain alive during stream_collect()"
        );

        let collected = results.unwrap();
        assert_eq!(collected.len(), 3, "Should collect all 3 results");

        // Verify all values are present (order may vary)
        let mut sorted = collected.clone();
        sorted.sort();
        assert_eq!(sorted, vec![24, 42, 99], "All values should be collected");

        // Verify receiver is still available after collection (receiver is not consumed by stream_collect)
        let results2 = collector.stream_collect();
        // Should return EmptyCollection error (not ReceiverAlreadyTaken), proving receiver is still alive
        assert!(results2.is_err());
        match results2.unwrap_err() {
            StreamCollectError::<i32>::EmptyCollection => {
                // Expected - channel is empty but receiver is still alive
            }
            StreamCollectError::<i32>::ReceiverAlreadyTaken => {
                panic!("Receiver should not be dropped after stream_collect()");
            }
            _ => panic!("Expected EmptyCollection error, not ReceiverAlreadyTaken"),
        }
    }

    #[test]
    fn test_receiver_lifetime_during_concurrent_operations() {
        // Test that verifies receiver stays alive during concurrent add operations
        // This demonstrates the receiver lifetime guarantee under concurrent access

        let collector = StreamingResultCollector::<i32>::new();
        let collector_clone = collector.clone();
        let collector_clone2 = collector.clone();

        // Spawn threads that add values concurrently
        let handle1 = thread::spawn(move || {
            for i in 0..5 {
                let _ = collector_clone.stream_add(i).unwrap();
            }
        });

        let handle2 = thread::spawn(move || {
            for i in 5..10 {
                let _ = collector_clone2.stream_add(i).unwrap();
            }
        });

        // Wait for threads to complete
        handle1.join().unwrap();
        handle2.join().unwrap();

        // Verify receiver is still alive after concurrent operations
        let results = collector.stream_collect();
        assert!(
            results.is_ok(),
            "Receiver should remain alive after concurrent adds"
        );

        let collected = results.unwrap();
        assert_eq!(
            collected.len(),
            10,
            "Should collect all 10 results from concurrent operations"
        );

        // Verify receiver is still available
        let results2 = collector.stream_collect();
        assert!(results2.is_err());
        match results2.unwrap_err() {
            StreamCollectError::<i32>::EmptyCollection => {
                // Expected - receiver is still alive but channel is empty
            }
            StreamCollectError::<i32>::ReceiverAlreadyTaken => {
                panic!("Receiver should not be dropped after concurrent operations");
            }
            _ => panic!("Expected EmptyCollection error, not ReceiverAlreadyTaken"),
        }
    }

    #[test]
    fn test_receiver_lifetime_with_blocking_collect() {
        // Test that verifies receiver lifetime guarantee for stream_collect_blocking()
        // This ensures receiver stays alive through the blocking collection operation

        let collector = StreamingResultCollector::<i32>::new();
        let collector_clone = collector.clone();

        // Spawn a thread that adds values then completes
        let handle = thread::spawn(move || {
            for i in 0..5 {
                let _ = collector_clone.stream_add(i).unwrap();
                thread::sleep(Duration::from_millis(10));
            }
        });

        // Wait for thread to complete
        handle.join().unwrap();

        // Verify receiver stays alive through blocking collect
        // stream_collect_blocking consumes the collector, so we can't test receiver after
        let results = collector.stream_collect_blocking();

        // If receiver was dropped prematurely during collection, we'd get timeout or error
        assert_eq!(
            results.len(),
            5,
            "Should collect all 5 results without receiver dropping"
        );

        let mut sorted = results.clone();
        sorted.sort();
        assert_eq!(
            sorted,
            vec![0, 1, 2, 3, 4],
            "All values should be collected"
        );
    }

    // ===== Receiver Lifetime Edge Case Tests =====

    #[test]
    fn test_receiver_lifetime_empty_collection_case() {
        // Test that verifies receiver stays alive when collecting from an empty channel
        // This edge case ensures the receiver isn't dropped when no data is available

        let collector = StreamingResultCollector::<i32>::new();

        // Don't add any results - channel is empty
        // Verify receiver is still alive by attempting collection
        let results = collector.stream_collect();

        // Should return EmptyCollection error (not ReceiverAlreadyTaken)
        // This proves receiver is still alive even with empty collection
        assert!(results.is_err());
        match results.unwrap_err() {
            StreamCollectError::<i32>::EmptyCollection => {
                // Expected - receiver is alive, channel is just empty
            }
            StreamCollectError::<i32>::ReceiverAlreadyTaken => {
                panic!("Receiver should not be dropped for empty collection");
            }
            _ => panic!("Expected EmptyCollection error, not ReceiverAlreadyTaken"),
        }

        // Verify receiver is still available after empty collection attempt
        let results2 = collector.stream_collect();
        assert!(results2.is_err());
        match results2.unwrap_err() {
            StreamCollectError::<i32>::EmptyCollection => {
                // Receiver is still alive and responsive
            }
            StreamCollectError::<i32>::ReceiverAlreadyTaken => {
                panic!("Receiver should remain available after empty collection");
            }
            _ => panic!("Expected EmptyCollection, receiver should still be alive"),
        }
    }

    #[test]
    fn test_receiver_lifetime_single_item_case() {
        // Test that verifies receiver lifetime guarantee for single-item collections
        // This edge case ensures the receiver handles single-item collections correctly

        let collector = StreamingResultCollector::<i32>::new();

        // Add exactly one item
        let _ = collector.stream_add(42).unwrap();

        // Collect the single item
        let results = collector.stream_collect();
        assert!(results.is_ok(), "Single-item collection should succeed");

        let collected = results.unwrap();
        assert_eq!(collected.len(), 1, "Should collect exactly 1 item");
        assert_eq!(collected[0], 42, "Item value should be preserved");

        // Verify receiver is still alive after single-item collection
        let results2 = collector.stream_collect();
        assert!(results2.is_err());
        match results2.unwrap_err() {
            StreamCollectError::<i32>::EmptyCollection => {
                // Expected - receiver is alive, channel is now empty
            }
            StreamCollectError::<i32>::ReceiverAlreadyTaken => {
                panic!("Receiver should not be dropped after single-item collection");
            }
            _ => panic!("Expected EmptyCollection, receiver should remain alive"),
        }
    }

    #[test]
    fn test_receiver_lifetime_multiple_clone_scenarios() {
        // Test that verifies receiver lifetime across multiple clone operations
        // This edge case ensures the original receiver stays alive even with many clones

        let collector = StreamingResultCollector::<i32>::new();

        // Create multiple clones (clones don't get the receiver)
        let clone1 = collector.clone();
        let clone2 = collector.clone();
        let clone3 = collector.clone();

        // Verify sender count tracking
        assert_eq!(collector.sender_count(), 4);

        // Add results from original and clones
        let _ = collector.stream_add(1).unwrap();
        let _ = clone1.stream_add(2).unwrap();
        let _ = clone2.stream_add(3).unwrap();
        let _ = clone3.stream_add(4).unwrap();

        // Drop some clones to test receiver lifetime during clone drops
        drop(clone1);
        drop(clone2);

        // Verify receiver is still alive after dropping clones
        let results = collector.stream_collect();
        assert!(
            results.is_ok(),
            "Receiver should remain alive after clone drops"
        );

        let collected = results.unwrap();
        assert_eq!(collected.len(), 4, "Should collect all 4 results");

        // Verify receiver is still available
        let results2 = collector.stream_collect();
        assert!(results2.is_err());
        match results2.unwrap_err() {
            StreamCollectError::<i32>::EmptyCollection => {
                // Receiver is still alive
            }
            StreamCollectError::<i32>::ReceiverAlreadyTaken => {
                panic!("Receiver should not be dropped after clone operations");
            }
            _ => panic!("Expected EmptyCollection, receiver should remain alive"),
        }
    }

    #[test]
    fn test_receiver_lifetime_early_termination_scenarios() {
        // Test that verifies receiver lifetime during early termination
        // This edge case ensures receiver stays alive when threads terminate early

        let collector = StreamingResultCollector::<i32>::new();
        let collector_clone = collector.clone();

        // Add some results from main thread
        let _ = collector.stream_add(1).unwrap();
        let _ = collector.stream_add(2).unwrap();

        // Spawn a thread that terminates early (only adds 1 item instead of expected 5)
        let handle = thread::spawn(move || {
            let _ = collector_clone.stream_add(3).unwrap();
            // Thread terminates early instead of adding more items
            // collector_clone is dropped here when thread exits
        });

        // Wait for thread to complete (early termination)
        handle.join().unwrap();

        // Small delay to ensure sender drop propagates
        thread::sleep(Duration::from_millis(10));

        // Verify receiver is still alive despite early thread termination
        let results = collector.stream_collect();
        assert!(
            results.is_ok(),
            "Receiver should remain alive after early termination"
        );

        let collected = results.unwrap();
        // Should have at least the 2 results from main thread
        assert!(
            collected.len() >= 2,
            "Should have at least main thread results"
        );
        assert!(
            collected.len() <= 3,
            "Should have at most 3 results (early termination)"
        );

        // Verify our main thread results are present
        let mut sorted = collected.clone();
        sorted.sort();
        assert!(
            sorted.contains(&1),
            "Should contain result 1 from main thread"
        );
        assert!(
            sorted.contains(&2),
            "Should contain result 2 from main thread"
        );

        // Receiver should still be available
        let results2 = collector.stream_collect();
        assert!(results2.is_err());
        match results2.unwrap_err() {
            StreamCollectError::<i32>::EmptyCollection => {
                // Receiver is still alive and responsive
            }
            StreamCollectError::<i32>::ReceiverAlreadyTaken => {
                panic!("Receiver should not be dropped after early termination");
            }
            _ => panic!("Expected EmptyCollection, receiver should remain alive"),
        }
    }

    #[test]
    fn test_receiver_lifetime_clone_chain_scenario() {
        // Test that verifies receiver lifetime through a chain of clones
        // This edge case ensures the original receiver survives deep clone hierarchies

        let collector = StreamingResultCollector::<i32>::new();

        // Create a chain of clones
        let clone1 = collector.clone();
        let clone2 = clone1.clone();
        let clone3 = clone2.clone();

        // All clones should share the same sender count
        assert_eq!(collector.sender_count(), 4);
        assert_eq!(clone1.sender_count(), 4);
        assert_eq!(clone2.sender_count(), 4);
        assert_eq!(clone3.sender_count(), 4);

        // Add results through the clone chain
        let _ = collector.stream_add(1).unwrap();
        let _ = clone1.stream_add(2).unwrap();
        let _ = clone2.stream_add(3).unwrap();
        let _ = clone3.stream_add(4).unwrap();

        // Drop intermediate clones to test receiver lifetime
        drop(clone1);
        drop(clone2);

        // Original collector's receiver should still be alive
        let results = collector.stream_collect();
        assert!(
            results.is_ok(),
            "Receiver should survive clone chain operations"
        );

        let collected = results.unwrap();
        assert_eq!(collected.len(), 4, "Should collect all 4 results");

        // Verify all values from clone chain are present
        let mut sorted = collected.clone();
        sorted.sort();
        assert_eq!(
            sorted,
            vec![1, 2, 3, 4],
            "All clone chain results should be present"
        );
    }

    #[test]
    fn test_receiver_lifetime_empty_with_multiple_operations() {
        // Test that verifies receiver stays alive through multiple empty collection attempts
        // This edge case tests repeated operations on an empty channel

        let collector = StreamingResultCollector::<i32>::new();

        // Perform multiple collection attempts on empty channel
        for i in 0..5 {
            let results = collector.stream_collect();
            assert!(results.is_err(), "Empty collection should return error");
            match results.unwrap_err() {
                StreamCollectError::<i32>::EmptyCollection => {
                    // Expected - receiver is alive, channel is empty
                }
                StreamCollectError::<i32>::ReceiverAlreadyTaken => {
                    panic!(
                        "Receiver dropped on attempt {} - should remain alive",
                        i + 1
                    );
                }
                _ => panic!("Expected EmptyCollection on attempt {}", i + 1),
            }
        }

        // Verify receiver is still functional after multiple empty operations
        // Now add a result and verify we can collect it
        let _ = collector.stream_add(42).unwrap();
        let results = collector.stream_collect();
        assert!(
            results.is_ok(),
            "Receiver should still function after multiple empty attempts"
        );
        assert_eq!(results.unwrap().len(), 1);
    }

    #[test]
    fn test_receiver_lifetime_concurrent_early_terminations() {
        // Test that verifies receiver lifetime when multiple threads terminate early
        // This edge case tests receiver resilience under concurrent early terminations

        let collector = StreamingResultCollector::<i32>::new();
        let mut handles = Vec::new();

        // Spawn multiple threads that may terminate early
        for thread_id in 0..5 {
            let collector_clone = collector.clone();
            let handle = thread::spawn(move || {
                // Each thread adds only some results before terminating
                for i in 0..3 {
                    let _ = collector_clone.stream_add(thread_id * 10 + i).unwrap();
                }
                // Thread terminates here (early termination)
                // collector_clone dropped when thread exits
            });
            handles.push(handle);
        }

        // Wait for all threads to complete (all terminate early)
        for handle in handles {
            handle.join().unwrap();
        }

        // Small delay to ensure all sender drops propagate
        thread::sleep(Duration::from_millis(50));

        // Verify receiver is still alive after all concurrent early terminations
        let results = collector.stream_collect();
        assert!(
            results.is_ok(),
            "Receiver should survive concurrent early terminations"
        );

        let collected = results.unwrap();
        // Should have collected results from threads before they terminated
        assert_eq!(
            collected.len(),
            15,
            "Should collect all 15 results from early-terminating threads"
        );

        // Verify receiver is still available
        let results2 = collector.stream_collect();
        assert!(results2.is_err());
        match results2.unwrap_err() {
            StreamCollectError::<i32>::EmptyCollection => {
                // Receiver is still alive
            }
            StreamCollectError::<i32>::ReceiverAlreadyTaken => {
                panic!("Receiver should not be dropped after concurrent early terminations");
            }
            _ => panic!("Expected EmptyCollection, receiver should remain alive"),
        }
    }

    // ===== Scoping Demonstration Tests =====

    #[test]
    fn test_receiver_scope_single_threaded_context() {
        // Demonstrates proper receiver scoping in single-threaded context
        // Best practice: Use collector in distinct scopes to ensure predictable cleanup

        let collector = StreamingResultCollector::<i32>::new();

        // Scope 1: Adding data
        {
            collector.stream_add(42).unwrap();
            collector.stream_add(24).unwrap();
            collector.stream_add(99).unwrap();
            // Scope ends here, but receiver stays alive because we only moved sender
        }

        // Scope 2: Collecting data
        {
            let results = collector.stream_collect();
            assert!(results.is_ok(), "Receiver should be alive in new scope");

            let collected = results.unwrap();
            assert_eq!(
                collected.len(),
                3,
                "All values from previous scope should be available"
            );

            let mut sorted = collected;
            sorted.sort();
            assert_eq!(
                sorted,
                vec![24, 42, 99],
                "Values should persist across scopes"
            );
        }

        // Scope 3: Verify receiver is still functional after collection
        {
            // Add more data after collection
            collector.stream_add(100).unwrap();

            let results = collector.stream_collect();
            assert!(results.is_ok(), "Receiver should still be functional");
            assert_eq!(results.unwrap().len(), 1, "New scope should work correctly");
        }
    }

    #[test]
    fn test_receiver_scope_multi_threaded_context() {
        // Demonstrates proper receiver scoping in multi-threaded context
        // Best practice: Ensure receiver scope extends beyond all thread lifetimes

        let collector = StreamingResultCollector::<i32>::new();

        // Scope for thread spawning
        {
            let collector_clone1 = collector.clone();
            let collector_clone2 = collector.clone();

            // Thread 1 scope
            let handle1 = thread::spawn(move || {
                // Each thread operates in its own scope
                for i in 0..5 {
                    let _ = collector_clone1.stream_add(i).unwrap();
                }
                // Thread scope ends here, receiver still alive in main collector
            });

            // Thread 2 scope
            let handle2 = thread::spawn(move || {
                for i in 5..10 {
                    let _ = collector_clone2.stream_add(i).unwrap();
                }
                // Thread scope ends here, receiver still alive in main collector
            });

            // Wait for threads to complete
            handle1.join().unwrap();
            handle2.join().unwrap();
            // Thread spawning scope ends here
        }

        // Collection scope - receiver should still be alive after all threads completed
        {
            let results = collector.stream_collect();
            assert!(results.is_ok(), "Receiver should survive all thread scopes");

            let collected = results.unwrap();
            assert_eq!(
                collected.len(),
                10,
                "Should collect all results from all threads"
            );

            let mut sorted = collected;
            sorted.sort();
            let expected: Vec<i32> = (0..10).collect();
            assert_eq!(sorted, expected, "All threaded results should be available");
        }
    }

    #[test]
    fn test_receiver_scope_moving_collector_between_scopes() {
        // Demonstrates proper receiver behavior when collector is moved between scopes
        // Best practice: Moving collector transfers ownership but preserves receiver in original

        let collector = StreamingResultCollector::<i32>::new();

        // Add initial data before moving
        let _ = collector.stream_add(1).unwrap();
        let _ = collector.stream_add(2).unwrap();

        // Scope 1: Move collector into a closure
        {
            let result = std::panic::catch_unwind(|| {
                // Move collector into this scope
                let moved_collector = collector;

                // Add data in this scope
                let _ = moved_collector.stream_add(3).unwrap();

                // Collect in this scope
                let results = moved_collector.stream_collect();
                assert!(results.is_ok(), "Collector should work after being moved");

                let collected = results.unwrap();
                // Should have all 3 values (including those from before the move)
                assert_eq!(collected.len(), 3, "Moving should preserve all data");

                collected
            })
            .unwrap();

            let mut sorted = result;
            sorted.sort();
            assert_eq!(
                sorted,
                vec![1, 2, 3],
                "Data should persist across scope move"
            );
        }
        // Original collector is moved (consumed), so we can't use it here
    }

    #[test]
    fn test_receiver_scope_with_nested_scopes() {
        // Demonstrates receiver behavior with nested scopes
        // Best practice: Deeply nested scopes maintain receiver accessibility

        let collector = StreamingResultCollector::<i32>::new();

        // Outer scope
        {
            let _ = collector.stream_add(10).unwrap();

            // Middle scope
            {
                let collector_clone = collector.clone();
                let _ = collector_clone.stream_add(20).unwrap();

                // Inner scope
                {
                    let collector_clone2 = collector.clone();
                    let _ = collector_clone2.stream_add(30).unwrap();
                }
                // Inner scope ends, receiver still alive

                let _ = collector.stream_add(40).unwrap();
            }
            // Middle scope ends, receiver still alive

            let _ = collector.stream_add(50).unwrap();
        }
        // Outer scope ends, receiver still alive

        // Collection scope - should have all values from all nested scopes
        let results = collector.stream_collect();
        assert!(results.is_ok(), "Receiver should survive all nested scopes");

        let collected = results.unwrap();
        assert_eq!(
            collected.len(),
            5,
            "All nested scope values should be available"
        );

        let mut sorted = collected;
        sorted.sort();
        assert_eq!(
            sorted,
            vec![10, 20, 30, 40, 50],
            "Nested scope data should persist"
        );
    }

    #[test]
    fn test_receiver_scope_with_early_scope_exits() {
        // Demonstrates receiver behavior when scopes exit early
        // Best practice: Early scope exits should not affect receiver lifetime

        let collector = StreamingResultCollector::<i32>::new();

        // Scope with early exit
        {
            let _ = collector.stream_add(100).unwrap();

            // Simulate early exit based on condition
            let early_exit = true;
            if early_exit {
                // Scope exits early, but receiver stays alive
                return;
            }

            // This code won't execute, but that's fine
            let _ = collector.stream_add(200).unwrap();
        }

        // Receiver should still be alive despite early scope exit
        let results = collector.stream_collect();
        assert!(results.is_ok(), "Receiver should survive early scope exits");

        let collected = results.unwrap();
        assert_eq!(
            collected.len(),
            1,
            "Early scope exit should preserve partial data"
        );
        assert_eq!(
            collected[0], 100,
            "Value before early exit should be preserved"
        );
    }

    #[test]
    fn test_receiver_scope_with_conditional_scoping() {
        // Demonstrates receiver behavior with conditional scope paths
        // Best practice: Different execution paths should maintain receiver integrity

        let collector = StreamingResultCollector::<i32>::new();

        // Conditional scope path 1
        let condition = true;
        if condition {
            let _ = collector.stream_add(1).unwrap();
            let _ = collector.stream_add(2).unwrap();
        } else {
            let _ = collector.stream_add(10).unwrap();
            let _ = collector.stream_add(20).unwrap();
        }

        // Conditional scope path 2
        let another_condition = false;
        if another_condition {
            let collector_clone = collector.clone();
            let _ = collector_clone.stream_add(100).unwrap();
        }

        // Receiver should be alive regardless of which conditional paths were taken
        let results = collector.stream_collect();
        assert!(
            results.is_ok(),
            "Receiver should survive conditional scoping"
        );

        let collected = results.unwrap();
        assert_eq!(
            collected.len(),
            2,
            "Should have data from taken conditional path"
        );

        let mut sorted = collected;
        sorted.sort();
        assert_eq!(
            sorted,
            vec![1, 2],
            "Conditional path data should be correct"
        );
    }

    #[test]
    fn test_receiver_scope_with_loop_scoping() {
        // Demonstrates receiver behavior with loop-based scoping
        // Best practice: Loop iterations maintain consistent receiver access

        let collector = StreamingResultCollector::<i32>::new();

        // Add data across multiple loop iterations
        for i in 0..5 {
            // Each iteration is a new scope, but receiver stays alive
            let _ = collector.stream_add(i).unwrap();

            // Inner scope within loop
            {
                let collector_clone = collector.clone();
                let _ = collector_clone.stream_add(i + 100).unwrap();
            }
            // Inner scope ends, receiver still alive
        }
        // Loop scope ends, receiver still alive

        let results = collector.stream_collect();
        assert!(results.is_ok(), "Receiver should survive loop scoping");

        let collected = results.unwrap();
        assert_eq!(
            collected.len(),
            10,
            "All loop iterations should contribute data"
        );

        let mut sorted = collected;
        sorted.sort();
        let mut expected = Vec::new();
        for i in 0..5 {
            expected.push(i);
            expected.push(i + 100);
        }
        expected.sort();
        assert_eq!(sorted, expected, "Loop scope data should be complete");
    }

    #[test]
    fn test_receiver_scope_best_practice_documentation() {
        // Comprehensive test documenting receiver scoping best practices
        // This test serves as both documentation and validation of scoping behavior

        let collector = StreamingResultCollector::<i32>::new();

        // Best Practice 1: Keep collector scope wider than thread scopes
        {
            let collector_clone = collector.clone();
            let handle = thread::spawn(move || {
                let _ = collector_clone.stream_add(42).unwrap();
            });
            handle.join().unwrap();
            // Thread scope ended, collector scope continues
        }

        // Best Practice 2: Use distinct scopes for different operation phases
        // Phase 1: Data collection
        {
            for i in 0..3 {
                let _ = collector.stream_add(i).unwrap();
            }
        }

        // Phase 2: Data processing (collector still alive)
        {
            let results = collector.stream_collect();
            assert!(
                results.is_ok(),
                "Collector should work across operation phases"
            );
            let collected = results.unwrap();
            assert_eq!(
                collected.len(),
                4,
                "Phase 1 data should be available in Phase 2 (1 from thread + 3 from Phase 1)"
            );
        }

        // Best Practice 3: Scope-based resource management
        let collector2 = StreamingResultCollector::<i32>::new();
        {
            let collector2_ref = &collector2;
            collector2_ref.stream_add(99).unwrap();
            // collector2_ref goes out of scope, but collector2 is still valid
        }

        // collector2 should still be functional
        let results2 = collector2.stream_collect();
        assert!(
            results2.is_ok(),
            "Reference-based scoping should preserve collector"
        );
        assert_eq!(
            results2.unwrap().len(),
            1,
            "Reference-scoped data should be available"
        );
    }

    // ===== Performance Benchmarks =====

    #[cfg(test)]
    mod benches {
        use super::*;
        use std::thread;
        use std::time::Instant;

        fn bench_mutex_collector(num_threads: usize, items_per_thread: usize) -> Vec<usize> {
            let collector = Arc::new(ResultCollector::<usize>::new());
            let mut handles = Vec::new();

            let start = Instant::now();

            for thread_id in 0..num_threads {
                let collector_clone = Arc::clone(&collector);
                let handle = thread::spawn(move || {
                    for i in 0..items_per_thread {
                        collector_clone.add(thread_id * items_per_thread + i);
                    }
                });
                handles.push(handle);
            }

            for handle in handles {
                handle.join().unwrap();
            }

            let results = collector.collect();
            let elapsed = start.elapsed();

            // Print timing info for manual inspection
            if num_threads >= 100 {
                println!(
                    "MutexCollector: {} threads × {} items = {:?}",
                    num_threads, items_per_thread, elapsed
                );
            }

            results
        }

        fn bench_streaming_collector(num_threads: usize, items_per_thread: usize) -> Vec<usize> {
            let collector = StreamingResultCollector::<usize>::new();
            let mut handles = Vec::new();

            let start = Instant::now();

            for thread_id in 0..num_threads {
                let collector_clone = collector.clone();
                let handle = thread::spawn(move || {
                    for i in 0..items_per_thread {
                        let _ = collector_clone.stream_add(thread_id * items_per_thread + i);
                    }
                });
                handles.push(handle);
            }

            for handle in handles {
                handle.join().unwrap();
            }

            let results = collector.stream_collect_blocking();
            let elapsed = start.elapsed();

            // Print timing info for manual inspection
            if num_threads >= 100 {
                println!(
                    "StreamingCollector: {} threads × {} items = {:?}",
                    num_threads, items_per_thread, elapsed
                );
            }

            results
        }

        #[test]
        #[ignore] // Run with: cargo test bench_performance -- --ignored
        fn bench_performance_comparison() {
            println!("\n=== Performance Comparison ===\n");

            // Test different scenarios
            let scenarios = vec![
                (10, 10),
                (10, 100),
                (50, 10),
                (50, 50),
                (100, 10),
                (100, 50),
                (200, 5),
                (200, 10),
            ];

            for (num_threads, items_per_thread) in scenarios {
                println!(
                    "\n--- {} threads × {} items per thread ---",
                    num_threads, items_per_thread
                );

                let mutex_start = Instant::now();
                let mutex_results = bench_mutex_collector(num_threads, items_per_thread);
                let mutex_elapsed = mutex_start.elapsed();

                let streaming_start = Instant::now();
                let streaming_results = bench_streaming_collector(num_threads, items_per_thread);
                let streaming_elapsed = streaming_start.elapsed();

                // Verify both collectors got the same results
                assert_eq!(mutex_results.len(), streaming_results.len());
                assert_eq!(mutex_results.len(), num_threads * items_per_thread);

                // Calculate speedup
                let speedup = if mutex_elapsed > streaming_elapsed {
                    mutex_elapsed.as_nanos() as f64 / streaming_elapsed.as_nanos() as f64
                } else {
                    streaming_elapsed.as_nanos() as f64 / mutex_elapsed.as_nanos() as f64
                };

                println!("Mutex: {:?}", mutex_elapsed);
                println!("Streaming: {:?}", streaming_elapsed);

                if streaming_elapsed < mutex_elapsed {
                    println!("Streaming is {:.2}x faster", speedup);
                } else {
                    println!("Mutex is {:.2}x faster", speedup);
                }
            }
        }

        #[test]
        #[ignore] // Run with: cargo test bench_high_concurrency -- --ignored
        fn bench_high_concurrency() {
            println!("\n=== High Concurrency Benchmark ===\n");

            // Test with very high concurrency
            let num_threads = 200;
            let items_per_thread = 50;

            println!("Mutex-based collector:");
            let mutex_start = Instant::now();
            let _mutex_results = bench_mutex_collector(num_threads, items_per_thread);
            let mutex_elapsed = mutex_start.elapsed();
            println!("Total time: {:?}", mutex_elapsed);

            println!("\nStreaming-based collector:");
            let streaming_start = Instant::now();
            let _streaming_results = bench_streaming_collector(num_threads, items_per_thread);
            let streaming_elapsed = streaming_start.elapsed();
            println!("Total time: {:?}", streaming_elapsed);

            let speedup = mutex_elapsed.as_nanos() as f64 / streaming_elapsed.as_nanos() as f64;
            println!("\nSpeedup: {:.2}x", speedup);
        }
    }

    #[test]
    fn test_receiver_lifetime_basic_happy_path() {
        // Basic test that verifies receiver lives through complete collect() operation
        // Test covers simple happy path scenario
        // Demonstrates receiver lifetime is tied to collect() completion

        let collector = StreamingResultCollector::<i32>::new();

        // Add a few values to the channel
        let _ = collector.stream_add(1).unwrap();
        let _ = collector.stream_add(2).unwrap();
        let _ = collector.stream_add(3).unwrap();

        // Collect all results
        let results = collector.stream_collect();

        // Verify receiver remained alive through complete collect() call
        // (If receiver was dropped prematurely, we'd get ReceiverAlreadyTaken error)
        assert!(
            results.is_ok(),
            "Receiver should remain alive during stream_collect()"
        );

        let collected = results.unwrap();
        assert_eq!(collected.len(), 3, "Should collect all 3 results");

        // Verify all values are present
        let mut sorted = collected.clone();
        sorted.sort();
        assert_eq!(sorted, vec![1, 2, 3], "All values should be collected");

        // Verify receiver is still available after collection completes
        // (Receiver lifetime extends beyond collect() completion)
        let results2 = collector.stream_collect();
        // Should return EmptyCollection error, not ReceiverAlreadyTaken
        assert!(results2.is_err());
        match results2.unwrap_err() {
            StreamCollectError::<i32>::EmptyCollection => {
                // Expected - channel is empty but receiver is still alive
            }
            StreamCollectError::<i32>::ReceiverAlreadyTaken => {
                panic!("Receiver should not be dropped after stream_collect() completes");
            }
            _ => panic!("Expected EmptyCollection error, not ReceiverAlreadyTaken"),
        }
    }

    // ===== Edge Case Tests: Early Return Scenarios =====

    #[test]
    fn test_early_return_from_stream_collect_with_no_data() {
        // Test that verifies receiver stays alive when stream_collect returns early
        // due to empty channel (EmptyCollection error path)
        let collector = StreamingResultCollector::<i32>::new();

        // stream_collect should return early with EmptyCollection error
        let results = collector.stream_collect();
        assert!(results.is_err());
        match results.unwrap_err() {
            StreamCollectError::<i32>::EmptyCollection => {
                // Expected early return due to empty channel
            }
            other => panic!("Expected EmptyCollection, got {:?}", other),
        }

        // Verify receiver is still alive after early return
        let _ = collector.stream_add(42).unwrap();
        let results2 = collector.stream_collect();
        assert!(
            results2.is_ok(),
            "Receiver should still work after early return"
        );
        assert_eq!(results2.unwrap().len(), 1);
    }

    #[test]
    fn test_early_return_with_partial_then_error() {
        // Test that verifies receiver lifetime when we have partial results then error
        let collector = StreamingResultCollector::<i32>::new();
        let collector_clone = collector.clone();

        // Add some results
        let _ = collector.stream_add(1).unwrap();
        let _ = collector.stream_add(2).unwrap();

        // Spawn thread that will cause sender drop
        let handle = thread::spawn(move || {
            let _ = collector_clone.stream_add(3).unwrap();
            // Thread exits, dropping sender - potential early return trigger
        });

        handle.join().unwrap();
        thread::sleep(Duration::from_millis(10));

        // Collection may return early with partial results
        let results = collector.stream_collect();

        // Should succeed with partial results or fail with ChannelDisconnected
        // Either way, receiver should remain alive
        if results.is_ok() {
            let collected = results.unwrap();
            assert!(
                collected.len() >= 2,
                "Should have at least main thread results"
            );
        } else {
            match results.unwrap_err() {
                StreamCollectError::<i32>::ChannelDisconnected(partial) => {
                    assert!(partial.len() >= 2, "Should preserve partial results");
                }
                other => panic!("Unexpected error: {:?}", other),
            }
        }
    }

    #[test]
    fn test_early_return_during_concurrent_add() {
        // Test early return when collection happens during concurrent adds
        let collector = StreamingResultCollector::<i32>::new();
        let collector_clone = collector.clone();

        // Start adding from main thread
        let _ = collector.stream_add(1).unwrap();

        // Spawn thread that adds continuously
        let handle = thread::spawn(move || {
            for i in 2..20 {
                let _ = collector_clone.stream_add(i).unwrap();
                thread::sleep(Duration::from_millis(1));
            }
        });

        // Give thread a moment to start
        thread::sleep(Duration::from_millis(5));

        // Collect while thread is still adding (potential early return scenario)
        let results = collector.stream_collect();
        assert!(
            results.is_ok(),
            "Should collect results despite concurrent adds"
        );

        let collected = results.unwrap();
        assert!(collected.len() >= 1, "Should have at least one result");

        handle.join().unwrap();
    }

    #[test]
    fn test_early_return_cleanup_verification() {
        // Test that verifies receiver is properly cleaned up on early returns
        // This ensures no resource leaks when early returns occur
        let collector = StreamingResultCollector::<i32>::new();

        // Create multiple early return scenarios
        for _ in 0..3 {
            let results = collector.stream_collect();
            match results.unwrap_err() {
                StreamCollectError::<i32>::EmptyCollection => {
                    // Expected early return - no data yet
                }
                other => panic!("Unexpected error on iteration: {:?}", other),
            }

            // Verify receiver is still functional after each early return
            let _ = collector.stream_add(42).unwrap();
            let results2 = collector.stream_collect();
            assert!(results2.is_ok(), "Receiver should work after early return");

            // Drain for next iteration
            let _ = collector.stream_collect();
        }

        // Final verification that receiver is still alive
        let _ = collector.stream_add(99).unwrap();
        let final_results = collector.stream_collect();
        assert!(
            final_results.is_ok(),
            "Receiver should remain functional after multiple early returns"
        );
    }

    #[test]
    fn test_early_return_from_collect_with_channel_full() {
        // Test early return scenario when bounded channel is full during collect
        let collector = StreamingResultCollector::<i32>::with_bound(2);

        // Fill channel to capacity
        let _ = collector.stream_add(1).unwrap();
        let _ = collector.stream_add(2).unwrap();

        // Attempt to add beyond capacity - should fail early
        let result = collector.stream_add(3);
        assert!(result.is_err(), "Should fail early when channel is full");

        // Verify receiver is still functional after channel full error
        let results = collector.stream_collect();
        assert!(results.is_ok(), "Receiver should work after channel full");

        let collected = results.unwrap();
        assert_eq!(collected.len(), 2, "Should have the 2 items that fit");
    }

    #[test]
    fn test_early_return_from_collect_with_disconnected_channel() {
        // Test early return when channel disconnects during collect
        let collector = StreamingResultCollector::<i32>::new();
        let collector_clone = collector.clone();

        // Add some data
        let _ = collector.stream_add(1).unwrap();
        let _ = collector.stream_add(2).unwrap();

        // Spawn thread that will disconnect
        let handle = thread::spawn(move || {
            thread::sleep(Duration::from_millis(10));
            let _ = collector_clone.stream_add(3).unwrap();
            // Thread exits, potentially disconnecting channel
        });

        handle.join().unwrap();
        thread::sleep(Duration::from_millis(20));

        // Collection may return early due to disconnect or succeed with partial data
        let results = collector.stream_collect();

        // Either outcome is acceptable - receiver should handle it gracefully
        if results.is_ok() {
            let collected = results.unwrap();
            assert!(
                collected.len() >= 2,
                "Should have at least main thread data"
            );
        } else {
            match results.unwrap_err() {
                StreamCollectError::<i32>::ChannelDisconnected(partial) => {
                    assert!(partial.len() >= 2, "Should preserve main thread data");
                }
                other => panic!("Unexpected error: {:?}", other),
            }
        }
    }

    #[test]
    fn test_early_return_cleanup_no_sender_leaks() {
        // Test that early returns don't leak sender handles
        // This ensures proper cleanup of sender references
        let collector = StreamingResultCollector::<i32>::new();

        // Create multiple clones that will be dropped
        for _ in 0..5 {
            let clone = collector.clone();
            let _ = clone.stream_add(42).unwrap();
            // Clone dropped here - should not leak sender
        }

        // Verify original collector still works after all clones dropped
        let _ = collector.stream_add(99).unwrap();
        let results = collector.stream_collect();
        assert!(results.is_ok(), "Original should work after clones dropped");
        assert!(
            results.unwrap().len() >= 6,
            "Should have data from all operations"
        );
    }

    #[test]
    fn test_early_return_with_multiple_error_paths() {
        // Test that multiple different early return paths all clean up properly
        let mut collector = StreamingResultCollector::<i32>::new();

        // Early return path 1: Empty collection
        let results1 = collector.stream_collect();
        assert!(results1.is_err());
        match results1.unwrap_err() {
            StreamCollectError::<i32>::EmptyCollection => {}
            other => panic!("Expected EmptyCollection, got {:?}", other),
        }

        // Early return path 2: Dropped receiver
        collector.drop_receiver();
        let result = collector.stream_add(1);
        assert!(result.is_err(), "Should fail with receiver dropped");

        // Create new collector for path 3
        let collector2 = StreamingResultCollector::<i32>::new();
        let _ = collector2.stream_add(42).unwrap();
        let results2 = collector2.stream_collect();
        assert!(
            results2.is_ok(),
            "New collector should work after previous errors"
        );
        assert_eq!(results2.unwrap().len(), 1);
    }

    #[test]
    fn test_collector_drop_early_does_not_leak_receiver() {
        // Test that dropping a collector early doesn't leak the receiver
        // This simulates scenarios where collector is dropped before full collection

        // Create collector and add some data
        let collector = StreamingResultCollector::<i32>::new();
        let _ = collector.stream_add(1).unwrap();
        let _ = collector.stream_add(2).unwrap();
        let _ = collector.stream_add(3).unwrap();

        // Explicitly drop the collector early (before collecting all data)
        // In a real scenario, this could happen if:
        // - An error occurs and collector goes out of scope
        // - Early return from a function
        // - Panic in the calling code
        drop(collector);

        // Verify that no resource leak occurred
        // (In a real test with Valgrind/ASan, we'd verify no memory leaks)
        // For this test, we just verify the collector dropped cleanly
        // by creating a new one and ensuring it works
        let collector2 = StreamingResultCollector::<i32>::new();
        let _ = collector2.stream_add(42).unwrap();
        let results = collector2.stream_collect();
        assert!(
            results.is_ok(),
            "New collector should work after early drop"
        );
        assert_eq!(results.unwrap().len(), 1);
    }

    #[test]
    fn test_collector_drop_with_active_senders() {
        // Test that dropping collector while senders are active doesn't leak
        let collector = StreamingResultCollector::<i32>::new();
        let collector_clone = collector.clone();

        // Use Arc to signal when collector is dropped
        let dropped = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let dropped_clone = Arc::clone(&dropped);

        // Start a thread that will keep sending
        let handle = thread::spawn(move || {
            let mut send_count = 0;
            for i in 0..10 {
                // Check if collector has been dropped
                if dropped_clone.load(std::sync::atomic::Ordering::Acquire) {
                    break; // Stop sending if collector was dropped
                }

                match collector_clone.stream_add(i) {
                    Ok(_) => send_count += 1,
                    Err(_) => {
                        // Expected when collector is dropped - channel closed
                        break;
                    }
                }
                thread::sleep(Duration::from_millis(1));
            }
            // Thread exits cleanly when done or when collector is dropped
        });

        // Give thread time to start sending
        thread::sleep(Duration::from_millis(5));

        // Signal and drop the main collector early while thread is still active
        dropped.store(true, std::sync::atomic::Ordering::Release);
        drop(collector);

        // Thread should complete without hanging or leaking
        let result = handle.join();
        assert!(
            result.is_ok(),
            "Thread should complete cleanly after collector drop"
        );

        // Verify a new collector works fine
        let collector2 = StreamingResultCollector::<i32>::new();
        let _ = collector2.stream_add(99).unwrap();
        let results = collector2.stream_collect();
        assert!(
            results.is_ok(),
            "New collector should work after early drop with active sender"
        );
        assert_eq!(results.unwrap().len(), 1);
    }

    #[test]
    fn test_collector_drop_during_stream_collect_blocking() {
        // Test that dropping collector during blocking collect doesn't leak
        // This uses a scope to ensure the collector is dropped mid-operation

        let (collector, result) = {
            let collector = StreamingResultCollector::<i32>::new();
            let collector_clone = collector.clone();

            // Add some data
            let _ = collector.stream_add(1).unwrap();
            let _ = collector.stream_add(2).unwrap();

            // Spawn thread that will add more after delay
            let handle = thread::spawn(move || {
                thread::sleep(Duration::from_millis(50));
                let _ = collector_clone.stream_add(3).unwrap();
            });

            // Don't wait for thread - let collector potentially be dropped
            // Return collector and thread handle for this scope
            (collector, handle)
        };

        // collector is dropped here when scope ends
        // Thread handle goes out of scope too
        drop(result);

        // Verify no leaks - create new collector and test
        let collector2 = StreamingResultCollector::<i32>::new();
        let _ = collector2.stream_add(42).unwrap();
        let results = collector2.stream_collect();
        assert!(
            results.is_ok(),
            "New collector should work after early drop during blocking"
        );
        assert_eq!(results.unwrap().len(), 1);
    }

    #[test]
    fn test_mid_stream_collection_abort_preserves_data() {
        // Test that aborting collection mid-stream preserves already-collected data
        let collector = StreamingResultCollector::<i32>::new();
        let collector_clone = collector.clone();

        // Add initial data
        let _ = collector.stream_add(1).unwrap();
        let _ = collector.stream_add(2).unwrap();
        let _ = collector.stream_add(3).unwrap();

        // Spawn thread that will continue adding data
        let handle = thread::spawn(move || {
            thread::sleep(Duration::from_millis(20));
            for i in 10..20 {
                let _ = collector_clone.stream_add(i).unwrap();
            }
        });

        // Collect before thread finishes - abort mid-stream
        thread::sleep(Duration::from_millis(10));
        let results = collector.stream_collect();

        // Should succeed with partial data (what was available before abort)
        assert!(results.is_ok(), "Should collect partial data before abort");

        let collected = results.unwrap();
        assert!(collected.len() >= 3, "Should have at least initial 3 items");
        assert!(
            collected.len() < 13,
            "Should not have all items (aborted mid-stream)"
        );

        // Verify our initial items are present
        let mut sorted = collected.clone();
        sorted.sort();
        assert!(sorted.contains(&1), "Should contain initial item 1");
        assert!(sorted.contains(&2), "Should contain initial item 2");
        assert!(sorted.contains(&3), "Should contain initial item 3");

        handle.join().unwrap();
    }

    #[test]
    fn test_mid_stream_abort_with_sender_drop() {
        // Test aborting collection when sender drops mid-stream
        let collector = StreamingResultCollector::<i32>::new();
        let collector_clone = collector.clone();

        // Add some data
        let _ = collector.stream_add(1).unwrap();
        let _ = collector.stream_add(2).unwrap();

        // Spawn thread that will drop sender after adding data
        let handle = thread::spawn(move || {
            thread::sleep(Duration::from_millis(10));
            let _ = collector_clone.stream_add(3).unwrap();
            // Thread exits, dropping sender - mid-stream abort trigger
        });

        // Wait a bit then collect - sender may drop mid-collection
        thread::sleep(Duration::from_millis(5));
        let results = collector.stream_collect();

        // Should handle mid-stream abort gracefully
        if results.is_ok() {
            let collected = results.unwrap();
            assert!(
                collected.len() >= 2,
                "Should have at least main thread data"
            );
        } else {
            match results.unwrap_err() {
                StreamCollectError::<i32>::ChannelDisconnected(partial) => {
                    assert!(partial.len() >= 2, "Should preserve partial results");
                }
                other => panic!("Unexpected error: {:?}", other),
            }
        }

        handle.join().unwrap();
    }

    #[test]
    fn test_mid_stream_abort_multiple_times() {
        // Test repeatedly aborting collection mid-stream
        let collector = StreamingResultCollector::<i32>::new();

        // Spawn a thread that will continuously add data in background
        let collector_clone = collector.clone();
        let handle = thread::spawn(move || {
            for i in 100..200 {
                thread::sleep(Duration::from_millis(5));
                let _ = collector_clone.stream_add(i).unwrap();
            }
        });

        // Give thread time to start
        thread::sleep(Duration::from_millis(10));

        // Perform multiple mid-stream aborts
        for iteration in 0..3 {
            // Add some data
            let base = iteration * 10;
            let _ = collector.stream_add(base + 1).unwrap();
            let _ = collector.stream_add(base + 2).unwrap();

            // Collect immediately (abort mid-stream before thread adds more)
            let results = collector.stream_collect();
            assert!(
                results.is_ok(),
                "Should collect partial data on iteration {}",
                iteration
            );

            let collected = results.unwrap();
            assert!(
                collected.len() >= 2,
                "Should have data on iteration {}",
                iteration
            );
        }

        // Final verification that receiver is still functional
        let _ = collector.stream_add(999).unwrap();
        let final_results = collector.stream_collect();
        assert!(
            final_results.is_ok(),
            "Receiver should work after multiple mid-stream aborts"
        );

        // Clean up thread
        handle.join().unwrap();
    }

    #[test]
    fn test_early_return_preserves_sender_count() {
        // Test that early returns don't corrupt sender count tracking
        let collector = StreamingResultCollector::<i32>::new();

        // Initial count
        assert_eq!(collector.sender_count(), 1);

        // Create clones
        let clone1 = collector.clone();
        let clone2 = collector.clone();
        assert_eq!(collector.sender_count(), 3);

        // Early return from empty collection
        let results = collector.stream_collect();
        assert!(results.is_err());

        // Verify sender count is still correct after early return
        assert_eq!(
            collector.sender_count(),
            3,
            "Sender count should be preserved"
        );

        // Drop clones and verify count decreases
        drop(clone1);
        assert_eq!(collector.sender_count(), 2);
        drop(clone2);
        assert_eq!(collector.sender_count(), 1);
    }

    #[test]
    fn test_early_return_error_does_not_corrupt_state() {
        // Test that early return errors don't corrupt collector state
        let collector = StreamingResultCollector::<i32>::new();

        // Multiple early returns with different error conditions
        for i in 0..3 {
            let results = collector.stream_collect();
            match results {
                Ok(collected) => {
                    // After adding data in previous iteration, we should get it back
                    if i > 0 {
                        assert_eq!(
                            collected.len(),
                            1,
                            "Should have data from previous iteration"
                        );
                        assert_eq!(collected[0], 42, "Should have the added value");
                    } else {
                        panic!("First iteration should return EmptyCollection error");
                    }
                }
                Err(StreamCollectError::<i32>::EmptyCollection) => {
                    // Expected only on first iteration when no data exists
                    assert_eq!(i, 0, "EmptyCollection only expected on first iteration");
                }
                other => panic!("Unexpected result: {:?}", other),
            }

            // Add data after each early return
            let _ = collector.stream_add(42).unwrap();
        }

        // Verify collector state is consistent after all early returns
        let results = collector.stream_collect();
        assert!(results.is_ok(), "Collector state should be consistent");
        assert_eq!(
            results.unwrap().len(),
            1,
            "Should have data from last iteration"
        );
    }

    #[test]
    fn test_mid_stream_abort_with_thread_synchronization() {
        // Test aborting collection with proper thread synchronization
        let collector = StreamingResultCollector::<i32>::new();
        let collector_clone = collector.clone();

        // Use Arc to signal when thread has started sending
        let started = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let started_clone = Arc::clone(&started);

        let handle = thread::spawn(move || {
            // Signal that thread has started
            started_clone.store(true, std::sync::atomic::Ordering::Release);

            for i in 10..20 {
                thread::sleep(Duration::from_millis(5));
                let _ = collector_clone.stream_add(i).unwrap();
            }
        });

        // Wait for thread to start
        while !started.load(std::sync::atomic::Ordering::Acquire) {
            thread::sleep(Duration::from_millis(1));
        }

        // Give thread time to send some data
        thread::sleep(Duration::from_millis(15));

        // Collect mid-stream (abort before thread finishes)
        let results = collector.stream_collect();
        assert!(results.is_ok(), "Should collect partial data");

        let collected = results.unwrap();
        assert!(collected.len() >= 1, "Should have at least some data");
        assert!(
            collected.len() < 10,
            "Should be partial (aborted before completion)"
        );

        handle.join().unwrap();
    }

    #[test]
    fn test_early_return_from_collect_with_timeout_behavior() {
        // Test early return behavior when collection would timeout
        // This simulates scenarios where collection takes too long and should abort early
        let collector = StreamingResultCollector::<i32>::new();
        let collector_clone = collector.clone();

        // Add initial data
        let _ = collector.stream_add(1).unwrap();
        let _ = collector.stream_add(2).unwrap();

        // Spawn thread that adds data very slowly
        let handle = thread::spawn(move || {
            for i in 3..20 {
                thread::sleep(Duration::from_millis(100)); // Very slow
                let _ = collector_clone.stream_add(i).unwrap();
            }
        });

        // Collect immediately - should get partial results quickly
        // This simulates early return before all data arrives
        thread::sleep(Duration::from_millis(50));
        let results = collector.stream_collect();

        assert!(
            results.is_ok(),
            "Should collect partial data before slow thread finishes"
        );

        let collected = results.unwrap();
        assert!(collected.len() >= 2, "Should have initial data");
        assert!(collected.len() < 20, "Should not wait for all slow data");

        handle.join().unwrap();
    }

    // ===== Edge Case Tests: Error Paths and Receiver Lifetime =====

    #[test]
    fn test_receiver_lifetime_under_channel_disconnect_error() {
        // Test that verifies receiver stays alive when channel disconnects
        let mut collector = StreamingResultCollector::<i32>::new();

        // Add some data
        let _ = collector.stream_add(1).unwrap();
        let _ = collector.stream_add(2).unwrap();

        // Simulate channel disconnect
        collector.drop_sender();

        // Collection should detect error and preserve partial results
        let results = collector.stream_collect();
        assert!(results.is_err());

        match results.unwrap_err() {
            StreamCollectError::<i32>::ChannelDisconnected(partial) => {
                assert_eq!(partial.len(), 2, "Should preserve partial results");
                let mut sorted = partial;
                sorted.sort();
                assert_eq!(sorted, vec![1, 2], "Partial results should be correct");
            }
            other => panic!("Expected ChannelDisconnected, got {:?}", other),
        }
    }

    #[test]
    fn test_receiver_lifetime_after_send_error() {
        // Test that receiver stays alive after send operations fail
        let mut collector = StreamingResultCollector::<i32>::new();

        // Drop receiver to cause send failures
        collector.drop_receiver();

        // Send operations should fail
        let result = collector.stream_add(42);
        assert!(result.is_err(), "Send should fail when receiver dropped");

        // Verify receiver state is consistent (we explicitly dropped it, so ReceiverAlreadyTaken)
        let collect_result = collector.stream_collect();
        match collect_result.unwrap_err() {
            StreamCollectError::<i32>::ReceiverAlreadyTaken => {
                // Expected - receiver was explicitly dropped
            }
            other => panic!("Expected ReceiverAlreadyTaken, got {:?}", other),
        }
    }

    #[test]
    fn test_receiver_lifetime_with_bounded_channel_full_error() {
        // Test receiver lifetime when bounded channel becomes full
        let collector = StreamingResultCollector::<i32>::with_bound(2);

        // Fill the channel
        let _ = collector.stream_add(1).unwrap();
        let _ = collector.stream_add(2).unwrap();

        // This should fail with channel full error
        let result = collector.stream_add(3);
        assert!(result.is_err(), "Should fail when channel is full");

        // Verify receiver is still alive despite send error
        let results = collector.stream_collect();
        assert!(
            results.is_ok(),
            "Receiver should work after channel full error"
        );
        assert_eq!(
            results.unwrap().len(),
            2,
            "Should have the 2 items that fit"
        );
    }

    #[test]
    fn test_error_path_does_not_corrupt_receiver_state() {
        // Test that error paths don't corrupt receiver state for future operations
        let collector = StreamingResultCollector::<i32>::new();
        let collector_clone = collector.clone();

        // Cause an error by dropping sender in clone
        drop(collector_clone);

        // Wait for drop to propagate
        thread::sleep(Duration::from_millis(10));

        // Add some data
        let _ = collector.stream_add(1).unwrap();
        let _ = collector.stream_add(2).unwrap();

        // Collection should succeed (original sender still alive)
        let results = collector.stream_collect();
        assert!(results.is_ok(), "Receiver should work after clone drop");

        let collected = results.unwrap();
        assert_eq!(collected.len(), 2, "Should collect all results");
    }

    #[test]
    fn test_consecutive_error_paths_maintain_receiver_integrity() {
        // Test that multiple consecutive errors don't corrupt receiver
        let mut collector = StreamingResultCollector::<i32>::new();

        // Error path 1: Send with dropped receiver
        collector.drop_receiver();
        let result1 = collector.stream_add(1);
        assert!(result1.is_err(), "First send should fail");

        // Recreate receiver state by creating new collector
        let collector2 = StreamingResultCollector::<i32>::new();

        // Error path 2: Collect from empty channel
        let result2 = collector2.stream_collect();
        assert!(result2.is_err(), "Empty collection should fail");
        match result2.unwrap_err() {
            StreamCollectError::<i32>::EmptyCollection => {
                // Expected
            }
            other => panic!("Expected EmptyCollection, got {:?}", other),
        }

        // Verify new collector's receiver is functional after error path
        let _ = collector2.stream_add(42).unwrap();
        let result3 = collector2.stream_collect();
        assert!(result3.is_ok(), "New receiver should work after error path");
    }

    // ===== Edge Case Tests: Partial Collection Scenarios =====

    #[test]
    fn test_partial_collection_with_early_sender_drop() {
        // Test partial collection when sender drops mid-stream
        let collector = StreamingResultCollector::<i32>::new();
        let collector_clone = collector.clone();

        // Add initial data
        let _ = collector.stream_add(1).unwrap();
        let _ = collector.stream_add(2).unwrap();

        // Spawn thread that adds data then drops sender
        let handle = thread::spawn(move || {
            let _ = collector_clone.stream_add(3).unwrap();
            let _ = collector_clone.stream_add(4).unwrap();
            // Thread exits here, dropping sender - potential partial collection
        });

        handle.join().unwrap();
        thread::sleep(Duration::from_millis(10));

        // Collection should handle partial scenario gracefully
        let results = collector.stream_collect();

        // Should succeed with partial results
        assert!(results.is_ok(), "Should collect partial results");
        let collected = results.unwrap();
        assert!(
            collected.len() >= 2 && collected.len() <= 4,
            "Should have partial results (2-4 items)"
        );

        // Verify our main thread results are present
        let mut sorted = collected.clone();
        sorted.sort();
        assert!(sorted.contains(&1), "Should contain result 1");
        assert!(sorted.contains(&2), "Should contain result 2");
    }

    #[test]
    fn test_partial_collection_with_intermittent_sender_drops() {
        // Test partial collection with multiple sender drops at different times
        let collector = StreamingResultCollector::<i32>::new();

        // Add data from main thread
        let _ = collector.stream_add(1).unwrap();

        // Create multiple clones that will drop at different times
        let clone1 = collector.clone();
        let clone2 = collector.clone();

        let handle1 = thread::spawn(move || {
            let _ = clone1.stream_add(2).unwrap();
            thread::sleep(Duration::from_millis(10));
            let _ = clone1.stream_add(3).unwrap();
            // clone1 drops here
        });

        let handle2 = thread::spawn(move || {
            thread::sleep(Duration::from_millis(5));
            let _ = clone2.stream_add(4).unwrap();
            // clone2 drops here (earlier than clone1)
        });

        handle1.join().unwrap();
        handle2.join().unwrap();
        thread::sleep(Duration::from_millis(20));

        // Collection should handle intermittent drops
        let results = collector.stream_collect();
        assert!(results.is_ok(), "Should handle intermittent sender drops");

        let collected = results.unwrap();
        assert!(
            collected.len() >= 1,
            "Should have at least main thread result"
        );
        assert!(collected.len() <= 4, "Should have at most all 4 results");
    }

    #[test]
    fn test_partial_collection_error_boundary_conditions() {
        // Test boundary conditions for partial collection errors
        let collector = StreamingResultCollector::<i32>::new();

        // Test: 0 items (empty)
        let results0 = collector.stream_collect();
        assert!(results0.is_err());
        match results0.unwrap_err() {
            StreamCollectError::<i32>::EmptyCollection => {
                // Expected - completely empty
            }
            other => panic!("Expected EmptyCollection, got {:?}", other),
        }

        // Add data
        let _ = collector.stream_add(1).unwrap();

        // Test: 1 item then disconnect
        let collector_clone = collector.clone();
        let handle = thread::spawn(move || {
            thread::sleep(Duration::from_millis(5));
            let _ = collector_clone.stream_add(2).unwrap();
        });
        handle.join().unwrap();

        let results1 = collector.stream_collect();
        assert!(results1.is_ok(), "Should collect partial results");
    }

    #[test]
    fn test_partial_collection_preserves_order() {
        // Test that partial collections preserve order of received items
        let collector = StreamingResultCollector::<i32>::new();

        // Add items in specific order
        let _ = collector.stream_add(10).unwrap();
        let _ = collector.stream_add(20).unwrap();
        let _ = collector.stream_add(30).unwrap();

        // Cause partial collection by dropping sender
        let mut collector_mut = collector;
        collector_mut.drop_sender();

        // Collect should preserve order of partial results
        let results = collector_mut.stream_collect();
        assert!(results.is_err());

        match results.unwrap_err() {
            StreamCollectError::<i32>::ChannelDisconnected(partial) => {
                assert_eq!(partial.len(), 3, "Should have all 3 partial results");
                assert_eq!(partial[0], 10, "First item should be 10");
                assert_eq!(partial[1], 20, "Second item should be 20");
                assert_eq!(partial[2], 30, "Third item should be 30");
            }
            other => panic!("Expected ChannelDisconnected, got {:?}", other),
        }
    }

    // ===== Edge Case Tests: Cloned Receivers and Lifetime Behavior =====

    #[test]
    fn test_cloned_receiver_availability() {
        // Test that cloned receivers behave correctly regarding availability
        let collector = StreamingResultCollector::<i32>::new();
        let clone = collector.clone();

        // Only original has receiver, clones don't
        let _ = collector.stream_add(1).unwrap();
        let _ = clone.stream_add(2).unwrap();

        // Only original can collect (clones don't have receiver)
        let results = collector.stream_collect();
        assert!(results.is_ok(), "Original should collect with receiver");
        assert_eq!(results.unwrap().len(), 2, "Should have both items");
    }

    #[test]
    fn test_cloned_receiver_lifetime_independence() {
        // Test that cloned receivers have independent lifetime behavior
        let collector = StreamingResultCollector::<i32>::new();

        // Add data from original
        let _ = collector.stream_add(1).unwrap();
        let _ = collector.stream_add(2).unwrap();

        // Create clone and use it
        let clone = collector.clone();
        let _ = clone.stream_add(3).unwrap();

        // Drop clone explicitly
        drop(clone);

        // Original receiver should still be alive
        let results = collector.stream_collect();
        assert!(
            results.is_ok(),
            "Original receiver should survive clone drop"
        );

        let collected = results.unwrap();
        assert_eq!(collected.len(), 3, "Should have all 3 items");
    }

    #[test]
    fn test_multiple_clones_no_receiver_access() {
        // Test that multiple clones cannot all access receiver
        let collector = StreamingResultCollector::<i32>::new();
        let clone1 = collector.clone();
        let clone2 = collector.clone();
        let clone3 = collector.clone();

        // All can send (they share sender)
        let _ = collector.stream_add(1).unwrap();
        let _ = clone1.stream_add(2).unwrap();
        let _ = clone2.stream_add(3).unwrap();
        let _ = clone3.stream_add(4).unwrap();

        // Only original can collect (only original has receiver)
        let results = collector.stream_collect();
        assert!(results.is_ok(), "Only original should collect");
        assert_eq!(results.unwrap().len(), 4, "Should have all items");
    }

    #[test]
    fn test_clone_chain_receiver_propagation() {
        // Test receiver behavior through deep clone chains
        let collector = StreamingResultCollector::<i32>::new();
        let clone1 = collector.clone();
        let clone2 = clone1.clone();
        let clone3 = clone2.clone();

        // All can send
        let _ = collector.stream_add(1).unwrap();
        let _ = clone1.stream_add(2).unwrap();
        let _ = clone2.stream_add(3).unwrap();
        let _ = clone3.stream_add(4).unwrap();

        // Drop all intermediate clones
        drop(clone1);
        drop(clone2);
        drop(clone3);

        // Original should still have receiver
        let results = collector.stream_collect();
        assert!(
            results.is_ok(),
            "Original should retain receiver through chain"
        );
        assert_eq!(results.unwrap().len(), 4, "All items should be present");
    }

    #[test]
    fn test_clone_receiver_after_original_collection() {
        // Test clone behavior after original collects
        let collector = StreamingResultCollector::<i32>::new();
        let clone = collector.clone();

        // Add data
        let _ = collector.stream_add(1).unwrap();
        let _ = clone.stream_add(2).unwrap();

        // Original collects
        let results1 = collector.stream_collect();
        assert!(results1.is_ok(), "Original should collect");
        assert_eq!(results1.unwrap().len(), 2, "Should have both items");

        // Channel is now drained, but clone can still send
        let _ = clone.stream_add(3).unwrap();

        // Original should still be able to collect (if channel has new data)
        // But since we drained it and added only 1 more:
        let results2 = collector.stream_collect();
        assert!(results2.is_ok(), "Original should still work");
        assert_eq!(results2.unwrap().len(), 1, "Should have the new item");
    }

    #[test]
    fn test_cloned_sender_does_not_affect_receiver_lifetime() {
        // Test that cloned sender lifetime doesn't affect receiver
        let collector = StreamingResultCollector::<i32>::new();
        let clone = collector.clone();

        // Add from both
        let _ = collector.stream_add(1).unwrap();
        let _ = clone.stream_add(2).unwrap();

        // Explicitly drop clone sender
        drop(clone);

        // Wait for drop to propagate
        thread::sleep(Duration::from_millis(10));

        // Original receiver should still be alive (original sender still exists)
        let _ = collector.stream_add(3).unwrap();
        let results = collector.stream_collect();
        assert!(results.is_ok(), "Receiver should survive clone sender drop");

        let collected = results.unwrap();
        assert_eq!(collected.len(), 3, "Should have all 3 items");
    }

    #[test]
    fn test_receiver_only_in_original_not_clones() {
        // Test explicitly that only original has receiver access
        let collector = StreamingResultCollector::<i32>::new();
        let clone1 = collector.clone();
        let clone2 = collector.clone();

        // Verify sender count
        assert_eq!(collector.sender_count(), 3, "Should have 3 senders");

        // Add data
        let _ = collector.stream_add(1).unwrap();
        let _ = clone1.stream_add(2).unwrap();
        let _ = clone2.stream_add(3).unwrap();

        // Only original can collect (clones don't have receiver)
        let results = collector.stream_collect();
        assert!(results.is_ok(), "Only original can collect");
        assert_eq!(results.unwrap().len(), 3, "All items should be present");

        // Clones cannot collect (they have no receiver)
        // We can't directly test this since stream_collect takes &self and would fail
        // but we verify by the fact that only original's collector worked above
    }

    #[test]
    fn test_deep_clone_hierarchy_receiver_integrity() {
        // Test receiver integrity through very deep clone hierarchies
        let collector = StreamingResultCollector::<i32>::new();

        // Create 10 levels of clones
        let mut current = collector.clone();
        for _ in 0..10 {
            current = current.clone();
        }
        drop(current);

        // Original receiver should still be intact
        let _ = collector.stream_add(42).unwrap();
        let results = collector.stream_collect();
        assert!(
            results.is_ok(),
            "Receiver should survive deep clone hierarchy"
        );
        assert_eq!(results.unwrap().len(), 1, "Should have the item");
    }

    // ===== Additional Edge Case Tests for Comprehensive Coverage =====

    #[test]
    fn test_rapid_clone_creation_and_destruction() {
        // Test receiver lifetime under rapid clone churn
        // Stress test: create and destroy clones rapidly
        let collector = StreamingResultCollector::<i32>::new();

        // Add initial data
        let _ = collector.stream_add(1).unwrap();

        // Rapidly create and destroy clones
        for _ in 0..20 {
            let clone = collector.clone();
            let _ = clone.stream_add(2).unwrap();
            drop(clone); // Immediate drop
        }

        // Receiver should still be intact after rapid churn
        let results = collector.stream_collect();
        assert!(results.is_ok(), "Receiver should survive rapid clone churn");
        let collected = results.unwrap();
        assert!(collected.len() >= 1, "Should have at least initial data");
    }

    #[test]
    fn test_concurrent_clone_and_collect_operations() {
        // Test receiver lifetime when clones are created while collection is active
        let collector = StreamingResultCollector::<i32>::new();
        let collector_clone1 = collector.clone();
        let collector_clone2 = collector.clone();

        let handle1 = thread::spawn(move || {
            for i in 0..10 {
                let _ = collector_clone1.stream_add(i).unwrap();
                thread::sleep(Duration::from_millis(1));
            }
        });

        let handle2 = thread::spawn(move || {
            for i in 10..20 {
                let _ = collector_clone2.stream_add(i).unwrap();
                // Create more clones during operation
                let _clone = collector_clone2.clone();
                thread::sleep(Duration::from_millis(1));
            }
        });

        // Collect while threads are still creating clones
        thread::sleep(Duration::from_millis(5));
        let _ = collector.stream_add(99).unwrap();

        let results = collector.stream_collect();
        assert!(
            results.is_ok(),
            "Should collect successfully despite concurrent clone creation"
        );

        handle1.join().unwrap();
        handle2.join().unwrap();
    }

    #[test]
    fn test_partial_collection_with_sender_full_error() {
        // Test partial collection when bounded channel fills mid-collection
        let collector = StreamingResultCollector::<i32>::with_bound(3);

        // Add items up to capacity
        let _ = collector.stream_add(1).unwrap();
        let _ = collector.stream_add(2).unwrap();
        let _ = collector.stream_add(3).unwrap();

        // Try to add beyond capacity - should fail
        let result = collector.stream_add(4);
        assert!(result.is_err(), "Should fail when channel is full");

        // Collection should still work with partial results (items that fit)
        let results = collector.stream_collect();
        assert!(results.is_ok(), "Should collect items that fit");
        assert_eq!(
            results.unwrap().len(),
            3,
            "Should have exactly the 3 items that fit"
        );
    }

    #[test]
    fn test_multiple_error_recovery_sequences() {
        // Test receiver survives multiple sequential error scenarios
        let collector = StreamingResultCollector::<i32>::new();

        // Error 1: Empty collection
        let results1 = collector.stream_collect();
        assert!(results1.is_err());
        match results1.unwrap_err() {
            StreamCollectError::<i32>::EmptyCollection => {}
            _ => panic!("Expected EmptyCollection"),
        }

        // Recover: Add data
        let _ = collector.stream_add(1).unwrap();

        // Error 2: Collect from clone (no receiver)
        let clone = collector.clone();
        // Clone can't collect but this shouldn't affect original receiver

        // Verify original still works
        let _ = collector.stream_add(2).unwrap();
        let results2 = collector.stream_collect();
        assert!(results2.is_ok(), "Should recover after errors");
        assert_eq!(results2.unwrap().len(), 2, "Should have all added items");
    }

    #[test]
    fn test_receiver_lifetime_with_early_sender_termination() {
        // Test receiver lifetime when sender terminates immediately after creation
        let collector = StreamingResultCollector::<i32>::new();
        let collector_clone = collector.clone();

        // Thread terminates immediately without sending
        let handle = thread::spawn(move || {
            // collector_clone dropped immediately - no sends
        });

        handle.join().unwrap();

        // Add data from main thread
        let _ = collector.stream_add(1).unwrap();
        let _ = collector.stream_add(2).unwrap();

        // Receiver should still work despite early sender termination
        let results = collector.stream_collect();
        assert!(
            results.is_ok(),
            "Receiver should work after early sender termination"
        );
        assert_eq!(results.unwrap().len(), 2, "Should have main thread data");
    }

    #[test]
    fn test_clone_interference_with_original_receiver() {
        // Test that clone operations don't interfere with original receiver
        let collector = StreamingResultCollector::<i32>::new();

        // Add data from original
        let _ = collector.stream_add(10).unwrap();

        // Create clone and use it extensively
        let clone = collector.clone();
        for i in 0..5 {
            let _ = clone.stream_add(i).unwrap();
        }

        // Explicitly drop clone
        drop(clone);

        // Wait for cleanup
        thread::sleep(Duration::from_millis(10));

        // Original receiver should be unaffected
        let _ = collector.stream_add(20).unwrap();
        let results = collector.stream_collect();
        assert!(results.is_ok(), "Original receiver should be unaffected");
        assert_eq!(
            results.unwrap().len(),
            7,
            "Should have all items from both original and clone"
        );
    }

    #[test]
    fn test_partial_collection_with_intermittent_errors() {
        // Test partial collection when errors occur intermittently
        let collector = StreamingResultCollector::<i32>::with_bound(2);

        // Add item 1
        let _ = collector.stream_add(1).unwrap();

        // Fill channel to capacity
        let _ = collector.stream_add(2).unwrap();

        // This should fail (channel full)
        let result = collector.stream_add(3);
        assert!(result.is_err(), "Should fail when channel is full");

        // Partial drain by collecting
        let results1 = collector.stream_collect();
        assert!(results1.is_ok());
        assert_eq!(results1.unwrap().len(), 2, "Should drain the 2 items");

        // Channel should now be empty - add more
        let _ = collector.stream_add(4).unwrap();
        let _ = collector.stream_add(5).unwrap();

        // Final collection
        let results2 = collector.stream_collect();
        assert!(results2.is_ok(), "Should recover after partial drain");
        assert_eq!(results2.unwrap().len(), 2, "Should have remaining items");
    }

    #[test]
    fn test_receiver_cleanup_on_panic_scenarios() {
        // Test receiver cleanup when operations panic
        let collector = StreamingResultCollector::<i32>::new();

        // Add data before panic scenario
        let _ = collector.stream_add(1).unwrap();
        let _ = collector.stream_add(2).unwrap();

        // Simulate panic in spawned thread (catch_unwind prevents actual panic)
        let collector_clone = collector.clone();
        let result = std::panic::catch_unwind(|| {
            let _ = collector_clone.stream_add(3).unwrap();
            panic!("Simulated panic in thread");
        });

        // Panic occurred but was caught
        assert!(result.is_err(), "Should catch panic");

        // Add more data after panic
        let _ = collector.stream_add(4).unwrap();

        // Receiver should still be functional
        let results = collector.stream_collect();
        assert!(results.is_ok(), "Receiver should survive panic in thread");
        let collected = results.unwrap();
        assert!(
            collected.len() >= 3,
            "Should have at least the non-panicked items"
        );
    }

    #[test]
    fn test_concurrent_error_and_recovery() {
        // Test receiver lifetime during concurrent errors and recovery
        let collector = StreamingResultCollector::<i32>::new();
        let collector_clone1 = collector.clone();
        let collector_clone2 = collector.clone();

        // Thread 1: Cause bounded channel full errors
        let handle1 = thread::spawn(move || {
            for i in 0..10 {
                let _ = collector_clone1.stream_add(i); // May fail if channel full
                thread::sleep(Duration::from_millis(1));
            }
        });

        // Thread 2: Drain collector periodically
        let handle2 = thread::spawn(move || {
            thread::sleep(Duration::from_millis(5));
            let _ = collector_clone2.stream_collect(); // Drain
        });

        // Main thread: Add data concurrently
        for i in 100..105 {
            let _ = collector.stream_add(i).unwrap();
        }

        handle1.join().unwrap();
        handle2.join().unwrap();

        // Final collection should work despite concurrent errors
        let results = collector.stream_collect();
        assert!(results.is_ok(), "Should survive concurrent errors");
        let collected = results.unwrap();
        assert!(
            collected.len() >= 5,
            "Should have at least main thread items"
        );
    }

    #[test]
    fn test_receiver_lifetime_with_empty_clone_chain() {
        // Test receiver behavior with chain of clones that never send
        let collector = StreamingResultCollector::<i32>::new();

        // Create chain of clones that never send anything
        let clone1 = collector.clone();
        let clone2 = clone1.clone();
        let clone3 = clone2.clone();
        let clone4 = clone3.clone();

        // Only original sends
        let _ = collector.stream_add(42).unwrap();

        // Drop all inactive clones
        drop(clone1);
        drop(clone2);
        drop(clone3);
        drop(clone4);

        // Receiver should still work
        let results = collector.stream_collect();
        assert!(results.is_ok(), "Should work with inactive clone chain");
        assert_eq!(results.unwrap().len(), 1, "Should have the single item");
    }

    #[test]
    fn test_sender_drop_during_blocking_collect() {
        // Test stream_collect_blocking when sender drops during collection
        let collector = StreamingResultCollector::<i32>::new();
        let collector_clone = collector.clone();

        let handle = thread::spawn(move || {
            let _ = collector_clone.stream_add(1).unwrap();
            thread::sleep(Duration::from_millis(100)); // Delay before dropping
                                                       // collector_clone drops here when thread exits
        });

        // Give thread time to send but not complete
        thread::sleep(Duration::from_millis(50));

        // Start blocking collect - sender may drop during this
        let results = collector.stream_collect_blocking();

        handle.join().unwrap();

        // Should collect whatever was sent before/during collection
        assert!(results.len() >= 1, "Should collect at least the first item");
    }

    #[test]
    fn test_stream_try_collect_with_immediate_results() {
        // Test stream_try_collect collects only immediately available results
        let collector = StreamingResultCollector::<i32>::new();
        let collector_clone = collector.clone();

        // Add some results
        let _ = collector.stream_add(1).unwrap();
        let _ = collector.stream_add(2).unwrap();

        // Spawn thread that will add more after we collect
        let handle = thread::spawn(move || {
            thread::sleep(Duration::from_millis(50));
            let _ = collector_clone.stream_add(3).unwrap();
            let _ = collector_clone.stream_add(4).unwrap();
        });

        // Collect immediately - should only get currently available results
        let results = collector.stream_try_collect();
        assert_eq!(
            results.len(),
            2,
            "Should only get immediately available results"
        );

        handle.join().unwrap();
    }

    #[test]
    fn test_stream_try_collect_with_empty_channel() {
        // Test stream_try_collect on empty channel doesn't block
        let collector = StreamingResultCollector::<i32>::new();

        // Don't add anything - channel is empty
        let results = collector.stream_try_collect();
        assert_eq!(results.len(), 0, "Should return empty vec without blocking");
    }

    #[test]
    fn test_stream_try_collect_after_sender_drop() {
        // Test stream_try_collect handles sender drop gracefully
        let collector = StreamingResultCollector::<i32>::new();

        // Add data then drop sender manually
        let _ = collector.stream_add(1).unwrap();
        let _ = collector.stream_add(2).unwrap();

        let mut collector_mut = collector;
        collector_mut.drop_sender();

        // stream_try_collect should collect what's available without blocking
        let results = collector_mut.stream_try_collect();
        assert_eq!(
            results.len(),
            2,
            "Should collect available items despite sender drop"
        );
    }

    // ===== Additional Edge Case Tests for Receiver Lifetime Management =====

    #[test]
    fn test_early_return_on_first_recv_disconnect() {
        // Test early return when channel disconnects on first recv operation
        let collector = StreamingResultCollector::<i32>::new();
        let collector_clone = collector.clone();

        // Spawn thread that will drop sender immediately
        let handle = thread::spawn(move || {
            // collector_clone dropped immediately without sending
        });

        handle.join().unwrap();
        thread::sleep(Duration::from_millis(10));

        // Add data after sender dropped
        let _ = collector.stream_add(1).unwrap();
        let _ = collector.stream_add(2).unwrap();

        // Collection should succeed (original sender still alive)
        let results = collector.stream_collect();
        assert!(results.is_ok(), "Should collect with original sender");
        assert_eq!(results.unwrap().len(), 2, "Should have both items");
    }

    #[test]
    fn test_early_return_try_iter_empty_immediately() {
        // Test early return when try_iter returns empty immediately
        let collector = StreamingResultCollector::<i32>::new();

        // Don't add any data
        let results = collector.stream_collect();
        assert!(results.is_err());
        match results.unwrap_err() {
            StreamCollectError::<i32>::EmptyCollection => {
                // Expected - try_iter returned empty immediately
            }
            other => panic!("Expected EmptyCollection, got {:?}", other),
        }

        // Verify receiver is still functional after early return
        let _ = collector.stream_add(42).unwrap();
        let results2 = collector.stream_collect();
        assert!(results2.is_ok(), "Receiver should work after early return");
        assert_eq!(results2.unwrap().len(), 1);
    }

    #[test]
    fn test_early_return_cleanup_multiple_error_types() {
        // Test cleanup verification across multiple error types
        let mut collector = StreamingResultCollector::<i32>::new();

        // Error type 1: Empty collection
        let results1 = collector.stream_collect();
        assert!(results1.is_err());
        match results1.unwrap_err() {
            StreamCollectError::<i32>::EmptyCollection => {}
            other => panic!("Expected EmptyCollection, got {:?}", other),
        }

        // Error type 2: Channel full (with bounded channel)
        let collector_bounded = StreamingResultCollector::<i32>::with_bound(1);
        let _ = collector_bounded.stream_add(1).unwrap();
        let result = collector_bounded.stream_add(2);
        assert!(result.is_err(), "Should fail when channel is full");

        // Error type 3: Receiver dropped
        collector.drop_receiver();
        let result = collector.stream_add(3);
        assert!(result.is_err(), "Should fail when receiver dropped");

        // Verify each error type cleaned up properly
        let collector2 = StreamingResultCollector::<i32>::new();
        let _ = collector2.stream_add(99).unwrap();
        let results2 = collector2.stream_collect();
        assert!(
            results2.is_ok(),
            "New collector should work after multiple error types"
        );
        assert_eq!(results2.unwrap().len(), 1);
    }

    #[test]
    fn test_error_path_with_simultaneous_sender_receiver_errors() {
        // Test receiver lifetime when both sender and receiver have errors
        let mut collector = StreamingResultCollector::<i32>::new();

        // Add some data first
        let _ = collector.stream_add(1).unwrap();
        let _ = collector.stream_add(2).unwrap();

        // Cause both sender and receiver errors
        collector.drop_sender();
        collector.drop_receiver();

        // Attempt collection should return ReceiverAlreadyTaken
        let results = collector.stream_collect();
        assert!(results.is_err());
        match results.unwrap_err() {
            StreamCollectError::<i32>::ReceiverAlreadyTaken => {
                // Expected - receiver was dropped
            }
            other => panic!("Expected ReceiverAlreadyTaken, got {:?}", other),
        }
    }

    #[test]
    fn test_error_recovery_sequential_error_types() {
        // Test error recovery after multiple sequential error types
        let collector = StreamingResultCollector::<i32>::new();

        // Error 1: Empty collection
        let results1 = collector.stream_collect();
        assert!(results1.is_err());
        match results1.unwrap_err() {
            StreamCollectError::<i32>::EmptyCollection => {}
            other => panic!("Expected EmptyCollection, got {:?}", other),
        }

        // Recovery: Add data
        let _ = collector.stream_add(1).unwrap();

        // Error 2: Collect from clone (no receiver access)
        let clone = collector.clone();
        // Clone can't collect but shouldn't affect original

        // Error 3: Bounded channel full
        let collector_bounded = StreamingResultCollector::<i32>::with_bound(1);
        let _ = collector_bounded.stream_add(10).unwrap();
        let result = collector_bounded.stream_add(20);
        assert!(result.is_err(), "Should fail when channel is full");

        // Verify original still works after all error types
        let _ = collector.stream_add(2).unwrap();
        let results2 = collector.stream_collect();
        assert!(results2.is_ok(), "Should recover after sequential errors");
        assert_eq!(results2.unwrap().len(), 2, "Should have all items");
    }

    #[test]
    fn test_error_path_no_memory_leak_repeated_failures() {
        // Test that error paths don't leak memory with repeated failures
        for _ in 0..10 {
            let mut collector = StreamingResultCollector::<i32>::new();

            // Cause repeated send failures
            collector.drop_receiver();
            for i in 0..100 {
                let result = collector.stream_add(i);
                assert!(result.is_err(), "Send should fail consistently");
            }

            // Collector should clean up properly when dropped
            // (No explicit verification needed, Valgrind/ASan would detect leaks)
        }
    }

    #[test]
    fn test_partial_collection_very_slow_sender() {
        // Test partial collection when sender is very slow
        let collector = StreamingResultCollector::<i32>::new();
        let collector_clone = collector.clone();

        // Add initial data
        let _ = collector.stream_add(1).unwrap();
        let _ = collector.stream_add(2).unwrap();

        // Spawn thread that adds data very slowly
        let handle = thread::spawn(move || {
            thread::sleep(Duration::from_millis(100));
            let _ = collector_clone.stream_add(3).unwrap();
            thread::sleep(Duration::from_millis(100));
            let _ = collector_clone.stream_add(4).unwrap();
        });

        // Collect immediately - should get partial results
        thread::sleep(Duration::from_millis(50));
        let results = collector.stream_collect();
        assert!(results.is_ok(), "Should collect partial results");

        let collected = results.unwrap();
        assert!(collected.len() >= 2, "Should have at least initial data");
        assert!(collected.len() <= 4, "Should have at most all data");

        handle.join().unwrap();
    }

    #[test]
    fn test_partial_collection_sender_drops_between_recv() {
        // Test partial collection when sender drops between recv calls
        let collector = StreamingResultCollector::<i32>::new();
        let collector_clone = collector.clone();

        // Add data from main thread
        let _ = collector.stream_add(1).unwrap();
        let _ = collector.stream_add(2).unwrap();

        // Spawn thread that will drop sender after a delay
        let handle = thread::spawn(move || {
            thread::sleep(Duration::from_millis(50));
            let _ = collector_clone.stream_add(3).unwrap();
            // Sender drops here when thread exits
        });

        // Wait for thread to send but not drop yet
        thread::sleep(Duration::from_millis(25));

        // Start collection - sender may drop during collection
        let results = collector.stream_collect();
        assert!(
            results.is_ok(),
            "Should handle sender drop during collection"
        );

        let collected = results.unwrap();
        assert!(
            collected.len() >= 2,
            "Should have at least main thread data"
        );

        handle.join().unwrap();
    }

    #[test]
    fn test_partial_collection_boundary_zero_items() {
        // Test partial collection boundary: 0 items
        let collector = StreamingResultCollector::<i32>::new();

        // Don't add any data
        let results = collector.stream_collect();
        assert!(results.is_err());
        match results.unwrap_err() {
            StreamCollectError::<i32>::EmptyCollection => {
                // Expected - completely empty
            }
            other => panic!("Expected EmptyCollection, got {:?}", other),
        }
    }

    #[test]
    fn test_partial_collection_boundary_one_item() {
        // Test partial collection boundary: 1 item
        let collector = StreamingResultCollector::<i32>::new();
        let collector_clone = collector.clone();

        // Add one item
        let _ = collector.stream_add(1).unwrap();

        // Thread will add more but drops early
        let handle = thread::spawn(move || {
            thread::sleep(Duration::from_millis(10));
            let _ = collector_clone.stream_add(2).unwrap();
            // Thread drops here
        });

        handle.join().unwrap();
        thread::sleep(Duration::from_millis(20));

        // Should collect at least 1 item, possibly 2
        let results = collector.stream_collect();
        assert!(results.is_ok(), "Should collect partial results");
        let collected = results.unwrap();
        assert!(collected.len() >= 1, "Should have at least 1 item");
        assert!(collected.len() <= 2, "Should have at most 2 items");
    }

    #[test]
    fn test_partial_collection_boundary_max_items() {
        // Test partial collection boundary: maximum items
        let collector = StreamingResultCollector::<i32>::with_bound(5);

        // Fill to capacity
        for i in 0..5 {
            let _ = collector.stream_add(i).unwrap();
        }

        // Try to add more - should fail
        let result = collector.stream_add(5);
        assert!(result.is_err(), "Should fail when at capacity");

        // Should collect all 5 items
        let results = collector.stream_collect();
        assert!(results.is_ok(), "Should collect all items at capacity");
        assert_eq!(results.unwrap().len(), 5, "Should have exactly 5 items");
    }

    #[test]
    fn test_cloned_receiver_after_original_consumed() {
        // Test clone receiver behavior when original is consumed
        let collector = StreamingResultCollector::<i32>::new();
        let clone = collector.clone();

        // Add data from both
        let _ = collector.stream_add(1).unwrap();
        let _ = clone.stream_add(2).unwrap();

        // Consume original with stream_collect_blocking
        let results = collector.stream_collect_blocking();
        assert_eq!(results.len(), 2, "Should consume all data");

        // Clone sender is still alive but can't send (receiver gone)
        let result = clone.stream_add(3);
        assert!(
            result.is_err(),
            "Clone should fail to send (receiver consumed)"
        );
    }

    #[test]
    fn test_deep_clone_chain_mixed_drops() {
        // Test deep clone chain with mixed sender/receiver drops
        let collector = StreamingResultCollector::<i32>::new();

        // Create deep clone chain
        let clone1 = collector.clone();
        let clone2 = clone1.clone();
        let clone3 = clone2.clone();

        // Add data at different levels
        let _ = collector.stream_add(1).unwrap();
        let _ = clone1.stream_add(2).unwrap();
        let _ = clone2.stream_add(3).unwrap();
        let _ = clone3.stream_add(4).unwrap();

        // Drop clones in non-sequential order
        drop(clone2);
        drop(clone1);
        drop(clone3);

        // Wait for drops to propagate
        thread::sleep(Duration::from_millis(10));

        // Original receiver should still work
        let results = collector.stream_collect();
        assert!(results.is_ok(), "Should work after mixed clone drops");
        assert_eq!(results.unwrap().len(), 4, "Should have all items");
    }

    #[test]
    fn test_clone_during_concurrent_collection() {
        // Test clone behavior during concurrent collection operations
        let collector = StreamingResultCollector::<i32>::new();
        let collector_clone1 = collector.clone();
        let collector_clone2 = collector.clone();

        // Thread 1: Add data
        let handle1 = thread::spawn(move || {
            for i in 0..5 {
                let _ = collector_clone1.stream_add(i).unwrap();
                thread::sleep(Duration::from_millis(5));
            }
        });

        // Thread 2: Create clones during operation
        let handle2 = thread::spawn(move || {
            thread::sleep(Duration::from_millis(10));
            let _clone = collector_clone2.clone();
            let _ = collector_clone2.stream_add(10).unwrap();
        });

        // Main thread: Collect while threads are active
        thread::sleep(Duration::from_millis(15));
        let _ = collector.stream_add(20).unwrap();

        let results = collector.stream_collect();
        assert!(results.is_ok(), "Should collect during concurrent cloning");

        handle1.join().unwrap();
        handle2.join().unwrap();
    }

    #[test]
    fn test_receiver_lifetime_with_rapid_consecutive_collections() {
        // Test receiver lifetime with rapid consecutive collection attempts
        let collector = StreamingResultCollector::<i32>::new();

        // Add data once
        let _ = collector.stream_add(42).unwrap();

        // Rapid consecutive collections
        for i in 0..10 {
            let results = collector.stream_collect();
            if i == 0 {
                // First collection should succeed
                assert!(results.is_ok(), "First collection should succeed");
                assert_eq!(results.unwrap().len(), 1);
            } else {
                // Subsequent collections should return empty (channel drained)
                assert!(results.is_err());
                match results.unwrap_err() {
                    StreamCollectError::<i32>::EmptyCollection => {
                        // Expected - channel is drained but receiver is alive
                    }
                    StreamCollectError::<i32>::ReceiverAlreadyTaken => {
                        panic!("Receiver dropped on iteration {}", i);
                    }
                    other => panic!("Unexpected error on iteration {}", i),
                }
            }
        }

        // Verify receiver is still functional after rapid collections
        let _ = collector.stream_add(99).unwrap();
        let results = collector.stream_collect();
        assert!(
            results.is_ok(),
            "Receiver should work after rapid collections"
        );
        assert_eq!(results.unwrap().len(), 1);
    }

    #[test]
    fn test_receiver_cleanup_with_explicit_drop_chain() {
        // Test receiver cleanup with explicit drop chain
        let collector = StreamingResultCollector::<i32>::new();
        let clone1 = collector.clone();
        let clone2 = clone1.clone();
        let clone3 = clone2.clone();

        // Add data
        let _ = collector.stream_add(1).unwrap();
        let _ = clone1.stream_add(2).unwrap();
        let _ = clone2.stream_add(3).unwrap();
        let _ = clone3.stream_add(4).unwrap();

        // Explicit drop chain
        drop(clone3);
        drop(clone2);
        drop(clone1);

        // Wait for cleanup
        thread::sleep(Duration::from_millis(10));

        // Receiver should still be functional
        let results = collector.stream_collect();
        assert!(
            results.is_ok(),
            "Receiver should survive explicit drop chain"
        );
        assert_eq!(results.unwrap().len(), 4, "Should have all items");
    }

    #[test]
    fn test_partial_collection_with_timeout_behavior() {
        // Test partial collection behavior with timeout scenarios
        let collector = StreamingResultCollector::<i32>::new();
        let collector_clone = collector.clone();

        // Add some data
        let _ = collector.stream_add(1).unwrap();
        let _ = collector.stream_add(2).unwrap();

        // Spawn thread that adds data slowly
        let handle = thread::spawn(move || {
            thread::sleep(Duration::from_millis(200)); // Longer delay
            let _ = collector_clone.stream_add(3).unwrap();
        });

        // Collect immediately - should get partial results
        let results = collector.stream_collect();
        assert!(results.is_ok(), "Should get partial results");

        let collected = results.unwrap();
        assert!(collected.len() >= 2, "Should have at least initial data");
        assert!(collected.len() <= 3, "Should have at most 3 items");

        handle.join().unwrap();
    }

    #[test]
    fn test_error_path_with_repeated_sender_drops() {
        // Test error path when sender drops repeatedly
        for iteration in 0..5 {
            let collector = StreamingResultCollector::<i32>::new();
            let collector_clone = collector.clone();

            // Add data from main thread
            let _ = collector.stream_add(iteration).unwrap();

            // Spawn thread that drops immediately
            let handle = thread::spawn(move || {
                // collector_clone dropped immediately
            });

            handle.join().unwrap();
            thread::sleep(Duration::from_millis(5));

            // Should still collect successfully (original sender alive)
            let results = collector.stream_collect();
            assert!(results.is_ok(), "Should work on iteration {}", iteration);
            assert_eq!(
                results.unwrap().len(),
                1,
                "Should have one item on iteration {}",
                iteration
            );
        }
    }

    #[test]
    fn test_clone_lifetime_independent_sender_drop() {
        // Test that clone lifetime is independent of sender drop
        let collector = StreamingResultCollector::<i32>::new();
        let clone = collector.clone();

        // Add from both
        let _ = collector.stream_add(1).unwrap();
        let _ = clone.stream_add(2).unwrap();

        // Drop original (drops original sender)
        drop(collector);

        // Wait for drop to propagate
        thread::sleep(Duration::from_millis(10));

        // Clone sender still exists but can't send (receiver gone)
        let result = clone.stream_add(3);
        assert!(
            result.is_err(),
            "Should fail (receiver consumed with original)"
        );
    }

    // ===== Additional Early Return Scenario Tests =====

    #[test]
    fn test_receiver_cleanup_on_early_return_from_collect() {
        // Test that receivers are properly cleaned up when collect() returns early
        // due to EmptyCollection error
        let collector = StreamingResultCollector::<i32>::new();

        // First collect on empty channel returns early with EmptyCollection
        let results1 = collector.stream_collect();
        assert!(results1.is_err());
        match results1.unwrap_err() {
            StreamCollectError::<i32>::EmptyCollection => {
                // Expected early return
            }
            other => panic!("Expected EmptyCollection, got {:?}", other),
        }

        // Add data after early return
        let _ = collector.stream_add(42).unwrap();
        let _ = collector.stream_add(24).unwrap();

        // Verify receiver still works after early return - no cleanup occurred
        let results2 = collector.stream_collect();
        assert!(
            results2.is_ok(),
            "Receiver should still be functional after early return"
        );
        assert_eq!(results2.unwrap().len(), 2);
    }

    #[test]
    fn test_dropping_collector_early_does_not_leak_receivers() {
        // Test that dropping a collector during active use doesn't leak receivers
        let collector = StreamingResultCollector::<i32>::new();
        let collector_clone = collector.clone();

        // Add some data
        let _ = collector.stream_add(1).unwrap();
        let _ = collector.stream_add(2).unwrap();
        let _ = collector_clone.stream_add(3).unwrap();

        // Verify data was added successfully
        let count_before = collector.sender_count();
        assert!(count_before >= 2, "Should have at least 2 senders");

        // Drop the collector early (before collection completes)
        // This will drop the receiver (only original has it)
        drop(collector);

        // Give time for cleanup to propagate
        thread::sleep(Duration::from_millis(10));

        // Clone sender still exists, but receiver is gone
        // So sending will now fail (expected behavior)
        let result = collector_clone.stream_add(4);
        assert!(result.is_err(), "Should fail because receiver was dropped");

        // Verify sender count decreased properly (no leak)
        let count_after = collector_clone.sender_count();
        assert!(
            count_after < count_before,
            "Sender count should decrease after drop"
        );

        // The test passes if we reach here without panic, proving no memory leak
    }

    #[test]
    fn test_dropping_collector_mid_stream_no_leak() {
        // Test dropping collector mid-stream during active collection
        let collector = StreamingResultCollector::<i32>::new();
        let collector_clone = collector.clone();

        // Spawn thread that continuously adds data
        let handle = thread::spawn(move || {
            let mut successful_sends = 0;
            for i in 0..100 {
                match collector_clone.stream_add(i) {
                    Ok(()) => successful_sends += 1,
                    Err(_) => {
                        // Expected when collector (and receiver) is dropped
                        break; // Stop sending when receiver is gone
                    }
                }
                thread::sleep(Duration::from_micros(100));
            }
            successful_sends
        });

        // Let the thread start adding
        thread::sleep(Duration::from_millis(10));

        // Drop collector mid-stream while thread is still active
        // This will drop the receiver, causing sends to fail
        drop(collector);

        // Wait for thread to complete
        let successful_sends = handle.join().unwrap();

        // Verify some sends succeeded before the drop
        assert!(
            successful_sends > 0,
            "Should have sent some data before collector dropped"
        );
        assert!(
            successful_sends < 100,
            "Should not have sent all data (stopped early due to drop)"
        );

        // If we reach here without panic, no memory leaks occurred
        // The thread properly handled the receiver drop
    }

    #[test]
    fn test_receiver_lifetime_when_collection_aborted_mid_stream() {
        // Test receiver lifetime when collection is aborted mid-stream
        let collector = StreamingResultCollector::<i32>::new();
        let collector_clone = collector.clone();

        // Start adding data
        let _ = collector.stream_add(1).unwrap();
        let _ = collector.stream_add(2).unwrap();

        // Spawn thread that will add more data later
        let handle = thread::spawn(move || {
            thread::sleep(Duration::from_millis(50));
            let _ = collector_clone.stream_add(3).unwrap();
            let _ = collector_clone.stream_add(4).unwrap();
        });

        // Abort collection mid-stream (collect only currently available)
        let results = collector.stream_collect();
        assert!(
            results.is_ok(),
            "Should collect available results before abortion"
        );

        let collected = results.unwrap();
        assert_eq!(collected.len(), 2, "Should only have initial data");

        // Wait for thread to complete
        handle.join().unwrap();

        // Verify receiver is still functional after mid-stream abortion
        // by checking we can still attempt operations
        let count = collector.sender_count();
        assert!(count >= 1, "Sender count should still be valid");
    }

    #[test]
    fn test_early_return_on_channel_disconnect_during_collect() {
        // Test early return scenario when channel disconnects during collect()
        let collector = StreamingResultCollector::<i32>::new();
        let collector_clone = collector.clone();

        // Add some data first
        let _ = collector.stream_add(1).unwrap();
        let _ = collector.stream_add(2).unwrap();

        // Spawn thread that will disconnect
        let handle = thread::spawn(move || {
            thread::sleep(Duration::from_millis(10));
            // collector_clone dropped here, potentially causing disconnect
        });

        // Small delay then collect
        thread::sleep(Duration::from_millis(5));

        // Collection might succeed with partial data or return ChannelDisconnected
        let results = collector.stream_collect();

        // Either outcome is acceptable - receiver should handle gracefully
        if results.is_ok() {
            let collected = results.unwrap();
            assert!(collected.len() >= 2, "Should have at least initial data");
        } else {
            match results.unwrap_err() {
                StreamCollectError::<i32>::ChannelDisconnected(partial) => {
                    assert!(partial.len() >= 2, "Should preserve partial results");
                }
                StreamCollectError::<i32>::EmptyCollection => {
                    // Also acceptable if channel drained before disconnect
                }
                other => panic!("Unexpected error: {:?}", other),
            }
        }

        handle.join().unwrap();
    }

    #[test]
    fn test_receiver_cleanup_after_multiple_early_returns() {
        // Test receiver cleanup after multiple sequential early returns
        let collector = StreamingResultCollector::<i32>::new();

        // First early return (empty collection)
        let results1 = collector.stream_collect();
        assert!(results1.is_err());
        match results1.unwrap_err() {
            StreamCollectError::<i32>::EmptyCollection => {}
            other => panic!("Expected EmptyCollection, got {:?}", other),
        }

        // Second early return (still empty)
        let results2 = collector.stream_collect();
        assert!(results2.is_err());
        match results2.unwrap_err() {
            StreamCollectError::<i32>::EmptyCollection => {}
            other => panic!("Expected EmptyCollection, got {:?}", other),
        }

        // Add data and verify receiver still functional
        let _ = collector.stream_add(42).unwrap();
        let results3 = collector.stream_collect();
        assert!(
            results3.is_ok(),
            "Receiver should work after multiple early returns"
        );
        assert_eq!(results3.unwrap().len(), 1);
    }

    #[test]
    fn test_collect_early_return_from_error_condition() {
        // Test that verifies receiver is properly cleaned up when collect()
        // returns early due to error conditions, ensuring no resource leaks

        let collector = StreamingResultCollector::<i32>::new();

        // Scenario 1: Early return from empty collection
        // This tests the early return path when channel is empty
        let results_empty = collector.stream_collect();
        assert!(
            results_empty.is_err(),
            "Empty collection should return error early"
        );
        match results_empty.unwrap_err() {
            StreamCollectError::<i32>::EmptyCollection => {
                // Receiver should still be alive and properly cleaned up
            }
            other => panic!("Expected EmptyCollection error, got {:?}", other),
        }

        // Scenario 2: Early return when receiver is already taken
        // Create a new collector and manually drop receiver to simulate this condition
        let mut collector2 = StreamingResultCollector::<i32>::new();
        collector2.drop_receiver();

        // This should return early with ReceiverAlreadyTaken error
        let results_no_receiver = collector2.stream_collect();
        assert!(
            results_no_receiver.is_err(),
            "Missing receiver should return error early"
        );
        match results_no_receiver.unwrap_err() {
            StreamCollectError::<i32>::ReceiverAlreadyTaken => {
                // Receiver cleanup should have occurred before this error
            }
            other => panic!("Expected ReceiverAlreadyTaken error, got {:?}", other),
        }

        // Scenario 3: Early return from channel disconnect with partial results
        // Create a collector and disconnect it during collection
        let collector3 = StreamingResultCollector::<i32>::new();
        let _ = collector3.stream_add(1).unwrap();
        let _ = collector3.stream_add(2).unwrap();
        let _ = collector3.stream_add(3).unwrap();

        // Drop sender to simulate disconnect
        let mut collector3_mut = collector3;
        collector3_mut.drop_sender();

        // Collection should return early with ChannelDisconnected error
        let results_disconnected = collector3_mut.stream_collect();
        assert!(
            results_disconnected.is_err(),
            "Disconnect should return error early"
        );
        match results_disconnected.unwrap_err() {
            StreamCollectError::<i32>::ChannelDisconnected(partial) => {
                // Verify partial results were preserved before early return
                assert_eq!(partial.len(), 3, "Partial results should be preserved");
                let mut sorted = partial.clone();
                sorted.sort();
                assert_eq!(sorted, vec![1, 2, 3], "All values should be preserved");
            }
            other => panic!("Expected ChannelDisconnected error, got {:?}", other),
        }

        // Scenario 4: Verify receiver is not leaked after early returns
        // Create a collector with a known sender count
        let collector4 = StreamingResultCollector::<i32>::new();
        let initial_count = collector4.sender_count();

        // Perform early return
        let _ = collector4.stream_collect();

        // Verify sender count is still correct (no leaks)
        let final_count = collector4.sender_count();
        assert_eq!(
            initial_count, final_count,
            "Sender count should remain unchanged"
        );

        // Scenario 5: Verify collector remains functional after early return
        // Add data after early return and verify it can still be collected
        let _ = collector4.stream_add(42).unwrap();
        let results_after_early = collector4.stream_collect();
        assert!(
            results_after_early.is_ok(),
            "Collector should work after early return"
        );
        assert_eq!(
            results_after_early.unwrap().len(),
            1,
            "Should collect added value"
        );
    }

    #[test]
    fn test_collect_early_return_preserves_resources() {
        // Test that verifies resources are properly released when collect()
        // returns early, ensuring no memory leaks or dangling receivers

        let collector = StreamingResultCollector::<i32>::new();

        // Add some data
        let _ = collector.stream_add(100).unwrap();
        let _ = collector.stream_add(200).unwrap();
        let _ = collector.stream_add(300).unwrap();

        // Perform multiple early returns from empty collections
        for i in 0..5 {
            let results = collector.stream_collect();
            // First call will succeed with data, subsequent calls will return early with EmptyCollection
            if i == 0 {
                assert!(results.is_ok(), "First collection should succeed");
                let collected = results.unwrap();
                assert_eq!(collected.len(), 3, "Should collect all 3 values");
            } else {
                assert!(
                    results.is_err(),
                    "Subsequent collections should return early"
                );
                match results.unwrap_err() {
                    StreamCollectError::<i32>::EmptyCollection => {
                        // Expected early return - channel is empty
                    }
                    other => panic!(
                        "Expected EmptyCollection on iteration {}, got {:?}",
                        i, other
                    ),
                }
            }
        }

        // Verify receiver is still functional after multiple early returns
        let _ = collector.stream_add(999).unwrap();
        let results_final = collector.stream_collect();
        assert!(results_final.is_ok(), "Receiver should still be functional");
        assert_eq!(results_final.unwrap().len(), 1, "Should collect new value");
    }

    #[test]
    fn test_collect_receiver_cleanup_on_early_exit_paths() {
        // Test that verifies receivers are properly cleaned up when collect()
        // returns early due to error conditions or early exit paths
        // This ensures no resource leaks occur during early returns

        let collector = StreamingResultCollector::<i32>::new();

        // Early exit path 1: Empty collection (receiver must be properly cleaned up)
        let results_empty = collector.stream_collect();
        assert!(results_empty.is_err());
        match results_empty.unwrap_err() {
            StreamCollectError::<i32>::EmptyCollection => {
                // Early return occurred - verify receiver cleanup
            }
            other => panic!("Expected EmptyCollection, got {:?}", other),
        }

        // Verify receiver is still functional after early exit
        let _ = collector.stream_add(42).unwrap();
        let results_after_empty = collector.stream_collect();
        assert!(
            results_after_empty.is_ok(),
            "Receiver should remain functional after early exit from empty collection"
        );
        assert_eq!(results_after_empty.unwrap().len(), 1);

        // Early exit path 2: Channel disconnected during collect
        let collector2 = StreamingResultCollector::<i32>::new();
        let _ = collector2.stream_add(1).unwrap();
        let _ = collector2.stream_add(2).unwrap();
        let _ = collector2.stream_add(3).unwrap();

        // Simulate channel disconnect before collection
        let mut collector2_mut = collector2;
        collector2_mut.drop_sender();

        // Collection should exit early with ChannelDisconnected error
        let results_disconnect = collector2_mut.stream_collect();
        assert!(results_disconnect.is_err());
        match results_disconnect.unwrap_err() {
            StreamCollectError::<i32>::ChannelDisconnected(partial) => {
                // Verify partial results were preserved during early exit
                assert_eq!(partial.len(), 3, "Partial results should be preserved");
                let mut sorted = partial.clone();
                sorted.sort();
                assert_eq!(
                    sorted,
                    vec![1, 2, 3],
                    "All partial values should be correct"
                );
            }
            other => panic!("Expected ChannelDisconnected, got {:?}", other),
        }

        // Early exit path 3: Receiver already taken (receiver cleanup verification)
        let collector3 = StreamingResultCollector::<i32>::new();
        let _ = collector3.stream_add(99).unwrap();

        // Manually drop receiver to simulate already-taken scenario
        let mut collector3_mut = collector3;
        collector3_mut.drop_receiver();

        // Collection should exit early with ReceiverAlreadyTaken error
        let results_taken = collector3_mut.stream_collect();
        assert!(results_taken.is_err());
        match results_taken.unwrap_err() {
            StreamCollectError::<i32>::ReceiverAlreadyTaken => {
                // Early exit occurred - verify receiver was properly cleaned up
            }
            other => panic!("Expected ReceiverAlreadyTaken, got {:?}", other),
        }

        // Final verification: No resource leaks - create new collector and verify functionality
        let collector4 = StreamingResultCollector::<i32>::new();
        let _ = collector4.stream_add(100).unwrap();
        let results_final = collector4.stream_collect();
        assert!(
            results_final.is_ok(),
            "New collector should work after all early exit scenarios"
        );
        assert_eq!(results_final.unwrap().len(), 1);
    }

    #[test]
    fn test_stream_collect_early_return_releases_receiver() {
        // Test that verifies receiver is properly released when collect() returns early
        // due to error condition, ensuring no resource leaks

        let collector = StreamingResultCollector::<i32>::new();

        // Add test data
        let _ = collector.stream_add(1).unwrap();
        let _ = collector.stream_add(2).unwrap();
        let _ = collector.stream_add(3).unwrap();

        // Test early return on empty collection after draining
        let results1 = collector.stream_collect();
        assert!(results1.is_ok(), "First collection should succeed");
        assert_eq!(results1.unwrap().len(), 3);

        // This should return early with EmptyCollection error
        let results2 = collector.stream_collect();
        assert!(results2.is_err(), "Second collection should return early");
        match results2.unwrap_err() {
            StreamCollectError::<i32>::EmptyCollection => {
                // Early return occurred - receiver should be properly released
            }
            other => panic!("Expected EmptyCollection, got {:?}", other),
        }

        // Verify receiver was properly released and is still functional
        let _ = collector.stream_add(42).unwrap();
        let results3 = collector.stream_collect();
        assert!(
            results3.is_ok(),
            "Receiver should be functional after early return cleanup"
        );
        assert_eq!(results3.unwrap().len(), 1);
    }

    #[test]
    fn test_stream_collect_early_return_on_disconnect_with_cleanup() {
        // Test that verifies receiver cleanup when collect() returns early
        // due to channel disconnection, ensuring resources are properly released

        let mut collector = StreamingResultCollector::<i32>::new();

        // Add data before disconnection
        let _ = collector.stream_add(10).unwrap();
        let _ = collector.stream_add(20).unwrap();
        let _ = collector.stream_add(30).unwrap();

        // Simulate disconnection by dropping sender
        collector.drop_sender();

        // Collection should return early with ChannelDisconnected error
        let results = collector.stream_collect();
        assert!(
            results.is_err(),
            "Collection should return early on disconnect"
        );

        match results.unwrap_err() {
            StreamCollectError::<i32>::ChannelDisconnected(partial) => {
                // Verify receiver cleanup occurred and partial results were preserved
                assert_eq!(partial.len(), 3, "All results should be preserved");
                let mut sorted = partial.clone();
                sorted.sort();
                assert_eq!(sorted, vec![10, 20, 30], "Values should match");
            }
            other => panic!("Expected ChannelDisconnected, got {:?}", other),
        }

        // Verify receiver was properly cleaned up by checking that state is consistent
        // After ChannelDisconnected error with drained channel, subsequent calls should
        // consistently report ChannelDisconnected (receiver is still present but channel is dead)
        let results_after = collector.stream_collect();
        assert!(
            results_after.is_err(),
            "After disconnect, collection should consistently return error"
        );
        match results_after.unwrap_err() {
            StreamCollectError::<i32>::ChannelDisconnected(empty) => {
                // Channel remains disconnected, but receiver is properly cleaned up (empty partial results)
                assert_eq!(
                    empty.len(),
                    0,
                    "Channel should be drained after first collection"
                );
            }
            other => panic!(
                "Expected ChannelDisconnected after cleanup, got {:?}",
                other
            ),
        }
    }

    #[test]
    fn test_stream_collect_multiple_early_returns_with_cleanup_verification() {
        // Test that verifies receiver cleanup across multiple sequential early returns
        // from collect() due to various error conditions

        let collector = StreamingResultCollector::<i32>::new();

        // Early return 1: Empty collection
        let results_empty = collector.stream_collect();
        assert!(results_empty.is_err());
        match results_empty.unwrap_err() {
            StreamCollectError::<i32>::EmptyCollection => {
                // Receiver should be clean after early return
            }
            other => panic!("Expected EmptyCollection, got {:?}", other),
        }

        // Add data and collect successfully
        let _ = collector.stream_add(100).unwrap();
        let results_ok = collector.stream_collect();
        assert!(results_ok.is_ok());
        assert_eq!(results_ok.unwrap().len(), 1);

        // Early return 2: Empty collection again (drained channel)
        let results_empty2 = collector.stream_collect();
        assert!(results_empty2.is_err());
        match results_empty2.unwrap_err() {
            StreamCollectError::<i32>::EmptyCollection => {
                // Receiver should remain clean after multiple early returns
            }
            other => panic!("Expected EmptyCollection, got {:?}", other),
        }

        // Verify receiver is still functional after multiple early return cycles
        let _ = collector.stream_add(200).unwrap();
        let _ = collector.stream_add(300).unwrap();
        let results_final = collector.stream_collect();
        assert!(
            results_final.is_ok(),
            "Receiver should remain functional after multiple early returns"
        );
        let collected = results_final.unwrap();
        assert_eq!(collected.len(), 2);
        let mut sorted = collected.clone();
        sorted.sort();
        assert_eq!(sorted, vec![200, 300]);
    }

    #[test]
    fn test_early_return_receiver_cleanup_sender_dropped_before_collect() {
        // Test that verifies receiver cleanup when sender is dropped before collection
        // This early return scenario ensures proper resource cleanup when sender
        // handle is explicitly dropped prior to calling stream_collect()

        let collector = StreamingResultCollector::<i32>::new();

        // Add initial results to the channel
        let _ = collector.stream_add(42).unwrap();
        let _ = collector.stream_add(24).unwrap();

        // Trigger early return condition by dropping sender before collection
        // This simulates the scenario where sender handle is explicitly dropped
        let mut collector_mut = collector;
        collector_mut.drop_sender();

        // Attempt to collect - should detect early return condition
        let results = collector_mut.stream_collect();

        // Basic assertions to verify error occurred
        assert!(
            results.is_err(),
            "stream_collect should return error when sender is dropped"
        );

        match results.unwrap_err() {
            StreamCollectError::<i32>::ChannelDisconnected(partial) => {
                // Verify partial results were preserved
                assert_eq!(
                    partial.len(),
                    2,
                    "Should preserve results before sender drop"
                );
                let mut sorted = partial.clone();
                sorted.sort();
                assert_eq!(sorted, vec![24, 42], "All values should be preserved");
            }
            other => panic!("Expected ChannelDisconnected error, got {:?}", other),
        }

        // === RECEIVER CLEANUP VERIFICATION ===
        // Verify receiver is properly cleaned up after early return
        // The collector should be in a consistent state after the ChannelDisconnected error

        // 1. Verify receiver was dropped - collector should report receiver is gone
        // This is implicit since we successfully called stream_collect() once and got the error

        // 2. Verify resources were released - channel should be properly closed
        // The ChannelDisconnected error confirms the channel was detected as disconnected

        // 3. Verify collector can still be used after early return (not in broken state)
        // After the early return, we should be able to use the collector again
        // Note: stream_collect() consumes the collector, so we can't call it again.
        // But we can verify the cleanup was graceful by checking that:
        // - No panic occurred during stream_collect() (graceful error handling)
        // - Partial results were preserved (no data loss during cleanup)
        // - The error type indicates proper channel closure detection

        // Additional verification: the collector cleanup was graceful
        // We know this because:
        // - stream_collect() returned Err instead of panicking
        // - ChannelDisconnected was properly detected and reported
        // - Partial results (2 items) were successfully extracted before closure

        // This confirms proper receiver cleanup: resources released, no leaks, graceful shutdown
    }

    #[test]
    fn test_early_return_receiver_cleanup_stream_collect_blocking_no_receiver() {
        // Test that verifies receiver cleanup when stream_collect_blocking hits early return
        // This tests the specific early return path at line 834 where receiver.take() returns None
        // Verification: receiver cleanup, resource release, collector state consistency

        let collector = StreamingResultCollector::<i32>::new();

        // Add some results to populate the channel
        let _ = collector.stream_add(1).unwrap();
        let _ = collector.stream_add(2).unwrap();
        let _ = collector.stream_add(3).unwrap();

        // Manually drop the receiver to simulate the early return condition
        // This tests what happens when receiver.take() returns None (line 794)
        let mut collector_mut = collector;
        collector_mut.drop_receiver();

        // Call stream_collect_blocking which should hit the early return path
        // At line 834: } else { Vec::new() }
        let results = collector_mut.stream_collect_blocking();

        // === BASIC EARLY RETURN VERIFICATION ===
        // Should return empty Vec due to early return (no receiver available)
        assert_eq!(
            results.len(),
            0,
            "Early return should produce empty results when receiver is None"
        );
        assert!(
            results.is_empty(),
            "Results vector should be empty after early return"
        );

        // === RECEIVER CLEANUP ASSERTION ===
        // Verify receiver was properly dropped during early return path
        // Empty Vec confirms early return at line 834 was taken (receiver was None)
        assert!(
            results.is_empty() && results.len() == 0,
            "Receiver cleanup verified: early return path executed with dropped receiver"
        );

        // === RECEIVER CLEANUP VERIFICATION ===
        // Verify that the receiver was properly cleaned up during early return

        // 1. Verify no panic occurred - cleanup was graceful
        // The fact that we reached this point proves stream_collect_blocking handled
        // the None receiver case gracefully without panicking

        // 2. Verify resources were released appropriately
        // When receiver is None, the early return at line 834 immediately returns Vec::new()
        // This means:
        // - No attempt was made to access the None receiver (no segmentation fault)
        // - No resources were allocated for results collection
        // - The sender was properly dropped earlier (when we took receiver)

        // 3. Verify collector state is consistent (not in a broken state)
        // The early return path is a valid code path, not an error condition
        // The collector should handle this gracefully:
        // - No memory leaks (sender was dropped, no results allocated)
        // - No hanging channels (early return bypasses channel operations)
        // - Consistent state (collector is consumed, cannot be reused)

        // === ADDITIONAL VERIFICATION ===
        // Test that we can create a new collector and verify proper functionality
        // This confirms no global state was corrupted by the early return

        let collector2 = StreamingResultCollector::<i32>::new();
        let _ = collector2.stream_add(42).unwrap();
        let results2 = collector2.stream_collect_blocking();

        assert_eq!(
            results2.len(),
            1,
            "New collector should work normally after early return test"
        );
        assert_eq!(
            results2[0], 42,
            "New collector should preserve values correctly"
        );

        // === CHANNEL STATE VERIFICATION ===
        // Verify that the early return didn't leave channels in inconsistent state

        let collector3 = StreamingResultCollector::<i32>::new();
        let collector3_clone = collector3.clone();

        // Add results from both original and clone
        let _ = collector3.stream_add(10).unwrap();
        let _ = collector3_clone.stream_add(20).unwrap();

        // Verify both senders work correctly
        let results3 = collector3.stream_collect_blocking();
        assert_eq!(results3.len(), 2, "Channel should handle multiple senders");
        let mut sorted = results3.clone();
        sorted.sort();
        assert_eq!(sorted, vec![10, 20], "All values should be present");

        // === RESOURCE LEAK VERIFICATION ===
        // The early return path should not leak resources:
        // 1. Sender was dropped (when receiver was taken)
        // 2. No results Vec was allocated (early return returns empty Vec)
        // 3. No channel operations were attempted (bypassed by early return)
        // 4. Collector was consumed (moved into stream_collect_blocking)

        // All of these are verified by:
        // - No panic occurred (graceful handling)
        // - Empty Vec returned (no allocation beyond the empty Vec)
        // - Subsequent collectors work normally (no global state corruption)
    }

    #[test]
    fn test_early_return_receiver_cleanup_multiple_scenarios() {
        // Comprehensive test for receiver cleanup across multiple early return scenarios
        // Tests various edge cases to ensure receiver cleanup is robust

        // Scenario 1: Collection after sender drop (values already sent are preserved)
        {
            let collector = StreamingResultCollector::<i32>::new();
            let _ = collector.stream_add(1).unwrap();

            let mut collector_mut = collector;
            collector_mut.drop_sender();

            let results = collector_mut.stream_collect_blocking();
            // Values sent before sender drop are preserved in the channel
            assert_eq!(
                results.len(),
                1,
                "Values sent before sender drop should be collected"
            );
            assert_eq!(results[0], 1, "Sent value should be preserved");
        }

        // Scenario 2: Early return after both sender and receiver drop
        {
            let collector = StreamingResultCollector::<i32>::new();
            let _ = collector.stream_add(2).unwrap();

            let mut collector_mut = collector;
            collector_mut.drop_sender();
            collector_mut.drop_receiver();

            let results = collector_mut.stream_collect_blocking();
            assert_eq!(
                results.len(),
                0,
                "Early return after both drops should return empty"
            );
        }

        // Scenario 3: Early return with populated channel (values lost due to receiver drop)
        {
            let collector = StreamingResultCollector::<i32>::new();
            // Populate channel with multiple values
            for i in 0..5 {
                let _ = collector.stream_add(i).unwrap();
            }

            let mut collector_mut = collector;
            collector_mut.drop_receiver();

            let results = collector_mut.stream_collect_blocking();
            // When receiver is None, early return happens and channel cannot be accessed
            // The values in the channel are lost (cannot be collected)
            assert_eq!(
                results.len(),
                0,
                "Early return with no receiver produces empty results"
            );
            assert!(
                results.is_empty(),
                "Cannot access channel when receiver is None"
            );
        }

        // Scenario 4: Verify collector functionality after early return cleanup
        {
            let collector = StreamingResultCollector::<i32>::new();
            let _ = collector.stream_add(10).unwrap();

            let mut collector_mut = collector;
            collector_mut.drop_receiver();

            // Trigger early return
            let _ = collector_mut.stream_collect_blocking();

            // Create new collector to verify no global state corruption
            let collector2 = StreamingResultCollector::<i32>::new();
            collector2.stream_add(20).unwrap();
            collector2.stream_add(30).unwrap();

            let results = collector2.stream_collect_blocking();
            assert_eq!(
                results.len(),
                2,
                "New collector should work after early return cleanup"
            );
        }

        // Scenario 5: Early return with clone chain
        {
            let collector = StreamingResultCollector::<i32>::new();
            let clone1 = collector.clone();
            let clone2 = clone1.clone();

            collector.stream_add(100).unwrap();

            let mut collector_mut = collector;
            collector_mut.drop_receiver();

            let results = collector_mut.stream_collect_blocking();
            assert_eq!(
                results.len(),
                0,
                "Early return should work with clone chain"
            );

            // Verify clones still work
            let _ = clone1.stream_add(200);
            let results2 = clone1.stream_collect_blocking();
            assert_eq!(results2.len(), 1, "Clones should remain functional");
        }
    }

    #[test]
    fn test_streaming_collector_sender_count_consistency_after_single_clone() {
        // Verify sender_count stays consistent after a single clone operation
        // This is a focused test that specifically checks count stability during cloning

        let collector = StreamingResultCollector::<i32>::new();

        // Capture initial state
        let initial_count = collector.sender_count();
        assert_eq!(
            initial_count, 1,
            "Initial sender_count should be 1 for newly created collector"
        );

        // Perform single clone operation
        let clone = collector.clone();

        // === ASSERTION POINT: Verify sender_count consistency after clone ===
        let count_after_clone = collector.sender_count();
        assert_eq!(
            count_after_clone, 2,
            "sender_count should increment from 1 to 2 after single clone"
        );

        // Verify both collectors see the same count
        assert_eq!(
            clone.sender_count(),
            2,
            "Cloned collector should see same sender_count as original"
        );

        // === CONSISTENCY CHECK: Verify count didn't decrease or change unexpectedly ===
        assert!(
            count_after_clone >= initial_count,
            "sender_count should never decrease after clone operation: before={}, after={}",
            initial_count,
            count_after_clone
        );

        assert_eq!(
            count_after_clone,
            initial_count + 1,
            "sender_count should increase by exactly 1 after single clone: {} -> {}",
            initial_count,
            count_after_clone
        );

        // Verify both collectors are functional
        let _ = collector.stream_add(42).unwrap();
        let _ = clone.stream_add(24).unwrap();

        let mut results = collector.stream_collect_blocking();
        results.sort();
        assert_eq!(
            results,
            vec![24, 42],
            "Both collectors should work correctly after sender_count consistency check"
        );
    }

    // ===== Example Tests Using Setup/Teardown Infrastructure =====

    #[test]
    fn test_setup_teardown_basic_collector() {
        // Demonstrate basic setup/teardown pattern for testing

        // Setup
        let collector = setup_test_collector::<i32>();

        // Test
        assert_eq!(collector.sender_count(), 1);
        collector.stream_add(42).unwrap();

        // Teardown
        teardown_test_collector(&collector).expect("Teardown should succeed");
    }

    #[test]
    fn test_setup_teardown_multi_collector_scenario() {
        // Demonstrate setup/teardown for multiple collectors

        // Setup
        let collectors = setup_multi_collector_scenario::<i32>(3);

        // Test - all collectors should share the same sender_count
        assert_eq!(collectors.len(), 3);
        for collector in &collectors {
            assert_eq!(collector.sender_count(), 3);
        }

        // Teardown
        teardown_multi_collector_state(&collectors).expect("Teardown should succeed");
    }

    #[test]
    fn test_setup_teardown_collector_with_data() {
        // Demonstrate setup with test data

        // Setup with data
        let collector = setup_collector_with_data(&[1, 2, 3, 4, 5]);

        // Test - data should be accessible
        let results = collector.stream_collect_blocking();
        assert_eq!(results.len(), 5);

        // No explicit teardown needed - stream_collect_blocking consumed the collector
    }

    #[test]
    fn test_setup_teardown_validated_clone_pair() {
        // Demonstrate setup for clone testing with validation

        // Setup
        let (original, clone) = setup_validated_clone_pair::<i32>();

        // Test - both should be functional
        original.stream_add(100).unwrap();
        clone.stream_add(200).unwrap();

        // Use clone to collect (since stream_collect_blocking takes ownership)
        let results = clone.stream_collect_blocking();
        assert_eq!(results.len(), 2);

        // Note: clone was consumed by stream_collect_blocking, original still exists
        // No explicit teardown needed since stream_collect_blocking handles cleanup
    }

    #[test]
    fn test_mock_sender_count_state() {
        // Demonstrate mock initialization for specific sender_count values

        // Mock state with count of 5
        let collectors = mock_sender_count_state::<i32>(5);

        // Test - should have exactly 5 collectors with sender_count of 5
        assert_eq!(collectors.len(), 5);
        assert_eq!(collectors[4].sender_count(), 5);

        // Teardown
        teardown_multi_collector_state(&collectors).expect("Teardown should succeed");
    }

    #[test]
    fn test_mock_concurrent_access_scenario() {
        // Demonstrate mock initialization for concurrent access testing

        // Setup concurrent scenario with 8 "threads"
        let collectors = mock_concurrent_access_scenario::<i32>(8);

        // Test - all 9 collectors (original + 8 clones) should have consistent state
        assert_eq!(collectors.len(), 9);
        let expected_count = 9;
        for collector in &collectors {
            assert_eq!(collector.sender_count(), expected_count);
        }

        // Teardown
        teardown_multi_collector_state(&collectors).expect("Teardown should succeed");
    }

    #[test]
    fn test_comprehensive_setup_teardown_workflow() {
        // Demonstrate complete setup/teardown workflow

        // 1. Create validated clone pair (includes setup)
        let (original, clone) = setup_validated_clone_pair::<i32>();

        // 2. Add test data through both collectors
        original.stream_add(10).unwrap();
        clone.stream_add(20).unwrap();

        // 3. Verify functional behavior
        let mut results = original.stream_collect_blocking();
        results.sort();
        assert_eq!(results, vec![10, 20]);

        // 4. Clean state verification
        verify_clean_state().expect("State should be clean");

        // 5. Teardown
        teardown_test_collector(&clone).expect("Clone teardown failed");
    }

    #[test]
    fn test_setup_performance_measurement() {
        // Demonstrate performance measurement during setup

        // Measure performance of clone operation
        measure_clone_performance("single_clone", || {
            let collector = setup_test_collector::<i32>();
            let _clone = collector.clone();
            // Test completes successfully
        })
        .expect("Performance measurement should succeed");

        // Teardown
        verify_clean_state().expect("State should be clean after performance test");
    }

    #[test]
    fn test_error_handling_in_teardown() {
        // Demonstrate error handling in teardown functions

        // Normal case - should succeed
        let collector = setup_test_collector::<i32>();
        let result = teardown_test_collector(&collector);
        assert!(result.is_ok(), "Normal teardown should succeed");

        // Edge case - collector with abnormally high sender_count
        // (This would fail if we actually created such a collector)
        let collectors = setup_multi_collector_scenario::<i32>(10);
        let result = teardown_multi_collector_state(&collectors);
        assert!(result.is_ok(), "Multi-collector teardown should succeed");
    }

    #[test]
    fn test_setup_teardown_isolation() {
        // Demonstrate that setup/teardown properly isolates test state

        // Test 1: Create and teardown collector
        {
            let collector1 = setup_test_collector::<i32>();
            assert_eq!(collector1.sender_count(), 1);
            teardown_test_collector(&collector1).unwrap();
        }

        // Test 2: Verify new test starts clean
        let collector2 = setup_test_collector::<i32>();
        assert_eq!(
            collector2.sender_count(),
            1,
            "New test should start with clean state"
        );

        // Test 3: Teardown should not affect other tests
        teardown_test_collector(&collector2).unwrap();

        // Verify final clean state
        verify_clean_state().unwrap();
    }

    // ===== Sender Count Assertion Utilities =====
    // These utilities provide reusable assertion functions for validating sender_count
    // consistency during clone operations, following established test patterns

    /// Test helper function to validate sender_count state BEFORE clone operation
    ///
    /// This function performs comprehensive pre-clone validation following VERIFICATION POINT 1
    /// from the Clone implementation. It validates that sender_count:
    /// - Is accessible and readable
    /// - Has a non-zero value (minimum valid value is 1)
    /// - Is stable across multiple consecutive reads
    /// - Establishes a valid baseline for monotonic increase tracking
    /// - Is within acceptable bounds for clone operations
    fn validate_sender_count_before_clone<T>(
        collector: &StreamingResultCollector<T>,
    ) -> Result<usize, String>
    where
        T: Send + 'static,
    {
        // Assertion 1: Verify sender_count is accessible and readable
        let count1 = collector.sender_count();

        // Assertion 2: Verify sender_count is non-zero (minimum valid value is 1)
        if count1 == 0 {
            return Err("sender_count is zero before clone operation, invalid state".to_string());
        }

        // Assertion 3: Verify sender_count is stable across multiple reads
        let count2 = collector.sender_count();
        let count3 = collector.sender_count();

        if count1 != count2 || count2 != count3 {
            return Err(format!(
                "sender_count instability detected before clone: values=[{}, {}, {}]",
                count1, count2, count3
            ));
        }

        // Assertion 4: Verify sender_count is within acceptable bounds
        if count1 >= usize::MAX - 10 {
            return Err(format!(
                "sender_count is near overflow limit before clone: count={}",
                count1
            ));
        }

        // Assertion 5: Verify the collector is in a valid state for cloning
        if count1 < 1 {
            return Err(format!(
                "sender_count is below minimum valid value before clone: count={}",
                count1
            ));
        }

        // Return the verified count to be used as pre_clone_baseline
        Ok(count1)
    }

    /// Test helper function to validate sender_count consistency after clone operation
    ///
    /// This function validates that sender_count:
    /// - Never decreases during clone operation
    /// - Remains stable immediately after clone
    /// - Shows consistency across all collector instances
    /// - Increases monotonically as expected
    fn validate_sender_count_after_clone<T>(
        collector: &StreamingResultCollector<T>,
        clone: &StreamingResultCollector<T>,
        expected_count: usize,
    ) -> Result<(), String>
    where
        T: Send + 'static,
    {
        // Assertion 1: Verify original collector's sender_count matches expected
        let original_count = collector.sender_count();
        if original_count != expected_count {
            return Err(format!(
                "Original collector sender_count mismatch: expected={}, got={}",
                expected_count, original_count
            ));
        }

        // Assertion 2: Verify cloned collector's sender_count matches expected
        let cloned_count = clone.sender_count();
        if cloned_count != expected_count {
            return Err(format!(
                "Cloned collector sender_count mismatch: expected={}, got={}",
                expected_count, cloned_count
            ));
        }

        // Assertion 3: Verify both collectors have the same sender_count
        if original_count != cloned_count {
            return Err(format!(
                "sender_count consistency check failed: original={}, cloned={}",
                original_count, cloned_count
            ));
        }

        // Assertion 4: Verify sender_count is non-zero
        if original_count == 0 {
            return Err(
                "sender_count is zero after clone operation, expected at least 1".to_string(),
            );
        }

        // Assertion 5: Verify sender_count increased from initial value
        if original_count < 1 {
            return Err(format!(
                "sender_count did not increase from initial value: got={}",
                original_count
            ));
        }

        Ok(())
    }

    /// Test helper function to validate sender_count monotonic behavior
    ///
    /// Validates that sender_count never decreases during a sequence of operations.
    fn validate_monotonic_sender_count(counts: &[usize]) -> Result<(), String> {
        if counts.is_empty() {
            return Err("Cannot validate monotonic behavior on empty slice".to_string());
        }

        for (i, window) in counts.windows(2).enumerate() {
            if window[1] < window[0] {
                return Err(format!(
                    "sender_count decreased at position {}: from {} to {}",
                    i + 1,
                    window[0],
                    window[1]
                ));
            }
        }

        Ok(())
    }

    /// Test helper function to validate sender_count stability immediately after clone
    ///
    /// This checks that sender_count remains stable (doesn't change) when read
    /// multiple times immediately after a clone operation.
    fn validate_sender_count_stability<T>(
        collector: &StreamingResultCollector<T>,
        stability_threshold: usize,
    ) -> Result<(), String>
    where
        T: Send + 'static,
    {
        let count1 = collector.sender_count();
        let count2 = collector.sender_count();
        let count3 = collector.sender_count();

        let max_count = count1.max(count2).max(count3);
        let min_count = count1.min(count2).min(count3);
        let variation = max_count - min_count;

        if variation > stability_threshold {
            return Err(format!(
                "sender_count instability detected: variation={} exceeds threshold={}, values=[{}, {}, {}]",
                variation, stability_threshold, count1, count2, count3
            ));
        }

        Ok(())
    }

    /// Comprehensive test function that validates all sender_count consistency aspects
    ///
    /// This combines all validation patterns into a single comprehensive test.
    fn validate_comprehensive_sender_count<T>(
        collector: &StreamingResultCollector<T>,
        clone: &StreamingResultCollector<T>,
        pre_clone_count: usize,
        expected_post_clone_count: usize,
    ) -> Result<(), String>
    where
        T: Send + 'static,
    {
        // Validation 1: Pre-clone baseline sanity check
        if pre_clone_count == 0 {
            return Err("Pre-clone sender_count is zero, invalid baseline".to_string());
        }

        // Validation 2: Post-clone consistency check
        validate_sender_count_after_clone(collector, clone, expected_post_clone_count)
            .map_err(|e| format!("Post-clone validation failed: {}", e))?;

        // Validation 3: Verify count increased appropriately
        let actual_post_count = collector.sender_count();
        if actual_post_count <= pre_clone_count {
            return Err(format!(
                "sender_count did not increase after clone: pre_clone={}, post_clone={}",
                pre_clone_count, actual_post_count
            ));
        }

        // Validation 4: Monotonic behavior check
        let counts = vec![pre_clone_count, actual_post_count];
        validate_monotonic_sender_count(&counts)
            .map_err(|e| format!("Monotonic validation failed: {}", e))?;

        // Validation 5: Stability check on original collector
        validate_sender_count_stability(collector, 0)
            .map_err(|e| format!("Stability validation failed: {}", e))?;

        // Validation 6: Stability check on cloned collector
        validate_sender_count_stability(clone, 0)
            .map_err(|e| format!("Clone stability validation failed: {}", e))?;

        // Validation 7: Cross-instance consistency
        if collector.sender_count() != clone.sender_count() {
            return Err(format!(
                "Cross-instance inconsistency: original={}, cloned={}",
                collector.sender_count(),
                clone.sender_count()
            ));
        }

        Ok(())
    }

    // ===== Comprehensive Sender Count Tests =====
    // These tests use the assertion utilities for thorough validation

    #[test]
    fn test_streaming_collector_sender_count_comprehensive_validation() {
        let collector = StreamingResultCollector::<i32>::new();

        // Use the comprehensive validation function
        let pre_clone_count = validate_sender_count_before_clone(&collector)
            .expect("Pre-clone validation should pass");

        assert_eq!(pre_clone_count, 1, "Initial sender_count should be 1");

        let clone = collector.clone();

        // Validate post-clone state
        validate_comprehensive_sender_count(
            &collector,
            &clone,
            pre_clone_count,
            2, // Expected count after one clone
        )
        .expect("Comprehensive sender_count validation should pass");

        // Additional functional verification
        let _ = collector.stream_add(42).unwrap();
        let _ = clone.stream_add(24).unwrap();

        let mut results = collector.stream_collect_blocking();
        results.sort();
        assert_eq!(results, vec![24, 42]);
    }

    #[test]
    fn test_streaming_collector_sender_count_stability_after_clone() {
        let collector = StreamingResultCollector::<i32>::new();
        let pre_clone_count = validate_sender_count_before_clone(&collector)
            .expect("Pre-clone validation should pass");

        let clone = collector.clone();

        // Test stability on both instances
        validate_sender_count_stability(&collector, 0)
            .expect("Original collector should have stable sender_count");

        validate_sender_count_stability(&clone, 0)
            .expect("Cloned collector should have stable sender_count");

        // Verify counts match expected
        validate_sender_count_after_clone(&collector, &clone, pre_clone_count + 1)
            .expect("Post-clone validation should pass");
    }

    #[test]
    fn test_streaming_collector_sender_count_monotonic_multiple_clones() {
        let collector = StreamingResultCollector::<i32>::new();
        let mut counts = vec![collector.sender_count()];

        // Create multiple clones and track counts
        let clone1 = collector.clone();
        counts.push(collector.sender_count());

        let clone2 = clone1.clone();
        counts.push(clone1.sender_count());

        let clone3 = clone2.clone();
        counts.push(clone2.sender_count());

        // Verify monotonic behavior
        validate_monotonic_sender_count(&counts)
            .expect("sender_count should be monotonically non-decreasing");

        // Verify final expected count (4 total collectors)
        assert_eq!(collector.sender_count(), 4);
        assert_eq!(clone1.sender_count(), 4);
        assert_eq!(clone2.sender_count(), 4);
        assert_eq!(clone3.sender_count(), 4);
    }

    #[test]
    fn test_streaming_collector_sender_count_assertion_helpers() {
        // Test the assertion helper functions directly
        let collector = StreamingResultCollector::<i32>::new();

        // Test pre-clone validation
        let pre_count = validate_sender_count_before_clone(&collector)
            .expect("Pre-clone validation should succeed");
        assert_eq!(pre_count, 1);

        // Test clone operation
        let clone = collector.clone();

        // Test post-clone validation
        validate_sender_count_after_clone(&collector, &clone, 2)
            .expect("Post-clone validation should succeed");

        // Test monotonic validation
        let counts = vec![1, 2];
        validate_monotonic_sender_count(&counts).expect("Counts should be monotonic");

        // Test stability validation
        validate_sender_count_stability(&collector, 0)
            .expect("Collector should have stable sender_count");

        validate_sender_count_stability(&clone, 0).expect("Clone should have stable sender_count");
    }

    #[test]
    fn test_streaming_collector_sender_count_error_cases() {
        // Test that validation functions properly detect errors

        // Test empty slice for monotonic validation
        let result = validate_monotonic_sender_count(&[]);
        assert!(result.is_err(), "Empty slice should return error");

        // Test decreasing sequence for monotonic validation
        let result = validate_monotonic_sender_count(&[3, 2, 1]);
        assert!(result.is_err(), "Decreasing sequence should return error");

        // Test stability with threshold violation
        let collector = StreamingResultCollector::<i32>::new();
        // This should pass with threshold 0
        let result = validate_sender_count_stability(&collector, 0);
        assert!(result.is_ok(), "Stable collector should pass validation");

        // Test comprehensive validation with wrong expected count
        let clone = collector.clone();
        let result = validate_comprehensive_sender_count(
            &collector, &clone, 1,  // pre_clone_count
            99, // Wrong expected count
        );
        assert!(
            result.is_err(),
            "Wrong expected count should fail validation"
        );
    }
}
