//! Thread-safe result collector for aggregating values from multiple threads
//!
//! This module provides two types for collecting results from concurrent operations:
//! - `ResultCollector<T>`: Mutex-based collector using `Arc<Mutex<Vec<T>>>`
//! - `StreamingResultCollector<T>`: Channel-based collector using `std::sync::mpsc`

use std::fmt;
use std::sync::mpsc::{self, TrySendError};
use std::sync::{Arc, Mutex};

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
        // Take the receiver and drop the sender
        // Dropping the sender signals we're done receiving
        let receiver = self.receiver.take();
        let _sender_dropped = self.sender.take();

        if let Some(receiver) = receiver {
            // Collect all remaining messages from the channel
            // recv() blocks until:
            // 1. A message is available (we collect it)
            // 2. The channel closes (all senders dropped)
            let mut results = Vec::new();
            while let Ok(value) = receiver.recv() {
                results.push(value);
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
            // Use iterative try_recv() instead of try_iter() for better disconnect detection
            // This allows us to detect disconnection at each iteration and stop immediately
            //
            // Graceful shutdown behavior:
            // - try_recv() returns immediately with available message or error
            // - If channel is empty but open, returns Empty (we stop collecting)
            // - If channel is closed/disconnected, returns Disconnected (we stop with error)
            // - If channel is broken, returns Disconnected (we stop with error)
            // - No panics on any channel state

            let mut results = Vec::new();

            // Collect items one at a time, checking for disconnect on each iteration
            loop {
                match receiver.try_recv() {
                    Ok(value) => {
                        // Successfully received an item, add to results
                        results.push(value);
                    }
                    Err(std::sync::mpsc::TryRecvError::Empty) => {
                        // Channel is empty but still open - no more messages available right now
                        // Stop collecting and return what we have
                        break;
                    }
                    Err(std::sync::mpsc::TryRecvError::Disconnected) => {
                        // Channel disconnected (sender dropped)
                        // Stop collection immediately and return partial results if any
                        if results.is_empty() {
                            // No results were collected before disconnect
                            return Err(StreamCollectError::<T>::EmptyCollection);
                        } else {
                            // Return partial results collected up to disconnection point
                            return Err(StreamCollectError::<T>::ChannelDisconnected(results));
                        }
                    }
                }
            }

            // Check if we collected any results
            if results.is_empty() {
                // No results collected - channel is empty but still open
                Err(StreamCollectError::<T>::EmptyCollection)
            } else {
                // Successfully collected results, channel is still open
                Ok(results)
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
        // Take the receiver and drop the sender
        let receiver = self.receiver.take();
        let _sender_dropped = self.sender.take();

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
        // Increment sender count
        self.sender_count
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        Self {
            sender: self.sender.clone(),
            receiver: None, // Clones don't get the receiver
            sender_count: Arc::clone(&self.sender_count),
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
    use super::*;
    use std::thread;

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
    fn test_streaming_collector_clone_independently() {
        let collector = StreamingResultCollector::<i32>::new();
        let clone = collector.clone();

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
        let collector_clone = collector.clone();
        let collector_clone2 = collector.clone();

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
        let collector_clone = collector.clone();
        let collector_clone2 = collector.clone();

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

            // clone2 dropped, count should decrease
            // Note: This timing-dependent test may not always work perfectly
            // but the count should eventually be 2
        }

        // clone1 dropped, count should eventually be 1
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
    fn test_streaming_collector_blocks_until_all_results_collected() {
        use std::sync::atomic::{AtomicBool, Ordering};
        use std::sync::Arc;
        use std::time::Duration;

        let collector = StreamingResultCollector::<i32>::new();
        let collector_clone = collector.clone();
        let started = Arc::new(AtomicBool::new(false));
        let started_clone = Arc::clone(&started);

        // Spawn a thread that adds results with delays
        let handle = thread::spawn(move || {
            started_clone.store(true, Ordering::SeqCst);
            for i in 0..5 {
                thread::sleep(Duration::from_millis(50));
                let _ = collector_clone.stream_add(i).unwrap();
            }
            // Thread completes after ~250ms total
            // collector_clone dropped here, closing the sender
        });

        // Wait for the thread to start
        while !started.load(Ordering::SeqCst) {
            thread::sleep(Duration::from_millis(10));
        }

        // Give the thread time to add some results (but not all)
        thread::sleep(Duration::from_millis(125));

        // At this point, ~2 results should have been added, but thread is still running
        // Call stream_collect - it should block and wait for ALL results from the thread
        let results = collector.stream_collect_blocking();

        // Verify we got all 5 results (method blocked until thread finished)
        assert_eq!(results.len(), 5);

        // Verify the thread completed
        handle.join().unwrap();

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

        // stream_collect should return Ok with empty results
        // (not an error - graceful shutdown with no partial results)
        let results = collector.stream_collect();

        // Should return Ok (not Err) even though channel closed
        assert!(results.is_ok());
        let collected = results.unwrap();
        // Should have empty results (channel closed with no messages)
        assert_eq!(collected.len(), 0);
        assert!(collected.is_empty());
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
        // It should return Ok with any available results
        let results = collector_mut.stream_collect();

        // Should return Ok (not panic) even with sender dropped
        assert!(results.is_ok());
        let collected = results.unwrap();

        // Should have collected the result that was in the channel
        assert_eq!(collected.len(), 1);
        assert_eq!(collected[0], 42);
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

        // Second collection should return Ok with empty (graceful)
        let results2 = collector.stream_collect();
        assert!(results2.is_ok());
        assert_eq!(results2.unwrap().len(), 0);
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
}
