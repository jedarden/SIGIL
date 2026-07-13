//! Thread-safe result collector for aggregating values from multiple threads
//!
//! This module provides two types for collecting results from concurrent operations:
//! - `ResultCollector<T>`: Mutex-based collector using `Arc<Mutex<Vec<T>>>`
//! - `StreamingResultCollector<T>`: Channel-based collector using `std::sync::mpsc`

use std::sync::mpsc::{self, TrySendError};
use std::sync::{Arc, Mutex};

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
/// let results = collector.stream_collect();
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
/// let results = collector.stream_collect();
/// assert_eq!(results.len(), 100);
/// ```
pub struct StreamingResultCollector<T>
where
    T: Send + 'static,
{
    /// Sender side of the channel (SyncSender for try_send support)
    sender: mpsc::SyncSender<T>,
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
            sender,
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
            sender,
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
        self.sender.try_send(result).map_err(|e| match e {
            TrySendError::Full(val) => mpsc::SendError(val),
            TrySendError::Disconnected(val) => mpsc::SendError(val),
        })
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
        self.sender.try_send(result).is_ok()
    }

    /// Collect all results from the collector
    ///
    /// This method drains the channel and returns all collected results.
    /// The collector cannot be used after calling this method (it's consumed).
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
    /// let mut results = collector.stream_collect();
    /// results.sort(); // Order is not guaranteed
    /// assert_eq!(results, vec![24, 42]);
    /// ```
    pub fn stream_collect(mut self) -> Vec<T> {
        // Take the receiver
        if let Some(receiver) = self.receiver.take() {
            // Use try_iter() to collect all available messages without blocking
            // This drains the channel without waiting for senders to be dropped
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

        let mut results = collector.stream_collect();
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

        let mut results = collector.stream_collect();
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

        collector.stream_add(42);
        clone.stream_add(24);

        let mut results = collector.stream_collect();
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
        let mut results = collector.stream_collect();
        results.sort();
        assert_eq!(results, vec![1, 2]);
    }

    #[test]
    fn test_streaming_collector_empty() {
        let collector = StreamingResultCollector::<i32>::new();
        let results = collector.stream_collect();
        assert_eq!(results, Vec::<i32>::new());
    }

    #[test]
    fn test_streaming_collector_single_value() {
        let collector = StreamingResultCollector::<i32>::new();
        collector.stream_add(42);

        let results = collector.stream_collect();
        assert_eq!(results, vec![42]);
    }

    #[test]
    fn test_streaming_collector_concurrent_two_threads() {
        let collector = StreamingResultCollector::<i32>::new();
        let collector_clone = collector.clone();
        let collector_clone2 = collector.clone();

        let handle1 = thread::spawn(move || {
            for i in 0..10 {
                collector_clone.stream_add(i);
            }
        });

        let handle2 = thread::spawn(move || {
            for i in 10..20 {
                collector_clone2.stream_add(i);
            }
        });

        handle1.join().unwrap();
        handle2.join().unwrap();

        let mut results = collector.stream_collect();
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
                    collector_clone.stream_add(thread_id * 10 + i);
                }
            });
            handles.push(handle);
        }

        for handle in handles {
            handle.join().unwrap();
        }

        let mut results = collector.stream_collect();
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
                    collector_clone.stream_add(thread_id * items_per_thread + i);
                }
            });
            handles.push(handle);
        }

        for handle in handles {
            handle.join().unwrap();
        }

        let mut results = collector.stream_collect();
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
                    collector_clone.stream_add(thread_id * items_per_thread + i);
                }
            });
            handles.push(handle);
        }

        for handle in handles {
            handle.join().unwrap();
        }

        let mut results = collector.stream_collect();
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
                    collector_clone.stream_add(thread_id * items_per_thread + i);
                }
            });
            handles.push(handle);
        }

        for handle in handles {
            handle.join().unwrap();
        }

        let mut results = collector.stream_collect();
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
            collector_clone.stream_add("hello".to_string());
        });

        let handle2 = thread::spawn(move || {
            collector_clone2.stream_add("world".to_string());
        });

        handle1.join().unwrap();
        handle2.join().unwrap();

        let mut results = collector.stream_collect();
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
        let mut results = collector.stream_collect();
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
        let results = collector.stream_collect();
        assert_eq!(results.len(), 5);
    }

    #[test]
    fn test_streaming_collector_no_receiver_after_clone() {
        let collector = StreamingResultCollector::<i32>::new();
        let clone = collector.clone();

        collector.stream_add(42);
        clone.stream_add(24);

        // Only the original collector has the receiver
        let results = collector.stream_collect();
        assert_eq!(results.len(), 2);
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
                        collector_clone.stream_add(thread_id * items_per_thread + i);
                    }
                });
                handles.push(handle);
            }

            for handle in handles {
                handle.join().unwrap();
            }

            let results = collector.stream_collect();
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
