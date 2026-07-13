//! Thread-safe result collector for aggregating values from multiple threads
//!
//! This module provides a `ResultCollector<T>` type that allows multiple threads
//! to safely collect and aggregate results using `Arc<Mutex<Vec<T>>>`.

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

#[cfg(test)]
mod tests {
    use super::*;

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
}
