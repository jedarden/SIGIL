//! Thread spawn helper utilities for testing and concurrent operations
//!
//! This module provides reusable helper functions for spawning multiple threads
//! with proper error handling and resource management.

use std::fmt;
use std::io;
use std::thread;

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

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;

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
}
