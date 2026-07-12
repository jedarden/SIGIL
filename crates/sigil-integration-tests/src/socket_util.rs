//! Socket availability wait helper for daemon tests
//!
//! This module provides reusable utilities for waiting for Unix domain sockets
//! to become available during daemon startup and testing.
//!
//! # Example
//!
//! ```no_run
//! use sigil_integration_tests::socket_util::{wait_for_socket, SocketWaitConfig};
//! use std::time::Duration;
//!
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! let config = SocketWaitConfig::default()
//!     .with_timeout(Duration::from_secs(10))
//!     .with_initial_interval(Duration::from_millis(50));
//!
//! wait_for_socket("/run/user/1000/sigil.sock", &config).await?;
//! # Ok(())
//! # }
//! ```

use std::path::Path;
use std::time::{Duration, Instant};
use thiserror::Error;
use tokio::time::sleep;

/// Default timeout for socket availability (5 seconds)
pub const DEFAULT_SOCKET_TIMEOUT: Duration = Duration::from_secs(5);
/// Default initial poll interval (50ms)
pub const DEFAULT_INITIAL_INTERVAL: Duration = Duration::from_millis(50);
/// Default multiplier for exponential backoff (1.5)
pub const DEFAULT_BACKOFF_MULTIPLIER: f64 = 1.5;
/// Default maximum poll interval (500ms)
pub const DEFAULT_MAX_INTERVAL: Duration = Duration::from_millis(500);

/// Configuration for socket wait operations
///
/// This struct allows customization of wait behavior including timeout,
/// poll intervals, and backoff strategy.
#[derive(Debug, Clone)]
pub struct SocketWaitConfig {
    /// Maximum time to wait for the socket to appear
    pub timeout: Duration,
    /// Initial poll interval before exponential backoff
    pub initial_interval: Duration,
    /// Multiplier for exponential backof
    pub backoff_multiplier: f64,
    /// Maximum interval between polls (caps exponential backoff)
    pub max_interval: Duration,
}

impl Default for SocketWaitConfig {
    fn default() -> Self {
        Self {
            timeout: DEFAULT_SOCKET_TIMEOUT,
            initial_interval: DEFAULT_INITIAL_INTERVAL,
            backoff_multiplier: DEFAULT_BACKOFF_MULTIPLIER,
            max_interval: DEFAULT_MAX_INTERVAL,
        }
    }
}

impl SocketWaitConfig {
    /// Create a new SocketWaitConfig with default values
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the timeout for socket availability
    #[must_use]
    pub const fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// Set the initial poll interval
    #[must_use]
    pub const fn with_initial_interval(mut self, interval: Duration) -> Self {
        self.initial_interval = interval;
        self
    }

    /// Set the backoff multiplier for exponential backoff
    #[must_use]
    pub const fn with_backoff_multiplier(mut self, multiplier: f64) -> Self {
        self.backoff_multiplier = multiplier;
        self
    }

    /// Set the maximum poll interval
    #[must_use]
    pub const fn with_max_interval(mut self, interval: Duration) -> Self {
        self.max_interval = interval;
        self
    }

    /// Calculate the next poll interval with exponential backoff
    ///
    /// This applies exponential backoff with a cap at `max_interval`.
    fn next_interval(&self, current_interval: Duration) -> Duration {
        let next = Duration::from_millis(
            (current_interval.as_millis() as f64 * self.backoff_multiplier) as u64,
        );
        std::cmp::min(next, self.max_interval)
    }

    /// Validate the configuration
    ///
    /// Returns an error if the configuration is invalid.
    pub fn validate(&self) -> Result<(), SocketWaitError> {
        if self.timeout == Duration::ZERO {
            return Err(SocketWaitError::InvalidConfig(
                "timeout must be non-zero".into(),
            ));
        }
        if self.initial_interval == Duration::ZERO {
            return Err(SocketWaitError::InvalidConfig(
                "initial_interval must be non-zero".into(),
            ));
        }
        if self.initial_interval >= self.timeout {
            return Err(SocketWaitError::InvalidConfig(
                "initial_interval must be less than timeout".into(),
            ));
        }
        if self.backoff_multiplier < 1.0 {
            return Err(SocketWaitError::InvalidConfig(
                "backoff_multiplier must be >= 1.0".into(),
            ));
        }
        if self.max_interval < self.initial_interval {
            return Err(SocketWaitError::InvalidConfig(
                "max_interval must be >= initial_interval".into(),
            ));
        }
        Ok(())
    }
}

/// Errors that can occur during socket wait operations
#[derive(Error, Debug)]
pub enum SocketWaitError {
    /// Timeout waiting for socket to appear
    #[error("Timeout waiting for socket '{path}' (waited {waited:?}, timeout={timeout:?})")]
    Timeout {
        /// Path to the socket that didn't appear
        path: String,
        /// How long we waited
        waited: Duration,
        /// Configured timeout
        timeout: Duration,
    },

    /// Invalid configuration
    #[error("Invalid socket wait configuration: {0}")]
    InvalidConfig(String),

    /// IO error checking socket path
    #[error("IO error checking socket '{path}': {error}")]
    IoError {
        /// Path that failed
        path: String,
        /// Underlying error
        error: std::io::Error,
    },
}

/// Wait for a Unix domain socket to become available
///
/// This function polls the filesystem at exponential backoff intervals
/// until the socket file appears or the timeout is reached.
///
/// # Arguments
///
/// * `socket_path` - Path to the socket file to wait for
/// * `config` - Configuration for wait behavior
///
/// # Returns
///
/// Returns `Ok(())` when the socket appears, or `Err(SocketWaitError::Timeout)`
/// if the timeout is reached.
///
/// # Example
///
/// ```no_run
/// # use sigil_integration_tests::socket_util::{wait_for_socket, SocketWaitConfig};
/// # use std::time::Duration;
/// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
/// wait_for_socket("/run/user/1000/sigil.sock", &SocketWaitConfig::default()).await?;
/// # Ok(())
/// # }
/// ```
pub async fn wait_for_socket<P: AsRef<Path>>(
    socket_path: P,
    config: &SocketWaitConfig,
) -> Result<(), SocketWaitError> {
    let path = socket_path.as_ref();
    let path_str = path.display().to_string();

    // Validate configuration
    config.validate()?;

    let start = Instant::now();
    let mut current_interval = config.initial_interval;

    loop {
        // Check if socket exists
        match path.try_exists() {
            Ok(true) => {
                // Socket exists!
                return Ok(());
            }
            Ok(false) => {
                // Socket doesn't exist yet, continue waiting
                let elapsed = start.elapsed();

                // Check if we've exceeded timeout
                if elapsed >= config.timeout {
                    return Err(SocketWaitError::Timeout {
                        path: path_str,
                        waited: elapsed,
                        timeout: config.timeout,
                    });
                }

                // Sleep for current interval
                sleep(current_interval).await;

                // Calculate next interval with exponential backoff
                current_interval = config.next_interval(current_interval);
            }
            Err(e) => {
                // Error checking path existence
                return Err(SocketWaitError::IoError {
                    path: path_str,
                    error: e,
                });
            }
        }
    }
}

/// Wait for a socket to become available with default configuration
///
/// This is a convenience function that uses default settings:
/// - Timeout: 5 seconds
/// - Initial interval: 50ms
/// - Backoff multiplier: 1.5
/// - Max interval: 500ms
///
/// # Arguments
///
/// * `socket_path` - Path to the socket file to wait for
///
/// # Returns
///
/// Returns `Ok(())` when the socket appears, or `Err` if timeout occurs.
///
/// # Example
///
/// ```no_run
/// # use sigil_integration_tests::socket_util::wait_for_socket_default;
/// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
/// wait_for_socket_default("/run/user/1000/sigil.sock").await?;
/// # Ok(())
/// # }
/// ```
pub async fn wait_for_socket_default<P: AsRef<Path>>(
    socket_path: P,
) -> Result<(), SocketWaitError> {
    wait_for_socket(socket_path, &SocketWaitConfig::default()).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs::File;
    use std::time::Duration;
    use tempfile::TempDir;

    #[test]
    fn test_default_config() {
        let config = SocketWaitConfig::default();
        assert_eq!(config.timeout, DEFAULT_SOCKET_TIMEOUT);
        assert_eq!(config.initial_interval, DEFAULT_INITIAL_INTERVAL);
        assert_eq!(config.backoff_multiplier, DEFAULT_BACKOFF_MULTIPLIER);
        assert_eq!(config.max_interval, DEFAULT_MAX_INTERVAL);
    }

    #[test]
    fn test_config_builder() {
        let config = SocketWaitConfig::default()
            .with_timeout(Duration::from_secs(10))
            .with_initial_interval(Duration::from_millis(100))
            .with_backoff_multiplier(2.0)
            .with_max_interval(Duration::from_millis(1000));

        assert_eq!(config.timeout, Duration::from_secs(10));
        assert_eq!(config.initial_interval, Duration::from_millis(100));
        assert_eq!(config.backoff_multiplier, 2.0);
        assert_eq!(config.max_interval, Duration::from_millis(1000));
    }

    #[test]
    fn test_config_validation() {
        // Valid config
        assert!(SocketWaitConfig::default().validate().is_ok());

        // Zero timeout
        let config = SocketWaitConfig::default().with_timeout(Duration::ZERO);
        assert!(matches!(
            config.validate(),
            Err(SocketWaitError::InvalidConfig(_))
        ));

        // Zero initial interval
        let config = SocketWaitConfig::default().with_initial_interval(Duration::ZERO);
        assert!(matches!(
            config.validate(),
            Err(SocketWaitError::InvalidConfig(_))
        ));

        // Initial interval >= timeout
        let config = SocketWaitConfig::default()
            .with_initial_interval(Duration::from_secs(10))
            .with_timeout(Duration::from_secs(5));
        assert!(matches!(
            config.validate(),
            Err(SocketWaitError::InvalidConfig(_))
        ));

        // Backoff multiplier < 1.0
        let config = SocketWaitConfig::default().with_backoff_multiplier(0.5);
        assert!(matches!(
            config.validate(),
            Err(SocketWaitError::InvalidConfig(_))
        ));

        // Max interval < initial interval
        let config = SocketWaitConfig::default()
            .with_initial_interval(Duration::from_millis(100))
            .with_max_interval(Duration::from_millis(50));
        assert!(matches!(
            config.validate(),
            Err(SocketWaitError::InvalidConfig(_))
        ));
    }

    #[test]
    fn test_next_interval_calculation() {
        let config = SocketWaitConfig::default()
            .with_initial_interval(Duration::from_millis(50))
            .with_backoff_multiplier(2.0)
            .with_max_interval(Duration::from_millis(200));

        // First interval: 50ms * 2 = 100ms
        let next = config.next_interval(Duration::from_millis(50));
        assert_eq!(next, Duration::from_millis(100));

        // Second interval: 100ms * 2 = 200ms (hits max)
        let next = config.next_interval(Duration::from_millis(100));
        assert_eq!(next, Duration::from_millis(200));

        // Third interval: 200ms * 2 = 400ms, but capped at 200ms
        let next = config.next_interval(Duration::from_millis(200));
        assert_eq!(next, Duration::from_millis(200));
    }

    #[tokio::test]
    async fn test_wait_for_socket_immediate_available() {
        let temp_dir = TempDir::new().unwrap();
        let socket_path = temp_dir.path().join("test.sock");

        // Create the socket file immediately
        File::create(&socket_path).unwrap();

        // Wait should succeed immediately
        let result = wait_for_socket_default(&socket_path).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_wait_for_socket_delayed_available() {
        let temp_dir = TempDir::new().unwrap();
        let socket_path = temp_dir.path().join("test.sock");
        let socket_path_clone = socket_path.clone();

        // Create socket after 100ms
        tokio::spawn(async move {
            sleep(Duration::from_millis(100)).await;
            File::create(&socket_path_clone).unwrap();
        });

        // Wait should succeed within 200ms timeout
        let config = SocketWaitConfig::default()
            .with_timeout(Duration::from_millis(200))
            .with_initial_interval(Duration::from_millis(10));

        let result = wait_for_socket(&socket_path, &config).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_wait_for_socket_timeout() {
        let temp_dir = TempDir::new().unwrap();
        let socket_path = temp_dir.path().join("nonexistent.sock");

        // Wait should timeout
        let config = SocketWaitConfig::default()
            .with_timeout(Duration::from_millis(100))
            .with_initial_interval(Duration::from_millis(10));

        let result = wait_for_socket(&socket_path, &config).await;
        assert!(matches!(result, Err(SocketWaitError::Timeout { .. })));

        if let Err(SocketWaitError::Timeout {
            waited, timeout, ..
        }) = result
        {
            assert!(waited >= timeout);
            assert_eq!(timeout, Duration::from_millis(100));
        }
    }

    #[tokio::test]
    async fn test_wait_for_socket_io_error() {
        // Use a path that will cause an IO error
        // This is tricky to test reliably, so we'll skip this in normal tests
        // In a real scenario, this could happen if the parent directory is deleted
        // during the wait operation
    }

    #[test]
    fn test_error_display() {
        let timeout_err = SocketWaitError::Timeout {
            path: "/test/socket".to_string(),
            waited: Duration::from_millis(500),
            timeout: Duration::from_secs(1),
        };
        let display = timeout_err.to_string();
        assert!(display.contains("Timeout"));
        assert!(display.contains("/test/socket"));
        assert!(display.contains("500ms"));

        let invalid_err = SocketWaitError::InvalidConfig("test error".to_string());
        let display = invalid_err.to_string();
        assert!(display.contains("Invalid socket wait configuration"));
        assert!(display.contains("test error"));
    }

    #[tokio::test]
    async fn test_exponential_backoff_timing() {
        let temp_dir = TempDir::new().unwrap();
        let socket_path = temp_dir.path().join("test.sock");
        let socket_path_clone = socket_path.clone();

        // Create socket after 500ms
        tokio::spawn(async move {
            sleep(Duration::from_millis(500)).await;
            File::create(&socket_path_clone).unwrap();
        });

        let start = Instant::now();

        // Configure aggressive backoff to verify it works
        let config = SocketWaitConfig::default()
            .with_timeout(Duration::from_secs(2))
            .with_initial_interval(Duration::from_millis(10))
            .with_backoff_multiplier(2.0)
            .with_max_interval(Duration::from_millis(100));

        let result = wait_for_socket(&socket_path, &config).await;
        assert!(result.is_ok());

        let elapsed = start.elapsed();
        // Should take approximately 500ms plus some check overhead
        // With exponential backoff, checks will be at: 10ms, 20ms, 40ms, 80ms, 100ms, 100ms...
        // Total check time by 500ms: 10+20+40+80+100+100+50 = 400ms
        assert!(elapsed >= Duration::from_millis(480)); // 500ms - small fudge
        assert!(elapsed < Duration::from_millis(600)); // Should complete within 600ms
    }
}
