//! Common utilities for SIGIL integration tests

#![allow(dead_code)]

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::thread;
use std::time::Duration;

// Import environment detection module from the library crate
// We'll use specific imports where needed rather than re-exporting everything
use sigil_integration_tests::env_detect::{
    detect_bwrap, ensure_xdg_runtime_dir as lib_ensure_xdg_runtime_dir,
};

/// Get the workspace root directory
pub fn workspace_root() -> PathBuf {
    let manifest_dir = std::env::var("CARGO_MANIFEST_DIR").unwrap();
    PathBuf::from(manifest_dir)
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .to_path_buf()
}

/// Get the path to a crate's source file
pub fn crate_source_path(crate_name: &str, file: &str) -> PathBuf {
    workspace_root()
        .join("crates")
        .join(crate_name)
        .join("src")
        .join(file)
}

/// Check if bubblewrap is available on the system
///
/// This function now delegates to the centralized environment detection module.
pub fn is_bwrap_available() -> bool {
    detect_bwrap()
}

/// Wait for a Unix domain socket to appear and be ready for connections
///
/// This polls for socket existence and performs a basic connectivity check.
/// Returns true if the socket is ready within the timeout, false otherwise.
pub fn wait_for_socket(socket_path: &Path, timeout_ms: u64) -> bool {
    let start = std::time::Instant::now();
    let timeout = Duration::from_millis(timeout_ms);
    let poll_interval = Duration::from_millis(100);

    while start.elapsed() < timeout {
        if socket_path.exists() {
            // Socket exists - give it a moment to fully initialize
            // This handles the race between socket creation and daemon readiness
            thread::sleep(Duration::from_millis(100));

            // Verify socket is a Unix socket
            if let Ok(metadata) = fs::metadata(socket_path) {
                // On Unix, file type 12 is a socket
                #[cfg(unix)]
                {
                    use std::os::unix::fs::FileTypeExt;
                    if metadata.file_type().is_socket() {
                        return true;
                    }
                }

                // If not a socket, wait longer and recheck
                thread::sleep(poll_interval);
                continue;
            }
        }
        thread::sleep(poll_interval);
    }

    false
}

/// Wait for daemon to be ready by testing socket connectivity
///
/// This goes beyond socket existence and actually tests if the daemon
/// is accepting connections. It attempts a simple connection test.
pub fn wait_for_daemon_ready(socket_path: &Path, timeout_ms: u64) -> bool {
    let start = std::time::Instant::now();
    let timeout = Duration::from_millis(timeout_ms);

    while start.elapsed() < timeout {
        if socket_path.exists() {
            // Try to connect to the socket to verify daemon is ready
            #[cfg(unix)]
            {
                use std::os::unix::net::UnixStream;
                if UnixStream::connect(socket_path).is_ok() {
                    // Connection succeeded - daemon is ready
                    return true;
                }
            }

            #[cfg(not(unix))]
            {
                // Non-Unix platforms: just check socket existence
                if socket_path.exists() {
                    return true;
                }
            }

            // Connection failed - wait and retry
            thread::sleep(Duration::from_millis(100));
        } else {
            // Socket doesn't exist yet
            thread::sleep(Duration::from_millis(100));
        }
    }

    false
}

/// Ensure XDG_RUNTIME_DIR is set and usable
///
/// If XDG_RUNTIME_DIR is not set, creates a temporary directory and sets it.
/// This ensures consistent socket path behavior across all test environments.
/// Returns the path to the runtime directory.
///
/// This function now delegates to the centralized environment detection module.
pub fn ensure_xdg_runtime_dir() -> PathBuf {
    lib_ensure_xdg_runtime_dir()
}

/// Check if daemon startup is likely to succeed
///
/// This performs pre-flight checks before attempting to start the daemon:
/// - Verifies bwrap availability (for sandbox functionality)
/// - Verifies the daemon binary exists
/// - Returns true if all checks pass, false otherwise
pub fn can_start_daemon(daemon_path: &Path, require_bwrap: bool) -> bool {
    // Check binary exists
    if !daemon_path.exists() {
        eprintln!("Cannot start daemon: binary not found at {:?}", daemon_path);
        return false;
    }

    // Check bwrap availability if required
    if require_bwrap && !is_bwrap_available() {
        eprintln!("Cannot start daemon: bwrap not available (install bubblewrap)");
        return false;
    }

    true
}

/// Create a unique temporary runtime directory for a test
///
/// This creates a fresh temporary directory for each test to avoid
/// conflicts between tests and ensure clean isolation.
pub fn create_test_runtime_dir(test_name: &str) -> PathBuf {
    let temp_runtime = std::env::temp_dir().join(format!(
        "sigil-test-{}-{}-{}",
        test_name,
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
    ));

    fs::create_dir_all(&temp_runtime).expect("Failed to create test runtime dir");

    // Set permissions to 0700 for security
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = fs::metadata(&temp_runtime)
            .expect("Failed to get test runtime dir metadata")
            .permissions();
        perms.set_mode(0o700);
        fs::set_permissions(&temp_runtime, perms)
            .expect("Failed to set test runtime dir permissions");
    }

    temp_runtime
}

/// Cleanup a test runtime directory
///
/// This removes the temporary directory and all its contents.
pub fn cleanup_test_runtime_dir(runtime_dir: &Path) {
    // Ignore errors during cleanup - the directory might already be gone
    let _ = fs::remove_dir_all(runtime_dir);
}

/// Skip test if bwrap is not available
///
/// This macro can be used in tests to skip sandbox-dependent tests
/// when bubblewrap is not installed on the system.
///
/// This now delegates to the centralized skip module.
#[macro_export]
macro_rules! skip_if_no_bwrap {
    () => {
        sigil_integration_tests::env_detect::skip::if_no_bwrap();
    };
    ($($arg:tt)*) => {
        sigil_integration_tests::env_detect::skip::if_no_bwrap_with(&format!($($arg)*));
    };
}

/// Skip test if running in CI environment
///
/// This is useful for tests that require interactive features
/// or specific environment setup not available in CI.
///
/// This now delegates to the centralized skip module.
#[macro_export]
macro_rules! skip_if_ci {
    () => {
        sigil_integration_tests::env_detect::skip::if_ci();
    };
    ($($arg:tt)*) => {
        sigil_integration_tests::env_detect::skip::if_ci_with(&format!($($arg)*));
    };
}

/// Skip test if the binary does not exist
///
/// This macro skips tests when the required binary has not been built yet.
/// This is common during incremental development where not all binaries are available.
///
/// This now delegates to the centralized skip module.
#[macro_export]
macro_rules! skip_if_binary_missing {
    ($binary_path:expr) => {
        sigil_integration_tests::env_detect::skip::if_binary_missing($binary_path);
    };
    ($binary_path:expr, $reason:expr) => {
        sigil_integration_tests::env_detect::skip::if_binary_missing_with($binary_path, $reason);
    };
}

/// Synchronous wrapper for socket availability wait with timeout
///
/// This provides a synchronous interface to the async socket wait utilities,
/// suitable for use in non-async test functions.
///
/// # Arguments
///
/// * `socket_path` - Path to the socket file to wait for
/// * `timeout_ms` - Maximum time to wait in milliseconds
///
/// # Returns
///
/// * `Ok(())` if the socket appears and is accessible within timeout
/// * `Err(String)` with error message if timeout occurs or socket is invalid
///
/// # Example
///
/// ```no_run
/// # use std::path::Path;
/// # fn example() -> Result<(), String> {
/// match wait_for_socket_sync(Path::new("/tmp/sigil.sock"), 5000) {
///     Ok(()) => println!("Socket ready"),
///     Err(e) => eprintln!("Socket wait failed: {}", e),
/// }
/// # Ok(())
/// # }
/// ```
pub fn wait_for_socket_sync(socket_path: &Path, timeout_ms: u64) -> Result<(), String> {
    let start = std::time::Instant::now();
    let timeout = Duration::from_millis(timeout_ms);
    let poll_interval = Duration::from_millis(50);
    let mut last_error = String::new();

    while start.elapsed() < timeout {
        if socket_path.exists() {
            // Verify socket is a Unix socket
            if let Ok(metadata) = fs::metadata(socket_path) {
                #[cfg(unix)]
                {
                    use std::os::unix::fs::FileTypeExt;
                    if metadata.file_type().is_socket() {
                        // Try to connect to verify daemon is ready
                        #[cfg(unix)]
                        {
                            use std::os::unix::net::UnixStream;
                            if let Ok(_) = UnixStream::connect(socket_path) {
                                return Ok(());
                            } else {
                                last_error = format!(
                                    "Socket exists but daemon not ready at {:?}",
                                    socket_path
                                );
                            }
                        }
                    } else {
                        last_error =
                            format!("File exists but is not a Unix socket: {:?}", socket_path);
                    }
                }

                #[cfg(not(unix))]
                {
                    // Non-Unix platforms: just check existence
                    return Ok(());
                }
            }
        }
        thread::sleep(poll_interval);
    }

    Err(if last_error.is_empty() {
        format!(
            "Timeout waiting for socket {:?} (waited {:?}, timeout={:?})",
            socket_path,
            start.elapsed(),
            timeout
        )
    } else {
        format!(
            "Timeout waiting for socket: {} (waited {:?})",
            last_error,
            start.elapsed()
        )
    })
}

/// Daemon startup health check with comprehensive validation
///
/// This performs a full health check after daemon startup to verify:
/// - Socket file exists and is valid
/// - Daemon process is running (if PID checkable)
/// - Socket accepts connections
///
/// # Arguments
///
/// * `socket_path` - Path to the daemon socket
///
/// # Returns
///
/// * `Ok(())` if all health checks pass
/// * `Err(String)` with specific health check failure message
pub fn daemon_health_check(socket_path: &Path) -> Result<(), String> {
    // Check 1: Socket exists
    if !socket_path.exists() {
        return Err(format!("Socket does not exist: {:?}", socket_path));
    }

    // Check 2: Socket is valid Unix socket
    let metadata =
        fs::metadata(socket_path).map_err(|e| format!("Cannot read socket metadata: {}", e))?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::FileTypeExt;
        if !metadata.file_type().is_socket() {
            return Err(format!(
                "Path exists but is not a Unix socket: {:?}",
                socket_path
            ));
        }
    }

    // Check 3: Socket accepts connections
    #[cfg(unix)]
    {
        use std::os::unix::net::UnixStream;
        UnixStream::connect(socket_path)
            .map_err(|e| format!("Socket exists but daemon not accepting connections: {}", e))?;
    }

    Ok(())
}

/// Socket availability wait with health check
///
/// This combines socket waiting with comprehensive health validation,
/// providing a single call for robust daemon startup testing.
///
/// # Arguments
///
/// * `socket_path` - Path to the daemon socket
/// * `timeout_ms` - Maximum time to wait in milliseconds
///
/// # Returns
///
/// * `Ok(())` if socket is ready and passes all health checks
/// * `Err(String)` with specific failure message
///
/// # Example
///
/// ```no_run
/// # use std::path::Path;
/// # fn example() -> Result<(), String> {
/// socket_wait_helper(Path::new("/tmp/sigil.sock"), 5000)?;
/// println!("Daemon is ready and healthy");
/// # Ok(())
/// # }
/// ```
pub fn socket_wait_helper(socket_path: &Path, timeout_ms: u64) -> Result<(), String> {
    // First wait for socket to appear
    wait_for_socket_sync(socket_path, timeout_ms)?;

    // Then perform health check
    daemon_health_check(socket_path)?;

    Ok(())
}

/// Create a blocking runtime for async operations (if needed)
///
/// This function creates a tokio runtime for running async operations
/// in synchronous test code.
#[allow(dead_code)]
pub fn create_blocking_runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("Failed to create tokio runtime")
}
