//! On-demand daemon startup with lockfile coordination
//!
//! This module provides the on-demand startup functionality for the SIGIL daemon.
//! When a client needs to connect to the daemon, it can use this module to:
//! 1. Check if the daemon is already running
//! 2. If not running, acquire an exclusive lockfile
//! 3. Start the daemon process
//! 4. Wait for the socket to appear (with timeout)
//! 5. Release the lockfile
//! 6. Proceed with the original request
//!
//! The lockfile coordination ensures that only one daemon instance starts even when
//! multiple clients attempt to connect simultaneously.

use anyhow::{Context, Result};
use std::fs::File;
use std::io;
use std::os::unix::io::AsRawFd;
use std::path::{Path, PathBuf};
use std::time::Duration;
use tokio::time::sleep;
use tracing::{debug, info, warn};

/// Default timeout for waiting for the daemon socket to appear
const SOCKET_WAIT_TIMEOUT: Duration = Duration::from_secs(5);
/// Interval between socket existence checks
const SOCKET_CHECK_INTERVAL: Duration = Duration::from_millis(100);
/// Maximum number of spawn attempts
const MAX_SPAWN_ATTEMPTS: u32 = 3;

/// On-demand daemon startup coordinator
pub struct OnDemandCoordinator {
    /// Path to the daemon socket
    socket_path: PathBuf,
    /// Path to the lockfile
    lockfile_path: PathBuf,
    /// Path to the sigild binary
    daemon_binary: PathBuf,
}

impl OnDemandCoordinator {
    /// Create a new on-demand coordinator
    ///
    /// # Arguments
    ///
    /// * `socket_path` - Path to the daemon socket (default: $XDG_RUNTIME_DIR/sigil.sock)
    /// * `daemon_binary` - Path to the sigild binary (default: searches PATH)
    pub fn new<P: AsRef<Path>>(socket_path: P, daemon_binary: Option<P>) -> Result<Self> {
        let socket_path = socket_path.as_ref().to_path_buf();

        // Determine lockfile path (same directory as socket with .lock extension)
        let lockfile_path = socket_path.with_extension("lock");

        // Determine daemon binary path
        let daemon_binary = if let Some(path) = daemon_binary {
            path.as_ref().to_path_buf()
        } else {
            Self::find_daemon_binary()?
        };

        Ok(Self {
            socket_path,
            lockfile_path,
            daemon_binary,
        })
    }

    /// Find the sigild binary in PATH
    fn find_daemon_binary() -> Result<PathBuf> {
        // Try to find sigild in the same directory as the current executable
        if let Ok(current_exe) = std::env::current_exe() {
            if let Some(parent) = current_exe.parent() {
                let sigild_path = parent.join("sigild");
                if sigild_path.exists() {
                    debug!("Found sigild at: {}", sigild_path.display());
                    return Ok(sigild_path);
                }
            }
        }

        // Fall back to searching PATH
        if let Ok(path_var) = std::env::var("PATH") {
            for dir in std::env::split_paths(&path_var) {
                let sigild_path = dir.join("sigild");
                if sigild_path.exists() {
                    debug!("Found sigild in PATH at: {}", sigild_path.display());
                    return Ok(sigild_path);
                }
            }
        }

        // Default to /usr/local/bin/sigild
        let default_path = PathBuf::from("/usr/local/bin/sigild");
        warn!(
            "Could not find sigild in PATH, using default: {}",
            default_path.display()
        );
        Ok(default_path)
    }

    /// Check if the daemon is already running
    pub fn is_daemon_running(&self) -> bool {
        self.socket_path.exists()
    }

    /// Ensure the daemon is running, starting it if necessary
    ///
    /// This method implements the lockfile coordination protocol:
    /// 1. Check if daemon is running (socket exists)
    /// 2. If not running, acquire exclusive lockfile
    /// 3. Spawn daemon process
    /// 4. Wait for socket to appear (with timeout)
    /// 5. Release lockfile
    /// 6. Return success
    ///
    /// # Returns
    ///
    /// Returns `Ok(true)` if the daemon is running (either was already running or was started),
    /// `Ok(false)` if the daemon failed to start, and `Err` for other errors.
    pub async fn ensure_daemon_running(&self) -> Result<bool> {
        // Check if daemon is already running
        if self.is_daemon_running() {
            debug!("Daemon is already running");
            return Ok(true);
        }

        info!("Daemon is not running, attempting to start it");

        // Try multiple times in case of race conditions
        for attempt in 1..=MAX_SPAWN_ATTEMPTS {
            debug!("Spawn attempt {}", attempt);

            // Check again before acquiring lock (another client may have started it)
            if self.is_daemon_running() {
                info!("Daemon was started by another client");
                return Ok(true);
            }

            // Acquire exclusive lockfile
            let _lockfile = self.acquire_lockfile().await?;

            // Double-check after acquiring lock (another client may have started it while we waited)
            if self.is_daemon_running() {
                info!("Daemon was started while waiting for lockfile");
                return Ok(true);
            }

            // Spawn the daemon
            match self.spawn_daemon().await {
                Ok(_) => {
                    // Wait for the socket to appear
                    match self.wait_for_socket().await {
                        Ok(_) => {
                            info!("Daemon started successfully");
                            return Ok(true);
                        }
                        Err(e) => {
                            warn!("Failed to wait for socket: {}", e);
                            // Continue to next attempt
                        }
                    }
                }
                Err(e) => {
                    warn!("Failed to spawn daemon (attempt {}): {}", attempt, e);
                    // Continue to next attempt
                }
            }

            // Lockfile is released when _lockfile goes out of scope
            // Small delay before next attempt
            sleep(Duration::from_millis(100)).await;
        }

        Err(anyhow::anyhow!(
            "Failed to start daemon after {} attempts",
            MAX_SPAWN_ATTEMPTS
        ))
    }

    /// Acquire an exclusive lockfile using flock
    ///
    /// The lockfile is automatically released when the returned LockFileGuard is dropped.
    async fn acquire_lockfile(&self) -> Result<LockFileGuard> {
        // Ensure the parent directory exists
        if let Some(parent) = self.lockfile_path.parent() {
            if !parent.exists() {
                std::fs::create_dir_all(parent).with_context(|| {
                    format!("Failed to create lockfile directory: {}", parent.display())
                })?;
            }
        }

        // Open or create the lockfile
        let file = File::options()
            .write(true)
            .create(true)
            .truncate(true)
            .open(&self.lockfile_path)
            .with_context(|| {
                format!("Failed to open lockfile: {}", self.lockfile_path.display())
            })?;

        // Acquire exclusive lock using flock
        // This is a blocking call that will wait until the lock is available
        unsafe {
            let ret = libc::flock(file.as_raw_fd(), libc::LOCK_EX);
            if ret != 0 {
                let err = io::Error::last_os_error();
                return Err(anyhow::anyhow!("Failed to acquire lockfile: {}", err));
            }
        }

        debug!("Acquired lockfile: {}", self.lockfile_path.display());

        Ok(LockFileGuard {
            file,
            path: self.lockfile_path.clone(),
        })
    }

    /// Spawn the daemon process
    async fn spawn_daemon(&self) -> Result<()> {
        info!("Spawning daemon: {}", self.daemon_binary.display());

        // Use tokio::process::Command to spawn the daemon
        let mut child = tokio::process::Command::new(&self.daemon_binary)
            .arg("start")
            .arg("--socket")
            .arg(&self.socket_path)
            .spawn()
            .with_context(|| format!("Failed to spawn daemon: {}", self.daemon_binary.display()))?;

        // Don't wait for the child process - it should daemonize itself
        // Just check if it started successfully
        sleep(Duration::from_millis(100)).await;

        match child.try_wait() {
            Ok(Some(status)) => {
                // Child already exited
                if status.success() {
                    debug!("Daemon process exited successfully (may have daemonized)");
                    Ok(())
                } else {
                    Err(anyhow::anyhow!(
                        "Daemon process exited with error: {:?}",
                        status
                    ))
                }
            }
            Ok(None) => {
                // Child is still running (good - it's daemonizing)
                debug!("Daemon process is running");
                Ok(())
            }
            Err(e) => {
                // Error checking child status
                debug!("Could not check daemon status: {}", e);
                // Assume it's running
                Ok(())
            }
        }
    }

    /// Wait for the daemon socket to appear
    ///
    /// # Returns
    ///
    /// Returns `Ok` when the socket appears, or `Err` if the timeout is reached.
    async fn wait_for_socket(&self) -> Result<()> {
        let start = std::time::Instant::now();
        let mut elapsed = Duration::ZERO;

        while elapsed < SOCKET_WAIT_TIMEOUT {
            if self.socket_path.exists() {
                debug!("Socket appeared: {}", self.socket_path.display());
                return Ok(());
            }

            sleep(SOCKET_CHECK_INTERVAL).await;
            elapsed = start.elapsed();
        }

        Err(anyhow::anyhow!(
            "Timeout waiting for socket to appear: {} (waited {:?})",
            self.socket_path.display(),
            elapsed
        ))
    }
}

/// Guard for a lockfile that releases the lock when dropped
struct LockFileGuard {
    file: File,
    path: PathBuf,
}

impl Drop for LockFileGuard {
    fn drop(&mut self) {
        unsafe {
            // Release the lock
            let ret = libc::flock(self.file.as_raw_fd(), libc::LOCK_UN);
            if ret != 0 {
                warn!("Failed to release lockfile: {}", io::Error::last_os_error());
            } else {
                debug!("Released lockfile: {}", self.path.display());
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::TempDir;

    #[test]
    fn test_coordinator_creation() {
        let temp_dir = TempDir::new().unwrap();
        let socket_path = temp_dir.path().join("sigil.sock");

        let coordinator = OnDemandCoordinator::new(&socket_path, None).unwrap();
        assert_eq!(coordinator.socket_path, socket_path);
        assert_eq!(
            coordinator.lockfile_path,
            socket_path.with_extension("lock")
        );
    }

    #[test]
    fn test_is_daemon_running() {
        let temp_dir = TempDir::new().unwrap();
        let socket_path = temp_dir.path().join("sigil.sock");

        let coordinator = OnDemandCoordinator::new(&socket_path, None).unwrap();

        // Socket doesn't exist
        assert!(!coordinator.is_daemon_running());

        // Create socket file
        fs::File::create(&socket_path).unwrap();

        // Socket exists
        assert!(coordinator.is_daemon_running());
    }

    #[tokio::test]
    async fn test_acquire_lockfile() {
        let temp_dir = TempDir::new().unwrap();
        let socket_path = temp_dir.path().join("sigil.sock");

        let coordinator = OnDemandCoordinator::new(&socket_path, None).unwrap();

        // Acquire lockfile
        let _lock = coordinator.acquire_lockfile().await.unwrap();

        // Lockfile should exist
        assert!(coordinator.lockfile_path.exists());
    }

    #[tokio::test]
    async fn test_lockfile_guard_release() {
        let temp_dir = TempDir::new().unwrap();
        let socket_path = temp_dir.path().join("sigil.sock");

        let coordinator = OnDemandCoordinator::new(&socket_path, None).unwrap();

        {
            let _lock = coordinator.acquire_lockfile().await.unwrap();
            // Lockfile is held
        }
        // Lockfile should be released (but file still exists)

        // We can't easily test that the lock is released without another process,
        // but we can verify the file exists
        assert!(coordinator.lockfile_path.exists());
    }
}
