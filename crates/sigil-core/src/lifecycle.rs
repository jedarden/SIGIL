//! Daemon lifecycle management utilities
//!
//! This module provides functionality for managing the SIGIL daemon lifecycle,
//! including on-demand startup with lockfile coordination.

use anyhow::Result;
use nix::libc;
use std::fs::File;
use std::io::{BufRead, BufReader, Read, Write};
use std::os::fd::AsRawFd;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Duration;

/// Default socket path
pub fn default_socket_path() -> PathBuf {
    if let Ok(runtime_dir) = std::env::var("XDG_RUNTIME_DIR") {
        PathBuf::from(runtime_dir).join("sigil.sock")
    } else {
        // Fallback to /tmp with UID for multi-process coordination
        PathBuf::from("/tmp").join(format!("sigil-{}.sock", nix::unistd::Uid::effective()))
    }
}

/// Default lockfile path
pub fn default_lockfile_path() -> PathBuf {
    if let Ok(runtime_dir) = std::env::var("XDG_RUNTIME_DIR") {
        PathBuf::from(runtime_dir).join("sigil.lock")
    } else {
        // Fallback to /tmp with UID for multi-process coordination
        PathBuf::from("/tmp").join(format!("sigil-{}.lock", nix::unistd::Uid::effective()))
    }
}

/// Check if the daemon is running
pub fn is_daemon_running(socket_path: Option<&Path>) -> bool {
    let default_path = default_socket_path();
    let socket_path = socket_path.unwrap_or(&default_path);

    // Check if socket exists
    if !socket_path.exists() {
        return false;
    }

    // Try to connect to verify it's alive
    if let Ok(mut stream) = std::os::unix::net::UnixStream::connect(socket_path) {
        // Set a short timeout for the ping
        let _ = stream.set_read_timeout(Some(Duration::from_millis(500)));

        // Try to send a ping request
        let ping_request = serde_json::json!({
            "v": 1,
            "id": "ping_check",
            "op": "ping",
            "token": ""
        });

        if let Ok(request_json) = serde_json::to_string(&ping_request) {
            let request_bytes = request_json.as_bytes();

            // Write length prefix (4 bytes big-endian)
            let length = request_bytes.len() as u32;
            if stream.write_all(&length.to_be_bytes()).is_err() {
                return false;
            }

            // Write payload
            if stream.write_all(request_bytes).is_err() {
                return false;
            }

            // Try to read response
            let mut length_buf = [0u8; 4];
            if stream.read_exact(&mut length_buf).is_err() {
                return false;
            }

            let response_length = u32::from_be_bytes(length_buf) as usize;
            if response_length > 1024 || response_length == 0 {
                return false;
            }

            let mut response_buf = vec![0u8; response_length];
            if stream.read_exact(&mut response_buf).is_err() {
                return false;
            }

            // Try to parse response
            if let Ok(response) = serde_json::from_slice::<serde_json::Value>(&response_buf) {
                return response["ok"].as_bool().unwrap_or(false);
            }
        }
    }

    false
}

/// Lockfile manager for daemon startup coordination
pub struct LockfileManager {
    lockfile_path: PathBuf,
    file: Option<File>,
}

impl LockfileManager {
    /// Create a new lockfile manager
    pub fn new(lockfile_path: Option<PathBuf>) -> Result<Self> {
        let lockfile_path = lockfile_path.unwrap_or_else(default_lockfile_path);

        // Ensure parent directory exists
        if let Some(parent) = lockfile_path.parent() {
            std::fs::create_dir_all(parent)?;
        }

        Ok(Self {
            lockfile_path,
            file: None,
        })
    }

    /// Try to acquire exclusive lock
    ///
    /// Returns Ok(true) if lock was acquired, Ok(false) if lock is held by another process
    pub fn try_acquire(&mut self) -> Result<bool> {
        use std::os::unix::fs::OpenOptionsExt;

        // Open (or create) the lockfile
        let file = std::fs::OpenOptions::new()
            .create(true)
            .truncate(true)
            .write(true)
            .mode(0o600)
            .open(&self.lockfile_path)?;

        // Try to acquire exclusive lock (non-blocking)
        let result = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };

        if result == 0 {
            // Lock acquired
            // Write our PID to the lockfile
            let pid = std::process::id();
            std::fs::write(&self.lockfile_path, format!("{}\n", pid))?;

            self.file = Some(file);
            Ok(true)
        } else {
            // Lock is held by another process
            Ok(false)
        }
    }

    /// Release the lock
    pub fn release(&mut self) -> Result<()> {
        if let Some(file) = &self.file {
            unsafe {
                libc::flock(file.as_raw_fd(), libc::LOCK_UN);
            }
            self.file = None;

            // Try to remove the lockfile
            let _ = std::fs::remove_file(&self.lockfile_path);
        }
        Ok(())
    }

    /// Get the PID of the process holding the lock (if any)
    pub fn get_lock_holder_pid(&self) -> Option<u32> {
        if !self.lockfile_path.exists() {
            return None;
        }

        let file = File::open(&self.lockfile_path).ok()?;
        let reader = BufReader::new(file);
        let first_line = reader.lines().next()?;
        let line = first_line.ok()?;
        line.trim().parse().ok()
    }
}

impl Drop for LockfileManager {
    fn drop(&mut self) {
        let _ = self.release();
    }
}

/// Start the daemon on-demand
///
/// This function:
/// 1. Checks if daemon is already running
/// 2. If not, acquires lockfile
/// 3. Forks the daemon process
/// 4. Waits for the socket to appear (with timeout)
/// 5. Releases the lockfile
///
/// Returns Ok(true) if daemon is running, Ok(false) if startup failed
pub fn start_daemon_on_demand(
    socket_path: Option<&Path>,
    lockfile_path: Option<PathBuf>,
    timeout: Duration,
) -> Result<bool> {
    let default_path = default_socket_path();
    let socket_path = socket_path.unwrap_or(&default_path);
    let lockfile_path = lockfile_path.unwrap_or_else(default_lockfile_path);

    // Check if daemon is already running
    if is_daemon_running(Some(socket_path)) {
        return Ok(true);
    }

    // Acquire lockfile
    let mut lockfile = LockfileManager::new(Some(lockfile_path.clone()))?;

    if !lockfile.try_acquire()? {
        // Another process is starting the daemon, wait for it
        return wait_for_socket(socket_path, timeout);
    }

    // We acquired the lock, start the daemon
    // Find the sigild executable
    let sigild_path = std::env::current_exe()
        .ok()
        .map(|p| p.with_file_name("sigild"));

    let sigild_path = match sigild_path {
        Some(p) if p.exists() => p,
        _ => {
            // Try to find sigild in PATH
            which::which("sigild").map_err(|e| anyhow::anyhow!("sigild not found: {}", e))?
        }
    };

    // Fork the daemon process
    let mut child = Command::new(&sigild_path)
        .arg("start")
        .arg("--socket")
        .arg(socket_path)
        .spawn()
        .map_err(|e| anyhow::anyhow!("Failed to start daemon: {}", e))?;

    // Release the lockfile (daemon is now starting)
    lockfile.release()?;

    // Wait for the socket to appear
    let socket_existed = wait_for_socket(socket_path, timeout)?;

    // Check if the daemon process is still running
    match child.try_wait() {
        Ok(Some(_status)) => {
            // Daemon exited
            Ok(false)
        }
        Ok(None) => {
            // Still running
            Ok(socket_existed)
        }
        Err(_) => {
            // Couldn't check status
            Ok(socket_existed)
        }
    }
}

/// Wait for the socket file to appear
fn wait_for_socket(socket_path: &Path, timeout: Duration) -> Result<bool> {
    let start = std::time::Instant::now();
    let check_interval = Duration::from_millis(100);

    while start.elapsed() < timeout {
        if socket_path.exists() {
            // Give it a moment to be fully ready
            std::thread::sleep(Duration::from_millis(100));

            // Verify we can actually connect
            if is_daemon_running(Some(socket_path)) {
                return Ok(true);
            }
        }

        std::thread::sleep(check_interval);
    }

    Ok(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_socket_path() {
        let path = default_socket_path();
        assert!(path.ends_with("sigil.sock"));
    }

    #[test]
    fn test_default_lockfile_path() {
        let path = default_lockfile_path();
        assert!(path.ends_with("sigil.lock"));
    }

    #[test]
    fn test_lockfile_creation() {
        let temp_dir = tempfile::tempdir().unwrap();
        let lockfile_path = temp_dir.path().join("test.lock");

        let mut manager = LockfileManager::new(Some(lockfile_path.clone())).unwrap();

        // Try to acquire lock
        assert!(manager.try_acquire().unwrap());

        // Lockfile should exist
        assert!(lockfile_path.exists());

        // PID should be in the file
        let pid = manager.get_lock_holder_pid().unwrap();
        assert_eq!(pid, std::process::id());

        // Release lock
        manager.release().unwrap();
    }

    #[test]
    fn test_lockfile_exclusive() {
        let temp_dir = tempfile::tempdir().unwrap();
        let lockfile_path = temp_dir.path().join("test2.lock");

        let mut manager1 = LockfileManager::new(Some(lockfile_path.clone())).unwrap();

        // First manager should acquire lock
        assert!(manager1.try_acquire().unwrap());

        // Second manager should fail
        let mut manager2 = LockfileManager::new(Some(lockfile_path.clone())).unwrap();
        assert!(!manager2.try_acquire().unwrap());

        // Release first lock
        manager1.release().unwrap();

        // Second manager should now be able to acquire
        assert!(manager2.try_acquire().unwrap());
    }
}
