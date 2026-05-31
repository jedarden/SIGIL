//! PTY allocation for isolated TUI
//!
//! This module provides functionality to allocate a separate PTY for the TUI,
//! preventing the AI agent from accessing the TUI's terminal through /dev/pts/*.

#![warn(missing_docs)]
#![warn(clippy::all)]

use anyhow::{anyhow, Result};
use std::fs::File;
use std::os::fd::{FromRawFd, IntoRawFd, OwnedFd};
use std::path::PathBuf;

#[cfg(any(target_os = "linux", target_os = "macos"))]
use nix::pty::{openpty, Winsize};

/// Represents an allocated PTY pair
#[derive(Debug)]
pub struct PtyPair {
    /// Path to the slave PTY device (e.g., /dev/pts/X)
    pub slave_path: PathBuf,
    /// Master PTY handle
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    master: OwnedFd,
    /// Master PTY file for I/O (used by crossterm)
    master_file: Option<File>,
}

impl PtyPair {
    /// Allocate a new PTY pair for the TUI
    ///
    /// This creates a new pseudo-terminal pair that the TUI can use.
    /// The master fd is used by the TUI application, and the slave path
    /// is where the user (or a separate terminal emulator) connects.
    ///
    /// # Security
    ///
    /// By allocating a separate PTY, we prevent the AI agent from reading
    /// the TUI's terminal through /dev/pts/* since:
    /// 1. The TUI runs on a different PTY than the agent
    /// 2. PTY permissions prevent cross-user reads
    /// 3. In PID namespace isolation, the agent cannot see the TUI's PTY devices
    ///
    /// # Example
    ///
    /// ```no_run
    /// use sigil_tui::pty::PtyPair;
    ///
    /// let pty = PtyPair::allocate()?;
    /// println!("Connect to TUI at: {:?}", pty.slave_path);
    /// // Use pty.writer() for the TUI backend
    /// # Ok::<(), anyhow::Error>(())
    /// ```
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    pub fn allocate() -> Result<Self> {
        // Set reasonable terminal size
        let window_size = Winsize {
            ws_row: 24,
            ws_col: 80,
            ws_xpixel: 0,
            ws_ypixel: 0,
        };

        // Open a new PTY pair (nix 0.31+ returns OpenptyResult with OwnedFd)
        let result = openpty(Some(&window_size), None)?;
        let master_owned = result.master;

        // Get the path to the slave PTY
        // nix 0.31+ requires wrapping master fd in PtyMaster for ptsname_r
        let pty_master = unsafe { nix::pty::PtyMaster::from_owned_fd(master_owned) };
        let slave_path = PathBuf::from(nix::pty::ptsname_r(&pty_master)?);
        // Get the fd back - in nix 0.31 we need to use into_raw_fd and re-wrap
        let master = unsafe { OwnedFd::from_raw_fd(pty_master.into_raw_fd()) };

        tracing::info!("Allocated PTY pair: slave={:?}", slave_path);

        Ok(Self {
            slave_path,
            master,
            master_file: None,
        })
    }

    /// Allocate a new PTY pair for the TUI (stub for unsupported platforms)
    ///
    /// On unsupported platforms (e.g., Windows), this returns an error since PTY allocation
    /// is platform-specific. The TUI will fall back to using the standard
    /// terminal in that case.
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    pub fn allocate() -> Result<Self> {
        Err(anyhow!(
            "PTY allocation not supported on this platform. Using standard terminal."
        ))
    }

    /// Get the slave PTY path as a string
    pub fn slave_path_str(&self) -> String {
        self.slave_path
            .to_str()
            .unwrap_or("(invalid path)")
            .to_string()
    }

    /// Get a writable reference to the master PTY
    ///
    /// This returns a File that can be used with crossterm's CrosstermBackend.
    /// The first call will take ownership of the master PTY file descriptor.
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    pub fn writer(&mut self) -> Result<File> {
        if self.master_file.is_some() {
            return Err(anyhow!("Writer already taken"));
        }

        // Convert the PtyMaster to a File
        // nix 0.31 returns OwnedFd from dup, convert to File
        let owned_fd = nix::unistd::dup(&self.master)?;
        let file = File::from(owned_fd);
        self.master_file = Some(file.try_clone()?);
        Ok(file)
    }

    /// Get a writable reference to the master PTY (stub for unsupported platforms)
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    pub fn writer(&mut self) -> Result<File> {
        Err(anyhow!("PTY writer not available on this platform"))
    }

    /// Check if the current process is running on a PTY
    ///
    /// This can be used by `sigil doctor` to verify that the TUI is running
    /// on an isolated PTY, not the agent's terminal.
    pub fn is_running_on_pty() -> bool {
        #[cfg(target_os = "linux")]
        {
            // Check if stdout is a TTY - Stdout implements AsFd
            nix::unistd::isatty(std::io::stdout()).unwrap_or(false)
        }

        #[cfg(not(target_os = "linux"))]
        {
            // On other platforms, assume we're on a TTY if we can check
            unsafe { nix::libc::isatty(nix::libc::STDOUT_FILENO) != 0 }
        }
    }

    /// Get the current PTY path if running on one
    ///
    /// Returns the path to the PTY device if stdout is connected to a PTY.
    pub fn current_pty_path() -> Option<PathBuf> {
        #[cfg(any(target_os = "linux", target_os = "macos"))]
        {
            use std::os::unix::fs::MetadataExt;

            if !Self::is_running_on_pty() {
                return None;
            }

            // Get the device number of stdout
            let stdout = File::create("/dev/stdout").ok()?;
            let metadata = stdout.metadata().ok()?;
            let _dev = metadata.dev();
            let rdev = metadata.rdev();

            // Find the matching PTY device
            // Linux: /dev/pts/X
            // macOS: /dev/ttysXXX (directly in /dev)
            #[cfg(target_os = "linux")]
            let search_dir = "/dev/pts";
            #[cfg(target_os = "macos")]
            let search_dir = "/dev";

            let pts_dir = std::fs::read_dir(search_dir).ok()?;
            for entry in pts_dir.flatten() {
                let path = entry.path();
                // Filter to only PTY devices for the respective platform
                #[cfg(target_os = "linux")]
                let is_pty = path.to_str()?.starts_with("/dev/pts/");
                #[cfg(target_os = "macos")]
                let is_pty = path.to_str()?.starts_with("/dev/ttys");

                if is_pty {
                    let entry_metadata = entry.metadata().ok()?;
                    if entry_metadata.rdev() == rdev {
                        return Some(path);
                    }
                }
            }

            None
        }

        #[cfg(not(any(target_os = "linux", target_os = "macos")))]
        {
            let _ = std::io::stdout();
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    fn test_pty_allocation() {
        let pty = PtyPair::allocate();
        assert!(pty.is_ok());

        let pty = pty.unwrap();
        // On Linux: /dev/pts/X
        // On macOS: /dev/ttysXXX (BSD-style)
        #[cfg(target_os = "linux")]
        assert!(pty.slave_path.starts_with("/dev/pts/"));
        #[cfg(target_os = "macos")]
        assert!(pty.slave_path.starts_with("/dev/ttys"));
        assert!(!pty.slave_path_str().is_empty());
    }

    #[test]
    fn test_is_running_on_pty() {
        // This test runs in CI, so we might not be on a PTY
        let _ = PtyPair::is_running_on_pty();
    }

    #[test]
    fn test_current_pty_path() {
        // Just check it doesn't panic
        let _ = PtyPair::current_pty_path();
    }
}
