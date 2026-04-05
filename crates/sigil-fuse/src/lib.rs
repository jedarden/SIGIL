//! SIGIL FUSE - FUSE virtual filesystem for secret exposure
//!
//! This module implements a read-only FUSE filesystem that exposes secrets as files.
//! The filesystem is mounted at `/sigil/` inside the sandbox namespace and provides
//! universal compatibility - any tool that reads files can access secrets.

#![warn(missing_docs)]
#![warn(clippy::all)]

pub mod filesystem;
pub mod formatter;
pub mod mount;

pub use filesystem::SigilFs;
pub use formatter::{Formatter, FormatterType};
pub use mount::{mount_sigil, unmount_sigil};

use std::path::PathBuf;

/// FUSE mount configuration
#[derive(Debug, Clone)]
pub struct FuseConfig {
    /// Mount point (e.g., "/sigil")
    pub mount_point: PathBuf,
    /// Path to SIGIL daemon socket
    pub socket_path: PathBuf,
    /// Allowed sandbox PID (only this PID can read files)
    pub sandbox_pid: Option<u32>,
    /// Allowed sandbox UID (only this UID can read files)
    pub sandbox_uid: Option<u32>,
    /// Allowlist of GIDs that can access the filesystem
    pub allowed_gids: Vec<u32>,
    /// Session token for daemon authentication
    pub session_token: String,
    /// Enable automatic file generation (aws/credentials, k8s/kubeconfig, etc.)
    pub auto_generate: bool,
}

impl Default for FuseConfig {
    fn default() -> Self {
        Self {
            mount_point: PathBuf::from("/sigil"),
            socket_path: PathBuf::from(std::env::var("SIGIL_SOCKET").unwrap_or_else(|_| {
                format!("{}/.sigil/sigild.sock", std::env::var("HOME").unwrap_or_else(|_| ".".to_string()))
            })),
            sandbox_pid: None,
            sandbox_uid: None,
            allowed_gids: vec![],
            session_token: String::new(),
            auto_generate: true,
        }
    }
}

impl FuseConfig {
    /// Create a new FUSE configuration
    pub fn new(mount_point: PathBuf, socket_path: PathBuf, session_token: String) -> Self {
        Self {
            mount_point,
            socket_path,
            session_token,
            ..Default::default()
        }
    }

    /// Set the sandbox PID restriction
    pub fn with_sandbox_pid(mut self, pid: u32) -> Self {
        self.sandbox_pid = Some(pid);
        self
    }

    /// Set the sandbox UID restriction
    pub fn with_sandbox_uid(mut self, uid: u32) -> Self {
        self.sandbox_uid = Some(uid);
        self
    }

    /// Add an allowed GID
    pub fn with_allowed_gid(mut self, gid: u32) -> Self {
        self.allowed_gids.push(gid);
        self
    }

    /// Enable or disable automatic file generation
    pub fn with_auto_generate(mut self, enabled: bool) -> Self {
        self.auto_generate = enabled;
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_config_default() {
        let config = FuseConfig::default();
        assert_eq!(config.mount_point, PathBuf::from("/sigil"));
        assert!(config.auto_generate);
    }

    #[test]
    fn test_config_builder() {
        let config = FuseConfig::new(
            PathBuf::from("/mnt/sigil"),
            PathBuf::from("/tmp/sigild.sock"),
            "test-token".to_string(),
        )
        .with_sandbox_pid(123)
        .with_sandbox_uid(456)
        .with_allowed_gid(789)
        .with_auto_generate(false);

        assert_eq!(config.mount_point, PathBuf::from("/mnt/sigil"));
        assert_eq!(config.socket_path, PathBuf::from("/tmp/sigild.sock"));
        assert_eq!(config.session_token, "test-token");
        assert_eq!(config.sandbox_pid, Some(123));
        assert_eq!(config.sandbox_uid, Some(456));
        assert_eq!(config.allowed_gids, vec![789]);
        assert!(!config.auto_generate);
    }
}
