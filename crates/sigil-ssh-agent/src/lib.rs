//! SIGIL SSH Agent - SSH agent protocol implementation
//!
//! This module implements an SSH agent that serves SSH keys from the SIGIL vault.
//! It implements the SSH agent protocol (draft-miller-ssh-agent) over a Unix domain socket.

#![warn(missing_docs)]
#![warn(clippy::all)]

pub mod agent;
pub mod keys;
pub mod protocol;

pub use agent::SshAgent;
pub use agent::SshAgentConfig;
pub use keys::{KeyConstraint, SshIdentity};
pub use protocol::{MessageType, Request, Response};

use std::path::PathBuf;

/// SSH agent configuration
#[derive(Debug, Clone)]
pub struct Config {
    /// Socket path for the SSH agent
    pub socket_path: PathBuf,
    /// Path to SIGIL daemon socket
    pub sigil_socket: PathBuf,
    /// Session token for SIGIL daemon authentication
    pub session_token: String,
    /// Require confirmation for each key use
    pub confirm_before_use: bool,
    /// Maximum lifetime for keys in seconds (None = no limit)
    pub max_key_lifetime: Option<u64>,
    /// Enable verbose logging
    pub verbose: bool,
}

impl Default for Config {
    fn default() -> Self {
        let runtime_dir = std::env::var("XDG_RUNTIME_DIR")
            .or_else(|_| std::env::var("TMPDIR"))
            .unwrap_or_else(|_| "/tmp".to_string());

        Self {
            socket_path: PathBuf::from(format!("{}/sigil-ssh-agent.sock", runtime_dir)),
            sigil_socket: PathBuf::from(std::env::var("SIGIL_SOCKET").unwrap_or_else(|_| {
                format!(
                    "{}/.sigil/sigild.sock",
                    std::env::var("HOME").unwrap_or_else(|_| ".".to_string())
                )
            })),
            session_token: String::new(),
            confirm_before_use: false,
            max_key_lifetime: None,
            verbose: false,
        }
    }
}

impl Config {
    /// Create a new SSH agent configuration
    pub fn new(socket_path: PathBuf, sigil_socket: PathBuf, session_token: String) -> Self {
        Self {
            socket_path,
            sigil_socket,
            session_token,
            ..Default::default()
        }
    }

    /// Enable confirmation before each key use
    pub fn with_confirmation(mut self, confirm: bool) -> Self {
        self.confirm_before_use = confirm;
        self
    }

    /// Set maximum key lifetime in seconds
    pub fn with_max_lifetime(mut self, seconds: u64) -> Self {
        self.max_key_lifetime = Some(seconds);
        self
    }

    /// Enable verbose logging
    pub fn with_verbose(mut self, verbose: bool) -> Self {
        self.verbose = verbose;
        self
    }
}
