//! SIGIL Daemon library
//!
//! This library provides the client functionality for communicating with the SIGIL daemon.

#![warn(missing_docs)]
#![warn(clippy::all)]

pub mod client;
pub mod filesystem_monitor;

// Make ondemand available internally but not re-exported
pub mod ondemand;

pub use client::DaemonClient;
pub use filesystem_monitor::{FilesystemMonitor, MonitorConfig, SecretDetection};
