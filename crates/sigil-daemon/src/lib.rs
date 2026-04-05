//! SIGIL Daemon library
//!
//! This library provides the client functionality for communicating with the SIGIL daemon.

#![warn(missing_docs)]
#![warn(clippy::all)]

pub mod client;

// Make ondemand available internally but not re-exported
mod ondemand;

pub use client::DaemonClient;
