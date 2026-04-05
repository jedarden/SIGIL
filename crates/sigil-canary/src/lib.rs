//! SIGIL Canary - Breach detection via canary secrets
//!
//! Canary secrets are fake credentials planted in the sandbox to detect
//! unauthorized access attempts. They exist only in memory (tmpfs) inside
//! the bwrap sandbox overlay, never on the host filesystem.

#![warn(missing_docs)]
#![warn(clippy::all)]

pub mod canary;
pub mod generator;
pub mod monitor;

pub use canary::{CanaryFile, CanaryKind, CanarySecret};
pub use generator::CanaryGenerator;
pub use monitor::{BreachReport, BreachSeverity, CanaryAccessEvent, CanaryMonitor};
