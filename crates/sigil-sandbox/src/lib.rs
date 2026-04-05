//! SIGIL Sandbox - Sandbox implementation for secure command execution
//!
//! This crate provides sandboxing capabilities using multiple providers:
//! - Bubblewrap (Linux) - uses namespaces and seccomp
//! - Landlock (Linux fallback) - for kernels < 5.13
//! - Seatbelt (macOS) - uses Apple's sandbox_exec

#![warn(missing_docs)]
#![warn(clippy::all)]

pub mod bubblewrap;
pub mod injection;
pub mod landlock;
pub mod seatbelt;
pub mod secure_fd;
pub mod state;

pub use bubblewrap::{BubblewrapSandbox, SandboxCapabilities, SandboxConfig, SandboxProvider};
pub use injection::{FileInjection, InjectionManager, SecureFileInjection};
pub use landlock::{default_sensitive_paths, LandlockSandbox};
pub use seatbelt::SeatbeltSandbox;
pub use secure_fd::{SecureFile, SecurePid};
pub use state::{ShellState, StateCapture};
