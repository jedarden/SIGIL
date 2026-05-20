//! SIGIL TUI - Library for TUI components
//!
//! This library provides reusable TUI components for SIGIL,
//! including approval prompts for secret access requests
//! and the full TUI application for secret management.

#![warn(missing_docs)]
#![warn(clippy::all)]

pub mod approval;
pub mod browser;
pub mod pty;
pub mod tui_app;

pub use approval::{ApprovalDecision, ApprovalPrompt, ApprovalRequest};
pub use browser::run_browser;
pub use pty::PtyPair;
pub use tui_app::{
    App, AuditItem, FormField, FormState, Mode, SecretDetail, SecretItem, SessionItem,
    enable_process_isolation,
};
