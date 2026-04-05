//! SIGIL TUI - Library for TUI components
//!
//! This library provides reusable TUI components for SIGIL,
//! including approval prompts for secret access requests.

#![warn(missing_docs)]
#![warn(clippy::all)]

pub mod approval;

pub use approval::{ApprovalDecision, ApprovalPrompt, ApprovalRequest};
