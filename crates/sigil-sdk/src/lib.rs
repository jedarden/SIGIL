//! SIGIL SDK - Embeddable SDK for SIGIL secret management

#![warn(missing_docs)]
#![warn(clippy::all)]

pub mod client;

pub use client::{
    AccessGrant, DaemonStatusInfo, ExecResult, SecretMetadata, SigilClient,
};

// Re-export OperationDescription from sigil-core for convenience
pub use sigil_core::OperationDescription;
