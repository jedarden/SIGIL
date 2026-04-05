//! SIGIL Core - Core types and traits for secret management
//!
//! This crate provides the foundational types and traits used across all SIGIL components.

#![warn(missing_docs)]
#![warn(clippy::all)]

pub mod error;
pub mod ipc;
pub mod lifecycle;
pub mod monitor;
pub mod operations;
pub mod parser;
pub mod scanner;
pub mod types;
pub mod versions;

// Re-exports
pub use error::{ErrorCode, Result, SigilError, StructuredError};
pub use ipc::{
    get_peer_credentials, read_message, read_message_async, read_request, read_request_async,
    write_message, write_message_async, write_response, write_response_async, DaemonStatus,
    ExecuteOperationRequest, ExecuteOperationResponse, FuseReadRequest, FuseReadResponse, IpcError,
    IpcErrorCode, IpcOperation, IpcRequest, IpcResponse, ListOperationsResponse,
    OperationDescription, PeerCredentials, PingResponse, ResolveRequest, ResolveResponse,
    ScrubRequest, ScrubResponse, SessionInfo, SessionToken, PROTOCOL_VERSION,
};
pub use monitor::{FileChangeEvent, FilesystemMonitor, MonitorConfig, MonitorHandle, ScanResult};
pub use operations::{OperationResult, OperationsRegistry, OutputFilter, SealedOperation};
pub use parser::{CommandParser, InjectionMode, ResolvedCommand, SecretPlaceholder};
pub use scanner::{ProjectScanner, ScanConfig, SecretSuggestion};
pub use types::{SecretBackend, SecretMetadata, SecretPath, SecretType, SecretValue};
pub use versions::SecretVersion;
