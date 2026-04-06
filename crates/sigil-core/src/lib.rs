//! SIGIL Core - Core types and traits for secret management
//!
//! This crate provides the foundational types and traits used across all SIGIL components.

#![warn(missing_docs)]
#![warn(clippy::all)]

pub mod audit;
pub mod error;
pub mod install_manifest;
pub mod ipc;
pub mod lease;
pub mod lifecycle;
pub mod manifest;
pub mod monitor;
pub mod operations;
pub mod parser;
pub mod scanner;
pub mod terminal;
pub mod types;
pub mod versions;

// Re-exports
pub use audit::{AuditConfig, AuditEntry, AuditLogReader, AuditStats, ExportFormat};
pub use error::{ErrorCode, Result, SigilError, StructuredError};
pub use install_manifest::{
    BinaryInfo, CanaryInfo, HookInfo, HookType, InstallManifest, RuntimeArtifact, RuntimeInfo,
    VaultInfo,
};
pub use ipc::{
    get_peer_credentials, read_message, read_message_async, read_request, read_request_async,
    write_message, write_message_async, write_response, write_response_async, DaemonStatus,
    ExecuteOperationRequest, ExecuteOperationResponse, FuseReadRequest, FuseReadResponse, IpcError,
    IpcErrorCode, IpcOperation, IpcRequest, IpcResponse, KillSessionRequest, KillSessionResponse,
    ListOperationsResponse, ListSessionsResponse, OperationDescription, PeerCredentials,
    PingResponse, ResolveRequest, ResolveResponse, ScrubRequest, ScrubResponse, SessionDetails,
    SessionInfo, SessionToken, PROTOCOL_VERSION,
};
pub use lease::{
    Lease, LeaseConfig, LeaseManager, LeaseStats, LeaseSummary, DEFAULT_LEASE_TTL_SECS,
    MAX_LEASE_TTL_SECS, MIN_LEASE_TTL_SECS,
};
pub use lifecycle::{default_lockfile_path, default_socket_path};
pub use manifest::{
    find_manifest, InjectMode, InjectionRule, ManifestValidationResult, OperationDeclaration,
    OutputFilter as ManifestOutputFilter, ProjectManifest, ProjectMetadata, SecretDeclaration,
    SignatureRule,
};
pub use monitor::{FileChangeEvent, FilesystemMonitor, MonitorConfig, MonitorHandle, ScanResult};
pub use operations::{OperationResult, OperationsRegistry, OutputFilter, SealedOperation};
pub use parser::{CommandParser, InjectionMode, ResolvedCommand, SecretPlaceholder};
pub use scanner::{ProjectScanner, ScanConfig, SecretSuggestion};
pub use terminal::{
    colorize, BoxDrawings, ColorMode, LayoutMode, PaletteColor, StatusIndicator, TerminalSize,
    UnicodeMode, ANSI_RESET,
};

// Re-export atty for convenience
pub use atty;
pub use types::{SecretBackend, SecretMetadata, SecretPath, SecretType, SecretValue};
pub use versions::SecretVersion;
