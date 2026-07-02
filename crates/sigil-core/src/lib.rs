//! SIGIL Core - Core types and traits for secret management
//!
//! This crate provides the foundational types and traits used across all SIGIL components.

#![warn(missing_docs)]
#![warn(clippy::all)]

pub mod archive;
pub mod audit;
pub mod backend;
#[cfg(feature = "dynamic")]
pub mod dynamic;
pub mod error;
pub mod global_config;
pub mod install_manifest;
pub mod ipc;
pub mod keyring;
pub mod lease;
pub mod lifecycle;
pub mod linter;
pub mod manifest;
pub mod monitor;
pub mod operations;
pub mod parser;
pub mod scanner;
pub mod terminal;
pub mod types;
pub mod versions;

// Re-exports
pub use archive::{create_archive, extract_archive, ArchivePayload, ArchivedSecret};
pub use audit::{AuditConfig, AuditEntry, AuditLogReader, AuditStats, ExportFormat};
pub use backend::{
    BackendCache, BackendEntry, BackendFactory, BackendFromConfig, BackendRouter,
    BackendRouterConfig,
};
#[cfg(feature = "dynamic")]
pub use dynamic::{
    AwsStsProvider, DynamicSecretConfig, DynamicSecretProvider, DynamicSecretResponse,
    KubernetesTokenProvider, VaultDynamicProvider,
};
pub use error::{ErrorCode, Result, SigilError, StructuredError};
pub use global_config::{DaemonConfig, GlobalConfig, GlobalConfigManager, TuiConfig};
pub use install_manifest::{
    BinaryInfo, CanaryInfo, HookInfo, HookType, InstallManifest, RuntimeArtifact, RuntimeInfo,
    VaultInfo,
};
pub use ipc::{
    get_peer_credentials, read_message, read_message_async, read_request, read_request_async,
    write_message, write_message_async, write_response, write_response_async, BackendSyncRequest,
    BackendSyncResponse, CanaryStatusRequest, CanaryStatusResponse, DaemonStatus,
    DeleteSecretRequest, DeleteSecretResponse, ExecuteOperationRequest, ExecuteOperationResponse,
    FuseReadRequest, FuseReadResponse, GetSecretRequest, GetSecretResponse, IpcError, IpcErrorCode,
    IpcOperation, IpcRequest, IpcResponse, KillSessionRequest, KillSessionResponse, LintRequest,
    LintResponse, ListOperationsResponse, ListSecretsRequest, ListSecretsResponse,
    ListSessionsResponse, OperationDescription, PeerCredentials, PingResponse, ResolveRequest,
    ResolveResponse, ScrubRequest, ScrubResponse, SecretFinding, SessionDetails, SessionInfo,
    SessionNode, SessionStartRequest, SessionToken, SetSecretRequest, SetSecretResponse,
    WrapRequest, WrapResponse, PROTOCOL_VERSION,
};
pub use keyring::{
    add_session_token, is_keyring_available, read_session_token, remove_session_token,
    KEY_DESCRIPTION, KEY_TYPE_USER,
};
pub use lease::{
    Lease, LeaseConfig, LeaseManager, LeaseStats, LeaseSummary, DEFAULT_LEASE_TTL_SECS,
    MAX_LEASE_TTL_SECS, MIN_LEASE_TTL_SECS,
};
pub use lifecycle::{default_lockfile_path, default_socket_path};
pub use linter::{
    collect_files_in_directory, default_patterns, get_staged_files, LinterConfig, SecretLinter,
    SecretPattern,
};
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
