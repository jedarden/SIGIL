//! IPC protocol for SIGIL daemon communication
//!
//! This module defines the length-prefixed JSON protocol used for communication
//! between sigild and its clients (CLI, hooks, TUI, MCP server, SDK).

use crate::error::{Result, SigilError};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::io::{self, Read, Write};
use std::os::unix::io::AsRawFd;
use std::path::PathBuf;

/// Current protocol version
pub const PROTOCOL_VERSION: u16 = 1;

/// Maximum message size (16 MiB default)
pub const MAX_MESSAGE_SIZE: usize = 16 * 1024 * 1024;

/// IPC protocol error codes
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum IpcErrorCode {
    /// Session token was invalid or expired
    InvalidToken,
    /// Request JSON was malformed
    InvalidRequest,
    /// Operation is not recognized
    UnknownOp,
    /// Secret path does not exist
    SecretNotFound,
    /// Insufficient permissions for the operation
    AccessDenied,
    /// Vault is locked (not unsealed)
    VaultLocked,
    /// Too many requests (rate limited)
    RateLimited,
    /// Message exceeds size limit
    PayloadTooLarge,
    /// Internal daemon error
    InternalError,
    /// Session has expired
    SessionExpired,
    /// Command execution failed
    OperationFailed,
    /// Sandbox creation failed
    SandboxError,
    /// Scrubber failure
    ScrubError,
    /// External backend unreachable
    BackendError,
    /// Daemon is in lockdown mode
    LockedDown,
}

impl std::fmt::Display for IpcErrorCode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let code = serde_json::to_string(self).unwrap_or_default();
        // Remove quotes from JSON string
        write!(f, "{}", code.trim_matches('"'))
    }
}

impl std::error::Error for IpcErrorCode {}

/// IPC error details
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IpcError {
    /// Error code
    pub code: IpcErrorCode,
    /// Human-readable error message
    pub message: String,
}

impl IpcError {
    /// Create a new IPC error
    pub fn new(code: IpcErrorCode, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }
}

impl std::fmt::Display for IpcError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "[{}] {}", self.code, self.message)
    }
}

impl std::error::Error for IpcError {}

/// IPC operation names
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IpcOperation {
    /// Ping/heartbeat
    Ping,
    /// Get daemon status
    Status,
    /// Authenticate with session token
    Auth,
    /// Start a new session
    SessionStart,
    /// End a session
    SessionEnd,
    /// Resolve secret placeholders
    Resolve,
    /// Scrub output for secrets
    Scrub,
    /// Execute command in sandbox
    Exec,
    /// Pre-tool hook
    HookPre,
    /// Post-tool hook
    HookPost,
    /// Write file hook
    HookWrite,
    /// Read file hook
    HookRead,
    /// List secrets
    List,
    /// Get secret value
    Get,
    /// Set secret value
    Set,
    /// Delete secret
    Delete,
    /// Sync with external backend
    BackendSync,
    /// Get canary status
    CanaryStatus,
    /// Get breach report
    BreachReport,
    /// Lint codebase for secrets
    Lint,
    /// Wrap command with secrets
    Wrap,
    /// FUSE filesystem read
    FuseRead,
    /// Get proxy status
    ProxyStatus,
    /// Enter lockdown mode
    Lockdown,
    /// Lift lockdown mode
    Unlock,
    /// Health check
    Doctor,
    /// Request access to secret
    RequestAccess,
    /// Check if access is granted to a secret
    CheckAccess,
    /// List sealed operations
    ListOperations,
    /// Execute a sealed operation
    ExecuteOperation,
    /// Cancel a streaming operation
    Cancel,
    /// List active sessions
    ListSessions,
    /// Kill a specific session
    KillSession,
    /// Get session hierarchy tree
    GetSessionTree,
    /// Grant a lease for a secret
    LeaseGrant,
    /// Revoke a lease
    LeaseRevoke,
    /// List active leases
    LeaseList,
    /// Get lease statistics
    LeaseStats,
    /// Team vault operation (catch-all for unknown team operations)
    #[serde(other)]
    TeamOp,
}

/// IPC request envelope
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IpcRequest {
    /// Protocol version
    pub v: u16,
    /// Unique request ID (client-generated)
    pub id: String,
    /// Operation name
    pub op: IpcOperation,
    /// Session token (base64-encoded)
    pub token: String,
    /// Operation-specific payload (optional)
    #[serde(default)]
    pub payload: serde_json::Value,
}

impl IpcRequest {
    /// Create a new IPC request
    pub fn new(op: IpcOperation, token: String) -> Self {
        Self {
            v: PROTOCOL_VERSION,
            id: generate_request_id(),
            op,
            token,
            payload: serde_json::Value::Null,
        }
    }

    /// Create a new IPC request with a payload
    pub fn with_payload(op: IpcOperation, token: String, payload: serde_json::Value) -> Self {
        Self {
            v: PROTOCOL_VERSION,
            id: generate_request_id(),
            op,
            token,
            payload,
        }
    }

    /// Set the request ID
    pub fn with_id(mut self, id: String) -> Self {
        self.id = id;
        self
    }
}

/// IPC response envelope
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IpcResponse {
    /// Protocol version
    pub v: u16,
    /// Request ID (for correlation)
    pub id: String,
    /// Whether the request succeeded
    pub ok: bool,
    /// Response payload (on success)
    #[serde(default)]
    pub payload: serde_json::Value,
    /// Error details (on failure)
    pub error: Option<IpcError>,
    /// Whether this is a streaming frame
    #[serde(default)]
    pub stream: bool,
}

impl IpcResponse {
    /// Create a success response
    pub fn ok(id: String) -> Self {
        Self {
            v: PROTOCOL_VERSION,
            id,
            ok: true,
            payload: serde_json::Value::Null,
            error: None,
            stream: false,
        }
    }

    /// Create a success response with payload
    pub fn with_payload(id: String, payload: serde_json::Value) -> Self {
        Self {
            v: PROTOCOL_VERSION,
            id,
            ok: true,
            payload,
            error: None,
            stream: false,
        }
    }

    /// Create an error response
    pub fn error(id: String, error: IpcError) -> Self {
        Self {
            v: PROTOCOL_VERSION,
            id,
            ok: false,
            payload: serde_json::Value::Null,
            error: Some(error),
            stream: false,
        }
    }

    /// Create a streaming chunk response
    pub fn stream_chunk(id: String, chunk: String) -> Self {
        Self {
            v: PROTOCOL_VERSION,
            id,
            ok: true,
            payload: serde_json::json!({ "chunk": chunk }),
            error: None,
            stream: true,
        }
    }
}

/// Generate a unique request ID
fn generate_request_id() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_micros();
    let random: u32 = rand::random();
    format!("req_{:x}_{:08x}", timestamp, random)
}

/// Write a length-prefixed message to a stream
pub fn write_message<W: Write>(writer: &mut W, data: &[u8]) -> io::Result<()> {
    let len = data.len();
    if len > MAX_MESSAGE_SIZE {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "message exceeds maximum size",
        ));
    }

    // Write length as big-endian u32
    writer.write_all(&(len as u32).to_be_bytes())?;
    // Write payload
    writer.write_all(data)?;
    writer.flush()?;
    Ok(())
}

/// Read a length-prefixed message from a stream
pub fn read_message<R: Read>(reader: &mut R) -> io::Result<Vec<u8>> {
    // Read length prefix
    let mut len_bytes = [0u8; 4];
    reader.read_exact(&mut len_bytes)?;
    let len = u32::from_be_bytes(len_bytes) as usize;

    if len > MAX_MESSAGE_SIZE {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "message exceeds maximum size",
        ));
    }

    // Read payload
    let mut buffer = vec![0u8; len];
    reader.read_exact(&mut buffer)?;
    Ok(buffer)
}

/// Serialize and write an IPC response
pub fn write_response<W: Write>(writer: &mut W, response: &IpcResponse) -> Result<()> {
    let json =
        serde_json::to_vec(response).map_err(|e| SigilError::SerializationError(e.to_string()))?;
    write_message(writer, &json).map_err(|e| SigilError::IoError(e.to_string()))?;
    Ok(())
}

/// Read and deserialize an IPC request
pub fn read_request<R: Read>(reader: &mut R) -> Result<IpcRequest> {
    let data = read_message(reader).map_err(|e| SigilError::IoError(e.to_string()))?;
    let request: IpcRequest =
        serde_json::from_slice(&data).map_err(|e| SigilError::SerializationError(e.to_string()))?;

    // Validate protocol version
    if request.v != PROTOCOL_VERSION {
        return Err(SigilError::UnsupportedProtocolVersion(request.v));
    }

    Ok(request)
}

/// Async version of write_message for tokio streams
pub async fn write_message_async<W: tokio::io::AsyncWriteExt + Unpin>(
    writer: &mut W,
    data: &[u8],
) -> io::Result<()> {
    let len = data.len();
    if len > MAX_MESSAGE_SIZE {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "message exceeds maximum size",
        ));
    }

    // Write length as big-endian u32
    writer.write_all(&(len as u32).to_be_bytes()).await?;
    // Write payload
    writer.write_all(data).await?;
    writer.flush().await?;
    Ok(())
}

/// Async version of read_message for tokio streams
pub async fn read_message_async<R: tokio::io::AsyncReadExt + Unpin>(
    reader: &mut R,
) -> io::Result<Vec<u8>> {
    // Read length prefix
    let mut len_bytes = [0u8; 4];
    reader.read_exact(&mut len_bytes).await?;
    let len = u32::from_be_bytes(len_bytes) as usize;

    if len > MAX_MESSAGE_SIZE {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "message exceeds maximum size",
        ));
    }

    // Read payload
    let mut buffer = vec![0u8; len];
    reader.read_exact(&mut buffer).await?;
    Ok(buffer)
}

/// Async version of write_response
pub async fn write_response_async<W: tokio::io::AsyncWriteExt + Unpin>(
    writer: &mut W,
    response: &IpcResponse,
) -> Result<()> {
    let json =
        serde_json::to_vec(response).map_err(|e| SigilError::SerializationError(e.to_string()))?;
    write_message_async(writer, &json)
        .await
        .map_err(|e| SigilError::IoError(e.to_string()))?;
    Ok(())
}

/// Async version of read_request
pub async fn read_request_async<R: tokio::io::AsyncReadExt + Unpin>(
    reader: &mut R,
) -> Result<IpcRequest> {
    let data = read_message_async(reader)
        .await
        .map_err(|e| SigilError::IoError(e.to_string()))?;
    let request: IpcRequest =
        serde_json::from_slice(&data).map_err(|e| SigilError::SerializationError(e.to_string()))?;

    // Validate protocol version
    if request.v != PROTOCOL_VERSION {
        return Err(SigilError::UnsupportedProtocolVersion(request.v));
    }

    Ok(request)
}

/// Peer credentials from SO_PEERCRED
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PeerCredentials {
    /// Process ID
    pub pid: u32,
    /// User ID
    pub uid: u32,
    /// Group ID
    pub gid: u32,
}

impl PeerCredentials {
    /// Check if using pidfd protection (Linux-only feature)
    ///
    /// Returns false on non-Linux platforms and on Linux when using
    /// the basic PeerCredentials type (vs SecurePeerCredentials).
    pub fn is_using_pidfd(&self) -> bool {
        false
    }
}

/// Get peer credentials from a Unix socket
#[cfg(target_os = "linux")]
pub fn get_peer_credentials<S: AsRawFd>(stream: &S) -> Result<PeerCredentials> {
    use nix::sys::socket::sockopt::PeerCredentials as NixPeerCredentials;
    use nix::sys::socket::{getsockopt, UnixCredentials};
    use std::os::unix::io::BorrowedFd;

    // SAFETY: We're creating a BorrowedFd from the raw fd.
    // This is safe because we have a reference to the original stream,
    // ensuring the fd remains valid for the lifetime of the BorrowedFd.
    let fd = stream.as_raw_fd();
    let borrowed = unsafe { BorrowedFd::borrow_raw(fd) };

    let creds: UnixCredentials = getsockopt(&borrowed, NixPeerCredentials)
        .map_err(|e| SigilError::IoError(format!("failed to get peer credentials: {}", e)))?;

    Ok(PeerCredentials {
        pid: creds.pid() as u32,
        uid: creds.uid() as u32,
        gid: creds.gid() as u32,
    })
}

/// Get peer credentials from a Unix socket (macOS)
#[cfg(target_os = "macos")]
pub fn get_peer_credentials<S: AsRawFd>(stream: &S) -> Result<PeerCredentials> {
    use std::os::unix::io::AsRawFd;

    // macOS uses LOCAL_PEERCRED for getsockopt
    let fd = stream.as_raw_fd();

    // unsafe: calling getsockopt with LOCAL_PEERCRED
    unsafe {
        let mut creds: libc::xucred = std::mem::zeroed();
        let mut len = std::mem::size_of::<libc::xucred>() as libc::socklen_t;

        let ret = libc::getsockopt(
            fd,
            libc::SOL_LOCAL,
            libc::LOCAL_PEERCRED,
            &mut creds as *mut _ as *mut libc::c_void,
            &mut len,
        );

        if ret != 0 {
            return Err(SigilError::IoError(format!(
                "failed to get peer credentials: {}",
                std::io::Error::last_os_error()
            )));
        }

        Ok(PeerCredentials {
            pid: 0, // macOS doesn't provide PID in xucred
            uid: creds.cr_uid,
            gid: creds.cr_gid,
        })
    }
}

/// Get peer credentials from a Unix socket (fallback)
#[cfg(not(any(target_os = "linux", target_os = "macos")))]
pub fn get_peer_credentials<S: AsRawFd>(stream: &S) -> Result<PeerCredentials> {
    // Fallback: we can't get peer credentials on this platform
    // Return an error indicating the feature is not supported
    Err(SigilError::IoError(
        "peer credential verification not supported on this platform".to_string(),
    ))
}

/// Session token (32 bytes, base64-encoded)
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionToken(String);

impl SessionToken {
    /// Generate a new random session token
    pub fn generate() -> Self {
        use rand::RngCore;
        let mut bytes = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut bytes);
        use base64::prelude::*;
        SessionToken(BASE64_STANDARD.encode(bytes))
    }

    /// Create a session token from a string (validation only)
    pub fn from_string(s: String) -> Result<Self> {
        // Validate base64 encoding
        use base64::prelude::*;
        let bytes = BASE64_STANDARD
            .decode(&s)
            .map_err(|_| SigilError::InvalidSessionToken("invalid base64 encoding".into()))?;

        // Validate length (must decode to 32 bytes)
        if bytes.len() != 32 {
            return Err(SigilError::InvalidSessionToken(
                "token must decode to 32 bytes".into(),
            ));
        }

        Ok(SessionToken(s))
    }

    /// Create a session token from raw bytes (encodes as base64)
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        // Validate length (must be 32 bytes)
        if bytes.len() != 32 {
            return Err(SigilError::InvalidSessionToken(
                "token must be 32 bytes".into(),
            ));
        }

        // Encode as base64
        use base64::prelude::*;
        Ok(SessionToken(BASE64_STANDARD.encode(bytes)))
    }

    /// Get the token as raw bytes (decodes from base64)
    pub fn to_bytes(&self) -> Vec<u8> {
        use base64::prelude::*;
        BASE64_STANDARD
            .decode(&self.0)
            .expect("SessionToken is always valid base64")
    }

    /// Get the token as a string
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Get the token as base64 string
    pub fn to_base64(&self) -> String {
        self.0.clone()
    }
}

/// Session start request payload
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionStartRequest {
    /// Parent session token (for nested agent workers)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parent_token: Option<String>,
    /// Worker identifier (for debugging and audit)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub worker_id: Option<String>,
}

/// Session information
#[derive(Debug, Clone)]
pub struct SessionInfo {
    /// Session token
    pub token: SessionToken,
    /// Peer credentials of the session creator
    pub peer: PeerCredentials,
    /// Session creation time
    pub created_at: chrono::DateTime<chrono::Utc>,
    /// Last activity time
    pub last_activity: chrono::DateTime<chrono::Utc>,
    /// Parent session token (for nested agent sessions)
    pub parent_token: Option<String>,
    /// Worker identifier (for debugging and audit)
    pub worker_id: Option<String>,
}

impl SessionInfo {
    /// Create a new session
    pub fn new(token: SessionToken, peer: PeerCredentials) -> Self {
        let now = chrono::Utc::now();
        Self {
            token,
            peer,
            created_at: now,
            last_activity: now,
            parent_token: None,
            worker_id: None,
        }
    }

    /// Create a new session with a parent (for nested agent workers)
    pub fn with_parent(
        token: SessionToken,
        peer: PeerCredentials,
        parent_token: String,
        worker_id: Option<String>,
    ) -> Self {
        let now = chrono::Utc::now();
        Self {
            token,
            peer,
            created_at: now,
            last_activity: now,
            parent_token: Some(parent_token),
            worker_id,
        }
    }

    /// Update the last activity time
    pub fn update_activity(&mut self) {
        self.last_activity = chrono::Utc::now();
    }

    /// Check if the session is idle beyond the given duration
    pub fn is_idle_longer_than(&self, duration: chrono::Duration) -> bool {
        let idle_time = chrono::Utc::now() - self.last_activity;
        idle_time > duration
    }

    /// Check if this is a child session
    pub fn is_child_session(&self) -> bool {
        self.parent_token.is_some()
    }
}

/// Daemon status response payload
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DaemonStatus {
    /// Daemon version
    pub version: String,
    /// Vault is unlocked
    pub unlocked: bool,
    /// Number of loaded secrets
    pub secret_count: usize,
    /// Number of active sessions
    pub session_count: usize,
    /// Daemon uptime (seconds)
    pub uptime_secs: u64,
    /// Idle timeout (seconds, or None for never)
    pub idle_timeout_secs: Option<u64>,
    /// Configured vault backend type
    pub backend_type: String,
    /// Path to socket
    pub socket_path: PathBuf,
}

/// Ping response payload
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PingResponse {
    /// Daemon is alive
    pub alive: bool,
    /// Server time
    pub server_time: chrono::DateTime<chrono::Utc>,
    /// Protocol version
    pub protocol_version: u16,
}

/// Resolve request payload
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResolveRequest {
    /// Secret paths to resolve
    pub paths: Vec<String>,
}

/// Resolve response payload
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResolveResponse {
    /// Resolved secret values (base64-encoded)
    pub values: HashMap<String, String>,
}

/// Scrub request payload
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScrubRequest {
    /// Output text to scrub
    pub output: String,
}

/// Scrub response payload
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScrubResponse {
    /// Scrubbed output text
    pub output: String,
    /// Number of secrets found and redacted
    pub count: usize,
}

/// FUSE read request payload
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FuseReadRequest {
    /// Path to the secret file (e.g., "kalshi/api_key")
    pub path: String,
    /// Request offset in file
    pub offset: u64,
    /// Request size
    pub size: u32,
    /// PID of the requesting process (from fuse_req_ctx)
    pub req_pid: u32,
    /// UID of the requesting process (from fuse_req_ctx)
    pub req_uid: u32,
    /// GID of the requesting process (from fuse_req_ctx)
    pub req_gid: u32,
}

/// FUSE read response payload
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FuseReadResponse {
    /// File data (base64-encoded)
    pub data: String,
    /// Actual size of data returned
    pub size: u32,
    /// Whether this is the end of file
    pub eof: bool,
}

/// Execute operation request payload
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecuteOperationRequest {
    /// Operation ID to execute
    pub operation_id: String,
    /// Optional arguments to pass to the operation
    #[serde(default)]
    pub args: Vec<String>,
    /// Whether to skip approval (only for pre-approved operations)
    #[serde(default)]
    pub skip_approval: bool,
}

/// Execute operation response payload
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecuteOperationResponse {
    /// Operation result
    #[serde(flatten)]
    pub result: super::OperationResult,
}

/// Exec command request payload
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecRequest {
    /// Command to execute (e.g., "aws s3 ls")
    pub command: String,
    /// Command arguments
    #[serde(default)]
    pub args: Vec<String>,
    /// Working directory
    #[serde(default)]
    pub working_dir: Option<String>,
    /// Whether to enable network isolation
    #[serde(default)]
    pub network_isolated: bool,
    /// Project directory for signature lookup
    #[serde(default)]
    pub project_dir: Option<String>,
    /// Timeout in seconds (0 = no timeout)
    #[serde(default)]
    pub timeout_secs: u64,
}

/// Exec command response payload
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecResponse {
    /// Command exit code
    pub exit_code: i32,
    /// Command stdout (scrubbed)
    pub stdout: String,
    /// Command stderr (scrubbed)
    pub stderr: String,
    /// Whether the command timed out
    pub timed_out: bool,
    /// Execution duration in milliseconds
    pub duration_ms: u64,
    /// Number of secrets detected and scrubbed from output
    pub secrets_scrubbed: usize,
    /// Signatures that matched for auto-injection
    pub matched_signatures: Vec<String>,
}

/// Request access payload
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RequestAccessPayload {
    /// Secret path being requested
    pub secret: String,
    /// Reason for the request
    pub reason: String,
    /// Requested duration (e.g., "5m", "1h", "session")
    pub duration: String,
    /// Agent identifier (optional, for tracking)
    #[serde(default)]
    pub agent_id: Option<String>,
}

/// Request access response payload
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RequestAccessResponse {
    /// Whether access was granted
    pub granted: bool,
    /// Status message
    pub message: String,
    /// Expiration time (if granted with time limit)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<chrono::DateTime<chrono::Utc>>,
    /// Access grant ID (for tracking)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub grant_id: Option<String>,
}

/// Check access payload
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CheckAccessPayload {
    /// Secret path to check
    pub secret: String,
}

/// Check access response payload
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CheckAccessResponse {
    /// Whether access is currently granted
    pub granted: bool,
    /// Status message
    pub status: String,
    /// Time remaining (if time-limited)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_in: Option<u64>, // seconds
}

/// Grant lease request payload
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GrantLeaseRequest {
    /// Secret path to grant lease for
    pub secret_path: String,
    /// TTL in seconds (optional, uses default if not specified)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ttl_secs: Option<i64>,
}

/// Grant lease response payload
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GrantLeaseResponse {
    /// The granted lease
    pub lease: LeaseDetails,
}

/// Lease details (shared between request and response)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LeaseDetails {
    /// Lease ID
    pub id: String,
    /// Secret path
    pub secret_path: String,
    /// Granted at timestamp
    pub granted_at: String,
    /// Expires at timestamp
    pub expires_at: String,
    /// Remaining time in seconds
    pub remaining_secs: i64,
}

/// Revoke lease request payload
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RevokeLeaseRequest {
    /// Lease ID to revoke
    pub lease_id: String,
    /// Optional reason for revocation
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

/// List leases response payload
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ListLeasesResponse {
    /// Active leases
    pub leases: Vec<LeaseDetails>,
    /// Total count
    pub total_count: usize,
}

/// Lease statistics response payload
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LeaseStatsResponse {
    /// Total number of leases
    pub total_leases: usize,
    /// Number of active leases
    pub active_leases: usize,
    /// Number of expired leases
    pub expired_leases: usize,
    /// Number of revoked leases
    pub revoked_leases: usize,
}

/// Unlock request payload
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UnlockRequest {
    /// Vault passphrase for authentication
    pub passphrase: String,
}

/// List operations response payload
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ListOperationsResponse {
    /// Available operations (ID + description only, never commands)
    pub operations: Vec<OperationDescription>,
}

/// Description of an operation (safe to show to agent)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OperationDescription {
    /// Operation ID
    pub id: String,
    /// Human-readable description
    pub description: String,
    /// Whether this operation requires approval
    pub requires_approval: bool,
}

/// Session details for listing
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionDetails {
    /// Session token (truncated for display)
    pub token: String,
    /// Peer credentials
    pub peer: PeerCredentials,
    /// Session creation time
    pub created_at: chrono::DateTime<chrono::Utc>,
    /// Last activity time
    pub last_activity: chrono::DateTime<chrono::Utc>,
    /// Idle time in seconds
    pub idle_secs: i64,
}

/// List sessions response payload
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ListSessionsResponse {
    /// Active sessions
    pub sessions: Vec<SessionDetails>,
}

/// Kill session request payload
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KillSessionRequest {
    /// Session token to kill
    pub token: String,
}

/// Kill session response payload
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KillSessionResponse {
    /// Whether the session was killed
    pub killed: bool,
    /// Status message
    pub message: String,
}

/// Session node in the hierarchy tree
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionNode {
    /// Session token (truncated for display)
    pub token: String,
    /// Parent session token (if this is a child session)
    pub parent_token: Option<String>,
    /// Worker identifier
    pub worker_id: Option<String>,
    /// Process ID
    pub pid: u32,
    /// User ID
    pub uid: u32,
    /// Session creation time
    pub created_at: String,
    /// Last activity time
    pub last_activity: String,
    /// Child sessions (recursively)
    #[serde(default)]
    pub children: Vec<SessionNode>,
}

/// Get session tree response payload
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GetSessionTreeResponse {
    /// Session hierarchy as a forest (multiple root nodes)
    pub sessions: Vec<SessionNode>,
    /// Total number of sessions
    pub total_count: usize,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_session_token_generation() {
        let token1 = SessionToken::generate();
        let token2 = SessionToken::generate();
        assert_ne!(token1, token2);
        assert!(token1.to_base64().len() > 32);
    }

    #[test]
    fn test_session_token_validation() {
        let token = SessionToken::generate();
        let token_str = token.to_base64();
        assert!(SessionToken::from_string(token_str).is_ok());
        assert!(SessionToken::from_string("invalid".to_string()).is_err());
    }

    #[test]
    fn test_request_response_serialization() {
        let request = IpcRequest::new(IpcOperation::Ping, "test-token".to_string());
        let json = serde_json::to_string(&request).unwrap();
        assert!(json.contains("\"op\":\"ping\""));
        assert!(json.contains("\"v\":1"));

        let response = IpcResponse::ok(request.id.clone());
        let json = serde_json::to_string(&response).unwrap();
        assert!(json.contains("\"ok\":true"));
    }

    #[test]
    fn test_error_response() {
        let error = IpcError::new(IpcErrorCode::SecretNotFound, "test secret not found");
        let response = IpcResponse::error("req_123".to_string(), error);
        let json = serde_json::to_string(&response).unwrap();
        assert!(json.contains("\"ok\":false"));
        assert!(json.contains("\"code\":\"SECRET_NOT_FOUND\""));
    }

    #[test]
    fn test_length_prefix_encoding() {
        let data = b"hello world";
        let mut buffer = Vec::new();
        write_message(&mut buffer, data).unwrap();

        assert_eq!(buffer.len(), 4 + data.len());
        assert_eq!(&buffer[0..4], (data.len() as u32).to_be_bytes());

        let mut cursor = io::Cursor::new(buffer);
        let read_data = read_message(&mut cursor).unwrap();
        assert_eq!(read_data, data);
    }

    #[test]
    fn test_session_idle_check() {
        let token = SessionToken::generate();
        let peer = PeerCredentials {
            pid: 123,
            uid: 456,
            gid: 789,
        };
        let mut session = SessionInfo::new(token, peer);

        assert!(!session.is_idle_longer_than(chrono::Duration::seconds(10)));

        // Manually set last_activity to 11 seconds ago
        session.last_activity = chrono::Utc::now() - chrono::Duration::seconds(11);
        assert!(session.is_idle_longer_than(chrono::Duration::seconds(10)));
    }
}
