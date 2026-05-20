//! SIGIL SDK - Node.js bindings
//!
//! This crate provides Node.js native bindings for SIGIL using napi-rs.
//! It allows JavaScript/TypeScript code to interact with the SIGIL daemon.

#![warn(missing_docs)]
#![warn(clippy::all)]

use napi_derive::napi;
use sigil_sdk::{
    client::{AccessGrant as RustAccessGrant, DaemonStatusInfo as RustDaemonStatusInfo, ExecResult as RustExecResult, SecretMetadata as RustSecretMetadata},
    OperationDescription as RustOperationDescription,
    SigilClient as RustSigilClient,
};
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::Mutex;

/// SIGIL SDK client for Node.js
///
/// This client connects to the SIGIL daemon via Unix socket and provides
/// methods for interacting with secrets.
#[napi]
pub struct SigilClient {
    /// Inner Rust client
    inner: Arc<Mutex<RustSigilClient>>,
}

#[napi]
impl SigilClient {
    /// Create a new SIGIL client with default socket path
    #[napi(constructor)]
    pub fn new() -> napi::Result<Self> {
        let client = RustSigilClient::connect_default()
            .map_err(|e| napi::Error::from_reason(format!("Failed to create client: {}", e)))?;

        Ok(Self {
            inner: Arc::new(Mutex::new(client)),
        })
    }

    /// Create a new SIGIL client with a custom socket path
    ///
    /// # Arguments
    ///
    /// * `socket_path` - Path to the SIGIL daemon Unix socket
    #[napi(factory)]
    pub fn with_socket_path(socket_path: String) -> napi::Result<Self> {
        let client = RustSigilClient::new(PathBuf::from(socket_path))
            .map_err(|e| napi::Error::from_reason(format!("Failed to create client: {}", e)))?;

        Ok(Self {
            inner: Arc::new(Mutex::new(client)),
        })
    }

    /// Create a new SIGIL client and load session token from file
    ///
    /// This attempts to read the session token from the standard location
    /// ($XDG_RUNTIME_DIR/sigil-session-token) and configure the client with it.
    #[napi(factory)]
    pub fn with_token() -> napi::Result<Self> {
        let client = RustSigilClient::connect_with_token().map_err(|e| {
            napi::Error::from_reason(format!("Failed to create client with token: {}", e))
        })?;

        Ok(Self {
            inner: Arc::new(Mutex::new(client)),
        })
    }

    /// Connect to the SIGIL daemon (verifies connection)
    #[napi]
    pub async fn connect(&self) -> napi::Result<()> {
        let client = self.inner.clone();
        let client = client.lock().await;

        client
            .connect()
            .await
            .map_err(|e| napi::Error::from_reason(format!("Failed to connect to daemon: {}", e)))?;

        Ok(())
    }

    /// Get a secret value by path
    ///
    /// # Arguments
    ///
    /// * `path` - Secret path (e.g., "kalshi/api_key")
    #[napi]
    pub async fn get(&self, path: String) -> napi::Result<String> {
        let client = self.inner.clone();
        let client = client.lock().await;

        let secret_value = client
            .get(&path)
            .await
            .map_err(|e| napi::Error::from_reason(format!("Failed to get secret: {}", e)))?;

        secret_value.expose(|bytes| {
            String::from_utf8(bytes.to_vec())
                .map_err(|e| napi::Error::from_reason(format!("Secret is not valid UTF-8: {}", e)))
        })
    }

    /// Resolve placeholders in a string
    ///
    /// # Arguments
    ///
    /// * `input` - String containing placeholders like `{{secret:path}}`
    #[napi]
    pub async fn resolve(&self, input: String) -> napi::Result<String> {
        let client = self.inner.clone();
        let client = client.lock().await;

        client
            .resolve(&input)
            .await
            .map_err(|e| napi::Error::from_reason(format!("Failed to resolve placeholders: {}", e)))
    }

    /// Check if a secret exists
    ///
    /// # Arguments
    ///
    /// * `path` - Secret path to check
    #[napi]
    pub async fn exists(&self, path: String) -> napi::Result<bool> {
        let client = self.inner.clone();
        let client = client.lock().await;

        client.exists(&path).await.map_err(|e| {
            napi::Error::from_reason(format!("Failed to check secret existence: {}", e))
        })
    }

    /// List secrets with a given prefix
    ///
    /// # Arguments
    ///
    /// * `prefix` - Optional prefix to filter secrets (e.g., "aws/")
    #[napi]
    pub async fn list(&self, prefix: String) -> napi::Result<Vec<SecretMetadata>> {
        let client = self.inner.clone();
        let client = client.lock().await;

        let secrets = client
            .list(&prefix)
            .await
            .map_err(|e| napi::Error::from_reason(format!("Failed to list secrets: {}", e)))?;

        // Convert Rust SDK metadata to Node.js compatible metadata
        Ok(secrets.into_iter().map(SecretMetadata::from).collect())
    }

    /// Request access to a secret (triggers TUI approval workflow)
    ///
    /// # Arguments
    ///
    /// * `path` - Secret path to request access for
    /// * `reason` - Reason for the access request
    /// * `duration_secs` - Optional duration in seconds for time-bounded access
    #[napi]
    pub async fn request_access(
        &self,
        path: String,
        reason: String,
        duration_secs: Option<u32>,
    ) -> napi::Result<AccessGrant> {
        let client = self.inner.clone();
        let client = client.lock().await;

        let grant = client
            .request_access(&path, &reason, duration_secs)
            .await
            .map_err(|e| napi::Error::from_reason(format!("Failed to request access: {}", e)))?;

        Ok(AccessGrant::from(grant))
    }

    /// Scrub secrets from output
    ///
    /// # Arguments
    ///
    /// * `output` - Output string that may contain secrets
    #[napi]
    pub async fn scrub(&self, output: String) -> napi::Result<String> {
        let client = self.inner.clone();
        let client = client.lock().await;

        client
            .scrub(&output)
            .await
            .map_err(|e| napi::Error::from_reason(format!("Failed to scrub output: {}", e)))
    }

    /// Get daemon status information
    #[napi]
    pub async fn status(&self) -> napi::Result<DaemonStatusInfo> {
        let client = self.inner.clone();
        let client = client.lock().await;

        let status = client
            .status()
            .await
            .map_err(|e| napi::Error::from_reason(format!("Failed to get daemon status: {}", e)))?;

        Ok(DaemonStatusInfo::from(status))
    }

    /// Execute a command with automatic secret injection and output scrubbing
    ///
    /// # Arguments
    ///
    /// * `command` - Command to execute (e.g., "aws")
    /// * `args` - Command arguments
    /// * `working_dir` - Optional working directory
    /// * `network_isolated` - Whether to enable network isolation
    /// * `project_dir` - Optional project directory for signature lookup
    /// * `timeout_secs` - Timeout in seconds (0 = no timeout)
    #[napi]
    pub async fn exec(
        &self,
        command: String,
        args: Vec<String>,
        working_dir: Option<String>,
        network_isolated: bool,
        project_dir: Option<String>,
        timeout_secs: u64,
    ) -> napi::Result<ExecResult> {
        let client = self.inner.clone();
        let client = client.lock().await;

        let result = client
            .exec(&command, args, working_dir, network_isolated, project_dir, timeout_secs)
            .await
            .map_err(|e| napi::Error::from_reason(format!("Failed to execute command: {}", e)))?;

        Ok(ExecResult::from(result))
    }

    /// List available sealed operations
    ///
    /// Returns a list of operations that can be executed with approval.
    #[napi]
    pub async fn list_operations(&self) -> napi::Result<Vec<OperationDescription>> {
        let client = self.inner.clone();
        let client = client.lock().await;

        let operations = client
            .list_operations()
            .await
            .map_err(|e| napi::Error::from_reason(format!("Failed to list operations: {}", e)))?;

        Ok(operations.into_iter().map(OperationDescription::from).collect())
    }
}

/// Secret metadata for Node.js
#[napi(object)]
pub struct SecretMetadata {
    /// Secret path
    pub path: String,
    /// Secret type
    #[napi(js_name = "secretType")]
    pub secret_type: String,
    /// Creation timestamp (RFC3339)
    #[napi(js_name = "createdAt")]
    pub created_at: String,
    /// Last update timestamp (RFC3339)
    #[napi(js_name = "updatedAt")]
    pub updated_at: String,
    /// Tags
    pub tags: Vec<String>,
    /// Notes
    pub notes: Option<String>,
}

impl From<RustSecretMetadata> for SecretMetadata {
    fn from(meta: RustSecretMetadata) -> Self {
        Self {
            path: meta.path,
            secret_type: meta.secret_type,
            created_at: meta.created_at,
            updated_at: meta.updated_at,
            tags: meta.tags,
            notes: meta.notes,
        }
    }
}

/// Result of an access request
#[napi(object)]
pub struct AccessGrant {
    /// Whether access was granted
    pub granted: bool,
    /// When the grant expires (if applicable)
    #[napi(js_name = "expiresAt")]
    pub expires_at: Option<String>,
}

impl From<RustAccessGrant> for AccessGrant {
    fn from(grant: RustAccessGrant) -> Self {
        Self {
            granted: grant.granted,
            expires_at: grant.expires_at,
        }
    }
}

/// Daemon status information
#[napi(object)]
pub struct DaemonStatusInfo {
    /// Whether the daemon is running
    pub running: bool,
    /// Daemon uptime in seconds
    #[napi(js_name = "uptimeSecs")]
    pub uptime_secs: f64,
    /// Number of active sessions
    #[napi(js_name = "activeSessions")]
    pub active_sessions: u32,
    /// Number of secrets loaded
    #[napi(js_name = "secretsLoaded")]
    pub secrets_loaded: u32,
}

impl From<RustDaemonStatusInfo> for DaemonStatusInfo {
    fn from(info: RustDaemonStatusInfo) -> Self {
        Self {
            running: info.running,
            uptime_secs: info.uptime_secs as f64,
            active_sessions: info.active_sessions,
            secrets_loaded: info.secrets_loaded,
        }
    }
}

/// Result of executing a command
#[napi(object)]
pub struct ExecResult {
    /// Command exit code
    pub exit_code: i32,
    /// Command stdout (scrubbed)
    pub stdout: String,
    /// Command stderr (scrubbed)
    pub stderr: String,
    /// Whether the command timed out
    pub timed_out: bool,
    /// Execution duration in milliseconds
    #[napi(js_name = "durationMs")]
    pub duration_ms: f64,
    /// Number of secrets detected and scrubbed from output
    #[napi(js_name = "secretsScrubbed")]
    pub secrets_scrubbed: f64,
    /// Signatures that matched for auto-injection
    #[napi(js_name = "matchedSignatures")]
    pub matched_signatures: Vec<String>,
}

impl From<RustExecResult> for ExecResult {
    fn from(result: RustExecResult) -> Self {
        Self {
            exit_code: result.exit_code,
            stdout: result.stdout,
            stderr: result.stderr,
            timed_out: result.timed_out,
            duration_ms: result.duration_ms as f64,
            secrets_scrubbed: result.secrets_scrubbed as f64,
            matched_signatures: result.matched_signatures,
        }
    }
}

/// Description of a sealed operation
#[napi(object)]
pub struct OperationDescription {
    /// Operation ID
    pub id: String,
    /// Human-readable description
    pub description: String,
    /// Whether this operation requires approval
    #[napi(js_name = "requiresApproval")]
    pub requires_approval: bool,
}

impl From<RustOperationDescription> for OperationDescription {
    fn from(desc: RustOperationDescription) -> Self {
        Self {
            id: desc.id,
            description: desc.description,
            requires_approval: desc.requires_approval,
        }
    }
}
