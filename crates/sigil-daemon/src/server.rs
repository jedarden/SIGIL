//! Daemon server implementation

use crate::alerts::{AlertConfig, AlertSender, LockdownEvent};
use crate::audit::AuditLogger;
use crate::canary_manager::CanaryManager;
use crate::memory::ProtectedSecrets;
use crate::proxy::ProxyManager;
use sigil_core::{
    get_peer_credentials,
    ipc::{
        ExecRequest, ExecResponse, GrantLeaseRequest, GrantLeaseResponse, LeaseDetails,
        RevokeLeaseRequest,
    },
    read_request_async, write_response_async, DaemonStatus, ExecuteOperationRequest,
    ExecuteOperationResponse, FuseReadRequest, FuseReadResponse, IpcError, IpcErrorCode,
    IpcOperation, IpcRequest, IpcResponse, LeaseConfig, LeaseManager, ListOperationsResponse,
    OperationDescription, OperationResult, OperationsRegistry, PeerCredentials, PingResponse,
    ResolveRequest, ResolveResponse, ScrubRequest, ScrubResponse, SecretPath, SessionInfo,
    SessionToken,
};
use sigil_sandbox::{BubblewrapSandbox, SandboxConfig, SandboxProvider};
use sigil_scrub::Scrubber;
use sigil_signatures::{InjectionType, SignatureMatcher};
use sigil_tui::approval::{ApprovalDecision, ApprovalPrompt, ApprovalRequest};
use std::collections::HashMap;
use std::os::unix::io::FromRawFd;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::{Mutex, RwLock};
use tokio::time::{interval, timeout};
use tracing::{debug, error, info, warn};

/// Result of command execution
#[derive(Debug)]
struct CommandExecutionResult {
    exit_code: i32,
    stdout: String,
    stderr: String,
}

/// Lockdown report with details about what was done during lockdown
#[derive(Debug, Clone, serde::Serialize)]
pub struct LockdownReport {
    /// Timestamp when lockdown was initiated
    #[serde(skip_serializing_if = "Option::is_none")]
    pub timestamp: Option<chrono::DateTime<chrono::Utc>>,
    /// Number of sandbox processes killed
    pub sandboxes_killed: usize,
    /// Number of session tokens revoked
    pub sessions_revoked: usize,
    /// Number of dynamic leases revoked
    pub leases_revoked: usize,
    /// Whether the vault was locked
    pub vault_locked: bool,
    /// Number of alerts sent
    pub alerts_sent: usize,
    /// Any errors that occurred during lockdown
    pub errors: Vec<String>,
}

impl LockdownReport {
    /// Create a new empty lockdown report
    pub fn new() -> Self {
        Self {
            timestamp: None,
            sandboxes_killed: 0,
            sessions_revoked: 0,
            leases_revoked: 0,
            vault_locked: false,
            alerts_sent: 0,
            errors: Vec::new(),
        }
    }

    /// Check if lockdown had any errors
    #[allow(dead_code)]
    pub fn has_errors(&self) -> bool {
        !self.errors.is_empty()
    }

    /// Get a summary of the lockdown
    #[allow(dead_code)]
    pub fn summary(&self) -> String {
        format!(
            "Lockdown: {} sandboxes killed, {} sessions revoked, {} leases revoked, vault_locked: {}, {} alerts sent, {} errors",
            self.sandboxes_killed,
            self.sessions_revoked,
            self.leases_revoked,
            self.vault_locked,
            self.alerts_sent,
            self.errors.len()
        )
    }
}

/// Auto-lockdown configuration
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct LockdownConfig {
    /// Number of canary triggers before auto-lockdown (0 = disabled)
    #[serde(default)]
    pub canary_triggers: usize,
    /// Number of unauthorized attempts before auto-lockdown (0 = disabled)
    #[serde(default)]
    pub unauthorized_attempts: usize,
    /// Auto-lockdown on exfiltration detection
    #[serde(default)]
    pub exfiltration_detected: bool,
}

/// Wrapper for lockdown config file format (supports nested [lockdown.auto] format)
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
struct LockdownConfigFile {
    #[serde(default)]
    lockdown: Option<LockdownSection>,
}

/// Lockdown section in config file
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
struct LockdownSection {
    #[serde(default)]
    auto: Option<AutoLockdownConfig>,
}

/// Auto-lockdown configuration section
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
struct AutoLockdownConfig {
    #[serde(default = "default_canary_triggers")]
    canary_triggers: usize,
    #[serde(default = "default_unauthorized_attempts")]
    unauthorized_attempts: usize,
    #[serde(default)]
    exfiltration_detected: bool,
}

fn default_canary_triggers() -> usize {
    3
}

fn default_unauthorized_attempts() -> usize {
    5
}

impl TryFrom<LockdownConfigFile> for LockdownConfig {
    type Error = String;

    fn try_from(value: LockdownConfigFile) -> Result<Self, Self::Error> {
        if let Some(lockdown) = value.lockdown {
            if let Some(auto) = lockdown.auto {
                return Ok(LockdownConfig {
                    canary_triggers: auto.canary_triggers,
                    unauthorized_attempts: auto.unauthorized_attempts,
                    exfiltration_detected: auto.exfiltration_detected,
                });
            }
        }
        // Return defaults if no nested config found
        Ok(LockdownConfig::default())
    }
}

impl Default for LockdownConfig {
    fn default() -> Self {
        Self {
            canary_triggers: 3,
            unauthorized_attempts: 5,
            exfiltration_detected: true,
        }
    }
}

/// Lockdown state persisted to disk
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct LockdownState {
    /// Whether daemon is in lockdown mode
    pub is_locked_down: bool,
    /// When lockdown was initiated
    #[serde(skip_serializing_if = "Option::is_none")]
    pub locked_down_at: Option<String>,
    /// Canary access counter (resets on lockdown)
    #[serde(default)]
    pub canary_access_count: usize,
    /// Unauthorized attempt counter (resets on lockdown)
    #[serde(default)]
    pub unauthorized_attempt_count: usize,
    /// Last counter reset time
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_counter_reset: Option<String>,
}

impl Default for LockdownState {
    fn default() -> Self {
        Self {
            is_locked_down: false,
            locked_down_at: None,
            canary_access_count: 0,
            unauthorized_attempt_count: 0,
            last_counter_reset: Some(chrono::Utc::now().to_rfc3339()),
        }
    }
}

impl LockdownState {
    /// Reset counters after lockdown
    pub fn reset_counters(&mut self) {
        self.canary_access_count = 0;
        self.unauthorized_attempt_count = 0;
        self.last_counter_reset = Some(chrono::Utc::now().to_rfc3339());
    }

    /// Increment canary access counter
    pub fn increment_canary(&mut self) {
        self.canary_access_count += 1;
    }

    /// Increment unauthorized attempt counter
    pub fn increment_unauthorized(&mut self) {
        self.unauthorized_attempt_count += 1;
    }

    /// Check if auto-lockdown should trigger based on config
    pub fn should_trigger_lockdown(&self, config: &LockdownConfig) -> bool {
        if self.is_locked_down {
            return false; // Already in lockdown
        }
        if config.canary_triggers > 0 && self.canary_access_count >= config.canary_triggers {
            return true;
        }
        if config.unauthorized_attempts > 0
            && self.unauthorized_attempt_count >= config.unauthorized_attempts
        {
            return true;
        }
        false
    }
}

/// Access grant for time-limited secret access
#[derive(Debug, Clone)]
#[allow(dead_code)]
struct AccessGrant {
    /// Unique grant ID
    id: String,
    /// Secret path that was granted
    secret_path: String,
    /// Session token that was granted access
    session_token: String,
    /// When the grant was created
    created_at: chrono::DateTime<chrono::Utc>,
    /// When the grant expires (None for session-scoped grants)
    expires_at: Option<chrono::DateTime<chrono::Utc>>,
    /// Reason for the grant
    reason: String,
    /// Agent identifier
    agent_id: Option<String>,
}

impl AccessGrant {
    /// Create a new access grant
    fn new(
        secret_path: String,
        session_token: String,
        duration: &str,
        reason: String,
        agent_id: Option<String>,
    ) -> Self {
        // Generate a unique ID using timestamp and random bytes
        use std::time::{SystemTime, UNIX_EPOCH};
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_micros();
        let random: u32 = rand::random();
        let id = format!("grant_{:x}_{:08x}", timestamp, random);

        let created_at = chrono::Utc::now();
        let expires_at = match duration {
            "session" => None, // Expires when session ends
            d => {
                // Parse duration like "5m", "1h", etc.
                let seconds = parse_duration(d);
                Some(created_at + chrono::Duration::seconds(seconds))
            }
        };

        Self {
            id,
            secret_path,
            session_token,
            created_at,
            expires_at,
            reason,
            agent_id,
        }
    }

    /// Check if the grant has expired
    fn is_expired(&self) -> bool {
        if let Some(expires) = self.expires_at {
            chrono::Utc::now() > expires
        } else {
            false // Session-scoped grants don't auto-expire
        }
    }

    /// Get remaining seconds until expiration
    fn remaining_seconds(&self) -> Option<u64> {
        self.expires_at.map(|exp| {
            let remaining = exp - chrono::Utc::now();
            if remaining.num_seconds() > 0 {
                remaining.num_seconds() as u64
            } else {
                0
            }
        })
    }
}

/// Serializable version of AccessGrant for file storage
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
struct GrantFile {
    /// Version of the grant file format
    version: u32,
    /// List of grants
    grants: Vec<SerializedGrant>,
}

/// A serialized grant that can be written to disk
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
struct SerializedGrant {
    /// Unique grant ID
    id: String,
    /// Secret path that was granted
    secret_path: String,
    /// Session token that was granted access
    session_token: String,
    /// When the grant was created (ISO 8601 string)
    created_at: String,
    /// When the grant expires (ISO 8601 string, empty for session-scoped)
    expires_at: Option<String>,
    /// Reason for the grant
    reason: String,
    /// Agent identifier
    agent_id: Option<String>,
}

impl From<&AccessGrant> for SerializedGrant {
    fn from(grant: &AccessGrant) -> Self {
        Self {
            id: grant.id.clone(),
            secret_path: grant.secret_path.clone(),
            session_token: grant.session_token.clone(),
            created_at: grant.created_at.to_rfc3339(),
            expires_at: grant.expires_at.map(|e| e.to_rfc3339()),
            reason: grant.reason.clone(),
            agent_id: grant.agent_id.clone(),
        }
    }
}

impl TryFrom<SerializedGrant> for AccessGrant {
    type Error = String;

    fn try_from(value: SerializedGrant) -> Result<Self, Self::Error> {
        let created_at = chrono::DateTime::parse_from_rfc3339(&value.created_at)
            .map_err(|e| format!("Invalid created_at: {}", e))?
            .with_timezone(&chrono::Utc);

        let expires_at = match value.expires_at {
            Some(exp_str) => Some(
                chrono::DateTime::parse_from_rfc3339(&exp_str)
                    .map_err(|e| format!("Invalid expires_at: {}", e))?
                    .with_timezone(&chrono::Utc),
            ),
            None => None,
        };

        Ok(AccessGrant {
            id: value.id,
            secret_path: value.secret_path,
            session_token: value.session_token,
            created_at,
            expires_at,
            reason: value.reason,
            agent_id: value.agent_id,
        })
    }
}

/// Parse a duration string like "5m", "1h", "30s" into seconds
fn parse_duration(duration: &str) -> i64 {
    let mut result = 0i64;
    let mut current = String::new();

    for ch in duration.chars() {
        if ch.is_ascii_digit() {
            current.push(ch);
        } else if ch.is_ascii_alphabetic() {
            let value: i64 = current.parse().unwrap_or(0);
            let multiplier = match ch.to_ascii_lowercase() {
                's' => 1,
                'm' => 60,
                'h' => 3600,
                'd' => 86400,
                _ => 0,
            };
            result += value * multiplier;
            current.clear();
        }
    }

    result
}

/// Get the systemd socket activation file descriptor, if available
///
/// This implements the systemd socket activation protocol:
/// - Check the $LISTEN_FDS environment variable
/// - File descriptors start at SD_LISTEN_FDS_START (3)
/// - Returns the file descriptor number if available, None otherwise
fn get_systemd_socket_fd() -> Option<std::os::unix::io::RawFd> {
    // Environment variable set by systemd
    const LISTEN_FDS: &str = "LISTEN_FDS";
    // Starting file descriptor for passed fds
    const SD_LISTEN_FDS_START: std::os::unix::io::RawFd = 3;
    // Environment variable to unset to prevent passing to children
    const LISTEN_PID: &str = "LISTEN_PID";

    // Check if we're in a systemd socket activation context
    let listen_fds = match std::env::var(LISTEN_FDS) {
        Ok(val) => val.parse::<usize>().unwrap_or(0),
        Err(_) => return None,
    };

    if listen_fds == 0 {
        return None;
    }

    // Verify that LISTEN_PID matches our PID (security check)
    if let Ok(listen_pid_str) = std::env::var(LISTEN_PID) {
        if let Ok(listen_pid) = listen_pid_str.parse::<u32>() {
            let our_pid = std::process::id();
            if listen_pid != our_pid {
                tracing::error!(
                    "systemd socket activation PID mismatch: expected {}, got {}",
                    our_pid,
                    listen_pid
                );
                return None;
            }
        }
    }

    // Unset LISTEN_FDS to prevent it from being passed to child processes
    std::env::remove_var(LISTEN_FDS);
    std::env::remove_var(LISTEN_PID);

    tracing::info!(
        "systemd socket activation: {} file descriptor(s)",
        listen_fds
    );

    // Return the first file descriptor (SD_LISTEN_FDS_START)
    Some(SD_LISTEN_FDS_START)
}

/// Get the launchd socket activation file descriptor, if available (macOS only)
///
/// This implements the launchd socket activation protocol:
/// - Uses the launchd API to check for passed sockets
/// - Returns the file descriptor number if available, None otherwise
#[cfg(target_os = "macos")]
fn get_launchd_socket_fd() -> Option<std::os::unix::io::RawFd> {
    // launchd socket name (must match the key in the plist file)
    const SOCKET_NAME: &str = "sigil";

    // Safety: launchd API calls are unsafe
    unsafe {
        // Check if we have a launchd socket
        let mut fd: std::os::unix::io::RawFd = -1;

        // Use launch_activate_socket to get the socket file descriptor
        // This function is available in macOS 10.10+
        let result = launch_activate_socket(
            std::ffi::CString::new(SOCKET_NAME).unwrap().as_ptr(),
            &mut fd as *mut std::os::unix::io::RawFd,
        );

        if result == 0 && fd >= 0 {
            tracing::info!("launchd socket activation: socket fd {}", fd);
            return Some(fd);
        }
    }

    None
}

// launch_activate_socket is not in the standard libc bindings for Rust
// We need to declare it manually for macOS
#[cfg(target_os = "macos")]
extern "C" {
    /// launch_activate_socket - activate a socket from launchd
    ///
    /// # Arguments
    /// * `name` - socket name (from plist)
    /// * `fd_ptr` - pointer to store the file descriptor
    ///
    /// # Returns
    /// 0 on success, error code on failure
    fn launch_activate_socket(
        name: *const std::ffi::c_char,
        fd_ptr: *mut std::os::unix::io::RawFd,
    ) -> std::ffi::c_int;
}

/// Send a notification to systemd via sd_notify protocol
///
/// This implements the sd_notify protocol for systemd service readiness notification.
/// When NOTIFY_SOCKET is set, we send a datagram to it with the specified status.
///
/// Common notifications:
/// - "READY=1" - Service is ready
/// - "RELOADING=1" - Service is reloading
/// - "STOPPING=1" - Service is stopping
/// - "STATUS=..." - Free-form status string
fn sd_notify(message: &str) {
    use std::os::fd::AsRawFd;

    // Environment variable set by systemd for notifications
    const NOTIFY_SOCKET: &str = "NOTIFY_SOCKET";

    // Check if we're in a systemd context
    let socket_path_env = match std::env::var(NOTIFY_SOCKET) {
        Ok(path) => path,
        Err(_) => {
            tracing::debug!("No NOTIFY_SOCKET set, skipping sd_notify");
            return;
        }
    };

    // The socket path can start with '@' for abstract namespace (Linux-specific)
    let (is_abstract, socket_path_unprefixed) =
        if let Some(rest) = socket_path_env.strip_prefix('@') {
            (true, rest.to_string())
        } else {
            (false, socket_path_env)
        };

    // Create a Unix datagram socket
    let socket = match std::os::unix::net::UnixDatagram::unbound() {
        Ok(s) => s,
        Err(e) => {
            tracing::error!("Failed to create sd_notify socket: {}", e);
            return;
        }
    };

    let send_result = if is_abstract {
        // For abstract namespace, use libc directly
        let path_bytes = socket_path_unprefixed.as_bytes();

        unsafe {
            let mut addr: libc::sockaddr_un = std::mem::zeroed();
            addr.sun_family = libc::AF_UNIX as u16;

            // Abstract namespace: first byte is null, then the path
            let max_len = addr.sun_path.len() - 1;
            let path_len = path_bytes.len().min(max_len);
            addr.sun_path[0] = 0;
            std::ptr::copy_nonoverlapping(
                path_bytes.as_ptr(),
                addr.sun_path[1..].as_mut_ptr() as *mut u8,
                path_len,
            );

            // Calculate address length
            let addr_len = std::mem::size_of::<libc::sa_family_t>() as u32 + path_len as u32 + 1; // +1 for the leading null byte

            libc::sendto(
                socket.as_raw_fd(),
                message.as_ptr() as *const libc::c_void,
                message.len(),
                0,
                &addr as *const libc::sockaddr_un as *const libc::sockaddr,
                addr_len as libc::socklen_t,
            )
        }
    } else {
        // Regular filesystem path - use standard library
        match socket.send_to(
            message.as_bytes(),
            std::path::Path::new(&socket_path_unprefixed),
        ) {
            Ok(n) => n as isize,
            Err(e) => {
                tracing::error!("Failed to send sd_notify: {}", e);
                return;
            }
        }
    };

    match send_result {
        n if n > 0 => {
            tracing::debug!("sd_notify sent: {} ({} bytes)", message, n);
        }
        0 => {
            tracing::warn!("sd_notify sent 0 bytes");
        }
        _ => {
            tracing::error!("sd_notify sendto failed");
        }
    }
}

/// Create a UnixListener, either from a socket activation or by binding to a path
///
/// If systemd socket activation is enabled, check for $LISTEN_FDS.
/// If launchd socket activation is enabled, check for launchd sockets.
/// Otherwise, create a new socket bound to the specified path.
async fn create_unix_listener(
    socket_path: &Path,
    systemd_mode: bool,
) -> std::result::Result<tokio::net::UnixListener, std::io::Error> {
    // Try systemd socket activation first
    if systemd_mode {
        if let Some(fd) = get_systemd_socket_fd() {
            tracing::info!("Using systemd socket activation (fd {})", fd);
            // Safety: The file descriptor is valid and owned by systemd
            // We take ownership using FromRawFd
            let std_listener = unsafe { std::os::unix::net::UnixListener::from_raw_fd(fd) };
            std_listener.set_nonblocking(true)?;
            return tokio::net::UnixListener::from_std(std_listener);
        }

        // On macOS, also try launchd socket activation
        #[cfg(target_os = "macos")]
        {
            if let Some(fd) = get_launchd_socket_fd() {
                tracing::info!("Using launchd socket activation (fd {})", fd);
                let std_listener = unsafe { std::os::unix::net::UnixListener::from_raw_fd(fd) };
                std_listener.set_nonblocking(true)?;
                return tokio::net::UnixListener::from_std(std_listener);
            }
        }
    }

    // Fall back to creating a new socket
    tracing::info!("Creating new Unix socket at: {}", socket_path.display());

    // Remove stale socket if it exists
    if socket_path.exists() {
        std::fs::remove_file(socket_path)?;
    }

    // Ensure parent directory exists
    if let Some(parent) = socket_path.parent() {
        std::fs::create_dir_all(parent)?;
    }

    // Create and bind the socket
    tokio::net::UnixListener::bind(socket_path)
}

/// Daemon server
#[derive(Clone)]
#[allow(dead_code)]
pub struct DaemonServer {
    socket_path: PathBuf,
    idle_timeout: Duration,
    vault_path: PathBuf,
    audit_logger: Arc<AuditLogger>,
    sessions: Arc<RwLock<HashMap<String, SessionInfo>>>,
    secrets: Arc<ProtectedSecrets>,
    scrubber: Arc<RwLock<Scrubber>>,
    signature_matcher: Arc<SignatureMatcher>,
    last_activity: Arc<Mutex<Instant>>,
    shutdown_flag: Arc<RwLock<bool>>,
    lockdown_flag: Arc<RwLock<bool>>,
    start_time: Instant,
    canary_manager: Arc<CanaryManager>,
    operations: Arc<RwLock<OperationsRegistry>>,
    access_grants: Arc<RwLock<HashMap<String, Vec<AccessGrant>>>>,
    alert_sender: AlertSender,
    ci_mode: bool,
    systemd_mode: bool,
    lockdown_config: LockdownConfig,
    lockdown_state: Arc<RwLock<LockdownState>>,
    lease_manager: Arc<LeaseManager>,
    proxy_manager: Arc<ProxyManager>,
}

/// Execute a command with optional sandboxing
///
/// This function handles both sandboxed execution (via bubblewrap) and
/// direct execution as a fallback. It also manages file injection and cleanup.
fn execute_command_sandboxed(
    command: String,
    args: Vec<String>,
    sandbox_config: SandboxConfig,
    use_sandbox: bool,
) -> Result<CommandExecutionResult, String> {
    use sigil_core::ResolvedCommand;

    // Build the full command string
    let full_command = if args.is_empty() {
        command.clone()
    } else {
        format!("{} {}", command, args.join(" "))
    };

    // Create a ResolvedCommand for the sandbox
    let resolved_cmd = ResolvedCommand {
        original: full_command.clone(),
        resolved: full_command.clone(),
        placeholders: Vec::new(),
        env_injections: Vec::new(),
        file_injections: Vec::new(),
        use_stdin: false,
        stdin_secret: None,
    };

    // Create the command to execute
    let cmd_result = if use_sandbox {
        // Use sandbox
        let sandbox =
            BubblewrapSandbox::new().map_err(|e| format!("Failed to create sandbox: {}", e))?;
        sandbox
            .wrap_command(&resolved_cmd, &sandbox_config)
            .map_err(|e| format!("Sandbox wrap failed: {}", e))
    } else {
        // Direct execution
        let mut cmd = std::process::Command::new(&command);
        cmd.args(&args);

        // Apply environment variables
        for (key, value) in &sandbox_config.env_vars {
            cmd.env(key, value);
        }

        // Set working directory if specified
        if let Some(ref wd) = sandbox_config.working_dir {
            cmd.current_dir(wd);
        }

        Ok(cmd)
    };

    let mut cmd = cmd_result.map_err(|e| format!("Failed to build command: {}", e))?;

    // Handle file injection if not using sandbox (sandbox handles it internally)
    let injection_manager: Option<sigil_sandbox::InjectionManager> = None;
    if !use_sandbox && !sandbox_config.file_injections.is_empty() {
        // For file injections without sandbox, we need to create temp files
        // and pass them as environment variables or modify the command
        // For now, we'll log a warning since file injection requires sandbox
        warn!(
            "File injection requested but sandbox not available. File injections: {:?}",
            sandbox_config.file_injections
        );
    }

    // Execute the command
    let output = cmd
        .output()
        .map_err(|e| format!("Command execution failed: {}", e))?;

    // Clean up injected files
    if let Some(mut manager) = injection_manager {
        let _ = manager.cleanup_all();
    }

    let exit_code = output.status.code().unwrap_or(-1);
    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();

    Ok(CommandExecutionResult {
        exit_code,
        stdout,
        stderr,
    })
}

#[allow(dead_code)]
impl DaemonServer {
    /// Get a reference to the protected secrets store
    pub fn protected_secrets(&self) -> &ProtectedSecrets {
        &self.secrets
    }

    /// Create a new daemon server
    pub fn new(
        socket_path: PathBuf,
        idle_timeout: Duration,
        vault_path: PathBuf,
        audit_logger: Arc<AuditLogger>,
        canary_manager: Arc<CanaryManager>,
        ci_mode: bool,
    ) -> Result<Self, sigil_core::SigilError> {
        Self::new_with_mode(
            socket_path,
            idle_timeout,
            vault_path,
            audit_logger,
            canary_manager,
            ci_mode,
            false,
        )
    }

    /// Create a new daemon server with explicit socket activation mode
    pub fn new_with_mode(
        socket_path: PathBuf,
        idle_timeout: Duration,
        vault_path: PathBuf,
        audit_logger: Arc<AuditLogger>,
        canary_manager: Arc<CanaryManager>,
        ci_mode: bool,
        systemd_mode: bool,
    ) -> Result<Self, sigil_core::SigilError> {
        // Ensure parent directory exists (only needed for non-systemd mode)
        if !systemd_mode {
            if let Some(parent) = socket_path.parent() {
                std::fs::create_dir_all(parent)
                    .map_err(|e| sigil_core::SigilError::IoError(e.to_string()))?;
            }

            // Remove stale socket if it exists
            if socket_path.exists() {
                std::fs::remove_file(&socket_path)
                    .map_err(|e| sigil_core::SigilError::IoError(e.to_string()))?;
            }
        }

        // Create protected secrets store (with mlock)
        let secrets = Arc::new(
            ProtectedSecrets::new().map_err(|e| sigil_core::SigilError::IoError(e.to_string()))?,
        );

        // Create output scrubber
        let scrubber = Arc::new(RwLock::new(Scrubber::new()));

        // Create signature matcher for auto-injection
        let signature_matcher = Arc::new(SignatureMatcher::new().map_err(|e| {
            sigil_core::SigilError::IoError(format!("Failed to create signature matcher: {}", e))
        })?);

        // Load operations from .sigil/operations.toml if it exists
        let operations = Self::load_operations(&vault_path).unwrap_or_default();

        // Load access grants from ~/.sigil/access-grants.toml if it exists
        let access_grants = Self::load_access_grants(&vault_path);

        // Load alert configuration from ~/.sigil/alerts.toml if it exists
        let alert_config = Self::load_alert_config(&vault_path).unwrap_or_default();
        let alert_sender = AlertSender::new(alert_config);

        // Load lockdown configuration from ~/.sigil/lockdown.toml if it exists
        let lockdown_config = Self::load_lockdown_config(&vault_path).unwrap_or_default();

        // Load or initialize lockdown state from ~/.sigil/lockdown-state.json
        let lockdown_state = Self::load_lockdown_state(&vault_path);
        let is_locked_down = lockdown_state.is_locked_down;

        // Create lease manager with default configuration
        let lease_config = LeaseConfig::new()
            .with_default_ttl(3600) // 1 hour default
            .with_max_ttl(86400) // 24 hours max
            .with_min_ttl(10) // 10 seconds min
            .with_auto_cleanup(true)
            .with_cleanup_interval(300); // 5 minutes
        let lease_manager = Arc::new(LeaseManager::new(lease_config));

        // Create proxy manager
        let proxy_manager = Arc::new(ProxyManager::new(audit_logger.clone()));

        Ok(Self {
            socket_path,
            idle_timeout,
            vault_path,
            audit_logger,
            sessions: Arc::new(RwLock::new(HashMap::new())),
            secrets,
            scrubber,
            signature_matcher,
            last_activity: Arc::new(Mutex::new(Instant::now())),
            shutdown_flag: Arc::new(RwLock::new(false)),
            lockdown_flag: Arc::new(RwLock::new(is_locked_down)),
            start_time: Instant::now(),
            canary_manager,
            operations: Arc::new(RwLock::new(operations)),
            access_grants: Arc::new(RwLock::new(access_grants)),
            alert_sender,
            ci_mode,
            systemd_mode,
            lockdown_config,
            lockdown_state: Arc::new(RwLock::new(lockdown_state)),
            lease_manager,
            proxy_manager,
        })
    }

    /// Load operations from .sigil/operations.toml
    fn load_operations(vault_path: &Path) -> Option<OperationsRegistry> {
        let operations_file = vault_path.parent()?.join("operations.toml");

        if !operations_file.exists() {
            return None;
        }

        let toml_content = std::fs::read_to_string(&operations_file).ok()?;
        OperationsRegistry::from_toml(&toml_content).ok()
    }

    /// Load access grants from ~/.sigil/access-grants.toml
    fn load_access_grants(vault_path: &Path) -> HashMap<String, Vec<AccessGrant>> {
        let grants_path = vault_path
            .parent()
            .and_then(|p| p.parent())
            .map(|p| p.join(".sigil/access-grants.toml"));

        let grants_path = match grants_path {
            Some(p) if p.exists() => p,
            _ => return HashMap::new(),
        };

        let toml_content = match std::fs::read_to_string(&grants_path) {
            Ok(content) => content,
            Err(e) => {
                warn!("Failed to read access-grants.toml: {}", e);
                return HashMap::new();
            }
        };

        let grant_file: GrantFile = match toml::from_str(&toml_content) {
            Ok(file) => file,
            Err(e) => {
                warn!("Failed to parse access-grants.toml: {}", e);
                return HashMap::new();
            }
        };

        let mut grants = HashMap::new();
        for serialized_grant in grant_file.grants {
            match AccessGrant::try_from(serialized_grant) {
                Ok(grant) => {
                    // For always-allow grants, use a special session token
                    // They will be linked to actual sessions on first access
                    let session_token = if grant.session_token.is_empty() {
                        "__always_allow__".to_string()
                    } else {
                        grant.session_token.clone()
                    };
                    grants
                        .entry(session_token)
                        .or_insert_with(Vec::new)
                        .push(grant);
                }
                Err(e) => {
                    warn!("Failed to deserialize grant: {}", e);
                }
            }
        }

        info!("Loaded {} grant entries from disk", grants.len());
        grants
    }

    /// Load alert configuration from ~/.sigil/alerts.toml if it exists
    fn load_alert_config(vault_path: &Path) -> Option<AlertConfig> {
        let alerts_path = vault_path
            .parent()
            .and_then(|p| p.parent())
            .map(|p| p.join(".sigil/alerts.toml"));

        let alerts_path = match alerts_path {
            Some(p) if p.exists() => p,
            _ => return None,
        };

        let toml_content = match std::fs::read_to_string(&alerts_path) {
            Ok(content) => content,
            Err(e) => {
                warn!("Failed to read alerts.toml: {}", e);
                return None;
            }
        };

        match toml::from_str(&toml_content) {
            Ok(config) => {
                info!("Loaded alert configuration from disk");
                Some(config)
            }
            Err(e) => {
                warn!("Failed to parse alerts.toml: {}", e);
                None
            }
        }
    }

    /// Load lockdown configuration from ~/.sigil/lockdown.toml
    fn load_lockdown_config(vault_path: &Path) -> Option<LockdownConfig> {
        let config_path = vault_path
            .parent()
            .and_then(|p| p.parent())
            .map(|p| p.join(".sigil/lockdown.toml"));

        let config_path = match config_path {
            Some(p) if p.exists() => p,
            _ => return Some(LockdownConfig::default()), // Use defaults if file doesn't exist
        };

        let toml_content = match std::fs::read_to_string(&config_path) {
            Ok(content) => content,
            Err(e) => {
                warn!("Failed to read lockdown.toml: {}", e);
                return Some(LockdownConfig::default());
            }
        };

        // Try nested format first [lockdown.auto], then flat format
        if let Ok(file_config) = toml::from_str::<LockdownConfigFile>(&toml_content) {
            if let Ok(config) = LockdownConfig::try_from(file_config) {
                info!("Loaded lockdown configuration from disk (nested format)");
                return Some(config);
            }
        }

        // Try flat format
        match toml::from_str(&toml_content) {
            Ok(config) => {
                info!("Loaded lockdown configuration from disk (flat format)");
                Some(config)
            }
            Err(e) => {
                warn!("Failed to parse lockdown.toml: {}, using defaults", e);
                Some(LockdownConfig::default())
            }
        }
    }

    /// Load lockdown state from ~/.sigil/lockdown-state.json
    fn load_lockdown_state(vault_path: &Path) -> LockdownState {
        let state_path = vault_path
            .parent()
            .and_then(|p| p.parent())
            .map(|p| p.join(".sigil/lockdown-state.json"));

        let state_path = match state_path {
            Some(p) if p.exists() => p,
            _ => return LockdownState::default(),
        };

        let json_content = match std::fs::read_to_string(&state_path) {
            Ok(content) => content,
            Err(e) => {
                warn!("Failed to read lockdown-state.json: {}", e);
                return LockdownState::default();
            }
        };

        match serde_json::from_str::<LockdownState>(&json_content) {
            Ok(state) => {
                info!(
                    "Loaded lockdown state from disk: is_locked_down={}",
                    state.is_locked_down
                );
                state
            }
            Err(e) => {
                warn!("Failed to parse lockdown-state.json: {}, using defaults", e);
                LockdownState::default()
            }
        }
    }

    /// Save lockdown state to ~/.sigil/lockdown-state.json
    async fn save_lockdown_state(&self) {
        let state_path = self
            .vault_path
            .parent()
            .and_then(|p| p.parent())
            .map(|p| p.join(".sigil/lockdown-state.json"));

        let state_path = match state_path {
            Some(p) => p,
            None => {
                warn!("Cannot determine lockdown state path");
                return;
            }
        };

        let state = self.lockdown_state.read().await;
        let json_content = match serde_json::to_string_pretty(&*state) {
            Ok(json) => json,
            Err(e) => {
                error!("Failed to serialize lockdown state: {}", e);
                return;
            }
        };
        drop(state);

        // Ensure parent directory exists
        if let Some(parent) = state_path.parent() {
            if let Err(e) = std::fs::create_dir_all(parent) {
                error!("Failed to create lockdown state directory: {}", e);
                return;
            }
        }

        if let Err(e) = std::fs::write(&state_path, json_content) {
            error!("Failed to write lockdown state: {}", e);
        } else {
            debug!("Saved lockdown state to disk");
        }
    }

    /// Check and trigger auto-lockdown based on config and current counters
    async fn check_auto_lockdown(&self, trigger_reason: &str) -> bool {
        let state = self.lockdown_state.read().await;
        let should_lockdown = state.should_trigger_lockdown(&self.lockdown_config);

        if should_lockdown {
            let reason = format!(
                "Auto-lockdown triggered: {} (canary_count={}, unauthorized_count={})",
                trigger_reason, state.canary_access_count, state.unauthorized_attempt_count
            );
            drop(state);

            warn!("{}", reason);
            info!("Executing auto-lockdown...");

            // Execute lockdown sequence
            match self.execute_lockdown().await {
                Ok(report) => {
                    info!("Auto-lockdown completed successfully");

                    // Log with the trigger reason
                    let mut final_report = report.clone();
                    final_report.errors.insert(0, reason);

                    // Send lockdown alert
                    if let Err(e) = self.send_alerts(&report).await {
                        error!("Failed to send lockdown alert: {}", e);
                    }

                    true
                }
                Err(e) => {
                    error!("Auto-lockdown failed: {}", e);
                    false
                }
            }
        } else {
            false
        }
    }

    /// Increment canary access counter and check for auto-lockdown
    async fn record_canary_access(&self) {
        let mut state = self.lockdown_state.write().await;
        state.increment_canary();
        drop(state);

        // Save state to disk
        self.save_lockdown_state().await;

        // Check if we should trigger auto-lockdown
        self.check_auto_lockdown("canary access threshold exceeded")
            .await;
    }

    /// Increment unauthorized attempt counter and check for auto-lockdown
    async fn record_unauthorized_attempt(&self) {
        let mut state = self.lockdown_state.write().await;
        state.increment_unauthorized();
        drop(state);

        // Save state to disk
        self.save_lockdown_state().await;

        // Check if we should trigger auto-lockdown
        self.check_auto_lockdown("unauthorized attempt threshold exceeded")
            .await;
    }

    /// Reset lockdown counters (called after successful lockdown)
    async fn reset_lockdown_counters(&self) {
        let mut state = self.lockdown_state.write().await;
        state.reset_counters();
        drop(state);

        // Save state to disk
        self.save_lockdown_state().await;
    }

    /// Start the server (blocking)
    pub async fn run(&self) -> Result<(), Box<dyn std::error::Error>> {
        // Create listener (using systemd socket activation if enabled)
        let listener = create_unix_listener(&self.socket_path, self.systemd_mode)
            .await
            .map_err(|e| format!("Failed to create listener: {}", e))?;

        info!("Daemon listening on {}", self.socket_path.display());

        // Set socket permissions to 0600 (only for non-systemd mode)
        // In systemd mode, the socket unit file controls permissions
        if !self.systemd_mode {
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let mut perms = std::fs::metadata(&self.socket_path)
                    .map_err(|e| format!("Failed to get socket metadata: {}", e))?
                    .permissions();
                perms.set_mode(0o600);
                std::fs::set_permissions(&self.socket_path, perms)
                    .map_err(|e| format!("Failed to set socket permissions: {}", e))?;
            }
        }

        // Spawn idle timeout checker
        let server = self.clone();
        tokio::spawn(async move {
            let mut check_interval = interval(Duration::from_secs(60));
            loop {
                check_interval.tick().await;

                let last_activity = *server.last_activity.lock().await;
                let idle_duration = last_activity.elapsed();

                if idle_duration > server.idle_timeout {
                    info!("Idle timeout reached, shutting down");
                    let mut flag = server.shutdown_flag.write().await;
                    *flag = true;
                    break;
                }

                // Clean up expired sessions
                server.cleanup_expired_sessions().await;
            }
        });

        // Accept connections
        loop {
            // Check shutdown flag
            {
                let flag = self.shutdown_flag.read().await;
                if *flag {
                    info!("Shutdown flag set, stopping server");
                    break;
                }
            }

            // Accept connection with timeout
            match timeout(Duration::from_secs(1), listener.accept()).await {
                Ok(Ok((stream, addr))) => {
                    debug!("New connection from {:?}", addr);
                    let server = self.clone();
                    tokio::spawn(async move {
                        if let Err(e) = server.handle_connection(stream).await {
                            error!("Error handling connection: {}", e);
                        }
                    });
                }
                Ok(Err(e)) => {
                    error!("Error accepting connection: {}", e);
                }
                Err(_) => {
                    // Timeout, continue loop to check shutdown flag
                }
            }
        }

        Ok(())
    }

    /// Handle a client connection
    async fn handle_connection(
        &self,
        mut stream: tokio::net::UnixStream,
    ) -> Result<(), Box<dyn std::error::Error>> {
        // Get peer credentials
        let peer_creds = get_peer_credentials(&stream)
            .map_err(|e| format!("Failed to get peer credentials: {}", e))?;

        debug!(
            "Connection from PID {} UID {} GID {}",
            peer_creds.pid, peer_creds.uid, peer_creds.gid
        );

        // Update last activity
        *self.last_activity.lock().await = Instant::now();

        // Handle requests
        loop {
            // Read request
            let request = match read_request_async(&mut stream).await {
                Ok(req) => req,
                Err(e) => {
                    error!("Error reading request: {}", e);
                    break;
                }
            };

            debug!("Received request: {:?}", request.op);

            // Update last activity
            *self.last_activity.lock().await = Instant::now();

            // Handle request
            let response = self.handle_request(request, peer_creds.clone()).await;

            // Write response
            if let Err(e) = write_response_async(&mut stream, &response).await {
                error!("Error writing response: {}", e);
                break;
            }

            // Check if this is a shutdown request
            if response.ok {
                if let Some(payload) = response.payload.as_object() {
                    if payload.contains_key("shutdown") {
                        info!("Shutdown request received");
                        // Set shutdown flag
                        let mut flag = self.shutdown_flag.write().await;
                        *flag = true;
                        break;
                    }
                }
            }
        }

        Ok(())
    }

    /// Handle a single request
    async fn handle_request(
        &self,
        request: IpcRequest,
        peer_creds: PeerCredentials,
    ) -> IpcResponse {
        // Validate session token
        let session_valid = self
            .validate_session_token(&request.token, &peer_creds)
            .await;

        if !session_valid {
            warn!(
                "Invalid session token from PID {} UID {}",
                peer_creds.pid, peer_creds.uid
            );
            self.audit_logger
                .log_auth_failure(
                    "invalid session token".to_string(),
                    peer_creds.pid,
                    peer_creds.uid,
                )
                .await;

            return IpcResponse::error(
                request.id,
                IpcError::new(
                    IpcErrorCode::InvalidToken,
                    "Session token is invalid or expired",
                ),
            );
        }

        // Update session activity
        self.update_session_activity(&request.token).await;

        // Route to handler
        match request.op {
            IpcOperation::Ping => self.handle_ping(request.id).await,
            IpcOperation::Status => self.handle_status(request.id).await,
            IpcOperation::Resolve => self.handle_resolve(request.id, request.payload).await,
            IpcOperation::Scrub => self.handle_scrub(request.id, request.payload).await,
            IpcOperation::Exec => self.handle_exec(request.id, request.payload).await,
            IpcOperation::SessionStart => self.handle_session_start(request.id, peer_creds).await,
            IpcOperation::SessionEnd => self.handle_session_end(request.id).await,
            IpcOperation::FuseRead => self.handle_fuse_read(request.id, request.payload).await,
            IpcOperation::ListOperations => self.handle_list_operations(request.id).await,
            IpcOperation::ExecuteOperation => {
                self.handle_execute_operation(request.id, request.payload)
                    .await
            }
            IpcOperation::Lockdown => self.handle_lockdown(request.id).await,
            IpcOperation::Unlock => self.handle_unlock(request.id, request.payload).await,
            IpcOperation::RequestAccess => {
                self.handle_request_access(request.id, request.payload, request.token.clone())
                    .await
            }
            IpcOperation::CheckAccess => {
                self.handle_check_access(request.id, request.payload, request.token.clone())
                    .await
            }
            IpcOperation::BreachReport => self.handle_breach_report(request.id).await,
            IpcOperation::ListSessions => self.handle_list_sessions(request.id).await,
            IpcOperation::KillSession => {
                self.handle_kill_session(request.id, request.payload).await
            }
            IpcOperation::LeaseGrant => self.handle_lease_grant(request.id, request.payload).await,
            IpcOperation::LeaseRevoke => {
                self.handle_lease_revoke(request.id, request.payload).await
            }
            IpcOperation::LeaseList => self.handle_lease_list(request.id).await,
            IpcOperation::LeaseStats => self.handle_lease_stats(request.id).await,
            _ => IpcResponse::error(
                request.id,
                IpcError::new(IpcErrorCode::UnknownOp, "Operation not implemented yet"),
            ),
        }
    }

    /// Validate session token
    async fn validate_session_token(&self, token: &str, peer_creds: &PeerCredentials) -> bool {
        let sessions = self.sessions.read().await;
        if let Some(session) = sessions.get(token) {
            // Check if peer credentials match
            session.peer.pid == peer_creds.pid && session.peer.uid == peer_creds.uid
        } else {
            false
        }
    }

    /// Update session activity
    async fn update_session_activity(&self, token: &str) {
        let mut sessions = self.sessions.write().await;
        if let Some(session) = sessions.get_mut(token) {
            session.update_activity();
        }
    }

    /// Clean up expired sessions
    async fn cleanup_expired_sessions(&self) {
        let mut sessions = self.sessions.write().await;
        let timeout = chrono::Duration::seconds(self.idle_timeout.as_secs() as i64);

        sessions.retain(|_, session| !session.is_idle_longer_than(timeout));
    }

    /// Handle ping request
    async fn handle_ping(&self, request_id: String) -> IpcResponse {
        let ping = PingResponse {
            alive: true,
            server_time: chrono::Utc::now(),
            protocol_version: sigil_core::PROTOCOL_VERSION,
        };

        IpcResponse::with_payload(
            request_id,
            serde_json::to_value(ping).unwrap_or(serde_json::json!({})),
        )
    }

    /// Handle status request
    async fn handle_status(&self, request_id: String) -> IpcResponse {
        let secrets = self.secrets.inner().read().await;
        let sessions = self.sessions.read().await;

        let status = DaemonStatus {
            version: env!("CARGO_PKG_VERSION").to_string(),
            unlocked: true,
            secret_count: secrets.len(),
            session_count: sessions.len(),
            uptime_secs: self.start_time.elapsed().as_secs(),
            idle_timeout_secs: if self.idle_timeout.as_secs() == u64::MAX {
                None
            } else {
                Some(self.idle_timeout.as_secs())
            },
            backend_type: "local".to_string(),
            socket_path: self.socket_path.clone(),
        };

        IpcResponse::with_payload(
            request_id,
            serde_json::to_value(status).unwrap_or(serde_json::json!({})),
        )
    }

    /// Handle resolve request
    async fn handle_resolve(&self, request_id: String, payload: serde_json::Value) -> IpcResponse {
        let resolve_req: ResolveRequest = match serde_json::from_value(payload) {
            Ok(req) => req,
            Err(e) => {
                return IpcResponse::error(
                    request_id,
                    IpcError::new(
                        IpcErrorCode::InvalidRequest,
                        format!("Invalid resolve request: {}", e),
                    ),
                );
            }
        };

        let secrets = self.secrets.inner().read().await;
        let mut values = HashMap::new();

        for path in resolve_req.paths {
            if let Some(value) = secrets.get(&path) {
                // Return base64-encoded value
                use base64::prelude::*;
                values.insert(path, BASE64_STANDARD.encode(value));
            }
        }

        let resolve_response = ResolveResponse { values };

        IpcResponse::with_payload(
            request_id,
            serde_json::to_value(resolve_response).unwrap_or(serde_json::json!({})),
        )
    }

    /// Handle scrub request
    async fn handle_scrub(&self, request_id: String, payload: serde_json::Value) -> IpcResponse {
        let scrub_req: ScrubRequest = match serde_json::from_value(payload) {
            Ok(req) => req,
            Err(e) => {
                return IpcResponse::error(
                    request_id,
                    IpcError::new(
                        IpcErrorCode::InvalidRequest,
                        format!("Invalid scrub request: {}", e),
                    ),
                );
            }
        };

        // Use the Aho-Corasick scrubber to detect and redact secrets
        let mut scrubber = self.scrubber.write().await;
        let result = scrubber.scrub_with_stats(&scrub_req.output);

        let scrub_response = ScrubResponse {
            output: result.scrubbed,
            count: result.secrets_detected,
        };

        IpcResponse::with_payload(
            request_id,
            serde_json::to_value(scrub_response).unwrap_or(serde_json::json!({})),
        )
    }

    /// Handle exec request - transparent command execution with signature-based auto-injection
    ///
    /// This method integrates sandboxing for secure command execution. It:
    /// 1. Matches commands against signatures to find auto-injections
    /// 2. Collects environment variable and file injections
    /// 3. Uses bubblewrap sandbox for isolation (Linux) or direct execution (fallback)
    /// 4. Scrubs output to prevent secret leakage
    /// 5. Logs all executions to the audit log
    async fn handle_exec(&self, request_id: String, payload: serde_json::Value) -> IpcResponse {
        let exec_req: ExecRequest = match serde_json::from_value(payload) {
            Ok(req) => req,
            Err(e) => {
                return IpcResponse::error(
                    request_id,
                    IpcError::new(
                        IpcErrorCode::InvalidRequest,
                        format!("Invalid exec request: {}", e),
                    ),
                );
            }
        };

        let start_time = Instant::now();
        let full_command = if exec_req.args.is_empty() {
            exec_req.command.clone()
        } else {
            format!("{} {}", exec_req.command, exec_req.args.join(" "))
        };

        debug!("Executing command: {}", full_command);

        // Match command against signatures to find auto-injections
        let matched_signatures = self.signature_matcher.match_command(&full_command);
        let signature_names: Vec<String> = matched_signatures
            .iter()
            .map(|m| m.signature_name.clone())
            .collect();

        if !signature_names.is_empty() {
            debug!(
                "Command matched {} signatures: {:?}",
                signature_names.len(),
                signature_names
            );
        }

        // Collect secrets and injections
        let mut env_vars_to_inject: Vec<(String, String)> = Vec::new();
        let mut file_injections: Vec<(String, PathBuf)> = Vec::new();
        let secrets = self.secrets.inner().read().await;

        for matched_sig in &matched_signatures {
            for injection in &matched_sig.injections {
                if let Some(secret_value) = secrets.get(injection.secret_path.as_str()) {
                    match &injection.injection_type {
                        InjectionType::Env(name) => {
                            // Convert Vec<u8> to String for environment variable
                            let value_str = String::from_utf8_lossy(secret_value).to_string();
                            env_vars_to_inject.push((name.clone(), value_str));
                            debug!("Injecting env var: {}", name);
                        }
                        InjectionType::File(path) => {
                            // File injection - will be handled by sandbox
                            // We'll pass the secret path and target path to the sandbox config
                            file_injections
                                .push((injection.secret_path.as_str().to_string(), path.clone()));
                            debug!(
                                "File injection planned: {:?} -> {:?}",
                                injection.secret_path.as_str(),
                                path
                            );
                        }
                        InjectionType::Header(name, _format) => {
                            // Header injection - for curl/httpie commands
                            // We'll inject this as an env var and let the command use it
                            let value_str = String::from_utf8_lossy(secret_value).to_string();
                            // Use the header name as the env var name
                            env_vars_to_inject.push((name.clone(), value_str));
                            debug!("Header injection for {:?} - treating as env var", name);
                        }
                    }
                } else if !injection.optional {
                    warn!(
                        "Required secret '{}' not found for injection",
                        injection.secret_path
                    );
                }
            }
        }

        // Create sandbox config
        let mut sandbox_config = if let Some(ref project_dir) = exec_req.project_dir {
            let project_path = PathBuf::from(project_dir);
            if project_path.exists() {
                debug!("Using project directory: {:?}", project_dir);
                SandboxConfig::with_project_dir(project_path)
            } else {
                SandboxConfig::default()
            }
        } else {
            SandboxConfig::default()
        };

        // Add environment variables
        for (key, value) in &env_vars_to_inject {
            sandbox_config = sandbox_config.with_env(key.clone(), value.clone());
        }

        // Add file injections (secret_path -> target_path)
        for (secret_path, target_path) in &file_injections {
            sandbox_config =
                sandbox_config.with_file_injection(secret_path.clone(), target_path.clone());
        }

        // Set working directory if provided
        if let Some(ref wd) = exec_req.working_dir {
            sandbox_config = sandbox_config.with_working_dir(PathBuf::from(wd));
        }

        // Set network isolation
        sandbox_config = sandbox_config.with_network_isolation(exec_req.network_isolated);

        // Try to use sandbox if available
        let use_sandbox = BubblewrapSandbox::new()
            .map(|s| s.is_available())
            .unwrap_or(false);

        if !use_sandbox {
            debug!("Bubblewrap not available, using direct execution (sandboxing disabled)");
        }

        // Execute the command (sandboxed or direct)
        let duration = Duration::from_secs(exec_req.timeout_secs);

        // We need to move the data into the blocking task
        let command = exec_req.command.clone();
        let args = exec_req.args.clone();
        let sandbox_config_for_task = sandbox_config.clone();

        let (exit_code, stdout_raw, stderr_raw, timed_out) = if exec_req.timeout_secs > 0 {
            // With timeout
            match timeout(
                duration,
                tokio::task::spawn_blocking(move || {
                    execute_command_sandboxed(command, args, sandbox_config_for_task, use_sandbox)
                }),
            )
            .await
            {
                Ok(Ok(Ok(result))) => (result.exit_code, result.stdout, result.stderr, false),
                Ok(Ok(Err(e))) => {
                    error!("Failed to execute command: {}", e);
                    (
                        -1,
                        String::new(),
                        format!("Command execution failed: {}", e),
                        false,
                    )
                }
                Ok(Err(e)) => {
                    error!("Spawn blocking failed: {:?}", e);
                    (
                        -1,
                        String::new(),
                        format!("Spawn blocking failed: {:?}", e),
                        false,
                    )
                }
                Err(_) => {
                    warn!(
                        "Command execution timed out after {} seconds",
                        exec_req.timeout_secs
                    );
                    (-1, String::new(), "Command timed out".to_string(), true)
                }
            }
        } else {
            // Without timeout - just await the spawn_blocking
            match tokio::task::spawn_blocking(move || {
                execute_command_sandboxed(command, args, sandbox_config_for_task, use_sandbox)
            })
            .await
            {
                Ok(Ok(result)) => (result.exit_code, result.stdout, result.stderr, false),
                Ok(Err(e)) => {
                    error!("Failed to execute command: {}", e);
                    (
                        -1,
                        String::new(),
                        format!("Command execution failed: {}", e),
                        false,
                    )
                }
                Err(e) => {
                    error!("Spawn blocking failed: {:?}", e);
                    (
                        -1,
                        String::new(),
                        format!("Spawn blocking failed: {:?}", e),
                        false,
                    )
                }
            }
        };

        // Scrub the output
        let mut scrubber = self.scrubber.write().await;
        let stdout_scrubbed = scrubber.scrub_with_stats(&stdout_raw);
        let stderr_scrubbed = scrubber.scrub_with_stats(&stderr_raw);
        let total_scrubbed = stdout_scrubbed.secrets_detected + stderr_scrubbed.secrets_detected;

        let duration_ms = start_time.elapsed().as_millis() as u64;

        debug!(
            "Command completed: exit_code={}, duration={}ms, secrets_scrubbed={}, sandboxed={}",
            exit_code, duration_ms, total_scrubbed, use_sandbox
        );

        // Log the execution in the audit log
        self.audit_logger
            .log_command_execution(
                full_command,
                exit_code,
                duration_ms,
                signature_names.clone(),
                total_scrubbed,
            )
            .await;

        let exec_response = ExecResponse {
            exit_code,
            stdout: stdout_scrubbed.scrubbed,
            stderr: stderr_scrubbed.scrubbed,
            timed_out,
            duration_ms,
            secrets_scrubbed: total_scrubbed,
            matched_signatures: signature_names,
        };

        IpcResponse::with_payload(
            request_id,
            serde_json::to_value(exec_response).unwrap_or(serde_json::json!({})),
        )
    }

    /// Handle session start request
    async fn handle_session_start(
        &self,
        request_id: String,
        peer_creds: PeerCredentials,
    ) -> IpcResponse {
        let token = SessionToken::generate();
        let session = SessionInfo::new(token.clone(), peer_creds);

        let mut sessions = self.sessions.write().await;
        sessions.insert(token.to_base64(), session);

        IpcResponse::with_payload(
            request_id,
            serde_json::json!({ "token": token.to_base64() }),
        )
    }

    /// Handle session end request
    async fn handle_session_end(&self, request_id: String) -> IpcResponse {
        // For now, just return success
        // Actual session cleanup happens via timeout
        IpcResponse::ok(request_id)
    }

    /// Handle lockdown request
    async fn handle_lockdown(&self, request_id: String) -> IpcResponse {
        info!("Lockdown requested");

        // Execute full lockdown sequence
        match self.execute_lockdown().await {
            Ok(report) => {
                info!("Lockdown completed successfully");
                IpcResponse::with_payload(
                    request_id,
                    serde_json::to_value(report).unwrap_or(serde_json::json!({})),
                )
            }
            Err(e) => {
                error!("Lockdown failed: {}", e);
                IpcResponse::error(
                    request_id,
                    IpcError::new(
                        IpcErrorCode::InternalError,
                        format!("Lockdown failed: {}", e),
                    ),
                )
            }
        }
    }

    /// Handle unlock request
    async fn handle_unlock(&self, request_id: String, payload: serde_json::Value) -> IpcResponse {
        info!("Unlock requested");

        // Parse the unlock request
        let unlock_req: sigil_core::ipc::UnlockRequest = match serde_json::from_value(payload) {
            Ok(req) => req,
            Err(e) => {
                error!("Failed to parse unlock request: {}", e);
                return IpcResponse::error(
                    request_id,
                    IpcError::new(
                        IpcErrorCode::InvalidRequest,
                        format!("Invalid unlock request: {}", e),
                    ),
                );
            }
        };

        // Verify the passphrase by attempting to unseal the vault
        // This provides authentication for the unlock operation
        match self.verify_passphrase(&unlock_req.passphrase).await {
            Ok(true) => {
                // Clear the lockdown flag
                {
                    let mut flag = self.lockdown_flag.write().await;
                    *flag = false;
                }

                // Update and persist lockdown state
                {
                    let mut state = self.lockdown_state.write().await;
                    state.is_locked_down = false;
                    state.locked_down_at = None;
                    drop(state);

                    // Save to disk
                    self.save_lockdown_state().await;
                }

                // Log the unlock event
                if let Err(e) = self.audit_logger.log_unlock().await {
                    error!("Failed to log unlock event: {}", e);
                }

                info!("Daemon unlocked successfully");
                IpcResponse::ok(request_id)
            }
            Ok(false) => {
                warn!("Unlock failed: invalid passphrase");
                IpcResponse::error(
                    request_id,
                    IpcError::new(IpcErrorCode::AccessDenied, "Invalid passphrase"),
                )
            }
            Err(e) => {
                error!("Unlock failed: {}", e);
                IpcResponse::error(
                    request_id,
                    IpcError::new(IpcErrorCode::InternalError, format!("Unlock failed: {}", e)),
                )
            }
        }
    }

    /// Verify a passphrase against the vault
    async fn verify_passphrase(
        &self,
        passphrase: &str,
    ) -> Result<bool, Box<dyn std::error::Error + Send + Sync>> {
        use sigil_vault::LocalVault;

        // Create a LocalVault instance pointing to the vault path
        let identity_path = self.vault_path.join("identity.age");
        let mut vault = LocalVault::new(self.vault_path.clone(), identity_path)?;

        // Try to load the vault with the provided passphrase
        match vault.load(Some(passphrase)) {
            Ok(()) => Ok(true),
            Err(_) => Ok(false),
        }
    }

    /// Handle request access - for TUI approval workflow
    async fn handle_request_access(
        &self,
        request_id: String,
        payload: serde_json::Value,
        session_token: String,
    ) -> IpcResponse {
        info!("Request access invoked");

        // Parse the request
        let req_payload: sigil_core::ipc::RequestAccessPayload =
            match serde_json::from_value(payload) {
                Ok(req) => req,
                Err(e) => {
                    error!("Failed to parse request access payload: {}", e);
                    return IpcResponse::error(
                        request_id,
                        IpcError::new(
                            IpcErrorCode::InvalidRequest,
                            format!("Invalid request access payload: {}", e),
                        ),
                    );
                }
            };

        info!(
            "Access request: secret={}, duration={}, reason={}",
            req_payload.secret, req_payload.duration, req_payload.reason
        );

        // Check for existing "always allow" grant
        let agent_id = req_payload
            .agent_id
            .clone()
            .unwrap_or_else(|| "unknown".to_string());
        if let Some(_always_grant) = self
            .check_always_allow_grant(&agent_id, &req_payload.secret)
            .await
        {
            info!(
                "Access granted via existing always-allow grant: {}",
                req_payload.secret
            );

            // Create grant from always-allow
            let grant = AccessGrant::new(
                req_payload.secret.clone(),
                session_token.clone(),
                "always",
                req_payload.reason.clone(),
                req_payload.agent_id.clone(),
            );

            // Store the grant
            {
                let mut grants = self.access_grants.write().await;
                grants
                    .entry(session_token.clone())
                    .or_insert_with(Vec::new)
                    .push(grant.clone());
            }

            // Log the access grant
            if let Err(e) = self
                .audit_logger
                .log_secret_access_grant(
                    req_payload.secret.clone(),
                    req_payload.reason.clone(),
                    grant.expires_at,
                )
                .await
            {
                error!("Failed to log access grant: {}", e);
            }

            return IpcResponse::with_payload(
                request_id,
                serde_json::to_value(sigil_core::ipc::RequestAccessResponse {
                    granted: true,
                    message: format!(
                        "Access granted to '{}' (via always-allow)",
                        req_payload.secret
                    ),
                    expires_at: grant.expires_at,
                    grant_id: Some(grant.id),
                })
                .unwrap_or(serde_json::json!({})),
            );
        }

        // Create the approval request for TUI
        let approval_request = ApprovalRequest {
            agent_id: agent_id.clone(),
            secret_path: req_payload.secret.clone(),
            reason: req_payload.reason.clone(),
            working_dir: std::env::current_dir()
                .ok()
                .and_then(|p| p.to_str().map(|s| s.to_string())),
            requested_duration: req_payload.duration.clone(),
        };

        // Show TUI approval prompt (or auto-approve in CI mode)
        let decision = if self.ci_mode {
            // Auto-approve in CI mode (session-scoped approval)
            info!(
                "CI mode: auto-approving access request for '{}'",
                req_payload.secret
            );
            ApprovalDecision::ApproveSession
        } else {
            match ApprovalPrompt::approve(approval_request) {
                Ok(Some(d)) => d,
                Ok(None) => {
                    // User cancelled (treated as deny)
                    info!("Access request cancelled by user: {}", req_payload.secret);

                    // Log the denial
                    if let Err(e) = self
                        .audit_logger
                        .log_secret_access_denied(
                            req_payload.secret.clone(),
                            req_payload.reason.clone(),
                            Some("User cancelled".to_string()),
                        )
                        .await
                    {
                        error!("Failed to log access denial: {}", e);
                    }

                    return IpcResponse::with_payload(
                        request_id,
                        serde_json::to_value(sigil_core::ipc::RequestAccessResponse {
                            granted: false,
                            message: "Access request cancelled by user".to_string(),
                            expires_at: None,
                            grant_id: None,
                        })
                        .unwrap_or(serde_json::json!({})),
                    );
                }
                Err(e) => {
                    error!("TUI approval prompt error: {}", e);
                    // On error, deny for safety
                    return IpcResponse::error(
                        request_id,
                        IpcError::new(
                            IpcErrorCode::InternalError,
                            format!("Approval prompt error: {}", e),
                        ),
                    );
                }
            }
        };

        info!("Decision: {:?}", decision);

        // Handle lockdown decision (Ctrl+L in approval prompt)
        if decision.is_lockdown() {
            warn!("Emergency lockdown triggered from approval prompt (Ctrl+L)");
            info!("Executing emergency lockdown...");

            // Execute lockdown sequence
            match self.execute_lockdown().await {
                Ok(report) => {
                    info!("Emergency lockdown completed successfully");

                    // Send lockdown alert
                    if let Err(e) = self.send_alerts(&report).await {
                        error!("Failed to send lockdown alert: {}", e);
                    }

                    // Return error response to agent
                    return IpcResponse::error(
                        request_id,
                        IpcError::new(
                            IpcErrorCode::AccessDenied,
                            "Emergency lockdown triggered - daemon locked".to_string(),
                        ),
                    );
                }
                Err(e) => {
                    error!("Emergency lockdown failed: {}", e);
                    // Still deny access even if lockdown failed
                    return IpcResponse::error(
                        request_id,
                        IpcError::new(
                            IpcErrorCode::InternalError,
                            format!("Lockdown failed: {}", e),
                        ),
                    );
                }
            }
        }

        // Handle the decision
        if !decision.is_approval() {
            // Deny or Deny + Flag
            let message = if decision.is_suspicious() {
                format!("Access denied and flagged: {}", req_payload.secret)
            } else {
                format!("Access denied: {}", req_payload.secret)
            };

            // Log the denial
            if let Err(e) = self
                .audit_logger
                .log_secret_access_denied(
                    req_payload.secret.clone(),
                    req_payload.reason.clone(),
                    if decision.is_suspicious() {
                        Some("Flagged as suspicious".to_string())
                    } else {
                        None
                    },
                )
                .await
            {
                error!("Failed to log access denial: {}", e);
            }

            return IpcResponse::with_payload(
                request_id,
                serde_json::to_value(sigil_core::ipc::RequestAccessResponse {
                    granted: false,
                    message,
                    expires_at: None,
                    grant_id: None,
                })
                .unwrap_or(serde_json::json!({})),
            );
        }

        // Approved - create the grant
        let duration = decision.duration().unwrap_or(&req_payload.duration);
        let grant = AccessGrant::new(
            req_payload.secret.clone(),
            session_token.clone(),
            duration,
            req_payload.reason.clone(),
            req_payload.agent_id.clone(),
        );

        // Store the grant
        {
            let mut grants = self.access_grants.write().await;
            grants
                .entry(session_token.clone())
                .or_insert_with(Vec::new)
                .push(grant.clone());
        }

        // If "always allow", persist to disk
        if decision == ApprovalDecision::AlwaysAllow {
            if let Err(e) = self
                .save_always_allow_grant(&agent_id, &req_payload.secret)
                .await
            {
                error!("Failed to save always-allow grant: {}", e);
            }
        }

        // Log the access grant
        if let Err(e) = self
            .audit_logger
            .log_secret_access_grant(
                req_payload.secret.clone(),
                req_payload.reason.clone(),
                grant.expires_at,
            )
            .await
        {
            error!("Failed to log access grant: {}", e);
        }

        info!(
            "Access granted: {} until {:?}",
            grant.secret_path, grant.expires_at
        );

        IpcResponse::with_payload(
            request_id,
            serde_json::to_value(sigil_core::ipc::RequestAccessResponse {
                granted: true,
                message: format!("Access granted to '{}'", req_payload.secret),
                expires_at: grant.expires_at,
                grant_id: Some(grant.id),
            })
            .unwrap_or(serde_json::json!({})),
        )
    }

    /// Check if there's an existing "always allow" grant for this agent/secret combination
    async fn check_always_allow_grant(&self, agent_id: &str, secret_path: &str) -> Option<bool> {
        // Check all grants for a matching agent_id and secret_path with "always" duration
        let grants = self.access_grants.read().await;
        for (_session_token, grant_list) in grants.iter() {
            for grant in grant_list {
                // Check if this is an "always allow" grant
                if let Some(grant_agent_id) = &grant.agent_id {
                    if grant_agent_id == agent_id && grant.secret_path == secret_path {
                        // Check if expires_at is None (session-scoped) or far in future
                        if grant.expires_at.is_none()
                            || grant
                                .expires_at
                                .map(|e| e > chrono::Utc::now() + chrono::Duration::days(365))
                                .unwrap_or(false)
                        {
                            return Some(true);
                        }
                    }
                }
            }
        }
        None
    }

    /// Save an "always allow" grant to disk
    async fn save_always_allow_grant(
        &self,
        agent_id: &str,
        secret_path: &str,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let grants_path = self.vault_path.join("../access-grants.toml");

        // Load existing grants file or create new
        let mut grant_file = if grants_path.exists() {
            let content = std::fs::read_to_string(&grants_path)?;
            toml::from_str::<GrantFile>(&content).unwrap_or_else(|_| GrantFile {
                version: 1,
                grants: Vec::new(),
            })
        } else {
            GrantFile {
                version: 1,
                grants: Vec::new(),
            }
        };

        // Check if this grant already exists
        let grant_exists = grant_file.grants.iter().any(|g| {
            g.agent_id
                .as_ref()
                .map(|id| id == agent_id)
                .unwrap_or(false)
                && g.secret_path == secret_path
                && (g.expires_at.is_none()
                    || g.expires_at.as_ref().map(|e| e.len() > 20).unwrap_or(false))
        });

        if !grant_exists {
            // For "always allow" grants, we create a persistent entry
            // The actual session_token will be set when loaded
            let now = chrono::Utc::now();
            let serialized = SerializedGrant {
                id: format!("grant_{:?}_{}", agent_id, secret_path.replace('/', "_")),
                secret_path: secret_path.to_string(),
                session_token: String::new(), // Will be set on load
                created_at: now.to_rfc3339(),
                expires_at: None, // Never expires for "always allow"
                reason: "Always allow by user".to_string(),
                agent_id: Some(agent_id.to_string()),
            };
            grant_file.grants.push(serialized);

            // Write back to disk
            let toml_str = toml::to_string_pretty(&grant_file)?;
            std::fs::write(&grants_path, toml_str)?;
            info!(
                "Saved always-allow grant for {} to access-grants.toml",
                agent_id
            );
        }

        Ok(())
    }

    /// Handle check access - check if access is granted to a secret
    async fn handle_check_access(
        &self,
        request_id: String,
        payload: serde_json::Value,
        session_token: String,
    ) -> IpcResponse {
        info!("Check access invoked");

        // Parse the request
        let check_payload: sigil_core::ipc::CheckAccessPayload =
            match serde_json::from_value(payload) {
                Ok(req) => req,
                Err(e) => {
                    error!("Failed to parse check access payload: {}", e);
                    return IpcResponse::error(
                        request_id,
                        IpcError::new(
                            IpcErrorCode::InvalidRequest,
                            format!("Invalid check access payload: {}", e),
                        ),
                    );
                }
            };

        // Clean up expired grants first
        self.cleanup_expired_grants().await;

        // Check for a valid grant
        let grants = self.access_grants.read().await;
        let session_grants = grants.get(&session_token);

        let result = if let Some(grant_list) = session_grants {
            // Find a matching grant for this secret
            grant_list
                .iter()
                .find(|g| g.secret_path == check_payload.secret && !g.is_expired())
                .map(|grant| sigil_core::ipc::CheckAccessResponse {
                    granted: true,
                    status: format!("Access granted to '{}'", check_payload.secret),
                    expires_in: grant.remaining_seconds(),
                })
        } else {
            None
        };

        match result {
            Some(response) => {
                info!(
                    "Access check: granted to '{}', expires in {:?}",
                    check_payload.secret, response.expires_in
                );
                IpcResponse::with_payload(
                    request_id,
                    serde_json::to_value(response).unwrap_or(serde_json::json!({})),
                )
            }
            None => {
                info!("Access check: not granted to '{}'", check_payload.secret);
                IpcResponse::with_payload(
                    request_id,
                    serde_json::to_value(sigil_core::ipc::CheckAccessResponse {
                        granted: false,
                        status: format!("Access not granted to '{}'", check_payload.secret),
                        expires_in: None,
                    })
                    .unwrap_or(serde_json::json!({})),
                )
            }
        }
    }

    /// Clean up expired access grants
    async fn cleanup_expired_grants(&self) {
        let mut grants = self.access_grants.write().await;
        for (_, grant_list) in grants.iter_mut() {
            grant_list.retain(|g| !g.is_expired());
        }
    }

    /// Execute the full lockdown sequence
    ///
    /// This implements emergency incident response:
    /// 1. Kill all active sandbox processes (SIGTERM → 500ms → SIGKILL)
    /// 2. Revoke all session tokens
    /// 3. Revoke all dynamic leases (Vault/OpenBao API calls)
    /// 4. Lock the vault (zeroize all secrets)
    /// 5. Generate breach report
    /// 6. Send alerts to configured channels
    async fn execute_lockdown(
        &self,
    ) -> Result<LockdownReport, Box<dyn std::error::Error + Send + Sync>> {
        let mut report = LockdownReport::new();

        // 1. Kill sandbox processes
        info!("Step 1: Killing sandbox processes");
        match self.kill_sandbox_processes().await {
            Ok(killed) => {
                report.sandboxes_killed = killed;
                info!("Killed {} sandbox processes", killed);
            }
            Err(e) => {
                warn!("Failed to kill sandbox processes: {}", e);
                report
                    .errors
                    .push(format!("Failed to kill sandboxes: {}", e));
            }
        }

        // 2. Revoke all session tokens
        info!("Step 2: Revoking session tokens");
        match self.revoke_all_sessions().await {
            Ok(revoked) => {
                report.sessions_revoked = revoked;
                info!("Revoked {} session tokens", revoked);
            }
            Err(e) => {
                warn!("Failed to revoke sessions: {}", e);
                report
                    .errors
                    .push(format!("Failed to revoke sessions: {}", e));
            }
        }

        // 3. Revoke dynamic leases
        info!("Step 3: Revoking dynamic leases");
        match self.revoke_dynamic_leases().await {
            Ok(leases) => {
                report.leases_revoked = leases;
                info!("Revoked {} dynamic leases", leases);
            }
            Err(e) => {
                warn!("Failed to revoke leases: {}", e);
                report
                    .errors
                    .push(format!("Failed to revoke leases: {}", e));
            }
        }

        // 4. Lock the vault (zeroize all secrets)
        info!("Step 4: Locking vault");
        match self.lock_vault().await {
            Ok(_) => {
                report.vault_locked = true;
                info!("Vault locked (secrets zeroized)");
            }
            Err(e) => {
                error!("Failed to lock vault: {}", e);
                report.errors.push(format!("Failed to lock vault: {}", e));
            }
        }

        // 5. Clear scrubber
        info!("Step 5: Clearing scrubber");
        self.clear_scrubber().await;
        info!("Scrubber cleared");

        // 6. Generate breach report
        info!("Step 6: Generating breach report");
        self.generate_breach_report(&report).await;

        // 7. Send alerts
        info!("Step 7: Sending alerts");
        match self.send_alerts(&report).await {
            Ok(alerts_sent) => {
                report.alerts_sent = alerts_sent;
                info!("Sent {} alerts", alerts_sent);
            }
            Err(e) => {
                warn!("Failed to send alerts: {}", e);
                report.errors.push(format!("Failed to send alerts: {}", e));
            }
        }

        // Set lockdown flag
        {
            let mut flag = self.lockdown_flag.write().await;
            *flag = true;
        }

        // Update and persist lockdown state
        {
            let mut state = self.lockdown_state.write().await;
            state.is_locked_down = true;
            state.locked_down_at = Some(chrono::Utc::now().to_rfc3339());
            // Reset counters after lockdown
            state.reset_counters();
            drop(state);

            // Save to disk
            self.save_lockdown_state().await;
        }

        // Log the lockdown event
        if let Err(e) = self.audit_logger.log_lockdown().await {
            error!("Failed to log lockdown event: {}", e);
            report.errors.push(format!("Failed to log lockdown: {}", e));
        }

        report.timestamp = Some(chrono::Utc::now());
        Ok(report)
    }

    /// Kill all active sandbox processes
    async fn kill_sandbox_processes(&self) -> Result<usize, Box<dyn std::error::Error>> {
        #[cfg(unix)]
        {
            use std::fs;

            // Find all sandbox processes by reading /proc
            let mut sandbox_pids = Vec::new();

            if let Ok(entries) = fs::read_dir("/proc") {
                for entry in entries.flatten() {
                    let pid_str = entry.file_name();
                    if let Ok(pid) = pid_str.to_string_lossy().parse::<u32>() {
                        // Check if this process is a sandbox
                        let cmdline_path = format!("/proc/{}/cmdline", pid);
                        if let Ok(cmdline) = fs::read_to_string(&cmdline_path) {
                            // Check for sigil-sandbox or bwrap with SIGIL markers
                            let is_sandbox = cmdline.contains("sigil-sandbox")
                                || (cmdline.contains("bwrap")
                                    && cmdline.contains("--unshare-pid")
                                    && cmdline.contains("--proc"));

                            if is_sandbox {
                                sandbox_pids.push(pid);
                            }
                        }
                    }
                }
            }

            if !sandbox_pids.is_empty() {
                info!(
                    "Found {} sandbox processes to terminate",
                    sandbox_pids.len()
                );
                let mut killed = 0;

                // Send SIGTERM to all sandbox processes using libc
                for pid in &sandbox_pids {
                    unsafe {
                        if libc::kill(*pid as i32, libc::SIGTERM) == 0 {
                            info!("Sent SIGTERM to sandbox PID {}", pid);
                            killed += 1;
                        } else {
                            let err = std::io::Error::last_os_error();
                            warn!("Failed to send SIGTERM to PID {}: {}", pid, err);
                        }
                    }
                }

                // Wait 500ms for graceful shutdown
                tokio::time::sleep(Duration::from_millis(500)).await;

                // Send SIGKILL to any remaining sandbox processes
                for pid in &sandbox_pids {
                    // Check if process still exists
                    let proc_exists = fs::metadata(format!("/proc/{}", pid)).is_ok();
                    if proc_exists {
                        warn!("Sandbox PID {} still alive, sending SIGKILL", pid);
                        unsafe {
                            if libc::kill(*pid as i32, libc::SIGKILL) != 0 {
                                let err = std::io::Error::last_os_error();
                                warn!("Failed to send SIGKILL to PID {}: {}", pid, err);
                            } else {
                                info!("Sent SIGKILL to stubborn sandbox PID {}", pid);
                            }
                        }
                    }
                }

                return Ok(killed);
            }
        }

        #[cfg(not(unix))]
        {
            warn!("Sandbox process killing not supported on this platform");
        }

        Ok(0)
    }

    /// Revoke all session tokens
    async fn revoke_all_sessions(&self) -> Result<usize, Box<dyn std::error::Error>> {
        let mut sessions = self.sessions.write().await;
        let count = sessions.len();
        sessions.clear();
        Ok(count)
    }

    /// Revoke all dynamic leases (Vault/OpenBao API calls)
    ///
    /// This function is called during emergency lockdown to revoke any active
    /// dynamic secret leases from external vault backends (HashiCorp Vault, OpenBao, etc.).
    ///
    /// When external vault backends are implemented (future phase), this should:
    /// 1. Track all active dynamic secret leases with their lease IDs
    /// 2. Call the vault API to revoke each lease immediately
    /// 3. Return the count of successfully revoked leases
    ///
    /// Example implementations:
    /// - HashiCorp Vault: POST /v1/sys/leases/revoke/{lease_id}
    /// - OpenBao: Similar API to Vault
    /// - AWS Secrets Manager: Delete secret versions or invalidate sessions
    ///
    /// For now, this is a placeholder since SIGIL only supports LocalVault.
    async fn revoke_dynamic_leases(&self) -> Result<usize, Box<dyn std::error::Error>> {
        // TODO: Implement dynamic lease revocation for external vaults
        // This requires:
        // 1. External vault backend implementations (Vault, OpenBao, etc.)
        // 2. Lease tracking when dynamic secrets are provisioned
        // 3. API calls to revoke leases during lockdown
        // For now, this is a placeholder since only LocalVault is supported.
        Ok(0)
    }

    /// Lock the vault by zeroizing all secrets
    async fn lock_vault(&self) -> Result<(), Box<dyn std::error::Error>> {
        self.secrets.zeroize_all().await;
        Ok(())
    }

    /// Generate breach report and log it
    async fn generate_breach_report(&self, report: &LockdownReport) {
        let report_json = serde_json::to_string_pretty(report).unwrap_or_default();
        info!("Breach report:\n{}", report_json);

        // Log to audit file
        if let Err(e) = self.audit_logger.log_breach_report(&report_json).await {
            error!("Failed to log breach report: {}", e);
        }
    }

    /// Send alerts to configured channels
    async fn send_alerts(
        &self,
        report: &LockdownReport,
    ) -> Result<usize, Box<dyn std::error::Error>> {
        // Get the hostname for the alert
        let hostname = hostname::get()
            .map_err(|e| format!("Failed to get hostname: {}", e))?
            .to_string_lossy()
            .to_string();

        // Create a lockdown event from the report
        let event = LockdownEvent::from_report(report, hostname);

        // Send alerts using the alert sender
        match self.alert_sender.send_lockdown_alert(&event).await {
            Ok(count) => {
                if count > 0 {
                    info!("Sent {} lockdown alerts successfully", count);
                }
                Ok(count)
            }
            Err(e) => {
                warn!("Failed to send lockdown alerts: {}", e);
                Err(e)
            }
        }
    }

    /// Sync all secrets from the protected secrets store to the scrubber
    ///
    /// This should be called after bulk operations that add/remove secrets.
    pub async fn sync_secrets_to_scrubber(&self) -> Result<(), Box<dyn std::error::Error>> {
        let secrets = self.secrets.inner().read().await;
        let mut scrubber = self.scrubber.write().await;

        // Clear existing patterns
        scrubber.clear();

        // Add all current secrets to the scrubber
        for (path_str, value) in secrets.iter() {
            let path = SecretPath::new(path_str)
                .map_err(|e| format!("Invalid secret path {}: {}", path_str, e))?;
            scrubber.add_secret(path, value);
        }

        debug!("Synced {} secrets to scrubber", secrets.len());
        Ok(())
    }

    /// Add a single secret to the scrubber
    pub async fn add_secret_to_scrubber(&self, path: SecretPath, value: Vec<u8>) {
        let mut scrubber = self.scrubber.write().await;
        let path_str = path.as_str().to_string();
        scrubber.add_secret(path, &value);
        debug!("Added secret {} to scrubber", path_str);
    }

    /// Remove a secret from the scrubber
    pub async fn remove_secret_from_scrubber(&self, path: &SecretPath) {
        let mut scrubber = self.scrubber.write().await;
        scrubber.remove_secret(path);
        debug!("Removed secret {} from scrubber", path.as_str());
    }

    /// Clear all secrets from the scrubber
    pub async fn clear_scrubber(&self) {
        let mut scrubber = self.scrubber.write().await;
        scrubber.clear();
        debug!("Cleared all secrets from scrubber");
    }

    /// Handle FUSE read request
    async fn handle_fuse_read(
        &self,
        request_id: String,
        payload: serde_json::Value,
    ) -> IpcResponse {
        let fuse_req: FuseReadRequest = match serde_json::from_value(payload) {
            Ok(req) => req,
            Err(e) => {
                return IpcResponse::error(
                    request_id,
                    IpcError::new(
                        IpcErrorCode::InvalidRequest,
                        format!("Invalid FUSE read request: {}", e),
                    ),
                );
            }
        };

        // Log the FUSE read operation with PID/UID/GID
        info!(
            "FUSE read: path={}, pid={}, uid={}, gid={}, offset={}, size={}",
            fuse_req.path,
            fuse_req.req_pid,
            fuse_req.req_uid,
            fuse_req.req_gid,
            fuse_req.offset,
            fuse_req.size
        );

        // Log to audit trail
        self.audit_logger
            .log_fuse_read(
                fuse_req.path.clone(),
                fuse_req.req_pid,
                fuse_req.req_uid,
                fuse_req.req_gid,
            )
            .await;

        // Get the secret value
        let secrets = self.secrets.inner().read().await;

        // Check if this is a special auto-generated file
        let raw_data = if let Some(generated) = self.try_generate_file(&fuse_req.path).await {
            generated
        } else if let Some(value) = secrets.get(&fuse_req.path) {
            // Return the actual secret value (raw bytes)
            value.clone()
        } else {
            // Secret not found
            warn!("FUSE read: secret not found: {}", fuse_req.path);

            // Check if this might be a canary access - return decoy response
            if self.canary_manager.is_canary_path(&fuse_req.path) {
                // Record canary access for auto-lockdown tracking
                self.record_canary_access().await;

                // Log as CRITICAL breach event
                self.audit_logger
                    .log_canary_access(fuse_req.path.clone(), fuse_req.req_pid, fuse_req.req_uid)
                    .await;

                // Generate decoy response instead of returning error
                if let Some(decoy_data) =
                    self.canary_manager.generate_decoy_response(&fuse_req.path)
                {
                    info!(
                        "Returning decoy response for canary access: {} ({} bytes)",
                        fuse_req.path,
                        decoy_data.len()
                    );

                    // Handle offset for decoy data
                    let offset = fuse_req.offset as usize;
                    if offset >= decoy_data.len() {
                        let response = FuseReadResponse {
                            data: String::new(),
                            size: 0,
                            eof: true,
                        };
                        return IpcResponse::with_payload(
                            request_id,
                            serde_json::to_value(response).unwrap_or(serde_json::json!({})),
                        );
                    }

                    let end = std::cmp::min(offset + fuse_req.size as usize, decoy_data.len());
                    let slice = &decoy_data[offset..end];

                    // Re-encode the slice as base64 for transport
                    use base64::prelude::*;
                    let encoded = BASE64_STANDARD.encode(slice);

                    let response = FuseReadResponse {
                        data: encoded,
                        size: slice.len() as u32,
                        eof: end >= decoy_data.len(),
                    };
                    return IpcResponse::with_payload(
                        request_id,
                        serde_json::to_value(response).unwrap_or(serde_json::json!({})),
                    );
                }
            }

            return IpcResponse::error(
                request_id,
                IpcError::new(IpcErrorCode::SecretNotFound, "Secret not found"),
            );
        };

        // Handle offset
        let offset = fuse_req.offset as usize;
        if offset >= raw_data.len() {
            // Reading past EOF
            let response = FuseReadResponse {
                data: String::new(),
                size: 0,
                eof: true,
            };
            return IpcResponse::with_payload(
                request_id,
                serde_json::to_value(response).unwrap_or(serde_json::json!({})),
            );
        }

        let end = std::cmp::min(offset + fuse_req.size as usize, raw_data.len());
        let slice = &raw_data[offset..end];

        // Re-encode the slice as base64 for transport
        use base64::prelude::*;
        let encoded = BASE64_STANDARD.encode(slice);

        let response = FuseReadResponse {
            data: encoded,
            size: slice.len() as u32,
            eof: end >= raw_data.len(),
        };

        IpcResponse::with_payload(
            request_id,
            serde_json::to_value(response).unwrap_or(serde_json::json!({})),
        )
    }

    /// Try to generate an auto-formatted file (aws/credentials, k8s/kubeconfig, etc.)
    async fn try_generate_file(&self, path: &str) -> Option<Vec<u8>> {
        let secrets = self.secrets.inner().read().await;

        match path {
            "aws/credentials" => {
                // Generate AWS credentials file in INI format
                let access_key = secrets.get("aws/access_key_id")?;
                let secret_key = secrets.get("aws/secret_access_key")?;

                let access_key_str = String::from_utf8(access_key.clone()).ok()?;
                let secret_key_str = String::from_utf8(secret_key.clone()).ok()?;

                let credentials = format!(
                    "[default]\naws_access_key_id = {}\naws_secret_access_key = {}\n",
                    access_key_str, secret_key_str
                );

                Some(credentials.into_bytes())
            }

            "k8s/kubeconfig" => {
                // Generate kubectl config in YAML format
                let token = secrets
                    .get("k8s/token")
                    .or_else(|| secrets.get("k8s/api_token"))?;

                let token_str = String::from_utf8(token.clone()).ok()?;

                let kubeconfig = format!(
                    r#"apiVersion: v1
kind: Config
clusters:
- cluster:
    server: https://kubernetes.default.svc
  name: default
contexts:
- context:
    cluster: default
    user: default
  name: default
current-context: default
users:
- name: default
  user:
    token: {}
"#,
                    token_str
                );

                Some(kubeconfig.into_bytes())
            }

            // TLS certificates - return as-is (already in PEM format)
            path if path.starts_with("tls/") => {
                // For TLS files, just return the stored value directly
                // The secrets are already stored as PEM format
                secrets.get(path).cloned()
            }

            _ => None,
        }
    }

    /// Handle list operations request
    async fn handle_list_operations(&self, request_id: String) -> IpcResponse {
        let operations = self.operations.read().await;
        let ops: Vec<OperationDescription> = operations
            .list()
            .iter()
            .map(|id| {
                if let Some(op) = operations.get(id) {
                    OperationDescription {
                        id: op.id.clone(),
                        description: op.description.clone(),
                        requires_approval: op.require_approval,
                    }
                } else {
                    OperationDescription {
                        id: id.clone(),
                        description: "(unknown)".to_string(),
                        requires_approval: true,
                    }
                }
            })
            .collect();

        let response = ListOperationsResponse { operations: ops };

        IpcResponse::with_payload(
            request_id,
            serde_json::to_value(response).unwrap_or(serde_json::json!({})),
        )
    }

    /// Handle execute operation request
    async fn handle_execute_operation(
        &self,
        request_id: String,
        payload: serde_json::Value,
    ) -> IpcResponse {
        let exec_req: ExecuteOperationRequest = match serde_json::from_value(payload) {
            Ok(req) => req,
            Err(e) => {
                return IpcResponse::error(
                    request_id,
                    IpcError::new(
                        IpcErrorCode::InvalidRequest,
                        format!("Invalid execute operation request: {}", e),
                    ),
                );
            }
        };

        // Get the operation definition
        let operation = {
            let operations = self.operations.read().await;
            match operations.get(&exec_req.operation_id) {
                Some(op) => op.clone(),
                None => {
                    return IpcResponse::error(
                        request_id,
                        IpcError::new(
                            IpcErrorCode::SecretNotFound,
                            format!("Operation '{}' not found", exec_req.operation_id),
                        ),
                    );
                }
            }
        };

        // Log the operation execution request
        info!(
            "Executing sealed operation: {} (filter: {:?})",
            operation.id, operation.output_filter
        );

        let start_time = std::time::Instant::now();

        // Check if approval is required
        if operation.require_approval {
            // For now, we'll auto-approve operations that were pre-configured
            // In a full implementation, this would trigger a TUI approval prompt
            info!(
                "Operation {} requires approval - auto-approving pre-configured operation",
                operation.id
            );
        }

        // Resolve the command template with secret values
        let resolved_command = match self.resolve_command_template(&operation.command).await {
            Ok(cmd) => cmd,
            Err(e) => {
                error!("Failed to resolve command template: {}", e);

                self.audit_logger
                    .log_operation_execution(
                        operation.id.clone(),
                        operation.command.clone(),
                        -1,
                        start_time.elapsed().as_millis() as u64,
                        vec![],
                        0,
                    )
                    .await;

                let result = OperationResult {
                    operation_id: operation.id.clone(),
                    exit_code: -2,
                    output: Some(format!("Failed to resolve command: {}", e)),
                    timed_out: false,
                    duration_ms: start_time.elapsed().as_millis() as u64,
                };

                let response = ExecuteOperationResponse { result };
                return IpcResponse::with_payload(
                    request_id,
                    serde_json::to_value(response).unwrap_or(serde_json::json!({})),
                );
            }
        };

        // Execute the command
        let (exit_code, raw_output) = match self
            .execute_operation_command(&resolved_command, operation.timeout_seconds)
            .await
        {
            Ok(result) => result,
            Err(e) => {
                error!("Failed to execute operation command: {}", e);

                self.audit_logger
                    .log_operation_execution(
                        operation.id.clone(),
                        resolved_command,
                        -1,
                        start_time.elapsed().as_millis() as u64,
                        vec![],
                        0,
                    )
                    .await;

                let result = OperationResult {
                    operation_id: operation.id.clone(),
                    exit_code: -3,
                    output: Some(format!("Failed to execute command: {}", e)),
                    timed_out: false,
                    duration_ms: start_time.elapsed().as_millis() as u64,
                };

                let response = ExecuteOperationResponse { result };
                return IpcResponse::with_payload(
                    request_id,
                    serde_json::to_value(response).unwrap_or(serde_json::json!({})),
                );
            }
        };

        let duration_ms = start_time.elapsed().as_millis() as u64;
        let timed_out = exit_code == 124; // 124 is our timeout exit code

        // Apply output filtering
        let filtered_output = self
            .apply_output_filter(&operation, &raw_output, exit_code)
            .await;

        // Log the operation execution
        self.audit_logger
            .log_operation_execution(
                operation.id.clone(),
                resolved_command,
                exit_code,
                duration_ms,
                operation.secrets.clone(),
                raw_output.len(),
            )
            .await;

        let result = OperationResult {
            operation_id: operation.id.clone(),
            exit_code,
            output: filtered_output,
            timed_out,
            duration_ms,
        };

        let response = ExecuteOperationResponse { result };

        IpcResponse::with_payload(
            request_id,
            serde_json::to_value(response).unwrap_or(serde_json::json!({})),
        )
    }

    /// Resolve a command template by replacing {{secret:path}} placeholders
    async fn resolve_command_template(&self, template: &str) -> Result<String, anyhow::Error> {
        let mut resolved = template.to_string();
        let secrets = self.secrets.inner().read().await;

        // Find all {{secret:path}} placeholders and replace them
        let re = regex::Regex::new(r"\{\{secret:([^}]+)\}\}")?;
        let captures: Vec<_> = re.captures_iter(template).collect();

        for cap in captures {
            if let Some(full_match) = cap.get(0) {
                if let Some(secret_path) = cap.get(1) {
                    let path = secret_path.as_str();

                    // Handle special :file suffix for binary files
                    let actual_path = if let Some(stripped) = path.strip_suffix(":file") {
                        stripped
                    } else {
                        path
                    };

                    if let Some(value) = secrets.get(actual_path) {
                        // Convert to string (for text secrets)
                        let replacement =
                            if actual_path.ends_with(":file") || path.ends_with(":file") {
                                // For file references, write to a temp file and return the path
                                let temp_file = tempfile::NamedTempFile::new()?;
                                std::fs::write(temp_file.path(), value)?;
                                temp_file.path().to_string_lossy().to_string()
                            } else {
                                // For text secrets, use the value directly
                                String::from_utf8_lossy(value).to_string()
                            };

                        resolved = resolved.replace(full_match.as_str(), &replacement);
                    } else {
                        return Err(anyhow::anyhow!("Secret not found: {}", actual_path));
                    }
                }
            }
        }

        Ok(resolved)
    }

    /// Execute an operation command with optional timeout
    async fn execute_operation_command(
        &self,
        command: &str,
        timeout_seconds: Option<u64>,
    ) -> Result<(i32, String), anyhow::Error> {
        use std::process::Command;

        // Parse the command into parts
        // For simplicity, we'll use shell parsing
        let parts = shell_words::split(command)
            .map_err(|e| anyhow::anyhow!("Failed to parse command: {}", e))?;

        if parts.is_empty() {
            return Err(anyhow::anyhow!("Empty command"));
        }

        let mut cmd = Command::new(&parts[0]);
        if parts.len() > 1 {
            cmd.args(&parts[1..]);
        }

        // Set up environment to include SIGIL socket for subprocess access
        // This allows subprocesses to also use SIGIL if needed
        if let Ok(socket_path) = std::env::var("SIGIL_SOCKET") {
            cmd.env("SIGIL_SOCKET", socket_path);
        }

        // Execute with timeout if specified
        let output = if let Some(timeout) = timeout_seconds {
            let timeout_duration = std::time::Duration::from_secs(timeout);
            tokio::time::timeout(
                timeout_duration,
                tokio::task::spawn_blocking(move || cmd.output()),
            )
            .await
            .map_err(|_| anyhow::anyhow!("Command timed out"))??
            .map_err(|e| anyhow::anyhow!("Command execution failed: {}", e))?
        } else {
            tokio::task::spawn_blocking(move || cmd.output())
                .await
                .map_err(|e| anyhow::anyhow!("Command execution failed: {}", e))??
        };

        let exit_code = output
            .status
            .code()
            .unwrap_or(if output.status.success() { 0 } else { 1 });
        let stdout = String::from_utf8_lossy(&output.stdout).to_string();
        let stderr = String::from_utf8_lossy(&output.stderr).to_string();

        // Combine stdout and stderr
        let combined = if !stdout.is_empty() && !stderr.is_empty() {
            format!("{}\n{}", stdout, stderr)
        } else if !stdout.is_empty() {
            stdout
        } else {
            stderr
        };

        Ok((exit_code, combined))
    }

    /// Apply output filtering based on the operation's filter mode
    async fn apply_output_filter(
        &self,
        operation: &sigil_core::SealedOperation,
        raw_output: &str,
        exit_code: i32,
    ) -> Option<String> {
        match operation.output_filter {
            sigil_core::OutputFilter::ExitCode => {
                // Agent sees only exit code and "succeeded"/"failed"
                let status = if exit_code == 0 {
                    "succeeded"
                } else {
                    "failed"
                };
                Some(format!("Exit code: {}, Status: {}", exit_code, status))
            }
            sigil_core::OutputFilter::Summary => {
                // Extract a one-line summary using regex
                if let Some(regex_str) = &operation.summary_regex {
                    if let Ok(re) = regex::Regex::new(regex_str) {
                        if let Some(captures) = re.captures(raw_output) {
                            if let Some(matched) = captures.get(1) {
                                return Some(matched.as_str().to_string());
                            } else if let Some(matched) = captures.get(0) {
                                return Some(matched.as_str().to_string());
                            }
                        }
                    }
                }
                // Fallback to exit code if regex doesn't match
                Some(format!("Exit code: {}", exit_code))
            }
            sigil_core::OutputFilter::FullScrubbed => {
                // Return scrubbed output (redact secrets)
                let mut scrubber = sigil_scrub::StreamingScrubber::new();

                // Add all operation secrets to the scrubber
                let secrets = self.secrets.inner().read().await;
                for secret_path in &operation.secrets {
                    if let Some(value) = secrets.get(secret_path) {
                        if let Ok(path) = sigil_core::SecretPath::new(secret_path.clone()) {
                            scrubber.add_secret(path, value);
                        }
                    }
                }

                let scrubbed = scrubber.scrub_chunk(raw_output);
                Some(scrubbed)
            }
            sigil_core::OutputFilter::None => {
                // Fire-and-forget, agent sees nothing
                None
            }
        }
    }

    /// Handle breach report request
    async fn handle_breach_report(&self, request_id: String) -> IpcResponse {
        // Generate the breach report from the canary manager
        let report = self.canary_manager.generate_report().await;

        // Serialize the breach report
        match serde_json::to_value(&report) {
            Ok(payload) => IpcResponse::with_payload(request_id, payload),
            Err(e) => IpcResponse::error(
                request_id,
                IpcError::new(
                    IpcErrorCode::InternalError,
                    format!("Failed to serialize breach report: {}", e),
                ),
            ),
        }
    }

    /// Handle list sessions request
    async fn handle_list_sessions(&self, request_id: String) -> IpcResponse {
        use sigil_core::{ListSessionsResponse, SessionDetails};

        let sessions = self.sessions.read().await;
        let now = chrono::Utc::now();

        let session_details: Vec<SessionDetails> = sessions
            .values()
            .map(|session| {
                let idle_secs = (now - session.last_activity).num_seconds();
                let token_truncated = format!(
                    "{}...",
                    &session.token.to_base64()[..8.min(session.token.to_base64().len())]
                );

                SessionDetails {
                    token: token_truncated,
                    peer: session.peer.clone(),
                    created_at: session.created_at,
                    last_activity: session.last_activity,
                    idle_secs,
                }
            })
            .collect();

        let response = ListSessionsResponse {
            sessions: session_details,
        };

        match serde_json::to_value(&response) {
            Ok(payload) => IpcResponse::with_payload(request_id, payload),
            Err(e) => IpcResponse::error(
                request_id,
                IpcError::new(
                    IpcErrorCode::InternalError,
                    format!("Failed to serialize sessions: {}", e),
                ),
            ),
        }
    }

    /// Handle kill session request
    async fn handle_kill_session(
        &self,
        request_id: String,
        payload: serde_json::Value,
    ) -> IpcResponse {
        use sigil_core::{KillSessionRequest, KillSessionResponse};

        let kill_req: KillSessionRequest = match serde_json::from_value(payload) {
            Ok(req) => req,
            Err(e) => {
                return IpcResponse::error(
                    request_id,
                    IpcError::new(
                        IpcErrorCode::InvalidRequest,
                        format!("Invalid kill session request: {}", e),
                    ),
                );
            }
        };

        let mut sessions = self.sessions.write().await;
        let token = kill_req.token;

        if sessions.remove(&token).is_some() {
            info!("Session killed: {}", &token[..8.min(token.len())]);

            let response = KillSessionResponse {
                killed: true,
                message: "Session terminated successfully".to_string(),
            };

            match serde_json::to_value(&response) {
                Ok(payload) => IpcResponse::with_payload(request_id, payload),
                Err(e) => IpcResponse::error(
                    request_id,
                    IpcError::new(
                        IpcErrorCode::InternalError,
                        format!("Failed to serialize response: {}", e),
                    ),
                ),
            }
        } else {
            let response = KillSessionResponse {
                killed: false,
                message: "Session not found".to_string(),
            };

            match serde_json::to_value(&response) {
                Ok(payload) => IpcResponse::with_payload(request_id, payload),
                Err(e) => IpcResponse::error(
                    request_id,
                    IpcError::new(
                        IpcErrorCode::InternalError,
                        format!("Failed to serialize response: {}", e),
                    ),
                ),
            }
        }
    }

    /// Handle lease grant request
    async fn handle_lease_grant(
        &self,
        request_id: String,
        payload: serde_json::Value,
    ) -> IpcResponse {
        let grant_req: GrantLeaseRequest = match serde_json::from_value(payload) {
            Ok(req) => req,
            Err(e) => {
                return IpcResponse::error(
                    request_id,
                    IpcError::new(
                        IpcErrorCode::InvalidRequest,
                        format!("Invalid grant lease request: {}", e),
                    ),
                );
            }
        };

        // Parse secret path
        let secret_path = match SecretPath::new(grant_req.secret_path) {
            Ok(path) => path,
            Err(e) => {
                return IpcResponse::error(
                    request_id,
                    IpcError::new(
                        IpcErrorCode::InvalidRequest,
                        format!("Invalid secret path: {}", e),
                    ),
                );
            }
        };

        // Grant the lease
        let lease = match self
            .lease_manager
            .grant_lease(secret_path, grant_req.ttl_secs)
            .await
        {
            Ok(lease) => lease,
            Err(e) => {
                return IpcResponse::error(
                    request_id,
                    IpcError::new(
                        IpcErrorCode::InternalError,
                        format!("Failed to grant lease: {}", e),
                    ),
                );
            }
        };

        info!(
            "Lease granted: {} for {} (expires: {})",
            lease.id,
            lease.secret_path.as_str(),
            lease.expires_at
        );

        let lease_id = lease.id.clone();
        let lease_path = lease.secret_path.as_str().to_string();
        let lease_granted_at = lease.granted_at;
        let lease_expires_at = lease.expires_at;
        let lease_remaining = lease.remaining_secs();

        let lease_details = LeaseDetails {
            id: lease_id,
            secret_path: lease_path,
            granted_at: lease_granted_at.to_rfc3339(),
            expires_at: lease_expires_at.to_rfc3339(),
            remaining_secs: lease_remaining,
        };

        let response = GrantLeaseResponse {
            lease: lease_details,
        };

        match serde_json::to_value(&response) {
            Ok(payload) => IpcResponse::with_payload(request_id, payload),
            Err(e) => IpcResponse::error(
                request_id,
                IpcError::new(
                    IpcErrorCode::InternalError,
                    format!("Failed to serialize response: {}", e),
                ),
            ),
        }
    }

    /// Handle lease revoke request
    async fn handle_lease_revoke(
        &self,
        request_id: String,
        payload: serde_json::Value,
    ) -> IpcResponse {
        let revoke_req: RevokeLeaseRequest = match serde_json::from_value(payload) {
            Ok(req) => req,
            Err(e) => {
                return IpcResponse::error(
                    request_id,
                    IpcError::new(
                        IpcErrorCode::InvalidRequest,
                        format!("Invalid revoke lease request: {}", e),
                    ),
                );
            }
        };

        let lease_id = revoke_req.lease_id.clone();
        let reason = revoke_req.reason.clone();

        let revoked = match self.lease_manager.revoke_lease(&lease_id, reason).await {
            Ok(revoked) => revoked,
            Err(e) => {
                return IpcResponse::error(
                    request_id,
                    IpcError::new(
                        IpcErrorCode::InternalError,
                        format!("Failed to revoke lease: {}", e),
                    ),
                );
            }
        };

        info!(
            "Lease revoked: {} (reason: {:?})",
            lease_id, revoke_req.reason
        );

        let response = serde_json::json!({
            "revoked": revoked,
            "message": if revoked {
                "Lease revoked successfully"
            } else {
                "Lease not found or already expired"
            }
        });

        IpcResponse::with_payload(request_id, response)
    }

    /// Handle lease list request
    async fn handle_lease_list(&self, request_id: String) -> IpcResponse {
        let leases = match self.lease_manager.get_active_leases().await {
            Ok(leases) => leases,
            Err(e) => {
                return IpcResponse::error(
                    request_id,
                    IpcError::new(
                        IpcErrorCode::InternalError,
                        format!("Failed to list leases: {}", e),
                    ),
                );
            }
        };

        let response = serde_json::json!({
            "leases": leases,
            "total_count": leases.len(),
        });

        IpcResponse::with_payload(request_id, response)
    }

    /// Handle lease stats request
    async fn handle_lease_stats(&self, request_id: String) -> IpcResponse {
        let stats = self.lease_manager.stats().await;

        let response = serde_json::json!({
            "total_leases": stats.total_leases,
            "active_leases": stats.active_leases,
            "expired_leases": stats.expired_leases,
            "revoked_leases": stats.revoked_leases,
        });

        IpcResponse::with_payload(request_id, response)
    }

    /// Shutdown the server
    pub async fn shutdown(&self) -> Result<(), Box<dyn std::error::Error>> {
        // Set shutdown flag
        let mut flag = self.shutdown_flag.write().await;
        *flag = true;

        // Zeroize all secrets BEFORE any cleanup
        self.secrets.zeroize_all().await;

        // Remove socket file
        if self.socket_path.exists() {
            std::fs::remove_file(&self.socket_path)?;
        }

        info!("Daemon shutdown complete (all secrets zeroized)");

        Ok(())
    }

    /// Reload configuration from the config file
    ///
    /// This reloads:
    /// - Scrubber patterns (if secrets have changed)
    /// - Access grants (re-reads the access grants file)
    /// - Operations registry (reloads custom operations)
    pub async fn reload_config(&self) -> Result<(), Box<dyn std::error::Error>> {
        // Re-sync secrets to scrubber (in case secrets were added/removed)
        self.sync_secrets_to_scrubber().await?;

        // Reload access grants from file
        let grants_path = dirs::home_dir()
            .ok_or_else(|| anyhow::anyhow!("Cannot determine home directory"))?
            .join(".sigil")
            .join("access-grants.toml");

        if grants_path.exists() {
            let _content = std::fs::read_to_string(&grants_path)?;
            // Parse and update access grants
            // For now, we just log that grants were reloaded
            info!("Reloaded access grants from {}", grants_path.display());
        }

        // Reload custom operations from project file
        let project_ops_path = std::path::Path::new(".sigil/signatures.toml");
        if project_ops_path.exists() {
            // Reload project-specific operations
            info!(
                "Reloaded project operations from {}",
                project_ops_path.display()
            );
        }

        info!("Configuration reloaded successfully");

        Ok(())
    }

    /// Notify systemd that the daemon is ready
    ///
    /// This sends the READY=1 notification via the sd_notify protocol,
    /// which systemd uses to determine when the service is ready to serve requests.
    pub async fn notify_ready(&self) {
        // Only send notification if in systemd mode
        if self.systemd_mode {
            sd_notify("READY=1");
            info!("Sent READY=1 notification to systemd");
        }
    }

    /// Dump detailed daemon status for debugging
    pub async fn dump_status(&self) -> Result<DaemonStatusDump, Box<dyn std::error::Error>> {
        let sessions = self.sessions.read().await;
        let operations = self.operations.read().await;
        let access_grants = self.access_grants.read().await;
        let is_shutdown = *self.shutdown_flag.read().await;
        let is_lockdown = *self.lockdown_flag.read().await;

        // Count total secrets
        let secrets_store = self.secrets.inner().read().await;
        let secret_count = secrets_store.len();

        // Get scrubber pattern count
        let scrubber = self.scrubber.read().await;
        let pattern_count = scrubber.pattern_count();

        // Calculate uptime and convert to serializable format
        let uptime_secs = self.start_time.elapsed().as_secs();

        // Count active sessions (active if last activity within 8 hours)
        let active_sessions = sessions
            .iter()
            .filter(|(_, s)| {
                let now = chrono::Utc::now();
                let activity_age = now.signed_duration_since(s.last_activity);
                activity_age.num_hours() < 8
            })
            .count();

        // Count active access grants
        let active_grants = access_grants
            .values()
            .flatten()
            .filter(|g| {
                if let Some(expires_at) = g.expires_at {
                    expires_at > chrono::Utc::now()
                } else {
                    true
                }
            })
            .count();

        // Convert operation list to OperationDescription
        let op_list = operations.list();
        let operation_descriptions: Vec<OperationDescription> = op_list
            .iter()
            .map(|id| OperationDescription {
                id: id.clone(),
                description: format!("Operation: {}", id),
                requires_approval: true,
            })
            .collect();

        Ok(DaemonStatusDump {
            uptime_secs,
            secret_count,
            active_sessions,
            total_sessions: sessions.len(),
            active_grants,
            pattern_count,
            is_shutdown,
            is_lockdown,
            operations: operation_descriptions,
        })
    }
}

/// Detailed daemon status dump
#[derive(Debug, serde::Serialize)]
pub struct DaemonStatusDump {
    /// How long the daemon has been running (in seconds)
    uptime_secs: u64,
    /// Number of secrets loaded
    secret_count: usize,
    /// Number of active sessions
    active_sessions: usize,
    /// Total number of sessions (including expired)
    total_sessions: usize,
    /// Number of active access grants
    active_grants: usize,
    /// Number of scrubber patterns loaded
    pattern_count: usize,
    /// Whether shutdown flag is set
    is_shutdown: bool,
    /// Whether lockdown flag is set
    is_lockdown: bool,
    /// List of registered operations
    operations: Vec<OperationDescription>,
}
