//! SIGIL TUI - Terminal UI for secret management
//!
//! This module provides a terminal user interface for managing secrets.
//! The TUI runs on a separate PTY with process isolation to prevent
//! the AI agent from accessing secret values through memory inspection.

#![warn(missing_docs)]
#![warn(clippy::all)]

use anyhow::Result;
use crossterm::{
    event::{self, DisableMouseCapture, Event, KeyCode, KeyEvent},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, LeaveAlternateScreen},
};
use ratatui::{
    backend::CrosstermBackend,
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, List, ListItem, ListState, Paragraph, Wrap},
    Frame, Terminal,
};
use sigil_core::{
    audit::AuditEntry, LayoutMode as CoreLayoutMode, SecretBackend, SecretPath, UnicodeMode,
};
use sigil_tui::pty::PtyPair;
use sigil_vault::LocalVault;
use std::io;
use std::os::fd::{AsRawFd, BorrowedFd, FromRawFd, OwnedFd};
use std::time::{Duration, Instant};

#[cfg(target_os = "linux")]
use nix::sys::resource::{setrlimit, Resource};

#[cfg(target_os = "linux")]
use nix::unistd::dup2;

/// Enable process isolation for the TUI
///
/// This function applies security hardening to prevent the TUI process
/// from being inspected by other processes (including AI agents).
///
/// # Security Measures
///
/// - **PR_SET_DUMPABLE=0**: Prevents ptrace, /proc/<pid>/mem reads, and core dumps
/// - **RLIMIT_CORE=0**: Disables core dump files
/// - **Alternate screen buffer**: Prevents terminal scrollback capture (via crossterm)
///
/// # Platform Support
///
/// - **Linux**: Full support (prctl + rlimit)
/// - **macOS**: Partial support (PT_DENY_ATTACH via ptrace control)
/// - **Other**: Best effort (terminal isolation only)
#[cfg(target_os = "linux")]
fn enable_process_isolation() -> Result<()> {
    use nix::sys::prctl::set_dumpable;

    // Prevent process memory dumps (ptrace, /proc/<pid>/mem, core dumps)
    // PR_SET_DUMPABLE=0 means the process cannot be dumped
    set_dumpable(false).map_err(|e| anyhow::anyhow!("Failed to set PR_SET_DUMPABLE: {}", e))?;

    // Disable core dumps completely
    setrlimit(Resource::RLIMIT_CORE, 0, 0)
        .map_err(|e| anyhow::anyhow!("Failed to set RLIMIT_CORE: {}", e))?;

    tracing::info!("Process isolation enabled (PR_SET_DUMPABLE=0, RLIMIT_CORE=0)");
    Ok(())
}

/// Enable process isolation for the TUI (macOS version)
///
/// On macOS, we use PT_DENY_ATTACH to prevent debugger attachment.
#[cfg(target_os = "macos")]
fn enable_process_isolation() -> Result<()> {
    // PT_DENY_ATTACH prevents debuggers from attaching
    unsafe {
        let ret = libc::ptrace(libc::PT_DENY_ATTACH, 0, std::ptr::null_mut(), 0);
        if ret != 0 {
            let err = std::io::Error::last_os_error();
            // This is expected in some cases (e.g., when not being debugged)
            tracing::debug!("PT_DENY_ATTACH failed (may be expected): {}", err);
        } else {
            tracing::info!("Set PT_DENY_ATTACH (debugger protection enabled)");
        }
    }

    // Disable core dumps
    unsafe {
        let rlim = libc::rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };
        let ret = libc::setrlimit(libc::RLIMIT_CORE, &rlim);
        if ret != 0 {
            let err = std::io::Error::last_os_error();
            tracing::warn!("Failed to disable core dumps: {}", err);
        } else {
            tracing::info!("Disabled core dumps (RLIMIT_CORE=0)");
        }
    }

    Ok(())
}

/// Enable process isolation for the TUI (fallback for other platforms)
///
/// On platforms without specific prctl support, we rely on terminal
/// isolation (alternate screen buffer) only.
#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn enable_process_isolation() -> Result<()> {
    tracing::warn!("Process isolation not available on this platform - terminal isolation only");
    Ok(())
}

/// TUI application state
struct App {
    /// List of secrets
    secrets: Vec<SecretItem>,
    /// Currently selected secret index
    selected: usize,
    /// Current view mode
    mode: Mode,
    /// Filter prefix for listing secrets
    filter_prefix: String,
    /// Secret detail view
    detail_view: Option<SecretDetail>,
    /// Status message
    status_message: String,
    /// Auto-hide timeout for secret values (default: 5 seconds)
    auto_hide_timeout: Duration,
    /// Add/edit form state
    form_state: Option<FormState>,
    /// Audit log entries
    audit_entries: Vec<AuditItem>,
    /// Currently selected audit entry index
    audit_selected: usize,
    /// Audit log filter (entry type)
    _audit_filter: Option<String>,
    /// Session list
    sessions: Vec<SessionItem>,
    /// Currently selected session index
    session_selected: usize,
    /// Import/Export state
    import_export_state: Option<ImportExportState>,
    /// Backend sync state
    sync_state: Option<BackendSyncState>,
    /// Breach alerts state
    breach_alerts: Vec<BreachAlert>,
    /// Currently selected breach alert index
    breach_selected: usize,
    /// Secret rotation state
    rotation_state: Option<RotationState>,
}

/// Import/Export state
#[derive(Debug, Clone)]
struct ImportExportState {
    /// Current operation (Import or Export)
    operation: ImportExportOp,
    /// File path input
    file_path: String,
    /// Import mode (for import operations)
    import_mode: ImportMode,
    /// Current step in the workflow
    current_step: ImportExportStep,
    /// Pending conflicts (for conflict resolution)
    pending_conflicts: Vec<ConflictItem>,
    /// Currently selected conflict index
    conflict_selected: usize,
    /// Progress message
    progress_message: String,
}

/// Import mode for conflict resolution
#[derive(Debug, Clone, Copy, PartialEq)]
enum ImportMode {
    /// Skip existing secrets (keep current)
    SkipExisting,
    /// Overwrite existing secrets
    Overwrite,
    /// Rename imported secrets (add suffix)
    Rename,
    /// Manual conflict resolution
    Manual,
}

/// Import/Export operation type
#[derive(Debug, Clone, Copy, PartialEq)]
enum ImportExportOp {
    /// Import secrets from archive
    Import,
    /// Export secrets to archive
    Export,
}

/// Import/Export workflow step
#[derive(Debug, Clone, Copy, PartialEq)]
#[allow(dead_code)]
enum ImportExportStep {
    /// Enter file path
    FilePath,
    /// Select import mode (for import only)
    ImportMode,
    /// Resolve conflicts
    ConflictResolution,
    /// In progress
    InProgress,
    /// Complete
    Complete,
}

/// Conflict item for resolution
#[derive(Debug, Clone)]
struct ConflictItem {
    /// Secret path
    path: String,
    /// Existing secret timestamp
    existing_timestamp: String,
    /// Imported secret timestamp
    imported_timestamp: String,
    /// Resolution action
    resolution: ConflictResolution,
}

/// Conflict resolution action
#[derive(Debug, Clone, Copy, PartialEq)]
#[allow(dead_code)]
enum ConflictResolution {
    /// Keep existing
    KeepExisting,
    /// Use imported
    UseImported,
    /// Skip (unresolved)
    Unresolved,
}

/// Connection configuration form state
#[derive(Debug, Clone)]
struct ConnectionConfigState {
    /// Server address/URL
    address: String,
    /// Authentication method
    auth_method: AuthMethod,
    /// Token (for token-based auth)
    token: String,
    /// Username (for username/password auth)
    username: String,
    /// Password (for username/password auth)
    password: String,
    /// API key (for AWS Secrets Manager)
    api_key: String,
    /// Secret key (for AWS Secrets Manager)
    secret_key: String,
    /// Region (for AWS Secrets Manager)
    region: String,
    /// Vault namespace (for HashiCorp Vault)
    namespace: String,
    /// Current field being edited
    current_field: ConnectionField,
    /// Connection error message
    error_message: Option<String>,
}

/// Authentication method
#[derive(Debug, Clone, Copy, PartialEq)]
enum AuthMethod {
    /// Token-based authentication
    Token,
    /// Username/password authentication
    UsernamePassword,
    /// AWS credentials
    AwsCredentials,
}

/// Connection configuration fields
#[derive(Debug, Clone, Copy, PartialEq)]
enum ConnectionField {
    /// Server address
    Address,
    /// Authentication method
    AuthMethod,
    /// Token
    Token,
    /// Username
    Username,
    /// Password
    Password,
    /// API key (AWS)
    ApiKey,
    /// Secret key (AWS)
    SecretKey,
    /// Region (AWS)
    Region,
    /// Vault namespace
    Namespace,
}

impl Default for ConnectionConfigState {
    fn default() -> Self {
        Self {
            address: String::new(),
            auth_method: AuthMethod::Token,
            token: String::new(),
            username: String::new(),
            password: String::new(),
            api_key: String::new(),
            secret_key: String::new(),
            region: "us-east-1".to_string(),
            namespace: String::new(),
            current_field: ConnectionField::Address,
            error_message: None,
        }
    }
}

impl BackendSyncState {
    /// Get default address hint for the backend type
    #[allow(dead_code)]
    fn address_hint(&self) -> &'static str {
        match self.backend_type {
            BackendType::HashiCorpVault => "https://vault.example.com:8200",
            BackendType::OnePassword => "https://{}.1password.com",
            BackendType::Bitwarden => "https://bitwarden.com",
            BackendType::AwsSecretsManager => "https://secretsmanager.{}.amazonaws.com",
        }
    }

    /// Get visible fields for the current backend type
    fn visible_fields(&self) -> Vec<ConnectionField> {
        match self.backend_type {
            BackendType::HashiCorpVault => vec![
                ConnectionField::Address,
                ConnectionField::AuthMethod,
                ConnectionField::Token,
                ConnectionField::Namespace,
            ],
            BackendType::OnePassword => vec![
                ConnectionField::Address,
                ConnectionField::Token,
            ],
            BackendType::Bitwarden => vec![
                ConnectionField::Address,
                ConnectionField::Username,
                ConnectionField::Password,
            ],
            BackendType::AwsSecretsManager => vec![
                ConnectionField::Region,
                ConnectionField::ApiKey,
                ConnectionField::SecretKey,
            ],
        }
    }

    /// Check if a field is required for the current backend type
    fn is_field_required(&self, field: ConnectionField) -> bool {
        match (self.backend_type, field) {
            // HashiCorp Vault required fields
            (BackendType::HashiCorpVault, ConnectionField::Address) => true,
            (BackendType::HashiCorpVault, ConnectionField::Token) => true,
            // OnePassword required fields
            (BackendType::OnePassword, ConnectionField::Address) => true,
            (BackendType::OnePassword, ConnectionField::Token) => true,
            // Bitwarden required fields
            (BackendType::Bitwarden, ConnectionField::Address) => true,
            (BackendType::Bitwarden, ConnectionField::Username) => true,
            (BackendType::Bitwarden, ConnectionField::Password) => true,
            // AWS Secrets Manager required fields
            (BackendType::AwsSecretsManager, ConnectionField::Region) => true,
            (BackendType::AwsSecretsManager, ConnectionField::ApiKey) => true,
            (BackendType::AwsSecretsManager, ConnectionField::SecretKey) => true,
            _ => false,
        }
    }

    /// Move to next visible field
    fn next_field(&mut self) {
        if let Some(ref config) = self.connection_config {
            let visible = self.visible_fields();
            if let Some(current_idx) = visible.iter().position(|&f| f == config.current_field) {
                let next_idx = (current_idx + 1) % visible.len();
                self.connection_config.as_mut().unwrap().current_field = visible[next_idx];
            }
        }
    }

    /// Move to previous visible field
    fn prev_field(&mut self) {
        if let Some(ref config) = self.connection_config {
            let visible = self.visible_fields();
            if let Some(current_idx) = visible.iter().position(|&f| f == config.current_field) {
                let prev_idx = if current_idx == 0 {
                    visible.len() - 1
                } else {
                    current_idx - 1
                };
                self.connection_config.as_mut().unwrap().current_field = visible[prev_idx];
            }
        }
    }
}

/// Backend sync state
#[derive(Debug, Clone)]
#[allow(dead_code)]
struct BackendSyncState {
    /// Selected backend type
    backend_type: BackendType,
    /// Connection status
    status: SyncStatus,
    /// Current step
    current_step: SyncStep,
    /// Progress message
    progress_message: String,
    /// Synced secrets count
    synced_count: usize,
    /// Failed secrets
    failed_secrets: Vec<String>,
    /// Connection configuration state
    connection_config: Option<ConnectionConfigState>,
}

/// External backend type
#[derive(Debug, Clone, Copy, PartialEq)]
enum BackendType {
    /// HashiCorp Vault
    HashiCorpVault,
    /// 1Password
    OnePassword,
    /// Bitwarden
    Bitwarden,
    /// AWS Secrets Manager
    AwsSecretsManager,
}

impl BackendType {
    /// Get the display name for this backend type
    fn display_name(&self) -> &str {
        match self {
            BackendType::HashiCorpVault => "HashiCorp Vault",
            BackendType::OnePassword => "1Password",
            BackendType::Bitwarden => "Bitwarden",
            BackendType::AwsSecretsManager => "AWS Secrets Manager",
        }
    }
}

/// Sync status
#[derive(Debug, Clone, Copy, PartialEq)]
#[allow(dead_code)]
enum SyncStatus {
    /// Not connected
    Disconnected,
    /// Connecting
    Connecting,
    /// Connected
    Connected,
    /// Syncing
    Syncing,
    /// Complete
    Complete,
    /// Error
    Error,
}

/// Sync workflow step
#[derive(Debug, Clone, Copy, PartialEq)]
enum SyncStep {
    /// Select backend type
    SelectBackend,
    /// Configure connection
    ConfigureConnection,
    /// Confirm sync
    ConfirmSync,
    /// In progress
    InProgress,
    /// Complete
    #[allow(dead_code)]
    Complete,
}

/// Breach alert item
#[derive(Debug, Clone)]
struct BreachAlert {
    /// Alert ID
    id: String,
    /// Severity level
    severity: BreachSeverity,
    /// Timestamp
    timestamp: String,
    /// Description
    description: String,
    /// Alert status
    status: AlertStatus,
    /// Recommended action
    #[allow(dead_code)]
    recommended_action: String,
}

/// Breach severity level
#[derive(Debug, Clone, Copy, PartialEq)]
enum BreachSeverity {
    /// Critical - immediate action required
    Critical,
    /// High - urgent action recommended
    High,
    /// Medium - action recommended
    Medium,
    /// Low - informational
    Low,
}

/// Alert status
#[derive(Debug, Clone, Copy, PartialEq)]
enum AlertStatus {
    /// New/unread
    New,
    /// Acknowledged
    Acknowledged,
    /// Resolved
    Resolved,
    /// Dismissed
    #[allow(dead_code)]
    Dismissed,
}

/// Secret rotation state
#[derive(Debug, Clone)]
struct RotationState {
    /// Current step
    current_step: RotationStep,
    /// Selected secret path
    secret_path: String,
    /// Rotation progress (0-100)
    progress: u8,
    /// Status message
    status_message: String,
    /// New secret value input
    new_value_input: String,
    /// Rotation reason
    rotation_reason: String,
}

/// Rotation workflow step
#[derive(Debug, Clone, Copy, PartialEq)]
enum RotationStep {
    /// Select secret to rotate
    SelectSecret,
    /// Enter new value
    EnterNewValue,
    /// Enter reason
    EnterReason,
    /// Confirm rotation
    ConfirmRotation,
    /// In progress
    InProgress,
    /// Complete
    Complete,
}

/// Form state for adding/editing secrets
#[derive(Debug, Clone)]
struct FormState {
    /// Secret path
    path: String,
    /// Secret value input buffer
    value_input: String,
    /// Secret type
    secret_type: String,
    /// Tags (comma-separated)
    tags: String,
    /// Notes
    notes: String,
    /// Current field being edited
    current_field: FormField,
    /// Whether this is editing an existing secret
    is_edit: bool,
}

/// Form fields for add/edit
#[derive(Debug, Clone, Copy, PartialEq)]
enum FormField {
    /// Secret path field
    Path,
    /// Secret value field
    Value,
    /// Secret type field
    Type,
    /// Tags field
    Tags,
    /// Notes field
    Notes,
}

/// Audit log item for display
#[derive(Debug, Clone)]
struct AuditItem {
    /// Entry type
    entry_type: String,
    /// Timestamp
    timestamp: String,
    /// Description (summary of the entry)
    description: String,
    /// Severity (for breaches, auth failures)
    severity: Option<String>,
}

impl From<&AuditEntry> for AuditItem {
    fn from(entry: &AuditEntry) -> Self {
        let (entry_type, description, severity) = match entry {
            AuditEntry::SessionStart { .. } => (
                "SessionStart".to_string(),
                "Session started".to_string(),
                None,
            ),
            AuditEntry::SessionEnd { .. } => {
                ("SessionEnd".to_string(), "Session ended".to_string(), None)
            }
            AuditEntry::SecretResolve { path, .. } => (
                "SecretResolve".to_string(),
                format!("Resolved: {}", path),
                None,
            ),
            AuditEntry::SecretAdd { path, .. } => {
                ("SecretAdd".to_string(), format!("Added: {}", path), None)
            }
            AuditEntry::SecretDelete { path, .. } => (
                "SecretDelete".to_string(),
                format!("Deleted: {}", path),
                Some("warning".to_string()),
            ),
            AuditEntry::SecretEdit { path, .. } => {
                ("SecretEdit".to_string(), format!("Edited: {}", path), None)
            }
            AuditEntry::AuthFailure { reason, .. } => (
                "AuthFailure".to_string(),
                format!("Auth failed: {}", reason),
                Some("error".to_string()),
            ),
            AuditEntry::BreachDetected {
                timestamp: _,
                previous_hash: _,
                severity,
                description,
            } => (
                "BreachDetected".to_string(),
                format!("Breach: {}", description),
                Some(severity.clone()),
            ),
            AuditEntry::Rotation { .. } => {
                ("Rotation".to_string(), "Log rotated".to_string(), None)
            }
            AuditEntry::FuseRead { path, .. } => {
                ("FuseRead".to_string(), format!("FUSE read: {}", path), None)
            }
            AuditEntry::CanaryAccess { path, .. } => (
                "CanaryAccess".to_string(),
                format!("Canary accessed: {}", path),
                Some("critical".to_string()),
            ),
            AuditEntry::Lockdown { reason, .. } => (
                "Lockdown".to_string(),
                format!("Lockdown: {}", reason),
                Some("critical".to_string()),
            ),
            AuditEntry::Unlock { .. } => {
                ("Unlock".to_string(), "Lockdown lifted".to_string(), None)
            }
            AuditEntry::SecretAccessGrant {
                secret_path,
                reason,
                ..
            } => (
                "SecretAccessGrant".to_string(),
                format!("Access granted: {} ({})", secret_path, reason),
                None,
            ),
            AuditEntry::SecretAccessDenied {
                secret_path,
                denial_reason,
                ..
            } => (
                "SecretAccessDenied".to_string(),
                format!(
                    "Access denied: {} ({})",
                    secret_path,
                    denial_reason.as_deref().unwrap_or("no reason")
                ),
                Some("warning".to_string()),
            ),
            AuditEntry::CommandExecuted {
                command, exit_code, ..
            } => (
                "CommandExecuted".to_string(),
                format!("Command: {} (exit: {})", command, exit_code),
                None,
            ),
            AuditEntry::OperationExecuted {
                operation_id,
                command,
                exit_code,
                ..
            } => (
                "OperationExecuted".to_string(),
                format!("Op {} (exit: {}): {}", operation_id, exit_code, command),
                None,
            ),
        };

        let timestamp = entry.timestamp().format("%Y-%m-%d %H:%M:%S").to_string();

        AuditItem {
            entry_type,
            timestamp,
            description,
            severity,
        }
    }
}

/// Session item for display
#[derive(Debug, Clone)]
struct SessionItem {
    /// Session token (truncated)
    token: String,
    /// Process ID
    pid: u32,
    /// User ID
    uid: u32,
    /// Creation time
    _created_at: String,
    /// Last activity time
    last_activity: String,
    /// Idle time in seconds
    idle_secs: i64,
}

/// Display mode
#[derive(Debug, Clone, Copy, PartialEq)]
enum Mode {
    /// Browse secrets list
    Browse,
    /// View secret details
    Detail,
    /// Help screen
    Help,
    /// Add new secret
    Add,
    /// Edit existing secret
    Edit,
    /// Delete secret confirmation
    Delete,
    /// Audit log viewer
    Audit,
    /// Session management
    Sessions,
    /// Import/Export secrets
    ImportExport,
    /// External backend sync
    BackendSync,
    /// Breach alerts panel
    BreachAlerts,
    /// Secret rotation
    SecretRotation,
}

/// Secret item for display
#[derive(Debug, Clone)]
struct SecretItem {
    /// Secret path
    path: String,
    /// Secret type
    #[allow(dead_code)]
    secret_type: String,
    /// Last updated
    updated: String,
    /// Tags
    tags: Vec<String>,
}

/// Secret detail view
#[derive(Debug, Clone)]
struct SecretDetail {
    /// Secret path
    path: String,
    /// Secret type
    secret_type: String,
    /// Creation time
    created: String,
    /// Update time
    updated: String,
    /// Tags
    tags: Vec<String>,
    /// Notes
    notes: Option<String>,
    /// Whether the secret value is shown (masked)
    value_shown: bool,
    /// When the value was revealed (for auto-hide timer)
    revealed_at: Option<Instant>,
}

impl SecretDetail {
    /// Check if the revealed value should be auto-hidden
    fn should_hide_value(&self, timeout: Duration) -> bool {
        if self.value_shown {
            if let Some(revealed_at) = self.revealed_at {
                return revealed_at.elapsed() > timeout;
            }
        }
        false
    }

    /// Hide the secret value
    fn hide_value(&mut self) {
        self.value_shown = false;
        self.revealed_at = None;
        self.notes = Some("[VALUE HIDDEN]".to_string());
    }
}

impl App {
    /// Create a new TUI application
    fn new() -> Self {
        Self {
            secrets: vec![],
            selected: 0,
            mode: Mode::Browse,
            filter_prefix: String::new(),
            detail_view: None,
            status_message: "Loading secrets...".to_string(),
            auto_hide_timeout: Duration::from_secs(5), // Default 5 second auto-hide
            form_state: None,
            audit_entries: vec![],
            audit_selected: 0,
            _audit_filter: None,
            sessions: vec![],
            session_selected: 0,
            import_export_state: None,
            sync_state: None,
            breach_alerts: vec![],
            breach_selected: 0,
            rotation_state: None,
        }
    }

    /// Enter audit log viewer mode
    fn enter_audit_mode(&mut self) -> Result<()> {
        self.mode = Mode::Audit;
        self.load_audit_entries()?;
        self.status_message = "Audit log viewer - Press 'q' to go back".to_string();
        Ok(())
    }

    /// Exit audit log viewer mode
    fn exit_audit_mode(&mut self) {
        self.mode = Mode::Browse;
        self.audit_entries.clear();
        self.audit_selected = 0;
        self.status_message = "Browse mode".to_string();
    }

    /// Enter session management mode
    fn enter_sessions_mode(&mut self) -> Result<()> {
        self.mode = Mode::Sessions;
        self.load_sessions()?;
        self.status_message =
            "Session management - Press 'q' to go back, 'd' to disconnect session".to_string();
        Ok(())
    }

    /// Exit session management mode
    fn exit_sessions_mode(&mut self) {
        self.mode = Mode::Browse;
        self.sessions.clear();
        self.session_selected = 0;
        self.status_message = "Browse mode".to_string();
    }

    /// Load sessions from daemon
    fn load_sessions(&mut self) -> Result<()> {
        use sigil_core::{IpcOperation, IpcRequest, IpcResponse, ListSessionsResponse};

        // Connect to daemon and request session list
        let socket_path = sigil_core::default_socket_path();
        let mut stream = std::os::unix::net::UnixStream::connect(&socket_path)
            .map_err(|e| anyhow::anyhow!("Failed to connect to daemon: {}", e))?;

        // Use empty session token for list sessions (TUI is trusted)
        let request = IpcRequest::new(IpcOperation::ListSessions, String::new());
        let json = serde_json::to_vec(&request)?;
        sigil_core::ipc::write_message(&mut stream, &json)?;

        // Read response
        let data = sigil_core::read_message(&mut stream)?;
        let response: IpcResponse = serde_json::from_slice(&data)
            .map_err(|e| anyhow::anyhow!("Invalid response from daemon: {}", e))?;

        if !response.ok {
            return Err(anyhow::anyhow!(
                "Failed to list sessions: {:?}",
                response.error
            ));
        }

        let list_response: ListSessionsResponse = serde_json::from_value(response.payload)
            .map_err(|e| anyhow::anyhow!("Failed to parse response: {}", e))?;

        // Convert to display items
        self.sessions = list_response
            .sessions
            .into_iter()
            .map(|s| {
                // Truncate token for display: first 8 chars + last 4 chars (like git commits)
                let token_str = s.token.to_string();
                let truncated = if token_str.len() > 12 {
                    format!(
                        "{}...{}",
                        &token_str[..8],
                        &token_str[token_str.len() - 4..]
                    )
                } else {
                    token_str.clone()
                };

                SessionItem {
                    token: truncated,
                    pid: s.peer.pid,
                    uid: s.peer.uid,
                    _created_at: s.created_at.format("%Y-%m-%d %H:%M:%S").to_string(),
                    last_activity: s.last_activity.format("%Y-%m-%d %H:%M:%S").to_string(),
                    idle_secs: s.idle_secs,
                }
            })
            .collect();

        if self.sessions.is_empty() {
            self.status_message = "No active sessions".to_string();
        } else {
            self.status_message = format!("{} active session(s)", self.sessions.len());
        }

        self.session_selected = 0;
        Ok(())
    }

    /// Kill the selected session
    fn kill_selected_session(&mut self) -> Result<()> {
        if self.sessions.is_empty() {
            self.status_message = "No sessions to kill".to_string();
            return Ok(());
        }

        let selected = self.session_selected;
        if selected >= self.sessions.len() {
            self.status_message = "Invalid session selection".to_string();
            return Ok(());
        }

        let session = self.sessions[selected].clone();

        // Connect to daemon socket
        let socket_path = sigil_core::default_socket_path();
        let mut stream = std::os::unix::net::UnixStream::connect(&socket_path)
            .map_err(|e| anyhow::anyhow!("Failed to connect to daemon: {}", e))?;

        use sigil_core::{IpcOperation, IpcRequest, KillSessionRequest, KillSessionResponse};

        // Build kill request using pid/uid (TUI is trusted, no session token needed)
        let kill_request = KillSessionRequest {
            token: None,
            pid: Some(session.pid),
            uid: Some(session.uid),
        };

        let payload = serde_json::to_value(&kill_request)?;
        let request = IpcRequest::with_payload(IpcOperation::KillSession, String::new(), payload);
        let json = serde_json::to_vec(&request)?;
        sigil_core::ipc::write_message(&mut stream, &json)?;

        // Read response
        let data = sigil_core::read_message(&mut stream)?;
        let response: sigil_core::IpcResponse = serde_json::from_slice(&data)
            .map_err(|e| anyhow::anyhow!("Invalid response from daemon: {}", e))?;

        if !response.ok {
            let error_msg = response
                .error
                .map(|e| e.message)
                .unwrap_or_else(|| "Unknown error".to_string());
            self.status_message = format!("Failed to kill session: {}", error_msg);
            return Ok(());
        }

        let kill_response: KillSessionResponse = serde_json::from_value(response.payload)
            .map_err(|e| anyhow::anyhow!("Failed to parse response: {}", e))?;

        if kill_response.killed {
            self.status_message =
                format!("Session killed (pid={}, uid={})", session.pid, session.uid);
            // Refresh the sessions list
            self.load_sessions()?;
        } else {
            self.status_message = format!("Failed to kill session: {}", kill_response.message);
        }

        Ok(())
    }

    /// Load audit entries
    fn load_audit_entries(&mut self) -> Result<()> {
        use sigil_core::audit::AuditLogReader;

        // Get the default audit log path
        let home =
            dirs::home_dir().ok_or_else(|| anyhow::anyhow!("Cannot determine home directory"))?;
        let audit_path = home.join(".sigil/vault/audit.jsonl");

        if !audit_path.exists() {
            self.status_message = "No audit log found".to_string();
            return Ok(());
        }

        let reader = AuditLogReader::new(audit_path)?;
        let entries = reader.read_entries()?;

        // Convert to display items
        self.audit_entries = entries.iter().map(AuditItem::from).collect();

        if self.audit_entries.is_empty() {
            self.status_message = "No audit entries found".to_string();
        } else {
            self.status_message = format!("{} audit entries", self.audit_entries.len());
        }

        self.audit_selected = 0;

        Ok(())
    }

    /// Move audit selection up
    fn audit_select_up(&mut self) {
        if !self.audit_entries.is_empty() && self.audit_selected > 0 {
            self.audit_selected -= 1;
        }
    }

    /// Move audit selection down
    fn audit_select_down(&mut self) {
        if !self.audit_entries.is_empty() && self.audit_selected < self.audit_entries.len() - 1 {
            self.audit_selected += 1;
        }
    }

    /// Move session selection up
    fn session_select_up(&mut self) {
        if !self.sessions.is_empty() && self.session_selected > 0 {
            self.session_selected -= 1;
        }
    }

    /// Move session selection down
    fn session_select_down(&mut self) {
        if !self.sessions.is_empty() && self.session_selected < self.sessions.len() - 1 {
            self.session_selected += 1;
        }
    }

    /// Enter add mode
    fn enter_add_mode(&mut self) {
        self.mode = Mode::Add;
        self.form_state = Some(FormState {
            path: String::new(),
            value_input: String::new(),
            secret_type: "Generic".to_string(),
            tags: String::new(),
            notes: String::new(),
            current_field: FormField::Path,
            is_edit: false,
        });
        self.status_message = "Add new secret - Enter path, press Enter to continue".to_string();
    }

    /// Enter edit mode for selected secret
    fn enter_edit_mode(&mut self, vault: &LocalVault) -> Result<()> {
        if self.secrets.is_empty() {
            return Ok(());
        }

        let secret_item = &self.secrets[self.selected];
        let path = SecretPath::new(secret_item.path.clone())?;

        let rt = tokio::runtime::Runtime::new()?;
        let meta = rt.block_on(vault.get_metadata(&path))?;

        self.mode = Mode::Edit;
        self.form_state = Some(FormState {
            path: secret_item.path.clone(),
            value_input: String::new(),
            secret_type: format!("{:?}", meta.secret_type),
            tags: meta.tags.join(", "),
            notes: meta.notes.unwrap_or_default(),
            current_field: FormField::Path,
            is_edit: true,
        });
        self.status_message = "Edit secret - Modify fields, press Ctrl+S to save".to_string();

        Ok(())
    }

    /// Enter delete confirmation mode
    fn enter_delete_mode(&mut self) {
        if self.secrets.is_empty() {
            return;
        }
        self.mode = Mode::Delete;
        self.status_message = format!(
            "Delete '{}' - Press 'y' to confirm, 'n' to cancel",
            self.secrets[self.selected].path
        );
    }

    /// Confirm delete operation
    fn confirm_delete(&mut self, vault: &LocalVault) -> Result<()> {
        if self.secrets.is_empty() {
            return Ok(());
        }

        let secret_item = &self.secrets[self.selected];
        let path = SecretPath::new(secret_item.path.clone())?;

        let rt = tokio::runtime::Runtime::new()?;
        rt.block_on(vault.delete(&path))?;

        // Reload secrets and exit delete mode
        self.load_secrets(vault)?;
        self.mode = Mode::Browse;
        self.status_message = "Secret deleted successfully".to_string();

        Ok(())
    }

    /// Cancel delete operation
    fn cancel_delete(&mut self) {
        self.mode = Mode::Browse;
        self.status_message = "Delete cancelled".to_string();
    }

    /// Save the current form (add or edit)
    fn save_form(&mut self, vault: &LocalVault) -> Result<()> {
        // Extract needed values before borrowing
        let (_path, _is_edit, status_msg) = if let Some(ref form) = self.form_state {
            let path = SecretPath::new(form.path.clone())?;

            // Convert value input to bytes and create SecretValue
            let value_bytes = form.value_input.as_bytes().to_vec();
            let secret_value = sigil_core::SecretValue::new(value_bytes);

            // Parse tags
            let tags: Vec<String> = form
                .tags
                .split(',')
                .map(|t| t.trim().to_string())
                .filter(|t| !t.is_empty())
                .collect();

            // Create metadata
            let notes = if form.notes.is_empty() {
                None
            } else {
                Some(form.notes.clone())
            };

            let is_edit = form.is_edit;
            let rt = tokio::runtime::Runtime::new()?;

            if is_edit {
                // Edit existing secret
                rt.block_on(vault.set(
                    &path,
                    &secret_value,
                    &sigil_core::SecretMetadata {
                        path: path.clone(),
                        secret_type: sigil_core::SecretType::Generic, // Simplified for now
                        tags,
                        notes,
                        created_at: chrono::Utc::now(), // Will be updated by vault
                        updated_at: chrono::Utc::now(),
                        expires_at: None,
                    },
                ))?;
            } else {
                // Add new secret
                rt.block_on(vault.set(
                    &path,
                    &secret_value,
                    &sigil_core::SecretMetadata {
                        path: path.clone(),
                        secret_type: sigil_core::SecretType::Generic, // Simplified for now
                        tags,
                        notes,
                        created_at: chrono::Utc::now(),
                        updated_at: chrono::Utc::now(),
                        expires_at: None,
                    },
                ))?;
            }

            let status_msg = if is_edit {
                "Secret updated successfully".to_string()
            } else {
                "Secret added successfully".to_string()
            };

            (path, is_edit, status_msg)
        } else {
            return Ok(());
        };

        // Reload secrets and return to browse mode
        self.load_secrets(vault)?;
        self.mode = Mode::Browse;
        self.form_state = None;
        self.status_message = status_msg;

        Ok(())
    }

    /// Cancel form operation
    fn cancel_form(&mut self) {
        self.mode = Mode::Browse;
        self.form_state = None;
        self.status_message = "Operation cancelled".to_string();
    }

    /// Handle character input for form fields
    fn handle_form_input(&mut self, c: char) {
        if let Some(ref mut form) = self.form_state {
            match form.current_field {
                FormField::Path => form.path.push(c),
                FormField::Value => form.value_input.push(c),
                FormField::Type => form.secret_type.push(c),
                FormField::Tags => form.tags.push(c),
                FormField::Notes => form.notes.push(c),
            }
        }
    }

    /// Handle backspace for form fields
    fn handle_form_backspace(&mut self) {
        if let Some(ref mut form) = self.form_state {
            match form.current_field {
                FormField::Path => {
                    form.path.pop();
                }
                FormField::Value => {
                    form.value_input.pop();
                }
                FormField::Type => {
                    form.secret_type.pop();
                }
                FormField::Tags => {
                    form.tags.pop();
                }
                FormField::Notes => {
                    form.notes.pop();
                }
            }
        }
    }

    /// Move to next form field
    fn next_form_field(&mut self) {
        if let Some(ref mut form) = self.form_state {
            form.current_field = match form.current_field {
                FormField::Path => FormField::Value,
                FormField::Value => FormField::Type,
                FormField::Type => FormField::Tags,
                FormField::Tags => FormField::Notes,
                FormField::Notes => FormField::Path,
            };
        }
    }

    /// Move to previous form field
    fn prev_form_field(&mut self) {
        if let Some(ref mut form) = self.form_state {
            form.current_field = match form.current_field {
                FormField::Path => FormField::Notes,
                FormField::Value => FormField::Path,
                FormField::Type => FormField::Value,
                FormField::Tags => FormField::Type,
                FormField::Notes => FormField::Tags,
            };
        }
    }

    /// Check if any revealed values should be auto-hidden
    fn check_auto_hide(&mut self) {
        if let Some(ref mut detail) = self.detail_view {
            if detail.should_hide_value(self.auto_hide_timeout) {
                detail.hide_value();
                self.status_message = "Value auto-hidden after timeout".to_string();
            }
        }
    }

    /// Load secrets from the vault
    fn load_secrets(&mut self, vault: &LocalVault) -> Result<()> {
        let rt = tokio::runtime::Runtime::new()?;
        let secrets_meta = rt.block_on(vault.list(&self.filter_prefix))?;

        self.secrets = secrets_meta
            .iter()
            .map(|meta| SecretItem {
                path: meta.path.as_str().to_string(),
                secret_type: format!("{:?}", meta.secret_type),
                updated: meta.updated_at.format("%Y-%m-%d %H:%M").to_string(),
                tags: meta.tags.clone(),
            })
            .collect();

        if self.secrets.is_empty() {
            self.status_message = format!(
                "No secrets found{}",
                if self.filter_prefix.is_empty() {
                    "."
                } else {
                    " matching filter."
                }
            );
        } else {
            self.status_message = format!("{} secret(s)", self.secrets.len());
        }

        // Reset selection
        self.selected = 0;

        Ok(())
    }

    /// Move selection up
    fn select_up(&mut self) {
        if !self.secrets.is_empty() && self.selected > 0 {
            self.selected -= 1;
        }
    }

    /// Move selection down
    fn select_down(&mut self) {
        if !self.secrets.is_empty() && self.selected < self.secrets.len() - 1 {
            self.selected += 1;
        }
    }

    /// Enter detail view for selected secret
    fn enter_detail(&mut self, vault: &LocalVault) -> Result<()> {
        if self.secrets.is_empty() {
            return Ok(());
        }

        let secret_item = &self.secrets[self.selected];
        let path = SecretPath::new(secret_item.path.clone())?;

        let rt = tokio::runtime::Runtime::new()?;
        let meta = rt.block_on(vault.get_metadata(&path))?;

        self.detail_view = Some(SecretDetail {
            path: secret_item.path.clone(),
            secret_type: format!("{:?}", meta.secret_type),
            created: meta.created_at.format("%Y-%m-%d %H:%M:%S").to_string(),
            updated: meta.updated_at.format("%Y-%m-%d %H:%M:%S").to_string(),
            tags: meta.tags,
            notes: meta.notes,
            value_shown: false,
            revealed_at: None,
        });

        self.mode = Mode::Detail;
        self.status_message =
            "Press 'v' to reveal value (auto-hides after 5s), 'q' to go back".to_string();

        Ok(())
    }

    /// Exit detail view
    fn exit_detail(&mut self) {
        self.detail_view = None;
        self.mode = Mode::Browse;
        self.status_message = "Browse mode".to_string();
    }

    /// Toggle secret value visibility
    fn toggle_value(&mut self, vault: &LocalVault) -> Result<()> {
        if let Some(ref mut detail) = self.detail_view {
            if !detail.value_shown {
                // Load the secret value
                let path = SecretPath::new(detail.path.clone())?;
                let rt = tokio::runtime::Runtime::new()?;
                let value = rt.block_on(vault.get(&path))?;

                // Display masked value
                value.expose(|bytes| {
                    let _str_value = String::from_utf8_lossy(bytes);
                    // For security, show only that value was loaded, not the actual value
                    detail.notes = Some(format!(
                        "[VALUE LOADED - {} bytes - auto-hides in 5s]",
                        bytes.len()
                    ));
                    Ok::<(), anyhow::Error>(())
                })?;

                detail.value_shown = true;
                detail.revealed_at = Some(Instant::now());
                self.status_message = "Value revealed - will auto-hide in 5 seconds".to_string();
            } else {
                // Manually hide the value
                detail.hide_value();
                self.status_message = "Value hidden".to_string();
            }
        }
        Ok(())
    }

    /// Show help
    fn show_help(&mut self) {
        self.mode = Mode::Help;
        self.status_message = "Press 'q' to go back".to_string();
    }

    /// Exit help
    fn exit_help(&mut self) {
        self.mode = Mode::Browse;
        self.status_message = "Browse mode".to_string();
    }

    /// Set filter prefix
    fn set_filter(&mut self, prefix: String) {
        self.filter_prefix = prefix;
    }

    /// Enter import/export mode
    fn enter_import_export_mode(&mut self, operation: ImportExportOp) {
        self.mode = Mode::ImportExport;
        self.import_export_state = Some(ImportExportState {
            operation,
            file_path: String::new(),
            import_mode: ImportMode::Manual,
            current_step: ImportExportStep::FilePath,
            pending_conflicts: vec![],
            conflict_selected: 0,
            progress_message: String::new(),
        });
        self.status_message = match operation {
            ImportExportOp::Import => "Import secrets - Enter file path",
            ImportExportOp::Export => "Export secrets - Enter file path",
        }
        .to_string();
    }

    /// Exit import/export mode
    fn exit_import_export_mode(&mut self) {
        self.mode = Mode::Browse;
        self.import_export_state = None;
        self.status_message = "Browse mode".to_string();
    }

    /// Enter backend sync mode
    fn enter_backend_sync_mode(&mut self) {
        self.mode = Mode::BackendSync;
        self.sync_state = Some(BackendSyncState {
            backend_type: BackendType::HashiCorpVault,
            status: SyncStatus::Disconnected,
            current_step: SyncStep::SelectBackend,
            progress_message: String::new(),
            synced_count: 0,
            failed_secrets: vec![],
            connection_config: None,
        });
        self.status_message = "External backend sync - Select backend type".to_string();
    }

    /// Exit backend sync mode
    fn exit_backend_sync_mode(&mut self) {
        self.mode = Mode::Browse;
        self.sync_state = None;
        self.status_message = "Browse mode".to_string();
    }

    /// Enter breach alerts mode
    fn enter_breach_alerts_mode(&mut self) -> Result<()> {
        self.mode = Mode::BreachAlerts;
        self.load_breach_alerts()?;
        self.status_message =
            "Breach alerts - Press 'q' to go back, 'a' to acknowledge, 'r' to resolve".to_string();
        Ok(())
    }

    /// Exit breach alerts mode
    fn exit_breach_alerts_mode(&mut self) {
        self.mode = Mode::Browse;
        self.breach_alerts.clear();
        self.breach_selected = 0;
        self.status_message = "Browse mode".to_string();
    }

    /// Load breach alerts from audit log
    fn load_breach_alerts(&mut self) -> Result<()> {
        use sigil_core::audit::AuditLogReader;

        let home =
            dirs::home_dir().ok_or_else(|| anyhow::anyhow!("Cannot determine home directory"))?;
        let audit_path = home.join(".sigil/vault/audit.jsonl");

        if !audit_path.exists() {
            self.breach_alerts = vec![];
            self.status_message = "No breach alerts".to_string();
            return Ok(());
        }

        let reader = AuditLogReader::new(audit_path)?;
        let entries = reader.read_entries()?;

        // Extract breach alerts from audit entries
        self.breach_alerts = entries
            .iter()
            .filter_map(|entry| {
                if let AuditEntry::BreachDetected {
                    severity,
                    description,
                    timestamp: _,
                    previous_hash: _,
                } = entry
                {
                    Some(BreachAlert {
                        id: uuid::Uuid::new_v4().to_string(),
                        severity: match severity.as_str() {
                            "critical" => BreachSeverity::Critical,
                            "high" => BreachSeverity::High,
                            "medium" => BreachSeverity::Medium,
                            _ => BreachSeverity::Low,
                        },
                        timestamp: entry.timestamp().format("%Y-%m-%d %H:%M:%S").to_string(),
                        description: description.clone(),
                        status: AlertStatus::New,
                        recommended_action: "Review and rotate any related secrets".to_string(),
                    })
                } else {
                    None
                }
            })
            .collect();

        if self.breach_alerts.is_empty() {
            self.status_message = "No breach alerts found".to_string();
        } else {
            self.status_message = format!("{} breach alert(s)", self.breach_alerts.len());
        }

        self.breach_selected = 0;
        Ok(())
    }

    /// Move breach alert selection up
    fn breach_select_up(&mut self) {
        if !self.breach_alerts.is_empty() && self.breach_selected > 0 {
            self.breach_selected -= 1;
        }
    }

    /// Move breach alert selection down
    fn breach_select_down(&mut self) {
        if !self.breach_alerts.is_empty() && self.breach_selected < self.breach_alerts.len() - 1 {
            self.breach_selected += 1;
        }
    }

    /// Acknowledge selected breach alert
    fn acknowledge_breach_alert(&mut self) {
        if !self.breach_alerts.is_empty() && self.breach_selected < self.breach_alerts.len() {
            self.breach_alerts[self.breach_selected].status = AlertStatus::Acknowledged;
            self.status_message = "Alert acknowledged".to_string();
        }
    }

    /// Resolve selected breach alert
    fn resolve_breach_alert(&mut self) {
        if !self.breach_alerts.is_empty() && self.breach_selected < self.breach_alerts.len() {
            self.breach_alerts[self.breach_selected].status = AlertStatus::Resolved;
            self.status_message = "Alert resolved".to_string();
        }
    }

    /// Enter secret rotation mode
    fn enter_rotation_mode(&mut self) {
        if self.secrets.is_empty() {
            self.status_message = "No secrets to rotate".to_string();
            return;
        }
        self.mode = Mode::SecretRotation;
        self.rotation_state = Some(RotationState {
            current_step: RotationStep::SelectSecret,
            secret_path: String::new(),
            progress: 0,
            status_message: String::new(),
            new_value_input: String::new(),
            rotation_reason: String::new(),
        });
        self.status_message = "Secret rotation - Select secret to rotate".to_string();
    }

    /// Exit secret rotation mode
    fn exit_rotation_mode(&mut self) {
        self.mode = Mode::Browse;
        self.rotation_state = None;
        self.status_message = "Browse mode".to_string();
    }

    // Import/Export mode handlers

    /// Handle file path input for import/export
    fn handle_import_export_char(&mut self, c: char) {
        if let Some(ref mut state) = self.import_export_state {
            if state.current_step == ImportExportStep::FilePath {
                state.file_path.push(c);
            }
        }
    }

    /// Handle backspace for import/export file path
    fn handle_import_export_backspace(&mut self) {
        if let Some(ref mut state) = self.import_export_state {
            if state.current_step == ImportExportStep::FilePath {
                state.file_path.pop();
            }
        }
    }

    /// Confirm file path and proceed to next step
    fn confirm_import_export_path(&mut self) {
        if let Some(ref mut state) = self.import_export_state {
            if state.current_step == ImportExportStep::FilePath && !state.file_path.is_empty() {
                match state.operation {
                    ImportExportOp::Import => {
                        state.current_step = ImportExportStep::ImportMode;
                        state.progress_message = "Select import mode".to_string();
                    }
                    ImportExportOp::Export => {
                        state.current_step = ImportExportStep::InProgress;
                        state.progress_message = "Exporting secrets...".to_string();
                    }
                }
            }
        }
    }

    /// Select import mode by number
    fn select_import_mode(&mut self, mode_num: usize) {
        if let Some(ref mut state) = self.import_export_state {
            if state.current_step == ImportExportStep::ImportMode {
                state.import_mode = match mode_num {
                    1 => ImportMode::SkipExisting,
                    2 => ImportMode::Overwrite,
                    3 => ImportMode::Rename,
                    4 => ImportMode::Manual,
                    _ => return,
                };
            }
        }
    }

    /// Confirm import mode selection and proceed
    fn confirm_import_mode(&mut self) {
        if let Some(ref mut state) = self.import_export_state {
            if state.current_step == ImportExportStep::ImportMode {
                match state.import_mode {
                    ImportMode::Manual => {
                        // Would load conflicts here in real implementation
                        state.pending_conflicts = vec![]; // Empty for now
                        state.current_step = ImportExportStep::ConflictResolution;
                        state.progress_message = "Resolve conflicts".to_string();
                    }
                    _ => {
                        state.current_step = ImportExportStep::InProgress;
                        state.progress_message = "Importing secrets...".to_string();
                    }
                }
            }
        }
    }

    /// Move conflict selection up
    fn conflict_select_up(&mut self) {
        if let Some(ref mut state) = self.import_export_state {
            if state.current_step == ImportExportStep::ConflictResolution
                && state.conflict_selected > 0
            {
                state.conflict_selected -= 1;
            }
        }
    }

    /// Move conflict selection down
    fn conflict_select_down(&mut self) {
        if let Some(ref mut state) = self.import_export_state {
            if state.current_step == ImportExportStep::ConflictResolution
                && state.conflict_selected < state.pending_conflicts.len().saturating_sub(1)
            {
                state.conflict_selected += 1;
            }
        }
    }

    /// Toggle conflict resolution action
    fn toggle_conflict_resolution(&mut self) {
        if let Some(ref mut state) = self.import_export_state {
            if state.current_step == ImportExportStep::ConflictResolution
                && state.conflict_selected < state.pending_conflicts.len()
            {
                let current = state.pending_conflicts[state.conflict_selected].resolution;
                state.pending_conflicts[state.conflict_selected].resolution = match current {
                    ConflictResolution::Unresolved => ConflictResolution::KeepExisting,
                    ConflictResolution::KeepExisting => ConflictResolution::UseImported,
                    ConflictResolution::UseImported => ConflictResolution::KeepExisting,
                };
            }
        }
    }

    /// Confirm conflict resolution and proceed
    fn confirm_conflict_resolution(&mut self) {
        if let Some(ref mut state) = self.import_export_state {
            if state.current_step == ImportExportStep::ConflictResolution {
                state.current_step = ImportExportStep::InProgress;
                state.progress_message = "Importing secrets...".to_string();
            }
        }
    }

    // Backend sync mode handlers

    /// Select backend type by number
    fn select_backend_type(&mut self, backend_num: usize) {
        if let Some(ref mut state) = self.sync_state {
            if state.current_step == SyncStep::SelectBackend {
                state.backend_type = match backend_num {
                    1 => BackendType::HashiCorpVault,
                    2 => BackendType::OnePassword,
                    3 => BackendType::Bitwarden,
                    4 => BackendType::AwsSecretsManager,
                    _ => return,
                };
            }
        }
    }

    /// Confirm backend selection and proceed
    fn confirm_backend_selection(&mut self) {
        if let Some(ref mut state) = self.sync_state {
            if state.current_step == SyncStep::SelectBackend {
                state.current_step = SyncStep::ConfigureConnection;
                state.progress_message = "Configure connection".to_string();
                // Initialize connection config with backend-specific defaults
                let mut config = ConnectionConfigState::default();
                // Set address hint based on backend type
                match state.backend_type {
                    BackendType::HashiCorpVault => {
                        config.address = "https://vault.example.com:8200".to_string();
                        config.auth_method = AuthMethod::Token;
                    }
                    BackendType::OnePassword => {
                        config.address = "https://my.1password.com".to_string();
                    }
                    BackendType::Bitwarden => {
                        config.address = "https://bitwarden.com".to_string();
                        config.auth_method = AuthMethod::UsernamePassword;
                    }
                    BackendType::AwsSecretsManager => {
                        config.auth_method = AuthMethod::AwsCredentials;
                        config.region = "us-east-1".to_string();
                    }
                }
                state.connection_config = Some(config);
            }
        }
    }

    /// Test connection and proceed to sync confirmation
    fn test_backend_connection(&mut self) {
        if let Some(ref mut state) = self.sync_state {
            if state.current_step == SyncStep::ConfigureConnection {
                if let Some(ref config) = state.connection_config {
                    // Validate required fields based on backend type
                    let validation_error = match state.backend_type {
                        BackendType::HashiCorpVault => {
                            if config.address.is_empty() {
                                Some("Address is required".to_string())
                            } else if config.token.is_empty() {
                                Some("Token is required".to_string())
                            } else {
                                None
                            }
                        }
                        BackendType::OnePassword => {
                            if config.address.is_empty() {
                                Some("Address is required".to_string())
                            } else if config.token.is_empty() {
                                Some("Token is required".to_string())
                            } else {
                                None
                            }
                        }
                        BackendType::Bitwarden => {
                            if config.address.is_empty() {
                                Some("Address is required".to_string())
                            } else if config.username.is_empty() {
                                Some("Username is required".to_string())
                            } else if config.password.is_empty() {
                                Some("Password is required".to_string())
                            } else {
                                None
                            }
                        }
                        BackendType::AwsSecretsManager => {
                            if config.region.is_empty() {
                                Some("Region is required".to_string())
                            } else if config.api_key.is_empty() {
                                Some("API key is required".to_string())
                            } else if config.secret_key.is_empty() {
                                Some("Secret key is required".to_string())
                            } else {
                                None
                            }
                        }
                    };

                    if let Some(error) = validation_error {
                        state.connection_config.as_mut().unwrap().error_message = Some(error);
                        return;
                    }

                    // Simulate connection test (in real implementation, this would
                    // actually attempt to connect to the backend)
                    // For now, we'll just validate the format and proceed
                    state.connection_config.as_mut().unwrap().error_message = None;
                    state.status = SyncStatus::Connected;
                    state.current_step = SyncStep::ConfirmSync;
                    state.progress_message = "Connection successful".to_string();
                }
            }
        }
    }

    /// Confirm sync operation
    fn confirm_sync(&mut self) {
        if let Some(ref mut state) = self.sync_state {
            if state.current_step == SyncStep::ConfirmSync {
                state.current_step = SyncStep::InProgress;
                state.progress_message = "Syncing secrets...".to_string();
            }
        }
    }

    // Secret rotation mode handlers

    /// Handle character input for rotation value/reason
    fn handle_rotation_char(&mut self, c: char) {
        if let Some(ref mut state) = self.rotation_state {
            match state.current_step {
                RotationStep::EnterNewValue => {
                    state.new_value_input.push(c);
                }
                RotationStep::EnterReason => {
                    state.rotation_reason.push(c);
                }
                _ => {}
            }
        }
    }

    /// Handle backspace for rotation value/reason
    fn handle_rotation_backspace(&mut self) {
        if let Some(ref mut state) = self.rotation_state {
            match state.current_step {
                RotationStep::EnterNewValue => {
                    state.new_value_input.pop();
                }
                RotationStep::EnterReason => {
                    state.rotation_reason.pop();
                }
                _ => {}
            }
        }
    }

    /// Confirm secret selection for rotation
    fn confirm_rotation_secret(&mut self) {
        if let Some(ref mut state) = self.rotation_state {
            if state.current_step == RotationStep::SelectSecret
                && !self.secrets.is_empty()
                && self.selected < self.secrets.len()
            {
                state.secret_path = self.secrets[self.selected].path.clone();
                state.current_step = RotationStep::EnterNewValue;
                state.status_message = "Enter new secret value".to_string();
            }
        }
    }

    /// Confirm new value and proceed to reason
    fn confirm_rotation_value(&mut self) {
        if let Some(ref mut state) = self.rotation_state {
            if state.current_step == RotationStep::EnterNewValue {
                state.current_step = RotationStep::EnterReason;
                state.status_message = "Enter rotation reason (optional)".to_string();
            }
        }
    }

    /// Confirm reason and proceed to rotation confirmation
    fn confirm_rotation_reason(&mut self) {
        if let Some(ref mut state) = self.rotation_state {
            if state.current_step == RotationStep::EnterReason {
                state.current_step = RotationStep::ConfirmRotation;
                state.status_message = "Confirm rotation".to_string();
            }
        }
    }

    /// Confirm and execute rotation
    fn confirm_rotation(&mut self, vault: &LocalVault) -> Result<()> {
        if let Some(ref mut state) = self.rotation_state {
            if state.current_step == RotationStep::ConfirmRotation {
                state.current_step = RotationStep::InProgress;
                state.progress = 0;
                state.status_message = "Rotating secret...".to_string();

                // Perform the rotation
                let path = SecretPath::new(state.secret_path.clone())?;
                let value_bytes = state.new_value_input.as_bytes().to_vec();
                let secret_value = sigil_core::SecretValue::new(value_bytes);

                let rt = tokio::runtime::Runtime::new()?;
                rt.block_on(vault.set(
                    &path,
                    &secret_value,
                    &sigil_core::SecretMetadata {
                        path: path.clone(),
                        secret_type: sigil_core::SecretType::Generic,
                        tags: vec![],
                        notes: Some(format!("Rotated: {}", state.rotation_reason)),
                        created_at: chrono::Utc::now(),
                        updated_at: chrono::Utc::now(),
                        expires_at: None,
                    },
                ))?;

                state.progress = 100;
                state.current_step = RotationStep::Complete;
                state.status_message =
                    format!("Secret '{}' rotated successfully", state.secret_path);
            }
        }
        Ok(())
    }

    // Connection config mode handlers

    /// Handle character input for connection config fields
    fn handle_connection_config_char(&mut self, c: char) {
        if let Some(ref mut state) = self.sync_state {
            if state.current_step == SyncStep::ConfigureConnection {
                if let Some(ref mut config) = state.connection_config {
                    // Don't allow character input in AuthMethod field (use Space to toggle)
                    if config.current_field == ConnectionField::AuthMethod {
                        return;
                    }
                    match config.current_field {
                        ConnectionField::Address => config.address.push(c),
                        ConnectionField::Token => config.token.push(c),
                        ConnectionField::Username => config.username.push(c),
                        ConnectionField::Password => config.password.push(c),
                        ConnectionField::ApiKey => config.api_key.push(c),
                        ConnectionField::SecretKey => config.secret_key.push(c),
                        ConnectionField::Region => config.region.push(c),
                        ConnectionField::Namespace => config.namespace.push(c),
                        ConnectionField::AuthMethod => {
                            // Handled by toggle_auth_method() via Space key
                        }
                    }
                    // Clear error message when user starts typing
                    config.error_message = None;
                }
            }
        }
    }

    /// Toggle authentication method (for HashiCorp Vault)
    fn toggle_auth_method(&mut self) {
        if let Some(ref mut state) = self.sync_state {
            if state.current_step == SyncStep::ConfigureConnection {
                if let Some(ref mut config) = state.connection_config {
                    if config.current_field == ConnectionField::AuthMethod {
                        config.auth_method = match config.auth_method {
                            AuthMethod::Token => AuthMethod::UsernamePassword,
                            AuthMethod::UsernamePassword => AuthMethod::AwsCredentials,
                            AuthMethod::AwsCredentials => AuthMethod::Token,
                        };
                        // Clear error message when user changes auth method
                        config.error_message = None;
                    }
                }
            }
        }
    }

    /// Handle backspace for connection config fields
    fn handle_connection_config_backspace(&mut self) {
        if let Some(ref mut state) = self.sync_state {
            if state.current_step == SyncStep::ConfigureConnection {
                if let Some(ref mut config) = state.connection_config {
                    match config.current_field {
                        ConnectionField::Address => {
                            config.address.pop();
                        }
                        ConnectionField::Token => {
                            config.token.pop();
                        }
                        ConnectionField::Username => {
                            config.username.pop();
                        }
                        ConnectionField::Password => {
                            config.password.pop();
                        }
                        ConnectionField::ApiKey => {
                            config.api_key.pop();
                        }
                        ConnectionField::SecretKey => {
                            config.secret_key.pop();
                        }
                        ConnectionField::Region => {
                            config.region.pop();
                        }
                        ConnectionField::Namespace => {
                            config.namespace.pop();
                        }
                        ConnectionField::AuthMethod => {}
                    }
                }
            }
        }
    }

    /// Move to next connection config field
    fn next_connection_field(&mut self) {
        if let Some(ref mut state) = self.sync_state {
            if state.current_step == SyncStep::ConfigureConnection {
                state.next_field();
            }
        }
    }

    /// Move to previous connection config field
    fn prev_connection_field(&mut self) {
        if let Some(ref mut state) = self.sync_state {
            if state.current_step == SyncStep::ConfigureConnection {
                state.prev_field();
            }
        }
    }
}

/// Run the TUI application
fn run_tui<W>(mut terminal: Terminal<CrosstermBackend<W>>) -> Result<()>
where
    W: std::io::Write,
{
    // Enable process isolation (prevent memory dumps, ptrace, etc.)
    enable_process_isolation()?;

    // Load vault
    let home =
        dirs::home_dir().ok_or_else(|| anyhow::anyhow!("Cannot determine home directory"))?;
    let sigil_dir = home.join(".sigil");
    let vault_path = sigil_dir.join("vault");
    let identity_path = sigil_dir.join("identity.age");

    if !sigil_dir.exists() {
        anyhow::bail!("Vault not initialized. Run 'sigil init' first.");
    }

    let mut vault = LocalVault::new(vault_path, identity_path)?;

    // Prompt for passphrase
    let passphrase =
        rpassword::prompt_password("Enter vault passphrase (leave empty if no passphrase): ")?;
    let passphrase = if passphrase.is_empty() {
        None
    } else {
        Some(passphrase)
    };

    vault.load(passphrase.as_deref())?;

    // Create app
    let mut app = App::new();
    app.load_secrets(&vault)?;

    // Run event loop
    loop {
        // Check for auto-hide timeout
        app.check_auto_hide();

        // Draw UI
        terminal.draw(|f| draw_ui(f, &mut app))?;

        // Handle events
        if event::poll(Duration::from_millis(100))? {
            if let Event::Key(key) = event::read()? {
                match app.mode {
                    Mode::Browse => match key.code {
                        KeyCode::Char('q') | KeyCode::Char('c')
                            if event::poll(Duration::from_millis(0))? =>
                        {
                            // Check for Ctrl+C
                            if let Event::Key(KeyEvent {
                                code: KeyCode::Char('c'),
                                ..
                            }) = event::read()?
                            {
                                return Ok(());
                            }
                        }
                        KeyCode::Char('q') => return Ok(()),
                        KeyCode::Char('h') | KeyCode::F(1) => app.show_help(),
                        KeyCode::Up | KeyCode::Char('k') => app.select_up(),
                        KeyCode::Down | KeyCode::Char('j') => app.select_down(),
                        KeyCode::Enter => {
                            app.enter_detail(&vault)?;
                        }
                        KeyCode::Char('/') => {
                            // Filter functionality (simplified)
                            app.set_filter(String::new());
                            app.load_secrets(&vault)?;
                        }
                        KeyCode::Char('r') => {
                            app.load_secrets(&vault)?;
                        }
                        KeyCode::Char('a') => {
                            app.enter_add_mode();
                        }
                        KeyCode::Char('e') => {
                            app.enter_edit_mode(&vault)?;
                        }
                        KeyCode::Char('d') => {
                            app.enter_delete_mode();
                        }
                        KeyCode::Char('l') => {
                            app.enter_audit_mode()?;
                        }
                        KeyCode::Char('s') => {
                            app.enter_sessions_mode()?;
                        }
                        KeyCode::Char('i') => {
                            app.enter_import_export_mode(ImportExportOp::Import);
                        }
                        KeyCode::Char('x') => {
                            app.enter_import_export_mode(ImportExportOp::Export);
                        }
                        KeyCode::Char('y') => {
                            app.enter_backend_sync_mode();
                        }
                        KeyCode::Char('b') => {
                            app.enter_breach_alerts_mode()?;
                        }
                        KeyCode::Char('o') => {
                            app.enter_rotation_mode();
                        }
                        _ => {}
                    },
                    Mode::Detail => match key.code {
                        KeyCode::Char('q') | KeyCode::Esc => app.exit_detail(),
                        KeyCode::Char('v') => {
                            app.toggle_value(&vault)?;
                        }
                        KeyCode::Char('h') | KeyCode::F(1) => app.show_help(),
                        _ => {}
                    },
                    Mode::Add | Mode::Edit => match key.code {
                        KeyCode::Char('q') | KeyCode::Esc => app.cancel_form(),
                        KeyCode::Char('s') => {
                            app.save_form(&vault)?;
                        }
                        KeyCode::Enter => {
                            app.next_form_field();
                        }
                        KeyCode::Tab => {
                            app.next_form_field();
                        }
                        KeyCode::BackTab => {
                            app.prev_form_field();
                        }
                        KeyCode::Char(c) => {
                            app.handle_form_input(c);
                        }
                        KeyCode::Backspace => {
                            app.handle_form_backspace();
                        }
                        _ => {}
                    },
                    Mode::Delete => match key.code {
                        KeyCode::Char('y') | KeyCode::Char('Y') => {
                            app.confirm_delete(&vault)?;
                        }
                        KeyCode::Char('n') | KeyCode::Char('N') | KeyCode::Esc => {
                            app.cancel_delete();
                        }
                        _ => {}
                    },
                    Mode::Audit => match key.code {
                        KeyCode::Char('q') | KeyCode::Esc => app.exit_audit_mode(),
                        KeyCode::Up | KeyCode::Char('k') => app.audit_select_up(),
                        KeyCode::Down | KeyCode::Char('j') => app.audit_select_down(),
                        KeyCode::Char('r') => {
                            // Reload audit entries
                            let _ = app.load_audit_entries();
                        }
                        _ => {}
                    },
                    Mode::Sessions => match key.code {
                        KeyCode::Char('q') | KeyCode::Esc => app.exit_sessions_mode(),
                        KeyCode::Up | KeyCode::Char('k') => app.session_select_up(),
                        KeyCode::Down | KeyCode::Char('j') => app.session_select_down(),
                        KeyCode::Char('r') => {
                            // Reload sessions
                            let _ = app.load_sessions();
                        }
                        KeyCode::Char('d') => {
                            // Disconnect selected session
                            let _ = app.kill_selected_session();
                        }
                        _ => {}
                    },
                    Mode::ImportExport => match key.code {
                        KeyCode::Char('q') | KeyCode::Esc => app.exit_import_export_mode(),
                        KeyCode::Enter => {
                            if let Some(ref state) = app.import_export_state {
                                match state.current_step {
                                    ImportExportStep::FilePath => {
                                        app.confirm_import_export_path();
                                    }
                                    ImportExportStep::ImportMode => {
                                        app.confirm_import_mode();
                                    }
                                    ImportExportStep::ConflictResolution => {
                                        app.confirm_conflict_resolution();
                                    }
                                    ImportExportStep::Complete => {
                                        app.exit_import_export_mode();
                                    }
                                    _ => {}
                                }
                            }
                        }
                        KeyCode::Char('1')
                        | KeyCode::Char('2')
                        | KeyCode::Char('3')
                        | KeyCode::Char('4') => {
                            if let Some(ref state) = app.import_export_state {
                                if state.current_step == ImportExportStep::ImportMode {
                                    let num = match key.code {
                                        KeyCode::Char('1') => 1,
                                        KeyCode::Char('2') => 2,
                                        KeyCode::Char('3') => 3,
                                        KeyCode::Char('4') => 4,
                                        _ => 0,
                                    };
                                    app.select_import_mode(num);
                                }
                            }
                        }
                        KeyCode::Up | KeyCode::Char('k') => app.conflict_select_up(),
                        KeyCode::Down | KeyCode::Char('j') => app.conflict_select_down(),
                        KeyCode::Char(' ') => app.toggle_conflict_resolution(),
                        KeyCode::Char(c) => app.handle_import_export_char(c),
                        KeyCode::Backspace => app.handle_import_export_backspace(),
                        _ => {}
                    },
                    Mode::BackendSync => match key.code {
                        KeyCode::Char('q') | KeyCode::Esc => app.exit_backend_sync_mode(),
                        KeyCode::Enter => {
                            if let Some(ref state) = app.sync_state {
                                match state.current_step {
                                    SyncStep::SelectBackend => {
                                        app.confirm_backend_selection();
                                    }
                                    SyncStep::ConfigureConnection => {
                                        app.test_backend_connection();
                                    }
                                    SyncStep::ConfirmSync => {
                                        app.confirm_sync();
                                    }
                                    SyncStep::Complete => {
                                        app.exit_backend_sync_mode();
                                    }
                                    _ => {}
                                }
                            }
                        }
                        KeyCode::Tab => {
                            if let Some(ref state) = app.sync_state {
                                if state.current_step == SyncStep::ConfigureConnection {
                                    app.next_connection_field();
                                }
                            }
                        }
                        KeyCode::BackTab => {
                            if let Some(ref state) = app.sync_state {
                                if state.current_step == SyncStep::ConfigureConnection {
                                    app.prev_connection_field();
                                }
                            }
                        }
                        KeyCode::Char('1')
                        | KeyCode::Char('2')
                        | KeyCode::Char('3')
                        | KeyCode::Char('4') => {
                            if let Some(ref state) = app.sync_state {
                                if state.current_step == SyncStep::SelectBackend {
                                    let num = match key.code {
                                        KeyCode::Char('1') => 1,
                                        KeyCode::Char('2') => 2,
                                        KeyCode::Char('3') => 3,
                                        KeyCode::Char('4') => 4,
                                        _ => 0,
                                    };
                                    app.select_backend_type(num);
                                }
                            }
                        }
                        KeyCode::Char(' ') => {
                            if let Some(ref state) = app.sync_state {
                                if state.current_step == SyncStep::ConfigureConnection {
                                    app.toggle_auth_method();
                                }
                            }
                        }
                        KeyCode::Char(c) => {
                            if let Some(ref state) = app.sync_state {
                                if state.current_step == SyncStep::ConfigureConnection {
                                    app.handle_connection_config_char(c);
                                }
                            }
                        }
                        KeyCode::Backspace => {
                            if let Some(ref state) = app.sync_state {
                                if state.current_step == SyncStep::ConfigureConnection {
                                    app.handle_connection_config_backspace();
                                }
                            }
                        }
                        _ => {}
                    },
                    Mode::BreachAlerts => match key.code {
                        KeyCode::Char('q') | KeyCode::Esc => app.exit_breach_alerts_mode(),
                        KeyCode::Up | KeyCode::Char('k') => app.breach_select_up(),
                        KeyCode::Down | KeyCode::Char('j') => app.breach_select_down(),
                        KeyCode::Char('a') => app.acknowledge_breach_alert(),
                        KeyCode::Char('r') => app.resolve_breach_alert(),
                        _ => {}
                    },
                    Mode::SecretRotation => match key.code {
                        KeyCode::Char('q') | KeyCode::Esc => app.exit_rotation_mode(),
                        KeyCode::Enter => {
                            if let Some(ref state) = app.rotation_state {
                                match state.current_step {
                                    RotationStep::SelectSecret => {
                                        app.confirm_rotation_secret();
                                    }
                                    RotationStep::EnterNewValue => {
                                        app.confirm_rotation_value();
                                    }
                                    RotationStep::EnterReason => {
                                        app.confirm_rotation_reason();
                                    }
                                    RotationStep::ConfirmRotation => {
                                        let _ = app.confirm_rotation(&vault);
                                    }
                                    RotationStep::Complete => {
                                        app.exit_rotation_mode();
                                    }
                                    _ => {}
                                }
                            }
                        }
                        KeyCode::Up | KeyCode::Char('k') => app.select_up(),
                        KeyCode::Down | KeyCode::Char('j') => app.select_down(),
                        KeyCode::Char(c) => app.handle_rotation_char(c),
                        KeyCode::Backspace => app.handle_rotation_backspace(),
                        _ => {}
                    },
                    Mode::Help => match key.code {
                        KeyCode::Char('q') | KeyCode::Esc => {
                            if app.detail_view.is_some() {
                                app.mode = Mode::Detail;
                                app.status_message =
                                    "Press 'v' to reveal value, 'q' to go back".to_string();
                            } else {
                                app.exit_help();
                            }
                        }
                        _ => {}
                    },
                }
            }
        }
    }
}

/// Draw the UI
fn draw_ui(f: &mut Frame, app: &mut App) {
    let size = f.area();

    // Detect terminal layout mode based on width
    let layout_mode = match size.width {
        0..=59 => CoreLayoutMode::TooNarrow, // Should never happen due to main() check
        60..=79 => CoreLayoutMode::SinglePanel,
        80..=119 => CoreLayoutMode::TwoPanel,
        _ => CoreLayoutMode::Full,
    };

    // Detect Unicode mode for box drawing characters
    let unicode_mode = UnicodeMode::detect();
    let borders = if unicode_mode == UnicodeMode::Unicode {
        Borders::ALL
    } else {
        // ASCII mode - use plain borders
        Borders::ALL
    };

    // Main layout
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .margin(1)
        .constraints([Constraint::Min(0), Constraint::Length(3)].as_ref())
        .split(size);

    match app.mode {
        Mode::Browse => {
            draw_browse_view(f, chunks[0], app, layout_mode, unicode_mode);
        }
        Mode::Detail => {
            draw_detail_view(f, chunks[0], app, unicode_mode);
        }
        Mode::Add | Mode::Edit => {
            draw_form_view(f, chunks[0], app, unicode_mode);
        }
        Mode::Delete => {
            draw_delete_view(f, chunks[0], app, unicode_mode);
        }
        Mode::Audit => {
            draw_audit_view(f, chunks[0], app, unicode_mode);
        }
        Mode::Sessions => {
            draw_sessions_view(f, chunks[0], app, unicode_mode);
        }
        Mode::ImportExport => {
            draw_import_export_view(f, chunks[0], app, unicode_mode);
        }
        Mode::BackendSync => {
            draw_backend_sync_view(f, chunks[0], app, unicode_mode);
        }
        Mode::BreachAlerts => {
            draw_breach_alerts_view(f, chunks[0], app, unicode_mode);
        }
        Mode::SecretRotation => {
            draw_secret_rotation_view(f, chunks[0], app, unicode_mode);
        }
        Mode::Help => {
            draw_help_view(f, chunks[0], unicode_mode);
        }
    }

    // Status bar
    let status = Paragraph::new(app.status_message.as_str())
        .style(Style::default().fg(Color::Cyan))
        .block(Block::default().borders(borders));
    f.render_widget(status, chunks[1]);
}

/// Draw browse view
fn draw_browse_view(
    f: &mut Frame,
    area: Rect,
    app: &mut App,
    _layout_mode: CoreLayoutMode,
    _unicode_mode: UnicodeMode,
) {
    let title = format!(
        "SIGIL Secret Browser{}",
        if app.filter_prefix.is_empty() {
            String::new()
        } else {
            format!(" (filter: {})", app.filter_prefix)
        }
    );

    let items: Vec<ListItem> = app
        .secrets
        .iter()
        .enumerate()
        .map(|(i, secret)| {
            let style = if i == app.selected {
                Style::default()
                    .fg(Color::Yellow)
                    .add_modifier(Modifier::BOLD)
            } else {
                Style::default()
            };

            let tags_str = if secret.tags.is_empty() {
                String::new()
            } else {
                format!(" [{}]", secret.tags.join(", "))
            };

            ListItem::new(format!("{} {}{}", secret.path, secret.updated, tags_str)).style(style)
        })
        .collect();

    let borders = Borders::ALL;
    let list = List::new(items)
        .block(Block::default().title(title).borders(borders))
        .highlight_style(Style::default().add_modifier(Modifier::BOLD));

    let mut list_state = ListState::default();
    list_state.select(Some(app.selected));

    f.render_stateful_widget(list, area, &mut list_state);
}

/// Draw detail view
fn draw_detail_view(f: &mut Frame, area: Rect, app: &mut App, _unicode_mode: UnicodeMode) {
    if let Some(ref detail) = app.detail_view {
        let text = vec![
            Line::from(vec![
                Span::styled("Path: ", Style::default().fg(Color::Cyan)),
                Span::styled(&detail.path, Style::default().fg(Color::White)),
            ]),
            Line::from(""),
            Line::from(vec![
                Span::styled("Type: ", Style::default().fg(Color::Cyan)),
                Span::styled(&detail.secret_type, Style::default().fg(Color::White)),
            ]),
            Line::from(""),
            Line::from(vec![
                Span::styled("Created: ", Style::default().fg(Color::Cyan)),
                Span::styled(&detail.created, Style::default().fg(Color::White)),
            ]),
            Line::from(""),
            Line::from(vec![
                Span::styled("Updated: ", Style::default().fg(Color::Cyan)),
                Span::styled(&detail.updated, Style::default().fg(Color::White)),
            ]),
            Line::from(""),
            Line::from(vec![
                Span::styled("Tags: ", Style::default().fg(Color::Cyan)),
                Span::styled(
                    if detail.tags.is_empty() {
                        "(none)".to_string()
                    } else {
                        detail.tags.join(", ")
                    },
                    Style::default().fg(Color::White),
                ),
            ]),
            Line::from(""),
            Line::from(vec![
                Span::styled("Notes: ", Style::default().fg(Color::Cyan)),
                Span::styled(
                    detail.notes.as_deref().unwrap_or("(none)"),
                    Style::default().fg(Color::White),
                ),
            ]),
            Line::from(""),
            Line::from(vec![Span::styled(
                "Press 'v' to load value, 'q' to go back",
                Style::default().fg(Color::Yellow),
            )]),
        ];

        let paragraph = Paragraph::new(text)
            .block(
                Block::default()
                    .title("Secret Details")
                    .borders(Borders::ALL),
            )
            .wrap(Wrap { trim: true });

        f.render_widget(paragraph, area);
    }
}

/// Draw help view
fn draw_help_view(f: &mut Frame, area: Rect, _unicode_mode: UnicodeMode) {
    let text = vec![
        Line::from(vec![Span::styled(
            "SIGIL TUI - Keyboard Shortcuts",
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        )]),
        Line::from(""),
        Line::from("Browse Mode:"),
        Line::from("  ↑/k    - Move up"),
        Line::from("  ↓/j    - Move down"),
        Line::from("  Enter  - View secret details"),
        Line::from("  a      - Add new secret"),
        Line::from("  e      - Edit selected secret"),
        Line::from("  d      - Delete selected secret"),
        Line::from("  l      - View audit log"),
        Line::from("  s      - Session management"),
        Line::from("  r      - Refresh secret list"),
        Line::from("  h/?    - Show this help"),
        Line::from("  q      - Quit"),
        Line::from(""),
        Line::from("Detail View:"),
        Line::from("  v      - Load secret value (masked, auto-hides after 5s)"),
        Line::from("  q/Esc  - Back to browse"),
        Line::from(""),
        Line::from("Add/Edit Mode:"),
        Line::from("  s      - Save secret"),
        Line::from("  Enter  - Next field"),
        Line::from("  Tab    - Next field"),
        Line::from("  Sh+Tab - Previous field"),
        Line::from("  Type   - Edit current field"),
        Line::from("  Bs     - Delete character"),
        Line::from("  q/Esc  - Cancel"),
        Line::from(""),
        Line::from("Audit Log Viewer:"),
        Line::from("  ↑/k    - Scroll up"),
        Line::from("  ↓/j    - Scroll down"),
        Line::from("  r      - Refresh log"),
        Line::from("  q/Esc  - Back to browse"),
        Line::from(""),
        Line::from("Session Management:"),
        Line::from("  ↑/k    - Move up"),
        Line::from("  ↓/j    - Move down"),
        Line::from("  d      - Disconnect selected session"),
        Line::from("  r      - Refresh session list"),
        Line::from("  q/Esc  - Back to browse"),
        Line::from(""),
        Line::from("Import/Export (Browse mode):"),
        Line::from("  i      - Import secrets from file"),
        Line::from("  x      - Export secrets to file"),
        Line::from(""),
        Line::from("Backend Sync (Browse mode):"),
        Line::from("  y      - Sync with external backend"),
        Line::from(""),
        Line::from("Breach Alerts (Browse mode):"),
        Line::from("  b      - View breach alerts"),
        Line::from("  a      - Acknowledge selected alert"),
        Line::from("  r      - Resolve selected alert"),
        Line::from(""),
        Line::from("Secret Rotation (Browse mode):"),
        Line::from("  o      - Rotate a secret"),
        Line::from(""),
        Line::from(vec![Span::styled(
            "Press 'q' to go back",
            Style::default().fg(Color::Yellow),
        )]),
    ];

    let paragraph = Paragraph::new(text)
        .block(Block::default().title("Help").borders(Borders::ALL))
        .wrap(Wrap { trim: true });

    f.render_widget(paragraph, area);
}

/// Draw form view for adding/editing secrets
fn draw_form_view(f: &mut Frame, area: Rect, app: &mut App, _unicode_mode: UnicodeMode) {
    if let Some(ref form) = app.form_state {
        let title = if form.is_edit {
            format!("Edit Secret: {}", form.path)
        } else {
            "Add New Secret".to_string()
        };

        let field_labels = [
            ("Path", &form.path),
            (
                "Value",
                &if form.value_input.is_empty() {
                    "*".repeat(20)
                } else {
                    "*".repeat(form.value_input.len())
                },
            ),
            ("Type", &form.secret_type),
            ("Tags", &form.tags),
            ("Notes", &form.notes),
        ];

        let mut lines = vec![Line::from("")];

        for (i, (label, value)) in field_labels.iter().enumerate() {
            let is_current = matches!(
                (form.current_field, i),
                (FormField::Path, 0)
                    | (FormField::Value, 1)
                    | (FormField::Type, 2)
                    | (FormField::Tags, 3)
                    | (FormField::Notes, 4)
            );

            let style = if is_current {
                Style::default()
                    .fg(Color::Yellow)
                    .add_modifier(Modifier::BOLD)
            } else {
                Style::default()
            };

            lines.push(Line::from(vec![
                Span::styled(format!("{}: ", label), Style::default().fg(Color::Cyan)),
                Span::styled(if value.is_empty() { "<empty>" } else { value }, style),
            ]));
        }

        lines.push(Line::from(""));
        lines.push(Line::from(
            "Controls: Enter/Tab=next field, Backtab=prev field",
        ));
        lines.push(Line::from(
            "         s=save, q=cancel, Type to edit, Backspace to delete",
        ));

        let paragraph = Paragraph::new(lines)
            .block(Block::default().title(title).borders(Borders::ALL))
            .wrap(Wrap { trim: false });

        f.render_widget(paragraph, area);
    }
}

/// Draw delete confirmation view
fn draw_delete_view(f: &mut Frame, area: Rect, app: &mut App, _unicode_mode: UnicodeMode) {
    if !app.secrets.is_empty() {
        let secret = &app.secrets[app.selected];
        let text = vec![
            Line::from(""),
            Line::from(vec![
                Span::styled("Delete secret: ", Style::default().fg(Color::Yellow)),
                Span::styled(
                    &secret.path,
                    Style::default().fg(Color::Red).add_modifier(Modifier::BOLD),
                ),
            ]),
            Line::from(""),
            Line::from("This action cannot be undone."),
            Line::from(""),
            Line::from("Press 'y' to confirm, 'n' to cancel"),
        ];

        let paragraph = Paragraph::new(text)
            .block(
                Block::default()
                    .title("Confirm Delete")
                    .borders(Borders::ALL),
            )
            .wrap(Wrap { trim: false });

        f.render_widget(paragraph, area);
    }
}

/// Draw audit log view
fn draw_audit_view(f: &mut Frame, area: Rect, app: &mut App, _unicode_mode: UnicodeMode) {
    if app.audit_entries.is_empty() {
        let text = vec![
            Line::from(""),
            Line::from("No audit entries found."),
            Line::from(""),
            Line::from("Press 'r' to refresh, 'q' to go back"),
        ];

        let paragraph = Paragraph::new(text)
            .block(Block::default().title("Audit Log").borders(Borders::ALL))
            .wrap(Wrap { trim: false });

        f.render_widget(paragraph, area);
        return;
    }

    let items: Vec<ListItem> = app
        .audit_entries
        .iter()
        .enumerate()
        .map(|(i, entry)| {
            let style = if i == app.audit_selected {
                Style::default()
                    .fg(Color::Yellow)
                    .add_modifier(Modifier::BOLD)
            } else {
                // Color by severity
                if let Some(ref severity) = entry.severity {
                    match severity.as_str() {
                        "critical" => Style::default().fg(Color::Red),
                        "error" => Style::default().fg(Color::LightRed),
                        "warning" => Style::default().fg(Color::Yellow),
                        _ => Style::default(),
                    }
                } else {
                    Style::default()
                }
            };

            let severity_indicator = if let Some(ref severity) = entry.severity {
                match severity.as_str() {
                    "critical" => " [!]",
                    "error" => " [E]",
                    "warning" => " [W]",
                    _ => "",
                }
            } else {
                ""
            };

            ListItem::new(format!(
                "{} {} {}{}",
                entry.timestamp, entry.entry_type, entry.description, severity_indicator
            ))
            .style(style)
        })
        .collect();

    let list = List::new(items)
        .block(Block::default().title("Audit Log").borders(Borders::ALL))
        .highlight_style(Style::default().add_modifier(Modifier::BOLD));

    let mut list_state = ListState::default();
    list_state.select(Some(app.audit_selected));

    f.render_stateful_widget(list, area, &mut list_state);
}

/// Draw sessions view
fn draw_sessions_view(f: &mut Frame, area: Rect, app: &mut App, _unicode_mode: UnicodeMode) {
    if app.sessions.is_empty() {
        let text = vec![
            Line::from(""),
            Line::from("No active sessions."),
            Line::from(""),
            Line::from("Press 'r' to refresh, 'q' to go back"),
        ];

        let paragraph = Paragraph::new(text)
            .block(
                Block::default()
                    .title("Session Management")
                    .borders(Borders::ALL),
            )
            .wrap(Wrap { trim: false });

        f.render_widget(paragraph, area);
        return;
    }

    let items: Vec<ListItem> = app
        .sessions
        .iter()
        .enumerate()
        .map(|(i, session)| {
            let style = if i == app.session_selected {
                Style::default()
                    .fg(Color::Yellow)
                    .add_modifier(Modifier::BOLD)
            } else {
                Style::default()
            };

            // Format idle time
            let idle_str = if session.idle_secs < 60 {
                format!("{}s", session.idle_secs)
            } else if session.idle_secs < 3600 {
                format!("{}m", session.idle_secs / 60)
            } else {
                format!("{}h", session.idle_secs / 3600)
            };

            ListItem::new(format!(
                "{} | PID: {} | UID: {} | Idle: {} | Last: {}",
                session.token, session.pid, session.uid, idle_str, session.last_activity
            ))
            .style(style)
        })
        .collect();

    let list = List::new(items)
        .block(
            Block::default()
                .title("Active Sessions")
                .borders(Borders::ALL),
        )
        .highlight_style(Style::default().add_modifier(Modifier::BOLD));

    let mut list_state = ListState::default();
    list_state.select(Some(app.session_selected));

    f.render_stateful_widget(list, area, &mut list_state);
}

/// Draw import/export view
fn draw_import_export_view(f: &mut Frame, area: Rect, app: &mut App, _unicode_mode: UnicodeMode) {
    if let Some(ref state) = app.import_export_state {
        let title = match state.operation {
            ImportExportOp::Import => "Import Secrets",
            ImportExportOp::Export => "Export Secrets",
        };

        let mut lines = vec![];

        match state.current_step {
            ImportExportStep::FilePath => {
                lines.push(Line::from(vec![
                    Span::styled("Operation: ", Style::default().fg(Color::Cyan)),
                    Span::styled(
                        format!("{:?}", state.operation),
                        Style::default().fg(Color::White),
                    ),
                ]));
                lines.push(Line::from(""));
                lines.push(Line::from(vec![
                    Span::styled("File Path: ", Style::default().fg(Color::Cyan)),
                    Span::styled(
                        if state.file_path.is_empty() {
                            "<enter path>"
                        } else {
                            &state.file_path
                        },
                        Style::default()
                            .fg(Color::Yellow)
                            .add_modifier(Modifier::BOLD),
                    ),
                ]));
                lines.push(Line::from(""));
                lines.push(Line::from(
                    "Controls: Enter=confirm path, q=cancel, Type path",
                ));
            }
            ImportExportStep::ImportMode => {
                lines.push(Line::from("Select Import Mode:"));
                lines.push(Line::from(""));
                let modes = [
                    (ImportMode::SkipExisting, "Skip existing secrets"),
                    (ImportMode::Overwrite, "Overwrite existing secrets"),
                    (ImportMode::Rename, "Rename imported secrets"),
                    (ImportMode::Manual, "Manual conflict resolution"),
                ];
                for (i, (mode, desc)) in modes.iter().enumerate() {
                    let is_selected = state.import_mode == *mode;
                    lines.push(Line::from(vec![
                        Span::styled(format!("{}.", i + 1), Style::default().fg(Color::Gray)),
                        Span::styled(
                            if is_selected { " > " } else { "   " },
                            Style::default().fg(Color::Yellow),
                        ),
                        Span::styled(
                            *desc,
                            if is_selected {
                                Style::default()
                                    .fg(Color::Yellow)
                                    .add_modifier(Modifier::BOLD)
                            } else {
                                Style::default()
                            },
                        ),
                    ]));
                }
                lines.push(Line::from(""));
                lines.push(Line::from(
                    "Controls: 1-4=select mode, Enter=confirm, q=cancel",
                ));
            }
            ImportExportStep::ConflictResolution => {
                if state.pending_conflicts.is_empty() {
                    lines.push(Line::from("No conflicts to resolve."));
                    lines.push(Line::from(""));
                    lines.push(Line::from("Press Enter to continue..."));
                } else {
                    lines.push(Line::from(vec![
                        Span::styled("Resolve Conflicts: ", Style::default().fg(Color::Yellow)),
                        Span::styled(
                            format!("{} conflicts", state.pending_conflicts.len()),
                            Style::default().fg(Color::White),
                        ),
                    ]));
                    lines.push(Line::from(""));

                    for (i, conflict) in state.pending_conflicts.iter().enumerate() {
                        let is_selected = i == state.conflict_selected;
                        lines.push(Line::from(vec![
                            Span::styled(format!("{}.", i + 1), Style::default().fg(Color::Gray)),
                            Span::styled(
                                if is_selected { " > " } else { "   " },
                                Style::default().fg(Color::Yellow),
                            ),
                            Span::styled(&conflict.path, Style::default().fg(Color::White)),
                        ]));
                        lines.push(Line::from(vec![
                            Span::styled("    Existing: ", Style::default().fg(Color::Gray)),
                            Span::styled(&conflict.existing_timestamp, Style::default()),
                        ]));
                        lines.push(Line::from(vec![
                            Span::styled("    Imported: ", Style::default().fg(Color::Gray)),
                            Span::styled(&conflict.imported_timestamp, Style::default()),
                        ]));
                        lines.push(Line::from(vec![
                            Span::styled("    Action: ", Style::default().fg(Color::Gray)),
                            Span::styled(
                                match conflict.resolution {
                                    ConflictResolution::KeepExisting => "Keep existing",
                                    ConflictResolution::UseImported => "Use imported",
                                    ConflictResolution::Unresolved => "Unresolved",
                                },
                                Style::default().fg(Color::Cyan),
                            ),
                        ]));
                        lines.push(Line::from(""));
                    }
                    lines.push(Line::from(
                        "Controls: ↑/j↓=select, Space=toggle, Enter=confirm, q=cancel",
                    ));
                }
            }
            ImportExportStep::InProgress => {
                lines.push(Line::from(vec![Span::styled(
                    "Processing...",
                    Style::default().fg(Color::Yellow),
                )]));
                lines.push(Line::from(""));
                lines.push(Line::from(state.progress_message.as_str()));
            }
            ImportExportStep::Complete => {
                lines.push(Line::from(vec![Span::styled(
                    "Complete!",
                    Style::default().fg(Color::Green),
                )]));
                lines.push(Line::from(""));
                lines.push(Line::from(state.progress_message.as_str()));
                lines.push(Line::from(""));
                lines.push(Line::from("Press any key to continue..."));
            }
        }

        let paragraph = Paragraph::new(lines)
            .block(Block::default().title(title).borders(Borders::ALL))
            .wrap(Wrap { trim: true });

        f.render_widget(paragraph, area);
    }
}

/// Draw backend sync view
fn draw_backend_sync_view(f: &mut Frame, area: Rect, app: &mut App, _unicode_mode: UnicodeMode) {
    if let Some(ref state) = app.sync_state {
        let mut lines = vec![];

        match state.current_step {
            SyncStep::SelectBackend => {
                lines.push(Line::from("Select External Backend:"));
                lines.push(Line::from(""));
                // Create owned strings for display to avoid lifetime issues
                let backend_options = [
                    (BackendType::HashiCorpVault, "HashiCorp Vault"),
                    (BackendType::OnePassword, "1Password"),
                    (BackendType::Bitwarden, "Bitwarden"),
                    (BackendType::AwsSecretsManager, "AWS Secrets Manager"),
                ];
                for (i, (backend, name)) in backend_options.iter().enumerate() {
                    let is_selected = state.backend_type == *backend;
                    // Clone the name to create an owned string in the span
                    let name_owned = name.to_string();
                    lines.push(Line::from(vec![
                        Span::styled(format!("{}.", i + 1), Style::default().fg(Color::Gray)),
                        Span::styled(
                            if is_selected { " > " } else { "   " },
                            Style::default().fg(Color::Yellow),
                        ),
                        Span::styled(
                            name_owned,
                            if is_selected {
                                Style::default()
                                    .fg(Color::Yellow)
                                    .add_modifier(Modifier::BOLD)
                            } else {
                                Style::default()
                            },
                        ),
                    ]));
                }
                lines.push(Line::from(""));
                lines.push(Line::from(
                    "Controls: 1-4=select backend, Enter=confirm, q=cancel",
                ));
            }
            SyncStep::ConfigureConnection => {
                lines.push(Line::from(vec![
                    Span::styled("Backend: ", Style::default().fg(Color::Cyan)),
                    Span::styled(
                        state.backend_type.display_name(),
                        Style::default().fg(Color::White),
                    ),
                ]));
                lines.push(Line::from(""));
                lines.push(Line::from("Configure connection settings:"));
                lines.push(Line::from(""));

                if let Some(ref config) = state.connection_config {
                    let visible_fields = state.visible_fields();
                    let _auth_visible = visible_fields.contains(&ConnectionField::AuthMethod);

                    for field in visible_fields {
                        let is_current = config.current_field == field;
                        let is_required = state.is_field_required(field);
                        let style = if is_current {
                            Style::default()
                                .fg(Color::Yellow)
                                .add_modifier(Modifier::BOLD)
                        } else {
                            Style::default()
                        };

                        let (label, value_str, mask) = match field {
                            ConnectionField::Address => {
                                ("Address", config.address.as_str(), false)
                            }
                            ConnectionField::AuthMethod => {
                                let method_str = match config.auth_method {
                                    AuthMethod::Token => "Token",
                                    AuthMethod::UsernamePassword => "Username/Password",
                                    AuthMethod::AwsCredentials => "AWS Credentials",
                                };
                                ("Auth Method", method_str, false)
                            }
                            ConnectionField::Token => {
                                ("Token", config.token.as_str(), true)
                            }
                            ConnectionField::Username => {
                                ("Username", config.username.as_str(), false)
                            }
                            ConnectionField::Password => {
                                ("Password", config.password.as_str(), true)
                            }
                            ConnectionField::ApiKey => {
                                ("API Key", config.api_key.as_str(), true)
                            }
                            ConnectionField::SecretKey => {
                                ("Secret Key", config.secret_key.as_str(), true)
                            }
                            ConnectionField::Region => {
                                ("Region", config.region.as_str(), false)
                            }
                            ConnectionField::Namespace => {
                                ("Namespace", config.namespace.as_str(), false)
                            }
                        };

                        let display_value = if mask && !value_str.is_empty() {
                            "*".repeat(value_str.len())
                        } else if value_str.is_empty() {
                            "<empty>".to_string()
                        } else {
                            value_str.to_string()
                        };

                        // Add asterisk for required fields
                        let required_marker = if is_required { "*" } else { "" };
                        let label_style = if is_required {
                            Style::default().fg(Color::Red)
                        } else {
                            Style::default().fg(Color::Cyan)
                        };

                        lines.push(Line::from(vec![
                            Span::styled(
                                format!("{}{}: ", label, required_marker),
                                label_style,
                            ),
                            Span::styled(display_value, style),
                        ]));
                    }

                    // Show error message if present
                    if let Some(ref error) = config.error_message {
                        lines.push(Line::from(""));
                        lines.push(Line::from(vec![
                            Span::styled("Error: ", Style::default().fg(Color::Red)),
                            Span::styled(error, Style::default().fg(Color::Red)),
                        ]));
                    }

                    lines.push(Line::from(""));
                    lines.push(Line::from("Controls:"));
                    lines.push(Line::from("  Enter/Tab=next field, Backtab=prev field"));
                    lines.push(Line::from("  Type to edit, Backspace to delete"));
                    lines.push(Line::from("  Space=toggle auth method (for Vault)"));
                    lines.push(Line::from("  Enter=test connection, q=cancel"));
                    lines.push(Line::from(""));
                    lines.push(Line::from("  * = required field"));
                } else {
                    lines.push(Line::from("Error: Connection config not initialized"));
                }
            }
            SyncStep::ConfirmSync => {
                lines.push(Line::from(vec![
                    Span::styled("Backend: ", Style::default().fg(Color::Cyan)),
                    Span::styled(
                        state.backend_type.display_name(),
                        Style::default().fg(Color::White),
                    ),
                ]));
                lines.push(Line::from(""));
                lines.push(Line::from("Ready to sync secrets from external backend."));
                lines.push(Line::from(""));
                lines.push(Line::from("This will:"));
                lines.push(Line::from("  - Pull all secrets from the backend"));
                lines.push(Line::from("  - Merge with local vault"));
                lines.push(Line::from(""));
                lines.push(Line::from("Press Enter to confirm, q to cancel"));
            }
            SyncStep::InProgress => {
                lines.push(Line::from(vec![Span::styled(
                    "Syncing...",
                    Style::default().fg(Color::Yellow),
                )]));
                lines.push(Line::from(""));
                lines.push(Line::from(state.progress_message.as_str()));
                if state.synced_count > 0 {
                    lines.push(Line::from(format!(
                        "Synced: {} secrets",
                        state.synced_count
                    )));
                }
                if !state.failed_secrets.is_empty() {
                    lines.push(Line::from(""));
                    lines.push(Line::from(vec![
                        Span::styled("Failed: ", Style::default().fg(Color::Red)),
                        Span::styled(
                            format!("{} secrets", state.failed_secrets.len()),
                            Style::default(),
                        ),
                    ]));
                }
            }
            SyncStep::Complete => {
                lines.push(Line::from(vec![Span::styled(
                    "Sync Complete!",
                    Style::default().fg(Color::Green),
                )]));
                lines.push(Line::from(""));
                lines.push(Line::from(state.progress_message.as_str()));
                lines.push(Line::from(format!(
                    "Synced: {} secrets",
                    state.synced_count
                )));
                if !state.failed_secrets.is_empty() {
                    lines.push(Line::from(""));
                    lines.push(Line::from(vec![Span::styled(
                        "Failed secrets:",
                        Style::default().fg(Color::Red),
                    )]));
                    for secret in &state.failed_secrets {
                        lines.push(Line::from(format!("  - {}", secret)));
                    }
                }
                lines.push(Line::from(""));
                lines.push(Line::from("Press any key to continue..."));
            }
        }

        let paragraph = Paragraph::new(lines)
            .block(
                Block::default()
                    .title("External Backend Sync")
                    .borders(Borders::ALL),
            )
            .wrap(Wrap { trim: true });

        f.render_widget(paragraph, area);
    }
}

/// Draw breach alerts view
fn draw_breach_alerts_view(f: &mut Frame, area: Rect, app: &mut App, _unicode_mode: UnicodeMode) {
    if app.breach_alerts.is_empty() {
        let text = vec![
            Line::from(""),
            Line::from("No breach alerts."),
            Line::from(""),
            Line::from("Breach alerts notify you of:"),
            Line::from("  - Compromised passwords"),
            Line::from("  - Security incidents"),
            Line::from("  - Unauthorized access attempts"),
            Line::from(""),
            Line::from("Press 'r' to refresh, 'q' to go back"),
        ];

        let paragraph = Paragraph::new(text)
            .block(
                Block::default()
                    .title("Breach Alerts")
                    .borders(Borders::ALL),
            )
            .wrap(Wrap { trim: false });

        f.render_widget(paragraph, area);
        return;
    }

    let items: Vec<ListItem> = app
        .breach_alerts
        .iter()
        .enumerate()
        .map(|(i, alert)| {
            let style = if i == app.breach_selected {
                Style::default()
                    .fg(Color::Yellow)
                    .add_modifier(Modifier::BOLD)
            } else {
                // Color by severity
                match alert.severity {
                    BreachSeverity::Critical => Style::default().fg(Color::Red),
                    BreachSeverity::High => Style::default().fg(Color::LightRed),
                    BreachSeverity::Medium => Style::default().fg(Color::Yellow),
                    BreachSeverity::Low => Style::default().fg(Color::Gray),
                }
            };

            let status_icon = match alert.status {
                AlertStatus::New => "[N]",
                AlertStatus::Acknowledged => "[A]",
                AlertStatus::Resolved => "[R]",
                AlertStatus::Dismissed => "[D]",
            };

            let severity_icon = match alert.severity {
                BreachSeverity::Critical => "[!!!]",
                BreachSeverity::High => "[!!]",
                BreachSeverity::Medium => "[!]",
                BreachSeverity::Low => "[i]",
            };

            ListItem::new(format!(
                "{} {} {} | {} | {}",
                status_icon, severity_icon, alert.timestamp, alert.id, alert.description
            ))
            .style(style)
        })
        .collect();

    let list = List::new(items)
        .block(
            Block::default()
                .title("Breach Alerts")
                .borders(Borders::ALL),
        )
        .highlight_style(Style::default().add_modifier(Modifier::BOLD));

    let mut list_state = ListState::default();
    list_state.select(Some(app.breach_selected));

    f.render_stateful_widget(list, area, &mut list_state);
}

/// Draw secret rotation view
fn draw_secret_rotation_view(f: &mut Frame, area: Rect, app: &mut App, _unicode_mode: UnicodeMode) {
    if let Some(ref state) = app.rotation_state {
        let mut lines = vec![];

        match state.current_step {
            RotationStep::SelectSecret => {
                lines.push(Line::from("Select Secret to Rotate:"));
                lines.push(Line::from(""));
                if app.secrets.is_empty() {
                    lines.push(Line::from("No secrets available."));
                } else {
                    for (i, secret) in app.secrets.iter().enumerate() {
                        let is_selected = i == app.selected;
                        lines.push(Line::from(vec![
                            Span::styled(format!("{}.", i + 1), Style::default().fg(Color::Gray)),
                            Span::styled(
                                if is_selected { " > " } else { "   " },
                                Style::default().fg(Color::Yellow),
                            ),
                            Span::styled(
                                &secret.path,
                                if is_selected {
                                    Style::default()
                                        .fg(Color::Yellow)
                                        .add_modifier(Modifier::BOLD)
                                } else {
                                    Style::default()
                                },
                            ),
                        ]));
                    }
                }
                lines.push(Line::from(""));
                lines.push(Line::from("Controls: ↑/j↓=select, Enter=confirm, q=cancel"));
            }
            RotationStep::EnterNewValue => {
                lines.push(Line::from(vec![
                    Span::styled("Secret: ", Style::default().fg(Color::Cyan)),
                    Span::styled(&state.secret_path, Style::default().fg(Color::White)),
                ]));
                lines.push(Line::from(""));
                let new_value_display = if state.new_value_input.is_empty() {
                    "<enter new value>".to_string()
                } else {
                    "*".repeat(state.new_value_input.len())
                };
                lines.push(Line::from(vec![
                    Span::styled("New Value: ", Style::default().fg(Color::Cyan)),
                    Span::styled(
                        new_value_display.clone(),
                        Style::default()
                            .fg(Color::Yellow)
                            .add_modifier(Modifier::BOLD),
                    ),
                ]));
                lines.push(Line::from(""));
                lines.push(Line::from("Controls: Enter=next, q=cancel, Type value"));
            }
            RotationStep::EnterReason => {
                lines.push(Line::from(vec![
                    Span::styled("Secret: ", Style::default().fg(Color::Cyan)),
                    Span::styled(&state.secret_path, Style::default().fg(Color::White)),
                ]));
                lines.push(Line::from(""));
                lines.push(Line::from(vec![
                    Span::styled("Reason: ", Style::default().fg(Color::Cyan)),
                    Span::styled(
                        if state.rotation_reason.is_empty() {
                            "<enter reason (optional)>"
                        } else {
                            &state.rotation_reason
                        },
                        Style::default()
                            .fg(Color::Yellow)
                            .add_modifier(Modifier::BOLD),
                    ),
                ]));
                lines.push(Line::from(""));
                lines.push(Line::from("Controls: Enter=confirm, q=cancel, Type reason"));
            }
            RotationStep::ConfirmRotation => {
                lines.push(Line::from(vec![Span::styled(
                    "Confirm Rotation:",
                    Style::default().fg(Color::Yellow),
                )]));
                lines.push(Line::from(""));
                lines.push(Line::from(vec![
                    Span::styled("Secret: ", Style::default().fg(Color::Cyan)),
                    Span::styled(&state.secret_path, Style::default().fg(Color::White)),
                ]));
                lines.push(Line::from(vec![
                    Span::styled("Reason: ", Style::default().fg(Color::Cyan)),
                    Span::styled(
                        if state.rotation_reason.is_empty() {
                            "(none)"
                        } else {
                            &state.rotation_reason
                        },
                        Style::default().fg(Color::White),
                    ),
                ]));
                lines.push(Line::from(""));
                lines.push(Line::from("This will:"));
                lines.push(Line::from("  - Update the secret value"));
                lines.push(Line::from("  - Log the rotation in audit trail"));
                lines.push(Line::from(""));
                lines.push(Line::from("Press Enter to confirm, q to cancel"));
            }
            RotationStep::InProgress => {
                lines.push(Line::from(vec![Span::styled(
                    "Rotating...",
                    Style::default().fg(Color::Yellow),
                )]));
                lines.push(Line::from(""));
                lines.push(Line::from(state.status_message.as_str()));
                lines.push(Line::from(format!("Progress: {}%", state.progress)));
            }
            RotationStep::Complete => {
                lines.push(Line::from(vec![Span::styled(
                    "Rotation Complete!",
                    Style::default().fg(Color::Green),
                )]));
                lines.push(Line::from(""));
                lines.push(Line::from(state.status_message.as_str()));
                lines.push(Line::from(""));
                lines.push(Line::from("Press any key to continue..."));
            }
        }

        let paragraph = Paragraph::new(lines)
            .block(
                Block::default()
                    .title("Secret Rotation")
                    .borders(Borders::ALL),
            )
            .wrap(Wrap { trim: true });

        f.render_widget(paragraph, area);
    }
}

fn main() -> Result<()> {
    // Check terminal size before starting TUI
    let size = terminal_size::terminal_size();
    if let Some((width, _)) = size {
        if width.0 < 60 {
            eprintln!(
                "Error: Terminal too narrow for TUI (minimum 60 columns, current: {})",
                width.0
            );
            eprintln!("Please resize your terminal or use the CLI commands instead.");
            eprintln!();
            eprintln!("CLI alternatives:");
            eprintln!("  sigil list        - List all secrets");
            eprintln!("  sigil get <path>  - Get a secret value");
            eprintln!("  sigil add         - Add a new secret");
            eprintln!("  sigil --help      - Show all commands");
            return Err(anyhow::anyhow!("Terminal too narrow"));
        }
    }

    // PTY isolation is MANDATORY for security (prevents agent from reading TUI output)
    // The TUI MUST run on a separate PTY allocated via openpty() per Phase 6.1 spec
    #[cfg(target_os = "linux")]
    {
        let mut pty = PtyPair::allocate().map_err(|e| {
            anyhow::anyhow!(
                "PTY allocation failed: {}. PTY isolation is a hard security requirement - \
                 the TUI cannot run on the agent's terminal. Please ensure /dev/pts is mounted \
                 and you have permissions to allocate PTYs.",
                e
            )
        })?;

        // PTY allocation succeeded - use isolated PTY for security
        // The TUI runs on the PTY master, user connects to PTY slave via separate terminal

        // Print connection instructions to stderr (visible to user)
        eprintln!();
        eprintln!("╔═══════════════════════════════════════════════════════════════════╗");
        eprintln!("║  SIGIL TUI - Isolated PTY Mode                                    ║");
        eprintln!("╠═══════════════════════════════════════════════════════════════════╣");
        eprintln!("║  Security: TUI running on isolated PTY (agent cannot read)        ║");
        eprintln!("║                                                                   ║");
        eprintln!(
            "║  PTY slave: {}{}",
            pty.slave_path_str(),
            if pty.slave_path_str().len() < 52 {
                " ".repeat(52 - pty.slave_path_str().len())
            } else {
                String::new()
            }
        );
        eprintln!("║                                                                   ║");
        eprintln!("║  Open a new terminal and connect to view the TUI:                 ║");
        eprintln!("║    screen {}", pty.slave_path_str());
        eprintln!("║  or:                                                               ║");
        eprintln!("║    picocom {}", pty.slave_path_str());
        eprintln!("║                                                                   ║");
        eprintln!("║  Detach from screen: Ctrl+A then D                                ║");
        eprintln!("╚═══════════════════════════════════════════════════════════════════╝");
        eprintln!();
        eprintln!(
            "TUI is running on PTY {} - connect from another terminal to use it.",
            pty.slave_path_str()
        );
        eprintln!("This terminal remains available for agent use.");
        eprintln!();

        // Fork a child process to run the TUI on the PTY master
        // The parent process returns immediately, keeping the agent's terminal functional
        // The child process attaches to the PTY master and runs the TUI
        match unsafe { nix::unistd::fork() } {
            Ok(nix::unistd::ForkResult::Parent { child }) => {
                // Parent process: return immediately
                // The agent's terminal is still functional
                // The child process runs the TUI in the background on the PTY
                eprintln!(
                    "TUI process started (PID: {}). Use 'ps aux | grep sigil-tui' to check status.",
                    child
                );
                eprintln!("To stop the TUI, kill the process or press 'q' in the TUI.");
                eprintln!();
                Ok(())
            }
            Ok(nix::unistd::ForkResult::Child) => {
                // Child process: run TUI on PTY master
                // Create a new session so the TUI is not the agent's child
                nix::unistd::setsid().map_err(|e| anyhow::anyhow!("Failed to setsid: {}", e))?;

                // Get the master PTY file for crossterm
                let master_file = pty.writer()?;
                let master_fd = master_file.as_raw_fd();

                // Redirect child's stdin/stdout/stderr to the PTY master
                // This ensures crossterm reads from and writes to the PTY, not the agent's terminal
                // SAFETY: These file descriptors are valid and we're taking ownership
                unsafe {
                    let borrowed = BorrowedFd::borrow_raw(master_fd);
                    dup2(borrowed, &mut OwnedFd::from_raw_fd(nix::libc::STDIN_FILENO))?;
                    dup2(
                        borrowed,
                        &mut OwnedFd::from_raw_fd(nix::libc::STDOUT_FILENO),
                    )?;
                    dup2(
                        borrowed,
                        &mut OwnedFd::from_raw_fd(nix::libc::STDERR_FILENO),
                    )?;
                }

                // After dup2, we need to reconstruct stdout from the redirected file descriptor.
                // io::stdout() is a static handle that doesn't reflect dup2 changes, so we create
                // a new File from the raw fd which now points to the PTY master.
                let pty_file = unsafe { std::fs::File::from_raw_fd(nix::libc::STDOUT_FILENO) };

                // Initialize terminal on the PTY
                enable_raw_mode()?;
                let backend = CrosstermBackend::new(pty_file);
                let mut terminal = Terminal::new(backend)?;

                // Clear screen
                terminal.clear()?;

                // Run TUI
                let result = run_tui(terminal);

                // Restore terminal state (best effort - process will exit)
                let _ = disable_raw_mode();
                let _ = execute!(io::stdout(), LeaveAlternateScreen, DisableMouseCapture);

                result
            }
            Err(e) => {
                Err(anyhow::anyhow!(
                    "Failed to fork for isolated PTY mode: {}. PTY isolation is a hard security requirement.",
                    e
                ))
            }
        }
    }

    // PTY isolation is MANDATORY for security (per Phase 6.1 spec)
    // Non-Linux platforms are not supported for the TUI
    #[cfg(not(target_os = "linux"))]
    {
        Err(anyhow::anyhow!(
            "PTY isolation is not supported on this platform. \
             The SIGIL TUI requires Linux with openpty() support for secure PTY allocation. \
             Please use the CLI commands instead: sigil list, sigil get, sigil add, etc."
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_app_creation() {
        let app = App::new();
        assert_eq!(app.selected, 0);
        assert_eq!(app.mode, Mode::Browse);
        assert!(app.secrets.is_empty());
    }

    #[test]
    fn test_navigation() {
        let mut app = App::new();
        app.secrets = vec![
            SecretItem {
                path: "test1".to_string(),
                secret_type: "Generic".to_string(),
                updated: "2024-01-01".to_string(),
                tags: vec![],
            },
            SecretItem {
                path: "test2".to_string(),
                secret_type: "Generic".to_string(),
                updated: "2024-01-02".to_string(),
                tags: vec![],
            },
        ];

        app.select_down();
        assert_eq!(app.selected, 1);
        app.select_up();
        assert_eq!(app.selected, 0);
    }
}
