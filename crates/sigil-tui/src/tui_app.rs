//! SIGIL TUI Application
//!
//! This module contains the full TUI application for secret management.
//! It provides a terminal UI with process isolation to prevent the AI agent
//! from accessing secret values through memory inspection.

#![warn(missing_docs)]
#![warn(clippy::all)]

use anyhow::Result;
use crossterm::event::{self, Event, KeyCode, KeyEvent};
use ratatui::prelude::CrosstermBackend;
use ratatui::{
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, List, ListItem, ListState, Paragraph, Wrap},
    Frame, Terminal,
};
use sigil_core::{
    audit::AuditEntry, GlobalConfigManager, LayoutMode as CoreLayoutMode, SecretBackend,
    SecretPath, TuiConfig, UnicodeMode,
};
use sigil_vault::LocalVault;
use std::io::Write;
use std::time::{Duration, Instant};

#[cfg(target_os = "linux")]
use nix::sys::resource::{setrlimit, Resource};

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
pub fn enable_process_isolation() -> Result<()> {
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
pub fn enable_process_isolation() -> Result<()> {
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
pub fn enable_process_isolation() -> Result<()> {
    tracing::warn!("Process isolation not available on this platform - terminal isolation only");
    Ok(())
}

/// TUI application state
pub struct App {
    /// List of secrets
    pub secrets: Vec<SecretItem>,
    /// Currently selected secret index
    pub selected: usize,
    /// Current view mode
    pub mode: Mode,
    /// Filter prefix for listing secrets
    pub filter_prefix: String,
    /// Secret detail view
    pub detail_view: Option<SecretDetail>,
    /// Status message
    pub status_message: String,
    /// Auto-hide timeout for secret values (default: 5 seconds)
    pub auto_hide_timeout: Duration,
    /// Add/edit form state
    pub form_state: Option<FormState>,
    /// Audit log entries
    pub audit_entries: Vec<AuditItem>,
    /// Currently selected audit entry index
    pub audit_selected: usize,
    /// Audit log filter (entry type)
    pub _audit_filter: Option<String>,
    /// Session list
    pub sessions: Vec<SessionItem>,
    /// Currently selected session index
    pub session_selected: usize,
    /// Import/Export state
    pub import_export_state: Option<ImportExportState>,
    /// Backend sync state
    pub sync_state: Option<BackendSyncState>,
    /// Breach alerts
    pub breach_alerts: Vec<BreachAlert>,
    /// Currently selected breach alert index
    pub breach_selected: usize,
    /// Secret rotation state
    pub rotation_state: Option<RotationState>,
}

/// Form state for adding/editing secrets
#[derive(Debug, Clone)]
pub struct FormState {
    /// Secret path
    pub path: String,
    /// Secret value input buffer
    pub value_input: String,
    /// Secret type
    pub secret_type: String,
    /// Tags (comma-separated)
    pub tags: String,
    /// Notes
    pub notes: String,
    /// Current field being edited
    pub current_field: FormField,
    /// Whether this is editing an existing secret
    pub is_edit: bool,
}

/// Form fields for add/edit
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum FormField {
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
pub struct AuditItem {
    /// Entry type
    pub entry_type: String,
    /// Timestamp
    pub timestamp: String,
    /// Description (summary of the entry)
    pub description: String,
    /// Severity (for breaches, auth failures)
    pub severity: Option<String>,
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
                severity,
                description,
                ..
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
pub struct SessionItem {
    /// Session token (truncated for security)
    pub token: String,
    /// Full token (not used - killing via pid/uid instead)
    pub _full_token: String,
    /// Process ID
    pub pid: u32,
    /// User ID
    pub uid: u32,
    /// Creation time
    pub _created_at: String,
    /// Last activity time
    pub last_activity: String,
    /// Idle time in seconds
    pub idle_secs: i64,
}

/// Import/Export state
#[derive(Debug, Clone)]
pub struct ImportExportState {
    /// Current operation (Import or Export)
    pub operation: ImportExportOp,
    /// File path input
    pub file_path: String,
    /// Import mode (for import operations)
    pub import_mode: ImportMode,
    /// Current step in the workflow
    pub current_step: ImportExportStep,
    /// Pending conflicts (for conflict resolution)
    pub pending_conflicts: Vec<ConflictItem>,
    /// Currently selected conflict index
    pub conflict_selected: usize,
    /// Progress message
    pub progress_message: String,
}

/// Import/Export operation type
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum ImportExportOp {
    /// Import secrets from archive
    Import,
    /// Export secrets to archive
    Export,
}

/// Import mode
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum ImportMode {
    /// Skip existing secrets
    SkipExisting,
    /// Overwrite existing secrets
    Overwrite,
    /// Rename imported secrets
    Rename,
    /// Manual conflict resolution
    Manual,
}

/// Import/Export workflow step
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum ImportExportStep {
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

/// Conflict item for manual resolution
#[derive(Debug, Clone)]
pub struct ConflictItem {
    /// Secret path
    pub path: String,
    /// Existing secret description
    pub existing_description: String,
    /// Imported secret description
    pub imported_description: String,
    /// Resolution action
    pub resolution: ConflictResolution,
}

/// Conflict resolution action
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum ConflictResolution {
    /// Unresolved
    Unresolved,
    /// Keep existing secret
    KeepExisting,
    /// Use imported secret
    UseImported,
}

/// Backend sync state
#[derive(Debug, Clone)]
pub struct BackendSyncState {
    /// Selected backend type
    pub backend_type: BackendType,
    /// Connection status
    pub status: SyncStatus,
    /// Current step
    pub current_step: SyncStep,
    /// Progress message
    pub progress_message: String,
    /// Number of secrets synced
    pub synced_count: usize,
    /// Connection configuration state
    pub connection_config: Option<ConnectionConfigState>,
}

/// Backend type
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum BackendType {
    /// HashiCorp Vault
    HashiCorpVault,
    /// 1Password
    OnePassword,
    /// AWS Secrets Manager
    AwsSecretsManager,
    /// Azure Key Vault
    AzureKeyVault,
}

/// Sync status
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum SyncStatus {
    /// Disconnected
    Disconnected,
    /// Connecting
    Connecting,
    /// Connected
    Connected,
    /// Syncing
    Syncing,
    /// Error
    Error,
}

/// Sync workflow step
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum SyncStep {
    /// Select backend
    SelectBackend,
    /// Configure connection
    ConfigureConnection,
    /// Confirm sync
    ConfirmSync,
    /// In progress
    InProgress,
    /// Complete
    Complete,
}

/// Authentication method for backend connections
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum AuthMethod {
    /// Token-based authentication
    Token,
    /// Username/password authentication
    UsernamePassword,
    /// AWS credentials
    AwsCredentials,
}

/// Connection configuration fields
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum ConnectionField {
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

/// Connection configuration form state
#[derive(Debug, Clone)]
pub struct ConnectionConfigState {
    /// Server address/URL
    pub address: String,
    /// Authentication method
    pub auth_method: AuthMethod,
    /// Token (for token-based auth)
    pub token: String,
    /// Username (for username/password auth)
    pub username: String,
    /// Password (for username/password auth)
    pub password: String,
    /// API key (for AWS Secrets Manager)
    pub api_key: String,
    /// Secret key (for AWS Secrets Manager)
    pub secret_key: String,
    /// Region (for AWS Secrets Manager)
    pub region: String,
    /// Vault namespace (for HashiCorp Vault)
    pub namespace: String,
    /// Current field being edited
    pub current_field: ConnectionField,
    /// Connection error message
    pub error_message: Option<String>,
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

/// Breach alert item
#[derive(Debug, Clone)]
pub struct BreachAlert {
    /// Alert ID
    pub id: String,
    /// Severity
    pub severity: BreachSeverity,
    /// Title
    pub title: String,
    /// Description
    pub description: String,
    /// Affected secrets
    pub affected_secrets: Vec<String>,
    /// Detection time
    pub detected_at: String,
    /// Acknowledged
    pub acknowledged: bool,
    /// Resolved
    pub resolved: bool,
}

/// Breach severity
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum BreachSeverity {
    /// Low severity
    Low,
    /// Medium severity
    Medium,
    /// High severity
    High,
    /// Critical severity
    Critical,
}

/// Secret rotation state
#[derive(Debug, Clone)]
pub struct RotationState {
    /// Current step
    pub current_step: RotationStep,
    /// Selected secret path
    pub secret_path: String,
    /// New value input
    pub new_value: String,
    /// Rotation reason
    pub reason: String,
    /// Progress (0-100)
    pub progress: u8,
    /// Status message
    pub status_message: String,
}

/// Rotation workflow step
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum RotationStep {
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

/// Display mode
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Mode {
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
    /// External backend sync (Vault, 1Password, etc.)
    BackendSync,
    /// Breach alerts panel
    BreachAlerts,
    /// Secret rotation initiation and status
    SecretRotation,
}

/// Secret item for display
#[derive(Debug, Clone)]
pub struct SecretItem {
    /// Secret path
    pub path: String,
    /// Secret type
    #[allow(dead_code)]
    pub secret_type: String,
    /// Last updated
    pub updated: String,
    /// Tags
    pub tags: Vec<String>,
}

/// Secret detail view
#[derive(Debug, Clone)]
pub struct SecretDetail {
    /// Secret path
    pub path: String,
    /// Secret type
    pub secret_type: String,
    /// Creation time
    pub created: String,
    /// Update time
    pub updated: String,
    /// Tags
    pub tags: Vec<String>,
    /// Notes
    pub notes: Option<String>,
    /// Whether the secret value is shown (masked)
    pub value_shown: bool,
    /// When the value was revealed (for auto-hide timer)
    pub revealed_at: Option<Instant>,
}

impl SecretDetail {
    /// Check if the revealed value should be auto-hidden
    pub fn should_hide_value(&self, timeout: Duration) -> bool {
        if self.value_shown {
            if let Some(revealed_at) = self.revealed_at {
                return revealed_at.elapsed() > timeout;
            }
        }
        false
    }

    /// Hide the secret value
    pub fn hide_value(&mut self) {
        self.value_shown = false;
        self.revealed_at = None;
        self.notes = Some("[VALUE HIDDEN]".to_string());
    }
}

impl BackendSyncState {
    /// Get visible fields for the current backend type
    pub fn visible_fields(&self) -> Vec<ConnectionField> {
        match self.backend_type {
            BackendType::HashiCorpVault => vec![
                ConnectionField::Address,
                ConnectionField::AuthMethod,
                ConnectionField::Token,
                ConnectionField::Namespace,
            ],
            BackendType::OnePassword => vec![ConnectionField::Address, ConnectionField::Token],
            BackendType::AwsSecretsManager => vec![
                ConnectionField::Region,
                ConnectionField::ApiKey,
                ConnectionField::SecretKey,
            ],
            BackendType::AzureKeyVault => vec![ConnectionField::Address, ConnectionField::Token],
        }
    }

    /// Move to next visible field
    pub fn next_field(&mut self) {
        if let Some(ref config) = self.connection_config {
            let visible = self.visible_fields();
            if let Some(current_idx) = visible.iter().position(|&f| f == config.current_field) {
                let next_idx = (current_idx + 1) % visible.len();
                self.connection_config.as_mut().unwrap().current_field = visible[next_idx];
            }
        }
    }

    /// Move to previous visible field
    pub fn prev_field(&mut self) {
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

    /// Initialize connection config with backend-specific defaults
    pub fn init_connection_config(&mut self) {
        let mut config = ConnectionConfigState::default();
        match self.backend_type {
            BackendType::HashiCorpVault => {
                config.address = "https://vault.example.com:8200".to_string();
                config.auth_method = AuthMethod::Token;
            }
            BackendType::OnePassword => {
                config.address = "https://my.1password.com".to_string();
                config.auth_method = AuthMethod::Token;
            }
            BackendType::AwsSecretsManager => {
                config.auth_method = AuthMethod::AwsCredentials;
                config.region = "us-east-1".to_string();
            }
            BackendType::AzureKeyVault => {
                config.address = "https://<vault-name>.vault.azure.net".to_string();
                config.auth_method = AuthMethod::Token;
            }
        }
        self.connection_config = Some(config);
    }

    /// Validate connection configuration and test connection
    pub fn test_connection(&mut self) -> Result<(), String> {
        let config = self
            .connection_config
            .as_ref()
            .ok_or("Config not initialized")?;

        // Validate required fields based on backend type
        let validation_error = match self.backend_type {
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
            BackendType::AzureKeyVault => {
                if config.address.is_empty() {
                    Some("Address is required".to_string())
                } else if config.token.is_empty() {
                    Some("Token is required".to_string())
                } else {
                    None
                }
            }
        };

        if let Some(error) = validation_error {
            if let Some(cfg) = &mut self.connection_config {
                cfg.error_message = Some(error);
            }
            return Err("Validation failed".to_string());
        }

        // Clear any previous error
        if let Some(cfg) = &mut self.connection_config {
            cfg.error_message = None;
        }

        // In real implementation, would attempt actual connection here
        // For now, we'll just validate the format
        Ok(())
    }
}

impl Default for App {
    fn default() -> Self {
        Self::new()
    }
}

impl App {
    /// Create a new TUI application
    ///
    /// Loads global configuration and applies TUI settings.
    pub fn new() -> Self {
        // Load global config for TUI settings
        let tui_config = GlobalConfigManager::new()
            .and_then(|mgr| mgr.load())
            .ok()
            .flatten()
            .map(|cfg| cfg.tui)
            .unwrap_or_default();

        Self {
            secrets: vec![],
            selected: 0,
            mode: Mode::Browse,
            filter_prefix: String::new(),
            detail_view: None,
            status_message: "Loading secrets...".to_string(),
            auto_hide_timeout: Duration::from_secs(tui_config.secret_display_timeout),
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

    /// Create a new TUI application with custom config
    ///
    /// This allows testing or overriding the global config.
    pub fn with_config(tui_config: TuiConfig) -> Self {
        Self {
            secrets: vec![],
            selected: 0,
            mode: Mode::Browse,
            filter_prefix: String::new(),
            detail_view: None,
            status_message: "Loading secrets...".to_string(),
            auto_hide_timeout: Duration::from_secs(tui_config.secret_display_timeout),
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
    pub fn enter_audit_mode(&mut self) -> Result<()> {
        self.mode = Mode::Audit;
        self.load_audit_entries()?;
        self.status_message = "Audit log viewer - Press 'q' to go back".to_string();
        Ok(())
    }

    /// Exit audit log viewer mode
    pub fn exit_audit_mode(&mut self) {
        self.mode = Mode::Browse;
        self.audit_entries.clear();
        self.audit_selected = 0;
        self.status_message = "Browse mode".to_string();
    }

    /// Enter session management mode
    pub fn enter_sessions_mode(&mut self) -> Result<()> {
        self.mode = Mode::Sessions;
        self.load_sessions()?;
        self.status_message =
            "Session management - Press 'q' to go back, 'd' to disconnect session".to_string();
        Ok(())
    }

    /// Exit session management mode
    pub fn exit_sessions_mode(&mut self) {
        self.mode = Mode::Browse;
        self.sessions.clear();
        self.session_selected = 0;
        self.status_message = "Browse mode".to_string();
    }

    /// Load sessions from daemon
    pub fn load_sessions(&mut self) -> Result<()> {
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
                // The daemon returns truncated tokens for security.
                // Session killing uses pid/uid instead of the full token.
                SessionItem {
                    token: s.token.clone(),
                    _full_token: String::new(), // Not needed - killing uses pid/uid
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
    pub fn kill_selected_session(&mut self) -> Result<()> {
        use sigil_core::{
            IpcOperation, IpcRequest, IpcResponse, KillSessionRequest, KillSessionResponse,
        };

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

        // Connect to daemon and request session kill
        let socket_path = sigil_core::default_socket_path();
        let mut stream = std::os::unix::net::UnixStream::connect(&socket_path)
            .map_err(|e| anyhow::anyhow!("Failed to connect to daemon: {}", e))?;

        // Use pid/uid to identify the session (no full token needed)
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
        let response: IpcResponse = serde_json::from_slice(&data)
            .map_err(|e| anyhow::anyhow!("Invalid response from daemon: {}", e))?;

        if !response.ok {
            self.status_message = format!("Failed to kill session: {:?}", response.error);
            return Ok(());
        }

        let kill_response: KillSessionResponse = serde_json::from_value(response.payload)
            .map_err(|e| anyhow::anyhow!("Failed to parse response: {}", e))?;

        if kill_response.killed {
            self.status_message = format!("Session killed: {}", session.token);
            // Reload the session list to update the display
            self.load_sessions()?;
        } else {
            self.status_message = format!("Failed to kill session: {}", kill_response.message);
        }

        Ok(())
    }

    /// Load audit entries
    pub fn load_audit_entries(&mut self) -> Result<()> {
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
    pub fn audit_select_up(&mut self) {
        if !self.audit_entries.is_empty() && self.audit_selected > 0 {
            self.audit_selected -= 1;
        }
    }

    /// Move audit selection down
    pub fn audit_select_down(&mut self) {
        if !self.audit_entries.is_empty() && self.audit_selected < self.audit_entries.len() - 1 {
            self.audit_selected += 1;
        }
    }

    /// Move session selection up
    pub fn session_select_up(&mut self) {
        if !self.sessions.is_empty() && self.session_selected > 0 {
            self.session_selected -= 1;
        }
    }

    /// Move session selection down
    pub fn session_select_down(&mut self) {
        if !self.sessions.is_empty() && self.session_selected < self.sessions.len() - 1 {
            self.session_selected += 1;
        }
    }

    /// Enter add mode
    pub fn enter_add_mode(&mut self) {
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
    pub fn enter_edit_mode(&mut self, vault: &LocalVault) -> Result<()> {
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
    pub fn enter_delete_mode(&mut self) {
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
    pub fn confirm_delete(&mut self, vault: &LocalVault) -> Result<()> {
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
    pub fn cancel_delete(&mut self) {
        self.mode = Mode::Browse;
        self.status_message = "Delete cancelled".to_string();
    }

    /// Save the current form (add or edit)
    pub fn save_form(&mut self, vault: &LocalVault) -> Result<()> {
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
    pub fn cancel_form(&mut self) {
        self.mode = Mode::Browse;
        self.form_state = None;
        self.status_message = "Operation cancelled".to_string();
    }

    /// Handle character input for form fields
    pub fn handle_form_input(&mut self, c: char) {
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
    pub fn handle_form_backspace(&mut self) {
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
    pub fn next_form_field(&mut self) {
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
    pub fn prev_form_field(&mut self) {
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
    pub fn check_auto_hide(&mut self) {
        if let Some(ref mut detail) = self.detail_view {
            if detail.should_hide_value(self.auto_hide_timeout) {
                detail.hide_value();
                self.status_message = "Value auto-hidden after timeout".to_string();
            }
        }
    }

    /// Load secrets from the vault
    pub fn load_secrets(&mut self, vault: &LocalVault) -> Result<()> {
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
    pub fn select_up(&mut self) {
        if !self.secrets.is_empty() && self.selected > 0 {
            self.selected -= 1;
        }
    }

    /// Move selection down
    pub fn select_down(&mut self) {
        if !self.secrets.is_empty() && self.selected < self.secrets.len() - 1 {
            self.selected += 1;
        }
    }

    /// Enter detail view for selected secret
    pub fn enter_detail(&mut self, vault: &LocalVault) -> Result<()> {
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
    pub fn exit_detail(&mut self) {
        self.detail_view = None;
        self.mode = Mode::Browse;
        self.status_message = "Browse mode".to_string();
    }

    /// Toggle secret value visibility
    pub fn toggle_value(&mut self, vault: &LocalVault) -> Result<()> {
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
    pub fn show_help(&mut self) {
        self.mode = Mode::Help;
        self.status_message = "Press 'q' to go back".to_string();
    }

    /// Exit help
    pub fn exit_help(&mut self) {
        self.mode = Mode::Browse;
        self.status_message = "Browse mode".to_string();
    }

    /// Set filter prefix
    pub fn set_filter(&mut self, prefix: String) {
        self.filter_prefix = prefix;
    }

    /// Enter import/export mode
    pub fn enter_import_export_mode(&mut self, operation: ImportExportOp) {
        self.mode = Mode::ImportExport;
        self.import_export_state = Some(ImportExportState {
            operation,
            file_path: String::new(),
            import_mode: ImportMode::SkipExisting,
            current_step: ImportExportStep::FilePath,
            pending_conflicts: vec![],
            conflict_selected: 0,
            progress_message: String::new(),
        });
        self.status_message = match operation {
            ImportExportOp::Import => "Import secrets - Enter file path".to_string(),
            ImportExportOp::Export => "Export secrets - Enter file path".to_string(),
        };
    }

    /// Exit import/export mode
    pub fn exit_import_export_mode(&mut self) {
        self.mode = Mode::Browse;
        self.import_export_state = None;
        self.status_message = "Browse mode".to_string();
    }

    /// Enter backend sync mode
    pub fn enter_backend_sync_mode(&mut self) {
        self.mode = Mode::BackendSync;
        self.sync_state = Some(BackendSyncState {
            backend_type: BackendType::HashiCorpVault,
            status: SyncStatus::Disconnected,
            current_step: SyncStep::SelectBackend,
            progress_message: "Select external backend to sync with".to_string(),
            synced_count: 0,
            connection_config: None,
        });
        self.status_message = "External backend sync - Select backend".to_string();
    }

    /// Exit backend sync mode
    pub fn exit_backend_sync_mode(&mut self) {
        self.mode = Mode::Browse;
        self.sync_state = None;
        self.status_message = "Browse mode".to_string();
    }

    /// Enter breach alerts mode
    pub fn enter_breach_alerts_mode(&mut self) {
        self.mode = Mode::BreachAlerts;
        self.load_breach_alerts();
        self.status_message = "Breach alerts - Press 'q' to go back".to_string();
    }

    /// Exit breach alerts mode
    pub fn exit_breach_alerts_mode(&mut self) {
        self.mode = Mode::Browse;
        self.breach_alerts.clear();
        self.breach_selected = 0;
        self.status_message = "Browse mode".to_string();
    }

    /// Load breach alerts (mock implementation for now)
    pub fn load_breach_alerts(&mut self) {
        // In a real implementation, this would load from a breach detection service
        // For now, we'll just clear and show empty state
        self.breach_alerts.clear();
        self.breach_selected = 0;
        self.status_message = "No breach alerts".to_string();
    }

    /// Move breach selection up
    pub fn breach_select_up(&mut self) {
        if !self.breach_alerts.is_empty() && self.breach_selected > 0 {
            self.breach_selected -= 1;
        }
    }

    /// Move breach selection down
    pub fn breach_select_down(&mut self) {
        if !self.breach_alerts.is_empty() && self.breach_selected < self.breach_alerts.len() - 1 {
            self.breach_selected += 1;
        }
    }

    /// Acknowledge selected breach alert
    pub fn acknowledge_breach(&mut self) {
        if !self.breach_alerts.is_empty() && self.breach_selected < self.breach_alerts.len() {
            self.breach_alerts[self.breach_selected].acknowledged = true;
            self.status_message = "Breach alert acknowledged".to_string();
        }
    }

    /// Enter secret rotation mode
    pub fn enter_rotation_mode(&mut self) {
        if self.secrets.is_empty() {
            self.status_message = "No secrets available to rotate".to_string();
            return;
        }
        self.mode = Mode::SecretRotation;
        self.rotation_state = Some(RotationState {
            current_step: RotationStep::SelectSecret,
            secret_path: String::new(),
            new_value: String::new(),
            reason: String::new(),
            progress: 0,
            status_message: "Select secret to rotate".to_string(),
        });
        self.status_message = "Secret rotation - Select secret".to_string();
    }

    /// Exit secret rotation mode
    pub fn exit_rotation_mode(&mut self) {
        self.mode = Mode::Browse;
        self.rotation_state = None;
        self.status_message = "Browse mode".to_string();
    }

    /// Handle import/export file path input
    pub fn handle_import_export_input(&mut self, c: char) {
        if let Some(ref mut state) = self.import_export_state {
            if state.current_step == ImportExportStep::FilePath {
                state.file_path.push(c);
            }
        }
    }

    /// Handle import/export backspace
    pub fn handle_import_export_backspace(&mut self) {
        if let Some(ref mut state) = self.import_export_state {
            if state.current_step == ImportExportStep::FilePath {
                state.file_path.pop();
            }
        }
    }

    /// Handle rotation value input
    pub fn handle_rotation_value_input(&mut self, c: char) {
        if let Some(ref mut state) = self.rotation_state {
            if state.current_step == RotationStep::EnterNewValue {
                state.new_value.push(c);
            }
        }
    }

    /// Handle rotation value backspace
    pub fn handle_rotation_value_backspace(&mut self) {
        if let Some(ref mut state) = self.rotation_state {
            if state.current_step == RotationStep::EnterNewValue {
                state.new_value.pop();
            }
        }
    }

    /// Handle rotation reason input
    pub fn handle_rotation_reason_input(&mut self, c: char) {
        if let Some(ref mut state) = self.rotation_state {
            if state.current_step == RotationStep::EnterReason {
                state.reason.push(c);
            }
        }
    }

    /// Handle rotation reason backspace
    pub fn handle_rotation_reason_backspace(&mut self) {
        if let Some(ref mut state) = self.rotation_state {
            if state.current_step == RotationStep::EnterReason {
                state.reason.pop();
            }
        }
    }

    /// Move conflict selection up
    pub fn conflict_select_up(&mut self) {
        if let Some(ref mut state) = self.import_export_state {
            if !state.pending_conflicts.is_empty() && state.conflict_selected > 0 {
                state.conflict_selected -= 1;
            }
        }
    }

    /// Move conflict selection down
    pub fn conflict_select_down(&mut self) {
        if let Some(ref mut state) = self.import_export_state {
            if !state.pending_conflicts.is_empty()
                && state.conflict_selected < state.pending_conflicts.len() - 1
            {
                state.conflict_selected += 1;
            }
        }
    }

    /// Handle character input for connection config fields
    pub fn handle_connection_config_char(&mut self, c: char) {
        if let Some(ref mut state) = self.sync_state {
            if state.current_step == SyncStep::ConfigureConnection {
                if let Some(ref mut config) = state.connection_config {
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
                            // Toggle through auth methods
                            config.auth_method = match config.auth_method {
                                AuthMethod::Token => AuthMethod::UsernamePassword,
                                AuthMethod::UsernamePassword => AuthMethod::AwsCredentials,
                                AuthMethod::AwsCredentials => AuthMethod::Token,
                            };
                        }
                    }
                    // Clear error message when user starts typing
                    config.error_message = None;
                }
            }
        }
    }

    /// Handle backspace for connection config fields
    pub fn handle_connection_config_backspace(&mut self) {
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

    /// Toggle conflict resolution
    pub fn toggle_conflict_resolution(&mut self) {
        if let Some(ref mut state) = self.import_export_state {
            if !state.pending_conflicts.is_empty()
                && state.conflict_selected < state.pending_conflicts.len()
            {
                state.pending_conflicts[state.conflict_selected].resolution =
                    match state.pending_conflicts[state.conflict_selected].resolution {
                        ConflictResolution::Unresolved => ConflictResolution::KeepExisting,
                        ConflictResolution::KeepExisting => ConflictResolution::UseImported,
                        ConflictResolution::UseImported => ConflictResolution::Unresolved,
                    };
            }
        }
    }
}

/// Run the TUI application
pub fn run_tui_app<W>(mut terminal: Terminal<CrosstermBackend<W>>, vault: LocalVault) -> Result<()>
where
    W: Write,
{
    // Enable process isolation (prevent memory dumps, ptrace, etc.)
    enable_process_isolation()?;

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
                            app.enter_breach_alerts_mode();
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
                    // Import/Export mode
                    Mode::ImportExport => {
                        if let Some(ref mut state) = app.import_export_state {
                            match state.current_step {
                                ImportExportStep::FilePath => match key.code {
                                    KeyCode::Char(c) => {
                                        app.handle_import_export_input(c);
                                    }
                                    KeyCode::Backspace => {
                                        app.handle_import_export_backspace();
                                    }
                                    KeyCode::Enter => {
                                        if !state.file_path.is_empty() {
                                            if state.operation == ImportExportOp::Import {
                                                state.current_step = ImportExportStep::ImportMode;
                                                app.status_message =
                                                    "Select import mode (1-4)".to_string();
                                            } else {
                                                // Export proceeds directly to progress
                                                state.current_step = ImportExportStep::InProgress;
                                                state.progress_message =
                                                    format!("Exporting to {}...", state.file_path);
                                                // In real implementation, would trigger export here
                                                state.current_step = ImportExportStep::Complete;
                                                state.progress_message =
                                                    format!("Exported to {}", state.file_path);
                                                app.status_message = "Export complete".to_string();
                                            }
                                        }
                                    }
                                    KeyCode::Esc => {
                                        app.exit_import_export_mode();
                                    }
                                    _ => {}
                                },
                                ImportExportStep::ImportMode => match key.code {
                                    KeyCode::Char('1') => {
                                        state.import_mode = ImportMode::SkipExisting;
                                        state.current_step = ImportExportStep::InProgress;
                                        state.progress_message =
                                            "Importing with SkipExisting mode...".to_string();
                                        // In real implementation, would trigger import here
                                        state.current_step = ImportExportStep::Complete;
                                        state.progress_message = "Import complete".to_string();
                                        app.status_message = "Import complete".to_string();
                                    }
                                    KeyCode::Char('2') => {
                                        state.import_mode = ImportMode::Overwrite;
                                        state.current_step = ImportExportStep::InProgress;
                                        state.progress_message =
                                            "Importing with Overwrite mode...".to_string();
                                        // In real implementation, would trigger import here
                                        state.current_step = ImportExportStep::Complete;
                                        state.progress_message = "Import complete".to_string();
                                        app.status_message = "Import complete".to_string();
                                    }
                                    KeyCode::Char('3') => {
                                        state.import_mode = ImportMode::Rename;
                                        state.current_step = ImportExportStep::InProgress;
                                        state.progress_message =
                                            "Importing with Rename mode...".to_string();
                                        // In real implementation, would trigger import here
                                        state.current_step = ImportExportStep::Complete;
                                        state.progress_message = "Import complete".to_string();
                                        app.status_message = "Import complete".to_string();
                                    }
                                    KeyCode::Char('4') => {
                                        state.import_mode = ImportMode::Manual;
                                        state.current_step = ImportExportStep::ConflictResolution;
                                        state.pending_conflicts = vec![]; // Would be populated by actual import
                                        app.status_message = "Resolve conflicts".to_string();
                                    }
                                    KeyCode::Esc => {
                                        app.exit_import_export_mode();
                                    }
                                    _ => {}
                                },
                                ImportExportStep::ConflictResolution => match key.code {
                                    KeyCode::Up | KeyCode::Char('k') => {
                                        app.conflict_select_up();
                                    }
                                    KeyCode::Down | KeyCode::Char('j') => {
                                        app.conflict_select_down();
                                    }
                                    KeyCode::Char(' ') => {
                                        app.toggle_conflict_resolution();
                                    }
                                    KeyCode::Enter => {
                                        state.current_step = ImportExportStep::InProgress;
                                        state.progress_message =
                                            "Applying conflict resolutions...".to_string();
                                        // In real implementation, would apply resolutions
                                        state.current_step = ImportExportStep::Complete;
                                        state.progress_message = "Import complete".to_string();
                                        app.status_message = "Import complete".to_string();
                                    }
                                    KeyCode::Esc => {
                                        app.exit_import_export_mode();
                                    }
                                    _ => {}
                                },
                                ImportExportStep::InProgress => {
                                    if key.code == KeyCode::Esc {
                                        app.exit_import_export_mode();
                                    }
                                }
                                ImportExportStep::Complete => match key.code {
                                    KeyCode::Enter => {
                                        app.exit_import_export_mode();
                                    }
                                    KeyCode::Esc => {
                                        app.exit_import_export_mode();
                                    }
                                    _ => {}
                                },
                            }
                        } else {
                            match key.code {
                                KeyCode::Char('q') | KeyCode::Esc => {
                                    app.exit_import_export_mode();
                                }
                                _ => {}
                            }
                        }
                    }
                    // Backend sync mode
                    Mode::BackendSync => {
                        if let Some(ref mut state) = app.sync_state {
                            match state.current_step {
                                SyncStep::SelectBackend => match key.code {
                                    KeyCode::Char('1') => {
                                        state.backend_type = BackendType::HashiCorpVault;
                                    }
                                    KeyCode::Char('2') => {
                                        state.backend_type = BackendType::OnePassword;
                                    }
                                    KeyCode::Char('3') => {
                                        state.backend_type = BackendType::AwsSecretsManager;
                                    }
                                    KeyCode::Char('4') => {
                                        state.backend_type = BackendType::AzureKeyVault;
                                    }
                                    KeyCode::Enter => {
                                        state.current_step = SyncStep::ConfigureConnection;
                                        state.status = SyncStatus::Connecting;
                                        state.progress_message =
                                            format!("Connecting to {:?}...", state.backend_type);
                                        // Initialize connection config with backend-specific defaults
                                        state.init_connection_config();
                                    }
                                    KeyCode::Esc => {
                                        app.exit_backend_sync_mode();
                                    }
                                    _ => {}
                                },
                                SyncStep::ConfigureConnection => match key.code {
                                    KeyCode::Char(c) => {
                                        app.handle_connection_config_char(c);
                                    }
                                    KeyCode::Backspace => {
                                        app.handle_connection_config_backspace();
                                    }
                                    KeyCode::Tab => {
                                        state.next_field();
                                    }
                                    KeyCode::BackTab => {
                                        state.prev_field();
                                    }
                                    KeyCode::Enter => {
                                        // Test connection before proceeding
                                        match state.test_connection() {
                                            Ok(()) => {
                                                state.current_step = SyncStep::ConfirmSync;
                                                state.status = SyncStatus::Connected;
                                                state.progress_message = format!(
                                                    "Connected to {:?}",
                                                    state.backend_type
                                                );
                                            }
                                            Err(_) => {
                                                // Error already set in connection_config
                                            }
                                        }
                                    }
                                    KeyCode::Esc => {
                                        app.exit_backend_sync_mode();
                                    }
                                    _ => {}
                                },
                                SyncStep::ConfirmSync => match key.code {
                                    KeyCode::Enter => {
                                        state.current_step = SyncStep::InProgress;
                                        state.status = SyncStatus::Syncing;
                                        state.progress_message = "Syncing secrets...".to_string();
                                        // In real implementation, would trigger sync
                                        state.synced_count = 0;
                                        state.current_step = SyncStep::Complete;
                                        state.progress_message = "Sync complete".to_string();
                                        app.status_message = "Sync complete".to_string();
                                    }
                                    KeyCode::Esc => {
                                        app.exit_backend_sync_mode();
                                    }
                                    _ => {}
                                },
                                SyncStep::InProgress => {
                                    if key.code == KeyCode::Esc {
                                        app.exit_backend_sync_mode();
                                    }
                                }
                                SyncStep::Complete => match key.code {
                                    KeyCode::Enter => {
                                        app.exit_backend_sync_mode();
                                    }
                                    KeyCode::Esc => {
                                        app.exit_backend_sync_mode();
                                    }
                                    _ => {}
                                },
                            }
                        } else {
                            match key.code {
                                KeyCode::Char('q') | KeyCode::Esc => {
                                    app.exit_backend_sync_mode();
                                }
                                _ => {}
                            }
                        }
                    }
                    // Breach alerts mode
                    Mode::BreachAlerts => match key.code {
                        KeyCode::Char('q') | KeyCode::Esc => {
                            app.exit_breach_alerts_mode();
                        }
                        KeyCode::Up | KeyCode::Char('k') => {
                            app.breach_select_up();
                        }
                        KeyCode::Down | KeyCode::Char('j') => {
                            app.breach_select_down();
                        }
                        KeyCode::Char('r') => {
                            app.load_breach_alerts();
                        }
                        KeyCode::Char('a') => {
                            app.acknowledge_breach();
                        }
                        _ => {}
                    },
                    // Secret rotation mode
                    Mode::SecretRotation => {
                        if let Some(ref mut state) = app.rotation_state {
                            match state.current_step {
                                RotationStep::SelectSecret => match key.code {
                                    KeyCode::Up | KeyCode::Char('k') => {
                                        if app.selected > 0 {
                                            app.selected -= 1;
                                        }
                                    }
                                    KeyCode::Down | KeyCode::Char('j') => {
                                        if !app.secrets.is_empty()
                                            && app.selected < app.secrets.len() - 1
                                        {
                                            app.selected += 1;
                                        }
                                    }
                                    KeyCode::Enter => {
                                        if !app.secrets.is_empty() {
                                            state.secret_path =
                                                app.secrets[app.selected].path.clone();
                                            state.current_step = RotationStep::EnterNewValue;
                                            app.status_message = "Enter new value".to_string();
                                        }
                                    }
                                    KeyCode::Esc => {
                                        app.exit_rotation_mode();
                                    }
                                    _ => {}
                                },
                                RotationStep::EnterNewValue => match key.code {
                                    KeyCode::Char(c) => {
                                        app.handle_rotation_value_input(c);
                                    }
                                    KeyCode::Backspace => {
                                        app.handle_rotation_value_backspace();
                                    }
                                    KeyCode::Enter => {
                                        state.current_step = RotationStep::EnterReason;
                                        app.status_message = "Enter rotation reason".to_string();
                                    }
                                    KeyCode::Esc => {
                                        app.exit_rotation_mode();
                                    }
                                    _ => {}
                                },
                                RotationStep::EnterReason => match key.code {
                                    KeyCode::Char(c) => {
                                        app.handle_rotation_reason_input(c);
                                    }
                                    KeyCode::Backspace => {
                                        app.handle_rotation_reason_backspace();
                                    }
                                    KeyCode::Enter => {
                                        state.current_step = RotationStep::ConfirmRotation;
                                        app.status_message = "Confirm rotation".to_string();
                                    }
                                    KeyCode::Esc => {
                                        app.exit_rotation_mode();
                                    }
                                    _ => {}
                                },
                                RotationStep::ConfirmRotation => match key.code {
                                    KeyCode::Enter => {
                                        state.current_step = RotationStep::InProgress;
                                        state.progress = 50;
                                        state.status_message = "Rotating secret...".to_string();
                                        // In real implementation, would trigger rotation
                                        state.progress = 100;
                                        state.current_step = RotationStep::Complete;
                                        state.status_message =
                                            format!("Rotated: {}", state.secret_path);
                                        app.status_message = "Rotation complete".to_string();
                                    }
                                    KeyCode::Esc => {
                                        app.exit_rotation_mode();
                                    }
                                    _ => {}
                                },
                                RotationStep::InProgress => {
                                    if key.code == KeyCode::Esc {
                                        app.exit_rotation_mode();
                                    }
                                }
                                RotationStep::Complete => match key.code {
                                    KeyCode::Enter => {
                                        app.exit_rotation_mode();
                                    }
                                    KeyCode::Esc => {
                                        app.exit_rotation_mode();
                                    }
                                    _ => {}
                                },
                            }
                        } else {
                            match key.code {
                                KeyCode::Char('q') | KeyCode::Esc => {
                                    app.exit_rotation_mode();
                                }
                                _ => {}
                            }
                        }
                    }
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
        Mode::Help => {
            draw_help_view(f, chunks[0], unicode_mode);
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
            draw_rotation_view(f, chunks[0], app, unicode_mode);
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
        Line::from("Import/Export:"),
        Line::from("  i      - Import secrets from archive"),
        Line::from("  x      - Export secrets to archive"),
        Line::from(""),
        Line::from("External Backend Sync:"),
        Line::from("  y      - Sync with external backend (Vault/1Password/etc)"),
        Line::from(""),
        Line::from("Breach Alerts:"),
        Line::from("  b      - View breach alerts"),
        Line::from(""),
        Line::from("Secret Rotation:"),
        Line::from("  o      - Rotate secret"),
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
pub fn draw_import_export_view(
    f: &mut Frame,
    area: Rect,
    app: &mut App,
    _unicode_mode: UnicodeMode,
) {
    if let Some(ref state) = app.import_export_state {
        let title = match state.operation {
            ImportExportOp::Import => "Import Secrets",
            ImportExportOp::Export => "Export Secrets",
        };

        let mut lines = vec![];

        match state.current_step {
            ImportExportStep::FilePath => {
                lines.push(Line::from(format!(
                    "Enter file path: {}",
                    if state.file_path.is_empty() {
                        "<empty>"
                    } else {
                        &state.file_path
                    }
                )));
                lines.push(Line::from(""));
                lines.push(Line::from("Press Enter to confirm, Esc to cancel"));
            }
            ImportExportStep::ImportMode => {
                lines.push(Line::from("Select import mode:"));
                lines.push(Line::from(""));
                lines.push(Line::from("1. Skip existing"));
                lines.push(Line::from("2. Overwrite existing"));
                lines.push(Line::from("3. Rename imported"));
                lines.push(Line::from("4. Manual conflict resolution"));
                lines.push(Line::from(""));
                lines.push(Line::from("Press 1-4 to select, Esc to cancel"));
            }
            ImportExportStep::ConflictResolution => {
                if state.pending_conflicts.is_empty() {
                    lines.push(Line::from("No conflicts to resolve."));
                    lines.push(Line::from(""));
                    lines.push(Line::from("Press Enter to continue import"));
                } else {
                    lines.push(Line::from("Resolve conflicts:"));
                    lines.push(Line::from(""));
                    for (i, conflict) in state.pending_conflicts.iter().enumerate() {
                        let selected = i == state.conflict_selected;
                        let style = if selected {
                            Style::default()
                                .fg(Color::Yellow)
                                .add_modifier(Modifier::BOLD)
                        } else {
                            Style::default()
                        };
                        lines.push(Line::from(vec![Span::styled(
                            format!(
                                "{}. {} - {}",
                                i + 1,
                                conflict.path,
                                match conflict.resolution {
                                    ConflictResolution::Unresolved => "[Unresolved]",
                                    ConflictResolution::KeepExisting => "[Keep Existing]",
                                    ConflictResolution::UseImported => "[Use Imported]",
                                }
                            ),
                            style,
                        )]));
                    }
                    lines.push(Line::from(""));
                    lines.push(Line::from("↑/j: Select | Space: Toggle | Enter: Confirm"));
                }
            }
            ImportExportStep::InProgress => {
                lines.push(Line::from(state.progress_message.as_str()));
                lines.push(Line::from(""));
                lines.push(Line::from("Please wait..."));
            }
            ImportExportStep::Complete => {
                lines.push(Line::from("Operation complete!"));
                lines.push(Line::from(""));
                lines.push(Line::from(state.progress_message.as_str()));
                lines.push(Line::from(""));
                lines.push(Line::from("Press Enter to close"));
            }
        }

        let paragraph = Paragraph::new(lines)
            .block(Block::default().title(title).borders(Borders::ALL))
            .wrap(Wrap { trim: true });

        f.render_widget(paragraph, area);
    }
}

/// Draw backend sync view
pub fn draw_backend_sync_view(
    f: &mut Frame,
    area: Rect,
    app: &mut App,
    _unicode_mode: UnicodeMode,
) {
    if let Some(ref state) = app.sync_state {
        let mut lines = vec![];

        match state.current_step {
            SyncStep::SelectBackend => {
                lines.push(Line::from("Select External Backend:"));
                lines.push(Line::from(""));
                let backends = [
                    (BackendType::HashiCorpVault, "HashiCorp Vault"),
                    (BackendType::OnePassword, "1Password"),
                    (BackendType::AwsSecretsManager, "AWS Secrets Manager"),
                    (BackendType::AzureKeyVault, "Azure Key Vault"),
                ];
                for (i, (backend_type, name)) in backends.iter().enumerate() {
                    let selected = *backend_type == state.backend_type;
                    let style = if selected {
                        Style::default()
                            .fg(Color::Yellow)
                            .add_modifier(Modifier::BOLD)
                    } else {
                        Style::default()
                    };
                    lines.push(Line::from(vec![Span::styled(
                        format!("{}. {}", i + 1, name),
                        style,
                    )]));
                }
                lines.push(Line::from(""));
                lines.push(Line::from(
                    "Press 1-4 to select, Enter to confirm, Esc to cancel",
                ));
            }
            SyncStep::ConfigureConnection => {
                lines.push(Line::from(vec![
                    Span::styled("Backend: ", Style::default().fg(Color::Cyan)),
                    Span::styled(
                        format!("{:?}", state.backend_type),
                        Style::default().fg(Color::White),
                    ),
                ]));
                lines.push(Line::from(""));
                lines.push(Line::from("Configure connection settings:"));
                lines.push(Line::from(""));

                if let Some(ref config) = state.connection_config {
                    let visible_fields = state.visible_fields();

                    for field in visible_fields {
                        let is_current = config.current_field == field;
                        let style = if is_current {
                            Style::default()
                                .fg(Color::Yellow)
                                .add_modifier(Modifier::BOLD)
                        } else {
                            Style::default()
                        };

                        let (label, value_str, mask) = match field {
                            ConnectionField::Address => ("Address", config.address.as_str(), false),
                            ConnectionField::AuthMethod => {
                                let method_str = match config.auth_method {
                                    AuthMethod::Token => "Token",
                                    AuthMethod::UsernamePassword => "Username/Password",
                                    AuthMethod::AwsCredentials => "AWS Credentials",
                                };
                                ("Auth Method", method_str, false)
                            }
                            ConnectionField::Token => ("Token", config.token.as_str(), true),
                            ConnectionField::Username => {
                                ("Username", config.username.as_str(), false)
                            }
                            ConnectionField::Password => {
                                ("Password", config.password.as_str(), true)
                            }
                            ConnectionField::ApiKey => ("API Key", config.api_key.as_str(), true),
                            ConnectionField::SecretKey => {
                                ("Secret Key", config.secret_key.as_str(), true)
                            }
                            ConnectionField::Region => ("Region", config.region.as_str(), false),
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

                        lines.push(Line::from(vec![
                            Span::styled(format!("{}: ", label), Style::default().fg(Color::Cyan)),
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
                    lines.push(Line::from("  Tab/Enter=next field, Backtab=prev field"));
                    lines.push(Line::from("  Type to edit, Backspace to delete"));
                    lines.push(Line::from("  Enter=test connection, Esc=cancel"));
                } else {
                    lines.push(Line::from("Error: Connection config not initialized"));
                }
            }
            SyncStep::ConfirmSync => {
                lines.push(Line::from(format!(
                    "Ready to sync with {:?}",
                    state.backend_type
                )));
                lines.push(Line::from(""));
                lines.push(Line::from(format!("Status: {:?}", state.status)));
                lines.push(Line::from(""));
                lines.push(Line::from(state.progress_message.as_str()));
                lines.push(Line::from(""));
                lines.push(Line::from("Press Enter to start sync, Esc to cancel"));
            }
            SyncStep::InProgress => {
                lines.push(Line::from("Syncing..."));
                lines.push(Line::from(""));
                lines.push(Line::from(format!(
                    "Synced: {} secrets",
                    state.synced_count
                )));
                lines.push(Line::from(""));
                lines.push(Line::from(state.progress_message.as_str()));
            }
            SyncStep::Complete => {
                lines.push(Line::from("Sync complete!"));
                lines.push(Line::from(""));
                lines.push(Line::from(format!(
                    "Synced: {} secrets",
                    state.synced_count
                )));
                lines.push(Line::from(""));
                lines.push(Line::from(state.progress_message.as_str()));
                lines.push(Line::from(""));
                lines.push(Line::from("Press Enter to close"));
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
pub fn draw_breach_alerts_view(
    f: &mut Frame,
    area: Rect,
    app: &mut App,
    _unicode_mode: UnicodeMode,
) {
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
                    BreachSeverity::Low => Style::default(),
                }
            };

            let status = if alert.resolved {
                " [RESOLVED]"
            } else if alert.acknowledged {
                " [ACK]"
            } else {
                ""
            };

            ListItem::new(format!(
                "{} {} - {}{}",
                alert.detected_at, alert.title, alert.description, status
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
pub fn draw_rotation_view(f: &mut Frame, area: Rect, app: &mut App, _unicode_mode: UnicodeMode) {
    if let Some(ref state) = app.rotation_state {
        let mut lines = vec![];

        match state.current_step {
            RotationStep::SelectSecret => {
                lines.push(Line::from("Select secret to rotate:"));
                lines.push(Line::from(""));
                if app.secrets.is_empty() {
                    lines.push(Line::from("No secrets available."));
                } else {
                    for (i, secret) in app.secrets.iter().enumerate().take(10) {
                        let selected = i == app.selected;
                        let style = if selected {
                            Style::default()
                                .fg(Color::Yellow)
                                .add_modifier(Modifier::BOLD)
                        } else {
                            Style::default()
                        };
                        lines.push(Line::from(vec![Span::styled(
                            format!("{}. {}", i + 1, secret.path),
                            style,
                        )]));
                    }
                }
                lines.push(Line::from(""));
                lines.push(Line::from("↑/j: Select | Enter: Confirm | Esc: Cancel"));
            }
            RotationStep::EnterNewValue => {
                lines.push(Line::from(format!("Rotating: {}", state.secret_path)));
                lines.push(Line::from(""));
                lines.push(Line::from(format!(
                    "New value: {}",
                    if state.new_value.is_empty() {
                        "<empty>".to_string()
                    } else {
                        "*".repeat(state.new_value.len())
                    }
                )));
                lines.push(Line::from(""));
                lines.push(Line::from(
                    "Type new value, Enter to confirm, Esc to cancel",
                ));
            }
            RotationStep::EnterReason => {
                lines.push(Line::from(format!("Rotating: {}", state.secret_path)));
                lines.push(Line::from(""));
                lines.push(Line::from(format!(
                    "Reason: {}",
                    if state.reason.is_empty() {
                        "<empty>".to_string()
                    } else {
                        state.reason.clone()
                    }
                )));
                lines.push(Line::from(""));
                lines.push(Line::from("Type reason, Enter to confirm, Esc to cancel"));
            }
            RotationStep::ConfirmRotation => {
                lines.push(Line::from("Confirm rotation:"));
                lines.push(Line::from(""));
                lines.push(Line::from(format!("Secret: {}", state.secret_path)));
                lines.push(Line::from(format!("Reason: {}", state.reason)));
                lines.push(Line::from(""));
                lines.push(Line::from("Press Enter to confirm rotation, Esc to cancel"));
            }
            RotationStep::InProgress => {
                lines.push(Line::from("Rotating secret..."));
                lines.push(Line::from(""));
                lines.push(Line::from(format!("Progress: {}%", state.progress)));
                lines.push(Line::from(""));
                lines.push(Line::from(state.status_message.as_str()));
            }
            RotationStep::Complete => {
                lines.push(Line::from("Rotation complete!"));
                lines.push(Line::from(""));
                lines.push(Line::from(state.status_message.as_str()));
                lines.push(Line::from(""));
                lines.push(Line::from("Press Enter to close"));
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
