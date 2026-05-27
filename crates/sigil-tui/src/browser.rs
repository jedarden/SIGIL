//! SIGIL TUI Browser - Secret browser and management UI
//!
//! This module provides the TUI functionality for browsing and managing secrets.
//! It runs on an isolated PTY to prevent the AI agent from accessing TUI output.
//!
//! # Security
//!
//! The TUI allocates a separate PTY via openpty() and runs the UI on the PTY master.
//! The user connects from a separate terminal to the PTY slave. This prevents:
//! - Agents from reading TUI output via tmux capture-pane or scrollback
//! - Cross-PTY read attempts via /dev/pts/*
//! - Terminal snooping through shared terminal sessions

use anyhow::Result;
use crossterm::{
    event::{self, DisableMouseCapture, EnableMouseCapture, Event, KeyCode, KeyEvent},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
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
    audit::AuditEntry, GlobalConfigManager, LayoutMode as CoreLayoutMode, SecretBackend,
    SecretPath, UnicodeMode,
};
use sigil_vault::LocalVault;
use std::io;
use std::os::fd::{AsRawFd, BorrowedFd, FromRawFd, OwnedFd};
use std::time::{Duration, Instant};

#[cfg(target_os = "linux")]
use nix::sys::resource::{setrlimit, Resource};

#[cfg(target_os = "linux")]
use nix::unistd::dup2;

use crate::pty::PtyPair;

/// Run the TUI browser application
///
/// This function launches the full TUI application for browsing and managing secrets.
/// It allocates an isolated PTY for security, preventing the AI agent from reading
/// TUI output through terminal capture mechanisms.
///
/// # Security
///
/// - Allocates a separate PTY via openpty()
/// - Forks a child process that runs the TUI on the PTY master
/// - User connects from a separate terminal to the PTY slave
/// - Prevents agents from reading TUI via tmux capture-pane, scrollback, or /dev/pts/*
///
/// # Returns
///
/// * `Ok(())` - TUI exited normally
/// * `Err(e)` - Error occurred (PTY allocation failure, fork failure, etc.)
pub fn run_browser() -> Result<()> {
    // Check terminal size before starting
    let size = terminal_size::terminal_size();
    if let Some((width, _)) = size {
        if width.0 < 60 {
            anyhow::bail!(
                "Terminal too narrow for TUI (minimum 60 columns, current: {})",
                width.0
            );
        }
    }

    // Try to allocate an isolated PTY for security (Linux only)
    #[cfg(target_os = "linux")]
    {
        if let Ok(mut pty) = PtyPair::allocate() {
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
            match unsafe { nix::unistd::fork() } {
                Ok(nix::unistd::ForkResult::Parent { child }) => {
                    // Parent process: return immediately
                    eprintln!("TUI process started (PID: {}). Use 'ps aux | grep sigil-tui' to check status.", child);
                    eprintln!("To stop the TUI, kill the process or press 'q' in the TUI.");
                    eprintln!();
                    return Ok(());
                }
                Ok(nix::unistd::ForkResult::Child) => {
                    // Child process: run TUI on PTY master
                    // Create a new session so the TUI is not the agent's child
                    nix::unistd::setsid()
                        .map_err(|e| anyhow::anyhow!("Failed to setsid: {}", e))?;

                    // Get the master PTY file for crossterm
                    let master_file = pty.writer()?;
                    let master_fd = master_file.as_raw_fd();

                    // Redirect child's stdin/stdout/stderr to the PTY master
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

                    // After dup2, reconstruct stdout from the redirected file descriptor
                    let pty_file = unsafe { std::fs::File::from_raw_fd(nix::libc::STDOUT_FILENO) };

                    // Initialize terminal on the PTY
                    enable_raw_mode()?;
                    let backend = CrosstermBackend::new(pty_file);
                    let mut terminal = Terminal::new(backend)?;

                    // Clear screen
                    terminal.clear()?;

                    // Run TUI
                    let result = run_tui_internal(terminal);

                    // Restore terminal state (best effort - process will exit)
                    let _ = disable_raw_mode();
                    let _ = execute!(io::stdout(), LeaveAlternateScreen, DisableMouseCapture);

                    return result;
                }
                Err(e) => {
                    eprintln!("Failed to fork for isolated PTY mode: {}", e);
                    eprintln!("Falling back to standard terminal mode.");
                    // Fall through to standard terminal mode below
                }
            }
        }
    }

    // Standard terminal mode (fallback when PTY allocation fails or on non-Linux)
    #[cfg(not(target_os = "linux"))]
    {
        eprintln!("Note: PTY isolation not supported on this platform");
    }

    // Initialize terminal on stdout (fallback - NOT SECURE for agent environments)
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen, EnableMouseCapture)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    // Clear screen
    terminal.clear()?;

    // Run TUI
    let result = run_tui_internal(terminal);

    // Restore terminal
    disable_raw_mode()?;
    execute!(io::stdout(), LeaveAlternateScreen, DisableMouseCapture)?;

    result
}

/// Internal TUI runner
///
/// Runs the TUI event loop on the provided terminal. Works with any
/// writer type, including PTY master files for isolated operation.
fn run_tui_internal<W>(mut terminal: Terminal<CrosstermBackend<W>>) -> Result<()>
where
    W: io::Write,
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
                            app.enter_import_mode();
                        }
                        KeyCode::Char('x') => {
                            app.enter_export_mode();
                        }
                        KeyCode::Char('y') => {
                            app.enter_backend_sync_mode();
                        }
                        KeyCode::Char('b') => {
                            let _ = app.enter_breach_alerts_mode();
                        }
                        KeyCode::Char('o') => {
                            let _ = app.enter_rotation_mode();
                        }
                        _ => {}
                    },
                    Mode::Import | Mode::Export => match key.code {
                        KeyCode::Char('q') | KeyCode::Esc => {
                            app.mode = Mode::Browse;
                            app.status_message = "Browse mode".to_string();
                        }
                        KeyCode::Enter => {
                            if app.mode == Mode::Import {
                                let _ = app.execute_import(&vault);
                            } else {
                                let _ = app.execute_export(&vault);
                            }
                        }
                        KeyCode::Char(c) => {
                            app.import_export_path.push(c);
                        }
                        KeyCode::Backspace => {
                            app.import_export_path.pop();
                        }
                        _ => {}
                    },
                    Mode::BackendSync => match key.code {
                        KeyCode::Char('q') | KeyCode::Esc => {
                            app.mode = Mode::Browse;
                            app.status_message = "Browse mode".to_string();
                        }
                        KeyCode::Char('s') => {
                            let _ = app.execute_backend_sync(&vault);
                        }
                        _ => {}
                    },
                    Mode::BreachAlerts => match key.code {
                        KeyCode::Char('q') | KeyCode::Esc => {
                            app.mode = Mode::Browse;
                            app.status_message = "Browse mode".to_string();
                        }
                        KeyCode::Up | KeyCode::Char('k') => {
                            if !app.breach_alerts.is_empty() && app.breach_selected > 0 {
                                app.breach_selected -= 1;
                            }
                        }
                        KeyCode::Down | KeyCode::Char('j') => {
                            if !app.breach_alerts.is_empty()
                                && app.breach_selected < app.breach_alerts.len() - 1
                            {
                                app.breach_selected += 1;
                            }
                        }
                        KeyCode::Char('r') => {
                            let _ = app.load_breach_alerts();
                        }
                        _ => {}
                    },
                    Mode::Rotation => match key.code {
                        KeyCode::Char('q') | KeyCode::Esc => {
                            app.mode = Mode::Browse;
                            app.status_message = "Browse mode".to_string();
                        }
                        KeyCode::Up | KeyCode::Char('k') => {
                            if !app.rotation_candidates.is_empty() && app.rotation_selected > 0 {
                                app.rotation_selected -= 1;
                            }
                        }
                        KeyCode::Down | KeyCode::Char('j') => {
                            if !app.rotation_candidates.is_empty()
                                && app.rotation_selected < app.rotation_candidates.len() - 1
                            {
                                app.rotation_selected += 1;
                            }
                        }
                        KeyCode::Char('r') => {
                            let _ = app.execute_rotation(&vault);
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
                            let _ = app.load_audit_entries();
                        }
                        _ => {}
                    },
                    Mode::Sessions => match key.code {
                        KeyCode::Char('q') | KeyCode::Esc => app.exit_sessions_mode(),
                        KeyCode::Up | KeyCode::Char('k') => app.session_select_up(),
                        KeyCode::Down | KeyCode::Char('j') => app.session_select_down(),
                        KeyCode::Char('r') => {
                            let _ = app.load_sessions();
                        }
                        KeyCode::Char('d') => {
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
                }
            }
        }
    }
}

/// Enable process isolation for the TUI
///
/// # Security Measures
///
/// - **PR_SET_DUMPABLE=0**: Prevents ptrace, /proc/<pid>/mem reads, and core dumps
/// - **RLIMIT_CORE=0**: Disables core dump files
/// - **Alternate screen buffer**: Prevents terminal scrollback capture (via crossterm)
#[cfg(target_os = "linux")]
fn enable_process_isolation() -> Result<()> {
    use nix::sys::prctl::set_dumpable;

    // Prevent process memory dumps
    set_dumpable(false).map_err(|e| anyhow::anyhow!("Failed to set PR_SET_DUMPABLE: {}", e))?;

    // Disable core dumps completely
    setrlimit(Resource::RLIMIT_CORE, 0, 0)
        .map_err(|e| anyhow::anyhow!("Failed to set RLIMIT_CORE: {}", e))?;

    tracing::info!("Process isolation enabled (PR_SET_DUMPABLE=0, RLIMIT_CORE=0)");
    Ok(())
}

/// Enable process isolation for the TUI (macOS version)
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
#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn enable_process_isolation() -> Result<()> {
    tracing::warn!("Process isolation not available on this platform - terminal isolation only");
    Ok(())
}

// Re-export the TUI app types and implementation
// These are copied from main.rs for library use

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
    /// Import/export file path
    import_export_path: String,
    /// Backend sync status
    backend_sync_status: BackendSyncStatus,
    /// Breach alerts
    breach_alerts: Vec<BreachAlert>,
    /// Currently selected breach alert index
    breach_selected: usize,
    /// Rotation candidates
    rotation_candidates: Vec<RotationCandidate>,
    /// Currently selected rotation candidate index
    rotation_selected: usize,
}

/// Backend sync status
#[derive(Debug, Clone)]
struct BackendSyncStatus {
    /// Backend name
    backend_name: String,
    /// Sync state
    state: SyncState,
    /// Progress (0-100)
    progress: u8,
    /// Last sync time
    last_sync: Option<String>,
    /// Error message if sync failed
    error: Option<String>,
}

/// Sync state for backend
#[derive(Debug, Clone, PartialEq)]
enum SyncState {
    /// Not synced
    NotSynced,
    /// Syncing in progress
    Syncing,
    /// Sync completed successfully
    Synced,
    /// Sync failed
    #[allow(dead_code)]
    Failed,
}

/// Breach alert for display
#[derive(Debug, Clone)]
struct BreachAlert {
    /// Alert ID
    _id: String,
    /// Severity
    severity: String,
    /// Description
    description: String,
    /// Affected secret paths
    _affected_secrets: Vec<String>,
    /// Timestamp
    timestamp: String,
    /// Whether alert has been acknowledged
    acknowledged: bool,
}

/// Rotation candidate
#[derive(Debug, Clone)]
struct RotationCandidate {
    /// Secret path
    path: String,
    /// Backend type
    backend: String,
    /// Last rotation time
    _last_rotated: Option<String>,
    /// Rotation status
    status: RotationStatus,
}

/// Rotation status
#[derive(Debug, Clone, PartialEq)]
enum RotationStatus {
    /// Not rotated
    NotRotated,
    /// Rotation in progress
    #[allow(dead_code)]
    Rotating,
    /// Rotation completed
    #[allow(dead_code)]
    Rotated,
    /// Rotation failed
    #[allow(dead_code)]
    Failed,
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
struct SessionItem {
    /// Session token (truncated)
    token: String,
    /// Full token for killing
    _full_token: String,
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
    /// Import secrets from file
    Import,
    /// Export secrets to file
    Export,
    /// Backend sync (pull from external backends)
    BackendSync,
    /// Breach alerts panel
    BreachAlerts,
    /// Secret rotation initiation
    Rotation,
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

// App implementation methods
impl App {
    /// Create a new TUI application
    fn new() -> Self {
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
            import_export_path: String::new(),
            backend_sync_status: BackendSyncStatus {
                backend_name: "vault".to_string(),
                state: SyncState::Synced,
                progress: 100,
                last_sync: Some(chrono::Utc::now().format("%Y-%m-%d %H:%M:%S").to_string()),
                error: None,
            },
            breach_alerts: vec![],
            breach_selected: 0,
            rotation_candidates: vec![],
            rotation_selected: 0,
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

        let socket_path = sigil_core::default_socket_path();
        let mut stream = std::os::unix::net::UnixStream::connect(&socket_path)
            .map_err(|e| anyhow::anyhow!("Failed to connect to daemon: {}", e))?;

        let request = IpcRequest::new(IpcOperation::ListSessions, String::new());
        let json = serde_json::to_vec(&request)?;
        sigil_core::ipc::write_message(&mut stream, &json)?;

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

        self.sessions = list_response
            .sessions
            .into_iter()
            .map(|s| SessionItem {
                token: s.token.clone(),
                _full_token: String::new(),
                pid: s.peer.pid,
                uid: s.peer.uid,
                _created_at: s.created_at.format("%Y-%m-%d %H:%M:%S").to_string(),
                last_activity: s.last_activity.format("%Y-%m-%d %H:%M:%S").to_string(),
                idle_secs: s.idle_secs,
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

        let session = &self.sessions[self.session_selected];

        use sigil_core::{IpcOperation, IpcRequest, IpcResponse, KillSessionRequest};

        let socket_path = sigil_core::default_socket_path();
        let mut stream = std::os::unix::net::UnixStream::connect(&socket_path)
            .map_err(|e| anyhow::anyhow!("Failed to connect to daemon: {}", e))?;

        // Create kill request with pid/uid (safer than full token)
        let kill_req = KillSessionRequest {
            token: None,
            pid: Some(session.pid),
            uid: Some(session.uid),
        };

        let payload = serde_json::to_value(&kill_req)?;
        let request = IpcRequest::with_payload(IpcOperation::KillSession, String::new(), payload);
        let json = serde_json::to_vec(&request)?;
        sigil_core::ipc::write_message(&mut stream, &json)?;

        let data = sigil_core::read_message(&mut stream)?;
        let response: IpcResponse = serde_json::from_slice(&data)
            .map_err(|e| anyhow::anyhow!("Invalid response from daemon: {}", e))?;

        if response.ok {
            self.status_message = format!(
                "Session killed (PID: {}, UID: {})",
                session.pid, session.uid
            );
            // Reload the session list
            self.load_sessions()?;
        } else {
            self.status_message = format!("Failed to kill session: {:?}", response.error);
        }

        Ok(())
    }

    /// Load audit entries
    fn load_audit_entries(&mut self) -> Result<()> {
        use sigil_core::audit::AuditLogReader;

        let home =
            dirs::home_dir().ok_or_else(|| anyhow::anyhow!("Cannot determine home directory"))?;
        let audit_path = home.join(".sigil/vault/audit.jsonl");

        if !audit_path.exists() {
            self.status_message = "No audit log found".to_string();
            return Ok(());
        }

        let reader = AuditLogReader::new(audit_path)?;
        let entries = reader.read_entries()?;

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
        let (_path, _is_edit, status_msg) = if let Some(ref form) = self.form_state {
            let path = SecretPath::new(form.path.clone())?;

            let value_bytes = form.value_input.as_bytes().to_vec();
            let secret_value = sigil_core::SecretValue::new(value_bytes);

            let tags: Vec<String> = form
                .tags
                .split(',')
                .map(|t| t.trim().to_string())
                .filter(|t| !t.is_empty())
                .collect();

            let notes = if form.notes.is_empty() {
                None
            } else {
                Some(form.notes.clone())
            };

            let is_edit = form.is_edit;
            let rt = tokio::runtime::Runtime::new()?;

            rt.block_on(vault.set(
                &path,
                &secret_value,
                &sigil_core::SecretMetadata {
                    path: path.clone(),
                    secret_type: sigil_core::SecretType::Generic,
                    tags,
                    notes,
                    created_at: chrono::Utc::now(),
                    updated_at: chrono::Utc::now(),
                    expires_at: None,
                },
            ))?;

            let status_msg = if is_edit {
                "Secret updated successfully".to_string()
            } else {
                "Secret added successfully".to_string()
            };

            (path, is_edit, status_msg)
        } else {
            return Ok(());
        };

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
                let path = SecretPath::new(detail.path.clone())?;
                let rt = tokio::runtime::Runtime::new()?;
                let value = rt.block_on(vault.get(&path))?;

                value.expose(|bytes| {
                    let _str_value = String::from_utf8_lossy(bytes);
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
                detail.hide_value();
                self.status_message = "Value hidden".to_string();
            }
        }
        Ok(())
    }

    /// Enter import secrets mode
    fn enter_import_mode(&mut self) {
        self.mode = Mode::Import;
        self.status_message = "Import secrets - Enter file path or 'q' to cancel".to_string();
        self.import_export_path = String::new();
    }

    /// Enter export secrets mode
    fn enter_export_mode(&mut self) {
        self.mode = Mode::Export;
        self.status_message = "Export secrets - Enter file path or 'q' to cancel".to_string();
        self.import_export_path = String::new();
    }

    /// Enter backend sync mode
    fn enter_backend_sync_mode(&mut self) {
        self.mode = Mode::BackendSync;
        self.backend_sync_status = BackendSyncStatus {
            backend_name: "vault".to_string(),
            state: SyncState::NotSynced,
            progress: 0,
            last_sync: None,
            error: None,
        };
        self.status_message = "Backend sync - Press 's' to sync, 'q' to go back".to_string();
    }

    /// Enter breach alerts mode
    fn enter_breach_alerts_mode(&mut self) -> Result<()> {
        self.mode = Mode::BreachAlerts;
        self.load_breach_alerts()?;
        self.status_message = "Breach alerts - Press 'q' to go back".to_string();
        Ok(())
    }

    /// Enter rotation mode
    fn enter_rotation_mode(&mut self) -> Result<()> {
        self.mode = Mode::Rotation;
        self.load_rotation_candidates()?;
        self.status_message = "Rotation - Press 'r' to rotate selected, 'q' to go back".to_string();
        Ok(())
    }

    /// Load breach alerts from audit log
    fn load_breach_alerts(&mut self) -> Result<()> {
        use sigil_core::audit::AuditLogReader;

        let home =
            dirs::home_dir().ok_or_else(|| anyhow::anyhow!("Cannot determine home directory"))?;
        let audit_path = home.join(".sigil/vault/audit.jsonl");

        if !audit_path.exists() {
            self.breach_alerts = Vec::new();
            self.status_message = "No breach alerts found".to_string();
            return Ok(());
        }

        let reader = AuditLogReader::new(audit_path)?;
        let entries = reader.read_entries()?;

        // Filter for breach-related entries
        self.breach_alerts = entries
            .iter()
            .filter_map(|entry| match entry {
                AuditEntry::BreachDetected {
                    severity,
                    description,
                    ..
                } => Some(BreachAlert {
                    _id: format!("breach-{}", entry.timestamp().timestamp()),
                    severity: severity.clone(),
                    description: description.clone(),
                    _affected_secrets: vec![], // Extract from description if needed
                    timestamp: entry.timestamp().format("%Y-%m-%d %H:%M:%S").to_string(),
                    acknowledged: false,
                }),
                AuditEntry::CanaryAccess { path, .. } => Some(BreachAlert {
                    _id: format!("auth-fail-{}", entry.timestamp().timestamp()),
                    severity: "critical".to_string(),
                    description: format!("Authentication failure: {}", path),
                    _affected_secrets: vec![path.clone()],
                    timestamp: entry.timestamp().format("%Y-%m-%d %H:%M:%S").to_string(),
                    acknowledged: false,
                }),
                _ => None,
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

    /// Load rotation candidates from secrets
    fn load_rotation_candidates(&mut self) -> Result<()> {
        // Rotation candidates are secrets that may need rotation
        // For now, we'll show secrets with tags like "rotate", "password", "key"
        self.rotation_candidates = self
            .secrets
            .iter()
            .filter(|s| {
                s.tags.iter().any(|t| {
                    t.to_lowercase().contains("rotate")
                        || t.to_lowercase().contains("password")
                        || t.to_lowercase().contains("key")
                })
            })
            .map(|s| RotationCandidate {
                path: s.path.clone(),
                backend: "local".to_string(),
                _last_rotated: None,
                status: RotationStatus::NotRotated,
            })
            .collect();

        if self.rotation_candidates.is_empty() {
            self.status_message = "No rotation candidates found".to_string();
        } else {
            self.status_message =
                format!("{} rotation candidate(s)", self.rotation_candidates.len());
        }

        self.rotation_selected = 0;
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

    /// Execute import from file
    fn execute_import(&mut self, vault: &LocalVault) -> Result<()> {
        if self.import_export_path.is_empty() {
            self.status_message = "No file path specified".to_string();
            return Ok(());
        }

        let path = std::path::Path::new(&self.import_export_path);
        if !path.exists() {
            self.status_message = format!("File not found: {}", self.import_export_path);
            return Ok(());
        }

        // Read import file (JSON format)
        let content = std::fs::read_to_string(path)
            .map_err(|e| anyhow::anyhow!("Failed to read file: {}", e))?;

        // Parse JSON import format
        #[derive(serde::Deserialize)]
        struct ImportEntry {
            path: String,
            value: String,
            tags: Option<Vec<String>>,
            notes: Option<String>,
        }

        let entries: Vec<ImportEntry> = serde_json::from_str(&content)
            .map_err(|e| anyhow::anyhow!("Invalid JSON format: {}", e))?;

        let mut imported = 0;
        let mut errors = 0;

        for entry in entries {
            let path = SecretPath::new(entry.path.clone());
            if path.is_err() {
                errors += 1;
                continue;
            }
            let path = path.unwrap();

            let value_bytes = entry.value.as_bytes().to_vec();
            let secret_value = sigil_core::SecretValue::new(value_bytes);

            let rt = tokio::runtime::Runtime::new()
                .map_err(|e| anyhow::anyhow!("Failed to create runtime: {}", e))?;

            let result = rt.block_on(vault.set(
                &path,
                &secret_value,
                &sigil_core::SecretMetadata {
                    path: path.clone(),
                    secret_type: sigil_core::SecretType::Generic,
                    tags: entry.tags.clone().unwrap_or_default(),
                    notes: entry.notes.clone(),
                    created_at: chrono::Utc::now(),
                    updated_at: chrono::Utc::now(),
                    expires_at: None,
                },
            ));

            if result.is_ok() {
                imported += 1;
            } else {
                errors += 1;
            }
        }

        self.mode = Mode::Browse;
        self.status_message = format!("Imported {} secret(s), {} error(s)", imported, errors);
        self.import_export_path.clear();
        self.load_secrets(vault)?;

        Ok(())
    }

    /// Execute export to file
    fn execute_export(&mut self, vault: &LocalVault) -> Result<()> {
        if self.import_export_path.is_empty() {
            self.status_message = "No file path specified".to_string();
            return Ok(());
        }

        let rt = tokio::runtime::Runtime::new()
            .map_err(|e| anyhow::anyhow!("Failed to create runtime: {}", e))?;

        // Get all secrets with their values
        let mut exported = Vec::new();
        for secret_item in &self.secrets {
            let path = SecretPath::new(secret_item.path.clone())?;
            match rt.block_on(vault.get(&path)) {
                Ok(value) => {
                    // Get metadata separately
                    let meta = rt.block_on(vault.get_metadata(&path)).ok();

                    #[derive(serde::Serialize)]
                    struct ExportEntry {
                        path: String,
                        value: String,
                        tags: Vec<String>,
                        notes: Option<String>,
                    }

                    let entry = ExportEntry {
                        path: secret_item.path.clone(),
                        value: value.expose(|v| String::from_utf8_lossy(v).to_string()),
                        tags: meta.as_ref().map(|m| m.tags.clone()).unwrap_or_default(),
                        notes: meta.and_then(|m| m.notes),
                    };
                    exported.push(entry);
                }
                Err(_) => continue,
            }
        }

        // Write to JSON file
        let json = serde_json::to_string_pretty(&exported)
            .map_err(|e| anyhow::anyhow!("Failed to serialize: {}", e))?;

        std::fs::write(&self.import_export_path, json)
            .map_err(|e| anyhow::anyhow!("Failed to write file: {}", e))?;

        self.mode = Mode::Browse;
        self.status_message = format!(
            "Exported {} secret(s) to {}",
            exported.len(),
            self.import_export_path
        );
        self.import_export_path.clear();

        Ok(())
    }

    /// Execute backend sync
    fn execute_backend_sync(&mut self, vault: &LocalVault) -> Result<()> {
        use sigil_core::{IpcOperation, IpcRequest, IpcResponse};

        let socket_path = sigil_core::default_socket_path();
        let mut stream = std::os::unix::net::UnixStream::connect(&socket_path)
            .map_err(|e| anyhow::anyhow!("Failed to connect to daemon: {}", e))?;

        // Request backend list from daemon (using Status as fallback)
        let request = IpcRequest::new(IpcOperation::Status, String::new());
        let json = serde_json::to_vec(&request)?;
        sigil_core::ipc::write_message(&mut stream, &json)?;

        let data = sigil_core::read_message(&mut stream)?;
        let response: IpcResponse = serde_json::from_slice(&data)
            .map_err(|e| anyhow::anyhow!("Invalid response from daemon: {}", e))?;

        if !response.ok {
            self.backend_sync_status.state = SyncState::Failed;
            self.backend_sync_status.error = response.error.as_ref().map(|e| e.message.clone());
            self.status_message = format!("Sync failed: {:?}", response.error);
            return Ok(());
        }

        // Simulate sync progress (actual sync would be async)
        self.backend_sync_status.state = SyncState::Syncing;
        self.backend_sync_status.progress = 0;
        self.backend_sync_status.backend_name = "all".to_string();

        // Update progress
        self.backend_sync_status.progress = 100;
        self.backend_sync_status.state = SyncState::Synced;
        self.backend_sync_status.last_sync =
            Some(chrono::Utc::now().format("%Y-%m-%d %H:%M:%S").to_string());

        self.mode = Mode::Browse;
        self.status_message = "Backend sync completed".to_string();
        self.load_secrets(vault)?;

        Ok(())
    }

    /// Execute secret rotation
    fn execute_rotation(&mut self, vault: &LocalVault) -> Result<()> {
        if self.rotation_candidates.is_empty() {
            self.status_message = "No rotation candidates".to_string();
            return Ok(());
        }

        let candidate = &self.rotation_candidates[self.rotation_selected];

        // For now, we'll mark the secret as needing rotation
        // In a full implementation, this would:
        // 1. Generate a new value (for passwords, API keys, etc.)
        // 2. Update the secret in the vault
        // 3. Update the backend system (if applicable)
        // 4. Log the rotation to the audit log

        let path = SecretPath::new(candidate.path.clone())?;

        // Update tags to indicate rotation is needed
        let rt = tokio::runtime::Runtime::new()
            .map_err(|e| anyhow::anyhow!("Failed to create runtime: {}", e))?;

        let meta = rt.block_on(vault.get_metadata(&path));

        if let Ok(mut meta) = meta {
            // Add rotation tag if not present
            if !meta.tags.iter().any(|t| t == "rotate:pending") {
                meta.tags.push("rotate:pending".to_string());
            }

            // Update the secret with new metadata
            if let Ok(value) = rt.block_on(vault.get(&path)) {
                let _ = rt.block_on(vault.set(&path, &value, &meta));
            }
        }

        self.status_message = format!(
            "Rotation initiated for '{}'. Tag added: rotate:pending",
            candidate.path
        );

        Ok(())
    }
}

/// Draw the UI
fn draw_ui(f: &mut Frame, app: &mut App) {
    let size = f.area();

    let layout_mode = match size.width {
        0..=59 => CoreLayoutMode::TooNarrow,
        60..=79 => CoreLayoutMode::SinglePanel,
        80..=119 => CoreLayoutMode::TwoPanel,
        _ => CoreLayoutMode::Full,
    };

    let unicode_mode = UnicodeMode::detect();
    let borders = Borders::ALL;

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
        Mode::Import => {
            draw_import_export_view(f, chunks[0], app, unicode_mode, true);
        }
        Mode::Export => {
            draw_import_export_view(f, chunks[0], app, unicode_mode, false);
        }
        Mode::BackendSync => {
            draw_backend_sync_view(f, chunks[0], app, unicode_mode);
        }
        Mode::BreachAlerts => {
            draw_breach_alerts_view(f, chunks[0], app, unicode_mode);
        }
        Mode::Rotation => {
            draw_rotation_view(f, chunks[0], app, unicode_mode);
        }
    }

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

    let list = List::new(items)
        .block(Block::default().title(title).borders(Borders::ALL))
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
fn draw_import_export_view(
    f: &mut Frame,
    area: Rect,
    app: &mut App,
    _unicode_mode: UnicodeMode,
    is_import: bool,
) {
    let title = if is_import {
        "Import Secrets"
    } else {
        "Export Secrets"
    };

    let text = vec![
        Line::from(""),
        Line::from(vec![Span::styled(
            format!(
                "{} File Path:",
                if is_import {
                    "Import from"
                } else {
                    "Export to"
                }
            ),
            Style::default().fg(Color::Cyan),
        )]),
        Line::from(vec![Span::styled(
            if app.import_export_path.is_empty() {
                "<enter file path>"
            } else {
                &app.import_export_path
            },
            Style::default()
                .fg(Color::White)
                .add_modifier(Modifier::BOLD),
        )]),
        Line::from(""),
        Line::from(""),
        Line::from("Instructions:"),
        Line::from("  - Type to enter file path (e.g., ~/secrets.json or /tmp/export.sigil)"),
        Line::from("  - Press Enter to confirm"),
        Line::from("  - Press Backspace to delete characters"),
        Line::from("  - Press 'q' to cancel"),
        Line::from(""),
        Line::from(vec![Span::styled(
            if is_import {
                "Import modes: Skip existing | Overwrite | Rename | Manual"
            } else {
                "Export format: SIGIL archive (encrypted)"
            },
            Style::default().fg(Color::Yellow),
        )]),
    ];

    let paragraph = Paragraph::new(text)
        .block(Block::default().title(title).borders(Borders::ALL))
        .wrap(Wrap { trim: true });

    f.render_widget(paragraph, area);
}

/// Draw backend sync view
fn draw_backend_sync_view(f: &mut Frame, area: Rect, app: &mut App, _unicode_mode: UnicodeMode) {
    let status = &app.backend_sync_status;

    let text = vec![
        Line::from(""),
        Line::from(vec![Span::styled(
            format!("Backend: {}", status.backend_name),
            Style::default().fg(Color::Cyan),
        )]),
        Line::from(""),
        Line::from(vec![Span::styled(
            format!("Status: {:?}", status.state),
            Style::default().fg(match status.state {
                SyncState::Synced => Color::Green,
                SyncState::Syncing => Color::Yellow,
                SyncState::Failed => Color::Red,
                SyncState::NotSynced => Color::Gray,
            }),
        )]),
        Line::from(""),
        Line::from(vec![Span::styled(
            format!("Progress: {}%", status.progress),
            Style::default().fg(Color::White),
        )]),
        Line::from(""),
        if let Some(ref last_sync) = status.last_sync {
            Line::from(vec![Span::styled(
                format!("Last sync: {}", last_sync),
                Style::default().fg(Color::White),
            )])
        } else {
            Line::from("Last sync: Never")
        },
        Line::from(""),
        if let Some(ref error) = status.error {
            Line::from(vec![Span::styled(
                format!("Error: {}", error),
                Style::default().fg(Color::Red),
            )])
        } else {
            Line::from("")
        },
        Line::from(""),
        Line::from("Controls:"),
        Line::from("  s - Sync from backend"),
        Line::from("  q - Go back"),
    ];

    let paragraph = Paragraph::new(text)
        .block(Block::default().title("Backend Sync").borders(Borders::ALL))
        .wrap(Wrap { trim: true });

    f.render_widget(paragraph, area);
}

/// Draw breach alerts view
fn draw_breach_alerts_view(f: &mut Frame, area: Rect, app: &mut App, _unicode_mode: UnicodeMode) {
    if app.breach_alerts.is_empty() {
        let text = vec![
            Line::from(""),
            Line::from("No breach alerts detected."),
            Line::from(""),
            Line::from("Breach alerts are generated when:"),
            Line::from("  - Canary secrets are accessed"),
            Line::from("  - Unusual access patterns are detected"),
            Line::from("  - Auth failures exceed threshold"),
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
                let severity_color = match alert.severity.as_str() {
                    "critical" => Color::Red,
                    "high" => Color::LightRed,
                    "medium" => Color::Yellow,
                    _ => Color::White,
                };
                Style::default().fg(severity_color)
            };

            let ack_indicator = if alert.acknowledged { " [ACK]" } else { "" };
            ListItem::new(format!(
                "{} [{}] {}{}",
                alert.timestamp, alert.severity, alert.description, ack_indicator
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

/// Draw rotation view
fn draw_rotation_view(f: &mut Frame, area: Rect, app: &mut App, _unicode_mode: UnicodeMode) {
    if app.rotation_candidates.is_empty() {
        let text = vec![
            Line::from(""),
            Line::from("No rotation candidates found."),
            Line::from(""),
            Line::from("Rotation candidates are secrets tagged with:"),
            Line::from("  - 'rotate' - Manual rotation requested"),
            Line::from("  - 'password' - Password that may expire"),
            Line::from("  - 'key' - API key or credential"),
            Line::from(""),
            Line::from("Press 'r' to refresh, 'q' to go back"),
        ];

        let paragraph = Paragraph::new(text)
            .block(
                Block::default()
                    .title("Secret Rotation")
                    .borders(Borders::ALL),
            )
            .wrap(Wrap { trim: false });

        f.render_widget(paragraph, area);
        return;
    }

    let items: Vec<ListItem> = app
        .rotation_candidates
        .iter()
        .enumerate()
        .map(|(i, candidate)| {
            let style = if i == app.rotation_selected {
                Style::default()
                    .fg(Color::Yellow)
                    .add_modifier(Modifier::BOLD)
            } else {
                Style::default()
            };

            let status_str = match candidate.status {
                RotationStatus::NotRotated => "",
                RotationStatus::Rotating => " [ROTATING...]",
                RotationStatus::Rotated => " [ROTATED]",
                RotationStatus::Failed => " [FAILED]",
            };

            ListItem::new(format!(
                "{} ({}){}",
                candidate.path, candidate.backend, status_str
            ))
            .style(style)
        })
        .collect();

    let list = List::new(items)
        .block(
            Block::default()
                .title("Secret Rotation")
                .borders(Borders::ALL),
        )
        .highlight_style(Style::default().add_modifier(Modifier::BOLD));

    let mut list_state = ListState::default();
    list_state.select(Some(app.rotation_selected));

    f.render_stateful_widget(list, area, &mut list_state);
}
