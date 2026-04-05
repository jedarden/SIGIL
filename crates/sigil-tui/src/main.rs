//! SIGIL TUI - Terminal UI for secret management
//!
//! This module provides a terminal user interface for managing secrets.
//! The TUI runs on a separate PTY with process isolation to prevent
//! the AI agent from accessing secret values through memory inspection.

#![warn(missing_docs)]
#![warn(clippy::all)]

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
use sigil_core::{SecretBackend, SecretPath};
use sigil_vault::LocalVault;
use std::io;
use std::time::Duration;

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
        });

        self.mode = Mode::Detail;
        self.status_message = "Press 'v' to reveal value, 'q' to go back".to_string();

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
                    detail.notes = Some(format!("[VALUE LOADED - {} bytes]", bytes.len()));
                    Ok::<(), anyhow::Error>(())
                })?;

                detail.value_shown = true;
                self.status_message = "Value loaded (masked for display)".to_string();
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
}

/// Run the TUI application
fn run_tui(mut terminal: Terminal<CrosstermBackend<std::io::Stdout>>) -> Result<()> {
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

    // Main layout
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .margin(1)
        .constraints([Constraint::Min(0), Constraint::Length(3)].as_ref())
        .split(size);

    match app.mode {
        Mode::Browse => {
            draw_browse_view(f, chunks[0], app);
        }
        Mode::Detail => {
            draw_detail_view(f, chunks[0], app);
        }
        Mode::Help => {
            draw_help_view(f, chunks[0]);
        }
    }

    // Status bar
    let status = Paragraph::new(app.status_message.as_str())
        .style(Style::default().fg(Color::Cyan))
        .block(Block::default().borders(Borders::ALL));
    f.render_widget(status, chunks[1]);
}

/// Draw browse view
fn draw_browse_view(f: &mut Frame, area: Rect, app: &mut App) {
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
fn draw_detail_view(f: &mut Frame, area: Rect, app: &mut App) {
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
fn draw_help_view(f: &mut Frame, area: Rect) {
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
        Line::from("  r      - Refresh secret list"),
        Line::from("  h/?    - Show this help"),
        Line::from("  q      - Quit"),
        Line::from(""),
        Line::from("Detail View:"),
        Line::from("  v      - Load secret value (masked)"),
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

fn main() -> Result<()> {
    // Initialize terminal
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen, EnableMouseCapture)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    // Clear screen
    terminal.clear()?;

    // Run TUI
    let result = run_tui(terminal);

    // Restore terminal
    disable_raw_mode()?;
    execute!(io::stdout(), LeaveAlternateScreen, DisableMouseCapture)?;

    result
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
