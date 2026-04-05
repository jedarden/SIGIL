//! TUI approval prompt for secret access requests
//!
//! This module provides a terminal UI for approving secret access requests.
//! It presents the user with options to grant or deny access with various
//! time bounds or conditions.

use anyhow::Result;
use crossterm::{
    event::{self, DisableMouseCapture, EnableMouseCapture, Event, KeyCode, KeyModifiers},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use ratatui::{
    backend::CrosstermBackend,
    layout::{Alignment, Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Clear, Paragraph, Wrap},
    Frame, Terminal,
};
use std::io;
use std::time::{Duration, Instant};

/// Approval request details
#[derive(Debug, Clone)]
pub struct ApprovalRequest {
    /// Agent identifier (e.g., "claude-session-a7f3e2")
    pub agent_id: String,
    /// Secret path being requested (e.g., "db/production/password")
    pub secret_path: String,
    /// Reason for the request
    pub reason: String,
    /// Working directory where the request originated
    pub working_dir: Option<String>,
    /// Requested duration (e.g., "5m", "1h", "session")
    pub requested_duration: String,
}

/// Approval decision
#[derive(Debug, Clone, PartialEq)]
pub enum ApprovalDecision {
    /// Approve for 5 minutes
    Approve5Min,
    /// Approve for 1 hour
    Approve1Hour,
    /// Approve for the session (until agent exits)
    ApproveSession,
    /// Always allow this secret for this agent/project
    AlwaysAllow,
    /// Deny this request
    Deny,
    /// Deny and flag as suspicious
    DenyAndFlag,
    /// Trigger emergency lockdown (Ctrl+L)
    Lockdown,
}

impl ApprovalDecision {
    /// Get the duration string for this decision
    pub fn duration(&self) -> Option<&str> {
        match self {
            ApprovalDecision::Approve5Min => Some("5m"),
            ApprovalDecision::Approve1Hour => Some("1h"),
            ApprovalDecision::ApproveSession => Some("session"),
            ApprovalDecision::AlwaysAllow => Some("always"),
            ApprovalDecision::Deny | ApprovalDecision::DenyAndFlag | ApprovalDecision::Lockdown => {
                None
            }
        }
    }

    /// Whether this is an approval decision
    pub fn is_approval(&self) -> bool {
        matches!(
            self,
            ApprovalDecision::Approve5Min
                | ApprovalDecision::Approve1Hour
                | ApprovalDecision::ApproveSession
                | ApprovalDecision::AlwaysAllow
        )
    }

    /// Whether this decision should flag as suspicious
    pub fn is_suspicious(&self) -> bool {
        matches!(self, ApprovalDecision::DenyAndFlag)
    }

    /// Whether this decision triggers lockdown
    pub fn is_lockdown(&self) -> bool {
        matches!(self, ApprovalDecision::Lockdown)
    }
}

/// Approval prompt application state
struct ApprovalApp {
    /// The request being approved
    request: ApprovalRequest,
    /// Currently selected option
    selected: usize,
    /// Options available
    options: Vec<ApprovalOption>,
    /// Start time (for timeout tracking)
    start_time: Option<Instant>,
    /// Timeout in seconds (None = no timeout)
    timeout_secs: Option<u64>,
}

/// Approval option display
struct ApprovalOption {
    /// The decision this option represents
    decision: ApprovalDecision,
    /// Display key (e.g., "a", "s", "h")
    key: char,
    /// Display label
    label: String,
    /// Description
    description: String,
}

impl ApprovalApp {
    /// Create a new approval prompt app
    fn new(request: ApprovalRequest) -> Self {
        Self::with_timeout(request, None)
    }

    /// Create a new approval prompt app with timeout
    fn with_timeout(request: ApprovalRequest, timeout_secs: Option<u64>) -> Self {
        let options = vec![
            ApprovalOption {
                decision: ApprovalDecision::Approve5Min,
                key: 'a',
                label: "Approve 5 min".to_string(),
                description: "Grant access for 5 minutes".to_string(),
            },
            ApprovalOption {
                decision: ApprovalDecision::Approve1Hour,
                key: 'h',
                label: "Approve 1 hour".to_string(),
                description: "Grant access for 1 hour".to_string(),
            },
            ApprovalOption {
                decision: ApprovalDecision::ApproveSession,
                key: 's',
                label: "Approve session".to_string(),
                description: "Grant access until agent exits".to_string(),
            },
            ApprovalOption {
                decision: ApprovalDecision::AlwaysAllow,
                key: 'A',
                label: "Always allow".to_string(),
                description: "Permanently allow this secret for this agent/project".to_string(),
            },
            ApprovalOption {
                decision: ApprovalDecision::Deny,
                key: 'd',
                label: "Deny".to_string(),
                description: "Deny this request".to_string(),
            },
            ApprovalOption {
                decision: ApprovalDecision::DenyAndFlag,
                key: 'D',
                label: "Deny + Flag".to_string(),
                description: "Deny and log as suspicious behavior".to_string(),
            },
        ];

        Self {
            request,
            selected: 0,
            options,
            start_time: timeout_secs.map(|_| Instant::now()),
            timeout_secs,
        }
    }

    /// Get the currently selected decision
    fn selected_decision(&self) -> ApprovalDecision {
        self.options[self.selected].decision.clone()
    }

    /// Move selection up
    fn select_up(&mut self) {
        if self.selected > 0 {
            self.selected -= 1;
        }
    }

    /// Move selection down
    fn select_down(&mut self) {
        if self.selected < self.options.len() - 1 {
            self.selected += 1;
        }
    }

    /// Check if timeout has been reached
    fn is_timeout_reached(&self) -> bool {
        if let (Some(start), Some(timeout)) = (self.start_time, self.timeout_secs) {
            start.elapsed() >= Duration::from_secs(timeout)
        } else {
            false
        }
    }

    /// Get remaining seconds until timeout
    fn remaining_seconds(&self) -> Option<u64> {
        if let (Some(start), Some(timeout)) = (self.start_time, self.timeout_secs) {
            let elapsed = start.elapsed().as_secs();
            if elapsed < timeout {
                Some(timeout - elapsed)
            } else {
                Some(0)
            }
        } else {
            None
        }
    }

    /// Select option by key
    fn select_by_key(&mut self, key: char) -> bool {
        for (i, option) in self.options.iter().enumerate() {
            if option.key == key {
                self.selected = i;
                return true;
            }
        }
        false
    }
}

/// Draw the approval prompt UI
fn draw_ui(f: &mut Frame, app: &ApprovalApp) {
    let size = f.area();

    // Create a centered popup (80% of width, 60% of height)
    let popup_width = size.width * 4 / 5;
    let popup_height = size.height * 3 / 5;
    let popup_x = (size.width - popup_width) / 2;
    let popup_y = (size.height - popup_height) / 2;

    let popup_area = Rect::new(popup_x, popup_y, popup_width, popup_height);

    // Clear the area behind the popup
    f.render_widget(Clear, popup_area);

    // Create layout for the popup
    // Footer height is 2 if there's a timeout, 1 otherwise
    let footer_height = if app.timeout_secs.is_some() { 3 } else { 2 };

    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints(
            [
                Constraint::Length(3),             // Title
                Constraint::Length(7),             // Request details
                Constraint::Min(6),                // Options
                Constraint::Length(footer_height), // Footer
            ]
            .as_ref(),
        )
        .margin(1)
        .split(popup_area);

    // Title
    let title = Paragraph::new("🔑 Secret Access Request")
        .block(
            Block::default()
                .borders(Borders::ALL)
                .border_style(Style::default().fg(Color::Yellow)),
        )
        .alignment(Alignment::Center)
        .style(
            Style::default()
                .fg(Color::Yellow)
                .add_modifier(Modifier::BOLD),
        );
    f.render_widget(title, chunks[0]);

    // Request details
    let details_text = vec![
        Line::from(vec![
            Span::styled("Agent: ", Style::default().fg(Color::Cyan)),
            Span::raw(&app.request.agent_id),
        ]),
        Line::from(vec![
            Span::styled("Secret: ", Style::default().fg(Color::Cyan)),
            Span::raw(&app.request.secret_path),
        ]),
        Line::from(vec![
            Span::styled("Reason: ", Style::default().fg(Color::Cyan)),
            Span::raw(&app.request.reason),
        ]),
        Line::from(vec![
            Span::styled("Requested: ", Style::default().fg(Color::Cyan)),
            Span::raw(&app.request.requested_duration),
        ]),
        Line::from(vec![
            Span::styled("Working in: ", Style::default().fg(Color::Cyan)),
            Span::raw(app.request.working_dir.as_deref().unwrap_or("(unknown)")),
        ]),
    ];

    let details = Paragraph::new(details_text)
        .block(Block::default().borders(Borders::ALL))
        .wrap(Wrap { trim: true });
    f.render_widget(details, chunks[1]);

    // Options
    let options_text: Vec<Line> = app
        .options
        .iter()
        .enumerate()
        .map(|(i, option)| {
            let is_selected = i == app.selected;
            let style = if is_selected {
                Style::default()
                    .fg(Color::Green)
                    .add_modifier(Modifier::BOLD)
            } else {
                Style::default().fg(Color::Gray)
            };

            Line::from(vec![
                Span::styled(
                    format!("[{}] ", option.key),
                    Style::default()
                        .fg(Color::Yellow)
                        .add_modifier(Modifier::BOLD),
                ),
                Span::styled(&option.label, style),
                Span::raw(" - "),
                Span::styled(&option.description, Style::default().fg(Color::DarkGray)),
            ])
        })
        .collect();

    let options = Paragraph::new(options_text)
        .block(Block::default().borders(Borders::ALL).title("Options"))
        .wrap(Wrap { trim: true });
    f.render_widget(options, chunks[2]);

    // Footer
    let footer_text = if let Some(remaining) = app.remaining_seconds() {
        let timeout_color = if remaining <= 10 {
            Color::Red
        } else if remaining <= 30 {
            Color::Yellow
        } else {
            Color::Green
        };
        vec![
            Line::from(vec![
                Span::styled("↑↓", Style::default().fg(Color::Cyan)),
                Span::raw(" navigate, "),
                Span::styled("Enter", Style::default().fg(Color::Cyan)),
                Span::raw(" select, "),
                Span::styled("Esc/q", Style::default().fg(Color::Cyan)),
                Span::raw(" cancel"),
            ]),
            Line::from(vec![
                Span::styled(
                    "Ctrl+L",
                    Style::default().fg(Color::Red).add_modifier(Modifier::BOLD),
                ),
                Span::raw(" emergency lockdown, "),
                Span::raw("Timeout in: "),
                Span::styled(
                    format!("{}s", remaining),
                    Style::default()
                        .fg(timeout_color)
                        .add_modifier(Modifier::BOLD),
                ),
            ]),
        ]
    } else {
        vec![Line::from(vec![
            Span::styled("↑↓", Style::default().fg(Color::Cyan)),
            Span::raw(" navigate, "),
            Span::styled("Enter", Style::default().fg(Color::Cyan)),
            Span::raw(" select, "),
            Span::styled("Esc/q", Style::default().fg(Color::Cyan)),
            Span::raw(" cancel, "),
            Span::styled(
                "Ctrl+L",
                Style::default().fg(Color::Red).add_modifier(Modifier::BOLD),
            ),
            Span::raw(" emergency lockdown"),
        ])]
    };

    let footer = Paragraph::new(footer_text)
        .block(Block::default().borders(Borders::ALL))
        .alignment(Alignment::Center)
        .style(Style::default().fg(Color::DarkGray));
    f.render_widget(footer, chunks[3]);
}

/// Approval prompt - shows a TUI prompt for secret access approval
///
/// # Arguments
///
/// * `request` - The approval request details
///
/// # Returns
///
/// * `Ok(Some(decision))` - User made a decision
/// * `Ok(None)` - User cancelled (treated as deny)
/// * `Err(e)` - Error occurred
pub struct ApprovalPrompt;

impl ApprovalPrompt {
    /// Show approval prompt and wait for user decision
    ///
    /// # Arguments
    ///
    /// * `request` - The approval request details
    ///
    /// # Returns
    ///
    /// * `Ok(Some(decision))` - User made a decision
    /// * `Ok(None)` - User cancelled (Esc/q without selection)
    /// * `Err(e)` - Error occurred
    pub fn approve(request: ApprovalRequest) -> Result<Option<ApprovalDecision>> {
        // Setup terminal
        enable_raw_mode()?;
        let mut stdout = io::stdout();
        execute!(stdout, EnterAlternateScreen, EnableMouseCapture)?;
        let backend = CrosstermBackend::new(stdout);
        let mut terminal = Terminal::new(backend)?;

        // Create app
        let mut app = ApprovalApp::new(request);

        // Run event loop
        let result = loop {
            // Draw UI
            terminal.draw(|f| draw_ui(f, &app))?;

            // Handle events
            if event::poll(Duration::from_millis(100))? {
                if let Event::Key(key) = event::read()? {
                    // Check for Ctrl+L to trigger lockdown
                    if key.code == KeyCode::Char('l')
                        && key.modifiers.contains(KeyModifiers::CONTROL)
                    {
                        break Ok(Some(ApprovalDecision::Lockdown));
                    }

                    match key.code {
                        KeyCode::Up | KeyCode::Char('k') => {
                            app.select_up();
                        }
                        KeyCode::Down | KeyCode::Char('j') => {
                            app.select_down();
                        }
                        KeyCode::Enter => {
                            break Ok(Some(app.selected_decision()));
                        }
                        KeyCode::Esc | KeyCode::Char('q') => {
                            break Ok(None);
                        }
                        KeyCode::Char(c) => {
                            if app.select_by_key(c) {
                                break Ok(Some(app.selected_decision()));
                            }
                        }
                        _ => {}
                    }
                }
            }
        };

        // Restore terminal
        disable_raw_mode()?;
        execute!(
            terminal.backend_mut(),
            LeaveAlternateScreen,
            DisableMouseCapture
        )?;
        terminal.show_cursor()?;

        result
    }

    /// Show approval prompt with a timeout
    ///
    /// # Arguments
    ///
    /// * `request` - The approval request details
    /// * `timeout_secs` - Timeout in seconds (default deny if no response)
    ///
    /// # Returns
    ///
    /// * `Ok(Some(decision))` - User made a decision
    /// * `Ok(None)` - User cancelled or timed out
    /// * `Err(e)` - Error occurred
    pub fn approve_with_timeout(
        request: ApprovalRequest,
        timeout_secs: u64,
    ) -> Result<Option<ApprovalDecision>> {
        // Setup terminal
        enable_raw_mode()?;
        let mut stdout = io::stdout();
        execute!(stdout, EnterAlternateScreen, EnableMouseCapture)?;
        let backend = CrosstermBackend::new(stdout);
        let mut terminal = Terminal::new(backend)?;

        // Create app with timeout
        let mut app = ApprovalApp::with_timeout(request, Some(timeout_secs));

        // Run event loop
        let result = loop {
            // Check for timeout
            if app.is_timeout_reached() {
                break Ok(None); // Timeout = deny
            }

            // Draw UI
            terminal.draw(|f| draw_ui(f, &app))?;

            // Handle events
            if event::poll(Duration::from_millis(100))? {
                if let Event::Key(key) = event::read()? {
                    // Check for Ctrl+L to trigger lockdown
                    if key.code == KeyCode::Char('l')
                        && key.modifiers.contains(KeyModifiers::CONTROL)
                    {
                        break Ok(Some(ApprovalDecision::Lockdown));
                    }

                    match key.code {
                        KeyCode::Up | KeyCode::Char('k') => {
                            app.select_up();
                        }
                        KeyCode::Down | KeyCode::Char('j') => {
                            app.select_down();
                        }
                        KeyCode::Enter => {
                            break Ok(Some(app.selected_decision()));
                        }
                        KeyCode::Esc | KeyCode::Char('q') => {
                            break Ok(None);
                        }
                        KeyCode::Char(c) => {
                            if app.select_by_key(c) {
                                break Ok(Some(app.selected_decision()));
                            }
                        }
                        _ => {}
                    }
                }
            }
        };

        // Restore terminal
        disable_raw_mode()?;
        execute!(
            terminal.backend_mut(),
            LeaveAlternateScreen,
            DisableMouseCapture
        )?;
        terminal.show_cursor()?;

        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_approval_decision_duration() {
        assert_eq!(ApprovalDecision::Approve5Min.duration(), Some("5m"));
        assert_eq!(ApprovalDecision::Approve1Hour.duration(), Some("1h"));
        assert_eq!(ApprovalDecision::ApproveSession.duration(), Some("session"));
        assert_eq!(ApprovalDecision::AlwaysAllow.duration(), Some("always"));
        assert_eq!(ApprovalDecision::Deny.duration(), None);
    }

    #[test]
    fn test_approval_decision_is_approval() {
        assert!(ApprovalDecision::Approve5Min.is_approval());
        assert!(ApprovalDecision::Approve1Hour.is_approval());
        assert!(ApprovalDecision::ApproveSession.is_approval());
        assert!(ApprovalDecision::AlwaysAllow.is_approval());
        assert!(!ApprovalDecision::Deny.is_approval());
        assert!(!ApprovalDecision::DenyAndFlag.is_approval());
    }

    #[test]
    fn test_approval_decision_is_suspicious() {
        assert!(!ApprovalDecision::Deny.is_suspicious());
        assert!(ApprovalDecision::DenyAndFlag.is_suspicious());
    }
}
