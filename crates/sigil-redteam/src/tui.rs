//! Real-time TUI dashboard for red-team testing
//!
//! Shows attacks in progress, detection status, and security metrics.

use crate::attack::{AttackResult, AttackStatus};
use crate::report::SecurityScore;
use crossterm::{
    event::{self, DisableMouseCapture, EnableMouseCapture, Event, KeyCode},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use ratatui::{
    backend::CrosstermBackend,
    layout::{Alignment, Constraint, Direction, Layout},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Paragraph, Wrap},
    Frame, Terminal,
};
use std::io;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;

/// Configuration for the red-team dashboard
#[derive(Debug, Clone)]
pub struct DashboardConfig {
    /// Refresh interval for the dashboard
    pub refresh_interval: Duration,
    /// Enable verbose output
    pub verbose: bool,
}

impl Default for DashboardConfig {
    fn default() -> Self {
        Self {
            refresh_interval: Duration::from_millis(100),
            verbose: false,
        }
    }
}

/// Shared state for the dashboard
#[derive(Debug, Clone)]
pub struct DashboardState {
    /// Current security score
    pub score: SecurityScore,
    /// Total attacks
    pub total_attacks: usize,
    /// Blocked attacks
    pub blocked: usize,
    /// Detected attacks (canary triggers)
    pub detected: usize,
    /// Evaded attacks
    pub evaded: usize,
    /// Errors
    pub errors: usize,
    /// Current attack being executed
    pub current_attack: Option<String>,
    /// Attack results
    pub results: Vec<AttackResult>,
    /// Start time
    pub start_time: Instant,
    /// Whether testing is complete
    pub complete: bool,
}

impl Default for DashboardState {
    fn default() -> Self {
        Self {
            score: SecurityScore::A,
            total_attacks: 0,
            blocked: 0,
            detected: 0,
            evaded: 0,
            errors: 0,
            current_attack: None,
            results: Vec::new(),
            start_time: Instant::now(),
            complete: false,
        }
    }
}

impl DashboardState {
    /// Update the state with a new attack result
    pub fn add_result(&mut self, result: AttackResult) {
        self.total_attacks += 1;

        match result.status {
            AttackStatus::Blocked => self.blocked += 1,
            AttackStatus::Detected => self.detected += 1,
            AttackStatus::Evaded => self.evaded += 1,
            AttackStatus::Error(_) => self.errors += 1,
        }

        self.results.push(result.clone());
        self.current_attack = None;

        // Recalculate score
        let total = self.total_attacks as f64;
        let blocked = (self.blocked + self.detected) as f64;
        let has_critical = self.results.iter().any(|r| {
            r.was_evaded() && r.details.get("severity").and_then(|v| v.as_str()) == Some("Critical")
        });

        self.score = SecurityScore::from_block_rate((blocked / total) * 100.0, has_critical);
    }

    /// Get the block rate as a percentage
    pub fn block_rate(&self) -> f64 {
        if self.total_attacks == 0 {
            return 100.0;
        }

        ((self.blocked + self.detected) as f64 / self.total_attacks as f64) * 100.0
    }

    /// Get elapsed time
    pub fn elapsed(&self) -> Duration {
        self.start_time.elapsed()
    }
}

/// Red-team TUI dashboard
pub struct RedTeamDashboard {
    /// Dashboard configuration
    config: DashboardConfig,
    /// Shared state
    state: Arc<RwLock<DashboardState>>,
}

impl RedTeamDashboard {
    /// Create a new dashboard
    pub fn new(config: DashboardConfig) -> Self {
        Self {
            config,
            state: Arc::new(RwLock::new(DashboardState::default())),
        }
    }

    /// Get the shared state
    pub fn state(&self) -> Arc<RwLock<DashboardState>> {
        self.state.clone()
    }

    /// Run the dashboard
    pub async fn run(&self) -> anyhow::Result<()> {
        // Setup terminal
        enable_raw_mode()?;
        let mut stdout = io::stdout();
        execute!(stdout, EnterAlternateScreen, EnableMouseCapture)?;
        let backend = CrosstermBackend::new(stdout);
        let mut terminal = Terminal::new(backend)?;

        // Event loop
        loop {
            let state = self.state.read().await;

            // Draw UI
            terminal.draw(|f| draw_ui(f, &state, &self.config))?;

            // Check if complete
            if state.complete {
                // Wait for user to press a key before exiting
                drop(state);
                tokio::time::sleep(Duration::from_millis(100)).await;
                if event::poll(Duration::from_millis(100))? {
                    if let Event::Key(_) = event::read()? {
                        break;
                    }
                }
                continue;
            }

            drop(state);

            // Handle events
            if event::poll(self.config.refresh_interval)? {
                if let Event::Key(key) = event::read()? {
                    match key.code {
                        KeyCode::Char('q') | KeyCode::Esc => {
                            break;
                        }
                        KeyCode::Char('v') => {
                            // Toggle verbose mode (would need mutable access)
                        }
                        _ => {}
                    }
                }
            }
        }

        // Restore terminal
        disable_raw_mode()?;
        execute!(
            terminal.backend_mut(),
            LeaveAlternateScreen,
            DisableMouseCapture
        )?;
        terminal.show_cursor()?;

        Ok(())
    }
}

/// Draw the dashboard UI
fn draw_ui(f: &mut Frame, state: &DashboardState, _config: &DashboardConfig) {
    let size = f.area();

    // Main layout
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints(
            [
                Constraint::Length(3), // Header
                Constraint::Length(9), // Stats
                Constraint::Min(10),   // Attack list
                Constraint::Length(3), // Footer
            ]
            .as_ref(),
        )
        .split(size);

    // Header
    let elapsed_min = state.elapsed().as_secs_f64() / 60.0;
    let elapsed_str = format!("{:.1}", elapsed_min);
    let header_text = vec![Line::from(vec![
        Span::styled("🔴", Style::default().fg(Color::Red)),
        Span::raw(" "),
        Span::styled(
            "SIGIL Red-Team Mode",
            Style::default().fg(Color::Red).add_modifier(Modifier::BOLD),
        ),
        Span::raw(" - "),
        Span::styled(&elapsed_str, Style::default().fg(Color::Cyan)),
        Span::raw(" minutes"),
    ])];

    let header = Paragraph::new(header_text)
        .block(Block::default().borders(Borders::ALL))
        .alignment(Alignment::Center);
    f.render_widget(header, chunks[0]);

    // Stats section
    let stats_chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints(
            [
                Constraint::Percentage(25),
                Constraint::Percentage(25),
                Constraint::Percentage(25),
                Constraint::Percentage(25),
            ]
            .as_ref(),
        )
        .split(chunks[1]);

    // Security score
    let score_color = match state.score {
        SecurityScore::A => Color::Green,
        SecurityScore::B => Color::Cyan,
        SecurityScore::C => Color::Yellow,
        SecurityScore::D => Color::Magenta,
        SecurityScore::F => Color::Red,
    };

    let score_text = vec![Line::from(vec![
        Span::styled("Security Score\n", Style::default().fg(Color::Gray)),
        Span::styled(
            format!("{}", state.score),
            Style::default()
                .fg(score_color)
                .add_modifier(Modifier::BOLD),
        ),
    ])];

    let score_widget = Paragraph::new(score_text)
        .block(Block::default().borders(Borders::ALL).title("Score"))
        .alignment(Alignment::Center);
    f.render_widget(score_widget, stats_chunks[0]);

    // Blocked
    let blocked_text = vec![Line::from(vec![
        Span::styled("BLOCKED\n", Style::default().fg(Color::Gray)),
        Span::styled(
            format!("{} ({:.1}%)", state.blocked, state.block_rate()),
            Style::default()
                .fg(Color::Green)
                .add_modifier(Modifier::BOLD),
        ),
    ])];

    let blocked_widget = Paragraph::new(blocked_text)
        .block(Block::default().borders(Borders::ALL).title("Blocked"))
        .alignment(Alignment::Center);
    f.render_widget(blocked_widget, stats_chunks[1]);

    // Detected
    let detected_text = vec![Line::from(vec![
        Span::styled("DETECTED\n", Style::default().fg(Color::Gray)),
        Span::styled(
            format!("{}", state.detected),
            Style::default()
                .fg(Color::Yellow)
                .add_modifier(Modifier::BOLD),
        ),
    ])];

    let detected_widget = Paragraph::new(detected_text)
        .block(Block::default().borders(Borders::ALL).title("Detected"))
        .alignment(Alignment::Center);
    f.render_widget(detected_widget, stats_chunks[2]);

    // Evaded
    let evaded_text = vec![Line::from(vec![
        Span::styled("EVADED\n", Style::default().fg(Color::Gray)),
        Span::styled(
            format!("{}", state.evaded),
            Style::default().fg(Color::Red).add_modifier(Modifier::BOLD),
        ),
    ])];

    let evaded_widget = Paragraph::new(evaded_text)
        .block(Block::default().borders(Borders::ALL).title("Evaded"))
        .alignment(Alignment::Center);
    f.render_widget(evaded_widget, stats_chunks[3]);

    // Attack list
    let mut attack_lines = vec![Line::from(vec![
        Span::styled(
            "Attack Results",
            Style::default().add_modifier(Modifier::BOLD),
        ),
        Span::raw(" ("),
        Span::styled(
            format!("{}", state.total_attacks),
            Style::default().fg(Color::Cyan),
        ),
        Span::raw(" total)"),
    ])];

    // Show recent attacks (most recent first)
    for result in state
        .results
        .iter()
        .rev()
        .take(chunks[2].height as usize - 3)
    {
        let (status, color) = match result.status {
            AttackStatus::Blocked => ("BLOCKED", Color::Green),
            AttackStatus::Detected => ("DETECTED", Color::Yellow),
            AttackStatus::Evaded => ("EVADED", Color::Red),
            AttackStatus::Error(_) => ("ERROR", Color::Gray),
        };

        attack_lines.push(Line::from(vec![
            Span::styled(format!("[{:8}] ", status), Style::default().fg(color)),
            Span::raw(&result.attack_name),
            Span::styled(
                format!(" ({}ms)", result.duration_ms),
                Style::default().fg(Color::DarkGray),
            ),
        ]));
    }

    // Show current attack if any
    if let Some(ref attack) = state.current_attack {
        attack_lines.push(Line::from(vec![
            Span::styled(
                "RUNNING: ",
                Style::default()
                    .fg(Color::Cyan)
                    .add_modifier(Modifier::SLOW_BLINK),
            ),
            Span::raw(attack),
        ]));
    }

    let attack_list = Paragraph::new(attack_lines)
        .block(Block::default().borders(Borders::ALL).title("Attacks"))
        .wrap(Wrap { trim: true });
    f.render_widget(attack_list, chunks[2]);

    // Footer
    let footer_text = vec![Line::from(vec![
        Span::raw("Press "),
        Span::styled("q", Style::default().fg(Color::Cyan)),
        Span::raw(" to quit"),
    ])];

    let footer = Paragraph::new(footer_text)
        .block(Block::default().borders(Borders::ALL))
        .alignment(Alignment::Center)
        .style(Style::default().fg(Color::DarkGray));
    f.render_widget(footer, chunks[3]);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dashboard_state_default() {
        let state = DashboardState::default();
        assert_eq!(state.total_attacks, 0);
        assert_eq!(state.blocked, 0);
        assert_eq!(state.evaded, 0);
        assert_eq!(state.block_rate(), 100.0);
    }

    #[test]
    fn test_dashboard_state_add_result() {
        let mut state = DashboardState::default();

        state.add_result(AttackResult {
            attack_name: "test".to_string(),
            status: AttackStatus::Blocked,
            duration_ms: 100,
            details: std::collections::HashMap::new(),
        });

        assert_eq!(state.total_attacks, 1);
        assert_eq!(state.blocked, 1);
        assert_eq!(state.block_rate(), 100.0);
    }

    #[test]
    fn test_dashboard_config_default() {
        let config = DashboardConfig::default();
        assert_eq!(config.refresh_interval, Duration::from_millis(100));
        assert!(!config.verbose);
    }
}
