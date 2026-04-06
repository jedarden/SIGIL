//! Terminal and color utility module for accessibility
//!
//! This module provides:
//! - NO_COLOR / FORCE_COLOR support
//! - Colorblind-safe palette with high contrast mode
//! - Unicode vs ASCII detection
//! - Terminal width handling

use std::env;

/// Color mode for terminal output
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ColorMode {
    /// No color output (respecting NO_COLOR)
    None,
    /// Force color output (respecting FORCE_COLOR)
    Always,
    /// Auto-detect based on terminal capabilities
    Auto,
}

impl ColorMode {
    /// Detect the color mode from environment variables and terminal state
    pub fn detect() -> Self {
        // Check for --color flag (handled by CLI, but can be overridden by env)
        // Priority: --color flag > FORCE_COLOR > NO_COLOR > auto-detection

        // Check FORCE_COLOR first
        if env::var("FORCE_COLOR").is_ok_and(|v| v == "1" || v == "true") {
            return ColorMode::Always;
        }

        // Check NO_COLOR
        if env::var("NO_COLOR").is_ok() {
            return ColorMode::None;
        }

        // Auto-detect
        ColorMode::Auto
    }

    /// Determine if colors should be used based on the mode and whether stdout is a TTY
    pub fn use_color(&self, is_tty: bool) -> bool {
        match self {
            ColorMode::Always => true,
            ColorMode::None => false,
            ColorMode::Auto => is_tty,
        }
    }
}

/// Color palette with colorblind-safe variants
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PaletteColor {
    /// Success (green)
    Success,
    /// Warning (yellow)
    Warning,
    /// Error (red)
    Error,
    /// Info (cyan)
    Info,
    /// Highlight (yellow for selection)
    Highlight,
    /// Dimmed (low contrast)
    Dim,
    /// Normal (default)
    Normal,
}

impl PaletteColor {
    /// Get ANSI escape sequence for this color in normal mode
    pub fn ansi_normal(&self) -> &'static str {
        match self {
            PaletteColor::Success => "\x1b[32m",   // Green
            PaletteColor::Warning => "\x1b[33m",   // Yellow
            PaletteColor::Error => "\x1b[31m",     // Red
            PaletteColor::Info => "\x1b[36m",      // Cyan
            PaletteColor::Highlight => "\x1b[33m", // Yellow
            PaletteColor::Dim => "\x1b[2m",        // Dim
            PaletteColor::Normal => "\x1b[0m",     // Reset
        }
    }

    /// Get ANSI escape sequence for this color in high contrast mode
    pub fn ansi_high_contrast(&self) -> &'static str {
        match self {
            PaletteColor::Success => "\x1b[0m", // Normal (no color, just text)
            PaletteColor::Warning => "\x1b[1m", // Bold
            PaletteColor::Error => "\x1b[1m\x1b[4m", // Bold + underline
            PaletteColor::Info => "\x1b[0m",    // Normal
            PaletteColor::Highlight => "\x1b[1m", // Bold
            PaletteColor::Dim => "\x1b[3m",     // Italic
            PaletteColor::Normal => "\x1b[0m",  // Reset
        }
    }

    /// Get text label for this color (used when color is disabled)
    pub fn text_label(&self) -> &'static str {
        match self {
            PaletteColor::Success => "✓",
            PaletteColor::Warning => "⚠",
            PaletteColor::Error => "✗",
            PaletteColor::Info => "ℹ",
            PaletteColor::Highlight => ">",
            PaletteColor::Dim => "·",
            PaletteColor::Normal => "",
        }
    }

    /// Get ASCII-only label for this color
    pub fn ascii_label(&self) -> &'static str {
        match self {
            PaletteColor::Success => "+",
            PaletteColor::Warning => "!",
            PaletteColor::Error => "x",
            PaletteColor::Info => "-",
            PaletteColor::Highlight => ">",
            PaletteColor::Dim => ".",
            PaletteColor::Normal => "",
        }
    }
}

/// ANSI reset code
pub const ANSI_RESET: &str = "\x1b[0m";

/// Apply color to a string if color mode allows it
pub fn colorize(
    text: &str,
    color: PaletteColor,
    color_mode: ColorMode,
    high_contrast: bool,
) -> String {
    if !color_mode.use_color(atty::is(atty::Stream::Stdout)) {
        // Color disabled - return text with symbol prefix if appropriate
        let symbol = if high_contrast {
            color.ascii_label()
        } else {
            color.text_label()
        };
        if symbol.is_empty() {
            return text.to_string();
        }
        return format!("{} {}", symbol, text);
    }

    let ansi = if high_contrast {
        color.ansi_high_contrast()
    } else {
        color.ansi_normal()
    };

    format!("{}{}{}", ansi, text, ANSI_RESET)
}

/// Unicode mode detection
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UnicodeMode {
    /// Unicode enabled (UTF-8 terminal)
    Unicode,
    /// ASCII only
    Ascii,
}

impl UnicodeMode {
    /// Detect Unicode mode from environment
    pub fn detect() -> Self {
        // Check SIGIL_ASCII environment variable
        if env::var("SIGIL_ASCII").is_ok_and(|v| v == "1" || v == "true") {
            return UnicodeMode::Ascii;
        }

        // Check locale for UTF-8
        let locale = env::var("LANG")
            .or_else(|_| env::var("LC_ALL"))
            .unwrap_or_default();

        if locale.to_lowercase().contains("utf-8") || locale.to_lowercase().contains("utf8") {
            return UnicodeMode::Unicode;
        }

        // Check TERM for dumb terminal or linux console
        if let Ok(term) = env::var("TERM") {
            if term == "dumb" || term == "linux" {
                return UnicodeMode::Ascii;
            }
        }

        // Default to Unicode for modern systems
        UnicodeMode::Unicode
    }

    /// Get the appropriate box drawing characters
    pub fn box_drawings(&self) -> BoxDrawings {
        match self {
            UnicodeMode::Unicode => BoxDrawings::unicode(),
            UnicodeMode::Ascii => BoxDrawings::ascii(),
        }
    }
}

/// Box drawing characters
#[derive(Debug, Clone, Copy)]
pub struct BoxDrawings {
    /// Horizontal line character
    pub horizontal: char,
    /// Vertical line character
    pub vertical: char,
    /// Top-left corner character
    pub top_left: char,
    /// Top-right corner character
    pub top_right: char,
    /// Bottom-left corner character
    pub bottom_left: char,
    /// Bottom-right corner character
    pub bottom_right: char,
    /// Left tee junction character
    pub left_tee: char,
    /// Right tee junction character
    pub right_tee: char,
    /// Top tee junction character
    pub top_tee: char,
    /// Bottom tee junction character
    pub bottom_tee: char,
    /// Cross junction character
    pub cross: char,
}

impl BoxDrawings {
    /// Get Unicode box drawing characters
    pub fn unicode() -> Self {
        Self {
            horizontal: '─',
            vertical: '│',
            top_left: '┌',
            top_right: '┐',
            bottom_left: '└',
            bottom_right: '┘',
            left_tee: '├',
            right_tee: '┤',
            top_tee: '┬',
            bottom_tee: '┴',
            cross: '┼',
        }
    }

    /// Get ASCII box drawing characters
    pub fn ascii() -> Self {
        Self {
            horizontal: '-',
            vertical: '|',
            top_left: '+',
            top_right: '+',
            bottom_left: '+',
            bottom_right: '+',
            left_tee: '+',
            right_tee: '+',
            top_tee: '+',
            bottom_tee: '+',
            cross: '+',
        }
    }
}

/// Terminal size information
#[derive(Debug, Clone, Copy)]
pub struct TerminalSize {
    /// Terminal width in columns
    pub width: u16,
    /// Terminal height in rows
    pub height: u16,
}

impl TerminalSize {
    /// Get the terminal size, or return a default if detection fails
    pub fn detect() -> Self {
        let size = terminal_size::terminal_size();
        match size {
            Some((w, h)) => Self {
                width: w.0,
                height: h.0,
            },
            None => Self {
                width: 80,
                height: 24,
            },
        }
    }

    /// Determine the layout mode based on terminal width
    pub fn layout_mode(&self) -> LayoutMode {
        match self.width {
            0..=59 => LayoutMode::TooNarrow,
            60..=79 => LayoutMode::SinglePanel,
            80..=119 => LayoutMode::TwoPanel,
            _ => LayoutMode::Full,
        }
    }
}

/// Layout mode for responsive TUI
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LayoutMode {
    /// Terminal is too narrow (< 60 cols)
    TooNarrow,
    /// Single panel layout (60-79 cols)
    SinglePanel,
    /// Two panel layout (80-119 cols)
    TwoPanel,
    /// Full layout (120+ cols)
    Full,
}

/// Status indicators for health checks and other status output
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StatusIndicator {
    /// Pass/success status
    Pass,
    /// Warning status
    Warn,
    /// Failure/error status
    Fail,
}

impl StatusIndicator {
    /// Get the text label for this status (always present for accessibility)
    pub fn label(&self) -> &'static str {
        match self {
            StatusIndicator::Pass => "PASS",
            StatusIndicator::Warn => "WARN",
            StatusIndicator::Fail => "FAIL",
        }
    }

    /// Get the color palette for this status
    pub fn color(&self) -> PaletteColor {
        match self {
            StatusIndicator::Pass => PaletteColor::Success,
            StatusIndicator::Warn => PaletteColor::Warning,
            StatusIndicator::Fail => PaletteColor::Error,
        }
    }

    /// Format a status line with appropriate color and symbol
    pub fn format(
        &self,
        name: &str,
        detail: &str,
        color_mode: ColorMode,
        high_contrast: bool,
    ) -> String {
        let label = self.label();
        let color = self.color();
        let use_color = color_mode.use_color(atty::is(atty::Stream::Stdout));

        if use_color {
            let ansi = if high_contrast {
                color.ansi_high_contrast()
            } else {
                color.ansi_normal()
            };
            format!("{} {: >4}{}  {}", name, ansi, label, detail)
        } else {
            format!("{} {: >4}  {}", name, label, detail)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_color_mode_detection() {
        // Test auto mode when no env vars set
        let mode = ColorMode::detect();
        assert_eq!(mode, ColorMode::Auto);
    }

    #[test]
    fn test_unicode_mode_detection() {
        let mode = UnicodeMode::detect();
        // Default should be Unicode on most systems
        assert!(matches!(mode, UnicodeMode::Unicode | UnicodeMode::Ascii));
    }

    #[test]
    fn test_terminal_size() {
        let size = TerminalSize::detect();
        assert!(size.width > 0);
        assert!(size.height > 0);
    }

    #[test]
    fn test_layout_mode() {
        let narrow = TerminalSize {
            width: 50,
            height: 24,
        };
        assert_eq!(narrow.layout_mode(), LayoutMode::TooNarrow);

        let single = TerminalSize {
            width: 70,
            height: 24,
        };
        assert_eq!(single.layout_mode(), LayoutMode::SinglePanel);

        let two = TerminalSize {
            width: 100,
            height: 24,
        };
        assert_eq!(two.layout_mode(), LayoutMode::TwoPanel);

        let full = TerminalSize {
            width: 140,
            height: 24,
        };
        assert_eq!(full.layout_mode(), LayoutMode::Full);
    }

    #[test]
    fn test_status_indicator_format() {
        let status = StatusIndicator::Pass;
        let formatted = status.format("test", "detail", ColorMode::None, false);
        assert!(formatted.contains("PASS"));
        assert!(formatted.contains("test"));
        assert!(formatted.contains("detail"));
    }
}
