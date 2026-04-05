//! Shell state tracking for persistent command execution
//!
//! Tracks working directory, environment variables, and shell options
//! across multiple command executions.

use std::collections::{HashMap, HashSet};
use std::path::PathBuf;

/// State capture markers for command suffixes
pub const CWD_MARKER: &str = ":::SIGIL_CWD:::";

/// Exit code marker for state capture
pub const EXIT_MARKER: &str = ":::SIGIL_EXIT:::";

/// Blocked environment variables that should never be tracked or injected
const BLOCKED_ENV_VARS: &[&str] = &["PATH", "LD_PRELOAD", "LD_LIBRARY_PATH", "SHELL"];

/// Shell state tracked across command executions
#[derive(Debug, Clone)]
pub struct ShellState {
    /// Current working directory
    pub cwd: PathBuf,
    /// Exported environment variables (name -> value)
    pub env_vars: HashMap<String, String>,
    /// Shell options (e.g., set -e, set -x)
    pub shell_options: HashSet<String>,
    /// Last exit code
    pub last_exit_code: Option<i32>,
}

impl Default for ShellState {
    fn default() -> Self {
        Self {
            cwd: PathBuf::from("."),
            env_vars: HashMap::new(),
            shell_options: HashSet::new(),
            last_exit_code: None,
        }
    }
}

impl ShellState {
    /// Create a new shell state with the given current working directory
    pub fn new(cwd: PathBuf) -> Self {
        Self {
            cwd,
            ..Default::default()
        }
    }

    /// Create a shell state from the current process environment
    pub fn from_current_env() -> Self {
        let cwd = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
        let mut env_vars = HashMap::new();

        // Copy allowed environment variables
        for (key, value) in std::env::vars() {
            if !BLOCKED_ENV_VARS.contains(&key.as_str()) {
                env_vars.insert(key, value);
            }
        }

        Self {
            cwd,
            env_vars,
            shell_options: HashSet::new(),
            last_exit_code: None,
        }
    }

    /// Set the current working directory
    pub fn set_cwd(&mut self, cwd: PathBuf) {
        self.cwd = cwd;
    }

    /// Get the current working directory
    pub fn cwd(&self) -> &PathBuf {
        &self.cwd
    }

    /// Set an environment variable
    ///
    /// Returns false if the variable is blocked.
    pub fn set_env(&mut self, name: String, value: String) -> bool {
        if BLOCKED_ENV_VARS.contains(&name.as_str()) {
            return false;
        }
        self.env_vars.insert(name, value);
        true
    }

    /// Get an environment variable
    pub fn get_env(&self, name: &str) -> Option<&String> {
        self.env_vars.get(name)
    }

    /// Remove an environment variable
    pub fn unset_env(&mut self, name: &str) -> Option<String> {
        self.env_vars.remove(name)
    }

    /// Get all environment variables
    pub fn env_vars(&self) -> &HashMap<String, String> {
        &self.env_vars
    }

    /// Add a shell option
    pub fn add_option(&mut self, option: String) {
        self.shell_options.insert(option);
    }

    /// Remove a shell option
    pub fn remove_option(&mut self, option: &str) {
        self.shell_options.remove(option);
    }

    /// Check if a shell option is set
    pub fn has_option(&self, option: &str) -> bool {
        self.shell_options.contains(option)
    }

    /// Get all shell options
    pub fn options(&self) -> &HashSet<String> {
        &self.shell_options
    }

    /// Set the last exit code
    pub fn set_exit_code(&mut self, code: i32) {
        self.last_exit_code = Some(code);
    }

    /// Get the last exit code
    pub fn last_exit_code(&self) -> Option<i32> {
        self.last_exit_code
    }

    /// Update state from a state capture string
    ///
    /// Parses state markers like ":::SIGIL_CWD:::/path" and ":::SIGIL_EXIT:::0"
    pub fn update_from_capture(&mut self, capture: &StateCapture) {
        if let Some(ref cwd) = capture.cwd {
            self.cwd = PathBuf::from(cwd);
        }
        if let Some(exit_code) = capture.exit_code {
            self.last_exit_code = Some(exit_code);
        }
    }

    /// Build command suffix for state capture
    ///
    /// Returns a suffix string that can be appended to a command to capture
    /// the shell state after execution.
    pub fn build_capture_suffix(&self) -> String {
        // Note: The actual capture uses shell built-ins like pwd and $?
        // This returns the suffix that will be added to the command
        format!(
            " ; echo \"{}$(pwd)\" ; echo \"{}$?\"",
            CWD_MARKER, EXIT_MARKER
        )
    }

    /// Export environment variables for command execution
    ///
    /// Returns an iterator of (name, value) pairs suitable for use with
    /// `std::process::Command::envs`.
    pub fn export_env(&self) -> impl Iterator<Item = (&String, &String)> {
        self.env_vars.iter()
    }

    /// Check if an environment variable is blocked
    pub fn is_blocked_env_var(name: &str) -> bool {
        BLOCKED_ENV_VARS.contains(&name)
    }

    /// Get the list of blocked environment variable names
    pub fn blocked_env_vars() -> &'static [&'static str] {
        BLOCKED_ENV_VARS
    }
}

/// Parsed state capture from command output
#[derive(Debug, Clone)]
pub struct StateCapture {
    /// Current working directory after command execution
    pub cwd: Option<String>,
    /// Exit code of the command
    pub exit_code: Option<i32>,
}

impl StateCapture {
    /// Create a new empty state capture
    pub fn new() -> Self {
        Self {
            cwd: None,
            exit_code: None,
        }
    }

    /// Parse state capture markers from command output
    ///
    /// Looks for patterns like ":::SIGIL_CWD:::/path" and ":::SIGIL_EXIT:::0"
    /// in the output and extracts the values.
    pub fn parse_from_output(output: &str) -> Self {
        let mut capture = Self::new();

        for line in output.lines() {
            if let Some(cwd_pos) = line.find(CWD_MARKER) {
                let cwd_value = line[cwd_pos + CWD_MARKER.len()..].trim();
                capture.cwd = Some(cwd_value.to_string());
            }
            if let Some(exit_pos) = line.find(EXIT_MARKER) {
                let exit_value = line[exit_pos + EXIT_MARKER.len()..].trim();
                capture.exit_code = exit_value.parse().ok();
            }
        }

        capture
    }

    /// Strip state capture markers from output
    ///
    /// Returns the output with all SIGIL state capture lines removed.
    pub fn strip_from_output(output: &str) -> String {
        output
            .lines()
            .filter(|line| !line.contains(CWD_MARKER) && !line.contains(EXIT_MARKER))
            .collect::<Vec<_>>()
            .join("\n")
    }

    /// Check if the capture is complete (has both cwd and exit code)
    pub fn is_complete(&self) -> bool {
        self.cwd.is_some() && self.exit_code.is_some()
    }
}

impl Default for StateCapture {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_shell_state_default() {
        let state = ShellState::default();
        assert_eq!(state.cwd, PathBuf::from("."));
        assert!(state.env_vars.is_empty());
        assert!(state.shell_options.is_empty());
        assert!(state.last_exit_code.is_none());
    }

    #[test]
    fn test_shell_state_new() {
        let cwd = PathBuf::from("/test/path");
        let state = ShellState::new(cwd.clone());
        assert_eq!(state.cwd, cwd);
    }

    #[test]
    fn test_shell_state_set_cwd() {
        let mut state = ShellState::default();
        let new_cwd = PathBuf::from("/new/path");
        state.set_cwd(new_cwd.clone());
        assert_eq!(state.cwd, new_cwd);
    }

    #[test]
    fn test_shell_state_env_allowed() {
        let mut state = ShellState::default();
        assert!(state.set_env("TEST_VAR".to_string(), "value".to_string()));
        assert_eq!(state.get_env("TEST_VAR"), Some(&"value".to_string()));
    }

    #[test]
    fn test_shell_state_env_blocked() {
        let mut state = ShellState::default();
        assert!(!state.set_env("PATH".to_string(), "/bin".to_string()));
        assert!(state.get_env("PATH").is_none());
    }

    #[test]
    fn test_shell_state_unset_env() {
        let mut state = ShellState::default();
        state.set_env("TEST_VAR".to_string(), "value".to_string());
        assert_eq!(state.unset_env("TEST_VAR"), Some("value".to_string()));
        assert!(state.get_env("TEST_VAR").is_none());
    }

    #[test]
    fn test_shell_state_options() {
        let mut state = ShellState::default();
        state.add_option("errexit".to_string());
        assert!(state.has_option("errexit"));
        state.remove_option("errexit");
        assert!(!state.has_option("errexit"));
    }

    #[test]
    fn test_shell_state_exit_code() {
        let mut state = ShellState::default();
        state.set_exit_code(0);
        assert_eq!(state.last_exit_code(), Some(0));
    }

    #[test]
    fn test_is_blocked_env_var() {
        assert!(ShellState::is_blocked_env_var("PATH"));
        assert!(ShellState::is_blocked_env_var("LD_PRELOAD"));
        assert!(!ShellState::is_blocked_env_var("MY_VAR"));
    }

    #[test]
    fn test_state_capture_new() {
        let capture = StateCapture::new();
        assert!(capture.cwd.is_none());
        assert!(capture.exit_code.is_none());
        assert!(!capture.is_complete());
    }

    #[test]
    fn test_state_capture_parse_from_output() {
        let output = "some output\n:::SIGIL_CWD:::/test/path\n:::SIGIL_EXIT:::0\nmore output";
        let capture = StateCapture::parse_from_output(output);
        assert_eq!(capture.cwd, Some("/test/path".to_string()));
        assert_eq!(capture.exit_code, Some(0));
        assert!(capture.is_complete());
    }

    #[test]
    fn test_state_capture_parse_partial() {
        let output = ":::SIGIL_CWD:::/test/path";
        let capture = StateCapture::parse_from_output(output);
        assert_eq!(capture.cwd, Some("/test/path".to_string()));
        assert!(capture.exit_code.is_none());
        assert!(!capture.is_complete());
    }

    #[test]
    fn test_state_capture_strip_from_output() {
        let output = "some output\n:::SIGIL_CWD:::/test/path\n:::SIGIL_EXIT:::0\nmore output";
        let stripped = StateCapture::strip_from_output(output);
        assert!(!stripped.contains(":::SIGIL_CWD:::"));
        assert!(!stripped.contains(":::SIGIL_EXIT:::"));
        assert!(stripped.contains("some output"));
        assert!(stripped.contains("more output"));
    }

    #[test]
    fn test_shell_state_build_capture_suffix() {
        let state = ShellState::default();
        let suffix = state.build_capture_suffix();
        assert!(suffix.contains(":::SIGIL_CWD:::"));
        assert!(suffix.contains(":::SIGIL_EXIT:::"));
        assert!(suffix.contains("pwd"));
        assert!(suffix.contains("$?"));
    }

    #[test]
    fn test_shell_state_update_from_capture() {
        let mut state = ShellState::default();
        let mut capture = StateCapture::new();
        capture.cwd = Some("/updated/path".to_string());
        capture.exit_code = Some(1);

        state.update_from_capture(&capture);
        assert_eq!(state.cwd, PathBuf::from("/updated/path"));
        assert_eq!(state.last_exit_code, Some(1));
    }

    #[test]
    fn test_blocked_env_vars_list() {
        let blocked = ShellState::blocked_env_vars();
        assert!(blocked.contains(&"PATH"));
        assert!(blocked.contains(&"LD_PRELOAD"));
        assert!(blocked.contains(&"LD_LIBRARY_PATH"));
        assert!(blocked.contains(&"SHELL"));
    }
}
