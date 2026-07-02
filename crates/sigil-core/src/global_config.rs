//! SIGIL global configuration
//!
//! This module provides global SIGIL configuration stored in `~/.sigil/config.toml`.
//! It includes TUI settings, backend configurations, and other user-level settings.

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};

use super::backend::{BackendEntry, BackendRouter, BackendRouterConfig};

/// Current global config format version
pub const GLOBAL_CONFIG_FORMAT_VERSION: u16 = 1;

/// SIGIL global configuration
///
/// This configuration file contains user-level settings that apply across
/// all SIGIL projects. It includes TUI settings, backend configurations,
/// and other global preferences.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GlobalConfig {
    /// Config format version
    #[serde(default = "default_global_config_version")]
    pub format_version: u16,

    /// TUI configuration
    #[serde(default)]
    pub tui: TuiConfig,

    /// Backend router configuration
    #[serde(default)]
    pub backends: BackendRouterConfig,

    /// Daemon configuration
    #[serde(default)]
    pub daemon: DaemonConfig,
}

impl Default for GlobalConfig {
    fn default() -> Self {
        Self {
            format_version: GLOBAL_CONFIG_FORMAT_VERSION,
            tui: TuiConfig::default(),
            backends: BackendRouterConfig::default(),
            daemon: DaemonConfig::default(),
        }
    }
}

fn default_global_config_version() -> u16 {
    GLOBAL_CONFIG_FORMAT_VERSION
}

/// TUI configuration section
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TuiConfig {
    /// Auto-hide timeout for secret values in seconds (default: 5)
    #[serde(default = "default_secret_display_timeout")]
    pub secret_display_timeout: u64,

    /// Enable alternate screen buffer (default: true)
    #[serde(default = "default_true")]
    pub alternate_screen: bool,

    /// Enable process isolation (PR_SET_DUMPABLE=0) (default: true)
    #[serde(default = "default_true")]
    pub process_isolation: bool,

    /// Terminal width minimum for TUI (default: 60)
    #[serde(default = "default_min_terminal_width")]
    pub min_terminal_width: u16,

    /// Enable mouse capture in TUI (default: false)
    #[serde(default)]
    pub mouse_capture: bool,
}

impl Default for TuiConfig {
    fn default() -> Self {
        Self {
            secret_display_timeout: default_secret_display_timeout(),
            alternate_screen: true,
            process_isolation: true,
            min_terminal_width: 60,
            mouse_capture: false,
        }
    }
}

fn default_secret_display_timeout() -> u64 {
    5
}

fn default_true() -> bool {
    true
}

fn default_min_terminal_width() -> u16 {
    60
}

/// Daemon configuration section
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DaemonConfig {
    /// Enable auto-start on login (default: false)
    #[serde(default)]
    pub auto_start: bool,

    /// Default lease TTL in seconds (default: 300)
    #[serde(default = "default_lease_ttl")]
    pub default_lease_ttl: u64,

    /// Audit log retention days (default: 30)
    #[serde(default = "default_audit_retention")]
    pub audit_retention_days: u32,

    /// Enable breach detection (default: true)
    #[serde(default = "default_true")]
    pub breach_detection: bool,
}

impl Default for DaemonConfig {
    fn default() -> Self {
        Self {
            auto_start: false,
            default_lease_ttl: default_lease_ttl(),
            audit_retention_days: default_audit_retention(),
            breach_detection: true,
        }
    }
}

fn default_lease_ttl() -> u64 {
    300
}

fn default_audit_retention() -> u32 {
    30
}

/// SIGIL global configuration manager
pub struct GlobalConfigManager {
    /// Path to the global config directory
    config_dir: PathBuf,
    /// Path to the config file
    config_path: PathBuf,
}

impl GlobalConfigManager {
    /// Create a new global config manager
    ///
    /// Uses `~/.sigil/config.toml` as the config file path.
    pub fn new() -> Result<Self> {
        let config_dir = Self::sigil_config_dir()?;
        let config_path = config_dir.join("config.toml");

        Ok(Self {
            config_dir,
            config_path,
        })
    }

    /// Get the SIGIL config directory path
    ///
    /// Returns `~/.sigil/` or `$XDG_CONFIG_HOME/sigil/` if set.
    fn sigil_config_dir() -> Result<PathBuf> {
        if let Ok(xdg_config) = std::env::var("XDG_CONFIG_HOME") {
            return Ok(PathBuf::from(xdg_config).join("sigil"));
        }

        let home = std::env::var("HOME").context("HOME environment variable not set")?;

        Ok(PathBuf::from(home).join(".sigil"))
    }

    /// Load the global configuration
    ///
    /// Returns None if the config file doesn't exist.
    pub fn load(&self) -> Result<Option<GlobalConfig>> {
        if !self.config_path.exists() {
            return Ok(None);
        }

        let content = fs::read_to_string(&self.config_path)
            .with_context(|| format!("Failed to read {}", self.config_path.display()))?;

        let config: GlobalConfig = toml::from_str(&content)
            .with_context(|| format!("Failed to parse {}", self.config_path.display()))?;

        // Validate format version
        if config.format_version != GLOBAL_CONFIG_FORMAT_VERSION {
            return Err(anyhow::anyhow!(
                "Unsupported config format version: {} (expected: {})",
                config.format_version,
                GLOBAL_CONFIG_FORMAT_VERSION
            ));
        }

        Ok(Some(config))
    }

    /// Save the global configuration
    pub fn save(&self, config: &GlobalConfig) -> Result<()> {
        // Ensure the config directory exists
        fs::create_dir_all(&self.config_dir)
            .with_context(|| format!("Failed to create {}", self.config_dir.display()))?;

        // Serialize to TOML
        let content =
            toml::to_string_pretty(config).context("Failed to serialize config to TOML")?;

        // Write to file with restricted permissions (0600)
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let perms = fs::Permissions::from_mode(0o600);
            fs::write(&self.config_path, content)?;
            fs::set_permissions(&self.config_path, perms)?;
        }

        #[cfg(not(unix))]
        {
            fs::write(&self.config_path, content)?;
        }

        Ok(())
    }

    /// Load or create default configuration
    ///
    /// If the config file doesn't exist, creates a new default config.
    pub fn load_or_default(&self) -> Result<GlobalConfig> {
        match self.load()? {
            Some(config) => Ok(config),
            None => {
                let default_config = GlobalConfig::default();
                self.save(&default_config)?;
                Ok(default_config)
            }
        }
    }

    /// Get the config file path
    pub fn config_path(&self) -> &Path {
        &self.config_path
    }

    /// Get the config directory path
    pub fn config_dir(&self) -> &Path {
        &self.config_dir
    }

    /// Initialize a new config file with defaults
    pub fn init(&self) -> Result<GlobalConfig> {
        let config = GlobalConfig::default();
        self.save(&config)?;
        Ok(config)
    }

    /// Add a backend configuration
    pub fn add_backend(&self, entry: BackendEntry) -> Result<()> {
        let mut config = self.load_or_default()?;
        config.backends.add_backend(entry);
        self.save(&config)
    }

    /// Remove a backend configuration by ID
    pub fn remove_backend(&self, backend_id: &str) -> Result<()> {
        let mut config = self.load_or_default()?;
        config.backends.backends.retain(|b| b.id != backend_id);
        self.save(&config)
    }

    /// Get the backend router from config
    pub fn get_backend_router(&self) -> Result<BackendRouter> {
        let config = self.load_or_default()?;
        Ok(config.backends.build())
    }
}

impl Default for GlobalConfigManager {
    fn default() -> Self {
        Self::new().expect("Failed to create GlobalConfigManager")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_global_config_default() {
        let config = GlobalConfig::default();
        assert_eq!(config.format_version, GLOBAL_CONFIG_FORMAT_VERSION);
        assert_eq!(config.tui.secret_display_timeout, 5);
        assert!(config.tui.alternate_screen);
        assert!(config.tui.process_isolation);
    }

    #[test]
    fn test_tui_config_default() {
        let config = TuiConfig::default();
        assert_eq!(config.secret_display_timeout, 5);
        assert_eq!(config.min_terminal_width, 60);
        assert!(config.alternate_screen);
        assert!(config.process_isolation);
        assert!(!config.mouse_capture);
    }

    #[test]
    fn test_daemon_config_default() {
        let config = DaemonConfig::default();
        assert_eq!(config.default_lease_ttl, 300);
        assert_eq!(config.audit_retention_days, 30);
        assert!(config.breach_detection);
        assert!(!config.auto_start);
    }

    #[test]
    fn test_global_config_serialize() {
        let config = GlobalConfig::default();
        let toml_str = toml::to_string_pretty(&config).unwrap();
        assert!(toml_str.contains("format_version"));
        assert!(toml_str.contains("[tui]"));
        assert!(toml_str.contains("secret_display_timeout"));
        assert!(toml_str.contains("[backends]"));
        assert!(toml_str.contains("[daemon]"));
    }

    #[test]
    fn test_global_config_deserialize() {
        let toml_str = r#"
format_version = 1

[tui]
secret_display_timeout = 10
alternate_screen = true
process_isolation = true
min_terminal_width = 80
mouse_capture = false

[daemon]
auto_start = false
default_lease_ttl = 600
audit_retention_days = 60
breach_detection = true

[backends]
enabled = true
backends = []
"#;

        let config: GlobalConfig = toml::from_str(toml_str).unwrap();
        assert_eq!(config.format_version, 1);
        assert_eq!(config.tui.secret_display_timeout, 10);
        assert_eq!(config.daemon.default_lease_ttl, 600);
    }

    #[test]
    fn test_backend_config_integration() {
        let config = GlobalConfig::default();
        assert!(config.backends.enabled);
        assert!(config.backends.backends.is_empty());
    }
}
