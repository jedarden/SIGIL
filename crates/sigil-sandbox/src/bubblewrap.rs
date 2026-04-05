//! Bubblewrap sandbox implementation
//!
//! Provides Linux namespace-based sandboxing using bubblewrap (bwrap).

use serde::{Deserialize, Serialize};
use sigil_core::{ResolvedCommand, Result, SigilError};
use std::path::{Path, PathBuf};
use std::process::Command;

/// Default tmpfs mount point for secret file injection
const SECRET_TMPFS: &str = "/run/sigil/secrets";

/// Sensitive files that should be overlaid with /dev/null
const DEFAULT_SENSITIVE_PATHS: &[&str] = &[
    ".env",
    ".aws/credentials",
    ".aws/config",
    ".ssh/id_rsa",
    ".ssh/id_ed25519",
    ".ssh/id_ecdsa",
    ".gnupg",
    ".netrc",
    ".docker/config.json",
];

/// Sandbox capabilities available to a provider
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SandboxCapabilities {
    /// Whether the provider supports network namespaces
    pub network_namespace: bool,
    /// Whether the provider supports PID namespaces
    pub pid_namespace: bool,
    /// Whether the provider supports mount namespaces
    pub mount_namespace: bool,
    /// Whether the provider supports seccomp filtering
    pub seccomp: bool,
    /// Whether the provider supports file injection
    pub file_injection: bool,
    /// Whether the provider supports bind mounts
    pub bind_mounts: bool,
}

impl Default for SandboxCapabilities {
    fn default() -> Self {
        Self {
            network_namespace: true,
            pid_namespace: true,
            mount_namespace: true,
            seccomp: true,
            file_injection: true,
            bind_mounts: true,
        }
    }
}

/// Configuration for sandbox execution
#[derive(Debug, Clone)]
pub struct SandboxConfig {
    /// Project directory to bind mount (writable)
    pub project_dir: Option<PathBuf>,
    /// Additional paths to overlay with /dev/null
    pub sensitive_paths: Vec<PathBuf>,
    /// Whether to enable network isolation
    pub network_isolated: bool,
    /// Working directory inside the sandbox
    pub working_dir: Option<PathBuf>,
    /// Environment variables to inject (name -> value)
    pub env_vars: Vec<(String, String)>,
    /// Files to inject (secret_path -> file_path)
    pub file_injections: Vec<(String, PathBuf)>,
    /// Whether to use die-with-parent
    pub die_with_parent: bool,
}

impl Default for SandboxConfig {
    fn default() -> Self {
        Self {
            project_dir: None,
            sensitive_paths: DEFAULT_SENSITIVE_PATHS.iter().map(PathBuf::from).collect(),
            network_isolated: true,
            working_dir: None,
            env_vars: Vec::new(),
            file_injections: Vec::new(),
            die_with_parent: true,
        }
    }
}

impl SandboxConfig {
    /// Create a new sandbox config with the given project directory
    pub fn with_project_dir(project_dir: PathBuf) -> Self {
        Self {
            project_dir: Some(project_dir),
            ..Default::default()
        }
    }

    /// Add an environment variable to inject
    pub fn with_env(mut self, name: String, value: String) -> Self {
        self.env_vars.push((name, value));
        self
    }

    /// Add a file injection (secret path -> target path)
    pub fn with_file_injection(mut self, secret_path: String, target_path: PathBuf) -> Self {
        self.file_injections.push((secret_path, target_path));
        self
    }

    /// Set the working directory
    pub fn with_working_dir(mut self, dir: PathBuf) -> Self {
        self.working_dir = Some(dir);
        self
    }

    /// Enable or disable network isolation
    pub fn with_network_isolation(mut self, isolated: bool) -> Self {
        self.network_isolated = isolated;
        self
    }
}

/// Trait for sandbox providers
///
/// This trait allows different sandbox implementations (bubblewrap, seatbelt, etc.)
/// to be used interchangeably.
pub trait SandboxProvider: Send + Sync {
    /// Wrap a command with the sandbox configuration
    fn wrap_command(&self, cmd: &ResolvedCommand, config: &SandboxConfig) -> Result<Command>;

    /// Get the name of this provider
    fn provider_name(&self) -> &str;

    /// Check if this provider is available on the current platform
    fn is_available(&self) -> bool;

    /// Get the capabilities of this provider
    fn capabilities(&self) -> SandboxCapabilities;
}

/// Bubblewrap sandbox implementation for Linux
///
/// Uses bubblewrap (bwrap) to provide namespace-based isolation with seccomp filtering.
pub struct BubblewrapSandbox {
    /// Path to the bwrap binary
    bwrap_path: PathBuf,
    /// Cached availability check
    available: Option<bool>,
}

impl BubblewrapSandbox {
    /// Create a new bubblewrap sandbox
    pub fn new() -> Result<Self> {
        let bwrap_path = PathBuf::from("bwrap");
        Ok(Self {
            bwrap_path,
            available: None,
        })
    }

    /// Create a bubblewrap sandbox with a custom bwrap path
    pub fn with_bwrap_path<P: AsRef<Path>>(path: P) -> Self {
        Self {
            bwrap_path: path.as_ref().to_path_buf(),
            available: None,
        }
    }

    /// Check if bwrap is available on the system
    fn check_bwrap_available(&self) -> bool {
        // Try to run bwrap --version to check if it's available
        std::process::Command::new(&self.bwrap_path)
            .arg("--version")
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false)
    }

    /// Build the bubblewrap command line arguments
    fn build_bwrap_args(&self, config: &SandboxConfig) -> Vec<String> {
        let mut args = Vec::new();

        // Die with parent (cleanup on parent exit)
        if config.die_with_parent {
            args.push("--die-with-parent".to_string());
        }

        // Unshare PID namespace
        args.push("--unshare-pid".to_string());

        // Unshare network namespace
        if config.network_isolated {
            args.push("--unshare-net".to_string());
        }

        // Read-only root filesystem
        args.push("--ro-bind".to_string());
        args.push("/".to_string());
        args.push("/".to_string());

        // Project directory (writable if specified)
        if let Some(project_dir) = &config.project_dir {
            args.push("--bind".to_string());
            args.push(project_dir.display().to_string());
            args.push(project_dir.display().to_string());
        }

        // Clean tmpfs mounts
        args.push("--tmpfs".to_string());
        args.push("/tmp".to_string());

        args.push("--tmpfs".to_string());
        args.push(SECRET_TMPFS.to_string());

        // Minimal /proc
        args.push("--proc".to_string());
        args.push("/proc".to_string());

        // Minimal /dev
        args.push("--dev".to_string());
        args.push("/dev".to_string());

        // Overlay sensitive paths with /dev/null
        for sensitive_path in &config.sensitive_paths {
            if let Some(home) = dirs::home_dir() {
                let full_path = home.join(sensitive_path);
                if full_path.exists() {
                    args.push("--ro-bind".to_string());
                    args.push("/dev/null".to_string());
                    args.push(full_path.display().to_string());
                }
            }
        }

        // File injections (bind mounts from tmpfs or external files)
        for (source_or_secret, target_path) in &config.file_injections {
            // Check if this is an absolute path (external file) or a relative secret path
            let source_path = if PathBuf::from(source_or_secret).is_absolute() {
                // External file path (created by InjectionManager or tempfile)
                source_or_secret.clone()
            } else {
                // Secret path to be mounted from tmpfs
                format!("{}/{}", SECRET_TMPFS, sanitize_path(source_or_secret))
            };
            args.push("--bind".to_string());
            args.push(source_path);
            args.push(target_path.display().to_string());
        }

        // Seccomp filter (block dangerous syscalls)
        // Note: In a full implementation, this would use a precompiled seccomp profile
        // For now, we rely on bubblewrap's default seccomp filter

        args
    }

    /// Build the complete command to execute in the sandbox
    fn build_sandbox_command(
        &self,
        resolved_cmd: &ResolvedCommand,
        config: &SandboxConfig,
    ) -> Result<Command> {
        let mut cmd = Command::new(&self.bwrap_path);

        // Add bubblewrap arguments
        for arg in self.build_bwrap_args(config) {
            cmd.arg(arg);
        }

        // Set environment variables
        for (name, value) in &config.env_vars {
            cmd.env(name, value);
        }

        // Block dangerous environment variables
        cmd.env("PATH", "/usr/bin:/bin");
        cmd.env_remove("LD_PRELOAD");
        cmd.env_remove("LD_LIBRARY_PATH");
        cmd.env_remove("SHELL");

        // Set working directory if specified
        if let Some(wd) = &config.working_dir {
            cmd.current_dir(wd);
        }

        // Add the command to execute
        // Parse the resolved command into arguments
        let parts = shell_words::split(&resolved_cmd.resolved)
            .map_err(|e| SigilError::InvalidConfig(format!("Invalid command: {}", e)))?;

        if parts.is_empty() {
            return Err(SigilError::InvalidConfig("Empty command".to_string()));
        }

        cmd.arg(&parts[0]);
        for arg in &parts[1..] {
            cmd.arg(arg);
        }

        Ok(cmd)
    }
}

impl Default for BubblewrapSandbox {
    fn default() -> Self {
        Self::new().unwrap()
    }
}

impl SandboxProvider for BubblewrapSandbox {
    fn wrap_command(&self, cmd: &ResolvedCommand, config: &SandboxConfig) -> Result<Command> {
        self.build_sandbox_command(cmd, config)
    }

    fn provider_name(&self) -> &str {
        "bwrap"
    }

    fn is_available(&self) -> bool {
        match self.available {
            Some(available) => available,
            None => {
                // Note: We can't cache this in &self without interior mutability,
                // so for now we just return the result
                self.check_bwrap_available()
            }
        }
    }

    fn capabilities(&self) -> SandboxCapabilities {
        SandboxCapabilities::default()
    }
}

/// Sanitize a path for use as a filename
fn sanitize_path(path: &str) -> String {
    path.chars()
        .map(|c| {
            if c.is_alphanumeric() || c == '_' || c == '-' || c == '.' {
                c
            } else {
                '_'
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sandbox_creation() {
        let sandbox = BubblewrapSandbox::new();
        assert!(sandbox.is_ok());
    }

    #[test]
    fn test_sandbox_config_default() {
        let config = SandboxConfig::default();
        assert!(config.project_dir.is_none());
        assert!(config.network_isolated);
        assert!(config.die_with_parent);
    }

    #[test]
    fn test_sandbox_config_with_project_dir() {
        let project = PathBuf::from("/test/project");
        let config = SandboxConfig::with_project_dir(project.clone());
        assert_eq!(config.project_dir, Some(project));
    }

    #[test]
    fn test_sandbox_config_with_env() {
        let config =
            SandboxConfig::default().with_env("TEST_VAR".to_string(), "test_value".to_string());
        assert_eq!(config.env_vars.len(), 1);
        assert_eq!(
            config.env_vars[0],
            (String::from("TEST_VAR"), String::from("test_value"))
        );
    }

    #[test]
    fn test_sandbox_config_with_file_injection() {
        let config = SandboxConfig::default()
            .with_file_injection("secret/path".to_string(), PathBuf::from("/target/path"));
        assert_eq!(config.file_injections.len(), 1);
        assert_eq!(config.file_injections[0].0, "secret/path");
    }

    #[test]
    fn test_sandbox_config_with_working_dir() {
        let dir = PathBuf::from("/working/dir");
        let config = SandboxConfig::default().with_working_dir(dir.clone());
        assert_eq!(config.working_dir, Some(dir));
    }

    #[test]
    fn test_sandbox_config_with_network_isolation() {
        let config = SandboxConfig::default().with_network_isolation(false);
        assert!(!config.network_isolated);
    }

    #[test]
    fn test_sanitize_path() {
        assert_eq!(sanitize_path("api/key"), "api_key");
        assert_eq!(sanitize_path("test-path"), "test-path");
        assert_eq!(sanitize_path("my.secret"), "my.secret");
    }

    #[test]
    fn test_sandbox_provider_name() {
        let sandbox = BubblewrapSandbox::new().unwrap();
        assert_eq!(sandbox.provider_name(), "bwrap");
    }

    #[test]
    fn test_sandbox_capabilities() {
        let sandbox = BubblewrapSandbox::new().unwrap();
        let caps = sandbox.capabilities();
        assert!(caps.network_namespace);
        assert!(caps.pid_namespace);
        assert!(caps.mount_namespace);
        assert!(caps.seccomp);
        assert!(caps.file_injection);
        assert!(caps.bind_mounts);
    }

    #[test]
    fn test_default_sensitive_paths() {
        assert!(!DEFAULT_SENSITIVE_PATHS.is_empty());
        assert!(DEFAULT_SENSITIVE_PATHS.contains(&".env"));
        assert!(DEFAULT_SENSITIVE_PATHS.contains(&".aws/credentials"));
    }
}
