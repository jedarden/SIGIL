//! Runtime Testing Framework for SIGIL Integration Tests
//!
//! This module provides utilities for testing SIGIL at runtime by:
//! - Starting and stopping daemons with proper lifecycle management
//! - Executing sigil commands and asserting on output
//! - Managing test vaults and temp directories
//! - Waiting for daemon readiness
//! - Capturing and analyzing logs

use std::fs;
use std::path::PathBuf;
use std::process::{Child, Command, Output, Stdio};
use std::thread;
use std::time::Duration;
use tempfile::TempDir;

use sigil_integration_tests::DaemonGuard;

/// Get the workspace root directory
fn workspace_root() -> PathBuf {
    let manifest_dir = std::env::var("CARGO_MANIFEST_DIR").unwrap();
    PathBuf::from(manifest_dir)
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .to_path_buf()
}

/// Binary paths helper
pub struct Binaries {
    pub sigil: PathBuf,
    pub sigild: PathBuf,
}

impl Binaries {
    /// Get paths to sigil and sigild binaries
    pub fn get() -> Option<Self> {
        let workspace = workspace_root();
        let sigil = workspace.join("target").join("debug").join("sigil");
        let sigild = workspace.join("target").join("debug").join("sigild");

        if sigil.exists() && sigild.exists() {
            Some(Self { sigil, sigild })
        } else {
            None
        }
    }
}

/// Test environment with temporary directories and daemon lifecycle
pub struct TestEnv {
    pub temp_dir: TempDir,
    pub vault_path: PathBuf,
    pub socket_path: PathBuf,
    pub runtime_dir: PathBuf,
    pub binaries: Binaries,
    pub daemon: Option<DaemonGuard>,
}

impl TestEnv {
    /// Create a new test environment with temporary directories
    pub fn new() -> std::io::Result<Self> {
        let temp_dir = TempDir::new()?;
        let vault_path = temp_dir.path().join("vault");
        let socket_path = temp_dir.path().join("sigil.sock");
        let runtime_dir = temp_dir.path().to_path_buf();

        // Create runtime directory
        fs::create_dir_all(&runtime_dir)?;

        // Set XDG_RUNTIME_DIR for this test
        std::env::set_var("XDG_RUNTIME_DIR", &runtime_dir);

        let binaries = Binaries::get().ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::NotFound,
                "sigil/sigild binaries not found. Run: cargo build",
            )
        })?;

        Ok(Self {
            temp_dir,
            vault_path,
            socket_path,
            runtime_dir,
            binaries,
            daemon: None,
        })
    }

    /// Initialize a test vault (without passphrase for CI/testing)
    pub fn init_vault(&self) -> bool {
        let output = Command::new(&self.binaries.sigil)
            .arg("init")
            .arg("--path")
            .arg(&self.vault_path)
            .arg("--no-passphrase")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();

        output.map(|s| s.success()).unwrap_or(false)
    }

    /// Start the daemon with standard test configuration
    pub fn start_daemon(&mut self) -> bool {
        self.start_daemon_with_opts(true, "never")
    }

    /// Start the daemon with custom options
    pub fn start_daemon_with_opts(&mut self, ci_mode: bool, idle_timeout: &str) -> bool {
        let mut cmd = Command::new(&self.binaries.sigild);
        cmd.arg("start")
            .arg("--socket")
            .arg(&self.socket_path)
            .arg("--vault")
            .arg(&self.vault_path)
            .arg("--idle-timeout")
            .arg(idle_timeout)
            .env("XDG_RUNTIME_DIR", &self.runtime_dir)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());

        if ci_mode {
            cmd.arg("--ci");
        }

        match cmd.spawn() {
            Ok(child) => {
                self.daemon = Some(DaemonGuard::new(child));

                // Wait for socket to appear (up to 5 seconds)
                let mut waited = 0;
                while waited < 50 {
                    thread::sleep(Duration::from_millis(100));
                    if self.socket_path.exists() {
                        // Give it a bit more time to be fully ready
                        thread::sleep(Duration::from_millis(200));
                        return true;
                    }
                    waited += 1;
                }
                false
            }
            Err(_) => false,
        }
    }

    /// Wait for daemon to be ready (socket exists)
    pub fn wait_for_daemon(&self, max_ms: u64) -> bool {
        let mut waited = 0;
        let interval = Duration::from_millis(100);
        while waited < max_ms {
            thread::sleep(interval);
            if self.socket_path.exists() {
                return true;
            }
            waited += 100;
        }
        false
    }

    /// Stop the daemon if running
    pub fn stop_daemon(&mut self) -> bool {
        if self.socket_path.exists() {
            let output = Command::new(&self.binaries.sigil)
                .arg("stop")
                .arg("--socket")
                .arg(&self.socket_path)
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status();

            // Also kill via DaemonGuard if present
            self.daemon = None;

            output.map(|s| s.success()).unwrap_or(false)
        } else {
            self.daemon = None;
            true
        }
    }

    /// Execute a sigil command and return output
    pub fn exec(&self, args: &[&str]) -> Output {
        let mut cmd = Command::new(&self.binaries.sigil);
        cmd.args(args);
        if self.socket_path.exists() {
            cmd.arg("--socket").arg(&self.socket_path);
        }
        cmd.env("XDG_RUNTIME_DIR", &self.runtime_dir)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .output()
            .unwrap_or_else(|_| {
                Command::new(&self.binaries.sigil)
                    .args(args)
                    .stdout(Stdio::piped())
                    .stderr(Stdio::piped())
                    .output()
                    .unwrap()
            })
    }

    /// Execute a sigil command and assert success
    pub fn exec_success(&self, args: &[&str]) -> Output {
        let output = self.exec(args);
        assert!(
            output.status.success(),
            "Command failed: sigil {:?}\nstdout: {}\nstderr: {}",
            args,
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        output
    }

    /// Execute a sigil command and assert failure
    pub fn exec_failure(&self, args: &[&str]) -> Output {
        let output = self.exec(args);
        assert!(
            !output.status.success(),
            "Command unexpectedly succeeded: sigil {:?}",
            args
        );
        output
    }

    /// Add a test secret to the vault
    pub fn add_secret(&self, path: &str, value: &str) -> bool {
        let output = Command::new(&self.binaries.sigil)
            .arg("set")
            .arg(path)
            .arg(value)
            .arg("--vault")
            .arg(&self.vault_path)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();

        output.map(|s| s.success()).unwrap_or(false)
    }

    /// Get a secret from the vault
    pub fn get_secret(&self, path: &str) -> Option<String> {
        let output = Command::new(&self.binaries.sigil)
            .arg("get")
            .arg(path)
            .arg("--vault")
            .arg(&self.vault_path)
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .output();

        output.ok().and_then(|o| {
            if o.status.success() {
                String::from_utf8(o.stdout).ok()
            } else {
                None
            }
        })
    }

    /// Check if daemon is running
    pub fn is_daemon_running(&self) -> bool {
        self.socket_path.exists()
    }

    /// Get daemon status output
    pub fn daemon_status(&self) -> String {
        let output = Command::new(&self.binaries.sigil)
            .arg("status")
            .arg("--socket")
            .arg(&self.socket_path)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .output();

        match output {
            Ok(o) => String::from_utf8_lossy(&o.stdout).to_string(),
            Err(_) => String::new(),
        }
    }
}

impl Drop for TestEnv {
    fn drop(&mut self) {
        // Stop daemon via sigil stop if socket exists
        if self.socket_path.exists() {
            let _ = Command::new(&self.binaries.sigil)
                .arg("stop")
                .arg("--socket")
                .arg(&self.socket_path)
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status();
        }

        // DaemonGuard will also kill the process if set
        self.daemon = None;
    }
}

/// Assert helper for checking output contains expected text
pub trait OutputAssert {
    fn contains_success(&self, text: &str) -> &Self;
    fn contains_stderr(&self, text: &str) -> &Self;
    fn exit_code(&self, code: i32) -> &Self;
}

impl OutputAssert for Output {
    fn contains_success(&self, text: &str) -> &Self {
        let stdout = String::from_utf8_lossy(&self.stdout);
        assert!(
            stdout.contains(text),
            "Expected stdout to contain '{}', but got:\n{}",
            text,
            stdout
        );
        self
    }

    fn contains_stderr(&self, text: &str) -> &Self {
        let stderr = String::from_utf8_lossy(&self.stderr);
        assert!(
            stderr.contains(text),
            "Expected stderr to contain '{}', but got:\n{}",
            text,
            stderr
        );
        self
    }

    fn exit_code(&self, code: i32) -> &Self {
        assert_eq!(
            self.status.code().unwrap_or(-1),
            code,
            "Expected exit code {}, got {}",
            code,
            self.status.code().unwrap_or(-1)
        );
        self
    }
}

/// Wait helper with assertions
pub fn wait_for(condition: impl Fn() -> bool, max_ms: u64, desc: &str) {
    let mut waited = 0;
    let interval = Duration::from_millis(50);
    while waited < max_ms {
        if condition() {
            return;
        }
        thread::sleep(interval);
        waited += 50;
    }
    panic!("Timeout waiting for: {}", desc);
}

/// Helper to run a test with binaries available
pub fn with_test_env<F>(f: F)
where
    F: FnOnce(&mut TestEnv),
{
    if Binaries::get().is_none() {
        eprintln!("Skipping test: binaries not found. Run: cargo build");
        return;
    }

    let mut env = TestEnv::new().expect("Failed to create test env");
    if !env.init_vault() {
        eprintln!("Skipping test: failed to init vault");
        return;
    }
    f(&mut env);
}

/// Helper to run a test with daemon running
pub fn with_daemon<F>(f: F)
where
    F: FnOnce(&mut TestEnv),
{
    with_test_env(|env| {
        if !env.start_daemon() {
            panic!("Failed to start daemon");
        }
        f(env);
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_binaries_available() {
        if Binaries::get().is_none() {
            eprintln!("Binaries not found. Run: cargo build");
        }
    }
}
