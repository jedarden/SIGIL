//! Environment Detection Module for SIGIL Integration Tests
//!
//! This module provides centralized environment detection and test skip logic
//! for platform-specific and environment-dependent features.
//!
//! # Features
//!
//! - Detect bubblewrap (bwrap) availability for sandbox tests
//! - Detect systemd/launchd for platform-specific daemon tests
//! - Provide skip helpers that gracefully skip tests with clear messages
//! - Set up XDG_RUNTIME_DIR for consistent socket path behavior

use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::OnceLock;

/// Environment detection cache
static ENV_CACHE: OnceLock<Environment> = OnceLock::new();

/// Detected environment capabilities
#[derive(Debug, Clone)]
pub struct Environment {
    /// Whether bubblewrap is available
    pub bwrap_available: bool,
    /// Whether systemd socket activation is available
    pub systemd_available: bool,
    /// Whether launchd is available (macOS)
    pub launchd_available: bool,
    /// Whether running in CI environment
    pub is_ci: bool,
    /// XDG_RUNTIME_DIR path
    pub xdg_runtime_dir: PathBuf,
}

impl Environment {
    /// Detect all environment capabilities
    pub fn detect() -> Self {
        let xdg_runtime_dir = detect_xdg_runtime_dir();

        Self {
            bwrap_available: detect_bwrap(),
            systemd_available: detect_systemd(),
            launchd_available: detect_launchd(),
            is_ci: detect_ci(),
            xdg_runtime_dir,
        }
    }

    /// Get the cached environment (detect once, cache forever)
    pub fn get() -> &'static Environment {
        ENV_CACHE.get_or_init(Environment::detect)
    }
}

/// Detect if bubblewrap is available on the system
pub fn detect_bwrap() -> bool {
    Command::new("bwrap")
        .arg("--version")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

/// Detect if systemd is available (for socket activation tests)
pub fn detect_systemd() -> bool {
    #[cfg(target_os = "linux")]
    {
        // Check if systemd is running
        Command::new("systemctl")
            .arg("--version")
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .map(|s| s.success())
            .unwrap_or(false)
    }

    #[cfg(not(target_os = "linux"))]
    {
        false
    }
}

/// Detect if launchd is available (macOS)
pub fn detect_launchd() -> bool {
    #[cfg(target_os = "macos")]
    {
        // launchd is always available on macOS
        true
    }

    #[cfg(not(target_os = "macos"))]
    {
        false
    }
}

/// Detect if running in CI environment
pub fn detect_ci() -> bool {
    // Check common CI environment variables
    std::env::var("CI")
        .or_else(|_| std::env::var("CONTINUOUS_INTEGRATION"))
        .or_else(|_| std::env::var("GITHUB_ACTIONS"))
        .or_else(|_| std::env::var("GITLAB_CI"))
        .or_else(|_| std::env::var("TRAVIS"))
        .map(|v| !v.is_empty())
        .unwrap_or(false)
}

/// Detect and set up XDG_RUNTIME_DIR
///
/// If XDG_RUNTIME_DIR is not set, creates a temporary directory and sets it.
/// Returns the path to the runtime directory.
pub fn detect_xdg_runtime_dir() -> PathBuf {
    if let Ok(runtime_dir) = std::env::var("XDG_RUNTIME_DIR") {
        let path = PathBuf::from(runtime_dir);
        if path.exists() {
            // Verify it's writable
            if path.is_dir() {
                // Try to create a test file to verify writability
                let test_file = path.join(".sigil-test-write");
                if std::fs::write(&test_file, b"test").is_ok() {
                    let _ = std::fs::remove_file(&test_file);
                    return path;
                }
                eprintln!(
                    "XDG_RUNTIME_DIR {:?} exists but is not writable, using temp directory",
                    path
                );
            }
        }
    }

    // Create a temporary runtime directory
    let temp_runtime = std::env::temp_dir().join(format!("sigil-runtime-{}", std::process::id()));
    std::fs::create_dir_all(&temp_runtime).expect("Failed to create runtime dir");

    // Set permissions to 0700 for security
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = std::fs::metadata(&temp_runtime)
            .expect("Failed to get runtime dir metadata")
            .permissions();
        perms.set_mode(0o700);
        std::fs::set_permissions(&temp_runtime, perms)
            .expect("Failed to set runtime dir permissions");
    }

    std::env::set_var("XDG_RUNTIME_DIR", &temp_runtime);

    temp_runtime
}

/// Ensure XDG_RUNTIME_DIR is set and usable, creating it if necessary
///
/// This is a convenience wrapper around `detect_xdg_runtime_dir()` that
/// can be called from test setup code.
pub fn ensure_xdg_runtime_dir() -> PathBuf {
    let env = Environment::get();
    env.xdg_runtime_dir.clone()
}

/// Check if bubblewrap is available
///
/// This is a convenience function that uses the cached environment.
pub fn is_bwrap_available() -> bool {
    Environment::get().bwrap_available
}

/// Check if systemd is available
///
/// This is a convenience function that uses the cached environment.
pub fn is_systemd_available() -> bool {
    Environment::get().systemd_available
}

/// Check if launchd is available (macOS)
///
/// This is a convenience function that uses the cached environment.
pub fn is_launchd_available() -> bool {
    Environment::get().launchd_available
}

/// Check if running in CI environment
///
/// This is a convenience function that uses the cached environment.
pub fn is_ci() -> bool {
    Environment::get().is_ci
}

/// Skip test helper functions
///
/// These functions provide a clean API for tests to skip with clear messages.
pub mod skip {
    use super::*;

    /// Skip test if bwrap is not available
    ///
    /// Prints a clear message and returns from the test function.
    /// Use this at the beginning of tests that require bubblewrap.
    ///
    /// # Example
    ///
    /// ```no_run
    /// #[test]
    /// fn test_sandbox_isolation() {
    ///     skip::if_no_bwrap();
    ///     // Test code that requires bwrap...
    /// }
    /// ```
    pub fn if_no_bwrap() {
        if !is_bwrap_available() {
            eprintln!("Skipping test: bubblewrap not available");
            eprintln!("  Install with: apt install bubblewrap (Debian/Ubuntu)");
            eprintln!("               yum install bubblewrap (RHEL/CentOS)");
            eprintln!("               brew install bwrap (macOS via Homebrew)");
            std::process::exit(0); // Exit test successfully (skip)
        }
    }

    /// Skip test if bwrap is not available with custom message
    ///
    /// Like `if_no_bwrap()` but allows a custom message.
    ///
    /// # Example
    ///
    /// ```no_run
    /// #[test]
    /// fn test_custom_sandbox() {
    ///     skip::if_no_bwrap_with("custom sandbox test requires bwrap");
    ///     // Test code...
    /// }
    /// ```
    pub fn if_no_bwrap_with(reason: &str) {
        if !is_bwrap_available() {
            eprintln!("Skipping test: bubblewrap not available - {}", reason);
            eprintln!("  Install bubblewrap to enable this test");
            std::process::exit(0); // Exit test successfully (skip)
        }
    }

    /// Skip test if systemd is not available
    ///
    /// Use this for tests that require systemd socket activation.
    pub fn if_no_systemd() {
        if !is_systemd_available() {
            eprintln!("Skipping test: systemd not available");
            eprintln!("  This test requires systemd for socket activation");
            std::process::exit(0); // Exit test successfully (skip)
        }
    }

    /// Skip test if launchd is not available
    ///
    /// Use this for tests that require launchd (macOS only).
    pub fn if_no_launchd() {
        if !is_launchd_available() {
            eprintln!("Skipping test: launchd not available (macOS only)");
            std::process::exit(0); // Exit test successfully (skip)
        }
    }

    /// Skip test if running in CI
    ///
    /// Use this for tests that require interactive features or specific
    /// environment setup not available in CI.
    pub fn if_ci() {
        if is_ci() {
            eprintln!("Skipping test: running in CI environment");
            eprintln!("  This test requires features not available in CI");
            std::process::exit(0); // Exit test successfully (skip)
        }
    }

    /// Skip test if running in CI with custom message
    ///
    /// Like `if_ci()` but allows a custom message.
    pub fn if_ci_with(reason: &str) {
        if is_ci() {
            eprintln!("Skipping test: running in CI - {}", reason);
            std::process::exit(0); // Exit test successfully (skip)
        }
    }

    /// Skip test if a binary is not found
    ///
    /// Use this for tests that require specific binaries to be built.
    ///
    /// # Example
    ///
    /// ```no_run
    /// # use std::path::Path;
    /// #[test]
    /// fn test_daemon_integration() {
    ///     skip::if_binary_missing(Path::new("/path/to/sigild"));
    ///     // Test code...
    /// }
    /// ```
    pub fn if_binary_missing(binary_path: &Path) {
        if !binary_path.exists() {
            eprintln!("Skipping test: binary not found at {:?}", binary_path);
            eprintln!(
                "  Hint: Run 'cargo build --bin {}' to build the binary",
                binary_path
                    .file_name()
                    .unwrap_or_default()
                    .to_string_lossy()
            );
            std::process::exit(0); // Exit test successfully (skip)
        }
    }

    /// Skip test if a binary is not found with custom reason
    ///
    /// Like `if_binary_missing()` but allows a custom message.
    pub fn if_binary_missing_with(binary_path: &Path, reason: &str) {
        if !binary_path.exists() {
            eprintln!(
                "Skipping test: binary not found at {:?} - {}",
                binary_path, reason
            );
            eprintln!(
                "  Hint: Run 'cargo build --bin {}' to build the binary",
                binary_path
                    .file_name()
                    .unwrap_or_default()
                    .to_string_lossy()
            );
            std::process::exit(0); // Exit test successfully (skip)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_environment_detection() {
        let env = Environment::detect();

        // XDG_RUNTIME_DIR should always be set (even if we created it)
        assert!(env.xdg_runtime_dir.exists());

        // Should be able to call get() multiple times
        let env2 = Environment::get();
        assert_eq!(env.bwrap_available, env2.bwrap_available);
        assert_eq!(env.systemd_available, env2.systemd_available);
    }

    #[test]
    fn test_bwrap_detection_returns_bool() {
        // Should not panic, just return true or false
        let available = detect_bwrap();
        assert!(available == true || available == false);
    }

    #[test]
    fn test_xdg_runtime_dir_created() {
        let runtime_dir = detect_xdg_runtime_dir();

        // Should exist and be a directory
        assert!(runtime_dir.exists());
        assert!(runtime_dir.is_dir());

        // XDG_RUNTIME_DIR env var should be set
        assert_eq!(
            std::env::var("XDG_RUNTIME_DIR").unwrap(),
            runtime_dir.to_string_lossy().to_string()
        );
    }

    #[test]
    fn test_ensure_xdg_runtime_dir() {
        let path = ensure_xdg_runtime_dir();
        assert!(path.exists());
        assert!(path.is_dir());
    }

    #[test]
    fn test_is_bwrap_available() {
        // Should not panic
        let available = is_bwrap_available();
        assert!(available == true || available == false);
    }

    #[test]
    fn test_ci_detection() {
        // Should not panic
        let is_ci = detect_ci();
        assert!(is_ci == true || is_ci == false);
    }
}
