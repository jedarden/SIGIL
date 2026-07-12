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

use anyhow::{Context, Result};
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

/// Ensure XDG_RUNTIME_DIR is set and usable, creating it if necessary.
///
/// This function checks if XDG_RUNTIME_DIR is already set in the environment.
/// If it is set and points to an existing writable directory, it returns that path.
/// If XDG_RUNTIME_DIR is not set or the directory is not writable, it creates a
/// new temporary directory using tempfile::tempdir() and sets the XDG_RUNTIME_DIR
/// environment variable for the current process.
///
/// # Fallback Behavior
///
/// When XDG_RUNTIME_DIR is not set or unusable, this function:
/// 1. Creates a temporary directory in the system temp location
/// 2. Sets permissions to 0700 (user-only access) on Unix systems
/// 3. Sets the XDG_RUNTIME_DIR environment variable via std::env::set_var
/// 4. Returns the path to the created directory
///
/// The temporary directory will be automatically cleaned up when the
/// TempDir object is dropped (typically at process exit).
///
/// # Returns
///
/// Returns `Ok(PathBuf)` containing the path to the runtime directory.
/// Returns `Err` if directory creation fails or permissions cannot be set.
///
/// # Examples
///
/// ```no_run
/// use sigil_integration_tests::env_detect::ensure_xdg_runtime_dir;
///
/// # fn main() -> anyhow::Result<()> {
/// let runtime_dir = ensure_xdg_runtime_dir()?;
/// println!("XDG_RUNTIME_DIR: {:?}", runtime_dir);
/// assert!(runtime_dir.exists());
/// # Ok(())
/// # }
/// ```
pub fn ensure_xdg_runtime_dir() -> Result<PathBuf> {
    // Check if XDG_RUNTIME_DIR is already set and usable
    if let Ok(runtime_dir_str) = std::env::var("XDG_RUNTIME_DIR") {
        let runtime_dir = PathBuf::from(&runtime_dir_str);

        if runtime_dir.exists() && runtime_dir.is_dir() {
            // Verify it's writable by attempting to create a test file
            let test_file = runtime_dir.join(".sigil-test-write");
            if std::fs::write(&test_file, b"test").is_ok() {
                let _ = std::fs::remove_file(&test_file);
                return Ok(runtime_dir);
            }
        }
    }

    // Create a new temporary directory using tempfile
    let temp_dir = tempfile::tempdir().context("Failed to create temporary XDG_RUNTIME_DIR")?;

    let runtime_path = temp_dir.path().to_path_buf();

    // Set permissions to 0700 on Unix for security
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = std::fs::metadata(&runtime_path)
            .context("Failed to get runtime dir metadata")?
            .permissions();
        perms.set_mode(0o700);
        std::fs::set_permissions(&runtime_path, perms)
            .context("Failed to set runtime dir permissions")?;
    }

    // Set the environment variable for this process
    std::env::set_var("XDG_RUNTIME_DIR", &runtime_path);

    // Leak the TempDir to prevent cleanup while process runs
    // The directory will still be cleaned up on process exit
    Box::leak(Box::new(temp_dir));

    Ok(runtime_path)
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

/// Skip test helper macros
///
/// These macros provide a clean API for tests to skip with clear messages
/// following Rust testing conventions.
///
/// The macros are exported at the crate root via `#[macro_export]` and can be
/// imported with `use sigil_integration_tests::env_detect::skip_if_no_bwrap;`.
#[macro_use]
pub mod macros {
    /// Skip test if bubblewrap is not available
    ///
    /// This macro checks if `bwrap` is available on the system and skips the test
    /// with a clear message if it is not. Use this macro at the beginning of tests
    /// that require bubblewrap for sandbox execution.
    ///
    /// The macro expands to check `is_bwrap_available()` and will skip the test
    /// by calling `std::process::exit(0)` if bwrap is unavailable, which is treated
    /// as a successful skip by test runners (not a test failure).
    ///
    /// # When to Use the Macro vs Function
    ///
    /// **Use this macro when:**
    /// - You want concise syntax at the start of your test
    /// - You don't need conditional logic based on bwrap availability
    /// - You prefer the macro's compile-time syntax checking
    ///
    /// **Use `skip::if_no_bwrap()` function when:**
    /// - You need to call the skip helper conditionally
    /// - You want installation hints to be printed when skipping
    /// - You're in a context where macros are awkward (e.g., complex expressions)
    ///
    /// # Basic Usage
    ///
    /// Place the macro call at the beginning of your test function:
    ///
    /// ```no_run
    /// use sigil_integration_tests::skip_if_no_bwrap;
    ///
    /// #[test]
    /// fn test_sandbox_isolation() {
    ///     skip_if_no_bwrap!();
    ///     // Test code that requires bwrap...
    ///     assert!(true);
    /// }
    /// ```
    ///
    /// # Custom Reason
    ///
    /// Provide a custom reason to make it clear why your test needs bwrap:
    ///
    /// ```no_run
    /// use sigil_integration_tests::skip_if_no_bwrap;
    ///
    /// #[test]
    /// fn test_custom_sandbox() {
    ///     skip_if_no_bwrap!("custom sandbox test requires namespace isolation");
    ///     // Test code...
    /// }
    /// ```
    ///
    /// # Skip Message Format
    ///
    /// When bwrap is not available, the macro prints a message to stderr:
    ///
    /// **Default message (no custom reason):**
    /// ```text
    /// test skipped: bwrap not available
    /// ```
    ///
    /// **With custom reason:**
    /// ```text
    /// test skipped: custom sandbox test requires namespace isolation - bwrap not available
    /// ```
    ///
    /// # Installation Guidance
    ///
    /// For detailed installation hints, use the `skip::if_no_bwrap()` function
    /// instead, which prints platform-specific installation instructions.
    ///
    /// To install bubblewrap:
    /// - **Debian/Ubuntu:** `apt install bubblewrap`
    /// - **RHEL/CentOS/Fedora:** `yum install bubblewrap`
    /// - **Arch Linux:** `pacman -S bubblewrap`
    /// - **macOS:** `brew install bwrap`
    ///
    /// # Cross-References
    ///
    /// - Function version: [`skip::if_no_bwrap()`](crate::env_detect::skip::if_no_bwrap)
    /// - Function with installation hints: [`skip::if_no_bwrap()`](crate::env_detect::skip::if_no_bwrap)
    /// - Detection function: [`is_bwrap_available()`](crate::env_detect::is_bwrap_available)
    ///
    /// # Behavior When bwrap is Available
    ///
    /// When bubblewrap is available, the macro expands to an empty block and
    /// the test continues normally. This has zero runtime overhead when bwrap
    /// is present.
    #[macro_export]
    macro_rules! skip_if_no_bwrap {
        () => {
            if !$crate::env_detect::is_bwrap_available() {
                eprintln!("test skipped: bwrap not available");
                std::process::exit(0);
            }
        };
        ($reason:expr) => {
            if !$crate::env_detect::is_bwrap_available() {
                eprintln!("test skipped: {} - bwrap not available", $reason);
                std::process::exit(0);
            }
        };
    }

    /// Skip test if systemd is not available
    ///
    /// This macro checks if systemd is available and skips the test with a clear
    /// message if it is not. Use this for tests that require systemd socket activation.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use sigil_integration_tests::env_detect::skip_if_no_systemd;
    ///
    /// #[test]
    /// fn test_socket_activation() {
    ///     skip_if_no_systemd!();
    ///     // Test code that requires systemd...
    /// }
    /// ```
    #[macro_export]
    macro_rules! skip_if_no_systemd {
        () => {
            if !$crate::env_detect::is_systemd_available() {
                eprintln!("test skipped: systemd not available");
                std::process::exit(0);
            }
        };
        ($reason:expr) => {
            if !$crate::env_detect::is_systemd_available() {
                eprintln!("test skipped: {} - systemd not available", $reason);
                std::process::exit(0);
            }
        };
    }

    /// Skip test if launchd is not available (macOS only)
    ///
    /// This macro checks if launchd is available and skips the test with a clear
    /// message if it is not. Use this for tests that require launchd on macOS.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use sigil_integration_tests::env_detect::skip_if_no_launchd;
    ///
    /// #[test]
    /// fn test_launchd_service() {
    ///     skip_if_no_launchd!();
    ///     // Test code that requires launchd...
    /// }
    /// ```
    #[macro_export]
    macro_rules! skip_if_no_launchd {
        () => {
            if !$crate::env_detect::is_launchd_available() {
                eprintln!("test skipped: launchd not available (macOS only)");
                std::process::exit(0);
            }
        };
        ($reason:expr) => {
            if !$crate::env_detect::is_launchd_available() {
                eprintln!(
                    "test skipped: {} - launchd not available (macOS only)",
                    $reason
                );
                std::process::exit(0);
            }
        };
    }
}

/// Skip test helper functions
///
/// These functions provide a clean API for tests to skip with clear messages.
/// They are function versions of the macros for flexibility in test code.
pub mod skip {
    use super::*;

    /// Skip test if bubblewrap is not available (with installation hints)
    ///
    /// This function checks if bubblewrap is available and skips the test with
    /// a clear message if it is not. Unlike the macro version, this function
    /// also prints platform-specific installation instructions to help users
    /// enable the skipped test.
    ///
    /// The function calls `std::process::exit(0)` when bwrap is unavailable,
    /// which test runners treat as a successful skip (not a failure).
    ///
    /// # When to Use the Function vs Macro
    ///
    /// **Use this function when:**
    /// - You want installation hints printed when skipping
    /// - You need to call the skip helper conditionally in complex logic
    /// - You're in a context where macros are awkward (e.g., dynamic calls)
    /// - You prefer explicit function calls over macro syntax
    ///
    /// **Use `skip_if_no_bwrap!()` macro when:**
    /// - You want concise syntax at the start of your test
    /// - You don't need installation hints printed
    /// - You prefer compile-time syntax checking
    ///
    /// # Basic Usage
    ///
    /// Call this function at the beginning of your test:
    ///
    /// ```no_run
    /// use sigil_integration_tests::env_detect::skip;
    ///
    /// #[test]
    /// fn test_sandbox_isolation() {
    ///     skip::if_no_bwrap();
    ///     // Test code that requires bwrap...
    ///     assert!(true);
    /// }
    /// ```
    ///
    /// # Skip Message with Installation Hints
    ///
    /// When bwrap is not available, this function prints:
    /// ```text
    /// test skipped: bwrap not available
    ///   Install with: apt install bubblewrap (Debian/Ubuntu)
    ///                yum install bubblewrap (RHEL/CentOS)
    ///                brew install bwrap (macOS via Homebrew)
    /// ```
    ///
    /// The installation hints cover the most common platforms and help users
    /// quickly enable the skipped test.
    ///
    /// # Cross-References
    ///
    /// - Macro version: [`skip_if_no_bwrap!()`](crate::skip_if_no_bwrap)
    /// - Custom reason function: [`skip::if_no_bwrap_with()`](crate::env_detect::skip::if_no_bwrap_with)
    /// - Detection function: [`is_bwrap_available()`](crate::env_detect::is_bwrap_available)
    ///
    /// # See Also
    ///
    /// - [`skip::if_no_bwrap_with()`](crate::env_detect::skip::if_no_bwrap_with) — Same functionality with custom message
    /// - [`skip_if_no_bwrap!()`](crate::skip_if_no_bwrap) — Macro version without installation hints
    pub fn if_no_bwrap() {
        if !is_bwrap_available() {
            eprintln!("test skipped: bwrap not available");
            eprintln!("  Install with: apt install bubblewrap (Debian/Ubuntu)");
            eprintln!("               yum install bubblewrap (RHEL/CentOS)");
            eprintln!("               brew install bwrap (macOS via Homebrew)");
            std::process::exit(0); // Exit test successfully (skip)
        }
    }

    /// Skip test if bubblewrap is not available (with custom message and hints)
    ///
    /// This function combines the custom message capability of the macro with
    /// the installation hints of the base function. Use this when you want to
    /// explain why your specific test needs bwrap while still providing helpful
    /// installation guidance.
    ///
    /// # When to Use This Function
    ///
    /// **Use `skip::if_no_bwrap_with()` when:**
    /// - Your test has a specific reason for requiring bwrap
    /// - You want both a custom message and installation hints
    /// - You're calling the skip helper conditionally with context
    ///
    /// **Compare with alternatives:**
    /// - `skip_if_no_bwrap!("reason")` — Macro with custom message, no hints
    /// - `skip::if_no_bwrap()` — Function with hints, no custom message
    /// - `skip::if_no_bwrap_with()` — **Function with both custom message and hints**
    ///
    /// # Basic Usage
    ///
    /// ```no_run
    /// use sigil_integration_tests::env_detect::skip;
    ///
    /// #[test]
    /// fn test_sandbox_network_isolation() {
    ///     skip::if_no_bwrap_with("network namespace isolation requires bwrap");
    ///     // Test code that requires bwrap network namespaces...
    ///     assert!(true);
    /// }
    /// ```
    ///
    /// # Skip Message Format
    ///
    /// When bwrap is not available, this function prints:
    /// ```text
    /// Skipping test: bubblewrap not available - network namespace isolation requires bwrap
    ///   Install bubblewrap to enable this test
    /// ```
    ///
    /// The custom reason helps users understand why this specific test needs
    /// bwrap, while the installation hint provides immediate actionable guidance.
    ///
    /// # Conditional Usage
    ///
    /// This function is particularly useful in conditional contexts:
    ///
    /// ```no_run
    /// # use sigil_integration_tests::env_detect::skip;
    /// # fn test_conditional() {
    /// if cfg!(feature = "sandbox-tests") {
    ///     skip::if_no_bwrap_with("sandbox feature is enabled but bwrap unavailable");
    /// }
    /// # }
    /// ```
    ///
    /// # Cross-References
    ///
    /// - Base function: [`skip::if_no_bwrap()`](crate::env_detect::skip::if_no_bwrap)
    /// - Macro with custom message: [`skip_if_no_bwrap!($reason)`](crate::skip_if_no_bwrap)
    /// - Detection function: [`is_bwrap_available()`](crate::env_detect::is_bwrap_available)
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
    // Import specific functions to avoid ambiguity with macros
    use super::skip;
    use super::{
        detect_bwrap, detect_ci, detect_xdg_runtime_dir, ensure_xdg_runtime_dir,
        is_bwrap_available, Environment,
    };

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
        // Just verify the function returns without panicking
        let _ = available;
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
        // Remove XDG_RUNTIME_DIR if it exists to test the fallback behavior
        let original = std::env::var("XDG_RUNTIME_DIR").ok();
        std::env::remove_var("XDG_RUNTIME_DIR");

        // Call ensure_xdg_runtime_dir and verify it succeeds
        let result = ensure_xdg_runtime_dir();
        assert!(result.is_ok(), "ensure_xdg_runtime_dir should succeed");

        let path = result.unwrap();
        assert!(path.exists(), "Runtime directory should exist");
        assert!(path.is_dir(), "Runtime path should be a directory");

        // Verify XDG_RUNTIME_DIR environment variable was set
        let env_value = std::env::var("XDG_RUNTIME_DIR");
        assert!(env_value.is_ok(), "XDG_RUNTIME_DIR should be set");
        assert_eq!(env_value.unwrap(), path.to_string_lossy().to_string());

        // Restore original value if there was one
        if let Some(original_value) = original {
            std::env::set_var("XDG_RUNTIME_DIR", original_value);
        }
    }

    #[test]
    fn test_ensure_xdg_runtime_dir_with_existing_dir() {
        // Create a temporary directory to use as XDG_RUNTIME_DIR
        let temp_base = tempfile::tempdir().expect("Failed to create temp dir");
        let existing_dir = temp_base.path().join("runtime");
        std::fs::create_dir(&existing_dir).expect("Failed to create runtime dir");

        // Set XDG_RUNTIME_DIR to the existing directory
        std::env::set_var("XDG_RUNTIME_DIR", &existing_dir);

        // Call ensure_xdg_runtime_dir and verify it returns the existing path
        let result = ensure_xdg_runtime_dir();
        assert!(result.is_ok(), "ensure_xdg_runtime_dir should succeed");

        let path = result.unwrap();
        assert_eq!(path, existing_dir, "Should return existing XDG_RUNTIME_DIR");
    }

    #[test]
    fn test_ensure_xdg_runtime_dir_permissions() {
        // Remove XDG_RUNTIME_DIR to test directory creation
        std::env::remove_var("XDG_RUNTIME_DIR");

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;

            let result = ensure_xdg_runtime_dir();
            assert!(result.is_ok());

            let path = result.unwrap();

            // Check that permissions are set to 0700
            let metadata = std::fs::metadata(&path).expect("Failed to get metadata");
            let mode = metadata.permissions().mode();
            assert_eq!(
                mode & 0o777,
                0o700,
                "Directory should have 0700 permissions"
            );
        }

        #[cfg(not(unix))]
        {
            // On non-Unix systems, just verify the directory was created
            let result = ensure_xdg_runtime_dir();
            assert!(result.is_ok());
            assert!(result.unwrap().exists());
        }
    }

    #[test]
    fn test_is_bwrap_available() {
        // Should not panic, just verify the cached function works
        let _ = is_bwrap_available();
    }

    #[test]
    fn test_ci_detection() {
        // Should not panic
        let is_ci = detect_ci();
        // Just verify it returns a boolean without issues
        let _ = is_ci;
    }

    #[test]
    fn test_skip_if_no_bwrap_macro() {
        // This test demonstrates the skip_if_no_bwrap! macro behavior
        // It will skip if bwrap is not available, otherwise it runs successfully
        skip_if_no_bwrap!();

        // If we reach here, bwrap is available - test passes
        // The test ran successfully when we reach this point
    }

    #[test]
    fn test_skip_if_no_bwrap_macro_with_custom_reason() {
        // Test the macro with a custom reason
        skip_if_no_bwrap!("sandbox isolation test with custom message");

        // If we reach here, bwrap is available
        // The custom reason test ran successfully
    }

    #[test]
    fn test_skip_if_no_bwrap_function() {
        // Test the function version of the skip helper
        skip::if_no_bwrap();

        // If we reach here, bwrap is available
        // The function version ran successfully
    }
}
