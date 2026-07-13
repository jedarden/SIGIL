//! Binary Fixture Utilities
//!
//! This module provides utility functions for creating temporary test binaries
//! with specific permissions, including setuid binaries for testing sandbox
//! security properties.
//!
//! # Features
//!
//! - Create temporary binaries with specific permissions (including setuid)
//! - Clean up test binaries after tests complete
//! - Add binaries to test PATH for execution
//! - Support for both setuid and non-setuid binaries
//! - RAII guards for automatic cleanup
//!
//! # Security Testing
//!
//! These utilities are primarily used for testing SIGIL's sandbox security:
//! - Verify sandbox detects and blocks setuid binaries
//! - Test namespace isolation prevents privilege escalation
//! - Validate seccomp filters block privileged syscalls
//!
//! # Examples
//!
//! ```rust
//! use sigil_integration_tests::binary_fixture::*;
//!
//! // Create a temporary setuid binary
//! let setuid_bin = create_setuid_binary("test_setuid", b"#!/bin/sh\necho test\n").unwrap();
//!
//! // Add to PATH for a test
//! let _path_guard = add_to_path(&setuid_bin);
//!
//! // Binary is automatically cleaned up when _path_guard is dropped
//! ```

use anyhow::{Context, Result};
use std::env;
use std::fs;
use std::io::Write;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::Mutex;

/// Temporary directory for test binaries
static TEST_BIN_DIR: Mutex<Option<PathBuf>> = Mutex::new(None);

/// Initialize the test binary directory
///
/// This function creates a temporary directory for test binaries and
/// caches it for the lifetime of the test process. Subsequent calls
/// return the same directory.
///
/// # Returns
///
/// The path to the test binary directory
///
/// # Examples
///
/// ```rust
/// use sigil_integration_tests::binary_fixture::init_test_bin_dir;
///
/// let dir = init_test_bin_dir().unwrap();
/// println!("Test binaries will be created in: {:?}", dir);
/// ```
pub fn init_test_bin_dir() -> Result<PathBuf> {
    let mut cache = TEST_BIN_DIR
        .lock()
        .map_err(|e| anyhow::anyhow!("Lock failed: {}", e))?;

    // Create a temporary directory for test binaries
    let temp_dir = std::env::temp_dir();
    let test_dir = temp_dir.join(format!("sigil-test-binaries-{}", std::process::id()));

    // Always ensure the directory exists
    if !test_dir.exists() {
        fs::create_dir_all(&test_dir).context("Failed to create test binary directory")?;
    }

    // Update the cache
    *cache = Some(test_dir.clone());
    Ok(test_dir)
}

/// Create a temporary test binary with specified content and permissions
///
/// This function creates a new binary file with the given content and
/// permissions. The binary is created in the test binary directory and
/// will be cleaned up when `cleanup_test_binaries` is called.
///
/// # Arguments
///
/// * `name` - The name of the binary (without extension)
/// * `content` - The binary content (e.g., shell script, compiled binary)
/// * `mode` - The file permission bits (e.g., 0o755 for executable)
/// * `setuid` - Whether to set the setuid bit
///
/// # Returns
///
/// The path to the created binary
///
/// # Errors
///
/// Returns an error if:
/// - The test binary directory cannot be created
/// - The binary file cannot be written
/// - Permissions cannot be set
///
/// # Examples
///
/// ```rust
/// use sigil_integration_tests::binary_fixture::create_test_binary;
///
/// // Create a regular executable binary
/// let bin = create_test_binary("mytest", b"#!/bin/sh\necho hello\n", 0o755, false).unwrap();
///
/// // Create a setuid binary
/// let setuid_bin = create_test_binary("sudotest", b"#!/bin/sh\nid\n", 0o755, true).unwrap();
/// ```
pub fn create_test_binary(name: &str, content: &[u8], mode: u32, setuid: bool) -> Result<PathBuf> {
    let test_dir = init_test_bin_dir()?;

    // Ensure the directory exists (in case it was cleaned up)
    if !test_dir.exists() {
        fs::create_dir_all(&test_dir).context("Failed to create test binary directory")?;
    }

    let binary_path = test_dir.join(name);

    // Write the binary content
    let mut file = fs::File::create(&binary_path)
        .with_context(|| format!("Failed to create binary file: {:?}", binary_path))?;
    file.write_all(content)
        .context("Failed to write binary content")?;

    // Set permissions
    let mut perms = fs::metadata(&binary_path)
        .context("Failed to get file metadata")?
        .permissions();

    let mut mode_bits = mode & 0o777; // Extract permission bits

    if setuid {
        mode_bits |= 0o4000; // Set setuid bit
    }

    perms.set_mode(mode_bits);
    fs::set_permissions(&binary_path, perms).context("Failed to set file permissions")?;

    Ok(binary_path)
}

/// Create a temporary setuid binary
///
/// This is a convenience function for creating setuid binaries with
/// executable permissions (0o4755).
///
/// # Arguments
///
/// * `name` - The name of the binary
/// * `content` - The binary content
///
/// # Returns
///
/// The path to the created setuid binary
///
/// # Examples
///
/// ```rust
/// use sigil_integration_tests::binary_fixture::create_setuid_binary;
///
/// let setuid_bin = create_setuid_binary("privileged", b"#!/bin/sh\nid\n").unwrap();
/// ```
pub fn create_setuid_binary(name: &str, content: &[u8]) -> Result<PathBuf> {
    create_test_binary(name, content, 0o4755, true)
}

/// Create a setuid fixture for testing
///
/// This is a specialized helper function for creating setuid test fixtures
/// that mimic real setuid binaries (like sudo, passwd, etc.). This function
/// is specifically designed for use in setuid detection tests.
///
/// # Arguments
///
/// * `name` - The name of the binary fixture
/// * `content` - The binary content
///
/// # Returns
///
/// The path to the created setuid fixture
///
/// # Examples
///
/// ```rust
/// use sigil_integration_tests::binary_fixture::create_setuid_fixture;
///
/// let fixture = create_setuid_fixture("test_setuid", b"#!/bin/sh\nid\n").unwrap();
/// ```
pub fn create_setuid_fixture(name: &str, content: &[u8]) -> Result<PathBuf> {
    create_setuid_binary(name, content)
}

/// Create a temporary regular (non-setuid) executable binary
///
/// This is a convenience function for creating regular executable binaries
/// with standard permissions (0o755).
///
/// # Arguments
///
/// * `name` - The name of the binary
/// * `content` - The binary content
///
/// # Returns
///
/// The path to the created binary
///
/// # Examples
///
/// ```rust
/// use sigil_integration_tests::binary_fixture::create_executable_binary;
///
/// let bin = create_executable_binary("normal", b"#!/bin/sh\necho test\n").unwrap();
/// ```
pub fn create_executable_binary(name: &str, content: &[u8]) -> Result<PathBuf> {
    create_test_binary(name, content, 0o755, false)
}

/// Check if a binary has the setuid bit set
///
/// This function examines the file metadata to determine if the setuid
/// bit is set on the binary.
///
/// # Arguments
///
/// * `path` - Path to the binary to check
///
/// # Returns
///
/// `true` if the setuid bit is set, `false` otherwise
///
/// # Errors
///
/// Returns an error if the file metadata cannot be read
///
/// # Examples
///
/// ```rust
/// use sigil_integration_tests::binary_fixture::{create_setuid_binary, is_setuid};
///
/// let setuid_bin = create_setuid_binary("test", b"test").unwrap();
/// assert!(is_setuid(&setuid_bin).unwrap());
/// ```
pub fn is_setuid(path: &Path) -> Result<bool> {
    let metadata = fs::metadata(path).context("Failed to get file metadata")?;

    let mode = metadata.mode();
    Ok(mode & 0o4000 != 0)
}

/// RAII guard for PATH modification
///
/// This guard adds a directory to PATH and automatically restores the
/// original PATH when dropped. Use this to temporarily add test binaries
/// to PATH for testing.
///
/// # Examples
///
/// ```rust
/// use sigil_integration_tests::binary_fixture::add_to_path;
///
/// {
///     let _guard = add_to_path(&PathBuf::from("/tmp/test-bin")).unwrap();
///     // Test binaries in /tmp/test-bin are now available in PATH
/// } // _guard is dropped here, PATH is restored
/// ```
pub struct PathGuard {
    original_path: String,
}

impl PathGuard {
    /// Create a new PathGuard
    fn new(original_path: String) -> Self {
        Self { original_path }
    }
}

impl Drop for PathGuard {
    fn drop(&mut self) {
        // Restore the original PATH
        env::set_var("PATH", &self.original_path);
    }
}

/// Add a directory to the PATH for the duration of a test
///
/// This function adds a directory to the front of PATH and returns a guard
/// that will restore the original PATH when dropped.
///
/// # Arguments
///
/// * `dir` - The directory to add to PATH
///
/// # Returns
///
/// A `PathGuard` that will restore PATH when dropped
///
/// # Examples
///
/// ```rust
/// use sigil_integration_tests::binary_fixture::add_to_path;
///
/// // Add test binaries to PATH
/// let _guard = add_to_path(&PathBuf::from("/tmp/test-bin")).unwrap();
///
/// // Now commands in that directory are available
/// let output = std::process::Command::new("test-cmd")
///     .output()
///     .unwrap();
/// ```
pub fn add_to_path(dir: &Path) -> Result<PathGuard> {
    let dir_str = dir.to_str().context("Directory path is not valid UTF-8")?;

    // Save the original PATH before modifying it
    let original_path = env::var("PATH").unwrap_or_default();

    let new_path = format!("{}:{}", dir_str, original_path);
    env::set_var("PATH", new_path);

    Ok(PathGuard::new(original_path))
}

/// Add a binary to the PATH for the duration of a test
///
/// This is a convenience function that adds the parent directory of a
/// binary to PATH.
///
/// # Arguments
///
/// * `binary_path` - Path to the binary
///
/// # Returns
///
/// A `PathGuard` that will restore PATH when dropped
///
/// # Examples
///
/// ```rust
/// use sigil_integration_tests::binary_fixture::add_binary_to_path;
///
/// let bin = create_executable_binary("test", b"#!/bin/sh\necho test\n").unwrap();
/// let _guard = add_binary_to_path(&bin).unwrap();
///
/// // Now the binary is available in PATH
/// let output = std::process::Command::new("test")
///     .output()
///     .unwrap();
/// ```
pub fn add_binary_to_path(binary_path: &Path) -> Result<PathGuard> {
    let parent = binary_path.parent().unwrap_or(Path::new("/"));
    add_to_path(parent)
}

/// Clean up all test binaries
///
/// This function removes the test binary directory and all binaries
/// created by the fixture helpers. It's safe to call multiple times.
///
/// # Examples
///
/// ```rust
/// use sigil_integration_tests::binary_fixture::{create_executable_binary, cleanup_test_binaries};
///
/// // Create some test binaries
/// let bin1 = create_executable_binary("test1", b"test1").unwrap();
/// let bin2 = create_executable_binary("test2", b"test2").unwrap();
///
/// // Clean up all test binaries
/// cleanup_test_binaries().unwrap();
/// ```
pub fn cleanup_test_binaries() -> Result<()> {
    let mut cache = TEST_BIN_DIR
        .lock()
        .map_err(|e| anyhow::anyhow!("Lock failed: {}", e))?;

    if let Some(ref dir) = *cache {
        // Remove the entire directory if it exists
        if dir.exists() {
            fs::remove_dir_all(dir).context("Failed to remove test binary directory")?;
        }
    }

    // Always clear the cache, even if directory doesn't exist
    *cache = None;

    Ok(())
}

/// Clean up setuid fixtures after testing
///
/// This is a specialized helper function for cleaning up setuid test fixtures.
/// It's specifically designed for use in setuid detection tests to ensure
/// proper cleanup of setuid binaries after testing completes.
///
/// # Examples
///
/// ```rust
/// use sigil_integration_tests::binary_fixture::{create_setuid_fixture, cleanup_setuid_fixtures};
///
/// let fixture = create_setuid_fixture("test_setuid", b"test\n").unwrap();
/// // Run tests...
/// cleanup_setuid_fixtures().unwrap();
/// ```
pub fn cleanup_setuid_fixtures() -> Result<()> {
    cleanup_test_binaries()
}

/// RAII guard for automatic cleanup of test binaries
///
/// This guard automatically cleans up all test binaries when dropped.
/// Use this to ensure cleanup even if a test panics.
///
/// # Examples
///
/// ```rust
/// use sigil_integration_tests::binary_fixture::BinaryFixtureGuard;
///
/// {
///     let _guard = BinaryFixtureGuard::new();
///
///     // Create test binaries
///     let bin = create_executable_binary("test", b"test").unwrap();
///
///     // Test code here...
/// } // _guard is dropped here, all binaries are cleaned up
/// ```
pub struct BinaryFixtureGuard;

impl Default for BinaryFixtureGuard {
    fn default() -> Self {
        Self::new()
    }
}

impl BinaryFixtureGuard {
    /// Create a new BinaryFixtureGuard
    pub fn new() -> Self {
        Self
    }
}

impl Drop for BinaryFixtureGuard {
    fn drop(&mut self) {
        // Clean up test binaries, ignoring errors
        let _ = cleanup_test_binaries();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::os::unix::fs::PermissionsExt;

    #[test]
    fn test_init_test_bin_dir() {
        let dir = init_test_bin_dir().unwrap();

        assert!(dir.exists(), "Test directory should exist");
        assert!(dir.is_dir(), "Should be a directory");

        // Verify it's in the temp directory
        let temp_dir = std::env::temp_dir();
        assert!(dir.starts_with(&temp_dir), "Should be in temp directory");
    }

    #[test]
    fn test_create_executable_binary() {
        let bin = create_executable_binary("test_exec", b"#!/bin/sh\necho test\n").unwrap();

        assert!(bin.exists(), "Binary should exist");
        assert!(bin.is_file(), "Should be a file");

        // Check permissions
        let metadata = fs::metadata(&bin).unwrap();
        let mode = metadata.permissions().mode();

        assert_eq!(mode & 0o755, 0o755, "Should have executable permissions");
        assert_eq!(mode & 0o4000, 0, "Should NOT have setuid bit");
    }

    #[test]
    fn test_create_setuid_binary() {
        let bin = create_setuid_binary("test_setuid", b"#!/bin/sh\nid\n").unwrap();

        assert!(bin.exists(), "Binary should exist");

        // Check setuid bit
        let metadata = fs::metadata(&bin).unwrap();
        let mode = metadata.permissions().mode();

        assert_eq!(mode & 0o755, 0o755, "Should have executable permissions");
        assert_ne!(mode & 0o4000, 0, "Should have setuid bit");
    }

    #[test]
    fn test_is_setuid() {
        let regular_bin = create_executable_binary("test_regular_is_setuid", b"test").unwrap();
        let setuid_bin = create_setuid_binary("test_setuid_check", b"test").unwrap();

        assert!(
            !is_setuid(&regular_bin).unwrap(),
            "Regular binary should not be setuid"
        );
        assert!(
            is_setuid(&setuid_bin).unwrap(),
            "Setuid binary should be setuid"
        );
    }

    #[test]
    fn test_create_test_binary_custom_mode() {
        let bin = create_test_binary("custom", b"test", 0o644, false).unwrap();

        assert!(bin.exists(), "Binary should exist");

        let metadata = fs::metadata(&bin).unwrap();
        let mode = metadata.permissions().mode();

        assert_eq!(mode & 0o644, 0o644, "Should have custom permissions");
        assert_eq!(mode & 0o4000, 0, "Should NOT have setuid bit");
    }

    #[test]
    fn test_add_to_path() {
        let test_dir = init_test_bin_dir().unwrap();
        let test_dir_str = test_dir.to_string_lossy().to_string();

        // Get the current PATH before modification
        let original_path = env::var("PATH").unwrap();

        {
            let _guard = add_to_path(&test_dir).unwrap();

            let new_path = env::var("PATH").unwrap();
            assert!(
                new_path.starts_with(&test_dir_str),
                "PATH should start with test directory"
            );
        }

        // PATH should be restored
        let restored_path = env::var("PATH").unwrap();
        assert_eq!(restored_path, original_path, "PATH should be restored");
    }

    #[test]
    fn test_add_binary_to_path() {
        let bin = create_executable_binary("test_path_bin", b"#!/bin/sh\necho test\n").unwrap();
        let parent = bin.parent().unwrap();
        let parent_str = parent.to_string_lossy().to_string();

        let original_path = env::var("PATH").unwrap();

        {
            let _guard = add_binary_to_path(&bin).unwrap();

            let new_path = env::var("PATH").unwrap();
            assert!(
                new_path.starts_with(&parent_str),
                "PATH should start with binary directory"
            );
        }

        // PATH should be restored
        let restored_path = env::var("PATH").unwrap();
        assert_eq!(restored_path, original_path, "PATH should be restored");
    }

    #[test]
    fn test_cleanup_test_binaries() {
        // Ensure we have a clean state
        let _ = cleanup_test_binaries();

        let dir = init_test_bin_dir().unwrap();
        let bin = dir.join("test_cleanup");

        fs::write(&bin, b"test").unwrap();
        assert!(bin.exists(), "Binary should exist before cleanup");

        cleanup_test_binaries().unwrap();
        assert!(!bin.exists(), "Binary should not exist after cleanup");
        assert!(!dir.exists(), "Directory should not exist after cleanup");
    }

    #[test]
    fn test_binary_fixture_guard() {
        // Ensure we have a clean state
        let _ = cleanup_test_binaries();

        let test_dir = init_test_bin_dir().unwrap();
        let bin = test_dir.join("guard_test");

        {
            let _guard = BinaryFixtureGuard::new();

            fs::write(&bin, b"test").unwrap();
            assert!(bin.exists(), "Binary should exist");
        }

        // After guard is dropped, binaries should be cleaned up
        // The directory should have been removed
        assert!(
            !test_dir.exists(),
            "Test directory should be cleaned up after guard drop"
        );
        assert!(
            !bin.exists(),
            "Binary should be cleaned up after guard drop"
        );
    }

    #[test]
    fn test_multiple_binaries() {
        // Ensure we have a clean state
        let _ = cleanup_test_binaries();

        let bin1 = create_executable_binary("test1", b"test1").unwrap();
        let bin2 = create_setuid_binary("test2", b"test2").unwrap();
        let bin3 = create_executable_binary("test3", b"test3").unwrap();

        assert!(bin1.exists());
        assert!(bin2.exists());
        assert!(bin3.exists());

        cleanup_test_binaries().unwrap();

        assert!(!bin1.exists());
        assert!(!bin2.exists());
        assert!(!bin3.exists());
    }

    #[test]
    fn test_setuid_bit_persistence() {
        let bin = create_setuid_binary("persist", b"test").unwrap();

        // Verify setuid bit immediately after creation
        assert!(is_setuid(&bin).unwrap());

        // Verify it persists (re-read from filesystem)
        let metadata = fs::metadata(&bin).unwrap();
        let mode = metadata.permissions().mode();
        assert_ne!(mode & 0o4000, 0, "Setuid bit should persist");
    }

    #[test]
    fn test_init_test_bin_dir_caching() {
        let dir1 = init_test_bin_dir().unwrap();
        let dir2 = init_test_bin_dir().unwrap();

        assert_eq!(dir1, dir2, "Should return the same directory");
    }

    #[test]
    fn test_cleanup_idempotent() {
        // Ensure we have a clean state
        let _ = cleanup_test_binaries();

        // First cleanup should succeed
        assert!(cleanup_test_binaries().is_ok());

        // Second cleanup should also succeed (no error even if nothing to clean)
        assert!(cleanup_test_binaries().is_ok());
    }
}
