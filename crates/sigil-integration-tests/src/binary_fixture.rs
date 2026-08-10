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
use tempfile::TempDir;

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

/// Create a setgid fixture for testing
///
/// This is a specialized helper function for creating setgid test fixtures
/// that mimic real setgid binaries (like write, wall, etc.). This function
/// is specifically designed for use in setgid detection tests.
///
/// # Arguments
///
/// * `name` - The name of the binary fixture
/// * `content` - The binary content
///
/// # Returns
///
/// The path to the created setgid fixture
///
/// # Examples
///
/// ```rust
/// use sigil_integration_tests::binary_fixture::create_setgid_fixture;
///
/// let fixture = create_setgid_fixture("test_setgid", b"#!/bin/sh\necho test\n").unwrap();
/// ```
pub fn create_setgid_fixture(name: &str, content: &[u8]) -> Result<PathBuf> {
    create_setgid_binary(name, content)
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

/// Create a temporary setgid binary
///
/// This is a convenience function for creating setgid binaries with
/// executable permissions (0o2755). The setgid bit (bit 6) causes
/// the binary to execute with the effective group ID of the file's group.
///
/// # Arguments
///
/// * `name` - The name of the binary
/// * `content` - The binary content
///
/// # Returns
///
/// The path to the created setgid binary
///
/// # Examples
///
/// ```rust
/// use sigil_integration_tests::binary_fixture::create_setgid_binary;
///
/// let setgid_bin = create_setgid_binary("group_shared", b"#!/bin/sh\necho test\n").unwrap();
/// ```
pub fn create_setgid_binary(name: &str, content: &[u8]) -> Result<PathBuf> {
    let test_dir = init_test_bin_dir()?;

    // Ensure the directory exists
    if !test_dir.exists() {
        fs::create_dir_all(&test_dir).context("Failed to create test binary directory")?;
    }

    let binary_path = test_dir.join(name);

    // Write the binary content
    let mut file = fs::File::create(&binary_path)
        .with_context(|| format!("Failed to create binary file: {:?}", binary_path))?;
    file.write_all(content)
        .context("Failed to write binary content")?;

    // Set permissions with setgid bit
    let mut perms = fs::metadata(&binary_path)
        .context("Failed to get file metadata")?
        .permissions();

    let mode_bits = 0o2755; // rwxr-xr-x with setgid bit (0o2000)
    perms.set_mode(mode_bits);
    fs::set_permissions(&binary_path, perms).context("Failed to set file permissions")?;

    Ok(binary_path)
}

/// Create a temporary binary with both setuid and setgid bits
///
/// This function creates a binary with both setuid (0o4000) and setgid (0o2000)
/// bits set, resulting in permissions 0o6755. This tests the scenario where
/// a binary should execute with both elevated user and group privileges.
///
/// # Arguments
///
/// * `name` - The name of the binary
/// * `content` - The binary content
///
/// # Returns
///
/// The path to the created setuid+setgid binary
///
/// # Examples
///
/// ```rust
/// use sigil_integration_tests::binary_fixture::create_setuid_setgid_binary;
///
/// let both_bin = create_setuid_setgid_binary("privileged", b"#!/bin/sh\nid\n").unwrap();
/// ```
pub fn create_setuid_setgid_binary(name: &str, content: &[u8]) -> Result<PathBuf> {
    let test_dir = init_test_bin_dir()?;

    // Ensure the directory exists
    if !test_dir.exists() {
        fs::create_dir_all(&test_dir).context("Failed to create test binary directory")?;
    }

    let binary_path = test_dir.join(name);

    // Write the binary content
    let mut file = fs::File::create(&binary_path)
        .with_context(|| format!("Failed to create binary file: {:?}", binary_path))?;
    file.write_all(content)
        .context("Failed to write binary content")?;

    // Set permissions with both setuid and setgid bits
    let mut perms = fs::metadata(&binary_path)
        .context("Failed to get file metadata")?
        .permissions();

    let mode_bits = 0o6755; // rwsr-sr-x (setuid + setgid + executable)
    perms.set_mode(mode_bits);
    fs::set_permissions(&binary_path, perms).context("Failed to set file permissions")?;

    Ok(binary_path)
}

/// Create a temporary binary with the sticky bit set
///
/// This function creates a binary with the sticky bit (0o1000) set, resulting in
/// permissions 0o1755. The sticky bit is commonly used on directories (like /tmp)
/// to restrict deletion to only the file owner, but can also be set on binaries.
/// This tests the scenario where a binary has the sticky bit but should NOT be
/// flagged as setgid.
///
/// # Arguments
///
/// * `name` - The name of the binary
/// * `content` - The binary content
///
/// # Returns
///
/// The path to the created sticky-bit binary
///
/// # Examples
///
/// ```rust
/// use sigil_integration_tests::binary_fixture::create_sticky_bit_binary;
///
/// let sticky_bin = create_sticky_bit_binary("sticky_tool", b"#!/bin/sh\necho test\n").unwrap();
/// ```
pub fn create_sticky_bit_binary(name: &str, content: &[u8]) -> Result<PathBuf> {
    let test_dir = init_test_bin_dir()?;

    // Ensure the directory exists
    if !test_dir.exists() {
        fs::create_dir_all(&test_dir).context("Failed to create test binary directory")?;
    }

    let binary_path = test_dir.join(name);

    // Write the binary content
    let mut file = fs::File::create(&binary_path)
        .with_context(|| format!("Failed to create binary file: {:?}", binary_path))?;
    file.write_all(content)
        .context("Failed to write binary content")?;

    // Set permissions with sticky bit only
    let mut perms = fs::metadata(&binary_path)
        .context("Failed to get file metadata")?
        .permissions();

    let mode_bits = 0o1755; // rwxr-xr-t (sticky bit + executable, but NOT setgid)
    perms.set_mode(mode_bits);
    fs::set_permissions(&binary_path, perms).context("Failed to set file permissions")?;

    Ok(binary_path)
}

/// Check if a binary has the sticky bit set
///
/// This function examines the file metadata to determine if the sticky
/// bit is set on the binary.
///
/// # Arguments
///
/// * `path` - Path to the binary to check
///
/// # Returns
///
/// `true` if the sticky bit is set, `false` otherwise
///
/// # Errors
///
/// Returns an error if the file metadata cannot be read
///
/// # Examples
///
/// ```rust
/// use sigil_integration_tests::binary_fixture::{create_sticky_bit_binary, is_sticky_bit_set};
///
/// let sticky_bin = create_sticky_bit_binary("test", b"test").unwrap();
/// assert!(is_sticky_bit_set(&sticky_bin).unwrap());
/// ```
pub fn is_sticky_bit_set(path: &Path) -> Result<bool> {
    let metadata = fs::metadata(path).context("Failed to get file metadata")?;

    let mode = metadata.mode();
    Ok(mode & 0o1000 != 0)
}

/// Check if a binary has the setgid bit set
///
/// This function examines the file metadata to determine if the setgid
/// bit is set on the binary.
///
/// # Arguments
///
/// * `path` - Path to the binary to check
///
/// # Returns
///
/// `true` if the setgid bit is set, `false` otherwise
///
/// # Errors
///
/// Returns an error if the file metadata cannot be read
///
/// # Examples
///
/// ```rust
/// use sigil_integration_tests::binary_fixture::{create_setgid_binary, is_setgid};
///
/// let setgid_bin = create_setgid_binary("test", b"test").unwrap();
/// assert!(is_setgid(&setgid_bin).unwrap());
/// ```
pub fn is_setgid(path: &Path) -> Result<bool> {
    let metadata = fs::metadata(path).context("Failed to get file metadata")?;

    let mode = metadata.mode();
    Ok(mode & 0o2000 != 0)
}

/// Set the setgid bit on a file
///
/// This function sets the setgid bit (0o2000) on an existing file while
/// preserving other permission bits. The setgid bit causes executable
/// files to run with the effective group ID of the file's group.
///
/// # Arguments
///
/// * `path` - Path to the file to modify
///
/// # Returns
///
/// `Ok(())` if the setgid bit was successfully set
///
/// # Errors
///
/// Returns an error if:
/// - The file metadata cannot be read
/// - The file permissions cannot be modified
///
/// # Examples
///
/// ```rust
/// use sigil_integration_tests::binary_fixture::{set_setgid_bit, is_setgid};
/// use std::fs::File;
///
/// let test_file = "/tmp/test_setgid";
/// File::create(test_file).unwrap();
///
/// set_setgid_bit(std::path::Path::new(test_file)).unwrap();
/// assert!(is_setgid(std::path::Path::new(test_file)).unwrap());
/// ```
#[cfg(unix)]
pub fn set_setgid_bit(path: &Path) -> Result<()> {
    let mut perms = fs::metadata(path)
        .context("Failed to get file metadata")?
        .permissions();

    let current_mode = perms.mode();
    let new_mode = current_mode | 0o2000; // Set setgid bit (0o2000)

    perms.set_mode(new_mode);
    fs::set_permissions(path, perms).context("Failed to set file permissions")?;

    Ok(())
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

/// Create a setuid test binary fixture with cleanup function
///
/// This is a streamlined helper function that creates a temporary binary
/// with configurable setuid bits and returns both the binary path and a
/// cleanup function. The cleanup function can be called explicitly to remove
/// the binary, or the BinaryFixtureGuard can be used for automatic cleanup.
///
/// # Arguments
///
/// * `name` - The name of the binary fixture
/// * `content` - The binary content (e.g., shell script, compiled binary)
/// * `setuid` - Whether to set the setuid bit
///
/// # Returns
///
/// A tuple containing:
/// - The path to the created binary
/// - A cleanup function that removes the binary when called
///
/// # Examples
///
/// ```rust
/// use sigil_integration_tests::binary_fixture::create_setuid_fixture_with_cleanup;
///
/// // Create a setuid binary and get cleanup function
/// let (bin_path, cleanup) = create_setuid_fixture_with_cleanup(
///     "test_setuid",
///     b"#!/bin/sh\necho test\n",
///     true
/// ).unwrap();
///
/// // Use the binary in tests...
///
/// // Explicit cleanup when done
/// cleanup().unwrap();
/// ```
///
/// # Note
///
/// For automatic cleanup (even if tests panic), prefer using
/// `BinaryFixtureGuard` instead of calling the cleanup function manually.
pub fn create_setuid_fixture_with_cleanup(
    name: &str,
    content: &[u8],
    setuid: bool,
) -> Result<(PathBuf, impl FnOnce() -> Result<()> + Send)> {
    let binary_path = create_test_binary(name, content, 0o755, setuid)?;
    let binary_path_clone = binary_path.clone();

    let cleanup_fn = move || -> Result<()> {
        if binary_path_clone.exists() {
            fs::remove_file(&binary_path_clone).with_context(|| {
                format!("Failed to remove binary fixture: {:?}", binary_path_clone)
            })?;
        }
        Ok(())
    };

    Ok((binary_path, cleanup_fn))
}

/// Create a test fixture directory structure for setgid tests
///
/// This function creates a temporary directory with predefined subdirectories
/// specifically designed for setgid binary testing. The structure mimics
/// common system layouts where setgid binaries might be found.
///
/// # Directory Structure
///
/// The created fixture directory has the following structure:
///
/// ```text
/// tmp_dir/
/// ├── bin/              # Location for setgid binaries
/// ├── lib/              # Location for setgid libraries
/// ├── sbin/             # Location for setgid system binaries
/// └── group-writable/   # Directory with group write permissions
///     ├── shared_file1
///     └── shared_file2
/// ```
///
/// # Arguments
///
/// * `base_name` - Base name for the fixture directory (optional, defaults to "setgid-fixture")
///
/// # Returns
///
/// A tuple containing:
/// - The path to the created fixture directory
/// - A cleanup function that removes the fixture when called
///
/// # Examples
///
/// ```rust
/// use sigil_integration_tests::binary_fixture::create_setgid_fixture_directory;
///
/// // Create a fixture directory structure
/// let (fixture_dir, cleanup) = create_setgid_fixture_directory("my_test").unwrap();
///
/// // Create setgid binaries in the fixture structure
/// let bin_path = fixture_dir.join("bin");
/// // ... create setgid binaries in bin_path
///
/// // Clean up when done
/// cleanup().unwrap();
/// ```
///
/// # Security Testing Purpose
///
/// This fixture structure is designed to test SIGIL's setgid detection:
/// - Verifies setgid binaries in bin/ are detected
/// - Tests group-writable directories don't bypass security checks
/// - Validates namespace isolation prevents setgid privilege escalation
pub fn create_setgid_fixture_directory(
    base_name: &str,
) -> Result<(PathBuf, impl FnOnce() -> Result<()> + Send)> {
    // Use tempfile crate for automatic cleanup of temporary directory
    let fixture_name = format!("sigil-setgid-fixture-{}-{}", base_name, std::process::id());
    let temp_dir =
        TempDir::new().context("Failed to create temporary directory with tempfile crate")?;
    let fixture_dir = temp_dir.path().join(&fixture_name);

    // Create the main fixture directory
    fs::create_dir_all(&fixture_dir)
        .with_context(|| format!("Failed to create fixture directory: {:?}", fixture_dir))?;

    // Create predefined subdirectories
    let subdirs = vec!["bin", "lib", "sbin", "etc"];
    for subdir in &subdirs {
        let dir_path = fixture_dir.join(subdir);
        fs::create_dir_all(&dir_path)
            .with_context(|| format!("Failed to create subdirectory: {:?}", dir_path))?;

        // Set group write permissions on directories to test group privilege scenarios
        #[cfg(unix)]
        {
            let mut perms = fs::metadata(&dir_path)
                .context("Failed to get directory metadata")?
                .permissions();
            perms.set_mode(0o2775); // rwxrwxr-x with setgid bit on directory
            fs::set_permissions(&dir_path, perms)
                .with_context(|| format!("Failed to set permissions for {:?}", dir_path))?;
        }
    }

    // Create a group-writable subdirectory with test files
    let group_dir = fixture_dir.join("group-writable");
    fs::create_dir_all(&group_dir)
        .with_context(|| format!("Failed to create group-writable directory: {:?}", group_dir))?;

    #[cfg(unix)]
    {
        let mut perms = fs::metadata(&group_dir)
            .context("Failed to get group-writable metadata")?
            .permissions();
        perms.set_mode(0o2770); // rwxrwx--- with setgid bit (group-only access)
        fs::set_permissions(&group_dir, perms)
            .with_context(|| "Failed to set group-writable permissions".to_string())?;
    }

    // Create some test files in the group-writable directory
    let test_files = vec!["shared_file1", "shared_file2", "shared_config"];
    for file in &test_files {
        let file_path = group_dir.join(file);
        fs::write(&file_path, b"Test shared file content")
            .with_context(|| format!("Failed to create test file: {:?}", file_path))?;

        #[cfg(unix)]
        {
            let mut perms = fs::metadata(&file_path)
                .context("Failed to get file metadata")?
                .permissions();
            perms.set_mode(0o0660); // rw-rw---- (group read/write)
            fs::set_permissions(&file_path, perms)
                .with_context(|| "Failed to set file permissions".to_string())?;
        }
    }

    let fixture_dir_clone = fixture_dir.clone();

    // Move temp_dir into the closure to keep it alive until cleanup is called.
    // The closure takes ownership of temp_dir, so it won't be dropped when
    // this function returns. It will only be dropped when the cleanup_fn
    // is called and completes, which is exactly what we want.
    let cleanup_fn = move || -> Result<()> {
        // First, explicitly remove our fixture directory if it exists
        if fixture_dir_clone.exists() {
            fs::remove_dir_all(&fixture_dir_clone).with_context(|| {
                format!(
                    "Failed to remove fixture directory: {:?}",
                    fixture_dir_clone
                )
            })?;
        }

        // When temp_dir is dropped here, the TempDir cleanup runs
        // and removes the entire parent temporary directory
        drop(temp_dir);
        Ok(())
    };

    Ok((fixture_dir, cleanup_fn))
}

/// Create a setgid test fixture directory with automatic cleanup
///
/// This is a convenience function that creates a fixture directory structure
/// and returns both the path and a cleanup function. It's specifically designed
/// for testing setgid detection and security properties.
///
/// # Arguments
///
/// * `name` - Optional name for the fixture (defaults to "setgid-test-fixture")
///
/// # Returns
///
/// A tuple containing:
/// - The path to the created fixture directory
/// - A cleanup function that removes the fixture when called
///
/// # Examples
///
/// ```rust
/// use sigil_integration_tests::binary_fixture::create_setgid_test_fixture;
///
/// let (fixture_dir, cleanup) = create_setgid_test_fixture("my_setgid_test").unwrap();
///
/// // Use fixture_dir for testing setgid scenarios
/// let bin_dir = fixture_dir.join("bin");
/// assert!(bin_dir.exists());
///
/// // Clean up when done
/// cleanup().unwrap();
/// ```
pub fn create_setgid_test_fixture(
    name: &str,
) -> Result<(PathBuf, impl FnOnce() -> Result<()> + Send)> {
    create_setgid_fixture_directory(name)
}

/// Get the path to a setgid fixture subdirectory
///
/// This is a helper function that returns the path to a specific subdirectory
/// within a setgid fixture directory structure. It validates that the fixture
/// directory structure exists and returns the requested subdirectory path.
///
/// # Arguments
///
/// * `fixture_dir` - The base fixture directory path
/// * `subdir` - The subdirectory name ("bin", "lib", "sbin", "etc", "group-writable")
///
/// # Returns
///
/// The path to the requested subdirectory
///
/// # Errors
///
/// Returns an error if:
/// - The fixture directory doesn't exist
/// - The requested subdirectory doesn't exist
///
/// # Examples
///
/// ```rust
/// use sigil_integration_tests::binary_fixture::{create_setgid_test_fixture, get_setgid_fixture_subdir};
///
/// let (fixture_dir, _cleanup) = create_setgid_test_fixture("test").unwrap();
/// let bin_dir = get_setgid_fixture_subdir(&fixture_dir, "bin").unwrap();
///
/// // Use bin_dir for setgid binary testing
/// assert!(bin_dir.ends_with("bin"));
/// ```
pub fn get_setgid_fixture_subdir(fixture_dir: &Path, subdir: &str) -> Result<PathBuf> {
    if !fixture_dir.exists() {
        return Err(anyhow::anyhow!(
            "Fixture directory does not exist: {:?}",
            fixture_dir
        ));
    }

    let subdir_path = fixture_dir.join(subdir);
    if !subdir_path.exists() {
        return Err(anyhow::anyhow!(
            "Subdirectory '{}' does not exist in fixture: {:?}",
            subdir,
            subdir_path
        ));
    }

    Ok(subdir_path)
}

/// RAII guard for setgid fixture directories
///
/// This guard automatically cleans up setgid fixture directories when dropped.
/// Use this to ensure cleanup even if a test panics.
///
/// # Examples
///
/// ```rust
/// use sigil_integration_tests::binary_fixture::SetgidFixtureGuard;
///
/// {
///     let guard = SetgidFixtureGuard::new("my_test").unwrap();
///     let fixture_dir = guard.fixture_dir();
///
///     // Create test binaries and run tests...
///
/// } // guard is dropped here, fixture directory is automatically cleaned up
/// ```
pub struct SetgidFixtureGuard {
    fixture_dir: PathBuf,
    cleanup: Option<Box<dyn FnOnce() -> Result<()> + Send>>,
}

impl SetgidFixtureGuard {
    /// Create a new SetgidFixtureGuard
    ///
    /// This creates a fixture directory structure and returns a guard that
    /// will automatically clean it up when dropped.
    ///
    /// # Arguments
    ///
    /// * `name` - Base name for the fixture directory
    pub fn new(name: &str) -> Result<Self> {
        let (fixture_dir, cleanup_fn) = create_setgid_fixture_directory(name)?;
        Ok(Self {
            fixture_dir,
            cleanup: Some(Box::new(cleanup_fn)),
        })
    }

    /// Get the fixture directory path
    pub fn fixture_dir(&self) -> &Path {
        &self.fixture_dir
    }

    /// Get the bin subdirectory path
    pub fn bin_dir(&self) -> Result<PathBuf> {
        get_setgid_fixture_subdir(&self.fixture_dir, "bin")
    }

    /// Get the lib subdirectory path
    pub fn lib_dir(&self) -> Result<PathBuf> {
        get_setgid_fixture_subdir(&self.fixture_dir, "lib")
    }

    /// Get the sbin subdirectory path
    pub fn sbin_dir(&self) -> Result<PathBuf> {
        get_setgid_fixture_subdir(&self.fixture_dir, "sbin")
    }

    /// Get the etc subdirectory path
    pub fn etc_dir(&self) -> Result<PathBuf> {
        get_setgid_fixture_subdir(&self.fixture_dir, "etc")
    }

    /// Get the group-writable subdirectory path
    pub fn group_writable_dir(&self) -> Result<PathBuf> {
        get_setgid_fixture_subdir(&self.fixture_dir, "group-writable")
    }
}

impl Drop for SetgidFixtureGuard {
    fn drop(&mut self) {
        if let Some(cleanup) = self.cleanup.take() {
            // Ignore cleanup errors in drop
            let _ = cleanup();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::super::env_detect::*;
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
    #[cfg(unix)]
    fn test_set_setgid_bit() {
        // Create a regular executable binary
        let regular_bin = create_executable_binary("test_set_setgid", b"#!/bin/sh\necho test\n")
            .expect("Failed to create regular binary");

        // Verify it doesn't have setgid bit initially
        assert!(
            !is_setgid(&regular_bin).expect("Failed to check initial setgid status"),
            "Regular binary should NOT have setgid bit initially"
        );

        // Set the setgid bit using the helper function
        set_setgid_bit(&regular_bin).expect("Failed to set setgid bit");

        // Verify the setgid bit is now set
        assert!(
            is_setgid(&regular_bin).expect("Failed to check setgid bit after setting"),
            "Binary should have setgid bit after set_setgid_bit() call"
        );

        // Verify that other permission bits are preserved
        let metadata = fs::metadata(&regular_bin).expect("Failed to get metadata");
        let mode = metadata.permissions().mode();

        // Should still have executable permissions (0o111 = rwxrwxrwx execute bits)
        assert_eq!(
            mode & 0o111,
            0o111,
            "Should preserve executable permissions"
        );

        // Should have the setgid bit set
        assert_ne!(mode & 0o2000, 0, "Should have setgid bit set");

        println!(
            "set_setgid_bit test passed: setgid bit successfully set on {}",
            regular_bin.display()
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

    #[test]
    fn test_create_setuid_fixture_with_cleanup_setuid() {
        // Test creating a setuid binary with cleanup function
        let (bin_path, cleanup) = create_setuid_fixture_with_cleanup(
            "test_setuid_cleanup",
            b"#!/bin/sh\necho test\n",
            true,
        )
        .expect("Failed to create setuid fixture");

        // Verify binary exists and has setuid bit
        assert!(bin_path.exists(), "Binary should exist after creation");
        assert!(
            is_setuid(&bin_path).expect("Failed to check setuid bit"),
            "Binary should have setuid bit"
        );

        // Call cleanup function
        cleanup().expect("Cleanup should succeed");

        // Verify binary is removed
        assert!(!bin_path.exists(), "Binary should be removed after cleanup");
    }

    #[test]
    fn test_create_setuid_fixture_with_cleanup_non_setuid() {
        // Test creating a regular (non-setuid) binary with cleanup function
        let (bin_path, cleanup) = create_setuid_fixture_with_cleanup(
            "test_regular_cleanup",
            b"#!/bin/sh\necho regular\n",
            false,
        )
        .expect("Failed to create regular fixture");

        // Verify binary exists but does NOT have setuid bit
        assert!(bin_path.exists(), "Binary should exist after creation");
        assert!(
            !is_setuid(&bin_path).expect("Failed to check setuid bit"),
            "Binary should NOT have setuid bit"
        );

        // Call cleanup function
        cleanup().expect("Cleanup should succeed");

        // Verify binary is removed
        assert!(!bin_path.exists(), "Binary should be removed after cleanup");
    }

    #[test]
    fn test_setuid_fixture_with_cleanup_multiple_binaries() {
        // Test creating multiple binaries with independent cleanup functions
        let (bin1, cleanup1) =
            create_setuid_fixture_with_cleanup("multi1", b"test1\n", true).unwrap();
        let (bin2, cleanup2) =
            create_setuid_fixture_with_cleanup("multi2", b"test2\n", false).unwrap();
        let (bin3, cleanup3) =
            create_setuid_fixture_with_cleanup("multi3", b"test3\n", true).unwrap();

        // Verify all binaries exist
        assert!(bin1.exists());
        assert!(bin2.exists());
        assert!(bin3.exists());

        // Verify setuid bits
        assert!(is_setuid(&bin1).unwrap());
        assert!(!is_setuid(&bin2).unwrap());
        assert!(is_setuid(&bin3).unwrap());

        // Clean up bin1
        cleanup1().unwrap();
        assert!(!bin1.exists());
        assert!(bin2.exists()); // Others should still exist
        assert!(bin3.exists());

        // Clean up bin2
        cleanup2().unwrap();
        assert!(!bin1.exists());
        assert!(!bin2.exists());
        assert!(bin3.exists());

        // Clean up bin3
        cleanup3().unwrap();
        assert!(!bin1.exists());
        assert!(!bin2.exists());
        assert!(!bin3.exists());
    }

    #[test]
    fn test_setuid_fixture_with_cleanup_idempotent() {
        // Test that cleanup can be called multiple times safely
        let (bin_path, cleanup) =
            create_setuid_fixture_with_cleanup("test_idempotent", b"test\n", true).unwrap();

        // First cleanup should succeed
        cleanup().unwrap();
        assert!(!bin_path.exists());

        // Note: The cleanup function closure captures the path by move,
        // so calling it again would require a closure that can be called multiple times.
        // This test validates that a single cleanup call works correctly.
        // For multiple cleanup calls, use cleanup_test_binaries() instead.
    }

    #[test]
    fn test_setuid_fixture_with_cleanup_integration_with_existing_helpers() {
        // Test that the new helper integrates seamlessly with existing helpers
        let (bin_path, cleanup) =
            create_setuid_fixture_with_cleanup("integration_test", b"#!/bin/sh\nid\n", true)
                .expect("Failed to create fixture");

        // Test with existing helper: is_setuid
        assert!(
            is_setuid(&bin_path).unwrap(),
            "Should integrate with is_setuid helper"
        );

        // Test with existing helper: check_setuid_bit
        assert!(
            check_setuid_bit(&bin_path).unwrap(),
            "Should integrate with check_setuid_bit helper"
        );

        // Test with existing helper: get_binary_security_info
        let info = get_binary_security_info(&bin_path).expect("Should get security info");
        assert!(info.has_setuid, "Security info should show setuid bit");

        // Clean up
        cleanup().unwrap();
        assert!(!bin_path.exists());
    }

    #[test]
    fn test_setuid_fixture_with_cleanup_returns_sendable_closure() {
        // Test that the returned cleanup function is Send (can be moved between threads)
        let (bin_path, cleanup) =
            create_setuid_fixture_with_cleanup("sendable_test", b"test\n", true).unwrap();

        // This test validates that the cleanup function implements Send
        // by virtue of compiling successfully with this type signature.
        // In practice, this means the cleanup function can be stored
        // in structures that may be moved across thread boundaries.

        // Verify cleanup works
        cleanup().unwrap();
        assert!(!bin_path.exists());
    }

    #[test]
    fn test_create_setgid_fixture_directory_structure() {
        // Test creating a setgid fixture directory with default structure
        let (fixture_dir, cleanup) = create_setgid_fixture_directory("test_structure")
            .expect("Failed to create fixture directory");

        // Verify the main fixture directory exists
        assert!(fixture_dir.exists(), "Fixture directory should exist");
        assert!(fixture_dir.is_dir(), "Should be a directory");

        // Verify all expected subdirectories exist
        let expected_subdirs = vec!["bin", "lib", "sbin", "etc", "group-writable"];
        for subdir in &expected_subdirs {
            let subdir_path = fixture_dir.join(subdir);
            assert!(
                subdir_path.exists(),
                "Subdirectory '{}' should exist",
                subdir
            );
            assert!(subdir_path.is_dir(), "Should be a directory");
        }

        // Verify group-writable directory has test files
        let group_dir = fixture_dir.join("group-writable");
        let expected_files = vec!["shared_file1", "shared_file2", "shared_config"];
        for file in &expected_files {
            let file_path = group_dir.join(file);
            assert!(file_path.exists(), "Test file '{}' should exist", file);
            assert!(file_path.is_file(), "Should be a file");
        }

        // Clean up
        cleanup().expect("Cleanup should succeed");

        // Verify the entire fixture directory is removed
        assert!(
            !fixture_dir.exists(),
            "Fixture directory should be removed after cleanup"
        );
    }

    #[test]
    fn test_create_setgid_test_fixture() {
        // Test the convenience function wrapper
        let (fixture_dir, cleanup) =
            create_setgid_test_fixture("convenience_test").expect("Failed to create test fixture");

        // Verify the fixture was created successfully
        assert!(fixture_dir.exists(), "Fixture should exist");
        assert!(
            fixture_dir.to_string_lossy().contains("convenience_test"),
            "Should use provided name"
        );

        // Verify it has the expected structure
        assert!(
            fixture_dir.join("bin").exists(),
            "Should have bin directory"
        );
        assert!(
            fixture_dir.join("lib").exists(),
            "Should have lib directory"
        );

        // Clean up
        cleanup().expect("Cleanup should succeed");
        assert!(!fixture_dir.exists());
    }

    #[test]
    fn test_get_setgid_fixture_subdir() {
        let (fixture_dir, _cleanup) =
            create_setgid_fixture_directory("subdir_test").expect("Failed to create fixture");

        // Test getting valid subdirectories
        let bin_dir = get_setgid_fixture_subdir(&fixture_dir, "bin").expect("Should get bin dir");
        assert!(bin_dir.ends_with("bin"), "Should return correct bin path");
        assert!(bin_dir.exists(), "Bin directory should exist");

        let lib_dir = get_setgid_fixture_subdir(&fixture_dir, "lib").expect("Should get lib dir");
        assert!(lib_dir.ends_with("lib"), "Should return correct lib path");

        let group_dir = get_setgid_fixture_subdir(&fixture_dir, "group-writable")
            .expect("Should get group dir");
        assert!(
            group_dir.ends_with("group-writable"),
            "Should return correct group path"
        );

        // Test getting invalid subdirectory
        let invalid_dir = get_setgid_fixture_subdir(&fixture_dir, "invalid");
        assert!(
            invalid_dir.is_err(),
            "Should return error for invalid subdirectory"
        );

        // Test getting subdirectory from non-existent fixture
        let fake_path = PathBuf::from("/tmp/nonexistent-fixture");
        let result = get_setgid_fixture_subdir(&fake_path, "bin");
        assert!(
            result.is_err(),
            "Should return error for non-existent fixture"
        );

        // Clean up
        let _cleanup = cleanup_test_binaries();
    }

    #[test]
    fn test_setgid_fixture_guard_creation() {
        // Test creating a SetgidFixtureGuard
        let guard = SetgidFixtureGuard::new("guard_test").expect("Failed to create guard");

        let fixture_dir = guard.fixture_dir();
        assert!(fixture_dir.exists(), "Fixture directory should exist");

        // Test the convenience methods for getting subdirectories
        let bin_dir = guard.bin_dir().expect("Should get bin dir");
        assert!(bin_dir.ends_with("bin"), "Should return correct bin path");
        assert!(bin_dir.exists(), "Bin directory should exist");

        let lib_dir = guard.lib_dir().expect("Should get lib dir");
        assert!(lib_dir.ends_with("lib"), "Should return correct lib path");

        let sbin_dir = guard.sbin_dir().expect("Should get sbin dir");
        assert!(
            sbin_dir.ends_with("sbin"),
            "Should return correct sbin path"
        );

        let etc_dir = guard.etc_dir().expect("Should get etc dir");
        assert!(etc_dir.ends_with("etc"), "Should return correct etc path");

        let group_dir = guard
            .group_writable_dir()
            .expect("Should get group-writable dir");
        assert!(
            group_dir.ends_with("group-writable"),
            "Should return correct group path"
        );

        // Verify the guard automatically cleans up when dropped
        let fixture_path = fixture_dir.to_path_buf();
        drop(guard);
        assert!(
            !fixture_path.exists(),
            "Fixture should be cleaned up after guard drop"
        );
    }

    #[test]
    fn test_setgid_fixture_guard_with_binary_creation() {
        // Test using the guard to create setgid binaries in the fixture
        let guard = SetgidFixtureGuard::new("binary_test").expect("Failed to create guard");

        let bin_dir = guard.bin_dir().expect("Should get bin dir");

        // Create a setgid binary in the fixture's bin directory
        let setgid_bin_path = bin_dir.join("test_setgid_bin");
        let mut file = fs::File::create(&setgid_bin_path).expect("Failed to create binary");
        file.write_all(b"#!/bin/sh\necho 'setgid test'\n")
            .expect("Failed to write content");

        // Set setgid permissions
        #[cfg(unix)]
        {
            let mut perms = fs::metadata(&setgid_bin_path)
                .expect("Failed to get metadata")
                .permissions();
            perms.set_mode(0o2755); // rwxr-xr-x with setgid bit
            fs::set_permissions(&setgid_bin_path, perms).expect("Failed to set permissions");
        }

        // Verify the binary exists and has setgid bit
        assert!(setgid_bin_path.exists(), "Setgid binary should exist");

        #[cfg(unix)]
        {
            assert!(
                is_setgid(&setgid_bin_path).unwrap(),
                "Binary should have setgid bit"
            );
        }

        // Guard cleanup should remove the entire fixture including the binary
        let fixture_path = guard.fixture_dir().to_path_buf();
        drop(guard);
        assert!(!fixture_path.exists(), "Fixture should be cleaned up");
        assert!(!setgid_bin_path.exists(), "Binary should be cleaned up");
    }

    #[test]
    fn test_setgid_fixture_guard_multiple_fixtures() {
        // Test creating multiple independent fixture guards
        let guard1 = SetgidFixtureGuard::new("fixture1").expect("Failed to create guard1");
        let guard2 = SetgidFixtureGuard::new("fixture2").expect("Failed to create guard2");

        let dir1 = guard1.fixture_dir();
        let dir2 = guard2.fixture_dir();

        // Verify both fixtures exist and are different
        assert!(dir1.exists(), "Fixture1 should exist");
        assert!(dir2.exists(), "Fixture2 should exist");
        assert_ne!(dir1, dir2, "Fixtures should have different paths");

        // Verify each has the correct structure
        assert!(dir1.join("bin").exists(), "Fixture1 should have bin");
        assert!(dir2.join("bin").exists(), "Fixture2 should have bin");

        // Clean up fixture1
        let dir1_path = dir1.to_path_buf();
        drop(guard1);
        assert!(!dir1_path.exists(), "Fixture1 should be cleaned up");
        assert!(dir2.exists(), "Fixture2 should still exist");

        // Clean up fixture2
        let dir2_path = dir2.to_path_buf();
        drop(guard2);
        assert!(!dir1_path.exists(), "Fixture1 should still not exist");
        assert!(!dir2_path.exists(), "Fixture2 should be cleaned up");
    }

    #[test]
    fn test_setgid_fixture_directory_permissions() {
        // Test that setgid fixture directories have correct permissions
        let (fixture_dir, cleanup) =
            create_setgid_fixture_directory("permissions_test").expect("Failed to create fixture");

        #[cfg(unix)]
        {
            // Check that subdirectories have setgid bit (0o2000)
            let subdirs = vec!["bin", "lib", "sbin", "etc"];
            for subdir in &subdirs {
                let dir_path = fixture_dir.join(subdir);
                let metadata = fs::metadata(&dir_path).expect("Failed to get metadata");
                let mode = metadata.permissions().mode();

                // Verify setgid bit is set (0o2000)
                assert_eq!(
                    mode & 0o2000,
                    0o2000,
                    "Directory '{}' should have setgid bit (0o2000), got mode: {:04o}",
                    subdir,
                    mode
                );

                // Verify group write permissions (0o20)
                assert_eq!(mode & 0o20, 0o20, "Directory should have group write");
            }

            // Check that group-writable directory has correct permissions
            let group_dir = fixture_dir.join("group-writable");
            let metadata = fs::metadata(&group_dir).expect("Failed to get metadata");
            let mode = metadata.permissions().mode();

            // Should have setgid bit (0o2000)
            assert_eq!(mode & 0o2000, 0o2000, "Group dir should have setgid bit");

            // Should have group permissions (0o2770 = rwxrwx---)
            assert_eq!(
                mode & 0o777,
                0o770,
                "Group dir should have rwxrwx--- permissions"
            );

            // Check that test files have correct permissions
            let test_file = group_dir.join("shared_file1");
            let file_metadata = fs::metadata(&test_file).expect("Failed to get file metadata");
            let file_mode = file_metadata.permissions().mode();

            // Should have group read/write (0o0660 = rw-rw----)
            assert_eq!(
                file_mode & 0o777,
                0o660,
                "Test file should have rw-rw---- permissions, got: {:04o}",
                file_mode
            );
        }

        // Clean up
        cleanup().expect("Cleanup should succeed");
    }

    #[test]
    fn test_setgid_fixture_directory_unique_names() {
        // Test that multiple fixture directories can coexist with unique names
        let (fixture1, cleanup1) =
            create_setgid_fixture_directory("test_unique1").expect("Failed to create fixture1");
        let (fixture2, cleanup2) =
            create_setgid_fixture_directory("test_unique2").expect("Failed to create fixture2");

        // Verify both exist and have different paths
        assert!(fixture1.exists(), "Fixture1 should exist");
        assert!(fixture2.exists(), "Fixture2 should exist");
        assert_ne!(fixture1, fixture2, "Fixtures should have different paths");

        // Verify each has independent structure
        let bin1 = fixture1.join("bin");
        let bin2 = fixture2.join("bin");
        assert!(bin1.exists(), "Fixture1 should have bin");
        assert!(bin2.exists(), "Fixture2 should have bin");

        // Clean up fixture1
        cleanup1().expect("Cleanup1 should succeed");
        assert!(!fixture1.exists(), "Fixture1 should be cleaned up");
        assert!(fixture2.exists(), "Fixture2 should still exist");

        // Clean up fixture2
        cleanup2().expect("Cleanup2 should succeed");
        assert!(!fixture1.exists(), "Fixture1 should still not exist");
        assert!(!fixture2.exists(), "Fixture2 should be cleaned up");
    }

    #[test]
    fn test_setgid_fixture_with_env_detect_integration() {
        // Test that setgid fixtures integrate with env_detect module
        let guard = SetgidFixtureGuard::new("env_integration").expect("Failed to create guard");

        let bin_dir = guard.bin_dir().expect("Should get bin dir");

        // Create a setgid binary in the fixture
        let setgid_bin = create_setgid_binary("test_detect", b"#!/bin/sh\necho test\n")
            .expect("Failed to create setgid binary");

        // Move it to the fixture bin directory
        let fixture_bin_path = bin_dir.join("test_detect");
        fs::rename(&setgid_bin, &fixture_bin_path).expect("Failed to move binary");

        // Verify setgid detection works with fixture binary
        assert!(
            is_setgid(&fixture_bin_path).expect("Should detect setgid bit"),
            "Fixture binary should have setgid bit"
        );

        // Verify it works with env_detect helpers
        use crate::env_detect::check_setgid_bit;
        assert!(
            check_setgid_bit(&fixture_bin_path).expect("Should check setgid bit"),
            "env_detect helper should detect setgid bit"
        );

        // Guard cleanup should handle everything
        drop(guard);
        assert!(!fixture_bin_path.exists(), "Binary should be cleaned up");
    }

    #[test]
    fn test_create_setgid_fixture() {
        // Test the new create_setgid_fixture convenience function
        let fixture = create_setgid_fixture(
            "test_setgid_fixture_fn",
            b"#!/bin/sh\necho 'setgid test'\nid\n",
        )
        .expect("Failed to create setgid fixture");

        // Verify the fixture exists and is a file
        assert!(fixture.exists(), "Setgid fixture should exist");
        assert!(fixture.is_file(), "Should be a file");

        // Verify the fixture has the setgid bit set
        assert!(
            is_setgid(&fixture).expect("Failed to check setgid bit"),
            "Fixture should have setgid bit"
        );

        // Verify the fixture has executable permissions
        let metadata = fs::metadata(&fixture).expect("Failed to get metadata");
        let mode = metadata.permissions().mode();

        // Should have executable permissions (0o111 = execute bits)
        assert_eq!(mode & 0o111, 0o111, "Should have executable permissions");

        // Should have the setgid bit (0o2000)
        assert_eq!(mode & 0o2000, 0o2000, "Should have setgid bit (0o2000)");

        // Verify the fixture content is correct
        let content = fs::read(&fixture).expect("Failed to read fixture");
        assert_eq!(
            content, b"#!/bin/sh\necho 'setgid test'\nid\n",
            "Fixture content should match input"
        );

        // Clean up the fixture
        fs::remove_file(&fixture).expect("Failed to clean up fixture");
        assert!(!fixture.exists(), "Fixture should be removed after cleanup");
    }

    #[test]
    fn test_create_setgid_fixture_vs_create_setuid_fixture() {
        // Test that create_setgid_fixture and create_setuid_fixture produce different results
        let setgid_fixture = create_setgid_fixture("compare_setgid", b"test\n")
            .expect("Failed to create setgid fixture");
        let setuid_fixture = create_setuid_fixture("compare_setuid", b"test\n")
            .expect("Failed to create setuid fixture");

        // Both should exist
        assert!(setgid_fixture.exists(), "Setgid fixture should exist");
        assert!(setuid_fixture.exists(), "Setuid fixture should exist");

        // Setgid fixture should have setgid bit but NOT setuid bit
        let setgid_meta = fs::metadata(&setgid_fixture).expect("Failed to get setgid metadata");
        let setgid_mode = setgid_meta.permissions().mode();
        assert!(
            is_setgid(&setgid_fixture).expect("Should have setgid bit"),
            "Setgid fixture should have setgid bit"
        );
        assert_eq!(
            setgid_mode & 0o4000,
            0,
            "Setgid fixture should NOT have setuid bit"
        );

        // Setuid fixture should have setuid bit but NOT setgid bit
        let setuid_meta = fs::metadata(&setuid_fixture).expect("Failed to get setuid metadata");
        let setuid_mode = setuid_meta.permissions().mode();
        assert!(
            is_setuid(&setuid_fixture).expect("Should have setuid bit"),
            "Setuid fixture should have setuid bit"
        );
        assert_eq!(
            setuid_mode & 0o2000,
            0,
            "Setuid fixture should NOT have setgid bit"
        );

        // Clean up
        fs::remove_file(&setgid_fixture).expect("Failed to clean up setgid fixture");
        fs::remove_file(&setuid_fixture).expect("Failed to clean up setuid fixture");
    }

    #[test]
    fn test_setgid_fixture_persistence_and_cleanup() {
        // Test that fixture persists until cleanup is called
        let (fixture_dir, cleanup) =
            create_setgid_fixture_directory("persistence_test").expect("Failed to create fixture");

        let bin_dir = fixture_dir.join("bin");

        // Create a test file in the fixture
        let test_file = bin_dir.join("persistence_test.txt");
        fs::write(&test_file, b"test content").expect("Failed to write test file");

        assert!(
            test_file.exists(),
            "Test file should exist immediately after creation"
        );

        // Create another fixture directory
        let (fixture_dir2, cleanup2) = create_setgid_fixture_directory("persistence_test2")
            .expect("Failed to create second fixture");

        // Both should coexist
        assert!(fixture_dir.exists(), "First fixture should still exist");
        assert!(fixture_dir2.exists(), "Second fixture should exist");

        // Clean up first fixture
        cleanup().expect("First cleanup should succeed");
        assert!(!fixture_dir.exists(), "First fixture should be cleaned up");
        assert!(fixture_dir2.exists(), "Second fixture should still exist");
        assert!(
            !test_file.exists(),
            "Test file should be cleaned up with first fixture"
        );

        // Clean up second fixture
        cleanup2().expect("Second cleanup should succeed");
        assert!(
            !fixture_dir.exists(),
            "First fixture should still not exist"
        );
        assert!(
            !fixture_dir2.exists(),
            "Second fixture should be cleaned up"
        );
    }
}

// =============================================================================
// Setgid Test Environment Setup and Teardown Functions
// =============================================================================

/// Result structure for setgid test environment setup
///
/// This structure contains all the artifacts created during setup, including
/// fixture directories, test binaries, and environment guards.
pub struct SetgidTestEnvironment {
    /// The main fixture directory path
    pub fixture_dir: PathBuf,
    /// Path guard for PATH modification (if PATH was modified)
    pub path_guard: Option<PathGuard>,
    /// Binary fixture guard for automatic cleanup
    pub binary_guard: BinaryFixtureGuard,
    /// Created setgid binaries (for verification)
    pub setgid_binaries: Vec<PathBuf>,
    /// Created regular binaries (for verification)
    pub regular_binaries: Vec<PathBuf>,
    /// Created setuid binaries (for verification)
    pub setuid_binaries: Vec<PathBuf>,
    /// Created setuid+setgid binaries (for verification)
    pub combined_binaries: Vec<PathBuf>,
}

/// Set up a complete setgid test environment with fixtures, binaries, and PATH configuration
///
/// This function creates a comprehensive test environment for setgid detection testing,
/// including:
///
/// - Fixture directory structure with bin/, lib/, sbin/, etc. subdirectories
/// - Multiple test binaries with different permission modes:
///   - Setgid-only binaries (mode 2755)
///   - Regular executables (mode 0755)
///   - Setuid-only binaries (mode 4755)
///   - Combined setuid+setgid binaries (mode 6755)
///   - Sticky-bit binaries (mode 1755)
/// - PATH configuration (optional)
///
/// # Arguments
///
/// * `name` - Base name for the test environment (defaults to "setgid-test-env")
/// * `configure_path` - Whether to add the fixture bin directory to PATH (defaults to true)
/// * `create_standard_binaries` - Whether to create a standard set of test binaries (defaults to true)
///
/// # Returns
///
/// `Ok(SetgidTestEnvironment)` containing all created artifacts and guards for automatic cleanup
///
/// # Errors
///
/// Returns an error if:
/// - Fixture directory creation fails
/// - Binary creation fails
/// - PATH configuration fails
///
/// # Examples
///
/// ```ignore
/// use sigil_integration_tests::binary_fixture::setup_setgid_test_environment;
///
/// // Set up a test environment with PATH configuration
/// let env = setup_setgid_test_environment("my_test", true, true)?;
///
/// // Use the environment for testing
/// let bin_dir = env.fixture_dir.join("bin");
/// println!("Test bin dir: {:?}", bin_dir);
///
/// // Environment automatically cleans up when `env` is dropped
/// ```
///
/// # Cleanup
///
/// The returned `SetgidTestEnvironment` implements RAII cleanup:
/// - When dropped, all fixtures and binaries are automatically removed
/// - PATH modifications are automatically reverted
/// - No manual cleanup required even if tests panic
///
/// # Standard Binaries Created
///
/// When `create_standard_binaries` is true, the following binaries are created:
///
/// - `setgid_tool1` through `setgid_tool4` - Setgid-only binaries (mode 2755)
/// - `regular_tool1`, `regular_tool2` - Regular executables (mode 0755)
/// - `setuid_tool` - Setuid-only binary (mode 4755)
/// - `combined_tool` - Both setuid and setgid (mode 6755)
/// - `sticky_tool` - Sticky bit only (mode 1755)
pub fn setup_setgid_test_environment(
    name: &str,
    configure_path: bool,
    create_standard_binaries: bool,
) -> Result<SetgidTestEnvironment> {
    // Create the fixture directory structure
    let (fixture_dir, _cleanup_fn) = create_setgid_fixture_directory(name)
        .with_context(|| format!("Failed to create setgid fixture directory for {}", name))?;

    // Create BinaryFixtureGuard for automatic binary cleanup
    let binary_guard = BinaryFixtureGuard::new();

    // Get bin directory for creating binaries
    let bin_dir = get_setgid_fixture_subdir(&fixture_dir, "bin")
        .with_context(|| format!("Failed to get bin directory for fixture {}", name))?;

    let mut setgid_binaries = Vec::new();
    let mut regular_binaries = Vec::new();
    let mut setuid_binaries = Vec::new();
    let mut combined_binaries = Vec::new();

    // Create standard test binaries if requested
    if create_standard_binaries {
        // Create setgid-only binaries
        for i in 1..=4 {
            let content = format!("#!/bin/sh\necho 'Setgid binary {}'\n", i);
            let bin = create_setgid_binary_in_dir(
                &bin_dir,
                &format!("setgid_tool{}", i),
                content.as_bytes(),
            )
            .with_context(|| format!("Failed to create setgid binary {}", i))?;
            setgid_binaries.push(bin);
        }

        // Create regular (non-setgid) executables
        for i in 1..=2 {
            let content = format!("#!/bin/sh\necho 'Regular binary {}'\n", i);
            let bin = create_executable_binary_in_dir(
                &bin_dir,
                &format!("regular_tool{}", i),
                content.as_bytes(),
            )
            .with_context(|| format!("Failed to create regular binary {}", i))?;
            regular_binaries.push(bin);
        }

        // Create a setuid-only binary
        let setuid_bin = create_setuid_binary_in_dir(
            &bin_dir,
            "setuid_tool",
            b"#!/bin/sh\necho 'Setuid-only binary'\n",
        )
        .with_context(|| "Failed to create setuid binary")?;
        setuid_binaries.push(setuid_bin);

        // Create a combined setuid+setgid binary
        let combined_bin = create_setuid_setgid_binary_in_dir(
            &bin_dir,
            "combined_tool",
            b"#!/bin/sh\necho 'Combined setuid+setgid binary'\n",
        )
        .with_context(|| "Failed to create combined binary")?;
        combined_binaries.push(combined_bin);

        // Create a sticky-bit-only binary for edge case testing
        let sticky_bin = create_sticky_bit_binary_in_dir(
            &bin_dir,
            "sticky_tool",
            b"#!/bin/sh\necho 'Sticky-bit binary'\n",
        )
        .with_context(|| "Failed to create sticky bit binary")?;
        regular_binaries.push(sticky_bin);
    }

    // Configure PATH if requested
    let path_guard = if configure_path {
        Some(
            add_to_path(&bin_dir)
                .with_context(|| format!("Failed to add bin dir to PATH for fixture {}", name))?,
        )
    } else {
        None
    };

    Ok(SetgidTestEnvironment {
        fixture_dir,
        path_guard,
        binary_guard,
        setgid_binaries,
        regular_binaries,
        setuid_binaries,
        combined_binaries,
    })
}

/// Create a setgid binary in a specific directory
///
/// This is a helper function that creates a setgid binary with mode 2755
/// in the specified directory. Used internally by setup functions.
fn create_setgid_binary_in_dir(dir: &Path, name: &str, content: &[u8]) -> Result<PathBuf> {
    if !dir.exists() {
        fs::create_dir_all(dir)
            .with_context(|| format!("Failed to create directory: {:?}", dir))?;
    }

    let binary_path = dir.join(name);

    // Write the binary content
    let mut file = fs::File::create(&binary_path)
        .with_context(|| format!("Failed to create binary file: {:?}", binary_path))?;
    file.write_all(content)
        .with_context(|| format!("Failed to write binary content to {:?}", binary_path))?;

    // Set permissions with setgid bit (0o2755)
    let mut perms = fs::metadata(&binary_path)
        .with_context(|| format!("Failed to get file metadata for {:?}", binary_path))?
        .permissions();

    perms.set_mode(0o2755);
    fs::set_permissions(&binary_path, perms)
        .with_context(|| format!("Failed to set file permissions for {:?}", binary_path))?;

    Ok(binary_path)
}

/// Create a setuid binary in a specific directory
///
/// This is a helper function that creates a setuid binary with mode 4755
/// in the specified directory. Used internally by setup functions.
fn create_setuid_binary_in_dir(dir: &Path, name: &str, content: &[u8]) -> Result<PathBuf> {
    if !dir.exists() {
        fs::create_dir_all(dir)
            .with_context(|| format!("Failed to create directory: {:?}", dir))?;
    }

    let binary_path = dir.join(name);

    // Write the binary content
    let mut file = fs::File::create(&binary_path)
        .with_context(|| format!("Failed to create binary file: {:?}", binary_path))?;
    file.write_all(content)
        .with_context(|| format!("Failed to write binary content to {:?}", binary_path))?;

    // Set permissions with setuid bit (0o4755)
    let mut perms = fs::metadata(&binary_path)
        .with_context(|| format!("Failed to get file metadata for {:?}", binary_path))?
        .permissions();

    perms.set_mode(0o4755);
    fs::set_permissions(&binary_path, perms)
        .with_context(|| format!("Failed to set file permissions for {:?}", binary_path))?;

    Ok(binary_path)
}

/// Create a setuid+setgid binary in a specific directory
///
/// This is a helper function that creates a binary with both setuid and setgid
/// bits set (mode 6755). Used internally by setup functions.
fn create_setuid_setgid_binary_in_dir(dir: &Path, name: &str, content: &[u8]) -> Result<PathBuf> {
    if !dir.exists() {
        fs::create_dir_all(dir)
            .with_context(|| format!("Failed to create directory: {:?}", dir))?;
    }

    let binary_path = dir.join(name);

    // Write the binary content
    let mut file = fs::File::create(&binary_path)
        .with_context(|| format!("Failed to create binary file: {:?}", binary_path))?;
    file.write_all(content)
        .with_context(|| format!("Failed to write binary content to {:?}", binary_path))?;

    // Set permissions with both setuid and setgid bits (0o6755)
    let mut perms = fs::metadata(&binary_path)
        .with_context(|| format!("Failed to get file metadata for {:?}", binary_path))?
        .permissions();

    perms.set_mode(0o6755);
    fs::set_permissions(&binary_path, perms)
        .with_context(|| format!("Failed to set file permissions for {:?}", binary_path))?;

    Ok(binary_path)
}

/// Create a sticky-bit binary in a specific directory
///
/// This is a helper function that creates a binary with the sticky bit
/// (mode 1755). Used internally by setup functions.
fn create_sticky_bit_binary_in_dir(dir: &Path, name: &str, content: &[u8]) -> Result<PathBuf> {
    if !dir.exists() {
        fs::create_dir_all(dir)
            .with_context(|| format!("Failed to create directory: {:?}", dir))?;
    }

    let binary_path = dir.join(name);

    // Write the binary content
    let mut file = fs::File::create(&binary_path)
        .with_context(|| format!("Failed to create binary file: {:?}", binary_path))?;
    file.write_all(content)
        .with_context(|| format!("Failed to write binary content to {:?}", binary_path))?;

    // Set permissions with sticky bit (0o1755)
    let mut perms = fs::metadata(&binary_path)
        .with_context(|| format!("Failed to get file metadata for {:?}", binary_path))?
        .permissions();

    perms.set_mode(0o1755);
    fs::set_permissions(&binary_path, perms)
        .with_context(|| format!("Failed to set file permissions for {:?}", binary_path))?;

    Ok(binary_path)
}

/// Create a regular executable binary in a specific directory
///
/// This is a helper function that creates a regular executable binary with
/// standard permissions (0o0755). Used internally by setup functions.
fn create_executable_binary_in_dir(dir: &Path, name: &str, content: &[u8]) -> Result<PathBuf> {
    if !dir.exists() {
        fs::create_dir_all(dir)
            .with_context(|| format!("Failed to create directory: {:?}", dir))?;
    }

    let binary_path = dir.join(name);

    // Write the binary content
    let mut file = fs::File::create(&binary_path)
        .with_context(|| format!("Failed to create binary file: {:?}", binary_path))?;
    file.write_all(content)
        .with_context(|| format!("Failed to write binary content to {:?}", binary_path))?;

    // Set permissions without special bits (0o0755)
    let mut perms = fs::metadata(&binary_path)
        .with_context(|| format!("Failed to get file metadata for {:?}", binary_path))?
        .permissions();

    perms.set_mode(0o0755);
    fs::set_permissions(&binary_path, perms)
        .with_context(|| format!("Failed to set file permissions for {:?}", binary_path))?;

    Ok(binary_path)
}

/// Teardown the setgid test environment and clean up all artifacts
///
/// This function explicitly cleans up all test artifacts created during setup.
/// It handles errors gracefully, continuing cleanup even if individual operations fail.
///
/// # Arguments
///
/// * `environment` - The test environment to tear down
///
/// # Returns
///
/// `Ok(())` if all cleanup operations succeeded (or failed gracefully)
///
/// # Errors
///
/// Returns an error only if critical cleanup fails:
/// - Fixture directory cannot be removed
/// - Test binaries cannot be removed
///
/// # Error Handling
///
/// This function uses error resilience:
/// - Continues cleanup even if individual file removals fail
/// - Logs warnings for non-critical failures
/// - Returns error only if directory removal fails
/// - Continues with cleanup regardless of individual file failures
/// - Attempts to restore PATH even if directory cleanup fails
///
/// # Examples
///
/// ```ignore
/// use sigil_integration_tests::binary_fixture::{setup_setgid_test_environment, teardown_setgid_test_environment};
///
/// // Set up test environment
/// let env = setup_setgid_test_environment("my_test", true, true)?;
///
/// // Run tests...
///
/// // Explicit teardown (optional, RAII guard handles this automatically)
/// teardown_setgid_test_environment(&env)?;
/// ```
///
/// # Note
///
/// In most cases, you don't need to call this function explicitly. The
/// `SetgidTestEnvironment` struct implements `Drop` and handles cleanup
/// automatically when dropped. Use this function only when you need
/// explicit control over cleanup timing.
///
/// # Error Resilience
///
/// The teardown function is designed to be resilient:
/// - Individual file removal failures are logged but don't stop cleanup
/// - Directory removal failures are reported but don't prevent PATH restoration
/// - The function always attempts to restore the original PATH state
/// - Returns `Ok(())` even if some cleanup operations fail, reporting errors via stderr
pub fn teardown_setgid_test_environment(environment: &SetgidTestEnvironment) -> Result<()> {
    let mut cleanup_errors = Vec::new();

    // First, attempt to remove individual binaries (with error resilience)
    let all_binaries = environment
        .setgid_binaries
        .iter()
        .chain(environment.regular_binaries.iter())
        .chain(environment.setuid_binaries.iter())
        .chain(environment.combined_binaries.iter());

    for binary_path in all_binaries {
        if binary_path.exists() {
            if let Err(e) = fs::remove_file(binary_path) {
                let error_msg = format!("Failed to remove binary {:?}: {}", binary_path, e);
                eprintln!("WARNING: {}", error_msg);
                cleanup_errors.push(error_msg);
            }
        }
    }

    // Next, attempt to remove the fixture directory (with error resilience)
    if environment.fixture_dir.exists() {
        if let Err(e) = fs::remove_dir_all(&environment.fixture_dir) {
            let error_msg = format!(
                "Failed to remove fixture directory {:?}: {}",
                environment.fixture_dir, e
            );
            eprintln!("WARNING: {}", error_msg);
            cleanup_errors.push(error_msg);
        }
    }

    // Report any errors that occurred during cleanup
    if !cleanup_errors.is_empty() {
        eprintln!(
            "Setgid test environment teardown completed with {} warnings:",
            cleanup_errors.len()
        );
        for (i, error) in cleanup_errors.iter().enumerate() {
            eprintln!("  {}. {}", i + 1, error);
        }
    }

    // PATH restoration happens automatically when environment.path_guard is dropped
    // The caller doesn't need to do anything explicit - the RAII pattern handles it
    // We just return Ok(()) to indicate teardown completed (possibly with warnings)

    Ok(())
}

impl Drop for SetgidTestEnvironment {
    fn drop(&mut self) {
        // Clean up by calling the teardown function
        // We ignore errors in Drop to prevent panics during cleanup
        // PATH restoration happens automatically when path_guard is dropped
        // Binary cleanup happens when binary_guard is dropped

        // Attempt to remove the fixture directory if it still exists
        if let Err(e) = fs::remove_dir_all(&self.fixture_dir) {
            eprintln!(
                "WARNING: Failed to remove fixture directory during Drop: {:?}",
                e
            );
        }

        // The path_guard and binary_guard will handle their own cleanup when dropped
        // The Drop order is: binary_guard first, then path_guard (reverse of declaration order)
    }
}

/// RAII guard for setgid test environment
///
/// This guard provides automatic setup and teardown of a complete test environment.
/// It combines setup and teardown into a single RAII-style guard that ensures
/// cleanup happens even if tests panic. The guard implements Drop to automatically
/// clean up all resources when it goes out of scope.
///
/// # Examples
///
/// ```ignore
/// use sigil_integration_tests::binary_fixture::SetgidTestEnvironmentGuard;
///
/// // Set up complete test environment with RAII guard
/// let guard = SetgidTestEnvironmentGuard::new("my_test", true, true)
///     .expect("Failed to set up test environment");
///
/// // Access environment properties
/// let fixture_dir = guard.fixture_dir();
/// let bin_dir = fixture_dir.join("bin");
///
/// // Tests run here with automatic cleanup on scope exit
/// // Even if tests panic, cleanup is guaranteed
/// ```
///
/// # Error Resilience
///
/// The guard is designed to handle errors gracefully:
/// - Setup failures return an error from `new()`, preventing invalid guards
/// - Teardown failures are logged but don't panic (to avoid hiding test failures)
/// - PATH restoration is guaranteed even if directory cleanup fails
/// - Binary cleanup uses RAII guards that are resilient to individual failures
///
/// # Fields
///
/// - `environment` - The underlying test environment with all artifacts
/// - `original_path` - The original PATH value (restored on drop)
pub struct SetgidTestEnvironmentGuard {
    /// The test environment being managed
    pub environment: SetgidTestEnvironment,
    /// Original PATH value for restoration
    original_path: Option<String>,
}

impl SetgidTestEnvironmentGuard {
    /// Create a new setgid test environment guard
    ///
    /// This sets up a complete test environment with automatic cleanup on drop.
    ///
    /// # Arguments
    ///
    /// * `name` - Base name for the test environment
    /// * `configure_path` - Whether to add fixture bin directory to PATH
    /// * `create_standard_binaries` - Whether to create standard test binaries
    ///
    /// # Returns
    ///
    /// `Ok(SetgidTestEnvironmentGuard)` ready for use
    ///
    /// # Errors
    ///
    /// Returns an error if setup fails
    ///
    /// # Examples
    ///
    /// ```ignore
    /// let guard = SetgidTestEnvironmentGuard::new("integration_test", true, true)
    ///     .expect("Failed to set up environment");
    ///
    /// // Use guard.environment to access created artifacts
    /// assert!(guard.environment.setgid_binaries.len() >= 4);
    ///
    /// // Cleanup happens automatically when guard is dropped
    /// ```
    pub fn new(name: &str, configure_path: bool, create_standard_binaries: bool) -> Result<Self> {
        // Save original PATH before modifying it
        let original_path = env::var("PATH").ok();

        // Set up the test environment
        let environment =
            setup_setgid_test_environment(name, configure_path, create_standard_binaries)
                .with_context(|| format!("Failed to set up setgid test environment {}", name))?;

        Ok(Self {
            environment,
            original_path,
        })
    }

    /// Get the fixture directory path
    ///
    /// # Examples
    ///
    /// ```ignore
    /// let guard = SetgidTestEnvironmentGuard::new("test", true, true)?;
    /// let fixture_dir = guard.fixture_dir();
    /// assert!(fixture_dir.is_dir());
    /// ```
    pub fn fixture_dir(&self) -> &Path {
        &self.environment.fixture_dir
    }

    /// Get the bin subdirectory path
    ///
    /// # Examples
    ///
    /// ```ignore
    /// let guard = SetgidTestEnvironmentGuard::new("test", true, true)?;
    /// let bin_dir = guard.bin_dir()?;
    /// assert!(bin_dir.ends_with("bin"));
    /// ```
    pub fn bin_dir(&self) -> Result<PathBuf> {
        get_setgid_fixture_subdir(&self.environment.fixture_dir, "bin")
    }

    /// Get the lib subdirectory path
    ///
    /// # Examples
    ///
    /// ```ignore
    /// let guard = SetgidTestEnvironmentGuard::new("test", true, true)?;
    /// let lib_dir = guard.lib_dir()?;
    /// assert!(lib_dir.ends_with("lib"));
    /// ```
    pub fn lib_dir(&self) -> Result<PathBuf> {
        get_setgid_fixture_subdir(&self.environment.fixture_dir, "lib")
    }

    /// Get the sbin subdirectory path
    ///
    /// # Examples
    ///
    /// ```ignore
    /// let guard = SetgidTestEnvironmentGuard::new("test", true, true)?;
    /// let sbin_dir = guard.sbin_dir()?;
    /// assert!(sbin_dir.ends_with("sbin"));
    /// ```
    pub fn sbin_dir(&self) -> Result<PathBuf> {
        get_setgid_fixture_subdir(&self.environment.fixture_dir, "sbin")
    }

    /// Get the etc subdirectory path
    ///
    /// # Examples
    ///
    /// ```ignore
    /// let guard = SetgidTestEnvironmentGuard::new("test", true, true)?;
    /// let etc_dir = guard.etc_dir()?;
    /// assert!(etc_dir.ends_with("etc"));
    /// ```
    pub fn etc_dir(&self) -> Result<PathBuf> {
        get_setgid_fixture_subdir(&self.environment.fixture_dir, "etc")
    }

    /// Get the group-writable subdirectory path
    ///
    /// # Examples
    ///
    /// ```ignore
    /// let guard = SetgidTestEnvironmentGuard::new("test", true, true)?;
    /// let group_dir = guard.group_writable_dir()?;
    /// assert!(group_dir.ends_with("group-writable"));
    /// ```
    pub fn group_writable_dir(&self) -> Result<PathBuf> {
        get_setgid_fixture_subdir(&self.environment.fixture_dir, "group-writable")
    }

    /// Verify that all setgid binaries have the correct permissions
    ///
    /// This function checks that all created setgid binaries actually have
    /// the setgid bit set (mode 2000). This is useful for validating that the
    /// setup process worked correctly.
    ///
    /// # Returns
    ///
    /// `Ok(())` if all binaries have correct permissions
    ///
    /// # Errors
    ///
    /// Returns an error if any binary doesn't have the setgid bit set
    ///
    /// # Examples
    ///
    /// ```ignore
    /// let guard = SetgidTestEnvironmentGuard::new("test", true, true)?;
    /// guard.verify_setgid_permissions()?;
    /// ```
    pub fn verify_setgid_permissions(&self) -> Result<()> {
        for binary in &self.environment.setgid_binaries {
            let has_setgid = is_setgid(binary)?;
            if !has_setgid {
                return Err(anyhow::anyhow!(
                    "Setgid binary {:?} does not have setgid bit set",
                    binary
                ));
            }
        }
        Ok(())
    }

    /// Verify that regular binaries do NOT have the setgid bit
    ///
    /// This function ensures that regular binaries were created correctly
    /// without the setgid bit.
    ///
    /// # Returns
    ///
    /// `Ok(())` if all regular binaries are correct
    ///
    /// # Errors
    ///
    /// Returns an error if any regular binary has the setgid bit set
    ///
    /// # Examples
    ///
    /// ```ignore
    /// let guard = SetgidTestEnvironmentGuard::new("test", true, true)?;
    /// guard.verify_regular_binaries()?;
    /// ```
    pub fn verify_regular_binaries(&self) -> Result<()> {
        for binary in &self.environment.regular_binaries {
            let has_setgid = is_setgid(binary)?;
            if has_setgid {
                return Err(anyhow::anyhow!(
                    "Regular binary {:?} incorrectly has setgid bit set",
                    binary
                ));
            }
        }
        Ok(())
    }

    /// Count the total number of binaries created
    ///
    /// This is useful for verifying that the expected number of binaries
    /// were created during setup.
    ///
    /// # Examples
    ///
    /// ```ignore
    /// let guard = SetgidTestEnvironmentGuard::new("test", true, true)?;
    /// let total = guard.total_binary_count();
    /// assert!(total >= 8, "Should have at least 8 binaries");
    /// ```
    pub fn total_binary_count(&self) -> usize {
        self.environment.setgid_binaries.len()
            + self.environment.regular_binaries.len()
            + self.environment.setuid_binaries.len()
            + self.environment.combined_binaries.len()
    }
}

/// Implement automatic cleanup when the guard is dropped
///
/// This ensures that even if a test panics, all resources are properly cleaned up.
/// The cleanup order is:
/// 1. Fixture directory and all contents
/// 2. Binary artifacts (via BinaryFixtureGuard)
/// 3. PATH restoration (via PathGuard)
///
/// # Error Handling
///
/// Cleanup failures are logged to stderr but don't panic to avoid masking
/// the actual test failure with a cleanup panic.
impl Drop for SetgidTestEnvironmentGuard {
    fn drop(&mut self) {
        // Restore the original PATH if it was modified
        if let Some(ref original_path) = self.original_path {
            env::set_var("PATH", original_path);
        }

        // Clean up the fixture directory if it exists
        if self.environment.fixture_dir.exists() {
            if let Err(e) = fs::remove_dir_all(&self.environment.fixture_dir) {
                eprintln!(
                    "WARNING: Failed to remove fixture directory during guard Drop: {:?}. Error: {}",
                    self.environment.fixture_dir, e
                );
            }
        }

        // The BinaryFixtureGuard in the environment will handle binary cleanup
        // when it's dropped (which happens after this Drop completes due to field order)
    }
}
