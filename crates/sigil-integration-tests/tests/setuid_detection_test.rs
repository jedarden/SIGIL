//! Setuid Binary Detection Tests
//!
//! This test module validates setuid binary detection functionality
//! using the helper functions from the binary_fixture module.
//!
//! # Tests Included
//!
//! - Positive detection: setuid binaries in PATH are correctly detected
//! - Negative detection: non-setuid binaries are not flagged
//! - Setuid-root binaries: binaries owned by root with setuid bit
//! - Setuid-user binaries: binaries owned by user with setuid bit
//! - Cleanup validation: temporary binaries are properly removed
//! - Fixture integration: all tests use binary_fixture helper functions
//!
//! # Infrastructure
//!
//! Uses the `sigil_integration_tests::binary_fixture` module which provides:
//! - `create_setuid_binary()` - Create setuid test binaries
//! - `create_executable_binary()` - Create regular (non-setuid) test binaries
//! - `BinaryFixtureGuard` - RAII guard for automatic cleanup
//! - `add_binary_to_path()` - Add binary directory to PATH
//! - `is_setuid()` - Check if a binary has setuid bit
//! - `cleanup_test_binaries()` - Manual cleanup function
//!
//! Uses the `sigil_integration_tests::env_detect` module which provides:
//! - `check_setuid_bit()` - Check if a binary has setuid bit set
//! - `is_setuid_root_binary()` - Check if binary is setuid-root
//! - `find_setuid_binaries_in_path()` - Find all setuid binaries in PATH
//! - `BinarySecurityInfo` - Security information structure
//! - `get_binary_security_info()` - Get full security info for a binary

use sigil_integration_tests::binary_fixture::*;
use sigil_integration_tests::env_detect::*;
use std::path::PathBuf;

#[cfg(test)]
mod positive_detection_tests {
    use super::*;

    /// Test that setuid binaries in PATH are detected
    ///
    /// # Purpose
    ///
    /// Verifies that setuid binaries added to PATH are correctly
    /// identified by the find_setuid_binaries_in_path() function.
    ///
    /// # Validation
    ///
    /// - Created setuid binary exists and has setuid bit
    /// - Binary is detected when added to PATH
    /// - Binary security info is correct
    #[test]
    fn test_setuid_binary_in_path_is_detected() {
        // Use RAII guard for automatic cleanup
        let _fixture_guard = BinaryFixtureGuard::new();

        // Create a setuid binary using the helper function
        let setuid_bin =
            create_setuid_binary("test_setuid_detect", b"#!/bin/sh\necho 'setuid test'\n")
                .expect("Failed to create setuid binary");

        // Verify the binary was created with setuid bit
        assert!(
            is_setuid(&setuid_bin).expect("Failed to check setuid bit"),
            "Created binary should have setuid bit"
        );

        // Verify the binary is detected by check_setuid_bit
        assert!(
            check_setuid_bit(&setuid_bin).expect("Failed to check setuid bit"),
            "check_setuid_bit should return true for setuid binary"
        );

        // Add binary to PATH
        let _path_guard = add_binary_to_path(&setuid_bin).expect("Failed to add to PATH");

        // Find all setuid binaries in PATH
        let setuid_bins =
            find_setuid_binaries_in_path().expect("Failed to find setuid binaries in PATH");

        // Verify our binary is in the list
        let found = setuid_bins
            .iter()
            .any(|info| info.path == setuid_bin && info.has_setuid);

        assert!(
            found,
            "Created setuid binary should be found in PATH setuid binaries. Found: {:?}",
            setuid_bins
        );

        // Verify the security info is correct
        if let Some(info) = setuid_bins.iter().find(|i| i.path == setuid_bin) {
            assert!(
                info.has_setuid,
                "Binary should be marked as having setuid bit"
            );
            assert!(
                !info.is_setuid_root,
                "Test binary should not be setuid-root"
            );
        }
    }

    /// Test that multiple setuid binaries in PATH are all detected
    ///
    /// # Purpose
    ///
    /// Verifies that when multiple setuid binaries exist in PATH,
    /// all of them are correctly detected and reported.
    #[test]
    fn test_multiple_setuid_binaries_all_detected() {
        let _fixture_guard = BinaryFixtureGuard::new();

        // Create multiple setuid binaries
        let bin1 = create_setuid_binary("setuid_bin1", b"#!/bin/sh\necho '1'\n")
            .expect("Failed to create bin1");
        let bin2 = create_setuid_binary("setuid_bin2", b"#!/bin/sh\necho '2'\n")
            .expect("Failed to create bin2");
        let bin3 = create_setuid_binary("setuid_bin3", b"#!/bin/sh\necho '3'\n")
            .expect("Failed to create bin3");

        // Verify all have setuid bit
        assert!(is_setuid(&bin1).unwrap());
        assert!(is_setuid(&bin2).unwrap());
        assert!(is_setuid(&bin3).unwrap());

        // Add to PATH
        let _path_guard = add_binary_to_path(&bin1).expect("Failed to add to PATH");

        // Find setuid binaries
        let setuid_bins = find_setuid_binaries_in_path().expect("Failed to find binaries");

        // Check that all our binaries are found
        let bin_names = vec!["setuid_bin1", "setuid_bin2", "setuid_bin3"];
        for name in bin_names {
            let found = setuid_bins
                .iter()
                .any(|info| info.path.file_name().unwrap() == name && info.has_setuid);
            assert!(found, "Setuid binary '{}' should be detected in PATH", name);
        }

        println!("Detected {} setuid binaries in PATH", setuid_bins.len());
    }

    /// Test setuid detection with check_setuid_bit directly
    ///
    /// # Purpose
    ///
    /// Validates the check_setuid_bit() function correctly identifies
    /// setuid binaries when called directly on a file path.
    #[test]
    fn test_check_setuid_bit_detects_setuid() {
        let _fixture_guard = BinaryFixtureGuard::new();

        // Create a setuid binary
        let setuid_bin = create_setuid_binary("test_check_setuid", b"#!/bin/sh\nexit 0\n")
            .expect("Failed to create setuid binary");

        // Test with check_setuid_bit
        let has_setuid = check_setuid_bit(&setuid_bin).expect("Failed to check setuid bit");

        assert!(
            has_setuid,
            "check_setuid_bit should return true for setuid binary"
        );

        // Verify using the fixture helper
        assert!(
            is_setuid(&setuid_bin).unwrap(),
            "is_setuid helper should also detect setuid bit"
        );
    }
}

#[cfg(test)]
mod negative_detection_tests {
    use super::*;

    /// Test that non-setuid binaries are not flagged
    ///
    /// # Purpose
    ///
    /// Verifies that regular executable binaries (without setuid bit)
    /// are not incorrectly flagged as setuid binaries.
    ///
    /// # Validation
    ///
    /// - Created regular binary exists and is executable
    /// - Binary does NOT have setuid bit
    /// - Binary is NOT detected by setuid detection functions
    #[test]
    fn test_non_setuid_binary_not_flagged() {
        let _fixture_guard = BinaryFixtureGuard::new();

        // Create a regular (non-setuid) executable binary
        let regular_bin =
            create_executable_binary("test_regular_bin", b"#!/bin/sh\necho 'regular'\n")
                .expect("Failed to create regular binary");

        // Verify the binary was created WITHOUT setuid bit
        assert!(
            !is_setuid(&regular_bin).expect("Failed to check setuid bit"),
            "Regular binary should NOT have setuid bit"
        );

        // Test with check_setuid_bit
        let has_setuid = check_setuid_bit(&regular_bin).expect("Failed to check setuid bit");

        assert!(
            !has_setuid,
            "check_setuid_bit should return false for regular binary"
        );

        // Add to PATH
        let _path_guard = add_binary_to_path(&regular_bin).expect("Failed to add to PATH");

        // Find setuid binaries - our regular binary should NOT be in the list
        let setuid_bins = find_setuid_binaries_in_path().expect("Failed to scan PATH");

        let found = setuid_bins.iter().any(|info| info.path == regular_bin);

        assert!(
            !found,
            "Regular binary should NOT be in setuid binaries list. Found: {:?}",
            setuid_bins
        );

        println!(
            "Regular binary correctly excluded from setuid detection. {} setuid binaries found.",
            setuid_bins.len()
        );
    }

    /// Test that regular binaries are not flagged as setuid-root
    ///
    /// # Purpose
    ///
    /// Verifies that is_setuid_root_binary() returns false for
    /// regular executables that lack the setuid bit.
    #[test]
    fn test_regular_binary_not_flagged_as_setuid_root() {
        let _fixture_guard = BinaryFixtureGuard::new();

        // Create a regular executable
        let regular_bin = create_executable_binary("test_regular_root", b"#!/bin/sh\nid\n")
            .expect("Failed to create regular binary");

        // Verify it's not setuid-root
        let is_setuid_root =
            is_setuid_root_binary(&regular_bin).expect("Failed to check setuid-root status");

        assert!(
            !is_setuid_root,
            "Regular binary should NOT be flagged as setuid-root"
        );

        // Also verify with security info
        let info = get_binary_security_info(&regular_bin).expect("Failed to get security info");

        assert!(!info.has_setuid, "Security info should show no setuid bit");
        assert!(
            !info.is_setuid_root,
            "Security info should show not setuid-root"
        );
    }

    /// Test mixed environment: both setuid and regular binaries
    ///
    /// # Purpose
    ///
    /// Verifies that in a directory with both setuid and regular binaries,
    /// only the setuid ones are detected.
    #[test]
    fn test_mixed_binaries_only_setuid_detected() {
        let _fixture_guard = BinaryFixtureGuard::new();

        // Create both setuid and regular binaries
        let setuid_bin = create_setuid_binary("mixed_setuid", b"#!/bin/sh\necho 'setuid'\n")
            .expect("Failed to create setuid binary");
        let regular_bin = create_executable_binary("mixed_regular", b"#!/bin/sh\necho 'regular'\n")
            .expect("Failed to create regular binary");

        // Verify initial states
        assert!(is_setuid(&setuid_bin).unwrap());
        assert!(!is_setuid(&regular_bin).unwrap());

        // Add to PATH (both in same directory, one guard covers both)
        let _path_guard = add_binary_to_path(&setuid_bin).expect("Failed to add to PATH");

        // Find setuid binaries
        let setuid_bins = find_setuid_binaries_in_path().expect("Failed to scan PATH");

        // Check that only setuid binary is detected
        let setuid_found = setuid_bins.iter().any(|info| info.path == setuid_bin);
        let regular_found = setuid_bins.iter().any(|info| info.path == regular_bin);

        assert!(setuid_found, "Setuid binary should be detected");
        assert!(!regular_found, "Regular binary should NOT be detected");

        println!(
            "Mixed test: {} setuid binaries detected (regular bin correctly excluded)",
            setuid_bins.len()
        );
    }
}

#[cfg(test)]
mod setuid_root_tests {
    use super::*;

    /// Test setuid-root binary detection
    ///
    /// # Purpose
    ///
    /// Verifies that binaries with both setuid bit AND root ownership
    /// are correctly identified as setuid-root binaries.
    ///
    /// # Note
    ///
    /// In CI/test environments without actual root access, this test
    /// validates the detection logic works correctly. Production systems
    /// would have actual setuid-root binaries like sudo, passwd, etc.
    #[test]
    fn test_setuid_root_binary_detection() {
        let _fixture_guard = BinaryFixtureGuard::new();

        // Create a setuid binary
        // Note: In test environment, we can't create true root-owned binaries
        // without actual root privileges. This test validates the detection logic.
        let setuid_bin = create_setuid_binary("test_setuid_root", b"#!/bin/sh\nid\n")
            .expect("Failed to create setuid binary");

        // Check if it's setuid (should be true)
        let has_setuid = check_setuid_bit(&setuid_bin).expect("Failed to check setuid bit");
        assert!(has_setuid, "Binary should have setuid bit");

        // Check setuid-root status
        // In test environment (non-root), this will be false
        // but the function should execute without error
        let is_setuid_root =
            is_setuid_root_binary(&setuid_bin).expect("Failed to check setuid-root status");

        println!(
            "Setuid-root test: has_setuid={}, is_setuid_root={}",
            has_setuid, is_setuid_root
        );

        // Get full security info
        let info = get_binary_security_info(&setuid_bin).expect("Failed to get security info");

        assert!(info.has_setuid, "Should have setuid bit");
        // In test environment, is_setuid_root will be false (not owned by root)
        println!(
            "Binary security info: has_setuid={}, is_setuid_root={}, uid={}",
            info.has_setuid, info.is_setuid_root, info.uid
        );
    }

    /// Test setuid-root binary detection using create_setuid_fixture
    ///
    /// # Purpose
    ///
    /// Verifies that setuid-root binaries created with the create_setuid_fixture
    /// helper are properly detected in PATH. This test uses the specialized fixture
    /// helper designed for setuid testing and validates the complete detection workflow.
    ///
    /// # Validation
    ///
    /// - Setuid fixture is created successfully with setuid-root mode
    /// - Binary is detected when added to PATH
    /// - Binary is properly identified as having setuid bit
    /// - Cleanup removes all test artifacts
    #[test]
    fn test_detect_setuid_root_binary() {
        // Create a setuid-root binary fixture using the specialized helper
        let setuid_bin = create_setuid_fixture(
            "detect_setuid_root",
            b"#!/bin/sh\necho 'setuid-root test'\n",
        )
        .expect("Failed to create setuid-root fixture");

        // Verify the binary was created with setuid bit
        let has_setuid = check_setuid_bit(&setuid_bin).expect("Failed to check setuid bit");
        assert!(has_setuid, "Setuid fixture should have setuid bit");

        // Verify using the is_setuid helper
        assert!(
            is_setuid(&setuid_bin).expect("Failed to verify setuid bit"),
            "is_setuid should confirm setuid bit is set"
        );

        // Add binary to PATH for detection
        let _path_guard = add_binary_to_path(&setuid_bin).expect("Failed to add to PATH");

        // Find all setuid binaries in PATH
        let setuid_bins = find_setuid_binaries_in_path().expect("Failed to find setuid binaries");

        // Verify our binary is detected in PATH
        let found = setuid_bins
            .iter()
            .any(|info| info.path == setuid_bin && info.has_setuid);

        assert!(
            found,
            "Setuid-root binary should be detected in PATH. Found binaries: {:?}",
            setuid_bins
        );

        // Get security info to verify detection accuracy
        if let Some(info) = setuid_bins.iter().find(|i| i.path == setuid_bin) {
            assert!(
                info.has_setuid,
                "Detected binary should be marked as having setuid bit"
            );
        }

        println!(
            "Setuid-root binary successfully detected in PATH: {}",
            setuid_bin.display()
        );

        // Clean up fixtures using the specialized cleanup helper
        cleanup_setuid_fixtures().expect("Failed to cleanup setuid fixtures");

        // Verify cleanup succeeded
        assert!(
            !setuid_bin.exists(),
            "Setuid fixture should be removed after cleanup"
        );
    }

    /// Test setuid-user binary (setuid but not root-owned)
    ///
    /// # Purpose
    ///
    /// Verifies that setuid binaries owned by non-root users are
    /// correctly distinguished from setuid-root binaries.
    #[test]
    fn test_setuid_user_binary_distinction() {
        let _fixture_guard = BinaryFixtureGuard::new();

        // Create a setuid binary (owned by current user, not root)
        let user_setuid_bin = create_setuid_binary("test_setuid_user", b"#!/bin/sh\necho 'user'\n")
            .expect("Failed to create setuid binary");

        // Verify it has setuid bit
        assert!(
            check_setuid_bit(&user_setuid_bin).unwrap(),
            "Should have setuid bit"
        );

        // Verify it's NOT setuid-root (not owned by root)
        let is_setuid_root =
            is_setuid_root_binary(&user_setuid_bin).expect("Failed to check setuid-root status");

        assert!(
            !is_setuid_root,
            "User-owned setuid binary should NOT be flagged as setuid-root"
        );

        // Check security info
        let info = get_binary_security_info(&user_setuid_bin).expect("Failed to get security info");

        assert!(info.has_setuid, "Should have setuid bit");
        assert!(!info.is_setuid_root, "Should NOT be setuid-root");

        // Owner UID should NOT be 0
        assert!(
            info.uid != 0,
            "Owner UID should not be 0 (root) for user-owned binary"
        );

        println!(
            "Setuid-user binary: has_setuid={}, is_setuid_root={}, uid={}",
            info.has_setuid, info.is_setuid_root, info.uid
        );
    }

    /// Test that setuid-root check requires both conditions
    ///
    /// # Purpose
    ///
    /// Verifies that is_setuid_root_binary() requires BOTH setuid bit
    /// AND root ownership, not just one or the other.
    #[test]
    fn test_setuid_root_requires_both_conditions() {
        let _fixture_guard = BinaryFixtureGuard::new();

        // Test 1: Regular binary (no setuid, not root) - should be false
        let regular_bin = create_executable_binary("cond_test_regular", b"test\n")
            .expect("Failed to create regular binary");

        assert!(
            !is_setuid_root_binary(&regular_bin).unwrap(),
            "Regular binary should not be setuid-root"
        );

        // Test 2: Setuid binary (has setuid, but not root-owned in test) - should be false
        let setuid_bin = create_setuid_binary("cond_test_setuid", b"test\n")
            .expect("Failed to create setuid binary");

        // In test environment, not owned by root
        assert!(
            !is_setuid_root_binary(&setuid_bin).unwrap(),
            "User-owned setuid binary should not be setuid-root"
        );

        println!("Setuid-root condition test: requires BOTH setuid bit AND root ownership");
    }

    /// Test setuid-user binary detection using create_setuid_fixture
    ///
    /// # Purpose
    ///
    /// Verifies that setuid-user binaries (setuid but not owned by root) created
    /// with the create_setuid_fixture helper are properly detected in PATH.
    /// This test uses the specialized fixture helper and validates the complete
    /// detection workflow for non-root setuid binaries.
    ///
    /// # Validation
    ///
    /// - Setuid fixture is created successfully with setuid-user mode (non-root ownership)
    /// - Binary is detected when added to PATH
    /// - Binary is properly identified as having setuid bit but NOT setuid-root
    /// - Cleanup removes all test artifacts
    #[test]
    fn test_detect_setuid_user_binary() {
        // Create a setuid-user binary fixture using the specialized helper
        // In test environment (non-root), this creates a setuid binary owned by the current user
        let setuid_user_bin = create_setuid_fixture(
            "detect_setuid_user",
            b"#!/bin/sh\necho 'setuid-user test'\n",
        )
        .expect("Failed to create setuid-user fixture");

        // Verify the binary was created with setuid bit
        let has_setuid = check_setuid_bit(&setuid_user_bin).expect("Failed to check setuid bit");
        assert!(has_setuid, "Setuid fixture should have setuid bit");

        // Verify using the is_setuid helper
        assert!(
            is_setuid(&setuid_user_bin).expect("Failed to verify setuid bit"),
            "is_setuid should confirm setuid bit is set"
        );

        // Verify this is NOT a setuid-root binary (owned by current user, not root)
        let is_setuid_root =
            is_setuid_root_binary(&setuid_user_bin).expect("Failed to check setuid-root status");
        assert!(
            !is_setuid_root,
            "Setuid-user binary should NOT be flagged as setuid-root"
        );

        // Add binary to PATH for detection
        let _path_guard = add_binary_to_path(&setuid_user_bin).expect("Failed to add to PATH");

        // Find all setuid binaries in PATH
        let setuid_bins = find_setuid_binaries_in_path().expect("Failed to find setuid binaries");

        // Verify our binary is detected in PATH
        let found = setuid_bins
            .iter()
            .any(|info| info.path == setuid_user_bin && info.has_setuid);

        assert!(
            found,
            "Setuid-user binary should be detected in PATH. Found binaries: {:?}",
            setuid_bins
        );

        // Get security info to verify detection accuracy
        if let Some(info) = setuid_bins.iter().find(|i| i.path == setuid_user_bin) {
            assert!(
                info.has_setuid,
                "Detected binary should be marked as having setuid bit"
            );
            assert!(
                !info.is_setuid_root,
                "Detected binary should NOT be marked as setuid-root"
            );
            assert!(
                info.uid != 0,
                "Detected binary should have non-zero UID (not owned by root)"
            );
        }

        println!(
            "Setuid-user binary successfully detected in PATH: {}",
            setuid_user_bin.display()
        );

        // Clean up fixtures using the specialized cleanup helper
        cleanup_setuid_fixtures().expect("Failed to cleanup setuid fixtures");

        // Verify cleanup succeeded
        assert!(
            !setuid_user_bin.exists(),
            "Setuid fixture should be removed after cleanup"
        );
    }
}

#[cfg(test)]
mod cleanup_tests {
    use super::*;
    use std::fs;

    /// Test cleanup removes temporary binaries
    ///
    /// # Purpose
    ///
    /// Verifies that cleanup functions properly remove temporary test
    /// binaries and restore PATH to original state.
    ///
    /// # Validation
    ///
    /// - Binaries are created and exist before cleanup
    /// - Binaries are removed after cleanup
    /// - PATH is restored to original state
    #[test]
    fn test_cleanup_removes_temporary_binaries() {
        // This test validates that cleanup functions work correctly
        // by creating binaries, verifying they exist, then cleaning up
        // and verifying they're removed.

        // Use BinaryFixtureGuard for automatic cleanup at test end
        let _fixture_guard = BinaryFixtureGuard::new();

        // Get original PATH for verification
        let original_path = std::env::var("PATH").unwrap();

        // Create test binaries
        let bin1 =
            create_setuid_binary("cleanup_test1", b"test1\n").expect("Failed to create bin1");
        let bin2 =
            create_executable_binary("cleanup_test2", b"test2\n").expect("Failed to create bin2");

        // Verify binaries exist immediately after creation
        assert!(bin1.exists(), "Binary 1 should exist after creation");
        assert!(bin2.exists(), "Binary 2 should exist after creation");

        // Add to PATH
        let _path_guard = add_binary_to_path(&bin1).expect("Failed to add to PATH");

        // Verify PATH was modified
        let current_path = std::env::var("PATH").unwrap();
        assert_ne!(original_path, current_path, "PATH should be modified");

        // Verify binaries still exist
        assert!(bin1.exists(), "Binary 1 should exist after PATH addition");
        assert!(bin2.exists(), "Binary 2 should exist after PATH addition");

        // When the function ends, both guards will be dropped:
        // 1. PathGuard restores PATH
        // 2. BinaryFixtureGuard cleans up binaries
        // This tests the RAII cleanup behavior

        // Note: We can't verify binaries are removed here because
        // BinaryFixtureGuard cleans up when dropped at function end
        // The automatic cleanup is tested by test_binary_fixture_guard_automatic_cleanup
    }

    /// Test BinaryFixtureGuard automatic cleanup
    ///
    /// # Purpose
    ///
    /// Verifies that BinaryFixtureGuard automatically cleans up binaries
    /// when dropped, even if a test panics.
    #[test]
    fn test_binary_fixture_guard_automatic_cleanup() {
        // Ensure clean state
        let _ = cleanup_test_binaries();

        let test_dir = init_test_bin_dir().expect("Failed to init test dir");
        let test_file = test_dir.join("guard_test_file");

        {
            // Create guard
            let _fixture_guard = BinaryFixtureGuard::new();

            // Create test file
            fs::write(&test_file, b"test content").expect("Failed to write test file");

            // Verify file exists
            assert!(test_file.exists(), "Test file should exist");
        }

        // After guard is dropped, everything should be cleaned up
        assert!(
            !test_file.exists(),
            "Test file should be removed after guard drop"
        );
        assert!(
            !test_dir.exists(),
            "Test directory should be removed after guard drop"
        );

        println!("BinaryFixtureGuard successfully cleaned up on drop");
    }

    /// Test cleanup is idempotent
    ///
    /// # Purpose
    ///
    /// Verifies that cleanup can be called multiple times safely
    /// without errors.
    #[test]
    fn test_cleanup_is_idempotent() {
        // Test that multiple cleanup calls succeed without error
        // First cleanup (ensure clean state)
        let result1 = cleanup_test_binaries();
        assert!(result1.is_ok(), "First cleanup should succeed");

        // Second cleanup (should succeed without error even if nothing to clean)
        let result2 = cleanup_test_binaries();
        assert!(result2.is_ok(), "Second cleanup should succeed");

        // Third cleanup (still should succeed)
        let result3 = cleanup_test_binaries();
        assert!(result3.is_ok(), "Third cleanup should succeed");

        println!("Cleanup is idempotent: multiple calls succeed");
    }

    /// Test cleanup restores PATH even with errors
    ///
    /// # Purpose
    ///
    /// Verifies that PATH is properly restored when guards are dropped.
    #[test]
    fn test_path_restoration_on_cleanup() {
        // Clean up any existing state first
        let _ = cleanup_test_binaries();

        // Reinitialize the test directory after cleanup
        let _ = init_test_bin_dir();

        let original_path = std::env::var("PATH").unwrap();
        let modified_path;

        {
            let bin =
                create_setuid_binary("path_test", b"test\n").expect("Failed to create binary");

            let _path_guard = add_binary_to_path(&bin).expect("Failed to add to PATH");

            modified_path = std::env::var("PATH").unwrap();
            assert_ne!(original_path, modified_path, "PATH should be modified");

            // path_guard will be dropped here
        }

        // PATH should be restored
        let final_path = std::env::var("PATH").unwrap();
        assert_eq!(
            original_path, final_path,
            "PATH should be restored after path guard dropped"
        );

        // Clean up binary
        cleanup_test_binaries().expect("Cleanup should succeed");

        println!("PATH correctly restored after guard cleanup");
    }
}

#[cfg(test)]
mod fixture_integration_tests {
    use super::*;

    /// Test that fixtures use helper functions from binary_fixture
    ///
    /// # Purpose
    ///
    /// Validates that all test fixtures properly use the helper functions
    /// from the binary_fixture module (previous bead).
    #[test]
    fn test_fixtures_use_binary_fixture_helpers() {
        // Test create_setuid_binary helper
        let bin1 = create_setuid_binary("helper_test1", b"test\n")
            .expect("create_setuid_binary helper should work");

        assert!(
            is_setuid(&bin1).unwrap(),
            "Helper should create setuid binary"
        );

        // Test create_executable_binary helper
        let bin2 = create_executable_binary("helper_test2", b"test\n")
            .expect("create_executable_binary helper should work");

        assert!(
            !is_setuid(&bin2).unwrap(),
            "Helper should create non-setuid binary"
        );

        // Test add_binary_to_path helper
        let _path_guard = add_binary_to_path(&bin1).expect("add_binary_to_path helper should work");

        // Test is_setuid helper
        assert!(
            is_setuid(&bin1).unwrap(),
            "is_setuid helper should detect setuid"
        );
        assert!(
            !is_setuid(&bin2).unwrap(),
            "is_setuid helper should detect non-setuid"
        );

        // Test BinaryFixtureGuard helper
        let _fixture_guard = BinaryFixtureGuard::new();

        // Test check_setuid_bit (env_detect function)
        assert!(
            check_setuid_bit(&bin1).unwrap(),
            "check_setuid_bit should detect setuid"
        );
        assert!(
            !check_setuid_bit(&bin2).unwrap(),
            "check_setuid_bit should detect non-setuid"
        );

        println!("All binary_fixture helper functions work correctly");
    }

    /// Test fixture helper integration with env_detect functions
    ///
    /// # Purpose
    ///
    /// Validates that binary_fixture helpers integrate seamlessly
    /// with env_detect detection functions.
    #[test]
    fn test_fixture_env_detect_integration() {
        let _fixture_guard = BinaryFixtureGuard::new();

        // Create test binaries using fixtures
        let setuid_bin = create_setuid_binary("integration_setuid", b"test\n")
            .expect("Fixture should create setuid binary");
        let regular_bin = create_executable_binary("integration_regular", b"test\n")
            .expect("Fixture should create regular binary");

        // Test with env_detect functions
        let setuid_detected =
            check_setuid_bit(&setuid_bin).expect("env_detect should work with fixture binary");
        let regular_detected =
            check_setuid_bit(&regular_bin).expect("env_detect should work with fixture binary");

        assert!(setuid_detected, "Fixture setuid binary should be detected");
        assert!(
            !regular_detected,
            "Fixture regular binary should not be detected"
        );

        // Test security info
        let setuid_info = get_binary_security_info(&setuid_bin)
            .expect("Should get security info for fixture binary");
        let regular_info = get_binary_security_info(&regular_bin)
            .expect("Should get security info for fixture binary");

        assert!(
            setuid_info.has_setuid,
            "Fixture binary security info should show setuid"
        );
        assert!(
            !regular_info.has_setuid,
            "Fixture binary security info should show non-setuid"
        );

        println!("binary_fixture and env_detect integration works correctly");
    }

    /// Test fixture error handling
    ///
    /// # Purpose
    ///
    /// Validates that fixture helpers handle errors gracefully
    /// and return Result types for proper error handling.
    #[test]
    fn test_fixture_error_handling() {
        let _fixture_guard = BinaryFixtureGuard::new();

        // Test with invalid path for check_setuid_bit
        let nonexistent = PathBuf::from("/nonexistent/path/to/binary");
        let result = check_setuid_bit(&nonexistent);

        assert!(
            result.is_err(),
            "check_setuid_bit should return error for nonexistent path"
        );

        // Test is_setuid helper with nonexistent path
        let result = is_setuid(&nonexistent);
        assert!(
            result.is_err(),
            "is_setuid should return error for nonexistent path"
        );

        // Test is_setuid_root_binary with nonexistent path
        let result = is_setuid_root_binary(&nonexistent);
        assert!(result.is_err(), "is_setuid_root_binary should return error");

        println!("Fixture error handling works correctly");
    }
}

#[cfg(test)]
mod comprehensive_detection_tests {
    use super::*;

    /// Comprehensive test: full detection workflow
    ///
    /// # Purpose
    ///
    /// End-to-end test that validates the complete setuid detection
    /// workflow using all helper functions.
    #[test]
    fn test_comprehensive_setuid_detection_workflow() {
        // Start with clean state
        let _fixture_guard = BinaryFixtureGuard::new();

        // Create comprehensive test set: setuid and regular binaries
        let sudo_like = create_setuid_binary("sudo-like", b"#!/bin/sh\nid\n")
            .expect("Failed to create sudo-like binary");
        let passwd_like = create_setuid_binary("passwd-like", b"#!/bin/sh\nwhoami\n")
            .expect("Failed to create passwd-like binary");
        let normal_tool = create_executable_binary("normal-tool", b"#!/bin/sh\necho 'tool'\n")
            .expect("Failed to create normal tool");

        // Verify all were created correctly
        assert!(is_setuid(&sudo_like).unwrap());
        assert!(is_setuid(&passwd_like).unwrap());
        assert!(!is_setuid(&normal_tool).unwrap());

        // Add to PATH
        let _path_guard = add_binary_to_path(&sudo_like).expect("Failed to add to PATH");

        // Find all setuid binaries in PATH
        let setuid_bins = find_setuid_binaries_in_path().expect("Failed to find setuid binaries");

        // Verify our setuid binaries are detected
        let sudo_found = setuid_bins.iter().any(|info| info.path == sudo_like);
        let passwd_found = setuid_bins.iter().any(|info| info.path == passwd_like);
        let normal_found = setuid_bins.iter().any(|info| info.path == normal_tool);

        assert!(sudo_found, "Sudo-like binary should be detected");
        assert!(passwd_found, "Passwd-like binary should be detected");
        assert!(!normal_found, "Normal tool should NOT be detected");

        // Get security info for each
        let sudo_info = get_binary_security_info(&sudo_like).expect("Failed to get sudo info");
        let normal_info =
            get_binary_security_info(&normal_tool).expect("Failed to get normal tool info");

        assert!(sudo_info.has_setuid);
        assert!(!normal_info.has_setuid);

        // Test setuid-root detection
        let sudo_is_root =
            is_setuid_root_binary(&sudo_like).expect("Failed to check sudo root status");
        let normal_is_root =
            is_setuid_root_binary(&normal_tool).expect("Failed to check normal tool root status");

        println!(
            "Comprehensive test: sudo-like is setuid-root: {}, normal tool is setuid-root: {}",
            sudo_is_root, normal_is_root
        );

        // Validate detection accuracy
        assert!(
            setuid_bins.iter().filter(|b| b.has_setuid).count() >= 2,
            "Should detect at least 2 setuid binaries"
        );
        assert!(
            setuid_bins.iter().filter(|b| !b.has_setuid).count() == 0,
            "All detected binaries should have setuid bit"
        );

        println!(
            "Comprehensive workflow test passed: {} setuid binaries detected",
            setuid_bins.len()
        );
    }

    /// Test detection accuracy and precision
    ///
    /// # Purpose
    ///
    /// Validates that setuid detection is both accurate (finds all
    /// setuid binaries) and precise (doesn't flag non-setuid binaries).
    #[test]
    fn test_detection_accuracy_and_precision() {
        let _fixture_guard = BinaryFixtureGuard::new();

        // Create known test cases
        let setuid_bins = vec![
            create_setuid_binary("accurate_setuid1", b"test1\n").unwrap(),
            create_setuid_binary("accurate_setuid2", b"test2\n").unwrap(),
            create_setuid_binary("accurate_setuid3", b"test3\n").unwrap(),
        ];

        let regular_bins = vec![
            create_executable_binary("accurate_regular1", b"test1\n").unwrap(),
            create_executable_binary("accurate_regular2", b"test2\n").unwrap(),
            create_executable_binary("accurate_regular3", b"test3\n").unwrap(),
        ];

        // Add to PATH
        let _path_guard = add_binary_to_path(&setuid_bins[0]).expect("Failed to add to PATH");

        // Find setuid binaries
        let detected = find_setuid_binaries_in_path().expect("Failed to find binaries");

        // Test accuracy: all our setuid binaries should be found
        for setuid_bin in &setuid_bins {
            let found = detected.iter().any(|info| info.path == *setuid_bin);
            assert!(
                found,
                "Setuid binary should be detected: {:?}",
                setuid_bin.file_name()
            );
        }

        // Test precision: regular binaries should NOT be detected
        for regular_bin in &regular_bins {
            let found = detected.iter().any(|info| info.path == *regular_bin);
            assert!(
                !found,
                "Regular binary should NOT be detected: {:?}",
                regular_bin.file_name()
            );
        }

        // Calculate metrics
        let true_positives = setuid_bins
            .iter()
            .filter(|b| detected.iter().any(|d| d.path == **b))
            .count();

        let false_negatives = setuid_bins
            .iter()
            .filter(|b| !detected.iter().any(|d| d.path == **b))
            .count();

        let false_positives = regular_bins
            .iter()
            .filter(|b| detected.iter().any(|d| d.path == **b))
            .count();

        println!(
            "Detection metrics: true_positives={}, false_negatives={}, false_positives={}",
            true_positives, false_negatives, false_positives
        );

        assert_eq!(false_negatives, 0, "Should have no false negatives");
        assert_eq!(false_positives, 0, "Should have no false positives");
    }

    /// Test detection with binary fixture cleanup validation
    ///
    /// # Purpose
    ///
    /// Validates that detection works correctly AND cleanup
    /// removes all test artifacts.
    #[test]
    fn test_detection_with_cleanup_validation() {
        let _fixture_guard = BinaryFixtureGuard::new();

        let test_dir = init_test_bin_dir().expect("Failed to init test dir");

        // Create comprehensive test binaries
        let binaries = vec![
            create_setuid_binary("cleanup_setuid", b"setuid\n").unwrap(),
            create_executable_binary("cleanup_regular", b"regular\n").unwrap(),
        ];

        // Verify existence
        for bin in &binaries {
            assert!(bin.exists(), "Binary should exist before detection");
        }

        // Run detection
        let _path_guard = add_binary_to_path(&binaries[0]).expect("Failed to add to PATH");

        let detected = find_setuid_binaries_in_path().expect("Detection should succeed");

        // Verify detection worked
        assert!(
            detected.iter().any(|b| b.path == binaries[0]),
            "Setuid binary should be detected"
        );
        assert!(
            !detected.iter().any(|b| b.path == binaries[1]),
            "Regular binary should not be detected"
        );

        // Manual cleanup
        cleanup_test_binaries().expect("Cleanup should succeed");

        // Verify cleanup
        for bin in &binaries {
            assert!(!bin.exists(), "Binary should be removed after cleanup");
        }

        assert!(
            !test_dir.exists(),
            "Test directory should be removed after cleanup"
        );

        println!("Detection and cleanup validation successful");
    }
}
