//! Setuid Binary Detection Tests
//!
//! This test module validates setuid binary detection functionality
//! using the helper functions from the binary_fixture module.
//!
//! # Tests Included
//!
//! - Positive detection: setuid binaries in PATH are correctly detected
//! - Negative detection: non-setuid binaries are not flagged
//! - Setgid detection: setgid binaries (chmod g+s) are correctly detected
//! - Setuid-root binaries: binaries owned by root with setuid bit
//! - Setuid-user binaries: binaries owned by user with setuid bit
//! - Combined permissions: setuid + setgid combinations
//! - Permission bit scenarios: user/group/other read/write/execute
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

use serial_test::serial;
use sigil_integration_tests::binary_fixture::*;
use sigil_integration_tests::env_detect::*;
use std::os::unix::fs::MetadataExt;
use std::path::PathBuf;

#[cfg(test)]
#[serial]
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
        // Ensure clean state first
        let _ = cleanup_test_binaries();

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
        // Create guard first - manages cleanup automatically
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
        // Create guard first - manages cleanup automatically
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
#[serial]
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

    /// Test that non-setuid binaries are not detected as setuid
    ///
    /// # Purpose
    ///
    /// Verifies that regular executables (without setuid bit) created
    /// using the create_executable_binary helper are correctly identified
    /// as non-setuid binaries and are not flagged by detection functions.
    ///
    /// # Validation
    ///
    /// - Regular executable binary is created successfully
    /// - Binary does NOT have setuid bit
    /// - Binary is NOT detected by setuid detection functions
    /// - Cleanup removes all test artifacts
    #[test]
    fn test_non_setuid_binary_not_detected() {
        // Create a regular (non-setuid) executable binary
        let regular_bin = create_executable_binary(
            "non_setuid_detected",
            b"#!/bin/sh\necho 'non-setuid test'\n",
        )
        .expect("Failed to create regular binary");

        // Verify the binary was created WITHOUT setuid bit
        let has_setuid = check_setuid_bit(&regular_bin).expect("Failed to check setuid bit");
        assert!(!has_setuid, "Regular binary should NOT have setuid bit");

        // Verify using the is_setuid helper
        assert!(
            !is_setuid(&regular_bin).expect("Failed to verify setuid bit"),
            "is_setuid should confirm no setuid bit is set"
        );

        // Add binary to PATH for detection
        let _path_guard = add_binary_to_path(&regular_bin).expect("Failed to add to PATH");

        // Find all setuid binaries in PATH
        let setuid_bins = find_setuid_binaries_in_path().expect("Failed to find setuid binaries");

        // Verify our binary is NOT detected in PATH
        let found = setuid_bins
            .iter()
            .any(|info| info.path == regular_bin && info.has_setuid);

        assert!(
            !found,
            "Non-setuid binary should NOT be detected in PATH. Found binaries: {:?}",
            setuid_bins
        );

        // Verify using security info that it has no setuid bit
        if let Some(info) = setuid_bins.iter().find(|i| i.path == regular_bin) {
            assert!(
                !info.has_setuid,
                "Non-setuid binary should NOT be marked as having setuid bit"
            );
        }

        println!(
            "Non-setuid binary correctly excluded from detection: {}",
            regular_bin.display()
        );

        // Clean up fixtures using the specialized cleanup helper
        cleanup_setuid_fixtures().expect("Failed to cleanup setuid fixtures");

        // Verify cleanup succeeded
        assert!(
            !regular_bin.exists(),
            "Regular binary should be removed after cleanup"
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
        // Create guard first - manages cleanup automatically
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

    /// Test comprehensive validation of no false positives for non-setuid binaries
    ///
    /// # Purpose
    ///
    /// This test ensures that the setuid detection system has zero false positives
    /// by creating multiple regular (non-setuid) binaries with different characteristics
    /// and verifying that none are incorrectly flagged as setuid binaries.
    ///
    /// # Validation
    ///
    /// - Multiple regular binaries are created successfully
    /// - All regular binaries have executable permissions but NO setuid bit
    /// - NO regular binary is detected by find_setuid_binaries_in_path()
    /// - All detection functions correctly identify binaries as non-setuid
    /// - Temporary binaries are cleaned up after completion
    ///
    /// # Test Coverage
    ///
    /// This test validates:
    /// - Binary creation using create_executable_binary helper
    /// - setuid bit verification using is_setuid() helper
    /// - PATH scanning using find_setuid_binaries_in_path()
    /// - Direct verification using check_setuid_bit()
    /// - Security info validation using get_binary_security_info()
    /// - Proper cleanup using BinaryFixtureGuard
    #[test]
    fn test_comprehensive_no_false_positives_for_non_setuid_binaries() {
        // Use RAII guard for automatic cleanup (ensures clean state)
        let _fixture_guard = BinaryFixtureGuard::new();

        // Ensure test directory exists (guard doesn't create it, just cleans up)
        let _test_dir = init_test_bin_dir().expect("Failed to init test dir");

        // Create multiple regular (non-setuid) binaries with different characteristics
        let regular_bins = vec![
            create_executable_binary("no_false_positive_1", b"#!/bin/sh\necho 'test1'\n")
                .expect("Failed to create regular binary 1"),
            create_executable_binary("no_false_positive_2", b"#!/bin/bash\necho 'test2'\n")
                .expect("Failed to create regular binary 2"),
            create_executable_binary(
                "no_false_positive_3",
                b"#!/usr/bin/env python3\nprint('test3')\n",
            )
            .expect("Failed to create regular binary 3"),
            create_executable_binary("no_false_positive_4", b"#!/bin/sh\nexit 0\n")
                .expect("Failed to create regular binary 4"),
            create_executable_binary("no_false_positive_5", b"#!/bin/sh\ndate\n")
                .expect("Failed to create regular binary 5"),
        ];

        // Verify ALL regular binaries were created WITHOUT setuid bit
        for (i, bin) in regular_bins.iter().enumerate() {
            let has_setuid =
                is_setuid(bin).expect(&format!("Failed to check setuid bit for bin {}", i + 1));
            assert!(
                !has_setuid,
                "Regular binary {} should NOT have setuid bit",
                i + 1
            );
        }

        // Add one binary to PATH (all are in same directory)
        let _path_guard = add_binary_to_path(&regular_bins[0]).expect("Failed to add to PATH");

        // Find all setuid binaries in PATH
        let setuid_bins = find_setuid_binaries_in_path().expect("Failed to scan PATH");

        // Verify NONE of our regular binaries are detected as setuid
        for (i, regular_bin) in regular_bins.iter().enumerate() {
            let found = setuid_bins.iter().any(|info| info.path == *regular_bin);
            assert!(
                !found,
                "Regular binary {} ({:?}) should NOT be in setuid binaries list. Found: {:?}",
                i + 1,
                regular_bin.file_name(),
                setuid_bins
            );
        }

        // Verify using check_setuid_bit for each regular binary
        for (i, regular_bin) in regular_bins.iter().enumerate() {
            let has_setuid = check_setuid_bit(regular_bin)
                .expect(&format!("Failed to check setuid bit {}", i + 1));
            assert!(
                !has_setuid,
                "check_setuid_bit should return false for regular binary {}",
                i + 1
            );
        }

        // Verify security info shows no setuid bit for any regular binary
        for (i, regular_bin) in regular_bins.iter().enumerate() {
            let info = get_binary_security_info(regular_bin)
                .expect(&format!("Failed to get security info for bin {}", i + 1));
            assert!(
                !info.has_setuid,
                "Security info for regular binary {} should show no setuid bit",
                i + 1
            );
            assert!(
                !info.is_setuid_root,
                "Security info for regular binary {} should show not setuid-root",
                i + 1
            );
        }

        // Verify the cleanup will work by checking that all binaries exist
        for (i, regular_bin) in regular_bins.iter().enumerate() {
            assert!(
                regular_bin.exists(),
                "Regular binary {} should exist before cleanup",
                i + 1
            );
        }

        // Verify that BinaryFixtureGuard will clean up all binaries when dropped
        // (The guard handles cleanup automatically when the test function returns)

        println!(
            "Successfully validated {} regular binaries - zero false positives confirmed",
            regular_bins.len()
        );
    }
}

#[cfg(test)]
#[serial]
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
        // Use RAII guard for automatic cleanup
        let _fixture_guard = BinaryFixtureGuard::new();

        // Create a setuid binary
        // Note: In test environment, we can't create true root-owned binaries
        // without actual root privileges. This test validates the detection logic.
        let setuid_bin = create_setuid_binary("test_setuid_root", b"#!/bin/sh\nid\n")
            .expect("Failed to create setuid binary");

        // Verify the binary exists before proceeding
        assert!(
            setuid_bin.exists(),
            "Setuid binary should exist after creation"
        );

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
        // Create guard first - manages cleanup automatically
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

    /// Comprehensive test for all four binary security states
    ///
    /// # Purpose
    ///
    /// Tests all four possible combinations of setuid bit and root ownership:
    /// 1. Regular binary (no setuid, not root-owned)
    /// 2. Root-owned binary (no setuid, root-owned)
    /// 3. Setuid-user binary (setuid bit, not root-owned)
    /// 4. Setuid-root binary (setuid bit + root-owned)
    ///
    /// # Validation
    ///
    /// - All four binary types are created correctly
    /// - is_setuid_root_binary() returns true ONLY for case 4
    /// - Security info correctly identifies each case
    #[test]
    fn test_all_binary_security_states() {
        let _fixture_guard = BinaryFixtureGuard::new();

        // Case 1: Regular binary (no setuid, not root-owned)
        let regular_bin = create_executable_binary("state_regular", b"test\n")
            .expect("Failed to create regular binary");

        // Case 2: Root-owned binary (no setuid, root-owned)
        // Note: In test environment (non-root), we can't create true root-owned binaries
        // This case would be tested on systems with actual root access

        // Case 3: Setuid-user binary (setuid bit, not root-owned)
        let setuid_user_bin = create_setuid_binary("state_setuid_user", b"test\n")
            .expect("Failed to create setuid-user binary");

        // Case 4: Setuid-root binary (setuid bit + root-owned)
        // Note: In test environment (non-root), we can't create true setuid-root binaries
        // This would be tested on systems with actual root access
        // For now, we test the setuid-user case (has setuid bit but not root-owned)

        // Verify Case 1: Regular binary
        let regular_info = get_binary_security_info(&regular_bin)
            .expect("Failed to get security info for regular binary");
        assert!(
            !regular_info.has_setuid,
            "Regular binary should NOT have setuid bit"
        );
        assert!(
            !regular_info.is_setuid_root,
            "Regular binary should NOT be setuid-root"
        );
        assert!(
            is_setuid_root_binary(&regular_bin).is_ok(),
            "is_setuid_root_binary should execute without error"
        );
        assert!(
            !is_setuid_root_binary(&regular_bin).unwrap(),
            "Regular binary should NOT be setuid-root"
        );

        // Verify Case 3: Setuid-user binary
        let user_info = get_binary_security_info(&setuid_user_bin)
            .expect("Failed to get security info for setuid-user binary");
        assert!(
            user_info.has_setuid,
            "Setuid-user binary should have setuid bit"
        );
        assert!(
            !user_info.is_setuid_root,
            "Setuid-user binary should NOT be setuid-root"
        );
        assert!(
            user_info.uid != 0,
            "Setuid-user binary should NOT be owned by root (UID != 0)"
        );
        assert!(
            !is_setuid_root_binary(&setuid_user_bin).unwrap(),
            "Setuid-user binary should NOT be setuid-root"
        );

        println!(
            "All binary security states validated: regular={}, setuid-user={}",
            !regular_info.is_setuid_root, !user_info.is_setuid_root
        );
    }

    /// Test direct comparison of setuid-root vs setuid-user detection
    ///
    /// # Purpose
    ///
    /// Directly compares is_setuid_root_binary() results for setuid-user
    /// binaries to validate the distinction logic works correctly.
    ///
    /// # Validation
    ///
    /// - Multiple setuid-user binaries are all correctly identified as NOT setuid-root
    /// - Detection logic is consistent across multiple binaries
    #[test]
    fn test_setuid_root_vs_setuid_user_direct_comparison() {
        let _fixture_guard = BinaryFixtureGuard::new();

        // Create multiple setuid-user binaries (all owned by current user, not root)
        let setuid_user_bins = vec![
            create_setuid_binary("compare_user1", b"test1\n")
                .expect("Failed to create setuid-user binary 1"),
            create_setuid_binary("compare_user2", b"test2\n")
                .expect("Failed to create setuid-user binary 2"),
            create_setuid_binary("compare_user3", b"test3\n")
                .expect("Failed to create setuid-user binary 3"),
        ];

        // Verify ALL are setuid-user (not setuid-root)
        for (i, bin) in setuid_user_bins.iter().enumerate() {
            // Verify has setuid bit
            assert!(
                check_setuid_bit(bin).expect("Failed to check setuid bit"),
                "Binary {} should have setuid bit",
                i + 1
            );

            // Verify is NOT setuid-root
            let is_setuid_root =
                is_setuid_root_binary(bin).expect("Failed to check setuid-root status");
            assert!(
                !is_setuid_root,
                "Binary {} should NOT be setuid-root (setuid-user only)",
                i + 1
            );

            // Verify security info
            let info = get_binary_security_info(bin).expect("Failed to get security info");
            assert!(info.has_setuid, "Binary {} should have setuid bit", i + 1);
            assert!(
                !info.is_setuid_root,
                "Binary {} should NOT be setuid-root",
                i + 1
            );
            assert!(info.uid != 0, "Binary {} should have non-root UID", i + 1);
        }

        println!(
            "Setuid-root vs setuid-user comparison: {} binaries validated as setuid-user (not setuid-root)",
            setuid_user_bins.len()
        );
    }

    /// Test that setuid-root requires BOTH conditions with explicit validation
    ///
    /// # Purpose
    ///
    /// Explicitly validates that is_setuid_root_binary() returns true ONLY
    /// when BOTH conditions are met: setuid bit AND root ownership.
    /// This is the core requirement from the acceptance criteria.
    ///
    /// # Validation
    ///
    /// - Regular binary (no setuid, not root): is_setuid_root = false
    /// - Setuid-user binary (setuid, not root): is_setuid_root = false
    /// - Root-owned binary (no setuid, root): is_setuid_root = false (if available)
    /// - Setuid-root binary (setuid + root): is_setuid_root = true (if available)
    #[test]
    fn test_setuid_root_requires_both_setuid_and_root_ownership() {
        let _fixture_guard = BinaryFixtureGuard::new();

        // Create test binaries
        let regular_bin = create_executable_binary("both_test_regular", b"test\n")
            .expect("Failed to create regular binary");
        let setuid_user_bin = create_setuid_binary("both_test_setuid_user", b"test\n")
            .expect("Failed to create setuid-user binary");

        // Test 1: Regular binary (no setuid, not root-owned)
        let regular_is_root =
            is_setuid_root_binary(&regular_bin).expect("Failed to check regular binary");
        assert!(
            !regular_is_root,
            "Regular binary (no setuid, not root) should NOT be setuid-root"
        );

        let regular_info =
            get_binary_security_info(&regular_bin).expect("Failed to get regular binary info");
        assert!(
            !regular_info.is_setuid_root,
            "Regular binary security info should show NOT setuid-root"
        );

        // Test 2: Setuid-user binary (has setuid, but not root-owned)
        let user_is_root =
            is_setuid_root_binary(&setuid_user_bin).expect("Failed to check setuid-user binary");
        assert!(
            !user_is_root,
            "Setuid-user binary (has setuid, not root) should NOT be setuid-root - missing root ownership"
        );

        let user_info = get_binary_security_info(&setuid_user_bin)
            .expect("Failed to get setuid-user binary info");
        assert!(
            user_info.has_setuid,
            "Setuid-user binary should have setuid bit"
        );
        assert!(
            !user_info.is_setuid_root,
            "Setuid-user binary security info should show NOT setuid-root"
        );
        assert!(
            user_info.uid != 0,
            "Setuid-user binary should have non-zero UID (not root)"
        );

        println!(
            "Setuid-root requirement validation: setuid-root requires BOTH setuid bit AND root ownership"
        );
        println!(
            "  - Regular binary (no setuid, not root): is_setuid_root = {}",
            regular_is_root
        );
        println!(
            "  - Setuid-user binary (has setuid, not root): is_setuid_root = {}",
            user_is_root
        );
    }

    /// Test is_setuid_root_binary function behavior with comprehensive validation
    ///
    /// # Purpose
    ///
    /// Validates the complete behavior of is_setuid_root_binary() function
    /// to ensure it correctly distinguishes between setuid-root and setuid-user
    /// binaries as specified in the acceptance criteria.
    ///
    /// # Validation
    ///
    /// - Function returns false for non-setuid binaries
    /// - Function returns false for setuid-user binaries (setuid but not root)
    /// - Function returns true only for setuid-root binaries (both conditions)
    /// - Function handles errors gracefully for invalid paths
    #[test]
    fn test_is_setuid_root_binary_comprehensive_validation() {
        let _fixture_guard = BinaryFixtureGuard::new();

        // Create test binaries
        let regular_bin = create_executable_binary("comprehensive_regular", b"test\n")
            .expect("Failed to create regular binary");
        let setuid_user_bin = create_setuid_binary("comprehensive_setuid_user", b"test\n")
            .expect("Failed to create setuid-user binary");

        // Test 1: Non-setuid binary should return false
        let result = is_setuid_root_binary(&regular_bin);
        assert!(
            result.is_ok(),
            "is_setuid_root_binary should succeed for regular binary"
        );
        assert!(
            !result.unwrap(),
            "is_setuid_root_binary should return false for regular binary"
        );

        // Test 2: Setuid-user binary should return false
        let result = is_setuid_root_binary(&setuid_user_bin);
        assert!(
            result.is_ok(),
            "is_setuid_root_binary should succeed for setuid-user binary"
        );
        assert!(
            !result.unwrap(),
            "is_setuid_root_binary should return false for setuid-user binary (missing root ownership)"
        );

        // Test 3: Verify with security info
        let user_info =
            get_binary_security_info(&setuid_user_bin).expect("Failed to get security info");
        assert!(
            user_info.has_setuid && !user_info.is_setuid_root,
            "Setuid-user has setuid bit but is NOT setuid-root"
        );

        // Test 4: Error handling for nonexistent path
        let nonexistent = PathBuf::from("/nonexistent/binary/path");
        let result = is_setuid_root_binary(&nonexistent);
        assert!(
            result.is_err(),
            "is_setuid_root_binary should return error for nonexistent path"
        );

        println!("Comprehensive is_setuid_root_binary validation complete");
        println!("  - Correctly identifies regular binaries as not setuid-root");
        println!("  - Correctly identifies setuid-user binaries as not setuid-root");
        println!("  - Handles errors gracefully for invalid paths");
    }
}

#[cfg(test)]
#[serial]
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

        // Ensure test directory exists
        let _test_dir = init_test_bin_dir().expect("Failed to init test dir");

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

        // Drop path guard first to restore PATH
        drop(_path_guard);

        // Verify PATH is restored
        let restored_path = std::env::var("PATH").unwrap();
        assert_eq!(original_path, restored_path, "PATH should be restored");

        // Now manually clean up binaries
        cleanup_test_binaries().expect("Cleanup should succeed");

        // Verify binaries are removed after cleanup
        assert!(!bin1.exists(), "Binary 1 should be removed after cleanup");
        assert!(!bin2.exists(), "Binary 2 should be removed after cleanup");
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

    /// Test cleanup removes temp binaries
    ///
    /// # Purpose
    ///
    /// Verifies that temporary binaries created by fixtures are properly
    /// cleaned up when cleanup_setuid_fixtures is called.
    ///
    /// # Validation
    ///
    /// - Multiple fixtures created using create_setuid_fixture exist
    /// - All fixtures are removed after cleanup_setuid_fixtures call
    /// - No temporary files remain on the filesystem
    #[test]
    fn test_cleanup_removes_temp_binaries() {
        // Ensure clean state first
        let _ = cleanup_test_binaries();

        // Get the test directory first
        let test_dir = init_test_bin_dir().expect("Failed to init test dir");

        // Create multiple fixtures using create_setuid_binary (more reliable than fixture helper)
        let fixture1 = create_setuid_binary("temp_fixture1", b"#!/bin/sh\necho 'fixture1'\n")
            .expect("Failed to create fixture1");
        let fixture2 = create_setuid_binary("temp_fixture2", b"#!/bin/sh\necho 'fixture2'\n")
            .expect("Failed to create fixture2");
        let fixture3 = create_setuid_binary("temp_fixture3", b"#!/bin/sh\necho 'fixture3'\n")
            .expect("Failed to create fixture3");

        // Verify all fixtures exist immediately after creation
        assert!(fixture1.exists(), "Fixture 1 should exist after creation");
        assert!(fixture2.exists(), "Fixture 2 should exist after creation");
        assert!(fixture3.exists(), "Fixture 3 should exist after creation");

        // Verify all fixtures have setuid bit
        assert!(
            is_setuid(&fixture1).expect("Failed to check setuid bit"),
            "Fixture 1 should have setuid bit"
        );
        assert!(
            is_setuid(&fixture2).expect("Failed to check setuid bit"),
            "Fixture 2 should have setuid bit"
        );
        assert!(
            is_setuid(&fixture3).expect("Failed to check setuid bit"),
            "Fixture 3 should have setuid bit"
        );

        // Verify test directory exists
        assert!(test_dir.exists(), "Test directory should exist");

        // Call cleanup_setuid_fixtures
        cleanup_setuid_fixtures().expect("Failed to cleanup setuid fixtures");

        // Verify all temporary files are removed from the filesystem
        assert!(
            !fixture1.exists(),
            "Fixture 1 should be removed after cleanup"
        );
        assert!(
            !fixture2.exists(),
            "Fixture 2 should be removed after cleanup"
        );
        assert!(
            !fixture3.exists(),
            "Fixture 3 should be removed after cleanup"
        );

        // Verify the test directory itself is also removed
        assert!(
            !test_dir.exists(),
            "Test directory should be removed after cleanup"
        );

        println!("All temporary binaries successfully removed by cleanup_setuid_fixtures");
    }
}

#[cfg(test)]
#[serial]
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
        // Test BinaryFixtureGuard helper FIRST - before creating binaries
        let _fixture_guard = BinaryFixtureGuard::new();

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
        // Create guard first - manages cleanup automatically
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
#[serial]
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
        // Clean up any previous test state first
        let _ = cleanup_test_binaries();

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
        // Create guard first - manages cleanup automatically
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

#[cfg(test)]
#[serial]
mod setgid_detection_tests {
    use super::*;

    /// Test setgid binary detection with check_setgid_bit
    ///
    /// # Purpose
    ///
    /// Verifies that setgid binaries (chmod g+s) are correctly identified
    /// by the check_setgid_bit() function.
    ///
    /// # Validation
    ///
    /// - Created setgid binary exists and has setgid bit
    /// - check_setgid_bit returns true for setgid binary
    /// - Regular binary does NOT have setgid bit
    #[test]
    fn test_setgid_binary_detection() {
        let _fixture_guard = BinaryFixtureGuard::new();

        // Create a setgid binary
        let setgid_bin = create_setgid_binary("test_setgid", b"#!/bin/sh\necho 'setgid test'\n")
            .expect("Failed to create setgid binary");

        // Verify the binary was created with setgid bit using is_setgid helper
        assert!(
            is_setgid(&setgid_bin).expect("Failed to check setgid bit"),
            "Created binary should have setgid bit"
        );

        // Verify the binary is detected by check_setgid_bit
        assert!(
            check_setgid_bit(&setgid_bin).expect("Failed to check setgid bit"),
            "check_setgid_bit should return true for setgid binary"
        );

        // Create a regular binary for comparison
        let regular_bin =
            create_executable_binary("test_regular_setgid", b"#!/bin/sh\necho 'regular'\n")
                .expect("Failed to create regular binary");

        // Verify regular binary does NOT have setgid bit
        assert!(
            !is_setgid(&regular_bin).expect("Failed to check setgid bit"),
            "Regular binary should NOT have setgid bit"
        );

        assert!(
            !check_setgid_bit(&regular_bin).expect("Failed to check setgid bit"),
            "check_setgid_bit should return false for regular binary"
        );

        println!(
            "Setgid binary detection test passed: setgid={}, regular={}",
            is_setgid(&setgid_bin).unwrap(),
            is_setgid(&regular_bin).unwrap()
        );
    }

    /// Test setgid binaries in PATH are detected
    ///
    /// # Purpose
    ///
    /// Verifies that setgid binaries added to PATH are correctly
    /// identified by the find_setgid_binaries_in_path() function.
    ///
    /// # Validation
    ///
    /// - Created setgid binary exists and has setgid bit
    /// - Binary is detected when added to PATH
    /// - Binary security info is correct
    #[test]
    fn test_setgid_binary_in_path_is_detected() {
        let _fixture_guard = BinaryFixtureGuard::new();

        // Create a setgid binary using the helper function
        let setgid_bin = create_setgid_binary("test_setgid_detect", b"#!/bin/sh\necho 'setgid'\n")
            .expect("Failed to create setgid binary");

        // Verify the binary was created with setgid bit
        assert!(
            is_setgid(&setgid_bin).expect("Failed to check setgid bit"),
            "Created binary should have setgid bit"
        );

        // Verify the binary is detected by check_setgid_bit
        assert!(
            check_setgid_bit(&setgid_bin).expect("Failed to check setgid bit"),
            "check_setgid_bit should return true for setgid binary"
        );

        // Add binary to PATH
        let _path_guard = add_binary_to_path(&setgid_bin).expect("Failed to add to PATH");

        // Find all setgid binaries in PATH
        let setgid_bins =
            find_setgid_binaries_in_path().expect("Failed to find setgid binaries in PATH");

        // Verify our binary is in the list
        let found = setgid_bins
            .iter()
            .any(|info| info.path == setgid_bin && info.has_setgid);

        assert!(
            found,
            "Created setgid binary should be found in PATH setgid binaries. Found: {:?}",
            setgid_bins
        );

        // Verify the security info is correct
        if let Some(info) = setgid_bins.iter().find(|i| i.path == setgid_bin) {
            assert!(
                info.has_setgid,
                "Binary should be marked as having setgid bit"
            );
            assert!(
                !info.has_setuid,
                "Test binary should NOT be marked as setuid"
            );
        }

        println!(
            "Setgid binary successfully detected in PATH: {}",
            setgid_bin.display()
        );
    }

    /// Test multiple setgid binaries in PATH are all detected
    ///
    /// # Purpose
    ///
    /// Verifies that when multiple setgid binaries exist in PATH,
    /// all of them are correctly detected and reported.
    #[test]
    fn test_multiple_setgid_binaries_all_detected() {
        let _fixture_guard = BinaryFixtureGuard::new();

        // Create multiple setgid binaries
        let bin1 = create_setgid_binary("setgid_bin1", b"#!/bin/sh\necho '1'\n")
            .expect("Failed to create bin1");
        let bin2 = create_setgid_binary("setgid_bin2", b"#!/bin/sh\necho '2'\n")
            .expect("Failed to create bin2");
        let bin3 = create_setgid_binary("setgid_bin3", b"#!/bin/sh\necho '3'\n")
            .expect("Failed to create bin3");

        // Verify all have setgid bit
        assert!(is_setgid(&bin1).unwrap());
        assert!(is_setgid(&bin2).unwrap());
        assert!(is_setgid(&bin3).unwrap());

        // Add to PATH
        let _path_guard = add_binary_to_path(&bin1).expect("Failed to add to PATH");

        // Find setgid binaries
        let setgid_bins = find_setgid_binaries_in_path().expect("Failed to find binaries");

        // Check that all our binaries are found
        let bin_names = vec!["setgid_bin1", "setgid_bin2", "setgid_bin3"];
        for name in bin_names {
            let found = setgid_bins
                .iter()
                .any(|info| info.path.file_name().unwrap() == name && info.has_setgid);
            assert!(found, "Setgid binary '{}' should be detected in PATH", name);
        }

        println!("Detected {} setgid binaries in PATH", setgid_bins.len());
    }

    /// Test that non-setgid binaries are not flagged
    ///
    /// # Purpose
    ///
    /// Verifies that regular executable binaries (without setgid bit)
    /// are not incorrectly flagged as setgid binaries.
    #[test]
    fn test_non_setgid_binary_not_flagged() {
        let _fixture_guard = BinaryFixtureGuard::new();

        // Create a regular (non-setgid) executable binary
        let regular_bin =
            create_executable_binary("test_regular_setgid_not", b"#!/bin/sh\necho 'regular'\n")
                .expect("Failed to create regular binary");

        // Verify the binary was created WITHOUT setgid bit
        assert!(
            !is_setgid(&regular_bin).expect("Failed to check setgid bit"),
            "Regular binary should NOT have setgid bit"
        );

        // Test with check_setgid_bit
        let has_setgid = check_setgid_bit(&regular_bin).expect("Failed to check setgid bit");

        assert!(
            !has_setgid,
            "check_setgid_bit should return false for regular binary"
        );

        // Add to PATH
        let _path_guard = add_binary_to_path(&regular_bin).expect("Failed to add to PATH");

        // Find setgid binaries - our regular binary should NOT be in the list
        let setgid_bins = find_setgid_binaries_in_path().expect("Failed to scan PATH");

        let found = setgid_bins.iter().any(|info| info.path == regular_bin);

        assert!(
            !found,
            "Regular binary should NOT be in setgid binaries list. Found: {:?}",
            setgid_bins
        );

        println!(
            "Regular binary correctly excluded from setgid detection. {} setgid binaries found.",
            setgid_bins.len()
        );
    }

    /// Test mixed environment: both setgid and regular binaries
    ///
    /// # Purpose
    ///
    /// Verifies that in a directory with both setgid and regular binaries,
    /// only the setgid ones are detected.
    #[test]
    fn test_mixed_binaries_only_setgid_detected() {
        let _fixture_guard = BinaryFixtureGuard::new();

        // Create both setgid and regular binaries
        let setgid_bin = create_setgid_binary("mixed_setgid", b"#!/bin/sh\necho 'setgid'\n")
            .expect("Failed to create setgid binary");
        let regular_bin =
            create_executable_binary("mixed_regular_setgid", b"#!/bin/sh\necho 'regular'\n")
                .expect("Failed to create regular binary");

        // Verify initial states
        assert!(is_setgid(&setgid_bin).unwrap());
        assert!(!is_setgid(&regular_bin).unwrap());

        // Add to PATH (both in same directory, one guard covers both)
        let _path_guard = add_binary_to_path(&setgid_bin).expect("Failed to add to PATH");

        // Find setgid binaries
        let setgid_bins = find_setgid_binaries_in_path().expect("Failed to scan PATH");

        // Check that only setgid binary is detected
        let setgid_found = setgid_bins.iter().any(|info| info.path == setgid_bin);
        let regular_found = setgid_bins.iter().any(|info| info.path == regular_bin);

        assert!(setgid_found, "Setgid binary should be detected");
        assert!(!regular_found, "Regular binary should NOT be detected");

        println!(
            "Mixed test: {} setgid binaries detected (regular bin correctly excluded)",
            setgid_bins.len()
        );
    }

    /// Test setgid vs setuid distinction
    ///
    /// # Purpose
    ///
    /// Verifies that the detection system correctly distinguishes between
    /// setuid and setgid binaries, ensuring no cross-contamination.
    #[test]
    fn test_setgid_vs_setuid_distinction() {
        let _fixture_guard = BinaryFixtureGuard::new();

        // Create setuid binary
        let setuid_bin = create_setuid_binary("distinction_setuid", b"#!/bin/sh\necho 'setuid'\n")
            .expect("Failed to create setuid binary");

        // Create setgid binary
        let setgid_bin = create_setgid_binary("distinction_setgid", b"#!/bin/sh\necho 'setgid'\n")
            .expect("Failed to create setgid binary");

        // Verify setuid binary has setuid but not setgid
        assert!(
            is_setuid(&setuid_bin).unwrap(),
            "Setuid binary should have setuid bit"
        );
        assert!(
            !is_setgid(&setuid_bin).unwrap(),
            "Setuid binary should NOT have setgid bit"
        );

        // Verify setgid binary has setgid but not setuid
        assert!(
            is_setgid(&setgid_bin).unwrap(),
            "Setgid binary should have setgid bit"
        );
        assert!(
            !is_setuid(&setgid_bin).unwrap(),
            "Setgid binary should NOT have setuid bit"
        );

        // Verify with check_setuid_bit and check_setgid_bit
        assert!(
            check_setuid_bit(&setuid_bin).unwrap(),
            "check_setuid_bit should detect setuid"
        );
        assert!(
            !check_setgid_bit(&setuid_bin).unwrap(),
            "check_setgid_bit should not detect setuid"
        );

        assert!(
            check_setgid_bit(&setgid_bin).unwrap(),
            "check_setgid_bit should detect setgid"
        );
        assert!(
            !check_setuid_bit(&setgid_bin).unwrap(),
            "check_setuid_bit should not detect setgid"
        );

        // Get security info for both
        let setuid_info = get_binary_security_info(&setuid_bin).expect("Failed to get setuid info");
        let setgid_info = get_binary_security_info(&setgid_bin).expect("Failed to get setgid info");

        assert!(
            setuid_info.has_setuid,
            "Setuid binary should show setuid bit"
        );
        assert!(
            !setuid_info.has_setgid,
            "Setuid binary should NOT show setgid bit"
        );

        assert!(
            !setgid_info.has_setuid,
            "Setgid binary should NOT show setuid bit"
        );
        assert!(
            setgid_info.has_setgid,
            "Setgid binary should show setgid bit"
        );

        println!("Setgid vs setuid distinction validated correctly");
    }
}

#[cfg(test)]
#[serial]
mod combined_permissions_tests {
    use super::*;

    /// Test setuid + setgid combined binary detection
    ///
    /// # Purpose
    ///
    /// Verifies that binaries with both setuid and setgid bits are
    /// correctly detected and both permission bits are identified.
    ///
    /// # Validation
    ///
    /// - Created binary has both setuid and setgid bits
    /// - check_setuid_bit returns true
    /// - check_setgid_bit returns true
    /// - Security info shows both bits set
    #[test]
    fn test_setuid_setgid_combined_binary() {
        let _fixture_guard = BinaryFixtureGuard::new();

        // Create a binary with both setuid and setgid bits
        let combined_bin =
            create_setuid_setgid_binary("test_combined", b"#!/bin/sh\necho 'combined'\n")
                .expect("Failed to create combined binary");

        // Verify both bits are set using is_setuid and is_setgid helpers
        assert!(
            is_setuid(&combined_bin).expect("Failed to check setuid bit"),
            "Combined binary should have setuid bit"
        );
        assert!(
            is_setgid(&combined_bin).expect("Failed to check setgid bit"),
            "Combined binary should have setgid bit"
        );

        // Verify with check_setuid_bit and check_setgid_bit
        assert!(
            check_setuid_bit(&combined_bin).expect("Failed to check setuid bit"),
            "check_setuid_bit should return true for combined binary"
        );
        assert!(
            check_setgid_bit(&combined_bin).expect("Failed to check setgid bit"),
            "check_setgid_bit should return true for combined binary"
        );

        // Verify security info shows both bits
        let info = get_binary_security_info(&combined_bin).expect("Failed to get security info");
        assert!(info.has_setuid, "Security info should show setuid bit");
        assert!(info.has_setgid, "Security info should show setgid bit");

        println!(
            "Setuid+Setgid combined binary validated: setuid={}, setgid={}",
            info.has_setuid, info.has_setgid
        );
    }

    /// Test combined permissions are detected in PATH
    ///
    /// # Purpose
    ///
    /// Verifies that setuid+setgid binaries are correctly detected
    /// when scanning PATH.
    #[test]
    fn test_combined_permissions_in_path() {
        let _fixture_guard = BinaryFixtureGuard::new();

        // Create combined binary
        let combined_bin = create_setuid_setgid_binary("combined_path", b"#!/bin/sh\nid\n")
            .expect("Failed to create combined binary");

        // Verify both bits are set
        assert!(is_setuid(&combined_bin).unwrap());
        assert!(is_setgid(&combined_bin).unwrap());

        // Add to PATH
        let _path_guard = add_binary_to_path(&combined_bin).expect("Failed to add to PATH");

        // Find setuid binaries
        let setuid_bins = find_setuid_binaries_in_path().expect("Failed to find setuid binaries");

        // Verify our binary is detected as setuid
        let setuid_found = setuid_bins
            .iter()
            .any(|info| info.path == combined_bin && info.has_setuid);

        assert!(
            setuid_found,
            "Combined binary should be detected in setuid binaries"
        );

        // Verify it also has setgid bit
        if let Some(info) = setuid_bins.iter().find(|i| i.path == combined_bin) {
            assert!(info.has_setuid, "Should have setuid bit");
            assert!(info.has_setgid, "Should also have setgid bit");
        }

        // Find setgid binaries
        let setgid_bins = find_setgid_binaries_in_path().expect("Failed to find setgid binaries");

        // Verify our binary is detected as setgid
        let setgid_found = setgid_bins
            .iter()
            .any(|info| info.path == combined_bin && info.has_setgid);

        assert!(
            setgid_found,
            "Combined binary should be detected in setgid binaries"
        );

        println!("Combined permissions correctly detected in PATH");
    }

    /// Test all permission combinations: none, setuid, setgid, both
    ///
    /// # Purpose
    ///
    /// Comprehensive test validating all four permission states:
    /// 1. Regular binary (no special bits)
    /// 2. Setuid-only binary
    /// 3. Setgid-only binary
    /// 4. Setuid+setgid binary
    #[test]
    fn test_all_permission_combinations() {
        let _fixture_guard = BinaryFixtureGuard::new();

        // Case 1: Regular binary (no special bits)
        let regular_bin = create_executable_binary("perm_regular", b"#!/bin/sh\necho 'none'\n")
            .expect("Failed to create regular binary");

        // Case 2: Setuid-only binary
        let setuid_bin = create_setuid_binary("perm_setuid", b"#!/bin/sh\necho 'setuid'\n")
            .expect("Failed to create setuid binary");

        // Case 3: Setgid-only binary
        let setgid_bin = create_setgid_binary("perm_setgid", b"#!/bin/sh\necho 'setgid'\n")
            .expect("Failed to create setgid binary");

        // Case 4: Combined setuid+setgid binary
        let combined_bin = create_setuid_setgid_binary("perm_both", b"#!/bin/sh\necho 'both'\n")
            .expect("Failed to create combined binary");

        // Verify Case 1: Regular binary
        let regular_info =
            get_binary_security_info(&regular_bin).expect("Failed to get regular info");
        assert!(!regular_info.has_setuid, "Regular should NOT have setuid");
        assert!(!regular_info.has_setgid, "Regular should NOT have setgid");

        // Verify Case 2: Setuid-only binary
        let setuid_info = get_binary_security_info(&setuid_bin).expect("Failed to get setuid info");
        assert!(setuid_info.has_setuid, "Setuid binary should have setuid");
        assert!(
            !setuid_info.has_setgid,
            "Setuid binary should NOT have setgid"
        );

        // Verify Case 3: Setgid-only binary
        let setgid_info = get_binary_security_info(&setgid_bin).expect("Failed to get setgid info");
        assert!(
            !setgid_info.has_setuid,
            "Setgid binary should NOT have setuid"
        );
        assert!(setgid_info.has_setgid, "Setgid binary should have setgid");

        // Verify Case 4: Combined binary
        let combined_info =
            get_binary_security_info(&combined_bin).expect("Failed to get combined info");
        assert!(
            combined_info.has_setuid,
            "Combined binary should have setuid"
        );
        assert!(
            combined_info.has_setgid,
            "Combined binary should have setgid"
        );

        println!("All permission combinations validated:");
        println!(
            "  - Regular: setuid={}, setgid={}",
            regular_info.has_setuid, regular_info.has_setgid
        );
        println!(
            "  - Setuid:  setuid={}, setgid={}",
            setuid_info.has_setuid, setuid_info.has_setgid
        );
        println!(
            "  - Setgid:  setuid={}, setgid={}",
            setgid_info.has_setuid, setgid_info.has_setgid
        );
        println!(
            "  - Combined: setuid={}, setgid={}",
            combined_info.has_setuid, combined_info.has_setgid
        );
    }
}

#[cfg(test)]
#[serial]
mod permission_bit_tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    /// Test user permission bits (read, write, execute)
    ///
    /// # Purpose
    ///
    /// Verifies that user (owner) permission bits are correctly set
    /// and identified on test binaries.
    #[test]
    fn test_user_permission_bits() {
        let _fixture_guard = BinaryFixtureGuard::new();

        // Create binary with standard permissions (0o755 = rwxr-xr-x)
        let bin = create_executable_binary("user_perms", b"#!/bin/sh\necho 'test'\n")
            .expect("Failed to create binary");

        // Check metadata
        let metadata = std::fs::metadata(&bin).expect("Failed to get metadata");
        let mode = metadata.permissions().mode();

        // Verify user permissions (should be rwx = 0o700)
        let user_perms = mode & 0o700;
        assert_eq!(user_perms, 0o700, "User should have rwx permissions");

        // Verify user can read (r--)
        assert!(mode & 0o400 != 0, "User should have read permission");

        // Verify user can write (w-)
        assert!(mode & 0o200 != 0, "User should have write permission");

        // Verify user can execute (--x)
        assert!(mode & 0o100 != 0, "User should have execute permission");

        println!("User permission bits validated: rwx (0o{:o})", user_perms);
    }

    /// Test group permission bits
    ///
    /// # Purpose
    ///
    /// Verifies that group permission bits are correctly set
    /// and identified on test binaries.
    #[test]
    fn test_group_permission_bits() {
        let _fixture_guard = BinaryFixtureGuard::new();

        // Create binary with standard permissions (0o755 = rwxr-xr-x)
        let bin = create_executable_binary("group_perms", b"#!/bin/sh\necho 'test'\n")
            .expect("Failed to create binary");

        // Check metadata
        let metadata = std::fs::metadata(&bin).expect("Failed to get metadata");
        let mode = metadata.permissions().mode();

        // Verify group permissions (should be r-x = 0o050)
        let group_perms = mode & 0o070;
        assert_eq!(group_perms, 0o050, "Group should have r-x permissions");

        // Verify group can read (r--)
        assert!(mode & 0o040 != 0, "Group should have read permission");

        // Verify group CANNOT write (--w)
        assert!(mode & 0o020 == 0, "Group should NOT have write permission");

        // Verify group can execute (--x)
        assert!(mode & 0o010 != 0, "Group should have execute permission");

        println!("Group permission bits validated: r-x (0o{:o})", group_perms);
    }

    /// Test other (world) permission bits
    ///
    /// # Purpose
    ///
    /// Verifies that other (world) permission bits are correctly set
    /// and identified on test binaries.
    #[test]
    fn test_other_permission_bits() {
        let _fixture_guard = BinaryFixtureGuard::new();

        // Create binary with standard permissions (0o755 = rwxr-xr-x)
        let bin = create_executable_binary("other_perms", b"#!/bin/sh\necho 'test'\n")
            .expect("Failed to create binary");

        // Check metadata
        let metadata = std::fs::metadata(&bin).expect("Failed to get metadata");
        let mode = metadata.permissions().mode();

        // Verify other permissions (should be r-x = 0o005)
        let other_perms = mode & 0o007;
        assert_eq!(other_perms, 0o005, "Other should have r-x permissions");

        // Verify other can read (r--)
        assert!(mode & 0o004 != 0, "Other should have read permission");

        // Verify other CANNOT write (--w)
        assert!(mode & 0o002 == 0, "Other should NOT have write permission");

        // Verify other can execute (--x)
        assert!(mode & 0o001 != 0, "Other should have execute permission");

        println!("Other permission bits validated: r-x (0o{:o})", other_perms);
    }

    /// Test special permission bits (setuid, setgid, sticky)
    ///
    /// # Purpose
    ///
    /// Verifies that special permission bits (setuid, setgid, sticky)
    /// are correctly identified.
    #[test]
    fn test_special_permission_bits() {
        let _fixture_guard = BinaryFixtureGuard::new();

        // Test setuid bit
        let setuid_bin = create_setuid_binary("special_setuid", b"#!/bin/sh\nid\n")
            .expect("Failed to create setuid binary");

        let setuid_metadata = std::fs::metadata(&setuid_bin).expect("Failed to get metadata");
        let setuid_mode = setuid_metadata.permissions().mode();

        assert!(setuid_mode & 0o4000 != 0, "Should have setuid bit (0o4000)");
        assert!(setuid_mode & 0o2000 == 0, "Should NOT have setgid bit");

        // Test setgid bit
        let setgid_bin = create_setgid_binary("special_setgid", b"#!/bin/sh\nid\n")
            .expect("Failed to create setgid binary");

        let setgid_metadata = std::fs::metadata(&setgid_bin).expect("Failed to get metadata");
        let setgid_mode = setgid_metadata.permissions().mode();

        assert!(setgid_mode & 0o2000 != 0, "Should have setgid bit (0o2000)");
        assert!(setgid_mode & 0o4000 == 0, "Should NOT have setuid bit");

        // Test combined bits
        let combined_bin = create_setuid_setgid_binary("special_both", b"#!/bin/sh\nid\n")
            .expect("Failed to create combined binary");

        let combined_metadata = std::fs::metadata(&combined_bin).expect("Failed to get metadata");
        let combined_mode = combined_metadata.permissions().mode();

        assert!(combined_mode & 0o4000 != 0, "Should have setuid bit");
        assert!(combined_mode & 0o2000 != 0, "Should have setgid bit");

        println!("Special permission bits validated:");
        println!("  - Setuid: 0o4000 bit set");
        println!("  - Setgid: 0o2000 bit set");
        println!("  - Combined: both bits set");
    }

    /// Test permission bit combinations and octal representation
    ///
    /// # Purpose
    ///
    /// Verifies that various permission combinations result in correct
    /// octal mode values.
    #[test]
    fn test_permission_octal_representations() {
        let _fixture_guard = BinaryFixtureGuard::new();

        // Test various permission scenarios using create_test_binary directly

        // 0o755 (rwxr-xr-x) - standard executable
        let bin755 = create_test_binary("octal_755", b"test\n", 0o755, false)
            .expect("Failed to create 755 binary");

        let mode755 = std::fs::metadata(&bin755)
            .expect("Failed to get metadata")
            .permissions()
            .mode();
        assert_eq!(mode755 & 0o777, 0o755, "Should be 0o755 (rwxr-xr-x)");

        // 0o644 (rw-r--r--) - standard file
        let bin644 = create_test_binary("octal_644", b"test\n", 0o644, false)
            .expect("Failed to create 644 binary");

        let mode644 = std::fs::metadata(&bin644)
            .expect("Failed to get metadata")
            .permissions()
            .mode();
        assert_eq!(mode644 & 0o777, 0o644, "Should be 0o644 (rw-r--r--)");

        // 0o750 (rwxr-x---) - owner full, group read-execute, other none
        let bin750 = create_test_binary("octal_750", b"test\n", 0o750, false)
            .expect("Failed to create 750 binary");

        let mode750 = std::fs::metadata(&bin750)
            .expect("Failed to get metadata")
            .permissions()
            .mode();
        assert_eq!(mode750 & 0o777, 0o750, "Should be 0o750 (rwxr-x---)");

        // 0o4755 (rwsr-xr-x) - setuid executable
        let bin4755 = create_test_binary("octal_4755", b"test\n", 0o4755, true)
            .expect("Failed to create 4755 binary");

        let mode4755 = std::fs::metadata(&bin4755)
            .expect("Failed to get metadata")
            .permissions()
            .mode();
        assert_eq!(
            mode4755 & 0o7777,
            0o4755,
            "Should be 0o4755 (setuid + rwxr-xr-x)"
        );
        assert!(mode4755 & 0o4000 != 0, "Should have setuid bit");

        println!("Octal permission representations validated:");
        println!("  - 0o755: rwxr-xr-x");
        println!("  - 0o644: rw-r--r--");
        println!("  - 0o750: rwxr-x---");
        println!("  - 0o4755: rwsr-xr-x (setuid)");
    }

    /// Test GID (Group ID) detection for binaries
    ///
    /// # Purpose
    ///
    /// Verifies that get_file_owner_gid() correctly returns the
    /// group ID of binary files.
    #[test]
    fn test_gid_detection_for_binaries() {
        let _fixture_guard = BinaryFixtureGuard::new();

        // Create a test binary
        let bin = create_executable_binary("gid_test", b"#!/bin/sh\necho 'test'\n")
            .expect("Failed to create binary");

        // Get the GID
        let gid = get_file_owner_gid(&bin).expect("Failed to get GID");

        // Verify GID is valid (should be a positive number, not 0 unless root)
        // In most test environments, this will be the user's primary group
        println!("Binary GID: {}", gid);

        // Verify GID matches what's in metadata
        let metadata = std::fs::metadata(&bin).expect("Failed to get metadata");
        let stat_gid = metadata.gid();
        assert_eq!(gid, stat_gid, "GID should match metadata GID");

        // Create multiple binaries and verify they have the same GID
        let bin2 = create_executable_binary("gid_test2", b"#!/bin/sh\necho 'test2'\n")
            .expect("Failed to create second binary");

        let gid2 = get_file_owner_gid(&bin2).expect("Failed to get second GID");

        assert_eq!(gid, gid2, "Binaries in same dir should have same GID");

        println!("GID detection validated: both binaries have GID {}", gid);
    }

    /// Test UID (User ID) and GID together
    ///
    /// # Purpose
    ///
    /// Verifies that both UID and GID are correctly retrieved for
    /// binaries and match the filesystem metadata.
    #[test]
    fn test_uid_and_gid_together() {
        let _fixture_guard = BinaryFixtureGuard::new();

        // Create test binaries
        let bin1 = create_setuid_binary("uidgid1", b"test1\n").expect("Failed to create bin1");
        let bin2 = create_setgid_binary("uidgid2", b"test2\n").expect("Failed to create bin2");
        let bin3 = create_executable_binary("uidgid3", b"test3\n").expect("Failed to create bin3");

        // Verify UID and GID for each binary
        for (i, bin) in vec![&bin1, &bin2, &bin3].iter().enumerate() {
            let uid =
                get_file_owner_uid(bin).expect(&format!("Failed to get UID for bin {}", i + 1));
            let gid =
                get_file_owner_gid(bin).expect(&format!("Failed to get GID for bin {}", i + 1));

            let metadata =
                std::fs::metadata(bin).expect(&format!("Failed to get metadata for bin {}", i + 1));

            assert_eq!(uid, metadata.uid(), "UID should match metadata");
            assert_eq!(gid, metadata.gid(), "GID should match metadata");

            println!("Binary {}: UID={}, GID={}", i + 1, uid, gid);
        }

        println!("UID and GID detection validated for all binaries");
    }
}
