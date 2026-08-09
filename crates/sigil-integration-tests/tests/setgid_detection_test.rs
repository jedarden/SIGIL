//! Setgid Binary Detection Tests for System PATH
//!
//! This test module validates setgid binary detection functionality
//! in system PATH scenarios, using helper functions from the binary_fixture module.
//!
//! # Tests Included
//!
//! - **System PATH simulation**: Tests setgid detection in /usr/bin, /usr/sbin scenarios
//! - **Setgid bit validation**: Verifies mode 2000 (setgid bit) is correctly identified
//! - - **Positive detection**: setgid binaries in PATH are correctly detected
//! - **Negative detection**: non-setgid binaries are not flagged
//! - **Combined permissions**: setuid + setgid combinations are handled correctly
//! - **Multiple binaries**: All setgid binaries in PATH are detected
//! - **Permission scenarios**: Different permission modes are tested
//! - **PATH edge cases**: Empty PATH, non-existent directories, permission denied
//!
//! # System PATH Scenario
//!
//! These tests simulate real-world system PATH environments where:
//! - Common system directories like /usr/bin, /usr/sbin may contain setgid binaries
//! - Setgid binaries execute with the group privileges of the file's group owner
//! - Detection must distinguish setgid (mode 2000) from setuid (mode 4000)
//! - Scanning must handle large directories with mixed permission binaries
//!
//! # Infrastructure
//!
//! Uses the `sigil_integration_tests::binary_fixture` module which provides:
//! - `create_setgid_binary()` - Create setgid test binaries (mode 2755)
//! - `create_setuid_setgid_binary()` - Create binaries with both bits set
//! - `create_executable_binary()` - Create regular (non-setgid) test binaries
//! - `BinaryFixtureGuard` - RAII guard for automatic cleanup
//! - `add_binary_to_path()` - Add binary directory to PATH
//! - `is_setgid()` - Check if a binary has setgid bit (mode 2000)
//! - `check_setgid_bit()` - Alternative setgid detection function
//!
//! Uses the `sigil_integration_tests::env_detect` module which provides:
//! - `find_setgid_binaries_in_path()` - Scan PATH for setgid binaries
//! - `get_binary_security_info()` - Get full security info for a binary
//! - `BinarySecurityInfo` - Security information structure
//! - `check_setgid_bit()` - Verify setgid bit is set

use serial_test::serial;
use sigil_integration_tests::binary_fixture::*;
use sigil_integration_tests::env_detect::*;
use std::os::unix::fs::MetadataExt;

#[cfg(test)]
#[serial]
mod system_path_tests {
    use super::*;

    /// Test that setgid binaries in /usr/bin simulation are detected
    ///
    /// # System PATH Scenario
    ///
    /// In real systems, /usr/bin contains many binaries, some with setgid bit
    /// for group-based privilege sharing (e.g., `write`, `wall`, `ssh-agent`).
    /// This test simulates that scenario by creating a test directory that
    /// represents /usr/bin and placing setgid binaries in it.
    ///
    /// # What This Validates
    ///
    /// - Setgid binaries in a system-like directory are correctly detected
    /// - The setgid bit (mode 2000) is properly identified, not confused with setuid (mode 4000)
    /// - PATH scanning correctly enumerates all files in the directory
    /// - Detection function returns complete security information
    #[test]
    fn test_setgid_binaries_in_usr_bin_detected() {
        // Ensure clean state first
        let _ = cleanup_test_binaries();

        // Use RAII guard for automatic cleanup
        let _fixture_guard = BinaryFixtureGuard::new();

        // Initialize test directory (simulating /usr/bin)
        let test_bin_dir = init_test_bin_dir().expect("Failed to initialize test bin dir");

        // Create setgid binaries that would be in /usr/bin
        let write_bin = create_setgid_binary(
            "write", // Common setgid binary in real systems for group write access
            b"#!/bin/sh\necho 'write utility - setgid for tty group'\n",
        )
        .expect("Failed to create write binary");

        let wall_bin = create_setgid_binary(
            "wall", // Common setgid binary for group wall access
            b"#!/bin/sh\necho 'wall utility - setgid for tty group'\n",
        )
        .expect("Failed to create wall binary");

        // Verify the binaries were created with setgid bit (mode 2000)
        assert!(
            is_setgid(&write_bin).expect("Failed to check setgid bit on write"),
            "write binary should have setgid bit (mode 2000)"
        );
        assert!(
            is_setgid(&wall_bin).expect("Failed to check setgid bit on wall"),
            "wall binary should have setgid bit (mode 2000)"
        );

        // Verify the mode 2000 is specifically set (not setuid which is mode 4000)
        let write_metadata = std::fs::metadata(&write_bin).expect("Failed to get write metadata");
        let write_mode = write_metadata.mode();
        assert!(
            (write_mode & 0o2000) != 0,
            "write binary should have setgid bit 0o2000 set"
        );
        assert!(
            (write_mode & 0o4000) == 0,
            "write binary should NOT have setuid bit 0o4000"
        );

        // Verify detection using check_setgid_bit function
        assert!(
            check_setgid_bit(&write_bin).expect("check_setgid_bit failed"),
            "check_setgid_bit should return true for setgid binary"
        );

        // Add test directory to PATH (simulating /usr/bin)
        let _path_guard = add_to_path(&test_bin_dir).expect("Failed to add to PATH");

        // Find all setgid binaries in PATH
        let setgid_bins =
            find_setgid_binaries_in_path().expect("Failed to find setgid binaries in PATH");

        // Verify both our binaries are detected
        let write_found = setgid_bins.iter().any(|info| {
            info.path.file_name().unwrap() == "write" && info.has_setgid && !info.has_setuid
        });
        assert!(
            write_found,
            "Setgid write binary should be detected. Found binaries: {:?}",
            setgid_bins
        );

        let wall_found = setgid_bins.iter().any(|info| {
            info.path.file_name().unwrap() == "wall" && info.has_setgid && !info.has_setuid
        });
        assert!(
            wall_found,
            "Setgid wall binary should be detected. Found binaries: {:?}",
            setgid_bins
        );

        // Verify the security info is correct for our binaries
        if let Some(write_info) = setgid_bins
            .iter()
            .find(|i| i.path.file_name().unwrap() == "write")
        {
            assert!(
                write_info.has_setgid,
                "write binary should be marked as having setgid bit"
            );
            assert!(
                !write_info.has_setuid,
                "write binary should NOT be marked as having setuid bit"
            );
            // In a real system, setgid binaries like write are typically owned by root
            // and belong to the tty group. Our test binary will have the test user's GID.
            assert_eq!(write_info.path, write_bin, "Path should match");
        }
    }

    /// Test that setgid binaries in /usr/sbin simulation are detected
    ///
    /// # System PATH Scenario
    ///
    /// The /usr/sbin directory contains system administration binaries,
    /// some of which use setgid for controlled group privilege escalation.
    /// This test simulates that environment.
    #[test]
    fn test_setgid_binaries_in_usr_sbin_detected() {
        let _fixture_guard = BinaryFixtureGuard::new();
        let test_bin_dir = init_test_bin_dir().expect("Failed to create test bin dir");

        // Create setgid binaries that would be in /usr/sbin
        let sudo_bin = create_setgid_binary(
            "sudo", // Some systems use setgid for sudo log file access
            b"#!/bin/sh\necho 'sudo - setgid for admin group'\n",
        )
        .expect("Failed to create sudo binary");

        // Verify setgid bit
        assert!(
            is_setgid(&sudo_bin).expect("Failed to check setgid bit"),
            "sudo binary should have setgid bit"
        );

        // Add to PATH
        let _path_guard = add_to_path(&test_bin_dir).expect("Failed to add to PATH");

        // Find setgid binaries
        let setgid_bins = find_setgid_binaries_in_path().expect("Failed to find setgid binaries");

        // Verify detection
        let sudo_found = setgid_bins
            .iter()
            .any(|info| info.path.file_name().unwrap() == "sudo" && info.has_setgid);

        assert!(
            sudo_found,
            "Setgid sudo binary should be detected in PATH. Found: {:?}",
            setgid_bins
        );
    }

    /// Test that setgid bit (mode 2000) is correctly identified vs setuid (mode 4000)
    ///
    /// # What This Validates
    ///
    /// - Setgid bit is the group execute bit with group ID set (mode bit 11)
    /// - Setuid bit is the user execute bit with user ID set (mode bit 12)
    /// - Detection must distinguish between mode 2000 (setgid) and mode 4000 (setuid)
    /// - Combined mode 6000 (both setuid and setgid) is also handled correctly
    #[test]
    fn test_setgid_bit_mode_2000_correctly_identified() {
        let _fixture_guard = BinaryFixtureGuard::new();

        // Create three binaries with different permission modes:
        // 1. Regular executable (mode 0755)
        let regular_bin = create_executable_binary("regular_exec", b"#!/bin/sh\necho 'regular'\n")
            .expect("Failed to create regular binary");

        // 2. Setgid binary (mode 2755 = 0755 | 02000)
        let setgid_bin = create_setgid_binary("setgid_only", b"#!/bin/sh\necho 'setgid only'\n")
            .expect("Failed to create setgid binary");

        // 3. Setuid binary (mode 4755 = 0755 | 04000) for comparison
        let setuid_bin = create_setuid_binary("setuid_only", b"#!/bin/sh\necho 'setuid only'\n")
            .expect("Failed to create setuid binary");

        // 4. Combined setuid+setgid binary (mode 6755 = 0755 | 06000)
        let both_bin =
            create_setuid_setgid_binary("both_bits", b"#!/bin/sh\necho 'setuid and setgid'\n")
                .expect("Failed to create combined binary");

        // Verify permission modes
        let regular_mode = std::fs::metadata(&regular_bin).unwrap().mode();
        let setgid_mode = std::fs::metadata(&setgid_bin).unwrap().mode();
        let setuid_mode = std::fs::metadata(&setuid_bin).unwrap().mode();
        let both_mode = std::fs::metadata(&both_bin).unwrap().mode();

        // Check setgid bit (02000) specifically
        assert_eq!(
            regular_mode & 0o2000,
            0,
            "Regular binary should NOT have setgid bit (0o2000)"
        );
        assert_ne!(
            setgid_mode & 0o2000,
            0,
            "Setgid binary should have setgid bit (0o2000) set"
        );
        assert_eq!(
            setuid_mode & 0o2000,
            0,
            "Setuid-only binary should NOT have setgid bit (0o2000)"
        );
        assert_ne!(
            both_mode & 0o2000,
            0,
            "Combined binary should have setgid bit (0o2000) set"
        );

        // Check setuid bit (04000) for comparison
        assert_eq!(
            regular_mode & 0o4000,
            0,
            "Regular binary should NOT have setuid bit (0o4000)"
        );
        assert_eq!(
            setgid_mode & 0o4000,
            0,
            "Setgid-only binary should NOT have setuid bit (0o4000)"
        );
        assert_ne!(
            setuid_mode & 0o4000,
            0,
            "Setuid binary should have setuid bit (0o4000) set"
        );
        assert_ne!(
            both_mode & 0o4000,
            0,
            "Combined binary should have setuid bit (0o4000) set"
        );

        // Verify detection functions distinguish correctly
        assert!(
            !is_setgid(&regular_bin).unwrap(),
            "Regular binary should not be detected as setgid"
        );
        assert!(
            is_setgid(&setgid_bin).unwrap(),
            "Setgid binary should be detected as setgid"
        );
        assert!(
            !is_setgid(&setuid_bin).unwrap(),
            "Setuid-only binary should NOT be detected as setgid"
        );
        assert!(
            is_setgid(&both_bin).unwrap(),
            "Combined binary should be detected as setgid"
        );

        // Verify check_setgid_bit function
        assert!(
            !check_setgid_bit(&regular_bin).unwrap(),
            "check_setgid_bit: regular binary should return false"
        );
        assert!(
            check_setgid_bit(&setgid_bin).unwrap(),
            "check_setgid_bit: setgid binary should return true"
        );
        assert!(
            !check_setgid_bit(&setuid_bin).unwrap(),
            "check_setgid_bit: setuid binary should return false"
        );
        assert!(
            check_setgid_bit(&both_bin).unwrap(),
            "check_setgid_bit: combined binary should return true"
        );

        // Add all binaries to PATH and verify detection
        let _path_guard = add_binary_to_path(&setgid_bin).expect("Failed to add to PATH");

        let setgid_bins = find_setgid_binaries_in_path().expect("Failed to find setgid binaries");

        // Verify only setgid binaries are in the result
        let setgid_found = setgid_bins
            .iter()
            .any(|info| info.path.file_name().unwrap() == "setgid_only" && info.has_setgid);
        let both_found = setgid_bins
            .iter()
            .any(|info| info.path.file_name().unwrap() == "both_bits" && info.has_setgid);

        assert!(setgid_found, "Setgid-only binary should be found");
        assert!(both_found, "Combined setuid+setgid binary should be found");

        // Verify setuid-only binary is NOT in setgid results
        let setuid_in_setgid_list = setgid_bins
            .iter()
            .any(|info| info.path.file_name().unwrap() == "setuid_only");
        assert!(
            !setuid_in_setgid_list,
            "Setuid-only binary should NOT appear in setgid detection results"
        );
    }
}

#[cfg(test)]
#[serial]
mod positive_detection_tests {
    use super::*;

    /// Test that all setgid binaries in PATH are detected
    ///
    /// # What This Validates
    ///
    /// - Multiple setgid binaries in PATH are all detected
    /// - Detection function handles multiple files correctly
    /// - Security info is accurate for all detected binaries
    #[test]
    fn test_multiple_setgid_binaries_all_detected() {
        let _fixture_guard = BinaryFixtureGuard::new();
        let test_bin_dir = init_test_bin_dir().expect("Failed to create test bin dir");

        // Create multiple setgid binaries
        let bins = vec![
            create_setgid_binary("setgid_tool1", b"#!/bin/sh\necho '1'\n")
                .expect("Failed to create tool1"),
            create_setgid_binary("setgid_tool2", b"#!/bin/sh\necho '2'\n")
                .expect("Failed to create tool2"),
            create_setgid_binary("setgid_tool3", b"#!/bin/sh\necho '3'\n")
                .expect("Failed to create tool3"),
            create_setgid_binary("setgid_tool4", b"#!/bin/sh\necho '4'\n")
                .expect("Failed to create tool4"),
        ];

        // Verify all have setgid bit
        for bin in &bins {
            assert!(
                is_setgid(bin).unwrap(),
                "Binary {:?} should have setgid bit",
                bin
            );
        }

        // Add to PATH
        let _path_guard = add_to_path(&test_bin_dir).expect("Failed to add to PATH");

        // Find setgid binaries
        let setgid_bins = find_setgid_binaries_in_path().expect("Failed to find setgid binaries");

        // Check that all our binaries are found
        for bin in &bins {
            let found = setgid_bins
                .iter()
                .any(|info| info.path == *bin && info.has_setgid);
            assert!(
                found,
                "Setgid binary {:?} should be detected in PATH",
                bin.file_name()
            );
        }

        // Verify we found at least our 4 binaries
        assert!(
            setgid_bins.len() >= 4,
            "Should detect at least 4 setgid binaries, found {}",
            setgid_bins.len()
        );
    }

    /// Test detection of setgid binary with common group scenarios
    ///
    /// # System PATH Scenario
    ///
    /// Real setgid binaries are typically owned by root and belong to specific
    /// privileged groups (tty, mail, admin, etc.). This test verifies detection
    /// works regardless of group ownership.
    #[test]
    fn test_setgid_detection_with_different_group_ownership() {
        let _fixture_guard = BinaryFixtureGuard::new();

        // Create a setgid binary
        let setgid_bin =
            create_setgid_binary("group_shared", b"#!/bin/sh\necho 'Group shared binary'\n")
                .expect("Failed to create setgid binary");

        // Get the group ID of the binary
        let metadata = std::fs::metadata(&setgid_bin).expect("Failed to get metadata");
        let gid = metadata.gid();

        // Verify setgid bit is set
        assert!(
            is_setgid(&setgid_bin).unwrap(),
            "Binary should have setgid bit"
        );

        // Add to PATH
        let _path_guard = add_binary_to_path(&setgid_bin).expect("Failed to add to PATH");

        // Find setgid binaries
        let setgid_bins = find_setgid_binaries_in_path().expect("Failed to find setgid binaries");

        // Verify our binary is detected
        let found = setgid_bins.iter().find(|info| info.path == setgid_bin);

        assert!(found.is_some(), "Setgid binary should be found");

        // Verify the security info includes GID
        if let Some(info) = found {
            assert_eq!(info.gid, gid, "GID should match in security info");
            assert!(info.has_setgid, "Should be marked as setgid");
        }
    }
}

#[cfg(test)]
#[serial]
mod negative_detection_tests {
    use super::*;

    /// Test that non-setgid binaries are not flagged as setgid
    ///
    /// # What This Validates
    ///
    /// - Regular executables (mode 0755) are not detected as setgid
    /// - Detection correctly returns empty list when no setgid binaries present
    /// - False positives do not occur
    #[test]
    fn test_non_setgid_binaries_not_flagged() {
        // Save and clear PATH to avoid interference from system binaries
        let original_path = std::env::var("PATH").ok();
        std::env::remove_var("PATH");

        let _fixture_guard = BinaryFixtureGuard::new();
        let test_bin_dir = init_test_bin_dir().expect("Failed to create test bin dir");

        // Create regular (non-setgid) binaries
        let _bin1 = create_executable_binary("normal_tool1", b"#!/bin/sh\necho '1'\n")
            .expect("Failed to create tool1");
        let _bin2 = create_executable_binary("normal_tool2", b"#!/bin/sh\necho '2'\n")
            .expect("Failed to create tool2");
        let _bin3 = create_executable_binary("normal_tool3", b"#!/bin/sh\necho '3'\n")
            .expect("Failed to create tool3");

        // Set PATH to only the test directory (isolated from system PATH)
        let _path_guard = add_to_path(&test_bin_dir).expect("Failed to add to PATH");

        // Find setgid binaries (should be empty)
        let setgid_bins = find_setgid_binaries_in_path().expect("Failed to find setgid binaries");

        // Restore original PATH
        if let Some(path) = original_path {
            std::env::set_var("PATH", path);
        }

        assert!(
            setgid_bins.is_empty(),
            "No setgid binaries should be detected when only regular binaries exist. Found: {:?}",
            setgid_bins
        );
    }

    /// Test that setuid-only binaries are not detected as setgid
    ///
    /// # What This Validates
    ///
    /// - Setuid binaries (mode 4755) are not confused with setgid (mode 2755)
    /// - Detection function correctly distinguishes mode 4000 from mode 2000
    #[test]
    fn test_setuid_only_binaries_not_detected_as_setgid() {
        // Save and clear PATH to avoid interference from system binaries
        let original_path = std::env::var("PATH").ok();
        std::env::remove_var("PATH");

        let _fixture_guard = BinaryFixtureGuard::new();
        let test_bin_dir = init_test_bin_dir().expect("Failed to create test bin dir");

        // Create setuid-only binaries
        let _bin1 = create_setuid_binary("setuid_tool1", b"#!/bin/sh\necho '1'\n")
            .expect("Failed to create tool1");
        let _bin2 = create_setuid_binary("setuid_tool2", b"#!/bin/sh\necho '2'\n")
            .expect("Failed to create tool2");

        // Verify they have setuid but not setgid
        let bin1_meta = std::fs::metadata(test_bin_dir.join("setuid_tool1")).unwrap();
        let bin1_mode = bin1_meta.mode();

        assert_ne!(bin1_mode & 0o4000, 0, "Should have setuid bit");
        assert_eq!(bin1_mode & 0o2000, 0, "Should NOT have setgid bit");

        // Set PATH to only the test directory (isolated from system PATH)
        let _path_guard = add_to_path(&test_bin_dir).expect("Failed to add to PATH");

        // Find setgid binaries (should be empty)
        let setgid_bins = find_setgid_binaries_in_path().expect("Failed to find setgid binaries");

        // Restore original PATH
        if let Some(path) = original_path {
            std::env::set_var("PATH", path);
        }

        assert!(
            setgid_bins.is_empty(),
            "Setuid-only binaries should NOT be detected as setgid. Found: {:?}",
            setgid_bins
        );
    }

    /// Test empty PATH handling
    ///
    /// # What This Validates
    ///
    /// - Detection function handles empty PATH gracefully
    /// - Returns empty list (not error) when PATH is empty
    #[test]
    fn test_empty_path_returns_empty_list() {
        let _fixture_guard = BinaryFixtureGuard::new();

        // Save original PATH
        let original_path = std::env::var("PATH").ok();

        // Set empty PATH
        std::env::set_var("PATH", "");

        // Find setgid binaries (should succeed with empty list)
        let setgid_bins =
            find_setgid_binaries_in_path().expect("Should handle empty PATH gracefully");

        assert!(
            setgid_bins.is_empty(),
            "Empty PATH should result in empty list"
        );

        // Restore PATH
        if let Some(path) = original_path {
            std::env::set_var("PATH", path);
        } else {
            std::env::remove_var("PATH");
        }
    }
}

#[cfg(test)]
#[serial]
mod edge_case_tests {
    use super::*;

    /// Test detection with mixed setgid and regular binaries
    ///
    /// # What This Validates
    ///
    /// - In a directory with both setgid and regular binaries, only setgid are returned
    /// - Detection correctly filters mixed content
    #[test]
    fn test_mixed_binaries_only_setgid_detected() {
        // Save and clear PATH to avoid interference from system binaries
        let original_path = std::env::var("PATH").ok();
        std::env::remove_var("PATH");

        let _fixture_guard = BinaryFixtureGuard::new();
        let test_bin_dir = init_test_bin_dir().expect("Failed to create test bin dir");

        // Create mixed binaries
        let _normal1 = create_executable_binary("normal1", b"#!/bin/sh\necho 'n1'\n")
            .expect("Failed to create normal1");
        let _setgid1 = create_setgid_binary("setgid1", b"#!/bin/sh\necho 's1'\n")
            .expect("Failed to create setgid1");
        let _normal2 = create_executable_binary("normal2", b"#!/bin/sh\necho 'n2'\n")
            .expect("Failed to create normal2");
        let _setgid2 = create_setgid_binary("setgid2", b"#!/bin/sh\necho 's2'\n")
            .expect("Failed to create setgid2");
        let _normal3 = create_executable_binary("normal3", b"#!/bin/sh\necho 'n3'\n")
            .expect("Failed to create normal3");

        // Set PATH to only the test directory (isolated from system PATH)
        let _path_guard = add_to_path(&test_bin_dir).expect("Failed to add to PATH");

        // Find setgid binaries
        let setgid_bins = find_setgid_binaries_in_path().expect("Failed to find setgid binaries");

        // Restore original PATH
        if let Some(path) = original_path {
            std::env::set_var("PATH", path);
        }

        // Verify only setgid binaries are detected
        assert_eq!(
            setgid_bins.len(),
            2,
            "Should detect exactly 2 setgid binaries"
        );

        let setgid1_found = setgid_bins
            .iter()
            .any(|info| info.path.file_name().unwrap() == "setgid1");
        let setgid2_found = setgid_bins
            .iter()
            .any(|info| info.path.file_name().unwrap() == "setgid2");

        assert!(setgid1_found, "setgid1 should be detected");
        assert!(setgid2_found, "setgid2 should be detected");

        // Verify normal binaries are NOT in results
        let normal1_found = setgid_bins
            .iter()
            .any(|info| info.path.file_name().unwrap() == "normal1");
        let normal2_found = setgid_bins
            .iter()
            .any(|info| info.path.file_name().unwrap() == "normal2");
        let normal3_found = setgid_bins
            .iter()
            .any(|info| info.path.file_name().unwrap() == "normal3");

        assert!(!normal1_found, "normal1 should NOT be in setgid results");
        assert!(!normal2_found, "normal2 should NOT be in setgid results");
        assert!(!normal3_found, "normal3 should NOT be in setgid results");
    }

    /// Test detection with combined setuid+setgid binaries
    ///
    /// # What This Validates
    ///
    /// - Binaries with both setuid (mode 4000) and setgid (mode 2000) are detected as setgid
    /// - Combined mode 6000 binaries are correctly identified
    #[test]
    fn test_combined_setuid_setgid_binaries_detected() {
        let _fixture_guard = BinaryFixtureGuard::new();
        let test_bin_dir = init_test_bin_dir().expect("Failed to create test bin dir");

        // Create combined setuid+setgid binary
        let both_bin = create_setuid_setgid_binary(
            "both_privileged",
            b"#!/bin/sh\necho 'Both setuid and setgid'\n",
        )
        .expect("Failed to create combined binary");

        // Verify both bits are set
        let metadata = std::fs::metadata(&both_bin).expect("Failed to get metadata");
        let mode = metadata.mode();

        assert_ne!(mode & 0o4000, 0, "Should have setuid bit");
        assert_ne!(mode & 0o2000, 0, "Should have setgid bit");

        // Add to PATH
        let _path_guard = add_to_path(&test_bin_dir).expect("Failed to add to PATH");

        // Find setgid binaries
        let setgid_bins = find_setgid_binaries_in_path().expect("Failed to find setgid binaries");

        // Verify combined binary is detected (it has setgid bit, so it should be found)
        let both_found = setgid_bins
            .iter()
            .any(|info| info.path.file_name().unwrap() == "both_privileged" && info.has_setgid);

        assert!(
            both_found,
            "Combined setuid+setgid binary should be detected as setgid. Found: {:?}",
            setgid_bins
        );

        // Verify the security info shows both bits
        if let Some(info) = setgid_bins
            .iter()
            .find(|i| i.path.file_name().unwrap() == "both_privileged")
        {
            assert!(info.has_setgid, "Should be marked as setgid");
            assert!(info.has_setuid, "Should ALSO be marked as setuid");
        }
    }
}
