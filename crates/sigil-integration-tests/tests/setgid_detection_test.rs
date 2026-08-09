//! Setgid Binary Detection Tests for System PATH
//!
//! This test module validates setgid binary detection functionality
//! in system PATH scenarios, using helper functions from the binary_fixture module.
//!
//! # Technical Background: Unix Setgid Bit
//!
//! The setgid bit (set group ID upon execution) is a Unix file permission bit that
//! allows users to run a binary with the effective group ID (EGID) of the binary's
//! group owner, rather than the user's current group. This is commonly used for:
//!
//! - **Shared group utilities**: Tools like `write`, `wall`, `ssh-agent` that need
//!   to access group-owned resources (e.g., tty devices)
//! - **Collaborative directories**: Setgid on directories causes new files to inherit
//!   the parent directory's group ownership
//! - **Controlled privilege escalation**: Granting specific group permissions without
//!   granting full user-level privileges
//!
//! ## Setgid Bit Encoding
//!
//! In Unix filesystem permissions, the setgid bit is encoded as bit 11 in the 12-bit
//! mode field (counting from bit 0 as the least significant bit):
//!
//! ```text
//! Bit positions:  11 10 9 8 | 7 6 5 4 | 3 2 1 0
//!               --------|--------|--------
//!               Special  | Group  | Owner
//!               bits     | perms  | perms
//!
//! Bit 11 (0o2000): Setgid bit - execute with effective group ID
//! Bit 10 (0o4000): Setuid bit - execute with effective user ID
//! Bit  9 (0o1000): Sticky bit - special directory behavior
//! ```
//!
//! The octal value 2000 (0o2000 in Rust notation) represents the setgid bit:
//! - Binary: `010 000 000 000`
//! - When set on an executable (e.g., mode 2755 = 0o2755): `010 111 101 101`
//! - The bit is checked using: `mode & 0o2000 != 0`
//!
//! ## Why Mode 2000 Is Correct
//!
//! The setgid bit is **NOT** the same as:
//! - Mode 4000 (0o4000): setuid bit - effective user ID (different security concern)
//! - Mode 6000 (0o6000): both setuid and setgid bits set together
//! - Mode 1000 (0o1000): sticky bit - used for deletion restrictions in /tmp
//!
//! Correctly identifying mode 2000 matters because:
//! 1. **Security scanning must be precise**: Setgid binaries are a distinct security
//!    surface from setuid binaries and require different handling
//! 2. **Permission enumeration**: Listing setgid binaries should NOT include setuid-only
//!    binaries (mode 4755), as they represent different privilege escalation paths
//! 3. **Combined permissions**: Binaries with both setuid and setgid (mode 6755) should
//!    be detected as having BOTH properties, not just one
//!
//! # Tests Included
//!
//! - **System PATH simulation**: Tests setgid detection in /usr/bin, /usr/sbin scenarios
//! - **Setgid bit validation**: Verifies mode 2000 (setgid bit) is correctly identified
//! - **Positive detection**: setgid binaries in PATH are correctly detected
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
//! - `is_setgid()` - Check if a binary has setgid bit (mode 2000) using `mode & 0o2000`
//! - `check_setgid_bit()` - Alternative setgid detection function
//!
//! Uses the `sigil_integration_tests::env_detect` module which provides:
//! - `find_setgid_binaries_in_path()` - Scan PATH for setgid binaries
//! - `get_binary_security_info()` - Get full security info for a binary
//! - `BinarySecurityInfo` - Security information structure
//! - `check_setgid_bit()` - Verify setgid bit is set
//!
//! # Test Organization
//!
//! Tests are organized into modules by scenario:
//! - `system_path_tests`: /usr/bin, /usr/sbin system directory scenarios
//! - `positive_detection_tests`: Setgid binaries are correctly found
//! - `negative_detection_tests`: Non-setgid binaries are correctly excluded
//! - `edge_case_tests`: Mixed permissions, combined setuid+setgid scenarios
//! - `user_path_tests`: ~/.local/bin, ~/bin, custom user PATH scenarios
//!
//! # Edge Cases Covered
//!
//! 1. **Permission bit combinations**:
//!    - Regular executable (0755): No special bits
//!    - Setgid only (2755): Only bit 11 set
//!    - Setuid only (4755): Only bit 10 set
//!    - Both setuid+setgid (6755): Both bits 10 and 11 set
//!
//! 2. **PATH variations**:
//!    - System paths: /usr/bin, /usr/sbin
//!    - User paths: ~/.local/bin, ~/bin, custom directories
//!    - Relative paths: "./bin", "bin/"
//!    - Absolute paths: Full path to custom directories
//!    - Empty PATH: Graceful handling with empty result
//!
//! 3. **Mixed content**:
//!    - Directories with both setgid and non-setgid binaries
//!    - Multiple setgid binaries across multiple PATH entries
//!    - System and user PATH entries mixed together

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
    /// # System PATH Scenario
    ///
    /// Real-world systems have binaries with various permission modes. It's critical
    /// that setgid detection distinguishes between different privilege elevation modes
    /// to avoid false positives and missing real security concerns.
    ///
    /// # What This Validates
    ///
    /// ## Core Permission Bit Verification
    ///
    /// This test verifies that the detection functions correctly identify the setgid
    /// bit (mode 2000) by testing it against related but distinct permission modes:
    ///
    /// - **Setgid bit** (mode 2000 = 0o2000): Binary executes with effective GID of file's group
    /// - **Setuid bit** (mode 4000 = 0o4000): Binary executes with effective UID of file's owner
    /// - **Both bits** (mode 6000 = 0o6000): Binary has both setuid AND setgid properties
    ///
    /// ### Why This Distinction Matters
    ///
    /// 1. **Security scanning accuracy**: A security scanner must report setgid and setuid
    ///    binaries as separate findings. They represent different privilege escalation
    ///    vectors and require different remediation strategies.
    ///
    /// 2. **Detection function correctness**: The bitwise AND check `mode & 0o2000` must
    ///    ONLY match bit 11 (setgid), not bit 10 (setuid) or any other bit.
    ///
    /// 3. **Combined permissions**: Binaries with both setuid and setgid are relatively
    ///    rare but do exist (e.g., some multi-user system tools). Detection must recognize
    ///    BOTH properties, not just one or the other.
    ///
    /// ### Bit Encoding Details
    ///
    /// Unix permission modes are 12-bit values (though only lower 9 bits are commonly shown):
    ///
    /// ```text
    /// Mode 2755 (setgid only):
    ///   Binary: 010 111 101 101
    ///   Octal:   2   7   5   5
    ///           |   |   |   |
    ///           |   |   |   +--- Owner: rwx (read, write, execute)
    ///           |   |   +------- Group: r-x (read, execute)
    ///           |   +----------- Others: r-x (read, execute)
    ///           +--------------- Setgid bit (bit 11)
    ///
    /// Mode 4755 (setuid only):
    ///   Binary: 100 111 101 101
    ///   Octal:   4   7   5   5
    ///           |
    ///           +--------------- Setuid bit (bit 10)
    ///
    /// Mode 6755 (both setuid and setgid):
    ///   Binary: 110 111 101 101
    ///   Octal:   6   7   5   5
    ///           |
    ///           +--- Both bits 11 and 10 set
    /// ```
    ///
    /// ### Test Scenarios
    ///
    /// 1. **Regular executable** (mode 0755): Should NOT trigger setgid detection
    /// 2. **Setgid only** (mode 2755): SHOULD trigger setgid detection
    /// 3. **Setuid only** (mode 4755): Should NOT trigger setgid detection (this is the key test!)
    /// 4. **Both bits** (mode 6755): SHOULD trigger setgid detection (and also setuid detection)
    ///
    /// ## Edge Case: Why Setuid-Only Must Not Be Detected
    ///
    /// A common bug in setgid detection is to check "any special permission bit" rather
    /// than specifically the setgid bit. This would cause setuid-only binaries (like
    /// sudo, passwd, su) to appear in setgid scan results, creating false positives and
    /// potentially masking real setgid binaries in the noise.
    ///
    /// This test specifically guards against that bug by verifying that a setuid-only
    /// binary is NOT detected as setgid.
    #[test]
    fn test_setgid_bit_mode_2000_correctly_identified() {
        let _fixture_guard = BinaryFixtureGuard::new();

        // Create four binaries with different permission modes to test detection accuracy:
        //
        // Binary 1: Regular executable (mode 0755)
        //   - No special permission bits
        //   - Used as baseline: should NOT be detected as setgid
        let regular_bin = create_executable_binary("regular_exec", b"#!/bin/sh\necho 'regular'\n")
            .expect("Failed to create regular binary");

        // Binary 2: Setgid-only binary (mode 2755 = 0o2755)
        //   - Has ONLY the setgid bit (bit 11) set
        //   - This is the primary positive test case
        let setgid_bin = create_setgid_binary("setgid_only", b"#!/bin/sh\necho 'setgid only'\n")
            .expect("Failed to create setgid binary");

        // Binary 3: Setuid-only binary (mode 4755 = 0o4755)
        //   - Has ONLY the setuid bit (bit 10) set
        //   - Critical negative test: should NOT be detected as setgid
        //   - This tests that we distinguish setgid from setuid
        let setuid_bin = create_setuid_binary("setuid_only", b"#!/bin/sh\necho 'setuid only'\n")
            .expect("Failed to create setuid binary");

        // Binary 4: Combined setuid+setgid binary (mode 6755 = 0o6755)
        //   - Has BOTH bit 10 (setuid) AND bit 11 (setgid) set
        //   - Should be detected as setgid (and also as setuid in a separate check)
        let both_bin =
            create_setuid_setgid_binary("both_bits", b"#!/bin/sh\necho 'setuid and setgid'\n")
                .expect("Failed to create combined binary");

        // Step 1: Verify the binaries were created with the expected permission modes
        //
        // We read the actual mode bits from the filesystem to verify the creation
        // functions set the permissions correctly. This tests the fixture infrastructure.
        let regular_mode = std::fs::metadata(&regular_bin).unwrap().mode();
        let setgid_mode = std::fs::metadata(&setgid_bin).unwrap().mode();
        let setuid_mode = std::fs::metadata(&setuid_bin).unwrap().mode();
        let both_mode = std::fs::metadata(&both_bin).unwrap().mode();

        // Step 2: Verify the setgid bit (0o2000) specifically
        //
        // The bitwise AND operation isolates individual permission bits:
        // - `mode & 0o2000` extracts only bit 11 (the setgid bit)
        // - If the result is 0, the bit is not set
        // - If non-zero, the bit is set
        //
        // Test each binary to verify the setgid bit state matches expectations:

        // Regular binary: should have NO special bits (0o2000, 0o4000, 0o1000 all clear)
        assert_eq!(
            regular_mode & 0o2000,
            0,
            "Regular binary should NOT have setgid bit (0o2000) - this verifies baseline"
        );

        // Setgid binary: should have setgid bit (0o2000) SET
        assert_ne!(
            setgid_mode & 0o2000,
            0,
            "Setgid binary should have setgid bit (0o2000) set - this is the primary positive test"
        );

        // Setuid binary: should have setgid bit (0o2000) CLEAR
        // This is the critical test that proves we distinguish setgid from setuid
        assert_eq!(
            setuid_mode & 0o2000,
            0,
            "Setuid-only binary should NOT have setgid bit (0o2000) - this proves detection distinguishes setgid from setuid"
        );

        // Combined binary: should have setgid bit (0o2000) SET (along with setuid)
        assert_ne!(
            both_mode & 0o2000,
            0,
            "Combined setuid+setgid binary should have setgid bit (0o2000) set - verifies detection works with multiple special bits"
        );

        // Step 3: Verify the setuid bit (0o4000) for comparison
        //
        // This demonstrates that our four test binaries have the expected setuid state:
        // - Regular: no setuid
        // - Setgid-only: no setuid (only bit 11 set, not bit 10)
        // - Setuid-only: has setuid (only bit 10 set, not bit 11)
        // - Combined: has both setuid and setgid
        assert_eq!(
            regular_mode & 0o4000,
            0,
            "Regular binary should NOT have setuid bit (0o4000)"
        );
        assert_eq!(
            setgid_mode & 0o4000,
            0,
            "Setgid-only binary should NOT have setuid bit (0o4000) - confirms setgid test doesn't accidentally set setuid"
        );
        assert_ne!(
            setuid_mode & 0o4000,
            0,
            "Setuid binary should have setuid bit (0o4000) set - confirms setuid bit is independent from setgid"
        );
        assert_ne!(
            both_mode & 0o4000,
            0,
            "Combined binary should have setuid bit (0o4000) set - verifies both special bits can coexist"
        );

        // Step 4: Verify the detection functions distinguish correctly
        //
        // Test the `is_setgid()` helper function which implements the core detection logic.
        // This function should return true ONLY for binaries with the setgid bit.
        assert!(
            !is_setgid(&regular_bin).unwrap(),
            "is_setgid(): Regular binary should return false - baseline test"
        );
        assert!(
            is_setgid(&setgid_bin).unwrap(),
            "is_setgid(): Setgid binary should return true - primary positive test"
        );
        assert!(
            !is_setgid(&setuid_bin).unwrap(),
            "is_setgid(): Setuid-only binary should return false - critical negative test proves setgid ≠ setuid"
        );
        assert!(
            is_setgid(&both_bin).unwrap(),
            "is_setgid(): Combined binary should return true - verifies detection works with multiple special bits"
        );

        // Step 5: Verify the alternative detection function
        //
        // Test the `check_setgid_bit()` function which should match `is_setgid()`.
        // This provides defense-in-depth by testing two independent implementations.
        assert!(
            !check_setgid_bit(&regular_bin).unwrap(),
            "check_setgid_bit(): Regular binary should return false"
        );
        assert!(
            check_setgid_bit(&setgid_bin).unwrap(),
            "check_setgid_bit(): Setgid binary should return true"
        );
        assert!(
            !check_setgid_bit(&setuid_bin).unwrap(),
            "check_setgid_bit(): Setuid binary should return false - confirms both functions distinguish setgid from setuid"
        );
        assert!(
            check_setgid_bit(&both_bin).unwrap(),
            "check_setgid_bit(): Combined binary should return true"
        );

        // Step 6: End-to-end PATH scanning test
        //
        // Add all binaries to PATH and verify that `find_setgid_binaries_in_path()`
        // correctly identifies only the setgid binaries (setgid_only and both_bits).
        let _path_guard = add_binary_to_path(&setgid_bin).expect("Failed to add to PATH");

        let setgid_bins = find_setgid_binaries_in_path().expect("Failed to find setgid binaries");

        // Verify the scan results include our setgid binaries
        let setgid_found = setgid_bins
            .iter()
            .any(|info| info.path.file_name().unwrap() == "setgid_only" && info.has_setgid);
        let both_found = setgid_bins
            .iter()
            .any(|info| info.path.file_name().unwrap() == "both_bits" && info.has_setgid);

        assert!(setgid_found, "Setgid-only binary should be found in PATH scan");
        assert!(both_found, "Combined setuid+setgid binary should be found in PATH scan");

        // Critical: Verify the setuid-only binary is NOT in the setgid results
        //
        // This proves the PATH scanner also distinguishes setgid from setuid,
        // not just the low-level detection functions.
        let setuid_in_setgid_list = setgid_bins
            .iter()
            .any(|info| info.path.file_name().unwrap() == "setuid_only");
        assert!(
            !setuid_in_setgid_list,
            "Setuid-only binary should NOT appear in setgid detection results - this is the key end-to-end verification that the entire detection pipeline (filesystem scan + permission check) correctly distinguishes setgid from setuid"
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
    /// # System PATH Scenario
    ///
    /// Real system directories (e.g., /usr/bin) contain a mix of binaries:
    /// - Regular executables: Most binaries have no special permission bits
    /// - Setgid binaries: A few tools (write, wall, ssh-agent) use setgid for group access
    /// - Setuid binaries: Some tools (sudo, passwd, su) use setuid for user privilege escalation
    ///
    /// A security scanner must correctly filter this mixed content, returning ONLY
    /// the setgid binaries without false positives or false negatives.
    ///
    /// # What This Validates
    ///
    /// ## Filtering Accuracy in Mixed Content
    ///
    /// This test validates that the PATH scanner correctly handles directories with
    /// heterogeneous permission modes:
    ///
    /// 1. **Positive detection**: Setgid binaries in the directory are found
    /// 2. **Negative filtering**: Regular (non-setgid) binaries are NOT included
    /// 3. **No false positives**: Regular binaries don't accidentally match setgid criteria
    /// 4. **No false negatives**: Setgid binaries aren't missed in the presence of regular binaries
    ///
    /// ### Why This Edge Case Matters
    ///
    /// Common bugs in directory scanning that this test guards against:
    ///
    /// 1. **Permission check errors**: Checking "is executable" instead of "has setgid bit"
    ///    would incorrectly flag ALL binaries, creating massive false positive noise.
    ///
    /// 2. **Short-circuit bugs**: Stopping after the first setgid binary is found would
    ///    miss additional setgid binaries in the same directory (false negatives).
    ///
    /// 3. **Type confusion**: Treating "non-setuid" as "setgid" would incorrectly include
    ///    regular binaries that have neither special bit set.
    ///
    /// 4. **Iterator bugs**: Incorrect filtering logic could skip entries or process
    ///    entries multiple times.
    ///
    /// ### Test Pattern: Alternating Binary Types
    ///
    /// The test creates binaries in an alternating pattern (normal, setgid, normal, setgid, normal)
    /// to maximize the chance of catching off-by-one errors or iteration bugs.
    /// This pattern tests: first entry is regular (scanner doesn't assume all are setgid),
    /// middle entries are both types (scanner handles transitions correctly),
    /// last entry is regular (scanner doesn't have off-by-one error at the end).
    ///
    /// ### Test Isolation
    ///
    /// The test saves and clears the system PATH before running, then restores it
    /// afterward. This ensures test results are reproducible across different systems.
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

#[cfg(test)]
#[serial]
mod user_path_tests {
    use super::*;
    use anyhow::Context;
    use std::fs;
    use std::io::Write;
    use std::os::unix::fs::PermissionsExt;
    use std::path::{Path, PathBuf};

    /// Test that setgid binaries in ~/.local/bin are detected
    ///
    /// # User PATH Scenario
    ///
    /// User-specific PATH directories like ~/.local/bin are commonly used for
    /// user-installed binaries that don't require root privileges. This test
    /// simulates a scenario where a user has installed a setgid binary in their
    /// local bin directory, which could be a security concern if the setgid bit
    /// was set accidentally or maliciously.
    ///
    /// # What This Validates
    ///
    /// - Setgid binaries in user home directories are correctly detected
    /// - PATH expansion of ~ works correctly for user bin detection
    /// - Security scanning includes user-local directories, not just system paths
    /// - Detection works even when the user PATH directory doesn't exist in system PATH
    #[test]
    fn test_setgid_binaries_in_user_local_bin_detected() {
        let _fixture_guard = BinaryFixtureGuard::new();

        // Create a test directory to simulate ~/.local/bin
        let home_dir = std::env::temp_dir().join(format!("sigil-test-home-{}", std::process::id()));
        let local_bin_dir = home_dir.join(".local/bin");

        // Create the directory structure
        fs::create_dir_all(&local_bin_dir).expect("Failed to create .local/bin directory");

        // Create a setgid binary in the user's local bin
        let user_tool_bin = create_setgid_binary_in_dir(
            &local_bin_dir,
            "user_tool",
            b"#!/bin/sh\necho 'User tool - potentially suspicious setgid binary'\n",
        )
        .expect("Failed to create user tool binary");

        // Verify the binary has setgid bit
        assert!(
            is_setgid(&user_tool_bin).expect("Failed to check setgid bit"),
            "User tool binary should have setgid bit"
        );

        // Add ~/.local/bin to PATH (simulating user PATH configuration)
        let _path_guard = add_to_path(&local_bin_dir).expect("Failed to add to PATH");

        // Find setgid binaries in PATH
        let setgid_bins = find_setgid_binaries_in_path().expect("Failed to find setgid binaries");

        // Verify the user's setgid binary is detected
        let user_tool_found = setgid_bins
            .iter()
            .any(|info| info.path.file_name().unwrap() == "user_tool" && info.has_setgid);

        assert!(
            user_tool_found,
            "Setgid binary in ~/.local/bin should be detected. Found binaries: {:?}",
            setgid_bins
        );

        // Clean up the test directory
        fs::remove_dir_all(&home_dir).expect("Failed to clean up test home directory");
    }

    /// Test setgid detection with absolute user PATH entries
    ///
    /// # User PATH Scenario
    ///
    /// Users can configure their PATH with absolute paths to custom directories.
    /// This test validates that setgid binaries in absolute-pathed user directories
    /// are correctly detected.
    ///
    /// # What This Validates
    ///
    /// - Absolute path entries in PATH are correctly scanned
    /// - Setgid binaries in custom absolute paths are detected
    /// - PATH parsing handles absolute paths correctly
    #[test]
    fn test_setgid_detection_with_absolute_user_path() {
        let _fixture_guard = BinaryFixtureGuard::new();

        // Create a custom user directory with absolute path
        let custom_bin_dir =
            std::env::temp_dir().join(format!("sigil-custom-bin-{}", std::process::id()));

        fs::create_dir_all(&custom_bin_dir).expect("Failed to create custom bin directory");

        // Create a setgid binary in the custom directory
        let custom_tool = create_setgid_binary_in_dir(
            &custom_bin_dir,
            "custom_tool",
            b"#!/bin/sh\necho 'Custom tool with absolute path'\n",
        )
        .expect("Failed to create custom tool");

        // Verify setgid bit
        assert!(
            is_setgid(&custom_tool).expect("Failed to check setgid bit"),
            "Custom tool should have setgid bit"
        );

        // Add absolute path to PATH
        let _path_guard = add_to_path(&custom_bin_dir).expect("Failed to add to PATH");

        // Find setgid binaries
        let setgid_bins = find_setgid_binaries_in_path().expect("Failed to find setgid binaries");

        // Verify detection
        let custom_found = setgid_bins
            .iter()
            .any(|info| info.path.file_name().unwrap() == "custom_tool" && info.has_setgid);

        assert!(
            custom_found,
            "Setgid binary in absolute user PATH should be detected. Found: {:?}",
            setgid_bins
        );

        // Clean up
        fs::remove_dir_all(&custom_bin_dir).expect("Failed to clean up custom bin directory");
    }

    /// Test setgid detection with relative user PATH entries
    ///
    /// # User PATH Scenario
    ///
    /// Users sometimes add relative paths like "./bin" or "bin/" to their PATH.
    /// This test validates that setgid binaries in relative-pathed directories are
    /// correctly detected when resolved from the current working directory.
    ///
    /// # What This Validates
    ///
    /// - Relative path entries in PATH are correctly resolved and scanned
    /// - Setgid binaries in relative paths are detected
    /// - Current working directory context is properly handled
    #[test]
    fn test_setgid_detection_with_relative_user_path() {
        let _fixture_guard = BinaryFixtureGuard::new();

        // Save current directory
        let original_dir = std::env::current_dir().expect("Failed to get current directory");

        // Create a test directory with relative path "bin"
        let test_dir =
            std::env::temp_dir().join(format!("sigil-relative-test-{}", std::process::id()));
        let relative_bin_dir = test_dir.join("bin");

        fs::create_dir_all(&relative_bin_dir).expect("Failed to create relative bin directory");

        // Change to the test directory (so relative paths resolve correctly)
        std::env::set_current_dir(&test_dir).expect("Failed to change directory");

        // Create a setgid binary in the relative "bin" directory
        let relative_tool = create_setgid_binary_in_dir(
            &relative_bin_dir,
            "relative_tool",
            b"#!/bin/sh\necho 'Relative path tool'\n",
        )
        .expect("Failed to create relative tool");

        // Verify setgid bit
        assert!(
            is_setgid(&relative_tool).expect("Failed to check setgid bit"),
            "Relative tool should have setgid bit"
        );

        // Add relative path "bin" to PATH
        let bin_path = PathBuf::from("bin");
        let _path_guard = add_to_path(&bin_path).expect("Failed to add to PATH");

        // Find setgid binaries
        let setgid_bins = find_setgid_binaries_in_path().expect("Failed to find setgid binaries");

        // Verify detection
        let relative_found = setgid_bins
            .iter()
            .any(|info| info.path.file_name().unwrap() == "relative_tool" && info.has_setgid);

        assert!(
            relative_found,
            "Setgid binary in relative user PATH should be detected. Found: {:?}",
            setgid_bins
        );

        // Restore original directory
        std::env::set_current_dir(original_dir).expect("Failed to restore directory");

        // Clean up
        fs::remove_dir_all(&test_dir).expect("Failed to clean up test directory");
    }

    /// Test setgid detection with mocked user PATH environment variable
    ///
    /// # User PATH Scenario
    ///
    /// This test mocks a realistic user PATH environment that includes both
    /// system directories (/usr/bin, /usr/local/bin) and user-specific directories
    /// (~/.local/bin, ~/bin). It validates that setgid binaries in all locations
    /// are detected correctly.
    ///
    /// # What This Validates
    ///
    /// - Mixed system and user PATH entries are all scanned correctly
    /// - Setgid binaries in user directories within a complex PATH are detected
    /// - PATH parsing handles multiple colon-separated entries correctly
    /// - Environment variable mocking works correctly for PATH testing
    #[test]
    fn test_setgid_detection_with_mocked_user_path_env() {
        let _fixture_guard = BinaryFixtureGuard::new();

        // Create a test user bin directory
        let user_bin_dir =
            std::env::temp_dir().join(format!("sigil-user-bin-{}", std::process::id()));

        fs::create_dir_all(&user_bin_dir).expect("Failed to create user bin directory");

        // Create a setgid binary in user bin
        let user_tool = create_setgid_binary_in_dir(
            &user_bin_dir,
            "user_path_tool",
            b"#!/bin/sh\necho 'Tool in mocked user PATH'\n",
        )
        .expect("Failed to create user tool");

        // Verify setgid bit
        assert!(
            is_setgid(&user_tool).expect("Failed to check setgid bit"),
            "User tool should have setgid bit"
        );

        // Save original PATH
        let original_path = std::env::var("PATH").unwrap_or_default();

        // Mock a realistic user PATH: /usr/local/bin:/usr/bin:~/.local/bin:~/bin
        // We'll add our test user bin directory to simulate ~/bin
        let mocked_path = format!(
            "/usr/local/bin:/usr/bin:{}:{}",
            user_bin_dir.display(),
            original_path
        );

        std::env::set_var("PATH", mocked_path);

        // Find setgid binaries
        let setgid_bins = find_setgid_binaries_in_path().expect("Failed to find setgid binaries");

        // Verify our user tool is detected
        let user_tool_found = setgid_bins
            .iter()
            .any(|info| info.path.file_name().unwrap() == "user_path_tool" && info.has_setgid);

        assert!(
            user_tool_found,
            "Setgid binary in mocked user PATH should be detected. Found: {:?}",
            setgid_bins
        );

        // Verify the path was correctly set
        let current_path = std::env::var("PATH").expect("Failed to get PATH");
        assert!(
            current_path.contains(&user_bin_dir.to_string_lossy().to_string()),
            "PATH should contain user bin directory"
        );

        // Restore original PATH
        std::env::set_var("PATH", original_path);

        // Clean up
        fs::remove_dir_all(&user_bin_dir).expect("Failed to clean up user bin directory");
    }

    /// Test multiple setgid binaries across different user PATH locations
    ///
    /// # User PATH Scenario
    ///
    /// Users may have multiple user-specific directories in their PATH
    /// (e.g., ~/.local/bin, ~/bin, ~/tools/bin). This test validates that
    /// setgid binaries in multiple user PATH locations are all detected.
    ///
    /// # What This Validates
    ///
    /// - All setgid binaries across multiple user PATH directories are detected
    /// - PATH scanning correctly handles multiple user directories
    /// - Detection is comprehensive across user's entire PATH configuration
    #[test]
    fn test_multiple_setgid_binaries_across_user_path_locations() {
        let _fixture_guard = BinaryFixtureGuard::new();

        // Create multiple user bin directories
        let local_bin_dir =
            std::env::temp_dir().join(format!("sigil-local-bin-{}", std::process::id()));
        let user_bin_dir =
            std::env::temp_dir().join(format!("sigil-user-bin-{}", std::process::id()));
        let tools_bin_dir =
            std::env::temp_dir().join(format!("sigil-tools-bin-{}", std::process::id()));

        fs::create_dir_all(&local_bin_dir).expect("Failed to create .local/bin");
        fs::create_dir_all(&user_bin_dir).expect("Failed to create ~/bin");
        fs::create_dir_all(&tools_bin_dir).expect("Failed to create ~/tools/bin");

        // Create setgid binaries in each directory
        let local_tool = create_setgid_binary_in_dir(
            &local_bin_dir,
            "local_bin_tool",
            b"#!/bin/sh\necho 'Tool in .local/bin'\n",
        )
        .expect("Failed to create .local/bin tool");

        let user_tool = create_setgid_binary_in_dir(
            &user_bin_dir,
            "user_bin_tool",
            b"#!/bin/sh\necho 'Tool in ~/bin'\n",
        )
        .expect("Failed to create ~/bin tool");

        let tools_tool = create_setgid_binary_in_dir(
            &tools_bin_dir,
            "tools_bin_tool",
            b"#!/bin/sh\necho 'Tool in ~/tools/bin'\n",
        )
        .expect("Failed to create ~/tools/bin tool");

        // Verify all have setgid bit
        assert!(is_setgid(&local_tool).unwrap());
        assert!(is_setgid(&user_tool).unwrap());
        assert!(is_setgid(&tools_tool).unwrap());

        // Add all directories to PATH
        let original_path = std::env::var("PATH").unwrap_or_default();
        let new_path = format!(
            "{}:{}:{}:{}",
            local_bin_dir.display(),
            user_bin_dir.display(),
            tools_bin_dir.display(),
            original_path
        );
        std::env::set_var("PATH", new_path);

        // Find setgid binaries
        let setgid_bins = find_setgid_binaries_in_path().expect("Failed to find setgid binaries");

        // Verify all three user tools are detected
        let local_found = setgid_bins
            .iter()
            .any(|info| info.path.file_name().unwrap() == "local_bin_tool" && info.has_setgid);
        let user_found = setgid_bins
            .iter()
            .any(|info| info.path.file_name().unwrap() == "user_bin_tool" && info.has_setgid);
        let tools_found = setgid_bins
            .iter()
            .any(|info| info.path.file_name().unwrap() == "tools_bin_tool" && info.has_setgid);

        assert!(
            local_found,
            "Setgid binary in .local/bin should be detected. Found: {:?}",
            setgid_bins
        );
        assert!(
            user_found,
            "Setgid binary in ~/bin should be detected. Found: {:?}",
            setgid_bins
        );
        assert!(
            tools_found,
            "Setgid binary in ~/tools/bin should be detected. Found: {:?}",
            setgid_bins
        );

        // Restore PATH
        std::env::set_var("PATH", original_path);

        // Clean up all directories
        fs::remove_dir_all(&local_bin_dir).expect("Failed to clean up .local/bin");
        fs::remove_dir_all(&user_bin_dir).expect("Failed to clean up ~/bin");
        fs::remove_dir_all(&tools_bin_dir).expect("Failed to clean up ~/tools/bin");
    }

    /// Test that regular binaries in user PATH are not flagged as setgid
    ///
    /// # User PATH Scenario
    ///
    /// User PATH directories typically contain regular, non-setgid binaries.
    /// This test ensures that false positives don't occur and that only
    /// binaries with the setgid bit are flagged.
    ///
    /// # What This Validates
    ///
    /// - Regular binaries in user PATH are not incorrectly flagged
    /// - Detection accuracy is maintained in user directories
    /// - No false positives for normal user tools
    #[test]
    fn test_regular_binaries_in_user_path_not_flagged() {
        let _fixture_guard = BinaryFixtureGuard::new();

        // Create a user bin directory
        let user_bin_dir =
            std::env::temp_dir().join(format!("sigil-user-regular-{}", std::process::id()));

        fs::create_dir_all(&user_bin_dir).expect("Failed to create user bin directory");

        // Create regular (non-setgid) binaries
        let regular1 = create_executable_binary_in_dir(
            &user_bin_dir,
            "regular_user_tool1",
            b"#!/bin/sh\necho 'Regular user tool 1'\n",
        )
        .expect("Failed to create regular tool 1");

        let regular2 = create_executable_binary_in_dir(
            &user_bin_dir,
            "regular_user_tool2",
            b"#!/bin/sh\necho 'Regular user tool 2'\n",
        )
        .expect("Failed to create regular tool 2");

        // Verify they don't have setgid bit
        assert!(
            !is_setgid(&regular1).expect("Failed to check setgid bit"),
            "Regular tool 1 should NOT have setgid bit"
        );
        assert!(
            !is_setgid(&regular2).expect("Failed to check setgid bit"),
            "Regular tool 2 should NOT have setgid bit"
        );

        // Add to PATH
        let _path_guard = add_to_path(&user_bin_dir).expect("Failed to add to PATH");

        // Find setgid binaries (should be empty for this test)
        let setgid_bins = find_setgid_binaries_in_path().expect("Failed to find setgid binaries");

        // Filter to only binaries in our test directory
        let user_dir_bins: Vec<_> = setgid_bins
            .iter()
            .filter(|info| info.path.starts_with(&user_bin_dir))
            .collect();

        assert!(
            user_dir_bins.is_empty(),
            "Regular binaries in user PATH should NOT be flagged as setgid. Found: {:?}",
            user_dir_bins
        );

        // Clean up
        fs::remove_dir_all(&user_bin_dir).expect("Failed to clean up user bin directory");
    }

    /// Test setgid detection in user PATH with combined system and user paths
    ///
    /// # User PATH Scenario
    ///
    /// A typical user PATH includes both system directories (/usr/bin, /usr/local/bin)
    /// and user-specific directories (~/.local/bin). This test validates that setgid
    /// binaries are detected correctly in this mixed scenario.
    ///
    /// # What This Validates
    ///
    /// - Setgid binaries are detected in both system and user PATH components
    /// - PATH scanning correctly handles the combination of system and user paths
    /// - Detection works correctly when user PATH is interleaved with system PATH
    #[test]
    fn test_setgid_detection_with_mixed_system_and_user_paths() {
        let _fixture_guard = BinaryFixtureGuard::new();

        // Use the standard test bin directory (simulating system PATH)
        let test_bin_dir = init_test_bin_dir().expect("Failed to initialize test bin dir");

        // Create a system-like setgid binary
        let system_tool = create_setgid_binary(
            "system_setgid_tool",
            b"#!/bin/sh\necho 'System setgid tool'\n",
        )
        .expect("Failed to create system tool");

        // Create a user bin directory
        let user_bin_dir =
            std::env::temp_dir().join(format!("sigil-mixed-user-{}", std::process::id()));

        fs::create_dir_all(&user_bin_dir).expect("Failed to create user bin directory");

        // Create a user setgid binary
        let user_tool = create_setgid_binary_in_dir(
            &user_bin_dir,
            "user_setgid_tool",
            b"#!/bin/sh\necho 'User setgid tool'\n",
        )
        .expect("Failed to create user tool");

        // Verify both have setgid bit
        assert!(is_setgid(&system_tool).unwrap());
        assert!(is_setgid(&user_tool).unwrap());

        // Create a mixed PATH: system paths + user paths
        let original_path = std::env::var("PATH").unwrap_or_default();
        let mixed_path = format!(
            "/usr/local/bin:/usr/bin:{}:{}:{}",
            test_bin_dir.display(),
            user_bin_dir.display(),
            original_path
        );
        std::env::set_var("PATH", mixed_path);

        // Find setgid binaries
        let setgid_bins = find_setgid_binaries_in_path().expect("Failed to find setgid binaries");

        // Verify both tools are detected
        let system_found = setgid_bins
            .iter()
            .any(|info| info.path.file_name().unwrap() == "system_setgid_tool" && info.has_setgid);
        let user_found = setgid_bins
            .iter()
            .any(|info| info.path.file_name().unwrap() == "user_setgid_tool" && info.has_setgid);

        assert!(
            system_found,
            "System setgid binary should be detected in mixed PATH. Found: {:?}",
            setgid_bins
        );
        assert!(
            user_found,
            "User setgid binary should be detected in mixed PATH. Found: {:?}",
            setgid_bins
        );

        // Restore PATH
        std::env::set_var("PATH", original_path);

        // Clean up user directory
        fs::remove_dir_all(&user_bin_dir).expect("Failed to clean up user bin directory");
    }

    /// Helper function to create a setgid binary in a specific directory
    ///
    /// This is a helper function that creates a setgid binary with mode 2755
    /// in the specified directory, used for testing user PATH scenarios.
    fn create_setgid_binary_in_dir(
        dir: &Path,
        name: &str,
        content: &[u8],
    ) -> anyhow::Result<PathBuf> {
        // Ensure the directory exists
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

    /// Helper function to create a regular executable binary in a specific directory
    ///
    /// This is a helper function that creates a regular executable binary with mode 0755
    /// in the specified directory, used for testing that regular binaries aren't flagged.
    fn create_executable_binary_in_dir(
        dir: &Path,
        name: &str,
        content: &[u8],
    ) -> anyhow::Result<PathBuf> {
        // Ensure the directory exists
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

        // Set permissions without setgid bit (0o0755)
        let mut perms = fs::metadata(&binary_path)
            .with_context(|| format!("Failed to get file metadata for {:?}", binary_path))?
            .permissions();

        perms.set_mode(0o0755);
        fs::set_permissions(&binary_path, perms)
            .with_context(|| format!("Failed to set file permissions for {:?}", binary_path))?;

        Ok(binary_path)
    }
}
