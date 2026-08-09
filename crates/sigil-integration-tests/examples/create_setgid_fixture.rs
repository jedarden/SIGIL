//! Example: Create and Verify Setgid Test Fixtures
//!
//! This example demonstrates how to create test binaries with the setgid bit
//! set for use in detection tests. It shows the complete workflow:
//!
//! 1. Create a setgid binary
//! 2. Verify the setgid bit is properly set using ls -l
//! 3. Verify the setgid bit using the is_setgid() helper function
//! 4. Clean up the test fixture

use sigil_integration_tests::binary_fixture::*;
use std::os::unix::fs::PermissionsExt;

fn main() -> anyhow::Result<()> {
    println!("=== Setgid Test Fixture Example ===\n");

    // Create a BinaryFixtureGuard for automatic cleanup
    let _guard = BinaryFixtureGuard::new();

    // 1. Create a simple setgid binary
    println!("1. Creating setgid binary...");
    let setgid_bin = create_setgid_binary(
        "test_setgid_fixture",
        b"#!/bin/sh
echo 'This is a setgid test binary'
echo 'Running with group privileges'
id
",
    )?;

    println!("   Created: {:?}", setgid_bin);

    // 2. Verify using stat command (shows permissions in octal)
    println!("\n2. Verifying setgid bit using stat:");
    let stat_output = std::process::Command::new("stat")
        .arg("-c")
        .arg("%a %n") // Show octal permissions and filename
        .arg(&setgid_bin)
        .output()?;

    if stat_output.status.success() {
        let perms = String::from_utf8_lossy(&stat_output.stdout);
        println!("   stat output: {}", perms.trim());
    }

    // 3. Verify using ls -l (shows symbolic permissions)
    println!("\n3. Verifying setgid bit using ls -l:");
    let ls_output = std::process::Command::new("ls")
        .arg("-l")
        .arg(&setgid_bin)
        .output()?;

    if ls_output.status.success() {
        let ls_result = String::from_utf8_lossy(&ls_output.stdout);
        println!("   ls -l output: {}", ls_result.trim());
        // The setgid bit shows as 's' in the group execute position
        if ls_result.contains('s') {
            println!("   ✓ Setgid bit is visible as 's' in group permissions");
        }
    }

    // 4. Verify programmatically using is_setgid()
    println!("\n4. Verifying setgid bit programmatically:");
    let has_setgid = is_setgid(&setgid_bin)?;
    println!("   is_setgid({:?}) = {}", setgid_bin, has_setgid);

    if has_setgid {
        println!("   ✓ Setgid bit is correctly set");
    } else {
        println!("   ✗ ERROR: Setgid bit is NOT set!");
        return Err(anyhow::anyhow!("Setgid bit verification failed"));
    }

    // 5. Verify the actual permission bits
    println!("\n5. Checking permission bits:");
    let metadata = std::fs::metadata(&setgid_bin)?;
    let mode = metadata.permissions().mode();
    println!("   Raw mode: {:04o}", mode);
    println!("   Setgid bit (0o2000): {}", (mode & 0o2000) != 0);
    println!("   Execute bits: {:04o}", mode & 0o755);

    if (mode & 0o2000) != 0 {
        println!("   ✓ Setgid bit (0o2000) is present");
    } else {
        println!("   ✗ ERROR: Setgid bit (0o2000) is missing!");
        return Err(anyhow::anyhow!("Permission bit check failed"));
    }

    // 6. Create a regular (non-setgid) binary for comparison
    println!("\n6. Creating regular binary for comparison:");
    let regular_bin = create_executable_binary(
        "test_regular_fixture",
        b"#!/bin/sh\necho 'Regular binary'\n",
    )?;

    println!("   Created: {:?}", regular_bin);

    let regular_has_setgid = is_setgid(&regular_bin)?;
    println!("   is_setgid({:?}) = {}", regular_bin, regular_has_setgid);

    if !regular_has_setgid {
        println!("   ✓ Regular binary correctly does NOT have setgid bit");
    } else {
        println!("   ✗ ERROR: Regular binary should NOT have setgid bit!");
        return Err(anyhow::anyhow!("Regular binary incorrectly has setgid bit"));
    }

    // 7. Create a binary with both setuid and setgid bits
    println!("\n7. Creating binary with both setuid and setgid bits:");
    let both_bin = create_setuid_setgid_binary(
        "test_setuid_setgid_fixture",
        b"#!/bin/sh\necho 'Has both setuid and setgid bits'\nid\n",
    )?;

    println!("   Created: {:?}", both_bin);

    let both_has_setuid = is_setuid(&both_bin)?;
    let both_has_setgid = is_setgid(&both_bin)?;
    println!("   is_setuid({:?}) = {}", both_bin, both_has_setuid);
    println!("   is_setgid({:?}) = {}", both_bin, both_has_setgid);

    if both_has_setuid && both_has_setgid {
        println!("   ✓ Binary correctly has both setuid and setgid bits");
    } else {
        println!("   ✗ ERROR: Binary should have both bits!");
        return Err(anyhow::anyhow!("Combined bits verification failed"));
    }

    println!("\n=== All Verifications Passed ===");
    println!("\nSummary:");
    println!("- Setgid binary created with correct permissions");
    println!("- is_setgid() function correctly detects setgid bit");
    println!("- Regular binary does NOT have setgid bit (correct)");
    println!("- Combined setuid+setgid binary has both bits (correct)");
    println!("\nFixture location: {:?}", setgid_bin.parent().unwrap());
    println!("Purpose: Test binaries for setgid detection in security tests");

    Ok(())
}
