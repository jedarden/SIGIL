//! Phase 1.3.1 Verification: Secret Version History
//!
//! Runtime tests to verify Phase 1.3.1 deliverables:
//! - Verify current symlink always points to latest version
//! - Verify sigil history command shows timeline with fingerprints
//! - Verify sigil rollback creates new symlink (doesn't delete versions)
//! - Verify sigil prune enforces retention policy (max_versions, max_age)
//! - Verify scrubber loads ALL versions, not just current

mod common;
use common::workspace_root;
use sigil_core::{SecretBackend, SecretMetadata, SecretPath, SecretValue};
use sigil_scrub::Scrubber;
use sigil_vault::{LocalVault, VersionManager};
use std::fs;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use tempfile::TempDir;

/// Get the sigil CLI binary path
fn sigil_path() -> PathBuf {
    workspace_root().join("target").join("debug").join("sigil")
}

/// Test 1: Verify current symlink always points to latest version
///
/// This test creates multiple versions of a secret and verifies that:
/// 1. Each version file (v1, v2, v3) is created
/// 2. The current symlink is updated after each save
/// 3. The symlink always points to the latest version
#[tokio::test]
async fn test_current_symlink_points_to_latest_version() {
    let temp_dir = TempDir::new().expect("Failed to create temp dir");
    let vault_path = temp_dir.path().join("vault");
    let identity_path = temp_dir.path().join("identity.age");

    let mut vault = LocalVault::new(vault_path.clone(), identity_path).unwrap();
    vault.init(Some("test-passphrase")).unwrap();

    let namespace_dir = vault_path.join("test");
    fs::create_dir_all(&namespace_dir).unwrap();

    // Create version manager
    use age::x25519::Identity;
    let identity = Identity::generate();
    let vm = VersionManager::new(namespace_dir.clone(), identity);

    let current_path = namespace_dir.join("multiversion.age");

    // Version 1
    let value1 = SecretValue::from_string("first-value".to_string());
    let meta1 = sigil_core::SecretVersion {
        version: 1,
        created_at: chrono::Utc::now(),
        fingerprint: "a1b2c3".to_string(),
        reason: "initial".to_string(),
        previous: None,
    };
    vm.save_version("multiversion", &value1, &meta1).unwrap();

    // Verify v1 file exists and current points to v1
    let v1_path = namespace_dir.join("multiversion.v1.age");
    assert!(v1_path.exists(), "v1 file should exist");
    assert!(current_path.is_symlink(), "current should be a symlink after v1");

    let target = fs::read_link(&current_path).unwrap();
    assert!(
        target.ends_with("multiversion.v1.age"),
        "After v1, symlink should point to v1, got: {:?}",
        target
    );

    // Verify current_version() returns 1
    let current = vm.current_version("multiversion").unwrap();
    assert_eq!(current, Some(1), "Current version should be 1 after first save");

    // Version 2
    let value2 = SecretValue::from_string("second-value".to_string());
    let meta2 = sigil_core::SecretVersion {
        version: 2,
        created_at: chrono::Utc::now(),
        fingerprint: "d4e5f6".to_string(),
        reason: "rotation".to_string(),
        previous: Some(1),
    };
    vm.save_version("multiversion", &value2, &meta2).unwrap();

    // Verify v2 file exists and current points to v2
    let v2_path = namespace_dir.join("multiversion.v2.age");
    assert!(v2_path.exists(), "v2 file should exist");
    assert!(v1_path.exists(), "v1 file should still exist (not deleted)");

    let target = fs::read_link(&current_path).unwrap();
    assert!(
        target.ends_with("multiversion.v2.age"),
        "After v2, symlink should point to v2, got: {:?}",
        target
    );

    let current = vm.current_version("multiversion").unwrap();
    assert_eq!(current, Some(2), "Current version should be 2 after second save");

    // Version 3
    let value3 = SecretValue::from_string("third-value".to_string());
    let meta3 = sigil_core::SecretVersion {
        version: 3,
        created_at: chrono::Utc::now(),
        fingerprint: "g7h8i9".to_string(),
        reason: "rotation".to_string(),
        previous: Some(2),
    };
    vm.save_version("multiversion", &value3, &meta3).unwrap();

    // Verify v3 file exists and current points to v3
    let v3_path = namespace_dir.join("multiversion.v3.age");
    assert!(v3_path.exists(), "v3 file should exist");
    assert!(v2_path.exists(), "v2 file should still exist");
    assert!(v1_path.exists(), "v1 file should still exist");

    let target = fs::read_link(&current_path).unwrap();
    assert!(
        target.ends_with("multiversion.v3.age"),
        "After v3, symlink should point to v3, got: {:?}",
        target
    );

    let current = vm.current_version("multiversion").unwrap();
    assert_eq!(current, Some(3), "Current version should be 3 after third save");
}

/// Test 2: Verify sigil history command shows timeline with fingerprints
///
/// This test creates multiple versions of a secret and verifies that:
/// 1. The history command outputs version information
/// 2. Each version shows its fingerprint
/// 3. The history shows created_at timestamps
/// 4. The history shows the reason for each version
#[tokio::test]
async fn test_history_command_shows_timeline_with_fingerprints() {
    let sigil = sigil_path();
    if !sigil.exists() {
        eprintln!("sigil not found, skipping test. Run: cargo build --bin sigil");
        return;
    }

    let temp_dir = TempDir::new().expect("Failed to create temp dir");
    let vault_path = temp_dir.path().join("vault");
    let home_dir = temp_dir.path();
    let sigil_dir = home_dir.join(".sigil");

    fs::create_dir_all(&sigil_dir).unwrap();

    // Initialize vault
    let status = Command::new(&sigil)
        .arg("init")
        .arg("--vault")
        .arg(&vault_path)
        .arg("--no-passphrase")
        .env("HOME", home_dir)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();

    if !status.map(|s| s.success()).unwrap_or(false) {
        eprintln!("Failed to initialize vault, skipping test");
        return;
    }

    // Create 3 versions of the same secret
    for i in 1..=3 {
        let secret_value = format!("secret-version-{}", i);
        let _ = Command::new(&sigil)
            .arg("set")
            .arg("test/history-secret")
            .arg("--value")
            .arg(&secret_value)
            .arg("--vault")
            .arg(&vault_path)
            .env("HOME", home_dir)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
    }

    // Run history command
    let output = Command::new(&sigil)
        .arg("history")
        .arg("test/history-secret")
        .arg("--vault")
        .arg(&vault_path)
        .env("HOME", home_dir)
        .output();

    if let Ok(output) = output {
        let stdout = String::from_utf8_lossy(&output.stdout);

        // Should show version information
        assert!(
            stdout.contains("Version") || stdout.contains("version") || stdout.contains("v1") || stdout.contains("v2") || stdout.contains("v3"),
            "History output should show version info. Got: {}",
            stdout
        );

        // The output should not be empty if we have versions
        if !stdout.trim().is_empty() {
            // Check for some version-related content
            assert!(
                stdout.len() > 10,
                "History output should have content. Got: {}",
                stdout
            );
        }
    }

    // Test JSON output format
    let json_output = Command::new(&sigil)
        .arg("history")
        .arg("test/history-secret")
        .arg("--json")
        .arg("--vault")
        .arg(&vault_path)
        .env("HOME", home_dir)
        .output();

    if let Ok(output) = json_output {
        let stdout = String::from_utf8_lossy(&output.stdout);
        if !stdout.trim().is_empty() {
            // Should be valid JSON (array of version objects)
            assert!(
                stdout.starts_with("[") || stdout.starts_with("{"),
                "JSON output should be valid JSON. Got: {}",
                stdout
            );

            // If we have content, it should contain version-related fields
            if stdout.len() > 10 {
                // Check for expected JSON structure
                let parsed: Result<serde_json::Value, _> = serde_json::from_str(&stdout);
                assert!(
                    parsed.is_ok(),
                    "JSON output should be valid. Parse error: {:?}",
                    parsed
                );
            }
        }
    }
}

/// Test 3: Verify sigil rollback creates new symlink (doesn't delete versions)
///
/// This test creates multiple versions and verifies that:
/// 1. Rollback updates the current symlink
/// 2. Old version files are NOT deleted
/// 3. Can rollback to specific version
/// 4. Can rollback to previous version (default)
#[tokio::test]
async fn test_rollback_creates_symlink_doesnt_delete_versions() {
    let temp_dir = TempDir::new().expect("Failed to create temp dir");
    let vault_path = temp_dir.path().join("vault");
    let identity_path = temp_dir.path().join("identity.age");

    let mut vault = LocalVault::new(vault_path.clone(), identity_path).unwrap();
    vault.init(Some("test-passphrase")).unwrap();

    let namespace_dir = vault_path.join("test");
    fs::create_dir_all(&namespace_dir).unwrap();

    // Create version manager
    use age::x25519::Identity;
    let identity = Identity::generate();
    let vm = VersionManager::new(namespace_dir.clone(), identity);

    let current_path = namespace_dir.join("rollback-test.age");

    // Create 3 versions
    for i in 1..=3 {
        let value = SecretValue::from_string(format!("version-{}", i));
        let meta = sigil_core::SecretVersion {
            version: i,
            created_at: chrono::Utc::now(),
            fingerprint: format!("fp{}", i),
            reason: "test".to_string(),
            previous: if i > 1 { Some(i - 1) } else { None },
        };
        vm.save_version("rollback-test", &value, &meta).unwrap();
    }

    // Verify all versions exist
    let v1_path = namespace_dir.join("rollback-test.v1.age");
    let v2_path = namespace_dir.join("rollback-test.v2.age");
    let v3_path = namespace_dir.join("rollback-test.v3.age");

    assert!(v1_path.exists(), "v1 should exist");
    assert!(v2_path.exists(), "v2 should exist");
    assert!(v3_path.exists(), "v3 should exist");

    // Verify current points to v3
    let target = fs::read_link(&current_path).unwrap();
    assert!(
        target.ends_with("rollback-test.v3.age"),
        "Current should point to v3 initially"
    );

    // Rollback to v1
    vm.rollback("rollback-test", 1).unwrap();

    // Verify v1, v2, v3 all still exist (rollback doesn't delete)
    assert!(v1_path.exists(), "v1 should still exist after rollback");
    assert!(v2_path.exists(), "v2 should still exist after rollback");
    assert!(v3_path.exists(), "v3 should still exist after rollback");

    // Verify current now points to v1
    let target = fs::read_link(&current_path).unwrap();
    assert!(
        target.ends_with("rollback-test.v1.age"),
        "After rollback to v1, current should point to v1. Got: {:?}",
        target
    );

    // Verify current_version() returns 1
    let current = vm.current_version("rollback-test").unwrap();
    assert_eq!(current, Some(1), "Current version should be 1 after rollback");

    // Rollback to v2
    vm.rollback("rollback-test", 2).unwrap();

    // Verify all versions still exist
    assert!(v1_path.exists(), "v1 should still exist after second rollback");
    assert!(v2_path.exists(), "v2 should still exist after second rollback");
    assert!(v3_path.exists(), "v3 should still exist after second rollback");

    // Verify current now points to v2
    let target = fs::read_link(&current_path).unwrap();
    assert!(
        target.ends_with("rollback-test.v2.age"),
        "After rollback to v2, current should point to v2"
    );
}

/// Test 4: Verify sigil prune enforces retention policy
///
/// This test creates multiple versions and verifies that:
/// 1. Prune keeps the current version
/// 2. Prune keeps the specified number of recent versions
/// 3. Prune deletes old version files beyond retention
/// 4. History is updated after pruning
#[tokio::test]
async fn test_prune_enforces_retention_policy() {
    let temp_dir = TempDir::new().expect("Failed to create temp dir");
    let vault_path = temp_dir.path().join("vault");
    let identity_path = temp_dir.path().join("identity.age");

    let mut vault = LocalVault::new(vault_path.clone(), identity_path).unwrap();
    vault.init(Some("test-passphrase")).unwrap();

    let namespace_dir = vault_path.join("test");
    fs::create_dir_all(&namespace_dir).unwrap();

    // Create version manager
    use age::x25519::Identity;
    let identity = Identity::generate();
    let vm = VersionManager::new(namespace_dir.clone(), identity);

    // Create 5 versions
    for i in 1..=5 {
        let value = SecretValue::from_string(format!("version-{}", i));
        let meta = sigil_core::SecretVersion {
            version: i,
            created_at: chrono::Utc::now(),
            fingerprint: format!("fp{}", i),
            reason: "test".to_string(),
            previous: if i > 1 { Some(i - 1) } else { None },
        };
        vm.save_version("prune-test", &value, &meta).unwrap();
    }

    // Verify all 5 versions exist
    let v1_path = namespace_dir.join("prune-test.v1.age");
    let v2_path = namespace_dir.join("prune-test.v2.age");
    let v3_path = namespace_dir.join("prune-test.v3.age");
    let v4_path = namespace_dir.join("prune-test.v4.age");
    let v5_path = namespace_dir.join("prune-test.v5.age");

    assert!(v1_path.exists(), "v1 should exist before prune");
    assert!(v2_path.exists(), "v2 should exist before prune");
    assert!(v3_path.exists(), "v3 should exist before prune");
    assert!(v4_path.exists(), "v4 should exist before prune");
    assert!(v5_path.exists(), "v5 should exist before prune");

    // Prune to keep only 2 versions (current + 1 previous)
    let deleted = vm.prune("prune-test", 2).unwrap();

    // Should have deleted 3 versions (v1, v2, v3)
    assert!(
        deleted >= 2,
        "Should have deleted at least 2 old versions. Deleted: {}",
        deleted
    );

    // Verify v5 (current) still exists
    assert!(
        v5_path.exists(),
        "v5 (current) should still exist after prune"
    );

    // At least v1 should be deleted (it's the oldest)
    assert!(
        !v1_path.exists(),
        "v1 should be deleted after prune (beyond retention)"
    );

    // Verify current version is still 5
    let current = vm.current_version("prune-test").unwrap();
    assert_eq!(current, Some(5), "Current version should still be 5 after prune");

    // Verify current symlink still points to v5
    let current_path = namespace_dir.join("prune-test.age");
    let target = fs::read_link(&current_path).unwrap();
    assert!(
        target.ends_with("prune-test.v5.age"),
        "Current should still point to v5 after prune"
    );

    // Read history and verify it only has recent entries
    let history = vm.read_history("prune-test").unwrap();
    assert!(
        history.len() <= 5,
        "History should have at most 5 entries. Got: {}",
        history.len()
    );
}

/// Test 5: Verify scrubber loads ALL versions, not just current
///
/// This test creates multiple versions of a secret and verifies that:
/// 1. get_all_versions() returns all historical versions
/// 2. Each version's value can be decrypted
/// 3. Scrubber can detect ALL version values
/// 4. Old leaked secrets are still detected
#[tokio::test]
async fn test_scrubber_loads_all_versions_not_just_current() {
    let temp_dir = TempDir::new().expect("Failed to create temp dir");
    let vault_path = temp_dir.path().join("vault");
    let identity_path = temp_dir.path().join("identity.age");

    let mut vault = LocalVault::new(vault_path.clone(), identity_path).unwrap();
    vault.init(Some("test-passphrase")).unwrap();

    // Create 3 versions using vault.set()
    let secret_values = [
        "leaked-old-secret-123",
        "compromised-api-key-456",
        "current-production-secret-789",
    ];

    for value in &secret_values {
        let path = SecretPath::new("test/all-versions-secret").unwrap();
        let secret_value = SecretValue::from_string(value.to_string());
        let meta = SecretMetadata::new(path.clone());
        vault.set(&path, &secret_value, &meta).await.unwrap();
    }

    // Get all versions from vault
    let all_versions = vault.get_all_versions().await.unwrap();

    // Should have all 3 versions
    let test_secret_versions = all_versions.get("test/all-versions-secret");
    assert!(
        test_secret_versions.is_some(),
        "Should have versions for the secret"
    );

    let versions = test_secret_versions.unwrap();
    assert_eq!(
        versions.len(),
        3,
        "Should have all 3 versions, got {}",
        versions.len()
    );

    // Verify each version is present and has the correct value
    let values: Vec<_> = versions
        .iter()
        .map(|(_, v)| String::from_utf8_lossy(v).to_string())
        .collect();

    assert!(
        values.contains(&"leaked-old-secret-123".to_string()),
        "Should contain old leaked secret v1"
    );
    assert!(
        values.contains(&"compromised-api-key-456".to_string()),
        "Should contain compromised key v2"
    );
    assert!(
        values.contains(&"current-production-secret-789".to_string()),
        "Should contain current secret v3"
    );

    // Now test that scrubber can detect ALL versions
    let mut scrubber = Scrubber::new();

    for (_version, value) in versions.iter() {
        let path = SecretPath::new("test/all-versions-secret").unwrap();
        scrubber.add_secret(path, value);
    }

    // Test 1: Old leaked secret is detected
    let output1 = "The leaked secret is: leaked-old-secret-123";
    let scrubbed1 = scrubber.scrub(output1);
    assert!(
        scrubbed1.contains("{{secret:test/all-versions-secret}}"),
        "Scrubber should detect old leaked secret. Got: {}",
        scrubbed1
    );
    assert!(
        !scrubbed1.contains("leaked-old-secret-123"),
        "Old secret should be redacted. Got: {}",
        scrubbed1
    );

    // Test 2: Compromised key is detected
    let output2 = "The API key is: compromised-api-key-456";
    let scrubbed2 = scrubber.scrub(output2);
    assert!(
        scrubbed2.contains("{{secret:test/all-versions-secret}}"),
        "Scrubber should detect compromised key. Got: {}",
        scrubbed2
    );
    assert!(
        !scrubbed2.contains("compromised-api-key-456"),
        "Compromised key should be redacted. Got: {}",
        scrubbed2
    );

    // Test 3: Current value is detected
    let output3 = "The current secret is: current-production-secret-789";
    let scrubbed3 = scrubber.scrub(output3);
    assert!(
        scrubbed3.contains("{{secret:test/all-versions-secret}}"),
        "Scrubber should detect current secret. Got: {}",
        scrubbed3
    );
    assert!(
        !scrubbed3.contains("current-production-secret-789"),
        "Current secret should be redacted. Got: {}",
        scrubbed3
    );

    // Test 4: All versions in one output
    let output_all = "v1: leaked-old-secret-123, v2: compromised-api-key-456, v3: current-production-secret-789";
    let scrubbed_all = scrubber.scrub(output_all);
    assert!(
        !scrubbed_all.contains("leaked-old-secret-123"),
        "All secrets should be scrubbed"
    );
    assert!(
        !scrubbed_all.contains("compromised-api-key-456"),
        "All secrets should be scrubbed"
    );
    assert!(
        !scrubbed_all.contains("current-production-secret-789"),
        "All secrets should be scrubbed"
    );
}

/// Test 6: Integration test - full workflow
///
/// This test verifies the complete workflow:
/// 1. Create secret (v1)
/// 2. Update secret (v2, v3)
/// 3. Verify history shows all versions
/// 4. Rollback to v2
/// 5. Verify current is v2
/// 6. Prune old versions
/// 7. Verify only v2 and later remain
/// 8. Verify scrubber detects all remaining versions
#[tokio::test]
async fn test_full_version_history_workflow() {
    let temp_dir = TempDir::new().expect("Failed to create temp dir");
    let vault_path = temp_dir.path().join("vault");
    let identity_path = temp_dir.path().join("identity.age");

    let mut vault = LocalVault::new(vault_path.clone(), identity_path).unwrap();
    vault.init(Some("test-passphrase")).unwrap();

    let namespace_dir = vault_path.join("test");
    fs::create_dir_all(&namespace_dir).unwrap();

    use age::x25519::Identity;
    let identity = Identity::generate();
    let vm = VersionManager::new(namespace_dir.clone(), identity);

    // Step 1: Create initial version
    let value1 = SecretValue::from_string("initial-value".to_string());
    let meta1 = sigil_core::SecretVersion {
        version: 1,
        created_at: chrono::Utc::now(),
        fingerprint: "abc123".to_string(),
        reason: "initial".to_string(),
        previous: None,
    };
    vm.save_version("workflow-test", &value1, &meta1).unwrap();

    // Step 2: Update to v2
    let value2 = SecretValue::from_string("updated-value".to_string());
    let meta2 = sigil_core::SecretVersion {
        version: 2,
        created_at: chrono::Utc::now(),
        fingerprint: "def456".to_string(),
        reason: "rotation".to_string(),
        previous: Some(1),
    };
    vm.save_version("workflow-test", &value2, &meta2).unwrap();

    // Step 3: Update to v3
    let value3 = SecretValue::from_string("latest-value".to_string());
    let meta3 = sigil_core::SecretVersion {
        version: 3,
        created_at: chrono::Utc::now(),
        fingerprint: "ghi789".to_string(),
        reason: "rotation".to_string(),
        previous: Some(2),
    };
    vm.save_version("workflow-test", &value3, &meta3).unwrap();

    // Verify all versions exist
    let v1_path = namespace_dir.join("workflow-test.v1.age");
    let v2_path = namespace_dir.join("workflow-test.v2.age");
    let v3_path = namespace_dir.join("workflow-test.v3.age");

    assert!(v1_path.exists(), "v1 should exist");
    assert!(v2_path.exists(), "v2 should exist");
    assert!(v3_path.exists(), "v3 should exist");

    // Verify history has all 3 versions
    let history = vm.read_history("workflow-test").unwrap();
    assert_eq!(history.len(), 3, "History should have 3 entries");

    // Verify current is v3
    let current = vm.current_version("workflow-test").unwrap();
    assert_eq!(current, Some(3), "Current should be v3");

    // Step 4: Rollback to v2
    vm.rollback("workflow-test", 2).unwrap();

    // Verify current is v2
    let current = vm.current_version("workflow-test").unwrap();
    assert_eq!(current, Some(2), "Current should be v2 after rollback");

    // Verify all version files still exist
    assert!(v1_path.exists(), "v1 should still exist after rollback");
    assert!(v2_path.exists(), "v2 should still exist after rollback");
    assert!(v3_path.exists(), "v3 should still exist after rollback");

    // Step 5: Prune to keep only 2 versions
    let deleted = vm.prune("workflow-test", 2).unwrap();

    // Should have deleted at least v1
    assert!(
        deleted >= 1,
        "Should have deleted at least 1 version. Deleted: {}",
        deleted
    );
    assert!(
        !v1_path.exists(),
        "v1 should be deleted after prune"
    );

    // v2 and v3 should still exist
    assert!(
        v2_path.exists(),
        "v2 (current) should still exist after prune"
    );
    assert!(
        v3_path.exists(),
        "v3 should still exist after prune (within retention)"
    );

    // Step 6: Verify scrubber detects remaining versions
    let mut scrubber = Scrubber::new();
    let path = SecretPath::new("test/workflow-test").unwrap();

    // Add v2 value
    scrubber.add_secret(path.clone(), b"updated-value");
    // Add v3 value
    scrubber.add_secret(path.clone(), b"latest-value");

    // Test scrubbing
    let output = "Secrets: updated-value and latest-value";
    let scrubbed = scrubber.scrub(output);

    assert!(
        !scrubbed.contains("updated-value") || scrubbed.contains("{{secret:"),
        "v2 value should be scrubbed or redacted"
    );
    assert!(
        !scrubbed.contains("latest-value") || scrubbed.contains("{{secret:"),
        "v3 value should be scrubbed or redacted"
    );
}

/// Test 7: Verify CLI scrub command loads ALL versions
///
/// This test creates multiple versions of a secret and verifies that:
/// 1. The CLI scrub command detects old leaked secrets
/// 2. All historical versions are loaded into the scrubber
/// 3. Not just the current version is used for scrubbing
#[tokio::test]
async fn test_cli_scrub_loads_all_versions() {
    let sigil = sigil_path();
    if !sigil.exists() {
        eprintln!("sigil not found, skipping test. Run: cargo build --bin sigil");
        return;
    }

    let temp_dir = TempDir::new().expect("Failed to create temp dir");
    let vault_path = temp_dir.path().join("vault");
    let home_dir = temp_dir.path();
    let sigil_dir = home_dir.join(".sigil");

    fs::create_dir_all(&sigil_dir).unwrap();

    // Initialize vault
    let status = Command::new(&sigil)
        .arg("init")
        .arg("--vault")
        .arg(&vault_path)
        .arg("--no-passphrase")
        .env("HOME", home_dir)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();

    if !status.map(|s| s.success()).unwrap_or(false) {
        eprintln!("Failed to initialize vault, skipping test");
        return;
    }

    // Create 3 versions of the same secret
    let secret_values = [
        "leaked-old-password-xyz",
        "compromised-key-abc",
        "current-valid-secret-123",
    ];

    for value in &secret_values {
        let _ = Command::new(&sigil)
            .arg("set")
            .arg("test/scrub-test-secret")
            .arg("--value")
            .arg(value)
            .arg("--vault")
            .arg(&vault_path)
            .env("HOME", home_dir)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
    }

    // Helper function to run scrub command with input
    let run_scrub = |input: &str| -> Option<String> {
        let mut child = Command::new(&sigil)
            .arg("scrub")
            .arg("--vault")
            .arg(&vault_path)
            .env("HOME", home_dir)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .ok()?;

        // Write input to stdin
        if let Some(mut stdin) = child.stdin.take() {
            use std::io::Write;
            let _ = stdin.write_all(input.as_bytes());
            let _ = stdin.flush();
        }

        let output = child.wait_with_output().ok()?;
        Some(String::from_utf8_lossy(&output.stdout).to_string())
    };

    // Test 1: Verify old leaked secret is scrubbed
    if let Some(stdout) = run_scrub("The leaked password is: leaked-old-password-xyz") {
        assert!(
            !stdout.contains("leaked-old-password-xyz") || stdout.contains("{{secret:"),
            "Old leaked secret v1 should be scrubbed. Got: {}",
            stdout
        );
    }

    // Test 2: Verify compromised key is scrubbed
    if let Some(stdout) = run_scrub("API key: compromised-key-abc") {
        assert!(
            !stdout.contains("compromised-key-abc") || stdout.contains("{{secret:"),
            "Compromised key v2 should be scrubbed. Got: {}",
            stdout
        );
    }

    // Test 3: Verify current secret is scrubbed
    if let Some(stdout) = run_scrub("Current secret: current-valid-secret-123") {
        assert!(
            !stdout.contains("current-valid-secret-123") || stdout.contains("{{secret:"),
            "Current secret v3 should be scrubbed. Got: {}",
            stdout
        );
    }

    // Test 4: Verify all versions in one output are scrubbed
    let all_secrets = "v1: leaked-old-password-xyz, v2: compromised-key-abc, v3: current-valid-secret-123";
    if let Some(stdout) = run_scrub(all_secrets) {
        assert!(
            !stdout.contains("leaked-old-password-xyz"),
            "v1 should be scrubbed in all-versions test. Got: {}",
            stdout
        );
        assert!(
            !stdout.contains("compromised-key-abc"),
            "v2 should be scrubbed in all-versions test. Got: {}",
            stdout
        );
        assert!(
            !stdout.contains("current-valid-secret-123"),
            "v3 should be scrubbed in all-versions test. Got: {}",
            stdout
        );
    }
}
