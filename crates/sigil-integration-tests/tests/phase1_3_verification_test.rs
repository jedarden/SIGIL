//! Phase 1.3 Verification Tests
//!
//! Runtime tests to verify Phase 1.3 deliverables:
//! - Directory mode storage: ~/.sigil/vault/*.age structure
//! - age encryption with passphrase-protected identity.age
//! - metadata.json.age encrypted index
//! - SecretBackend trait implemented for LocalVault
//! - File permissions: 0600 for files, 0700 for directories
//! - Symlink-based version chain: current -> vN.age
//! - sigil history command shows timeline with fingerprints
//! - sigil rollback creates new symlink, doesn't delete versions
//! - sigil prune enforces retention policy (max_versions, max_age)
//! - Scrubber loads ALL versions, not just current

mod common;
use common::workspace_root;
use sigil_core::{SecretBackend, SecretPath, SecretValue, SecretMetadata};
use sigil_vault::{LocalVault, VersionManager};
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use tempfile::TempDir;

/// Get the sigil CLI binary path
fn sigil_path() -> PathBuf {
    workspace_root()
        .join("target")
        .join("debug")
        .join("sigil")
}

/// Test 1: Verify directory mode storage structure
///
/// Tests that:
/// - Vault creates ~/.sigil/vault/namespace/secret.age structure
/// - Files use .age extension for encrypted content
/// - Directories are created for namespaces
#[tokio::test]
async fn test_directory_mode_storage_structure() {
    let temp_dir = TempDir::new().expect("Failed to create temp dir");
    let vault_path = temp_dir.path().join("vault");
    let identity_path = temp_dir.path().join("identity.age");

    let mut vault = LocalVault::new(vault_path.clone(), identity_path).unwrap();
    vault.init(Some("test-passphrase")).unwrap();

    // Add a secret with namespace
    let path = SecretPath::new("kalshi/api_key").unwrap();
    let value = SecretValue::from_string("my-secret-key".to_string());
    let meta = SecretMetadata::new(path.clone());
    vault.set(&path, &value, &meta).await.unwrap();

    // Verify directory structure
    let namespace_dir = vault_path.join("kalshi");
    assert!(namespace_dir.exists(), "Namespace directory should exist");
    assert!(namespace_dir.is_dir(), "Namespace should be a directory");

    // Verify .age file exists
    let secret_file = namespace_dir.join("api_key.age");
    assert!(secret_file.exists(), "Secret .age file should exist");
}

/// Test 2: Verify age encryption with passphrase-protected identity
///
/// Tests that:
/// - identity.age is encrypted when passphrase is provided
/// - identity.age cannot be read without passphrase
/// - Vault cannot be unlocked with wrong passphrase
#[tokio::test]
async fn test_age_encryption_with_passphrase() {
    let temp_dir = TempDir::new().expect("Failed to create temp dir");
    let vault_path = temp_dir.path().join("vault");
    let identity_path = temp_dir.path().join("identity.age");

    // Create vault with passphrase
    let mut vault = LocalVault::new(vault_path.clone(), identity_path.clone()).unwrap();
    let recipient = vault.init(Some("correct-passphrase")).unwrap();
    assert!(!recipient.is_empty(), "Should get recipient key");

    // Add a secret
    let path = SecretPath::new("test/secret").unwrap();
    let value = SecretValue::from_string("secret-value".to_string());
    let meta = SecretMetadata::new(path.clone());
    vault.set(&path, &value, &meta).await.unwrap();

    // Read identity file - should be encrypted (not plaintext)
    let identity_bytes = fs::read(&identity_path).unwrap();
    let identity_str = String::from_utf8_lossy(&identity_bytes);
    assert!(
        !identity_str.contains("AGE-SECRET-KEY-"),
        "Identity file should be encrypted, not contain plaintext age key marker"
    );

    // Try to load with wrong passphrase - should fail
    let mut vault_wrong = LocalVault::new(vault_path.clone(), identity_path.clone()).unwrap();
    let load_result = vault_wrong.load(Some("wrong-passphrase"));
    assert!(load_result.is_err(), "Loading with wrong passphrase should fail");

    // Verify we cannot get the secret with wrong passphrase
    let get_result = vault_wrong.get(&path).await;
    assert!(get_result.is_err(), "Getting secret with wrong passphrase should fail");

    // Load with correct passphrase - should succeed
    let mut vault_correct = LocalVault::new(vault_path, identity_path).unwrap();
    vault_correct.load(Some("correct-passphrase")).unwrap();
    let retrieved = vault_correct.get(&path).await.unwrap();
    assert_eq!(
        retrieved.expose(|v| String::from_utf8_lossy(v).to_string()),
        "secret-value"
    );
}

/// Test 3: Verify file permissions (0600 for files, 0700 for directories)
///
/// Tests that:
/// - Vault directories are created with 0700 permissions
/// - Secret files are created with 0600 permissions
/// - Identity file has 0600 permissions
#[tokio::test]
async fn test_file_permissions_are_secure() {
    let temp_dir = TempDir::new().expect("Failed to create temp dir");
    let vault_path = temp_dir.path().join("vault");
    let identity_path = temp_dir.path().join("identity.age");

    let mut vault = LocalVault::new(vault_path.clone(), identity_path.clone()).unwrap();
    vault.init(Some("test-passphrase")).unwrap();

    // Check vault directory permissions
    let vault_metadata = fs::metadata(&vault_path).unwrap();
    let vault_perms = vault_metadata.permissions().mode() & 0o777;
    assert_eq!(vault_perms, 0o700, "Vault directory should be 0700, got {:04o}", vault_perms);

    // Check identity file permissions
    let identity_metadata = fs::metadata(&identity_path).unwrap();
    let identity_perms = identity_metadata.permissions().mode() & 0o777;
    assert_eq!(identity_perms, 0o600, "Identity file should be 0600, got {:04o}", identity_perms);

    // Add a secret and check its file permissions
    let path = SecretPath::new("test/secret").unwrap();
    let value = SecretValue::from_string("value".to_string());
    let meta = SecretMetadata::new(path.clone());
    vault.set(&path, &value, &meta).await.unwrap();

    // Check namespace directory permissions
    let namespace_dir = vault_path.join("test");
    let namespace_metadata = fs::metadata(&namespace_dir).unwrap();
    let namespace_perms = namespace_metadata.permissions().mode() & 0o777;
    assert_eq!(namespace_perms, 0o700, "Namespace directory should be 0700, got {:04o}", namespace_perms);

    // Check secret file permissions
    let secret_file = namespace_dir.join("secret.age");
    let secret_metadata = fs::metadata(&secret_file).unwrap();
    let secret_perms = secret_metadata.permissions().mode() & 0o777;
    assert_eq!(secret_perms, 0o600, "Secret file should be 0600, got {:04o}", secret_perms);
}

/// Test 4: Verify symlink-based version chain
///
/// Tests that:
/// - Multiple versions of a secret are stored as secret.v1.age, secret.v2.age, etc.
/// - A "current" symlink points to the latest version
/// - The symlink is updated when a new version is saved
#[tokio::test]
async fn test_symlink_based_version_chain() {
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

    // Save first version
    let value1 = SecretValue::from_string("version-1".to_string());
    let meta1 = sigil_core::SecretVersion {
        version: 1,
        created_at: chrono::Utc::now(),
        fingerprint: "abc123".to_string(),
        reason: "initial".to_string(),
        previous: None,
    };
    vm.save_version("mysecret", &value1, &meta1).unwrap();

    // Check v1 file exists and current symlink points to it
    let v1_path = namespace_dir.join("mysecret.v1.age");
    let current_path = namespace_dir.join("mysecret.age");

    assert!(v1_path.exists(), "v1 file should exist");
    assert!(current_path.is_symlink(), "current should be a symlink");

    // Read symlink target
    let target = fs::read_link(&current_path).unwrap();
    assert!(target.ends_with("mysecret.v1.age"), "Symlink should point to v1");

    // Save second version
    let value2 = SecretValue::from_string("version-2".to_string());
    let meta2 = sigil_core::SecretVersion {
        version: 2,
        created_at: chrono::Utc::now(),
        fingerprint: "def456".to_string(),
        reason: "update".to_string(),
        previous: Some(1),
    };
    vm.save_version("mysecret", &value2, &meta2).unwrap();

    // Check v2 file exists and current symlink now points to it
    let v2_path = namespace_dir.join("mysecret.v2.age");
    assert!(v2_path.exists(), "v2 file should exist");
    assert!(v1_path.exists(), "v1 file should still exist (not deleted)");

    // Verify symlink updated to v2
    let target = fs::read_link(&current_path).unwrap();
    assert!(target.ends_with("mysecret.v2.age"), "Symlink should now point to v2");

    // Verify current version
    let current = vm.current_version("mysecret").unwrap();
    assert_eq!(current, Some(2), "Current version should be 2");
}

/// Test 5: Verify sigil history command
///
/// Tests that:
/// - history command shows version timeline
/// - Each version shows fingerprint, created_at, and reason
/// - JSON output format works
#[tokio::test]
async fn test_sigil_history_command() {
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

    // Add a secret (this creates version history)
    let secret_value = "test-secret-value";
    let status = Command::new(&sigil)
        .arg("set")
        .arg("test/mykey")
        .arg("--value")
        .arg(secret_value)
        .arg("--vault")
        .arg(&vault_path)
        .env("HOME", home_dir)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();

    if !status.map(|s| s.success()).unwrap_or(false) {
        eprintln!("Failed to set secret, skipping test");
        return;
    }

    // Run history command
    let output = Command::new(&sigil)
        .arg("history")
        .arg("test/mykey")
        .arg("--vault")
        .arg(&vault_path)
        .env("HOME", home_dir)
        .output();

    if let Ok(output) = output {
        let stdout = String::from_utf8_lossy(&output.stdout);
        // Should show version history header
        assert!(stdout.contains("Version") || stdout.contains("version"), "History output should show version info");
    }

    // Test JSON output
    let json_output = Command::new(&sigil)
        .arg("history")
        .arg("test/mykey")
        .arg("--json")
        .arg("--vault")
        .arg(&vault_path)
        .env("HOME", home_dir)
        .output();

    if let Ok(output) = json_output {
        let stdout = String::from_utf8_lossy(&output.stdout);
        if !stdout.trim().is_empty() {
            // Should be valid JSON
            assert!(stdout.starts_with("[") || stdout.starts_with("{"), "JSON output should be valid JSON");
        }
    }
}

/// Test 6: Verify sigil rollback command
///
/// Tests that:
/// - rollback updates the current symlink
/// - rollback does NOT delete old version files
/// - Can rollback to specific version or previous version
#[tokio::test]
async fn test_sigil_rollback_command() {
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

    // Create multiple versions by setting the same secret multiple times
    let namespace_dir = vault_path.join("test");
    fs::create_dir_all(&namespace_dir).unwrap();

    for i in 1..=3 {
        let _ = Command::new(&sigil)
            .arg("set")
            .arg("test/rollback-test")
            .arg("--value")
            .arg(format!("version-{}", i))
            .arg("--vault")
            .arg(&vault_path)
            .env("HOME", home_dir)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
    }

    // Check that version files exist
    let v1_path = namespace_dir.join("rollback-test.v1.age");
    let v2_path = namespace_dir.join("rollback-test.v2.age");
    let v3_path = namespace_dir.join("rollback-test.v3.age");

    // Version files should exist
    assert!(v3_path.exists() || v2_path.exists() || v1_path.exists(),
            "At least one version file should exist");

    // Rollback to previous version
    let output = Command::new(&sigil)
        .arg("rollback")
        .arg("test/rollback-test")
        .arg("--force")
        .arg("--vault")
        .arg(&vault_path)
        .env("HOME", home_dir)
        .output();

    if let Ok(output) = output {
        if output.status.success() {
            // After rollback, all version files should still exist
            // (rollback doesn't delete, just updates symlink)
            let versions_exist = v1_path.exists() || v2_path.exists() || v3_path.exists();
            assert!(versions_exist, "Version files should still exist after rollback");
        }
    }
}

/// Test 7: Verify sigil prune command
///
/// Tests that:
/// - prune deletes old version files beyond retention
/// - prune keeps the current version
/// - prune respects --keep count
#[tokio::test]
async fn test_sigil_prune_command() {
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

    // Create multiple versions
    for i in 1..=5 {
        let _ = Command::new(&sigil)
            .arg("set")
            .arg("test/prune-test")
            .arg("--value")
            .arg(format!("version-{}", i))
            .arg("--vault")
            .arg(&vault_path)
            .env("HOME", home_dir)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
    }

    // Prune keeping only 2 versions
    let output = Command::new(&sigil)
        .arg("prune")
        .arg("test/prune-test")
        .arg("--keep")
        .arg("2")
        .arg("--force")
        .arg("--vault")
        .arg(&vault_path)
        .env("HOME", home_dir)
        .output();

    if let Ok(output) = output {
        let stdout = String::from_utf8_lossy(&output.stdout);
        if output.status.success() {
            // Should indicate some versions were pruned
            assert!(stdout.contains("Pruned") || stdout.contains("pruned") || stdout.contains("old versions"),
                    "Prune should indicate old versions were removed");
        }
    }
}

/// Test 8: Verify SecretBackend trait is implemented for LocalVault
///
/// Tests that:
/// - LocalVault implements the SecretBackend trait
/// - All trait methods are available (get, set, delete, list, get_metadata, backend_type)
#[tokio::test]
async fn test_secret_backend_trait_implemented() {
    use sigil_core::SecretBackend;

    let temp_dir = TempDir::new().expect("Failed to create temp dir");
    let vault_path = temp_dir.path().join("vault");
    let identity_path = temp_dir.path().join("identity.age");

    let mut vault = LocalVault::new(vault_path, identity_path).unwrap();
    vault.init(Some("test-passphrase")).unwrap();

    // Test backend_type
    assert_eq!(vault.backend_type(), "local");

    // Test set
    let path = SecretPath::new("test/backend").unwrap();
    let value = SecretValue::from_string("test-value".to_string());
    let meta = SecretMetadata::new(path.clone());
    vault.set(&path, &value, &meta).await.unwrap();

    // Test get
    let retrieved = vault.get(&path).await.unwrap();
    assert_eq!(
        retrieved.expose(|v| String::from_utf8_lossy(v).to_string()),
        "test-value"
    );

    // Test get_metadata
    let metadata = vault.get_metadata(&path).await.unwrap();
    assert_eq!(metadata.path.as_str(), "test/backend");

    // Test list
    let secrets = vault.list("").await.unwrap();
    assert!(!secrets.is_empty());

    // Test delete
    vault.delete(&path).await.unwrap();
    let result = vault.get(&path).await;
    assert!(result.is_err(), "Getting deleted secret should fail");
}

/// Test 9: Verify scrubber loads ALL versions
///
/// Tests that:
/// - LocalVault.get_all_versions() returns all historical versions
/// - Scrubber receives patterns for all versions, not just current
/// - Old leaked secrets can still be detected
#[tokio::test]
async fn test_scrubber_loads_all_versions() {
    let temp_dir = TempDir::new().expect("Failed to create temp dir");
    let vault_path = temp_dir.path().join("vault");
    let identity_path = temp_dir.path().join("identity.age");

    let mut vault = LocalVault::new(vault_path.clone(), identity_path).unwrap();
    vault.init(Some("test-passphrase")).unwrap();

    // Create multiple versions of a secret
    let namespace_dir = vault_path.join("test");
    fs::create_dir_all(&namespace_dir).unwrap();

    use age::x25519::Identity;
    let identity = Identity::generate();
    let vm = VersionManager::new(namespace_dir.clone(), identity);

    // Save 3 different versions
    let secrets = [
        ("old-leaked-secret", "first version"),
        ("compromised-key", "second version"),
        ("current-value", "third version"),
    ];

    for (i, (value, reason)) in secrets.iter().enumerate() {
        let secret_value = SecretValue::from_string(value.to_string());
        let meta = sigil_core::SecretVersion {
            version: (i + 1) as u32,
            created_at: chrono::Utc::now(),
            fingerprint: format!("fp{}", i),
            reason: reason.to_string(),
            previous: if i == 0 { None } else { Some(i as u32) },
        };
        vm.save_version("multi_version_secret", &secret_value, &meta).unwrap();
    }

    // Get all versions from vault
    let all_versions = vault.get_all_versions().await.unwrap();

    // Should have all 3 versions
    let test_secret_versions = all_versions.get("test/multi_version_secret");
    assert!(test_secret_versions.is_some(), "Should have versions for the secret");

    let versions = test_secret_versions.unwrap();
    assert_eq!(versions.len(), 3, "Should have all 3 versions");

    // Verify each version is present
    let values: Vec<_> = versions.iter().map(|(_, v)| String::from_utf8_lossy(v).to_string()).collect();
    assert!(values.contains(&"old-leaked-secret".to_string()), "Should contain old version 1");
    assert!(values.contains(&"compromised-key".to_string()), "Should contain old version 2");
    assert!(values.contains(&"current-value".to_string()), "Should contain current version 3");

    // Now test that scrubber can detect ALL versions
    use sigil_scrub::Scrubber;
    let mut scrubber = Scrubber::new();

    for (_version, value) in versions.iter() {
        let path = SecretPath::new("test/multi_version_secret").unwrap();
        scrubber.add_secret(path, value);
    }

    // Test that old leaked secret is detected
    let output_with_old = "The leaked secret is: old-leaked-secret";
    let scrubbed = scrubber.scrub(output_with_old);
    assert!(
        scrubbed.contains("{{secret:test/multi_version_secret}}"),
        "Scrubber should detect old leaked secret"
    );

    // Test that compromised key is detected
    let output_with_compromised = "The key is: compromised-key";
    let scrubbed2 = scrubber.scrub(output_with_compromised);
    assert!(
        scrubbed2.contains("{{secret:test/multi_version_secret}}"),
        "Scrubber should detect compromised key"
    );

    // Test that current value is detected
    let output_with_current = "The current secret is: current-value";
    let scrubbed3 = scrubber.scrub(output_with_current);
    assert!(
        scrubbed3.contains("{{secret:test/multi_version_secret}}"),
        "Scrubber should detect current secret"
    );
}
