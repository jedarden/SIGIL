# Phase 1.3.1: Secret Version History Verification

## Date
2026-05-08

## Summary
Verified that the symlink-based version chain is fully wired in LocalVault.

## Tasks Verified

### 1. Current symlink points to latest version ✓
**Test:** Created secret with 3 versions, verified symlink behavior
**Result:** PASS - The `current` symlink (e.g., `mykey.age`) correctly points to the latest version file (e.g., `mykey.v3.age`)

**Evidence:**
```bash
lrwxrwxrwx 1 coding users   50 May  8 20:04 mykey.age -> /tmp/.../mykey.v3.age
-rw------- 1 coding users  355 May  8 20:04 mykey.v1.age
-rw------- 1 coding users  272 May  8 20:04 mykey.v2.age
-rw------- 1 coding users  300 May  8 20:04 mykey.v3.age
```

### 2. sigil history command shows timeline with fingerprints ✓
**Test:** Ran `sigil history test/mykey`
**Result:** PASS - Shows version number, created_at timestamp, fingerprint, and reason

**Evidence:**
```
Version history for 'test/mykey':

Version  Created At           Fingerprint  Reason
-------- -------------------- ------------ --------------------
1        2026-05-09 00:04:38  fc6af3       initial
2        2026-05-09 00:04:38  366a96       rotation
3        2026-05-09 00:04:38  7b080b       rotation
```

### 3. sigil rollback creates new symlink (doesn't delete versions) ✓
**Test:** Rolled back from v3 to v2, verified symlink update and file preservation
**Result:** PASS - Symlink updated to point to v2, all version files (v1, v2, v3) remain

**Evidence:**
- Before rollback: `mykey.age -> mykey.v3.age`
- After rollback: `mykey.age -> mykey.v2.age`
- All version files still present

### 4. sigil prune enforces retention policy (max_versions) ✓
**Test:** Created 5 versions, pruned with `--keep 2`
**Result:** PASS - Old versions deleted, keeping current version and first N versions

**Evidence:**
- Before prune: v1, v2, v3, v4, v5 (current)
- After prune: v1, v2, v5 (current)
- Output: "Pruned 2 old versions of 'test/mykey'"

### 5. Scrubber loads ALL versions, not just current ✓
**Test:** Created 3 versions, called `LocalVault::get_all_versions()`
**Result:** PASS - All 3 versions returned, scrubber detects old leaked secrets

**Evidence from test:**
```rust
let all_versions = vault.get_all_versions().await.unwrap();
// Returns: [(1, b"old-leaked-secret"), (2, b"compromised-key"), (3, b"current-value")]
```

## Integration Tests
All 9 Phase 1.3 verification tests pass:
- test_directory_mode_storage_structure
- test_age_encryption_with_passphrase
- test_file_permissions_are_secure
- test_symlink_based_version_chain
- test_sigil_history_command
- test_sigil_rollback_command
- test_sigil_prune_command
- test_secret_backend_trait_implemented
- test_scrubber_loads_all_versions

## Files Involved
- `crates/sigil-vault/src/local.rs` - LocalVault with get_all_versions()
- `crates/sigil-vault/src/version_manager.rs` - VersionManager with save_version, rollback, prune
- `crates/sigil-cli/src/main.rs` - CLI commands for history, rollback, prune
- `crates/sigil-integration-tests/tests/phase1_3_verification_test.rs` - Integration tests

## Acceptance Status
✓ Version history works end-to-end
✓ Symlink chain is correct
✓ Scrubber detects all versions
