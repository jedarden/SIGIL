# Phase 1.3.1 Verification Complete: Secret Version History

## Date: 2026-05-09

## Summary

Phase 1.3.1 (Secret Version History) is fully implemented and verified. The symlink-based version chain is correctly wired throughout LocalVault, and all CLI commands work as expected.

## Verification Tasks - ALL PASSED ✓

### 1. Current symlink always points to latest version ✓
- Verified that after each save, the current symlink is updated
- Verified v1, v2, v3 files are created and retained
- Verified symlink target changes: v1 → v2 → v3

### 2. sigil history command shows timeline with fingerprints ✓
- Verified history output includes Version, Created At, Fingerprint, and Reason columns
- Verified --json flag produces valid JSON output
- Verified all versions appear in history

### 3. sigil rollback creates new symlink (doesn't delete versions) ✓
- Verified rollback to v2 updates symlink target
- Verified v1, v2, v3 files all exist after rollback
- Verified rolled-back value matches expected version

### 4. sigil prune enforces retention policy (max_versions, max_age) ✓
- Verified prune with --keep 2 retains current and 1 previous version
- Verified old versions beyond retention are deleted
- Verified current version is never deleted

### 5. Scrubber loads ALL versions, not just current ✓
- Verified LocalVault.get_all_versions() returns all historical versions
- Verified all version values can be decrypted
- Verified scrubber can detect old leaked secrets (v1, v2) not just current (v3)

## Test Results

### Integration Tests (7 tests) - ALL PASSED
```
test test_cli_scrub_loads_all_versions ... ok
test test_history_command_shows_timeline_with_fingerprints ... ok
test test_rollback_creates_symlink_doesnt_delete_versions ... ok
test test_prune_enforces_retention_policy ... ok
test test_current_symlink_points_to_latest_version ... ok
test test_scrubber_loads_all_versions_not_just_current ... ok
test test_full_version_history_workflow ... ok
```

### Example Program - PASSED
```
=== SIGIL Version History Verification ===
1. Testing: Create secret, add 3 times, verify v1/v2/v3 + current symlink exist
   ✓ All version files exist and current points to v3 (latest)
2. Testing: Run history, verify output format
   ✓ History shows 3 versions with fingerprints
3. Testing: Run rollback, verify symlink updated (versions not deleted)
   ✓ Rolled back to version 2, all versions still exist
4. Testing: Run prune with keep=2, verify old versions deleted
   ✓ Prune correctly deleted old versions while keeping current and recent
5. Testing: Verify scrubber loads ALL versions
   ✓ Scrubber integration verified via vault.get_all_versions()
=== All Version History Tests Passed! ===
```

## Implementation Verified

### VersionManager (crates/sigil-vault/src/version_manager.rs)
- `next_version()` - Calculates next version number
- `save_version()` - Saves encrypted version file, updates symlink, appends history
- `update_current_symlink()` - Creates/updates symlink to latest version
- `current_version()` - Reads current version from symlink
- `rollback()` - Updates symlink to target version (doesn't delete files)
- `prune()` - Deletes old versions beyond retention policy
- `read_history()` - Returns version metadata with fingerprints

### LocalVault (crates/sigil-vault/src/local.rs)
- `set()` - Uses VersionManager for version tracking
- `get_all_versions()` - Returns all historical versions with decrypted values
- Symlink chain: `secret.age` → `secret.vN.age`

### CLI Commands (crates/sigil-cli/src/main.rs)
- `sigil history <path>` - Shows version timeline with fingerprints
- `sigil rollback <path> --to N` - Rollback to specific version
- `sigil prune <path> --keep N` - Prune old versions

## File Structure

For a secret at `namespace/secret`:
- `namespace/secret.age` - Symlink to current version
- `namespace/secret.v1.age` - Version 1 (encrypted)
- `namespace/secret.v2.age` - Version 2 (encrypted)
- `namespace/secret.v3.age` - Version 3 (encrypted)
- `namespace/secret.history.jsonl.age` - Encrypted version metadata

## Acceptance Criteria Met

- [x] Version history works end-to-end
- [x] Symlink chain is correct
- [x] Scrubber detects all versions
