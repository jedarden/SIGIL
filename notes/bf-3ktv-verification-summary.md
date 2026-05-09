# Phase 1.3.1 Verification Summary: Secret Version History

## Date
2026-05-09

## Verification Results

### All Tests PASSED ✓

### Test Coverage

1. **Current symlink always points to latest version** ✓
   - Verified that after each save, the current symlink is updated
   - Verified v1, v2, v3 files are created
   - Verified symlink target changes: v1 → v2 → v3
   - Verified old version files are retained (not deleted)

2. **sigil history command shows timeline with fingerprints** ✓
   - Verified history output includes Version, Created At, Fingerprint, and Reason columns
   - Verified --json flag produces valid JSON output
   - Verified all 3 versions appear in history

3. **sigil rollback creates new symlink (doesn't delete versions)** ✓
   - Verified rollback to v2 updates symlink target
   - Verified v1, v2, v3 files all exist after rollback
   - Verify rolled-back value matches expected version

4. **sigil prune enforces retention policy** ✓
   - Verified prune with --keep 2 retains current and 1 previous version
   - Verified old versions beyond retention are deleted
   - Verified current version (v5) is never deleted
   - Verified symlink remains valid after prune

5. **Scrubber loads ALL versions, not just current** ✓
   - Verified LocalVault.get_all_versions() returns all historical versions
   - Verified all version values can be decrypted
   - Verified scrubber can detect old leaked secrets (v1, v2) not just current (v3)

## Test Execution

### Unit Tests
- `sigil-vault::version_manager::tests::test_next_version` - PASSED
- `sigil-core::versions::tests::test_fingerprint_generation` - PASSED
- `sigil-core::versions::tests::test_rotation_version` - PASSED

### Integration Tests (7 tests)
- `test_current_symlink_points_to_latest_version` - PASSED
- `test_history_command_shows_timeline_with_fingerprints` - PASSED
- `test_rollback_creates_symlink_doesnt_delete_versions` - PASSED
- `test_prune_enforces_retention_policy` - PASSED
- `test_scrubber_loads_all_versions_not_just_current` - PASSED
- `test_full_version_history_workflow` - PASSED
- `test_cli_scrub_loads_all_versions` - PASSED

### Shell Verification Script
All 6 verification tests PASSED:
1. Vault initialization
2. Current symlink points to latest version
3. History shows timeline with fingerprints
4. Rollback creates symlink, doesn't delete versions
5. Prune enforces retention policy
6. Version files retained for scrubber loading

## Implementation Status

### VersionManager (crates/sigil-vault/src/version_manager.rs)
- ✓ `next_version()` - Calculates next version number
- ✓ `save_version()` - Saves encrypted version file, updates symlink, appends history
- ✓ `update_current_symlink()` - Creates/updates symlink to latest version
- ✓ `current_version()` - Reads current version from symlink
- ✓ `rollback()` - Updates symlink to target version (doesn't delete files)
- ✓ `prune()` - Deletes old versions beyond retention policy

### LocalVault Integration (crates/sigil-vault/src/local.rs)
- ✓ `set()` uses VersionManager for version tracking
- ✓ `get_all_versions()` returns all historical versions with decrypted values
- ✓ Symlink chain: `secret.age` → `secret.vN.age`

### CLI Commands (crates/sigil-cli/src/main.rs)
- ✓ `sigil history <path>` - Shows version timeline with fingerprints
- ✓ `sigil history <path> --json` - Outputs JSON format
- ✓ `sigil rollback <path> --to N` - Rollback to specific version
- ✓ `sigil rollback <path>` - Rollback to previous version
- ✓ `sigil prune <path> --keep N` - Prune old versions
- ✓ `sigil prune --all --keep N` - Prune all secrets

## File Structure

For a secret at `namespace/secret`:
- `namespace/secret.age` - Symlink to current version
- `namespace/secret.v1.age` - Version 1 (encrypted)
- `namespace/secret.v2.age` - Version 2 (encrypted)
- `namespace/secret.v3.age` - Version 3 (encrypted)
- `namespace/secret.history.jsonl.age` - Encrypted version metadata

## Conclusion

Phase 1.3.1 (Secret Version History) is fully implemented and verified.
The symlink-based version chain is correctly wired throughout LocalVault,
and all CLI commands work as expected.
