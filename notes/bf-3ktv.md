# Phase 1.3.1 Verification: Secret Version History

## Summary

Verified that the symlink-based version chain is fully wired in LocalVault. All 6 verification tests pass.

## Verification Results

### Test 1: Current symlink points to latest version ✓

**Test**: `test_current_symlink_points_to_latest_version`

**Verified**:
- After saving v1, symlink points to `secret.v1.age`
- After saving v2, symlink points to `secret.v2.age`
- After saving v3, symlink points to `secret.v3.age`
- `current_version()` returns correct version after each save
- All version files remain (no deletion)

**Implementation**: `VersionManager::update_current_symlink()` creates/updates the symlink after each save.

### Test 2: History command shows timeline with fingerprints ✓

**Test**: `test_history_command_shows_timeline_with_fingerprints`

**Verified**:
- `sigil history` command outputs version information
- `--json` flag produces valid JSON output
- History includes version numbers, fingerprints, and timestamps

**Implementation**: `CommandHistory::run()` calls `VersionManager::read_history()` which decrypts and parses the history file.

### Test 3: Rollback creates symlink, doesn't delete versions ✓

**Test**: `test_rollback_creates_symlink_doesnt_delete_versions`

**Verified**:
- `VersionManager::rollback(target_version)` updates symlink to point to target version
- All version files (v1, v2, v3) remain after rollback
- Can rollback to any version (1, 2, 3)
- `current_version()` returns the rolled-back version

**Implementation**: `VersionManager::rollback()` calls `update_current_symlink()` without deleting any files.

### Test 4: Prune enforces retention policy ✓

**Test**: `test_prune_enforces_retention_policy`

**Verified**:
- `VersionManager::prune(keep_count)` keeps current version
- Prune deletes old versions beyond `keep_count`
- After pruning v1-v5 with keep=2, v1 is deleted, v5 (current) remains
- History is maintained

**Implementation**: `VersionManager::prune()` iterates through version files, skipping current, and deletes those beyond retention.

### Test 5: Scrubber loads ALL versions, not just current ✓

**Test**: `test_scrubber_loads_all_versions_not_just_current`

**Verified**:
- `LocalVault::get_all_versions()` returns all historical versions
- Each version's value is correctly decrypted
- Scrubber detects old leaked secrets (v1, v2)
- Scrubber detects current secret (v3)
- All values are redacted in output

**Implementation**: `LocalVault::get_all_versions()` walks the vault directory, finds all `*.vN.age` files, decrypts each one, and returns a map of all versions.

### Test 6: Full workflow integration test ✓

**Test**: `test_full_version_history_workflow`

**Verified**:
- Create v1 → v2 → v3
- History shows all 3 versions
- Rollback to v2 works
- Prune with keep=2 deletes v1
- Scrubber detects remaining v2 and v3

## Code Locations

| Component | File | Key Functions |
|-----------|------|---------------|
| VersionManager | `crates/sigil-vault/src/version_manager.rs` | `save_version()`, `rollback()`, `prune()`, `read_history()` |
| LocalVault | `crates/sigil-vault/src/local.rs` | `get_all_versions()` |
| CLI History | `crates/sigil-cli/src/main.rs:1688` | `CommandHistory::run()` |
| CLI Rollback | `crates/sigil-cli/src/main.rs:1761` | `CommandRollback::run()` |
| CLI Prune | `crates/sigil-cli/src/main.rs:1848` | `CommandPrune::run()` |
| Scrubber | `crates/sigil-scrub/src/scrubber.rs` | `Scrubber::add_secret()`, `scrub()` |

## Test Coverage

- **Unit tests**: `version_manager.rs` has tests for `next_version()`
- **Integration tests**: `phase1_3_verification_test.rs` (9 tests) and `phase1_3_1_verification_test.rs` (6 tests)
- **All tests pass**: 15/15 tests pass

## Security Verification

The version history feature meets security requirements:
1. All version files are encrypted with age (same key as current)
2. File permissions are 0600 (user read/write only)
3. Scrubber loads ALL versions - old leaked secrets are still detected
4. Prune respects retention policy - old versions are deleted when no longer needed
