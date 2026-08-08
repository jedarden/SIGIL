# Test File Structure Catalog

## File: `phase1_5_6_7_verification_test.rs`

### Overview
- **Location**: `crates/sigil-integration-tests/tests/phase1_5_6_7_verification_test.rs`
- **Purpose**: Runtime tests to verify Phase 1.5-1.7 deliverables
- **Total Lines**: 1089 lines
- **Test Functions**: 16 test functions

### Phase Coverage
- **Phase 1.5**: Export/Import Format
- **Phase 1.6**: Versioning and Migration  
- **Phase 1.7**: Lifecycle Management

### Imports and Dependencies

**Standard Library:**
- `std::fs` - File system operations
- `std::io::Write` - Writing to stdin
- `std::path::PathBuf` - Path handling
- `std::process::{Command, Stdio}` - Process control

**External Dependencies:**
- `tokio::test` - Async test framework
- `tempfile::TempDir` - Temporary directory management

**Internal Dependencies:**
- `common::workspace_root` - Workspace utilities
- `sigil_core::InstallManifest` - Core lifecycle types

### Test Organization

#### Section 1: Phase 1.5 - Export/Import Format Tests (Lines 38-514)
1. `test_archive_format_structure` - Magic bytes, version field, encrypted payload
2. `test_archive_passphrase_encryption` - Encryption support verification
3. `test_selective_export_namespace` - Namespace filtering functionality
4. `test_import_conflict_resolution` - Merge vs overwrite modes
5. `test_export_import_roundtrip` - Complete round-trip preservation

#### Section 2: Phase 1.6 - Versioning and Migration Tests (Lines 516-789)
6. `test_format_version_fields` - Version field presence verification
7. `test_migrate_dry_run` - Non-destructive migration testing
8. `test_migrate_creates_backup` - Backup directory creation
9. `test_migrate_auto_mode` - Non-interactive migration
10. `test_forward_compatibility_rejects_future_versions` - Future version rejection

#### Section 3: Phase 1.7 - Lifecycle Management Tests (Lines 791-1089)
11. `test_install_manifest_creation` - Manifest type and path verification
12. `test_uninstall_dry_run` - Preview uninstall changes
13. `test_uninstall_hooks_only` - Hook removal while preserving vault
14. `test_uninstall_keep_vault` - Vault preservation during uninstall
15. `test_uninstall_purge_requires_confirmation` - Warning for destructive operations
16. `test_uninstall_cli_available` - CLI command structure verification

### Helper Functions

**`sigil_path()`**: Returns path to sigil CLI binary for testing
- Input: None
- Output: `PathBuf` pointing to `target/debug/sigil`

### Test Architecture Patterns

**Common Patterns:**
1. **Isolation**: `TempDir::new()` for each test
2. **Binary Check**: Skip tests if sigil binary not found
3. **Command Spawning**: `Command::new()` for CLI invocation
4. **Status Validation**: `output.status.success()` checks
5. **Output Parsing**: `String::from_utf8_lossy()` for result validation
6. **Non-Destructive**: Use of `--dry-run` flags where possible

**Data Management:**
- Secrets via `--from-stdin` with stdin piping
- Empty passphrase for automated export/import testing
- Multiple vault directories for test isolation

### Test Coverage Summary

**Phase 1.5 Coverage**: Export/import format, encryption, namespace filtering, conflict resolution
**Phase 1.6 Coverage**: Versioning, dry-run migration, backup creation, auto-mode, forward compatibility
**Phase 1.7 Coverage**: Install manifest, uninstall modes, CLI structure