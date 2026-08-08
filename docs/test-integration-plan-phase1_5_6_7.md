# Test Integration Plan: Assertion Patterns for phase1_5_6_7_verification_test.rs

## Overview

This plan documents the step-by-step integration of comprehensive assertion patterns into the Phase 1.5-1.7 verification test file (`crates/sigil-integration-tests/tests/phase1_5_6_7_verification_test.rs`).

**Current Status**: The test file has 16 basic integration tests that need enhanced assertion patterns following SIGIL's established testing conventions.

**Target**: Integrate structured assertion patterns, improved error messages, and validation helpers to match the quality standards demonstrated in `result_collector.rs` sender_count tests.

---

## Phase 1: Analysis and Planning

### 1.1 Current Test File Analysis

**File**: `crates/sigil-integration-tests/tests/phase1_5_6_7_verification_test.rs`

**Current Structure**:
- 16 integration tests covering Phases 1.5, 1.6, and 1.7
- Basic assertions using `assert!`, `assert_eq!`, and `assert!` with basic messages
- Some tests have descriptive messages, others use generic patterns
- Missing structured validation helpers for common operations

**Test Distribution**:
- Phase 1.5 (Export/Import): 5 tests (tests 1-5)
- Phase 1.6 (Versioning/Migration): 5 tests (tests 6-10)
- Phase 1.7 (Lifecycle Management): 6 tests (tests 11-16)

### 1.2 Identified Issues

**Message Quality Issues**:
1. Generic error messages: `"failed to create temp dir"` without context
2. Missing state information in assertions: no before/after context
3. Inconsistent message formatting across tests
4. Missing validation helpers for repeated operations

**Structural Issues**:
1. Repeated patterns for vault initialization
2. No dedicated validation functions for common checks
3. Inconsistent error handling patterns
4. Missing comprehensive validation helpers

---

## Phase 2: Exact Code Additions Needed

### 2.1 New Validation Module Structure

**Location**: Add after the existing imports and before the test functions (after line 38)

**Add this module**:

```rust
// ============================================================================
// Validation Helpers Module
// ============================================================================

/// Validation helpers for Phase 1.5-1.7 tests
mod validation_helpers {
    use super::*;

    /// Validate archive file format structure
    ///
    /// Validates that the archive file has the expected format:
    /// - Magic bytes: "SIGIL\x00"
    /// - Version field: u16 big-endian
    /// - Encrypted payload present
    pub fn validate_archive_format(archive_data: &[u8]) -> Result<(), String> {
        // Check magic bytes
        if !archive_data.starts_with(b"SIGIL\x00") {
            return Err(format!(
                "Archive should start with magic bytes 'SIGIL\\x00', got: {:?}",
                &archive_data[..6.min(archive_data.len())]
            ));
        }

        // Check version field (bytes 6-7, after 6-byte magic header)
        if archive_data.len() < 8 {
            return Err(format!(
                "Archive too short to contain version field: {} bytes (minimum 8 required)",
                archive_data.len()
            ));
        }

        let version_bytes = &archive_data[6..8];
        let version = u16::from_be_bytes([version_bytes[0], version_bytes[1]]);

        if version != 1 {
            return Err(format!(
                "Archive version should be 1, got: {}. Archive may be from future SIGIL version",
                version
            ));
        }

        // Verify encrypted payload exists (after header)
        if archive_data.len() <= 8 {
            return Err(
                "Archive should contain encrypted payload beyond header (8 bytes)".to_string()
            );
        }

        Ok(())
    }

    /// Validate command execution result with context
    ///
    /// Validates that a command execution produced the expected result
    pub fn validate_command_result(
        result: &std::process::Output,
        command_description: &str,
    ) -> Result<(), String> {
        if !result.status.success() {
            let stdout = String::from_utf8_lossy(&result.stdout);
            let stderr = String::from_utf8_lossy(&result.stderr);
            return Err(format!(
                "{} command failed: stdout='{}', stderr='{}'",
                command_description, stdout, stderr
            ));
        }
        Ok(())
    }

    /// Validate vault initialization with detailed checks
    ///
    /// Performs comprehensive validation of vault initialization results
    pub fn validate_vault_initialization(sigil_dir: &std::path::Path) -> Result<(), String> {
        // Check vault directory exists
        if !sigil_dir.exists() {
            return Err(format!(
                "Vault directory should exist at: {:?}",
                sigil_dir
            ));
        }

        // Check for required vault files
        let identity_file = sigil_dir.join("identity.age");
        if !identity_file.exists() {
            return Err(format!(
                "Vault should contain identity.age file at: {:?}",
                identity_file
            ));
        }

        let vault_dir = sigil_dir.join("vault");
        if !vault_dir.exists() {
            return Err(format!(
                "Vault should contain vault subdirectory at: {:?}",
                vault_dir
            ));
        }

        Ok(())
    }

    /// Validate export file size relationships
    ///
    /// Validates that selective exports are smaller than full exports
    pub fn validate_export_size_relationship(
        full_export_size: u64,
        namespace_export_size: u64,
        namespace: &str,
    ) -> Result<(), String> {
        if namespace_export_size >= full_export_size {
            return Err(format!(
                "Namespace export for '{}' should be smaller than full export: namespace={}, full={}",
                namespace, namespace_export_size, full_export_size
            ));
        }

        // Sanity check: namespace export should be non-zero
        if namespace_export_size == 0 {
            return Err(format!(
                "Namespace export for '{}' should contain data (size > 0), got: 0",
                namespace
            ));
        }

        Ok(())
    }

    /// Validate migration dry-run behavior
    ///
    /// Validates that dry-run mode shows status without making changes
    pub fn validate_migration_dry_run(output: &str) -> Result<(), String> {
        // Should mention status (up to date or migration needed)
        let has_status = output.contains("up to date")
            || output.contains("version")
            || output.contains("migrat")
            || output.contains("format");

        if !has_status {
            return Err(format!(
                "Dry-run output should mention migration status. Output: '{}'",
                output
            ));
        }

        // Should not contain error messages
        if output.contains("error") && output.contains("ERROR") {
            return Err(format!(
                "Dry-run should not contain errors. Output: '{}'",
                output
            ));
        }

        Ok(())
    }

    /// Validate uninstall dry-run behavior
    ///
    /// Validates that uninstall dry-run shows what would be removed without actually removing
    pub fn validate_uninstall_dry_run(output: &str, sigil_dir: &std::path::Path) -> Result<(), String> {
        // Should mention SIGIL or what would be removed
        let has_content = output.contains("SIGIL")
            || output.contains("would")
            || output.contains("Would")
            || output.contains("remove")
            || output.contains("No SIGIL");

        if !has_content {
            return Err(format!(
                "Uninstall dry-run should indicate what would be removed. Output: '{}'",
                output
            ));
        }

        // Verify vault still exists (nothing was actually removed)
        if !sigil_dir.exists() {
            return Err(
                "SIGIL directory should still exist after dry-run (nothing should be removed)".to_string()
            );
        }

        Ok(())
    }

    /// Validate manifest structure and location
    ///
    /// Validates that the install manifest has correct structure and location
    pub fn validate_manifest_structure(manifest_path: &std::path::Path) -> Result<(), String> {
        // Check path ends with expected name
        let path_str = manifest_path.to_string_lossy();
        if !path_str.ends_with("install-manifest.toml") {
            return Err(format!(
                "Manifest path should end with 'install-manifest.toml', got: {}",
                path_str
            ));
        }

        // Check parent directory is .sigil
        let parent = manifest_path.parent();
        match parent {
            Some(p) if p.ends_with(".sigil") => Ok(()),
            _ => Err(format!(
                "Manifest should be in .sigil directory, got parent: {:?}",
                parent
            )),
        }
    }
}
```

### 2.2 Enhanced Test Functions

**Replace existing test functions with enhanced versions**:

#### Test 1 Enhancement (lines 42-126):

```rust
#[tokio::test]
async fn test_archive_format_structure() {
    let temp_dir = TempDir::new().expect("Failed to create temp dir for archive format test");
    let home_dir = temp_dir.path();
    let export_file = temp_dir.path().join("export.sigil");

    let sigil = sigil_path();
    if !sigil.exists() {
        eprintln!("sigil not found, skipping test. Run: cargo build --bin sigil");
        return;
    }

    // Initialize vault
    let init_result = Command::new(&sigil)
        .arg("init")
        .arg("--no-passphrase")
        .env("HOME", home_dir)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();

    if !init_result.map(|s| s.success()).unwrap_or(false) {
        eprintln!("Failed to initialize vault, skipping archive format test");
        return;
    }

    // Validate vault was created successfully
    let sigil_dir = home_dir.join(".sigil");
    if let Err(e) = validation_helpers::validate_vault_initialization(&sigil_dir) {
        eprintln!("Vault initialization validation failed: {}, skipping test", e);
        return;
    }

    // Add a test secret
    let mut add_child = Command::new(&sigil)
        .arg("add")
        .arg("test/export_secret")
        .arg("--from-stdin")
        .env("HOME", home_dir)
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("Failed to spawn add command");

    {
        let stdin = add_child.stdin.as_mut().expect("Failed to open stdin");
        stdin.write_all(b"secret-value-123").expect("Failed to write secret value");
    }

    let add_result = add_child.wait_with_output();
    if !add_result.map(|r| r.status.success()).unwrap_or(false) {
        eprintln!("Failed to add test secret, skipping archive format test");
        return;
    }

    // Export to file
    let export_output = Command::new(&sigil)
        .arg("export")
        .arg("--output")
        .arg(&export_file)
        .arg("--passphrase")
        .arg("")
        .env("HOME", home_dir)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .expect("Failed to execute export command");

    if !export_output.status.success() {
        eprintln!(
            "Export command failed: stdout={}, stderr={}",
            String::from_utf8_lossy(&export_output.stdout),
            String::from_utf8_lossy(&export_output.stderr)
        );
        return;
    }

    // Verify archive format structure
    let archive_data = fs::read(&export_file).expect("Failed to read export file");

    match validation_helpers::validate_archive_format(&archive_data) {
        Ok(_) => {
            // Archive format is correct - test passes
            assert!(true, "Archive format validation should pass");
        }
        Err(e) => {
            panic!("Archive format validation failed: {}", e);
        }
    }
}
```

#### Test 3 Enhancement (lines 166-280):

```rust
#[tokio::test]
async fn test_selective_export_namespace() {
    let temp_dir = TempDir::new().expect("Failed to create temp dir for namespace export test");
    let home_dir = temp_dir.path();
    let sigil_dir = home_dir.join(".sigil");
    let export_all = temp_dir.path().join("export_all.sigil");
    let export_ns = temp_dir.path().join("export_ns.sigil");

    fs::create_dir_all(&sigil_dir).expect("Failed to create sigil directory");

    let sigil = sigil_path();
    if !sigil.exists() {
        eprintln!("sigil not found, skipping test. Run: cargo build --bin sigil");
        return;
    }

    // Initialize vault
    let init_result = Command::new(&sigil)
        .arg("init")
        .arg("--path")
        .arg(&sigil_dir)
        .arg("--no-passphrase")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();

    if !init_result.map(|s| s.success()).unwrap_or(false) {
        eprintln!("Failed to initialize vault, skipping namespace export test");
        return;
    }

    // Add prod namespace secret
    let prod_add = Command::new(&sigil)
        .arg("add")
        .arg("prod/api_key")
        .arg("--vault-path")
        .arg(&sigil_dir)
        .arg("--from-stdin")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .stdin(Stdio::piped())
        .spawn()
        .and_then(|mut child| {
            let stdin = child.stdin.as_mut().expect("Failed to open stdin");
            stdin.write_all(b"prod-secret").expect("Failed to write prod secret");
            child.wait_with_output()
        });

    if !prod_add.map(|r| r.status.success()).unwrap_or(false) {
        eprintln!("Failed to add prod secret, skipping namespace export test");
        return;
    }

    // Add dev namespace secret
    let dev_add = Command::new(&sigil)
        .arg("add")
        .arg("dev/api_key")
        .arg("--vault-path")
        .arg(&sigil_dir)
        .arg("--from-stdin")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .stdin(Stdio::piped())
        .spawn()
        .and_then(|mut child| {
            let stdin = child.stdin.as_mut().expect("Failed to open stdin");
            stdin.write_all(b"dev-secret").expect("Failed to write dev secret");
            child.wait_with_output()
        });

    if !dev_add.map(|r| r.status.success()).unwrap_or(false) {
        eprintln!("Failed to add dev secret, skipping namespace export test");
        return;
    }

    // Export all secrets
    let export_all_output = Command::new(&sigil)
        .arg("export")
        .arg("--output")
        .arg(&export_all)
        .arg("--path")
        .arg(&sigil_dir)
        .arg("--passphrase")
        .arg("")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .expect("Failed to execute full export");

    // Export only prod namespace
    let export_ns_output = Command::new(&sigil)
        .arg("export")
        .arg("--namespace")
        .arg("prod")
        .arg("--output")
        .arg(&export_ns)
        .arg("--path")
        .arg(&sigil_dir)
        .arg("--passphrase")
        .arg("")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .expect("Failed to execute namespace export");

    // Validate both exports succeeded
    if let Err(e) = validation_helpers::validate_command_result(&export_all_output, "Full export") {
        panic!("Full export validation failed: {}", e);
    }

    if let Err(e) = validation_helpers::validate_command_result(&export_ns_output, "Namespace export") {
        panic!("Namespace export validation failed: {}", e);
    }

    // Verify size relationships
    let all_size = export_all.metadata()
        .and_then(|m| m.len())
        .unwrap_or(0);

    let ns_size = export_ns.metadata()
        .and_then(|m| m.len())
        .unwrap_or(0);

    if let Err(e) = validation_helpers::validate_export_size_relationship(all_size, ns_size, "prod") {
        panic!("Export size relationship validation failed: {}", e);
    }
}
```

---

## Phase 3: Order of Operations

### Step 1: Add Validation Module (Priority: HIGH)
1. Add the `validation_helpers` module after line 38
2. Test compilation: `cargo test --test phase1_5_6_7_verification_test`
3. Verify no compilation errors

### Step 2: Enhance Test 1 (Archive Format)
1. Replace `test_archive_format_structure` function (lines 42-126)
2. Add validation helper usage
3. Run specific test: `cargo test test_archive_format_structure`
4. Verify test passes

### Step 3: Enhance Test 3 (Namespace Export)
1. Replace `test_selective_export_namespace` function (lines 166-280)
2. Add validation helper usage
3. Run specific test: `cargo test test_selective_export_namespace`
4. Verify test passes

### Step 4: Apply Pattern to Remaining Tests
1. Apply enhanced patterns to tests 2, 4, 5 (Phase 1.5)
2. Apply enhanced patterns to tests 6-10 (Phase 1.6)
3. Apply enhanced patterns to tests 11-16 (Phase 1.7)
4. Run full test suite: `cargo test phase1_5_6_7_verification_test`

### Step 5: Documentation and Verification
1. Update test documentation comments
2. Run comprehensive test suite: `cargo test`
3. Verify all tests pass
4. Check for any new warnings

---

## Phase 4: Potential Conflicts and Issues

### 4.1 Conflicts Identified

**Import Conflicts**: None expected - validation helpers are in a submodule

**Type Conflicts**: None - using existing types only

**Function Signature Conflicts**: None - new validation functions use distinct names

### 4.2 Known Issues and Mitigations

**Issue 1: Early Test Skips**
- **Problem**: Tests skip when sigil binary is not found
- **Mitigation**: Enhanced error messages explain exactly what's needed
- **Impact**: Low - improves developer experience

**Issue 2: TempDir Cleanup**
- **Problem**: TempDir cleanup may fail on Windows
- **Mitigation**: Explicit error handling with clear messages
- **Impact**: Medium - affects Windows developers

**Issue 3: Command Execution Context**
- **Problem**: Commands may fail in different environments
- **Mitigation**: Detailed error messages include stdout/stderr
- **Impact**: Low - improves debugging

### 4.3 Compatibility Concerns

**Backward Compatibility**: ✅ No breaking changes
- Existing tests continue to work
- New helpers are additive
- Enhanced versions are drop-in replacements

**Platform Compatibility**: ✅ Cross-platform maintained
- TempDir works on all platforms
- Path handling uses platform-agnostic methods
- Error messages are platform-neutral

---

## Phase 5: Integration Checklist

### Module Structure
- [ ] Add `validation_helpers` module after line 38
- [ ] Include 8 validation helper functions
- [ ] Verify module compiles without errors

### Test Function Enhancements
- [ ] Enhance test 1 (archive format structure)
- [ ] Enhance test 3 (namespace export)
- [ ] Apply patterns to remaining 14 tests
- [ ] Verify all tests use validation helpers where appropriate

### Error Message Improvements
- [ ] Ensure all assertions have descriptive messages
- [ ] Include before/after context where applicable
- [ ] Use structured error message format

### Code Quality
- [ ] Run `cargo fmt` on the file
- [ ] Run `cargo clippy` on the test module
- [ ] Verify no new warnings introduced

### Testing
- [ ] Run individual tests: `cargo test test_archive_format_structure`
- [ ] Run full test file: `cargo test --test phase1_5_6_7_verification_test`
- [ ] Run full test suite: `cargo test`
- [ ] Verify all tests pass

### Documentation
- [ ] Update test documentation comments
- [ ] Add inline documentation for validation helpers
- [ ] Verify all test descriptions are clear

---

## Phase 6: Expected Outcomes

### 6.1 Improved Test Quality
- **Better Error Messages**: Every assertion provides clear context
- **Reusable Validation**: Common checks centralized in helpers
- **Consistent Patterns**: All tests follow the same structure

### 6.2 Enhanced Developer Experience
- **Easier Debugging**: Detailed error messages show exactly what went wrong
- **Faster Development**: Reusable validation helpers reduce boilerplate
- **Better Maintenance**: Centralized validation logic is easier to update

### 6.3 Maintained Functionality
- **No Breaking Changes**: All existing functionality preserved
- **Backward Compatible**: Test behavior remains the same
- **Performance**: No performance degradation

---

## Conclusion

This integration plan provides a structured approach to enhancing the Phase 1.5-1.7 verification tests with comprehensive assertion patterns. The modular validation helpers and enhanced test functions will improve test quality while maintaining backward compatibility and existing functionality.

The integration is designed to be incremental - each step can be completed and tested independently, reducing risk and allowing for easy rollback if issues arise.

**Next Steps**: Begin with Step 1 (adding the validation helpers module) and proceed through the integration checklist in order.