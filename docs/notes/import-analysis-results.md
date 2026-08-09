# Missing Import Analysis - SIGIL Workspace

**Analysis Date:** 2026-08-09  
**Scope:** All 28 SIGIL crates, focusing on sigil-core, sigil-vault, sigil-cli, sigil-daemon  
**Method:** `cargo check --all-targets --all-features`  

## Executive Summary

- **Total Missing Imports Found:** 1
- **Affected Crates:** 1 (sigil-daemon)
- **Priority Crates Status:** 
  - ✅ sigil-core: No compilation errors
  - ✅ sigil-vault: No compilation errors  
  - ✅ sigil-cli: No compilation errors
  - ❌ sigil-daemon: 1 missing import found

## Detailed Findings

### 1. sigil-daemon - Missing Trait Import

**File:** `crates/sigil-daemon/src/lease_tracker.rs`  
**Line:** 323  
**Error Code:** E0599  
**Severity:** Compilation error (build failure)

#### Error Message
```
error[E0599]: no method named `revoke_lease` found for struct `VaultDynamicProvider` in the current scope
   --> crates/sigil-daemon/src/lease_tracker.rs:323:24
    |
323 |         match provider.revoke_lease(&lease.lease_id).await {
    |                        ^^^^^^^^^^^^ method not found in `VaultDynamicProvider`
    |
    ::: crates/sigil-core/src/dynamic.rs:143:14
    |
143 |     async fn revoke_lease(&self, lease_id: &str) -> Result<()>;
    |              ------------ the method is available for `VaultDynamicProvider` here
    |
    = help: items from traits can only be used if the trait is in scope
help: trait `DynamicSecretProvider` which provides `revoke_lease` is implemented but not in scope; perhaps you want to import it
    |
11 + use sigil_core::DynamicSecretProvider;
```

#### Root Cause
The `revoke_vault_lease` function (lines 291-330) is marked with `#[cfg(feature = "dynamic")]`. Inside this function:

- **Line 297:** `use sigil_core::VaultDynamicProvider;` imports the struct
- **Line 323:** Calls `provider.revoke_lease(&lease.lease_id).await`
- **Problem:** The `revoke_lease` method is defined in the `DynamicSecretProvider` trait, but the trait is not imported

In Rust, trait methods can only be called when the trait is in scope, even if the type implements the trait.

#### Missing Import
```rust
// At line 11 (after other imports), add:
use sigil_core::DynamicSecretProvider;
```

#### Feature Context
This error only appears when building with `--all-features` because:
- The function is gated by `#[cfg(feature = "dynamic")]`
- The `sigil-daemon` Cargo.toml defines: `dynamic = ["sigil-core/dynamic"]`
- Building without the feature skips the compilation of this code path

## Methodology

### Commands Used
```bash
# Full workspace check
cargo check --all-targets --all-features

# Individual crate checks  
cargo check --package sigil-core
cargo check --package sigil-vault
cargo check --package sigil-cli
cargo check --package sigil-daemon
```

### Analysis Process
1. Ran `cargo check --all-targets --all-features` to identify compilation errors
2. Parsed output for error codes (E-prefix) and "trait not in scope" messages
3. Verified each error by examining the affected source files
4. Checked feature gates and conditional compilation context
5. Cross-referenced with trait definitions to confirm missing imports

### Excluded Findings
- **Unused imports:** Not included in this analysis (task focused on MISSING imports only)
- **Warnings:** Only compilation errors (E-prefix) were analyzed
- **Test failures:** The 7 test failures in sigil-core/thread_utils are logic errors, not import issues

## Next Steps

### Immediate Action Required
1. Add `use sigil_core::DynamicSecretProvider;` to `crates/sigil-daemon/src/lease_tracker.rs` at line 11
2. Re-run `cargo check --all-features` to verify the fix
3. Run `cargo test --all-features` to ensure no test regressions

### Verification
After import restoration, verify:
- [ ] `cargo check --all-targets --all-features` passes
- [ ] `cargo test --all-features` passes  
- [ ] `cargo clippy --all-targets --all-features -- -D warnings` passes
- [ ] No new warnings introduced

## Additional Notes

### Why This Wasn't Caught Earlier
- The error only appears with `--all-features`
- Individual `cargo check --package sigil-daemon` passes (without enabling all features)
- The dynamic feature backend code path may not be covered in regular CI without explicit feature flags

### Import Best Practices
When importing types that implement traits, consider:
1. Import both the type and trait if using trait methods
2. Use wildcard imports sparingly: `use sigil_core::DynamicSecretProvider;`
3. Keep trait imports close to where they're used for readability

### Related Files
- `crates/sigil-core/src/dynamic.rs` - Defines `DynamicSecretProvider` trait
- `crates/sigil-daemon/Cargo.toml` - Features configuration
- `crates/sigil-daemon/src/lease_tracker.rs` - Missing import location
