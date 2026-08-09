# Missing Imports Analysis - Current State (2026-08-09)

## Task Verification

**Objective:** Identify missing imports across core SIGIL crates
**Date:** 2026-08-09  
**Methodology:** `cargo check --all-features` to catch feature-gated errors

## Current Status

### Compilation Check Results

✅ **sigil-core**: No compilation errors
✅ **sigil-vault**: No compilation errors  
✅ **sigil-cli**: No compilation errors
❌ **sigil-daemon**: 1 compilation error (feature-gated)
✅ **sigil-sandbox**: No compilation errors
✅ **sigil-scrub**: No compilation errors
✅ **sigil-tui**: No compilation errors
✅ **sigil-mcp**: No compilation errors
✅ **All backend crates**: No compilation errors
✅ **All credential helper crates**: No compilation errors

## Detailed Finding

### Missing Import in sigil-daemon

**File:** `crates/sigil-daemon/src/lease_tracker.rs`  
**Line:** 323  
**Error Code:** E0599  
**Feature Gate:** `#[cfg(feature = "dynamic")]`

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

#### Root Cause Analysis

The `revoke_vault_lease` function (lines 291-330) is feature-gated with `#[cfg(feature = "dynamic")]`:

```rust
#[cfg(feature = "dynamic")]
async fn revoke_vault_lease(
    &self,
    config: &BackendConfig,
    lease: &LeaseInfo,
) -> LeaseRevocationResult {
    use sigil_core::VaultDynamicProvider;  // ← Line 297: imports struct only
    
    // ... code to create VaultDynamicProvider ...
    
    match provider.revoke_lease(&lease.lease_id).await {
        //    ^^^^^^^^^^^^ ERROR: trait method not accessible
        Ok(()) => LeaseRevocationResult::Revoked(lease.lease_id.clone()),
        Err(e) => LeaseRevocationResult::Failed(lease.lease_id.clone(), format!("Revocation failed: {}", e)),
    }
}
```

**Problem:** 
- Line 297 imports only `VaultDynamicProvider` (the struct)
- Line 323 calls `provider.revoke_lease()` 
- The `revoke_lease` method is defined in the `DynamicSecretProvider` trait
- **Rust Rule:** Trait methods can only be called when the trait is in scope

**Why This Error Exists:**
- The error only appears with `--all-features` flag
- Standard `cargo check` without features doesn't compile the dynamic code path
- CI may not catch this if it doesn't test with all features enabled

## Required Fix

### Single Import Addition

**Location:** `crates/sigil-daemon/src/lease_tracker.rs`  
**Add after line 297:**

```rust
#[cfg(feature = "dynamic")]
async fn revoke_vault_lease(
    &self,
    config: &BackendConfig,
    lease: &LeaseInfo,
) -> LeaseRevocationResult {
    use sigil_core::VaultDynamicProvider;
    use sigil_core::DynamicSecretProvider;  // ← ADD THIS LINE
    
    // ... rest of function unchanged ...
```

**Alternative:** Add the trait import at the module level (line 11 area with other imports):

```rust
use anyhow::{anyhow, Result};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
// ... other imports ...
#[cfg(feature = "dynamic")]
use sigil_core::DynamicSecretProvider;  // ← Module-level import
```

## Verification Commands

After adding the import, verify with:

```bash
# Should pass without errors
cargo check --all-features

# Should pass without warnings  
cargo clippy --all-features -- -D warnings

# All tests should pass
cargo test --all-features
```

## Summary

- **Total Missing Imports Found:** 1
- **Affected Crates:** 1 (sigil-daemon)  
- **Severity:** Compilation error (blocks builds with `--all-features`)
- **Fix Complexity:** Trivial (one-line import addition)
- **Risk Assessment:** Low (isolated to feature-gated code)

## Notes

1. This is the **only** compilation error across the entire 28-crate workspace
2. All other crates compile successfully without missing imports
3. The error is well-isolated and has a clear compiler-suggested fix
4. This error does not affect default builds, only `--all-features` builds
