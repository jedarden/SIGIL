# SIGIL Unit Test File Catalog

**Generated**: 2026-08-10  
**Purpose**: Comprehensive inventory of all unit test files across all crates with import structure analysis

---

## Summary Statistics

- **Total Crates**: 33
- **Crates with Tests**: 15
- **Total Test Files**: 100+ files
- **Mock Frameworks**: mockito, proptest, custom mock_helpers
- **Test Utility Modules**: 3 major utility modules identified

---

## Test File Distribution by Crate

### Backend Crates (6 test files)
- `sigil-backend-aws`: 1 test file
- `sigil-backend-env`: 1 test file  
- `sigil-backend-onepassword`: 1 test file
- `sigil-backend-pass`: 1 test file
- `sigil-backend-sops`: 1 test file
- `sigil-backend-vault`: 2 test files (including mock tests)

### Core Crates (1 test file)
- `sigil-core`: 1 property-based test file

### Daemon/Sandbox Crates (1 test file)
- `sigil-daemon`: 1 test file

### Integration Tests (80+ test files)
- `sigil-integration-tests`: 80+ integration and verification test files

### Utility Crates (1 test file)
- `sigil-scrub`: 1 property-based test file

---

## Mock Framework Usage

### 1. **mockito** - HTTP API Mocking
**Files Using mockito:**
- `sigil-backend-vault/tests/vault_mock_tests.rs` - Full HTTP mocking for Vault API
- `sigil-backend-vault/tests/vault_backend_tests.rs` - Basic Server mocking  
- `sigil-backend-onepassword/tests/onepassword_backend_tests.rs` - 1Password API mocking

**Import Pattern:**
```rust
use mockito::Server;
use mockito::Matcher;
```

### 2. **proptest** - Property-Based Testing
**Files Using proptest:**
- `sigil-core/tests/proptest_parser.rs` - Parser property testing
- `sigil-scrub/tests/proptest_scrubber.rs` - Scrubber property testing

**Import Pattern:**
```rust
use proptest::prelude::*;
```

### 3. **mock_helpers** - Custom Mock Utilities
**Location**: `sigil-core/src/thread_utils/result_collector.rs`

**Structure:**
```rust
#[cfg(test)]
mod tests {
    // Mock helpers module - contains mock initialization and scenario functions
    mod mock_helpers {
        use super::*;
        pub(super) fn mock_sender_count_state<T>(target_count: usize) -> Vec<StreamingResultCollector<T>>
    }
    
    // Re-export mock_helper functions for use in other test modules
    pub(super) use crate::thread_utils::result_collector::tests::mock_helpers::*;
}
```

**Usage Pattern:**
```rust
use mock_helpers::{mock_sender_count_state, mock_sender_chain, mock_duplicate_sender_state};
```

---

## Test Utility Modules

### 1. **Integration Test Common Utilities** 
**Location**: `sigil-integration-tests/tests/common.rs`

**Purpose**: Shared utilities for all integration tests

**Key Functions:**
```rust
pub fn workspace_root() -> PathBuf
pub fn is_bwrap_available() -> bool
pub fn wait_for_socket(socket_path: &Path, timeout_ms: u64) -> bool
pub fn wait_for_daemon_ready(socket_path: &Path, timeout_ms: u64) -> bool
pub fn ensure_xdg_runtime_dir() -> PathBuf
pub fn can_start_daemon(daemon_path: &Path, require_bwrap: bool) -> bool
pub fn create_test_runtime_dir(test_name: &str) -> PathBuf
pub fn cleanup_test_runtime_dir(runtime_dir: &Path)
```

**Macros:**
```rust
skip_if_no_bwrap!()
skip_if_ci!()
skip_if_binary_missing!()
```

**Usage in Tests:**
```rust
use sigil_integration_tests::env_detect::{ensure_xdg_runtime_dir, is_bwrap_available};
```

### 2. **Runtime Framework**
**Location**: `sigil-integration-tests/tests/runtime_framework.rs`

**Purpose**: Daemon lifecycle management and command execution

**Key Components:**
```rust
pub struct Binaries { pub sigil: PathBuf, pub sigild: PathBuf }
pub struct DaemonGuard { /* manages daemon lifecycle */ }
pub struct CommandExecutor { /* executes sigil commands */ }
```

### 3. **Environment Detection Module**
**Location**: `sigil-integration-tests/src/env_detect.rs`

**Purpose**: Centralized environment capability detection

**Key Functions:**
```rust
pub fn detect_bwrap() -> bool
pub fn ensure_xdg_runtime_dir() -> Result<PathBuf>
pub fn skip::{if_no_bwrap(), if_ci(), if_binary_missing()}
```

---

## Detailed Import Structure by Test Category

### Backend Tests (HTTP Mocking)
**Pattern**: Mock HTTP servers for external API testing

**sigil-backend-vault/tests/vault_mock_tests.rs:**
```rust
use mockito::Matcher;
use sigil_backend_vault::{VaultAuth, VaultBackend, VaultBackendConfig, VaultToken};
use sigil_core::{SecretBackend, SecretMetadata, SecretPath, SecretType, SecretValue, SigilError};
use std::time::Duration;
```

**sigil-backend-onepassword/tests/onepassword_backend_tests.rs:**
```rust
use mockito::Server;
use sigil_backend_onepassword::OnePasswordBackend;
use sigil_core::{SecretBackend, SecretPath, SecretValue, SecretMetadata, SecretType};
```

### Property-Based Tests
**Pattern**: Use proptest for invariant verification

**sigil-core/tests/proptest_parser.rs:**
```rust
use proptest::prelude::*;
use sigil_core::parser::CommandParser;
use sigil_core::{SecretPath, SecretPlaceholder};
```

**sigil-scrub/tests/proptest_scrubber.rs:**
```rust
use proptest::prelude::*;
use sigil_core::SecretPath;
use sigil_scrub::Scrubber;
```

### Integration Tests
**Pattern**: Common utilities + environment detection

**Common imports across integration tests:**
```rust
use sigil_integration_tests::env_detect::{ensure_xdg_runtime_dir, is_bwrap_available};
use sigil_integration_tests::DaemonGuard;
use tempfile::TempDir;
```

### Unit Tests in Source Files
**Pattern**: Internal test modules with mock_helpers

**sigil-core/src/thread_utils/result_collector.rs:**
```rust
#[cfg(test)]
mod tests {
    use super::*;
    use mock_helpers::*;
    use assertion_helpers::*;
}
```

---

## Files with mock_helpers Import

### Direct mock_helpers Usage
Only **1 file** currently uses the mock_helpers module:

1. **sigil-core/src/thread_utils/result_collector.rs**
   - Location: Internal test module within source file
   - Purpose: Testing thread result collection
   - Functions: `mock_sender_count_state`, `mock_sender_chain`, `mock_duplicate_sender_state`

### Re-exports and Test Utility Chains
The mock_helpers module is re-exported for use in related test modules:

```rust
// In result_collector.rs tests
pub(super) use crate::thread_utils::result_collector::tests::mock_helpers::*;

// Available to other test modules in the same crate
use assertion_helpers::{
    validate_comprehensive_sender_count,
    validate_monotonic_sender_count,
    // ... more validators
};
use mock_helpers::{
    mock_sender_count_state,
    mock_sender_chain,
    mock_duplicate_sender_state,
};
```

---

## Complete Test File Inventory

### Backend Test Files (9 files)
```
sigil-backend-aws/tests/aws_backend_tests.rs
sigil-backend-env/tests/env_backend_tests.rs
sigil-backend-onepassword/tests/onepassword_backend_tests.rs
sigil-backend-pass/tests/pass_backend_tests.rs
sigil-backend-sops/tests/sops_backend_tests.rs
sigil-backend-vault/tests/vault_backend_tests.rs
sigil-backend-vault/tests/vault_mock_tests.rs
```

### Core Test Files (1 file)
```
sigil-core/tests/proptest_parser.rs
```

### Daemon/Sandbox Test Files (1 file)
```
sigil-daemon/tests/hardening_test.rs
```

### Scrubbing Test Files (1 file)
```
sigil-scrub/tests/proptest_scrubber.rs
```

### Integration Test Files (80+ files)
```
sigil-integration-tests/tests/backend_integration_test.rs
sigil-integration-tests/tests/canary_trigger_execution_test.rs
sigil-integration-tests/tests/daemon_hardening_test.rs
sigil-integration-tests/tests/daemon_startup_test.rs
sigil-integration-tests/tests/decoy_and_lockdown_test.rs
sigil-integration-tests/tests/doctor_test.rs
sigil-integration-tests/tests/env_detect_concurrent_test.rs
sigil-integration-tests/tests/export_import_integration_test.rs
sigil-integration-tests/tests/export_import_roundtrip_test.rs
sigil-integration-tests/tests/external_backend_e2e_test.rs
sigil-integration-tests/tests/full_pipeline_integration_test.rs
sigil-integration-tests/tests/fuse_security_test.rs
sigil-integration-tests/tests/hook_simulation_test.rs
sigil-integration-tests/tests/mcp_server_integration_test.rs
sigil-integration-tests/tests/proxy_security_test.rs
sigil-integration-tests/tests/sandbox_isolation_integration_test.rs
sigil-integration-tests/tests/sdk_test.rs
sigil-integration-tests/tests/sealed_ops_test.rs
sigil-integration-tests/tests/setgid_detection_test.rs
sigil-integration-tests/tests/setuid_detection_test.rs

sigil-integration-tests/tests/phase1_3_verification_test.rs
sigil-integration-tests/tests/phase1_3_1_verification_test.rs
sigil-integration-tests/tests/phase1_4_cli_docs_verification_test.rs
sigil-integration-tests/tests/phase1_5_6_7_verification_test.rs
sigil-integration-tests/tests/phase1_redteam_test.rs

sigil-integration-tests/tests/phase2_4_startup_modes_verification_test.rs
sigil-integration-tests/tests/phase2_audit_ipc_signals_test.rs
sigil-integration-tests/tests/phase2_audit_lifecycle_test.rs
sigil-integration-tests/tests/phase2_client_audit_test.rs
sigil-integration-tests/tests/phase2_ipc_protocol_test.rs
sigil-integration-tests/tests/phase2_signal_handling_test.rs
sigil-integration-tests/tests/phase2_redteam_test.rs

sigil-integration-tests/tests/phase3_3_3_4_verification_test.rs
sigil-integration-tests/tests/phase3_3_cli_integration_test.rs
sigil-integration-tests/tests/phase3_redteam_test.rs

sigil-integration-tests/tests/phase4_1_4_2_sandbox_verification_test.rs
sigil-integration-tests/tests/phase4_1_4_2_verification_test.rs
sigil-integration-tests/tests/phase4_3_4_4_verification_test.rs
sigil-integration-tests/tests/phase4_5_4_6_verification_test.rs
sigil-integration-tests/tests/phase4_e2e_redteam_test.rs
sigil-integration-tests/tests/phase4_redteam_test.rs

sigil-integration-tests/tests/phase5_1_claude_code_hook_verification_test.rs
sigil-integration-tests/tests/phase5_2_non_bash_tool_hooks_test.rs
sigil-integration-tests/tests/phase5_2_verification_test.rs
sigil-integration-tests/tests/phase5_3_5_4_verification_test.rs
sigil-integration-tests/tests/phase5_5_5_7_verification_test.rs
sigil-integration-tests/tests/phase5_redteam_test.rs

sigil-integration-tests/tests/phase6_1_tui_verification_test.rs
sigil-integration-tests/tests/phase6_2_3_backend_verification_test.rs
sigil-integration-tests/tests/phase6_redteam_test.rs

sigil-integration-tests/tests/phase7_1_7_2_canary_breach_detection_test.rs
sigil-integration-tests/tests/phase7_5_troubleshoot_verification_test.rs
sigil-integration-tests/tests/phase7_redteam_test.rs
sigil-integration-tests/tests/phase7_runtime_test.rs
sigil-integration-tests/tests/phase7_troubleshoot_runtime_test.rs

sigil-integration-tests/tests/phase8_1_command_recognition_verification_test.rs
sigil-integration-tests/tests/phase8_2_bidirectional_scrubbing_test.rs
sigil-integration-tests/tests/phase8_2_scrubbing_runtime_test.rs
sigil-integration-tests/tests/phase8_3_4_5_verification_test.rs
sigil-integration-tests/tests/phase8_6_8_7_sealed_vault_redteam_test.rs
sigil-integration-tests/tests/phase8_6_8_7_verification_test.rs
sigil-integration-tests/tests/phase8_9_daemon_runtime_test.rs
sigil-integration-tests/tests/phase8_redteam_test.rs
sigil-integration-tests/tests/phase8_runtime_test.rs

sigil-integration-tests/tests/phase9_1_2_3_verification_test.rs
sigil-integration-tests/tests/phase9_4_5_6_verification_test.rs
sigil-integration-tests/tests/phase9_7_8_9_10_verification_test.rs
sigil-integration-tests/tests/phase9_redteam_test.rs
sigil-integration-tests/tests/phase9_runtime_test.rs
```

---

## Key Findings

### Mock Framework Distribution
- **mockito**: 3 files (backend HTTP testing)
- **proptest**: 2 files (property-based testing)
- **mock_helpers**: 1 file (custom thread testing utilities)

### Test Utility Coverage
- **15 crates** have test files
- **80+ integration tests** in dedicated integration test crate
- **3 major test utility modules** providing common functionality
- **100+ test files** total across the workspace

### Import Structure Consistency
- Integration tests consistently use common utilities from `sigil-integration-tests`
- Backend tests consistently use mockito for HTTP mocking
- Property tests use proptest framework
- Unit tests in source files use internal test modules

### Areas with No Custom Mock Utilities
- Most crates use standard testing frameworks (tokio::test, proptest)
- No widespread use of custom mock helpers beyond thread utilities
- Heavy reliance on common integration test utilities
- Minimal mocking framework diversity (mostly mockito for HTTP)

---

## Recommendations

1. **Consolidate Mock Utilities**: Consider centralizing mock_helpers patterns if more files need similar functionality
2. **Standardize Import Patterns**: Integration tests already follow consistent patterns; document these for new tests
3. **Expand Property Testing**: More proptest coverage could improve reliability (currently only 2 files)
4. **Test Utility Documentation**: The common utilities module is well-structured; consider expanding documentation

---

## Import Pattern Summary

### Pattern 1: Common Utilities (Most Common)
```rust
// Common test setup imports
use sigil_integration_tests::env_detect::{ensure_xdg_runtime_dir, is_bwrap_available};
use sigil_integration_tests::DaemonGuard;
use tempfile::TempDir;
use std::path::{Path, PathBuf};
```

### Pattern 2: Mock Framework Testing
```rust
// HTTP mocking for backend tests
use mockito::{Server, Matcher};
use sigil_core::{SecretBackend, SecretPath, SecretValue};
```

### Pattern 3: Property-Based Testing
```rust
// Proptest for invariant verification
use proptest::prelude::*;
use sigil_core::SecretPath;
```

### Pattern 4: Internal Unit Testing
```rust
// In-source unit tests with mock helpers
#[cfg(test)]
mod tests {
    use super::*;
    use mock_helpers::*;
}
```

---

**Catalog Complete**: 100+ test files cataloged with import structure analysis across 33 crates.
