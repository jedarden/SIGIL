# SIGIL Test Import Structure Analysis

**Generated:** 2026-08-09  
**Analysis Type:** Import patterns and test utility usage across all test files

## Complete Import Structure Map

### 1. Standard Library Imports (All Tests)

```rust
use std::fs;                                  // File system operations
use std::path::{Path, PathBuf};              // Path manipulation
use std::process::{Command, Stdio};          // Process execution
use std::thread;                               // Thread management
use std::time::{Duration, Instant};           // Timing and delays
use std::io::{Cursor, Read, Write};            // I/O operations
```

### 2. Core SIGIL Imports (Most Common)

```rust
// Core types and traits
use sigil_core::{SecretPath, SecretValue, SecretMetadata, SecretBackend};
use sigil_core::ipc::{IpcRequest, IpcResponse, IpcErrorCode, SessionToken};
use sigil_core::audit::{AuditEntry, AuditLogReader, AuditConfig};
use sigil_core::ErrorCode;

// Vault implementations
use sigil_vault::{LocalVault, VersionManager};

// Scrubber
use sigil_scrub::Scrubber;

// Sandbox
use sigil_sandbox::{SandboxConfig, SandboxProvider, ShellState};

// Signatures
use sigil_signatures::{SignatureMatcher, BUILTIN_SIGNATURES};

// TUI
use sigil_tui::{ApprovalDecision, ApprovalRequest};
```

### 3. Test Framework Imports

```rust
// Integration test framework
use sigil_integration_tests::env_detect::*;
use sigil_integration_tests::DaemonGuard;
use sigil_integration_tests::binary_fixture::*;
use sigil_integration_tests::thread_util::*;

// Common utilities
use common::{workspace_root, crate_source_path};
use runtime_framework::*;

// Async testing
use tokio::test;

// Property-based testing
use proptest::prelude::*;

// HTTP mocking (backends)
use mockito::Server;

// Test serialization
use serial_test::serial;

// Temp files and directories
use tempfile::{TempDir, NamedTempFile};
```

### 4. Test Utility Module Structure

#### sigil-integration-tests/src/

**env_detect.rs** - Environment detection and skip logic:
```rust
use anyhow::{Context, Result};
use std::path::{Path, PathBuf};
use std::process::Command;

pub struct Environment {
    pub bwrap_available: bool,
    pub systemd_available: bool,
    pub launchd_available: bool,
    pub is_ci: bool,
    pub xdg_runtime_dir: PathBuf,
}

pub fn detect_bwrap() -> bool;
pub fn ensure_xdg_runtime_dir() -> Result<PathBuf>;
pub mod skip {
    pub fn if_no_bwrap();
    pub fn if_ci();
    pub fn if_binary_missing(path: &Path);
}
```

**socket_util.rs** - Socket management:
```rust
use std::path::Path;
use std::time::Duration;

pub fn wait_for_socket(socket_path: &Path, timeout_ms: u64) -> bool;
pub fn wait_for_daemon_ready(socket_path: &Path, timeout_ms: u64) -> bool;
```

**thread_util.rs** - Thread utilities:
```rust
use std::thread;
use std::time::Duration;

pub fn spawn_named_thread(name: String, f: F);
pub fn sleep_with_logging(duration: Duration);
```

**binary_fixture.rs** - Test binary management:
```rust
use std::path::PathBuf;

pub struct Binaries {
    pub sigil: PathBuf,
    pub sigild: PathBuf,
}

impl Binaries {
    pub fn get() -> Option<Self>;
}
```

## Test File Classification by Import Patterns

### Category A: Integration Tests with Full Framework

**Files:** 40+ files in `sigil-integration-tests/tests/`

**Import Pattern:**
```rust
mod common;
use common::workspace_root;
use runtime_framework::*;
use sigil_integration_tests::env_detect::*;
use sigil_integration_tests::DaemonGuard;
use tempfile::TempDir;
```

**Examples:**
- `phase1_3_verification_test.rs`
- `phase2_ipc_protocol_test.rs`
- `phase3_3_cli_integration_test.rs`
- `full_pipeline_integration_test.rs`

### Category B: Backend Tests with HTTP Mocking

**Files:** All `sigil-backend-*/tests/*.rs`

**Import Pattern:**
```rust
use mockito::Server;
use serde_json::json;
use sigil_core::{SecretPath, SecretValue};
use sigil_backend_X::BackendType;

#[tokio::test]
async fn test_backend_operation() {
    let mut server = Server::new_async().await;
    // HTTP mocking setup
}
```

**Examples:**
- `vault_backend_tests.rs`
- `onepassword_backend_tests.rs`
- `aws_backend_tests.rs`

### Category C: Property-Based Tests

**Files:** 
- `sigil-scrub/tests/proptest_scrubber.rs`
- `sigil-core/tests/proptest_parser.rs`

**Import Pattern:**
```rust
use proptest::prelude::*;
use sigil_core::SecretPath;
use sigil_scrub::Scrubber;

proptest! {
    #[test]
    fn test_property(input in "[a-zA-Z0-9]{0,100}") {
        // Property-based test logic
    }
}
```

### Category D: Source Code Verification Tests

**Files:**
- `sigil-daemon/tests/hardening_test.rs`
- `sigil-daemon/tests/runtime_hardening_verification.rs`
- `phase1_redteam_test.rs` (and similar)

**Import Pattern:**
```rust
use std::fs;
use std::path::PathBuf;

fn test_security_property() {
    let src_path = PathBuf::from("path/to/source.rs");
    let code = fs::read_to_string(&src_path).unwrap();
    assert!(code.contains("SECURITY_PATTERN"));
}
```

### Category E: Internal Unit Tests with mock_helpers

**Files:**
- `sigil-core/src/thread_utils/result_collector.rs`
- Various `sigil-vault` source files

**Import Pattern:**
```rust
#[cfg(test)]
mod tests {
    use super::*;
    use crate::module::tests::mock_helpers::*;
    
    #[test]
    fn test_internal_logic() {
        let mock_state = mock_helper_function();
        // Test using mock
    }
}
```

## Specific Test Utility Functions Catalog

### Common Test Functions (from common.rs)

**Path Management:**
```rust
workspace_root() -> PathBuf
crate_source_path(crate_name: &str, file: &str) -> PathBuf
```

**Environment Detection:**
```rust
is_bwrap_available() -> bool
ensure_xdg_runtime_dir() -> PathBuf
detect_bwrap() -> bool
```

**Socket Management:**
```rust
wait_for_socket(socket_path: &Path, timeout_ms: u64) -> bool
wait_for_daemon_ready(socket_path: &Path, timeout_ms: u64) -> bool
wait_for_socket_sync(socket_path: &Path, timeout_ms: u64) -> Result<(), String>
socket_wait_helper(socket_path: &Path, timeout_ms: u64) -> Result<(), String>
daemon_health_check(socket_path: &Path) -> Result<(), String>
```

**Test Environment:**
```rust
create_test_runtime_dir(test_name: &str) -> PathBuf
cleanup_test_runtime_dir(runtime_dir: &Path)
can_start_daemon(daemon_path: &Path, require_bwrap: bool) -> bool
create_blocking_runtime() -> tokio::runtime::Runtime
```

**Conditional Test Macros:**
```rust
skip_if_no_bwrap!();
skip_if_ci!("reason");
skip_if_binary_missing!(path);
```

### Runtime Framework Functions (from runtime_framework.rs)

**Binary Management:**
```rust
Binaries::get() -> Option<Binaries>  // Provides paths to sigil and sigild
```

**Daemon Lifecycle:**
```rust
start_daemon() -> DaemonGuard
stop_daemon() -> Result<(), Error>
```

**Command Execution:**
```rust
sigil_cmd(args: &[&str]) -> Output
sigil_success(args: &[&str]) -> String
```

### mock_helpers Functions (from result_collector.rs)

```rust
mock_sender_count_state(target_count: usize) -> Vec<StreamingResultCollector<T>>
mock_chain_scenario(nodes: usize) -> ResultCollector<T>
mock_error_scenario() -> ResultCollector<T>
```

## Test Organization Patterns

### Phase-Based Organization

Tests are organized by implementation phase:

```
sigil-integration-tests/tests/
├── phase1_*_test.rs              # Phase 1: Core Vault and CLI
├── phase2_*_test.rs              # Phase 2: Daemon and IPC  
├── phase3_*_test.rs              # Phase 3: Parser and Scrubber
├── phase4_*_test.rs              # Phase 4: Sandbox Execution
├── phase5_*_test.rs              # Phase 5: Agent Integration
├── phase6_*_test.rs              # Phase 6: TUI and Backends
├── phase7_*_test.rs              # Phase 7: Breach Detection
├── phase8_*_test.rs              # Phase 8: Advanced Features
├── phase9_*_test.rs              # Phase 9: Platform Features
├── *_redteam_test.rs             # Red team checkpoint tests
├── *_verification_test.rs        # Phase completion verification
└── common.rs                     # Shared utilities
```

### Functional Organization

**Security-focused tests:**
- `*_redteam_test.rs`
- `*_security_test.rs`
- `hardening_test.rs`

**Integration-focused tests:**
- `*_integration_test.rs`
- `full_pipeline_integration_test.rs`

**Backend-focused tests:**
- `backend_integration_test.rs`
- `external_backend_e2e_test.rs`

## Test Dependencies and Relationships

### Dependency Graph

```
common.rs (basic utilities)
    ↓
env_detect.rs (environment detection)
    ↓
runtime_framework.rs (daemon management)
    ↓
All integration tests
```

**Backend Tests** → Independent, use mockito directly

**Unit Tests** → Use internal mock_helpers

**Integration Tests** → Depend on common utilities

## External Test Library Dependencies

| Library | Version (implied) | Usage | Files Using |
|---------|------------------|-------|-------------|
| mockito | latest | HTTP mocking | 6 backend test files |
| proptest | latest | Property-based testing | 2 test files |
| tempfile | latest | Temporary files | 40+ test files |
| tokio | latest | Async runtime | All async tests |
| serial_test | latest | Test serialization | 2 test files |
| serde_json | latest | JSON manipulation | Backend tests |

## Test Configuration Patterns

### Test Attributes Used

```rust
#[test]                    // Standard unit test
#[tokio::test]             // Async unit test
#[cfg(target_os = "linux")] // Platform-specific
#[cfg(test)]                // Test-only code
#[allow(dead_code)]         // Test utilities
```

### Test Organization Patterns

**Nested test modules:**
```rust
#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_feature() {
        // Test code
    }
    
    mod mock_helpers {
        // Mock utilities for tests
    }
}
```

**Integration test structure:**
```rust
mod common;
use common::*;

#[test]
fn test_integration() {
    skip_if_no_bwrap!();
    // Test code
}
```

## Test Coverage Summary

### Files with mock_helpers Usage (6 files)

1. `sigil-core/src/thread_utils/result_collector.rs` - Internal mock helpers
2. `sigil-vault/src/local.rs` - Vault state mocking
3. `sigil-vault/src/version_manager.rs` - Version control mocking
4. `sigil-daemon/src/client.rs` - Client mocking
5. `sigil-daemon/src/audit.rs` - Audit state mocking
6. `sigil-daemon/src/vault.rs` - Vault daemon mocking

### Files Using Common Test Utilities (45+ files)

All files in `sigil-integration-tests/tests/` use:
- `common::*` utilities
- `runtime_framework::*` utilities
- `sigil_integration_tests::*` library functions

### Files Using External Test Libraries (15+ files)

- **mockito:** 6 backend test files
- **proptest:** 2 property-based test files  
- **tempfile:** 40+ integration test files
- **serial_test:** 2 serialization test files

## Recommendations for Test Utility Consolidation

### 1. Create sigil-testing Crate

**Current:** Utilities scattered across multiple locations  
**Proposed:** Consolidate into dedicated testing crate

```rust
// sigil-testing/
├── src/
│   ├── common.rs          // Path, file, environment utilities
│   ├── mock_helpers.rs    // All mock utilities
│   ├── framework.rs       // Daemon lifecycle management
│   └── assertions.rs      // Custom test assertions
```

### 2. Standardize Import Patterns

**Current:** Multiple import patterns across test files  
**Proposed:** Prelude module for common imports

```rust
// sigil-testing::prelude
use sigil_testing::{
    workspace_root, test_runtime_dir, mock_helpers, 
    DaemonGuard, TestAssertions
};
```

### 3. Unify Skip Logic

**Current:** Skip macros in common.rs + env_detect.rs  
**Proposed:** Single skip module with comprehensive detection

### 4. Mock Helper Standardization

**Current:** Internal mock_helpers in 6 locations  
**Proposed:** Centralized mock helper library

## Conclusion

The SIGIL workspace has a comprehensive but fragmented test infrastructure:

**Strengths:**
- Comprehensive phase-based organization
- Multiple testing approaches (unit, integration, property-based, source verification)
- Strong environment detection and skip logic
- Good backend testing with HTTP mocking

**Areas for Improvement:**
- Test utilities scattered across multiple files
- Inconsistent import patterns across test types
- Multiple mock helper implementations
- No centralized testing crate

**Recommendation:** Create a unified `sigil-testing` crate to consolidate test utilities and standardize import patterns across all test types.

This analysis provides the foundation for systematic test infrastructure improvements and better maintainability across the SIGIL workspace.
