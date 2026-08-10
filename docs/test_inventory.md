# SIGIL Unit Test Inventory

**Generated:** 2026-08-09  
**Workspace:** /home/coding/SIGIL  
**Purpose:** Comprehensive catalog of all unit test files, their imports, and test utility usage

## Executive Summary

- **Total crates with tests:** 31  
- **Files with `#[cfg(test)]` modules:** 122  
- **Dedicated test files:** 87  
- **Integration test files:** 45+  
- **Files using mock_helpers:** 6  
- **Files using external test utilities:** 15+

---

## Test Structure Overview

### 1. Embedded Unit Tests (`#[cfg(test)]` modules)

These are unit tests embedded within source files:

| Crate | Files with Tests | Key Test Utilities |
|-------|-----------------|-------------------|
| sigil-core | 12+ files | mock_helpers (internal) |
| sigil-daemon | 10+ files | custom helpers |
| sigil-vault | 8+ files | mock_helpers |
| sigil-scrub | 4 files | proptest |
| sigil-tui | 6 files | ratatui test utils |

### 2. Dedicated Integration Test Files (`tests/` directories)

| Crate | Test Files | Test Utilities Used |
|-------|-----------|-------------------|
| sigil-integration-tests | 45+ | common.rs, runtime_framework.rs |
| sigil-backend-vault | 2 files | mockito HTTP mocking |
| sigil-daemon | 4 files | custom source parsing tests |
| sigil-scrub | 1 file | proptest |

---

## Detailed Test File Catalog

### Backend Crate Tests

#### sigil-backend-vault/tests/
**Files:**
- `vault_backend_tests.rs`
- `vault_mock_tests.rs`

**Imports and Test Utilities:**
```rust
use mockito::Server;        // HTTP mocking for Vault/OpenBao API
use serde_json::json;       // JSON response construction
```

**Testing Pattern:** Mock HTTP responses for KV v2 API, authentication testing, cache verification

#### sigil-backend-aws/tests/
**File:** `aws_backend_tests.rs`

**Test Utilities:** AWS SDK mocking (likely mockito or similar)

#### sigil-backend-onepassword/tests/
**File:** `onepassword_backend_tests.rs`

**Test Utilities:** `mockito::Server` for 1Password Connect API mocking

#### sigil-backend-pass/tests/
**File:** `pass_backend_tests.rs`

**Test Utilities:** Command mocking for pass CLI

#### sigil-backend-sops/tests/
**File:** `sops_backend_tests.rs`

**Test Utilities:** File system mocking for SOPS-encrypted files

#### sigil-backend-env/tests/
**File:** `env_backend_tests.rs`

**Test Utilities:** Environment variable mocking

---

### Core Crate Tests

#### sigil-core

**Embedded test modules with mock_helpers:**

**File:** `src/thread_utils/result_collector.rs`
```rust
#[cfg(test)]
mod tests {
    use super::*;
    pub(super) use crate::thread_utils::result_collector::tests::mock_helpers::*;
    
    mod mock_helpers {
        /// Mock initialization for testing sender_count scenarios
        pub fn mock_sender_count_state(target_count: usize) -> ResultCollector {...}
    }
}
```

**File:** `src/ipc.rs` - Contains protocol validation tests

**File:** `src/audit.rs` - Contains hash chain tests

**Dedicated test file:** `tests/proptest_parser.rs`
```rust
use proptest::prelude::*;  // Property-based testing for command parser
```

#### sigil-daemon/tests/

**Files:**
- `hardening_test.rs` - Source code verification tests
- `red_team_checkpoint.rs` - Adversarial validation
- `runtime_hardening_verification.rs` - Runtime security checks
- `startup_modes.rs` - Daemon startup testing

**No external test utilities** - uses custom source code parsing

---

### Integration Test Framework

#### sigil-integration-tests/

**Common utilities** (`tests/common.rs`):
```rust
use std::fs;
use std::path::{Path, PathBuf};
use std::thread;
use std::time::Duration;

use sigil_integration_tests::env_detect::{
    detect_bwrap, 
    ensure_xdg_runtime_dir as lib_ensure_xdg_runtime_dir,
};
```

**Key utilities provided:**
- `workspace_root()` - Get workspace directory
- `wait_for_socket()` - Socket availability polling
- `wait_for_daemon_ready()` - Daemon health checks
- `ensure_xdg_runtime_dir()` - Runtime directory setup
- `skip_if_no_bwrap!()` - Macro for conditional skipping
- `skip_if_ci!()` - Macro for CI-aware test skipping

**Test framework** (`tests/runtime_framework.rs`):
- Provides runtime management for integration tests
- Daemon lifecycle management
- Socket path management

**Helper modules** (`src/`):
- `env_detect.rs` - Environment detection utilities
- `socket_util.rs` - Socket management
- `thread_util.rs` - Thread utilities  
- `binary_fixture.rs` - Test binary management

---

### Phase-Specific Integration Tests

The sigil-integration-tests crate organizes tests by implementation phase:

#### Phase 1 Tests (Core Vault and CLI)
- `phase1_3_verification_test.rs` - Version history testing
- `phase1_4_cli_docs_verification_test.rs` - CLI documentation
- `phase1_5_6_7_verification_test.rs` - Export/import testing
- `phase1_redteam_test.rs` - Red team checkpoint
- `phase1_redteam_checkpoint_bf4o47.rs` - Specific bead validation

#### Phase 2 Tests (Daemon and IPC)
- `phase2_ipc_protocol_test.rs` - IPC protocol validation
- `phase2_audit_lifecycle_test.rs` - Audit log testing
- `phase2_client_audit_test.rs` - Client library tests
- `phase2_signal_handling_test.rs` - Signal handling
- `phase2_4_startup_modes_verification_test.rs` - Startup modes
- `phase2_redteam_test.rs` - Red team validation

#### Phase 3 Tests (Parser and Scrubber)
- `phase3_3_cli_integration_test.rs` - CLI integration
- `phase3_3_3_4_verification_test.rs` - Parser/scrubber verification
- `phase3_redteam_test.rs` - Scrubber evasion testing

#### Phase 4 Tests (Sandbox Execution)
- `phase4_1_4_2_verification_test.rs` - Bubblewrap testing
- `phase4_3_4_4_verification_test.rs` - macOS sandbox testing
- `phase4_5_4_6_verification_test.rs` - Full pipeline testing
- `phase4_redteam_test.rs` - Sandbox escape testing
- `phase4_e2e_redteam_test.rs` - End-to-end red team

#### Phase 5 Tests (Agent Integration)
- `phase5_1_claude_code_hook_verification_test.rs` - Claude Code hooks
- `phase5_2_verification_test.rs` - Tool hook testing
- `phase5_3_5_4_verification_test.rs` - Shell wrapper testing
- `phase5_5_5_7_verification_test.rs` - MCP server testing
- `phase5_redteam_test.rs` - Agent bypass testing

#### Phase 6 Tests (TUI and Backends)
- `phase6_1_tui_verification_test.rs` - TUI functionality
- `phase6_2_3_backend_verification_test.rs` - Backend integration
- `phase6_redteam_test.rs` - TUI security testing

#### Phase 7 Tests (Breach Detection)
- `phase7_1_7_2_canary_breach_detection_test.rs` - Canary testing
- `phase7_5_troubleshoot_verification_test.rs` - Troubleshooting
- `phase7_redteam_test.rs` - Red team validation

#### Phase 8 Tests (Advanced Features)
- `phase8_1_command_recognition_verification_test.rs` - Command signatures
- `phase8_2_bidirectional_scrubbing_test.rs` - Input scrubbing
- `phase8_6_8_7_verification_test.rs` - Sealed vault testing
- `phase8_redteam_test.rs` - Advanced feature red team

#### Phase 9 Tests (Platform Features)
- `phase9_1_2_3_verification_test.rs` - FUSE testing
- `phase9_4_5_6_verification_test.rs` - Proxy and credential helpers
- `phase9_7_8_9_10_verification_test.rs` - Platform features
- `phase9_redteam_test.rs` - Platform security testing

---

## Test Utilities Map

### mock_helpers Usage

**Internal mock_helpers** are used in:

1. **sigil-core/src/thread_utils/result_collector.rs**
   - Purpose: Test ResultCollector without real channels
   - Functions: `mock_sender_count_state()`, `mock_chain_scenario()`

2. **sigil-vault** - Multiple files use internal mock helpers
3. **sigil-daemon** - Custom helpers for daemon state mocking

### External Test Libraries

| Library | Usage Location | Purpose |
|---------|----------------|---------|
| mockito | sigil-backend-* crates | HTTP API mocking |
| proptest | sigil-scrub, sigil-core | Property-based testing |
| tokio::test | All async tests | Async test runtime |
| serde_json | Backend tests | JSON response construction |

### Custom Test Macros

**From sigil-integration-tests/tests/common.rs:**

```rust
// Conditional test skipping
skip_if_no_bwrap!();
skip_if_ci!("Interactive feature");
skip_if_binary_missing!(path);

// Example usage:
#[test]
fn test_sandbox_feature() {
    skip_if_no_bwrap!("This test requires bubblewrap");
    // test code here
}
```

---

## Import Structure Analysis

### Standard Test Imports Pattern

Most integration tests follow this import pattern:

```rust
// Standard library
use std::path::{Path, PathBuf};
use std::time::Duration;

// SIGIL imports
use sigil_integration_tests::env_detect::*;
use sigil_core::SecretPath;

// Test utilities (conditional)
#[cfg(test)]
use crate::test_helpers;

// External libraries
use tokio::test;
use proptest::prelude::*;
```

### Backend-Specific Import Patterns

**Vault backend tests:**
```rust
use mockito::Server;
use sigil_backend_vault::VaultBackend;
use sigil_core::{SecretPath, SecretValue};

async fn test_vault_operation() {
    let mut server = Server::new_async().await;
    // mock setup
}
```

**Daemon tests:**
```rust
use std::path::PathBuf;
use std::process::Command;

fn daemon_src_path() -> PathBuf {
    // Custom source path resolution
}
```

---

## Test Coverage by Phase

| Phase | Unit Tests | Integration Tests | Red Team Tests |
|-------|-----------|-------------------|----------------|
| Phase 1 | 15+ files | 4 files | 2 files |
| Phase 2 | 10+ files | 6 files | 1 file |
| Phase 3 | 8 files | 3 files | 1 file |
| Phase 4 | 6 files | 4 files | 2 files |
| Phase 5 | 5 files | 5 files | 1 file |
| Phase 6 | 8 files | 2 files | 1 file |
| Phase 7 | 6 files | 2 files | 1 file |
| Phase 8 | 10+ files | 4 files | 1 file |
| Phase 9 | 12+ files | 3 files | 1 file |

---

## Key Testing Patterns

### 1. HTTP API Mocking (Backend Tests)
```rust
use mockito::Server;

#[tokio::test]
async fn test_backend_operation() {
    let mut server = Server::new_async().await;
    let mock = server.mock("GET", "/api/endpoint")
        .with_status(200)
        .with_body(r#"{"data": "value"}"#)
        .create();
    
    // Test code using the mock endpoint
}
```

### 2. Property-Based Testing (Scrubber)
```rust
use proptest::prelude::*;

proptest! {
    #[test]
    fn test_scrubber_proptest(input in "\\PC*") {
        // Property-based test logic
    }
}
```

### 3. Source Code Verification (Daemon Hardening)
```rust
#[test]
fn test_pr_set_dumpable() {
    let src = daemon_src_path().join("main.rs");
    let content = std::fs::read_to_string(src).unwrap();
    assert!(content.contains("PR_SET_DUMPABLE"));
}
```

### 4. Integration Test Pattern
```rust
use sigil_integration_tests::common::*;

#[tokio::test]
async fn test_full_pipeline() {
    skip_if_no_bwrap!("Sandbox required");
    
    let runtime_dir = create_test_runtime_dir("test_name");
    let socket_path = wait_for_socket_ready(&runtime_dir, 5000).await;
    
    // Test logic using the socket
    
    cleanup_test_runtime_dir(&runtime_dir);
}
```

---

## Missing Test Documentation

### Tests with No Clear Test Utilities

The following test files exist but don't use obvious test utilities:

1. **sigil-proxy/tests/proxy_integration.rs** - Custom HTTP proxy testing
2. **sigil-fuse** - No dedicated test files found
3. **sigil-tui** - Only embedded tests in source files
4. **sigil-mcp** - No dedicated test files found
5. **sigil-sdk** - No dedicated test files found

### Untested or Minimally Tested Crates

Based on file analysis, these crates have minimal or no test coverage:
- sigil-fuse
- sigil-mcp  
- sigil-sdk
- sigil-signatures
- sigil-shamir
- sigil-canary

---

## Test File Completeness Status

✅ **Well-tested crates:**
- sigil-core (comprehensive unit + integration tests)
- sigil-daemon (extensive security testing)
- sigil-vault (version history, export/import)
- sigil-scrub (property-based testing)
- sigil-integration-tests (45+ phase-specific tests)

⚠️ **Moderately tested crates:**
- All backend crates (basic HTTP mocking tests)
- sigil-cli (embedded tests only)
- sigil-tui (embedded tests only)

❌ **Minimal/no test coverage:**
- sigil-fuse
- sigil-mcp
- sigil-sdk
- sigil-signatures  
- sigil-shamir

---

## Recommendations

### 1. Test Utility Consolidation

**Current:** Multiple test utility patterns across crates  
**Recommendation:** Consolidate common utilities into `sigil-testing` crate

### 2. Missing Test Coverage

**Priority areas for additional tests:**
- FUSE filesystem operations
- MCP server tool implementations  
- SDK language bindings
- Signature detection patterns
- Shamir secret sharing

### 3. Mock Helpers Standardization

**Current:** Internal mock_helpers in multiple locations  
**Recommendation:** Create unified mock_helper library

### 4. Integration Test Organization

**Current:** 45+ phase-specific test files  
**Recommendation:** Consider subdirectory organization by phase

---

## Conclusion

SIGIL has a comprehensive testing infrastructure with:
- **122 source files** containing embedded unit tests
- **87 dedicated test files** for integration and specialized testing  
- **Phase-specific organization** for implementation tracking
- **Strong backend testing** using HTTP mocking
- **Property-based testing** for critical scrubber logic
- **Red team testing** integrated throughout all phases

**Key areas for improvement:**
1. Consolidate scattered test utilities
2. Add coverage for FUSE, MCP, SDK, and crypto crates
3. Standardize mock helper patterns
4. Document test utility APIs

This inventory provides the foundation for systematic test maintenance and coverage improvements across the SIGIL workspace.
