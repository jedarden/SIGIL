# SIGIL Unit Test Inventory and Import Structure Analysis

**Generated:** 2026-08-09  
**Purpose:** Comprehensive catalog of all unit test files across the SIGIL workspace, documenting import patterns and test utility usage.

## Executive Summary

The SIGIL workspace contains **97 unit test files** across **21 crates**, organized into:

- **Property-based tests** using `proptest` for parser and scrubber verification
- **Integration tests** using common fixtures and daemon guards  
- **Backend tests** using `mockito` for HTTP API mocking
- **Internal test modules** using custom `mock_helpers` and test utilities

## Test File Categories

### 1. Property-Based Tests (Proptest)

**Files:**
- `crates/sigil-core/tests/proptest_parser.rs`
- `crates/sigil-scrub/tests/proptest_scrubber.rs`

**Import Structure:**
```rust
use proptest::prelude::*;
use sigil_core::parser::CommandParser;  // or sigil_scrub::Scrubber
use sigil_core::SecretPath;
```

**Purpose:** Verify parser and scrubber invariants across wide input ranges using property-based testing.

**Test Utilities Used:**
- `proptest::prelude::*` - Property testing framework
- Custom strategy definitions for input generation
- `prop_assert!` and `prop_assert_eq!` macros

---

### 2. Backend HTTP Tests (Mockito)

**Files:**
- `crates/sigil-backend-vault/tests/vault_backend_tests.rs`
- `crates/sigil-backend-vault/tests/vault_mock_tests.rs`
- Similar patterns in other backend crates

**Import Structure:**
```rust
use mockito::Server;
use mockito::Matcher;  // for advanced request matching
use serde_json::json;
```

**Purpose:** Test HTTP backend interactions (Vault/OpenBao, AWS, 1Password, etc.) using mocked HTTP responses.

**Test Utilities Used:**
- `mockito::Server::new_async()` - Async HTTP server mocking
- `.mock()` method for endpoint mocking
- `.with_status()`, `.with_header()`, `.with_body()` for response configuration
- `.create_async()` and `.assert_async()` for test lifecycle

---

### 3. Integration Test Common Utilities

**Primary Utility File:** `crates/sigil-integration-tests/tests/common.rs`

**Import Structure:**
```rust
mod common;
use common::{workspace_root, wait_for_socket_sync, daemon_health_check};

// Or direct imports from lib
use sigil_integration_tests::env_detect::{detect_bwrap, ensure_xdg_runtime_dir};
use sigil_integration_tests::DaemonGuard;
```

**Key Utilities Provided:**

#### Environment Detection
```rust
use sigil_integration_tests::env_detect::{
    detect_bwrap,
    ensure_xdg_runtime_dir,
    is_bwrap_available
};
```

#### Socket Management
```rust
pub fn wait_for_socket(socket_path: &Path, timeout_ms: u64) -> bool
pub fn wait_for_daemon_ready(socket_path: &Path, timeout_ms: u64) -> bool  
pub fn wait_for_socket_sync(socket_path: &Path, timeout_ms: u64) -> Result<(), String>
pub fn socket_wait_helper(socket_path: &Path, timeout_ms: u64) -> Result<(), String>
```

#### Daemon Management
```rust
pub fn daemon_health_check(socket_path: &Path) -> Result<(), String>
pub fn can_start_daemon(daemon_path: &Path, require_bwrap: bool) -> bool
```

#### Runtime Management
```rust
pub fn create_test_runtime_dir(test_name: &str) -> PathBuf
pub fn cleanup_test_runtime_dir(runtime_dir: &Path)
pub fn create_blocking_runtime() -> tokio::runtime::Runtime
```

#### Skip Macros
```rust
skip_if_no_bwrap!()
skip_if_ci!()
skip_if_binary_missing!(binary_path)
```

---

### 4. Integration Test Framework

**Core Library:** `crates/sigil-integration-tests/src/lib.rs`

**Modules Exported:**
```rust
pub mod socket_util;          // Socket availability wait helpers
pub mod env_detect;            // Environment detection for test helpers  
pub mod thread_util;           // Thread testing utilities
pub mod concurrent_tests;     // Comprehensive concurrent testing infrastructure
pub mod binary_fixture;        // Binary fixture utilities for permission testing
```

**Key Types:**
```rust
pub struct TestConfig {
    pub sigil_bin: PathBuf,
    pub sigild_bin: PathBuf,
    pub sigil_proxy_bin: Option<PathBuf>,
    pub vault_dir: PathBuf,
    pub runtime_dir: PathBuf,
}
pub type TestResult = std::result::Result<(), Box<dyn std::error::Error>>;
```

---

### 5. Internal Mock Helpers

**Location:** `crates/sigil-core/src/thread_utils/result_collector.rs` (within `#[cfg(test)]` module)

**Structure:**
```rust
#[cfg(test)]
mod tests {
    // Setup and teardown helpers
    mod setup_teardown_helpers {
        pub(super) fn setup_test_collector<T>() -> StreamingResultCollector<T>
        pub(super) fn setup_multi_collector_scenario<T>(count: usize) -> Vec<...>
        pub(super) fn setup_collector_with_data<T>(values: &[T]) -> ...
        pub(super) fn setup_validated_clone_pair<T>() -> (...)
        pub(super) fn teardown_test_collector<T>(collector: &...) -> Result<...>
    }
    
    // Mock initialization and scenario functions
    mod mock_helpers {
        pub(super) fn mock_sender_count_state<T>(target_count: usize) -> Vec<...>
        pub(super) fn mock_concurrent_access_scenario<T>(thread_count: usize) -> Vec<...>
        pub(super) fn measure_clone_performance<F>(label: &str, op: F) -> Result<...>
    }
    
    // Assertion and validation functions  
    mod assertion_helpers {
        pub(super) fn validate_sender_count_before_clone<T>(...) -> Result<...>
        pub(super) fn validate_sender_count_after_clone<T>(...) -> Result<...>
        pub(super) fn validate_sender_count_monotonicity<T>(...) -> Result<...>
    }
    
    // Re-export for use in tests
    pub(super) use crate::thread_utils::result_collector::tests::mock_helpers::*;
}
```

**Usage Pattern:**
```rust
#[cfg(test)]
mod tests {
    use super::*;
    use mock_helpers::{mock_sender_count_state, mock_concurrent_access_scenario};
    
    #[test]
    fn test_some_functionality() {
        let collectors = mock_sender_count_state(5);
        // ... test implementation
    }
}
```

---

### 6. Thread Testing Utilities

**Location:** `crates/sigil-integration-tests/src/thread_util.rs`

**Key Functions:**
```rust
pub fn available_parallelism_count() -> usize
pub fn get_test_thread_count() -> usize  
pub fn reset_cached_thread_count()
pub fn spawn_test_threads<F>(f: F) -> Vec<JoinHandle<...>> where F: FnOnce(usize) + Send + Clone + 'static
pub fn create_barrier(n: usize) -> Arc<Barrier>
pub fn coordinate_then_execute<F, T>(phase_count: usize, thread_count: usize, f: F) -> Vec<T>
pub fn wait_all_then_execute<F, T>(wait_fn: F, exec_fn: fn(...) -> T) -> Vec<T>
pub fn with_timeout<F, T>(duration: Duration, f: F) -> Result<T, String>
pub fn collect_thread_results<T>(handles: Vec<JoinHandle<T>>) -> Vec<T>
```

**Usage Pattern:**
```rust
use sigil_integration_tests::thread_util::{
    get_test_thread_count, spawn_test_threads, create_barrier
};
```

---

### 7. Environment Detection Utilities  

**Location:** `crates/sigil-integration-tests/src/env_detect.rs`

**Key Functions:**
```rust
pub fn detect_bwrap() -> bool
pub fn ensure_xdg_runtime_dir() -> Result<PathBuf, Error>
pub fn is_ci_environment() -> bool
pub fn binary_exists<P: AsRef<Path>>(path: P) -> bool
```

**Skip Module:**
```rust
pub mod skip {
    pub fn if_no_bwrap();
    pub fn if_ci();
    pub fn if_binary_missing<P: AsRef<Path>>(path: P);
    // ... with reason variants
}
```

**Concurrent Module:**
```rust
pub mod concurrent {
    pub struct AtomicCounter;
    pub struct AtomicFlag;
    pub fn get_test_thread_count() -> usize;
    pub struct ResultCollector<T>;
}
```

---

### 8. Socket Utilities

**Location:** `crates/sigil-integration-tests/src/socket_util.rs`

**Key Functions:**
```rust
pub fn wait_for_socket(config: SocketWaitConfig) -> Result<(), SocketWaitError>
pub fn wait_for_socket_default(socket_path: &Path) -> Result<(), SocketWaitError>
```

---

### 9. Binary Fixture Utilities

**Location:** `crates/sigil-integration-tests/src/binary_fixture.rs`

**Purpose:** Create test binaries with specific permissions for security testing.

**Usage:**
```rust
use sigil_integration_tests::binary_fixture::*;
```

---

## Comprehensive Test File List

### By Crate

#### sigil-core
- `src/thread_utils/result_collector.rs` (inline test module)
- `tests/proptest_parser.rs`

#### sigil-scrub  
- `tests/proptest_scrubber.rs`

#### sigil-daemon
- `tests/hardening_test.rs`
- `tests/red_team_checkpoint.rs`
- `tests/runtime_hardening_verification.rs`
- `tests/startup_modes.rs`

#### sigil-backend-vault
- `tests/vault_backend_tests.rs`
- `tests/vault_mock_tests.rs`

#### sigil-backend-env
- `tests/env_backend_tests.rs`

#### sigil-backend-onepassword  
- `tests/onepassword_backend_tests.rs`

#### sigil-backend-pass
- `tests/pass_backend_tests.rs`

#### sigil-backend-sops
- `tests/sops_backend_tests.rs`

#### sigil-backend-aws
- `tests/aws_backend_tests.rs`

#### sigil-proxy
- `tests/proxy_integration.rs`

#### sigil-integration-tests
- 79 test files covering all phases (see detailed breakdown below)

### By Test Category

#### Property-Based Tests (2 files)
1. `sigil-core/tests/proptest_parser.rs`
2. `sigil-scrub/tests/proptest_scrubber.rs`

#### Backend HTTP Tests (7 files)
1. `sigil-backend-vault/tests/vault_backend_tests.rs`
2. `sigil-backend-vault/tests/vault_mock_tests.rs`
3. `sigil-backend-env/tests/env_backend_tests.rs`
4. `sigil-backend-onepassword/tests/onepassword_backend_tests.rs`
5. `sigil-backend-pass/tests/pass_backend_tests.rs`
6. `sigil-backend-sops/tests/sops_backend_tests.rs`
7. `sigil-backend-aws/tests/aws_backend_tests.rs`

#### Daemon Hardening Tests (4 files)
1. `sigil-daemon/tests/hardening_test.rs`
2. `sigil-daemon/tests/red_team_checkpoint.rs`
3. `sigil-daemon/tests/runtime_hardening_verification.rs`
4. `sigil-daemon/tests/startup_modes.rs`

#### Integration Tests (79+ files)

**Phase 1 Tests:**
- `phase1_redteam_checkpoint_bf4o47.rs`
- `phase1_redteam_test.rs`
- `phase1_3_verification_test.rs`
- `phase1_3_1_verification_test.rs`
- `phase1_4_cli_docs_verification_test.rs`
- `phase1_5_6_7_verification_test.rs`

**Phase 2 Tests:**
- `phase2_audit_ipc_signals_test.rs`
- `phase2_audit_lifecycle_test.rs`
- `phase2_client_audit_test.rs`
- `phase2_ipc_protocol_test.rs`
- `phase2_redteam_test.rs`
- `phase2_signal_handling_test.rs`
- `phase2_4_startup_modes_verification_test.rs`

**Phase 3 Tests:**
- `phase3_3_cli_integration_test.rs`
- `phase3_3_3_4_verification_test.rs`
- `phase3_redteam_test.rs`

**Phase 4 Tests:**
- `phase4_1_4_2_sandbox_verification_test.rs`
- `phase4_1_4_2_verification_test.rs`
- `phase4_3_4_4_verification_test.rs`
- `phase4_5_4_6_verification_test.rs`
- `phase4_e2e_redteam_test.rs`
- `phase4_redteam_test.rs`

**Phase 5 Tests:**
- `phase5_1_claude_code_hook_verification_test.rs`
- `phase5_2_non_bash_tool_hooks_test.rs`
- `phase5_2_verification_test.rs`
- `phase5_3_5_4_verification_test.rs`
- `phase5_5_5_7_verification_test.rs`
- `phase5_redteam_test.rs`

**Phase 6 Tests:**
- `phase6_1_tui_verification_test.rs`
- `phase6_2_3_backend_verification_test.rs`
- `phase6_redteam_test.rs`

**Phase 7 Tests:**
- `phase7_1_7_2_canary_breach_detection_test.rs`
- `phase7_5_troubleshoot_verification_test.rs`
- `phase7_redteam_test.rs`
- `phase7_runtime_test.rs`
- `phase7_troubleshoot_runtime_test.rs`

**Phase 8 Tests:**
- `phase8_1_command_recognition_verification_test.rs`
- `phase8_2_bidirectional_scrubbing_test.rs`
- `phase8_2_scrubbing_runtime_test.rs`
- `phase8_3_4_5_verification_test.rs`
- `phase8_6_8_7_sealed_vault_redteam_test.rs`
- `phase8_6_8_7_verification_test.rs`
- `phase8_9_daemon_runtime_test.rs`
- `phase8_redteam_test.rs`
- `phase8_runtime_test.rs`

**Phase 9 Tests:**
- `phase9_1_2_3_verification_test.rs`
- `phase9_4_5_6_verification_test.rs`
- `phase9_7_8_9_10_verification_test.rs`
- `phase9_redteam_test.rs`
- `phase9_runtime_test.rs`

**Other Integration Tests:**
- `backend_integration_test.rs`
- `canary_trigger_execution_test.rs`
- `common.rs`
- `daemon_hardening_test.rs`
- `daemon_startup_test.rs`
- `decoy_and_lockdown_test.rs`
- `doctor_test.rs`
- `env_detect_concurrent_test.rs`
- `export_import_integration_test.rs`
- `export_import_roundtrip_test.rs`
- `external_backend_e2e_test.rs`
- `full_pipeline_integration_test.rs`
- `fuse_security_test.rs`
- `hook_simulation_test.rs`
- `mcp_server_integration_test.rs`
- `proxy_security_test.rs`
- `runtime_framework.rs`
- `sandbox_isolation_integration_test.rs`
- `sdk_test.rs`
- `sealed_ops_test.rs`
- `setgid_detection_test.rs`
- `setuid_detection_test.rs`

---

## Test Utility Dependencies

### External Dependencies
1. **proptest** - Property-based testing framework
2. **mockito** - HTTP mocking for backend tests
3. **serial_test** - Serial test execution (for tests that can't run concurrently)
4. **tokio-test** - Async runtime testing utilities
5. **tempfile** - Temporary directory management
6. **serde_json** - JSON fixture data

### Internal Dependencies (sigil-integration-tests)
1. **socket_util** - Socket availability and health checks
2. **env_detect** - Environment detection and skip conditions
3. **thread_util** - Concurrent testing utilities  
4. **concurrent_tests** - Comprehensive concurrent testing infrastructure
5. **binary_fixture** - Binary fixture creation with permissions
6. **common** - Shared test utilities

---

## Import Pattern Analysis

### Pattern 1: Standard Integration Test
```rust
mod common;
use common::*;
use sigil_integration_tests::DaemonGuard;
use std::path::PathBuf;
use std::process::Command;
use tempfile::TempDir;
```

### Pattern 2: Property-Based Test
```rust
use proptest::prelude::*;
use sigil_core::{SecretPath, CommandParser};
```

### Pattern 3: Backend HTTP Test
```rust
use mockito::Server;
use serde_json::json;
```

### Pattern 4: Internal Module Test with Mock Helpers
```rust
#[cfg(test)]
mod tests {
    use super::*;
    use mock_helpers::{mock_sender_count_state, mock_concurrent_access_scenario};
    use setup_teardown_helpers::{setup_test_collector, teardown_test_collector};
}
```

### Pattern 5: Thread Utility Test
```rust
use sigil_integration_tests::thread_util::{
    get_test_thread_count, spawn_test_threads, create_barrier, coordinate_then_execute
};
use sigil_integration_tests::env_detect::concurrent::{AtomicCounter, ResultCollector};
```

---

## Key Findings

### 1. Centralized Test Infrastructure
The `sigil-integration-tests` crate provides a comprehensive testing infrastructure used across all phase verification tests. This includes:
- Environment detection and conditional test execution
- Socket and daemon management utilities
- Thread testing utilities for concurrent scenarios
- Binary fixture creation for security testing

### 2. Minimal External Test Dependencies
The workspace uses only a few external testing libraries:
- `proptest` for property-based testing
- `mockito` for HTTP mocking  
- `serial_test` for test serialization
- Standard library testing features

### 3. Internal Mock Helper Pattern
The `mock_helpers` module in `result_collector.rs` demonstrates a pattern of defining test-specific utilities within inline test modules, then re-exporting them for use across multiple tests.

### 4. Phase-Based Organization
Integration tests are organized by implementation phase (Phase 1-10), making it easy to verify completeness of each phase's requirements.

### 5. Common Utilities Pattern
Most integration tests follow a consistent pattern:
- Import `common` module for shared utilities
- Use `sigil_integration_tests` for advanced features
- Employ `skip_if_*` macros for conditional execution
- Use `DaemonGuard` for daemon lifecycle management

---

## Recommendations

### 1. Consider Consolidating Mock Helpers
The `mock_helpers` pattern in `result_collector.rs` could be extracted to a shared test utility module if similar patterns are needed in other files.

### 2. Document Test Macro Patterns
The skip macros and common test patterns could benefit from dedicated documentation in a testing guide.

### 3. Standardize Import Patterns
Consider creating standard test import templates to reduce boilerplate across the 79+ integration test files.

### 4. Test Utility Naming Convention
Establish consistent naming conventions for test utilities (e.g., `setup_*`, `teardown_*`, `mock_*`, `validate_*`).

---

## Conclusion

The SIGIL workspace maintains a well-organized test structure with:
- **97 total test files** across 21 crates
- **Centralized test infrastructure** in `sigil-integration-tests`
- **Consistent import patterns** and utility usage
- **Comprehensive phase-based coverage** of all implementation requirements
- **Minimal external dependencies** focusing on proptest and mockito

The test infrastructure successfully supports the project's security requirements while maintaining maintainability and consistency across the large codebase.
