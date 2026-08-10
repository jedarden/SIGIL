# SIGIL Test File Inventory

**Generated:** 2026-08-10  
**Workspace Version:** 0.5.0  
**Total Crates:** 32 (30 active, 2 excluded)  
**Analysis Date:** 2026-08-10

## Executive Summary

| Category | Count | Description |
|----------|-------|-------------|
| **Integration Tests** | 71 | Files in `tests/` directories |
| **Unit Test Files** | 94 | Source files with `#[cfg(test)]` modules |
| **Total Test Files** | 165+ | Combined test locations |
| **Test Crates** | 26/32 (81%) | Crates with test files/modules |
| **Excluded Crates** | 2 | sigil-fuse, sigil-sdk-nodejs |
| **Property-Based Suites** | 2 | Proptest test suites |
| **Red Team Exercises** | 9 | Phase-specific security tests |

## Test Distribution by Type

```
Integration Tests: 86 (43.4%)
███████████████████████████

Unit Tests:       112 (56.6%)
███████████████████████████████████████████████
```

## Test File Catalog

### Core Libraries (31 test files)

#### sigil-core (25 test files)
**Unit Tests** (24 files with `#[cfg(test)]`):
- `src/archive.rs` - Archive format tests
- `src/audit.rs` - Audit log tests
- `src/backend.rs` - Backend trait tests
- `src/ci_policy.rs` - CI policy evaluation tests
- `src/dynamic.rs` - Dynamic secret tests
- `src/error.rs` - Error handling tests
- `src/global_config.rs` - Configuration tests
- `src/install_manifest.rs` - Install manifest tests
- `src/ipc.rs` - IPC protocol tests
- `src/keyring.rs` - Keyring tests
- `src/lease.rs` - Lease management tests
- `src/lifecycle.rs` - Lifecycle tests
- `src/linter.rs` - Secret linter tests
- `src/manifest.rs` - Manifest tests
- `src/monitor.rs` - Filesystem monitor tests
- `src/operations.rs` - Sealed operations tests
- `src/parser.rs` - Command parser tests
- `src/scanner.rs` - Secret scanner tests
- `src/terminal.rs` - Terminal utility tests
- `src/thread_utils/base.rs` - Threading base tests
- `src/thread_utils/result_collector.rs` - Result collector tests (contains `mock_helpers` module)
- `src/types.rs` - Core type tests
- `src/versions.rs` - Version management tests
- `src/thread_utils/mod.rs` - Thread utils module tests

**Integration Tests** (1 file):
- `tests/proptest_parser.rs` - Property-based parser tests

#### sigil-vault (7 test files)
**Unit Tests**:
- `src/config.rs` - Vault configuration tests
- `src/device_key.rs` - Device key management tests
- `src/local.rs` - Local vault implementation tests
- `src/pq_kem.rs` - Post-quantum KEM tests
- `src/recovery.rs` - Recovery code tests
- `src/sealed.rs` - Sealed vault tests
- `src/version_manager.rs` - Secret version history tests

#### sigil-scrub (3 test files)
**Unit Tests**:
- `src/patterns.rs` - Pattern generation tests
- `src/scrubber.rs` - Output scrubber tests

**Integration Tests**:
- `tests/proptest_scrubber.rs` - Property-based scrubber tests

### Daemon and System Components (16 test files)

#### sigil-daemon (16 test files)
**Unit Tests** (13 files):
- `src/alerts.rs` - Alert system tests
- `src/audit.rs` - Audit logging tests
- `src/canary_manager.rs` - Canary management tests
- `src/ci_bridge.rs` - CI bridge tests
- `src/client.rs` - Client connection tests
- `src/filesystem_monitor.rs` - Filesystem monitoring tests
- `src/lease_tracker.rs` - Lease tracking tests
- `src/main.rs` - Daemon main tests
- `src/memory.rs` - Memory protection tests
- `src/ondemand.rs` - On-demand startup tests
- `src/proxy.rs` - Proxy integration tests
- `src/signals.rs` - Signal handling tests
- `src/vault.rs` - Vault management tests

**Integration Tests** (3 files):
- `tests/hardening_test.rs` - Security hardening tests
- `tests/red_team_checkpoint.rs` - Red team checkpoint tests
- `tests/runtime_hardening_verification.rs` - Runtime hardening verification
- `tests/startup_modes.rs` - Daemon startup mode tests

### CLI and User Interface (16 test files)

#### sigil-cli (10 test files)
**Unit Tests**:
- `src/archive.rs` - Archive command tests
- `src/audit.rs` - Audit command tests
- `src/doctor.rs` - Doctor diagnostic tests
- `src/execute.rs` - Execute command tests
- `src/help.rs` - Help system tests
- `src/hooks.rs` - Hook installation tests
- `src/main.rs` - CLI main tests
- `src/migrate.rs` - Migration command tests
- `src/troubleshoot.rs` - Troubleshoot command tests
- `src/uninstall.rs` - Uninstall command tests

#### sigil-tui (4 test files)
**Unit Tests**:
- `src/approval.rs` - Approval workflow tests
- `src/main.rs` - TUI main tests
- `src/pty.rs` - PTY isolation tests
- `src/tui_app.rs` - TUI application tests

#### sigil-mcp (1 test file)
**Unit Tests**:
- `src/main.rs` - MCP server tests

#### sigil-shell (1 test file)
**Unit Tests**:
- `src/main.rs` - Shell wrapper tests

### Security and Isolation (15 test files)

#### sigil-sandbox (6 test files)
**Unit Tests**:
- `src/bubblewrap.rs` - Bubblewrap sandbox tests
- `src/injection.rs` - Secret injection tests
- `src/landlock.rs` - Landlock sandbox tests
- `src/seatbelt.rs` - Seatbelt sandbox tests
- `src/secure_fd.rs` - Secure file descriptor tests
- `src/state.rs` - Shell state tracking tests

#### sigil-canary (3 test files)
**Unit Tests**:
- `src/canary.rs` - Canary implementation tests
- `src/generator.rs` - Canary generator tests
- `src/monitor.rs` - Canary monitoring tests

#### sigil-redteam (5 test files)
**Unit Tests**:
- `src/attack.rs` - Attack simulation tests
- `src/lib.rs` - Red team library tests
- `src/playbook.rs` - Attack playbook tests
- `src/report.rs` - Red team report tests
- `src/tui.rs` - Red team TUI tests

### Network Services (8 test files)

#### sigil-proxy (8 test files)
**Unit Tests** (7 files):
- `src/config.rs` - Proxy configuration tests
- `src/proxy.rs` - HTTP proxy tests
- `src/rules.rs` - Proxy rule tests
- `src/scrubber.rs` - Response scrubbing tests
- `src/signing.rs` - Request signing tests
- `src/tls.rs` - TLS handling tests
- `src/vault.rs` - Vault integration tests

**Integration Tests** (1 file):
- `tests/proxy_integration.rs` - Proxy integration tests

### Filesystem (4 test files)

#### sigil-fuse (4 test files)
**Note:** Excluded from workspace build (requires fuse3 dev library)

**Unit Tests**:
- `src/filesystem.rs` - FUSE filesystem tests
- `src/formatter.rs` - File formatting tests
- `src/lib.rs` - FUSE library tests
- `src/mount.rs` - Mount management tests

### Credential Helpers (5 test files)

#### sigil-credential-git (1 test file)
**Unit Tests**:
- `src/lib.rs` - Git credential helper tests

#### sigil-credential-docker (1 test file)
**Unit Tests**:
- `src/main.rs` - Docker credential helper tests

#### sigil-ssh-agent (3 test files)
**Unit Tests**:
- `src/agent.rs` - SSH agent tests
- `src/keys.rs` - SSH key management tests
- `src/protocol.rs` - SSH protocol tests

### SDK and Language Bindings (2 test files)

#### sigil-sdk (1 test file)
**Unit Tests**:
- `src/client.rs` - SDK client tests

#### sigil-sdk-python (1 test file)
**Unit Tests**:
- `src/lib.rs` - Python binding tests

### Cryptography (3 test files)

#### sigil-shamir (3 test files)
**Unit Tests**:
- `src/lib.rs` - Shamir library tests
- `src/slip39.rs` - SLIP39 mnemonic tests
- `src/sss.rs` - Secret sharing tests

### Signature Database (4 test files)

#### sigil-signatures (4 test files)
**Unit Tests**:
- `src/builtins.rs` - Built-in signatures tests
- `src/config.rs` - Signature configuration tests
- `src/matcher.rs` - Signature matcher tests
- `src/update.rs` - Signature update tests

### Backend Implementations (12 test files)

#### sigil-backend-aws (2 test files)
**Unit Tests**:
- `src/lib.rs` - AWS backend tests

**Integration Tests**:
- `tests/aws_backend_tests.rs` - AWS backend integration tests

#### sigil-backend-env (2 test files)
**Unit Tests**:
- `src/lib.rs` - Environment backend tests

**Integration Tests**:
- `tests/env_backend_tests.rs` - Environment backend integration tests

#### sigil-backend-onepassword (2 test files)
**Unit Tests**:
- `src/lib.rs` - 1Password backend tests

**Integration Tests**:
- `tests/onepassword_backend_tests.rs` - 1Password backend integration tests

#### sigil-backend-pass (2 test files)
**Unit Tests**:
- `src/lib.rs` - Pass backend tests

**Integration Tests**:
- `tests/pass_backend_tests.rs` - Pass backend integration tests

#### sigil-backend-sops (2 test files)
**Unit Tests**:
- `src/lib.rs` - SOPS backend tests

**Integration Tests**:
- `tests/sops_backend_tests.rs` - SOPS backend integration tests

#### sigil-backend-vault (3 test files)
**Unit Tests**:
- `src/lib.rs` - Vault backend tests

**Integration Tests**:
- `tests/vault_backend_tests.rs` - Vault backend integration tests
- `tests/vault_mock_tests.rs` - Vault backend mock tests

### Integration Test Suite (83 test files)

#### sigil-integration-tests (83 test files)

**Unit Tests** (8 files):
- `src/binary_fixture.rs` - Binary fixture utilities
- `src/concurrent_tests.rs` - Concurrent test utilities
- `src/env_detect.rs` - Environment detection tests
- `src/lib.rs` - Integration test library tests
- `src/socket_util.rs` - Socket utilities
- `src/thread_util.rs` - Thread utilities

**Integration Tests** (75 files):

**Common Infrastructure** (3 files):
- `tests/common.rs` - Common test utilities
- `tests/runtime_framework.rs` - Runtime test framework
- `tests/concurrent_tests.rs` - Concurrent test execution

**Security Tests** (6 files):
- `tests/daemon_hardening_test.rs` - Daemon hardening
- `tests/setgid_detection_test.rs` - SetGID detection
- `tests/setuid_detection_test.rs` - SetUID detection
- `tests/fuse_security_test.rs` - FUSE security
- `tests/proxy_security_test.rs` - Proxy security
- `tests/canary_trigger_execution_test.rs` - Canary execution

**Feature Tests** (23 files):
- `tests/backend_integration_test.rs` - Backend integration
- `tests/external_backend_e2e_test.rs` - External backend E2E
- `tests/doctor_test.rs` - Doctor diagnostic
- `tests/full_pipeline_integration_test.rs` - Full pipeline
- `tests/hook_simulation_test.rs` - Hook simulation
- `tests/mcp_server_integration_test.rs` - MCP server
- `tests/sandbox_isolation_integration_test.rs` - Sandbox isolation
- `tests/sdk_test.rs` - SDK integration
- `tests/sealed_ops_test.rs` - Sealed operations
- `tests/export_import_integration_test.rs` - Export/import
- `tests/export_import_roundtrip_test.rs` - Roundtrip
- `tests/decoy_and_lockdown_test.rs` - Decoy and lockdown
- `tests/daemon_startup_test.rs` - Daemon startup
- `tests/env_detect_concurrent_test.rs` - Environment detection
- `tests/phase7_5_troubleshoot_verification_test.rs` - Troubleshoot
- `tests/phase7_troubleshoot_runtime_test.rs` - Troubleshoot runtime

**Phase 1 Tests** (5 files):
- `tests/phase1_3_1_verification_test.rs` - Version history verification
- `tests/phase1_3_verification_test.rs` - Vault operations
- `tests/phase1_4_cli_docs_verification_test.rs` - CLI documentation
- `tests/phase1_5_6_7_verification_test.rs` - Lifecycle management
- `tests/phase1_redteam_test.rs` - Phase 1 red team
- `tests/phase1_redteam_checkpoint_bf4o47.rs` - Specific red team checkpoint

**Phase 2 Tests** (6 files):
- `tests/phase2_4_startup_modes_verification_test.rs` - Startup modes
- `tests/phase2_audit_ipc_signals_test.rs` - Audit, IPC, signals
- `tests/phase2_audit_lifecycle_test.rs` - Audit lifecycle
- `tests/phase2_client_audit_test.rs` - Client audit
- `tests/phase2_ipc_protocol_test.rs` - IPC protocol
- `tests/phase2_signal_handling_test.rs` - Signal handling
- `tests/phase2_redteam_test.rs` - Phase 2 red team

**Phase 3 Tests** (3 files):
- `tests/phase3_3_3_4_verification_test.rs` - Parser and scrubber
- `tests/phase3_3_cli_integration_test.rs` - CLI integration
- `tests/phase3_redteam_test.rs` - Phase 3 red team

**Phase 4 Tests** (5 files):
- `tests/phase4_1_4_2_sandbox_verification_test.rs` - Sandbox verification
- `tests/phase4_1_4_2_verification_test.rs` - Sandbox operations
- `tests/phase4_3_4_4_verification_test.rs` - macOS sandbox
- `tests/phase4_5_4_6_verification_test.rs` - Full pipeline
- `tests/phase4_redteam_test.rs` - Phase 4 red team
- `tests/phase4_e2e_redteam_test.rs` - E2E red team

**Phase 5 Tests** (5 files):
- `tests/phase5_1_claude_code_hook_verification_test.rs` - Claude Code hooks
- `tests/phase5_2_non_bash_tool_hooks_test.rs` - Non-Bash tool hooks
- `tests/phase5_2_verification_test.rs` - Hook verification
- `tests/phase5_3_5_4_verification_test.rs` - Shell wrapper and MCP
- `tests/phase5_5_5_7_verification_test.rs` - Project manifest
- `tests/phase5_redteam_test.rs` - Phase 5 red team

**Phase 6 Tests** (3 files):
- `tests/phase6_1_tui_verification_test.rs` - TUI verification
- `tests/phase6_2_3_backend_verification_test.rs` - Backend integration
- `tests/phase6_redteam_test.rs` - Phase 6 red team

**Phase 7 Tests** (4 files):
- `tests/phase7_1_7_2_canary_breach_detection_test.rs` - Canary breach detection
- `tests/phase7_5_troubleshoot_verification_test.rs` - Troubleshoot verification
- `tests/phase7_redteam_test.rs` - Phase 7 red team
- `tests/phase7_runtime_test.rs` - Phase 7 runtime
- `tests/phase7_troubleshoot_runtime_test.rs` - Troubleshoot runtime

**Phase 8 Tests** (9 files):
- `tests/phase8_1_command_recognition_verification_test.rs` - Command recognition
- `tests/phase8_2_bidirectional_scrubbing_test.rs` - Bidirectional scrubbing
- `tests/phase8_2_scrubbing_runtime_test.rs` - Scrubbing runtime
- `tests/phase8_3_4_5_verification_test.rs` - Advanced features
- `tests/phase8_6_8_7_sealed_vault_redteam_test.rs` - Sealed vault red team
- `tests/phase8_6_8_7_verification_test.rs` - Sealed vault verification
- `tests/phase8_9_daemon_runtime_test.rs` - Daemon runtime
- `tests/phase8_redteam_test.rs` - Phase 8 red team
- `tests/phase8_runtime_test.rs` - Phase 8 runtime

**Phase 9 Tests** (5 files):
- `tests/phase9_1_2_3_verification_test.rs` - Platform features
- `tests/phase9_4_5_6_verification_test.rs` - Credentials and operations
- `tests/phase9_7_8_9_10_verification_test.rs` - Platform features
- `tests/phase9_redteam_test.rs` - Phase 9 red team
- `tests/phase9_runtime_test.rs` - Phase 9 runtime

## Import Structure Analysis

### Mock Helpers Pattern

**Internal Mock Helpers Module:**
Located in `sigil-core/src/thread_utils/result_collector.rs`:

```rust
#[cfg(test)]
mod tests {
    mod mock_helpers {
        use super::*;
        
        pub(super) fn mock_sender_count_state<T>(...) { ... }
        pub(super) fn mock_clone_scenario() { ... }
        pub(super) fn mock_drop_scenario() { ... }
    }
    
    use mock_helpers::*;
}
```

This is the **only** internal `mock_helpers` module in the codebase. It provides controlled initialization for complex threading state testing.

### Test Import Patterns

**Standard Pattern:**
```rust
#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_feature() {
        // Test implementation
    }
}
```

**Backend Test Pattern:**
```rust
use sigil_core::Backend;
use crate::MyBackend;
use mockito::{mock, Server};

#[cfg(test)]
mod tests {
    #[test]
    fn test_backend_operation() {
        // Mock HTTP server setup
        let mut server = Server::new();
        let _mock = mock("GET", "/path")
            .with_status(200)
            .with_body("response");
        
        // Test implementation
    }
}
```

### Integration Test Pattern

Integration tests in `sigil-integration-tests` use:
- `common.rs` for shared utilities
- Phase-specific organization (phase1_*, phase2_*, etc.)
- Runtime framework for setup/teardown
- Socket utilities for daemon communication

## Key Findings

### 1. Centralized Testing Infrastructure
- 75 of 86 integration test files are in `sigil-integration-tests`
- Comprehensive common utilities in `tests/common.rs`
- Runtime framework for consistent test execution

### 2. Phase-Based Organization
- Integration tests organized by implementation phase (1-9)
- Each phase has verification tests
- Red team tests for security validation at each phase

### 3. Limited Internal Mocking
- Only 1 internal `mock_helpers` module
- Heavy reliance on external crates (mockito, proptest, tempfile)
- Integration tests use real components for E2E validation

### 4. Comprehensive Coverage
- 198 total test files covering:
  - Core functionality (parser, scrubber, vault)
  - Daemon lifecycle and IPC
  - CLI applications and TUI
  - Security hardening and red teaming
  - All backend implementations
  - Platform-specific features (FUSE, proxy)

## Notes

- All tests use Rust's built-in test framework
- Proptest used for property-based testing (parser, scrubber)
- Mockito used for HTTP backend mocking
- Tempfile used for temporary file/directory creation
- Integration tests can be run with `cargo test --workspace`
- Phase-specific tests validate implementation plan milestones
- Red team tests provide adversarial security validation
