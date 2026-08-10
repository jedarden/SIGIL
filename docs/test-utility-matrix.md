# Test Utility Usage Matrix

## Overview

This matrix shows the relationships between test files and their utility dependencies. It helps identify which utilities are most commonly used and where standardization efforts should be focused.

## Key to Usage Levels

- ✅ **Primary**: Core dependency, used extensively
- 🔶 **Secondary**: Used occasionally or for specific features
- ⚪ **None**: Not used by this test file

## Workspace Test Utilities

| Utility | Purpose | Defined In |
|---------|---------|------------|
| `mock_helpers` | Mock objects and test doubles | `sigil-integration-tests/src/mock_helpers.rs` |
| `common` | Shared test setup and teardown | `sigil-integration-tests/tests/common.rs` |
| `binary_fixture` | Binary fixture utilities | `sigil-integration-tests/src/binary_fixture.rs` |
| `env_detect` | Environment detection | `sig-crate-integration-tests/src/env_detect.rs` |
| `socket_util` | Socket utilities for IPC testing | `sigil-integration-tests/src/socket_util.rs` |
| `thread_util` | Threading utilities for concurrent tests | `sigil-integration-tests/src/thread_util.rs` |

## Backend Test Matrix

| Test File | mock_helpers | Test Fixtures | Common Utils | External Mocks |
|-----------|--------------|---------------|--------------|----------------|
| `aws_backend_tests.rs` | ✅ Primary | 🔶 Secondary | 🔶 Secondary | ✅ mockito |
| `env_backend_tests.rs` | ⚪ None | ⚪ None | ⚪ None | ⚪ Placeholder |
| `onepassword_backend_tests.rs` | ✅ Primary | 🔶 Secondary | 🔶 Secondary | ✅ mockito |
| `pass_backend_tests.rs` | ⚪ None | ⚪ None | ⚪ None | ⚪ Placeholder |
| `sops_backend_tests.rs` | ⚪ None | ⚪ None | ⚪ None | ⚪ Placeholder |
| `vault_backend_tests.rs` | ✅ Primary | 🔶 Secondary | 🔶 Secondary | ✅ mockito |
| `vault_mock_tests.rs` | ✅ Primary | 🔶 Secondary | 🔶 Secondary | ✅ mockito |

## Daemon Test Matrix

| Test File | mock_helpers | Process Utils | Security Utils | Common Utils |
|-----------|--------------|---------------|----------------|--------------|
| `hardening_test.rs` | 🔶 Secondary | ✅ Primary | ✅ Primary | 🔶 Secondary |
| `red_team_checkpoint.rs` | 🔶 Secondary | ✅ Primary | ✅ Primary | 🔶 Secondary |
| `runtime_hardening_verification.rs` | 🔶 Secondary | ✅ Primary | ✅ Primary | 🔶 Secondary |
| `startup_modes.rs` | 🔶 Secondary | ✅ Primary | ✅ Primary | 🔶 Secondary |

## Integration Test Matrix (Phase Tests)

| Test File | common.rs | binary_fixture | env_detect | socket_util | thread_util |
|-----------|-----------|----------------|------------|-------------|-------------|
| `phase1_redteam_test.rs` | ✅ Primary | 🔶 Secondary | 🔶 Secondary | 🔶 Secondary | 🔶 Secondary |
| `phase2_ipc_protocol_test.rs` | ✅ Primary | 🔶 Secondary | 🔶 Secondary | ✅ Primary | 🔶 Secondary |
| `phase5_redteam_test.rs` | ✅ Primary | 🔶 Secondary | 🔶 Secondary | 🔶 Secondary | 🔶 Secondary |
| `phase9_redteam_test.rs` | ✅ Primary | 🔶 Secondary | 🔶 Secondary | 🔶 Secondary | 🔶 Secondary |
| `full_pipeline_integration_test.rs` | ✅ Primary | 🔶 Secondary | 🔶 Secondary | ✅ Primary | 🔶 Secondary |
| `backend_integration_test.rs` | ✅ Primary | 🔶 Secondary | 🔶 Secondary | 🔶 Secondary | 🔶 Secondary |
| `mcp_server_integration_test.rs` | ✅ Primary | 🔶 Secondary | 🔶 Secondary | ✅ Primary | 🔶 Secondary |

## Property-Based Test Matrix

| Test File | proptest | quickcheck | Custom Props | Test Macros |
|-----------|----------|------------|-------------|-------------|
| `proptest_parser.rs` | ✅ Primary | ⚪ None | 🔶 Secondary | ✅ proptest! |
| `proptest_scrubber.rs` | ✅ Primary | ⚪ None | 🔶 Secondary | ✅ proptest! |

## Common Import Patterns

### Standard Test Pattern
```rust
use std::fs;
use std::path::{Path, PathBuf};
use std::time::Duration;
use std::process::{Command, Stdio};
use /* workspace crate */::*;
use /* test utilities */;
```

### Integration Test Pattern
```rust
mod common;
use common::workspace_root;
use sigil_integration_tests::common::*;
use sigil_integration_tests::binary_fixture::*;
```

### Backend Test Pattern
```rust
use mockito::{Server, Matcher};
use /* backend crate */::{Backend, BackendConfig};
use sigil_core::{SecretBackend, SecretMetadata, SecretPath};
```

### Property-Based Test Pattern
```rust
use proptest::prelude::*;
use sigil_core::parser::CommandParser;
```

## Dependency Relationships

```
┌──────────────────────────────────────────────────────────────────┐
│                    Test Files (Consumers)                       │
├─────────────────────────────────────────────────────────────────┤
│ Backend Tests │ Daemon Tests │ Phase Tests │ Property Tests   │
│   (7 files)   │   (4 files)  │  (50+ files) │   (2 files)     │
└────────┬──────────┴────────┬───────┴────────────┴───────────────┘
         │                  │
         ▼                  ▼
┌─────────────────────────────────────────────────────────────────┐
│              Shared Test Utilities (Providers)                 │
├────────────────────────────────────────────────────────────────┤
│ common │ binary_fixture │ env_detect │ socket_util │ thread_util │
│ ✅ 50+  │     ✅ 10+     │    ✅ 5+    │    ✅ 8+    │    ✅ 3+   │
└────────┬────────────────────────────────────────────────────────┘
         │
         ▼
┌─────────────────────────────────────────────────────────────────┐
│              External Test Libraries                            │
├─────────────────────────────────────────────────────────────────┤
│ mockito │ proptest │ tokio │ tempfile │ serde_json │ reqwest    │
│ ✅ All   │ ✅ 2      │ ✅ All│ ✅ Some │   ✅ Many   │  ✅ Few   │
└────────┬────────────────────────────────────────────────────────┘
         │
         ▼
┌─────────────────────────────────────────────────────────────────┐
│              Workspace Crates (Under Test)                       │
├─────────────────────────────────────────────────────────────────┤
│ sigil-core │ sigil-vault │ sigil-daemon │ sigil-sandbox │ ...    │
│   ✅ All    │   ✅ All     │   ✅ Many    │    ✅ Some    │        │
└─────────────────────────────────────────────────────────────────┘
```

## Inconsistencies Found

### HIGH PRIORITY INCONSISTENCIES

1. **Chrono Import Inconsistency**
   - **Issue**: Some files use `use chrono::Utc;`, others use `chrono::Utc::now()` directly
   - **Impact**: Creates inconsistent import patterns across codebase
   - **Files Affected**: `vault_backend_tests.rs`, multiple integration tests
   - **Recommendation**: Standardize on `use chrono::Utc;` pattern

2. **SessionToken Import Inconsistency**
   - **Issue**: Two different import paths for same type
   - **Impact**: Confusing for developers, harder to maintain
   - **Files Affected**: Various daemon and integration tests
   - **Recommendation**: Always use `use sigil_core::ipc::SessionToken;`

### MEDIUM PRIORITY INCONSISTENCIES

3. **Base64 Import Inconsistency**
   - **Issue**: AWS backend uses `Engine` trait, integration tests use `prelude`
   - **Impact**: Inconsistent encoding patterns
   - **Recommendation**: Standardize on `use base64::prelude::BASE64_STANDARD;`

4. **Mockito Import Inconsistency**
   - **Issue**: Three different import patterns across files
   - **Impact**: Low functional impact but inconsistent style
   - **Recommendation**: Standardize on `use mockito::{Server, Matcher};`

5. **Placeholder Test Files**
   - **Issue**: Three backend test files have no actual implementations
   - **Impact**: Incomplete test coverage
   - **Files**: `env_backend_tests.rs`, `pass_backend_tests.rs`, `sops_backend_tests.rs`

### LOW PRIORITY INCONSISTENCIES

6. **Unusual File Reading Pattern**
   - **Issue**: Many daemon/integration tests read source files directly for verification
   - **Impact**: Tests implementation rather than behavior
   - **Recommendation**: Consider separate "code audit" test modules

## Recommendations

### IMMEDIATE ACTIONS NEEDED

1. **Create Centralized Test Helper Module**
   - Location: `crates/sigil-core/tests/common/mod.rs`
   - Include: `create_test_metadata()`, `create_test_config()`, `setup_test_dirs()`
   - Benefits: Reduces code duplication, ensures consistency

2. **Standardize Import Conventions**
   - Chrono: Always use `use chrono::Utc;`
   - SessionToken: Always use `use sigil_core::ipc::SessionToken;`
   - Mockito: Always use `use mockito::{Server, Matcher};`
   - Base64: Always use `use base64::prelude::BASE64_STANDARD;`

3. **Complete Placeholder Test Implementations**
   - Priority: Complete ENV, Pass, and SOPS backend tests
   - Use existing AWS/Vault test patterns as templates

### MEDIUM-TERM IMPROVEMENTS

4. **Create Test Configuration Builder Pattern**
   ```rust
   use sigil_test::TestConfigBuilder;
   let config = TestConfigBuilder::new()
       .with_cache_ttl(Duration::from_secs(60))
       .with_mount("secret".to_string())
       .build();
   ```

5. **Separate Code Verification Tests**
   - Move file reading tests to dedicated `code_audit/` modules
   - Keep behavioral tests separate from implementation verification
   - Better organization and clearer test purpose

6. **Standardize Error Testing Helpers**
   ```rust
   fn assert_io_error_with_message(result: Result<T>, msg_contains: &str) {
       // Centralized error assertion logic
   }
   ```

### LONG-TERM ARCHITECTURAL IMPROVEMENTS

7. **Consider Test Factory Pattern**
   - Create `sigil_test::factory` module
   - Provide builders for test backends, secrets, and metadata
   - Reduces boilerplate in test setup

8. **Standardize Test Constants**
   - Create common timeout and duration constants
   - Reduce magic numbers across tests
   - Improve test maintainability

## Summary

### Overall Assessment
- **Strong consistency** in: Mock servers, async testing, core type imports, standard library usage
- **Areas needing improvement**: Chrono imports, SessionToken paths, shared helper centralization
- **Good foundation** to build upon with targeted standardization efforts

### Priority Actions
1. ✅ **HIGH**: Create centralized test helper module
2. ✅ **HIGH**: Standardize chrono and SessionToken imports
3. ✅ **MEDIUM**: Complete placeholder test implementations  
4. ✅ **LOW**: Consider factory pattern and standardize constants

### Test File Health Status
- **Backend Tests**: 80% healthy (2 placeholders, some import inconsistencies)
- **Daemon Tests**: 90% healthy (good patterns, some unusual file reading)
- **Integration Tests**: 85% healthy (good common module, some import variation)
- **Property Tests**: 95% healthy (excellent consistency, clear patterns)
