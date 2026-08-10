# Test Utility Import Patterns

## Overview

This document describes the import patterns and dependencies across test files in the SIGIL workspace. It serves as a reference for understanding how test utilities are organized and used across different crates and test types.

## Test File Categories

### 1. Backend Integration Tests
- `sigil-backend-aws/tests/aws_backend_tests.rs`
- `sigil-backend-env/tests/env_backend_tests.rs`
- `sigil-backend-onepassword/tests/onepassword_backend_tests.rs`
- `sigil-backend-pass/tests/pass_backend_tests.rs`
- `sigil-backend-sops/tests/sops_backend_tests.rs`
- `sigil-backend-vault/tests/vault_backend_tests.rs`
- `sigil-backend-vault/tests/vault_mock_tests.rs`

### 2. Daemon Verification Tests
- `sigil-daemon/tests/hardening_test.rs`
- `sigil-daemon/tests/red_team_checkpoint.rs`
- `sigil-daemon/tests/runtime_hardening_verification.rs`
- `sigil-daemon/tests/startup_modes.rs`

### 3. Phase Verification Tests (sigil-integration-tests)
- Phase 1: `phase1_*` test files
- Phase 2: `phase2_*` test files
- Phase 3: `phase3_*` test files
- Phase 4: `phase4_*` test files
- Phase 5: `phase5_*` test files
- Phase 6: `phase6_*` test files
- Phase 7: `phase7_*` test files
- Phase 8: `phase8_*` test files
- Phase 9: `phase9_*` test files

### 4. Property-Based Tests
- `sigil-core/tests/proptest_parser.rs`
- `sigil-scrub/tests/proptest_scrubber.rs`

### 5. Integration Infrastructure
- `sigil-integration-tests/src/lib.rs`
- `sigil-integration-tests/src/common.rs`
- `sigil-integration-tests/src/binary_fixture.rs`
- `sigil-integration-tests/src/env_detect.rs`
- `sigil-integration-tests/src/socket_util.rs`
- `sigil-integration-tests/src/thread_util.rs`

## Import Pattern Categories

### Standard Library Imports (Consistent across most files)

```rust
// Filesystem operations
use std::fs;
use std::path::{Path, PathBuf};

// Time and environment  
use std::time::Duration;
use std::env;

// Threading and synchronization
use std::thread;

// Process management
use std::process::{Command, Stdio};

// Collections
use std::collections::{HashSet, HashMap};

// I/O operations
use std::io::Cursor;
```

### External Crate Imports (High consistency)

```rust
// Mocking framework - UNIVERSAL across backend tests
use mockito::{Server, Matcher}; // or mockito::Server

// Async testing - UNIVERSAL
#[tokio::test]

// JSON handling
use serde_json::json;

// Property testing
use proptest::prelude::*;

// Temp directories
use tempfile::TempDir;

// HTTP client (in some tests)
use reqwest::Client;
```

### Workspace Crate Imports (Pattern varies by crate type)

```rust
// Backend-specific imports
use sigil_backend_aws::{AwsBackend, AwsBackendConfig};
use sigil_backend_onepassword::{OnePasswordBackend, OnePasswordBackendConfig};
use sigil_backend_vault::{VaultAuth, VaultBackend, VaultBackendConfig, VaultToken};

// Core types - UNIVERSAL
use sigil_core::{SecretBackend, SecretMetadata, SecretPath, SecretType, SecretValue, SigilError};

// Daemon-specific
use sigil_daemon::ondemand::OnDemandCoordinator;
use sigil_integration_tests::DaemonGuard;
use sigil_core::ipc::{IpcError, IpcErrorCode, IpcOperation, IpcRequest, IpcResponse, SessionToken};
```

### Test-Specific Imports

```rust
// Common test helper pattern (found in multiple files)
fn create_test_metadata(path: &str) -> SecretMetadata {
    SecretMetadata {
        path: SecretPath::new(path.to_string()).unwrap(),
        secret_type: SecretType::Generic,
        tags: vec!["test".to_string()],
        notes: Some("Test secret".to_string()),
        created_at: chrono::Utc::now(),
        updated_at: chrono::Utc::now(),
        expires_at: None,
    }
}
```

## Shared Test Utilities

### Mock Server Pattern (Consistent across all backend tests)

```rust
#[tokio::test]
async fn test_operation() {
    let mut server = mockito::Server::new_async().await;
    
    let mock = server
        .mock("GET", "/v1/endpoint")
        .with_status(200)
        .with_body(r#"{"data": "value"}"#)
        .create_async().await;
        
    // Test code...
    mock.assert();
}
```

### Common Module Pattern (Integration tests)

```rust
mod common;
use common::workspace_root;
```

### Binary Fixture System (from `binary_fixture.rs`)

**Purpose:** Create temporary test binaries with specific permissions for security testing

**Key Fixtures:**
- `create_executable_binary(name, content)` - Regular executable (0o755)
- `create_setuid_binary(name, content)` - Setuid executable (0o4755)
- `create_setgid_binary(name, content)` - Setgid executable (0o2755)
- `create_setuid_setgid_binary(name, content)` - Both bits set (0o6755)

### Environment Detection (from `env_detect.rs`)

**Purpose:** Detect system capabilities and conditionally run tests

**Key Detection Functions:**
- `detect_bwrap()` - Check if bubblewrap is available
- `detect_systemd()` - Check for systemd socket activation
- `detect_launchd()` - Check for macOS launchd
- `detect_ci()` - Detect CI environment

### Common Test Utilities (from `common.rs`)

**Purpose:** Shared helper functions for all integration tests

**Key Functions:**
- `workspace_root()` - Navigate to project root
- `crate_source_path()` - Navigate to specific crate files
- `wait_for_socket()` - Poll for socket file appearance
- `wait_for_daemon_ready()` - Verify daemon accepting connections
- `daemon_health_check()` - Comprehensive health validation
- `ensure_xdg_runtime_dir()` - Set up XDG runtime directory
- `create_test_runtime_dir()` - Create isolated test directory

## Utility Usage Matrix

<!-- To be populated by agent analysis -->

## Inconsistencies and Anomalies

### INCONSISTENCY: Chrono Imports

```rust
// Some files use explicit chrono import
use chrono::Utc; // vault_backend_tests.rs

// Others use chrono::Utc directly in code
let created_at = chrono::Utc::now(); // multiple files
```

**Impact:** Medium - Creates inconsistent import patterns across codebase

### INCONSISTENCY: Base64 Imports

```rust
// AWS backend uses Engine trait
use base64::Engine;

// Integration tests use prelude
use base64::prelude::*;
```

**Impact:** Medium - Makes code harder to maintain and understand

### INCONSISTENCY: Mockito Imports

```rust
// Most files use Server only
use mockito::Server;

// Some use both
use mockito::{Server, Matcher};

// Vault tests use Matcher only
use mockito::Matcher;
```

**Impact:** Low - Functional but inconsistent

### PATTERN: Placeholder Files (ENV/Pass/SOPS backends)

```rust
// These files have NO imports - just empty test scaffolds
// - env_backend_tests.rs
// - pass_backend_tests.rs  
// - sops_backend_tests.rs
```

**Impact:** Low - Incomplete test implementations

### UNUSUAL: Direct File Reading in Tests (Daemon/Integration tests)

```rust
// Many daemon/integration tests read source files directly
let vault_code = fs::read_to_string(&vault_path).expect("Failed to read vault code");

// This is used for code verification rather than runtime testing
assert!(vault_code.contains("age") || vault_code.contains("rage"));
```

**Impact:** Medium - Unusual pattern for testing implementation rather than behavior

### INCONSISTENCY: SessionToken Imports

```rust
// Some files import from sigil_core::ipc
use sigil_core::ipc::SessionToken;

// Others import from sigil_core
use sigil_core::SessionToken;
```

**Impact:** Low - Works but inconsistent paths

## Recommendations

### HIGH PRIORITY

1. **Standardize Test Helper Module**
   - Create `crates/sigil-core/tests/common/mod.rs` with shared helpers
   - Include: `create_test_metadata()`, `create_test_config()`, `setup_test_dirs()`
   - Import pattern: `use sigil_core::test_helpers::*;`

2. **Unify Chrono Import**
   ```rust
   // Recommended standard
   use chrono::Utc;
   
   // Then use: Utc::now() consistently
   ```

3. **Standardize Mockito Import**
   ```rust
   // Recommended for all backend tests
   use mockito::{Server, Matcher};
   ```

4. **Standardize SessionToken Import**
   ```rust
   // Always use full path
   use sigil_core::ipc::SessionToken;
   ```

### MEDIUM PRIORITY

5. **Create Test Configuration Builder Pattern**
   ```rust
   use sigil_test::TestConfigBuilder;
   
   let config = TestConfigBuilder::new()
       .with_cache_ttl(Duration::from_secs(60))
       .with_mount("secret".to_string())
       .build();
   ```

6. **Standardize Error Message Testing**
   ```rust
   // Create helper in test module
   fn assert_io_error_with_message(result: Result<T>, msg_contains: &str) {
       match result {
           Err(SigilError::IoError(msg)) => {
               assert!(msg.contains(msg_contains));
           }
           _ => panic!("Expected IoError containing: {}", msg_contains),
       }
   }
   ```

7. **Unify Base64 Import**
   ```rust
   // Standardize across all files
   use base64::prelude::BASE64_STANDARD;
   ```

### LOW PRIORITY

8. **Consider Test Factory Pattern**
   ```rust
   use sigil_test::factory::{TestBackend, TestSecret, TestMetadata};
   
   let backend = TestBackend::aws().with_cache(false).build();
   let secret = TestSecret::with_value(b"test-value");
   ```

9. **Standardize Test Constants**
   ```rust
   // Create common test constants module
   pub const TEST_TIMEOUT: Duration = Duration::from_secs(5);
   pub const DEFAULT_CACHE_TTL: Duration = Duration::from_secs(300);
   ```

### File-Specific Recommendations

#### Backend Tests (AWS, Vault, OnePassword)
- ✅ Already well-standardized with mockito pattern
- ✅ Consistent use of helper functions
- ⚠️ Consider extracting common helpers to shared module

#### Daemon Tests 
- ⚠️ Heavy use of file reading for code verification is unusual
- ✅ Good use of platform-specific tests (`#[cfg(target_os = "linux")]`)
- 💡 Consider refactoring file reading tests into separate "code audit" test module

#### Integration Tests
- ✅ Good common module pattern
- ⚠️ Some files import `common` differently
- 💡 Standardize on: `mod common; use common::*;`

#### Property Tests
- ✅ Excellent consistency with `proptest::prelude::*`
- ✅ Good use of property-based testing patterns
- ✅ Clear test naming convention: `prop_*`
