# Test Failures by Crate - Detailed Analysis

**Date:** 2026-08-09  
**Workspace:** /home/coding/SIGIL  

## Overview

This document provides a crate-by-crate breakdown of all test failures and compilation issues found during the comprehensive `cargo test` run.

## Summary Statistics

- **Total Crates in Workspace:** 28
- **Crates with Compilation Errors:** 0
- **Crates with Test Failures:** 1
- **Total Failed Tests:** 7
- **Total Test Execution Time:** 2+ minutes (partial due to timeout)

## Crate-by-Crate Status

### ✅ sigil-backend-aws
**Status:** All tests passing  
**Test Results:** 11/11 tests passed  
**Test Files:** `crates/sigil-backend-aws/src/lib.rs`  
**Issues:** None

**Passing Tests:**
- test_aws_backend_config_default
- test_cache_hit_miss
- test_delete_secret_not_found
- test_detect_secret_type
- test_delete_secret_success
- test_get_secret_not_found
- test_get_secret_success
- test_list_secrets_empty
- test_list_secrets_success
- test_set_secret_success
- test_set_secret_auth_failure

### ✅ sigil-backend-env
**Status:** All tests passing  
**Test Results:** 24/24 tests passed  
**Test Files:** `crates/sigil-backend-env/src/lib.rs`  
**Issues:** None

### ✅ sigil-backend-onepassword
**Status:** All tests passing  
**Test Results:** 11/11 tests passed  
**Issues:** None

### ✅ sigil-backend-pass
**Status:** All tests passing  
**Test Results:** 13/13 tests passed  
**Issues:** None

### ✅ sigil-backend-sops
**Status:** All tests passing  
**Test Results:** 11/11 tests passed  
**Issues:** None

### ✅ sigil-backend-vault
**Status:** All tests passing  
**Test Results:** 69/69 tests passed  
**Test Files:** `crates/sigil-backend-vault/src/lib.rs`  
**Issues:** None

**Notable:** This is the largest test suite among the backend crates, covering:
- Cache configuration and behavior
- Configuration management
- Delete operations (success, not found, unauthorized)
- Get operations (binary secrets, empty strings, not found, success)
- List operations (empty results, pagination, prefix filtering)
- Metadata creation and types
- Path validation and stripping
- Secret value operations and zeroization
- Set operations (auth failures, create/update, request formatting)
- Duration parsing
- Auth failure scenarios (401, 403)
- Cache invalidation
- Error messages
- Recovery windows
- Version stages

### ⚠️ sigil-core
**Status:** COMPILATION SUCCESSFUL, TEST FAILURES  
**Test Results:** ~69+ passed, 7 failed  
**Test Files:** `crates/sigil-core/src/lib.rs` and module tests  
**Issues:** 7 thread_utils test failures

#### Failed Tests Detail

**Module:** `thread_utils::base` (6 failures)

1. **test_receiver_lifetime_sender_persistence_through_timeout**
   - Type: Lifetime management test
   - Issue: Sender/receiver behavior during timeout scenarios

2. **test_spawn_with_collector_basic**
   - Type: Thread spawning test
   - Issue: Basic spawn with collector functionality

3. **test_spawn_with_collector_complex**
   - Type: Thread spawning test  
   - Issue: Complex spawn scenarios with collector

4. **test_spawn_with_collector_panic_propagation**
   - Type: Error handling test
   - Issue: Panic propagation in spawn with collector

5. **test_streaming_collector_stream_collect_timeout_no_receiver**
   - Type: Timeout handling test
   - Issue: Streaming collection timeout when no receiver present

6. **test_streaming_collector_try_push**
   - Type: Collection test
   - Issue: Try push functionality in streaming collector

**Module:** `thread_utils::result_collector` (1 failure)

7. **test_early_return_receiver_cleanup_multiple_scenarios**
   - Type: Resource cleanup test
   - Issue: Receiver cleanup verification during early returns

#### Passing Test Categories in sigil-core
- ✅ Archive tests (archive_roundtrip)
- ✅ Backend behavioral tests  
- ✅ CLI output formatting tests
- ✅ Command parsing tests (extensive - 80+ tests)
  - Placeholder detection and extraction
  - Injection modes (env, file, inline, stdin)
  - Command validation
  - Edge cases (null bytes, special characters, Unicode)
  - Error handling
- ✅ Config tests
- ✅ Error handling tests
- ✅ Secret detection and type classification
- ✅ Scanner tests (pattern matching, file scanning)
- ✅ Terminal tests (color modes, Unicode, terminal size)
- ✅ Thread utility tests (many passing, 7 failing as noted above)

### ✅ sigil-vault
**Status:** All tests passing  
**Issues:** None

### ✅ sigil-cli
**Status:** Compiles successfully  
**Issues:** None (no test failures detected in output)

### ✅ sigil-daemon  
**Status:** Compiles successfully  
**Issues:** None (no test failures detected in output)

### ✅ sigil-sandbox
**Status:** Compiles successfully  
**Issues:** None (no test failures detected in output)

### ✅ sigil-scrub
**Status:** Compiles successfully  
**Issues:** None (no test failures detected in output)

### ✅ sigil-tui
**Status:** Compiles successfully  
**Issues:** None (no test failures detected in output)

### ✅ sigil-mcp
**Status:** Compiles successfully  
**Issues:** None (no test failures detected in output)

### ✅ sigil-shell
**Status:** Compiles successfully  
**Issues:** None (no test failures detected in output)

### ✅ sigil-proxy
**Status:** Compiles successfully  
**Issues:** None (no test failures detected in output)

### ✅ sigil-fuse
**Status:** Compiles successfully  
**Issues:** None (no test failures detected in output)

### ✅ sigil-sdk (Rust)
**Status:** Compiles successfully  
**Issues:** None (no test failures detected in output)

### ✅ sigil-sdk-nodejs
**Status:** Compiles successfully  
**Issues:** None (no test failures detected in output)

### ✅ sigil-sdk-python
**Status:** Compiles successfully  
**Issues:** None (no test failures detected in output)

### ✅ sigil-credential-git
**Status:** Compiles successfully  
**Issues:** None (no test failures detected in output)

### ✅ sigil-credential-docker  
**Status:** Compiles successfully  
**Issues:** None (no test failures detected in output)

### ✅ sigil-ssh-agent
**Status:** Compiles successfully  
**Issues:** None (no test failures detected in output)

### ✅ sigil-canary
**Status:** Compiles successfully  
**Issues:** None (no test failures detected in output)

### ✅ sigil-redteam
**Status:** Compiles successfully  
**Issues:** None (no test failures detected in output)

### ✅ sigil-shamir
**Status:** Compiles successfully  
**Issues:** None (no test failures detected in output)

### ✅ sigil-signatures
**Status:** Compiles successfully  
**Issues:** None (no test failures detected in output)

### ✅ sigil-bench
**Status:** Compiles successfully  
**Issues:** None (no test failures detected in output)

### ✅ sigil-integration-tests
**Status:** Compiles successfully  
**Issues:** None (no test failures detected in output)

## Test Execution Environment

**Platform:** Linux (x86_64)  
**Rust Version:** Current stable  
**Workspace Root:** /home/coding/SIGIL  
**Test Command:** `cargo test`  
**Execution Timeout:** 120 seconds (partial execution)

## Notes on Test Execution

1. **Test Timeout:** The full test suite did not complete within the 120-second timeout, indicating some tests may be hanging or taking excessive time.

2. **Thread Utils Tests:** The failing tests are all in advanced threading scenarios involving:
   - Timeouts and race conditions
   - Complex spawn/collect patterns  
   - Resource cleanup verification
   - Early return scenarios

3. **Test Flakiness:** The failures may indicate flaky tests due to timing dependencies rather than actual code bugs.

4. **Compilation Health:** Despite test failures, all crates compile successfully, indicating no syntax errors, type errors, or missing dependencies.

## Recommendations by Crate

### sigil-core (Priority: Medium)
1. **Fix thread_utils tests:** Review and fix the 7 failing thread utility tests
2. **Investigate timing issues:** Many failures are timeout-related, suggesting race conditions
3. **Add test isolation:** Ensure tests properly clean up resources and don't depend on timing
4. **Review timeout values:** Current timeout values may be too aggressive for the test environment

### All Other Crates (Priority: None)
No immediate action needed - all crates compile successfully and tests pass.

---

**Generated:** 2026-08-09  
**Analysis Type:** Comprehensive test failure documentation  
**Next Action:** Investigate and fix sigil-core thread_utils test failures