# SIGIL Test Failure Report
Generated: 2026-07-13

## Summary

After running the full test suite (`cargo test --all-targets`), the following failures were identified:

### Test Results Overview

**Total Tests Run:** 300+ tests across all crates
**Total Failed Tests:** 0 (all unit tests pass)
**Benchmark Panics:** 1

## All Unit Tests: PASSING ✅

All unit tests across all crates pass successfully:

- sigil-core: All tests pass
- sigil-vault: All tests pass
- sigil-daemon: All tests pass
- sigil-cli: All tests pass
- sigil-sandbox: All tests pass
- sigil-scrub: All tests pass
- sigil-tui: All tests pass
- sigil-mcp: All tests pass
- sigil-shell: All tests pass
- sigil-proxy: All tests pass
- sigil-sdk: All tests pass
- sigil-signatures: All tests pass
- All backend crates (aws, env, onepassword, pass, sops, vault): All tests pass

## Receiver-Related Tests

The following receiver-related tests exist and **ALL PASS**:

### 1. sigil-daemon/src/signals.rs
- `test_multiple_receivers` (line 266) - ✅ PASSES

### 2. sigil-core/src/thread_utils/result_collector.rs
- `test_streaming_collector_stream_add_receiver_dropped` (line 1423) - ✅ PASSES
- `test_streaming_collector_no_receiver_after_clone` (line 1745) - ✅ PASSES
- `test_streaming_collector_graceful_shutdown_no_receiver` (line 2180) - ✅ PASSES

### 3. sigil-core/src/thread_utils/base.rs
- `test_streaming_collector_stream_collect_timeout_no_receiver` (line 3003) - ✅ PASSES
- `test_streaming_collector_stream_collect_receiver_already_taken` (line 3314) - ✅ PASSES

## Benchmark Failure: CRITICAL ❌

### File: `benches/ipc_bench.rs`

**Error:** Duplicate benchmark ID causing panic

```
thread 'main' (792073) panicked at /home/coding/.cargo/registry/src/index.crates.io-1949cf8c6b5b557f/criterion-0.5.1/src/benchmark_group.rs:291:9:
Benchmark IDs must be unique within a group. Encountered duplicated benchmark ID ipc_session_token/valid_base64/28
```

**Location:** `benches/ipc_bench.rs`

**Impact:** This panic prevents the benchmark suite from completing successfully.

## Compiler Warnings

The following warnings are present (non-blocking):

### sigil-core/src/thread_utils/base.rs
- Line 17: Unused import: `Instant`
- Line 25: Missing documentation for struct field `TooManyThreads.requested`
- Line 25: Missing documentation for struct field `TooManyThreads.available`

### sigil-integration-tests
- Multiple warnings about unused functions and variables
- Ambiguous glob import warnings for `get_test_thread_count`

## Raw Test Logs

Full test output saved to: `/tmp/sigil-test-full.log`

## Conclusion

**No receiver tests are failing.** All receiver-related unit tests pass successfully. The only failure is a duplicate benchmark ID in the IPC benchmark suite, which is unrelated to receiver functionality.

### Recommendations

1. Fix the duplicate benchmark ID in `benches/ipc_bench.rs`
2. Clean up compiler warnings (unused imports, missing docs)
3. All receiver functionality appears to be working correctly based on test coverage
