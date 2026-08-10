
# SIGIL-Core Test Results Analysis

## Summary Statistics
- **Total Tests**: 478
- **Passed**: 468 (97.9%)
- **Failed**: 8 (1.7%)
- **Ignored**: 2 (0.4%)
- **Timeouts**: 2

## Test Success Rate: 98.3%

## Failed Tests (8)

### thread_utils (8 tests)
- `thread_utils::base::tests::test_receiver_lifetime_sender_persistence_through_timeout`
- `thread_utils::base::tests::test_spawn_with_collector_basic`
- `thread_utils::base::tests::test_spawn_with_collector_complex`
- `thread_utils::base::tests::test_spawn_with_collector_panic_propagation`
- `thread_utils::base::tests::test_streaming_collector_stream_collect_timeout_no_receiver`
- `thread_utils::base::tests::test_streaming_collector_try_push`
- `thread_utils::result_collector::tests::test_early_return_receiver_cleanup_multiple_scenarios`
- `thread_utils::result_collector::tests::test_error_handling_in_teardown`

## Timeout Tests (2)

The following tests are still running after 60 seconds:

- `thread_utils::base::tests::test_streaming_collector_bounded`
- `thread_utils::result_collector::tests::test_early_return_receiver_cleanup_stream_collect_blocking_no_receiver`

## Ignored Tests (2)

The following tests were marked as ignored:

- `thread_utils::result_collector::tests::benches::bench_high_concurrency`
- `thread_utils::result_collector::tests::benches::bench_performance_comparison`

## Module-Level Results

### ✅ archive: 3/3 (100.0%)
### ✅ audit: 2/2 (100.0%)
### ✅ backend: 15/15 (100.0%)
### ✅ ci_policy: 20/20 (100.0%)
### ✅ error: 14/14 (100.0%)
### ✅ global_config: 6/6 (100.0%)
### ✅ install_manifest: 5/5 (100.0%)
### ✅ ipc: 6/6 (100.0%)
### ✅ keyring: 2/2 (100.0%)
### ✅ lease: 14/14 (100.0%)
### ✅ lifecycle: 4/4 (100.0%)
### ✅ linter: 3/3 (100.0%)
### ✅ manifest: 6/6 (100.0%)
### ✅ monitor: 8/8 (100.0%)
### ✅ operations: 4/4 (100.0%)
### ✅ parser: 49/49 (100.0%)
### ✅ scanner: 7/7 (100.0%)
### ✅ terminal: 5/5 (100.0%)
### ❌ thread_utils: 266/274 (97.1%)
### ✅ types: 27/27 (100.0%)
### ✅ versions: 2/2 (100.0%)
