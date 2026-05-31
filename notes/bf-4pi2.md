# bf-4pi2: Verify lint and wrap IPC handlers are wired

## Task Description
Original bead described `handle_lint` and `handle_wrap` as stubs at lines 4478-4502 in `crates/sigil-daemon/src/server.rs`, requesting to:
1. Extract core lint (ProjectScanner) logic from CLI into sigil-core
2. Extract core wrap (CommandWrap) logic from CLI into sigil-core
3. Wire daemon IPC handlers with audit logging

## Investigation Findings

### 1. Line Number Discrepancy
- Lines 4478-4502 in server.rs contain **hook handler code** (handle_post_tool_use)
- **Lint handler** is actually at line 4558 (`handle_lint`)
- **Wrap handler** is actually at line 4684 (`handle_wrap`)

The bead description appears to reference an older version of the code or had incorrect line numbers.

### 2. Current Implementation Status

#### Lint Handler (lines 4558-4657)
**FULLY IMPLEMENTED** - Uses sigil-core exclusively:
- `sigil_core::get_staged_files()` - for staged mode
- `sigil_core::collect_files_in_directory()` - for directory scanning
- `sigil_core::SecretLinter` - for actual secret detection
- Audit logging: `audit_logger.log_lint_scan(&lint_req.path, findings.len())`
- Returns proper `LintResponse` with findings

#### Wrap Handler (lines 4684-4780)
**FULLY IMPLEMENTED** - Delegates to existing exec pipeline:
- Converts `WrapRequest` → `ExecRequest`
- Delegates to `handle_exec()` for actual command execution
- Audit logging: `audit_logger.log_wrap_execution(&wrapped_command, exec_response.exit_code)`
- Returns proper `WrapResponse` with wrapped_command field

### 3. sigil-core Integration

#### Linter Module (crates/sigil-core/src/linter.rs)
- `SecretLinter::new()` - Creates linter with default patterns
- `linter.scan_file(path)` - Returns `Vec<SecretFinding>`
- `get_staged_files()` - Gets git staged files
- `collect_files_in_directory(dir)` - Recursive directory scan
- `default_patterns()` - Returns 8 built-in secret patterns

All are exported from sigil-core's lib.rs and used by the daemon.

### 4. Audit Logging (crates/sigil-daemon/src/audit.rs)

Both audit log entries exist and are properly implemented:

```rust
// Line 218-223: LintScan entry
LintScan {
    timestamp: DateTime<Utc>,
    previous_hash: String,
    path: String,
    finding_count: usize,
},

// Line 225-230: WrapExecution entry
WrapExecution {
    timestamp: DateTime<Utc>,
    previous_hash: String,
    command: String,
    exit_code: i32,
},
```

Methods:
- `audit_logger.log_lint_scan(path, finding_count)` - Line 729
- `audit_logger.log_wrap_execution(command, exit_code)` - Line 742

### 5. Test Results

All lint and wrap tests pass:

```
cargo test --package sigil-integration-tests --test phase8_runtime_test
running 12 tests
test test_sigil_lint_dry_run ... ok
test test_sigil_lint_fix_mode ... ok
test test_sigil_lint_multiple_file_types ... ok
test test_sigil_lint_json_format ... ok
test test_sigil_lint_runs ... ok
test test_sigil_wrap_basic_execution ... ok
test test_sigil_wrap_env_injection ... ok
test test_sigil_wrap_exit_code_preservation ... ok
test test_sigil_wrap_output_scrubbing ... ok
test test_sigil_wrap_placeholder_parsing ... ok
test test_sigil_wrap_shell_syntax ... ok
test test_sigil_wrap_with_daemon ... ok

test result: ok. 12 passed; 0 failed
```

Daemon runtime tests:
```
cargo test --package sigil-integration-tests --test phase8_9_daemon_runtime_test
test test_8_5_1_wrap_with_daemon ... ok
test test_8_5_2_wrap_exit_code_preservation ... ok

test result: 23 passed; 1 failed (unrelated - binary build check)
```

## Conclusion

**The lint and wrap IPC handlers are already fully implemented and working correctly.**

This work was completed in:
- Commit 4a281723 "feat(ipc): Implement daemon IPC handlers for Phase 5-8 operations"
- Verified in commit 9c3e50e0 "docs(bf-2r2a): Verify Phase 5-8 IPC handlers already implemented"

The bead description was likely created from an outdated task template or before the implementation was completed.

## Retrospective

- **What worked:** Code review and test verification confirmed the implementation is complete. All 12 lint/wrap runtime tests pass. The handlers properly use sigil-core functionality (SecretLinter, get_staged_files, collect_files_in_directory) and log audit events correctly.
- **What didn't:** The bead description referenced incorrect line numbers (4478-4502 are hook handlers, not lint/wrap) and described stub code that doesn't exist in the current codebase.
- **Surprise:** The implementation was already complete - the task was based on outdated information.
- **Reusable pattern:** Always verify the current state of the codebase before starting implementation work. Bead descriptions can become stale as code evolves.
