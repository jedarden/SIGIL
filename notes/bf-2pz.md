# Phase 3.3-3.4: CLI Integration and Error Response Specification Verification

## Summary

Completed verification of CLI integration (resolve/scrub commands) and error response specification. All 35 integration tests pass.

## Verification Results

### 3.3 CLI Integration

**Resolve Command:**
- `sigil resolve --command "..." --json` works correctly
- Returns JSON with resolved command structure
- Includes: `command`, `resolved`, `has_secrets`, `secret_paths`, `env_injections`, `file_injections`, `use_stdin`
- Handled internally by daemon via `IpcOperation::Resolve`
- Daemon handler: `handle_resolve()` in `server.rs`

**Scrub Command:**
- `sigil scrub` (stdin pipeline) works correctly
- Returns scrubbed output via stdout
- JSON format: `{"scrubbed": "...", "matches_found": true/false, "secrets_detected": N}`
- Handled internally by daemon via `IpcOperation::Scrub`
- Daemon handler: `handle_scrub()` in `server.rs`

### 3.4 Error Response Specification

**All 9 Agent-Facing Error Codes:**
1. `SECRET_NOT_FOUND` - "The referenced credential could not be resolved."
2. `COMMAND_BLOCKED` - "This command is not permitted by security policy"
3. `PATH_RESTRICTED` - "Access to this path is restricted"
4. `DAEMON_UNAVAILABLE` - "SIGIL daemon is not running. Start with 'sigil daemon start'"
5. `VAULT_LOCKED` - "Vault is locked. Authenticate via SIGIL TUI"
6. `SESSION_EXPIRED` - "Session expired. Reconnect required"
7. `ACCESS_DENIED` - "Access denied for this secret. Request via sigil_request"
8. `OPERATION_FAILED` - "Command execution failed"
9. `INTERNAL_ERROR` - "Internal error. Check sigil daemon logs"

**Claude Code Hook Integration:**
- PreToolUse: exit code 2 + JSON decision block on errors
- Structure: `{permission_decision: "ask", sigil_error: {...}}`
- Error response includes sanitized message only

**MCP Integration:**
- Returns JSON-RPC error with `error` field (no explicit `isError` boolean needed per JSON-RPC 2.0 spec)
- Structure: `{jsonrpc: "2.0", id: "...", error: {code: -32603, message: "...", data: {...}}}`
- Data field includes SIGIL error code and sanitized message

**Audit Log Separation:**
- Internal SigilError contains full details (path, context) for audit logging
- Agent-facing StructuredError contains only sanitized messages
- Request IDs enable audit trail correlation

**Security-Conscious Messaging:**
- Never reveals architecture (no bwrap, seccomp, namespaces in errors)
- PATH_RESTRICTED returns uniform message for all blocked paths
- No secret echoing in errors
- No path enumeration (SECRET_NOT_FOUND doesn't suggest similar paths)

## Test Results

All 35 tests in `phase3_3_3_4_verification_test.rs` pass:
- CLI integration tests: 6/6 passed
- Error code tests: 11/11 passed
- SigilError mapping tests: 5/5 passed
- Claude Code hook error tests: 2/2 passed
- Daemon integration tests: 3/3 passed
- MCP error response tests: 2/2 passed
- Audit log separation tests: 4/4 passed

## Implementation Status

- CLI resolve command: Complete
- CLI scrub command: Complete
- Daemon resolve handler: Complete
- Daemon scrub handler: Complete
- Error code definitions: Complete (9 codes)
- Sanitized error messages: Complete
- Claude Code hook error format: Complete
- MCP error format: Complete
- Audit log separation: Complete

## Files Verified

- `crates/sigil-core/src/error.rs` - Error code definitions and StructuredError
- `crates/sigil-core/src/ipc.rs` - IPC protocol with Resolve/Scrub operations
- `crates/sigil-cli/src/hooks.rs` - Claude Code hook integration
- `crates/sigil-cli/src/main.rs` - Resolve and scrub CLI commands
- `crates/sigil-daemon/src/server.rs` - Daemon handlers for resolve/scrub
- `crates/sigil-mcp/src/main.rs` - MCP server with error handling
- `crates/sigil-integration-tests/tests/phase3_3_3_4_verification_test.rs` - Comprehensive tests

## Acceptance Criteria Met

- [x] resolve and scrub commands work end-to-end
- [x] All error codes return sanitized messages
- [x] Audit log has full context, agent sees minimal info
