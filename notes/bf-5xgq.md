# Phase 3.3-3.4: CLI Integration and Error Response Specification Verification

## Summary

Verified CLI resolve/scrub commands and error response specification for SIGIL.

## What Was Verified

### 3.3 CLI Integration

1. **sigil resolve --command "..." --json works** ✓
   - Tested with simple commands: `echo hello world`
   - Returns valid JSON with command, has_secrets, secret_paths, env_injections, file_injections, use_stdin fields

2. **sigil scrub (stdin pipeline) works** ✓
   - Tested with stdin input containing potential secrets
   - Returns JSON with scrubbed, matches_found, secrets_detected fields

3. **Resolve returns JSON with resolved command** ✓
   - CommandParser::resolve_command() parses and resolves {{secret:path}} placeholders
   - Returns environment variable injection format (e.g., ${TEST_API_KEY})

4. **Scrub returns scrubbed output via stdout** ✓
   - Scrubber detects and redacts secret values from output
   - Returns plain text or JSON format

**Note:** Operations are handled directly by the CLI (not daemon) - this is the current architecture. The CLI loads the vault directly for resolve/scrub operations.

### 3.4 Error Response Specification

1. **All 9 agent-facing error codes return correct sanitized messages** ✓
   - SECRET_NOT_FOUND, COMMAND_BLOCKED, PATH_RESTRICTED, DAEMON_UNAVAILABLE, VAULT_LOCKED, SESSION_EXPIRED, ACCESS_DENIED, OPERATION_FAILED, INTERNAL_ERROR
   - All defined in sigil_core::error::ErrorCode with sanitized messages

2. **Claude Code PreToolUse: exit code 2 + JSON decision block** ✓
   - Implemented in sigil-cli/src/main.rs::CommandHook::run()
   - On error: prints JSON error response and exits with code 2
   - Error response includes permission_decision: "ask" for Claude Code

3. **MCP: JSON-RPC error with isError: true** ✓
   - Implemented in sigil-mcp/src/main.rs
   - Uses JsonRpcResult::Error with code, message, and optional data fields
   - Follows JSON-RPC 2.0 specification

4. **sigil-shell: plain text to stderr** ✓
   - Implemented in sigil-shell/src/main.rs
   - Errors printed via eprintln!() on line 196

5. **Audit log separation** ✓
   - Internal SigilError contains full details (e.g., secret path)
   - Agent-facing StructuredError uses sanitized messages only
   - Tests verify no secret values or path enumeration in error messages

### Security-Conscious Messaging

- Never reveals architecture (no bwrap, seccomp, namespaces in errors) ✓
- Uniform denial: PATH_RESTRICTED returns same message for all blocked paths ✓
- No secret echoing in errors ✓
- No path enumeration: SECRET_NOT_FOUND doesn't suggest similar paths ✓

## Test Results

All 35 tests in phase3_3_3_4_verification_test.rs pass:
- CLI integration tests: 6 tests
- Error code tests: 10 tests
- SigilError mapping tests: 6 tests
- Claude Code hook error tests: 2 tests
- MCP error response tests: 2 tests
- Audit log separation tests: 4 tests
- Daemon integration tests: 3 tests
- Claude Code hook exit code tests: 2 tests

## Files Examined

- crates/sigil-core/src/error.rs - Error code definitions and StructuredError
- crates/sigil-core/src/ipc.rs - IPC protocol with IpcErrorCode
- crates/sigil-cli/src/main.rs - CLI commands (resolve, scrub, hook)
- crates/sigil-cli/src/hooks.rs - Claude Code hook integration
- crates/sigil-mcp/src/main.rs - MCP server with JSON-RPC errors
- crates/sigil-shell/src/main.rs - Shell wrapper with stderr errors
- crates/sigil-integration-tests/tests/phase3_3_3_4_verification_test.rs - Comprehensive tests

## Acceptance Status

✓ resolve and scrub commands work end-to-end
✓ All error codes return sanitized messages
✓ Audit log has full context, agent sees minimal info
✓ Claude Code hooks return exit code 2 + JSON decision block
✓ MCP returns JSON-RPC error format
✓ sigil-shell returns plain text to stderr
