# Phase 2.5-2.7: Audit Lifecycle, IPC Protocol, and Signal Handling Verification

## Summary

Completed verification of Phase 2.5-2.7 deliverables:

### 2.5 Audit Log Lifecycle
- Size-based rotation: Implemented in `AuditLogger::rotate()` with configurable max_size (default 50MB)
- Hash-chain continuity: `Rotation` entry type includes `previous_file_hash` for chain verification
- Compression: Implemented using `flate2` when `compress=true` in config
- Export: `sigil audit export --from/--to --format json|csv` implemented in CLI
- Verify: `sigil audit verify` checks hash chain integrity via `AuditLogReader::verify_chain()`
- Prune: `sigil audit prune` removes logs exceeding retention policy
- Stats: `sigil audit stats` shows log size, entry count, date range
- Tamper detection: Hash chain verification detects broken chains

### 2.6 IPC Protocol
- Length-prefixed JSON: Implemented using big-endian u32 length prefix
- Request envelope: `IpcRequest` with v, id, op, token, payload fields
- Response envelope: `IpcResponse` with v, id, ok, payload/error, stream fields
- Error codes: All 15 error codes implemented (InvalidToken, InvalidRequest, UnknownOp, SecretNotFound, AccessDenied, VaultLocked, RateLimited, PayloadTooLarge, InternalError, SessionExpired, OperationFailed, SandboxError, ScrubError, BackendError, LockedDown)
- Multiplexing: Request ID correlation via unique request IDs
- Streaming: `stream` field and `stream_chunk()` helper for long-running operations
- Protocol version: `PROTOCOL_VERSION` constant enables backward compatibility

### 2.7 Signal Handling
- SIGTERM/SIGINT: Graceful shutdown with 5s drain period
- SIGHUP: Reload config without vault re-unseal
- SIGUSR1: Dump status to audit log
- SIGUSR2: Force audit log rotation
- SIGQUIT: Immediate exit (debugging only, disabled in production)
- SIGPIPE: Ignored globally, handled per-connection
- PR_SET_PDEATHSIG: Implemented via bubblewrap `--die-with-parent` flag
- Signal forwarding: sigil-shell forwards signals to sandbox child

## Test Results

All 53 Phase 2 tests pass:
- phase2_audit_lifecycle_test.rs: 6 tests passed
- phase2_ipc_protocol_test.rs: 9 tests passed
- phase2_signal_handling_test.rs: 12 tests passed
- phase2_audit_ipc_signals_test.rs: 26 tests passed

## Files Modified

- `crates/sigil-integration-tests/tests/phase2_audit_ipc_signals_test.rs`: Fixed 3 failing tests
  - Added `drop(writer)` to flush BufWriter before reading files
  - Fixed sandbox PR_SET_PDEATHSIG test to check bubblewrap module
