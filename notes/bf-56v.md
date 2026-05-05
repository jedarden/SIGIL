# Phase 2.1: Daemon Hardening Verification

## Summary

Verified all daemon hardening measures are properly implemented.

## Hardening Measures Verified

### 1. PR_SET_DUMPABLE=0 (Prevent Memory Inspection)
- **Location**: `crates/sigil-daemon/src/memory.rs::enable_memory_protection()`
- **Implementation**: Calls `libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0)`
- **Timing**: Called FIRST in `start_daemon()` before any secret loading
- **Verification**: Test confirms `/proc/<pid>/status` shows `dumpable: 0`

### 2. mlockall(MCL_CURRENT | MCL_FUTURE) (Prevent Swap)
- **Location**: `crates/sigil-daemon/src/memory.rs::ProtectedSecrets::mlock_secrets()`
- **Implementation**: Calls `libc::mlockall(libc::MCL_CURRENT | libc::MCL_FUTURE)`
- **Behavior**: Best-effort with warning on failure (RLIMIT_MEMLOCK may be exceeded)
- **Verification**: Test checks log for "Memory locked" message and VmLck in /proc

### 3. Kernel Session Keyring (Session Token Storage)
- **Location**: `crates/sigil-core/src/keyring.rs`
- **Functions**: `add_session_token()`, `read_session_token()`, `remove_session_token()`
- **Implementation**: Uses `libc::syscall(SYS_add_key, ...)` with `KEY_SPEC_SESSION_KEYRING`
- **Fallback**: File-based storage at `$XDG_RUNTIME_DIR/sigil-session-token` with 0400 permissions
- **Verification**: Test confirms no token file exists when keyring is available

### 4. RLIMIT_CORE=0 (Disable Core Dumps)
- **Location**: `crates/sigil-daemon/src/memory.rs::enable_memory_protection()`
- **Implementation**: Sets `rlimit { rlim_cur: 0, rlim_max: 0 }` for `RLIMIT_CORE`
- **Verification**: Test confirms `/proc/<pid>/limits` shows core size as 0

### 5. Socket with 0600 Permissions
- **Location**: `crates/sigil-daemon/src/server.rs::run()`
- **Implementation**: After `UnixListener::bind()`, sets permissions to 0o600
- **Verification**: Test confirms socket file has 0600 permissions

## Startup Sequence

1. `enable_memory_protection()` → PR_SET_DUMPABLE=0, RLIMIT_CORE=0
2. `SessionTokenFile::new()` → Check keyring availability
3. Vault unlock → Prompt for passphrase, load secrets into ProtectedSecrets
4. `SessionToken::generate()` → 32-byte random token via getrandom()
5. `session_token_file.write_token()` → Store in kernel keyring (or file fallback)
6. `create_unix_listener()` → Create Unix socket
7. Set socket permissions to 0600

## Tests Added

Created `crates/sigil-integration-tests/tests/daemon_hardening_test.rs` with 5 runtime tests:

1. `test_daemon_sets_dumpable_zero` - Verifies /proc/pid/status shows dumpable: 0
2. `test_session_token_in_keyring` - Verifies keyctl finds token, no token file exists
3. `test_socket_permissions_are_0600` - Verifies socket has 0600 permissions
4. `test_rlimit_core_is_zero` - Verifies /proc/pid/limits shows core size 0
5. `test_mlockall_is_called` - Verifies mlockall log message

All tests pass.

## Acceptance Criteria

- [x] Daemon is hardened against memory inspection (PR_SET_DUMPABLE=0)
- [x] Memory is locked to prevent swap (mlockall)
- [x] Session token stored in kernel keyring (not disk)
- [x] Core dumps disabled (RLIMIT_CORE=0)
- [x] Socket has 0600 permissions
- [x] Runtime tests verify all hardening measures
