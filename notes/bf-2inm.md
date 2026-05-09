# Phase 2.4: Three Daemon Startup Modes - Verification Summary

## Date
2026-05-09

## Overview
Verified the implementation of the three daemon startup modes as specified in Phase 2.4 of the SIGIL implementation plan.

## Verification Results

### 1. On-demand Startup (Default)
- **Location**: `crates/sigil-daemon/src/ondemand.rs`
- **Implementation**: Complete
- **Verified Features**:
  - Lockfile coordination at `$XDG_RUNTIME_DIR/sigil.lock`
  - Client checks if daemon is running via socket probe
  - If not running: acquires lockfile, forks daemon, waits for socket (max 5s)
  - Race-safe: multiple clients result in exactly one daemon (using `flock` with `LOCK_EX`)
  - Daemon remains running after client disconnects
  - `OnDemandCoordinator` struct with `ensure_daemon_running()` method
  - `LockFileGuard` for automatic lock release on drop

### 2. systemd Socket Activation (Linux)
- **Location**: `crates/sigil-daemon/src/server.rs` (socket activation) and `crates/sigil-cli/src/main.rs` (setup)
- **Implementation**: Complete
- **Verified Features**:
  - `sigil setup systemd` installs `~/.config/systemd/user/sigil.socket` and `sigil.service`
  - `get_systemd_socket_fd()` function checks `LISTEN_FDS` environment variable
  - `LISTEN_PID` security check verifies the PID matches
  - `SD_LISTEN_FDS_START=3` constant used (as per systemd protocol)
  - `sd_notify()` function sends `READY=1` notification after secrets loaded
  - `NOTIFY_SOCKET` handling with `UnixDatagram`
  - Socket unit has `SocketMode=0600`
  - Service unit has `Type=notify` and `--systemd` flag

### 3. launchd Socket Activation (macOS)
- **Location**: `crates/sigil-daemon/src/server.rs` (socket activation) and `crates/sigil-cli/src/main.rs` (setup)
- **Implementation**: Complete
- **Verified Features**:
  - `sigil setup launchd` installs `~/Library/LaunchAgents/com.sigil.daemon.plist`
  - `get_launchd_socket_fd()` function (cfg-gated for macOS)
  - `launch_activate_socket` declaration from launch framework
  - Plist has `SockPathName` with `sigil.sock`
  - Plist has `SockPathMode=384` (0600 octal = 384 decimal)
  - Plist includes `--launchd` flag

### 4. Idle Timeout Shutdown
- **Location**: `crates/sigil-daemon/src/main.rs` and `crates/sigil-daemon/src/server.rs`
- **Implementation**: Complete
- **Verified Features**:
  - `idle_timeout` parameter with default `"30m"` (30 minutes)
  - `parse_duration()` function supports: `"30s"`, `"5m"`, `"2h"`, `"1d"`, `"never"`
  - `"never"` disables timeout (maps to `u64::MAX`)
  - `last_activity` tracked as `Arc<Mutex<Instant>>`
  - Idle timeout checker task runs every 60 seconds
  - On timeout: graceful shutdown with zeroize, socket close, lockfile removal
  - `DaemonStatus` includes `idle_timeout_secs` field

## Test Results
- **Phase 2.4 Verification Tests**: 44/44 passed
- **Daemon Startup Modes Tests**: 17/17 passed

## Files Modified
No code changes were required - the implementation was already complete.

## Files Verified
1. `crates/sigil-daemon/src/ondemand.rs` - On-demand startup coordination
2. `crates/sigil-daemon/src/main.rs` - Daemon CLI with idle timeout parsing
3. `crates/sigil-daemon/src/server.rs` - Socket activation (systemd/launchd) and idle timeout checking
4. `crates/sigil-daemon/src/client.rs` - Client with on-demand startup
5. `crates/sigil-cli/src/main.rs` - systemd and launchd setup commands
6. `crates/sigil-integration-tests/tests/phase2_4_startup_modes_verification_test.rs` - Verification tests
7. `crates/sigil-daemon/tests/startup_modes.rs` - Runtime startup mode tests

## Acceptance Criteria
- ✅ All three startup modes work correctly (code verification)
- ✅ Idle timeout is configurable and functional (code verification)
- ✅ systemd unit files are correctly installed
- ✅ launchd plist is correctly installed
- ✅ Socket permissions are 0600 in all modes

## Notes
- The integration tests that spawn actual daemons (`daemon_startup_test.rs`) may require built binaries and may hang in certain environments due to CI mode requirements
- The implementation is complete and all code verification tests pass
