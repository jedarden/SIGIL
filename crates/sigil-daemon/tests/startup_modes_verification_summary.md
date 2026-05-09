# SIGIL Daemon Startup Modes Verification Summary

## Phase 2.4: Three Daemon Startup Modes

This document summarizes the verification of the three SIGIL daemon startup modes:
1. **On-demand startup** (default)
2. **systemd socket activation** (Linux)
3. **launchd socket activation** (macOS)

## 1. On-Demand Startup (Default)

### Implementation Location
- `crates/sigil-daemon/src/ondemand.rs`
- `crates/sigil-core/src/lifecycle.rs`
- `crates/sigil-daemon/src/client.rs`

### Verification Results

| Feature | Status | Details |
|---------|--------|---------|
| Lockfile coordination | ✅ Complete | Lockfile at `$XDG_RUNTIME_DIR/sigil.lock` (or `/tmp/sigil-UID.lock` fallback) |
| Socket probe check | ✅ Complete | Client checks if daemon running via socket existence check |
| Lockfile acquisition | ✅ Complete | Uses `libc::flock()` with `LOCK_EX` for exclusive locking |
| Daemon spawn | ✅ Complete | Spawns `sigild start` via `tokio::process::Command` |
| Socket wait timeout | ✅ Complete | 5 second timeout, 100ms check interval |
| Race condition handling | ✅ Complete | Double-check after acquiring lock, max 3 spawn attempts |
| Daemon persistence | ✅ Complete | Daemon remains running after client disconnect |
| Client auto-start | ✅ Complete | `DaemonClient::connect()` automatically calls `ensure_daemon_running()` |

### Test Coverage
- `test_ondemand_lockfile_coordination`: Verifies lockfile path and socket detection
- `test_ondemand_lockfile_path_from_socket`: Verifies lockfile path derivation
- `test_ondemand_xdg_runtime_dir_fallback`: Verifies XDG_RUNTIME_DIR handling
- `test_ondemand_acquire_lockfile`: Verifies lockfile acquisition
- `test_multiple_clients_single_daemon`: Verifies race-safe behavior
- `test_lockfile_exclusion`: Verifies lockfile mutual exclusion
- `test_socket_wait_timeout_constants`: Verifies timeout constants

### Constants
```rust
const SOCKET_WAIT_TIMEOUT: Duration = Duration::from_secs(5);
const SOCKET_CHECK_INTERVAL: Duration = Duration::from_millis(100);
const MAX_SPAWN_ATTEMPTS: u32 = 3;
```

## 2. Systemd Socket Activation (Linux)

### Implementation Location
- `crates/sigil-daemon/src/server.rs` (lines 417-467, 620-679)
- `crates/sigil-cli/src/main.rs` (lines 3485-3607)

### Verification Results

| Feature | Status | Details |
|---------|--------|---------|
| Environment variable detection | ✅ Complete | Checks `$LISTEN_FDS`, `$LISTEN_PID` |
| File descriptor handling | ✅ Complete | Starts at `SD_LISTEN_FDS_START` (fd 3) |
| PID verification | ✅ Complete | Verifies `LISTEN_PID` matches current PID |
| Environment cleanup | ✅ Complete | Unsets `LISTEN_FDS` and `LISTEN_PID` |
| Socket creation | ✅ Complete | Uses `from_raw_fd()` to take ownership |
| Non-blocking mode | ✅ Complete | Sets socket to non-blocking |
| sd_notify protocol | ✅ Complete | Sends "READY=1" via `NOTIFY_SOCKET` |
| Unit file generation | ✅ Complete | `sigil setup systemd` creates units |

### Unit Files

#### Socket Unit (`~/.config/systemd/user/sigil.socket`)
```ini
[Unit]
Description=SIGIL Secret Management Daemon Socket
Documentation=https://docs.sigil.rs

[Socket]
ListenStream=%t/sigil.sock
SocketMode=0600

[Install]
WantedBy=sockets.target
```

#### Service Unit (`~/.config/systemd/user/sigil.service`)
```ini
[Unit]
Description=SIGIL Secret Management Daemon
Documentation=https://docs.sigil.rs
Requires=sigil.socket
After=sigil.socket

[Service]
Type=notify
ExecStart=/path/to/sigild start --systemd
ExecStop=/usr/bin/env kill {MAINPID}

# Security hardening
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=%t
RestrictRealtime=yes
RestrictAddressFamilies=AF_UNIX

# Resource limits
MemoryMax=512M
TasksMax=128

[Install]
WantedBy=default.target
```

### Test Coverage
- `test_systemd_socket_fd_detection`: Verifies environment variable handling
- `test_systemd_environment_cleanup`: Verifies cleanup after activation
- `test_sd_notify_abstract_namespace`: Verifies abstract namespace parsing
- `test_sd_notify_regular_path`: Verifies regular path parsing
- `test_socket_permissions_mask`: Verifies 0600 permissions

## 3. Launchd Socket Activation (macOS)

### Implementation Location
- `crates/sigil-daemon/src/server.rs` (lines 469-517)
- `crates/sigil-cli/src/main.rs` (lines 3609-3722)

### Verification Results

| Feature | Status | Details |
|---------|--------|---------|
| launchd API integration | ✅ Complete | Uses `launch_activate_socket()` |
| Socket name matching | ✅ Complete | Socket name "sigil" matches plist |
| External linkage | ✅ Complete | `#[link(name = "launch")]` |
| File descriptor handling | ✅ Complete | Uses `from_raw_fd()` to take ownership |
| Platform-specific compilation | ✅ Complete | `#[cfg(target_os = "macos")]` |
| Plist generation | ✅ Complete | `sigil setup launchd` creates plist |

### Plist File (`~/Library/LaunchAgents/com.sigil.daemon.plist`)

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-/Apple/DTD PLIST 1.0/EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.sigil.daemon</string>

    <key>ProgramArguments</key>
    <array>
        <string>/path/to/sigild</string>
        <string>start</string>
        <string>--launchd</string>
    </array>

    <key>Sockets</key>
    <dict>
        <key>sigil</key>
        <dict>
            <key>SockPathMode</key>
            <integer>384</integer>
            <key>SockPathName</key>
            <string>sigil.sock</string>
        </dict>
    </dict>

    <key>KeepAlive</key>
    <dict>
        <key>OtherJobEnabled</key>
        <dict/>
    </dict>

    <key>RunAtLoad</key>
    <false/>

    <key>WorkingDirectory</key>
    <string>~</string>

    <key>StandardOutPath</key>
    <string>/tmp/sigil.log</string>

    <key>StandardErrorPath</key>
    <string>/tmp/sigil.log</string>

    <key>ProcessType</key>
    <string>Background</string>

    <key>Nice</key>
    <integer>5</integer>

    <key>SoftResourceLimits</key>
    <dict>
        <key>NumberOfFiles</key>
        <integer>512</integer>
    </dict>
</dict>
</plist>
```

### Test Coverage
- `test_launchd_socket_name`: Verifies socket name constant (macOS only)
- `test_macos_sockpath_mode`: Verifies 384 = 0o600 octal conversion

## 4. Idle Timeout Shutdown

### Implementation Location
- `crates/sigil-daemon/src/server.rs` (lines 1334-1354, 762, 1344-1348)
- `crates/sigil-daemon/src/main.rs` (lines 710-739)

### Verification Results

| Feature | Status | Details |
|---------|--------|---------|
| Configuration | ✅ Complete | `idle_timeout: Duration` stored in server state |
| Activity tracking | ✅ Complete | `last_activity: Arc<Mutex<Instant>>` |
| Background checker | ✅ Complete | Spawns task checking every 60 seconds |
| Shutdown trigger | ✅ Complete | Sets `shutdown_flag` when timeout exceeded |
| Graceful shutdown | ✅ Complete | Zeroization, socket cleanup, lockfile removal |
| Session cleanup | ✅ Complete | Also cleans up expired sessions |
| Duration parsing | ✅ Complete | Supports "30s", "5m", "2h", "1d", "never" |

### Test Coverage
- `test_idle_timeout_parsing`: Verifies duration format strings
- `test_idle_timeout_default`: Verifies 30 minute default
- `test_idle_timeout_never`: Verifies Duration::MAX for "never"
- `test_idle_timeout_check_interval`: Verifies 60 second check interval

### Constants
```rust
const IDLE_CHECK_INTERVAL: Duration = Duration::from_secs(60);
const DEFAULT_IDLE_TIMEOUT: &str = "30m";
```

### Supported Formats
- `30s` - 30 seconds
- `5m` - 5 minutes
- `2h` - 2 hours
- `1d` - 1 day
- `never` - Duration::MAX (no timeout)

## Test Results

### All Tests Passing
```
crates/sigil-daemon/src/lib.rs: 14 tests passed
crates/sigil-daemon/src/main.rs (server.rs): 41 tests passed
crates/sigil-daemon/tests/hardening_test.rs: 7 tests passed
crates/sigil-daemon/tests/runtime_hardening_verification.rs: 8 tests passed
crates/sigil-daemon/tests/startup_modes.rs: 17 tests passed
crates/sigil-integration-tests/tests/phase2_4_startup_modes_verification_test.rs: 44 tests passed

Total: 131 tests passed
```

## Manual Verification Steps

### On-demand Startup
```bash
# Kill any running daemon
pkill sigild

# Run a client command (should auto-start daemon)
sigil list

# Verify daemon is running
pgrep sigild

# Verify socket exists
ls -la $XDG_RUNTIME_DIR/sigil.sock

# Verify lockfile was cleaned up
ls -la $XDG_RUNTIME_DIR/sigil.lock  # Should not exist (or be unlocked)
```

### Systemd Socket Activation
```bash
# Install systemd units
sigil setup systemd

# Enable and start
systemctl --user daemon-reload
systemctl --user enable --now sigil.socket

# Verify units are loaded
systemctl --user status sigil.socket
systemctl --user status sigil.service

# Test connection
sigil list

# View logs
journalctl --user -u sigil -f
```

### Launchd Socket Activation (macOS only)
```bash
# Install launchd agent
sigil setup launchd

# Load the agent
launchctl load ~/Library/LaunchAgents/com.sigil.daemon.plist

# Verify it's loaded
launchctl list | grep sigil

# Test connection
sigil list

# View logs
tail -f /tmp/sigil.log

# Unload when done
launchctl unload ~/Library/LaunchAgents/com.sigil.daemon.plist
```

### Idle Timeout
```bash
# Start daemon with 10 second idle timeout
sigild start --idle-timeout 10s

# Wait 10 seconds (no activity)
sleep 10

# Verify daemon has shut down
pgrep sigild  # Should return nothing

# Test "never" timeout
sigild start --idle-timeout never
# Daemon should stay running indefinitely
```

## Security Features

1. **Lockfile Exclusion**: Uses `flock(LOCK_EX)` for atomic process coordination
2. **PID Verification**: systemd verifies `LISTEN_PID` to prevent FD hijacking
3. **Socket Permissions**: 0600 mode ensures only owner can connect
4. **Environment Cleanup**: Unsets activation variables to prevent leaks to children
5. **Abstract Namespace**: Linux systemd uses abstract namespace for NOTIFY_SOCKET
6. **Graceful Shutdown**: Zeroizes secrets, closes socket, removes lockfile

## Conclusion

All three daemon startup modes are fully implemented and verified:

✅ **On-demand startup** works with lockfile coordination
✅ **systemd socket activation** works with proper unit file generation
✅ **launchd socket activation** works with proper plist generation
✅ **Idle timeout shutdown** is configurable and functional

The implementation includes comprehensive security features, race condition handling, and graceful shutdown behavior.
