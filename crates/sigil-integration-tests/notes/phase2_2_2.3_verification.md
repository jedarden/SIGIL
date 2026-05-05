# Phase 2.2-2.3 Verification: Client Library and Audit Logger

## Summary

Phase 2.2 (Client Library) and Phase 2.3 (Audit Logger) are **COMPLETE**. All integration tests pass (7/7).

## 2.2 Client Library (sigil-sdk::client)

### Implementation Location
- `crates/sigil-sdk/src/client.rs` - SDK client for application use
- `crates/sigil-daemon/src/client.rs` - Daemon client with keyring integration
- `crates/sigil-core/src/keyring.rs` - Kernel keyring support

### Features Implemented

#### 1. Async Client for Communicating with sigild
```rust
pub struct SigilClient {
    socket_path: PathBuf,
    session_token: Option<SessionToken>,
    timeout: u64,
    pool: Arc<Mutex<ConnectionPool>>,
    max_retries: u32,
}
```

All operations are async:
- `connect()`, `close()`
- `get()`, `exists()`, `list()`
- `resolve()`, `scrub()`
- `request_access()`, `status()`

#### 2. Connection Pooling (Single Persistent Connection)
```rust
struct ConnectionPool {
    connection: Option<PooledConnection>,
    semaphore: Arc<Semaphore>,  // Ensures single access
}

struct PooledConnection {
    stream: UnixStream,
    last_used: Instant,
}

impl PooledConnection {
    fn is_stale(&self) -> bool {
        self.last_used.elapsed() > Duration::from_secs(300)  // 5 minutes
    }
}
```

- Single connection per client via `Arc<Semaphore>` (permit count = 1)
- Stale connection detection (5 min timeout)
- Automatic stale connection removal

#### 3. Automatic Reconnection with Backoff
```rust
const DEFAULT_MAX_RETRIES: u32 = 5;
const BASE_BACKOFF_MS: u64 = 100;
const MAX_BACKOFF_SECS: u64 = 30;

async fn connect_with_retry(socket_path: &PathBuf, timeout_secs: u64) -> Result<PooledConnection> {
    for attempt in 0..DEFAULT_MAX_RETRIES {
        let backoff_ms = BASE_BACKOFF_MS * 2_u64.pow(attempt);
        let backoff = Duration::from_millis(backoff_ms.min(MAX_BACKOFF_SECS * 1000));

        match tokio::time::timeout(Duration::from_secs(timeout_secs), UnixStream::connect(socket_path)).await {
            Ok(Ok(stream)) => return Ok(PooledConnection::new(stream)),
            _ => {
                if attempt < DEFAULT_MAX_RETRIES - 1 {
                    tokio::time::sleep(backoff).await;
                }
            }
        }
    }
}
```

Exponential backoff: 100ms, 200ms, 400ms, 800ms, 1600ms (capped at 30s)

#### 4. Token Acquisition from Kernel Keyring
```rust
// crates/sigil-daemon/src/client.rs
fn read_session_token() -> Result<SessionToken, String> {
    // Try kernel keyring first
    if sigil_core::is_keyring_available() {
        match sigil_core::read_session_token() {
            Ok(token_str) => return SessionToken::from_string(token_str),
            Err(e) => tracing::debug!("Failed to read from keyring: {}, trying file fallback", e),
        }
    }

    // Fallback to file-based storage
    let token_path = std::path::PathBuf::from(runtime_dir).join("sigil-session-token");
    let token_str = std::fs::read_to_string(&token_path)?;
    SessionToken::from_string(token_str.trim().to_string())
}
```

## 2.3 Audit Logger

### Implementation Location
- `crates/sigil-daemon/src/audit.rs` - Audit logger implementation
- `crates/sigil-core/src/audit.rs` - Audit types and read-only reader

### Features Implemented

#### 1. Append-Only JSON Lines Log
```rust
pub struct AuditLogger {
    log_path: PathBuf,
    current_hash: Arc<Mutex<Option<String>>>,
}

async fn write_entry(&self, entry: AuditEntry) -> Result<()> {
    let mut file = OpenOptions::new()
        .create(true)
        .append(true)  // Append-only mode
        .open(&self.log_path)?;

    writeln!(file, "{}", json)?;
    set_audit_log_permissions(&self.log_path)?;  // 0600 permissions
}
```

Log location: `~/.sigil/vault/audit.jsonl` (or `$XDG_DATA_HOME/.sigil/vault/audit.jsonl`)

#### 2. Hash-Chained Entries
```rust
impl AuditEntry {
    pub fn compute_hash(&self, previous_hash: &str) -> String {
        let json = serde_json::to_string(self).expect("Failed to serialize audit entry");
        let input = format!("{}{}", previous_hash, json);
        let hash = Sha256::digest(input.as_bytes());
        hex::encode(hash)
    }
}
```

Each entry contains `previous_hash` field linking to previous entry's hash.

#### 3. chattr +a Attempted (Best-Effort)
```rust
#[cfg(target_os = "linux")]
async fn set_append_only_flag(&self, file: &File) {
    const FS_APPEND_FL: u32 = 0x00000020;
    const FS_IOC_SETFLAGS: u64 = 0x40046602;

    let fd = file.as_raw_fd();
    let mut flags: u32 = FS_APPEND_FL;
    let result = unsafe { libc::ioctl(fd as libc::c_int, FS_IOC_SETFLAGS, &mut flags) };

    if result != 0 {
        let err = std::io::Error::last_os_error();
        if err.raw_os_error() == Some(libc::EPERM) {
            tracing::warn!("Cannot set append-only flag (requires root).");
        }
    }
}

#[cfg(target_os = "macos")]
async fn set_append_only_flag(&self, file: &File) {
    const UF_APPEND: u32 = 0x00000004;
    let fd = file.as_raw_fd();
    let result = unsafe { libc::fchflags(fd as libc::c_int, UF_APPEND as libc::c_int) };

    if result != 0 {
        tracing::warn!("Cannot set append-only flag (requires root).");
    }
}
```

Best-effort approach: continues if setting flag fails (requires root).

#### 4. Events Logged
All required event types are implemented in `AuditEntry` enum:
- `SessionStart` / `SessionEnd`
- `SecretResolve` (with fingerprint, pid, uid)
- `SecretAdd` (with path, fingerprint)
- `SecretDelete` (with path)
- `SecretEdit` (with old_fingerprint, new_fingerprint)
- `AuthFailure` (with reason, pid, uid)
- `BreachDetected` (with severity, description)

Additional events:
- `Rotation`, `FuseRead`, `CanaryAccess`
- `Lockdown`, `Unlock`
- `SecretAccessGrant`, `SecretAccessDenied`
- `CommandExecuted`, `OperationExecuted`
- `ProxyConfigLoaded`, `ProxyStarted`, `ProxyStopped`, `ProxyRequest`

#### 5. Never Logs Secret Values
```rust
pub async fn log_secret_resolve(&self, path: String, fingerprint: String, pid: u32, uid: u32) {
    // Only logs fingerprint (first 6 chars of SHA256 hash), never the actual value
    let entry = AuditEntry::SecretResolve {
        timestamp: Utc::now(),
        previous_hash,
        path,
        fingerprint,  // NOT the value
        pid,
        uid,
    };
}
```

Audit log contains:
- Secret paths (not values)
- Fingerprints (SHA256[0..6])
- PIDs, UIDs, timestamps
- Event types

## Integration Tests

All 7 tests in `crates/sigil-integration-tests/tests/phase2_client_audit_test.rs` pass:

1. **test_client_connection_pooling** - Verifies ConnectionPool struct, semaphore, acquire/return methods, stale detection
2. **test_client_exponential_backoff** - Verifies backoff calculation, exponential increase, max cap, retry logic
3. **test_token_acquisition_from_keyring** - Verifies SessionToken handling, load_token_from_file fallback, keyring functions
4. **test_audit_log_append_only_enforcement** - Verifies append mode, ioctl/chflags, best-effort warnings
5. **test_audit_log_tamper_detection** - Verifies hash chain verification, tampering breaks chain
6. **test_client_reconnection_after_daemon_restart** - Runtime test: kill daemon, restart, verify secret still accessible
7. **test_audit_log_entry_creation** - Runtime test: add secret, verify audit entry created, no values logged

## Acceptance Criteria

| Criterion | Status | Notes |
|-----------|--------|-------|
| Client library handles reconnection gracefully | ✅ | Exponential backoff, max 5 retries |
| Audit log is tamper-evident via hash chain | ✅ | SHA256 chaining, verify_chain() detects tampering |
| No secret values appear in audit log | ✅ | Only fingerprints logged |

## Additional Verification

### Kernel Keyring Support
- Linux-specific implementation using `libc::syscall` with `SYS_add_key`, `SYS_keyctl`
- Session keyring (`KEY_SPEC_SESSION_KEYRING`) for tokens
- User keyring (`KEY_SPEC_USER_KEYRING`) for device key encryption key
- Graceful fallback to file-based storage on non-Linux or when keyring unavailable

### Secure File Permissions
- Audit log files created with 0600 permissions (owner read/write only)
- Applied via `set_audit_log_permissions()` on every write

### Hash Chain Verification
```rust
pub fn verify_chain(&self) -> Result<bool> {
    let mut previous_hash = String::new();
    for entry in entries.iter() {
        if let Some(stored_previous) = entry.previous_hash() {
            if stored_previous != previous_hash {
                return Ok(false);  // Chain broken
            }
        }
        previous_hash = entry.compute_hash(&previous_hash);
    }
    Ok(true)
}
```

## Running Tests

```bash
# Run all Phase 2.2-2.3 tests
cargo test -p sigil-integration-tests --test phase2_client_audit_test

# Run specific test
cargo test -p sigil-integration-tests test_client_reconnection_after_daemon_restart
```

## Conclusion

Phase 2.2 (Client Library) and Phase 2.3 (Audit Logger) are fully implemented and verified. All acceptance criteria are met.
