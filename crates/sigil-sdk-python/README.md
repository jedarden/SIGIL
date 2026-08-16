# sigil-sdk - Python SDK for SIGIL

Python native bindings for SIGIL secret management system.

## Installation

```bash
pip install sigil-sdk
```

## Quick Start

```python
import asyncio
from sigil_sdk_python import PySigilClient

async def main():
    # Connect to the SIGIL daemon
    client = await PySigilClient.connect_default()
    
    # Get a secret
    api_key = await client.get('kalshi/api_key')
    print('API Key:', api_key)
    
    # Resolve placeholders
    resolved = await client.resolve('Bearer {{secret:kalshi/api_key}}')
    print('Resolved:', resolved)

asyncio.run(main())
```

## API Reference

### Creating a Client

#### `await SigilClient.connect_default()`

Create a new client with the default socket path.

```python
client = await PySigilClient.connect_default()
```

The default socket path is:
- `$XDG_RUNTIME_DIR/sigil.sock` if `XDG_RUNTIME_DIR` is set
- `/tmp/sigil-<uid>.sock` as a fallback

#### `await SigilClient.connect(socket_path)`

Create a client with a custom socket path.

```python
client = await PySigilClient.connect('/custom/path/sigil.sock')
```

### Methods

#### `await client.get(path)`

Get a secret value by path.

- **path**: `str` - Secret path (e.g., `"kalshi/api_key"`)
- **Returns**: `str`

```python
api_key = await client.get('kalshi/api_key')
```

#### `await client.resolve(input)`

Resolve placeholders in a string. Placeholders use the format `{{secret:path}}`.

- **input**: `str` - String containing placeholders
- **Returns**: `str`

```python
resolved = await client.resolve('Bearer {{secret:kalshi/api_key}}')
# Returns: "Bearer sk_live_..."
```

#### `await client.exists(path)`

Check if a secret exists.

- **path**: `str` - Secret path to check
- **Returns**: `bool`

```python
exists = await client.exists('aws/access_key_id')
if exists:
    print('Secret exists!')
```

#### `await client.list(prefix)`

List secrets with optional prefix filter.

- **prefix**: `str` - Prefix to filter secrets (e.g., `"aws/"`)
- **Returns**: `list[SecretMetadata]`

```python
secrets = await client.list('aws/')
for secret in secrets:
    print(f"{secret.path}: {secret.secret_type}")
```

#### `await client.request_access(path, reason, duration_secs=None)`

Request access to a secret. This triggers the TUI approval workflow if needed.

- **path**: `str` - Secret path to request access for
- **reason**: `str` - Reason for the access request
- **duration_secs**: `int | None` - Optional duration in seconds for time-bounded access
- **Returns**: `AccessGrant`

```python
grant = await client.request_access('prod/db_password', 'Running migrations', 300)
if grant.granted:
    print('Access granted until:', grant.expires_at)
else:
    print('Access denied')
```

#### `await client.scrub(output)`

Remove secrets from output text.

- **output**: `str` - Output string that may contain secrets
- **Returns**: `str`

```python
scrubbed = await client.scrub('API key: sk_live_abc123')
# Returns: "API key: [REDACTED]"
```

#### `await client.status()`

Get daemon status information.

- **Returns**: `DaemonStatusInfo`

```python
status = await client.status()
print('Daemon running:', status.running)
print('Uptime:', status.uptime_secs, 'seconds')
print('Active sessions:', status.active_sessions)
print('Secrets loaded:', status.secrets_loaded)
```

### Types

#### `SecretMetadata`

Metadata about a secret.

```python
class SecretMetadata:
    path: str              # Secret path
    secret_type: str       # Secret type
    created_at: str        # Creation timestamp (RFC3339)
    updated_at: str        # Last update timestamp (RFC3339)
    tags: list[str]       # Tags
    notes: str | None      # Notes
```

#### `AccessGrant`

Result of an access request.

```python
class AccessGrant:
    granted: bool          # Whether access was granted
    expires_at: str | None  # When the grant expires (if applicable)
```

#### `DaemonStatusInfo`

Daemon status information.

```python
class DaemonStatusInfo:
    running: bool           # Whether the daemon is running
    uptime_secs: int        # Daemon uptime in seconds
    active_sessions: int     # Number of active sessions
    secrets_loaded: int     # Number of secrets loaded
```

## Requirements

- Python >= 3.8
- SIGIL daemon running (sigild)
- SIGIL socket available at default location or custom path

## License

MIT OR Apache-2.0
