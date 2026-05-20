# @sigil/sdk - Node.js SDK for SIGIL

Node.js native bindings for SIGIL secret management system.

## Installation

```bash
npm install @sigil/sdk
```

## Quick Start

```javascript
const { SigilClient } = require('@sigil/sdk');

// Connect to the SIGIL daemon
const client = new SigilClient();
await client.connect();

// Get a secret
const apiKey = await client.get('kalshi/api_key');
console.log('API Key:', apiKey);

// Resolve placeholders
const resolved = await client.resolve('Bearer {{secret:kalshi/api_key}}');
console.log('Resolved:', resolved);
```

## API Reference

### Creating a Client

#### `new SigilClient()`

Create a new client with the default socket path.

```javascript
const client = new SigilClient();
```

The default socket path is:
- `$XDG_RUNTIME_DIR/sigil.sock` if `XDG_RUNTIME_DIR` is set
- `/tmp/sigil-<pid>.sock` as a fallback

#### `SigilClient.withSocketPath(socketPath)`

Create a client with a custom socket path.

```javascript
const client = SigilClient.withSocketPath('/custom/path/sigil.sock');
```

#### `SigilClient.withToken()`

Create a client and automatically load the session token from the standard location (`$XDG_RUNTIME_DIR/sigil-session-token`).

```javascript
const client = SigilClient.withToken();
```

### Methods

#### `client.connect()`

Verify connection to the SIGIL daemon.

```javascript
await client.connect();
```

#### `client.get(path)`

Get a secret value by path.

- **path**: `string` - Secret path (e.g., `"kalshi/api_key"`)
- **Returns**: `Promise<string>`

```javascript
const apiKey = await client.get('kalshi/api_key');
```

#### `client.resolve(input)`

Resolve placeholders in a string. Placeholders use the format `{{secret:path}}`.

- **input**: `string` - String containing placeholders
- **Returns**: `Promise<string>`

```javascript
const resolved = await client.resolve('Bearer {{secret:kalshi/api_key}}');
// Returns: "Bearer sk_live_..."
```

#### `client.exists(path)`

Check if a secret exists.

- **path**: `string` - Secret path to check
- **Returns**: `Promise<boolean>`

```javascript
const exists = await client.exists('aws/access_key_id');
if (exists) {
  console.log('Secret exists!');
}
```

#### `client.list(prefix)`

List secrets with optional prefix filter.

- **prefix**: `string` - Prefix to filter secrets (e.g., `"aws/"`)
- **Returns**: `Promise<SecretMetadata[]>`

```javascript
const secrets = await client.list('aws/');
for (const secret of secrets) {
  console.log(`${secret.path}: ${secret.secretType}`);
}
```

#### `client.requestAccess(path, reason, durationSecs)`

Request access to a secret. This triggers the TUI approval workflow if needed.

- **path**: `string` - Secret path to request access for
- **reason**: `string` - Reason for the access request
- **durationSecs**: `number | undefined` - Optional duration in seconds for time-bounded access
- **Returns**: `Promise<AccessGrant>`

```javascript
const grant = await client.requestAccess('prod/db_password', 'Running migrations', 300);
if (grant.granted) {
  console.log('Access granted until:', grant.expiresAt);
} else {
  console.log('Access denied');
}
```

#### `client.scrub(output)`

Remove secrets from output text.

- **output**: `string` - Output string that may contain secrets
- **Returns**: `Promise<string>`

```javascript
const scrubbed = await client.scrub('API key: sk_live_abc123');
// Returns: "API key: [REDACTED]"
```

#### `client.status()`

Get daemon status information.

- **Returns**: `Promise<DaemonStatusInfo>`

```javascript
const status = await client.status();
console.log('Daemon running:', status.running);
console.log('Uptime:', status.uptimeSecs, 'seconds');
console.log('Active sessions:', status.activeSessions);
console.log('Secrets loaded:', status.secretsLoaded);
```

### Types

#### `SecretMetadata`

Metadata about a secret.

```typescript
interface SecretMetadata {
  path: string;           // Secret path
  secretType: string;     // Secret type
  createdAt: string;      // Creation timestamp (RFC3339)
  updatedAt: string;      // Last update timestamp (RFC3339)
  tags: string[];         // Tags
  notes?: string;         // Notes
}
```

#### `AccessGrant`

Result of an access request.

```typescript
interface AccessGrant {
  granted: boolean;       // Whether access was granted
  expiresAt?: string;     // When the grant expires (if applicable)
}
```

#### `DaemonStatusInfo`

Daemon status information.

```typescript
interface DaemonStatusInfo {
  running: boolean;       // Whether the daemon is running
  uptimeSecs: number;     // Daemon uptime in seconds
  activeSessions: number; // Number of active sessions
  secretsLoaded: number;  // Number of secrets loaded
}
```

## TypeScript

TypeScript definitions are included:

```typescript
import { SigilClient, SecretMetadata, AccessGrant, DaemonStatusInfo } from '@sigil/sdk';

const client = new SigilClient();
await client.connect();

const key: string = await client.get('kalshi/api_key');
const secrets: SecretMetadata[] = await client.list('aws/');
const grant: AccessGrant = await client.requestAccess('prod/db', 'reason', 300);
const status: DaemonStatusInfo = await client.status();
```

## Requirements

- Node.js >= 16
- SIGIL daemon running (sigild)
- SIGIL socket available at default location or custom path

## License

MIT OR Apache-2.0
