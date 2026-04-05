# @sigil/sdk - Node.js SDK for SIGIL

Node.js native bindings for SIGIL secret management system.

## Installation

```bash
npm install @sigil/sdk
```

## Usage

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

// Check if a secret exists
const exists = await client.exists('aws/access_key_id');
console.log('Exists:', exists);

// List secrets
const secrets = await client.list('aws/');
console.log('Secrets:', secrets);

// Request access (triggers TUI approval)
const result = await client.requestAccess('prod/db_password', 'running migrations');
if (result.granted) {
  console.log('Access granted until:', result.expires_at);
}
```

## TypeScript

TypeScript definitions are included:

```typescript
import { SigilClient, SecretMetadata, AccessRequestResult } from '@sigil/sdk';

const client = new SigilClient();
await client.connect();

const key: string = await client.get('kalshi/api_key');
const secrets: SecretMetadata[] = await client.list('aws/');
const result: AccessRequestResult = await client.requestAccess('prod/db', 'reason');
```

## Requirements

- Node.js >= 16
- SIGIL daemon running (sigild)
- SIGIL socket available at ~/.sigil/sigild.sock or SIGIL_SOCKET env var

## License

MIT OR Apache-2.0
