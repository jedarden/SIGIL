# 🟢 Node.js Integration Guide

> Using SIGIL with Node.js projects and frameworks for secure secret management in AI-assisted development.

---

## 📋 Prerequisites

- SIGIL installed and initialized
- Node.js 16+ installed
- A Node.js project that uses API keys, database credentials, or other secrets

---

## 🚀 Quick Start

### Basic Node.js Script with SIGIL

Create a Node.js script that uses SIGIL placeholders for environment variables:

```javascript
#!/usr/bin/env node
/**
 * Example: Using SIGIL with Node.js
 */

import fetch from 'node-fetch';

// These will be resolved by SIGIL before the script runs
const API_KEY = process.env.MY_API_KEY;
const DATABASE_URL = process.env.DATABASE_URL;

async function fetchData() {
  // Fetch data from API using SIGIL-managed secret
  const response = await fetch('https://api.example.com/data', {
    headers: {
      'Authorization': `Bearer ${API_KEY}`
    }
  });
  return response.json();
}

async function main() {
  const data = await fetchData();
  console.log(`Fetched ${data.length} items`);
}

main().catch(console.error);
```

Run with SIGIL:

```bash
# Add secrets to your vault first
sigil add my/api_key
sigil add database/url

# Execute with automatic secret injection
sigil exec -- node script.js
```

---

## 🎯 Common Patterns

### Pattern 1: Direct Placeholder in Commands

```bash
# Single command with inline secret
sigil exec -- node -e "
const fetch = require('node-fetch');
fetch('https://api.example.com', {
  headers: { 'Authorization': 'Bearer {{secret:my/api_key}}' }
})
.then(r => r.json())
.then(console.log);
"
```

### Pattern 2: Environment Variable Injection

```bash
# SIGIL automatically creates environment variables from secret paths
sigil exec -- MY_API_KEY={{secret:my/api_key}} node script.js
```

### Pattern 3: Configuration File with Placeholders

Create a `config.js` that uses placeholders:

```javascript
// config.js
const config = {
  apiKey: process.env.API_KEY || '{{secret:my/api_key}}',
  dbUrl: process.env.DB_URL || '{{secret:database/url}}',
  port: process.env.PORT || 3000,
};

// Warn if placeholders weren't resolved
if (config.apiKey.startsWith('{{secret:')) {
  console.warn('WARNING: API_KEY not resolved - SIGIL may not be active');
}

module.exports = config;
```

Then run with SIGIL:

```bash
sigil exec -- node app.js
```

---

## 🔗 Framework Integration

### Express.js Application

```javascript
// app.js
import express from 'express';
import fetch from 'node-fetch';

const app = express();
const PORT = process.env.PORT || 3000;

// SIGIL resolves these before the app starts
const API_KEY = process.env.API_KEY || '{{secret:my/api_key}}';
const DB_URL = process.env.DB_URL || '{{secret:database/url}}';

app.get('/', (req, res) => {
  res.json({ status: 'running', sigil: 'active' });
});

app.get('/external-api', async (req, res) => {
  const response = await fetch('https://api.example.com/data', {
    headers: { 'Authorization': `Bearer ${API_KEY}` }
  });
  const data = await response.json();
  res.json(data);
});

// Use 0.0.0.0 so it's accessible inside the SIGIL sandbox
app.listen(PORT, '0.0.0.0', () => {
  console.log(`Server running on port ${PORT}`);
});
```

### NestJS Application

```typescript
// app.config.ts
export default () => ({
  port: parseInt(process.env.PORT, 10) || 3000,
  database: {
    url: process.env.DATABASE_URL || '{{secret:database/url}}',
  },
  api: {
    key: process.env.API_KEY || '{{secret:my/api_key}}',
  },
});

// app.module.ts
import { Module } from '@nestjs/common';
import { ConfigModule } from '@nestjs/config';

@Module({
  imports: [
    ConfigModule.forRoot({
      isGlobal: true,
      validate: (config) => {
        // Warn if SIGIL placeholders weren't resolved
        if (config.API_KEY?.startsWith('{{secret:')) {
          console.warn('WARNING: API_KEY not resolved - run with SIGIL');
        }
        return config;
      },
    }),
  ],
})
export class AppModule {}
```

### Next.js Application

```javascript
// next.config.js
module.exports = {
  env: {
    // SIGIL resolves these at build/run time
    API_KEY: process.env.API_KEY || '{{secret:my/api_key}}',
    DATABASE_URL: process.env.DATABASE_URL || '{{secret:database/url}}',
  },
};

// lib/api.js
export async function fetchFromAPI() {
  const response = await fetch('https://api.example.com/data', {
    headers: {
      'Authorization': `Bearer ${process.env.API_KEY}}`,
    },
  });
  return response.json();
}
```

### Server-Side Rendering with React

```javascript
// server.js
import express from 'express';
import React from 'react';
import { renderToString } from 'react-dom/server';

const app = express();

// SIGIL-resolved environment variables
const API_KEY = process.env.API_KEY;

app.get('/', (req, res) => {
  const html = renderToString(
    React.createElement('div', null,
      React.createElement('h1', null, 'SSR App'),
      React.createElement('p', null, `API Key: ${API_KEY.slice(0, 4)}***`)
    )
  );
  res.send(html);
});

app.listen(3000);
```

---

## 🧪 Testing with SIGIL

### Jest Configuration

Create a `setupEnv.js` for SIGIL-aware tests:

```javascript
// setupEnv.js
// Warn if running tests without SIGIL
if (Object.values(process.env).some(v => v?.startsWith('{{secret:'))) {
  console.warn('WARNING: SIGIL not active - secrets not resolved.');
  console.warn('Run tests with: sigil exec -- npm test');
  process.exit(1);
}
```

Update `jest.config.js`:

```javascript
module.exports = {
  setupFiles: ['<rootDir>/setupEnv.js'],
  testEnvironment: 'node',
};
```

Run tests with SIGIL:

```bash
sigil exec -- npm test
```

### Vitest Configuration

```javascript
// vitest.config.js
import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    setupFiles: ['./setupEnv.js'],
    environment: 'node',
  },
});
```

### Mock Mode for CI

Create a test-only `.env.test` file:

```bash
# .env.test - For CI where SIGIL isn't available
API_KEY=test_key_123
DB_URL=postgresql://test:test@localhost/test_db

# Run tests
npm test
```

---

## 🐳 Docker Integration

### Dockerfile with SIGIL

```dockerfile
FROM node:20-alpine

WORKDIR /app

# Install SIGIL in the container
RUN apk add --no-cache cargo
RUN cargo install sigil-cli

# Copy package files
COPY package*.json ./
RUN npm ci --only=production

# Copy application files
COPY . .

# SIGIL vault will be mounted as a volume
VOLUME ["/root/.sigil"]

# Default command - assumes secrets are in vault
CMD ["sigil", "exec", "--", "node", "app.js"]
```

### docker-compose.yml

```yaml
version: '3.8'

services:
  app:
    build: .
    volumes:
      # Mount SIGIL vault from host
      - ~/.sigil:/root/.sigil:ro
      # Mount application code
      - .:/app
    environment:
      - NODE_ENV=production
      - SIGIL_VAULT_PATH=/root/.sigil/vault
    # SIGIL resolves secrets before Node starts
    command: ["sigil", "exec", "--", "node", "app.js"]
    ports:
      - "3000:3000"
```

---

## 🔒 Security Best Practices

### 1. Never Hardcode Secrets

```javascript
// ❌ BAD - hardcoded in source
const API_KEY = "sk-live-abc123xyz789";

// ✅ GOOD - placeholder for SIGIL
const API_KEY = process.env.API_KEY || '{{secret:my/api_key}}';
```

### 2. Use .sigil.toml for Project Secrets

Create `.sigil.toml` in your project root:

```toml
# .sigil.toml - SIGIL project manifest

[secrets]
# Required secrets for this project
my/api_key = "API key for external service"
database/url = "PostgreSQL connection string"
stripe/webhook_secret = "Stripe webhook verification secret"

[[operations]]
name = "migrate"
command = "npm run migrate"
secrets = ["database/url"]

[[operations]]
name = "test"
command = "npm test"
secrets = ["my/api_key"]
```

### 3. Validate Secrets at Startup

```javascript
// utils/config.js
function requireEnv(key) {
  const value = process.env[key];
  if (!value || value.startsWith('{{secret:')) {
    console.error(`Error: ${key} not set.`);
    console.error(`Run with: sigil exec -- node app.js`);
    process.exit(1);
  }
  return value;
}

export const config = {
  apiKey: requireEnv('API_KEY'),
  dbUrl: requireEnv('DATABASE_URL'),
};
```

### 4. Use SIGIL SDK for Direct Access

```javascript
import { SigilClient } from '@sigil/sdk';

async function main() {
  // Connect to the SIGIL daemon
  const client = await SigilClient.connect();

  // Get a secret value
  const apiKey = await client.get('my/api_key');

  // Check if a secret exists
  const hasDbUrl = await client.exists('database/url');

  // List secrets
  const secrets = await client.list('aws/');

  // Resolve placeholders
  const resolved = await client.resolve('Bearer {{secret:my/api_key}}');

  // Request access (triggers TUI approval)
  const grant = await client.requestAccess(
    'prod/db_password',
    'Running migrations',
    300 // 5 minutes
  );

  // Scrub secrets from output
  const safe = await client.scrub('API key: sk_live_abc123');

  // Get daemon status
  const status = await client.status();
}

main().catch(console.error);
```

---

## 🚧 Known Limitations

- **Debuggers**: Running Node.js with `--inspect` or IDE debuggers may bypass SIGIL's hooks. Use `sigil exec` before the debug command.
- **Hot Reload**: Tools like `nodemon` restart the process but may not properly inherit SIGIL's environment. Use environment variables instead.
- **Worker Threads**: Worker threads in Node.js don't inherit all environment variables. Pass secrets explicitly via worker data.
- **Bundlers**: Tools like `webpack` or `esbuild` may embed SIGIL placeholders in bundles if build runs outside SIGIL. Build with `sigil exec -- npm run build`.

---

## 📦 Package Manager Integration

### npm scripts

```json
{
  "scripts": {
    "dev": "sigil exec -- node watch.js",
    "start": "sigil exec -- node app.js",
    "test": "sigil exec -- jest",
    "build": "sigil exec -- webpack --mode production",
    "migrate": "sigil exec -- node migrate.js"
  }
}
```

### pnpm scripts

```json
{
  "scripts": {
    "dev": "sigil exec -- pnpm nodemon",
    "start": "sigil exec -- pnpm node src/index.js"
  }
}
```

### Yarn scripts

```json
{
  "scripts": {
    "dev": "sigil exec -- yarn nodemon",
    "start": "sigil exec -- yarn node src/index.js"
  }
}
```

---

## 🛠️ Development Workflow

### TypeScript Integration

```typescript
// types/env.d.ts
declare global {
  namespace NodeJS {
    interface ProcessEnv {
      API_KEY?: string;
      DATABASE_URL?: string;
      PORT?: string;
    }
  }
}

export {};

// config.ts
interface Config {
  apiKey: string;
  databaseUrl: string;
  port: number;
}

export function loadConfig(): Config {
  const apiKey = process.env.API_KEY || '{{secret:my/api_key}}';

  if (apiKey.startsWith('{{secret:')) {
    throw new Error('API_KEY not resolved - run with SIGIL');
  }

  return {
    apiKey,
    databaseUrl: process.env.DATABASE_URL || '{{secret:database/url}}',
    port: parseInt(process.env.PORT || '3000', 10),
  };
}
```

### Using with ts-node

```bash
# Development with ts-node
sigil exec -- ts-node src/index.ts

# With nodemon
sigil exec -- nodemon --exec ts-node src/index.ts
```

### Using with tsx

```bash
# Fast TypeScript execution
sigil exec -- tsx src/index.ts

# Watch mode
sigil exec -- tsx watch src/index.ts
```

---

## 👉 Next Steps

- Return to [Examples Index](README.md)
- Read [Basic Workflow](basic-workflow.md) for SIGIL fundamentals
- Read [Security Best Practices](security-best-practices.md)
- Read [CI/CD Integration](ci-cd-integration.md) for pipeline setup
- Explore [SIGIL SDK for Node.js](https://www.npmjs.com/package/@sigil/sdk)
