# 🐍 Python Integration Guide

> Using SIGIL with Python projects and frameworks for secure secret management in AI-assisted development.

---

## 📋 Prerequisites

- SIGIL installed and initialized
- Python 3.8+ installed
- A Python project or script that uses API keys, database credentials, or other secrets

---

## 🚀 Quick Start

### Basic Python Script with SIGIL

Create a Python script that uses SIGIL placeholders for environment variables:

```python
#!/usr/bin/env python3
"""Example: Using SIGIL with Python"""

import os
import requests

# These will be resolved by SIGIL before the script runs
API_KEY = os.environ['MY_API_KEY']
DATABASE_URL = os.environ['DATABASE_URL']

def fetch_data():
    """Fetch data from API using SIGIL-managed secret"""
    response = requests.get(
        'https://api.example.com/data',
        headers={'Authorization': f'Bearer {API_KEY}'}
    )
    return response.json()

def main():
    data = fetch_data()
    print(f"Fetched {len(data)} items")

if __name__ == '__main__':
    main()
```

Run with SIGIL:

```bash
# Add secrets to your vault first
sigil add my/api_key
sigil add database/url

# Execute with automatic secret injection
sigil exec -- python3 script.py
```

---

## 🎯 Common Patterns

### Pattern 1: Direct Placeholder in Commands

```bash
# Single command with inline secret
sigil exec -- python3 -c "
import requests
resp = requests.get('https://api.example.com', headers={
    'Authorization': 'Bearer {{secret:my/api_key}}'
})
print(resp.json())
"
```

### Pattern 2: Environment Variable Injection

```bash
# SIGIL automatically creates environment variables from secret paths
sigil exec -- MY_API_KEY={{secret:my/api_key}} python3 script.py
```

### Pattern 3: Configuration File with Placeholders

Create a `config.py` that uses placeholders:

```python
# config.py
import os

class Config:
    API_KEY = os.environ.get('API_KEY', '{{secret:my/api_key}}')
    DB_URL = os.environ.get('DB_URL', '{{secret:database/url}}')
```

Then run with SIGIL:

```bash
sigil exec -- python3 app.py
```

---

## 🔗 Framework Integration

### Django Settings

```python
# settings.py
import os
import warnings

def get_secret(key, default=None):
    """Get secret from environment, warning if using default placeholder"""
    value = os.environ.get(key, default)
    if value and value.startswith('{{secret:'):
        warnings.warn(f"Secret {key} not resolved - SIGIL may not be active")
    return value

SECRET_KEY = get_secret('DJANGO_SECRET_KEY', '{{secret:django/secret_key}}')
DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.postgresql',
        'NAME': get_secret('DB_NAME', '{{secret:database/name}}'),
        'USER': get_secret('DB_USER', '{{secret:database/user}}'),
        'PASSWORD': get_secret('DB_PASSWORD', '{{secret:database/password}}'),
        'HOST': get_secret('DB_HOST', '{{secret:database/host}}'),
        'PORT': get_secret('DB_PORT', '5432'),
    }
}

# Third-party API keys
STRIPE_SECRET_KEY = get_secret('STRIPE_KEY', '{{secret:stripe/api_key}}')
AWS_SECRET_ACCESS_KEY = get_secret('AWS_SECRET', '{{secret:aws/secret_access_key}}')
```

Run Django management commands:

```bash
sigil exec -- python manage.py migrate
sigil exec -- python manage.py runserver
```

### Flask Application

```python
# app.py
from flask import Flask
import os

app = Flask(__name__)

# SIGIL resolves these before the app starts
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', '{{secret:flask/secret_key}}')
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get(
    'DATABASE_URL',
    '{{secret:database/url}}'
)

@app.route('/')
def home():
    return "App running with SIGIL-managed secrets"

if __name__ == '__main__':
    # Use 0.0.0.0 so it's accessible inside the SIGIL sandbox
    app.run(host='0.0.0.0', port=5000, debug=False)
```

### FastAPI with Async

```python
# main.py
from fastapi import FastAPI
import os
import asyncio
import httpx

app = FastAPI()

API_KEY = os.environ.get('API_KEY', '{{secret:my/api_key}}')

@app.get("/")
async def root():
    return {"status": "running", "sigil": "active"}

@app.get("/external-api")
async def call_external():
    async with httpx.AsyncClient() as client:
        response = await client.get(
            'https://api.example.com/data',
            headers={'Authorization': f'Bearer {API_KEY}'}
        )
        return response.json()
```

---

## 🧪 Testing with SIGIL

### pytest Configuration

Create a `conftest.py` for SIGIL-aware tests:

```python
# conftest.py
import os
import pytest

def check_sigil_active():
    """Warn if running tests without SIGIL"""
    if any(v.startswith('{{secret:') for v in os.environ.values() if v):
        pytest.skip("SIGIL not active - secrets not resolved. Run: sigil exec -- pytest")

@pytest.fixture(autouse=True)
def verify_sigil():
    """Automatically verify SIGIL is active for tests that need secrets"""
    check_sigil_active()
```

Run tests with SIGIL:

```bash
sigil exec -- pytest -v
```

### Mock Mode for CI

Create a test-only secrets file:

```bash
# For CI where SIGIL isn't available
export API_KEY="test_key_123"
export DB_URL="postgresql://test:test@localhost/test_db"

pytest
```

---

## 🐳 Docker Integration

### Dockerfile with SIGIL

```dockerfile
FROM python:3.11-slim

WORKDIR /app

# Install SIGIL in the container (optional - alternative: bind-mount from host)
RUN cargo install sigil-cli

# Copy application files
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# SIGIL vault will be mounted as a volume
VOLUME ["/root/.sigil"]

# Default command - assumes secrets are in vault
CMD ["sigil", "exec", "--", "python", "app.py"]
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
      - SIGIL_VAULT_PATH=/root/.sigil/vault
    # SIGIL resolves secrets before Python starts
    command: ["sigil", "exec", "--", "python", "app.py"]
```

---

## 🔒 Security Best Practices

### 1. Never Hardcode Secrets

```python
# ❌ BAD - hardcoded in source
API_KEY = "sk-live-abc123xyz789"

# ✅ GOOD - placeholder for SIGIL
API_KEY = os.environ.get('API_KEY', '{{secret:my/api_key}}')
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
command = "python manage.py migrate"
secrets = ["database/url"]

[[operations]]
name = "test"
command = "pytest"
secrets = ["my/api_key"]
```

### 3. Validate Secrets at Startup

```python
# app.py
import os
import sys

def require_env(key):
    """Require an environment variable to be set"""
    value = os.environ.get(key)
    if not value or value.startswith('{{secret:'):
        print(f"Error: {key} not set. Run with: sigil exec -- python app.py")
        sys.exit(1)
    return value

API_KEY = require_env('API_KEY')
DB_URL = require_env('DATABASE_URL')
```

---

## 🚧 Known Limitations

- **Debuggers**: Running Python with `pdb` or IDE debuggers may bypass SIGIL's hooks. Use `sigil exec` before the debugger command.
- **Jupyter Notebooks**: SIGIL placeholders in notebook cells won't be resolved. Use environment variables: `os.environ['KEY']` and run Jupyter with `sigil exec -- jupyter notebook`.
- **Multiprocessing**: Child processes spawned via `multiprocessing` inherit environment variables but not SIGIL's process tracking. Use environment variables for secrets in these cases.

---

## 👉 Next Steps

- Return to [Examples Index](README.md)
- Read [Basic Workflow](basic-workflow.md) for SIGIL fundamentals
- Read [Security Best Practices](security-best-practices.md)
- Read [CI/CD Integration](ci-cd-integration.md) for pipeline setup
