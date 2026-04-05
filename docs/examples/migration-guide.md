# Migration Guide: Moving to SIGIL

This guide helps you migrate from other secret management systems to SIGIL.

## Overview

SIGIL can import secrets from various sources and formats, making it easy to switch from your current secret management solution.

## Supported Migration Sources

| Source | Method | Complexity |
|--------|--------|------------|
| **Environment variables** | Direct import | Simple |
| **.env files** | Import via CLI | Simple |
| **AWS Secrets Manager** | Export → Import | Moderate |
| **HashiCorp Vault** | Export → Import | Moderate |
| **1Password** | Export → Import | Moderate |
| **Docker secrets** | Import → Vault | Simple |
| **Kubernetes secrets** | Export → Import | Moderate |

## Migrating from Environment Variables

### Step 1: Identify Your Secrets

```bash
# List current environment variables containing secrets
env | grep -i "key\|token\|password\|secret" | sort
```

### Step 2: Add to SIGIL Vault

```bash
# For each secret, add it to SIGIL
sigil add aws/access_key_id
sigil add aws/secret_access_key
sigil add stripe/api_key
sigil add database/url
```

### Step 3: Create Project Manifest

Create `.sigil.toml` in your project root:

```toml
[project]
name = "my-app"

[[secrets]]
path = "aws/access_key_id"
env_var = "AWS_ACCESS_KEY_ID"

[[secrets]]
path = "aws/secret_access_key"
env_var = "AWS_SECRET_ACCESS_KEY"

[[secrets]]
path = "stripe/api_key"
env_var = "STRIPE_API_KEY"

[[secrets]]
path = "database/url"
env_var = "DATABASE_URL"
```

### Step 4: Update Your Application

Replace hardcoded environment variable access with SIGIL placeholders:

**Before:**
```bash
AWS_ACCESS_KEY_ID=xxx AWS_SECRET_ACCESS_KEY=yyy ./app
```

**After:**
```bash
sigil exec './app'
# SIGIL automatically injects environment variables
```

## Migrating from .env Files

### Simple Import

```bash
# Import all secrets from .env file
sigil import --env .env

# This automatically:
# - Parses KEY=value pairs
# - Converts keys to vault paths (e.g., API_KEY → api_key)
# - Prompts for each value
```

### Interactive Import with Custom Paths

```bash
# Import with custom path mapping
sigil import --env .env --map <<EOF
AWS_ACCESS_KEY_ID → aws/access_key_id
AWS_SECRET_ACCESS_KEY → aws/secret_access_key
DATABASE_URL → prod/database_url
STRIPE_API_KEY → stripe/api_key
EOF
```

### Preserve .env Structure

If you need to maintain .env files for compatibility:

```bash
# Create .env.sigil that references SIGIL secrets
cat > .env.sigil <<EOF
# Managed by SIGIL - do not edit manually
AWS_ACCESS_KEY_ID={{secret:aws/access_key_id}}
AWS_SECRET_ACCESS_KEY={{secret:aws/secret_access_key}}
DATABASE_URL={{secret:prod/database_url}}
STRIPE_API_KEY={{secret:stripe/api_key}}
EOF

# Use with SIGIL
sigil exec 'env $(subst-env < .env.sigil) ./app'
```

## Migrating from AWS Secrets Manager

### Step 1: Export from AWS

```bash
# Install AWS CLI if needed
pip install awscli

# Export secrets to JSON file
aws secretsmanager get-secret-value --secret-id prod/app/config \
  --query SecretString --output text > secrets.json

# Or export multiple secrets
for secret in $(aws secretsmanager list-secrets --query 'SecretList[*].Name' --output text); do
  aws secretsmanager get-secret-value --secret-id "$secret" \
    --query SecretString --output text > "${secret#*/}.json"
done
```

### Step 2: Convert to SIGIL Format

```python
#!/usr/bin/env python3
import json
import subprocess
import sys

def import_secret(name, value, secret_type="api_key"):
    """Import a secret into SIGIL vault"""
    # Convert name to vault path
    vault_path = name.lower().replace('_', '/')

    # Add to vault
    subprocess.run(
        ['sigil', 'add', vault_path],
        input=value.encode(),
        check=True
    )
    print(f"✓ Imported {name} → {vault_path}")

# Load secrets JSON
with open('secrets.json') as f:
    secrets = json.load(f)

# Import each secret
for key, value in secrets.items():
    import_secret(key, value)

print("\nAll secrets imported successfully!")
```

### Step 3: Update Application Code

**Before:**
```python
import boto3
session = boto3.session.Session()
client = session.client('secretsmanager')
secret = client.get_secret_value(SecretId='prod/app/config')
```

**After:**
```python
# Use environment variable populated by SIGIL
import os
database_url = os.environ['DATABASE_URL']
api_key = os.environ['API_KEY']
```

Run with SIGIL:
```bash
sigil exec 'python app.py'
```

## Migrating from HashiCorp Vault

### Step 1: Export from Vault

```bash
# Install Vault CLI
# https://www.vaultproject.io/downloads

# Export secret to JSON
vault kv get -format=json secret/prod/app > vault-secrets.json

# Or export multiple secrets
vault kv list -format=json secret/ | jq -r '.[]' | while read path; do
  vault kv get -format=json "secret/$path" > "$path.json"
done
```

### Step 2: Convert and Import

```bash
#!/bin/bash
# import-from-vault.sh

set -e

for file in *.json; do
  # Extract secret path and data
  path=$(jq -r '.data.metadata.path' "$file" | sed 's/secret\///')

  # Import each key-value pair
  jq -r '.data.data | to_entries[] | "\(.key) \(.value)"' "$file" | while read key value; do
    vault_path="${path}/${key}"
    echo "$value" | sigil add "$vault_path"
    echo "✓ Imported $vault_path"
  done
done
```

### Step 3: Update Configuration

Replace Vault references with SIGIL placeholders:

**Before (Consul template):**
```
{{ with secret "secret/prod/app" }}
DATABASE_URL="{{ .Data.data.database_url }}"
{{ end }}
```

**After (SIGIL):**
```
DATABASE_URL={{secret:prod/app/database_url}}
```

## Migrating from 1Password

### Step 1: Export from 1Password CLI

```bash
# Install 1Password CLI (op)
# https://developer.1password.com/docs/cli/get-started

# Authenticate
op account add

# Export items to JSON
op item list --format=json > items.json

# Or export specific vault
op item list --vault "Production" --format=json > prod-items.json
```

### Step 2: Import to SIGIL

```python
#!/usr/bin/env python3
import json
import subprocess
import sys

def import_1password_item(item):
    """Import a 1Password item to SIGIL"""
    title = item['overview']['title']
    vault_path = title.lower().replace(' ', '/')

    # Extract fields
    fields = item.get('fields', [])
    for field in fields:
        if field.get('value') and not field.get('designation', '').startswith('password'):
            field_name = field['label'].lower().replace(' ', '_')
            field_path = f"{vault_path}/{field_name}"

            # Add to vault
            subprocess.run(
                ['sigil', 'add', field_path],
                input=field['value'].encode(),
                check=True
            )
            print(f"✓ Imported {title}/{field['label']} → {field_path}")

# Load items
with open('prod-items.json') as f:
    items = json.load(f)

# Import each item
for item in items:
    import_1password_item(item)

print("\nAll 1Password items imported!")
```

### Step 3: Update Code References

Replace 1Password references with SIGIL environment variables:

**Before:**
```javascript
// Using 1Password CLI
const apiKey = execSync('op item get "API Key" --fields label=password').toString();
```

**After:**
```javascript
// Using SIGIL
const apiKey = process.env.API_KEY;
```

## Migrating from Docker Secrets

### Step 1: Export from Docker

```bash
# List all secrets
docker secret ls

# Export each secret to a file
docker secret inspect <secret-name> -f '{{index .Spec.Name 0}}' > secret.txt
```

### Step 2: Import to SIGIL

```bash
#!/bin/bash
# import-docker-secrets.sh

for secret_name in "$@"; do
  # Get secret value
  secret_value=$(docker secret inspect "$secret_name" -f '{{index .Spec.Name 0}}')

  # Import to SIGIL
  echo "$secret_value" | sigil add "docker/${secret_name}"

  echo "✓ Imported docker/${secret_name}"
done
```

### Step 3: Update Docker Compose

**Before:**
```yaml
services:
  app:
    secrets:
      - db_password
      - api_key

secrets:
  db_password:
    external: true
  api_key:
    external: true
```

**After:**
```yaml
services:
  app:
    environment:
      - DB_PASSWORD={{secret:docker/db_password}}
      - API_KEY={{secret:docker/api_key}}
    entrypoint: ["sigil", "exec", "./app"]
```

## Migrating from Kubernetes Secrets

### Step 1: Export from Kubernetes

```bash
# Export all secrets in a namespace
kubectl get secrets -n production -o json > secrets.json

# Or export specific secret
kubectl get secret db-credentials -n production -o json > db-credentials.json
```

### Step 2: Decode and Import

```bash
#!/bin/bash
# import-k8s-secret.sh

secret_file="$1"
namespace="$2"

# Extract secret data and decode base64 values
jq -r ".data | to_entries[] | \"\(.key) \(.value)\"" "$secret_file" | while read key value; do
  # Decode base64
  decoded_value=$(echo "$value" | base64 -d)

  # Import to SIGIL
  echo "$decoded_value" | sigil add "${namespace}/${key}"

  echo "✓ Imported ${namespace}/${key}"
done
```

Usage:
```bash
import-k8s-secret.sh db-credentials.json production
```

### Step 3: Update Kubernetes Deployments

Replace Secret volume mounts with SIGIL environment variables:

**Before:**
```yaml
apiVersion: v1
kind: Pod
spec:
  containers:
    - name: app
      env:
        - name: DB_PASSWORD
          valueFrom:
            secretKeyRef:
              name: db-credentials
              key: password
```

**After:**
```yaml
apiVersion: v1
kind: Pod
spec:
  containers:
    - name: app
      command: ["sigil", "exec", "./app"]
      env:
        - name: DB_PASSWORD
          value: "{{secret:production/db_password}}"
```

## Verification

After migration, verify everything works:

```bash
# List all imported secrets
sigil list

# Test secret access
sigil get aws/access_key_id

# Test command execution
sigil exec 'aws s3 ls'

# Run health check
sigil doctor

# Check for any remaining plaintext secrets
sigil lint .
```

## Rollback Plan

Keep your old secret system running until you've verified SIGIL works correctly:

1. **Parallel operation**: Run both systems during migration period
2. **Gradual cutover**: Switch applications one at a time
3. **Validation**: Test each application thoroughly
4. **Backup**: Keep export files until verification is complete

## Post-Migration Cleanup

After successful migration:

```bash
# Remove old secret files (carefully!)
# Make sure you have backups first

# Remove .env files (replaced by SIGIL)
rm .env .env.local .env.production

# Update .gitignore
echo ".env" >> .gitignore
echo ".env.*" >> .gitignore

# Commit changes
git add .
git commit -m "Migrate to SIGIL for secret management"
```

## Troubleshooting

### Secret Not Found

```bash
# Check if secret exists
sigil list | grep -i "database"

# Add missing secret
sigil add production/database_url
```

### Wrong Secret Value

```bash
# Get current value for verification
sigil get production/api_key

# Update secret
sigil edit production/api_key

# Or rollback to previous version
sigil rollback production/api_key --to 1
```

### Import Failed

```bash
# Check vault status
sigil doctor

# Re-run import with verbose output
sigil import --env .env --verbose
```

## Next Steps

- [Quickstart Guide](../quickstart.md) — Basic SIGIL usage
- [CI/CD Integration](./ci-cd-integration.md) — Using SIGIL in CI/CD
- [Team Vault](../topics/team.md) — Multi-user secret management
- [Security Best Practices](../concepts.md#threat-model) — Secure secret handling
