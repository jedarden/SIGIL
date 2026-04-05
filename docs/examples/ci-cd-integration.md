# CI/CD Integration with SIGIL

This example demonstrates how to use SIGIL in continuous integration and deployment pipelines while keeping secrets secure.

## Overview

SIGIL supports two primary CI/CD workflows:

1. **Daemon mode**: Full SIGIL daemon with sealed vault (recommended for production)
2. **No-daemon mode**: Direct vault access without daemon (simpler, but fewer features)

## Option 1: Sealed Vault (Recommended)

The sealed vault mode stores secrets in a single encrypted file (`.sigil/vault.sealed`) that can be safely committed to git. The device key stays local and never enters version control.

### Setup

```bash
# Initialize with git-safe vault
sigil init --git-safe

# This creates:
# - .sigil/vault.sealed (encrypted, git-committable)
# - .sigil/device.key (local only, added to .gitignore)
# - .sigil/config.toml (configuration)
```

### Add Secrets Locally

```bash
# Add secrets to your local vault
sigil add production/database_url
sigil add production/api_key
sigil add deploy/ssh_key
```

### Export Device Key for CI

```bash
# Generate a CI-specific device key
sigil enroll-device --name "github-actions"

# This outputs:
# - Device key: <base64-encoded-key>
# - Vault fingerprint: <sha256-hash>
```

### Configure CI Provider

#### GitHub Actions

```yaml
# .github/workflows/deploy.yml
name: Deploy to Production

on:
  push:
    branches: [main]

jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Install SIGIL
        run: |
          curl -sSL https://github.com/jedarden/sigil/releases/download/v0.1.0/sigil-linux-amd64 -o sigil
          chmod +x sigil
          sudo mv sigil /usr/local/bin/

      - name: Unseal vault
        env:
          SIGIL_DEVICE_KEY: ${{ secrets.SIGIL_DEVICE_KEY }}
        run: |
          echo "$SIGIL_DEVICE_KEY" | base64 -d > /tmp/sigil-ci.key
          sigil-ci unseal --device-key /tmp/sigil-ci.key --vault .sigil/vault.sealed
          rm /tmp/sigil-ci.key

      - name: Deploy application
        run: |
          sigil exec 'deploy.sh'
        env:
          SIGIL_VAULT: .sigil/vault.sealed

      - name: Run tests
        run: |
          sigil exec 'cargo test --features integration'
        env:
          SIGIL_VAULT: .sigil/vault.sealed
```

#### GitLab CI

```yaml
# .gitlab-ci.yml
stages:
  - test
  - deploy

variables:
  SIGIL_VAULT: "$CI_PROJECT_DIR/.sigil/vault.sealed"

before_script:
  - curl -sSL https://github.com/jedarden/sigil/releases/download/v0.1.0/sigil-linux-amd64 -o sigil
  - chmod +x sigil
  - sudo mv sigil /usr/local/bin/

test:
  stage: test
  script:
    - echo "$SIGIL_DEVICE_KEY" | base64 -d > /tmp/sigil-ci.key
    - sigil-ci unseal --device-key /tmp/sigil-ci.key --vault .sigil/vault.sealed
    - sigil exec 'cargo test'
    - rm /tmp/sigil-ci.key

deploy:
  stage: deploy
  script:
    - echo "$SIGIL_DEVICE_KEY" | base64 -d > /tmp/sigil-ci.key
    - sigil-ci unseal --device-key /tmp/sigil-ci.key --vault .sigil/vault.sealed
    - sigil exec 'kubectl apply -f manifests/'
    - rm /tmp/sigil-ci.key
  only:
    - main
```

#### Argo Workflows

```yaml
# .argo/workflows/deploy.yaml
apiVersion: argoproj.io/v1alpha1
kind: Workflow
metadata:
  name: deploy-app
spec:
  entrypoint: deploy
  templates:
    - name: deploy
      steps:
        - - name: checkout
            template: checkout

        - - name: test
            template: test

        - - name: deploy
            template: deploy-to-prod

    - name: checkout
      container:
        image: alpine/git:latest
      command:
        - git
        args:
        - clone
        - https://github.com/your-org/your-repo.git

    - name: test
      container:
        image: your-org/sigil-ci:latest
        command:
          - sigil
        args:
        - exec
        - cargo test
      env:
        - name: SIGIL_DEVICE_KEY
          valueFrom:
            secretKeyRef:
              name: sigil-device-key
              key: key

    - name: deploy-to-prod
      container:
        image: your-org/sigil-ci:latest
        command:
          - sigil
        args:
        - exec
        - kubectl apply -f manifests/
      env:
        - name: SIGIL_DEVICE_KEY
          valueFrom:
            secretKeyRef:
              name: sigil-device-key
              key: key
```

### Store Device Key as Secret

Add the device key to your CI provider's secret store:

**GitHub Actions:**
1. Go to repository Settings → Secrets and variables → Actions
2. Click "New repository secret"
3. Name: `SIGIL_DEVICE_KEY`
4. Value: Paste the base64-encoded device key from `sigil enroll-device`

**GitLab CI:**
1. Go to Settings → CI/CD → Variables
2. Add variable: `SIGIL_DEVICE_KEY`
3. Value: Paste the base64-encoded device key
4. Mask variable: Enabled

**Kubernetes (for Argo Workflows):**
```bash
kubectl create secret generic sigil-device-key \
  --from-file=key=device-key-base64.txt \
  --namespace=argo-workflows
```

## Option 2: No-Daemon Mode (Simpler)

For simpler CI setups, you can use SIGIL without the daemon. This mode reads secrets directly from the vault file without the full daemon IPC layer.

### Setup

```bash
# Standard vault initialization
sigil init

# Export secrets to environment variables
eval $(sigil export --env)
```

### Example Configuration

```yaml
# GitHub Actions with no-daemon mode
- name: Export secrets
  run: |
    echo "SIGIL_VAULT_PASSPHRASE=${{ secrets.SIGIL_VAULT_PASSPHRASE }}" >> $GITHUB_ENV

- name: Run tests
  env:
    SIGIL_VAULT_PASSPHRASE: ${{ secrets.SIGIL_VAULT_PASSPHRASE }}
  run: |
    # Export secrets as environment variables
    eval $(sigil export --env)

    # Run tests with secrets in environment
    cargo test --features integration
```

### Limitations of No-Daemon Mode

- No output scrubbing (secrets may appear in CI logs)
- No session management
- No audit logging
- Secrets exist in process environment during execution

## Best Practices

### 1. Use Separate Environments

```bash
# Development
sigil add development/api_key

# Staging
sigil add staging/api_key

# Production
sigil add production/api_key
```

### 2. Rotate CI Device Keys Regularly

```bash
# Rotate device key every 90 days
sigil rotate-ci-key

# Update CI secret with new device key
```

### 3. Use SIGIL Doctor in CI

```yaml
- name: Health check
  run: sigil doctor --ci
```

The `--ci` flag:
- Exits non-zero if configuration is invalid
- Outputs JSON for parsing
- Checks vault integrity
- Validates device key

### 4. Lock Down on Breach Detection

```yaml
- name: Deploy with canary
  run: |
    # Deploy with canary monitoring
    sigil exec 'deploy.sh --with-canary'

    # Check for canary triggers
    if sigil breach-report --check; then
      echo "Canary triggered! Initiating lockdown..."
      sigil lockdown
      exit 1
    fi
```

### 5. Audit Secret Access

```yaml
- name: Deploy with audit
  run: |
    # Deploy and capture audit log
    sigil exec 'deploy.sh'

    # Upload audit log to compliance system
    sigil audit --since "1 hour ago" > audit.json
    curl -X POST \
      -H "Authorization: Bearer $COMPLIANCE_API_KEY" \
      -F "audit=@audit.json" \
      https://compliance.example.com/api/audit
```

## Docker Integration

### Dockerfile with SIGIL

```dockerfile
FROM rust:1.70 as builder
WORKDIR /app
COPY . .
RUN cargo build --release

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y ca-certificates curl
COPY --from=builder /app/target/release/sigil /usr/local/bin/sigil
COPY . /app
WORKDIR /app
ENTRYPOINT ["sigil", "exec", "./app"]
```

### docker-compose.yml

```yaml
version: '3.8'
services:
  app:
    build: .
    environment:
      - SIGIL_VAULT=/app/.sigil/vault.sealed
      - SIGIL_DEVICE_KEY_FILE=/run/secrets/sigil_key
    secrets:
      - sigil_key

secrets:
  sigil_key:
    file: ./device-key.txt
```

## Kubernetes Integration

### Using External Secrets Operator

```yaml
# ExternalSecret for SIGIL vault
apiVersion: external-secrets.io/v1beta1
kind: ExternalSecret
metadata:
  name: app-secrets
spec:
  refreshInterval: 1h
  secretStoreRef:
    name: sigil-vault
    kind: SecretStore
  target:
    name: app-secrets
    creationPolicy: Owner
  data:
    - secretKey: DATABASE_URL
      remoteRef:
        key: production/database_url

---
# SecretStore pointing to SIGIL
apiVersion: external-secrets.io/v1beta1
kind: SecretStore
metadata:
  name: sigil-vault
spec:
  provider:
    sigil:
      endpoint: http://sigild.default.svc.cluster.local
```

## Troubleshooting

### Vault Won't Unseal in CI

```bash
# Check device key validity
sigil doctor --ci --verbose

# Re-enroll device if needed
sigil enroll-device --name "github-actions" --rotate
```

### Secrets Not Injected

```bash
# Verify vault path
echo $SIGIL_VAULT

# Check vault contents
sigil list

# Test secret access
sigil get production/api_key
```

### Permission Errors

```bash
# Ensure device key has correct permissions
chmod 600 /tmp/sigil-ci.key

# Check vault file permissions
ls -la .sigil/vault.sealed
```

## Security Considerations

1. **Never commit device keys**: Device keys should always be stored as CI/CD secrets
2. **Rotate device keys regularly**: Every 90 days for production systems
3. **Use separate device keys per environment**: Dev, staging, and production should have different keys
4. **Enable audit logging**: Track all secret access in CI/CD pipelines
5. **Use lockdown for breaches**: Immediately revoke access if a breach is detected
6. **Scan for secrets in commits**: Use `sigil lint` as a pre-commit hook

## Next Steps

- [Migration Guide](../topics/migrate.md) — Migrating from other secret managers
- [Team Vault](../topics/team.md) — Multi-user secret management
- [CI/CD Topic](../topics/ci.md) — CI-specific SIGIL features
