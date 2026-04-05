# CI/CD

SIGIL supports CI/CD pipelines with sealed vaults and no-daemon mode.

## CI/CD Modes

### Mode 1: Sealed Vault

Export vault as encrypted file for CI:

```bash
# On local machine
sigil export ci-vault.sigil

# In CI pipeline
sigil import ci-vault.sigil
sigil exec 'deploy.sh'
sigil uninstall --purge
```

### Mode 2: Environment Variables

Export secrets as environment variables:

```bash
# In CI pipeline
export API_KEY=$(sigil get api_key --raw)
export DB_URL=$(sigil get database_url --raw)

./deploy.sh
```

### Mode 3: Team Vault

Use team vault for shared CI/CD secrets:

```bash
sigil team init --backend openbao
sigil exec 'deploy.sh'
```

## CI Configuration

### GitHub Actions

```yaml
name: Deploy
on: push
jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - name: Install SIGIL
        run: cargo install sigil-cli
      - name: Import vault
        run: sigil import ${{ secrets.SIGIL_VAULT }}
      - name: Health check
        run: sigil doctor --ci --min-score 90
      - name: Deploy
        run: sigil exec 'deploy.sh'
      - name: Cleanup
        run: sigil uninstall --purge
```

### GitLab CI

```yaml
deploy:
  script:
    - cargo install sigil-cli
    - sigil import $SIGIL_VAULT
    - sigil doctor --ci --min-score 90
    - sigil exec 'deploy.sh'
    - sigil uninstall --purge
```

## Secrets Management

### Encrypted Storage

Store vault in encrypted secrets manager:

```bash
# Export vault
sigil export ci-vault.sigil

# Encrypt with GPG
gpg --encrypt --recipient ci@example.com ci-vault.sigil

# Store in CI secrets
```

### Base64 Encoding

For CI systems that don't support binary files:

```bash
# Export and encode
sigil export ci-vault.sigil | base64 > ci-vault.b64

# In CI, decode and import
echo $SIGIL_VAULT | base64 -d > /tmp/vault.sigil
sigil import /tmp/vault.sigil
```

## Health Checks

Require minimum security score:

```bash
sigil doctor --ci --min-score 90
```

Exits with code 2 if score below threshold.

## No-Daemon Mode

For CI environments without daemon:

```bash
# Commands work without daemon
sigil get api_key --raw
sigil exec 'deploy.sh'
```

Limitations:
- No canary monitoring
- No session management
- No real-time alerts

## Best Practices

1. **Vault rotation**: Rotate CI vault regularly
2. **Least privilege**: CI vault only has production secrets
3. **Audit logs**: Collect and review CI audit logs
4. **Fail closed**: CI fails if health check fails
5. **Cleanup**: Remove vault after deployment

## Example Workflows

### Deployment

```bash
sigil import ci-vault.sigil
sigil exec 'kubectl apply -f manifests/'
sigil uninstall --keep-vault
```

### Testing

```bash
sigil import test-vault.sigil
sigil exec 'cargo test'
sigil uninstall --purge
```

### Build

```bash
export API_KEY=$(sigil get api_key --raw)
cargo build --release
```

## Troubleshooting

### Vault Not Found

```bash
# Verify vault file exists
ls -la ci-vault.sigil

# Check import
sigil import ci-vault.sigil --dry-run
```

### Permission Denied

```bash
# Fix file permissions
chmod 600 ci-vault.sigil
```

### Health Check Fails

```bash
# Run without CI flag for details
sigil doctor

# Fix issues and re-run
```
