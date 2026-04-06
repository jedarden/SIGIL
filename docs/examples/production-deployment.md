# 🏭 Production Deployment Guide

> Deploy SIGIL in production environments with confidence.

---

## 📋 Prerequisites

- SIGIL installed and tested in development
- Understanding of your threat model
- Production access controls
- Monitoring infrastructure

---

## 🚀 Pre-Deployment Checklist

### 1. Security Assessment

```bash
# Run comprehensive health check
sigil doctor --min-score 95

# Run red-team testing
sigil red-team --profile prod --duration 15m

# Verify audit logging
sigil audit log --since 1h | head -20
```

**Requirements:**
- [ ] Health score ≥ 95
- [ ] All critical security checks pass
- [ ] Red-team tests complete with no critical failures
- [ ] Audit logging is configured and functional

### 2. Configuration Review

```bash
# Review current configuration
sigil config list

# Verify vault location
ls -la ~/.sigil/vault/

# Check backup strategy
ls -la ~/backups/sigil-*.sigil
```

**Requirements:**
- [ ] Vault path is appropriate for production
- [ ] Automated backups are configured
- [ ] Encryption settings meet security requirements
- [ ] Team access controls are in place

### 3. Team Setup

```bash
# Initialize team vault (if using team features)
sigil team init

# Enroll production devices
sigil team enroll-device --name prod-server-1

# Verify team members
sigil team list
```

**Requirements:**
- [ ] All production operators enrolled
- [ ] Access roles configured correctly
- [ ] Emergency access procedures documented

---

## 🔒 Production Configuration

### Daemon Configuration

Edit `~/.sigil/config.toml`:

```toml
[daemon]
# Production settings
idle_timeout = "1h"  # Longer timeout for production
log_level = "info"   # Info logs for production
audit_log = true     # Enable comprehensive audit logging

[security]
# Enable all security layers
lockdown_on_breach = true
canary_monitoring = true
auto_lockdown_threshold = 3

[sandbox]
# Always use sandbox in production
enabled = true
provider = "bubblewrap"  # or "seatbelt" on macOS

[scrubbing]
# Comprehensive scrubbing
level = "paranoid"
encodings = ["base64", "hex", "url", "jwt", "binary", "reversed", "doubled"]
```

### Vault Configuration

```toml
[vault]
# Production vault settings
retention_days = 90
auto_prune = true
backup_enabled = true
backup_schedule = "0 2 * * *"  # Daily at 2 AM

[team]
# Team vault settings
backend = "openbao"  # or "vault", "aws"
threshold = 3  # Shamir's threshold
members = 5  # Total members
```

---

## 🏗️ Deployment Patterns

### Pattern 1: Single Server Deployment

```bash
#!/bin/bash
# deploy-single-server.sh

# 1. Install SIGIL
cargo install sigil-cli

# 2. Initialize vault
sigil init --production

# 3. Import secrets from secure transfer
sigil import prod-vault.sigil

# 4. Start daemon with production config
sigild --config ~/.sigil/production.toml

# 5. Verify deployment
sigil doctor --ci --min-score 95
```

### Pattern 2: Multi-Server Deployment

```bash
#!/bin/bash
# deploy-multi-server.sh

SERVERS=("server1" "server2" "server3")

for server in "${SERVERS[@]}"; do
  echo "Deploying to $server..."

  # 1. SSH to server
  ssh "$server" << 'EOF'
    # Install SIGIL
    cargo install sigil-cli

    # Initialize vault
    sigil init --production

    # Start daemon
    sigild --production
EOF

  # 2. Enroll device
  sigil team enroll-device --name "$server"

  # 3. Verify
  ssh "$server" "sigil doctor --ci"
done
```

### Pattern 3: CI/CD Pipeline Deployment

```yaml
# .github/workflows/deploy-prod.yml
name: Deploy to Production

on:
  push:
    branches: [main]

jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
      - name: Checkout
        uses: actions/checkout@v4

      - name: Install SIGIL
        run: cargo install sigil-cli

      - name: Health Check
        run: sigil doctor --ci --min-score 95

      - name: Import Production Vault
        run: |
          # Decrypt vault from secrets
          echo "${{ secrets.VAULT_BASE64 }}" | base64 -d > prod.sigil
          sigil import prod.sigil

      - name: Deploy
        run: |
          sigil exec --operation deploy-production

      - name: Verify
        run: |
          sigil exec --operation health-check
```

---

## 📊 Monitoring

### Health Monitoring

```bash
# Continuous health monitoring
watch -n 60 'sigil status --json | jq "'
```

### Alert Thresholds

Configure alerts for:

| Metric | Threshold | Action |
|--------|-----------|--------|
| Health Score | < 90 | Warning |
| Health Score | < 80 | Critical |
| Daemon Uptime | < 99% | Critical |
| Audit Log Errors | > 0 | Warning |
| Canary Triggers | > 1 | Critical |
| Failed Logins | > 3 | Lockdown |

### Audit Log Monitoring

```bash
# Monitor for suspicious activity
tail -f ~/.sigil/vault/audit.jsonl | \
  grep --line-buffered -E "bypass|unauthorized|lockdown|canary" | \
  while read line; do
    # Send to alerting system
    curl -X POST https://alerts.example.com/sigil \
      -d "$line"
  done
```

---

## 🔄 Backup and Recovery

### Automated Backups

```bash
#!/bin/bash
# backup-vault.sh

# Create timestamped backup
BACKUP_FILE="sigil-backup-$(date +%Y%m%d-%H%M%S).sigil"
sigil export "$BACKUP_FILE"

# Upload to secure storage
aws s3 cp "$BACKUP_FILE" \
  s3://my-company-sigil-backups/ \
  --sse AES256

# Keep local backup for 7 days
find . -name "sigil-backup-*.sigil" -mtime +7 -delete
```

### Recovery Procedures

```bash
#!/bin/bash
# recover-vault.sh

BACKUP_FILE="$1"

# 1. Stop daemon
pkill sigild

# 2. Backup current vault (just in case)
mv ~/.sigil/vault ~/.sigil/vault.corrupted.$(date +%Y%m%d)

# 3. Import backup
sigil import "$BACKUP_FILE"

# 4. Restart daemon
sigild --production

# 5. Verify
sigil doctor --min-score 95
```

---

## 🚨 Incident Response

### Breach Detection

```bash
# 1. Immediate lockdown
sigil lockdown

# 2. Generate breach report
sigil breach-report --output breach-$(date +%Y%m%d).md

# 3. Review audit log
grep "canary\|bypass\|unauthorized" ~/.sigil/vault/audit.jsonl | \
  tail -100

# 4. Rotate compromised secrets
# (See Secret Rotation Procedure below)
```

### Secret Rotation Procedure

```bash
#!/bin/bash
# rotate-secret.sh

SECRET_PATH="$1"
NEW_VALUE="$2"

# 1. Add new version
echo "$NEW_VALUE" | sigil add "${SECRET_PATH}-new"

# 2. Update all references
grep -r "{{secret:${SECRET_PATH}}}" ./config/ | \
  while read file; do
    sed -i "s/{{secret:${SECRET_PATH}}}/{{secret:${SECRET_PATH}-new}}/g" "$file"
  done

# 3. Verify with canary
sigil add "canary/${SECRET_PATH}-old" --value "$(sigil get "${SECRET_PATH}")"

# 4. Remove old version after grace period
# sigil rm "${SECRET_PATH}"
```

---

## ✅ Post-Deployment Verification

### Smoke Tests

```bash
#!/bin/bash
# smoke-tests.sh

echo "Running smoke tests..."

# 1. Daemon connectivity
sigil status || exit 1

# 2. Secret access
sigil get test/secret > /dev/null 2>&1 || \
  echo "Expected test secret not found (OK if not configured)"

# 3. Placeholder resolution
RESOLVED=$(sigil resolve "test {{secret:test/placeholder}}")
[[ "$RESOLVED" == *"test"* ]] || exit 1

# 4. Scrubbing
echo "secret:value" | sigil scrub - | grep -q "REDACTED" || exit 1

# 5. Sandbox
sigil exec --sandbox -- echo "test" > /dev/null || exit 1

echo "All smoke tests passed!"
```

---

## 🔐 Compliance

### SOC 2 Considerations

- **Access Logging**: All secret accesses logged with timestamp, user, and justification
- **Audit Trail**: Immutable audit log stored securely
- **Access Review**: Regular review of access grants with `sigil lease list`
- **Secret Rotation**: Automated rotation with `sigil rotate-ci-key`
- **Incident Response**: Documented breach response procedures

### HIPAA Considerations

- **Encryption**: All secrets encrypted at rest (age) and in transit (Unix socket)
- **Audit Logging**: Complete audit trail for PHI access
- **Access Controls**: Role-based access with `sigil team grant`
- **Minimum Necessary**: Sealed operations limit output visibility
- **Breach Notification**: Automated breach detection with canary files

---

## 📚 Additional Resources

- [Security Best Practices](security-best-practices.md)
- [Team Collaboration](team-collaboration.md)
- [Troubleshooting Guide](troubleshooting.md)
- [CI/CD Integration](ci-cd-integration.md)

---

## 👉 Next Steps

- [Quickstart Guide](../quickstart.md) — Get started
- [Agent Setup Guides](../agents/) — Configure your agent
- [Examples Index](README.md) — More examples
