# Security Best Practices for SIGIL

This guide covers security best practices for using SIGIL to protect secrets in AI-assisted development.

## Core Security Principles

### 1. Zero Trust

**Never assume any component is fully trustworthy:**

```
┌─────────────────────────────────────────────────────────────┐
│                    Trust Boundaries                          │
│  ┌───────────────────┐    ┌───────────────────┐            │
│  │   AI Agent        │    │    SIGIL          │            │
│  │  ⚠️  Untrusted     │◄──►│    ✅ Trusted     │            │
│  │  (sees only       │    │    (handles real   │            │
│  │   placeholders)   │    │     secrets)       │            │
│  └───────────────────┘    └───────────────────┘            │
└─────────────────────────────────────────────────────────────┘
```

- Agent never sees plaintext secrets
- SIGIL daemon runs in isolated process
- Secrets encrypted at rest with age
- Memory protection with `mlock` and zeroize

### 2. Defense in Depth

SIGIL provides 6 layers of protection:

| Layer | Mechanism | Threat Addressed |
|-------|-----------|------------------|
| 1 | Agent Hooks (PreToolUse) | Malicious tool calls |
| 2 | Proxy Shell (sigil-shell) | Bash command injection |
| 3 | Filesystem Monitor | Secret writes to disk |
| 4 | Sandbox (bubblewrap) | Process isolation |
| 5 | Vault Encryption | Data at rest |
| 6 | Canary Monitoring | Breach detection |

## Installation Security

### Verify Binaries

Always verify SIGIL binaries before installation:

```bash
# Download and verify checksum
curl -sSL https://github.com/jedarden/sigil/releases/download/v0.4.0/sigil-linux-amd64 -o sigil
curl -sSL https://github.com/jedarden/sigil/releases/download/v0.4.0/sigil-linux-amd64.sha256 -o sigil.sha256

# Verify checksum
sha256sum -c sigil.sha256

# Make executable
chmod +x sigil
sudo mv sigil /usr/local/bin/
```

### Use System Package Managers

Prefer system package managers over direct downloads:

```bash
# Homebrew (macOS/Linux)
brew install sigil

# AUR (Arch Linux)
yay -S sigil

# Snap (universal)
snap install sigil --classic
```

## Vault Security

### Use Strong Passphrases

```bash
# SIGIL requires strong passphrases for vault encryption
sigil init

# Passphrase requirements:
# - Minimum 12 characters
# - Entropy > 80 bits (4-word Diceware passphrase)
# - Not found in common password databases

# Use Diceware for strong passphrases:
# correct horse battery staple (4 words = ~51 bits entropy)
# correct horse battery staple staple (5 words = ~64 bits entropy)
# correct horse battery staple staple dress (6 words = ~77 bits entropy)

# For production, use 6+ word Diceware phrases
```

### Enable Vault Auto-Lock

```toml
# ~/.sigil/config.toml
[daemon]
idle_timeout = "15m"  # Lock after 15 minutes of inactivity
session_timeout = "4h"  # Maximum session duration
```

### Rotate Secrets Regularly

```bash
# Set up automatic rotation
sigil rotate prod/api_key --schedule "90d"

# Manual rotation for critical secrets
sigil rotate finance/api_key
sigil rotate --all --env production
```

### Use Separate Vaults per Environment

```bash
# Never mix production and development secrets
sigil vault create development
sigil vault create staging
sigil vault create production

# Switch between vaults
sigil vault use development
```

## Agent Integration Security

### Install All Hook Types

```bash
# For Claude Code, install all hooks
sigil setup claude-code

# This installs hooks for:
# - UserPromptSubmit: Catches secrets in prompts
# - Bash: PreToolUse + PostToolUse
# - Write: PreToolUse + PostToolUse
# - Edit: PreToolUse + PostToolUse
# - Read: PreToolUse + PostToolUse
# - Grep: PostToolUse
# - Glob: PostToolUse
```

### Verify Hook Installation

```bash
# Check hooks are installed
sigil doctor --hooks

# Manually verify Claude Code hooks
cat ~/.claude/settings.json | grep -A 10 '"hooks"'
```

### Use Full Sandbox Mode

```bash
# Enable sandbox for maximum isolation
sigil config set sandbox.enabled true
sigil config set sandbox.mode "full"

# Verify sandbox is working
sigil doctor --sandbox
```

## Secret Usage Security

### Never Hardcode Secrets

**❌ BAD:**
```python
api_key = "sk_live_abc123xyz789"  # NEVER do this
```

**✅ GOOD:**
```python
# Use environment variable
api_key = os.environ['STRIPE_API_KEY']

# Or use placeholder in commands
sigil exec 'curl https://api.stripe.com/v1/charges -u {{secret:stripe/api_key}}'
```

### Use Appropriate Secret Types

```bash
# Use correct secret type for validation
sigil add stripe/api_key --type api_key
sigil add tls/certificate --type certificate
sigil add database/url --type database_url
```

### Limit Secret Scope

```bash
# Use environment-specific secrets
sigil add dev/api_key      # Development only
sigil add staging/api_key  # Staging only
sigil add prod/api_key     # Production only

# Grant minimum access needed
sigil device grant alice --role developer --env development
```

### Enable Secret Expiration

```bash
# Set expiration for temporary secrets
sigil add temp/access_key --expires 24h

# Check for expiring secrets
sigil list --filter expiring --within 7d
```

## Memory Security

### Enable Memory Locking

```toml
# ~/.sigil/config.toml
[security]
# Lock secret pages in RAM (prevents swap)
mlock_enabled = true

# Zeroize memory on drop
zeroize_on_drop = true
```

### Verify Memory Protection

```bash
# Check that mlock is working
sigil doctor --memory

# Check for secrets in swap
sudo strings /swapfile | grep -i "sk_live_" | head -5
```

### Use Secure Communication

```bash
# Always use Unix sockets for IPC (SO_PEERCRED)
sigil config set ipc.transport unix
sigil config set ipc.path "$XDG_RUNTIME_DIR/sigil.sock"

# Never use TCP for local IPC
```

## Audit and Monitoring

### Enable Audit Logging

```toml
# ~/.sigil/config.toml
[audit]
enabled = true
path = "~/.sigil/audit.jsonl"
max_size = "50MB"
rotate = true
compress = true
```

### Regular Security Audits

```bash
# Daily: Check for canary triggers
sigil breach-report --check

# Weekly: Review audit log
sigil audit --since "7 days" --report

# Monthly: Rotate secrets
sigil rotate --all

# Quarterly: Security review
sigil doctor --full --report > security-report.txt
```

### Set Up Canary Monitoring

```bash
# Deploy canaries in sensitive locations
sigil canary deploy ~/.aws/credentials --type decoy
sigil canary deploy ~/.env --type decoy

# Monitor for canary access
sigil canary watch --notify "security@example.com"
```

## Incident Response

### Breach Detection

If you suspect a secret has been compromised:

```bash
# 1. Immediate lockdown
sigil lockdown

# 2. Generate breach report
sigil breach-report --output breach-report.json

# 3. Rotate compromised secrets
sigil rotate prod/api_key
sigil rotate --all --env production

# 4. Re-enroll all devices
sigil vault rekey --rotate-all-devices

# 5. Review audit logs for scope
sigil audit --since "72 hours" --detailed
```

### Emergency Access

For critical situations requiring immediate vault access:

```bash
# Break-glass access (requires multi-admin approval)
sigil vault break-glass --reason "Production outage" --approvers 2

# Emergency unlock
sigil unlock --emergency

# Remember: All break-glass actions are logged for post-incident review
```

## Team Security

### Device Key Management

```bash
# Encrypt device keys at rest
sigil device encrypt --key ~/.sigil/device.key

# Use hardware security modules where available
sigil device enroll --hsm /dev/hsm0

# Rotate device keys quarterly
sigil device rotate
```

### Role-Based Access Control

```bash
# Define roles with minimum privilege
sigil role create developer --read dev/*,shared/* --write none
sigil role create deployer --read dev/*,staging/* --write staging/*
sigil role create admin --read "*" --write "*"

# Assign roles to devices
sigil device grant alice --role developer
sigil device grant bob --role deployer
```

### Approval Workflows

```bash
# Require approval for high-risk secrets
sigil policy create prod --require-approval 2
sigil policy create finance --require-approval 3 --mfa

# Set up approvers
sigil approvers add prod --approvers alice,bob,charlie
```

## CI/CD Security

### Use Sealed Vault for CI

```bash
# Initialize git-safe vault
sigil init --git-safe

# Enroll CI device
sigil enroll-device --name "github-actions"

# Store device key as CI secret
# (e.g., GitHub Actions Secret)
```

### Rotate CI Credentials

```bash
# Rotate CI device key monthly
sigil rotate-ci-key

# Update CI secret with new key
```

### Enable CI Mode

```bash
# CI mode exits non-zero on security issues
sigil doctor --ci

# Use in CI pipelines
if ! sigil doctor --ci; then
  echo "Security check failed"
  exit 1
fi
```

## Data Security

### Encrypt Vault Backups

```bash
# Export to encrypted archive
sigil export --output backup.sigil

# The archive is encrypted with your vault passphrase
# Store backups in secure location (e.g., encrypted S3 bucket)
```

### Secure Audit Logs

```bash
# Audit logs are append-only and hash-chained
# Cannot be modified without detection

# Verify audit log integrity
sigil audit --verify

# Export for compliance
sigil audit --since "30 days" --output audit-2026-04.json
```

### Zero Knowledge Proofs

For high-security environments, SIGIL supports zero-knowledge operations:

```bash
# Prove you have access without revealing the secret
sigil prove prod/api_key --challenge

# Verify someone has access without seeing the secret
sigil verify prod/api_key --proof proof.txt
```

## Common Security Pitfalls

### ❌ Don't: Commit Secrets to Git

```bash
# Never commit .env files, credentials, or vault files
echo ".env" >> .gitignore
echo ".env.*" >> .gitignore
echo ".sigil/device.key" >> .gitignore
echo ".sigil/vault/" >> .gitignore

# Scan for accidental commits
sigil lint . --git-history
```

### ❌ Don't: Share Secrets via Chat/Email

```bash
# Use SIGIL's secure sharing instead
sigil share prod/api_key --with alice --expires 1h

# Or use vault access control
sigil device grant alice --role deployer
```

### ❌ Don't: Disable Security Features

```toml
# Never disable sandbox, hooks, or audit logging
# These are your defense in depth

# ❌ BAD: Disable sandbox
[security]
sandbox_enabled = false

# ✅ GOOD: Keep all security features enabled
[security]
sandbox_enabled = true
hooks_enabled = true
audit_enabled = true
```

### ❌ Don't: Use Same Secret Across Environments

```bash
# Each environment should have unique secrets
sigil add dev/api_key --value "sk_test_abc123"
sigil add staging/api_key --value "sk_test_def456"
sigil add prod/api_key --value "sk_live_ghi789"

# Never reuse the same secret
```

## Compliance

### SOC 2 Compliance

```bash
# Enable all SOC 2 required features
sigil config set audit.enabled true
sigil config set audit.log_all_access true
sigil config set security.mlock_enabled true
sigil config set security.encryption "aes-256-gcm"

# Generate SOC 2 report
sigil compliance --soc2 --output soc2-report.json
```

### GDPR Compliance

```bash
# Enable right to be forgotten
sigil audit --export --subject "user@example.com"
sigil audit --delete --subject "user@example.com"

# Data retention policies
sigil config set audit.retention "90d"
sigil config set audit.auto_purge true
```

### HIPAA Compliance

```bash
# Enable HIPAA required controls
sigil config set audit.enabled true
sigil config set audit.log_all_access true
sigil config set security.mlock_enabled true
sigil config set compliance.hipaa_mode true

# Generate HIPAA report
sigil compliance --hipaa --output hipaa-report.json
```

## Security Checklist

Use this checklist to verify your SIGIL security:

- [ ] Strong passphrase (> 80 bits entropy)
- [ ] All agent hooks installed
- [ ] Sandbox mode enabled
- [ ] Audit logging enabled
- [ ] Canary monitoring deployed
- [ ] Separate vaults per environment
- [ ] Secrets rotated quarterly
- [ ] Device keys encrypted
- [ ] Role-based access configured
- [ ] CI/CD using sealed vault
- [ ] Regular security audits scheduled
- [ ] Incident response plan documented
- [ ] Backup encryption verified
- [ ] Memory locking enabled
- [ ] No secrets in git history

## Next Steps

- [Threat Model](../concepts.md#threat-model) — Understanding security risks
- [Team Collaboration](./team-collaboration.md) — Security for teams
- [Incident Response](../faq.md#incident-response) — What to do when things go wrong
- [Security Policy](../../SECURITY.md) — Responsible disclosure
