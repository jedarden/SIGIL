# Team Collaboration with SIGIL

This guide explains how to use SIGIL's team vault features for collaborative secret management.

## Overview

SIGIL supports multiple operational modes for team collaboration:

| Mode | Use Case | Git-Safe | Multi-User |
|------|----------|----------|------------|
| **Directory** | Single developer, local-only | ❌ No | ❌ No |
| **Sealed** | Team vault, git-committed | ✅ Yes | ✅ Yes |
| **External Backend** | Enterprise, existing infrastructure | ✅ Yes | ✅ Yes |

## Sealed Vault Mode (Recommended for Teams)

The sealed vault mode stores secrets in a single encrypted file (`.sigil/vault.sealed`) that can be safely committed to git. Each team member has their own device key that stays local.

### Architecture

```
┌─────────────────────────────────────────────────────────┐
│                    Git Repository                       │
│  ┌───────────────────────────────────────────────┐     │
│  │ .sigil/vault.sealed (encrypted, committed)    │     │
│  │ .sigil.toml (manifest, committed)             │     │
│  └───────────────────────────────────────────────┘     │
└─────────────────────────────────────────────────────────┘
         │                              │              │
         ▼                              ▼              ▼
    ┌─────────┐                    ┌─────────┐   ┌─────────┐
    │ Alice   │                    │ Bob     │   │ Charlie │
    │ device  │                    │ device  │   │ device  │
    │ .key    │                    │ .key    │   │ .key    │
    └─────────┘                    └─────────┘   └─────────┘
       (local)                        (local)      (local)
```

### Setup for Teams

#### Step 1: Initialize Sealed Vault

**Team lead (first time setup):**

```bash
# Initialize with git-safe vault
sigil init --git-safe

# This creates:
# - .sigil/vault.sealed (encrypted, git-committable)
# - .sigil/device.key (local only, added to .gitignore)
# - .sigil/config.toml (configuration)
```

#### Step 2: Enroll Team Members

**For each team member:**

```bash
# Team member enrolls their device
sigil enroll-device --name "alice@example.com"

# This outputs:
# Device key: <base64-encoded-key>
# Vault fingerprint: <sha256-hash>
```

The team lead adds the device key to the vault:

```bash
# Team lead adds team member's device
sigil device add alice@example.com --key <base64-key>

# Commit updated vault
git add .sigil/vault.sealed
git commit -m "Add alice's device to vault"
git push
```

#### Step 3: Team Member Access

**Alice (team member):**

```bash
# Clone repository
git clone https://github.com/team/project.git
cd project

# Configure device
echo "$DEVICE_KEY" | base64 -d > ~/.sigil/device.key
chmod 600 ~/.sigil/device.key

# Unseal vault
sigil unseal

# Access secrets
sigil list
sigil get production/database_url
```

### Managing Team Access

#### List Devices

```bash
# List all enrolled devices
sigil device list

# Output:
# alice@example.com  added 2026-04-01  fingerprint: a7f3e2...
# bob@example.com    added 2026-04-03  fingerprint: b8c4d1...
# charlie@example.com added 2026-04-05  fingerprint: c9d5e2...
```

#### Remove Team Member

```bash
# Remove device when team member leaves
sigil device remove alice@example.com

# Re-encrypt vault without alice's device
sigil vault rekey

# Commit updated vault
git add .sigil/vault.sealed
git commit -m "Remove alice's device from vault"
git push
```

#### Rotate All Device Keys

```bash
# After security incident or periodically
sigil vault rekey --rotate-all-devices

# Each team member gets a new device key
# Old keys are invalidated
```

### Role-Based Access Control

Define roles in `.sigil.toml`:

```toml
[team]
vault_url = "https://vault.example.com"  # Optional: external vault

# Define roles
[[team.roles]]
name = "developer"
description = "Can access development secrets"
allowed_secrets = ["dev/*", "shared/*"]

[[team.roles]]
name = "deployer"
description = "Can access production deployment secrets"
allowed_secrets = ["dev/*", "staging/*", "prod/deploy/*", "shared/*"]

[[team.roles]]
name = "admin"
description = "Full access to all secrets"
allowed_secrets = ["*"]

# Assign roles to devices
[[team.devices]]
device = "alice@example.com"
roles = ["developer"]

[[team.devices]]
device = "bob@example.com"
roles = ["developer", "deployer"]

[[team.devices]]
device = "charlie@example.com"
roles = ["admin"]
```

Enforce roles:

```bash
# Check access before allowing secret access
sigil get production/database_url --check-role
# Returns: Access denied - insufficient role
```

### Audit Logging for Teams

Every secret access is logged with device identity:

```bash
# View audit log
sigil audit --since "1 day ago"

# Output:
# 2026-04-05T10:30:00Z alice@example.com accessed dev/api_key
# 2026-04-05T10:35:00Z bob@example.com accessed staging/database_url
# 2026-04-05T11:00:00Z charlie@example.com accessed prod/api_key
# 2026-04-05T11:05:00Z bob@example.com denied access to prod/database_url (role: deployer)
```

Export for compliance:

```bash
# Export audit log for compliance reporting
sigil audit --since "30 days" --format json > audit-2026-04.json
```

### Secret Approval Workflow

For high-risk secrets, require approval:

```toml
# .sigil.toml
[team.approval]
require_for = ["prod/*", "finance/*", "legal/*"]

[[team.approvers]]
name = "alice@example.com"
role = "admin"

[[team.approvers]]
name = "bob@example.com"
role = "admin"
```

Access flow:

```bash
# Developer requests access
sigil request prod/database_url --reason "Deploy hotfix"

# TUI opens for approver:
# ┌─────────────────────────────────────────────────────────────┐
# │  🔑 Secret Access Request                                   │
# │  ────────────────────────────────────────────────────────── │
# │  Secret: prod/database_url                                  │
# │  Requester: charlie@example.com                             │
# │  Role: developer                                           │
# │  Reason: Deploy hotfix                                      │
# │  Duration: 1 hour                                          │
# │                                                             │
# │  Approve? [y/N]                                             │
# └─────────────────────────────────────────────────────────────┘

# Once approved, requester can access
sigil get prod/database_url
# Works for 1 hour, then expires
```

## External Backend Mode

For teams using existing secret management systems (HashiCorp Vault, AWS Secrets Manager, etc.):

### Setup HashiCorp Vault Backend

```bash
# Install Vault backend
sigil backend install vault

# Configure
cat > ~/.sigil/config.toml <<EOF
[backend]
type = "vault"
address = "https://vault.example.com"
namespace = "team"
auth_method = "token"  # or github, ldap, etc.
EOF

# Set Vault token
export VAULT_TOKEN="s.XXXXXXXXXXXX"
```

Use secrets transparently:

```bash
# Access Vault secrets through SIGIL
sigil get prod/database_url
# SIGIL fetches from Vault, returns value

# Or use placeholders
sigil exec 'psql $DATABASE_URL'
# SIGIL injects from Vault
```

### Setup AWS Secrets Manager Backend

```bash
# Install AWS backend
sigil backend install aws

# Configure
cat > ~/.sigil/config.toml <<EOF
[backend]
type = "aws"
region = "us-east-1"
EOF

# Set AWS credentials
export AWS_ACCESS_KEY_ID="xxx"
export AWS_SECRET_ACCESS_KEY="yyy"
```

Access AWS secrets:

```bash
# Secrets Manager secret names map to SIGIL paths
sigil get prod/database_url
# Fetches from AWS Secrets Manager: prod/database_url
```

## Collaboration Best Practices

### 1. Environment Separation

```bash
# Separate vaults per environment
sigil vault create development
sigil vault create staging
sigil vault create production

# Team members have different access per environment
# Developers: development only
# Deployers: development + staging
# Admins: all environments
```

### 2. Secret Rotation

```bash
# Rotate production secrets quarterly
sigil rotate prod/api_key

# Rotate device keys after security incidents
sigil vault rekey --rotate-all-devices

# Audit rotation
sigil audit --filter="rotate" --since "90 days"
```

### 3. Onboarding New Team Members

**Onboarding checklist:**

```bash
# 1. Generate device key
sigil enroll-device --name "new-member@example.com"

# 2. Assign roles
sigil device grant new-member@example.com --role developer

# 3. Grant access to specific environments
sigil device grant new-member@example.com --env development

# 4. Verify access
sigil audit --filter="new-member@example.com"

# 5. Document in team wiki
# Add device fingerprint to team documentation
```

### 4. Offboarding Team Members

**Offboarding checklist:**

```bash
# 1. Remove device access
sigil device remove former-member@example.com

# 2. Re-encrypt vault (invalidates their device key)
sigil vault rekey

# 3. Rotate any secrets they had access to
sigil rotate --all --env development

# 4. Audit their access
sigil audit --filter="former-member@example.com" --since "90 days"

# 5. Review for any shared credentials
sigil list --filter="shared" --audit
```

### 5. Emergency Access

For critical situations where you need immediate access:

```bash
# Emergency break-glass access (requires multi-admin approval)
sigil vault break-glass --reason "Production outage" --approvers 2

# Temporarily elevates access for 30 minutes
# Logs all actions with break-glass flag
# Requires post-incident review
```

## Security Considerations

### Device Key Security

```bash
# Device keys should be:
# - Stored encrypted at rest
# - Protected with strong passphrase
# - Never shared via email/chat
# - Rotated quarterly

# Encrypt device key
sigil device encrypt --key ~/.sigil/device.key --output ~/.sigil/device.key.enc

# Decrypt on use (prompts for passphrase)
sigil device use ~/.sigil/device.key.enc
```

### Principle of Least Privilege

```bash
# Grant minimum access needed
sigil device grant alice --role developer --env development

# Time-limited access for contractors
sigil device grant contractor --role deployer --env staging --expires 30d

# Audit access patterns
sigil audit --summary --by-device
```

### Secret Segregation

```bash
# Separate secrets by sensitivity
sigil add dev/api_key       # Low risk
sigil add prod/api_key      # High risk
sigil add finance/api_key   # Critical

# Different approval workflows
sigil policy create dev --no-approval
sigil policy create prod --require-approval 2
sigil policy create finance --require-approval 3 --mfa
```

## Troubleshooting

### Team Member Cannot Access Vault

```bash
# Check if device is enrolled
sigil device list | grep alice@example.com

# Check device key validity
sigil device validate --key ~/.sigil/device.key

# Re-enroll if needed
sigil enroll-device --rotate
```

### Vault Rekey Failed

```bash
# Check which devices failed
sigil vault rekey --dry-run

# Remove problematic devices
sigil device remove problematic-device@example.com

# Retry rekey
sigil vault rekey
```

### Audit Log Tampering

```bash
# Verify audit log integrity
sigil audit --verify

# If compromised:
# 1. Lockdown vault
sigil lockdown

# 2. Rotate all secrets
sigil rotate --all

# 3. Re-enroll all devices
sigil vault rekey --rotate-all-devices
```

## Next Steps

- [Sealed Vault Topic](../topics/vault.md#sealed-mode) — Technical details
- [CI/CD Integration](./ci-cd-integration.md) — Using team vaults in CI/CD
- [Security Best Practices](../concepts.md#threat-model) — Team security guidelines
- [External Backends](../topics/team.md) — Enterprise backend integration
