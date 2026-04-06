# ❓ FAQ — Frequently Asked Questions

> Common questions and scenarios when using SIGIL.

---

## ❓ How do I use SIGIL with Docker?

SIGIL integrates with Docker via credential helpers and build secrets.

### 🔑 Option 1: Credential Helper

```bash
# Install Docker credential helper
sigil setup docker

# Docker will automatically use SIGIL for registry auth
docker pull ghcr.io/example/image
```

### 🏗️ Option 2: Build Secrets

```bash
# Use SIGIL placeholders in Dockerfile
echo "FROM alpine
ARG API_KEY
RUN echo \$API_KEY > /app/config" > Dockerfile

# Build with secret injection
sigil exec 'docker build --build-arg API_KEY={{secret:api_key}} -t myapp .'
```

### 🐳 Option 3: Docker Compose

```yaml
# docker-compose.yml
services:
  app:
    image: myapp
    environment:
      - API_KEY=${SIGIL_API_KEY}
```

```bash
# Export secret as environment variable (scrubbed from logs)
export SIGIL_API_KEY=$(sigil get api_key --raw)
docker-compose up
```

### 🙅 .dockerignore

Always add SIGIL files to `.dockerignore`:

```
.sigil/
*.age
vault/
identity.age
```

> 💡 **Tip**: Never mount the vault directory into containers. Use credential helpers or environment variables instead.

---

## ❓ How do I use SIGIL in CI/CD?

SIGIL supports CI/CD with sealed vaults and no-daemon mode.

### 🔒 Option 1: Sealed Vault

```bash
# On your local machine
sigil export ci-vault.sigil

# Transfer to CI (via encrypted storage, secrets manager, etc.)

# In CI pipeline
sigil import ci-vault.sigil
sigil exec 'cargo deploy --api-key={{secret:prod/api_key}}'
sigil uninstall --purge  # Remove vault after deployment
```

### 🏥 Option 2: CI Mode with Health Check

```yaml
# .github/workflows/deploy.yml
steps:
  - name: Check SIGIL health
    run: sigil doctor --ci --min-score 90

  - name: Deploy
    run: sigil exec 'deploy.sh'
```

### 💉 Option 3: Environment Variable Injection

```bash
# Export specific secrets as environment variables
export API_KEY=$(sigil get api_key --raw)
export DB_URL=$(sigil get database_url --raw)

# Run your command (no daemon required)
./deploy.sh
```

> ⚠️ **Warning**: Environment variables are visible in process listings. Use sealed vaults for sensitive CI environments.

---

## ❓ How do I share secrets with my team?

SIGIL supports team vaults with role-based access control.

### 👥 Team Vault Setup (Phase 10+)

```bash
# Initialize team vault
sigil team init --backend openbao

# Enroll a device
sigil team enroll

# Share a secret with the team
sigil add team/database_url --shared
```

### 🎭 Role-Based Access

```bash
# Grant read access to a user
sigil team grant alice --secret database_url --access read

# Grant write access to a user
sigil team grant bob --secret database_url --access write

# Revoke access
sigil team revoke charlie --secret database_url
```

> 💡 **Tip**: For team secrets, use a dedicated backend (OpenBao, Vault) rather than local vault files.

---

## ❓ What do I do if my agent bypasses hooks?

Some agents may bypass SIGIL hooks. Detection layers provide fallback protection.

### 🔍 Detection Layers

1. **Filesystem Monitor**: Detects secret writes to disk
2. **Canary Files**: Detects unauthorized access to sensitive files
3. **Audit Log**: Records all secret access attempts

### 📋 Check the Audit Log

```bash
# View recent secret access
tail -f ~/.sigil/vault/audit.jsonl

# Look for suspicious entries
grep "bypass\|unauthorized" ~/.sigil/vault/audit.jsonl
```

### 🚨 When to Use Lockdown

```bash
# Immediate lockdown if breach suspected
sigil lockdown

# View breach report
cat ~/.sigil/breach-report-*.md
```

> ⚠️ **Warning**: Hook bypass indicates either agent limitations or potential compromise. Review the audit log and consider lockdown if suspicious activity is detected.

---

## ❓ How do I rotate a compromised secret?

If a secret is compromised, rotate it immediately.

### 🔄 Step-by-Step Rotation

1. **Generate a new secret** in the external service (API, database, etc.)

2. **Update in SIGIL**:
   ```bash
   sigil add api_key/new --value <new_value>
   ```

3. **Update references** in your code/config:
   ```bash
   # Find all references
   grep -r "{{secret:api_key}}" ./

   # Replace with new path
   sed -i 's/{{secret:api_key}}/{{secret:api_key\/new}}/g' config.toml
   ```

4. **Delete the old secret**:
   ```bash
   sigil rm api_key
   ```

5. **Generate breach report**:
   ```bash
   sigil breach-report --secret api_key --output breach-report.md
   ```

> 💡 **Tip**: Keep the old secret disabled (not deleted) for a grace period in case it's still referenced somewhere.

---

## ❓ Can SIGIL protect secrets in `.env` files?

SIGIL can detect and migrate secrets from `.env` files.

### 🔎 Detection

```bash
# Scan for secrets in .env files
sigil lint .env

# Output:
# ⚠️  Secret detected: API_KEY=sk_live_abc123
# ⚠️  Secret detected: DATABASE_URL=postgres://user:pass@host/db
```

### 🚚 Migration Workflow

```bash
# Step 1: Detect secrets
sigil lint .env

# Step 2: Add to vault
sigil add api_key
sigil add database_url

# Step 3: Replace with placeholders
sed -i 's/API_KEY=.*/API_KEY={{secret:api_key}}/' .env
sed -i 's/DATABASE_URL=.*/DATABASE_URL={{secret:database_url}}/' .env

# Step 4: Use with SIGIL
sigil exec 'source .env && ./run-app.sh'
```

> ⚠️ **Warning**: `.env` files are still plain text. Only use placeholders in `.env` and load them via `sigil exec`.

---

## ❓ What's the performance overhead?

SIGIL is designed for minimal performance impact.

### ⚡ Benchmarks

| Operation | Overhead | Notes |
|-----------|----------|-------|
| **Hook-only** | ~5ms | PreToolUse/PostToolUse hooks |
| **Full sandbox** | ~30ms | Including bubblewrap setup |
| **Secret scrubbing** | O(n) | Aho-Corasick algorithm, linear time |
| **Placeholder resolution** | ~1ms | Hash map lookup |

### 🌍 Real-World Impact

```bash
# Without SIGIL
time curl https://api.example.com
# real: 0m0.245s

# With SIGIL (hook-only)
time sigil exec 'curl https://api.example.com'
# real: 0m0.250s  (+5ms)

# With SIGIL (full sandbox)
time sigil exec --sandbox 'curl https://api.example.com'
# real: 0m0.275s  (+30ms)
```

> ⚡ **Performance**: For most workflows, SIGIL's overhead is negligible compared to network latency and command execution time.

---

## ❓ How do I uninstall SIGIL?

SIGIL provides granular uninstall options.

### 🗑️ Remove Everything

```bash
sigil uninstall --purge
```

This removes:
- Vault directory (`~/.sigil/vault/`)
- Configuration (`~/.sigil/config.toml`)
- Identity key (`~/.sigil/identity.age`)
- Audit logs
- Daemon socket

### 💾 Keep the Vault

```bash
sigil uninstall --keep-vault
```

This preserves:
- Vault directory (`~/.sigil/vault/`)
- Identity key (`~/.sigil/identity.age`)

Use this for:
- Backups before uninstallation
- Transferring to a new machine
- Temporary removal

### 🪝 Remove Agent Hooks

```bash
sigil setup claude-code --uninstall
```

This removes SIGIL hooks from agent configuration while keeping the vault intact.

> ⚠️ **Warning**: `--purge` permanently deletes your vault. Ensure you have a backup (via `sigil export`) before using this option.

---

## ❓ How do I backup my vault?

SIGIL supports encrypted vault exports for backup and transfer.

### 📤 Export to Encrypted File

```bash
# Export entire vault
sigil export backup-$(date +%Y%m%d).sigil

# Export specific secrets
sigil export backup.sigil --prefix prod/
```

### 📥 Import from Backup

```bash
# Import vault (merges with existing)
sigil import backup.sigil

# Import to new vault (replace existing)
sigil import backup.sigil --replace
```

### ⏰ Automated Backups

```bash
# Add to crontab for daily backups
crontab -e

# Add this line for daily backup at 2 AM
0 2 * * * sigil export ~/backups/sigil-$(date +\%Y\%m\%d).sigil
```

> 💡 **Tip**: Store backup files in encrypted storage (e.g., cryptomator, gpg-encrypted directory) for defense-in-depth.

---

## ❓ Can I use SIGIL with multiple vaults?

SIGIL supports multiple vaults for different contexts.

### 🔄 Switching Vaults

```bash
# List available vaults
sigil vault list

# Switch to a different vault
sigil vault use work

# Create a new vault
sigil vault create personal --path ~/.sigil/personal-vault/
```

### 📂 Per-Directory Vaults

```bash
# Create a vault in the current directory
cd ~/work/project
sigil init --local

# This vault is used for commands in this directory
sigil exec './deploy.sh'

# Switch back to default vault
cd ~
sigil exec './deploy.sh'
```

---

## ❓ How do I enable debug logging?

SIGIL provides detailed logging for troubleshooting.

### 🐛 Enable Debug Mode

```bash
# Set environment variable
export SIGIL_LOG=debug

# Run command with debug output
sigil exec 'echo test'

# Or enable for daemon
sigild --log-level debug
```

### 📺 View Logs

```bash
# Daemon logs
tail -f ~/.sigil/sigild.log

# Audit log
tail -f ~/.sigil/vault/audit.jsonl

# Hook logs
tail -f ~/.sigil/hook.log
```

> 💡 **Tip**: Include logs when filing bug reports. Redact sensitive values before sharing.

---

## ❓ How do I verify a secret is still valid?

SIGIL can validate secret formats and optionally verify against live APIs.

### 🔍 Format Validation

```bash
# Verify secret format (no network calls)
sigil verify github/token

# Output:
# 🔍 Verifying: github/token
#
#   ✅ Check 1: Format valid (40 bytes, type: Token)
#   ✅ Check 2: Valid GitHub token format
#   ✅ Check 3: No service-specific validation rule
#
# ✅ Secret is valid
```

### 🌐 Live API Verification

```bash
# Verify with live API check (where supported)
sigil verify stripe/api_key --live

# Output:
# 🔍 Verifying: stripe/api_key
#
#   ✅ Check 1: Format valid (34 bytes, type: Token)
#   ✅ Check 2: Valid Stripe key format
#   ℹ️ Check 3: Live API verification skipped (to prevent token leakage)
#
# ✅ Secret is valid
```

### 📋 Supported Service Formats

| Service | Format Validation | Live Verification |
|---------|------------------|-------------------|
| AWS Access Keys | ✅ AKIA... (20 chars) | ❌ Not available |
| GitHub Tokens | ✅ ghp_*, gho_*, 40-char hex | ❌ Skipped (prevents leakage) |
| Stripe Keys | ✅ pk_live_*, sk_live_* | ❌ Skipped (prevents leakage) |
| OpenAI Keys | ✅ sk-... | ❌ Skipped (prevents leakage) |
| JWT Tokens | ✅ 3-part structure | ❌ Not available |

> ⚠️ **Warning**: Live API verification is intentionally limited for most services to prevent token leakage in logs/network traffic. Format validation is usually sufficient for secret rotation workflows.

### 🔄 CI/CD Integration

```bash
# Verify secrets before deployment
sigil verify prod/api_key --json | jq '.verified'
# Output: true

# Fail deployment if secret is invalid
sigil verify prod/database_url || exit 1
```

> 💡 **Tip**: Use `sigil verify` in CI/CD pipelines to catch placeholder values or incorrectly formatted secrets before deployment.

---

## 👉 More Help

- [Quickstart Guide](quickstart.md) — Get started with SIGIL
- [Concepts and Architecture](concepts.md) — Understand how SIGIL works
- [Per-Agent Setup Guides](agents/) — Configure for your agent
- `sigil help` — In-terminal documentation for all commands
