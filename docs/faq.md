# ❓ SIGIL FAQ

> Answers to common questions about using SIGIL with AI coding agents.

---

## ❓ How do I use SIGIL with Docker?

### Docker Build Secrets

Use `sigil wrap` to inject secrets into docker builds:

```bash
sigil wrap docker build --secret id=api_key,src={{secret:docker/api_key}} .
```

### Docker Credential Helper

SIGIL provides a Docker credential helper:

```bash
sigil setup docker
```

This configures Docker to use SIGIL for registry authentication:

```json
{
  "credsStore": "sigil"
}
```

### .dockerignore

Add vault files to `.dockerignore`:

```
.sigil/
*.age
identity.age
```

> 💡 **Tip**: Never commit `.sigil/` or vault files to a Docker image.

---

## ❓ How do I use SIGIL in CI/CD?

### CI Mode

Run `sigil doctor` in CI mode to verify configuration:

```bash
sigil doctor --ci --min-score 90
```

This exits non-zero if the health score is below 90.

### Argo Workflows Integration

SIGIL CI runs on Argo Workflows. See [declarative-config](https://github.com/jedarden/declarative-config) for workflow templates.

### Sealed Vault for CI

Use sealed vault mode for team vaults:

```bash
sigil init --git-safe
```

This creates `.sigil/vault.sealed` which can be committed to git.

### No-Daemon Mode

For CI environments without a daemon:

```bash
sigil exec --no-daemon 'command with {{secret:placeholder}}'
```

This decrypts secrets directly without a running daemon.

### Kubernetes Integration

Use ExternalSecrets or SealedSecrets for Kubernetes:

```bash
sigil export --format k8s-secret --output k8s/secrets.yaml
```

---

## ❓ How do I share secrets with my team?

### Team Vault (Sealed Mode)

Use sealed vault mode for git-committable secrets:

```bash
# Initialize sealed vault
sigil init --git-safe

# Convert to sealed mode
sigil vault convert --to sealed

# Commit to git
git add .sigil/vault.sealed
git commit -m "Add sealed vault"
```

### Device Enrollment

Enroll team members' devices:

```bash
# Enroll a new device
sigil team enroll-user user@example.com

# List enrolled devices
sigil team list-devices

# Revoke a device
sigil team revoke-device <device-id>
```

### Role-Based Access

Configure roles in `.sigil/team.toml`:

```toml
[roles.developer]
can_read = ["dev/*", "staging/*"]
can_write = ["dev/*"]

[roles.admin]
can_read = ["*"]
can_write = ["*"]
```

> ⚠️ **Warning**: Team vaults require Shamir's Secret Sharing for recovery. Store recovery codes securely.

---

## ❓ What do I do if my agent bypasses hooks?

### Detection Layers

SIGIL has multiple detection layers that work even without hooks:

1. **Filesystem monitor** — Detects secret writes to disk
2. **Canary monitoring** — Flags unauthorized access
3. **Audit log** — Records all secret access

### Check Audit Log

```bash
sigil audit --tail
```

Look for:
- Unauthorized secret access
- Canary file reads
- Suspicious command patterns

### Canary Files

Place canary files to detect unauthorized access:

```bash
echo "fake-aws-key" > .aws-canary
echo "fake-github-token" > .github-canary
```

Any access to these files triggers a CRITICAL alert.

### Lockdown

If you suspect a breach:

```bash
sigil lockdown
```

This:
- Kills all sandbox processes
- Revokes all session tokens
- Locks the vault
- Generates a breach report

---

## ❓ How do I rotate a compromised secret?

### Step 1: Lockdown (if breach detected)

```bash
sigil lockdown
```

### Step 2: Generate Breach Report

```bash
sigil breach-report --output breach-report-$(date +%Y%m%d).md
```

### Step 3: Rotate in External System

Rotate the secret in the external system (AWS, GitHub, etc.).

### Step 4: Update in SIGIL

```bash
# Add new value
sigil add aws/access_key_id --rotate

# Verify
sigil get aws/access_key_id
```

### Step 5: Test Access

```bash
sigil exec 'aws s3 ls'
```

### Step 6: Unlock

```bash
sigil unlock
```

> 💡 **Tip**: Keep a record of rotation events in the audit log: `sigil audit --filter rotate`.

---

## ❓ Can SIGIL protect secrets in `.env` files?

### Detection

Use `sigil lint` to detect secrets in `.env` files:

```bash
sigil lint .env
```

This reports:
- Hardcoded API keys
- Suspicious patterns
- High-entropy strings

### Migration

Migrate secrets to SIGIL:

```bash
sigil migrate --from .env --to-vault
```

This:
- Extracts secrets from `.env`
- Adds them to the vault
- Replaces values with placeholders

### Placeholder Replacement

Update your `.env` file to use placeholders:

```bash
# Before
API_KEY=sk_live_1234567890abcdef

# After
API_KEY={{secret:api/my_key}}
```

> ⚠️ **Warning**: Don't commit `.env` files with placeholders to version control. Use `.env.example` instead.

---

## ❓ What's the performance overhead?

### Benchmarks

| Operation | Overhead | Notes |
|-----------|----------|-------|
| Hook-only (no sandbox) | ~5ms | PreToolUse/PostToolUse processing |
| Full sandbox | ~30ms | bubblewrap namespace setup |
| Scrubbing | O(n) | Aho-Corasick algorithm, linear in output size |
| FUSE read | ~0.1ms | Kernel-mediated, faster than IPC |
| Vault decrypt | ~10ms | Age decryption (depends on secret size) |

### Optimization Tips

1. **Use signature matching** — Automatic secret injection is faster than manual placeholders
2. **Enable caching** — Daemon caches decrypted secrets in memory
3. **Batch operations** — Resolve multiple secrets in one command
4. **Use FUSE** — File-based secrets are faster than IPC

> ⚡ **Performance**: For typical workloads, SIGIL adds < 50ms per command. For automated scripts, the overhead is negligible.

---

## ❓ How do I uninstall SIGIL?

### Uninstall Command

```bash
sigil uninstall --dry-run
```

Preview what would be removed, then:

```bash
sigil uninstall
```

### Granular Removal

Remove specific components:

```bash
# Remove only hooks
sigil uninstall --hooks-only

# Remove runtime artifacts
sigil uninstall --runtime-only

# Remove canary monitoring
sigil uninstall --canaries-only

# Remove credential helpers
sigil uninstall --credentials-only
```

### Keep Vault

To preserve your vault:

```bash
sigil uninstall --keep-vault
```

### Manual Cleanup

Remove remaining files:

```bash
# Remove vault
rm -rf ~/.sigil

# Remove binaries
rm /usr/local/bin/sigil
rm /usr/local/bin/sigild
rm /usr/local/bin/sigil-shell

# Remove completion scripts
rm ~/.local/share/bash-completion/completions/sigil
rm ~/.zfunc/_sigil
```

---

## ❓ How do I switch between agents?

### Multiple Agent Configurations

SIGIL supports multiple agent configurations:

```bash
# Setup for Claude Code
sigil setup claude-code

# Setup for Cursor
sigil setup cursor
```

### Per-Project Configuration

Create `.sigil/config.toml` for project-specific settings:

```toml
[agent]
type = "claude-code"

[hooks]
pre_tool_use = true
post_tool_use = true
```

### Switching Daemons

Stop the current daemon and start a new one:

```bash
# Stop current daemon
sigil daemon stop

# Start new daemon with different config
sigild --config ~/.sigil/alt-config.toml
```

---

## ❓ How do I backup and restore my vault?

### Backup

Export to encrypted archive:

```bash
sigil export --output sigil-backup-$(date +%Y%m%d).sigil
```

### Restore

Import from archive:

```bash
sigil import --input sigil-backup-20260407.sigil
```

### Selective Backup

Backup specific namespaces:

```bash
sigil export --namespace prod --output prod-backup.sigil
```

### Incremental Backup

Backup only changed secrets:

```bash
sigil export --incremental --output incremental-backup.sigil
```

> 💡 **Tip**: Store backups in a secure location (encrypted S3 bucket, etc.). Never store backups unencrypted.

---

## ❓ How do I debug SIGIL issues?

### Enable Debug Logging

```bash
sigil daemon start --log-level debug
```

### Check Health

```bash
sigil doctor
```

### View Audit Log

```bash
sigil audit --tail
```

### Test Secret Access

```bash
sigil test-access <secret-path>
```

### Troubleshoot Command

```bash
sigil troubleshoot
```

This runs diagnostics and suggests fixes.

---

## 🚧 Known Limitations

- **No native Windows support** — WSL2 is required
- **macOS sandbox limitations** — Reduced coverage on macOS
- **Agent memory** — SIGIL can't prevent agents from "remembering" secrets
- **Host compromise** — SIGIL doesn't protect against compromised hosts
- **Heuristic scrubbing gaps** — Modified secret formats may not be caught

---

## 👉 Next Steps

- [Quickstart Guide](quickstart.md) — Get up and running
- [Concepts and Architecture](concepts.md) — Understand how SIGIL works
- [Per-Agent Setup Guides](agents/) — Configure for your agent
- [GitHub Issues](https://github.com/sigil-rs/sigil/issues) — Report bugs or request features
