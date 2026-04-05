# Basic SIGIL Workflow

This example demonstrates the basic workflow for using SIGIL to protect secrets in an AI-assisted development project.

## Scenario

You're building an application that needs to call external APIs (Stripe, AWS, OpenAI). You want to use Claude Code to help develop the application, but you don't want your API keys to leak into the conversation.

## Step 1: Initialize Your Vault

```bash
sigil init
```

This creates an encrypted vault at `~/.sigil/vault/` and generates an age identity.

**What happens:**
- Creates `~/.sigil/vault/` directory
- Generates `~/.sigil/identity.age` (your private key, passphrase-protected)
- Creates `~/.sigil/config.toml` (configuration)

## Step 2: Add Your Secrets

```bash
sigil add stripe/api_key
# Prompt: Enter value (will be hidden): sk_live_abc123xyz...

sigil add aws/access_key_id
sigil add aws/secret_access_key

sigil add openai/api_key
```

**What happens:**
- Each secret is encrypted with your age identity
- Stored as an `.age` file in the vault
- You can list them: `sigil list`

## Step 3: Create Project Manifest (Optional)

Create `.sigil.toml` in your project root:

```toml
[project]
name = "my-app"
version = "1.0.0"

[[secrets]]
path = "stripe/api_key"
type = "api_key"
required = true
description = "Stripe API key for payments"

[[secrets]]
path = "aws/access_key_id"
type = "api_key"
required = true
env_var = "AWS_ACCESS_KEY_ID"

[[secrets]]
path = "aws/secret_access_key"
type = "api_key"
required = true
env_var = "AWS_SECRET_ACCESS_KEY"

[[secrets]]
path = "openai/api_key"
type = "api_key"
required = true
env_var = "OPENAI_API_KEY"
```

**What this does:**
- Declares which secrets your project uses
- Enables automatic environment variable injection
- Serves as documentation for your team

## Step 4: Use Secrets in Commands

With SIGIL, you use placeholders instead of real secrets:

```bash
# Environment variable injection
sigil exec 'curl https://api.stripe.com/v1/charges -u {{secret:stripe/api_key}}'

# Automatic env var injection (if declared in .sigil.toml)
sigil exec 'stripe charges list'

# Direct placeholder resolution
sigil exec 'aws s3 ls'
# SIGIL automatically injects AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY
```

**What the agent sees:**
- The command with placeholders: `curl https://api.stripe.com/v1/charges -u {{secret:stripe/api_key}}`
- Scrubbed output: Any returned secrets are replaced with `***REDACTED***`

**What SIGIL does:**
1. Detects the command needs `stripe/api_key`
2. Fetches and decrypts it from the vault
3. Injects it into the command
4. Executes the command
5. Scrubs secrets from the output
6. Returns cleaned output to the agent

## Step 5: Install Agent Hooks (Optional)

For Claude Code, install the hooks:

```bash
sigil setup claude-code
```

This adds hooks to `~/.claude/settings.json` that:
- Intercept user prompts for secret patterns
- Scrub tool outputs for leaked secrets
- Enable `sigil_exec` MCP tool

## Step 6: Verify Everything Works

```bash
# Test that secrets are accessible
sigil get stripe/api_key

# Test command execution
sigil exec 'echo "API key is: {{secret:stripe/api_key}}"'

# Run health check
sigil doctor
```

## Advanced: Using with a CI/CD Pipeline

For CI, use the sealed vault mode:

```bash
# Initialize with git-safe vault
sigil init --git-safe

# This creates:
# - .sigil/vault.sealed (encrypted, git-committable)
# - .sigil/device.key (local only, not committed)
```

In your CI pipeline:

```yaml
# .github/workflows/deploy.yml
- name: Unseal vault
  run: sigil-ci unseal --device-key ${{ secrets.DEVICE_KEY }}
  env:
    SIGIL_VAULT: .sigil/vault.sealed

- name: Deploy
  run: sigil exec 'deploy.sh'
  env:
    SIGIL_VAULT: .sigil/vault.sealed
```

## Common Commands

| Command | Purpose |
|---------|---------|
| `sigil init` | Create a new vault |
| `sigil add <path>` | Add a secret |
| `sigil list` | List all secrets |
| `sigil get <path>` | Get a secret value (debugging) |
| `sigil exec <cmd>` | Execute command with secret injection |
| `sigil lint <path>` | Scan for leaked secrets |
| `sigil export` | Backup vault to encrypted archive |
| `sigil import` | Import from archive |
| `sigil doctor` | Run health checks |

## Security Best Practices

1. **Never commit your vault passphrase** - Use environment variables in CI
2. **Use git-safe vault for teams** - `sigil init --git-safe` for shared vaults
3. **Rotate compromised secrets** - `sigil rotate <path>` if a secret leaks
4. **Enable audit logging** - Check `~/.sigil/audit.jsonl` regularly
5. **Use lockdown in emergencies** - `sigil lockdown` revokes all access

## Next Steps

- [Per-Agent Setup Guides](../agents/claude-code.md) — Agent-specific configuration
- [Concepts and Architecture](../concepts.md) — How SIGIL works
- [Sealed Operations](../topics/vault.md#sealed-mode) — Team vaults
