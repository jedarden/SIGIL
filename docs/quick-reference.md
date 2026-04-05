# 🚀 SIGIL Quick Reference

> One-page command reference for SIGIL secret management.

## 📦 Vault Operations

```bash
# Initialize a new vault
sigil init

# Add a secret (interactive prompt)
sigil add kalshi/api_key

# Add a secret from stdin
echo "sk-live-abc123" | sigil add kalshi/api_key --from-stdin

# Get a secret value
sigil get kalshi/api_key

# List all secrets
sigil list

# List secrets with prefix
sigil list aws/

# Edit a secret
sigil edit kalshi/api_key

# Remove a secret
sigil rm kalshi/api_key

# Show version history
sigil history kalshi/api_key

# Rollback to previous version
sigil rollback kalshi/api_key --to 2

# Export vault to encrypted archive
sigil export backup.sigil

# Import from archive
sigil import backup.sigil
```

## 🏃‍♂️ Command Execution

```bash
# Execute command with secret resolution
sigil exec -- curl -H "Authorization: Bearer {{secret:kalshi/api_key}}" https://api.example.com

# Wrap any command (for human use)
sigil wrap -- psql $(sigil get db/connection_string)

# Resolve placeholders without executing
sigil resolve "Bearer {{secret:kalshi/api_key}}"

# Scrub secrets from output
cat output.log | sigil scrub -
```

## 🛡️ Security & Monitoring

```bash
# Run health checks
sigil doctor

# Run diagnostics
sigil troubleshoot

# Generate breach report
sigil breach-report

# Emergency lockdown
sigil lockdown

# Unlock after lockdown
sigil unlock

# Lint files for secrets
sigil lint path/to/code

# Lint with auto-fix
sigil lint path/to/code --fix

# CI mode (exit non-zero if issues found)
sigil doctor --ci --min-score 90
sigil lint --ci
```

## 🔧 Configuration

```bash
# Manage configuration
sigil config set daemon.idle_timeout 30m
sigil config get daemon.idle_timeout
sigil config list

# Generate shell completions
sigil completions bash > ~/.local/share/bash-completion/completions/sigil
sigil completions zsh > ~/.zfunc/_sigil
sigil completions fish > ~/.config/fish/completions/sigil.fish

# Uninstall SIGIL
sigil uninstall
sigil uninstall --keep-vault
sigil uninstall --purge
```

## 👥 Team Vault

```bash
# Invite a team member
sigil team invite user@example.com --role member

# Join a team vault
sigil team join <invite-token>

# List team members
sigil team list

# Revoke team member access
sigil team revoke <fingerprint>

# Change member role
sigil team role <fingerprint> admin

# Audit team access
sigil team audit
```

## 🔐 Sealed Operations

```bash
# List sealed operations
sigil operations list

# Create a new operation
sigil operations add deploy --command "kubectl apply -f manifests/" --secrets prod/kubeconfig

# Execute an operation
sigil exec --operation deploy

# Show operation details
sigil operations show deploy

# Remove an operation
sigil operations rm deploy
```

## 🔑 SSH Agent

```bash
# Start SSH agent
sigil ssh-agent

# Add SSH key from vault
sigil ssh-agent add github/key

# List loaded keys
sigil ssh-agent list

# Remove a key
sigil ssh-agent remove github/key
```

## 🧪 Red-Team Testing

```bash
# Run red-team security tests
sigil red-team

# Run with specific profile
sigil red-team --profile prod

# Run with custom duration
sigil red-team --duration 10m

# Run in regression mode
sigil red-team --regression

# Run in CI mode
sigil red-team --ci --min-score 95
```

## 📋 Signatures

```bash
# List command signatures
sigil signatures list

# Add custom signature
sigil signatures add my-tool.toml

# Search signatures
sigil signatures search aws

# Update from community database
sigil signatures update
```

## 🔍 Audit & Status

```bash
# View audit log
sigil audit log

# View audit statistics
sigil audit stats

# Show recent events
sigil audit log --since 1h

# Export audit log
sigil audit export --format json > audit.json

# Show SIGIL status
sigil status

# Show detailed status
sigil status --verbose
```

## 🔌 Leases

```bash
# List active leases
sigil lease list

# Grant a lease
sigil lease grant db/password --duration 5m

# Revoke a lease
sigil lease revoke <lease-id>

# Show lease details
sigil lease show <lease-id>
```

## 📚 Help & Documentation

```bash
# Show general help
sigil help

# Show command help
sigil help add
sigil help exec

# Show topic documentation
sigil help vault
sigil help hooks
sigil help security

# Quickstart setup
sigil quickstart
```

## 🔧 Setup Integrations

```bash
# Setup agent hooks
sigil setup claude-code
sigil setup mcp

# Setup shell integration
sigil setup shell

# Setup git credential helper
sigil setup git

# Setup docker credential helper
sigil setup docker

# Setup ssh integration
sigil setup ssh
```

## 🌐 Environment Variables

```bash
# SIGIL socket path
export SIGIL_SOCKET=/path/to/sigil.sock

# CI mode (disable interactive prompts)
export SIGIL_CI=true

# Vault path
export SIGIL_VAULT_PATH=/custom/vault/path

# Log level
export SIGIL_LOG=debug
```

## 📝 Tips

- **Tab completion**: Use tab completion for secret paths: `sigil get aws/<TAB>`
- **Secret paths**: Use `/` as namespace separator: `aws/access_key_id`, `kalshi/api_key`
- **Placeholders**: Use `{{secret:path}}` syntax in commands
- **File injection**: Use `{{secret:path:file}}` to inject as temporary file
- **Output filtering**: Use sealed operations to control what agents see
- **Always allow**: Use persistent access grants for frequently-used secrets
- **Audit**: Everything is logged in `~/.sigil/audit.jsonl`

## 🚨 Emergency Commands

```bash
# Immediate lockdown
sigil lockdown

# Kill all sessions
sigil lockdown --force

# Generate breach report
sigil breach-report --output breach.md

# Rotate compromised secret
sigil add kalshi/api_key  # Add new value
# Update all references to use {{secret:kalshi/api_key}}
sigil rm kalshi/api_key --version 2  # Remove old compromised version
```

## 📖 Next Steps

- [Full Documentation](README.md)
- [Quickstart Guide](quickstart.md)
- [Concepts & Architecture](concepts.md)
- [Per-Agent Setup Guides](agents/)
