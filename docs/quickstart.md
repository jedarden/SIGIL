# 🚀 SIGIL Quickstart Guide

> A step-by-step guide to setting up SIGIL and protecting your secrets from AI coding agents.

---

## 📋 Prerequisites

SIGIL runs on Linux, macOS, and WSL2. Verify your system meets the requirements:

### 🖥️ Platform Requirements

**🐧 Linux / 🪟 WSL2** (Tier 1 — Fully Supported)
- Ubuntu 22.04+ or Debian 12+
- bubblewrap for sandbox isolation
- Verify: `bwrap --version`

**🍎 macOS** (Tier 2 — Supported with limitations)
- macOS 13+ (Ventura or later)
- Sandbox limitations: uses `sandbox-exec` instead of bubblewrap
- Reduced isolation compared to Linux

### 🐚 Shell Compatibility

SIGIL works with these shells:
- bash (4.0+)
- zsh (5.0+)
- fish (3.0+)

---

## 🔧 Installation

### 📦 Option 1: Install from Source

```bash
# Clone the repository
git clone https://github.com/jedarden/sigil.git
cd sigil

# Install SIGIL
cargo install --path .

# Verify installation
sigil --version
```

### 📦 Option 2: Install via Cargo

```bash
cargo install sigil-cli
```

### 📦 Option 3: Binary Download (Coming Soon)

Download the latest release from GitHub releases.

---

## 🚀 Step-by-Step Setup

### 📦 Step 1: Create Your Vault

```bash
sigil init
```

> ℹ️ **What just happened?**
> SIGIL created an age-encrypted vault at `~/.sigil/vault/` and generated a new identity key at `~/.sigil/identity.age`. The vault stores one encrypted file per secret.

You'll be prompted to enter a passphrase (optional but recommended):

```
🔐 Enter passphrase (optional, press Enter to skip): ********
🔐 Confirm passphrase: ********

✅ Vault created at ~/.sigil/vault/
✅ Identity key generated at ~/.sigil/identity.age
```

---

### 🔑 Step 2: Add Your First Secret

```bash
sigil add kalshi/api_key
```

SIGIL will prompt you to enter the secret value:

```
🔑 Enter secret value: ****************************
✅ Secret added: kalshi/api_key
```

> 💡 **Tip**: Secret paths use a `service/name` format. Organize your secrets hierarchically:
> - `aws/access_key_id`
> - `github/personal_token`
> - `prod/database_url`

---

### 🪝 Step 3: Install Agent Hooks

#### For Claude Code (Comprehensive Coverage)

```bash
sigil setup claude-code
```

> ℹ️ **What just happened?**
> SIGIL installed hooks into `~/.claude/settings.json`. These hooks intercept tool calls before and after execution, enabling input scrubbing and output sanitization.

Verify hooks are installed:

```bash
cat ~/.claude/settings.json | grep -A 5 sigil
```

---

### ✅ Step 4: Verify

Run a test command to verify SIGIL is working:

```bash
sigil exec 'echo "Testing secret: {{secret:kalshi/api_key}}"'
```

Expected output:

```
Testing secret: [REDACTED]
```

> ✅ **Done!** SIGIL is now protecting your secrets.

---

## 🎯 First Protected Command

Now that SIGIL is set up, let's use a secret in a real command:

```bash
# Add an API key for example
sigil add example/api_key

# Use it in a curl command
sigil exec 'curl -H "Authorization: Bearer {{secret:example/api_key}}" https://api.example.com/user'
```

What happens:

1. **Interception**: SIGIL intercepts the command before execution
2. **Resolution**: `{{secret:example/api_key}}` is replaced with the real value
3. **Execution**: The command runs with the real secret
4. **Scrubbing**: Output is sanitized before returning to your terminal
5. **Logging**: Access is logged to `~/.sigil/vault/audit.jsonl`

---

## 🔥 Troubleshooting

### ❌ "bwrap: command not found"

> ✅ **Fix**: Install bubblewrap

```bash
# Ubuntu/Debian
sudo apt install bubblewrap

# macOS (not available — sandbox will use sandbox-exec with limitations)
# WSL2 (Windows)
sudo apt install bubblewrap
```

---

### ❌ "permission denied: ~/.sigil/identity.age"

> ✅ **Fix**: Check file permissions

```bash
chmod 600 ~/.sigil/identity.age
```

---

### ❌ "Claude Code hooks not installed"

> ✅ **Fix**: Run the setup command

```bash
sigil setup claude-code
```

Then verify `~/.claude/settings.json` contains SIGIL hooks.

---

### ❌ "vault not initialized" after running `sigil init`

> ✅ **Fix**: Check that `~/.sigil/` directory was created

```bash
ls -la ~/.sigil/
```

If the directory doesn't exist, run `sigil init` again.

---

## 👉 Next Steps

- [Per-Agent Setup Guides](agents/claude-code.md) — Detailed configuration for your specific agent
- [Concepts and Architecture](concepts.md) — Understand how SIGIL protects your secrets
- [FAQ](faq.md) — Common questions and scenarios
- `sigil help` — In-terminal documentation for all commands

---

## 👉 Next Steps

- [Per-Agent Setup Guides](agents/claude-code.md) — Detailed configuration for your specific agent
- [Concepts and Architecture](concepts.md) — Understand how SIGIL protects your secrets
- [FAQ](faq.md) — Common questions and scenarios
- `sigil help` — In-terminal documentation for all commands

---

## 🎯 Common Use Cases

### 🔧 Environment Variables

```bash
# Add a database URL
sigil add prod/database_url

# Use in commands
sigil exec 'DATABASE_URL={{secret:prod/database_url}} cargo run'
```

### 📁 Configuration Files

```bash
# Add AWS credentials
sigil add aws/access_key_id
sigil add aws/secret_access_key

# Use in terraform
sigil exec 'terraform apply -var="access_key={{secret:aws/access_key_id}}"'
```

### 🔄 Git Operations

```bash
# Add GitHub token
sigil add github/token

# Use with git (via credential helper)
sigil setup git
git push origin main
```

---

## 📋 Checklist

Before you start using SIGIL with an agent:

- [ ] Vault initialized (`sigil init`)
- [ ] At least one secret added (`sigil add <path>`)
- [ ] Agent hooks installed (`sigil setup <agent>`)
- [ ] Test command verified (`sigil exec 'echo {{secret:<path>}}'`)
- [ ] Audit log accessible (`~/.sigil/vault/audit.jsonl`)
