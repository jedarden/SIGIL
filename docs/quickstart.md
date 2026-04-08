# 🚀 SIGIL Quickstart Guide

> Get up and running with SIGIL in 5 minutes — protect your secrets from AI coding agents.

---

## 📋 Prerequisites

Before installing SIGIL, verify your system meets the requirements:

**Platform support:**
- 🐧 **Linux** (Ubuntu 22.04+, Debian 12+, or equivalent) — Tier 1, fully supported
- 🪟 **WSL2** (Ubuntu 22.04+) — Tier 1, fully supported
- 🍎 **macOS** (13+ Ventura) — Tier 2, supported with sandbox limitations

**System requirements:**
- Rust 1.75+ (if installing from source)
- bubblewrap (Linux/WSL2) — for namespace isolation
- seccomp support (Linux/WSL2) — for syscall filtering

> 💡 **Tip**: Check if bubblewrap is installed with `bwrap --version`. On Debian/Ubuntu, install with `sudo apt-get install bubblewrap`.

---

## 🔧 Installation

### Option 1: Install from crates.io (Recommended)

```bash
cargo install sigil-cli
```

This installs the `sigil` binary to `~/.cargo/bin/`. Make sure this directory is in your PATH:

```bash
export PATH="$HOME/.cargo/bin:$PATH"
```

### Option 2: Install from source

```bash
git clone https://github.com/sigil-rs/sigil.git
cd sigil
cargo install --path crates/sigil-cli
```

### Option 3: Pre-built binaries

Download the latest release from [GitHub Releases](https://github.com/sigil-rs/sigil/releases):

```bash
wget https://github.com/sigil-rs/sigil/releases/download/v0.4.0/sigil-x86_64-unknown-linux-gnu.tar.gz
tar xzf sigil-x86_64-unknown-linux-gnu.tar.gz
sudo mv sigil /usr/local/bin/
```

---

## 🚀 Step-by-Step Setup

### 📦 Step 1: Create Your Vault

Initialize the SIGIL vault with age encryption:

```bash
sigil init
```

You'll be prompted for a passphrase:

```
Enter passphrase for vault: ********
Confirm passphrase: ********
Generating age keypair...
Vault created at ~/.sigil
```

> ℹ️ **What just happened?**
>
> SIGIL created:
> - `~/.sigil/vault/` — directory for encrypted secrets
> - `~/.sigil/identity.age` — your age identity (passphrase-protected)
> - `~/.sigil/config.toml` — configuration file
>
> Your secrets are encrypted with age (X25519 + ChaCha20-Poly1305). The identity file is protected by the passphrase you entered.

### 🔑 Step 2: Add Your First Secret

Add a secret to the vault:

```bash
sigil add kalshi/api_key
```

You'll be prompted for the secret value:

```
Enter value (will be hidden): ********
Confirm value: ********
Enter description (optional): Kalshi trading API key
✓ Added: kalshi/api_key
```

> ℹ️ **What just happened?**
>
> SIGIL created:
> - `~/.sigil/vault/kalshi/api_key.age` — encrypted secret file
> - `~/.sigil/metadata.json.age` — encrypted metadata index
>
> The secret is encrypted at rest. SIGIL never stores plaintext secrets on disk.

### 🪝 Step 3: Install Agent Hooks

Install SIGIL hooks for your AI coding agent:

```bash
sigil setup claude-code
```

> ⚠️ **Warning**: This modifies your agent's configuration file. Back up your existing config before proceeding.

For Claude Code, this installs hooks for:
- `PreToolUse` — intercept tool calls before execution
- `PostToolUse` — scrub outputs after tool execution
- `UserPromptSubmit` — scrub secrets in user prompts

> ℹ️ **What just happened?**
>
> SIGIL modified `~/.claude/settings.json` to add hook entries. These hooks intercept tool calls and scrub secrets before they reach the agent or are logged.

### ✅ Step 4: Verify

Verify that SIGIL is working:

```bash
sigil doctor
```

You should see output like:

```
✓ Vault integrity verified
✓ Daemon socket accessible
✓ Hooks installed for Claude Code
✓ bubblewrap available
✓ seccomp available

Health score: 100/100
```

> ✅ **Done!** SIGIL is now protecting your secrets.

---

## 🎯 First Protected Command

Let's use a secret without ever exposing it to the agent:

```bash
sigil exec 'curl -H "Authorization: Bearer {{secret:kalshi/api_key}}" https://api.kalshi.com/trade/v2/portfolio/balance'
```

The placeholder `{{secret:kalshi/api_key}}` is resolved at execution time:

```json
{"balance": 5000.00}
```

> 💡 **Tip**: The agent never sees the actual API key. It only sees the placeholder. If the agent tries to log or echo the command, the secret is scrubbed automatically.

**What happens under the hood:**

1. SIGIL parses the command and finds the placeholder
2. SIGIL decrypts `kalshi/api_key` from the vault
3. SIGIL executes the command with the real value injected
4. SIGIL scrubs any output that might contain the secret
5. The agent receives only the scrubbed output

---

## 🔥 Troubleshooting

### ❌ "bubblewrap not found"

Install bubblewrap on Debian/Ubuntu:

```bash
sudo apt-get install bubblewrap
```

> ✅ Verify with `bwrap --version`

### ❌ "Permission denied on settings.json"

Check the file permissions:

```bash
ls -la ~/.claude/settings.json
```

If the file is owned by root, fix the ownership:

```bash
sudo chown $USER:$USER ~/.claude/settings.json
```

### ❌ "Daemon not running"

Start the SIGIL daemon:

```bash
sigild
```

> ✅ Verify with `sigil doctor`

### ❌ WSL1 detected (WSL2 required)

Check your WSL version:

```bash
wsl --status
```

If you're on WSL1, upgrade to WSL2:

```bash
wsl --set-default-version 2
```

---

## 👉 Next Steps

- [Per-Agent Setup Guides](agents/claude-code.md) — detailed instructions for your agent
- [Concepts and Architecture](concepts.md) — understand how SIGIL works
- [sigil help topics](../README.md#-in-binary-documentation) — runtime documentation with `sigil help <topic>`

---

## 🚧 Known Limitations

- **No native Windows support** — WSL2 is required for Windows users
- **macOS sandbox limitations** — macOS lacks PID namespace and mount namespace isolation
- **Hook coverage varies** — See [Per-Agent Setup Guides](agents/) for detailed coverage information
