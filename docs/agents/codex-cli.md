# 🤖 Codex CLI Setup Guide

> Setup for SIGIL with Codex CLI — Strong coverage (Layers 2-4 active).

---

## 📋 Overview

| Aspect | Details |
|--------|---------|
| **Coverage Tier** | ✅ Strong |
| **Layers Active** | 2-4 (Proxy Shell, Filesystem Monitor, Sandbox) |
| **Hook Support** | PreToolUse |
| **Platform Support** | 🐧 Linux, 🪟 WSL2, 🍎 macOS (limited) |

---

## 📋 Prerequisites

Before setting up SIGIL with Codex CLI:

- ✅ SIGIL installed (`sigil --version`)
- ✅ Vault initialized (`sigil init`)
- ✅ At least one secret added (`sigil add <path>`)
- ✅ Codex CLI installed and working
- ✅ Bubblewrap available (Linux only) for sandbox features

---

## 🔧 Installation

### 📝 Step 1: Run the Setup Command

```bash
sigil setup codex-cli
```

This command:

1. Creates the Codex CLI hooks directory if needed
2. Adds PreToolUse hooks for command interception
3. Configures the proxy shell for command execution
4. Verifies sandbox availability (Linux)

Expected output:

```
🔧 Installing SIGIL hooks for Codex CLI...
✅ PreToolUse hook installed
✅ Proxy shell configured
✅ Sandbox verified (bubblewrap)
✅ Codex CLI setup complete
```

---

### ✅ Step 2: Verify Installation

```bash
cat ~/.codex/hooks/pre-tool-use.sh
```

You should see SIGIL hook script:

```bash
#!/bin/bash
# SIGIL PreToolUse hook for Codex CLI
sigil-hook pre-tool-use "$@"
```

---

## ✅ What's Protected

With Codex CLI, **Layers 2-4** are active:

| Layer | Protection | Status |
|-------|-----------|--------|
| **1. Agent Hooks** | Tool call interception | ✅ PreToolUse only |
| **2. Proxy Shell** | Command interception | ✅ Active |
| **3. Filesystem Monitor** | Secret write detection | ✅ Active |
| **4. Sandbox** | Process isolation | ✅ Active (Linux) |
| **5. Vault** | Encrypted storage | ✅ Active |
| **6. Canary Monitoring** | Unauthorized access detection | ⚠️ Limited |

### 🔧 Tool-by-Tool Coverage

| Tool | Input Scrubbing | Output Scrubbing | Notes |
|------|----------------|------------------|-------|
| Bash | ✅ | ✅ | Commands are intercepted and scrubbed |
| Write | ✅ | N/A | File content scanned for secrets |
| Edit | ✅ | N/A | Diff content scanned for secrets |
| Read | N/A | ✅ | File content scrubbed if contains secrets |
| Terminal | ✅ | ✅ | Full session protection |

---

## 🚧 What's Not Protected

Compared to Claude Code, Codex CLI has some coverage gaps:

| Gap | Description | Mitigation |
|-----|-------------|------------|
| **No PostToolUse hook** | Output scrubbing relies on proxy | Use proxy shell for all commands |
| **No UserPromptSubmit** | Input may reach agent before scrubbing | Be cautious with explicit secret mentions |
| **No MCP integration** | Direct secret access not available | Use `sigil exec` for operations |
| **Limited canary support** | Decoy responses may not trigger | Review audit logs regularly |
| **macOS limitations** | Sandbox not available on macOS | Use filesystem monitoring only |

> ⚠️ **Warning**: Codex CLI with SIGIL provides good protection for Linux systems. macOS users have reduced coverage due to sandbox limitations.

---

## 🎯 Example Session

### ➕ Adding a Secret

```
User: Add my OpenAI API key
Codex: I'll add your OpenAI API key to SIGIL.
Command: sigil add openai/api_key
Result: ✅ Secret added: openai/api_key
```

### 🔑 Using a Secret

```
User: List my OpenAI fine-tuned models
Codex: I'll query the OpenAI API for your fine-tuned models.
Command: sigil exec 'openai api fine_tunes.list -k {{secret:openai/api_key}}'
Result: {
  "data": [
    {"id": "ft-abc123", "model": "curie", ...}
  ],
  "object": "list"
}
```

---

## 🔧 Hook Behavior

### 🪝 PreToolUse Hook

Runs **before** each tool call:

1. **Scrubbs input** for secret values
2. **Replaces placeholders** with `{{secret:path}}` format
3. **Logs the access** attempt
4. **Returns modified input** to Codex

### 🏗️ Sandbox Integration

On Linux, Codex CLI tools run inside a bubblewrap sandbox:

```bash
bwrap \
  --ro-bind / / \
  --dev /dev \
  --proc /proc \
  --unshare-pid \
  --unshare-net \
  sigil-shell 'command with {{secret:path}}'
```

On macOS, sandbox is not available — commands run in proxy shell only.

---

## 🔥 Troubleshooting

### ❌ "PreToolUse hook not found"

> ✅ **Fix**: Run setup again

```bash
sigil setup codex-cli
```

Then verify:

```bash
cat ~/.codex/hooks/pre-tool-use.sh
```

---

### ❌ "Sandbox not available" (macOS)

> ✅ **Expected**: macOS doesn't support bubblewrap

SIGIL will use proxy shell mode instead:

```
⚠️  Warning: Sandbox not available on macOS
✅ Falling back to proxy shell mode
```

---

### ❌ "Bubblewrap not found" (Linux)

> ✅ **Fix**: Install bubblewrap

```bash
# Ubuntu/Debian
sudo apt install bubblewrap

# Arch
sudo pacman -S bubblewrap

# Fedora
sudo dnf install bubblewrap
```

---

### ❌ "Secret not found in vault"

> ✅ **Fix**: Add the missing secret

```bash
sigil add <path>
```

Or list available secrets:

```bash
sigil list
```

---

### ❌ "Proxy shell connection failed"

> ✅ **Fix**: Ensure SIGIL daemon is running

```bash
sigild start

# Verify
sigil doctor
```

---

## 📊 Session Example

Here's a complete session showing SIGIL protection with Codex CLI:

```
User: Add my AWS credentials and list S3 buckets
Codex: I'll add your AWS credentials and list your S3 buckets.
Command: sigil add aws/access_key_id
Enter secret value: AKIAIOSFODNN7EXAMPLE
Command: sigil add aws/secret_access_key
Enter secret value: wJalrXUtnFEMI/K7MDENG...
✅ Secrets added

Command: sigil exec 'aws s3 ls --profile default'
Output:
2023-10-01 12:34:56 my-bucket
2023-10-02 09:15:30 project-files
2023-10-05 16:20:45 backup-archive
✅ Command complete (output scrubbed)
```

---

## 🆚 Comparison with Claude Code

| Feature | Codex CLI | Claude Code |
|---------|-----------|-------------|
| PreToolUse hook | ✅ | ✅ |
| PostToolUse hook | ❌ | ✅ |
| UserPromptSubmit hook | ❌ | ✅ |
| MCP integration | ❌ | ✅ |
| Sandbox support | ✅ (Linux only) | ✅ |
| Proxy shell | ✅ | ✅ |
| Canary monitoring | ⚠️ Limited | ✅ Full |

---

## 👉 Next Steps

- [Quickstart Guide](../quickstart.md) — Get SIGIL basics working
- [Concepts and Architecture](../concepts.md) — Understand how SIGIL works
- [Claude Code Guide](claude-code.md) — Compare with comprehensive coverage
- [Generic Agent Guide](generic.md) — For unsupported agents
