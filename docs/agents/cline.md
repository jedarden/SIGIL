# 🤖 Cline Setup Guide

> Setup for SIGIL with Cline — Moderate coverage (Layers 2-4 active, limited hooks via VS Code).

---

## 📋 Overview

| Aspect | Details |
|--------|---------|
| **Coverage Tier** | ⚠️ Moderate |
| **Layers Active** | 2-4 (Proxy Shell, Filesystem Monitor, Sandbox) |
| **Hook Support** | ⚠️ Limited (VS Code extension) |
| **Platform Support** | 🐧 Linux, 🪟 WSL2, 🍎 macOS |

---

## 📋 Prerequisites

Before setting up SIGIL with Cline:

- ✅ SIGIL installed (`sigil --version`)
- ✅ Vault initialized (`sigil init`)
- ✅ At least one secret added (`sigil add <path>`)
- ✅ Cline (VS Code extension) installed
- ✅ VS Code configured
- ✅ SIGIL daemon running (`sigild start`)

---

## 🔧 Installation

### 📝 Step 1: Install the VS Code SIGIL Extension

Cline runs as a VS Code extension. Install SIGIL's VS Code extension:

```bash
# From VS Code Extensions marketplace
code --install-extension sigil.vscode-sigil
```

Or search for "SIGIL" in VS Code Extensions.

---

### ✅ Step 2: Configure VS Code Settings

Add to your VS Code `settings.json`:

```json
{
  "sigil.enabled": true,
  "sigil.proxyShell": true,
  "sigil.fileMonitor": true,
  "sigil.sandbox": true,
  "sigil.vaultPath": "~/.sigil/vault"
}
```

---

### 🔧 Step 3: Setup Cline Integration

Run the SIGIL setup command:

```bash
sigil setup cline
```

This command:

1. Configures VS Code extension settings
2. Enables SIGIL integration for Cline
3. Sets up the proxy shell wrapper
4. Verifies filesystem monitoring

Expected output:

```
🔧 Installing SIGIL hooks for Cline...
✅ VS Code extension configured
✅ Proxy shell enabled
✅ Filesystem monitor active
✅ Cline integration complete
```

---

### 🧪 Step 4: Verify Installation

```bash
# Check VS Code extension is loaded
code --list-extensions | grep sigil

# Verify daemon is running
sigil doctor
```

---

## ✅ What's Protected

With Cline, **Layers 2-4** are active:

| Layer | Protection | Status |
|-------|-----------|--------|
| **1. Agent Hooks** | Tool call interception | ⚠️ Limited (VS Code events) |
| **2. Proxy Shell** | Command interception | ✅ Active |
| **3. Filesystem Monitor** | Secret write detection | ✅ Active |
| **4. Sandbox** | Process isolation | ✅ Active (Linux only) |
| **5. Vault** | Encrypted storage | ✅ Active |
| **6. Canary Monitoring** | Unauthorized access detection | ⚠️ Limited |

### 🛡️ What Actually Gets Protected

| Scenario | Protected | Notes |
|----------|-----------|-------|
| Commands from Cline | ✅ Yes | Via proxy shell wrapper |
| File edits | ⚠️ Partial | Filesystem monitor detects writes |
| Terminal commands | ✅ Yes | Via SIGIL shell |
| Extension output | ⚠️ Limited | VS Code event interception |
| LLM context | ❌ No | Cline can see secrets in prompts |

---

## 🚧 What's Not Protected

Cline has **moderate coverage gaps** due to limited hook support:

| Gap | Description | Risk Level |
|-----|-------------|------------|
| **Limited tool interception** | Some tools bypass SIGIL | 🟠 Medium |
| **No input scrubbing** | Secrets in prompts may leak | 🔴 High |
| **No output scrubbing** | Tool output may contain secrets | 🟠 Medium |
| **LLM context exposure** | Secrets may appear in conversation | 🔴 High |
| **VS Code dependency** | Requires extension to be loaded | 🟡 Low |

> ⚠️ **Warning**: Cline with SIGIL provides moderate protection. The VS Code extension adds some interception, but secrets in prompts are still visible to the LLM.

---

## 🎯 Example Session

### 🔑 Using SIGIL with Cline

```
User: Add my OpenAI API key and generate code
Cline: I'll add your OpenAI API key and generate some code.

[Via SIGIL VS Code extension]
Command: sigil add openai/api_key
Result: ✅ Secret added

[In Cline conversation]
User: Create a Python script that uses the OpenAI API

Cline generates:
```python
import openai
import os

# Use SIGIL environment variable
client = openai.Client(api_key=os.environ.get("SIGIL_openai_api_key"))

response = client.chat.completions.create(
    model="gpt-4",
    messages=[{"role": "user", "content": "Hello"}]
)
```

[Terminal execution via SIGIL shell]
Command: python script.py
Output: ChatCompletion(id='chatcmpl-123', ...)
(API key scrubbed from output)
```

### 🔍 Filesystem Detection

```
User: Create a config file with my database credentials
Cline: I'll create a config file with your database credentials.

[Filesystem Monitor Alert]
⚠️  Secret detected in write operation
File: /path/to/project/db_config.py
Pattern: password = "*
Action: Blocked (use SIGIL vault instead)

Suggestion: Use environment variable:
password = os.getenv("SIGIL_db_password")
```

---

## 🔧 Manual Workflow

For better protection with Cline:

### 🔐 For Commands with Secrets

Use the SIGIL shell wrapper in terminal:

```bash
# Cline can invoke this via VS Code terminal
sigil exec 'python script.py'
```

### 📁 For Configuration Files

Use environment variable placeholders:

```python
# Instead of:
API_KEY = "sk_live_abc123xyz789"

# Use:
API_KEY = os.getenv("SIGIL_my_api_key")
```

SIGIL will resolve these at runtime.

---

## 🔥 Troubleshooting

### ❌ "VS Code extension not loaded"

> ✅ **Fix**: Reload VS Code window

```bash
# From command palette
# > Developer: Reload Window

# Or restart VS Code
code --reload
```

---

### ❌ "SIGIL shell not active in terminal"

> ✅ **Fix**: Configure terminal profile

Add to VS Code `settings.json`:

```json
{
  "terminal.integrated.profiles.linux": {
    "sigil": {
      "path": "/home/user/.sigil/shell/sigil-shell-wrapper",
      "args": []
    }
  },
  "terminal.integrated.defaultProfile.linux": "sigil"
}
```

---

### ❌ "Filesystem monitor not detecting writes"

> ✅ **Fix**: Ensure daemon is running

```bash
# Start daemon
sigild start

# Verify monitoring is active
sigil doctor | grep monitor
```

---

### ❌ "Secrets visible in LLM context"

> ✅ **Response**: This is a known limitation

Cline sends content to the LLM. Mitigation:

1. **Use placeholder patterns** in code
2. **Avoid including secret files** in conversations
3. **Use environment variables** instead of hardcoding
4. **Review conversation** for accidental secret exposure

---

### ❌ "Extension conflicts with other tools"

> ✅ **Fix**: Adjust extension priority

Add to VS Code `settings.json`:

```json
{
  "sigil.priority": 100,
  "sigil.coexist": true
}
```

---

## 📊 Risk Assessment

| Threat | Protection Level | Notes |
|--------|-----------------|-------|
| Agent reads secret from vault | ✅ Protected | Encrypted storage, daemon authentication |
| Agent writes secret to file | ✅ Protected | Filesystem monitor detects and blocks |
| Agent runs command with secret | ✅ Protected | Via proxy shell |
| Agent sees secret in output | ⚠️ Partial | Protected with SIGIL shell |
| Secret sent to LLM | ❌ Not protected | Cline sends content to LLM |
| Agent memorizes secret | ❌ Not protected | No mitigation possible |

---

## 🆚 Comparison with Other Agents

| Feature | Cline | Aider | Cursor | Claude Code |
|---------|-------|-------|--------|-------------|
| Hook support | ⚠️ Limited | ❌ None | ❌ None | ✅ Comprehensive |
| VS Code integration | ✅ Native | ❌ | ❌ | ✅ |
| Input scrubbing | ❌ | ❌ | ❌ | ✅ |
| Output scrubbing | ⚠️ Limited | ❌ | ❌ | ✅ |
| Filesystem monitor | ✅ | ✅ | ✅ | ✅ |
| Proxy shell | ✅ | ✅ Manual | ✅ Manual | ✅ Auto |
| Overall protection | ⚠️ Moderate | ⚠️ Basic | ⚠️ Basic | ✅ Comprehensive |

---

## 💡 Best Practices for Cline Users

1. **Install SIGIL VS Code extension** for better integration
2. **Use SIGIL terminal profile** in VS Code
3. **Keep secrets out of source files** — use environment variables
4. **Review .gitignore** — exclude secret files
5. **Check audit logs** regularly for suspicious activity
6. **Be cautious with LLM context** — avoid including secret files

---

## 🎯 Cline-Specific Configuration

### 📝 VS Code settings.json

```json
{
  // SIGIL Integration
  "sigil.enabled": true,
  "sigil.proxyShell": true,
  "sigil.fileMonitor": true,
  "sigil.sandbox": true,

  // Terminal
  "terminal.integrated.defaultProfile.linux": "sigil",
  "terminal.integrated.profiles.linux": {
    "sigil": {
      "path": "${env:HOME}/.sigil/shell/sigil-shell-wrapper",
      "args": []
    }
  },

  // File watching
  "files.watcherExclude": {
    "**/.sigil/**": true,
    "**/vault/**": true
  }
}
```

### 💉 Using Environment Variables

```python
# Python
api_key = os.getenv("SIGIL_openai_api_key")

# Node.js
const apiKey = process.env.SIGIL_OPENAI_API_KEY;

# Bash
curl -H "Authorization: Bearer $SIGIL_MY_API_KEY" https://api.example.com
```

---

## 👉 Next Steps

- [Quickstart Guide](../quickstart.md) — Get SIGIL basics working
- [Concepts and Architecture](../concepts.md) — Understand how SIGIL works
- [Claude Code Guide](claude-code.md) — For comprehensive protection
- [Generic Agent Guide](generic.md) — General workflow for unsupported agents
