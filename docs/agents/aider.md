# 🤖 Aider Setup Guide

> Setup for SIGIL with Aider — Basic coverage (Layers 2-3 active, no hooks available).

---

## 📋 Overview

| Aspect | Details |
|--------|---------|
| **Coverage Tier** | ⚠️ Basic |
| **Layers Active** | 2-3 (Proxy Shell, Filesystem Monitor) |
| **Hook Support** | ❌ None |
| **Platform Support** | 🐧 Linux, 🪟 WSL2, 🍎 macOS |

---

## 📋 Prerequisites

Before setting up SIGIL with Aider:

- ✅ SIGIL installed (`sigil --version`)
- ✅ Vault initialized (`sigil init`)
- ✅ At least one secret added (`sigil add <path>`)
- ✅ Aider installed and working
- ✅ SIGIL daemon running (`sigild start`)

---

## 🔧 Installation

### 📝 Step 1: Start the SIGIL Daemon

```bash
sigild start
```

The daemon provides:
- Proxy shell for command interception
- Filesystem monitoring
- Secret placeholder resolution

---

### ✅ Step 2: Configure Aider to Use SIGIL Proxy Shell

Aider doesn't support hooks, so protection relies on manual proxy shell usage.

**Configure Aider's shell:**

Add to your `~/.aider.conf.yml`:

```yaml
# Use SIGIL proxy shell for command execution
shell: /home/user/.sigil/shell/sigil-shell-wrapper
```

Or use environment variable:

```bash
export SIGIL_SHELL_ENABLED=true
aider
```

---

### 🔧 Step 3: Verify Filesystem Monitoring

```bash
# Verify monitoring is active
sigil doctor

# Check audit log for filesystem events
tail -f ~/.sigil/vault/audit.jsonl
```

---

## ✅ What's Protected

With Aider, **Layers 2-3** are active:

| Layer | Protection | Status |
|-------|-----------|--------|
| **1. Agent Hooks** | Tool call interception | ❌ Not supported by Aider |
| **2. Proxy Shell** | Command interception | ✅ Active (when configured) |
| **3. Filesystem Monitor** | Secret write detection | ✅ Active |
| **4. Sandbox** | Process isolation | ⚠️ Manual only |
| **5. Vault** | Encrypted storage | ✅ Active |
| **6. Canary Monitoring** | Unauthorized access detection | ⚠️ Limited |

### 🛡️ What Actually Gets Protected

| Scenario | Protected | Notes |
|----------|-----------|-------|
| Commands via configured shell | ✅ Yes | Full interception and scrubbing |
| Secret writes to disk | ✅ Yes | Filesystem monitor detects |
| Git operations with secrets | ✅ Yes | If using proxy shell |
| File edits with secrets | ⚠️ Limited | Monitor detects writes, not edits |
| LLM context | ❌ No | Aider can see secrets in prompts |

---

## 🚧 What's Not Protected

Aider has **significant coverage gaps** due to lack of hooks:

| Gap | Description | Risk Level |
|-----|-------------|------------|
| **No tool interception** | Aider can run commands directly | 🔴 High |
| **No input scrubbing** | Secrets in prompts may leak to LLM | 🔴 High |
| **No output scrubbing** | Tool output may contain secrets | 🟠 Medium |
| **LLM context exposure** | Secrets may appear in conversation | 🔴 High |
| **Limited canary detection** | Decoy responses may not trigger | 🟠 Medium |

> ⚠️ **Warning**: Aider with SIGIL provides baseline protection only. Aider sends file contents and command outputs to the LLM, which may include secrets if not carefully managed.

---

## 🎯 Example Session

### 🔑 Using SIGIL with Aider

```bash
# Start Aider with SIGIL proxy shell
export SIGIL_SHELL_ENABLED=true
aider

User: Add my GitHub token and create a commit
Aider: I'll add your GitHub token and create a commit.

[In Aider]
/add .git/config
/run git remote set-url origin https://{{secret:github/token}}@github.com/repo.git
/run git commit -m "Add feature"
/run git push

Output:
✓ File added
✓ Commit created
✓ Pushed to origin
(Authorization token scrubbed from output)
```

### 🔍 Filesystem Detection

```
User: Update the config with my API key
Aider: I'll update the config file with your API key.

[Filesystem Monitor Alert]
⚠️  Secret detected in write operation
File: /path/to/project/config.toml
Pattern: api_key = "sk_live_*
Action: Blocked (use SIGIL vault instead)

Suggestion: Use placeholder in config:
api_key = "{{secret:my/api_key}}"
```

---

## 🔧 Manual Workflow

Since Aider lacks hooks, you must manually use SIGIL:

### 🔄 For Git Operations

**Don't** put secrets in git commands:
```bash
git remote set-url origin https://token@github.com/repo.git
```

**Instead**, use placeholders:
```bash
git remote set-url origin https://{{secret:github/token}}@github.com/repo.git
```

Then use SIGIL's Git credential helper:
```bash
sigil setup git
```

### 📁 For Configuration Files

**Don't** let Aider write secrets directly:
```python
API_KEY = "sk_live_abc123xyz789"
```

**Instead**, use placeholder patterns:
```python
API_KEY = os.getenv("SIGIL_my_api_key")  # SIGIL will resolve
# Or in templates:
API_KEY = "{{secret:my/api_key}}"
```

---

## 🔥 Troubleshooting

### ❌ "Commands run without SIGIL interception"

> ✅ **Fix**: Configure Aider to use SIGIL shell

Edit `~/.aider.conf.yml`:

```yaml
# Use SIGIL proxy shell
shell: ~/.local/bin/sigil-shell-wrapper

# Or enable via environment
env:
  SIGIL_SHELL_ENABLED: "true"
```

---

### ❌ "Secrets visible in LLM context"

> ✅ **Response**: This is a known limitation of Aider

Aider sends file contents to the LLM. Mitigation strategies:

1. **Use .gitignore**: Ensure files with secrets are ignored
2. **Use placeholder templates**: Keep secrets out of source files
3. **Use SIGIL Git credential helper**: For git operations
4. **Review conversation**: Check for accidental secret exposure

---

### ❌ "Filesystem monitor not detecting writes"

> ✅ **Fix**: Ensure daemon is running

```bash
# Start daemon
sigild start

# Verify monitoring is active
sigil doctor | grep monitor

# Check audit log
tail -f ~/.sigil/vault/audit.jsonl
```

---

### ❌ "No hook support available"

> ✅ **Expected**: Aider doesn't support hooks

This is a limitation of Aider, not SIGIL. For better protection:

- Use Claude Code (comprehensive hook support)
- Use Codex CLI (PreToolUse hooks)
- Or manually configure SIGIL shell for Aider

---

## 📊 Risk Assessment

| Threat | Protection Level | Notes |
|--------|-----------------|-------|
| Agent reads secret from vault | ✅ Protected | Encrypted storage, daemon authentication |
| Agent writes secret to file | ✅ Protected | Filesystem monitor detects and blocks |
| Agent runs command with secret | ⚠️ Partial | Protected only with SIGIL shell |
| Agent sees secret in output | ⚠️ Partial | Protected only with SIGIL shell |
| Secret sent to LLM | ❌ Not protected | Aider sends content to LLM |
| Agent memorizes secret | ❌ Not protected | No mitigation possible |

---

## 🆚 Comparison with Other Agents

| Feature | Aider | Cursor | Claude Code | Codex CLI |
|---------|-------|--------|-------------|-----------|
| Hook support | ❌ None | ❌ None | ✅ Comprehensive | ✅ PreToolUse |
| Input scrubbing | ❌ | ❌ | ✅ | ✅ |
| Output scrubbing | ❌ | ❌ | ✅ | ⚠️ Limited |
| Filesystem monitor | ✅ | ✅ | ✅ | ✅ |
| Proxy shell | ✅ Manual | ✅ Manual | ✅ Auto | ✅ Auto |
| Git integration | ⚠️ Manual | ⚠️ Manual | ✅ Auto | ✅ Auto |
| Overall protection | ⚠️ Basic | ⚠️ Basic | ✅ Comprehensive | ✅ Strong |

---

## 💡 Best Practices for Aider Users

1. **Configure SIGIL shell** in `~/.aider.conf.yml`
2. **Use Git credential helper**: `sigil setup git`
3. **Keep secrets out of source files** — use placeholders
4. **Review .gitignore** — exclude secret files
5. **Check audit logs** regularly for suspicious activity
6. **Be cautious with LLM context** — avoid including secret files

---

## 🎯 Aider-Specific Configuration

### 📝 ~/.aider.conf.yml

```yaml
# SIGIL Integration
shell: ~/.sigil/shell/sigil-shell-wrapper

# Git integration
git: true
gitignore: true

# Security
safe_mode: true  # Ask before running commands

# Environment
env:
  SIGIL_SHELL_ENABLED: "true"
```

### 🎫 Using SIGIL Git Credential Helper

```bash
# Setup Git credential helper
sigil setup git

# Add GitHub token
sigil add github/token

# Use in Aider
/run git remote set-url origin https://github.com/user/repo.git
/run git push
# SIGIL will inject credentials automatically
```

---

## 👉 Next Steps

- [Quickstart Guide](../quickstart.md) — Get SIGIL basics working
- [Concepts and Architecture](../concepts.md) — Understand how SIGIL works
- [Claude Code Guide](claude-code.md) — For comprehensive protection
- [Git Credential Helper](../topics/vault.md) — Git-specific setup
