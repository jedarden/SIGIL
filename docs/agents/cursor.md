# 🤖 Cursor Setup Guide

> Setup for SIGIL with Cursor — Basic coverage (Layers 2-3 active, no hooks available).

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

Before setting up SIGIL with Cursor:

- ✅ SIGIL installed (`sigil --version`)
- ✅ Vault initialized (`sigil init`)
- ✅ At least one secret added (`sigil add <path>`)
- ✅ Cursor installed and working
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

### ✅ Step 2: Configure Cursor to Use SIGIL Proxy Shell

Cursor doesn't support hooks, so protection relies on the proxy shell:

**Option A: Terminal Environment**

Add to your `~/.bashrc` or `~/.zshrc`:

```bash
# Use SIGIL proxy shell for terminal sessions
export SHELL="$HOME/.sigil/shell/sigil-shell-wrapper"
```

**Option B: Per-Command Prefix**

For commands that need secrets, use the proxy shell directly:

```bash
sigil exec 'your-command-here'
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

With Cursor, **Layers 2-3** are active:

| Layer | Protection | Status |
|-------|-----------|--------|
| **1. Agent Hooks** | Tool call interception | ❌ Not supported by Cursor |
| **2. Proxy Shell** | Command interception | ✅ Active (when used) |
| **3. Filesystem Monitor** | Secret write detection | ✅ Active |
| **4. Sandbox** | Process isolation | ⚠️ Manual only |
| **5. Vault** | Encrypted storage | ✅ Active |
| **6. Canary Monitoring** | Unauthorized access detection | ⚠️ Limited |

### 🛡️ What Actually Gets Protected

| Scenario | Protected | Notes |
|----------|-----------|-------|
| Commands via `sigil exec` | ✅ Yes | Full interception and scrubbing |
| Secret writes to disk | ✅ Yes | Filesystem monitor detects |
| Direct terminal commands | ⚠️ Maybe | Only if using proxy shell wrapper |
| File edits with secrets | ⚠️ Limited | Monitor detects writes, not edits |
| Clipboard access | ❌ No | Cursor can read clipboard |

---

## 🚧 What's Not Protected

Cursor has **significant coverage gaps** due to lack of hooks:

| Gap | Description | Risk Level |
|-----|-------------|------------|
| **No tool interception** | Cursor can run commands directly | 🔴 High |
| **No input scrubbing** | Secrets in prompts may leak | 🔴 High |
| **No output scrubbing** | Tool output may contain secrets | 🟠 Medium |
| **No MCP integration** | Direct secret access unavailable | 🟡 Low |
| **Limited canary detection** | Decoy responses may not trigger | 🟠 Medium |

> ⚠️ **Warning**: Cursor with SIGIL provides baseline protection only. Agents with hook support (Claude Code, Codex CLI) provide significantly better protection.

---

## 🎯 Example Session

### 🔑 Using SIGIL Proxy Shell

```
User: Add my GitHub token and create a new repo
Cursor: I'll add your GitHub token and create a repository.
Command: sigil add github/token
Enter secret value: ghp_xxxxxxxxxxxx
✅ Secret added

Command: sigil exec 'gh repo create my-new-repo --private'
Output: ✓ Created repository username/my-new-repo
(Authorization header scrubbed from output)
```

### 🔍 Filesystem Detection

```
User: Create a .env file with my API key
Cursor: I'll create a .env file with your API key.
Command: cat > .env << EOF
API_KEY=sk_live_abc123xyz789
EOF

[Filesystem Monitor Alert]
⚠️  Secret detected in write operation
File: /path/to/project/.env
Pattern: API_KEY=sk_live_*
Action: Blocked (use SIGIL vault instead)
```

---

## 🔧 Manual Workflow

Since Cursor lacks hooks, you must manually use SIGIL:

### 🔐 For Commands with Secrets

**Don't** let Cursor run this directly:
```bash
curl -H "Authorization: Bearer $MY_API_KEY" https://api.example.com
```

**Instead**, use `sigil exec`:
```bash
sigil exec 'curl -H "Authorization: Bearer {{secret:my/api_key}}" https://api.example.com'
```

### 📁 For Configuration Files

**Don't** let Cursor write secrets to files:
```bash
echo "API_KEY=sk_live_abc123" > .env
```

**Instead**, use placeholder patterns:
```bash
echo "API_KEY={{secret:my/api_key}}" > .env.template
```

Then use SIGIL to resolve at runtime.

---

## 🔥 Troubleshooting

### ❌ "Commands run without SIGIL interception"

> ✅ **Fix**: Use `sigil exec` for all commands with secrets

Cursor doesn't intercept tool calls, so you must prefix commands:

```bash
# Instead of:
curl https://api.example.com

# Use:
sigil exec 'curl https://api.example.com'
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

### ❌ "Secret leaked in conversation"

> ✅ **Response**: Clear context and rotate secret

If a secret appears in Cursor's conversation:

1. **Clear the conversation** in Cursor
2. **Rotate the compromised secret**: `sigil rotate <path>`
3. **Review audit log**: `tail -f ~/.sigil/vault/audit.jsonl`
4. **Enable canary monitoring**: `sigil canary enable <path>`

---

### ❌ "No hook support available"

> ✅ **Expected**: Cursor doesn't support hooks

This is a limitation of Cursor, not SIGIL. For better protection:

- Use Claude Code (comprehensive hook support)
- Use Codex CLI (PreToolUse hooks)
- Or manually use `sigil exec` for all sensitive operations

---

## 📊 Risk Assessment

| Threat | Protection Level | Notes |
|--------|-----------------|-------|
| Agent reads secret from vault | ✅ Protected | Encrypted storage, daemon authentication |
| Agent writes secret to file | ✅ Protected | Filesystem monitor detects and blocks |
| Agent runs command with secret | ⚠️ Partial | Protected only with `sigil exec` |
| Agent sees secret in output | ⚠️ Partial | Protected only with `sigil exec` |
| Agent memorizes secret | ❌ Not protected | No mitigation possible |
| Agent exfiltrates via tool call | ❌ Not protected | No hooks to intercept |

---

## 🆚 Comparison with Other Agents

| Feature | Cursor | Claude Code | Codex CLI |
|---------|--------|-------------|-----------|
| Hook support | ❌ None | ✅ Comprehensive | ✅ PreToolUse |
| Input scrubbing | ❌ | ✅ | ✅ |
| Output scrubbing | ❌ | ✅ | ⚠️ Limited |
| Filesystem monitor | ✅ | ✅ | ✅ |
| Proxy shell | ✅ Manual | ✅ Auto | ✅ Auto |
| Sandbox | ⚠️ Manual | ✅ Auto | ✅ Auto |
| Overall protection | ⚠️ Basic | ✅ Comprehensive | ✅ Strong |

---

## 💡 Best Practices for Cursor Users

1. **Always use `sigil exec`** for commands with secrets
2. **Review audit logs regularly** for suspicious activity
3. **Enable canary monitoring** for high-value secrets
4. **Never store secrets in project files** — use the vault
5. **Clear conversation** if secrets appear in context
6. **Consider using Claude Code** for sensitive work

---

## 👉 Next Steps

- [Quickstart Guide](../quickstart.md) — Get SIGIL basics working
- [Concepts and Architecture](../concepts.md) — Understand how SIGIL works
- [Claude Code Guide](claude-code.md) — For comprehensive protection
- [Generic Agent Guide](generic.md) — General workflow for unsupported agents
