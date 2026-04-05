# 🤖 Claude Code Setup Guide

> Complete setup for SIGIL with Claude Code — Comprehensive coverage (all 6 layers active).

---

## 📋 Overview

| Aspect | Details |
|--------|---------|
| **Coverage Tier** | ✅ Comprehensive |
| **Layers Active** | 1-6 (All) |
| **Hook Support** | PreToolUse, PostToolUse, UserPromptSubmit |
| **MCP Integration** | ✅ Supported |
| **Platform Support** | 🐧 Linux, 🪟 WSL2, 🍎 macOS |

---

## 📋 Prerequisites

Before setting up SIGIL with Claude Code:

- ✅ SIGIL installed (`sigil --version`)
- ✅ Vault initialized (`sigil init`)
- ✅ At least one secret added (`sigil add <path>`)
- ✅ Claude Code installed and working
- ✅ `~/.claude/` directory exists

---

## 🔧 Installation

### 📝 Step 1: Run the Setup Command

```bash
sigil setup claude-code
```

This command:

1. Creates `~/.claude/settings.json` if it doesn't exist
2. Adds SIGIL hooks to the configuration
3. Installs the MCP server for SIGIL
4. Verifies hook installation

Expected output:

```
🔧 Installing SIGIL hooks for Claude Code...
✅ PreToolUse hook installed
✅ PostToolUse hook installed
✅ UserPromptSubmit hook installed
✅ MCP server configured
✅ Claude Code setup complete
```

---

### ✅ Step 2: Verify Installation

```bash
cat ~/.claude/settings.json | grep -A 10 sigil
```

You should see SIGIL hooks configured:

```json
{
  "hooks": {
    "PreToolUse": [
      {
        "type": "command",
        "command": "sigil-hook",
        "args": ["pre-tool-use"]
      }
    ],
    "PostToolUse": [
      {
        "type": "command",
        "command": "sigil-hook",
        "args": ["post-tool-use"]
      }
    ],
    "UserPromptSubmit": [
      {
        "type": "command",
        "command": "sigil-hook",
        "args": ["user-prompt-submit"]
      }
    ]
  },
  "mcpServers": {
    "sigil": {
      "command": "sigil-mcp",
      "args": []
    }
  }
}
```

---

## ✅ What's Protected

With Claude Code, **all 6 layers** are active:

| Layer | Protection | Status |
|-------|-----------|--------|
| **1. Agent Hooks** | Tool call interception | ✅ Active |
| **2. Proxy Shell** | Command interception | ✅ Active |
| **3. Filesystem Monitor** | Secret write detection | ✅ Active |
| **4. Sandbox** | Process isolation | ✅ Active |
| **5. Vault** | Encrypted storage | ✅ Active |
| **6. Canary Monitoring** | Unauthorized access detection | ✅ Active |

### 🔧 Tool-by-Tool Coverage

| Tool | Input Scrubbing | Output Scrubbing | Notes |
|------|----------------|------------------|-------|
| Bash | ✅ | ✅ | Commands are intercepted and scrubbed |
| Write | ✅ | N/A | File content scanned for secrets |
| Edit | ✅ | N/A | Diff content scanned for secrets |
| Read | N/A | ✅ | File content scrubbed if contains secrets |
| MCP | ✅ | ✅ | SIGIL MCP server handles all operations |
| Terminal | ✅ | ✅ | Full session protection |

---

## 🚧 What's Not Protected

Even with comprehensive coverage, some gaps remain:

| Gap | Description | Mitigation |
|-----|-------------|------------|
| **Pre-existing secrets** | Secrets in context before SIGIL | Clear context, restart session |
| **Clipboard** | Agent can access clipboard contents | Use clipboard managers with scrubbing |
| **Browser tools** | Web-based tools may leak | Use SIGIL proxy for HTTP requests |
| **Extension output** | Some extensions bypass hooks | Review extension permissions |

> ⚠️ **Warning**: Claude Code with SIGIL provides strong protection, but no system is perfect. Regular secret rotation and audit log review are recommended.

---

## 🔧 MCP Integration

SIGIL provides an MCP server for Claude Code. Enable it in your MCP configuration:

### 🔌 Available MCP Tools

| Tool | Description |
|------|-------------|
| `sigil_list` | List available secrets (paths only, never values) |
| `sigil_exec` | Execute command with secret injection + scrubbing |
| `sigil_write` | Write file with secret placeholders resolved |
| `sigil_env` | List environment variable mappings (names only) |
| `sigil_status` | Show session statistics and breach alerts |
| `sigil_list_operations` | List available sealed operations |
| `sigil_request` | Request access to a secret (triggers TUI approval) |
| `sigil_check_access` | Check if access to a secret is granted |

### 🎮 Using MCP Tools

Claude can use SIGIL's MCP tools directly:

```
Claude: List all secrets starting with "aws/"
Tool Call: sigil_list({"prefix": "aws/"})
Result: ["aws/access_key_id", "aws/secret_access_key", "aws/credentials"]

Claude: Execute a command with the AWS credentials
Tool Call: sigil_exec({"command": "aws s3 ls", "sandbox": true})
Result: (scrubbed output)
```

---

## 🎯 Example Session

### ➕ Adding a Secret

```
User: Add my Kalshi API key
Claude: I'll add your Kalshi API key to SIGIL.
Tool Call: sigil_write (simulated)
Result: ✅ Secret added: kalshi/api_key
```

### 🔑 Using a Secret

```
User: Make a request to the Kalshi API
Claude: I'll make a request to the Kalshi API using your stored credentials.
Tool Call: sigil_exec({"command": "curl https://api.kalshi.com/trade/v2/portfolio -H \"Authorization: Bearer {{secret:kalshi/api_key}}\""})
Result: {"balance": 5000.00, "positions": [...]}
```

---

## 🔄 Hook Behavior

### 🪝 PreToolUse Hook

Runs **before** each tool call:

1. **Scrubbs input** for secret values
2. **Replaces placeholders** with `{{secret:path}}` format
3. **Logs the access** attempt
4. **Returns modified input** to Claude

### 🪝 PostToolUse Hook

Runs **after** each tool call:

1. **Scrubbs output** for secret values
2. **Removes exact matches** across 7 encodings
3. **Returns scrubbed output** to Claude
4. **Logs the result** (success/failure)

### 🪝 UserPromptSubmit Hook

Runs **before** each user message:

1. **Scrubbs user input** for accidental secret pastes
2. **Detects canary triggers** (canary file access)
3. **Alerts on suspicious patterns**

---

## 🔥 Troubleshooting

### ❌ "SIGIL hooks not found in settings.json"

> ✅ **Fix**: Run setup again

```bash
sigil setup claude-code
```

Then verify:

```bash
cat ~/.claude/settings.json | grep sigil
```

---

### ❌ "MCP server not responding"

> ✅ **Fix**: Check MCP server configuration

```bash
# Verify SIGIL MCP server exists
which sigil-mcp

# Check Claude MCP logs
tail -f ~/.claude/logs/mcp.log
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

### ❌ "Hook execution failed"

> ✅ **Fix**: Check hook permissions

```bash
# Verify hook script is executable
which sigil-hook

# Check hook logs
tail -f ~/.sigil/hook.log
```

---

## 📊 Session Example

Here's a complete session showing SIGIL protection:

```
User: Add my GitHub token and create a new repository
Claude: I'll add your GitHub token and create a repository.
Tool Call: sigil_request({"secret": "github/token", "reason": "Create new repository", "duration": "5m"})
Result: ⏳ Waiting for TUI approval...

[TUI Approval Dialog]
🔑 Secret Access Request
─────────────────────────────
Agent: claude-session-a7f3e2
Secret: github/token
Reason: "Create new repository"
Duration: 5 minutes
─────────────────────────────
[a] Approve 5 min  [s] Approve session
[d] Deny         [D] Deny + flag

[User presses 'a']

Tool Call Result: ✅ Access granted for 5 minutes

Claude: Creating repository with gh CLI...
Tool Call: sigil_exec({"command": "gh repo create my-new-repo --private"})
Result: ✓ Created repository jedarden/my-new-repo
```

---

## 👉 Next Steps

- [Quickstart Guide](../quickstart.md) — Get SIGIL basics working
- [Concepts and Architecture](../concepts.md) — Understand how SIGIL works
- [Other Agent Guides](.) — Setup guides for Cursor, Aider, and more
