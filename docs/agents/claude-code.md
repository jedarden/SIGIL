# 🤖 Claude Code Setup Guide

> Complete setup for SIGIL with Claude Code — comprehensive protection across all 6 interception layers.

---

## 📋 Prerequisites

Before installing SIGIL for Claude Code, verify you have:

- **Claude Code installed** — Via VS Code extension or standalone CLI
- **SIGIL installed** — See [Quickstart Guide](../quickstart.md)
- **Claude Code settings file** — `~/.claude/settings.json` (auto-created by Claude Code)

> 💡 **Tip**: Run `claude --version` to verify Claude Code is installed.

---

## 🔧 Installation

Run the setup command:

```bash
sigil setup claude-code
```

This will:
1. Back up your existing `settings.json`
2. Add SIGIL hooks to the configuration
3. Configure the MCP server connection
4. Verify the setup

> ⚠️ **Warning**: This modifies `~/.claude/settings.json`. A backup is created at `~/.claude/settings.json.sigil-backup`.

---

## ✅ What's Protected

Claude Code has **comprehensive coverage** across all 6 layers:

| Layer | Protected | Details |
|-------|-----------|---------|
| Layer 5: Input scrubbing | ✅ Yes | UserPromptSubmit hook scrubs secrets in prompts |
| Layer 4: Tool hooks | ✅ Yes | PreToolUse/PostToolUse hooks on all 6 tools |
| Layer 3: Filesystem monitor | ✅ Yes | inotify watches detect secret writes |
| Layer 2: Proxy shell | ✅ Yes | sigil-shell intercepts all bash commands |
| Layer 1: Namespace isolation | ✅ Yes | bubblewrap sandbox (Linux/WSL2) |
| Layer 0: Network isolation | ✅ Yes | Network namespace (Linux/WSL2) |

### Tool Hook Coverage

| Tool | PreToolUse | PostToolUse | What's Protected |
|------|------------|-------------|------------------|
| Bash | ✅ | ✅ | Commands and output |
| Write | ✅ | ✅ | File writes (scrubs secrets before write) |
| Edit | ✅ | ✅ | File edits (scrubs secrets before edit) |
| Read | ✅ | ✅ | File reads (blocks canary files) |
| MCP | ✅ | ✅ | MCP tool calls |
| UserPromptSubmit | ✅ | N/A | User prompts (scrubs before sending to LLM) |

---

## 🚧 What's Not Protected

| Limitation | Explanation |
|------------|-------------|
| Agent memory | If Claude "memorizes" a secret, SIGIL can't prevent recall across sessions |
| Hardcoded secrets | If Claude types a secret directly (not from vault), SIGIL won't catch it |
| Host compromise | SIGIL doesn't protect against a compromised host system |

> 💡 **Tip**: SIGIL protects against **accidental** leakage, not **malicious** agents. If an agent is actively trying to exfiltrate secrets, it may find ways to bypass protections.

---

## 🔌 MCP Integration

SIGIL provides an MCP server for Claude Code with 8 tools:

### Available Tools

| Tool | Description |
|------|-------------|
| `sigil_list` | List available secret paths and types |
| `sigil_exec` | Execute command with injection + scrubbing |
| `sigil_write` | Write file with resolved placeholders |
| `sigil_env` | List available env var mappings (names only) |
| `sigil_status` | Session stats and breach alerts |
| `sigil_list_operations` | List sealed operation descriptions |
| `sigil_request` | Request access to a secret (triggers TUI approval) |
| `sigil_check_access` | Check if access to a secret is granted |

### MCP Configuration

The setup command adds this to your `settings.json`:

```json
{
  "mcpServers": {
    "sigil": {
      "command": "sigil-mcp",
      "args": [],
      "env": {
        "SIGIL_SOCKET": "/run/user/$UID/sigil.sock"
      }
    }
  }
}
```

> ℹ️ **Note**: The MCP server connects to the SIGIL daemon via Unix socket. Make sure the daemon is running: `sigild`

---

## 🎯 Example Session

### Adding a Secret

```bash
$ sigil add openai/api_key
Enter value (will be hidden): sk-ant-...
✓ Added: openai/api_key
```

### Using in Claude Code

Now in Claude Code:

```
User: Call the OpenAI API with my key

Claude: I'll use the sigil_exec tool to call the OpenAI API:
[sigil_exec({command: 'curl https://api.openai.com/v1/models 
  -H "Authorization: Bearer {{secret:openai/api_key}}"'})]
```

**What happens:**
1. Claude Code calls `sigil_exec` via MCP
2. SIGIL resolves `{{secret:openai/api_key}}` to the real value
3. SIGIL executes the curl command with the injected key
4. SIGIL scrubs any secrets from the response
5. Claude receives only the scrubbed output

### Protected File Write

```
User: Create a Python script that uses the OpenAI API

Claude: I'll create a script using the placeholder:
[sigil_write({
  path: "openai_client.py",
  content: """
import os
api_key = "{{secret:openai/api_key}}"
...
"""
})]
```

**What happens:**
1. Claude Code calls `sigil_write` via MCP
2. SIGIL resolves the placeholder and writes the file
3. The placeholder remains in the file (not the actual key)
4. When the script is run, SIGIL injects the real key

---

## 🔥 Troubleshooting

### ❌ "MCP server not responding"

**Problem:** Claude Code can't connect to the MCP server.

**Solution:**
1. Check if the daemon is running:
   ```bash
   ps aux | grep sigild
   ```
2. Start the daemon if needed:
   ```bash
   sigild
   ```
3. Verify the socket path:
   ```bash
   ls -la /run/user/$UID/sigil.sock
   ```

> ✅ Verify with `sigil doctor`

### ❌ "Hook not found in settings.json"

**Problem:** SIGIL hooks weren't added to the configuration.

**Solution:**
1. Check if hooks exist:
   ```bash
   cat ~/.claude/settings.json | grep sigil
   ```
2. Re-run setup:
   ```bash
   sigil setup claude-code
   ```

### ❌ "Secret not found in vault"

**Problem:** The placeholder references a non-existent secret.

**Solution:**
1. List available secrets:
   ```bash
   sigil list
   ```
2. Add the missing secret:
   ```bash
   sigil add <path>
   ```

### ❌ "Placeholder not resolved"

**Problem:** The placeholder appears in output without being resolved.

**Possible causes:**
1. Daemon not running — Start with `sigild`
2. Secret not in vault — Add with `sigil add`
3. Placeholder syntax error — Check format: `{{secret:path}}`

---

## 🔧 Advanced Configuration

### Custom Hook Behavior

Edit `~/.claude/settings.json` to customize hook behavior:

```json
{
  "hooks": {
    "PreToolUse": {
      "command": "sigil-hook",
      "args": ["pre-tool-use"],
      "env": {
        "SIGIL_SCRUB_STRICT": "true"
      }
    }
  }
}
```

### Session Token Configuration

SIGIL uses session tokens for secure IPC. Configure token lifetime:

```toml
# ~/.sigil/config.toml
[daemon]
session_lifetime = "1h"
```

---

## 🚧 Known Limitations

- **macOS**: Reduced coverage due to lack of PID namespace and mount namespace
- **WSL1**: Not supported — upgrade to WSL2
- **Network isolation**: Linux/WSL2 only
- **FUSE filesystem**: Requires libfuse3-dev (excluded from default build)

---

## 👉 Next Steps

- [Concepts and Architecture](../concepts.md) — Understand how SIGIL works
- [sigil help claude-code](../README.md#-in-binary-documentation) — Runtime documentation
- [FAQ](../faq.md) — Common questions and scenarios

---

## 📚 Additional Resources

- [Claude Code Documentation](https://docs.anthropic.com/claude-code)
- [MCP Protocol](https://modelcontextprotocol.io/)
- [SIGIL GitHub](https://github.com/sigil-rs/sigil)
