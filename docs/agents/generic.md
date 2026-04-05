# 🤖 Generic Agent Setup Guide

> Setup for SIGIL with any AI coding agent — Baseline protection (Layers 2-3 active).

---

## 📋 Overview

| Aspect | Details |
|--------|---------|
| **Coverage Tier** | ⚠️ Basic |
| **Layers Active** | 2-3 |
| **Hook Support** | ❌ None (unless agent supports hooks) |
| **MCP Integration** | ❌ No (unless agent supports MCP) |
| **Platform Support** | 🐧 Linux, 🪟 WSL2, 🍎 macOS |

---

## 🚧 Coverage Limitations

Agents without hook support have **reduced protection**:

| Layer | Protection | Status |
|-------|-----------|--------|
| **1. Agent Hooks** | Tool call interception | ❌ Not available |
| **2. Proxy Shell** | Command interception | ✅ Active (if agent uses `$SHELL`) |
| **3. Filesystem Monitor** | Secret write detection | ✅ Active |
| **4. Sandbox** | Process isolation | ⚠️ Partial (manual) |
| **5. Vault** | Encrypted storage | ✅ Active |
| **6. Canary Monitoring** | Unauthorized access detection | ✅ Active |

> ⚠️ **Warning**: Without agent hooks, SIGIL cannot intercept tool calls directly. Protection relies on the proxy shell and filesystem monitoring.

---

## 📋 Prerequisites

Before setting up SIGIL with a generic agent:

- ✅ SIGIL installed (`sigil --version`)
- ✅ Vault initialized (`sigil init`)
- ✅ At least one secret added (`sigil add <path>`)
- ✅ Agent installed and working
- ✅ Agent respects `$SHELL` environment variable

---

## 🔧 Installation

### 📝 Step 1: Configure Proxy Shell

Set the proxy shell as your default shell:

```bash
# Add to ~/.bashrc or ~/.zshrc
export SHELL=/usr/local/bin/sigil-shell

# Or use the alias approach
alias shell='sigil-shell'
```

### ✅ Step 2: Test Agent Shell Compatibility

Verify that the agent respects the `$SHELL` variable:

```bash
# In your agent's terminal session
echo $SHELL
# Should output: /usr/local/bin/sigil-shell (or your configured shell)
```

If the agent doesn't respect `$SHELL`, see the troubleshooting section below.

---

### 🔧 Step 3: Enable Filesystem Monitoring

Start the SIGIL filesystem monitor:

```bash
sigild monitor --daemon
```

This monitors for:
- Secret writes to disk
- Canary file access
- Suspicious file operations

---

## ✅ What's Protected

With generic agent setup, **Layers 2-3** are active:

| Protection | Status | Notes |
|-----------|--------|-------|
| **Command interception** | ✅ Active | If agent uses `$SHELL` |
| **Filesystem monitoring** | ✅ Active | All file operations monitored |
| **Secret storage** | ✅ Active | Vault is encrypted |
| **Canary detection** | ✅ Active | Unauthorized access logged |
| **Output scrubbing** | ⚠️ Partial | Only via proxy shell |

---

## 🚧 What's Not Protected

Without agent hooks, these protections are **not available**:

| Gap | Description | Mitigation |
|-----|-------------|------------|
| **Tool call interception** | Agent's tool calls not intercepted | Use proxy shell only |
| **Input scrubbing** | Agent inputs not scrubbed | Manual review required |
| **Output scrubbing** | Tool outputs not scrubbed | Proxy shell only |
| **MCP tools** | No SIGIL MCP integration | Use CLI commands |

> ⚠️ **Warning**: Generic agent setup provides **baseline protection only**. For comprehensive protection, use an agent with full hook support (e.g., Claude Code).

---

## 🎯 Testing

### 🧪 Test 1: Verify Proxy Shell

```bash
# Start a new shell session
sigil-shell

# Run a command with a secret placeholder
echo "Testing: {{secret:example/key}}"

# Should see: Testing: [REDACTED]
```

### 🔍 Test 2: Verify Filesystem Monitoring

```bash
# Write a file with a secret
echo "my_secret = sk_live_abc123" > /tmp/test.txt

# Check the audit log
tail -f ~/.sigil/vault/audit.jsonl

# Should see a log entry for the secret write
```

### 🐦 Test 3: Verify Canary Detection

```bash
# Create a canary file
sigil canary create ~/.aws/credentials

# Try to read it (in the agent session)
cat ~/.aws/credentials

# Check the audit log for breach alert
tail -f ~/.sigil/vault/audit.jsonl
```

---

## 🔥 Troubleshooting

### ❌ "Agent doesn't respect $SHELL"

Some agents hardcode the shell path. Workarounds:

**Option 1: Shell wrapper**

```bash
# Create a wrapper script
cat > ~/bin/agent-shell << 'EOF'
#!/bin/bash
exec sigil-shell "$@"
EOF

chmod +x ~/bin/agent-shell

# Configure agent to use this wrapper
```

**Option 2: Symlink bash to sigil-shell**

```bash
# Backup original bash
sudo mv /bin/bash /bin/bash.original

# Create symlink to sigil-shell
sudo ln -s /usr/local/bin/sigil-shell /bin/bash
```

> ⚠️ **Warning**: Option 2 affects the entire system. Use with caution.

---

### ❌ "Filesystem monitor not detecting writes"

> ✅ **Fix**: Check monitor is running

```bash
ps aux | grep sigild
```

If not running, start it:

```bash
sigild monitor --daemon
```

---

### ❌ "Commands not being intercepted"

> ✅ **Fix**: Verify agent is using proxy shell

```bash
# In agent session
echo $SHELL

# Should output: /usr/local/bin/sigil-shell
```

If not, see "Agent doesn't respect $SHELL" above.

---

## 📊 Example Session

Here's a typical session with a generic agent:

```
User: Add my API key and make a request
Agent: I'll add your API key and make a request.

[Agent writes to file]
> File write detected: api_key = sk_live_abc123
> ⚠️ Secret detected in write operation
> Logging to audit trail

[Agent executes command]
> Command intercepted via proxy shell
> Resolving placeholder: {{secret:api_key}}
> Executing with real value...
> Scrubbing output...
> Returning scrubbed output to agent
```

---

## 🔒 Security Considerations

### ⚠️ Reduced Protection

Generic agent setup provides **reduced protection** compared to agents with full hook support. Be aware of these limitations:

1. **No input scrubbing**: Agent can see secrets in user inputs
2. **No output scrubbing**: Agent can see secrets in tool outputs (unless using proxy shell)
3. **No tool interception**: Agent can bypass SIGIL for certain operations

### 💡 Recommended Practices

When using SIGIL with a generic agent:

- ✅ **Use the proxy shell** for all command execution
- ✅ **Enable filesystem monitoring** to detect secret writes
- ✅ **Review audit logs** regularly for suspicious activity
- ✅ **Rotate secrets frequently** to reduce exposure window
- ✅ **Consider using canary files** to detect unauthorized access

---

## 👉 Next Steps

- [Quickstart Guide](../quickstart.md) — Get SIGIL basics working
- [Concepts and Architecture](../concepts.md) — Understand how SIGIL works
- [Claude Code Guide](claude-code.md) — For comprehensive protection
- [FAQ](../faq.md) — Common questions and answers

---

## 📞 Getting Better Protection

If you need comprehensive protection, consider switching to an agent with full hook support:

| Agent | Coverage | Hooks | MCP |
|-------|----------|-------|-----|
| Claude Code | ✅ Comprehensive | ✅ All | ✅ Yes |
| Codex CLI | ✅ Strong | ✅ Partial | ❌ No |
| Cursor | ⚠️ Basic | ❌ No | ❌ No |
| Aider | ⚠️ Basic | ❌ No | ❌ No |

> 💡 **Tip**: Request SIGIL support for your favorite agent by opening an issue on GitHub.
