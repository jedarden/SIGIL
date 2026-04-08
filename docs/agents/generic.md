# 🤖 Generic Agent Setup Guide

> Setup for SIGIL with any unsupported AI coding agent — baseline protection via filesystem monitoring and proxy shell.

---

## 📋 Prerequisites

Before installing SIGIL for a generic agent, verify you have:

- **SIGIL installed** — See [Quickstart Guide](../quickstart.md)
- **Agent identified** — Know which agent you're using (Cursor, Aider, Windsurf, etc.)
- **Shell compatibility** — Agent respects `$SHELL` environment variable

> 💡 **Tip**: Run `echo $SHELL` to check your current shell.

---

## 🔧 Installation

For generic agents, SIGIL provides **baseline protection** via:

1. **Filesystem monitor** — Detects secret writes to disk
2. **Proxy shell** — Intercepts bash commands
3. **Network isolation** — Prevents exfiltration (Linux/WSL2)

### Step 1: Start the SIGIL Daemon

```bash
sigild
```

The daemon runs in the background and handles:
- Secret resolution
- Output scrubbing
- Filesystem monitoring
- Session management

### Step 2: Set the Proxy Shell

Tell your agent to use `sigil-shell` instead of bash:

```bash
export SHELL=$(which sigil-shell)
```

Or add to your `~/.bashrc` or `~/.zshrc`:

```bash
export SHELL=$(which sigil-shell)
```

> ⚠️ **Warning**: Not all agents respect `$SHELL`. See "Testing Shell Integration" below.

### Step 3: Enable Filesystem Monitoring

The daemon automatically monitors for:
- Secret writes to `~/.sigil/` (canary detection)
- Credential file access (`~/.aws/credentials`, `~/.git-credentials`)
- Suspicious file patterns (`.env`, `*.pem`, `*.key`)

No additional configuration required.

---

## ✅ What's Protected

Generic agents have **baseline coverage** across 4 layers:

| Layer | Protected | Details |
|-------|-----------|---------|
| Layer 5: Input scrubbing | ❌ No | No UserPromptSubmit hook |
| Layer 4: Tool hooks | ❌ No | No PreToolUse/PostToolUse hooks |
| Layer 3: Filesystem monitor | ✅ Yes | inotify watches detect secret writes |
| Layer 2: Proxy shell | ⚠️ Maybe | Depends on agent's `$SHELL` support |
| Layer 1: Namespace isolation | ✅ Yes | bubblewrap sandbox (Linux/WSL2) |
| Layer 0: Network isolation | ✅ Yes | Network namespace (Linux/WSL2) |

### What Works

- ✅ **Bash commands** — Intercepted by sigil-shell (if `$SHELL` is respected)
- ✅ **File writes** — Detected by filesystem monitor
- ✅ **Canary access** — Logged and flagged
- ✅ **Sandbox isolation** — Agent runs in isolated namespace

### What Doesn't Work

- ❌ **Write/Edit tool interception** — Agent can write files with secrets
- ❌ **Read tool interception** — Agent can read credential files
- ❌ **Output scrubbing** — No PostToolUse hook
- ❌ **Prompt scrubbing** — No UserPromptSubmit hook

---

## 🚧 What's Not Protected

| Limitation | Explanation |
|------------|-------------|
| No Write/Edit protection | Agent can write files containing secrets |
| No Read protection | Agent can read `~/.aws/credentials` and similar files |
| No output scrubbing | Secrets in command output are visible to agent |
| No prompt scrubbing | Secrets in user prompts are sent to LLM |
| Shell-dependent | Only works if agent respects `$SHELL` |

> ⚠️ **Warning**: Generic agents have **significantly reduced protection** compared to agents with first-class hook support (Claude Code, Codex CLI). Use with caution and consider switching to a better-supported agent.

---

## 🧪 Testing Shell Integration

### Test 1: Check Shell Variable

```bash
echo $SHELL
```

Expected output:
```
/usr/local/bin/sigil-shell
```

### Test 2: Run a Command with Placeholder

```bash
sigil exec 'echo "Test: {{secret:test/value}}"'
```

Expected output:
```
Test: ************  [SCRUBBED]
```

### Test 3: Verify Agent Session

Start your agent and run:

```bash
ps aux | grep sigil
```

You should see:
- `sigild` — the daemon
- `sigil-shell` — the proxy shell (if agent started a session)

---

## 🔥 Troubleshooting

### ❌ "Agent ignores $SHELL"

**Problem:** Agent doesn't respect the `$SHELL` environment variable.

**Possible causes:**
1. Agent has hardcoded shell path
2. Agent uses direct exec() calls
3. Agent runs in a container with different environment

**Workarounds:**
1. **Use wrapper scripts:**
   ```bash
   #!/usr/bin/env sigil-shell
   # Your command here
   ```
2. **Use `sigil wrap`:**
   ```bash
   sigil wrap <agent-command>
   ```
3. **Request first-class support** — See "Requesting Agent Support" below

### ❌ "Filesystem monitor not detecting writes"

**Problem:** Secret writes to disk aren't being detected.

**Solution:**
1. Check if daemon is running:
   ```bash
   ps aux | grep sigild
   ```
2. Verify inotify is available:
   ```bash
   ls -la /proc/sys/fs/inotify/
   ```
3. Check audit log:
   ```bash
   sigil audit --tail
   ```

### ❌ "Secrets visible in output"

**Problem:** Secrets are visible in command output.

**Explanation:** Generic agents lack PostToolUse hooks, so output scrubbing doesn't work automatically.

**Workaround:** Use `sigil exec` for commands that might echo secrets:
```bash
sigil exec '<command-with-secrets>'
```

---

## 🔧 Advanced Configuration

### Custom Filesystem Watches

Add custom watch paths in `~/.sigil/config.toml`:

```toml
[monitor.watches]
paths = [
  "~/project/secrets/",
  "/etc/deploy/keys/"
]
```

### Canary Files

Place canary files in your project directory:

```bash
echo "fake-aws-key" > .aws-canary
```

SIGIL will detect and log any access to this file.

---

## 🚧 Known Limitations

- **No Write/Edit protection** — Agent can write files with secrets
- **No Read protection** — Agent can read credential files
- **No output scrubbing** — Secrets in output are visible
- **Shell-dependent** — Only works if agent respects `$SHELL`
- **macOS limitations** — Reduced sandbox coverage on macOS

---

## 📧 Requesting Agent Support

Don't see your agent listed? Request first-class support:

1. **Check existing issues** — [GitHub Issues](https://github.com/sigil-rs/sigil/issues)
2. **File a new issue** — Include:
   - Agent name and version
   - Hook capabilities (if documented)
   - Example configuration file
3. **Contribute** — See [Contributing Guide](../CONTRIBUTING.md)

We prioritize agents with:
- Active user base
- Documented hook APIs
- Open-source codebase

---

## 👉 Next Steps

- [Claude Code Guide](claude-code.md) — Example of comprehensive protection
- [Concepts and Architecture](../concepts.md) — Understand interception layers
- [FAQ](../faq.md) — Common questions and scenarios
