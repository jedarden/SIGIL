# 🧠 SIGIL Concepts and Architecture

> Understand how SIGIL thinks — the mental model behind secret protection for AI coding agents.

---

## 🧠 Trust Boundaries

SIGIL operates by creating two distinct trust boundaries:

```
┌─────────────────────────────────────────────────────────────────────┐
│                      AGENT TRUST BOUNDARY                           │
│                                                                     │
│  AI Agent sees only:                                                │
│  • {{secret:path}} placeholders                                    │
│  • Sanitized command output                                        │
│  • Error messages with secrets scrubbed                            │
│                                                                     │
│  Agent CANNOT see:                                                 │
│  • Real secret values                                              │
│  • Decrypted vault contents                                        │
│  • Unfiltered command output                                       │
└─────────────────────────────────────────────────────────────────────┘
                              ↓
┌─────────────────────────────────────────────────────────────────────┐
│                      SIGIL TRUST BOUNDARY                           │
│                                                                     │
│  SIGIL handles:                                                    │
│  • Real secret values (decrypted from vault)                       │
│  • Placeholder resolution                                          │
│  • Output scrubbing                                                │
│  • Access control and auditing                                     │
│                                                                     │
│  Components:                                                       │
│  • Vault (age-encrypted storage)                                   │
│  • Daemon (sigild)                                                 │
│  • Proxy shell (sigil-shell)                                       │
│  • MCP server (sigil-mcp)                                          │
└─────────────────────────────────────────────────────────────────────┘
```

**The key insight:** The agent operates in its own trust boundary where secrets **do not exist**. Only placeholders exist in the agent's context. Real values are injected at execution time, inside SIGIL's trust boundary, where the agent cannot see them.

---

## 🔗 Placeholders

Placeholders are the bridge between the agent's world and SIGIL's world:

### 📝 Syntax

```
{{secret:path}}
```

**Examples:**
- `{{secret:kalshi/api_key}}` — Kalshi API key
- `{{secret:aws/access_key_id}}` — AWS access key
- `{{secret:github/token:file}}` — GitHub token as a file (not env var)

### ⚙️ Resolution

When SIGIL sees a placeholder:

1. **Parse** — Extract the path from `{{secret:...}}`
2. **Lookup** — Query the vault for the secret
3. **Decrypt** — Decrypt the value (in memory, never on disk)
4. **Inject** — Substitute the placeholder with the real value
5. **Execute** — Run the command with the injected value
6. **Scrub** — Remove any secrets from the output

### 📍 Where Placeholders Work

| Context | Supported | Example |
|---------|-----------|---------|
| Bash commands | ✅ | `sigil exec 'curl -H "Auth: {{secret:api_key}}"'` |
| Environment variables | ✅ | `API_KEY={{secret:api_key}} sigil exec ./myscript` |
| File paths | ✅ | `sigil exec 'cat {{secret:config/file:file}}'` |
| MCP tool calls | ✅ | `sigil_exec({command: "myscript {{secret:api_key}}"})` |
| Generated code | ❌ | Not applicable — agent generates code with placeholders |

> 💡 **Tip**: Use the `:file` modifier for secrets that should be injected as files rather than environment variables. This is useful for multi-line secrets (like PEM certificates) or secrets that tools read from files.

---

## 🧅 Interception Layers

SIGIL uses **defense-in-depth** with 6 interception layers:

### 🔒 Layer 5: Input Scrubbing

**Catches secrets in user prompts before they reach the LLM.**

- Agent user prompts are scanned for secret patterns
- Matching secrets are replaced with placeholders
- Works for prompts like "Here's my API key: sk_live_12345"

**Coverage:** Claude Code (UserPromptSubmit hook)

### 🪝 Layer 4: Agent Tool Hooks

**Intercepts ALL tool calls (Bash, Write, Edit, Read, MCP).**

- PreToolUse: Scrub inputs before tool execution
- PostToolUse: Scrub outputs after tool execution
- Covers all agent tools, not just bash

**Coverage:**
- ✅ Claude Code: Comprehensive (all 6 tools)
- ⚠️ Codex CLI: Strong (PreToolUse hook)
- ⚠️ Cursor/Aider: None (relies on Layers 2-3)

### 📁 Layer 3: Filesystem Monitor

**Detects secrets written to files via inotify/fanotify.**

- Monitors for secret patterns in file writes
- Triggers alerts when canary files are accessed
- Works even when agents bypass hooks

**Coverage:** All agents (Linux/WSL2 only)

### 🐚 Layer 2: Proxy Shell

**POSIX-compatible shell that proxies all commands.**

- All bash commands flow through sigil-shell
- Placeholder resolution happens at execution time
- Output scrubbing removes secrets from command output

**Coverage:** All agents (when `$SHELL` is set to `sigil-shell`)

### 📦 Layer 1: Namespace Isolation

**Sandbox (bubblewrap/sandbox-exec) prevents direct access.**

- Agent runs in isolated namespace
- Cannot access `~/.sigil/` directly
- Cannot read vault files or age identity

**Coverage:** All agents on Linux/WSL2 (limited on macOS)

### 🌐 Layer 0: Network Isolation

**Prevents exfiltration even if secrets leak.**

- Network namespace isolation (Linux)
- Default-deny network policy
- Whitelist for approved endpoints

**Coverage:** All agents on Linux/WSL2

### 📊 Coverage Summary

| Layer | Claude Code | Codex CLI | Cursor/Aider | Cline |
|-------|-------------|-----------|--------------|-------|
| Layer 5: Input scrubbing | ✅ | ❌ | ❌ | ❌ |
| Layer 4: Tool hooks | ✅ | ⚠️ | ❌ | ⚠️ |
| Layer 3: Filesystem monitor | ✅ | ✅ | ✅ | ✅ |
| Layer 2: Proxy shell | ✅ | ✅ | ✅ | ✅ |
| Layer 1: Namespace isolation | ✅ | ✅ | ✅ | ✅ |
| Layer 0: Network isolation | ✅ | ✅ | ✅ | ✅ |

---

## 🔍 Command Signatures

SIGIL recognizes commands that need secrets through **pattern matching**, not magic.

### ⚙️ How It Works

1. **Command database** — TOML files with command patterns
2. **Pattern matching** — Regex matches command invocations
3. **Injection rules** — Map secrets to env vars or args

### 📋 Example Signature

```toml
[[signature]]
name = "aws-cli"
pattern = "^aws (?P<subcommand>[a-z-]+)"
description = "AWS Command Line Interface"

[[signature.injection]]
env_var = "AWS_ACCESS_KEY_ID"
secret = "aws/access_key_id"

[[signature.injection]]
env_var = "AWS_SECRET_ACCESS_KEY"
secret = "aws/secret_access_key"
```

When you run `aws s3 ls`, SIGIL:
1. Matches the pattern
2. Injects `AWS_ACCESS_KEY_ID` and `AWS_SECRET_ACCESS_KEY`
3. Executes the command with the secrets

### ✏️ Custom Signatures

Add your own signatures in `.sigil/signatures.toml`:

```toml
[[signature]]
name = "my-api"
pattern = "^my-client"
description = "My custom API client"

[[signature.injection]]
env_var = "API_KEY"
secret = "my_api/key"
```

> 💡 **Tip**: Run `sigil signatures list` to see all available signatures. Run `sigil signatures search <query>` to find patterns for a specific tool.

---

## 🏦 Vault Modes

SIGIL supports two vault storage modes:

### 📁 Directory Mode (Default)

**Best for:** Single-developer, local-only workflows

```
~/.sigil/
├── vault/
│   ├── kalshi/
│   │   └── api_key.age
│   └── aws/
│       └── access_key.age
├── metadata.json.age
├── identity.age
└── config.toml
```

- **One age file per secret**
- **Not git-safe** (identity.age must stay local)
- **Simple and debuggable**

### 🔐 Sealed Mode (Team Vaults)

**Best for:** Team vaults, git-committed secrets

```
.sigil/
└── vault.sealed          # Single encrypted file
```

- **Single encrypted file** (XChaCha20-Poly1305)
- **Git-safe** (device key stays local, vault is committed)
- **Multi-factor authentication**
- **Shamir's Secret Sharing** for recovery

> 💡 **Tip**: Use directory mode for personal projects. Use sealed mode for team vaults where secrets need to be versioned and shared.

### 🔄 Conversion

Convert between modes:

```bash
# Directory → Sealed
sigil vault convert --to sealed

# Sealed → Directory
sigil vault convert --to directory
```

Both conversions are lossless and reversible.

---

## 🧹 Output Scrubbing

SIGIL scrubs secrets from command output using **exact matching** across 7 encodings:

### 🔢 Scrubbed Encodings

1. **Plaintext** — `sk_live_1234567890abcdef`
2. **URL-encoded** — `sk_live%201234567890abcdef`
3. **Base64** — `c2tfbGl2ZV8xMjM0NTY3ODkwYWJjZGVm`
4. **Hex** — `736b5f6c6976655f31323334353637383930616263646566`
5. **JSON-escaped** — `sk_live_1234567890\\u0024abcd`
6. **Unicode-escaped** — `\\u0073\\u006b\\u005f...`
7. **Reversed** — `fedcba0987654321evil_ks`

### ❓ Why Exact Matching?

**Heuristic scrubbing causes problems:**

- False positives: "My password is..." → entire sentence scrubbed
- False negatives: Secrets split across multiple lines
- Unpredictable behavior: Developers can't trust the scrubber

**Exact matching is reliable:**

- Only scrubs known secret values
- All encodings covered
- Predictable behavior

> ⚠️ **Warning**: If an API echoes your secret in a modified format (e.g., truncated, masked), SIGIL may not catch it. This is a known limitation.

---

## 🔒 Threat Model

### ✅ What SIGIL Protects Against

| Attack Vector | Protection |
|---------------|------------|
| Agent logs secrets in conversation | ✅ Scrubbed by output scrubbing |
| Agent includes secrets in generated code | ✅ Scrubbed by Write/Edit hooks |
| Agent exfiltrates via tool calls | ✅ Scrubbed by PostToolUse hooks |
| Agent reads credential files | ✅ Blocked by namespace isolation |
| Agent accesses vault directly | ✅ Blocked by namespace isolation |
| Secrets leaked in command output | ✅ Scrubbed by output scrubbing |
| Prompt injection steals secrets | ✅ Secrets not in agent context |

### ⚠️ What SIGIL Does NOT Protect Against

| Limitation | Explanation |
|------------|-------------|
| Agent memorizes secrets | If an agent "memorizes" a secret from a previous session, SIGIL can't prevent it from recalling that memory |
| Agent hardcodes secrets | If an agent types a secret directly into code (not from vault), SIGIL won't catch it |
| Compromised host | If the host system is compromised, all bets are off |
| Side-channel attacks | Timing attacks, power analysis, etc. are out of scope |
| Social engineering | SIGIL can't prevent users from manually sharing secrets |

> 💡 **Tip**: SIGIL is a **defense-in-depth** tool. It dramatically reduces the attack surface, but it's not a silver bullet. Combine it with other security practices: rotate secrets regularly, use least-privilege access, and monitor audit logs.

---

## 🚧 Known Limitations

- **Hook coverage varies** — Not all agents support all hook types. See [Per-Agent Setup Guides](agents/) for details.
- **macOS sandbox limitations** — macOS lacks PID namespace and mount namespace. Coverage is reduced.
- **Heuristic scrubbing gaps** — If APIs echo secrets in unexpected formats, SIGIL may not catch them.
- **Agent memory** — SIGIL can't prevent agents from "remembering" secrets across sessions.
- **Host compromise** — SIGIL doesn't protect against a compromised host system.

---

## 👉 Next Steps

- [Quickstart Guide](quickstart.md) — Get up and running
- [Per-Agent Setup Guides](agents/) — Configure SIGIL for your agent
- [sigil help vault](../README.md#-in-binary-documentation) — Runtime documentation
