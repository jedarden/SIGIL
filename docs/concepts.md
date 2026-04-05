# 🧠 SIGIL Concepts and Architecture

> Understand how SIGIL thinks, protects secrets, and keeps your AI agents safe.

---

## 🔒 Trust Boundaries

SIGIL operates on two trust boundaries:

### The Agent Trust Boundary

The agent operates within its context window. It knows:

- ✅ **Which secrets exist** (via `sigil list`)
- ✅ **Where to use them** (via `{{secret:path}}` placeholders)
- ✅ **Metadata** (creation time, tags, type)
- ❌ **Never the actual values**

### The SIGIL Trust Boundary

SIGIL operates outside the agent's context. It handles:

- ✅ **Secret storage** (age-encrypted vault)
- ✅ **Resolution** (placeholder → real value)
- ✅ **Injection** (into commands at execution time)
- ✅ **Scrubbing** (removing secrets from output)
- ✅ **Auditing** (logging all access)

```
┌─────────────────────────────────────────────────────────────┐
│                     Agent Trust Boundary                    │
│  Knows: paths, metadata, placeholders                        │
│  Never: actual secret values                                 │
└─────────────────────────────────────────────────────────────┘
                              │
                              │ Placeholder resolution
                              │ (outside agent context)
                              ▼
┌─────────────────────────────────────────────────────────────┐
│                     SIGIL Trust Boundary                    │
│  Handles: storage, injection, scrubbing, auditing           │
└─────────────────────────────────────────────────────────────┘
```

---

## 🔗 Placeholders

Placeholders are symbolic references to secrets. They use this syntax:

```
{{secret:path/to/secret}}
```

### Examples

```bash
# Basic placeholder
{{secret:api_key}}

# Hierarchical paths
{{secret:aws/production/access_key_id}}

# With default values (if secret doesn't exist)
{{secret:optional_key:default_value}}
```

### Resolution Rules

1. **Exact match first**: SIGIL looks for `path/to/secret` in the vault
2. **Environment fallback**: If not found, checks `SIGIL_SECRET_PATH_TO_SECRET`
3. **Default value**: If provided and secret doesn't exist, uses the default
4. **Error if missing**: If no default and secret not found, command fails

> 💡 **Tip**: Use hierarchical paths to organize secrets by service and environment:
> - `dev/database/url`
> - `stripe/api/live_key`
> - `github/personal_access_token`

---

## 🧅 Interception Layers

SIGIL provides **6 layers of defense**. Not all agents support all layers:

| Layer | What It Does | Claude Code | Cursor | Aider |
|-------|--------------|-------------|--------|-------|
| **1. Agent Hooks** | Intercept tool calls | ✅ | ❌ | ❌ |
| **2. Proxy Shell** | Intercept all commands | ✅ | ✅ | ✅ |
| **3. Filesystem Monitor** | Detect secret writes | ✅ | ✅ | ✅ |
| **4. Sandbox** | Isolate execution | ✅ | ⚠️ | ⚠️ |
| **5. Vault** | Encrypt secrets | ✅ | ✅ | ✅ |
| **6. Canary Monitoring** | Detect unauthorized access | ✅ | ✅ | ✅ |

**Coverage tiers:**
- ✅ **Full**: All 6 layers active (Claude Code)
- ⚠️ **Partial**: 4-5 layers active (Codex CLI, Cline)
- ⚠️ **Basic**: 2-3 layers active (Cursor, Aider)

---

## 🔍 Command Signatures

SIGIL recognizes commands that need secrets via **pattern matching**. These patterns are called **signatures**.

### Built-in Signatures

```toml
# curl with authorization
signature = "curl -H *Authorization*{{secret:*}}*"

# git push (requires git credential helper)
signature = "git push*"

# terraform with variables
signature = "terraform* -var *=*{{secret:*}}*"
```

### Custom Signatures

Add custom signatures in `~/.sigil/signatures.toml`:

```toml
[[signatures]]
name = "my-api-cli"
pattern = "my-api --token {{secret:*}}"
description = "My custom API CLI tool"
```

> 💡 **Tip**: Use `sigil signatures search <tool>` to find existing signatures for popular tools.

---

## 🏦 Vault Modes

SIGIL supports three vault modes:

### Local Vault (Default)

```bash
sigil init  # Creates ~/.sigil/vault/
```

- **Storage**: `~/.sigil/vault/`
- **Encryption**: age with local key
- **Access**: Single user, single machine
- **Use case**: Personal development

### Sealed Vault

```bash
sigil export vault.sigil
sigil import vault.sigil
```

- **Storage**: Single encrypted file
- **Encryption**: age with passphrase
- **Access**: Portable, shareable
- **Use case**: CI/CD, backup, transfer

### Team Vault (Phase 10+)

```bash
sigil team init
```

- **Storage**: Remote service (Vault, OpenBao)
- **Encryption**: Transit encryption
- **Access**: Multi-user, RBAC
- **Use case**: Team secrets management

> 💡 **Tip**: Use local vault for development, sealed vault for CI/CD, team vault for shared secrets.

---

## 🧹 Output Scrubbing

SIGIL scrubs secret values from command output using **exact-match detection** across 7 encodings:

1. **Plain text**: `sk_live_abc123xyz789`
2. **Base64**: `c2tfbGl2ZV9hYmMxMjN4eXo3ODk=`
3. **URL-encoded**: `sk_live_abc123xyz789` → `sk%5Flive%5Fabc123xyz789`
4. **JSON-escaped**: `sk_live_abc123xyz789` → `sk\\u005flive\\u005fabc123xyz789`
5. **Hex-encoded**: `736b5f6c6976655f61626331323378797a373839`
6. **ROT13**: `fx_yvir_abc123xyz789` → `fx_yvir_nop123klm789`
7. **Reversed**: `sk_live_abc123xyz789` → `987zyx321cba_evil_ks`

> ⚠️ **Warning**: SIGIL does **not** use heuristic scrubbing (fuzzy matching, partial detection). Heuristics cause false positives and break legitimate output. Use exact placeholders.

---

## 🔒 Threat Model

### What SIGIL Protects Against

| Threat | How SIGIL Prevents It |
|--------|----------------------|
| **Context window leaks** | Secrets never enter agent context |
| **Prompt injection** | Agent only sees placeholders |
| **Log exfiltration** | Scrubbed output contains no secrets |
| **Filesystem dumps** | Vault is age-encrypted |
| **Memory dumps** | Secrets use `mlock()` and `zeroize` |
| **Canary access** | Decoy responses + breach alerts |

### What SIGIL Does NOT Protect Against

| Threat | Why SIGIL Can't Prevent It |
|--------|---------------------------|
| **Agent memorizes secrets** | If agent sees secret before SIGIL is installed |
| **Compromised host** | Root access bypasses all protections |
| **Network interception** | Use TLS for API communication |
| **Social engineering** | Human factors are out of scope |

> ⚠️ **Warning**: SIGIL is a **defense-in-depth** tool, not a silver bullet. Use it alongside other security practices: least privilege, audit logs, and regular secret rotation.

---

## 🚧 Known Limitations

1. **Placeholder detection**: Only `{{secret:path}}` syntax is supported
2. **Dynamic paths**: No wildcard or regex-based secret references
3. **Multi-line secrets**: Not fully supported in all contexts
4. **Binary output**: Scrubbing assumes text output
5. **Sandbox escape**: Vulnerable hosts can bypass sandbox restrictions

---

## 📊 Architecture Diagram

```
┌─────────────────────────────────────────────────────────────────────┐
│                              AI Agent                               │
│                        (LLM Context Window)                         │
│                                                                      │
│  Input:  curl -H "Auth: {{secret:api_key}}" https://api.example.com │
│  Output: {"status": "ok"}  [scrubbed]                               │
└─────────────────────────────────────────────────────────────────────┘
                                  │
                                  │ Tool Call
                                  ▼
┌─────────────────────────────────────────────────────────────────────┐
│                           Claude Code                               │
│                          (Agent Harness)                            │
│                                                                      │
│  ┌────────────────────────────────────────────────────────────┐    │
│  │  PreToolUse Hook: Scrub input for secrets                  │    │
│  └────────────────────────────────────────────────────────────┘    │
│  ┌────────────────────────────────────────────────────────────┐    │
│  │  PostToolUse Hook: Scrub output for secrets                │    │
│  └────────────────────────────────────────────────────────────┘    │
└─────────────────────────────────────────────────────────────────────┘
                                  │
                                  │ IPC
                                  ▼
┌─────────────────────────────────────────────────────────────────────┐
│                            SIGIL Daemon                             │
│                                                                      │
│  ┌────────────────────────────────────────────────────────────┐    │
│  │  Vault Backend: Age-encrypted storage                      │    │
│  └────────────────────────────────────────────────────────────┘    │
│  ┌────────────────────────────────────────────────────────────┐    │
│  │  Placeholder Resolver: {{secret:x}} → real value           │    │
│  └────────────────────────────────────────────────────────────┘    │
│  ┌────────────────────────────────────────────────────────────┐    │
│  │  Output Scrubber: Remove secrets from stdout/stderr        │    │
│  └────────────────────────────────────────────────────────────┘    │
│  ┌────────────────────────────────────────────────────────────┐    │
│  │  Audit Log: Track all secret access                       │    │
│  └────────────────────────────────────────────────────────────┘    │
└─────────────────────────────────────────────────────────────────────┘
                                  │
                                  │ Exec
                                  ▼
┌─────────────────────────────────────────────────────────────────────┐
│                         Sandboxed Process                           │
│                                                                      │
│  bubblewrap --unshare-pid --unshare-net --ro-bind / /              │
│    curl -H "Auth: sk_live_abc123..." https://api.example.com      │
│                                                                      │
│  Real secret injected here                                          │
└─────────────────────────────────────────────────────────────────────┘
                                  │
                                  │ HTTP Request
                                  ▼
┌─────────────────────────────────────────────────────────────────────┐
│                         External API                                │
│                                                                      │
│  GET https://api.example.com/user                                   │
│  Authorization: Bearer sk_live_abc123...                            │
│                                                                      │
│  Response: {"status": "ok", "user": "..."}                          │
└─────────────────────────────────────────────────────────────────────┘
```

---

## 👉 Next Steps

- [Quickstart Guide](quickstart.md) — Get SIGIL up and running
- [Per-Agent Setup Guides](agents/) — Configure for your agent
- [FAQ](faq.md) — Common questions and answers
