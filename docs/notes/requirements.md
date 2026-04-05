# SIGIL — Requirements & Design Constraints

## Core Requirements

### 1. 🔌 Offline-First, No Cloud Dependencies

SIGIL must run entirely within the local coding terminal with zero cloud dependencies. The user should be able to manage, inject, and scrub secrets on an air-gapped machine.

- Local encrypted vault as the default secret store
- No network calls required for core functionality
- All cryptographic operations happen locally (age, GPG, or similar)
- The tool must start and operate without internet connectivity

### 2. 🔗 External Secret Backend Support

While offline-first, SIGIL must also integrate with external secret managers when available:

- **OpenBao / HashiCorp Vault** — via HTTP API or agent socket
- **1Password** — via `op` CLI or Connect server
- **AWS Secrets Manager / SSM Parameter Store**
- **Kubernetes Secrets** (via kubectl or service account)
- **pass / gopass** — GPG-based password stores
- **sops** — encrypted file support
- **Infisical, Doppler** — SaaS secret managers

Backend interface should be pluggable — a simple trait/interface that new backends can implement.

### 3. 📜 Multi-Line Secrets and Certificates

Must handle more than simple key-value pairs:

- **TLS certificates** (PEM-encoded, multi-line)
- **SSH private keys**
- **JSON credentials** (e.g., GCP service account files)
- **Kubeconfig fragments**
- **Multi-line API tokens or JWTs**

Injection strategies needed:
- **Inline injection** — for single-line values in command strings
- **Temporary file injection** — write to a tmpfs file, inject the path, clean up after execution
- **Environment variable injection** — for values referenced as `$VAR`
- **File mount injection** — for certificates/configs that must exist at a path during execution

### 4. 🖥️ Agent-Inaccessible TUI

A terminal user interface (TUI) for secret management that the AI agent **cannot observe or interact with**:

- Runs on a **separate TTY/PTY** — not in the agent's terminal session
- Uses **alternate screen buffer** — content not readable via scrollback
- **No filesystem artifacts** — secrets never written to disk unencrypted
- **Process isolation** — agent cannot ptrace or read `/proc/<pid>/mem`
- **Session authentication** — TUI and daemon share a session token established before the agent starts

The TUI should support:
- Adding / editing / deleting secrets
- Browsing secrets by namespace/path
- Importing from external backends
- Viewing audit logs
- Initiating secret rotation
- Reviewing breach detection alerts

### 5. 📦 Portable Export / Import

Secrets must be exportable and importable as encrypted archive files, similar to KeePass `.kdbx` files:

- **Export format**: A single encrypted file (e.g., `.sigil` extension) containing:
  - All secrets with their paths, metadata, and values
  - Folder/namespace hierarchy preserved
  - Secret type annotations (API key, certificate, SSH key, JSON credential, etc.)
  - Tags, notes, and expiration dates
- **Encryption**: Archive encrypted with a user-provided passphrase using age or Argon2id + ChaCha20-Poly1305 (resistant to brute-force)
- **Selective export**: Export an entire vault, a single namespace, or a hand-picked set of secrets
- **Import modes**:
  - **Merge** — add new secrets, skip existing (default)
  - **Overwrite** — replace existing secrets with imported values
  - **Interactive** — prompt per-conflict in the TUI (keep local, take imported, skip)
- **Cross-machine portability**: Transfer secrets between machines via USB, `scp`, or any file transfer — the archive is self-contained and cloud-free
- **Version awareness**: Archive includes a format version so future SIGIL versions can read older exports
- **Audit trail**: Imports are logged (which secrets were added/updated, when, from which archive hash) but the archive contents are never written to the audit log unencrypted

CLI interface:

```bash
# Export entire vault
sigil export --out secrets.sigil

# Export a namespace
sigil export --namespace kalshi --out kalshi-secrets.sigil

# Export specific secrets
sigil export --secrets kalshi/api_key,ibkr/client_secret --out trading.sigil

# Import with merge (default)
sigil import secrets.sigil

# Import with overwrite
sigil import --mode overwrite secrets.sigil

# Import interactively (TUI conflict resolution)
sigil import --mode interactive secrets.sigil
```

TUI support:
- Export/import accessible from the TUI menu
- Visual diff when importing conflicting secrets
- Drag-and-drop style selection for partial exports

---

## Architectural Requirements

### 5. 🧱 Bash Sandbox with Secret Injection

The agent must **never** execute commands directly. Instead:

1. Agent submits a command containing `{{secret:path}}` placeholders
2. SIGIL daemon (privileged process) resolves placeholders
3. Command executes in an **isolated environment** (namespace, container, or restricted shell)
4. Output is **scrubbed** — all secret values replaced with their placeholder references
5. Sanitized output returned to the agent

Key properties:
- The agent's process cannot access the daemon's memory or socket
- Secrets exist only in the execution environment's memory, never on the agent-accessible filesystem
- Temporary files (for certs, etc.) are created on tmpfs with restrictive permissions and cleaned up immediately

### 6. 🔍 Breach Detection and Incident Response

If a secret is detected in agent output despite scrubbing (defense in depth):

- **Flag the breach** in the audit log with full context (which secret, which command, timestamp)
- **Generate a rotation report** — list of compromised secrets with:
  - Secret path/name
  - When it was exposed
  - Which agent/session exposed it
  - Provider-specific rotation instructions (e.g., "Revoke and regenerate via `op item edit ...`")
- **Optional: automatic rotation** for backends that support it (Vault dynamic secrets, 1Password rotation)
- **Canary secrets** — honeypot values that trigger alerts if the agent ever references them, proving the agent attempted to access the secret store directly

### 7. 🔐 Trust Bootstrapping

The initial setup must happen **before** any agent is running:

1. User launches SIGIL TUI (separate terminal)
2. Creates or imports secrets
3. Configures which secrets are available to which project/workspace
4. SIGIL daemon starts with the decrypted secret material in memory
5. Agent starts and can only interact via `{{secret:path}}` placeholders
6. Agent never observes the setup process

### 8. 🌐 Cross-Harness Compatibility

SIGIL should work with multiple AI coding tools:

- **Claude Code** — via PreToolCall / PostToolCall hooks
- **Cursor** — via terminal proxy or shell wrapper
- **Aider** — via shell wrapper
- **Cline** — via VS Code terminal proxy
- **Any tool** — via a universal shell wrapper (`sigil-shell`) that can be set as the agent's `$SHELL`

The universal approach: SIGIL provides a shell wrapper that intercepts all commands, resolves secrets, executes in isolation, and returns scrubbed output. Harness-specific integrations (like Claude Code hooks) provide tighter integration where available.

### 9. 🤖 Agent Discovery — MCP Tool + Project Instructions

Agents need to know which secrets are available and how to reference them, without ever seeing values:

- **MCP server**: SIGIL exposes an MCP server with tools:
  - `sigil_list` — returns available secret paths and types (not values)
  - `sigil_exec` — runs a command with secret injection and output scrubbing
  - `sigil_status` — shows which secrets were accessed this session
- **Auto-generated project instructions**: `sigil init` writes a secrets inventory block into `CLAUDE.md` / `.cursorrules` / equivalent, listing available `{{secret:path}}` references
- **Pre-hook fallback**: For agents that bypass MCP and use raw Bash, hooks catch `{{secret:*}}` placeholders in any command

---

## Non-Functional Requirements

- **Performance**: Secret resolution adds < 50ms overhead per command
- **Reliability**: If SIGIL daemon is unavailable, commands with placeholders fail loudly (no silent fallback to raw placeholders)
- **Auditability**: Every secret access is logged with timestamp, requester, and context
- **Ergonomics**: Adding a new secret and using it in a command should take < 30 seconds via TUI
- **Language**: Implementation in Rust (performance, safety, single binary distribution) with TUI via `ratatui`
