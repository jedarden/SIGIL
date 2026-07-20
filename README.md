# SIGIL — Secret Injection, Guarding, and Isolation Layer

![CI](https://img.shields.io/badge/CI-Argo%20Workflows-success?style=flat-square)
![Version](https://img.shields.io/badge/version-0.4.0-blue?style=flat-square)
![License](https://img.shields.io/badge/license-MIT%2FApache--2.0-blue?style=flat-square)
![Platform](https://img.shields.io/badge/platform-linux%20%7C%20macos%20%7C%20wsl2-informational?style=flat-square)

**A secret management system for AI coding agents — agents use secrets without ever seeing their values.**

---

## The Problem

AI coding agents leak secrets at **2x the rate of human developers**. Why? Because secrets enter the agent's context window as plain text, where they can be:

- Leaked via prompt injection attacks
- Persisted in conversation logs and telemetry
- Echoed back in generated code or commands
- Exfiltrated through crafted tool calls

With **28.65 million hardcoded secrets** detected in public repos in 2024, this is not a theoretical problem — it's an existential risk for AI-assisted development.

---

## What SIGIL Does

SIGIL creates a **defense-in-depth interception layer** between AI agents and secrets:

```
┌─────────────────────────────────────────────────────────────────────┐
│                         AI Agent Context                            │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐ │
│  │   Bash      │  │   Write     │  │    Edit     │  │  Terminal   │ │
│  │   Tool      │  │   Tool      │  │   Tool      │  │   Output    │ │ │
│  └──────┬──────┘  └──────┬──────┘  └──────┬──────┘  └──────┬──────┘ │
│         │                │                │                │         │
└─────────┼────────────────┼────────────────┼────────────────┼─────────┘
          │                │                │                │
          ▼                ▼                ▼                ▼
┌─────────────────────────────────────────────────────────────────────┐
│                          SIGIL LAYER                                │
│  ┌─────────────────────────────────────────────────────────────┐   │
│  │  Layer 1: Agent Hooks (PreToolUse/PostToolUse/UserPrompt)  │   │
│  │  → Intercept tool calls, scrub inputs/outputs              │   │
│  └─────────────────────────────────────────────────────────────┘   │
│  ┌─────────────────────────────────────────────────────────────┐   │
│  │  Layer 2: Proxy Shell (sigil-shell)                        │   │
│  │  → Intercept all commands, resolve placeholders            │   │
│  └─────────────────────────────────────────────────────────────┘   │
│  ┌─────────────────────────────────────────────────────────────┐   │
│  │  Layer 3: Filesystem Monitor (inotify/fsevents)            │   │
│  │  → Detect secret writes to disk                            │   │
│  └─────────────────────────────────────────────────────────────┘   │
│  ┌─────────────────────────────────────────────────────────────┐   │
│  │  Layer 4: Sandbox (bubblewrap/sandbox-exec)                │   │
│  │  → Isolate execution, prevent direct access                 │   │
│  └─────────────────────────────────────────────────────────────┘   │
│  ┌─────────────────────────────────────────────────────────────┐   │
│  │  Layer 5: Vault (age-encrypted local storage)               │   │
│  │  → Secrets never live in plaintext                          │   │
│  └─────────────────────────────────────────────────────────────┘   │
│  ┌─────────────────────────────────────────────────────────────┐   │
│  │  Layer 6: Canary Monitoring                                 │   │
│  │  → Detect and respond to unauthorized access                │   │
│  └─────────────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────────┘
```

**The agent never sees the secret.** Only the sigil (`{{secret:path}}`) exists in the agent's context.

---

## Demo

A quick walkthrough of SIGIL's core workflow:

![SIGIL Demo](docs/demo.svg)

**What you see:**
1. **Vault initialization** — age-encrypted local storage with passphrase protection
2. **Adding a secret** — encrypted at rest, never plaintext on disk
3. **Listing secrets** — metadata only, values stay encrypted
4. **Using placeholders** — `{{secret:path}}` syntax for safe injection

The agent never sees the real secret value — only the placeholder.

---

## Installation

### Pre-built binaries (Linux/macOS)

Download binaries from the [releases page](https://github.com/jedarden/SIGIL/releases). SIGIL includes 10 binaries for different use cases:

| Binary | Purpose |
|--------|---------|
| `sigil` | Main CLI for vault management and operations |
| `sigild` | Long-running daemon that holds decrypted secrets |
| `sigil-shell` | Shell wrapper that intercepts commands |
| `sigil-tui` | Terminal UI for secret management |
| `sigil-mcp` | MCP server for Claude Code integration |
| `sigil-fuse` | FUSE virtual filesystem for secret access |
| `sigil-proxy` | HTTP forward proxy for auth injection |
| `sigil-ssh-agent` | SSH agent protocol implementation |
| `git-credential-sigil` | Git credential helper |
| `docker-credential-sigil` | Docker credential helper |

**Minimal installation** (CLI + daemon only):
```bash
curl -Lo /usr/local/bin/sigil https://github.com/jedarden/SIGIL/releases/latest/download/sigil
curl -Lo /usr/local/bin/sigild https://github.com/jedarden/SIGIL/releases/latest/download/sigild
chmod +x /usr/local/bin/sigil /usr/local/bin/sigild
```

**Full installation** (all binaries):
```bash
# Download all binaries
for bin in sigil sigild sigil-shell sigil-tui sigil-mcp sigil-fuse sigil-proxy sigil-ssh-agent git-credential-sigil docker-credential-sigil; do
  curl -Lo /usr/local/bin/$bin https://github.com/jedarden/SIGIL/releases/latest/download/$bin
  chmod +x /usr/local/bin/$bin
done

# Install credential helpers
git config --global credential.helper sigil
```

### Homebrew (macOS & Linuxbrew)

Install SIGIL via Homebrew from this repo's tap:

```bash
brew tap jedarden/sigil https://github.com/jedarden/SIGIL
brew install sigil
```

The formula builds SIGIL from source and installs the full binary set
(`sigil`, `sigild`, `sigil-shell`, `sigil-tui`, `sigil-mcp`, `sigil-proxy`,
`sigil-ssh-agent`, `git-credential-sigil`, `docker-credential-sigil`). On Linux
it also installs `bubblewrap` for the sandbox. See
[`Formula/sigil.rb`](Formula/sigil.rb).

> Pre-built binary bottles are not yet published, so the formula compiles from
> the released source. Binary distribution is tracked in
> [notes/bf-24w30.md](notes/bf-24w30.md).

### Build from source

Requires Rust 1.75+. On Linux, install `bubblewrap` and `libfuse3-dev` for full sandbox and FUSE support:

```bash
sudo apt-get install bubblewrap libfuse3-dev fuse3  # Debian/Ubuntu
brew install fuse3                                  # macOS (Homebrew)
```

Then build:

```bash
git clone https://github.com/jedarden/SIGIL.git
cd SIGIL

# Build specific binaries
cargo build --release --bin sigil --bin sigild
sudo cp target/release/sigil target/release/sigild /usr/local/bin/

# Or build all 10 binaries
cargo build --release
sudo cp target/release/sigil target/release/sigild \
  target/release/sigil-shell target/release/sigil-tui \
  target/release/sigil-mcp target/release/sigil-fuse \
  target/release/sigil-proxy target/release/sigil-ssh-agent \
  target/release/git-credential-sigil target/release/docker-credential-sigil \
  /usr/local/bin/
```

---

## Quickstart

```bash
# One-command setup (recommended)
sigil quickstart

# Or manual setup
sigil init
sigil add github/token
sigil add aws/access_key_id

# Use in commands — SIGIL resolves the placeholder at execution time
# The agent only ever sees {{secret:github/token}}, never the real value
sigil exec 'git push https://{{secret:github/token}}@github.com/user/repo.git main'
```

---

## Agent Support

| Agent | Coverage | Layers Active | Notes |
|-------|----------|---------------|-------|
| Claude Code | Comprehensive | 1-6 | Full hook support, MCP integration |
| Codex CLI | Strong | 2-4 | PreToolUse hooks, sandbox |
| Cursor | Basic | 2-3 | No hooks — filesystem monitor |
| Aider | Basic | 2-3 | No hooks — filesystem monitor |
| Cline | Moderate | 2-4 | Limited hooks |

**Coverage tiers:**
- **Comprehensive**: All 6 layers active, maximum protection
- **Strong**: Layers 2-4 active, good protection
- **Moderate**: Layers 2-4 active, some gaps
- **Basic**: Layers 2-3 active, baseline protection

---

## Secret Backends

SIGIL's default vault uses [age](https://age-encryption.org/) encryption stored in `~/.sigil/vault/`. For teams or existing secret infrastructure, SIGIL supports pluggable backends:

| Backend | Description |
|---------|-------------|
| `local` (default) | age-encrypted files in `~/.sigil/vault/` |
| `env` | Reads from a restricted env file (not the agent's process environment) |
| `pass` | Unix `pass` password manager |
| `sops` | Mozilla SOPS encrypted files (AWS KMS, GCP KMS, age) |
| `vault` | HashiCorp Vault or OpenBao (KV v2, dynamic secrets) |
| `onepassword` | 1Password via the `op` CLI or Connect API |
| `aws` | AWS Secrets Manager |

Multiple backends can be active simultaneously; SIGIL resolves secret paths across them. Configure in `~/.sigil/config.toml`.

---

## Platform Support

| Tier | Platform | Status |
|------|----------|--------|
| **Tier 1** | Linux (Ubuntu 22.04+, Debian 12+) | Fully supported |
| **Tier 1** | WSL2 (Ubuntu 22.04+) | Fully supported |
| **Tier 2** | macOS (13+ Ventura) | Supported (sandbox limitations) |
| **Tier 3** | Docker containers | Supported (requires bind mounts) |
| **Tier 3** | Windows (native) | Not supported — use WSL2 |

---

## Links

- [Documentation](docs/)
- [Quickstart Guide](docs/quickstart.md)
- [Concepts and Architecture](docs/concepts.md)
- [Per-Agent Setup Guides](docs/agents/)
- [Contributing Guide](CONTRIBUTING.md)
- [Security Policy](SECURITY.md)

---

## License

Licensed under either of:

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE))
- MIT license ([LICENSE-MIT](LICENSE-MIT))

at your option.

---

## The Acronym

| Letter | Word | Role |
|--------|------|------|
| **S** | Secret | The sensitive values being protected |
| **I** | Injection | Resolved into commands at execution time |
| **G** | Guarding | Agents are prevented from accessing raw values |
| **I** | Isolation | Secrets live in a separate trust boundary |
| **L** | Layer | Operates transparently between agent and shell |

## CI/CD Notes

CI runs on Argo Workflows (iad-ci cluster) via sigil-ci workflow template.
Triggered by push to main. Runs cargo fmt/clippy/test then publishes release.

