# SIGIL — Secret Injection, Guarding, and Isolation Layer

![CI](https://img.shields.io/badge/CI-Argo%20Workflows-success)
![Version](https://img.shields.io/badge/version-0.4.0-blue)
![License](https://img.shields.io/badge/license-MIT%2FApache--2.0-blue)
![Platform](https://img.shields.io/badge/platform-linux%20%7C%20macos%20%7C%20wsl2-informational)

**A secret management system for AI coding agents — agents use secrets without ever seeing their values.**

---

## ⚡ The Problem

AI coding agents leak secrets at **2x the rate of human developers**. Why? Because secrets enter the agent's context window as plain text, where they can be:

- 🕳️ Leaked via prompt injection attacks
- 📋 Persisted in conversation logs and telemetry
- 🔄 Echoed back in generated code or commands
- 📡 Exfiltrated through crafted tool calls

With **28.65 million hardcoded secrets** detected in public repos in 2024, this is not a theoretical problem — it's an existential risk for AI-assisted development.

---

## 🛡️ What SIGIL Does

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

## 🎬 Demo

A quick walkthrough of SIGIL's core workflow:

<p align="center">
  <img src="docs/demo.svg" alt="SIGIL Demo: Initialize vault, add secret, use placeholders" width="800"/>
</p>

**What you see:**
1. **Vault initialization** — age-encrypted local storage
2. **Adding a secret** — encrypted at rest, never plaintext
3. **Listing secrets** — metadata only, values stay encrypted
4. **Using placeholders** — `{{secret:path}}` syntax for safe injection

The agent never sees the real secret value — only the placeholder.

---

## 🚀 Quickstart

```bash
# Install
cargo install sigil-cli

# Initialize vault
sigil init

# Add a secret
sigil add kalshi/api_key

# Use in commands
sigil exec 'curl -H "Authorization: Bearer {{secret:kalshi/api_key}}" https://api.example.com'
```

---

## 🤖 Agent Support

| Agent | Coverage | Layers Active | Notes |
|-------|----------|---------------|-------|
| Claude Code | ✅ Comprehensive | 1-6 | Full hook support, MCP integration |
| Codex CLI | ✅ Strong | 2-4 | PreToolUse hooks, sandbox |
| Cursor | ⚠️ Basic | 2-3 | No hooks — filesystem monitor |
| Aider | ⚠️ Basic | 2-3 | No hooks — filesystem monitor |
| Cline | ⚠️ Moderate | 2-4 | Limited hooks |

**Coverage tiers:**
- ✅ **Comprehensive**: All 6 layers active, maximum protection
- ⚠️ **Strong**: Layers 2-4 active, good protection
- ⚠️ **Moderate**: Layers 2-4 active, some gaps
- ⚠️ **Basic**: Layers 2-3 active, baseline protection

---

## 📦 Platform Support

| Tier | Platforms | Status |
|------|-----------|--------|
| **Tier 1** | 🐧 Linux (Ubuntu 22.04+, Debian 12+) | ✅ Fully supported |
| **Tier 1** | 🪟 WSL2 (Ubuntu 22.04+) | ✅ Fully supported |
| **Tier 2** | 🍎 macOS (13+ Ventura) | ⚠️ Supported (sandbox limitations) |
| **Tier 3** | 🐧 Docker containers | ⚠️ Supported (requires bind mounts) |
| **Tier 3** | 🪟 Windows (native) | ❌ Not supported (use WSL2) |

---

## 👉 Links

- 📖 [Documentation](docs/)
- 🚀 [Quickstart Guide](docs/quickstart.md)
- 🧠 [Concepts and Architecture](docs/concepts.md)
- 🤖 [Per-Agent Setup Guides](docs/agents/)
- 🤝 [Contributing Guide](CONTRIBUTING.md)
- 🔐 [Security Policy](SECURITY.md)
- 📄 [License](LICENSE)

---

## 📄 License

Licensed under either of:

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)
- MIT license ([LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT)

at your option.

---

## 🎯 The Acronym

| Letter | Word | Role |
|--------|------|------|
| **S** | Secret | The sensitive values being protected |
| **I** | Injection | Resolved into commands at execution time |
| **G** | Guarding | Agents are prevented from accessing raw values |
| **I** | Isolation | Secrets live in a separate trust boundary |
| **L** | Layer | Operates transparently between agent and shell |
