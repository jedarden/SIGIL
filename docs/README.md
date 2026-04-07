# 🛡️ SIGIL — Secret Injection, Guarding, and Isolation Layer

![CI](https://img.shields.io/badge/CI-Argo%20Workflows-success)
![Version](https://img.shields.io/badge/version-0.4.0-blue)
![License](https://img.shields.io/badge/license-MIT%2FApache--2.0-blue)
![Platform](https://img.shields.io/badge/platform-linux%20%7C%20macos%20%7C%20wsl2-informational)

> A secret management system for AI coding agents — agents use secrets without ever seeing their values.

---

## ⚡ The Problem

AI coding agents leak secrets at **2x the rate of human developers**. Secrets enter the agent's context window as plain text, where they can be:

- 🕳️ Leaked via prompt injection attacks
- 📋 Persisted in conversation logs and telemetry
- 🔄 Echoed back in generated code or commands
- 📡 Exfiltrated through crafted tool calls

With **28.65 million hardcoded secrets** detected in public repos in 2024, this is an existential risk for AI-assisted development.

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

## 🎯 How It Works

1. **Placeholders replace secrets** — Agents use `{{secret:path}}` instead of real values
2. **Interception at every layer** — Hooks, shell, filesystem, and sandbox all prevent leaks
3. **Output scrubbing** — Exact-match scrubbing across 7 encodings removes secrets from responses
4. **Audit trail** — Every secret access is logged for security review
5. **Canary monitoring** — Decoy secrets detect unauthorized access attempts

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

> 💡 **Tip**: Run `sigil quickstart` for automatic setup with sensible defaults.

---

## 🤖 Agent Support

| Agent | Coverage | Notes |
|-------|----------|-------|
| Claude Code | ✅ Comprehensive | All 6 interception layers + MCP server |
| Codex CLI | ✅ Strong | PreToolUse hook + sandbox integration |
| Cline | ⚠️ Moderate | Partial hook support, filesystem monitoring |
| Cursor | ⚠️ Basic | No hooks, filesystem monitor + proxy shell |
| Aider | ⚠️ Basic | No hooks, filesystem monitor + proxy shell |
| Generic | ⚠️ Baseline | Filesystem monitor + proxy shell + network isolation |

See the [Agent Setup Guides](agents/) for detailed configuration.

---

## 📦 Platform Support

| Platform | Status | Notes |
|----------|--------|-------|
| 🐧 Linux | ✅ Tier 1 | Full support including bubblewrap sandbox |
| 🍎 macOS | ✅ Tier 1 | Full support using sandbox-exec |
| 🪟 WSL2 | ✅ Tier 1 | Native namespace support |

---

## 📚 Documentation

- **[Quickstart Guide](quickstart.md)** — Step-by-step setup walkthrough
- **[Quick Reference](quick-reference.md)** — Common commands and patterns
- **[Concepts](concepts.md)** — Trust boundaries, placeholders, interception layers
- **[FAQ](faq.md)** — Common questions and troubleshooting

---

## 🤝 Contributing

Contributions are welcome! See the [Contributing Guide](../CONTRIBUTING.md) for development setup, pull request process, and code contribution guidelines.

---

## 🔒 Security

SIGIL is a security tool. Report vulnerabilities responsibly — see [SECURITY.md](../SECURITY.md) for disclosure policy.

---

## 📄 License

MIT OR Apache-2.0 — see [LICENSE](../LICENSE) for details.

---

## 👉 Next Steps

- [Quickstart Guide](quickstart.md) — Get SIGIL running in 5 minutes
- [Agent Setup Guides](agents/) — Configure SIGIL for your AI agent
- [Examples](examples/) — Real-world usage patterns
