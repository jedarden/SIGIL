# SIGIL Documentation Style Guide

This guide defines the visual style and formatting conventions for all SIGIL documentation.

## 🎯 Goal

Scannable documents where users can find the right section at a glance. Emoji are used as section markers and visual anchors — not decoration.

## 📋 Emoji Convention

| Context | Emoji | Usage |
|---------|-------|-------|
| Page title / H1 | 🛡️ | `# 🛡️ SIGIL — Secret Injection, Guarding, and Isolation Layer` |
| Major sections / H2 | Topic-specific | `## 🚀 Quickstart`, `## 🔧 Installation`, `## 🧠 Concepts`, `## 🤖 Agent Guides` |
| Subsections / H3 | Topic-specific | `### 📦 Vault Creation`, `### 🔑 Adding Secrets`, `### 🪝 Hook Installation` |
| Prerequisites | 📋 | `### 📋 Prerequisites` |
| Warnings / security notes | ⚠️ | `> ⚠️ **Warning**: Never commit your vault passphrase...` |
| Tips / best practices | 💡 | `> 💡 **Tip**: Run \`sigil doctor\` after any configuration change...` |
| Info / context boxes | ℹ️ | `> ℹ️ **Note**: WSL2 is treated as a Tier 1 Linux target...` |
| Success / verification | ✅ | `> ✅ **Done!** SIGIL is now protecting your secrets.` |
| Failure / error states | ❌ | `> ❌ If you see "permission denied"...` |
| Performance / benchmarks | ⚡ | `### ⚡ Performance` |
| Security / threat model | 🔒 | `### 🔒 What SIGIL Protects Against` |
| Limitations / caveats | 🚧 | `### 🚧 Known Limitations` |
| Next steps / navigation | 👉 | `👉 Next: [Per-Agent Setup Guides](agents/claude-code.md)` |
| Platform indicators | 🐧🍎🪟 | `🐧 Linux`, `🍎 macOS`, `🪟 WSL2` |
| FAQ questions | ❓ | `### ❓ How do I use SIGIL with Docker?` |
| CLI commands inline | 🖥️ | Used sparingly in lists: `🖥️ \`sigil quickstart\` — one-command setup` |

## 📝 Rules

1. **Every H2 and H3 heading in external docs has a leading emoji**
2. **Emoji are NOT used in inline prose, list items, or table cells** (except the platform indicators 🐧🍎🪟 which appear inline in compatibility tables)
3. **Emoji are NOT used in `docs/topics/` files** — those are compiled into the binary for terminal rendering where emoji width is unreliable
4. **Emoji headings exist only in external-only documents** (README, guides, etc.)

## 📄 Document Structure Template

Every documentation page follows this skeleton:

```markdown
# 🛡️ Page Title

> One-sentence summary of what this page covers and who it's for.

## 📋 Prerequisites

(if applicable)

## 🔧 Installation

> ℹ️ **Note**: Platform-specific instructions...

## 🚀 Getting Started

Step-by-step instructions...

## 🔒 Security Considerations

> ⚠️ **Warning**: Important security note...

## 🚧 Known Limitations

Limitations and caveats...

## 👉 Next Steps

Links to related documentation...
```

## 🎨 Callout Boxes

Use blockquote callouts for important information:

```markdown
> ⚠️ **Warning**: Security-critical information that users must not ignore

> 💡 **Tip**: Helpful advice for better usage

> ℹ️ **Note**: Additional context or clarification

> ✅ **Success**: Confirmation that something worked

> ❌ **Error**: Problem description and fix
```

## 🖥️ Code Blocks

- Use fenced code blocks with language specified
- For terminal commands, omit the `$` prompt prefix (copy-friendly)
- Include expected output when helpful

```bash
# Install SIGIL
cargo install sigil-cli

# Initialize vault
sigil init
```

## 🔗 Links

- Use descriptive link text: `[Claude Code Guide](agents/claude-code.md)` not `[here](agents/claude-code.md)`
- For external links, include the URL in the link text if it's short and meaningful
