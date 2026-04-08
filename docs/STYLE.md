# SIGIL Documentation Style Guide

This guide defines the formatting and style conventions for all SIGIL documentation. All external-facing documentation should follow these conventions to ensure consistency across the project.

---

## 🎯 Guiding Principles

1. **Emoji as structural markers** — Emoji are used as section markers and visual anchors, not decoration
2. **Scannable documents** — Users should find the right section at a glance
3. **Callout boxes for emphasis** — Use GitHub-compatible blockquote syntax
4. **Consistent structure** — Every page follows a predictable template
5. **Honest communication** — Acknowledge limitations and security gaps plainly

---

## 📝 Emoji Convention

Every documentation file uses emoji as leading markers for headings and key structural elements:

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

### Rules

1. Every H2 and H3 heading in external docs has a leading emoji
2. Emoji are **not** used in inline prose, list items, or table cells (except platform indicators)
3. Emoji are **not** used in `docs/topics/` files (those are compiled into the binary for terminal rendering)
4. Platform indicators (🐧🍎🪟) may appear inline in compatibility tables

---

## 📄 Document Structure Template

Every documentation page follows this skeleton:

```markdown
# 🛡️ Page Title

> One-sentence summary of what this page covers and who it's for.

## 📋 Prerequisites

(if applicable)

## 🚀 Main Content

### 📦 Subsection

Content with code blocks, tables, and callout boxes.

> 💡 **Tip**: Contextual advice.

> ⚠️ **Warning**: Security-relevant caution.

## 🚧 Known Limitations

(honest summary — every page that makes claims includes caveats)

## 👉 Next Steps

- [Link to next logical page](path.md)
- [Link to related topic](path.md)
```

### Adaptations

- Not every page needs every section (e.g., not all pages have prerequisites)
- Internal links use relative paths: `[Quickstart](quickstart.md)`
- Every page ends with a "Next Steps" section to prevent dead ends

---

## 📦 Callout Boxes

Use GitHub-compatible blockquote syntax (`> `) for all callouts:

```markdown
> 💡 **Tip**: Run `sigil doctor` after any configuration change to verify your setup.

> ⚠️ **Warning**: Never commit your vault passphrase or age identity to version control.

> ℹ️ **Note**: WSL2 is treated as a Tier 1 Linux target with full namespace isolation.

> ✅ **Done!** SIGIL is now protecting your secrets.

> ❌ If you see "permission denied", check that the daemon socket path is correct.
```

### Callout Types

| Type | Emoji | Usage |
|------|-------|-------|
| Tip | 💡 | Helpful advice, best practices |
| Warning | ⚠️ | Security cautions, destructive actions |
| Note | ℹ️ | Additional context, clarifications |
| Success | ✅ | Confirmation that a step completed correctly |
| Error | ❌ | Error states and troubleshooting guidance |

---

## 💻 Code Blocks

All code blocks must specify the language for syntax highlighting:

```markdown
\`\`\`bash
cargo install sigil-cli
\`\`\`

\`\`\`toml
[daemon]
socket = "/run/user/1000/sigil.sock"
\`\`\`

\`\`\`rust
use sigil_sdk::SigilClient;
let client = SigilClient::connect()?;
\`\`\`
```

### Copy-Friendly Commands

Quickstart and installation blocks should NOT include shell prompt prefixes (`$`, `>`) on lines the user should copy:

```markdown
## 🚀 Quickstart

\`\`\`bash
# Install
cargo install sigil-cli

# Initialize vault
sigil init

# Add a secret
sigil add kalshi/api_key
\`\`\`
```

### Representative Output

When showing command output, include representative output to help users understand what to expect:

```bash
$ sigil list
Secrets in vault:
  kalshi/api_key          (ApiKey)     Created: 2025-04-01
  github/token            (Generic)    Created: 2025-03-15
```

---

## 📊 Tables

Use tables for structured comparisons and lists:

```markdown
| Platform | Architecture | Tier | Sandbox Engine |
|----------|-------------|------|---------------|
| 🐧 Linux | x86_64 | Tier 1 | bubblewrap + seccomp |
| 🍎 macOS | Apple Silicon | Tier 1 | sandbox-exec |
| 🪟 WSL2 | x86_64 | Tier 1 | bubblewrap + seccomp |
```

Use prose for explanations — tables are for structured data only.

---

## 🔗 Links

### Internal Links

Use relative paths for internal documentation:

```markdown
See [Quickstart](quickstart.md) for installation instructions.
See [Claude Code Guide](agents/claude-code.md) for agent-specific setup.
```

### External Links

Use descriptive link text:

```markdown
See the [bubblewrap documentation](https://github.com/containers/bubblewrap) for sandbox details.
```

---

## 📋 README Formatting Specifics

The README has additional formatting rules because it renders on the GitHub repository landing page:

1. **Badge row**: shield.io badges at the top (CI status, release version, license, platform support)
2. **Demo section**: embedded asciinema SVG or animated terminal recording (not GIF — GIFs are large and lossy)
3. **Quickstart code block**: single fenced block with copy-friendly commands (no `$` prompt prefix)
4. **Section dividers**: use `---` between major sections for visual breathing room
5. **No H1 emoji**: GitHub renders repo name as title — emoji begin at H2 level

---

## 🚧 Known Limitations

Every page that makes claims about capabilities MUST include a "Known Limitations" section that honestly states what SIGIL doesn't do or where coverage is incomplete.

Example:

```markdown
## 🚧 Known Limitations

- **No native Windows support** — WSL2 is required for Windows users
- **FUSE requires libfuse3-dev** — The sigil-fuse component is excluded from builds on systems without the development library
- **Hook coverage varies by agent** — See per-agent guides for detailed coverage information
```

---

## ✅ Checklist

Before marking a documentation page as complete, verify:

- [ ] All H2 and H3 headings have leading emoji
- [ ] Code blocks specify language for syntax highlighting
- [ ] Callout boxes use proper blockquote syntax with emoji
- [ ] Internal links use relative paths
- [ ] Page ends with "Next Steps" section
- [ ] "Known Limitations" section included (if applicable)
- [ ] Copy-friendly command blocks don't include shell prompt prefixes
- [ ] Tables are used for structured data, prose for explanations
- [ ] Platform indicators (🐧🍎🪟) used appropriately
