# 🤝 Contributing to SIGIL

> Thank you for your interest in contributing to SIGIL! This guide covers how to contribute code, signatures, and agent integrations.

---

## 🚀 Getting Started

### Prerequisites

- **Rust toolchain**: 1.70+ (2021 edition)
- **Development OS**: Linux (Ubuntu 22.04+, Debian 12+) or macOS 13+
- **Bubblewrap**: For sandbox testing (Linux only)
- **Git**: For cloning and contributing

### Clone and Build

```bash
# Clone the repository
git clone https://github.com/jedarden/sigil.git
cd sigil

# Install dependencies and build
cargo build

# Run tests
cargo test

# Run clippy (must pass)
cargo clippy --all-targets -- -D warnings

# Format code (automatic)
cargo fmt
```

### Development Workflow

```bash
# Create a feature branch
git checkout -b feat/my-feature

# Make your changes
# ...

# Run tests
cargo test

# Commit with conventional commit
git commit -m "feat(component): description"

# Push to your fork
git push origin feat/my-feature

# Open a pull request
```

---

## 🏗️ Architecture Overview

SIGIL is organized as a Rust workspace with multiple crates:

```
sigil/
├── Cargo.toml                  # Workspace root
├── crates/
│   ├── sigil-core/             # Core types and traits
│   ├── sigil-vault/            # Local vault implementation
│   ├── sigil-daemon/           # Long-running daemon
│   ├── sigil-cli/              # User-facing CLI
│   ├── sigil-sandbox/          # Sandbox implementation
│   ├── sigil-scrub/            # Output scrubber
│   ├── sigil-tui/              # Terminal UI
│   ├── sigil-mcp/              # MCP server
│   ├── sigil-shell/            # Proxy shell
│   ├── sigil-proxy/            # HTTP forward proxy
│   ├── sigil-fuse/             # FUSE filesystem
│   ├── sigil-canary/           # Canary monitoring
│   ├── sigil-signatures/       # Command signatures
│   ├── sigil-ssh-agent/        # SSH agent protocol
│   ├── sigil-credential-git/   # Git credential helper
│   ├── sigil-credential-docker/ # Docker credential helper
│   └── sigil-sdk/              # Embeddable SDK
```

### Crate Dependencies

```
sigil-cli
    ├── sigil-daemon
    │   ├── sigil-core
    │   ├── sigil-vault
    │   └── sigil-sandbox
    ├── sigil-tui
    │   └── sigil-core
    └── sigil-mcp
        └── sigil-core

sigil-core (no dependencies on other SIGIL crates)
```

### IPC Communication

The daemon and CLI communicate via Unix socket using JSON-RPC:

```json
{"jsonrpc": "2.0", "method": "get_secret", "params": {"path": "api_key"}, "id": 1}
{"jsonrpc": "2.0", "result": {"value": "sk_live_..."}, "id": 1}
```

> 💡 **Tip**: When adding new IPC methods, update both the daemon and client to handle the new message type.

---

## 📝 Adding a Command Signature

Command signatures enable SIGIL to recognize secret-bearing commands.

### Signature Format

Create a TOML file in `crates/sigil-signatures/builtins/`:

```toml
# my-tool.toml

[[signature]]
name = "my-tool-auth"
description = "My Tool CLI with authentication"
pattern = "my-tool --token {{secret:*}}"
severity = "high"  # high, medium, low
```

### Pattern Syntax

- `{{secret:*}}` — Matches any secret path
- `{{secret:aws/*}}` — Matches secrets under `aws/`
- `*` — Wildcard matching

### Testing Your Signature

```bash
# Test pattern matching
cargo run --bin sigil -- signatures test my-tool --token test_value

# Expected output:
# ✓ Matched: my-tool-auth
# Severity: high
# Secret path: (inferred from context)
```

### Contributing

1. Create the signature file in `crates/sigil-signatures/builtins/`
2. Add tests to `crates/sigil-signatures/src/builtins.rs`
3. Update the signature count in the module documentation
4. Submit a PR with the signature file

> 💡 **Tip**: Include example commands in your PR description to show how the signature works in practice.

---

## 🤖 Adding Agent Support

Adding support for a new agent involves implementing hooks and documenting coverage.

### Hook Types

| Hook | Purpose | Required |
|------|---------|----------|
| **PreToolUse** | Scrub tool inputs before execution | Recommended |
| **PostToolUse** | Scrub tool outputs after execution | Recommended |
| **UserPromptSubmit** | Scrub user messages before sending to LLM | Optional |

### Implementation Steps

1. **Research Agent Capabilities**
   - Does the agent support hooks?
   - What hook types are available?
   - How are hooks configured?

2. **Implement Hook Scripts**
   - Create `sigil-hook-<agent>` in `crates/sigil-cli/src/hooks/`
   - Handle agent-specific message format
   - Return scrubbed content in expected format

3. **Add Setup Command**
   - Add `sigil setup <agent>` subcommand
   - Install hooks to agent's config directory
   - Verify installation

4. **Document Coverage**
   - Create `docs/agents/<agent>.md`
   - Document active layers (1-6)
   - Include coverage table (like other agent guides)

5. **Red Team Testing**
   - Verify hooks can't be bypassed
   - Test with various tool types
   - Confirm output scrubbing works

### Coverage Tier Guidelines

| Tier | Layers Active | Hook Support |
|------|---------------|--------------|
| **Comprehensive** | 1-6 | All hooks + MCP |
| **Strong** | 2-4 | PreToolUse/PostToolUse |
| **Moderate** | 2-4 | Partial hooks |
| **Basic** | 2-3 | No hooks (filesystem only) |

---

## 🧪 Testing

### Unit Tests

Write unit tests in `#[cfg(test)]` modules:

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_secret_resolution() {
        let secret = Secret::new("test", "value");
        assert_eq!(secret.path(), "test");
    }
}
```

### Integration Tests

Use `assert_cmd` for CLI integration tests:

```rust
#[test]
fn test_add_command() {
    let mut cmd = Command::cargo_bin("sigil").unwrap();
    cmd.arg("add").arg("test/key");
    cmd.arg("--value").arg("test_value");
    cmd.assert().success();
}
```

### Red Team Checklist

For security-sensitive changes, complete this checklist:

- [ ] Agent cannot read secrets directly from vault
- [ ] Agent cannot extract secrets from process memory
- [ ] Agent cannot bypass hooks to execute commands
- [ ] Agent cannot see secrets in tool outputs
- [ ] Agent cannot leak secrets via filesystem
- [ ] Audit log captures all access attempts
- [ ] Canary detection triggers on unauthorized access

### Fuzzing

For parsers and scrubbers, add fuzzing targets:

```rust
// fuzz/fuzz_targets/scrub.rs
#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = sigil_scrub::scrub_output(data);
});
```

Run with:

```bash
cargo install cargo-fuzz
cargo fuzz run scrub
```

---

## 🔄 Pull Request Process

### Branch Naming

Use conventional commit prefixes:

- `feat/` — New feature
- `fix/` — Bug fix
- `docs/` — Documentation changes
- `refac/` — Refactoring
- `test/` — Test changes
- `security/` — Security fixes

Examples:
- `feat/add-ssh-agent`
- `fix/scrubbing-encoding`
- `docs/quickstart-guide`

### Commit Messages

Follow conventional commit format:

```
<type>(<scope>): <description>

[optional body]

[optional footer]
```

Types: `feat`, `fix`, `docs`, `refac`, `test`, `chore`, `security`

Examples:
- `feat(phase-9): implement SSH agent protocol`
- `fix(phase-3): fix base64 scrubbing for multline output`
- `docs(phase-10): add FAQ section`

### CI Checks

All PRs must pass:

1. **Build**: `cargo build --workspace`
2. **Tests**: `cargo test --workspace`
3. **Clippy**: `cargo clippy --all-targets -- -D warnings`
4. **Format**: `cargo fmt --check`

### Review Expectations

- **Code Review**: At least one maintainer approval
- **Security Review**: Required for security-sensitive changes
- **Documentation**: New features must include docs
- **Tests**: New features must include tests

---

## 🔒 Security Policy

### Responsible Disclosure

**Do not file public issues for security vulnerabilities.**

### Reporting Vulnerabilities

1. **Email**: security@sigil.sh (PGP key available)
2. **GitHub Security Advisory**: Use GitHub's private vulnerability reporting
3. **Include**: Steps to reproduce, impact assessment, suggested fix

### Disclosure Process

1. **Receipt**: We'll acknowledge within 48 hours
2. **Assessment**: We'll assess severity and impact within 7 days
3. **Fix**: We'll develop a fix based on severity
4. **Disclosure**: We'll coordinate public disclosure

### PGP Key

```
-----BEGIN PGP PUBLIC KEY BLOCK-----
[PGP key here]
-----END PGP PUBLIC KEY BLOCK-----
```

> ⚠️ **Warning**: Never disclose security vulnerabilities publicly before coordination. Premature disclosure puts users at risk.

---

## 📦 Release Process

### Versioning

SIGIL follows semantic versioning:

- **MAJOR**: Breaking changes
- **MINOR**: New features (backward compatible)
- **PATCH**: Bug fixes (backward compatible)

### Release Checklist

- [ ] Update version in `Cargo.toml`
- [ ] Update `CHANGELOG.md`
- [ ] Tag release: `git tag -a v0.1.0 -m "Release v0.1.0"`
- [ ] Push tag: `git push origin v0.1.0`
- [ ] GitHub release publishes automatically
- [ ] Update documentation links if needed

### Changelog Format

```markdown
## [0.1.0] - 2026-04-05

### Added
- SSH agent protocol support
- Docker credential helper

### Fixed
- Base64 scrubbing for multiline output

### Security
- No security changes
```

---

## 👉 Next Steps

- [Issue Tracker](https://github.com/jedarden/sigil/issues) — Find open issues to work on
- [Documentation](docs/) — Learn more about SIGIL's architecture
- [Security Policy](SECURITY.md) — Responsible disclosure guidelines
- `sigil help` — In-terminal documentation

---

## 🙏 Thank You

SIGIL is a community project. We appreciate all contributions, whether code, documentation, bug reports, or feature requests!

> 💡 **First-time contributors?** Look for issues labeled `good first issue` or `help wanted`.
