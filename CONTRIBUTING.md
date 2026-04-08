# 🤝 Contributing to SIGIL

> Guide for contributors — how to build, test, and contribute to SIGIL.

---

## 🚀 Getting Started

### Prerequisites

- **Rust 1.75+** — Install via [rustup](https://rustup.rs/)
- **Git** — For cloning the repository
- **Make** (optional) — For running make commands

### Clone and Build

```bash
# Clone the repository
git clone https://github.com/sigil-rs/sigil.git
cd sigil

# Build all workspace members
cargo build --release

# Run tests
cargo test

# Run linter
cargo clippy --all-targets -- -D warnings

# Format code
cargo fmt
```

### Development Workflow

1. **Create a branch** — `git checkout -b feature/my-feature`
2. **Make changes** — Edit code, add tests
3. **Verify** — `cargo test`, `cargo clippy`, `cargo fmt`
4. **Commit** — `git commit -m "feat: description"`
5. **Push** — `git push origin feature/my-feature`
6. **Open PR** — GitHub pull request with description

---

## 🏗️ Architecture Overview

SIGIL is a Rust workspace with multiple crates:

```
sigil/
├── Cargo.toml              # Workspace configuration
├── crates/
│   ├── sigil-core/         # Core types and traits
│   ├── sigil-vault/        # Vault implementations (directory, sealed)
│   ├── sigil-cli/          # User-facing CLI (`sigil` command)
│   ├── sigil-daemon/       # Long-running daemon (`sigild`)
│   ├── sigil-sandbox/      # Sandbox implementation (bubblewrap + seccomp)
│   ├── sigil-scrub/        # Output scrubber (Aho-Corasick)
│   ├── sigil-canary/       # Canary monitoring and decoy generation
│   ├── sigil-tui/          # Terminal UI (ratatui)
│   ├── sigil-mcp/          # MCP server for Claude Code
│   ├── sigil-shell/        # POSIX-compatible proxy shell
│   ├── sigil-proxy/        # HTTP forward proxy
│   ├── sigil-fuse/         # FUSE virtual filesystem (requires libfuse3-dev)
│   ├── sigil-sdk/          # Embeddable SDK (Rust)
│   ├── sigil-sdk-python/   # Python bindings (PyO3)
│   ├── sigil-sdk-nodejs/   # Node.js bindings (napi-rs)
│   ├── sigil-signatures/   # Command signature database
│   ├── sigil-shamir/       # Shamir's Secret Sharing
│   ├── sigil-credential-git/     # Git credential helper
│   ├── sigil-credential-docker/  # Docker credential helper
│   ├── sigil-ssh-agent/    # SSH agent implementation
│   ├── sigil-backend-*/    # External vault backends (Vault, AWS, etc.)
│   ├── sigil-redteam/      # Red team testing utilities
│   ├── sigil-bench/        # Performance benchmarks
│   └── sigil-integration-tests/  # Integration tests
└── docs/                   # Documentation
```

### Crate Dependencies

```
sigil-cli
  ├── sigil-core (types, traits)
  ├── sigil-vault (vault operations)
  ├── sigil-daemon (IPC client)
  └── sigil-signatures (command matching)

sigil-daemon
  ├── sigil-core (IPC protocol)
  ├── sigil-vault (vault access)
  ├── sigil-scrub (output scrubbing)
  ├── sigil-canary (canary monitoring)
  └── sigil-sandbox (execution isolation)

sigil-mcp
  ├── sigil-core (IPC client)
  └── sigil-daemon (via IPC)

sigil-proxy
  ├── sigil-core (types)
  ├── sigil-vault (secret access)
  └── sigil-scrub (response scrubbing)
```

### IPC Protocol

SIGIL uses a JSON-based IPC protocol over Unix socket:

```json
{
  "v": 1,
  "type": "resolve",
  "session_token": "abc123",
  "placeholder": "{{secret:kalshi/api_key}}"
}
```

Response:
```json
{
  "v": 1,
  "type": "resolve_response",
  "value": "sk_live_...",
  "scrubbed": true
}
```

---

## 📝 Adding a Command Signature

Command signatures enable automatic secret injection. Contribute new signatures to the community database.

### Signature Format

Create a TOML file in `crates/sigil-signatures/builtins/`:

```toml
# my-tool.toml

[[signature]]
name = "my-tool"
pattern = "^my-tool (?P<command>[a-z-]+)"
description = "My Custom CLI Tool"

[[signature.injection]]
env_var = "API_KEY"
secret = "my_tool/api_key"

[[signature.injection]]
env_var = "CONFIG_FILE"
secret = "my_tool/config:file"
```

### Test Your Signature

```bash
# Build with your signature
cargo build --release

# Test matching
sigil signatures test "my-tool command"

# Verify injection
sigil exec 'my-tool command'
```

### Submit Your Signature

1. **Fork the repository** — `https://github.com/sigil-rs/sigil`
2. **Create a branch** — `git checkout -b signatures/my-tool`
3. **Add signature file** — `crates/sigil-signatures/builtins/my-tool.toml`
4. **Update index** — Add to `crates/sigil-signatures/builtins.rs`
5. **Test** — `cargo test --package sigil-signatures`
6. **Submit PR** — With description of the tool and injection behavior

> 💡 **Tip**: Include a test case that verifies the signature matches expected commands.

---

## 🤖 Adding Agent Support

To add support for a new AI coding agent:

### 1. Identify Hook Capabilities

Check if the agent supports:
- **PreToolUse** — Intercept before tool execution
- **PostToolUse** — Scrub after tool execution
- **UserPromptSubmit** — Scrub user prompts

### 2. Implement Hooks

Create hook scripts in `crates/sigil-cli/src/hooks/`:

```rust
// my_agent_hooks.rs

pub fn install_pre_tool_use(config: &Config) -> Result<()> {
    // Add PreToolUse hook to agent config
}

pub fn install_post_tool_use(config: &Config) -> Result<()> {
    // Add PostToolUse hook to agent config
}
```

### 3. Add Setup Command

Add to `crates/sigil-cli/src/main.rs`:

```rust
/// Setup SIGIL for MyAgent
Setup(MyAgentSetupCommand),
```

### 4. Write Tests

Add integration tests in `crates/sigil-integration-tests/`:

```rust
#[test]
fn test_my_agent_pre_tool_use_hook() {
    // Verify hook intercepts tool calls
}

#[test]
fn test_my_agent_post_tool_use_scrubbing() {
    // Verify output is scrubbed
}
```

### 5. Documentation

Create agent guide in `docs/agents/my-agent.md` following the style guide.

---

## 🧪 Testing

### Unit Tests

Run unit tests for a specific crate:

```bash
cargo test --package sigil-core
cargo test --package sigil-vault
```

### Integration Tests

Run all integration tests:

```bash
cargo test --package sigil-integration-tests
```

### Red Team Tests

Run red team checkpoint tests:

```bash
cargo test --package sigil-redteam
```

### Benchmarks

Run performance benchmarks:

```bash
cargo test --package sigil-bench -- --nocapture
```

### Test Coverage

Generate coverage report:

```bash
cargo install cargo-tarpaulin
cargo tarpaulin --workspace --exclude-files "*/tests/*" --out Html
```

---

## 🔒 Pull Request Process

### Branch Naming

Use descriptive branch names:

- `feat/add-feature` — New feature
- `fix/bug-fix` — Bug fix
- `docs/update-readme` — Documentation update
- `refactor/rename-function` — Refactoring
- `test/add-tests` — Adding tests

### Commit Messages

Follow [Conventional Commits](https://www.conventionalcommits.org/):

```
feat(phase-N): description

fix(phase-N): description

refac(phase-N): description

docs(phase-N): description

test(phase-N): description
```

### PR Template

```markdown
## Description
Brief description of changes.

## Type
- [ ] Feature
- [ ] Bug fix
- [ ] Documentation
- [ ] Refactoring
- [ ] Tests

## Testing
- [ ] Unit tests pass
- [ ] Integration tests pass
- [ ] Manual testing completed

## Checklist
- [ ] Code follows style guide
- [ ] Documentation updated
- [ ] No clippy warnings
- [ ] All tests pass
```

### CI Checks

All PRs must pass:
1. **Argo Workflows CI** — `cargo fmt`, `cargo check`, `cargo clippy`, `cargo test`
2. **Code review** — At least one maintainer approval
3. **Security review** — For security-sensitive changes

---

## 🔒 Security Policy

### Reporting Vulnerabilities

> ⚠️ **Warning**: Do NOT file public issues for security vulnerabilities.

To report a security vulnerability:

1. **Email**: security@sigil-rs.org
2. **PGP Key**: Available at `https://sigil-rs.org/pgp-key.asc`
3. **Include**: Description, reproduction steps, impact assessment

### Security Review Process

1. **Acknowledgment** — Within 48 hours
2. **Assessment** — Within 1 week
3. **Fix** — Within 2 weeks (for critical issues)
4. **Disclosure** — Coordinated disclosure after fix is released

### Security-Sensitive Changes

For PRs that touch security-critical code:
- Require 2 maintainer approvals
- Additional red team testing
- Documentation update

Security-critical areas:
- Cryptography (sigil-vault, sigil-core)
- IPC protocol (sigil-daemon)
- Scrubbing logic (sigil-scrub)
- Sandbox (sigil-sandbox)

---

## 📋 Development Guidelines

### Code Style

- **Rust 2021 edition** — Use modern Rust features
- **No unwrap/expect** — Use `?` or `Result` propagation
- **Zeroize secrets** — Use `Zeroizing<Vec<u8>>` for secret data
- **Error handling** — Return `Result<T>` with `anyhow` or `thiserror`
- **Documentation** — All public functions must have docs

### Security Guidelines

1. **Secret handling** — Always use `zeroize` for secret data
2. **Memory protection** — Use `mlock()` where appropriate
3. **Path validation** — Validate all SecretPath inputs
4. **Audit logging** — Log all secret access
5. **Testing** — Include red team tests for security features

### Performance Guidelines

1. **Benchmark** — Add benchmarks for hot paths
2. **Profile** — Use `cargo flamegraph` for optimization
3. **Allocations** — Minimize allocations in hot paths
4. **Async** — Use async I/O for network operations

---

## 🚧 Known Issues

See [GitHub Issues](https://github.com/sigil-rs/sigil/issues) for known issues and feature requests.

---

## 👉 Next Steps

- [GitHub Issues](https://github.com/sigil-rs/sigil/issues) — Find something to work on
- [Documentation Style Guide](docs/STYLE.md) — Follow the style guide
- [SECURITY.md](SECURITY.md) — Security policy and reporting
