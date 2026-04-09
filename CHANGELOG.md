# Changelog

All notable changes to SIGIL will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [Unreleased]

### Added
- **Post-quantum hybrid mode** (experimental, `pq-hybrid` feature)
  - ML-KEM-768 (Kyber) key encapsulation infrastructure
  - Hybrid encryption: ML-KEM-768 + age X25519 for quantum-resistant vaults
  - `sigil-vault` now supports optional `pq-hybrid` feature for future-proofing
  - Note: Full ML-KEM-768 encapsulation/decapsulation pending stable ml-kem crate release
- **Phase 10: Documentation and Onboarding (Complete)**
  - Documentation style guide (`docs/STYLE.md`) with emoji conventions
  - Quickstart guide (`docs/quickstart.md`) with step-by-step setup
  - Concepts and architecture guide (`docs/concepts.md`)
  - Per-agent setup guides for Claude Code, Cursor, Aider, Cline, Codex CLI, and generic agents
  - FAQ (`docs/faq.md`) with common scenarios
  - Contributing guide (`CONTRIBUTING.md`) with development workflow
  - Security policy (`SECURITY.md`) with responsible disclosure
- All 10 phases of the SIGIL implementation plan are now complete

### Changed
- Updated README to match Phase 10 documentation specifications
- Replaced demo SVG reference with terminal output example
- All documentation follows the standardized style guide with emoji section markers

### Security
- No security changes in this release
- Red team report documents 95% block rate (39/41 attacks blocked, 2 known limitations with compensating controls)

---

## [0.4.0] - 2026-04-07

### Added - Phase 8: Advanced Features
- Sealed vault mode with git-committable single-file vault
- Multi-factor authentication with Shamir's Secret Sharing
- Device enrollment and management for team vaults
- Recovery codes for emergency vault access
- 2SKD (Two-Server Key Derivation) for enhanced security
- Configuration opacity (Tier 2 config protection)
- `sigil vault convert` for vault mode conversion
- `sigil team` commands for user and device management
- `sigil recovery` commands for recovery code management

### Added - Phase 9: Platform Features
- FUSE virtual filesystem (`sigil-fuse`) for universal secret file access
- FUSE mount integration with sandbox via `--ro-bind` at `/sigil/`
- HTTP(S) forward proxy (`sigil-proxy`) with domain-based auth injection
- AWS SigV4 request signing support
- Git credential helper (`git-credential-sigil`)
- Docker credential helper (`docker-credential-sigil`)
- SSH agent (`sigil-ssh-agent`) with key constraints
- Decoy response mode for canary files
- Sealed operations with output filtering
- Secret request workflow with TUI approval
- Emergency lockdown with auto-triggers
- `sigil unlock` for post-lockdown recovery
- Community signature database with 50+ built-in patterns
- SIGIL SDK for Rust, Python, and Node.js
- `sigil doctor` with automated fix suggestions
- `sigil signatures` commands for signature management
- `sigil lockdown` command for incident response
- MCP tools: `sigil_list_operations`, `sigil_request`, `sigil_check_access`

### Changed
- Improved vault performance with caching
- Enhanced scrubbing with 7 encoding variants
- Updated CLI help with embedded topic documentation
- Improved sandbox performance benchmarks

### Fixed
- Fixed vault migration issues
- Fixed daemon socket permissions on macOS
- Fixed canary detection race condition

---

## [0.3.0] - 2026-03-15

### Added - Phase 5: Agent Integration Layer
- MCP server (`sigil-mcp`) with 8 tools for Claude Code
- Claude Code hook integration (PreToolUse, PostToolUse, UserPromptSubmit)
- Sealed operations support
- Secret request workflow with time-bounded approvals
- Output filtering modes (exit_code, summary, full_scrubbed, none)
- TUI approval interface for sensitive operations
- Persistent access grants in `~/.sigil/access-grants.toml`
- `sigil setup claude-code` for automated hook installation

### Added - Phase 6: TUI and External Backends
- Terminal UI (`sigil-tui`) with ratatui
- External vault backends: HashiCorp Vault, 1Password, pass, sops
- AWS Secrets Manager backend
- Backend configuration in `config.toml`
- `sigil tui` command for interactive secret management
- `sigil backend` commands for backend management

### Added - Phase 7: Breach Detection, Canaries, and Red-Teaming
- Canary monitoring with inotify/fanotify
- Decoy credential generation
- Breach detection and reporting
- Audit log with hash chain integrity
- `sigil canary` commands for canary management
- `sigil audit` commands for log inspection
- `sigil breach-report` for incident documentation
- Red team checkpoint tests for security validation

### Changed
- Improved error messages throughout
- Enhanced vault migration handling
- Better sandbox error recovery

---

## [0.2.0] - 2026-02-01

### Added - Phase 3: Command Parser and Output Scrubber
- Command parser with placeholder extraction
- Aho-Corasick output scrubber with 7 encoding variants
- Command signature database for automatic injection
- `sigil exec` for running commands with secret injection
- `sigil scrub` for standalone output scrubbing
- `sigil parse` for testing command parsing
- Signature matching and injection rules

### Added - Phase 4: Sandbox Execution Engine
- bubblewrap sandbox integration (Linux/WSL2)
- sandbox-exec integration (macOS)
- seccomp filter for syscall restriction
- Namespace isolation (PID, mount, network, UTS, IPC)
- `sigil sandbox` commands for sandbox management
- Platform-specific sandbox configuration
- Performance benchmarking suite

### Changed
- Rewrote vault backend for better performance
- Improved age encryption handling
- Better cross-platform support

### Fixed
- Fixed sandbox mount point issues
- Fixed seccomp filter compatibility
- Fixed macOS sandbox limitations

---

## [0.1.0] - 2026-01-15

### Added - Phase 1: Core Vault and CLI
- Initial release
- Rust workspace with multiple crates
- Core types and traits (`SecretPath`, `SecretValue`, `SecretMetadata`)
- Local vault implementation with age encryption
- CLI commands: `init`, `add`, `get`, `list`, `edit`, `rm`, `export`, `import`
- Export/import format (.sigil archives)
- Versioning and migration support
- Lifecycle management (`sigil uninstall`)
- In-binary documentation with `sigil help` topics

### Added - Phase 2: Daemon and IPC
- Long-running daemon (`sigild`)
- Unix socket IPC protocol
- Session token authentication
- Memory protection (mlock, PR_SET_DUMPABLE)
- Secret caching in secure memory
- Audit logging for all secret access
- `sigil daemon` commands for daemon management

---

## [0.0.1] - 2025-12-01

### Added
- Initial project scaffolding
- Basic crate structure
- CI via Argo Workflows

---

## Release Notes Format

Each release includes:

### Added
- New features
- New commands
- New capabilities

### Changed
- Changes to existing functionality
- Performance improvements
- Behavior changes

### Deprecated
- Features that will be removed in future releases

### Removed
- Features removed in this release

### Fixed
- Bug fixes
- Security fixes

### Security
- Security vulnerability disclosures
- Security improvements

---

## Versioning Policy

SIGIL follows [Semantic Versioning](https://semver.org/):

- **Major version (X.0.0)**: Breaking changes, incompatible API changes
- **Minor version (0.X.0)**: New features, backwards compatible
- **Patch version (0.0.X)**: Bug fixes, backwards compatible

### Migration Guides

For major version changes, migration guides will be provided:

```bash
sigil migrate --from 0.3.0 --to 0.4.0
```

---

## Signing Keys

Release binaries are signed with the SIGIL signing key:

- **Key ID**: `SIGIL-RS-RELEASE`
- **Fingerprint**: Available at `https://sigil-rs.org/release-key.txt`

Verify signatures:
```bash
gpg --verify sigil-0.4.0.sig sigil-0.4.0.tar.gz
```
