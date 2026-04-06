# Changelog

All notable changes to SIGIL will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Performance benchmark suite for SIGIL core operations (scrubber, vault, crypto)
- Dynamic lease revocation for external vault backends
- Red team checkpoint integration tests for all phases (1-9)
- Post-lockdown request rejection (daemon rejects all requests after lockdown)
- Bulk request support to sigil_request MCP tool
- `sigil merge` command for team vault conflict resolution
- `--canaries-only` and `--credentials-only` flags to `sigil uninstall`

### Changed
- Scrubber now loads ALL secret versions for detection (not just current)
- Improved documentation with comprehensive red-team security report
- Updated README badges and quickstart Next Steps section
- Applied clippy formatting improvements across all crates

### Fixed
- Benchmark bugs in scrub_bench and vault_bench
- Clippy warnings in shamir crate with appropriate allow attributes

### Security
- Enhanced secret version detection prevents old secret leaks
- Dynamic lease revocation improves external vault security

---

## [0.2.0] - 2026-04-06

### Added
- Performance benchmark suite for SIGIL core operations (scrubber, vault, crypto)
- Dynamic lease revocation for external vault backends
- Red team checkpoint integration tests for all phases (1-9)
- Post-lockdown request rejection (daemon rejects all requests after lockdown)
- Bulk request support to sigil_request MCP tool
- `sigil merge` command for team vault conflict resolution
- `--canaries-only` and `--credentials-only` flags to `sigil uninstall`

### Changed
- Scrubber now loads ALL secret versions for detection (not just current)
- Improved documentation with comprehensive red-team security report
- Updated README badges and quickstart Next Steps section
- Applied clippy formatting improvements across all crates

### Fixed
- Benchmark bugs in scrub_bench and vault_bench
- Clippy warnings in shamir crate with appropriate allow attributes

### Security
- Enhanced secret version detection prevents old secret leaks
- Dynamic lease revocation improves external vault security

---

## [0.1.0] - 2026-04-05

### Added
- Initial release of SIGIL (Phases 1-10 complete)
- Core vault with age encryption (directory mode + sealed mode)
- CLI commands (init, add, get, list, rm, export, import, doctor, lockdown, merge)
- Daemon with IPC via Unix socket (`sigild`)
- Proxy shell for command interception (`sigil-shell`)
- Sandbox execution with bubblewrap (Linux) and sandbox-exec (macOS)
- Output scrubbing with exact-match detection (7 encodings)
- Canary monitoring and breach detection
- Claude Code agent integration with hooks (PreToolUse, PostToolUse, UserPromptSubmit)
- MCP server for agent integration (`sigil-mcp`) with 8 tools
- Git credential helper (`git-credential-sigil`)
- SSH agent protocol (`sigil-ssh-agent`)
- Docker credential helper (`docker-credential-sigil`)
- HTTP forward proxy with auth injection (`sigil-proxy`)
- Decoy response mode
- Sealed operations with approval workflow
- Emergency lockdown command
- Community signature database framework
- SIGIL SDK for Rust, Python, and Node.js
- `sigil doctor` health check command
- Terminal UI for secret management (`sigil-tui`)
- FUSE virtual filesystem for `/sigil/` mount (sigil-fuse)
- Team vault support with sealed mode and Shamir's Secret Sharing
- Comprehensive documentation (README, quickstart, concepts, agent guides, FAQ, CONTRIBUTING, SECURITY)

### Security
- Initial security implementation with 6-layer defense
- Vault encryption using age (X25519 + ChaCha20-Poly1305)
- Sealed vault with XChaCha20-Poly1305 and Argon2id KDF
- Append-only audit log with hash chaining
- Memory protection with `zeroize` and `mlock`
- Process isolation with bubblewrap sandbox and seccomp
- TOCTOU-safe secret injection with memfd (Linux)

---

## [Future Versions]

### Planned
- External vault backend implementations (Vault, OpenBao, AWS Secrets Manager with dynamic lease revocation)
- Additional agent integrations (Codex CLI, Cursor, Aider, Cline - docs exist, hooks to be implemented)
- Advanced canary templates and community signature update mechanism
- CI/CD integration improvements (Argo Workflows sensor, GitHub Actions integration)

---

## Migration Guide

### Version Upgrades

When upgrading between versions, check this section for breaking changes.

#### 0.1.0 → 0.2.0 (Future)

No breaking changes expected.

---

## Security Policy

For vulnerability reporting, see [SECURITY.md](SECURITY.md).

All security-related changes are documented in the "Security" section for each release.

---

[Unreleased]: https://github.com/jedarden/sigil/compare/v0.2.0...HEAD
[0.2.0]: https://github.com/jedarden/sigil/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/jedarden/sigil/releases/tag/v0.1.0
