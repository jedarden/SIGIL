# Changelog

All notable changes to SIGIL will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Phase 9: Platform features (FUSE, HTTP proxy, credential helpers, decoy mode)
- Phase 10: Documentation and onboarding guides

### Changed
- Updated README with comprehensive project overview
- Added documentation style guide

### Security
- No security changes

---

## [0.1.0] - 2026-04-05

### Added
- Initial release of SIGIL
- Core vault with age encryption
- CLI commands (init, add, get, list, rm, export, import)
- Daemon with IPC via Unix socket
- Proxy shell for command interception
- Sandbox execution with bubblewrap
- Output scrubbing with exact-match detection
- Canary monitoring and breach detection
- Claude Code agent integration with hooks
- MCP server for agent integration
- Git credential helper
- SSH agent protocol
- Docker credential helper
- HTTP forward proxy with auth injection
- Decoy response mode
- Sealed operations
- Emergency lockdown command
- Community signature database
- SIGIL SDK for Rust
- `sigil doctor` health check command

### Security
- Initial security implementation with 6-layer defense
- Vault encryption using age
- Append-only audit log
- Memory protection with `zeroize` and `mlock`
- Process isolation with bubblewrap sandbox

---

## [Future Versions]

### Planned
- Team vault support with OpenBao/Vault backends
- TUI for secret management
- Additional agent integrations (Codex CLI, Cursor, Aider, Cline)
- Python and Node.js SDK bindings
- FUSE virtual filesystem for `/sigil/` mount
- Advanced canary templates
- Signature update mechanism
- CI/CD integration improvements

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

[Unreleased]: https://github.com/jedarden/sigil/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/jedarden/sigil/releases/tag/v0.1.0
