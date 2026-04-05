# SIGIL Coding Conventions

## Project Structure

SIGIL is a Rust workspace with multiple crates:

- **sigil-core**: Core types and traits (SecretPath, SecretValue, SecretBackend)
- **sigil-vault**: Local vault implementation using age encryption
- **sigil-cli**: User-facing CLI (`sigil` command)
- **sigil-daemon**: Long-running daemon (`sigild`)
- **sigil-sandbox**: Sandbox implementation (bubblewrap + seccomp)
- **sigil-scrub**: Output scrubber for detecting secrets
- **sigil-tui**: Terminal UI for secret management
- **sigil-mcp**: MCP server for Claude Code integration
- **sigil-shell**: POSIX-compatible shell wrapper
- **sigil-proxy**: HTTP forward proxy for auth injection
- **sigil-sdk**: Embeddable SDK for SIGIL

## Development Workflow

1. **Incremental development**: Implement one deliverable at a time
2. **Always compile**: Never leave the repo in a broken state
3. **Test first**: Write tests alongside code (unit tests in `#[cfg(test)]` modules)
4. **Security first**: Use `zeroize` and `secrecy` for all secret-holding types
5. **Error handling**: All public functions return `Result<T>` with `anyhow` or `thiserror`

## Code Quality

- **Clippy**: `cargo clippy --all-targets -- -D warnings` (must pass)
- **Formatting**: `cargo fmt` (automatic formatting)
- **Testing**: `cargo test` (all tests must pass)
- **No unwrap/expect**: Never use `unwrap()` or `expect()` in non-test code

## Security Guidelines

1. **Zeroize secrets**: Use `Zeroizing<Vec<u8>>` for all secret values
2. **No secret logging**: Never log secret values, only fingerprints
3. **Memory protection**: Use `mlock()` where appropriate (Phase 2+)
4. **Path validation**: Validate all SecretPath inputs to prevent directory traversal

## Commit Convention

- `feat(phase-N): description` - New feature
- `fix(phase-N): description` - Bug fix
- `refac(phase-N): description` - Refactoring
- `docs(phase-N): description` - Documentation
- `test(phase-N): description` - Tests only

## Current Phase

Phase 1: Core Vault and CLI

See `docs/plan/plan.md` for the full implementation plan.
