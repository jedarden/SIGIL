# SIGIL Overview

SIGIL is a secret management system for AI coding agents. It prevents secrets from leaking into agent context windows, conversation logs, and generated code.

## How It Works

SIGIL creates a defense-in-depth interception layer between AI agents and secrets:

1. **Placeholders replace secrets** - Agents use `{{secret:path}}` instead of real values
2. **Interception at every layer** - Hooks, shell, filesystem, and sandbox all prevent leaks
3. **Output scrubbing** - Exact-match scrubbing removes secrets from responses
4. **Audit trail** - Every secret access is logged for security review
5. **Canary monitoring** - Decoy secrets detect unauthorized access attempts

## Quickstart

```bash
# Install
cargo install sigil-cli

# One-command setup (recommended)
sigil quickstart

# Or manual setup
sigil init
sigil add kalshi/api_key

# Use in commands
sigil exec 'curl -H "Authorization: Bearer {{secret:kalshi/api_key}}" https://api.example.com'
```

## Key Concepts

- **Vault**: Age-encrypted local storage for secrets
- **Placeholders**: `{{secret:path}}` syntax for safe secret reference
- **Hooks**: Agent integration points for interception
- **Sandbox**: Process isolation for execution
- **Scrubbing**: Output sanitization to remove leaked secrets

## Architecture

SIGIL operates at 6 layers:

1. **Agent Hooks** - Intercept tool calls, scrub inputs/outputs
2. **Proxy Shell** - Intercept all commands, resolve placeholders
3. **Filesystem Monitor** - Detect secret writes to disk
4. **Sandbox** - Isolate execution, prevent direct access
5. **Vault** - Age-encrypted local storage
6. **Canary Monitoring** - Detect and respond to unauthorized access

## Documentation

For more information, see:
- `sigil topic vault` - Vault architecture and encryption
- `sigil topic hooks` - Agent hook integration
- `sigil topic placeholders` - Placeholder syntax and usage
- `sigil topic security` - Security best practices
- `sigil topic sandbox` - Sandbox execution engine
- `sigil topic migrate` - Data format migration
- `sigil topic team` - Team collaboration features
- `sigil topic ci` - CI/CD integration

## Support

- GitHub: https://github.com/jedarden/SIGIL
- Documentation: https://docs.sigil.rs
