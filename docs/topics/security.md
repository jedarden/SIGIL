# Security

SIGIL provides defense-in-depth protection for secrets used by AI agents.

## Threat Model

### What SIGIL Protects Against

- Context window leaks (secrets in agent context)
- Prompt injection attacks
- Log exfiltration
- Filesystem dumps (vault is encrypted)
- Memory dumps (secrets use mlock and zeroize)
- Canary access (decoy responses + breach alerts)

### What SIGIL Does NOT Protect Against

- Agent memorizing secrets before SIGIL installation
- Compromised host (root access bypasses protections)
- Network interception (use TLS for API communication)
- Social engineering (human factors out of scope)

## Defense Layers

### Layer 1: Agent Hooks
- Intercept tool calls before/after execution
- Scrub inputs and outputs
- Log access attempts

### Layer 2: Proxy Shell
- Intercept all shell commands
- Resolve placeholders
- Scrub outputs

### Layer 3: Filesystem Monitor
- Detect secret writes to disk
- Monitor for suspicious file operations
- Alert on canary access

### Layer 4: Sandbox
- Isolate process execution
- Restrict filesystem access
- Filter syscalls

### Layer 5: Vault
- Age encryption at rest
- Optional passphrase protection
- Append-only audit log

### Layer 6: Canary Monitoring
- Decoy responses for unauthorized access
- Breach alerts and logging
- Behavioral analysis

## Encryption

### Vault Encryption
- **Algorithm**: age (Rust implementation)
- **Key file**: `~/.sigil/identity.age`
- **Passphrase**: Optional but recommended

### IPC Encryption
- Unix socket with file permissions (0600)
- Session token authentication
- No network exposure by default

## Memory Protection

- **Zeroize**: Secrets cleared from memory when freed
- **mlock**: Secrets locked in RAM (not swapped to disk)
- **No copies**: Minimize secret copies in memory

## Audit Logging

All secret access is logged to `~/.sigil/vault/audit.jsonl`:

```json
{
  "timestamp": "2026-04-05T02:00:00Z",
  "secret": "api_key",
  "operation": "read",
  "pid": 1234,
  "uid": 1000,
  "result": "success"
}
```

Audit log properties:
- **Append-only**: Cannot be modified or deleted
- **Hash chain**: Tamper-evident
- **Rotated**: Archived periodically

## Canary Files

Canary files detect unauthorized access:

```bash
# Create canary
sigil canary create ~/.aws/credentials

# Monitor for access
sigild monitor --daemon
```

Canary access triggers:
- Decoy response returned
- CRITICAL breach alert logged
- Optional lockdown triggered

## Best Practices

1. **Use passphrases**: Add passphrase protection to vault
2. **Enable monitoring**: Run daemon with canary monitoring
3. **Review logs**: Check audit log regularly
4. **Rotate secrets**: Regular secret rotation
5. **Update dependencies**: Keep SIGIL updated
6. **Backup securely**: Encrypt vault backups
7. **Limit access**: Use team vault for shared secrets

## Incident Response

If breach is suspected:

```bash
# Immediate lockdown
sigil lockdown

# Generate breach report
sigil breach-report

# Rotate compromised secrets
# (follow service-specific procedures)

# Review audit log
grep "breach\|unauthorized" ~/.sigil/vault/audit.jsonl

# Lift lockdown (after remediation)
sigil unlock
```

## Reporting Vulnerabilities

See SECURITY.md for responsible disclosure guidelines.

Email: security@sigil.sh
