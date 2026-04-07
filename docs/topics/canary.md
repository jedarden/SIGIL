# Canary

Canary secrets are fake credentials planted in the sandbox to detect unauthorized access attempts. They exist only in memory (tmpfs) inside the bubblewrap sandbox overlay—never on the host filesystem.

## Concept

When an agent accesses a canary file (like `~/.aws/credentials`), SIGIL returns a realistic-looking fake value instead of "access denied". This allows SIGIL to:

1. Detect the unauthorized access
2. Track what the agent does with the fake credential
3. Log a CRITICAL breach event with full context

## Canary Files

Common canary file locations:

| File | Purpose |
|------|---------|
| `~/.aws/credentials` | AWS credential leakage |
| `~/.aws/config` | AWS config file access |
| `~/.ssh/id_rsa` | SSH private key access |
| `~/.ssh/id_ed25519` | SSH Ed25519 key access |
| `~/.docker/config.json` | Docker credential leakage |
| `~/.npmrc` | NPM token leakage |
| `.env` | Environment variable leakage |
| `.git/config` | Git credential helper access |

## Decoy Values

Canary responses are format-correct fake credentials:

| Type | Format |
|------|--------|
| AWS Access Key | `AKIA` + 16 uppercase alphanumeric |
| AWS Secret Key | 40-character base64-like string |
| GitHub Token | `ghp_` + 36 alphanumeric |
| Stripe Key | `sk_live_` + 24 alphanumeric |
| JWT | Valid header.payload.signature structure |
| SSH Key | Valid PEM structure with random key material |
| Certificate | Valid PEM but self-signed and expired |

## Access Detection

When an agent reads a canary file:

1. SIGIL serves a decoy value (realistic but fake)
2. The access is logged as a CRITICAL breach event
3. Behavioral tracking monitors what the agent does next

## Behavioral Intelligence

SIGIL tracks what happens after canary access:

| Behavior | Interpretation |
|----------|----------------|
| Agent tries to use the credential | Confirms unauthorized access intent |
| Agent attempts to exfiltrate it | Confirms adversarial behavior |
| Agent ignores it | May have been accidental access |
| Agent writes it to a file | Potential credential harvesting |

## Breach Severity

Canary access triggers different severity levels:

| Severity | Condition |
|----------|-----------|
| **INFO** | Single accidental access (e.g., `ls` of directory) |
| **WARNING** | Multiple reads without usage |
| **CRITICAL** | Usage or exfiltration attempt |

## Configuration

Canary files are configured in `config.toml`:

```toml
[canary]
# Enable canary monitoring
enabled = true

# Canary file locations
files = [
    "~/.aws/credentials",
    "~/.aws/config",
    "~/.ssh/id_rsa",
    "~/.docker/config.json",
]

# Auto-lockdown on canary access
auto_lockdown_threshold = 3  # 3 canary accesses → lockdown

# Generate format-specific decoys
decoy_types = ["aws", "ssh", "docker", "npm", "stripe", "jwt"]
```

## Audit Logging

All canary accesses are logged with full context:

```
[CRITICAL] Canary access detected
  File: ~/.aws/credentials
  PID: 12345 (agent subprocess)
  Command: cat ~/.aws/credentials
  Decoy served: AKIAIOSFODNN7EXAMPLE
  Timestamp: 2026-04-07T14:23:15Z
  Session: claude-ses-a7f3e2
```

## Integration with Lockdown

Canary monitoring integrates with auto-lockdown:

```toml
[lockdown.auto]
canary_triggers = 3  # 3 canary accesses → auto-lockdown
```

This provides automatic incident response when repeated canary access indicates malicious behavior.

## FUSE Integration

Canary values are also served via the FUSE filesystem at `/sigil/` paths:
- `/sigil/aws/credentials` → AWS canary credentials
- `/sigil/ssh/id_rsa` → SSH canary private key
- `/sigil/docker/config.json` → Docker canary config

This ensures canary detection works even when agents access secrets via FUSE.

## Security Considerations

- Canary values exist only in sandbox memory (tmpfs)
- Decoys are format-correct but functionally invalid
- No canary data is ever written to the host filesystem
- Canary access is always logged as a security event
- Auto-lockdown can trigger on repeated canary access
