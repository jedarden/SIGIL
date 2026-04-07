# Lockdown

Lockdown is SIGIL's emergency incident response mechanism—one command to instantly revoke all access and lock the vault.

## Triggering Lockdown

### Via CLI

```bash
sigil lockdown
```

For scripted incident response:

```bash
sigil lockdown --confirm
```

### Via TUI

Press `Ctrl+L` in the TUI to trigger lockdown immediately.

### Via API

Programmatic lockdown for automated incident response systems.

## What Lockdown Does

Lockdown executes the following sequence in under 2 seconds:

1. **Kill all active sandbox processes** (SIGTERM → 500ms → SIGKILL)
2. **Revoke all session tokens** (daemon rejects all requests)
3. **Revoke all dynamic leases** (Vault/OpenBao API calls invalidated)
4. **Lock the vault** (requires full re-authentication to unseal)
5. **Generate breach report** (`~/.sigil/breach-report-<timestamp>.md`)
6. **Send alerts** (Slack webhook, email if configured)

## Lockdown State

After lockdown, the daemon enters read-only mode:
- All secret access is blocked
- All session tokens are revoked
- All sandbox processes are terminated
- Vault is locked (requires passphrase to unseal)

The lockdown state persists across daemon restarts.

## Unlocking

To lift lockdown and restore normal operation:

```bash
sigil unlock
```

This requires:
- Full re-authentication (passphrase + device key)
- Explicit confirmation of the unlock action

`sigil unlock` is distinct from `sigil unseal`:
- `unlock` lifts lockdown on a running daemon
- `unseal` decrypts a cold vault at daemon startup

## Auto-Lockdown Triggers

Configure automatic lockdown based on security events:

```toml
[lockdown.auto]
canary_triggers = 3          # 3 canary accesses → auto-lockdown
unauthorized_attempts = 5    # 5 failed auth attempts → auto-lockdown
exfiltration_detected = true # any network exfiltration → auto-lockdown
```

## Breach Report

Lockdown automatically generates a breach report:

```markdown
# SIGIL Breach Report

**Generated:** 2026-04-07T14:23:15Z
**Trigger:** Manual lockdown via CLI

## Events Leading to Lockdown

1. 14:20:15 - Canary access: ~/.aws/credentials (PID 12345)
2. 14:21:30 - Canary access: ~/.aws/credentials (PID 12345)
3. 14:22:45 - Canary access: ~/.aws/credentials (PID 12345)

## Actions Taken

- Killed 3 sandbox processes
- Revoked 1 session token
- Revoked 2 dynamic leases
- Locked vault
- Generated this report

## Recommendations

1. Rotate all secrets that may have been exposed
2. Review audit logs for additional suspicious activity
3. Investigate the agent behavior that triggered canary access
```

## Alert Channels

Configure alert channels in `config.toml`:

```toml
[lockdown.alerts]
slack_webhook = "https://hooks.slack.com/services/..."
email_to = "security@example.com"
email_from = "sigil@example.com"
smtp_server = "smtp.example.com:587"
```

## Use Cases

**Confirmed breach:**
```bash
# Agent observed exfiltrating secrets
sigil lockdown
# Investigate breach report
# Rotate compromised secrets
sigil unlock
```

**Suspicious activity:**
```bash
# Multiple canary accesses detected
# Auto-lockdown triggers if configured
# Or manually trigger:
sigil lockdown --reason "Multiple canary accesses"
```

**Emergency response:**
```bash
# Part of automated incident response script
if detect_exfiltration; then
    sigil lockdown --confirm
    notify_security_team
fi
```

## Security Considerations

- Lockdown is immediate and irreversible—use with caution
- All in-progress operations are terminated
- Session tokens must be re-issued after unlock
- Vault passphrase is required to unlock
- Lockdown state survives daemon restart

## Distinction from Other Features

| Feature | Purpose |
|---------|---------|
| **Lockdown** | Emergency incident response, revokes all access |
| **Unseal** | Decrypt vault at daemon startup |
| **Revoke** | Revoke specific session tokens or leases |
| **Logout** | End a specific agent session |
