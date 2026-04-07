# Secret Request

The secret request workflow allows agents to request access to secrets they don't currently have, with human approval via the TUI.

## Concept

When an agent needs access to a secret it doesn't have, it can request access:

```
sigil_request({
  secret: "db/production/password",
  reason: "Need to run database migration",
  duration: "5m"
})
```

This triggers an approval workflow in the TUI, allowing the human operator to grant time-bounded or session-scoped access.

## Approval Options

The TUI presents several approval options:

| Option | Effect |
|--------|--------|
| **Approve N minutes** | Access granted for specified time, then auto-revoked |
| **Approve session** | Access granted until agent session ends |
| **Always allow** | Adds to project's permanent allowlist |
| **Deny** | Returns "access denied" to agent |
| **Deny + flag** | Denies and logs as suspicious behavior |

## Duration Format

Duration is specified as a string:
- `5m` - 5 minutes
- `1h` - 1 hour
- `30m` - 30 minutes
- `session` - until session ends

## Always Allow Persistence

When you select "Always allow" for a secret, it's persisted to `~/.sigil/access-grants.toml`:

```toml
# ~/.sigil/access-grants.toml — per-user access grants (not committed to git)

[grants."my-project"]
"db/production/password" = {
    approved_by = "user",
    approved_at = "2026-04-07T12:00:00Z",
    reason = "Migration workflow"
}
```

This file is never committed to git—it's user-local configuration.

## Checking Access Status

Agents can check if they have access to a secret:

```
sigil_check_access("db/production/password")
```

Returns:
- `"granted (expires in 3m)"` - Access is granted with time remaining
- `"granted (session)"` - Access for duration of session
- `"not granted"` - No access

## Bulk Requests

Agents can request multiple secrets at once:

```
sigil_request({
  secrets: ["db/production/password", "db/production/user"],
  reason: "Need to run database migration",
  duration: "10m"
})
```

All secrets must be approved for the request to succeed.

## Audit Logging

All request and approval events are logged in the audit trail:
- Request timestamp
- Agent session ID
- Secret paths requested
- Reason provided
- Approval decision
- Granted duration (if approved)
- Approval timestamp

## Security Considerations

- Access grants are scoped to specific projects (not global)
- Time-bounded approvals auto-revoke—no manual cleanup needed
- "Always allow" is persisted per-user, not per-project
- Suspicious requests can be flagged for review
- All requests are logged for security auditing

## CLI Equivalent

If the TUI is unavailable, the CLI falls back to terminal prompts:

```
SIGIL: Secret access requested by agent
  Secret: db/production/password
  Reason: "Need to run database migration"
  Duration: 5 minutes
  Approve? [y/N/session/always]
```

This fallback only works with a TTY. Without a TTY (pure agent session), requests are denied with a message to run `sigil tui`.
