# Hooks

SIGIL uses agent hooks to intercept tool calls before and after execution.

## Hook Types

### PreToolUse

Runs before a tool call:

- Scrubs tool inputs for secret values
- Replaces real values with placeholders
- Logs access attempts
- Returns modified input to agent

### PostToolUse

Runs after a tool call:

- Scrubs tool outputs for secret values
- Removes exact matches across 7 encodings
- Logs results (success/failure)
- Returns scrubbed output to agent

### UserPromptSubmit

Runs before user message submission:

- Scrubs user input for accidental secret pastes
- Detects canary triggers
- Alerts on suspicious patterns

## Hook Configuration

Hooks are configured in the agent's settings file.

### Claude Code Example

```json
{
  "hooks": {
    "PreToolUse": [
      {
        "type": "command",
        "command": "sigil-hook",
        "args": ["pre-tool-use"]
      }
    ],
    "PostToolUse": [
      {
        "type": "command",
        "command": "sigil-hook",
        "args": ["post-tool-use"]
      }
    ],
    "UserPromptSubmit": [
      {
        "type": "command",
        "command": "sigil-hook",
        "args": ["user-prompt-submit"]
      }
    ]
  }
}
```

## Installing Hooks

```bash
sigil setup <agent>
```

Available agents:
- `claude-code` - Comprehensive coverage
- `generic` - Basic coverage (any agent)

## Hook Behavior

### Input Scrubbing

Before tool execution:

1. Hook receives tool input
2. Scans for secret values (plain text, base64, etc.)
3. Replaces with `{{secret:path}}` placeholders
4. Returns modified input to agent

### Output Scrubbing

After tool execution:

1. Hook receives tool output
2. Scans for secret values (7 encodings)
3. Removes exact matches
4. Returns scrubbed output to agent

## Supported Agents

| Agent | PreToolUse | PostToolUse | UserPromptSubmit |
|-------|------------|-------------|------------------|
| Claude Code | Yes | Yes | Yes |
| Codex CLI | Yes | Yes | No |
| Cursor | No | No | No |
| Aider | No | No | No |
| Cline | Partial | Partial | No |

## Limitations

- Hooks depend on agent support
- Some agents don't support hooks at all
- Hook bypass is possible with compromised agents
- Use filesystem monitoring for fallback protection
