# Sealed Operations

Sealed operations are pre-defined command templates that allow agents to execute sensitive commands without ever seeing the secrets, command templates, or unfiltered output.

## Concept

A sealed operation is a named command template stored in `.sigil/operations.toml`:

```toml
[operations.deploy]
description = "Deploy manifests to production cluster"
command = "kubectl --kubeconfig={{secret:prod/kubeconfig:file}} apply -f manifests/"
secrets = ["prod/kubeconfig"]
output_filter = "summary"
require_approval = true
```

When an agent invokes a sealed operation, SIGIL:
1. Resolves the secrets internally
2. Executes the command in a sandbox
3. Filters the output according to the specified mode
4. Returns only the filtered result to the agent

## Output Filter Modes

| Mode | Agent Sees |
|------|------------|
| `exit_code` | Only exit code and "succeeded"/"failed" |
| `summary` | One-line summary extracted by regex |
| `full_scrubbed` | Complete output with secrets scrubbed |
| `none` | Nothing (fire-and-forget) |

## Agent Usage

Agents invoke sealed operations via the MCP server:

```
sigil_exec({operation: "deploy"})
```

The agent receives:
- Operation description (not the command)
- Filtered output (according to output_filter)
- Exit status

The agent never sees:
- The command template
- Secret paths
- Unfiltered output
- Secret values

## Approval Workflow

Operations with `require_approval = true` trigger a TUI prompt:

```
┌─────────────────────────────────────────────┐
│  Operation Approval Request                 │
│                                             │
│  Operation: deploy                          │
│  Description: Deploy manifests to prod      │
│  Secrets: prod/kubeconfig                   │
│                                             │
│  [a] Approve  [d] Deny                      │
└─────────────────────────────────────────────┘
```

## Security Benefits

1. **No secret exposure**: Agent never sees secret values
2. **No command visibility**: Agent cannot extract the command template
3. **Controlled output**: Only filtered results are returned
4. **Audit trail**: All operations logged with context
5. **Human approval**: High-risk operations require explicit approval

## Creating Operations

Create `.sigil/operations.toml` in your project:

```toml
[operations.deploy]
description = "Deploy to production"
command = "kubectl apply -f manifests/"
secrets = ["prod/kubeconfig"]
output_filter = "summary"
require_approval = true

[operations.db-migrate]
description = "Run database migrations"
command = "DATABASE_URL={{secret:prod/db_url}} cargo run --bin migrate"
secrets = ["prod/db_url"]
output_filter = "exit_code"
require_approval = true
```

## Listing Operations

List available operations via the CLI:

```
sigil operations list
```

Or via MCP:

```
sigil_list_operations()
```

This returns operation names and descriptions only—not commands or secret paths.
