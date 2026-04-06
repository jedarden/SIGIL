# 🔐 Sealed Operations Guide

> Pre-defined command templates that agents can trigger without seeing secrets, commands, or unfiltered output.

---

## 📋 What Are Sealed Operations?

Sealed operations are a security feature that allows AI agents to execute sensitive commands with your secrets **without ever seeing**:
- The actual command being run
- The secret values being used
- The raw command output (only filtered/scrubbed output is shown)

This is ideal for:
- Production deployments
- Database migrations
- Infrastructure changes
- Any operation where you want human oversight

---

## 🚀 Quick Start

### 1. Create an Operations File

Create `.sigil/operations.toml` in your project:

```toml
[operations.deploy]
description = "Deploy manifests to production cluster"
command = "kubectl --kubeconfig={{secret:prod/kubeconfig:file}} apply -f manifests/"
secrets = ["prod/kubeconfig"]
output_filter = "summary"
summary_regex = "(\\d+) resources deployed"
require_approval = true

[operations.db-migrate]
description = "Run database migrations"
command = "DATABASE_URL={{secret:prod/db_url}} cargo run --bin migrate"
secrets = ["prod/db_url"]
output_filter = "exit_code"
require_approval = true

[operations.integration-test]
description = "Run API integration tests"
command = "API_KEY={{secret:test/api_key}} cargo test --features integration"
secrets = ["test/api_key"]
output_filter = "full_scrubbed"
require_approval = false
```

### 2. Agent Invokes the Operation

The agent requests an operation by name:

```javascript
// Via MCP (Claude Code, etc.)
await sigil_exec({ operation: "deploy" });

// Or via CLI
sigil exec --operation deploy
```

### 3. You Approve (If Required)

SIGIL's TUI shows you exactly what will happen:

```
┌───────────────────────────────────────────────────────────┐
│  🔐 Sealed Operation: deploy                              │
│                                                            │
│  Description: Deploy manifests to production cluster      │
│                                                            │
│  Command: kubectl --kubeconfig=<redacted> apply -f ...   │
│  Secrets: prod/kubeconfig                                │
│                                                            │
│  [a] Approve    [d] Deny                                   │
└───────────────────────────────────────────────────────────┘
```

### 4. Agent Receives Filtered Output

```json
{
  "operation_id": "deploy",
  "exit_code": 0,
  "output": "15 resources deployed",
  "timed_out": false,
  "duration_ms": 3420
}
```

The agent **never saw**:
- The actual kubectl command
- The kubeconfig file contents
- Any secrets that might have been in the output

---

## 🎯 Output Filter Modes

### Exit Code (Default)

Agent sees only success/failure:

```toml
[operations.restart]
description = "Restart production service"
command = "ssh {{secret:prod/ssh_key:user@host}} systemctl restart myapp"
secrets = ["prod/ssh_key"]
output_filter = "exit_code"  # or omit (default)
```

**Agent receives:**
```json
{ "exit_code": 0, "succeeded": true }
```

### Summary

Agent sees a one-line summary extracted by regex:

```toml
[operations.deploy]
description = "Deploy to production"
command = "kubectl apply -f k8s/"
output_filter = "summary"
summary_regex = "(\\d+) resources? deployed"
```

**Agent receives:**
```json
{ "output": "15 resources deployed" }
```

### Full Scrubbed

Agent sees complete output with secrets redacted:

```toml
[operations.logs]
description = "Fetch application logs"
command = "kubectl logs --tail=100 deployment/myapp"
output_filter = "full_scrubbed"
```

**Agent receives:**
```
2024-01-15 10:23:45 INFO Starting service...
2024-01-15 10:23:46 ERROR Auth failed: token=*** (redacted)
2024-01-15 10:23:47 INFO Connected to database=*** (redacted)
```

### None

Agent sees nothing (fire-and-forget):

```toml
[operations.cleanup]
description = "Clean up temporary files"
command = "rm -rf /tmp/myapp-cache"
output_filter = "none"
```

**Agent receives:**
```json
{ "output": "" }
```

---

## 🔒 Security Features

### 1. Command Hiding

The agent **never sees** the command template. It only knows:
- The operation ID (e.g., "deploy")
- The description (e.g., "Deploy manifests to production cluster")

The actual command with secret placeholders is **never** exposed to the agent.

### 2. Secret Isolation

Secrets are injected **at execution time** by the SIGIL daemon. The agent:
- Cannot access secret values
- Cannot read secret files
- Cannot extract secrets from environment variables

### 3. TUI Approval Gate

For operations marked `require_approval = true`:
- The TUI displays the full command (you see everything)
- You must explicitly approve before execution
- The approval decision is logged in the audit trail

### 4. Timeout Protection

Prevent runaway operations:

```toml
[operations.long-running]
description = "Long-running data import"
command = "./import-data.sh"
timeout_seconds = 3600  # 1 hour max
```

---

## 📝 Configuration Reference

### Operation Fields

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `description` | string | ✅ Yes | Human-readable description shown to agent |
| `command` | string | ✅ Yes | Command template with `{{secret:path}}` placeholders |
| `secrets` | array | ❌ No | List of secret paths (auto-detected if omitted) |
| `output_filter` | string | ❌ No | One of: `exit_code`, `summary`, `full_scrubbed`, `none` |
| `summary_regex` | string | ❌ No | Regex for extracting summary (required if `output_filter = "summary"`) |
| `require_approval` | boolean | ❌ No | Default: `true` |
| `timeout_seconds` | integer | ❌ No | Maximum execution time (default: 300) |

### Secret Placeholders

| Syntax | Description |
|--------|-------------|
| `{{secret:path}}` | Inject secret value as string |
| `{{secret:path:file}}` | Inject secret as file path (for certs, keys) |
| `{{secret:path:base64}}` | Inject base64-encoded secret |

---

## 🎯 Real-World Examples

### Database Migration

```toml
[operations.migrate-prod]
description = "Run production database migrations"
command = "DB_PASSWORD={{secret:prod/db_password}} ./scripts/migrate.sh prod"
secrets = ["prod/db_password"]
output_filter = "summary"
summary_regex = "Migrated (\\d+) schema versions"
require_approval = true
timeout_seconds = 600
```

### Kubernetes Deployment

```toml
[operations.deploy-staging]
description = "Deploy to staging cluster"
command = "kubectl --kubeconfig={{secret:staging/kubeconfig:file}} apply -f k8s/staging/"
secrets = ["staging/kubeconfig"]
output_filter = "summary"
summary_regex = "(\\d+) resources? created"
require_approval = false
```

### Terraform Apply

```toml
[operations.tf-apply-prod]
description = "Apply Terraform changes to production"
command = "cd infra && AWS_SECRET_ACCESS_KEY={{secret:aws/secret_key}} AWS_ACCESS_KEY_ID={{secret:aws/access_key}} terraform apply -auto-approve"
secrets = ["aws/access_key", "aws/secret_key"]
output_filter = "summary"
summary_regex = "(\\d+) added?, (\\d+) changed?"
require_approval = true
timeout_seconds = 1800
```

### Restart Service

```toml
[operations.restart-api]
description = "Restart the API service"
command = "ssh -i {{secret:prod/ssh_key:file}} {{secret:prod/ssh_user}}@{{secret:prod/ssh_host}} 'systemctl restart api'"
secrets = ["prod/ssh_key", "prod/ssh_user", "prod/ssh_host"]
output_filter = "exit_code"
require_approval = false
```

### Backup Database

```toml
[operations.backup-db]
description = "Create database backup"
command = "PGPASSWORD={{secret:prod/db_password}} pg_dump -h {{secret:prod/db_host}} -U {{secret:prod/db_user}} dbname > /backups/db-$(date +%Y%m%d).sql"
secrets = ["prod/db_password", "prod/db_host", "prod/db_user"]
output_filter = "exit_code"
require_approval = true
```

---

## 🤖 Agent Usage

### Via MCP (Recommended)

For agents that support MCP (Claude Code, etc.):

```javascript
// Execute a sealed operation
const result = await sigil_exec({
  operation: "deploy"
});

// Result includes filtered output
console.log(result.output);
```

### Via CLI

```bash
# Execute a specific operation
sigil exec --operation deploy

# Execute with additional environment variables
sigil exec --operation migrate --env=DRY_RUN=true
```

### Via SDK

```javascript
import { SigilClient } from '@sigil/sdk';

const client = await SigilClient.connect();
const result = await client.executeOperation('deploy');
console.log(`Deploy result: ${result.output}`);
```

---

## 🧪 Testing Operations

### Test Mode

Create a test operations file:

```toml
# .sigil/operations.test.toml
[operations.deploy-staging]
description = "Deploy to staging (test mode)"
command = "echo 'Would deploy: kubectl apply -f k8s/staging/'"
output_filter = "summary"
require_approval = false
```

Test without approval:

```bash
SIGIL_OPERATIONS_FILE=.sigil/operations.test.toml sigil exec --operation deploy-staging
```

### Dry Run

See what would happen without executing:

```bash
sigil operations show deploy
```

Output:
```
Operation: deploy
Description: Deploy manifests to production cluster
Command: kubectl --kubeconfig=<redacted> apply -f manifests/
Secrets: prod/kubeconfig
Output Filter: summary
Require Approval: true
Timeout: 300s
```

---

## 📋 Managing Operations

### List Operations

```bash
sigil operations list
```

```
Available Operations:
  deploy              Deploy manifests to production cluster
  db-migrate          Run database migrations
  integration-test    Run API integration tests
```

### Show Operation Details

```bash
sigil operations show deploy
```

### Validate Operations File

```bash
sigil operations validate
```

Checks for:
- Valid TOML syntax
- Required fields present
- Valid regex patterns
- Non-empty descriptions and commands
- Proper secret placeholder syntax

---

## 🚧 Known Limitations

- **Interactive commands**: Operations that require user input (prompts, passwords) will fail. Use non-interactive flags.
- **TTY-dependent tools**: Tools that require a TTY (like `top`, `vim`) won't work in sealed operations.
- **Long-running operations**: Consider increasing `timeout_seconds` for operations that take more than 5 minutes.
- **Complex output parsing**: Summary regex must extract a single line. Multi-line summaries use `full_scrubbed` instead.

---

## 👉 Next Steps

- Return to [Examples Index](README.md)
- Read [Security Best Practices](security-best-practices.md)
- Read [Team Collaboration](team-collaboration.md) for production workflows
- Read [CI/CD Integration](ci-cd-integration.md) for pipeline usage
