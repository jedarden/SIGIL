# CI Policy

SIGIL provides policy-scoped secret access control for headless CI/CD workflows and autonomous agent fleets. When `SIGIL_CI` is set, the daemon evaluates secret access requests against explicit allow/deny rules instead of requiring interactive approval.

## Overview

In CI/CD environments and autonomous agent fleets, SIGIL cannot prompt for human approval via the TUI. Instead, SIGIL evaluates requested secret paths against a policy file (`.sigil/ci-policy.toml`) to determine access.

**Two modes of operation:**
1. **Policy mode** (`SIGIL_CI` + policy file): Evaluate requests against explicit rules (fail closed)
2. **Legacy CI mode** (`SIGIL_CI` without policy file): Blanket approve all requests (backward compatible)

## Policy File Schema

Create `.sigil/ci-policy.toml` in your project root or home directory:

```toml
version = 1

# Allow rules: secrets that can be accessed
[[policy.allow]]
pattern = "kalshi/*"
description = "Allow all Kalshi trading secrets"

[[policy.allow]]
pattern = "aws/access_key_id"
description = "Allow AWS access key ID (public)"

# Deny rules: secrets that cannot be accessed
[[policy.deny]]
pattern = "aws/*"
description = "Deny other AWS secrets"

[[policy.deny]]
pattern = "prod/*"
description = "Deny production secrets"

# Exception: allow specific production secret
[[policy.allow]]
pattern = "prod/deploy_key"
description = "Allow specific production deploy key"
```

**Schema fields:**
- `version`: Policy format version (must be `1`)
- `[[policy.allow]]`: Array of allow rules (each with `pattern` and optional `description`)
- `[[policy.deny]]`: Array of deny rules (each with `pattern` and optional `description`)

## Glob Pattern Syntax

Patterns use standard glob syntax for matching secret paths:

| Pattern | Matches | Does Not Match |
|---------|---------|----------------|
| `kalshi/*` | `kalshi/api_key`, `kalshi/secret` | `aws/api_key`, `kalshi/sub/path` |
| `**` | All paths | (none) |
| `**/*` | All paths | (none) |
| `*/api_key` | `kalshi/api_key`, `aws/api_key` | `kalshi/secret` |
| `prod/deploy_key` | Only that exact path | `prod/api_key` |
| `test/?` | `test/a`, `test/1` | `test/ab`, `test` |
| `[abc]/*` | `a/x`, `b/y`, `c/z` | `d/x`, `ab/x` |
| `[!abc]/*` | `d/x`, `e/y` | `a/x`, `b/y` |

**Pattern components:**
- `*`: Matches any sequence of characters except `/`
- `**`: Matches any sequence including `/` (wildcard for directory trees)
- `?`: Matches any single character except `/`
- `[abc]`: Matches any character in the set
- `[!abc]`: Matches any character not in the set

## Evaluation Logic

SIGIL evaluates secret access requests in a specific order:

1. **If SIGIL_CI is set and `.sigil/ci-policy.toml` exists:**
   - Check deny rules first (defense-in-depth)
   - If any deny rule matches → **ACCESS DENIED**
   - Check allow rules
   - If any allow rule matches → **ACCESS GRANTED** (session-scoped)
   - If no rule matches → **ACCESS DENIED** (fail closed)

2. **If SIGIL_CI is set but no policy file exists:**
   - **Blanket approve all requests** (backward compatible with existing CI pipelines)

3. **If SIGIL_CI is not set:**
   - Use interactive approval via TUI (default behavior)

**Precedence rules:**
- **Deny rules take precedence**: If a path matches both allow and deny rules, the deny wins
- **First match wins**: Evaluation stops at the first matching rule (deny first, then allow)
- **Fail closed**: No matching rule means access is denied

## Examples

### Least-Privilege CI Policy

```toml
version = 1

# Allow test environment secrets only
[[policy.allow]]
pattern = "test/*"
description = "Allow test environment secrets"

# Allow specific deployment key
[[policy.allow]]
pattern = "deploy/ssh_key"
description = "Allow deployment SSH key"

# Deny production secrets
[[policy.deny]]
pattern = "prod/*"
description = "Deny all production secrets"

# Deny database passwords (even in allowed environments)
[[policy.deny]]
pattern = "*/db_password"
description = "Deny database passwords"
```

### Autonomous Agent Fleet Policy

```toml
version = 1

# Allow agent-specific secrets
[[policy.allow]]
pattern = "agents/*"
description = "Allow agent fleet secrets"

# Allow specific operational secrets
[[policy.allow]]
pattern = "ops/monitoring_token"
description = "Allow monitoring endpoint access"

# Deny sensitive credentials
[[policy.deny]]
pattern = "*/root_*"
description = "Deny root-level credentials"

[[policy.deny]]
pattern = "*/admin_*"
description = "Deny admin-level credentials"
```

### Environment-Specific Policy

```toml
version = 1

# Development: full access to dev secrets
[[policy.allow]]
pattern = "dev/*"
description = "Allow development secrets"

# Staging: restricted access
[[policy.allow]]
pattern = "staging/api_key"
description = "Allow specific staging API key"

# Production: deny all except deployment key
[[policy.deny]]
pattern = "prod/*"
description = "Deny production secrets"

[[policy.allow]]
pattern = "prod/deploy_key"
description = "Allow production deployment key"
```

## Security Considerations

### Fail-Closed Default

When a policy file exists, SIGIL denies access by default. This is a security feature: if you're not explicitly allowing a secret, it's not accessible.

**Example:**
```toml
version = 1

[[policy.allow]]
pattern = "kalshi/api_key"
description = "Allow Kalshi API key"
```

In this policy, `kalshi/api_key` is allowed, but `kalshi/secret_key` (even though it's in the same namespace) is denied.

### Deny Rules Take Precedence

Deny rules are evaluated first and take precedence over allow rules. This ensures that sensitive secrets remain protected even if broad allow rules exist.

**Example:**
```toml
version = 1

[[policy.allow]]
pattern = "aws/*"
description = "Allow AWS secrets"

[[policy.deny]]
pattern = "aws/secret_access_key"
description = "Deny AWS secret access key (high sensitivity)"
```

In this policy, `aws/access_key_id` is allowed, but `aws/secret_access_key` is denied.

### Overly-Broad Patterns

Patterns that match everything (e.g., `*`, `**`, `**/*`) are detected by `sigil doctor` as overly broad. These patterns effectively disable the security benefit of policy-scoped access.

```toml
# ⚠️  AVOID: Overly-broad patterns
[[policy.allow]]
pattern = "**"
description = "Allow everything (defeats security purpose)"
```

**Better approach:** Start with an empty policy (allow nothing) and add specific allow rules.

## Audit Logging

All policy decisions are logged in the audit trail (`~/.sigil/audit.jsonl`):

```json
{
  "type": "secret_access_grant",
  "secret": "kalshi/api_key",
  "reason": "via CI policy: Matches allow rule: kalshi/*",
  "granted_at": "2026-08-16T12:34:56Z",
  "session_id": "ses_a7f3e2"
}
```

Denied requests are also logged:

```json
{
  "type": "secret_access_denied",
  "secret": "prod/db_password",
  "reason": "Matches deny rule: prod/*",
  "denied_at": "2026-08-16T12:35:01Z",
  "session_id": "ses_a7f3e2"
}
```

## Health Checks

### Doctor Check for Overly-Broad Rules

```bash
$ sigil doctor
...
  CI Policy    WARN   Overly-broad allow rules detected: **, **
                       Remove overly-broad patterns for better security
...
```

### Manual Policy Validation

```bash
# Test policy evaluation (dry run)
SIGIL_CI=1 sigil request kalshi/api_key --dry-run
```

## Usage

### Enable Policy Mode

```bash
# Set CI mode
export SIGIL_CI=1

# Create policy file
cat > .sigil/ci-policy.toml << 'EOF'
version = 1

[[policy.allow]]
pattern = "test/*"
description = "Allow test environment secrets"
EOF

# Run protected command
sigil exec 'cargo test'
```

### In Argo Workflows

```yaml
apiVersion: argoproj.io/v1alpha1
kind: Workflow
metadata:
  name: sigil-ci-test
spec:
  entrypoint: test
  templates:
    - name: test
      steps:
        - - name: install-sigil
            template: install-sigil
        - - name: run-tests
            template: run-tests
    
    - name: run-tests
      container:
        image: rust:1.75
        env:
          - name: SIGIL_CI
            value: "1"
        command: [sh, -c]
        args:
          - |
            cat > .sigil/ci-policy.toml << 'EOF'
            version = 1
            [[policy.allow]]
            pattern = "test/*"
            EOF
            sigil exec 'cargo test'
```

### In Autonomous Agent Fleets

```bash
# Dispatch agent with CI mode
SIGIL_CI=1 needle dispatch --workspace project-a

# Agent can only access secrets matching policy rules
# Other requests are denied (fail closed)
```

## Best Practices

1. **Start with deny-by-default**: Begin with an empty policy and add specific allow rules
2. **Use deny rules for sensitive paths**: Add deny rules for `prod/*`, `*/admin_*`, `*/root_*`, etc.
3. **Commit policy files to git**: Review policy changes via pull requests
4. **Test policies locally**: Use `sigil request --dry-run` before deploying
5. **Monitor audit logs**: Review denied requests to identify policy gaps
6. **Avoid overly-broad patterns**: Never use `*`, `**`, or `**/*` as allow patterns
7. **Document rule rationale**: Use `description` fields to explain why each rule exists
8. **Rotate secrets if needed**: If a policy was accidentally too permissive, rotate exposed secrets

## Troubleshooting

### Policy Not Found

```bash
# Verify policy file exists
ls -la .sigil/ci-policy.toml

# Check if SIGIL_CI is set
echo $SIGIL_CI
```

### Access Denied

```bash
# Check which rule matched
SIGIL_CI=1 sigil request kalshi/api_key --dry-run

# Review policy rules
cat .sigil/ci-policy.toml
```

### Doctor Warns About Overly-Broad Rules

```bash
# Fix overly-broad patterns
# Replace "**" with specific namespace patterns
# Example: "kalshi/*" instead of "**"
```

### Backward Compatibility

If existing CI pipelines break after adding a policy file:

```bash
# Temporary: remove policy file to restore blanket approval
rm .sigil/ci-policy.toml

# Permanent: fix policy to explicitly allow needed secrets
# Edit .sigil/ci-policy.toml and add allow rules
```

## Related Topics

- `sigil help ci` — CI/CD configuration and examples
- `sigil help request` — Secret request workflow and approval
- `sigil help doctor` — Health checks and policy validation
- `sigil help team` — Team vaults and multi-user access

---

For more information, see: https://docs.sigil.rs