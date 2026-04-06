# Team Vault

Team vaults enable shared secrets with role-based access control.

## Overview

Team vaults support:
- Multiple users with different access levels
- Centralized secret storage (OpenBao, Vault)
- Role-based access control
- Audit trails across team members

## Setup (Coming Soon)

```bash
# Initialize team vault
sigil team init --backend openbao

# Enroll a device
sigil team enroll

# Invite team members
sigil team invite user@example.com
```

## Access Control

### Grant Access

```bash
# Grant read access
sigil team grant alice --secret prod/api_key --access read

# Grant write access
sigil team grant bob --secret prod/api_key --access write

# Grant admin access
sigil team grant charlie --secret prod/api_key --access admin
```

### Revoke Access

```bash
# Revoke access
sigil team revoke dave --secret prod/api_key
```

## Roles

| Role | Permissions |
|------|-------------|
| **read** | Can read secret value |
| **write** | Can read and modify secret |
| **admin** | Can manage access control |

## Backends

### OpenBao

```bash
sigil team init --backend openbao --endpoint https://openbao.example.com
```

### HashiCorp Vault

```bash
sigil team init --backend vault --endpoint https://vault.example.com
```

## Usage

```bash
# Use team vault secrets
sigil exec 'curl -H "Authorization: Bearer {{secret:team/api_key}}" https://api.example.com'

# List team secrets
sigil list --team

# Add team secret
sigil add team/prod/api_key --shared
```

## Auditing

Team vault audit logs include:
- Who accessed which secrets
- When access occurred
- From which device
- Operation performed (read, write, delete)

## Best Practices

- Use principle of least privilege
- Regular access reviews
- Separate environments (dev, prod)
- Require approval for sensitive secrets
- Monitor audit logs for anomalies

## Limitations

- Requires backend service (OpenBao, Vault)
- Network dependency
- Additional infrastructure complexity
- May not be suitable for small teams

## Migration from Local Vault

```bash
# Migrate local secrets to team vault
sigil team migrate --source ~/.sigil/vault --backend openbao
```

---

For more information, see: https://docs.sigil.rs
