# Migration

SIGIL supports vault migration between versions and formats.

## Version Migration

Vault format includes a version number for compatibility:

```bash
# Check vault version
sigil doctor

# Migrate to latest format
sigil migrate
```

## Export and Import

### Export Vault

```bash
# Export entire vault
sigil export backup.sigil

# Export with passphrase
sigil export backup.sigil --passphrase

# Export specific secrets
sigil export backup.sigil --prefix prod/
```

### Import Vault

```bash
# Import vault (merges)
sigil import backup.sigil

# Import with passphrase
sigil import backup.sigil --passphrase

# Replace existing vault
sigil import backup.sigil --replace
```

## Format Changes

### Version 1 to Version 2 (Example)

If breaking changes are introduced:

```bash
# Backup old vault
sigil export backup-v1.sigil

# Migrate to new format
sigil migrate --from-version 1 --to-version 2

# Verify migration
sigil list
```

## Migration Checklist

Before migrating:

- [ ] Backup current vault
- [ ] Read migration notes in CHANGELOG.md
- [ ] Test migration in development
- [ ] Verify all secrets are accessible
- [ ] Update any dependent tooling

After migrating:

- [ ] Verify all secrets work
- [ ] Check audit log for errors
- [ ] Test with agent workflows
- [ ] Remove old backup after grace period

## Rollback

If migration fails:

```bash
# Import old backup
sigil import backup-v1.sigil --replace

# Report issue to GitHub
```

## CI/CD Migration

For CI/CD environments:

```bash
# Use sealed vault for CI
sigil export ci-vault.sigil
# Transfer to CI
sigil import ci-vault.sigil
```

## Team Vault Migration

For team vaults (coming soon):

```bash
# Migrate local vault to team vault
sigil team migrate --backend openbao
```

---

For more information, see: https://docs.sigil.rs
