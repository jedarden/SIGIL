# Vault

SIGIL stores secrets in an age-encrypted vault at `~/.sigil/vault/`.

## Vault Structure

Each secret is stored as a separate encrypted file:

```
~/.sigil/vault/
├── api_key.age
├── aws/
│   ├── access_key_id.age
│   └── secret_access_key.age
└── prod/
    └── database_url.age
```

## Vault Modes

### Local Vault (Default)

Stored locally at `~/.sigil/vault/` with age encryption.

```bash
sigil init
```

### Sealed Vault

Portable encrypted file for backup and transfer.

```bash
sigil export backup.sigil
sigil import backup.sigil
```

### Team Vault (Coming Soon)

Remote vault with role-based access control.

## Vault Commands

```bash
# Initialize vault
sigil init

# Add secret
sigil add <path>

# Get secret (raw value, for scripts)
sigil get <path> --raw

# List secrets
sigil list [prefix]

# Delete secret
sigil rm <path>

# Export vault
sigil export <file>

# Import vault
sigil import <file>
```

## Encryption

- **Algorithm**: age (Rust implementation of file encryption)
- **Key file**: `~/.sigil/identity.age`
- **Passphrase**: Optional (recommended for production)

## Security

- All secrets encrypted at rest
- Identity key should be backed up securely
- Passphrase adds additional protection layer
- Consider hardware security keys for production

## Backup

Regular backups are recommended:

```bash
# Automated daily backup
0 2 * * * sigil export ~/backups/sigil-$(date +\%Y\%m\%d).sigil
```

Store backups in encrypted storage for defense-in-depth.
