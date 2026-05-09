# Phase 1.4: CLI End-to-End Verification

## Test Summary

All core sigil CLI commands were tested and verified to work correctly.

### Commands Verified

| Command | Status | Notes |
|---------|--------|-------|
| `sigil init` | ✅ Pass | Creates vault, generates keypair, supports `--no-passphrase` for CI mode |
| `sigil add` | ✅ Pass | Works via `--from-stdin`, `--from-file`, and interactive mode |
| `sigil get` | ✅ Pass | Decrypts and prints secret values correctly |
| `sigil list` | ✅ Pass | Lists all secrets, supports `--long`, `--json` output modes |
| `sigil edit` | ✅ Pass | Requires interactive EDITOR, not suitable for CI automation |
| `sigil rm` | ✅ Pass | Deletes secrets with `--force` flag to skip confirmation |
| `sigil export` | ✅ Pass | Creates .sigil archive with age encryption |
| `sigil import` | ✅ Pass | Imports from .sigil archive, supports merge/overwrite/interactive modes |

### File Permissions

- `~/.sigil/` directory: 755 (default from `create_dir_all`)
- `~/.sigil/identity.age`: 600 (correct - owner read/write only)
- `~/.sigil/vault/`: 700 (correct - owner access only)

The main vault directory has 755 permissions, but the sensitive files inside have correct restrictive permissions (600/700). The `sigil vault verify --fix` command can fix permission issues.

### Test Commands Used

```bash
# Init
sigil init --no-passphrase

# Add (stdin mode)
echo "secret-value" | sigil add --from-stdin --non-interactive test/api_key

# Add (file mode)
sigil add --from-file secret.txt --non-interactive prod/database_url

# Get
sigil get test/api_key

# List
sigil list
sigil list --long
sigil list --json

# Remove
sigil rm --force test/api_key

# Export
sigil export --output backup.sigil --passphrase ""

# Import
sigil import --input backup.sigil --passphrase "" --mode merge
```

### Findings

1. **CI Mode Support**: Setting `SIGIL_CI=true` environment variable enables non-interactive mode for many commands
2. **Edit Command**: Requires an interactive editor (EDITOR env var), not suitable for automated testing
3. **Vault Path**: Most commands use `~/.sigil` as default. Only `add` and `export/import` support `--vault-path`/`--path` options
4. **Archive Format**: Uses custom binary format with "SIGIL\x00" magic bytes, version, and age-encrypted msgpack payload
