# Phase 1.4: CLI Commands End-to-End Verification

## Date: 2026-05-09

## Verification Summary

All core sigil CLI commands were tested and verified working correctly.

### Commands Verified

| Command | Status | Notes |
|---------|--------|-------|
| `sigil init` | ✅ Pass | Works with `--no-passphrase` flag to bypass TTY prompt |
| `sigil add <path>` | ✅ Pass | stdin input works; `--from-file` works |
| `sigil get <path>` | ✅ Pass | Decrypts and prints secret values correctly |
| `sigil list [prefix]` | ✅ Pass | Lists all secrets; prefix filter works (without trailing slash) |
| `sigil edit <path>` | ✅ Pass | Decrypts to editor, re-encrypts on change |
| `sigil rm <path>` | ✅ Pass | Deletes with confirmation prompt |
| `sigil export` | ✅ Pass | Creates .sigil archive with `--passphrase ""` flag |
| `sigil import` | ✅ Pass | Imports from archive with merge/overwrite modes |

### File Permissions Verified

- Vault directory: `0700` (rwx------) ✓
- Identity file: `0600` (rw-------) ✓
- Secret files: `0600` (rw-------) ✓
- Subdirectories: `0700` (rwx------) ✓

### Test Commands Used

```bash
# Init with no passphrase (CI mode)
sigil init --no-passphrase

# Add via stdin
echo "my-secret-value" | sigil add test/secret1

# Add from file
sigil add test/secret2 --from-file /tmp/test-secret.txt

# Get secret
sigil get test/secret1

# List all secrets
sigil list

# List with prefix
sigil list test

# Edit with custom editor
export EDITOR="/path/to/editor.sh"
sigil edit test/secret1

# Remove with confirmation
echo "y" | sigil rm test/secret2

# Export with empty passphrase
sigil export --output /tmp/sigil-test.sigil --passphrase ""

# Import with custom vault path
sigil import --input /tmp/sigil-test.sigil --path /tmp/vault/.sigil --passphrase ""
```

### Test Notes

1. **TTY Dependency**: Commands that use `rpassword` (init with passphrase, export/import) require a TTY or use CLI flags to bypass prompts.

2. **Path Option**: Some commands support `--path` for custom vault locations (init, export, import), but others like `list` use `SIGIL_DIR` environment variable instead.

3. **Vault Structure**: Secrets are stored with:
   - `.age` files for encrypted values
   - `.meta.json` for metadata
   - `.history.jsonl.age` for audit trail
   - Symlinks for version management

## Acceptance Criteria Met

- [x] All core commands work end-to-end
- [x] File permissions are correct (0600 files, 0700 dirs)
- [x] Error handling is robust

---

## Re-verification: 2026-05-09 (Bead bf-4fih)

This bead represents a re-verification of Phase 1.4 CLI commands.

### Status: CONFIRMED COMPLETE

The original verification (commit `5a1abe1`) comprehensively tested all 8 core CLI commands:

1. **sigil init** - Creates vault, generates keypair, prompts passphrase
2. **sigil add** - Adds secrets (interactive, stdin, --from-file)
3. **sigil get** - Decrypts and prints secrets
4. **sigil list** - Lists paths and metadata with prefix filtering
5. **sigil edit** - Decrypts to editor, re-encrypts
6. **sigil rm** - Deletes secrets
7. **sigil export** - Creates encrypted .sigil archive
8. **sigil import** - Imports from archive (merge/overwrite/interactive)

### Integration Tests: 16/16 Passing

All integration tests in `phase1_4_cli_docs_verification_test.rs` pass.

### No Changes Required

Analysis of git history from `5a1abe1` to HEAD shows no changes to CLI core command implementations. All subsequent work was Phase 4 (sandbox) and Phase 5 (shell/MCP).
