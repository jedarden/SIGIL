# SIGIL Quickstart Command Implementation (bf-2hs)

## Summary

The `sigil quickstart` command was already implemented in the codebase. This task involved:

1. **Fixed missing import** - Added `use std::env;` to main.rs (line 26)
2. **Updated documentation** - Modified README.md, docs/quickstart.md, and docs/topics/sigil.md to prominently feature the `sigil quickstart` command

## Implementation Details

### Command Structure

The `CommandQuickstart` struct (line 585) supports:
- `--non-interactive` - Skip all prompts
- `--passphrase-file <file>` - Read passphrase from file
- `--passphrase` - Prompt for passphrase instead of generating
- `--skip-secret` - Skip adding first secret prompt
- `--agent <agent>` - Install hooks for specific agent only
- `--dry-run` - Show what would happen without making changes

### Quickstart Flow

1. **Platform detection** (Step 0)
   - Detects Linux/macOS/WSL2
   - Shows OS and architecture

2. **Prerequisite checks** (Step 1)
   - Checks for bubblewrap on Linux
   - Checks for Rust (if running from source)
   - Provides remediation instructions for missing prerequisites

3. **Initialize vault** (Step 2)
   - Creates `~/.sigil` directory with secure permissions
   - Generates age keypair
   - Either generates a 6-word passphrase or accepts one via prompt/file

4. **Add first secret** (Step 3)
   - Interactive prompt for secret path and value
   - Validates path and adds to vault

5. **Install agent hooks** (Step 4)
   - Detects available agents (claude-code, cursor, aider, cline, codex)
   - Installs hooks for detected agents or specific agent via --agent flag

6. **Verify setup** (Step 5)
   - Runs `sigil doctor` to verify setup

7. **Print summary**
   - Shows next steps with helpful commands

### Documentation Updates

- **README.md**: Added `sigil quickstart` as the primary setup method
- **docs/quickstart.md**: Added "One-Command Setup" section at the top
- **docs/topics/sigil.md**: Added `sigil quickstart` to quickstart section

## Files Modified

1. `crates/sigil-cli/src/main.rs` - Added missing `use std::env;` import
2. `README.md` - Updated quickstart section to mention `sigil quickstart`
3. `docs/quickstart.md` - Added "One-Command Setup" section
4. `docs/topics/sigil.md` - Updated quickstart section

## Verification

The quickstart command was already implemented with all required features:
- ✅ Platform detection (Linux/macOS/WSL2)
- ✅ Prerequisites checking
- ✅ Vault initialization
- ✅ First secret prompt (interactive)
- ✅ Agent hook installation
- ✅ Health check via sigil doctor
- ✅ Summary with next steps
- ✅ Non-interactive mode
- ✅ --agent flag
- ✅ --passphrase-file flag
- ✅ Colored output
- ✅ Progress indicators
- ✅ Error handling with remediation

## Notes

- The demo.sh script in docs/ serves a different purpose (demonstration) and does not need to match quickstart exactly
- All hook setup functions exist in hooks.rs
- The doctor module provides run_doctor() and format_report() functions used by quickstart
