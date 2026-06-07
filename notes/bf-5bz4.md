# Bead bf-5bz4: macOS PTY Isolation Already Implemented

## Finding

The macOS PTY isolation described in this bead was **already implemented** in commit `00c336a4` (fix(tui): implement PTY isolation on macOS via nix crate).

## Implementation Details

The PTY allocation for macOS is fully functional in `crates/sigil-tui/src/pty.rs`:

- **Lines 54-82**: `allocate()` method is implemented for both `target_os = "linux"` AND `target_os = "macos"`
- **Uses `nix::pty::openpty`**: This crate correctly calls the POSIX `openpty()` function on macOS
- **Line 84 stub**: Is actually for unsupported platforms (Windows), NOT macOS

## Verification

```bash
# Tests pass
cargo test -p sigil-tui
# test result: ok. 8 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out
```

The test `test_pty_allocation` (lines 204-218) verifies:
- On Linux: slave path starts with `/dev/pts/`
- On macOS: slave path starts with `/dev/ttys` (BSD-style PTY naming)

## Conclusion

No additional work required. The bead description was based on an outdated version of the code prior to commit `00c336a4`.

## Git Push Status

Commit `8d7c5a86` created locally, but push blocked by GitHub secret scanning due to pre-existing secrets in unrelated commits (7fdeb130, 415ac92e). This is a repository-level issue, not related to this bead's work.
