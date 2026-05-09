# Phase 3.1 Verification: Command Parser with All Injection Modes

## Summary

Verified that `crates/sigil-core/src/parser.rs` (1042 lines) correctly implements all 5 injection modes and handles edge cases as specified in Phase 3.1.

## Injection Modes Verified

### 1. Inline Substitution (Default)
- Syntax: `{{secret:path}}`
- Behavior: Replaces placeholder with environment variable reference
- Test: `test_injection_mode_inline_default` ✅

### 2. Environment Variable Injection
- Syntax: `{{secret:path:env}}`
- Behavior: Injects as environment variable with sanitized name
- Test: `test_injection_mode_env` ✅

### 3. File Injection (Default Path)
- Syntax: `{{secret:path:file}}`
- Behavior: Writes to tmpfs at `/tmp/sigil_<sanitized_path>`
- Test: `test_injection_mode_file_default_path` ✅

### 4. File Injection (Custom Path)
- Syntax: `{{secret:path:file:/target/path}}`
- Behavior: Writes to tmpfs and bind-mounts at target path
- Test: `test_injection_mode_file_custom_path` ✅

### 5. Stdin Pipe
- Syntax: `{{secret:path:stdin}}`
- Behavior: Pipes secret to command's stdin, removes placeholder from command
- Test: `test_injection_mode_stdin` ✅

## Edge Cases Verified

### Nested Shell Quoting
- Single quotes: `bash -c 'curl {{secret:api/key}}'` ✅
- Double quotes: `bash -c "curl {{secret:api/key}}"` ✅
- Mixed: `bash -c "echo '{{secret:inner}}'"` ✅

### Piped Commands
- Inline mode rejected: `echo {{secret:x}} | sha256sum` → Error ✅
- Env mode allowed: `echo {{secret:x:env}} | sha256sum` → OK ✅

### Heredocs
- Placeholders detected: `cat <<EOF\n{{secret:my/secret}}\nEOF` ✅
- Env mode works in heredocs ✅

### Adversarial Inputs (Red Team Tests)
- Escape sequences handled ✅
- Null bytes handled gracefully ✅
- Special characters in paths ✅
- Unicode paths (emoji, Cyrillic, Arabic, Japanese) ✅
- Malformed braces ✅
- Very long paths (1000+ chars) ✅
- Adjacent placeholders ✅

## Regex Pattern

```regex
\{\{secret:([a-zA-Z0-9_/.-]+)(?::([a-z_]+)(?::([^\}]+))?)?\}\}
```

- Capture group 1: secret path (alphanumeric, `/`, `.`, `_`, `-`)
- Capture group 2: injection mode (optional)
- Capture group 3: file path argument (optional for `:file` mode)

## Test Results

All 48 parser tests pass:
- 48 passed; 0 failed; 0 ignored

## ResolvedCommand Structure

The parser produces a `ResolvedCommand` struct with:
- `original`: Original command string
- `placeholders`: All secret placeholders found
- `resolved`: Command with placeholders resolved
- `env_injections`: Vec<(env_name, secret_path)>
- `file_injections`: Vec<(secret_path, target_path)>
- `use_stdin`: Boolean flag
- `stdin_secret`: Option<secret_path>

## Security Properties

1. **Piped command protection**: Inline mode rejected in piped commands
2. **Single stdin injection**: Multiple stdin injections rejected
3. **Path sanitization**: Secret paths sanitized for env var and file names
4. **Position tracking**: All placeholder positions tracked for replacement
