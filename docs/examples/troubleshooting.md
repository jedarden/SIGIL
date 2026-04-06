# 🔧 Troubleshooting Guide

> Step-by-step diagnostic workflows for resolving common SIGIL issues.

---

## 📋 Prerequisites

Before troubleshooting, ensure you have:
- SIGIL installed (`sigil --version`)
- Daemon running (`sigil status`)
- Basic terminal knowledge

---

## 🚨 Quick Diagnostics

### Run Health Check

```bash
sigil doctor
```

This checks all components and provides a health score. Fix any critical issues before continuing.

### Run with Debug Logging

```bash
SIGIL_LOG=debug sigil exec 'echo test'
```

Enable verbose output to see what's happening internally.

---

## 🔍 Problem Categories

### 1. Daemon Issues

#### Problem: Daemon won't start

**Symptoms:**
- `sigil status` shows "daemon not running"
- Commands hang or timeout
- Error: "Failed to connect to daemon"

**Diagnostic Steps:**

1. **Check if daemon process exists:**
   ```bash
   ps aux | grep sigild
   ```

2. **Check socket file:**
   ```bash
   ls -la $XDG_RUNTIME_DIR/sigil.sock
   # Or if XDG_RUNTIME_DIR is not set:
   ls -la /tmp/sigil-$UID.sock
   ```

3. **Check daemon logs:**
   ```bash
   tail -f ~/.sigil/sigild.log
   ```

**Solutions:**

- **If daemon crashed**: Restart with `sigild`
- **If socket exists but daemon doesn't**: Remove socket and restart:
  ```bash
  rm $XDG_RUNTIME_DIR/sigil.sock
  sigild
  ```
- **If port conflict**: Check if another process is using the socket

#### Problem: Daemon keeps crashing

**Symptoms:**
- Daemon starts but exits immediately
- Commands work intermittently

**Diagnostic Steps:**

1. **Run daemon in foreground:**
   ```bash
   sigild --foreground
   ```

2. **Check for configuration errors:**
   ```bash
   sigil config list
   ```

3. **Check vault integrity:**
   ```bash
   sigil doctor --check-vault
   ```

**Solutions:**

- **Fix config errors**: Edit `~/.sigil/config.toml`
- **Restore vault**: Import from backup if corrupted
- **Check dependencies**: Ensure age, bubblewrap are installed

---

### 2. Vault Issues

#### Problem: Can't unlock vault

**Symptoms:**
- Prompted for passphrase repeatedly
- Error: "Failed to decrypt vault"
- Error: "Invalid passphrase"

**Diagnostic Steps:**

1. **Verify vault file exists:**
   ```bash
   ls -la ~/.sigil/vault/
   ls -la ~/.sigil/identity.age
   ```

2. **Test passphrase:**
   ```bash
   echo "test" | sigil add test/temp
   ```

**Solutions:**

- **Forgot passphrase**: Restore from backup with `sigil import backup.sigil`
- **Corrupted identity**: Re-initialize with `sigil init` (requires re-adding secrets)
- **Wrong vault**: Check `SIGIL_VAULT_PATH` environment variable

#### Problem: Secrets not found

**Symptoms:**
- `sigil get path` returns "secret not found"
- `sigil list` shows fewer secrets than expected

**Diagnostic Steps:**

1. **List all secrets:**
   ```bash
   sigil list
   ```

2. **Check for typos:**
   ```bash
   sigil list | grep -i expected_name
   ```

3. **Check vault switch:**
   ```bash
   sigil vault list
   sigil vault use default
   ```

**Solutions:**

- **Wrong vault**: Switch to correct vault with `sigil vault use <name>`
- **Wrong path**: Use correct path (case-sensitive)
- **Not added**: Add secret with `sigil add <path>`

---

### 3. Hook Issues

#### Problem: Agent hooks not working

**Symptoms:**
- Secrets appear in agent output
- Placeholders not resolved
- No scrubbing happens

**Diagnostic Steps:**

1. **Verify hooks installed:**
   ```bash
   # For Claude Code
   cat ~/.config/claude/settings.json | grep sigil
   ```

2. **Check daemon connection from hooks:**
   ```bash
   sigil setup claude-code --test
   ```

3. **Check hook logs:**
   ```bash
   tail -f ~/.sigil/hook.log
   ```

**Solutions:**

- **Reinstall hooks**: `sigil setup claude-code`
- **Check agent config**: Ensure hook paths are correct
- **Restart agent**: Some agents require restart after hook changes

#### Problem: Hooks cause agent to hang

**Symptoms:**
- Agent freezes when executing commands
- Commands timeout

**Diagnostic Steps:**

1. **Test hook manually:**
   ```bash
   sigil resolve "echo {{secret:test}}"
   ```

2. **Check daemon responsiveness:**
   ```bash
   sigil status
   ```

**Solutions:**

- **Increase timeout**: Adjust in agent settings
- **Restart daemon**: `pkill sigild && sigild`
- **Disable problematic hooks**: Temporarily disable to isolate issue

---

### 4. Sandbox Issues

#### Problem: Sandbox won't start

**Symptoms:**
- Error: "bubblewrap not found"
- Error: "Failed to create sandbox"
- Commands fail with sandbox-related errors

**Diagnostic Steps:**

1. **Check bubblewrap installation:**
   ```bash
   which bwrap
   bwrap --version
   ```

2. **Test sandbox manually:**
   ```bash
   sigil exec --sandbox -- echo "test"
   ```

3. **Run without sandbox:**
   ```bash
   sigil exec --no-sandbox -- echo "test"
   ```

**Solutions:**

- **Install bubblewrap**:
  ```bash
  # Debian/Ubuntu
  sudo apt install bubblewrap

  # macOS
  # Sandbox uses built-in sandbox-exec, no install needed
  ```
- **Use hook-only mode**: Run without `--sandbox` flag
- **Check permissions**: Ensure user can create namespaces

#### Problem: Commands behave differently in sandbox

**Symptoms:**
- Command works outside sandbox, fails inside
- File not found errors
- Permission denied errors

**Diagnostic Steps:**

1. **Compare outputs:**
   ```bash
   # Outside sandbox
   echo "test" > /tmp/test.txt

   # Inside sandbox
   sigil exec --sandbox -- 'ls /tmp/'
   ```

2. **Check mounted paths:**
   ```bash
   sigil exec --sandbox -- 'mount'
   ```

**Solutions:**

- **Add paths to manifest**: Edit `.sigil.toml` to include required directories
- **Check read-only mounts**: Some paths are read-only in sandbox
- **Use file injection**: `{{secret:path:file}}` for temporary files

---

### 5. Proxy Issues

#### Problem: Proxy not injecting headers

**Symptoms:**
- API calls return 401 Unauthorized
- No auth headers in requests
- Proxy rules not matching

**Diagnostic Steps:**

1. **Check proxy is running:**
   ```bash
   ps aux | grep sigil-proxy
   ```

2. **View proxy rules:**
   ```bash
   sigil config get proxy.rules
   ```

3. **Test proxy manually:**
   ```bash
   curl -x http://localhost:8080 https://api.example.com
   ```

**Solutions:**

- **Add proxy rule**: `sigil proxy add-rule --domain api.example.com --header "Authorization: Bearer {{secret:api/key}}"`
- **Check domain matching**: Ensure exact domain or wildcard matches
- **Verify secret exists**: `sigil get api/key`

#### Problem: Proxy blocks legitimate requests

**Symptoms:**
- Connection refused errors
- Timeout errors
- "Domain not in allowlist" errors

**Diagnostic Steps:**

1. **Check allowlist:**
   ```bash
   sigil config get proxy.allowlist
   ```

2. **Check audit log for blocked requests:**
   ```bash
   grep "blocked" ~/.sigil/proxy.log
   ```

**Solutions:**

- **Add domain to allowlist**: `sigil proxy allow-domain example.com`
- **Add proxy rule**: Create rule for the domain
- **Disable proxy**: Use `--no-proxy` flag if proxy not needed

---

### 6. Output Scrubbing Issues

#### Problem: Secrets appearing in output

**Symptoms:**
- Secret values visible in agent responses
- Scrubbing not working
- Only some secrets scrubbed

**Diagnostic Steps:**

1. **Test scrubbing directly:**
   ```bash
   echo "secret:value" | sigil scrub -
   ```

2. **Check loaded secrets:**
   ```bash
   sigil list
   ```

3. **Check scrubber configuration:**
   ```bash
   sigil config get scrubbing
   ```

**Solutions:**

- **Ensure secret exists**: Scrubber only knows about vault secrets
- **Check encodings**: Scrubber covers 7 encodings (base64, hex, etc.)
- **Use sealed operations**: For complete output control

#### Problem: Over-scrubbing (false positives)

**Symptoms:**
- Legitimate text replaced with [REDACTED]
- Output contains too many redactions

**Diagnostic Steps:**

1. **Check what's being scrubbed:**
   ```bash
   SIGIL_LOG=debug sigil scrub output.txt
   ```

2. **Review secret values:**
   ```bash
   sigil get <path> --show-fingerprint
   ```

**Solutions:**

- **Change secret value**: Use unique values that don't appear in normal text
- **Use specific paths**: More specific paths reduce false positives
- **Adjust scrubbing level**: `sigil config set scrubbing.level=conservative`

---

### 7. Performance Issues

#### Problem: Commands are slow

**Symptoms:**
- Commands take longer than expected
- Noticeable lag before output

**Diagnostic Steps:**

1. **Measure overhead:**
   ```bash
   time sigil exec -- echo "test"
   time echo "test"
   ```

2. **Check daemon load:**
   ```bash
   sigil status
   ```

3. **Profile with debug logging:**
   ```bash
   SIGIL_LOG=debug sigil exec -- command
   ```

**Solutions:**

- **Use hook-only mode**: Skip sandbox for faster execution
- **Reduce secret count**: Archive old secrets
- **Check system resources**: High CPU/memory usage affects performance
- **Adjust timeouts**: Reduce timeout for faster failure

---

### 8. Platform-Specific Issues

#### WSL2 Issues

**Problem**: WSL2-specific sandbox or socket issues

**Solutions:**
```bash
# Ensure /dev/shm is available
mount | grep shm

# Use XDG_RUNTIME_DIR for socket
export XDG_RUNTIME_DIR=/mnt/wsl/sharedsockets
sigild
```

#### macOS Issues

**Problem**: sandbox-exec warnings or limitations

**Solutions:**
```bash
# Check macOS version (sandbox-exec deprecated but functional)
sw_vers

# Use alternative if needed
sigil exec --no-sandbox -- command
```

---

## 🚨 Emergency Procedures

### Vault Lockdown

If you suspect a breach:

```bash
# Immediate lockdown
sigil lockdown

# Generate breach report
sigil breach-report --output breach.md

# After investigation, unlock
sigil unlock
```

### Vault Recovery

If vault is corrupted:

```bash
# Export to encrypted archive (if possible)
sigil export backup.sigil

# Re-initialize
sigil init

# Import from backup
sigil import backup.sigil
```

### Emergency Uninstall

If you need to completely remove SIGIL:

```bash
# Keep vault for backup
sigil uninstall --keep-vault

# Complete removal (deletes vault!)
sigil uninstall --purge
```

---

## 📞 Getting Help

If you can't resolve the issue:

1. **Check the FAQ**: [FAQ](../faq.md)
2. **Run diagnostics**: `sigil doctor --output diagnostics.txt`
3. **Check logs**: `~/.sigil/sigild.log`, `~/.sigil/hook.log`
4. **File an issue**: [GitHub Issues](https://github.com/jedarden/sigil/issues)

When filing an issue, include:
- SIGIL version (`sigil --version`)
- Platform (`uname -a`)
- Error messages
- Diagnostic output (`sigil doctor`)
- Relevant log excerpts

---

## 👉 Next Steps

- [Quick Reference Guide](../quick-reference.md) — Common commands
- [Security Best Practices](security-best-practices.md) — Stay secure
- [FAQ](../faq.md) — Common questions
