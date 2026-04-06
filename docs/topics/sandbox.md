# Sandbox

SIGIL uses sandbox execution to isolate processes from the host system.

## Sandboxing Technology

### Linux

Uses **bubblewrap** for namespace isolation:

```bash
bwrap --unshare-pid --unshare-net --ro-bind / / <command>
```

Features:
- PID namespace isolation
- Network isolation (optional)
- Read-only root filesystem
- Separate mount namespace
- Seccomp filter for syscall restrictions

### macOS

Uses **sandbox_exec** with macOS sandbox profile:

- Restricted filesystem access
- Network socket restrictions
- Process spawning restrictions
- Limitations compared to Linux

## Sandbox Commands

```bash
# Run command in sandbox
sigil exec --sandbox 'curl https://api.example.com'

# Disable sandbox (not recommended)
sigil exec --no-sandbox 'command'
```

## Security Properties

The sandbox provides:

- **Process isolation**: Processes cannot see host processes
- **Filesystem isolation**: Limited filesystem access
- **Network isolation**: Can restrict network access
- **Syscall filtering**: Seccomp filters dangerous syscalls

## Sandbox Escape

Sandbox escape is possible if:

- Host is compromised (root access)
- Kernel vulnerabilities exist
- Incorrect sandbox configuration

## Performance

Sandbox overhead: ~30ms per command

Includes:
- Namespace setup: ~10ms
- Mount setup: ~15ms
- Process spawn: ~5ms

## Limitations

- **Linux**: Full isolation with bubblewrap
- **macOS**: Limited isolation with sandbox_exec
- **WSL2**: Full isolation (treated as Linux)
- **Docker**: Requires bind mounts for vault access

## Best Practices

- Always use sandbox when possible
- Disable only for trusted commands
- Monitor audit logs for sandbox violations
- Keep kernel updated for security patches

---

For more information, see: https://docs.sigil.rs
