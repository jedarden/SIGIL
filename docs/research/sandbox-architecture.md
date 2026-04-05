## Part 1: Sandbox Execution Models

This section surveys how existing tools create isolated execution environments for AI coding agents, focusing on the mechanisms that are relevant to SIGIL's design.

---

### 1.1 Claude Code

Claude Code implements a two-layer sandbox using OS-level primitives, not containers. The implementation lives in the `anthropic-experimental/sandbox-runtime` package.

**Linux (bubblewrap + seccomp):**
The sandbox wraps every Bash tool call with `bwrap` (bubblewrap), constructing a command of the form:

```
bwrap [namespace args] [filesystem args] -- apply-seccomp [filter] -- /bin/bash -c "[user command]"
```

This is a two-stage execution model:

1. **Bubblewrap stage** -- creates isolated namespaces and mounts filesystems:
   - `--unshare-pid` with `--proc` mounting: sandboxed processes cannot enumerate or interact with host processes
   - `--unshare-net`: creates a completely isolated network namespace with no interfaces except loopback
   - Filesystem: starts with `--ro-bind / /` (read-only root), then selectively mounts writable paths via `--bind`
   - Symlink detection (`findSymlinkInPath`) prevents symlink replacement attacks
   - Missing path components are mounted to `/dev/null` to prevent `mkdir` workarounds

2. **Seccomp stage** -- applies BPF syscall filtering before executing the user command:
   - When `allowAllUnixSockets` is false, a BPF filter blocks Unix domain socket creation at the syscall level
   - Architecture-specific binaries for x64 and arm64; 32-bit x86 (ia32) is explicitly blocked due to the `socketcall` multiplexer vulnerability
   - The `apply-seccomp` binary applies the compiled BPF program before the user command runs

**Network isolation** is restored through a Unix socket bridge: a proxy server runs outside the sandbox, and connectivity is piped through Unix sockets bound into the namespace via `socat`. The proxy enforces domain-based filtering with deny-list-first precedence.

**macOS** uses Seatbelt sandbox profiles via `sandbox-exec`, with equivalent filesystem and network restrictions.

**Credential handling on Claude Code web**: Sensitive credentials (git credentials, signing keys) are never inside the sandbox. A custom proxy service transparently manages git interactions, authenticating with scoped credentials and validating operations before attaching authentication tokens. This is the closest existing analogue to SIGIL's proxy model.

**Hooks system**: Claude Code provides 25+ lifecycle events for deterministic command interception. The most relevant to SIGIL:
- `PreToolUse` (matcher: `Bash`) -- receives `tool_input.command` as JSON on stdin; can block (exit 2), allow (exit 0), or rewrite (`updatedInput`) the command
- `PostToolUse` (matcher: `Bash`) -- receives the tool output; can inject `additionalContext` or block with `decision: "block"`
- Hooks receive structured JSON: `{session_id, cwd, tool_name, tool_input: {command: "..."}}`
- Exit code 2 blocks execution and feeds stderr back to the LLM as feedback
- Hooks can return structured JSON for richer control (allow/deny/ask/defer decisions)

This hook architecture is the primary integration point for a Claude Code-native SIGIL implementation.

**Sources:**
- [Anthropic engineering blog on Claude Code sandboxing](https://www.anthropic.com/engineering/claude-code-sandboxing)
- [Claude Code sandboxing docs](https://code.claude.com/docs/en/sandboxing)
- [Anthropic sandbox-runtime bubblewrap integration (DeepWiki)](https://deepwiki.com/anthropic-experimental/sandbox-runtime/6.3.1-bubblewrap-integration)
- [Claude Code hooks guide](https://code.claude.com/docs/en/hooks-guide)

---

### 1.2 OpenAI Codex CLI

Codex uses a different model depending on whether execution is local or cloud.

**Cloud execution** runs in isolated OpenAI-managed containers with a two-phase runtime:
1. **Setup phase** -- has network access, installs dependencies
2. **Agent phase** -- network disabled by default; secrets configured for cloud environments are available only during setup and are removed before the agent phase starts

This "secrets removed before agent runs" pattern is directly relevant to SIGIL -- it demonstrates that the industry consensus is that secrets should not coexist with agent execution.

**Local sandbox** uses platform-specific mechanisms:
- **Linux**: bubblewrap + seccomp (default), with `use_legacy_landlock` as an alternative. Network egress routes through a proxy-only bridge that "fails closed" if it cannot build valid loopback proxy routes
- **macOS**: Seatbelt policies via `sandbox-exec`
- **Windows**: Dedicated lower-privilege sandbox users, filesystem permission boundaries, firewall rules

Codex is notable for having sandboxing enabled by default -- the only major agent to do so as of early 2026. Protected paths within writable roots include `.git` (read-only), `.agents`, and `.codex` directories.

**Sources:**
- [Codex CLI agent approvals and security](https://developers.openai.com/codex/agent-approvals-security)
- [Codex CLI advanced configuration](https://developers.openai.com/codex/config-advanced)

---

### 1.3 OpenHands

OpenHands uses full Docker containerization as its isolation primitive.

**Architecture**: The system defines an event-stream abstraction capturing actions and observations in a perception-action loop. Each agent reads event history and produces atomic actions executed in a sandboxed runtime.

**Workspace model**:
- `LocalWorkspace` -- in-process against host filesystem (development mode)
- `DockerWorkspace` -- containerized server with SSH access
- `APIRemoteWorkspace` -- delegates over HTTP to a managed runtime

Agents access the container via SSH, preserving remote-development semantics. Only project-specific files are mounted. The container is torn down post-session, ensuring filesystem integrity and preventing cross-agent interference.

**V1 SDK** refactors into modular packages with opt-in sandboxing, event-sourced state, immutable configuration, and workspace-level remote interfaces (VS Code, VNC, browser).

This is a heavier-weight approach than SIGIL needs -- full container lifecycle management -- but the event-stream abstraction and workspace isolation patterns are relevant.

**Sources:**
- [OpenHands Docker sandbox docs](https://docs.openhands.dev/sdk/guides/agent-server/docker-sandbox)
- [OpenHands SDK paper (arXiv)](https://arxiv.org/html/2511.03690v1)

---

### 1.4 SWE-agent and SWE-ReX

SWE-agent uses SWE-ReX as its runtime interface: "a runtime interface for interacting with sandboxed shell environments."

**Isolation strategy**: Isolate first, then grant full permissions inside the boundary. Each task runs in its own isolated sandbox with full shell access. The agent has full permissions within the sandbox, and errors are contained.

**Runtime backends**:
- Docker (default)
- AWS Fargate
- Modal
- Local execution

**Key capabilities**:
- Automatic command completion recognition
- Structured output extraction (exit codes, stdout, stderr)
- Interactive tool support (ipython, gdb)
- Multiple parallel shell sessions per agent
- 100+ agents in parallel

**SWE-MiniSandbox** takes a lighter approach: per-instance mount namespaces and chroot-based filesystem isolation instead of containers. This is closer to what SIGIL would need.

**Sources:**
- [SWE-ReX GitHub](https://github.com/SWE-agent/SWE-ReX)
- [SWE-MiniSandbox paper](https://arxiv.org/html/2602.11210v1)

---

### 1.5 Devcontainers

VS Code devcontainers provide Docker-based development environments configured via `devcontainer.json`.

**Isolation properties**:
- Process isolation via Docker containerization
- Network isolation via firewall configuration with allowlisted domains and default-deny policy
- Filesystem isolation with optional local Docker volumes (no host bind mount)
- Repository Containers mode avoids binding to local filesystem entirely

**Security limitations**:
- When executed with `--dangerously-skip-permissions`, devcontainers do not prevent exfiltration of anything accessible in the container, including Claude Code credentials
- VS Code server internals have been demonstrated to escape container boundaries (Red Guild research)

**For SIGIL**: Devcontainers are too heavy for per-command isolation but could serve as the outer execution boundary within which SIGIL operates.

**Sources:**
- [VS Code devcontainers docs](https://code.visualstudio.com/docs/devcontainers/containers)
- [Isolating AI agents with DevContainer](https://dev.to/siddhantkcode/isolating-ai-agents-with-devcontainer-a-secure-and-scalable-approach-4hi4)
- [VS Code container escape research](https://blog.theredguild.org/leveraging-vscode-internals-to-escape-containers/)

---

### 1.6 Nix Sandboxing

Nix builds run in sandboxed environments using Linux namespaces:
- Private PID, mount, network, IPC, and UTS namespaces
- Builds only see their declared dependencies in the Nix store
- Root filesystem is a tmpfs invisible from the host, automatically cleaned up when the last process exits
- Fixed-output derivations (those that need network access) do not use private network namespace

**Relevance to SIGIL**: The Nix model demonstrates that namespace-based isolation can be lightweight and fast. The key insight is the asymmetric access model -- read-only root with selective writable bind mounts -- which Claude Code's sandbox also adopts.

The `bubblewrap-claude` Nix flake wraps Claude Code execution in bwrap with a curated set of capabilities, demonstrating community demand for this exact pattern.

**Sources:**
- [Nix sandboxing discourse](https://discourse.nixos.org/t/what-is-sandboxing-and-what-does-it-entail/15533)
- [bubblewrap-claude Nix flake](https://github.com/matgawin/bubblewrap-claude)
- [nix-sandbox-mcp](https://github.com/SecBear/nix-sandbox-mcp)

---

### 1.7 GitHub Actions Runners

GitHub Actions provides the most mature secret management model in CI/CD:

**Secret injection**: Secrets are injected as environment variables, masked in logs via `::add-mask::VALUE`. The runner scans output for exact matches and common encodings (base64).

**Masking limitations** (critical for SIGIL's design):
- Derived values (substrings, base64-encoded, URL-encoded) are NOT automatically masked
- Structured data (JSON, YAML blobs) can cause masking to fail
- If a process transforms the value, the transformed version is not masked
- GitLab CI has similar limitations: variables must be 8+ characters, single line, no spaces

**Runner isolation**:
- GitHub-hosted runners: ephemeral clean VMs, no persistent compromise possible
- Self-hosted runners: no ephemeral guarantees, should never be used for public repos

**Injection attacks**: The `pull_request_target` event runs in the base repo's context with access to secrets. If it checks out malicious PR code and executes it, the attacker gains secret access. This is directly analogous to the SIGIL threat model: an untrusted agent executing in an environment that has access to secrets.

**Sources:**
- [GitHub Actions using secrets](https://docs.github.com/actions/security-guides/using-secrets-in-github-actions)
- [GitHub secure use reference](https://docs.github.com/en/actions/reference/security/secure-use)
- [GitHub Actions runner secret masking issue #2701](https://github.com/actions/runner/issues/2701)

---

### 1.8 Cursor

Cursor 2.0 implements sandboxed terminal execution (GA on macOS):
- Read/write workspace access, blocked internet access
- Enterprise administrators can enforce sandbox policies
- Parallel agents use Git worktrees or remote machines for isolation
- Audit logs track command usage and agent activity

Cursor does not appear to have a hook system comparable to Claude Code's -- its extension model is IDE-integrated rather than shell-interceptable.

---

### 1.9 Aider

Aider runs commands directly in the user's environment with no built-in sandboxing. Commands execute under `sh` with the user's full privileges. This makes Aider the canonical example of a tool that would benefit from SIGIL's external shell wrapper approach.

---

### 1.10 GitHub Copilot Workspace (Agentic Workflows)

GitHub's agentic workflow security architecture provides perhaps the most relevant reference for SIGIL:

**Four principles**: defense in depth, zero secrets for agents, staged and vetted writes, comprehensive logging.

**Secret isolation**: Agents receive zero access to secrets.
- LLM auth tokens: isolated in a dedicated API proxy, not exposed to agent containers
- MCP tokens: stored in a separate trusted MCP gateway container
- Network: agents communicate via firewalled private network

**Execution environment**: Agents run in a chroot jail with:
- Host filesystem mounted read-only at `/host`
- Selected paths overlaid with empty tmpfs layers
- Writable surface constrained to job requirements

**Safe outputs system**: Write operations undergo deterministic analysis:
1. Operation filtering (allowed write types)
2. Volume limits (e.g., max 3 PRs per run)
3. Content sanitization (remove URLs, secrets, patterns)
4. Staged processing (only vetted artifacts proceed)

**Sources:**
- [GitHub blog: security architecture of agentic workflows](https://github.blog/ai-and-ml/generative-ai/under-the-hood-security-architecture-of-github-agentic-workflows/)

---

### 1.11 Summary: Isolation Mechanisms Taxonomy

```
Isolation Strength (ascending):
                                                         ┌─────────────┐
                                                         │  Full VM    │
                                                         │ (Lima, EC2) │
                                                    ┌────┴─────────────┤
                                                    │  microVM/gVisor  │
                                               ┌────┴────────────────┤
                                               │  Docker container    │
                                          ┌────┴────────────────────┤
                                          │  bubblewrap + seccomp    │
                                     ┌────┴────────────────────────┤
                                     │  Landlock + seccomp          │
                                ┌────┴────────────────────────────┤
                                │  chroot + namespace isolation    │
                           ┌────┴────────────────────────────────┤
                           │  restricted shell + PATH control     │
                      ┌────┴────────────────────────────────────┤
                      │  hook-based interception (no isolation)   │
                 ┌────┴────────────────────────────────────────┤
                 │  no sandboxing (Aider, raw shell)             │
                 └──────────────────────────────────────────────┘
```

SIGIL's sweet spot is in the **bubblewrap + seccomp** tier for full sandbox mode, with a **hook-based interception** fallback for lightweight integration.

---

## Part 2: Proposed SIGIL Architecture

### The Proxy Shell Model

The fundamental insight: the agent believes it is talking to a normal shell. SIGIL interposes a transparent layer that handles the complete lifecycle of secret-bearing commands.

```
                          AGENT TRUST BOUNDARY
 ┌────────────────────────────────────────────────────────────┐
 │                                                            │
 │  ┌──────────────┐         ┌──────────────────────────┐    │
 │  │   AI Agent    │         │  Agent sees:              │    │
 │  │  (Claude,     │────────▶│  - {{secret:x}} syntax    │    │
 │  │   Cursor,     │         │  - sanitized output       │    │
 │  │   Aider)      │◀────────│  - exit codes             │    │
 │  └──────────────┘         └──────────────────────────┘    │
 │                                                            │
 └──────────────────────────┬─────────────────────────────────┘
                            │
                   sigil-shell / hook
                            │
 ┌──────────────────────────┴─────────────────────────────────┐
 │                     SIGIL TRUST BOUNDARY                    │
 │                                                            │
 │  ┌──────────┐  ┌───────────┐  ┌────────┐  ┌───────────┐  │
 │  │ Command  │  │  Secret   │  │ Exec   │  │  Output   │  │
 │  │ Parser   │──▶│ Resolver  │──▶│ Engine │──▶│ Scrubber  │  │
 │  └──────────┘  └─────┬─────┘  └───┬────┘  └─────┬─────┘  │
 │                      │            │              │         │
 │                ┌─────▼─────┐  ┌───▼────┐  ┌─────▼─────┐  │
 │                │  Secret   │  │ bwrap  │  │  Audit    │  │
 │                │  Store    │  │sandbox │  │  Logger   │  │
 │                │ (in-mem)  │  │        │  │           │  │
 │                └───────────┘  └────────┘  └───────────┘  │
 │                                                            │
 │  ┌───────────────────────────────────────────────────────┐ │
 │  │                 SIGIL Daemon (sigild)                  │ │
 │  │        Unix socket: /run/user/$UID/sigil.sock         │ │
 │  │        PID: isolated, PR_SET_DUMPABLE=0               │ │
 │  └───────────────────────────────────────────────────────┘ │
 │                                                            │
 └────────────────────────────────────────────────────────────┘
```

---

### 2.1 SIGIL Daemon (`sigild`)

The daemon is the privileged core of SIGIL. It holds decrypted secrets in memory and performs all secret-bearing operations.

#### Process Design

```
sigild
├── Secret Store (in-memory HashMap<SecretPath, SecretValue>)
├── Backend Manager (pluggable: local vault, Vault, 1Password, etc.)
├── Session Manager (active sessions, authentication tokens)
├── Audit Logger (append-only, tamper-evident)
├── Scrub Engine (compiled pattern matchers)
└── IPC Server (Unix domain socket)
```

**Memory protection**: The daemon calls `prctl(PR_SET_DUMPABLE, 0)` immediately on startup. This prevents any process running as the same user from reading its memory via `ptrace()` or `/proc/<pid>/mem`. Even if the agent discovers the daemon's PID, it cannot attach to or read from it. The daemon also uses `mlock()` on secret-containing memory pages to prevent swapping to disk.

**Process isolation**: The daemon runs as a separate process (not a thread within the harness). On Linux, it can optionally use a separate user namespace or run as a different UID, but the minimum viable isolation is:
- `PR_SET_DUMPABLE = 0`
- Socket with restrictive permissions (`0600`)
- PID visible but memory inaccessible
- Yama LSM `ptrace_scope >= 1` (default on most distributions)

#### IPC: Unix Domain Socket

The daemon listens on a Unix domain socket at `/run/user/$UID/sigil.sock` (or `$XDG_RUNTIME_DIR/sigil.sock`).

**Why Unix sockets over alternatives:**

| Mechanism | Pros | Cons |
|-----------|------|------|
| Unix domain socket | SO_PEERCRED for auth, filesystem permissions, fast, no network exposure | macOS lacks SO_PEERCRED (uses LOCAL_PEERCRED instead) |
| Named pipe (FIFO) | Simple, no socket overhead | Unidirectional, no peer auth, race conditions |
| TCP localhost | Cross-platform | Any process can connect, no peer auth |
| Shared memory | Fastest possible IPC | No access control, complex synchronization |
| D-Bus | Standard Linux IPC | Heavy dependency, overkill for this use case |

**Unix sockets win** because `SO_PEERCRED` (Linux) / `LOCAL_PEERCRED` (macOS) allows the daemon to retrieve the PID, UID, and GID of the connecting process via `getsockopt()`. This is kernel-populated and cannot be spoofed.

#### Authentication: Harness Hook vs. Agent

The daemon must distinguish between authorized harness hooks (which need secret resolution) and the agent itself (which must be denied direct access).

**Session token model:**

```
  1. User starts sigild (before agent)
     sigild generates a cryptographic session token (32 bytes, random)
     Token stored in:
       - sigild's memory
       - Environment variable SIGIL_SESSION_TOKEN (set in the hook's
         env, NOT the agent's env)
       - Or: written to a file readable only by the hook process

  2. Hook connects to socket
     Sends: {token: "abc...", command: "resolve", ...}
     sigild verifies:
       a. Token matches active session
       b. SO_PEERCRED UID matches expected user
       c. SO_PEERCRED PID traces to a known hook process lineage

  3. Agent attempts direct connection (attack scenario)
     Sends: {command: "resolve", secret: "kalshi/api_key"}
     sigild rejects: no valid session token
     Even if agent reads SIGIL_SESSION_TOKEN from hook's env:
       - Hook runs in a subprocess; token is in hook's env, not agent's
       - If hook is a Claude Code PreToolUse hook, it's a separate process
       - Agent would need to read /proc/<hook_pid>/environ (blocked by
         PR_SET_DUMPABLE=0 on the hook process)
```

**Defense in depth for token protection:**
1. Token is never in the agent's environment variables
2. Token is never written to a file in the agent's accessible filesystem
3. Hook processes set `PR_SET_DUMPABLE=0` before reading the token
4. Token file (if used) has `0400` permissions owned by a non-agent UID
5. The daemon validates PID lineage: the connecting process must be a child of the harness, not the agent

#### Preventing Direct Agent Connection

Even with authentication, we must consider an adversarial agent that tries to connect to the socket:

```
Attack vector                  │ Mitigation
──────────────────────────────┼──────────────────────────────────────
Agent reads socket path       │ Socket path is not in agent's env;
                              │ agent would need to scan /run/user/
                              │ (blocked by sandbox filesystem rules)
──────────────────────────────┼──────────────────────────────────────
Agent connects to socket      │ Requires session token (not in
                              │ agent's env or accessible files)
──────────────────────────────┼──────────────────────────────────────
Agent reads hook process env  │ PR_SET_DUMPABLE=0 on hook process
                              │ blocks /proc/pid/environ access
──────────────────────────────┼──────────────────────────────────────
Agent reads token from disk   │ Token file on tmpfs with 0400 perms
                              │ owned by separate UID; or no file at
                              │ all (passed via inherited fd)
──────────────────────────────┼──────────────────────────────────────
Agent ptraces hook process    │ Yama ptrace_scope + PR_SET_DUMPABLE
──────────────────────────────┼──────────────────────────────────────
Agent runs in bwrap sandbox   │ seccomp blocks socket() creation for
                              │ Unix domain sockets (Claude Code
                              │ already does this when configured)
```

The strongest mitigation is running the agent's commands inside a bubblewrap sandbox with seccomp filters that block Unix domain socket creation. Claude Code already has this capability when `allowAllUnixSockets` is false. SIGIL can rely on this for Claude Code, and must provide its own bwrap wrapper for other harnesses.

---

### 2.2 Pre-execution Pipeline

The pre-execution pipeline transforms agent commands containing sigil placeholders into executable commands with real secrets.

#### Step 1: Parse Command for Placeholders

```
Input:  curl -H "Authorization: Bearer {{secret:kalshi/api_key}}" \
             https://api.kalshi.com/trade/v2/portfolio/balance

Regex:  \{\{secret:([a-zA-Z0-9_/.-]+)(?::([a-z_]+))?\}\}

Captures:
  Match 1: path = "kalshi/api_key", modifier = None
  
Extended syntax:
  {{secret:path}}              -- inline value substitution
  {{secret:path:env}}          -- inject as environment variable
  {{secret:path:file}}         -- write to tmpfs, substitute path
  {{secret:path:file:/path}}   -- write to specific tmpfs path
```

The parser produces a `ResolvedCommand` struct:

```rust
struct ResolvedCommand {
    original: String,           // agent's command (with placeholders)
    executable: String,         // command with secrets substituted
    env_injections: Vec<(String, SecretValue)>,
    file_injections: Vec<FileInjection>,
    secrets_used: Vec<SecretPath>,  // for audit + scrubbing
}

struct FileInjection {
    secret_path: SecretPath,
    tmpfs_path: PathBuf,        // e.g., /run/user/1000/sigil/tmp/XXXXX
    target_path: PathBuf,       // path the command will see
    permissions: u32,           // 0400
}
```

#### Step 2: Resolve from Backend

The resolver fetches values from the configured backend through a pluggable trait:

```rust
#[async_trait]
trait SecretBackend {
    async fn get(&self, path: &SecretPath) -> Result<SecretValue>;
    async fn list(&self, prefix: &str) -> Result<Vec<SecretPath>>;
    fn backend_type(&self) -> &str;
}
```

The daemon caches resolved values in memory (with configurable TTL). For local vault backends, values are always in memory. For remote backends (Vault, 1Password), values are fetched on first use and cached.

#### Step 3: Inject into Command

**Inline injection** (default): Direct string substitution in the command. This is the simplest case and handles most API key / token usage.

```
Before: curl -H "Authorization: Bearer {{secret:kalshi/api_key}}"
After:  curl -H "Authorization: Bearer sk-live-abc123..."
```

**Environment variable injection** (`{{secret:path:env}}`): The secret is set as an environment variable in the execution environment. The command references it via `$VAR_NAME`. The variable name is derived from the secret path: `kalshi/api_key` becomes `KALSHI_API_KEY`.

```
Before: curl -H "Authorization: Bearer {{secret:kalshi/api_key:env}}"
After:  KALSHI_API_KEY=sk-live-abc123... curl -H "Authorization: Bearer $KALSHI_API_KEY"
```

**File injection** (`{{secret:path:file}}`): For multi-line secrets like TLS certificates, SSH keys, or JSON credentials. The process:

1. Create a directory on tmpfs: `/run/user/$UID/sigil/tmp/`
2. Write secret to a file with restrictive permissions: `0400`, owned by execution UID
3. Replace the placeholder with the file path
4. After execution, securely wipe the file (overwrite with zeros, then unlink)

```
Before: kubectl --kubeconfig={{secret:cluster/kubeconfig:file}} get pods
After:  kubectl --kubeconfig=/run/user/1000/sigil/tmp/a7f3e2.kubeconfig get pods
         (file exists only during execution)
```

For secrets that must exist at a specific path (e.g., `~/.docker/config.json`), the sandbox can use bind mounts to overlay the tmpfs file at the expected path within the namespace.

#### Step 4: Handling Edge Cases

**Nested commands**: A command like `bash -c "curl {{secret:x}}"` requires parsing through shell quoting. The parser must handle single quotes, double quotes, heredocs, and command substitution.

**Piped commands**: `echo {{secret:x}} | sha256sum` -- the secret appears in the first command's argv, visible via `/proc/pid/cmdline`. Mitigation: rewrite to use environment variables internally: `echo "$_SIGIL_0" | sha256sum` with `_SIGIL_0` set in the environment.

**Commands that write secrets to files**: `echo {{secret:x}} > config.toml` -- this creates a file containing the secret on the agent-visible filesystem. The post-execution pipeline must scan created/modified files and either scrub them or flag them for the audit log.

---

### 2.3 Execution Environment

#### Shell Execution Model

The critical question: should commands run in the agent's shell or a separate one?

**Recommendation: separate shell, with state synchronization.**

```
Agent's logical shell state:
  CWD=/home/user/project
  ENV={PATH=..., EDITOR=vim, ...}
  SHELL_VARS={foo=bar}
  
  ┌──────────────────────────────────────────────────────┐
  │             sigild execution pipeline                  │
  │                                                        │
  │  1. Capture current state from state tracker          │
  │  2. Launch bwrap sandbox with:                        │
  │     - CWD bind-mounted writable                       │
  │     - Environment vars propagated                     │
  │     - Shell vars injected via env                     │
  │     - Secrets injected (not visible to agent)         │
  │  3. Execute command in /bin/bash -c "..."             │
  │  4. Capture: stdout, stderr, exit code                │
  │  5. Capture state changes:                            │
  │     - New CWD (if cd was run)                         │
  │     - New/changed env vars (if export was run)        │
  │     - Created/modified files                          │
  │  6. Apply state changes to state tracker              │
  │  7. Scrub output                                      │
  │  8. Return to agent                                   │
  └──────────────────────────────────────────────────────┘
```

**State synchronization**: Each command runs in a fresh bash process, but SIGIL maintains a `ShellState` that tracks:
- Current working directory
- Exported environment variables
- Shell options (`set -e`, etc.)

Before each command, the state is reconstructed:
```bash
cd /tracked/cwd && \
export VAR1=val1 && \
export VAR2=val2 && \
<user command> ; \
echo ":::SIGIL_CWD:::$(pwd)" ; \
echo ":::SIGIL_ENV:::$(env -0 | base64)"
```

The trailing state-capture commands extract the post-execution state for the next command. These markers are stripped from the agent-visible output.

**Why not a persistent shell?** A persistent shell (e.g., via `expect` or a PTY) would be simpler for state management but creates problems:
- The agent could attempt to interact with the shell directly (via escape sequences, job control)
- Secret values would persist in the shell's memory across commands
- Harder to enforce per-command isolation

#### Performance Implications

The overhead of per-command isolation:

| Component | Estimated Overhead |
|-----------|-------------------|
| bwrap namespace creation | ~5-10ms |
| seccomp filter application | ~1ms |
| Filesystem bind mounts | ~2-5ms (depends on mount count) |
| Secret resolution (cached) | ~1ms |
| Secret resolution (remote) | ~50-200ms (first fetch, then cached) |
| Output scrubbing | ~1-5ms (depends on output size and secret count) |
| State capture/restore | ~2-5ms |
| **Total (cached secrets)** | **~15-30ms** |

This is well within the 50ms requirement. The dominant cost for most commands will be the command itself, not SIGIL's overhead.

#### Long-running Processes

For commands that run indefinitely (e.g., `npm run dev`, `tail -f`), SIGIL must:
1. Stream output through the scrubber in real-time (line-buffered)
2. Maintain the sandbox for the process lifetime
3. Handle signals (SIGINT, SIGTERM) forwarded through the sandbox
4. Clean up temporary files only after the process exits

The scrubber operates on a streaming basis: each line of output is checked against the secret pattern set before being passed through. This adds minimal latency (sub-millisecond per line for typical secret counts).

---

### 2.4 Post-execution Scrubbing

The output scrubber is SIGIL's last line of defense. It must catch any secret value that appears in command output, regardless of how it got there.

#### Pattern Matching Strategy

For each command execution, the scrubber builds a `ScrubSet` from the secrets used in that command plus all other loaded secrets (defense in depth -- a command might cause an unrelated secret to appear in output).

```rust
struct ScrubSet {
    // Exact match patterns (fastest)
    exact: AhoCorasick,           // Aho-Corasick automaton for multi-pattern search
    
    // Encoding variants
    base64_standard: AhoCorasick, // base64 of each secret
    base64_urlsafe: AhoCorasick,  // base64url of each secret
    url_encoded: AhoCorasick,     // percent-encoded of each secret
    hex_encoded: AhoCorasick,     // hex-encoded of each secret
    
    // Mapping from matched pattern -> placeholder
    pattern_to_sigil: HashMap<PatternId, String>,
}
```

**Aho-Corasick** is the correct algorithm here: it searches for all patterns simultaneously in O(n + m) time where n is the text length and m is the total number of matches. This is critical because we may have dozens of secrets, each with multiple encoding variants.

#### Encoding Variants

A secret value `sk-live-abc123` might appear in output as:

| Encoding | Value | Detected? |
|----------|-------|-----------|
| Raw | `sk-live-abc123` | Yes (exact match) |
| Base64 | `c2stbGl2ZS1hYmMxMjM=` | Yes (pre-computed) |
| Base64 (no padding) | `c2stbGl2ZS1hYmMxMjM` | Yes (pre-computed variant) |
| Base64url | `c2stbGl2ZS1hYmMxMjM=` | Yes (same for this value, differs for values with +/) |
| URL-encoded | `sk-live-abc123` | Yes (no special chars in this example) |
| Hex | `736b2d6c6976652d616263313233` | Yes (pre-computed) |
| JSON-escaped | `sk-live-abc123` | Yes (no special chars; but `\"` escaping matters for values with quotes) |
| Shell-escaped | `sk-live-abc123` | Yes (shell may add backslashes for special chars) |
| Partial match | `abc123` | **No** -- substring matching would cause false positives |
| Split across lines | `sk-live-\nabc123` | **Partial** -- line-buffered scrubbing misses cross-line splits |

**The base64 problem**: Base64 encoding of a secret changes depending on the offset within the base64 stream. The value "A" encodes to three different base64 representations depending on alignment. SIGIL must pre-compute all three offset variants for each secret:

```
Secret: "sk-live-abc123"
Offset 0: "c2stbGl2ZS1hYmMxMjM="
Offset 1: prepad 1 byte, encode, extract middle portion
Offset 2: prepad 2 bytes, encode, extract middle portion
```

This triples the pattern count for base64 but ensures detection regardless of where the secret appears in a base64-encoded stream.

#### Replacement Strategy

Matched patterns are replaced with the original sigil placeholder:

```
Before scrubbing: {"api_key": "sk-live-abc123", "status": "ok"}
After scrubbing:  {"api_key": "{{secret:stripe/api_key}}", "status": "ok"}
```

The agent sees the placeholder, confirming the secret was used but never learning its value.

#### Binary Output

Binary output (e.g., from `curl --output -` or compiled binaries) is handled differently:
1. If the command is known to produce binary output (heuristic: output contains null bytes in the first 512 bytes), scrub but note the reduced confidence
2. For binary output, perform exact byte-sequence matching only (no encoding variants)
3. Log a warning in the audit trail that binary output was returned with reduced scrubbing confidence

#### Scrubbing Failure Modes

| Scenario | Impact | Mitigation |
|----------|--------|------------|
| Secret split across output chunks | Secret passes through unscrubbed | Buffer the last N bytes (where N = max secret length) across chunk boundaries |
| Secret in a transformed encoding not pre-computed | Secret passes through | Canary secrets detect this; expand encoding variants over time |
| Secret appears as part of a larger string | False positive scrub | Use word-boundary-aware matching where possible |
| Output is enormous (GBs) | Memory/performance impact | Streaming scrubber with fixed-size buffer; limit output size |

---

### 2.5 Audit Trail

The audit system records every secret-related operation without ever logging secret values.

#### What Gets Logged

```json
{
  "timestamp": "2026-04-04T14:23:01.337Z",
  "session_id": "ses_a7f3e2",
  "event": "secret_resolve",
  "secret_path": "kalshi/api_key",
  "backend": "local_vault",
  "command_hash": "sha256:9f86d08...",
  "placeholders_used": ["{{secret:kalshi/api_key}}"],
  "injection_type": "inline",
  "execution_sandbox": "bwrap",
  "output_scrubbed": true,
  "scrub_replacements": 2,
  "exit_code": 0,
  "duration_ms": 342
}
```

**Never logged**: Secret values, resolved commands (which contain secrets), raw output (before scrubbing).

#### Tamper-Proof Logging

Each log entry includes a chained hash:

```
entry_hash = SHA256(previous_entry_hash || entry_json)
```

This creates a hash chain similar to a blockchain -- any modification to a past entry invalidates all subsequent hashes. The first entry in each session is anchored to the session token hash.

For stronger guarantees, the audit log can be written to an append-only file on a filesystem mounted `append-only` via `chattr +a`, or streamed to an external log aggregator.

#### Breach Detection Triggers

A breach is detected when:
1. A secret value appears in scrubbed output (the scrubber found and replaced it -- this is the normal case, logged as `scrub_replacements > 0`)
2. A canary secret is referenced by the agent (the agent attempted to access a honeypot secret it should not know about)
3. The daemon detects an unauthorized connection attempt (wrong token, unexpected PID)
4. A secret value appears in a file created by the command (post-execution filesystem scan)

Breach severity levels:
- **INFO**: Secret scrubbed from output (normal operation)
- **WARN**: Secret found in created/modified file
- **CRITICAL**: Canary secret triggered, unauthorized daemon access, secret found in agent's context after scrubbing should have removed it

---

### 2.6 Alternative: Harness-Native Hooks

For tools like Claude Code that have pre/post hooks, a lighter-weight integration is possible without the full daemon.

#### Claude Code Hook Integration

```json
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "Bash",
        "hooks": [
          {
            "type": "command",
            "command": "sigil resolve"
          }
        ]
      }
    ],
    "PostToolUse": [
      {
        "matcher": "Bash",
        "hooks": [
          {
            "type": "command",
            "command": "sigil scrub"
          }
        ]
      }
    ]
  }
}
```

The `sigil resolve` hook:
1. Reads `tool_input.command` from stdin JSON
2. Connects to `sigild` daemon via Unix socket
3. Resolves placeholders
4. Returns `updatedInput` JSON to rewrite the command
5. Returns `permissionDecision: "allow"` to skip the permission prompt (or `"ask"` for sensitive secrets)

The `sigil scrub` hook:
1. Reads `tool_output` from stdin JSON
2. Runs the scrubber against known secret values
3. Returns scrubbed output via `additionalContext`
4. Cannot modify the already-returned output (PostToolUse limitation), but can inject a system message telling Claude to disregard the leaked value

**Limitations of the hook-only approach**:
- The command still executes in the agent's shell (no bwrap isolation)
- The agent can observe the pre-resolved command in some harness configurations
- PostToolUse cannot retroactively scrub output already in the context window
- No seccomp protection against the agent connecting to the daemon socket
- Shell state (cd, exports) works natively since the agent's shell is used directly

#### When is Hook-Only "Good Enough"?

```
                          Hook-Only              Full Sandbox
                          ─────────              ────────────
Threat: prompt injection  Partial (scrubbing)    Strong (isolation)
Threat: process escape    None                   Strong (namespaces)
Threat: socket access     None                   Strong (seccomp)
Threat: file exfil        None                   Strong (filesystem)
Performance overhead      < 10ms                 15-30ms
State management          Free (agent's shell)   Complex (sync needed)
Setup complexity          Low (settings.json)    Medium (daemon + bwrap)
Cross-harness             Claude Code only       Universal
```

**Recommendation**: Use hook-only mode as the "quick start" integration for Claude Code, with the full sandbox as the production-grade option. The hook-only mode is also useful for development/testing where the security boundary is less critical.

---

## Part 3: Key Design Questions

### Q1: How do you prevent the agent from reading the SIGIL daemon's memory or process state?

**Multiple layers of defense:**

1. **`prctl(PR_SET_DUMPABLE, 0)`**: Called immediately on daemon startup. Prevents any same-UID process from reading `/proc/<daemon_pid>/mem` or attaching via `ptrace()`. This is the same mechanism used by `ssh-agent` and `gpg-agent`.

2. **Yama LSM `ptrace_scope`**: On most Linux distributions, `kernel.yama.ptrace_scope` defaults to 1 (restricted), meaning a process can only ptrace its own descendants. Since the agent is not a descendant of the daemon, ptrace is blocked even without `PR_SET_DUMPABLE`.

3. **PID namespace isolation (bwrap)**: When the agent runs in a bubblewrap sandbox with `--unshare-pid`, it cannot see processes outside its namespace. The daemon's PID is invisible to the agent entirely.

4. **Seccomp filtering**: The sandbox's seccomp filter can block `ptrace()`, `process_vm_readv()`, and other memory-inspection syscalls entirely.

5. **`mlock()` on secret pages**: Prevents the kernel from swapping secret-containing memory to disk, where it could be read from the swap partition.

6. **Separate UID (optional)**: Running the daemon as a different user provides the strongest isolation -- the agent cannot access any of the daemon's resources regardless of ptrace_scope or dumpable flags.

The combination of layers 1-4 provides strong defense even without a separate UID, which would complicate the setup flow.

### Q2: How do you handle secrets that appear in file contents (not just commands)?

**Three scenarios:**

**A. Agent explicitly requests file injection** (`{{secret:path:file}}`): SIGIL creates the file on tmpfs, uses it during execution, and removes it immediately after. The file path is in a SIGIL-controlled directory that the agent cannot access post-cleanup.

**B. A command writes a secret to a file** (e.g., `echo {{secret:x}} > config`): The pre-execution pipeline detects writes to files and either:
- Rewrites the command to write to a tmpfs location and bind-mount it
- Or flags it in the audit log and scrubs the file contents post-execution

**C. A secret appears in a pre-existing file the agent reads**: This is outside SIGIL's control for the initial version. Mitigation: the sandbox's filesystem read restrictions should prevent access to sensitive paths (`~/.aws/credentials`, `~/.ssh/*`, etc.). The post-execution scrubber catches secrets in command output regardless of their source.

**File scanning**: After each command execution (in full sandbox mode), SIGIL can scan modified files within the sandbox for secret values. Modified files are detected via inotify watches or by comparing mtimes before and after execution.

### Q3: How do you prevent the agent from modifying PATH or aliases to intercept the injection?

**In full sandbox mode**: The agent's commands execute in a fresh bash process each time. Any `PATH` modification or alias definition persists only in the SIGIL state tracker, not in a live shell. The state tracker can whitelist which environment changes to propagate:

```rust
fn should_propagate_env_change(key: &str, value: &str) -> bool {
    match key {
        // Block security-sensitive vars
        "PATH" | "LD_PRELOAD" | "LD_LIBRARY_PATH" | "SHELL" |
        "SIGIL_SESSION_TOKEN" | "SIGIL_SOCK" => false,
        // Allow normal development vars
        _ => true,
    }
}
```

**In hook-only mode**: This is a genuine weakness. The agent can modify PATH in one command and have it take effect in subsequent commands. Mitigation: the PreToolUse hook can inspect the command for PATH/alias manipulation and block it, but this is a heuristic defense (easily bypassed by indirect manipulation).

**Defense in the execution pipeline**: Even if the agent manages to modify PATH, SIGIL resolves secrets before the command reaches the shell. The injection uses absolute paths for any helper commands and does not rely on PATH.

### Q4: What's the performance overhead of proxying every command?

Based on the component analysis in section 2.3:

**Full sandbox mode**: ~15-30ms overhead per command (with cached secrets). This is dominated by namespace creation and bind mount setup. For context, typical AI agent command latency is 500ms-5s (including network roundtrip to the LLM), so 15-30ms is negligible.

**Hook-only mode**: ~5-10ms overhead (IPC to daemon + scrubbing). No namespace or mount overhead since the command runs in the agent's shell.

**Optimization opportunities**:
- Pre-create the sandbox namespace and reuse it across commands (amortize the setup cost)
- Use Landlock (Linux 5.13+) instead of bubblewrap for lighter-weight filesystem restrictions
- Cache the Aho-Corasick automaton across commands (rebuild only when secrets change)
- Parallelize secret resolution with sandbox setup

**Benchmark target**: The requirements specify < 50ms. Both modes are well within this bound for typical commands. Edge cases (very large output requiring extensive scrubbing, or first-time remote secret fetch) may exceed 50ms but will still be within acceptable bounds for interactive use.

### Q5: How do you handle interactive commands that need secrets mid-stream?

Interactive commands (e.g., a script that prompts for a password, or `mysql -u root -p`) present a unique challenge because the secret is needed after the command starts, not at launch time.

**Approach 1: Pre-analyze and rewrite** (preferred)
Many "interactive" prompts can be converted to non-interactive form:
- `mysql -u root -p` -> `mysql -u root --password={{secret:db/password}}`
- Script prompts -> pipe input via heredoc or `expect` scripts

SIGIL's pre-execution pipeline can recognize common interactive patterns and rewrite them.

**Approach 2: PTY interception**
For genuinely interactive commands, SIGIL can allocate a PTY and intercept the I/O stream:
1. Command runs in a PTY within the sandbox
2. SIGIL's PTY proxy monitors for known prompt patterns (e.g., `Password:`)
3. When detected, SIGIL injects the secret into the PTY's input stream
4. The secret never appears in the agent-visible output (the PTY proxy scrubs it)

This is complex and fragile. It should be a later-phase feature, with the initial version requiring all secrets to be injectable at command launch time.

**Approach 3: Agent instructs SIGIL to handle it**
The agent can use a special syntax: `{{secret:db/password:stdin}}` to indicate the secret should be piped to stdin. SIGIL rewrites the command to pipe the secret non-interactively.

### Q6: How would this work across different harnesses -- is a universal approach possible?

**Yes, through a layered architecture:**

```
┌─────────────────────────────────────────────────────┐
│                 sigild (daemon)                       │
│          Core: resolve, scrub, audit                 │
│          IPC: Unix socket                            │
├─────────────────────────────────────────────────────┤
│              Integration Layer                        │
│                                                       │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐          │
│  │ Claude   │  │ Cursor   │  │Universal │          │
│  │ Code     │  │ ext      │  │ Shell    │          │
│  │ hooks    │  │          │  │ Wrapper  │          │
│  └──────────┘  └──────────┘  └──────────┘          │
│       │              │              │                │
│  PreToolUse     Terminal       $SHELL=              │
│  PostToolUse    proxy          sigil-shell          │
│  hooks          intercept                            │
└─────────────────────────────────────────────────────┘
```

**Claude Code**: Native hooks (PreToolUse/PostToolUse) provide the tightest integration. The hook communicates with `sigild` via Unix socket.

**Cursor**: Cursor does not expose pre/post hooks. Options:
- Terminal proxy: Cursor's terminal output is intercepted by a proxy process
- VS Code extension: A Cursor-compatible extension that wraps terminal execution
- Devcontainer: Run Cursor in a devcontainer where SIGIL controls the shell

**Aider**: Aider runs commands via `sh`. Set `SHELL=sigil-shell` or configure Aider's test/lint command to use `sigil-shell -c "..."`.

**Universal shell wrapper (`sigil-shell`)**: A POSIX-compatible shell wrapper that:
1. Intercepts the command
2. Communicates with `sigild`
3. Resolves placeholders
4. Optionally wraps execution in bwrap
5. Scrubs output
6. Returns sanitized result

```bash
# sigil-shell (simplified pseudocode)
#!/bin/bash
# Parse -c flag (most harnesses use: $SHELL -c "command")
COMMAND="$2"

# Resolve placeholders via daemon
RESOLVED=$(sigil-cli resolve --command "$COMMAND")

# Execute in sandbox
OUTPUT=$(bwrap --unshare-pid --unshare-net ... -- /bin/bash -c "$RESOLVED" 2>&1)
EXIT_CODE=$?

# Scrub output
SCRUBBED=$(echo "$OUTPUT" | sigil-cli scrub)

echo "$SCRUBBED"
exit $EXIT_CODE
```

This shell wrapper approach is the most universal but also the most limited -- it cannot provide the same level of integration as native hooks (e.g., structured JSON input, tool-specific matching).

### Q7: How do you bootstrap trust -- what's the initial setup flow where the user configures secrets but the agent can't observe it?

**The bootstrap sequence:**

```
Step 1: User opens a SEPARATE terminal (not the agent's)
        This terminal is on a different TTY/PTY entirely.

Step 2: User runs: sigil init
        - Generates age encryption keypair
        - Creates local vault (~/.sigil/vault.age)
        - Generates session token
        - Starts sigild daemon with token

Step 3: User adds secrets via TUI:
        sigil tui
        - Uses alternate screen buffer (invisible to scrollback)
        - Runs on separate PTY
        - PR_SET_DUMPABLE=0 on TUI process

Step 4: User configures integration:
        sigil setup claude-code
        - Writes hooks to .claude/settings.json
        - Configures hook to inherit SIGIL_SESSION_TOKEN
          via file descriptor, NOT environment variable

Step 5: User starts agent (in original terminal):
        claude
        - Agent inherits NO sigil-related env vars
        - Agent's commands go through hooks
        - Hooks have access to the session token
          (via inherited fd or restricted file)
        - Agent cannot observe steps 1-4
```

**Key property**: The TUI uses the **alternate screen buffer** (`\e[?1049h`), which means its content is not in the terminal's scrollback buffer. Even if the agent somehow reads the terminal's scrollback, it will not see the TUI's content.

**File descriptor inheritance**: The session token can be passed to the hook process via an inherited file descriptor (e.g., fd 3). The hook process reads the token from fd 3, not from an environment variable or file. This prevents the agent from discovering the token via `/proc/self/environ` or filesystem scanning.

```bash
# How the hook inherits the token:
# sigild writes token to a pipe
# The hook is launched with the read end of the pipe as fd 3
# Hook reads: read -r TOKEN <&3
```

---

## Part 4: Reference Implementations

### 4.1 Directly Relevant Projects

#### nono (always-further/nono)
**Kernel-enforced agent sandbox with proxy-based API key protection.**

The closest existing project to SIGIL's goals. Key technical details:
- Uses Seatbelt (macOS) and Landlock (Linux 5.13+) for kernel-level isolation
- Once applied, sandbox restrictions are irreversible and inherited by all child processes
- **Proxy injection mode**: "Agent never sees the API key, even in its own memory." Credentials remain entirely outside the sandbox; the agent connects to localhost and the proxy injects real keys into upstream requests
- **Env injection mode**: Secrets load from OS keystore, 1Password, or Apple Passwords before the sandbox locks, then inject as environment variables
- Content-addressable snapshots with SHA-256 deduplication and Merkle tree commitments for rollback
- Automatic audit chain with cryptographic snapshot commitments

**Differences from SIGIL**: nono focuses on API key injection into HTTP requests (proxy model), not arbitrary shell command secret injection. It does not parse commands for placeholders or scrub output. SIGIL's scope is broader.

GitHub: [always-further/nono](https://github.com/always-further/nono)

#### AgentSecrets (The-17/agentsecrets)
**Zero-knowledge credential proxy for AI agents.**

Key technical details:
- Agents never receive credential values -- "OS keychain -> proxy resolves in memory -> value injected at transport layer"
- Encryption: X25519 (NaCl SealedBox), AES-256-GCM, Argon2id key derivation
- Keys stored in OS keychain (macOS Keychain, Windows Credential Manager, Linux Secret Service)
- **Response body redaction**: If external APIs echo injected credentials, the proxy replaces them with `[REDACTED_BY_AGENTSECRETS]` before the response reaches agents
- SSRF protection: private IP ranges, localhost, non-HTTPS blocked at proxy level
- Session token authentication: generated at proxy startup, required on every request
- Six auth injection styles: Bearer, custom header, query param, basic auth, JSON body, form field
- MCP server integration for Claude Desktop and Cursor
- Agent identity levels: anonymous, declared, and cryptographically issued (revocable per-agent)
- Audit log: every proxy call logged with key name, endpoint, environment, agent identity -- but NO value field (structural impossibility)

**Differences from SIGIL**: AgentSecrets is HTTP-proxy-focused (injecting into HTTP requests). SIGIL needs to handle arbitrary shell commands, not just HTTP. However, the zero-knowledge proxy architecture and response redaction are directly applicable design patterns.

GitHub: [The-17/agentsecrets](https://github.com/The-17/agentsecrets)

#### agent-secrets (joelhooks/agent-secrets)
**Daemon-based credential management with leases and killswitch.**

Key technical details:
- Unix socket-based client-server model: CLI communicates with daemon via JSON-RPC over `~/.agent-secrets/agent-secrets.sock`
- Daemon coordinates: encrypted storage, lease management, audit logging, rotation hooks, killswitch heartbeat
- Age encryption (X25519) for secrets at rest
- **Session leases**: Agents must acquire time-bounded leases (max 24h, typically 1h). Leases have unique IDs and track client information
- **Killswitch**: `revoke --all` immediately invalidates all active leases. Optional cascading: rotate all secrets, wipe encrypted store
- **Heartbeat auto-killswitch**: Daemon contacts external endpoint; if unreachable, all leases auto-revoke
- `secrets exec` wraps subprocess execution with automatic environment loading and cleanup
- Append-only JSON Lines audit log

**Relevance to SIGIL**: The lease model is interesting -- rather than permanent access, secrets have TTL-bounded access windows. This limits the blast radius of compromise. SIGIL could adopt a similar model for high-sensitivity secrets.

GitHub: [joelhooks/agent-secrets](https://github.com/joelhooks/agent-secrets)

---

### 4.2 Sandbox Frameworks

#### Rivet Sandbox Agent (rivet-dev/sandbox-agent)
**Universal HTTP/SSE server for running and controlling AI coding agents in sandboxes.**

Supports Claude Code, Codex, OpenCode, Amp. Provides a unified API over the diverse agent interfaces (Claude Code uses JSONL over stdout, Codex uses JSON-RPC, OpenCode uses HTTP+SSE). 15MB static binary.

**Relevance**: Not a secret management tool, but demonstrates the pattern of wrapping diverse agents behind a universal interface. SIGIL's `sigil-shell` wrapper faces the same agent-fragmentation problem.

GitHub: [rivet-dev/sandbox-agent](https://github.com/rivet-dev/sandbox-agent)

#### agent-infra/sandbox
**All-in-one sandbox combining browser, shell, file, MCP, and VSCode server in a single Docker container.**

GitHub: [agent-infra/sandbox](https://github.com/agent-infra/sandbox)

#### kubernetes-sigs/agent-sandbox
**Kubernetes-based isolated workload management for AI agent runtimes.**

GitHub: [kubernetes-sigs/agent-sandbox](https://github.com/kubernetes-sigs/agent-sandbox)

#### nix-sandbox-mcp (SecBear/nix-sandbox-mcp)
**Sandboxed code execution for LLMs powered by Nix.**

Uses Nix's reproducible build system to create isolated execution environments. Relevant as an alternative isolation primitive.

GitHub: [SecBear/nix-sandbox-mcp](https://github.com/SecBear/nix-sandbox-mcp)

---

### 4.3 CI/CD Secret Management Patterns Adaptable to SIGIL

#### HashiCorp Vault Agent Injector
The Vault sidecar injector pattern is directly analogous to SIGIL's architecture:
- Kubernetes mutating admission webhook intercepts pod creation
- Init container pre-populates secrets to a shared tmpfs volume (`/vault/secrets`)
- Sidecar container keeps secrets updated during runtime
- Applications read secrets from files -- they are "Vault unaware"
- No application code changes required

**Adaptation for SIGIL**: Replace "pod" with "command execution", "admission webhook" with "PreToolUse hook", and "sidecar" with "sigild daemon". The principle is identical: inject secrets into the execution environment without the consumer needing to know about the secret store.

#### GitHub Actions Secret Masking
GitHub's approach: scan output for exact matches of registered secrets and replace with `***`. Key lessons for SIGIL:
- Exact match is necessary but insufficient
- Derived values (base64, substrings) are not automatically masked -- SIGIL must pre-compute encoding variants
- Structured data (JSON blobs) can cause masking to fail -- SIGIL should warn about structured secret values
- Register derived values: if a workflow generates a value from a secret, register it separately

#### Credential Broker Pattern (SPIFFE/SPIRE)
The emerging CI/CD pattern: SPIFFE-authenticated jobs request ephemeral credentials from a broker that evaluates policy before issuing time-bound access. Key properties:
- No static secrets in the environment
- Credentials tied to job identity and valid for minutes
- Not reusable outside approved scope
- Even if leaked, usefulness is severely limited

**Adaptation for SIGIL**: For backends that support it (Vault dynamic secrets, AWS STS), SIGIL could issue ephemeral credentials per command execution rather than using long-lived secrets. This drastically reduces the blast radius of any compromise.

---

### 4.4 Related Research

#### NVIDIA Sandboxing Guidance (2025)
Key recommendations directly applicable to SIGIL:
- Use virtualization (microVMs, Kata containers) for kernel isolation; shared-kernel solutions (Docker, bubblewrap) remain exposed to kernel vulnerabilities
- Start with minimal/empty credential sets; inject only task-specific secrets
- Use credential brokers providing short-lived tokens
- Sandbox ALL agentic operations, not just command-line invocations (including hooks and MCP startup scripts)
- Never cache or persist approvals -- each execution must be independently authorized
- Ephemeral sandboxes per execution; periodic environment recreation

Source: [NVIDIA Practical Security Guidance for Sandboxing Agentic Workflows](https://developer.nvidia.com/blog/practical-security-guidance-for-sandboxing-agentic-workflows-and-managing-execution-risk/)

#### GitHub Agentic Workflow Security Architecture (2026)
Key patterns:
- Zero secrets for agents (secrets in isolated API proxy, not agent container)
- Chroot jail with tmpfs overlays for writable surface
- Safe outputs system with deterministic content sanitization
- Comprehensive logging at every trust boundary

Source: [GitHub Blog: Security Architecture of Agentic Workflows](https://github.blog/ai-and-ml/generative-ai/under-the-hood-security-architecture-of-github-agentic-workflows/)

---

### 4.5 Gap Analysis: What Exists vs. What SIGIL Needs

```
Capability                    │ nono │ AgentSecrets │ agent-secrets │ SIGIL (needed)
──────────────────────────────┼──────┼──────────────┼───────────────┼──────────────
Kernel-level sandbox          │  Y   │      N       │       N       │      Y
Secret placeholder syntax     │  N   │      N       │       N       │      Y
Arbitrary command injection   │  N   │      N       │    Partial    │      Y
Output scrubbing              │  N   │   HTTP only  │       N       │      Y
Multi-encoding scrub          │  N   │      N       │       N       │      Y
File injection (certs, keys)  │  N   │      N       │       N       │      Y
Cross-harness compatibility   │  N   │   MCP only   │    CLI only   │      Y
Audit trail                   │  Y   │      Y       │       Y       │      Y
Lease/TTL model               │  N   │      N       │       Y       │      Y
Breach detection              │  N   │      N       │       N       │      Y
TUI for management            │  N   │      N       │       N       │      Y
Pluggable backends            │  N   │    Partial   │       N       │      Y
```

**Conclusion**: No existing project covers SIGIL's full scope. The closest are nono (for sandbox isolation), AgentSecrets (for zero-knowledge proxy architecture), and agent-secrets (for lease-based credential management). SIGIL combines and extends all three with the addition of arbitrary command secret injection, multi-encoding output scrubbing, file injection, and universal harness compatibility.
