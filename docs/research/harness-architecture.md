## 1. Claude Code (Anthropic CLI)

### Command Execution Model

Claude Code executes shell commands through a dedicated **Bash tool**. When the LLM decides to run a command, it emits a tool-use block with `tool_name: "Bash"` containing `command`, `description`, `timeout`, and `run_in_background` fields. The harness passes this to the host shell (configurable, defaults to `bash`). Output (stdout/stderr combined) is captured and returned to the model as a tool result.

Commands run directly on the host OS with the user's full environment -- there is no sandboxing, containerization, or filesystem virtualization. The working directory persists between tool calls but shell state (variables, aliases) does not.

### Hook Points and Extension Mechanisms

Claude Code has the most mature hook system of any harness surveyed. Hooks are user-defined shell commands, HTTP endpoints, LLM prompts, or subagents that fire at 24 lifecycle events:

**Tool-related events (most relevant for SIGIL):**

| Event | Timing | Can Block? |
|---|---|---|
| `PreToolUse` | Before any tool executes | Yes |
| `PostToolUse` | After successful tool execution | No (tool already ran) |
| `PostToolUseFailure` | After failed tool execution | No |
| `PermissionRequest` | When permission dialog would appear | Yes |
| `PermissionDenied` | When auto-mode denies a tool call | No |

**Other notable events:** `SessionStart`, `UserPromptSubmit`, `Stop`, `SubagentStart/Stop`, `TaskCreated/Completed`, `InstructionsLoaded`, `ConfigChange`, `FileChanged`, `WorktreeCreate/Remove`, `PreCompact/PostCompact`, `Elicitation/ElicitationResult`, `SessionEnd`.

**Configuration format** (in `.claude/settings.json` or `~/.claude/settings.json`):

```json
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "Bash",
        "hooks": [
          {
            "type": "command",
            "if": "Bash(git *)",
            "command": "/path/to/script.sh",
            "timeout": 30,
            "statusMessage": "Validating..."
          }
        ]
      }
    ]
  }
}
```

**Hook handler types:**
- `command` -- runs a shell script, receives JSON on stdin, communicates via exit codes and stdout JSON
- `http` -- POSTs event JSON to a URL endpoint
- `prompt` -- single-turn LLM evaluation returning yes/no
- `agent` -- spawns a subagent with tool access (Read, Grep, Glob) to verify conditions

**Matchers** are regex patterns on tool name (e.g., `"Bash"`, `"Edit|Write"`, `"mcp__.*"`). The `if` field provides finer-grained filtering using permission-rule syntax like `Bash(rm *)`.

### Where Secret Injection Could Happen (Pre-Execution)

**PreToolUse hook with `updatedInput`** is the primary injection point. A PreToolUse hook can intercept any Bash tool call, inspect the command, and return modified input:

```json
{
  "hookSpecificOutput": {
    "hookEventName": "PreToolUse",
    "permissionDecision": "allow",
    "updatedInput": {
      "command": "AWS_SECRET_ACCESS_KEY=XXXX aws s3 ls"
    }
  }
}
```

The harness replaces the original command with the `updatedInput.command` value before execution. This is the ideal injection point -- the secret never appears in the LLM context, only in the executed command.

**SessionStart hook with `CLAUDE_ENV_FILE`** is another option. During `SessionStart` and `CwdChanged` events, hooks receive a `CLAUDE_ENV_FILE` path. Writing `export VAR=value` lines to this file persists environment variables for subsequent Bash tool calls:

```bash
#!/bin/bash
if [ -n "$CLAUDE_ENV_FILE" ]; then
  echo 'export DATABASE_URL=postgres://...' >> "$CLAUDE_ENV_FILE"
fi
```

### Where Output Scrubbing Could Happen (Post-Execution)

**PostToolUse hook** fires after the tool completes. The hook receives `tool_response` containing the command output. For MCP tools, the response can be replaced via `updatedMCPToolOutput`. For built-in tools like Bash, the hook can log/alert but **cannot modify** the response that goes back to the model.

This is a gap: PostToolUse cannot scrub secrets from Bash output before the LLM sees them. A SIGIL layer would need to wrap the command itself (via PreToolUse input modification) to pipe output through a scrubber, or operate at a lower level.

### Existing Secret Management

None built-in. Environment variables from the user's shell profile are inherited. The `CLAUDE_ENV_FILE` mechanism is the closest thing to managed secret injection, but it has no encryption, rotation, or access control.

### Permission/Approval Model

Three-tier: **default** (ask for each potentially dangerous action), **auto** (pre-approved patterns via allowlists in settings), and **dangerously skip permissions** (flag). Permission rules use tool-name + argument patterns:

```json
{
  "permissions": {
    "allow": [
      "Bash(npm test)",
      "Bash(git *)",
      "Read(*)"
    ],
    "deny": [
      "Bash(rm -rf *)"
    ]
  }
}
```

Settings cascade: managed policy > user settings > project settings > local settings.

---

## 2. Cursor

### Command Execution Model

Cursor is a full fork of VS Code. Its AI agent (Composer/Agent mode) executes terminal commands by spawning them in Cursor's integrated terminal. The agent has direct access to the terminal process, can send commands, read output, and react to errors. Commands run in the user's native shell environment with no isolation layer.

Starting in 2026, Cursor also offers a CLI mode (`cursor-cli`) that brings agent capabilities to the terminal outside the IDE.

### Hook Points and Extension Mechanisms

Cursor's extensibility is primarily through:

**Rules files** (`.cursor/rules/*.mdc`): MDC-format files that inject instructions into the model's system prompt. These influence behavior but do not intercept execution.

**MCP servers** (`.cursor/mcp.json` or `~/.cursor/mcp.json`): External tools exposed to the agent via Model Context Protocol. MCP tools require approval by default, with an `alwaysAllow` option per tool.

```json
{
  "mcpServers": {
    "my-server": {
      "command": "node",
      "args": ["server.js"],
      "env": { "API_KEY": "..." }
    }
  }
}
```

**VS Code extension API**: Since Cursor is a VS Code fork, extensions can hook into terminal events, though this is not an official agent extension point.

**AGENTS.md**: A repo-root file providing instructions to the agent, similar to `.cursor/rules/` but using a simpler format.

There is **no PreToolUse/PostToolUse hook system** equivalent to Claude Code's. Cursor has no mechanism for external scripts to intercept, modify, or block tool calls programmatically.

### Where Secret Injection Could Happen

**MCP server environment variables**: The `env` field in MCP server config can pass secrets to MCP tool processes, but this does not affect Bash commands.

**Shell profile**: Secrets in `.bashrc`/`.zshrc` are inherited by the terminal. This is the only current path for injecting secrets into agent-executed commands.

**VS Code extension**: A custom extension could intercept terminal creation or command sending, but this is fragile and not officially supported for agent integration.

### Where Output Scrubbing Could Happen

**No built-in mechanism.** Terminal output flows directly back to the model. A VS Code extension could theoretically intercept terminal output streams, but there is no official API for this in the agent pipeline.

### Existing Secret Management

None. Cursor relies entirely on the user's shell environment and any secrets already present in environment variables or credential files.

### Permission/Approval Model

**Default mode**: Agent asks permission before running terminal commands. User clicks "Run" to approve each command.

**YOLO mode** (`Settings > Features > Yolo mode`): Auto-approves terminal commands. Supports allowlist patterns:

```json
{
  "allowedCommands": ["npm run test", "npm run lint", "git *"]
}
```

Commands not matching the allowlist still require approval even in YOLO mode. There is no denylist -- unlisted commands simply fall back to manual approval.

---

## 3. Aider

### Command Execution Model

Aider is a terminal-based pair-programming tool. It executes shell commands through two mechanisms:

1. **`/run <command>` slash command**: Runs a command and optionally adds output to chat context
2. **`!<command>` prefix**: Shorthand for `/run`, executes directly via `run_cmd()` utility

The LLM can also **suggest** shell commands (controlled by `--suggest-shell-commands` flag, default True), which the user can then approve and execute.

Commands execute via Python's subprocess in the user's shell with full access to the host environment. Output (stdout + stderr) is captured and can be appended to the conversation history as a user/assistant message pair.

Additionally, Aider supports:
- **`--test-cmd`**: Commands run automatically after code changes (`AIDER_TEST_CMD` env var)
- **`--lint-cmd`**: Language-specific lint commands run after changes (`AIDER_LINT_CMD` env var)
- **`--auto-test` / `--auto-lint`**: Toggle automatic execution of test/lint after each edit

### Hook Points and Extension Mechanisms

Aider has **no formal hook or plugin system**. The extension points are limited to:

- **Configuration files**: `.aider.conf.yml` in project root, `~/.aider.conf.yml` globally
- **Test/lint commands**: These are the closest thing to hooks -- they execute automatically after code changes and their output is fed back to the model
- **`--notifications-command`**: A custom command for notifications (not for command interception)
- **Scripting mode**: Aider can be driven programmatically via stdin, enabling wrapper scripts

```yaml
# .aider.conf.yml
test-cmd: "pytest"
lint-cmd: "python: ruff check"
auto-test: true
auto-lint: true
suggest-shell-commands: true
```

### Where Secret Injection Could Happen

**Environment variables only.** Since Aider spawns commands via subprocess, secrets in the shell environment are inherited. There is no pre-execution hook to inject secrets programmatically.

A wrapper script driving Aider in scripting mode could potentially intercept and modify commands before they reach the shell, but this would be fragile.

### Where Output Scrubbing Could Happen

**No mechanism.** Command output goes directly into the chat history. The `run_cmd()` function captures stdout/stderr and appends it without any filtering pipeline.

A wrapper approach: run Aider inside a modified shell where a custom function intercepts command output, but this is outside Aider's architecture.

### Existing Secret Management

None. Aider stores API keys in environment variables or `.env` files but has no secret injection or scrubbing features for the commands it executes.

### Permission/Approval Model

**LLM-suggested commands require user confirmation** -- the user must explicitly run them. The `/run` and `!` commands are user-initiated, so there is no approval gate (the user is already approving by typing the command).

Auto-test and auto-lint commands run without additional approval after each code edit.

---

## 4. GitHub Copilot CLI

### Command Execution Model

GitHub Copilot CLI (GA February 2026) is an agent-based terminal tool. It plans and executes multi-step tasks directly in the terminal, including reading files, running shell commands, and chaining operations. Commands execute in the user's native shell.

The agent uses specialized sub-agents for different task types: **Explore** (codebase analysis), **Task** (builds/tests), **Code Review**, and **Plan** (implementation planning). The agent delegates to these automatically.

### Hook Points and Extension Mechanisms

Copilot CLI has a hook system modeled after Claude Code's, plus a plugin system:

**Hook configuration** (`.github/hooks/*.json`):

```json
{
  "version": 1,
  "hooks": {
    "preToolUse": [
      {
        "type": "command",
        "bash": "./scripts/pre-tool-policy.sh",
        "powershell": "./scripts/pre-tool-policy.ps1",
        "cwd": ".github/hooks",
        "timeoutSec": 10
      }
    ],
    "sessionStart": [...],
    "userPromptSubmitted": [...]
  }
}
```

**Hook types:** `sessionStart`, `userPromptSubmitted`, `preToolUse`. No postToolUse hook exists.

**preToolUse input** (JSON on stdin):
```json
{
  "toolName": "bash",
  "toolArgs": "{\"command\":\"git status\"}"
}
```

**preToolUse can deny** by outputting:
```json
{
  "permissionDecision": "deny",
  "permissionDecisionReason": "Blocked by policy"
}
```

Exit code 0 with no permission decision output implicitly allows. Hooks run synchronously and block execution.

**Plugin system**: Plugins installed via `/plugin install owner/repo` can bundle MCP servers, agents, skills, and hooks. Plugins discovered at every directory level from CWD to git root.

**Custom instructions**: `.github/copilot-instructions.md` provides natural-language guidance injected into prompts.

### Where Secret Injection Could Happen

**preToolUse hook**: Could inspect `toolArgs` and modify the command before execution (if the hook can return modified arguments -- the current documentation shows deny/allow but not input modification, unlike Claude Code).

**Plugin MCP servers**: A plugin could expose a "get-secret" MCP tool that the agent calls before executing commands requiring credentials.

**Shell environment**: Standard environment variable inheritance.

### Where Output Scrubbing Could Happen

**No postToolUse hook exists**, so there is no mechanism to scrub output after command execution. The preToolUse hook documentation explicitly recommends "Avoid logging secrets or credentials" and shows patterns for redacting sensitive data in log files, but this is for audit logging, not for scrubbing model-visible output.

### Existing Secret Management

None built-in. The hook documentation warns against logging `ghp_`, `gho_`, `ghu_`, `ghs_` (GitHub token prefixes), Bearer tokens, and password flags, suggesting awareness of the problem but no automated solution.

### Permission/Approval Model

**Directory trust**: The agent cannot access files outside explicitly trusted directories. Trust is established per-directory.

**Operational modes**: Default requires approval for file operations and commands. **Autopilot mode** lets the agent work autonomously. Granular patterns can auto-approve specific operations.

**MCP server trust**: Servers from `.mcp.json`, `.vscode/mcp.json`, and `devcontainer.json` only load after folder trust confirmation. Organization-level allowlists can restrict third-party MCP servers.

---

## 5. Windsurf (Codeium / Cognition AI)

### Command Execution Model

Windsurf is a VS Code fork (formerly Codeium, acquired by Cognition AI in December 2025 for ~$250M). Its AI agent **Cascade** executes terminal commands through a dedicated terminal instance. On macOS (Wave 13+), this is a separate terminal from the default that exclusively uses `zsh` and inherits `.zshrc` configuration.

Cascade has "flow awareness" -- it tracks files edited, terminal commands run, clipboard contents, and conversation history to infer intent. The agent can run commands, read output, detect errors, and iterate.

### Hook Points and Extension Mechanisms

**No hook system.** Windsurf has no equivalent to Claude Code's PreToolUse/PostToolUse hooks. Extension is limited to:

**Rules files**: `.windsurfrules` at repo root and `.windsurf/rules/` directory provide behavioral instructions (not execution interception).

**MCP servers**: Standard MCP configuration with `disabled` and `alwaysAllow` options per tool.

**.codeiumignore files**: Control which files Cascade can view or edit, but does not affect terminal commands.

**Enterprise admin controls**: Team-wide allowlists/denylists for terminal commands, max auto-execution level enforcement.

### Where Secret Injection Could Happen

**Shell environment only.** Since the dedicated terminal inherits `.zshrc`, secrets in the shell profile are available. No programmatic injection point exists.

**MCP server**: A custom MCP server could expose a secret-retrieval tool, but secrets would then appear in the conversation context.

### Where Output Scrubbing Could Happen

**No mechanism.** Terminal output goes directly back to Cascade. No interception layer exists.

### Existing Secret Management

None.

### Permission/Approval Model

Four-level auto-execution hierarchy:

| Level | Behavior |
|---|---|
| **Disabled** | All commands require manual approval |
| **Allowlist Only** | Commands matching `windsurf.cascadeCommandsAllowList` auto-execute; others need approval |
| **Auto** | Cascade determines safety; risky commands still need approval (premium feature) |
| **Turbo** | All commands auto-execute except those in `windsurf.cascadeCommandsDenyList` |

**Denylist always wins**: If a command matches both allowlist and denylist, approval is required.

Enterprise admins can set the maximum auto-execution level organization-wide and configure team-wide allow/deny lists.

---

## 6. Cline (formerly Claude Dev)

### Command Execution Model

Cline is a VS Code extension (also available as standalone CLI) that executes terminal commands through the VS Code terminal API. The **ToolExecutor** dispatches tool-use blocks across four domains: file operations, terminal commands, browser automation (Puppeteer), and MCP tools.

Commands execute in the **host environment's native shell** with no sandboxing. The `HostProvider` singleton abstracts platform-specific terminal APIs via `VscodeTerminalManager` (in VS Code) or `StandaloneTerminalManager` (CLI mode).

### Hook Points and Extension Mechanisms

**Hooks system** (enabled via `cline config`): Hooks fire at key workflow points, though the specifics of event types are less documented than Claude Code's.

**Command permissions** via `CLINE_COMMAND_PERMISSIONS` environment variable:
```json
{
  "allow": ["npm *", "git *", "pytest"],
  "deny": ["rm -rf *", "sudo *"],
  "allowRedirects": true
}
```
When `allow` is set, all commands not matching allow patterns are denied.

**.clinerules files**: Markdown files in `.clinerules/` directory (e.g., `01-coding-style.md`, `02-security-rules.md`) that guide agent behavior per workspace.

**MCP servers**: Configured in `~/.cline/data/settings/cline_mcp_settings.json`:
```json
{
  "mcpServers": {
    "my-server": {
      "command": "node",
      "args": ["server.js"],
      "env": { "KEY": "value" },
      "alwaysAllow": ["safe-tool"],
      "disabled": false
    }
  }
}
```

**Remote config**: `RemoteConfig` enforces organization-wide safety settings that override local preferences.

**.clineIgnore**: Blocks file reads/writes to specified paths (similar to `.gitignore` syntax).

### Where Secret Injection Could Happen

**CLINE_COMMAND_PERMISSIONS + wrapper**: The allow/deny pattern system could be combined with a command wrapper that injects secrets before execution, though this requires external tooling.

**MCP server**: A secret-management MCP server could provide credentials on demand.

**Shell environment**: Standard inheritance.

**Hooks** (if they support pre-execution modification): The hooks system could potentially intercept commands, but documentation on input modification is sparse.

### Where Output Scrubbing Could Happen

**Hooks** (if post-execution hooks exist): Could potentially process output before it reaches the model.

**No confirmed built-in mechanism** for output scrubbing. The `CommandPermissionController` validates commands pre-execution but does not filter output.

### Existing Secret Management

None built-in. The `CLINE_COMMAND_PERMISSIONS` system is for safety, not secrets.

### Permission/Approval Model

**Human-in-the-loop by default**: Every consequential action triggers `Task.ask()`, which suspends the agent loop and presents an approval dialog. The user must click approve before any file write, command execution, or browser action.

**Auto-approve settings** (fine-grained):
- Read files/directories
- Edit files
- Execute terminal commands
- Use browser
- Use MCP servers

**YOLO mode** (`-y` / `--yolo` flag or auto-approval settings): Bypasses approval for selected action types.

**Git checkpoints**: Automatic git snapshots enable diffing and rollback after agent actions.

---

## 7. Amazon Q Developer CLI

### Command Execution Model

Amazon Q Developer CLI (Rust-based, open source) provides an agentic chat experience in the terminal. It executes commands through built-in tools, with the primary tool being `execute_bash` for shell command execution.

For its cloud-hosted code generation feature, Amazon Q runs code in isolated Docker-based sandbox environments configured without credentials to access non-public internet resources. The local CLI, however, executes commands directly in the user's shell.

Note: As of early 2026, the `amazon-q-developer-cli` project has been deprecated in favor of **Kiro CLI**.

### Hook Points and Extension Mechanisms

**No hook system.** Amazon Q CLI does not provide PreToolUse/PostToolUse hooks or any script-injection mechanism.

**MCP servers**: Standard MCP configuration for extending tool capabilities.

**Devfiles**: For cloud execution environments, Devfiles model the configuration and dependencies, including curated shell command lists.

**Tool trust system** (see Permission Model below): The `/tools` command manages per-tool trust, which is the closest thing to an extension point.

### Where Secret Injection Could Happen

**Shell environment**: For local execution, standard environment variable inheritance.

**Sandbox environment variables**: For cloud sandbox execution, environment variables can be configured in the Devfile, but the sandbox is explicitly "configured without credentials to access non-public internet resources."

**MCP server**: A custom MCP tool could provide secrets on demand.

### Where Output Scrubbing Could Happen

**No mechanism.** Command output flows directly to the model.

### Existing Secret Management

The cloud sandbox model explicitly excludes credentials as a security measure. The local CLI has no secret management.

### Permission/Approval Model

**Tool-level trust**:
- **Trusted**: Tool executes without asking (only `fs_read` is trusted by default)
- **Per-request**: Tool asks for confirmation before each use (default for most tools)

**Management commands**:
- `/tools trust @mcp_name/tool_name` -- trust a specific tool
- `/tools trust-all` -- trust all tools (discouraged)
- `--trust-all-tools` CLI flag (security risk)
- `--trust-tools tool1,tool2` at session start

Permissions are session-scoped by default. Persistent tool permissions were added in July 2025 with the Custom Agents feature.

---

## 8. OpenHands (formerly OpenDevin)

### Command Execution Model

OpenHands is the only tool in this survey with **true sandbox isolation by default**. For each task session, it spins up a Docker container and runs all actions inside it. The architecture:

1. **Host controller** sends actions via an event stream
2. **REST API server** inside the Docker container receives action requests
3. **Actions execute** in the container's isolated environment
4. **Observations** flow back through the event stream

**Action types:**
- `CmdRunAction`: Executes bash commands via a persistent shell session inside the container
- `IPythonRunCellAction`: Runs Python code via a Jupyter server inside the container
- `BrowserInteractiveAction`: Browser automation via Playwright/Chromium inside the container

A configurable workspace directory is **mounted** into the container, giving the agent access to project files while isolating everything else.

### Hook Points and Extension Mechanisms

**Custom Docker images**: OpenHands installs its action execution API into any user-provided Docker image:
```toml
# config.toml [sandbox] section
[sandbox]
base_container_image = "my-custom-image:latest"
timeout = 120
```

**Runtime startup environment variables**: Inject variables into the sandbox at startup:
```toml
[sandbox]
runtime_startup_env_vars = { SECRET_KEY = "value", DB_URL = "postgres://..." }
```

**MCP servers**: Configurable in the settings UI or config:
```toml
[mcp.servers.my-server]
type = "stdio"
command = "node"
args = ["server.js"]
```

**Condenser strategies**: Control how conversation history is compressed (relevant for context management but not secret handling).

**Security analyzer**: Optional security analysis of agent actions:
```toml
[security]
confirmation_mode = true
security_analyzer = "default"
```

**V1 SDK architecture**: The refactored V1 provides composable packages (`agent`, `tool`, `workspace`) with clear boundaries and opt-in sandboxing, making it possible to build custom execution pipelines.

### Where Secret Injection Could Happen

**`runtime_startup_env_vars`** is the primary injection point. Secrets set here are available inside the sandbox but never appear in the LLM conversation context:

```toml
[sandbox]
runtime_startup_env_vars = { AWS_ACCESS_KEY_ID = "AKIA...", AWS_SECRET_ACCESS_KEY = "..." }
```

**Custom Docker image**: Bake secrets into the image (not recommended but possible).

**SANDBOX_VOLUMES**: Mount a secrets directory from the host into the container:
```
SANDBOX_VOLUMES="/host/secrets:/container/secrets:ro"
```

### Where Output Scrubbing Could Happen

**Custom Docker image with wrapper**: The action execution API could be modified in a custom image to scrub output before sending observations back. This is the most architecturally clean approach but requires maintaining a fork.

**Event stream processing**: The V1 SDK's modular design could support middleware in the event stream pipeline, but this is not a built-in feature.

**Security analyzer**: The `confirmation_mode` and `security_analyzer` features could potentially be extended for output scrubbing, though their current focus is on action validation, not output filtering.

### Existing Secret Management

**`runtime_startup_env_vars`** is the closest to managed secret injection. The Docker isolation model inherently prevents secrets on the host from leaking into the sandbox unless explicitly mounted or injected.

The cloud-hosted variant (via Daytona) provides "Zero-Trust Security" where each execution environment is sandboxed.

### Permission/Approval Model

**Sandbox-first**: All actions execute inside Docker containers, providing OS-level isolation. The agent cannot escape the container.

**Confirmation mode**: When enabled, actions are presented for user approval before execution.

**Iteration limits**: Configurable maximum iterations prevent runaway agents:
```toml
[core]
max_iterations = 100
```

**File management**: The workspace mount is the only bridge between host and sandbox. The agent cannot access files outside the mounted directory.

---

## 9. SWE-agent / SWE-ReX

### Command Execution Model

SWE-agent uses **SWE-ReX** (SWE Runtime and Execution) as its execution backend. SWE-ReX provides a unified interface for running commands across multiple environments:

- **Docker containers** (default): Ephemeral containers per task
- **AWS Fargate**: Serverless container execution
- **Modal**: Serverless cloud functions
- **Local execution** (not recommended)
- **Daytona** (work in progress)

The architecture:
1. SWE-agent's `Agent.forward()` compresses history, prompts the LLM, and extracts actions
2. Actions are parsed and sent to `SWEEnv`, which manages the execution environment
3. SWE-ReX handles deployment, starts a shell session in the container, sends commands, and returns output + exit codes
4. Output becomes an observation appended to conversation context

SWE-ReX supports **multiple parallel shell sessions** (bash, ipython, gdb, etc.) and can detect when commands finish, extract output, and return exit codes.

**ACI (Agent Command Interface)**: Custom tools installed into the container shell, extending standard Unix commands with agent-friendly operations.

### Hook Points and Extension Mechanisms

**YAML configuration**: Agent behavior controlled via YAML config files:
```yaml
# agent config
env:
  deployment:
    type: docker
    image: "swe-agent-tiny"
    container_runtime: docker  # or podman
```

**Custom Docker images**: Build images with pre-installed dependencies and SWE-ReX:
```dockerfile
FROM ubuntu:24.10
RUN apt-get update && apt-get install -y nodejs npm
RUN pipx install swe-rex
```

**Pluggable deployment providers**: Extend SWE-ReX with custom environment backends beyond Docker/Modal/Fargate.

**History processors**: Custom compression strategies for managing conversation context.

**Custom tools via ACI**: Define additional command-line tools available to the agent inside the sandbox.

There is **no PreToolUse/PostToolUse hook system**. The action-observation loop is internal to the agent with no interception points exposed.

### Where Secret Injection Could Happen

**Docker image**: Bake environment variables or credential files into the custom Docker image.

**Environment variables in deployment config**: Pass environment variables to the container via deployment configuration:
```yaml
env:
  deployment:
    type: docker
    image: "my-image"
    env:
      SECRET_KEY: "value"
```

**Volume mounts**: Mount a host directory containing secrets into the container.

### Where Output Scrubbing Could Happen

**Custom ACI tools**: Wrap commands in a custom ACI tool that scrubs output before returning it to the agent.

**Custom deployment provider**: A custom SWE-ReX deployment backend could intercept command output in the communication layer between container and agent.

**No built-in mechanism** for output scrubbing.

### Existing Secret Management

None. The ephemeral container model provides implicit isolation (secrets on the host are not available in the container unless explicitly provided), but there is no managed secret injection or rotation.

### Permission/Approval Model

**Near-full autonomy by default**: Agents can run any shell command inside their sandbox without per-command approval. The isolation boundary is the container itself.

**Ephemeral containers**: Containers are created per task and destroyed afterward, preventing cross-task contamination.

**Optional human intervention**: Possible but not enforced -- the system is designed for autonomous operation.

**No network restrictions by default**: Containers typically have full network access (configurable via Docker networking).

---

## 10. Codex CLI (OpenAI)

### Command Execution Model

Codex CLI runs in interactive mode (full-screen TUI) or non-interactive mode (`codex exec`). Commands execute with **OS-native sandboxing**:

**macOS**: Seatbelt framework. Commands run via `sandbox-exec` with a profile matching the selected sandbox mode. The Seatbelt profile restricts file access, network access, and process capabilities at the kernel level.

**Linux**: Bubblewrap (`bwrap`) pipeline plus seccomp filters. If `bwrap` is available on PATH, it is used for filesystem sandboxing. Landlock is available as a fallback. The sandbox creates a restricted filesystem view where only the workspace and explicitly allowed paths are writable.

**Windows/WSL**: WSL inherits Linux sandbox semantics. Native Windows uses elevated/unelevated modes with proxy-only networking.

**Default restrictions**: No network access, write permissions limited to the workspace directory. Protected paths include `.git` (read-only), `.agents`, and `.codex` directories.

### Hook Points and Extension Mechanisms

**Hooks** (via `hooks.json`, currently under development):

```json
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "Bash",
        "hooks": [
          {
            "type": "command",
            "command": "/path/to/script.sh",
            "timeout": 600
          }
        ]
      }
    ],
    "PostToolUse": [...],
    "SessionStart": [...],
    "UserPromptSubmit": [...],
    "Stop": [...]
  }
}
```

Discovery locations: `~/.codex/hooks.json` and `<repo>/.codex/hooks.json`.

**PreToolUse** currently supports **Bash tool interception only**. It can return `permissionDecision: "deny"` to block commands. It supports `systemMessage` for injecting context but not `updatedInput` for modifying commands (unlike Claude Code).

**MCP servers** (in `config.toml`):
```toml
[mcp_servers.my-server]
command = "node"
args = ["server.js"]
env = { KEY = "value" }
enabled = true
enabled_tools = ["tool1"]
disabled_tools = ["tool2"]
startup_timeout_sec = 10
tool_timeout_sec = 60
```

**Custom slash commands**: Team-specific shortcuts stored on disk.

**Feature flags**: Managed via `codex features` subcommand (e.g., `unified_exec`, `multi_agent`, `web_search`, `shell_tool`, `smart_approvals`).

### Where Secret Injection Could Happen

**Sandbox writable_roots with mounted secrets**: Extend the sandbox to include a secrets directory:
```toml
[sandbox_workspace_write]
writable_roots = ["/home/user/.secrets"]
```

**MCP server environment**: Secrets in MCP server `env` config are available to MCP tools but not to Bash commands.

**PreToolUse hook**: Could potentially inject secrets by modifying the command (if `updatedInput` support is added -- currently not supported).

**config.toml permissions with filesystem access**:
```toml
[permissions.my-profile.filesystem]
"/path/to/secrets" = "read"
```

### Where Output Scrubbing Could Happen

**PostToolUse hook**: Can receive tool output and provide `additionalContext` feedback, but documentation does not confirm ability to modify/replace the output seen by the model.

**The sandbox itself**: Since commands run inside the sandbox, a wrapper script in the sandbox could pipe output through a scrubber before it reaches Codex's output capture.

### Existing Secret Management

**Network isolation is a form of secret protection**: By default, sandboxed commands cannot make network requests, preventing accidental exfiltration. Web search defaults to cached results from an OpenAI-maintained index to reduce prompt injection risk.

**Filesystem isolation**: The sandbox restricts file access, preventing the agent from reading credential files outside the workspace.

No active secret injection or rotation features.

### Permission/Approval Model

**Sandbox modes**:
| Mode | Filesystem | Network |
|---|---|---|
| `read-only` | Read-only everywhere | None |
| `workspace-write` (default) | Write in workspace + `writable_roots` | None by default |
| `danger-full-access` | Unrestricted | Full |

**Approval policies**:
| Policy | Behavior |
|---|---|
| `untrusted` | Auto-runs reads; approval for mutations |
| `on-request` (default) | Approval for out-of-scope ops |
| `never` | No approval prompts |
| `granular` | Selective: `sandbox_approval`, `rules`, `mcp_elicitations`, `request_permissions`, `skill_approval` |

**Network access** (configurable per sandbox mode):
```toml
[sandbox_workspace_write]
network_access = true
```

**Domain-level network control** (in permission profiles):
```toml
[permissions.web.network]
enabled = true
mode = "limited"
allowed_domains = ["api.example.com"]
denied_domains = ["evil.com"]
```

---

## Comparative Summary

### Hook/Interception Capabilities

| Tool | PreExec Hook | PostExec Hook | Can Modify Input | Can Modify Output | Hook Format |
|---|---|---|---|---|---|
| Claude Code | Yes (PreToolUse) | Yes (PostToolUse) | Yes (updatedInput) | MCP only (updatedMCPToolOutput) | JSON settings |
| Cursor | No | No | No | No | N/A |
| Aider | No | No | No | No | N/A |
| Copilot CLI | Yes (preToolUse) | No | No (deny only) | No | JSON in .github/hooks/ |
| Windsurf | No | No | No | No | N/A |
| Cline | Partial (hooks, sparse docs) | Partial | Unknown | Unknown | Env var + config |
| Amazon Q | No | No | No | No | N/A |
| OpenHands | No (but Docker isolation) | No | Via env vars | Via custom image | TOML config |
| SWE-agent | No | No | No | No | YAML config |
| Codex CLI | Yes (PreToolUse, Bash only) | Yes (PostToolUse) | No (deny only, no updatedInput) | Unknown | JSON hooks.json |

### Sandbox/Isolation Model

| Tool | Isolation | Mechanism |
|---|---|---|
| Claude Code | None | Host shell |
| Cursor | None | Host shell (VS Code terminal) |
| Aider | None | Host shell (subprocess) |
| Copilot CLI | Directory trust | Filesystem path restrictions |
| Windsurf | None | Host shell (dedicated terminal) |
| Cline | None | Host shell (VS Code terminal) |
| Amazon Q | Cloud sandbox available | Docker (cloud); host shell (local) |
| OpenHands | Full Docker isolation | Per-session Docker container |
| SWE-agent | Full Docker isolation | Ephemeral Docker via SWE-ReX |
| Codex CLI | OS-level sandbox | Seatbelt (macOS) / Bubblewrap+seccomp (Linux) |

### SIGIL Integration Feasibility

| Tool | Secret Injection Path | Output Scrubbing Path | Integration Difficulty |
|---|---|---|---|
| Claude Code | PreToolUse updatedInput (ideal) | PreToolUse command wrapping | Low -- hooks are purpose-built |
| Cursor | Shell env / VS Code extension | VS Code extension (fragile) | High -- no official hooks |
| Aider | Shell env / wrapper script | Wrapper script | High -- no extension points |
| Copilot CLI | preToolUse + MCP server | No viable path (no postToolUse) | Medium -- hooks exist but limited |
| Windsurf | Shell env / MCP server | No viable path | High -- no hooks |
| Cline | MCP server / env var permissions | Hooks (if supported) | Medium -- has some extension points |
| Amazon Q | MCP server / tool trust | No viable path | High -- no hooks, deprecated |
| OpenHands | runtime_startup_env_vars | Custom Docker image | Low -- Docker model is natural fit |
| SWE-agent | Docker env vars / custom image | Custom ACI tools | Medium -- requires image customization |
| Codex CLI | MCP server / config.toml | PreToolUse command wrapping | Medium -- hooks exist but immature |
