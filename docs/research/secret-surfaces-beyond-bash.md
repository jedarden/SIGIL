# Secret Surfaces Beyond Bash Interception

An analysis of every pathway through which secrets appear in AI coding agent workflows, whether bash interception catches it, and what SIGIL must do to protect each surface.

---

## Executive Summary

Bash command interception covers approximately **30-40% of the attack surface** for secret exposure in AI coding agent workflows. The remaining 60-70% flows through channels that never touch a shell: direct filesystem writes via agent-native tools (Write, Edit), MCP tool calls with embedded credentials, code generation that hardcodes secrets into source files, git operations that commit secret-bearing files, and IDE configuration files that agents create or modify.

The core insight: **modern AI coding agents are not shell wrappers.** They are multi-tool systems where the shell is just one of 8-15 available tools. Claude Code has Read, Write, Edit, Glob, Grep, NotebookEdit, Bash, and MCP tools. Cursor uses the VS Code workspace edit API. Cline has `write_to_file` and `replace_in_file` that use VS Code's `WorkspaceEdit` API directly. None of these file operations go through bash.

SIGIL must protect all of these surfaces, not just the shell.

---

## Surface 1: File Operations (Write/Edit Tools)

### What Happens

AI coding agents write and edit files as their primary activity. They create configuration files (`.env`, `docker-compose.yml`, `terraform.tfvars`, `k8s-secrets.yaml`), source code files with connection strings, and scripts that embed credentials. Critically, most agents do this **without going through bash**.

### How Secrets Get There

1. **The agent generates code containing secrets.** The LLM produces a config file with a hardcoded API key because that is the simplest working solution. GitGuardian's 2026 report found AI-assisted commits leak secrets at a **3.2% rate, roughly 2x the baseline** of all public GitHub commits.

2. **The agent copies secrets from context.** If a secret value appears anywhere in the conversation (from command output, file contents, or user input), the LLM may reproduce it verbatim in a file write.

3. **The agent creates standard config files.** `.env`, `settings.json`, `config.yaml`, `docker-compose.yml` -- the agent writes what it knows the application needs, and for many applications that means database URLs, API keys, and tokens.

### Implementation Details Per Harness

**Claude Code:** The Write tool calls `fs.writeFileSync()` (or equivalent Node.js filesystem API) directly. The Edit tool performs string replacement via direct filesystem operations. Neither goes through bash. The system prompt explicitly instructs: "NEVER use bash for file operations (cat/head/tail, grep, find, sed/awk, echo >/cat <<EOF)." The tools are registered in `src/tools.ts` and execute as native Node.js filesystem calls within the Claude Code process.

**Cursor:** Uses the VS Code `vscode.workspace.applyEdit()` API via its "apply model" -- a custom fast-apply system for multi-file edits. File changes are applied through the VS Code workspace edit API, not through terminal commands.

**Cline:** Has two dedicated tools: `write_to_file` (create/overwrite) and `replace_in_file` (surgical edits using SEARCH/REPLACE blocks). These use `vscode.WorkspaceEdit` for atomic text replacements via the VS Code diff editor API with a custom URI scheme. No terminal involved.

**Aider:** Uses Python's native `open()` / `file.write()` to apply edits. The LLM returns diffs (unified diff, search/replace blocks, or whole-file format), and Aider's Python code applies them directly to the filesystem via its patching engine. No subprocess shell call.

**OpenHands:** The `FileWriteAction` and `FileEditAction` are distinct action types from `CmdRunAction`. File operations are handled by the agent runtime's file management API, not by shell commands.

### Does Bash Interception Catch This?

**No.** In every major harness, file write/edit operations bypass the shell entirely. A SIGIL PreToolUse hook on `"Bash"` will never fire for these operations.

### What SIGIL Needs

1. **PreToolUse hooks on Write and Edit tools** (Claude Code): Register matchers for `"Write|Edit|NotebookEdit"` in addition to `"Bash"`. The hook receives `tool_input.file_path` and `tool_input.content` (for Write) or `tool_input.new_string` (for Edit). SIGIL can scan the content for known secret patterns and block or sanitize.

   **Known bug (as of 2026):** Claude Code issue #13744 reports that PreToolUse hooks with exit code 2 properly block Bash operations but **do not block Write/Edit operations** -- the file is still created. SIGIL must account for this and may need a PostToolUse fallback that deletes or overwrites the file.

2. **Universal shell wrapper (`sigil-shell`)**: For harnesses without hook systems (Cursor, Aider, Windsurf), SIGIL cannot intercept Write/Edit tool calls. The only option is:
   - A filesystem-level watcher (inotify/fanotify on Linux, FSEvents on macOS) that monitors for secret patterns in newly written files
   - A Landlock or FUSE-based filesystem layer that intercepts all writes and scans content
   - Post-write scanning via git pre-commit hooks (catches at commit time, not write time)

3. **Content scanning in the scrub engine**: SIGIL's output scrubber must also function as an input scanner for file content. When the agent writes `API_KEY=sk-live-abc123...` to a file, SIGIL should detect the secret value and either block the write or replace it with `API_KEY={{secret:stripe/api_key}}`.

---

## Surface 2: Git Operations

### What Happens

Agents commit files (including files containing secrets), create branches, and push to remotes. Git operations are a two-stage problem: (1) the agent writes a secret-bearing file (Surface 1), then (2) the agent commits and pushes it.

### How Secrets Get There

1. **Direct commit of secret-bearing files**: The agent writes `.env`, `terraform.tfvars`, or a source file with an embedded API key, then runs `git add . && git commit -m "Add configuration"`. The secret is now in git history permanently.

2. **Git credentials**: `git push` requires authentication. Agents use credential helpers (`~/.gitconfig`), stored tokens (`~/.config/gh/hosts.yml`), or SSH keys (`~/.ssh/id_*`). These are typically pre-existing on the system, not injected by the agent.

3. **Accidental re-commit after rotation**: Even after a secret is rotated, if it exists in git history, it remains accessible via `git log -p` or by checking out old commits.

### Scale of the Problem

GitGuardian's 2026 State of Secrets Sprawl report:
- **28.65 million** new hardcoded secrets added to public GitHub in 2025
- **24,008** unique secrets found in MCP configuration files on public GitHub
- **2,117** of those were confirmed valid (live credentials in public repos)
- **64%** of secrets leaked in 2022 were still active in 2026
- AI-assisted commits leak at **2x the baseline rate**

### Does Bash Interception Catch This?

**Partially.** The `git add`, `git commit`, and `git push` commands go through bash and can be intercepted. However:
- The secret was already written to a file (Surface 1) before the git command runs
- Bash interception can block `git push` but the secret is already on disk and in git's local object store
- `git commit` via bash hook can be intercepted, but the agent might also configure git hooks or use library-level git operations

### What SIGIL Needs

1. **Pre-commit scanning**: SIGIL should integrate with or provide a git pre-commit hook that scans staged files for known secret values. This is defense-in-depth after Surface 1 controls.

2. **Push protection**: Block `git push` if the commit history contains any known secret values. GitHub's push protection (March 2026) now extends to AI coding agents via the GitHub MCP Server, but this is server-side. SIGIL needs client-side protection.

3. **Git credential isolation**: Git credentials (SSH keys, tokens) should not be accessible in the agent's filesystem namespace. In the bwrap sandbox, `~/.ssh`, `~/.config/gh`, and `~/.gitconfig` should be mounted read-only or replaced with SIGIL-managed credential proxies (similar to Claude Code web's git credential proxy).

4. **History scanning**: After agent sessions, scan recent commits for secret values. If found, trigger the breach detection workflow.

---

## Surface 3: HTTP/API Calls

### What Happens

Agents make HTTP requests to test APIs, download dependencies, interact with cloud services, and verify deployments. These happen through multiple channels.

### How Secrets Get There

1. **Bash-mediated HTTP**: `curl -H "Authorization: Bearer $TOKEN" https://api.example.com` -- the secret is in the command string.
2. **Code execution**: The agent writes and runs a Python script that uses `requests.get(url, headers={"Authorization": f"Bearer {token}"})`.
3. **MCP tools**: MCP servers like the GitHub MCP Server make HTTP requests with their own credentials, which are configured in the MCP server's `env` field.
4. **Built-in fetch tools**: Some harnesses have built-in web search or URL fetch tools that the LLM calls directly (not through bash).

### Does Bash Interception Catch This?

**Only channel 1.** Curl/wget/httpie commands go through bash. But:
- Channel 2 (code execution) involves the agent writing a script and then running `python script.py` via bash. SIGIL can intercept the `python` command but cannot easily parse the script to find secrets embedded in the Python code.
- Channel 3 (MCP tools) never touches bash at all.
- Channel 4 (built-in fetch) never touches bash.

### What SIGIL Needs

1. **Network egress control**: The bwrap sandbox with `--unshare-net` blocks all network access by default. Legitimate network access is proxied through a SIGIL-controlled gateway that can inspect and log requests, and strip or inject authorization headers.

2. **MCP tool interception**: PreToolUse hooks with `"mcp__.*"` matchers can intercept MCP tool calls. SIGIL should scan MCP tool arguments for secret values and block calls that would exfiltrate secrets.

3. **Script content analysis**: When the agent runs `python script.py` or `node app.js`, SIGIL should read the script file and scan for embedded secrets before allowing execution. This is a PreToolUse hook enhancement for Bash commands that execute interpreter+script patterns.

---

## Surface 4: Database Operations

### What Happens

Agents write ORM configurations, database migration files, connection string configurations, and directly execute SQL commands.

### How Secrets Get There

1. **Connection strings in code**: `DATABASE_URL=postgres://user:password@host:5432/db` in `.env`, `config.py`, `application.properties`, etc. (Surface 1 overlap)
2. **Direct CLI usage**: `mysql -u root -pSECRET_PASSWORD -h hostname` via bash
3. **Migration tool configs**: Prisma's `schema.prisma`, Django's `settings.py`, Rails' `database.yml` -- all contain connection details
4. **ORM initialization code**: The agent writes `sqlalchemy.create_engine("postgres://user:pass@host/db")` directly in source

### Does Bash Interception Catch This?

**Only channel 2** (direct CLI commands). Connection strings in code files (channels 1, 3, 4) go through Write/Edit tools and bypass bash entirely.

### What SIGIL Needs

1. **File write scanning** (Surface 1 controls): Detect connection string patterns (URI schemes like `postgres://`, `mysql://`, `mongodb://`, `redis://`) with embedded credentials in file writes
2. **Bash command scanning**: Detect `-p` password flags, connection URIs in command arguments, and environment variable patterns in database CLI commands
3. **Placeholder support for connection strings**: Allow `DATABASE_URL={{secret:db/connection_string}}` in files the agent writes, with SIGIL resolving at runtime

---

## Surface 5: Cloud Provider Interactions

### What Happens

Agents interact with cloud providers through CLI tools (aws, gcloud, az), Infrastructure-as-Code tools (Terraform, Pulumi, CDK), and SDK usage in generated code.

### How Secrets Get There

1. **CLI commands**: `aws s3 ls`, `gcloud compute instances list` -- these read credentials from well-known paths (`~/.aws/credentials`, `~/.config/gcloud/`)
2. **IaC configuration**: Terraform `terraform.tfvars` with `aws_access_key = "AKIA..."`, Pulumi config with plaintext secrets
3. **IaC state files**: Terraform state (`terraform.tfstate`) contains every resource attribute including passwords, tokens, and keys **in plaintext**
4. **SDK code**: The agent writes `boto3.client('s3', aws_access_key_id='AKIA...')` in Python source
5. **kubectl**: Kubernetes operations may reference kubeconfig files with embedded tokens or certificates

### Does Bash Interception Catch This?

**Channels 1 and 5** go through bash. Channels 2-4 are file operations (Surface 1). Channel 4 is code generation.

### What SIGIL Needs

1. **Credential file isolation**: `~/.aws/`, `~/.config/gcloud/`, `~/.azure/`, `~/.kube/` should be outside the agent's filesystem namespace. Cloud CLI credentials should be injected via SIGIL-managed environment variables or credential proxies.
2. **Terraform state protection**: `terraform.tfstate` and `.terraform/` must be treated as secret-bearing files. The agent should never be able to `cat terraform.tfstate` or read it via the Read tool.
3. **IaC file scanning**: Scan `*.tfvars`, `*.auto.tfvars`, `pulumi.*.yaml` for embedded credentials in Write/Edit operations.
4. **Cloud SDK pattern detection**: Detect patterns like `aws_access_key_id=`, `AKIA[A-Z0-9]{16}`, GCP service account JSON structure in both code files and command arguments.

---

## Surface 6: Docker/Container Operations

### What Happens

Agents create Dockerfiles, docker-compose files, build containers, and push to registries.

### How Secrets Get There

1. **Dockerfile ENV/ARG instructions**: `ENV API_KEY=sk-live-...` bakes the secret into the image layer permanently
2. **docker build --build-arg**: `docker build --build-arg SECRET=value .` -- visible in build history
3. **docker run -e**: `docker run -e API_KEY=secret my-image` -- visible in `docker inspect`
4. **docker-compose.yml environment section**: Inline secrets in `environment:` block
5. **Container registry auth**: `docker login` stores credentials in `~/.docker/config.json`
6. **docker-compose secrets**: Proper Docker secrets referenced via `secrets:` top-level key, but agents rarely use this pattern

### Does Bash Interception Catch This?

**Channels 2, 3** (bash commands) are caught. **Channels 1, 4** (file writes) are not. **Channel 5** (`docker login` via bash) is caught, but `~/.docker/config.json` is a file the agent could also read.

### What SIGIL Needs

1. **Dockerfile scanning**: Detect `ENV`, `ARG` directives with known secret values in Write/Edit operations
2. **docker-compose scanning**: Detect inline environment variables with secret values
3. **Build arg interception**: When the agent runs `docker build --build-arg`, SIGIL should detect secret values in build args and suggest `--secret` (BuildKit secrets) instead
4. **Registry credential isolation**: `~/.docker/config.json` must be outside the agent's filesystem namespace
5. **Image layer scanning**: Post-build, scan image layers for embedded secrets (this is beyond SIGIL's scope but worth noting)

---

## Surface 7: Package Manager Operations

### What Happens

Agents configure package managers for publishing (npm, PyPI, cargo, Docker Hub) and install private packages that require authentication.

### How Secrets Get There

1. **Auth config files**: `.npmrc` with `//registry.npmjs.org/:_authToken=npm_...`, `.pypirc` with `password:`, `~/.cargo/credentials.toml`
2. **Publish commands**: `npm publish`, `twine upload`, `cargo publish` -- these read auth from config files
3. **Private registry URLs**: `npm install @company/private-pkg --registry=https://user:token@registry.company.com`
4. **Lock files**: In rare cases, lock files can contain registry URLs with embedded tokens

### Does Bash Interception Catch This?

**Channels 2, 3** (bash commands) are caught. **Channel 1** (config file creation) is not if done via Write/Edit tools.

### What SIGIL Needs

1. **Auth config file isolation**: `.npmrc`, `.pypirc`, `~/.cargo/credentials.toml` should be outside the agent's writable namespace. SIGIL can inject scoped auth files via tmpfs for specific publish operations.
2. **Publish command gates**: `npm publish`, `twine upload`, `cargo publish` should require explicit approval even in auto-approve mode, as they are irreversible operations that may expose secrets.
3. **Registry URL scanning**: Detect `user:token@` patterns in registry URLs in both commands and config files.

---

## Surface 8: SSH/Remote Operations

### What Happens

Agents use SSH for remote command execution, SCP/rsync for file transfer, and SSH tunnels for port forwarding.

### How Secrets Get There

1. **SSH key access**: The agent reads `~/.ssh/id_ed25519` or `~/.ssh/id_rsa` to use for authentication
2. **SSH commands with passwords**: `sshpass -p 'password' ssh user@host` (rare but possible)
3. **SSH config**: `~/.ssh/config` may contain `IdentityFile` paths and proxy configurations
4. **Known hosts**: `~/.ssh/known_hosts` reveals infrastructure topology (not a secret per se, but sensitive)
5. **SSH agent forwarding**: If `SSH_AUTH_SOCK` is inherited, the agent has access to all keys loaded in the SSH agent

### Does Bash Interception Catch This?

**SSH commands** go through bash and are caught. But the underlying issue is filesystem access: the agent can **read** SSH keys via the Read tool without any bash involvement.

### What SIGIL Needs

1. **SSH directory isolation**: `~/.ssh/` must be outside the agent's filesystem namespace entirely
2. **SSH agent socket isolation**: `SSH_AUTH_SOCK` must not be set in the agent's environment. If SSH access is needed, SIGIL should provide a restricted SSH agent that only permits specific operations.
3. **SSH proxy model**: Similar to Claude Code web's git credential proxy -- SIGIL provides an SSH proxy that authenticates with keys the agent never sees.

---

## Surface 9: IDE/Editor Integration

### What Happens

Agents create and modify IDE configuration files that may contain secrets: VS Code `settings.json`, `launch.json`, `.env` files referenced by debug configurations, and extension settings.

### How Secrets Get There

1. **launch.json environment variables**: Debug configurations with `"env": {"API_KEY": "sk-live-..."}` for running applications during development
2. **settings.json**: Extension-specific settings that require API keys (e.g., `"claude.apiKey"`, `"github.token"`)
3. **tasks.json**: Build/run tasks with embedded environment variables
4. **Extensions**: VS Code extensions may store credentials in their own config files within `~/.vscode/` or workspace `.vscode/`

### Does Bash Interception Catch This?

**No.** These are file writes through Write/Edit tools or the IDE's native API. No bash involved.

### What SIGIL Needs

1. **VS Code config scanning**: Detect secret patterns in `.vscode/*.json` files during Write/Edit operations
2. **Environment block scanning**: Specifically scan `"env"` and `"environment"` JSON objects in launch/task configurations for secret values
3. **Extension config isolation**: Extension configuration directories should be considered sensitive and monitored for credential patterns

---

## Surface 10: MCP Tool Calls

### What Happens

MCP (Model Context Protocol) servers extend agent capabilities. Agents call MCP tools to interact with databases, APIs, cloud services, and other systems. MCP servers need credentials to authenticate with these services.

### How Secrets Get There

1. **MCP server `env` configuration**: Secrets are passed to MCP server processes via environment variables configured in `mcp.json` / `.claude/mcp.json`:
   ```json
   {
     "mcpServers": {
       "stripe": {
         "command": "npx",
         "args": ["stripe-mcp-server"],
         "env": { "STRIPE_SECRET_KEY": "sk_live_..." }
       }
     }
   }
   ```
   These configuration files are frequently committed to version control. GitGuardian found **24,008 unique secrets in MCP configuration files** on public GitHub, with 2,117 confirmed valid.

2. **MCP tool arguments**: The agent passes secrets as arguments to MCP tools. For example, calling a database MCP tool with a connection string, or an HTTP MCP tool with an Authorization header.

3. **MCP tool responses**: Tool responses may contain secrets -- a "get config" tool might return database credentials, a "list secrets" tool returns secret values, etc.

4. **Prompt injection via MCP responses**: A compromised MCP server can return adversarial prompts that instruct the agent to exfiltrate secrets. The SANDWORM_MODE attack (2025-2026) deployed rogue MCP servers via malicious npm packages that instructed agents to read SSH keys, AWS credentials, and `.env` files.

### Does Bash Interception Catch This?

**No.** MCP tool calls are a completely separate tool pathway from Bash. The agent emits a `tool_use` block with `tool_name: "mcp__server__tool"` and the harness routes it to the MCP server process via stdio/SSE, never touching a shell.

### What SIGIL Needs

1. **MCP tool call interception**: Claude Code supports PreToolUse hooks with `"mcp__.*"` matchers. SIGIL must register hooks that scan MCP tool arguments for secret values and block calls that would pass secrets to untrusted MCP servers.

2. **MCP configuration protection**: The `mcp.json` file should never contain plaintext secrets. SIGIL should:
   - Provide a `sigil-mcp` wrapper (like Astrix's MCP Secret Wrapper) that pulls secrets from the vault at MCP server startup
   - Support `{{secret:path}}` syntax in MCP `env` fields, resolved by SIGIL before the server process starts
   - Scan `mcp.json` for plaintext secrets and warn/block

3. **MCP response scrubbing**: PostToolUse hooks for MCP tools can use `updatedMCPToolOutput` (Claude Code supports this) to scrub secret values from MCP tool responses before the LLM sees them. This is the **only** PostToolUse output modification that Claude Code currently supports.

4. **MCP server sandboxing**: MCP server processes should run in their own isolated environment with only the secrets they need, preventing a compromised MCP server from accessing credentials belonging to other servers.

5. **SIGIL as an MCP server**: SIGIL itself should expose `sigil_list`, `sigil_exec`, and `sigil_status` as MCP tools. This gives agents a sanctioned channel for secret-bearing operations: instead of writing `API_KEY=sk-live-...` in code, the agent calls `sigil_exec` with a `{{secret:path}}` reference.

---

## Surface 11: Agent-to-Agent Communication

### What Happens

Modern agent architectures involve multi-agent systems where a parent agent delegates tasks to subagents, or multiple agents collaborate on shared tasks.

### How Secrets Get There

1. **Prompt inheritance**: When a parent agent spawns a subagent, it provides a task description that may include context containing secrets. If the parent's conversation history includes secret values (from command output, file reads, etc.), it might include them in the subagent prompt.

2. **Shared filesystem**: In Claude Code's worktree-based multi-agent system, agents share a git repository. If one agent writes a secret to a file, other agents can read it.

3. **Message passing**: Claude Code's Agent Teams feature uses `SendMessage` for typed inter-agent messaging. Message content could include secrets from one agent's context.

4. **Task context**: `TaskCreate` with dependency tracking means task descriptions accumulate context from completed tasks, potentially including secret values.

5. **NEEDLE-style orchestration**: Systems where a dispatcher creates workspace contexts for workers -- if the workspace context includes any secret material, all workers inherit it.

### Does Bash Interception Catch This?

**No.** Subagent spawning, message passing, and task creation are internal harness operations that never go through bash.

### Claude Code Subagent Context

Per the documentation, subagents inherit only: (1) the prompt string from the parent, (2) the system prompt from its markdown file, (3) environment details (cwd, platform), and (4) listed skills. They do **not** inherit conversation history, prior tool calls, or other subagents' outputs. This is a partial mitigation -- secrets can only reach subagents if the parent explicitly includes them in the prompt string.

### What SIGIL Needs

1. **Prompt scanning**: SIGIL should scan prompts passed to subagents for known secret values. This requires a SubagentStart hook (Claude Code supports this event).

2. **Shared filesystem controls**: In multi-agent scenarios, the shared filesystem should have the same secret-scanning protections as single-agent mode.

3. **Message content scanning**: For Agent Teams, SIGIL should intercept SendMessage calls and scan content for secret values.

---

## Surface 12: LLM API Calls

### What Happens

The harness itself makes API calls to LLM providers (Anthropic, OpenAI, etc.) using API keys. The agent may also write code that calls LLM APIs.

### How Secrets Get There

1. **Harness API keys**: `ANTHROPIC_API_KEY`, `OPENAI_API_KEY` in the user's environment. These are used by the harness process, not by the agent's commands, but they exist in the environment.

2. **Agent-written AI code**: When the agent builds an AI application, it writes code containing `openai.OpenAI(api_key="sk-proj-...")` or similar. This is the most common AI-service credential leak vector -- up **81% year-over-year** per GitGuardian.

3. **MCP server API keys**: MCP servers that proxy LLM calls need their own API keys.

4. **Conversation context**: The entire conversation (including any secrets the agent has seen) is sent to the LLM API. If SIGIL fails to scrub a secret from command output, it will be sent to the LLM provider's servers as part of the next prompt.

### Does Bash Interception Catch This?

**Channel 1**: The harness API key is used internally, never via bash. **Channel 2**: Code files with embedded API keys are written via Write/Edit tools (not bash). **Channel 3**: MCP server config (not bash). **Channel 4**: Conversation context is entirely internal to the harness.

### What SIGIL Needs

1. **Harness API key isolation**: `ANTHROPIC_API_KEY` and similar should not be in the agent's environment. SIGIL should strip LLM provider API keys from the environment when setting up the agent's execution context.

2. **AI API key pattern detection**: Detect patterns like `sk-proj-`, `sk-ant-`, `AKIA`, `gsk_` in both file writes and command arguments.

3. **Conversation hygiene as ultimate defense**: Because the conversation itself is sent to the LLM provider, SIGIL's output scrubbing is the last line of defense. Any secret that makes it into the conversation context is effectively exfiltrated to the LLM provider's infrastructure.

---

## Surface Comparison Matrix

| # | Surface | Goes Through Bash? | Caught by Bash Interception? | Additional SIGIL Control Needed |
|---|---------|-------------------|------------------------------|--------------------------------|
| 1 | File Write/Edit (agent tools) | **No** | **No** | PreToolUse hooks on Write/Edit; filesystem-level scanning |
| 2 | Git operations | Partially (commands=yes, file content=no) | Partially | Pre-commit scanning, push protection, credential isolation |
| 3 | HTTP/API calls (curl) | Yes (curl/wget) | Yes | Network egress control in sandbox |
| 3b | HTTP/API calls (code execution) | Partially (interpreter launch=yes, request content=no) | No (secret in script, not command) | Script content analysis before execution |
| 3c | HTTP/API calls (MCP tools) | **No** | **No** | MCP tool argument scanning |
| 3d | HTTP/API calls (built-in fetch) | **No** | **No** | PreToolUse hooks on fetch tools |
| 4 | Database operations (CLI) | Yes | Yes | Connection string pattern detection |
| 4b | Database operations (config files) | **No** | **No** | File write scanning |
| 5 | Cloud provider CLI | Yes | Yes | Credential file isolation |
| 5b | Cloud provider IaC files | **No** | **No** | IaC file scanning, state file protection |
| 6 | Docker commands | Yes | Yes | Build arg scanning, Dockerfile ENV detection |
| 6b | Docker config files | **No** | **No** | Dockerfile/compose scanning in Write/Edit |
| 7 | Package manager commands | Yes | Yes | Publish command gating |
| 7b | Package manager config files | **No** | **No** | Auth config file scanning |
| 8 | SSH commands | Yes | Yes | SSH key/agent isolation |
| 8b | SSH key file access | **No** (via Read tool) | **No** | Filesystem namespace isolation |
| 9 | IDE config files | **No** | **No** | Config file scanning in Write/Edit |
| 10 | MCP tool calls | **No** | **No** | MCP argument/response scanning, config protection |
| 11 | Agent-to-agent communication | **No** | **No** | Prompt/message scanning, shared filesystem controls |
| 12 | LLM API calls | **No** | **No** | API key isolation, conversation hygiene |

**Bash interception catches 8 of 20 identified sub-surfaces (40%).**

---

## Priority Ranking for SIGIL Implementation

### Tier 1: Critical (must have for MVP)

1. **File Write/Edit interception** -- This is the single largest gap. The agent's primary activity is writing files, and most secret-bearing operations happen here. Claude Code's hook system supports `"Write|Edit"` matchers.

2. **MCP tool call interception** -- MCP is the fastest-growing agent capability and the least-protected channel. 88% of MCP servers require credentials, 53% use static secrets, and 79% pass keys via environment variables.

3. **Filesystem namespace isolation** -- Credential files (`~/.aws/`, `~/.ssh/`, `~/.docker/`, `~/.config/gh/`) must be inaccessible to the agent. This is a bwrap/sandbox configuration concern.

### Tier 2: Important (should have for v1.0)

4. **Git pre-commit scanning** -- Defense-in-depth for secrets that escape file-write scanning.

5. **MCP configuration protection** -- `{{secret:path}}` support in MCP `env` fields, or a wrapper like Astrix's MCP Secret Wrapper but vault-agnostic.

6. **Network egress control** -- Prevents exfiltration even if secrets leak into the agent's context.

7. **Script content analysis** -- When executing `python script.py`, scan the script for embedded secrets.

### Tier 3: Nice to have (v2.0+)

8. **Agent-to-agent prompt scanning** -- SubagentStart hook scanning.

9. **IDE config scanning** -- `.vscode/` file pattern detection.

10. **Docker/IaC specialized scanning** -- Dockerfile ENV, docker-compose, terraform.tfvars pattern detection.

11. **LLM API key isolation** -- Strip provider API keys from the agent's environment.

---

## Architectural Implications for SIGIL

### The Hook System Is Necessary But Not Sufficient

Claude Code's hook system is the most capable in the industry: it supports `PreToolUse` matchers for `"Bash"`, `"Write|Edit"`, and `"mcp__.*"`. This covers **most surfaces in Claude Code specifically**. But:

1. The Write/Edit blocking bug (#13744) means hooks may not reliably prevent file writes
2. No other harness has equivalent hook coverage (Cursor, Aider, Windsurf have zero hooks)
3. PostToolUse cannot modify Bash output -- only MCP output can be modified via `updatedMCPToolOutput`

### The Proxy Shell Is Necessary But Not Sufficient

`sigil-shell` as `$SHELL` catches all bash commands but misses everything else (file ops, MCP, agent-to-agent).

### The Correct Architecture Is Layered

```
Layer 4: Agent-level hooks (PreToolUse on all tools)    -- catches tool calls
Layer 3: Filesystem monitoring (inotify/fanotify/FUSE)  -- catches all file writes
Layer 2: Proxy shell (sigil-shell)                      -- catches all bash commands  
Layer 1: Namespace isolation (bwrap)                    -- prevents access to credentials
Layer 0: Network isolation (--unshare-net + proxy)      -- prevents exfiltration
```

Each layer catches what the layer above misses. No single layer is sufficient.

### SIGIL MCP Server as the Positive Path

Rather than only blocking secret exposure (negative path), SIGIL should provide a **positive path** for agents to work with secrets safely:

- `sigil_list` -- enumerate available secrets (names only, no values)
- `sigil_exec` -- execute a command with secret injection and output scrubbing
- `sigil_write` -- write a file with `{{secret:path}}` placeholders resolved at runtime
- `sigil_env` -- set environment variables with secret values for the current sandbox session

This gives agents a sanctioned channel for secret operations, reducing the temptation to hardcode values.

---

## Sources

- [Claude Code Hooks Guide](https://code.claude.com/docs/en/hooks-guide)
- [Claude Code Tools Reference](https://callsphere.tech/blog/claude-code-tool-system-explained)
- [Internal Claude Code Tools Implementation](https://gist.github.com/bgauryy/0cdb9aa337d01ae5bd0c803943aa36bd)
- [PreToolUse hooks with exit code 2 don't block Write/Edit operations - Issue #13744](https://github.com/anthropics/claude-code/issues/13744)
- [Cline Tools Reference Guide](https://docs.cline.bot/exploring-clines-tools/cline-tools-guide)
- [Cline File Operations (DeepWiki)](https://deepwiki.com/cline/cline/8.1-file-operations)
- [Aider Edit Formats](https://aider.chat/docs/more/edit-formats.html)
- [Code Surgery: How AI Assistants Make Precise Edits to Your Files](https://fabianhertwig.com/blog/coding-assistants-file-edits/)
- [GitGuardian State of Secrets Sprawl 2026](https://blog.gitguardian.com/the-state-of-secrets-sprawl-2026/)
- [29 Million Secrets Leaked on GitHub Last Year](https://dev.to/mistaike_ai/29-million-secrets-leaked-on-github-last-year-ai-coding-tools-made-it-worse-2a42)
- [Astrix State of MCP Server Security 2025](https://astrix.security/learn/blog/state-of-mcp-server-security-2025/)
- [Astrix MCP Secret Wrapper](https://github.com/astrix-security/mcp-secret-wrapper)
- [MCP Security Vulnerabilities Guide 2026](https://aembit.io/blog/the-ultimate-guide-to-mcp-security-vulnerabilities/)
- [GitHub MCP Server: Secret Scanning](https://github.blog/changelog/2026-03-17-secret-scanning-in-ai-coding-agents-via-the-github-mcp-server/)
- [Claude Code Subagents Documentation](https://code.claude.com/docs/en/sub-agents)
- [Claude Code Orchestrator: Inter-Agent Communication](https://www.morphllm.com/claude-orchestrator)
- [MCP Authentication in Cursor](https://www.truefoundry.com/blog/mcp-authentication-in-cursor-oauth-api-keys-and-secure-configuration)
- [Why Your AI Agents Shouldn't Have Your API Keys](https://dev.to/lucamorettibuilds/why-your-ai-agents-shouldnt-have-your-api-keys-and-what-to-do-about-it-1a8n)
- [Docker Compose Secure AI Coding Agents](https://www.docker.com/blog/cerebras-docker-compose-secure-ai-coding-agents/)
- [Claude Code Sandboxing (Anthropic Engineering)](https://www.anthropic.com/engineering/claude-code-sandboxing)
