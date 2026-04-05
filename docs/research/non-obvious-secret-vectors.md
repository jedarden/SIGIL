# Non-Obvious Secret Leakage Vectors in AI Coding Agent Workflows

This document catalogs the subtle, easy-to-miss ways secrets flow through software development workflows when AI coding agents are involved. Each vector is analyzed for its mechanism, whether it is agent-initiated or incidental, whether bash-level interception would catch it, what SIGIL must do to defend against it, and its criticality.

---

## Table of Contents

1. [Secrets in Generated Code](#1-secrets-in-generated-code)
2. [Secrets in Context / Conversation](#2-secrets-in-context--conversation)
3. [Secrets in Error Messages](#3-secrets-in-error-messages)
4. [Secrets in Clipboard](#4-secrets-in-clipboard)
5. [Secrets in Browser / Web Tools](#5-secrets-in-browser--web-tools)
6. [Secrets in Logs](#6-secrets-in-logs)
7. [Secrets in Package Lock Files and Registry Configs](#7-secrets-in-package-lock-files-and-registry-configs)
8. [Secrets in Git History](#8-secrets-in-git-history)
9. [Secrets in Temporary Files](#9-secrets-in-temporary-files)
10. [Secrets That Leak Through Tool Outputs](#10-secrets-that-leak-through-tool-outputs)
11. [Secrets in MCP Configuration Files](#11-secrets-in-mcp-configuration-files)
12. [Secrets in Infrastructure-as-Code State](#12-secrets-in-infrastructure-as-code-state)
13. [Secrets in Docker Image Layers](#13-secrets-in-docker-image-layers)
14. [Secrets in CI/CD Pipelines](#14-secrets-in-cicd-pipelines)

---

## 1. Secrets in Generated Code

### How the secret gets there

AI coding agents generate source code that directly contains secret values. This happens because:

- **Training data patterns**: LLMs learned from millions of repositories that contain hardcoded secrets. When prompted to write API integrations, they reproduce the patterns they observed, including inline credentials. The model does not inherently understand the concept of "secrets" -- it mimics patterns from training data.
- **User-provided context**: A user says "use API key AKIA..." and the agent writes `aws_access_key_id='AKIA...'` into a Python file. The agent treats the credential as any other string literal.
- **Dockerfile generation**: An agent writes `ENV API_KEY=sk-live-abc123` or `ARG SECRET_TOKEN=...` in a Dockerfile. These persist in image layers forever (see Vector 13).
- **CI/CD config generation**: An agent writes `.github/workflows/deploy.yml` with hardcoded secrets instead of using `${{ secrets.API_KEY }}` references.
- **Terraform/K8s manifests**: An agent writes `access_key = "AKIA..."` in `.tf` files or `stringData: password: "hunter2"` in Kubernetes Secret manifests.
- **Configuration files**: An agent writes `application.properties` or `config.yaml` with database connection strings containing passwords.

### Scale of the problem

The data is alarming:

- **GitGuardian 2026 report**: 28.65 million hardcoded secrets were added to public GitHub in 2025, a 34% YoY increase. Claude Code co-authored commits leaked secrets at a rate of **3.2%** -- roughly **double the 1.5% human baseline**. At the August 2025 peak, Claude Code commits leaked 31 secrets per 1,000 commits (2.4x human baseline).
- **Copilot study**: GitHub Copilot produced approximately 3.0 valid secrets per prompt across 8,127 test cases -- not random strings, but actual working credentials from training data.
- **Vibe coding**: 1 in 5 "vibe-coded" websites exposes at least one sensitive secret. The Moltbook platform (built entirely via AI prompting with no security review) exposed 1.5 million API tokens, 35,000 user email addresses, and private messages via a hardcoded Supabase key in client-side JavaScript.
- **AI service credentials specifically** surged 81% YoY to 1,275,105 leaked, with 113,000 exposed DeepSeek API keys as a notable single-provider example.

### Agent-initiated or incidental?

**Agent-initiated.** The agent explicitly writes the secret into a file. This is the most direct form of leakage.

### Would bash interception catch it?

**No.** The secret is written via the `Edit` or `Write` tool, not a bash command. Even if the agent uses `cat <<EOF > file.py`, the secret is embedded in the file content, not in a command that SIGIL's pre-hook would naturally scan. The file write tools (Edit, Write) are separate tool types from Bash in most harnesses.

### What SIGIL must do

1. **File-write scanning**: SIGIL must hook not just `Bash` but also `Edit`, `Write`, and any file-modification tools. Every file write must be scanned for known secret values from the vault.
2. **Pattern-based detection**: Beyond exact-match scrubbing of known vault secrets, SIGIL should detect high-entropy strings and known secret patterns (AWS key prefixes `AKIA`, GitHub token prefixes `ghp_`/`gho_`/`ghs_`, JWT structures, private key headers `-----BEGIN RSA PRIVATE KEY-----`).
3. **Block-before-write**: If a secret is detected in a file being written, SIGIL should block the write and return an error to the agent suggesting it use a `{{secret:path}}` placeholder or environment variable reference instead.
4. **Dockerfile-specific rules**: Detect `ENV` and `ARG` instructions containing secret patterns and reject them, suggesting BuildKit `--mount=type=secret` instead.
5. **CI/CD template awareness**: Detect hardcoded values in `.github/workflows/*.yml`, `.gitlab-ci.yml`, `Jenkinsfile`, etc. and suggest `${{ secrets.NAME }}` or equivalent.

### Criticality: **HIGH**

This is the most common and well-documented vector. It is the primary way AI agents leak secrets today.

---

## 2. Secrets in Context / Conversation

### How the secret gets there

The agent's conversation history (context window) is itself a data store that persists for the duration of the session and may be transmitted, cached, or retained by the provider:

- **User tells the agent a secret**: "The database password is P@ssw0rd123" -- this is now in the context window for every subsequent tool call.
- **Command output contains a secret**: A command like `cat .env` or `env | grep API` returns secret values. If SIGIL's output scrubber misses even one occurrence, the secret enters the context permanently.
- **File reads expose secrets**: The agent reads `~/.aws/credentials`, `docker-compose.yml` with inline passwords, or `.env.production`. These go into context as tool results.
- **Error messages echo secrets**: A failed database connection prints `FATAL: password authentication failed for user "admin" with password "hunter2"` into the context.
- **Accumulated context over long sessions**: As sessions grow, the probability of a secret entering context through any vector increases monotonically.

### Where context content goes

This is the non-obvious part. Once a secret enters the context window, it flows to multiple destinations:

1. **Provider API servers**: Every API call sends the full (or compressed) conversation to the provider. Data is encrypted in transit via TLS but stored at rest on provider infrastructure.
2. **Retention periods**:
   - Anthropic (Claude Code): **30 days** for commercial users (Team/Enterprise/API). **5 years** if consumer users opt in to model improvement. Zero Data Retention available for Enterprise.
   - GitHub Copilot: Starting **April 24, 2026**, interaction data from Free/Pro/Pro+ users is used to train AI models by default. This includes "accepted or modified outputs, inputs and code snippets sent to Copilot, code context surrounding the cursor position." Business/Enterprise exempt.
   - OpenAI: Consumer ChatGPT data used for training by default. API data not used for training since March 2023, with 30-day retention.
3. **Telemetry services**: Claude Code sends operational metrics to Statsig and error logs to Sentry. The official docs state telemetry "does not include any code or file paths" but the `/feedback` command sends "a copy of their full conversation history including code" to Anthropic, retained for 5 years.
4. **Session logs**: Claude Code stores sessions locally for up to 30 days. These are on-disk, readable by any process running as the same user.
5. **Shared conversations**: Google can index ChatGPT shared conversation links. Developers who paste credentials while troubleshooting risk permanent public exposure.
6. **Training data**: For consumer tiers, conversation content may become part of future model training data, meaning a secret could be memorized and reproduced to other users.

### Agent-initiated or incidental?

**Both.** The user may explicitly share a secret ("the API key is..."), or the agent may incidentally cause a secret to enter context by reading a file or running a command whose output contains secrets.

### Would bash interception catch it?

**Partially.** SIGIL's post-execution scrubber can prevent secrets from entering context via command output. But it cannot prevent:
- The user typing a secret directly into the prompt
- Secrets entering via file reads (`Read` tool, not Bash)
- Secrets already in context from earlier in the session

### What SIGIL must do

1. **Comprehensive output scrubbing**: Every tool output -- not just Bash, but Read, Glob, Grep, and MCP tool responses -- must be scanned and scrubbed before entering the context.
2. **File-read interception**: When the agent reads a file known to contain secrets (`.env`, `credentials`, `config.json` with passwords), SIGIL should redact secret values and replace them with `{{secret:path}}` references.
3. **User education**: Warn users never to paste raw secret values into the prompt. Provide a TUI or command (`sigil add`) for importing secrets that stays outside the agent's context.
4. **Context window monitoring**: A background process could scan the running conversation for any known secret values and alert if one is detected.
5. **Provider selection guidance**: Document that commercial/API tiers with shorter retention and no-training policies are strongly preferred for security-sensitive work.

### Criticality: **HIGH**

The context window is the largest and most persistent attack surface. Once a secret enters context, SIGIL cannot remove it -- prevention is the only defense.

---

## 3. Secrets in Error Messages

### How the secret gets there

Application errors routinely echo sensitive configuration back to the caller. When an AI agent triggers these errors (often through trial-and-error development), the secrets enter both the command output and the agent's context:

- **Database connection failures**: `FATAL: password authentication failed for user "admin"` or `OperationalError: (psycopg2.OperationalError) could not connect to server... connection string: "postgresql://admin:s3cret@db.example.com:5432/mydb"`
- **API errors echoing request headers**: `401 Unauthorized: {"error": "Invalid API key", "request_headers": {"Authorization": "Bearer sk-live-abc123..."}}`
- **ORM/Framework stack traces**: A malformed POST request can trigger an unhandled exception that dumps internal paths, database schema, and configuration values. Django's debug mode, Rails' detailed errors, and Spring Boot's actuator endpoints are notorious for this.
- **Build tool errors**: `npm ERR! code E401` followed by the full `.npmrc` line containing `//registry.npmjs.org/:_authToken=npm_abc123...`
- **Docker build errors**: Failed builds that print the full `ENV` or `ARG` values in the error output.
- **AWS CLI errors**: Errors that include the access key ID being used: `An error occurred (AccessDenied) when calling the GetObject operation: User: arn:aws:iam::123456789012:user/deploy is not authorized...`

### Agent-initiated or incidental?

**Incidental.** The agent does not intend to extract the secret. It runs a command, the command fails, and the error message happens to contain a secret. This makes it particularly insidious because neither the agent nor typical secret-detection heuristics are looking for it.

### Would bash interception catch it?

**Partially.** SIGIL's post-execution output scrubber can catch known secret values in error output. But it requires:
- The scrubber knowing all secret values that might appear (it must have the vault loaded)
- The scrubber recognizing secrets even in partial or encoded form (URL-encoded connection strings, base64-encoded headers)
- Error messages from non-Bash tools (Python tracebacks in a Read output, for instance) also being scrubbed

### What SIGIL must do

1. **Aggressive output scrubbing**: The scrubber must handle all known vault secrets in any encoding: raw, URL-encoded, base64-encoded, and quoted/escaped variants.
2. **Pattern-based scrubbing**: Beyond exact matches, detect and redact connection strings (`postgresql://`, `mongodb://`, `redis://` with embedded credentials), Authorization headers, and high-entropy strings in error contexts.
3. **Connection string parsing**: Specifically parse and redact the password component of database connection URIs, even for secrets not in the vault.
4. **Stack trace filtering**: Detect stack traces (by pattern: file paths + line numbers + exception names) and apply aggressive redaction to any variable values printed within them.
5. **Debug mode detection**: Warn when the agent enables debug/verbose modes (`DEBUG=true`, `--verbose`, `FLASK_DEBUG=1`) that are likely to produce secret-containing output.

### Criticality: **HIGH**

Error messages are one of the most common incidental leakage vectors. Every developer has seen a connection string in a stack trace. The agent encounters these constantly during iterative development.

---

## 4. Secrets in Clipboard

### How the secret gets there

- **Agent suggests clipboard operations**: An agent may generate `echo "sk-live-abc123" | pbcopy` or suggest the user copy a value.
- **User copies secrets from password managers**: Users copy passwords to clipboard to paste into the agent prompt or a config file. Clipboard managers (macOS Clipboard History, Windows Clipboard History, third-party tools like Alfred, CopyClip) may persist these values on disk indefinitely.
- **Agent has direct clipboard access**: Some agents (Windsurf/Cascade tracks clipboard contents as part of its "flow awareness") can read clipboard contents, meaning a secret copied from a password manager enters the agent's context without any command execution.
- **Cross-application leakage**: On older Android (pre-10) and some desktop OSes, any application can read the clipboard silently. Clipboard monitoring malware specifically targets copied passwords.

### Agent-initiated or incidental?

**Mostly incidental.** The user copies a secret for their own purposes, but it becomes accessible to the agent through clipboard integration or through the user pasting it into the prompt.

### Would bash interception catch it?

**No.** Clipboard operations are not bash commands (except explicit `pbcopy`/`xclip` calls, which would be caught). The agent reading clipboard state through its IDE integration is invisible to SIGIL's command hooks.

### What SIGIL must do

1. **Clipboard isolation**: In the sandbox environment, remove or neuter clipboard access (`xclip`, `xsel`, `pbcopy`, `pbpaste`). Block clipboard-related X11/Wayland protocols.
2. **Agent-specific mitigations**: For Windsurf/Cascade, document that clipboard flow-awareness is a secret leakage vector and recommend disabling it.
3. **User guidance**: Educate users to never copy secrets to clipboard when an agent session is active. Recommend using SIGIL's TUI for secret entry instead.
4. **Clipboard scrubbing**: If clipboard access cannot be blocked, implement a clipboard monitor that detects and clears secret-like values from the clipboard after a short timeout (similar to how password managers clear clipboard after 30 seconds).

### Criticality: **MEDIUM**

The risk depends heavily on the specific agent's clipboard integration. Most CLI-based agents (Claude Code, Aider) do not read the clipboard, but IDE-based agents (Windsurf, Cursor) may. The user-initiated clipboard copy is harder to prevent.

---

## 5. Secrets in Browser / Web Tools

### How the secret gets there

AI agents with browser automation capabilities (Playwright MCP, Puppeteer, browser-use) interact with web pages and need credentials to log in:

- **Login form filling**: The agent needs to log into a web service. The credentials must somehow reach the browser. If they pass through the LLM's context (e.g., user says "log in with username admin and password P@ss"), the secret is exposed.
- **Browser local storage / cookies**: After login, session tokens, JWTs, and cookies are stored in browser state. If the agent can inspect local storage or cookies, these become visible.
- **Screenshots capturing sensitive pages**: Agents with screenshot capabilities (Cline's browser tool, Playwright MCP) may capture pages that display API keys, tokens, or account settings.
- **Browser DevTools exposure**: Agents using Chrome DevTools Protocol (CDP) can access network requests, including Authorization headers, cookie values, and request/response bodies containing secrets.
- **Autofill data**: Browser autofill may populate forms with saved credentials, which the agent can then read from the DOM.

### The Cerberus pattern

A documented mitigation (from the Cerberus project) demonstrates the correct architecture: the LLM writes `{{password}}` placeholders in browser automation instructions. An MCP server running locally intercepts these, fetches credentials from a local Vaultwarden vault, and injects real values directly into the browser via CDP. The LLM never sees the actual credentials.

This is exactly the SIGIL model applied to browser automation.

### Agent-initiated or incidental?

**Both.** The agent explicitly requests login actions (initiated), but may also incidentally capture secrets through screenshots, DOM inspection, or network monitoring.

### Would bash interception catch it?

**No.** Browser automation happens through MCP tools or dedicated browser tools, not bash commands. The credential flow goes through CDP/WebSocket, completely outside the shell.

### What SIGIL must do

1. **Browser MCP integration**: Provide a SIGIL-aware browser automation MCP server (or middleware) that handles credential injection via the Cerberus pattern -- placeholders in, real values injected at the CDP layer, never through the LLM context.
2. **Screenshot scrubbing**: If the agent takes screenshots, scan them for secret-like patterns (using OCR or known page layouts) before they enter context. This is expensive but necessary for high-security environments.
3. **Network request filtering**: If the agent has access to network logs (CDP Network domain), scrub Authorization headers and cookie values.
4. **DOM access controls**: Restrict the agent's ability to read password-type input fields, local storage entries containing tokens, and cookie values.

### Criticality: **HIGH** (for agents with browser capabilities)

Browser automation is a rapidly growing agent capability. The Playwright MCP server is one of the most popular MCP tools. Without credential isolation, every login action leaks credentials.

---

## 6. Secrets in Logs

### How the secret gets there

Applications, containers, and systems generate logs that routinely contain secrets:

- **Application startup logs**: Many frameworks print their configuration on startup, including database URLs, API endpoints with keys, and feature flags with secret values. Spring Boot's `--debug` flag dumps the entire environment. Express apps commonly log their configuration object.
- **Docker container logs**: `docker logs <container>` shows stdout/stderr, which often includes startup configuration. Over 10,000 Docker Hub images were found leaking credentials in their layer metadata, and container logs are equally exposed.
- **Kubernetes pod logs**: `kubectl logs <pod>` exposes application logs. Pods that log environment variables on startup expose every secret mounted via `envFrom`.
- **systemd journal**: `journalctl -u <service>` shows service logs, which may include command-line arguments containing secrets (e.g., `ExecStart=/usr/bin/myapp --db-password=hunter2`).
- **Agent session transcripts**: Claude Code stores sessions locally for up to 30 days. These contain every command, its output, and all conversation text. Any secret that entered the session is preserved on disk in plaintext.
- **Debug/verbose mode logs**: When an agent enables debug mode to troubleshoot an issue, log verbosity increases dramatically, often including request/response bodies with credentials.

### Agent-initiated or incidental?

**Incidental in most cases.** The agent runs `docker logs` or `kubectl logs` to debug an issue and receives secret-containing output it did not request. However, it can also be **agent-initiated** when the agent explicitly enables debug mode or reads log files.

### Would bash interception catch it?

**Partially.** Commands like `docker logs`, `kubectl logs`, `journalctl`, and `cat /var/log/*` go through bash and their output can be scrubbed by SIGIL's post-execution hook. But:
- Log files read via the `Read` tool bypass bash
- Application logs appearing in real-time terminal output during `docker compose up` are harder to intercept
- Agent session logs on disk are outside SIGIL's purview

### What SIGIL must do

1. **Scrub outputs from log-reading commands**: Recognize `docker logs`, `kubectl logs`, `journalctl`, `tail -f`, and `cat` on log file paths as high-risk commands and apply aggressive scrubbing.
2. **Hook all tool types**: Ensure log files read via `Read`/`Grep` tools are also scrubbed, not just bash output.
3. **Session log protection**: If SIGIL cannot prevent the agent harness from writing session logs, it should at minimum ensure that scrubbed values (replaced with `[REDACTED:secret_name]`) are what appear in logs, not the raw secrets.
4. **Startup log awareness**: Detect application startup patterns and warn when debug/verbose modes are enabled.

### Criticality: **HIGH**

Logs are one of the most overlooked secret repositories. The combination of "debug an issue by reading logs" (extremely common in development) and "logs contain startup configuration with secrets" (extremely common in practice) makes this a frequent and dangerous vector.

---

## 7. Secrets in Package Lock Files and Registry Configs

### How the secret gets there

Package manager configuration and lock files can embed authentication credentials:

- **npm `.npmrc`**: Contains registry auth tokens in the format `//registry.npmjs.org/:_authToken=npm_abc123...`. Users configure this for private registries and forget it exists. If committed to a repo, the token is leaked.
- **npm `package-lock.json`**: When generated with a private registry configured, the lock file embeds the registry URL (which may contain credentials in the URL, e.g., `https://__token__:npm_abc@registry.example.com/`).
- **pip `requirements.txt`**: Private package index URLs with credentials: `--extra-index-url https://__token__:pypi_abc@private.pypi.example.com/simple/`. The `pip-compile` tool outputs these to compiled requirements files.
- **pip `pip.conf`**: Contains `index-url` with embedded credentials.
- **Cargo `.cargo/config.toml`**: Private registry tokens: `[registries.my-registry]\ntoken = "cargo_abc123"`.
- **Bundler `.bundle/config`**: Contains credentials for private gem servers.
- **Go `GONOSUMCHECK` / `GOFLAGS`**: Credentials for private modules embedded in environment or `.netrc`.
- **Maven `settings.xml`**: Contains repository credentials in the `<servers>` section.

### Agent-initiated or incidental?

**Incidental in most cases.** The agent runs `npm install` or `pip install` and the package manager generates a lock file containing registry credentials. The agent did not intend to expose the credential; it is a side effect of the package manager's behavior.

Can also be **agent-initiated** if the agent writes a `.npmrc` or `pip.conf` with hardcoded credentials when configuring a private registry.

### Would bash interception catch it?

**Partially.** If the agent runs `npm install` via bash, SIGIL could theoretically scrub the `.npmrc` token from any output. But the real danger is the credential being written to a file (lock file, config file) that is then committed to git. The bash hook cannot prevent a package manager from writing credentials to its own config files.

### What SIGIL must do

1. **File-write monitoring**: Watch for writes to `.npmrc`, `pip.conf`, `.cargo/config.toml`, `settings.xml`, `.bundle/config`, and `.netrc`. Scan these for embedded credentials.
2. **Lock file scanning**: After `npm install`, `pip-compile`, `cargo update`, etc., scan the generated lock files for credential patterns before the agent can commit them.
3. **Registry credential isolation**: Registry auth tokens should be in SIGIL's vault and injected via environment variables or temporary config files that are cleaned up, never written to persistent project files.
4. **Git pre-commit integration**: SIGIL could provide a git pre-commit hook that blocks commits containing registry tokens.

### Criticality: **MEDIUM**

This is less likely to be caught by general secret-detection because lock files and package manager configs are considered "auto-generated" and often excluded from review. The tokens are long-lived and have broad access to the registry.

---

## 8. Secrets in Git History

### How the secret gets there

Even if the current state of a repository is clean, secrets may persist in historical commits:

- **Previous commits**: A developer (or agent) committed a secret, then removed it in a subsequent commit. The secret remains in `git log -p`, `git show <old-commit>`, and `git diff <old>..<new>`.
- **Reflog**: Even after `git rebase` or `git commit --amend` removes a secret from the visible branch history, the old commits remain in `.git/refs/reflog` for at least 90 days (default `gc.reflogExpire`).
- **Agent reads git history**: The agent runs `git log -p`, `git show`, or `git diff` to understand code changes. Historical secrets in the diff output enter the agent's context.
- **Force-push does not help**: Force-pushing a cleaned branch only updates the remote ref. Anyone who cloned before the push retains the old commits. GitHub/GitLab also cache old commit objects.
- **git remote URLs**: `.git/config` may contain remote URLs with embedded tokens: `url = https://ghp_abc123@github.com/user/repo.git`. The agent running `git remote -v` exposes this.

### Agent-initiated or incidental?

**Incidental in most cases.** The agent reads git history as a normal part of understanding codebase evolution. It does not intend to extract secrets from old commits.

### Would bash interception catch it?

**Partially.** Commands like `git log -p`, `git show`, `git diff`, and `git remote -v` go through bash. SIGIL's output scrubber can catch known vault secrets in the output. However:
- The scrubber must know about historical secrets that may no longer be in the current vault
- The output of `git log -p` can be very large, making efficient scanning important
- Git data read via the `Read` tool on `.git/` files bypasses bash

### What SIGIL must do

1. **Scrub git command outputs**: Apply standard scrubbing to output from all git commands, particularly `git log`, `git show`, `git diff`, `git remote -v`, and `git config --list`.
2. **Historical secret tracking**: Maintain a "revoked secrets" list in the vault -- secrets that are no longer active but should still be scrubbed from output if encountered.
3. **Remote URL protection**: Detect and redact tokens in git remote URLs. Recommend using credential helpers instead of URL-embedded tokens.
4. **Reflog access restriction**: In the sandbox, consider making `.git/logs/` read-only or scrubbing its contents.
5. **Pre-push scanning**: Optional integration with gitleaks or trufflehog as a pre-push hook.

### Criticality: **MEDIUM**

The risk is primarily to historical secrets that should have been rotated. Current secrets are unlikely to be in git history if SIGIL is working. But the agent reading old diffs is a common workflow, and 64% of leaked secrets remain valid years after exposure (GitGuardian 2026).

---

## 9. Secrets in Temporary Files

### How the secret gets there

Multiple processes create temporary files that may contain secrets:

- **Build artifacts in `/tmp`**: Build processes, test runners, and CI scripts write intermediate files to `/tmp` or build cache directories. These may contain resolved configuration with secrets.
- **Editor swap/backup files**: Vim creates `.swp` files, Emacs creates `~` backup files, and various editors create `.bak` files. If a user (or agent) edits a file containing secrets, the swap file contains those secrets and may persist after a crash.
- **IDE temporary files**: VS Code, JetBrains IDEs, and others create workspace state files, search indexes, and cache files that may contain snippets of secret-bearing files.
- **Core dumps**: If a process handling secrets crashes, the core dump (if enabled) contains the process memory, including any secrets held in memory. Core dumps are typically written to `/tmp`, `/var/crash/`, or the current directory.
- **tmpfs-mounted files**: Even "secure" temporary files on tmpfs are accessible to any process running as the same user. If the SIGIL daemon writes secrets to tmpfs for injection, the agent's bash process (running as the same user) can read them.
- **Python `__pycache__`**: Compiled Python files cache constants, which may include hardcoded secrets.
- **npm/yarn cache**: Package managers cache downloaded packages, which may include `.npmrc` tokens in cached metadata.

### Agent-initiated or incidental?

**Incidental.** The agent does not create these files directly; they are side effects of editors, build tools, and the OS.

### Would bash interception catch it?

**No.** Temporary files are created by other processes, not by the agent's bash commands. The agent could later read them (`cat /tmp/build-config.json`), and that command would be intercepted, but the file's existence is the vulnerability.

### What SIGIL must do

1. **Sandbox isolation**: The bwrap sandbox should restrict `/tmp` access. Mount a private tmpfs for the sandboxed command so it cannot read the host's `/tmp`.
2. **Secret file cleanup**: When SIGIL writes secrets to temporary files for injection (e.g., certificates that must be at a file path), use:
   - `O_TMPFILE` for anonymous temporary files where supported
   - `memfd_create()` + `/proc/self/fd/N` for in-memory file descriptors
   - Immediate `unlink()` after opening
   - `flock()` to prevent concurrent reads
3. **Core dump prevention**: Set `PR_SET_DUMPABLE=0` on the SIGIL daemon process. In the sandbox, disable core dumps via `ulimit -c 0` and set `/proc/sys/kernel/core_pattern` to empty (or restrict via bwrap).
4. **Swap file awareness**: In documentation, warn users about editor swap files. Optionally, detect `.swp`, `~`, `.bak` files in the workspace and warn if they might contain secrets.

### Criticality: **MEDIUM**

The risk depends on the environment. In a well-configured sandbox, temporary file exposure is minimal. Without sandboxing, it is a realistic vector for secret exfiltration by a sophisticated agent.

---

## 10. Secrets That Leak Through Tool Outputs

### How the secret gets there

Common developer tools expose secrets as a side effect of their normal operation. An agent running routine diagnostic commands gets secret values in the output:

| Command | What it exposes |
|---------|----------------|
| `git remote -v` | Remote URLs that may contain tokens (`https://ghp_abc@github.com/...`) |
| `git config --list` | Credential helper configurations, sometimes cached tokens |
| `docker inspect <container>` | All environment variables, including injected secrets |
| `docker compose config` | Resolved docker-compose.yml with interpolated env vars |
| `kubectl describe pod <pod>` | Environment variables from configmaps and (non-opaque) secrets |
| `kubectl get secret <name> -o yaml` | Base64-encoded secret values (trivially decoded) |
| `terraform show` | Full state including all resource attributes, including passwords and keys |
| `terraform output` | Output values that may include secrets |
| `npm config list` | Registry tokens from `.npmrc` |
| `aws configure list` | Shows credential sources; for temporary credentials, may show cached access key and secret key |
| `aws sts get-caller-identity` | Shows account ID and ARN (useful for enumeration, though not a secret per se) |
| `env` / `printenv` / `set` | All environment variables, including secrets |
| `cat /proc/self/environ` | Process environment (NUL-delimited) |
| `heroku config` | All Heroku environment variables |
| `vercel env pull` | Downloads all environment variables to `.env` |
| `fly secrets list` | Lists secret names (not values, but reveals what exists) |
| `gcloud auth print-access-token` | Prints an OAuth2 access token |
| `az account get-access-token` | Prints an Azure access token |
| `vault kv get secret/myapp` | Prints secret values from HashiCorp Vault |

### Agent-initiated or incidental?

**Usually incidental.** The agent runs `docker inspect` to debug a container issue or `kubectl describe pod` to check pod status. It does not realize these commands expose secrets. Sometimes **agent-initiated** when the agent explicitly runs `env` or reads credential files to understand the environment.

### Would bash interception catch it?

**Yes** -- this is the vector SIGIL is best equipped to handle. All of these are bash commands whose output flows through the post-execution scrubber. The challenge is comprehensiveness: SIGIL must know which commands produce secret-containing output and scrub accordingly.

### What SIGIL must do

1. **Command-aware scrubbing**: Maintain a list of high-risk commands (`docker inspect`, `kubectl describe`, `terraform show`, `env`, etc.) and apply aggressive scrubbing to their output.
2. **Structural scrubbing**: For structured outputs (JSON from `docker inspect`, YAML from `kubectl get`), parse the structure and redact values of keys known to contain secrets (`password`, `token`, `secret`, `key`, `credential`, `auth`).
3. **Base64 detection**: Detect base64-encoded values in `kubectl get secret` output and decode them for scrubbing before re-encoding.
4. **Command blocking**: Optionally block commands like `env`, `printenv`, `cat /proc/*/environ` entirely, since these serve no purpose other than environment enumeration.
5. **Terraform state protection**: Block `terraform show` and `terraform state show` when they would expose plaintext secrets. Suggest `terraform output -json` with sensitive outputs marked.

### Criticality: **HIGH**

This is the vector SIGIL is explicitly designed to address, and it is extremely common. Agents run diagnostic commands constantly. Without scrubbing, every `docker inspect` or `kubectl describe` is a potential leak.

---

## 11. Secrets in MCP Configuration Files

### How the secret gets there

The Model Context Protocol ecosystem has created a new, systemic vector for secret leakage:

- **Plaintext in config files**: The standard MCP configuration pattern places API keys directly in JSON config files: `~/.config/Claude/claude_desktop_config.json`, `.cursor/mcp.json`, `~/.claude/mcp.json`. These are plaintext on the filesystem.
- **Environment variables in MCP server configs**: `"env": { "API_KEY": "sk-live-abc123" }` in MCP server definitions. These are passed to the MCP server process as environment variables and are readable by any same-user process.
- **Documentation encourages unsafe patterns**: Official MCP documentation and community tutorials recommend hardcoding API keys directly into configuration. GitGuardian found **24,008 unique secrets** in MCP configuration files on public GitHub, with **2,117 confirmed as valid live credentials**.
- **MCP servers can read all credentials**: Any MCP server process receives all environment variables from its configuration, meaning a malicious MCP server gets every credential configured for every other server in the same config file.
- **No sandbox for MCP servers**: Claude Desktop and most agents run MCP servers with full user privileges and no sandbox. A single-line Python script can steal every API key passed to the server's environment.
- **SANDWORM_MODE incident**: In February 2026, 19 malicious npm packages installed rogue MCP servers into coding tools. The "McpInject" module used prompt injection to tell agents to extract SSH keys, AWS credentials, npm tokens, and `.env` files.

### Agent-initiated or incidental?

**Both.** The agent can read MCP config files via file-read tools (incidental exposure). The configuration pattern itself is agent-adjacent -- the user configures it for the agent's benefit, and the agent's MCP tool calls trigger the credential flow.

### Would bash interception catch it?

**No.** MCP tool calls are not bash commands. They go through a separate tool-call pathway. The MCP server process reads credentials from its environment, which was set by the host application, not by a bash command.

### What SIGIL must do

1. **SIGIL as MCP credential proxy**: Instead of putting secrets in MCP config files, users should configure MCP servers to get credentials from SIGIL. SIGIL provides an MCP server that other MCP servers can call to get credentials, or SIGIL injects credentials into MCP server processes at launch time.
2. **MCP config file scanning**: SIGIL should scan MCP configuration files (`.cursor/mcp.json`, etc.) for hardcoded credentials and warn the user.
3. **MCP output scrubbing**: Hook the `PostToolUse` event for MCP tools (where harnesses support it -- Claude Code's `updatedMCPToolOutput` is the only current mechanism) to scrub secret values from MCP tool responses.
4. **MCP server isolation**: Document and recommend sandboxing MCP servers so they cannot read each other's credentials or the host filesystem.

### Criticality: **HIGH**

This is a rapidly growing vector. MCP adoption is exploding, the default configuration patterns are insecure by design, and 24,000+ secrets have already been found on GitHub. The OWASP MCP Top 10 lists this as #1 (MCP01-2025).

---

## 12. Secrets in Infrastructure-as-Code State

### How the secret gets there

Infrastructure-as-Code tools maintain state files that contain the real values of all managed resources, including secrets:

- **Terraform state files**: `terraform.tfstate` stores all resource attributes in plaintext JSON, including database passwords, API keys, SSL certificate private keys, and any `sensitive = true` marked values. The `sensitive` marker only hides values from `terraform plan` and `terraform output` console display -- it does not encrypt them in state. Developers have a false sense of security because console output shows "(sensitive value)" but the state file contains everything in plain text.
- **Pulumi state**: Similar to Terraform; state contains resource properties. Pulumi encrypts secrets in state by default (better than Terraform), but the encryption key must be managed.
- **CloudFormation**: Stack outputs and parameter values stored in AWS, accessible via `aws cloudformation describe-stacks`.
- **Ansible facts**: Gathered facts may include sensitive system information. `ansible-vault` encrypted files, when decrypted for use, expose secrets in memory and potentially in logs.

### Agent-initiated or incidental?

**Incidental.** The agent runs `terraform show` or reads `terraform.tfstate` to understand infrastructure, and the secrets are there. This is a particularly dangerous vector because the agent may legitimately need to understand infrastructure to do its job.

### Would bash interception catch it?

**Partially.** `terraform show` and `terraform state show` go through bash. But `cat terraform.tfstate` or reading it via the `Read` tool bypasses bash-level interception.

### What SIGIL must do

1. **State file access control**: In the sandbox, make `terraform.tfstate` and `.terraform/` read-only or inaccessible. Provide a SIGIL-aware wrapper that returns scrubbed state.
2. **Terraform command scrubbing**: Scrub output from `terraform show`, `terraform output`, `terraform state show`, and `terraform console`.
3. **File-read scrubbing**: When the agent reads state files via the `Read` tool, apply the same scrubbing as for bash output.
4. **Ephemeral resources advocacy**: Recommend using Terraform's ephemeral resources (introduced in late 2025) for secrets, which are not stored in state.

### Criticality: **HIGH**

Terraform state is one of the most dangerous secret stores because it is plaintext, often stored locally or in S3 without encryption, and contains every secret the infrastructure uses. The false sense of security from `(sensitive value)` masking makes it worse.

---

## 13. Secrets in Docker Image Layers

### How the secret gets there

Docker builds create immutable, stackable layers. Once data enters a layer, it is permanently recoverable:

- **`ENV` instructions**: `ENV API_KEY=sk-live-abc123` stores the secret permanently in the image's layer metadata. It is visible via `docker history` and `docker inspect`.
- **`ARG` instructions**: `ARG SECRET_TOKEN=abc` -- while not in the final image's environment, the value is recorded in the image's build cache and history. Anyone with image access can extract it.
- **`COPY` of secret files**: `COPY .env /app/.env` embeds the secret file in a layer. Even if a subsequent `RUN rm /app/.env` deletes it, the layer containing the file persists.
- **Build logs**: `RUN echo $SECRET` in a Dockerfile prints the secret value during build, which appears in build logs.
- **Multi-stage build leaks**: If secrets are used in an early build stage and the final stage doesn't include them, the intermediate layers are still stored in the build cache and may be pushed to a registry.

### Agent-initiated or incidental?

**Agent-initiated.** The agent writes the Dockerfile containing `ENV API_KEY=...` or `COPY .env /app/`. This is a form of Vector 1 (secrets in generated code) but with the additional property that the secret is permanently embedded in a distributable artifact.

### Would bash interception catch it?

**No.** The secret enters the Docker image through a `Write` tool call that creates or modifies the Dockerfile. The `docker build` command that bakes it in goes through bash, but by then the Dockerfile already contains the secret. SIGIL's pre-hook could theoretically scan the `docker build` command's context, but the secret is in the file being built from, not in the command itself.

### What SIGIL must do

1. **Dockerfile scanning**: When the agent writes a Dockerfile, scan for `ENV`, `ARG`, and `COPY` instructions that contain or reference secrets. Block the write and suggest BuildKit `--mount=type=secret` instead.
2. **Build command interception**: When `docker build` is invoked, scan the Dockerfile being built for secret patterns. Warn or block if secrets are found.
3. **Image scanning integration**: Optionally integrate with Trivy, Snyk, or similar tools to scan built images for embedded secrets.
4. **BuildKit secret injection**: Provide a SIGIL integration for Docker BuildKit that injects secrets via `--secret` mounts from the SIGIL vault, keeping them out of image layers entirely.

### Criticality: **HIGH**

Docker images are routinely pushed to registries (including public registries by accident). A secret baked into an image layer is permanently and widely accessible. Over 10,000 Docker Hub images have been found leaking credentials.

---

## 14. Secrets in CI/CD Pipelines

### How the secret gets there

AI coding agents are increasingly used to generate and modify CI/CD configurations, creating several secret leakage paths:

- **Hardcoded secrets in workflow files**: The agent writes `API_KEY: "sk-live-abc123"` directly in `.github/workflows/deploy.yml` instead of using `${{ secrets.API_KEY }}`.
- **Secret exposure through job outputs**: A workflow step captures a secret in its output: `echo "::set-output name=token::${{ secrets.API_TOKEN }}"`. This output may be logged or passed to subsequent steps that are less secure.
- **Debug mode in CI**: `ACTIONS_STEP_DEBUG=true` causes GitHub Actions to print all step inputs and outputs, including secret values that are normally masked.
- **Artifact persistence**: Secrets written to files during CI/CD steps may be uploaded as build artifacts. GitHub Actions artifacts are accessible to anyone with repo access.
- **Agent-as-CI-actor**: When AI agents run in GitHub Actions (e.g., Claude Code as a GitHub Actions agent for automated PR review), they inherit `GITHUB_TOKEN` and any repository secrets configured for the workflow. The agent has full access to these secrets in its execution environment.
- **Pull request context**: AI agents generating PR descriptions may inadvertently include secrets from code diffs or commit messages in the PR body, which is publicly visible on public repos.

### Agent-initiated or incidental?

**Agent-initiated** when the agent writes workflow files with hardcoded secrets. **Incidental** when the agent inherits CI/CD secrets through the execution environment.

### Would bash interception catch it?

**Partially.** If the agent writes workflow files through bash (`cat > .github/workflows/deploy.yml`), the file content could be scanned. But most agents use `Write` or `Edit` tools. CI/CD environment secrets inherited by the agent are not exposed through bash commands unless the agent explicitly runs `env` or `echo $SECRET`.

### What SIGIL must do

1. **Workflow file scanning**: Scan all writes to CI/CD configuration files (`.github/workflows/*.yml`, `.gitlab-ci.yml`, `Jenkinsfile`, `bitbucket-pipelines.yml`, `.circleci/config.yml`) for hardcoded secret patterns.
2. **CI/CD template guidance**: When the agent writes a CI/CD config that references a secret, suggest the platform's native secret management (`${{ secrets.NAME }}` for GitHub Actions, CI/CD variables for GitLab).
3. **Agent-in-CI isolation**: When SIGIL-protected agents run inside CI/CD, ensure that repository secrets are not passed as environment variables to the agent's process. Instead, use SIGIL's placeholder mechanism.
4. **Artifact scanning**: Optionally scan build artifacts for secret values before upload.

### Criticality: **HIGH**

CI/CD pipelines are high-value targets because they often have the most privileged credentials (deployment keys, cloud provider credentials, registry tokens). Agents generating CI/CD configs without understanding secret management create direct exposure.

---

## Summary Matrix

| # | Vector | Agent-Initiated? | Bash Intercept? | Criticality | SIGIL Coverage Required |
|---|--------|-------------------|-----------------|-------------|------------------------|
| 1 | Generated code | Yes | No (file writes) | HIGH | File-write hooks, pattern detection |
| 2 | Context / conversation | Both | Partial (output only) | HIGH | All-tool scrubbing, user education |
| 3 | Error messages | Incidental | Partial | HIGH | Encoding-aware scrubbing, pattern matching |
| 4 | Clipboard | Incidental | No | MEDIUM | Sandbox clipboard isolation |
| 5 | Browser / web tools | Both | No (MCP/CDP) | HIGH | Browser MCP integration, Cerberus pattern |
| 6 | Logs | Incidental | Partial | HIGH | Log command scrubbing, all-tool hooks |
| 7 | Package lock/config | Incidental | No (side effect) | MEDIUM | Lock file scanning, registry credential isolation |
| 8 | Git history | Incidental | Partial | MEDIUM | Historical secret tracking, remote URL scrubbing |
| 9 | Temporary files | Incidental | No | MEDIUM | Sandbox isolation, memfd_create, core dump prevention |
| 10 | Tool outputs | Incidental | Yes | HIGH | Command-aware + structural scrubbing |
| 11 | MCP config files | Both | No (MCP pathway) | HIGH | SIGIL as credential proxy, config scanning |
| 12 | IaC state | Incidental | Partial | HIGH | State file protection, Read-tool scrubbing |
| 13 | Docker layers | Agent-initiated | No (file writes) | HIGH | Dockerfile scanning, BuildKit integration |
| 14 | CI/CD pipelines | Both | Partial | HIGH | Workflow scanning, CI-specific isolation |

---

## Key Insight: Bash Interception Is Necessary But Insufficient

Of the 14 vectors cataloged, only **one** (Vector 10: tool outputs) is fully addressable through bash command interception alone. Five vectors are partially addressable, and **eight vectors are completely invisible to bash-level hooks**.

This validates SIGIL's multi-layer architecture:

1. **Bash pre/post hooks**: Handle command injection and output scrubbing (Vectors 3, 6, 8, 10, 12)
2. **File-write hooks**: Handle code generation, Dockerfiles, CI/CD configs, package configs (Vectors 1, 7, 13, 14)
3. **All-tool scrubbing**: Handle file reads, grep results, and non-bash tool outputs (Vectors 2, 6, 12)
4. **MCP integration**: Handle browser automation and MCP credential flow (Vectors 5, 11)
5. **Sandbox isolation**: Handle temporary files, clipboard, process enumeration (Vectors 4, 9)
6. **User education and process**: Handle context contamination from user input (Vector 2)

A tool that only intercepts bash commands would miss the majority of real-world secret leakage paths.

---

## Sources

- [GitGuardian: State of Secrets Sprawl 2026](https://blog.gitguardian.com/the-state-of-secrets-sprawl-2026/)
- [GitGuardian: State of Secrets Sprawl 2026 (PR)](https://blog.gitguardian.com/the-state-of-secrets-sprawl-2026-pr/)
- [OECD.AI: AI Coding Assistants Drive Surge in Secret Leaks](https://oecd.ai/en/incidents/2026-03-17-2273)
- [Doppler: LLM Security Risks -- AI Copilots Expand Attack Surface for Secrets](https://www.doppler.com/blog/llm-security-risks)
- [OX Security: Agentic AI and the Rise of Hardcoded Secrets](https://www.ox.security/blog/agentic-ai-and-the-rise-of-hardcoded-secrets/)
- [DEV Community: AI Agents Don't Understand Secrets](https://dev.to/0x711/ai-agents-dont-understand-secrets-thats-your-problem-43n4)
- [DEV Community: Your AI Agent Knows Your Passwords (Cerberus)](https://dev.to/demojacob/your-ai-agent-knows-your-passwords-heres-how-i-fixed-it-4kcd)
- [OWASP MCP Top 10: MCP01 Token Mismanagement and Secret Exposure](https://owasp.org/www-project-mcp-top-10/2025/MCP01-2025-Token-Mismanagement-and-Secret-Exposure)
- [Cyata: MCP's Quiet Crisis of Credential Exposure](https://cyata.ai/blog/whispering-secrets-loudly-inside-mcps-quiet-crisis-of-credential-exposure/)
- [Claude Code Data Usage Documentation](https://code.claude.com/docs/en/data-usage)
- [GitHub Blog: Updates to Copilot Interaction Data Usage Policy](https://github.blog/news-insights/company-news/updates-to-github-copilot-interaction-data-usage-policy/)
- [Anthropic Privacy Center: Data Retention](https://privacy.claude.com/en/articles/10023548-how-long-do-you-store-my-data)
- [Xygeni: Dockerfile Secrets -- Why Layers Keep Your Data Forever](https://xygeni.io/blog/dockerfile-secrets-why-layers-keep-your-sensitive-data-forever/)
- [Docker Docs: SecretsUsedInArgOrEnv Build Check](https://docs.docker.com/reference/build-checks/secrets-used-in-arg-or-env/)
- [HashiCorp: Protect Sensitive Input Variables](https://developer.hashicorp.com/terraform/tutorials/configuration-language/sensitive-variables)
- [Codefresh: Risks of Exposed Terraform Secrets](https://codefresh.io/learn/devsecops/risks-of-exposed-terraform-secrets-and-4-ways-to-secure-them/)
- [StepSecurity: When AI Meets CI/CD](https://www.stepsecurity.io/blog/when-ai-meets-ci-cd-coding-agents-in-github-actions-pose-hidden-security-risks)
- [Snyk: Why 28 Million Credentials Leaked on GitHub in 2025](https://snyk.io/articles/state-of-secrets/)
- [BuildMVPFast: Copilot Secrets Leak -- 2,702 Hard-Coded Keys Found](https://www.buildmvpfast.com/blog/copilot-secrets-api-key-leak-ai-code-security-2026)
- [npm CLI Issue #1092: Auth Token Leak in .npmrc](https://github.com/npm/cli/issues/1092)
- [pip-tools Issue #1198: Secrets in requirements.txt](https://github.com/jazzband/pip-tools/issues/1198)
- [OWASP: Insecure Temporary File](https://owasp.org/www-community/vulnerabilities/Insecure_Temporary_File)
- [Flatt Security: Clone2Leak -- Git Credential Leaks](https://flatt.tech/research/posts/clone2leak-your-git-credentials-belong-to-us/)
- [Medium: ORM Error Message Information Disclosure](https://medium.com/@cameronbardin/when-error-messages-leak-more-than-logs-orms-frameworks-and-the-quiet-reconnaissance-problem-cfb336ce1117)
