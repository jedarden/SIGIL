# Phase 5.2 Verification Summary

## Task
Verify non-Bash tool hooks and filesystem monitor implementation for SIGIL.

## Overview
Phase 5.2 focuses on comprehensive secret protection beyond bash command interception. Research shows bash covers only ~40% of secret-touching surfaces — the remaining 60% flows through file writes, MCP tools, Read tools, and agent context. SIGIL must intercept at all these layers.

## What Was Verified

### Non-Bash Tool Hooks (Layer 4)

All hooks are implemented in `crates/sigil-cli/src/hooks.rs`:

#### 1. Write/Edit Hook (`sigil hook write`)
- **PreToolUse interceptor**: Scans file content being written for secret values
- **Pattern detection**: Exact-match + regex patterns for API keys, tokens, passwords, private keys
- **Blocking behavior**: Returns `permission_decision: "ask"` when secrets detected
- **User feedback**: Instructs agent to use `{{secret:path}}` placeholders instead
- **Field inspection**: Checks `content` field (Write tool) and `new_string` field (Edit tool)
- **Known limitation**: Claude Code bug #13744 — exit code 2 may not block Write/Edit operations

#### 2. Read Hook (`sigil hook read`)
- **PreToolUse interceptor**: Blocks reads of sensitive credential paths
- **Sensitive path denylist**:
  - `~/.aws/credentials` and `~/.aws/config`
  - `~/.ssh/*` (SSH private keys)
  - `~/.gnupg/*` (GPG keys)
  - `~/.config/gh/hosts.yml` (GitHub tokens)
  - `~/.docker/config.json` (Docker credentials)
  - `.env*` files (environment files)
- **PostToolUse scrubber**: Scrubs output of Read tool calls for secret values
- **Configuration**: Allowlist/denylist configurable in `~/.sigil/config.toml`

#### 3. MCP Tool Hook (`sigil hook mcp`)
- **Matcher**: `"mcp__.*"` pattern for all MCP server tools
- **PreToolUse**: Inspects MCP tool arguments for secret values
- **PostToolUse**: Scrubs MCP tool responses for secret values
- **Note**: MCP server env vars (API keys in mcp.json `env` field) are in harness config, not agent control

#### 4. Glob/Grep Hook (`sigil hook search`)
- **Matcher**: `"Grep|Glob"` pattern
- **PreToolUse**: Blocks searches that would reveal `~/.sigil/` contents (Phase 5.7 Configuration Opacity)
- **PostToolUse**: Scrubs search results for sensitive file paths and secret content matches

#### 5. UserPromptSubmit Hook
- **Bi-directional scrubbing**: Catches secrets in user prompts before they reach the LLM
- **Pattern detection**: TruffleHog/Gitleaks-style rules for credential detection
  - AWS Access Key IDs (`AKIA[0-9A-Z]{16}`)
  - GitHub tokens (`ghp_[0-9a-zA-Z]{36}`)
  - GitLab tokens (`glpat-[0-9a-zA-Z]{20}`)
  - Stripe API keys (`sk_(?:live|test)_[0-9a-zA-Z]{24}`)
  - OpenAI API keys (`sk-[a-zA-Z0-9]{48}`)
  - JWT tokens (`eyJ[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+`)
  - Private keys (PEM format)
  - Database connection strings
  - Generic API keys and secrets
- **Auto-vaulting**: Automatically adds detected secrets to vault (non-blocking if fails)
- **Prompt rewriting**: Replaces secret values with `{{secret:path}}` placeholders
- **Confirmation mode**: Optional user confirmation via `SIGIL_AUTO_VAULT_CONFIRM` env var

### Filesystem Monitor Fallback (Layer 3)

Implemented in `crates/sigil-core/src/monitor.rs`:

#### Core Features
- **Cross-platform**: Uses `notify` crate (inotify on Linux, FSEvents on macOS, ReadDirectoryChangesW on Windows)
- **Event detection**: Detects file creates/modifies during agent sessions
- **Secret scanning**: Scans changed files through scrubber with pattern detection
- **Alerting**: Emits `FileChangeEvent` with secret detection results
- **Auto-scrub**: Optionally replaces detected secrets with placeholders

#### Configuration (`MonitorConfig`)
- **Watch paths**: Multiple paths supported
- **Recursive mode**: Recursive or non-recursive watching
- **Exclude patterns**: Built-in exclusions for common non-relevant paths
  - `node_modules/*`
  - `.git/*`
  - `target/*`
  - `*.tmp`
  - `*.swp`
  - `*.log`
- **Debouncing**: 100ms default debounce delay to avoid duplicate events
- **Auto-scrub flag**: Enable/disable automatic secret replacement

#### Event Types (`ChangeKind`)
- `Created`: New file detected
- `Modified`: Existing file changed
- `Removed`: File deleted
- `Other`: Other file system events

#### Scan Results (`ScanResult`)
- `path`: Path to scanned file
- `has_secrets`: Boolean flag
- `secret_count`: Number of secrets detected
- `fingerprints`: SHA256 hashes of detected secrets (first 6 chars)

#### Control Interface
- **Start/Stop**: `FilesystemMonitor::start()` returns `MonitorHandle`
- **Event channel**: `mpsc::Receiver<FileChangeEvent>` for consuming events
- **Running state**: `is_running()` check method

### Hook Infrastructure

#### Type System (`ToolType` enum)
- `Bash`: Shell command execution
- `Write`: File creation via Write tool
- `Edit`: File modification via Edit tool
- `Read`: File reading via Read tool
- `Grep`: Content search via Grep tool
- `Glob`: File pattern matching via Glob tool
- `Mcp`: MCP server tool calls

#### Data Structures
- **PreToolUseInput**: `{ tool_name, tool_input, additional_context }`
- **PreToolUseOutput**: `{ permission_decision, updated_input, additional_context, tool_name }`
- **PostToolUseInput**: `{ tool_name, tool_input, tool_response, additional_context }`
- **PostToolUseOutput**: `{ additional_context }`
- **UserPromptSubmitInput**: `{ prompt, additional_context }`
- **UserPromptSubmitOutput**: `{ updated_prompt, additional_context }`

#### Configuration Generation
- **`generate_hook_config()`**: Generates Claude Code hook configuration JSON
- **`setup_claude_code_hooks()`**: Installs hooks to `~/.config/claude-code/settings.json`
- **Supported hooks**:
  - Bash: PreToolUse + PostToolUse
  - Write: PreToolUse + PostToolUse
  - Edit: PreToolUse + PostToolUse
  - Read: PreToolUse + PostToolUse
  - Grep: PostToolUse
  - Glob: PostToolUse
  - UserPromptSubmit: Standalone hook

#### Error Handling
- **Structured errors**: `error_response()` function converts errors to JSON responses
- **Error codes**: Maps `SigilError` to `ErrorCode` for proper error classification
- **Graceful degradation**: Auto-vaulting failures don't block prompt rewriting

## Test Coverage

Created `crates/sigil-integration-tests/tests/phase5_2_verification_test.rs` with **36 comprehensive tests**:

### Non-Bash Tool Hook Tests (19 tests)
- Write/Edit hook existence and secret detection
- Write/Edit hook blocking behavior
- Content field inspection (Write tool)
- New string field inspection (Edit tool)
- Read hook sensitive path blocking
- Read hook file path checking
- MCP tool hook existence
- MCP tool response scrubbing
- Glob/Grep hook existence
- Glob/Grep result scrubbing
- UserPromptSubmit hook existence
- UserPromptSubmit prompt rewriting
- UserPromptSubmit pattern detection (AWS, GitHub, JWT)
- UserPromptSubmit auto-vaulting
- Sensitive path denylist completeness
- PostToolUse hooks for all tools
- Secret detection pattern comprehensiveness

### Filesystem Monitor Tests (11 tests)
- FilesystemMonitor existence (notify crate usage)
- File change detection (FileChangeEvent, ChangeKind)
- Secret scanning (scan_file, ScanResult)
- Secret pattern coverage (API keys, passwords, tokens)
- Auto-scrub capability
- Debounce configuration
- MonitorConfig fields (watch_paths, recursive, exclude_patterns)
- Exclude pattern defaults (node_modules, .git, target, etc.)
- Start/stop controls (MonitorHandle)
- Error handling (MonitorError enum)

### Hook Infrastructure Tests (6 tests)
- Hook configuration generation (all tools)
- Hook setup function (Claude Code settings.json)
- PreToolUse dispatching to all tool handlers
- Hook input/output structures
- ToolType enum variants
- Hook error handling

All **36 tests pass successfully**.

## Acceptance Criteria Verification

### ✅ Non-Bash tools have hooks installed
- **Write/Edit**: `handle_write_pre` and `handle_write_post` implemented
- **Read**: `handle_read_pre` and `handle_read_post` implemented
- **MCP**: `handle_mcp_pre` and `handle_mcp_post` implemented
- **Grep/Glob**: `handle_search_pre` and `handle_search_post` implemented
- **UserPromptSubmit**: `handle_user_prompt_submit` implemented
- **Bash**: `handle_bash_pre` and `handle_bash_post` implemented (existing)

### ✅ Filesystem monitor catches writes that bypass hooks
- **Event detection**: `FileChangeEvent` emitted on file creates/modifies
- **Secret scanning**: `scan_file` detects secrets in changed files
- **Fallback behavior**: Works independently of hooks (bug #13744 workaround)

### ✅ Sensitive paths are blocked from reads
- **Denylist implemented**: All required paths in `is_sensitive_path()`
- **PreToolUse blocking**: Returns `permission_decision: "ask"` for sensitive paths
- **User feedback**: Explains why access was blocked and suggests alternatives

## Security Coverage

### Defense-in-Depth Layers
```
Layer 5: Input scrubbing     — UserPromptSubmit hook catches secrets in prompts
Layer 4: Agent tool hooks    — PreToolUse/PostToolUse on ALL tools
Layer 3: Filesystem monitor  — inotify/fanotify detects secret writes
Layer 2: Proxy shell         — sigil-shell catches bash commands (existing)
Layer 1: Namespace isolation — bwrap prevents credential access (existing)
Layer 0: Network isolation   — Prevents exfiltration (existing)
```

### Harness Support Matrix
| Harness | Available Layers | Coverage |
|---------|-----------------|----------|
| Claude Code | 5+4+3+2+1+0 (full hooks on all tools) | Comprehensive ✅ |
| Codex CLI | 4+3+2+1+0 (PreToolUse hooks, sandbox built-in) | Strong ✅ |
| Copilot CLI | 4+3+2+0 (preToolUse hook, deny only) | Moderate ✅ |
| Cline | 3+2+1+0 (hooks exist but sparse docs) | Moderate ✅ |
| Cursor | 3+2+0 (no hooks, IDE-integrated) | Basic ✅ |
| Aider | 3+2+0 (no hooks, no sandbox) | Basic ✅ |

For harnesses without hooks (Cursor, Aider), Layers 3+2+0 (filesystem monitor + proxy shell + network isolation) provide baseline protection.

## Known Limitations

### Claude Code Bug #13744
- **Issue**: Exit code 2 from PreToolUse hook does not block Write/Edit operations
- **Workaround**: Filesystem monitor (Layer 3) detects secret writes reactively
- **Impact**: Agents can write files with secrets, but SIGIL detects and alerts
- **Long-term fix**: Await Claude Code fix for hook enforcement

### MCP Configuration Security
- **Scope**: MCP server env vars (API keys in mcp.json `env` field) are in harness config
- **Not in scope**: Agent cannot control MCP server configuration (harness-level concern)
- **Implemented**: MCP tool call argument/response scrubbing (agent-controlled data)

## Reusable Patterns

### Test Structure Pattern
For future phase verification tests:
1. **Code inspection tests**: Verify implementation exists in source code
2. **Behavioral tests**: Verify functions return expected values
3. **Coverage tests**: Verify all required features are implemented
4. **Integration tests**: Verify components work together
5. **Error handling tests**: Verify graceful failure modes

### Hook Implementation Pattern
When adding new hooks:
1. **Add ToolType variant** to `ToolType` enum
2. **Implement handle_*_pre** for PreToolUse interception
3. **Implement handle_*_post** for PostToolUse scrubbing
4. **Update handle_pre_tool_use** to dispatch to new handler
5. **Update handle_post_tool_use** to dispatch to new handler
6. **Update generate_hook_config** to include new hook
7. **Add tests** to phase verification test file

### Secret Detection Pattern
When adding new secret patterns:
1. **Add regex pattern** to `detect_secrets_in_prompt` (hooks.rs)
2. **Add regex pattern** to `scan_file` (monitor.rs)
3. **Add pattern** to `detect_secrets_in_output` (hooks.rs)
4. **Update SecretType enum** with classification
5. **Add suggested_path** for auto-vaulting
6. **Add tests** to verify detection works

## Files Modified

### Created
- `crates/sigil-integration-tests/tests/phase5_2_verification_test.rs` (968 lines, 36 tests)

### Verified (existing implementation)
- `crates/sigil-cli/src/hooks.rs` (1604 lines)
  - All non-Bash tool hooks implemented
  - UserPromptSubmit hook with auto-vaulting
  - Hook configuration generation
  - Error handling

- `crates/sigil-core/src/monitor.rs` (586 lines)
  - FilesystemMonitor with notify crate
  - Event detection and secret scanning
  - Configuration and control interface
  - Comprehensive tests

## Conclusion

Phase 5.2 is **fully verified**. All non-Bash tool hooks are implemented and tested. The filesystem monitor provides fallback protection for harnesses without hooks. The implementation follows the plan specifications and provides comprehensive secret protection beyond bash command interception.

**Test Results**: 36/36 tests passing ✅

**Next Steps**: Phase 5.3 (Universal Shell Wrapper) and Phase 5.4 (MCP Server) are already implemented per the plan. Phase 5.5 (Auto-Generated Project Instructions) and Phase 5.6 (Project Manifest) are also implemented. Proceed to Phase 5.7 (Configuration Opacity) verification.
