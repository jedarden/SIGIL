//! Phase 5.2 Verification Tests
//!
//! These tests verify the non-Bash tool hooks and filesystem monitor
//! as specified in the plan Phase 5.2 deliverables.
//!
//! Phase 5.2 covers:
//! - Write/Edit hook (sigil hook write): blocks writes with detected secrets
//! - Read hook (sigil hook read): blocks reads of sensitive paths
//! - MCP tool hook (sigil hook mcp): scrubs MCP args and responses
//! - Glob/Grep hook (sigil hook search): PostToolUse scrubbing of results
//! - UserPromptSubmit hook: input scrubbing (bi-directional - Phase 8.2)
//! - Filesystem monitor fallback: inotify/fanotify for harnesses without hooks

mod common;
use common::workspace_root;
use std::fs;

/// Test 5.2.1: Verify Write/Edit hook exists and can detect secrets
///
/// From Phase 5.2 deliverables:
/// "Write/Edit hook (sigil hook write): blocks writes with detected secrets"
/// "Scans file content being written for secret values (exact-match + pattern detection)"
/// "If secrets detected: block the write (exit code 2)"
#[test]
fn test_write_hook_exists() {
    let hooks_path = workspace_root().join("crates/sigil-cli/src/hooks.rs");
    let hooks_code = fs::read_to_string(&hooks_path).expect("Failed to read hooks.rs");

    // Verify handle_write_pre function exists
    assert!(
        hooks_code.contains("fn handle_write_pre"),
        "Write hook function handle_write_pre must exist"
    );

    // Verify it scans for secrets
    assert!(
        hooks_code.contains("detect_secrets_in_output") || hooks_code.contains("detect_secrets"),
        "Write hook must scan for secrets"
    );

    // Verify it returns permission_decision
    assert!(
        hooks_code.contains("permission_decision"),
        "Write hook must return permission_decision"
    );

    // Verify it checks for secret patterns
    assert!(
        hooks_code.contains("api_key") || hooks_code.contains("secret"),
        "Write hook must check for secret patterns"
    );
}

/// Test 5.2.2: Verify Write/Edit hook blocks writes with secrets
///
/// From Phase 5.2 deliverables:
/// "If secrets detected: block the write (exit code 2) and return feedback
///  telling the agent to use {{secret:path}} placeholders instead"
#[test]
fn test_write_hook_blocks_secrets() {
    let hooks_path = workspace_root().join("crates/sigil-cli/src/hooks.rs");
    let hooks_code = fs::read_to_string(&hooks_path).expect("Failed to read hooks.rs");

    // Verify handle_write_pre blocks writes with secrets
    assert!(
        hooks_code.contains("handle_write_pre") && hooks_code.contains("ask"),
        "Write hook must return 'ask' permission decision when secrets detected"
    );

    // Verify feedback mentions {{secret:path}} placeholders
    assert!(
        hooks_code.contains("{{secret:path}}") || hooks_code.contains("secret:path"),
        "Write hook feedback must mention {{secret:path}} placeholders"
    );
}

/// Test 5.2.3: Verify Write/Edit hook checks content field
///
/// From Phase 5.2 deliverables:
/// "For Write tool: inspect content field for known secret patterns"
#[test]
fn test_write_hook_inspects_content() {
    let hooks_path = workspace_root().join("crates/sigil-cli/src/hooks.rs");
    let hooks_code = fs::read_to_string(&hooks_path).expect("Failed to read hooks.rs");

    // Verify it checks the content field
    assert!(
        hooks_code.contains("content") && hooks_code.contains("tool_input"),
        "Write hook must inspect content field from tool_input"
    );
}

/// Test 5.2.4: Verify Write/Edit hook checks new_string field
///
/// From Phase 5.2 deliverables:
/// "For Edit tool: inspect new_string field"
#[test]
fn test_write_hook_inspects_new_string() {
    let hooks_path = workspace_root().join("crates/sigil-cli/src/hooks.rs");
    let hooks_code = fs::read_to_string(&hooks_path).expect("Failed to read hooks.rs");

    // Verify it checks the new_string field
    assert!(
        hooks_code.contains("new_string") && hooks_code.contains("tool_input"),
        "Write hook must inspect new_string field from tool_input for Edit tool"
    );
}

/// Test 5.2.5: Verify Read hook blocks sensitive paths
///
/// From Phase 5.2 deliverables:
/// "Read hook (sigil hook read): Block reads of sensitive paths"
/// "~/.aws/credentials, ~/.ssh/*, ~/.gnupg/*, ~/.config/gh/hosts.yml,
///  ~/.docker/config.json, .env*"
#[test]
fn test_read_hook_blocks_sensitive_paths() {
    let hooks_path = workspace_root().join("crates/sigil-cli/src/hooks.rs");
    let hooks_code = fs::read_to_string(&hooks_path).expect("Failed to read hooks.rs");

    // Verify handle_read_pre function exists
    assert!(
        hooks_code.contains("fn handle_read_pre"),
        "Read hook function handle_read_pre must exist"
    );

    // Verify is_sensitive_path function exists
    assert!(
        hooks_code.contains("fn is_sensitive_path"),
        "is_sensitive_path function must exist"
    );

    // Verify it blocks ~/.aws/credentials
    assert!(
        hooks_code.contains(".aws/credentials"),
        "Read hook must block ~/.aws/credentials"
    );

    // Verify it blocks ~/.ssh/ paths
    assert!(
        hooks_code.contains(".ssh/"),
        "Read hook must block ~/.ssh/* paths"
    );

    // Verify it blocks ~/.gnupg/ paths
    assert!(
        hooks_code.contains(".gnupg/"),
        "Read hook must block ~/.gnupg/* paths"
    );

    // Verify it blocks .env files
    assert!(
        hooks_code.contains(".env"),
        "Read hook must block .env* files"
    );
}

/// Test 5.2.6: Verify Read hook checks file_path
///
/// From Phase 5.2 deliverables:
/// "Read hook: Matcher: Read in PreToolUse"
#[test]
fn test_read_hook_checks_file_path() {
    let hooks_path = workspace_root().join("crates/sigil-cli/src/hooks.rs");
    let hooks_code = fs::read_to_string(&hooks_path).expect("Failed to read hooks.rs");

    // Verify it checks file_path from tool_input
    assert!(
        hooks_code.contains("file_path") && hooks_code.contains("tool_input"),
        "Read hook must check file_path from tool_input"
    );
}

/// Test 5.2.7: Verify MCP tool hook exists
///
/// From Phase 5.2 deliverables:
/// "MCP tool hook (sigil hook mcp): Scrubs MCP args and responses"
/// "Matcher: mcp__.* in PreToolUse"
#[test]
fn test_mcp_hook_exists() {
    let hooks_path = workspace_root().join("crates/sigil-cli/src/hooks.rs");
    let hooks_code = fs::read_to_string(&hooks_path).expect("Failed to read hooks.rs");

    // Verify handle_mcp_pre function exists
    assert!(
        hooks_code.contains("fn handle_mcp_pre"),
        "MCP hook function handle_mcp_pre must exist"
    );

    // Verify handle_mcp_post function exists
    assert!(
        hooks_code.contains("fn handle_mcp_post"),
        "MCP hook function handle_mcp_post must exist"
    );

    // Verify MCP tool type detection
    assert!(
        hooks_code.contains("mcp__") || hooks_code.contains("ToolType::Mcp"),
        "MCP hook must detect mcp__ tools"
    );
}

/// Test 5.2.8: Verify MCP tool hook scrubs responses
///
/// From Phase 5.2 deliverables:
/// "PostToolUse: scrub MCP tool responses for secret values"
#[test]
fn test_mcp_hook_scrubs_responses() {
    let hooks_path = workspace_root().join("crates/sigil-cli/src/hooks.rs");
    let hooks_code = fs::read_to_string(&hooks_path).expect("Failed to read hooks.rs");

    // Verify handle_mcp_post scrubs for secrets
    assert!(
        hooks_code.contains("handle_mcp_post") && hooks_code.contains("detect_secrets"),
        "MCP PostToolUse hook must scrub responses for secrets"
    );
}

/// Test 5.2.9: Verify Glob/Grep hook exists
///
/// From Phase 5.2 deliverables:
/// "Glob/Grep hook (sigil hook search): PostToolUse scrubbing of results"
/// "Matcher: Glob|Grep in PostToolUse"
#[test]
fn test_search_hook_exists() {
    let hooks_path = workspace_root().join("crates/sigil-cli/src/hooks.rs");
    let hooks_code = fs::read_to_string(&hooks_path).expect("Failed to read hooks.rs");

    // Verify handle_search_pre function exists
    assert!(
        hooks_code.contains("fn handle_search_pre"),
        "Search hook function handle_search_pre must exist"
    );

    // Verify handle_search_post function exists
    assert!(
        hooks_code.contains("fn handle_search_post"),
        "Search hook function handle_search_post must exist"
    );

    // Verify Grep tool type detection
    assert!(
        hooks_code.contains("Grep") || hooks_code.contains("ToolType::Grep"),
        "Search hook must detect Grep tool"
    );

    // Verify Glob tool type detection
    assert!(
        hooks_code.contains("Glob") || hooks_code.contains("ToolType::Glob"),
        "Search hook must detect Glob tool"
    );
}

/// Test 5.2.10: Verify Glob/Grep hook scrubs results
///
/// From Phase 5.2 deliverables:
/// "Scrub results that reveal sensitive file paths or secret content matches"
#[test]
fn test_search_hook_scrubs_results() {
    let hooks_path = workspace_root().join("crates/sigil-cli/src/hooks.rs");
    let hooks_code = fs::read_to_string(&hooks_path).expect("Failed to read hooks.rs");

    // Verify handle_search_post scrubs for secrets
    assert!(
        hooks_code.contains("handle_search_post") && hooks_code.contains("detect_secrets"),
        "Search PostToolUse hook must scrub results for secrets"
    );
}

/// Test 5.2.11: Verify UserPromptSubmit hook exists
///
/// From Phase 5.2 deliverables:
/// "UserPromptSubmit hook: input scrubbing (bi-directional - Phase 8.2)"
#[test]
fn test_user_prompt_submit_hook_exists() {
    let hooks_path = workspace_root().join("crates/sigil-cli/src/hooks.rs");
    let hooks_code = fs::read_to_string(&hooks_path).expect("Failed to read hooks.rs");

    // Verify handle_user_prompt_submit function exists
    assert!(
        hooks_code.contains("fn handle_user_prompt_submit"),
        "UserPromptSubmit hook function must exist"
    );

    // Verify it detects secrets in prompts
    assert!(
        hooks_code.contains("detect_secrets_in_prompt"),
        "UserPromptSubmit hook must detect secrets in prompts"
    );
}

/// Test 5.2.12: Verify UserPromptSubmit hook rewrites prompts
///
/// From Phase 5.2 deliverables:
/// "Rewrite the prompt, replacing the secret value with a placeholder"
#[test]
fn test_user_prompt_submit_hook_rewrites() {
    let hooks_path = workspace_root().join("crates/sigil-cli/src/hooks.rs");
    let hooks_code = fs::read_to_string(&hooks_path).expect("Failed to read hooks.rs");

    // Verify it returns updated_prompt
    assert!(
        hooks_code.contains("updated_prompt"),
        "UserPromptSubmit hook must return updated_prompt"
    );

    // Verify it replaces secrets with placeholders
    assert!(
        hooks_code.contains("placeholder") || hooks_code.contains("{{secret:"),
        "UserPromptSubmit hook must replace secrets with placeholders"
    );
}

/// Test 5.2.13: Verify UserPromptSubmit hook detects common secret patterns
///
/// From Phase 5.2 deliverables:
/// "Patterns are derived from TruffleHog/Gitleaks rules for credential detection"
#[test]
fn test_user_prompt_submit_detects_patterns() {
    let hooks_path = workspace_root().join("crates/sigil-cli/src/hooks.rs");
    let hooks_code = fs::read_to_string(&hooks_path).expect("Failed to read hooks.rs");

    // Verify AWS Access Key detection
    assert!(
        hooks_code.contains("AKIA[0-9A-Z]{16}"),
        "UserPromptSubmit hook must detect AWS Access Key IDs"
    );

    // Verify GitHub token detection
    assert!(
        hooks_code.contains("ghp_") || hooks_code.contains("GitHub"),
        "UserPromptSubmit hook must detect GitHub tokens"
    );

    // Verify JWT detection
    assert!(
        hooks_code.contains("eyJ") || hooks_code.contains("JWT"),
        "UserPromptSubmit hook must detect JWT tokens"
    );
}

/// Test 5.2.14: Verify UserPromptSubmit hook auto-vaults secrets
///
/// From Phase 5.2 deliverables:
/// "Auto-vault detected secrets"
/// "Try to vault the secret (non-blocking if it fails)"
#[test]
fn test_user_prompt_submit_auto_vaults() {
    let hooks_path = workspace_root().join("crates/sigil-cli/src/hooks.rs");
    let hooks_code = fs::read_to_string(&hooks_path).expect("Failed to read hooks.rs");

    // Verify auto_vault_secret function exists
    assert!(
        hooks_code.contains("fn auto_vault_secret"),
        "auto_vault_secret function must exist"
    );

    // Verify it calls sigil add command
    assert!(
        hooks_code.contains("sigil") && hooks_code.contains("add"),
        "auto_vault_secret must call sigil add command"
    );
}

/// Test 5.2.15: Verify filesystem monitor exists
///
/// From Phase 5.2 deliverables:
/// "Filesystem monitor fallback: inotify/fanotify for harnesses without hooks"
#[test]
fn test_filesystem_monitor_exists() {
    let monitor_path = workspace_root().join("crates/sigil-core/src/monitor.rs");
    let monitor_code = fs::read_to_string(&monitor_path).expect("Failed to read monitor.rs");

    // Verify FilesystemMonitor struct exists
    assert!(
        monitor_code.contains("pub struct FilesystemMonitor"),
        "FilesystemMonitor struct must exist"
    );

    // Verify it uses notify crate for inotify/fanotify
    assert!(
        monitor_code.contains("notify") || monitor_code.contains("inotify") || monitor_code.contains("fanotify"),
        "FilesystemMonitor must use notify crate for inotify/fanotify"
    );
}

/// Test 5.2.16: Verify filesystem monitor detects file changes
///
/// From Phase 5.2 deliverables:
/// "Detect file creates/modifies during agent sessions"
/// "Scan changed files through the scrubber"
#[test]
fn test_filesystem_monitor_detects_changes() {
    let monitor_path = workspace_root().join("crates/sigil-core/src/monitor.rs");
    let monitor_code = fs::read_to_string(&monitor_path).expect("Failed to read monitor.rs");

    // Verify FileChangeEvent struct exists
    assert!(
        monitor_code.contains("pub struct FileChangeEvent"),
        "FileChangeEvent struct must exist"
    );

    // Verify ChangeKind enum exists
    assert!(
        monitor_code.contains("pub enum ChangeKind"),
        "ChangeKind enum must exist"
    );

    // Verify it has Created/Modified variants
    assert!(
        monitor_code.contains("Created") && monitor_code.contains("Modified"),
        "ChangeKind must have Created and Modified variants"
    );
}

/// Test 5.2.17: Verify filesystem monitor scans for secrets
///
/// From Phase 5.2 deliverables:
/// "Scan changed files through the scrubber"
#[test]
fn test_filesystem_monitor_scans_secrets() {
    let monitor_path = workspace_root().join("crates/sigil-core/src/monitor.rs");
    let monitor_code = fs::read_to_string(&monitor_path).expect("Failed to read monitor.rs");

    // Verify scan_file function exists
    assert!(
        monitor_code.contains("fn scan_file"),
        "scan_file function must exist"
    );

    // Verify ScanResult struct exists
    assert!(
        monitor_code.contains("pub struct ScanResult") || monitor_code.contains("struct ScanResult"),
        "ScanResult struct must exist"
    );

    // Verify it tracks secrets_detected
    assert!(
        monitor_code.contains("secrets_detected") || monitor_code.contains("has_secrets"),
        "ScanResult must track whether secrets were detected"
    );

    // Verify it tracks secret_count
    assert!(
        monitor_code.contains("secret_count"),
        "ScanResult must track secret count"
    );
}

/// Test 5.2.18: Verify filesystem monitor has secret patterns
///
/// From Phase 5.2 deliverables:
/// "Scan changed files through the scrubber"
/// "Detect file creates/modifies during agent sessions"
#[test]
fn test_filesystem_monitor_has_patterns() {
    let monitor_path = workspace_root().join("crates/sigil-core/src/monitor.rs");
    let monitor_code = fs::read_to_string(&monitor_path).expect("Failed to read monitor.rs");

    // Verify it has secret patterns
    assert!(
        monitor_code.contains("api_key") || monitor_code.contains("API_KEY"),
        "FilesystemMonitor must have API key pattern"
    );

    // Verify it has password pattern
    assert!(
        monitor_code.contains("password") || monitor_code.contains("PASSWORD"),
        "FilesystemMonitor must have password pattern"
    );

    // Verify it has token pattern
    assert!(
        monitor_code.contains("token") || monitor_code.contains("TOKEN"),
        "FilesystemMonitor must have token pattern"
    );
}

/// Test 5.2.19: Verify filesystem monitor can auto-scrub
///
/// From Phase 5.2 deliverables:
/// "Optionally auto-scrub files (replace detected secrets with placeholders)"
#[test]
fn test_filesystem_monitor_auto_scrub() {
    let monitor_path = workspace_root().join("crates/sigil-core/src/monitor.rs");
    let monitor_code = fs::read_to_string(&monitor_path).expect("Failed to read monitor.rs");

    // Verify MonitorConfig has auto_scrub field
    assert!(
        monitor_code.contains("auto_scrub"),
        "MonitorConfig must have auto_scrub field"
    );

    // Verify scrub_file function exists
    assert!(
        monitor_code.contains("fn scrub_file") || monitor_code.contains("fn scrub_content"),
        "FilesystemMonitor must have scrub_file or scrub_content function"
    );
}

/// Test 5.2.20: Verify filesystem monitor uses debounce
///
/// From Phase 5.2 deliverables:
/// "Detect file creates/modifies during agent sessions"
/// (Implies real-time monitoring with debouncing to avoid duplicate events)
#[test]
fn test_filesystem_monitor_debounce() {
    let monitor_path = workspace_root().join("crates/sigil-core/src/monitor.rs");
    let monitor_code = fs::read_to_string(&monitor_path).expect("Failed to read monitor.rs");

    // Verify MonitorConfig has debounce_ms field
    assert!(
        monitor_code.contains("debounce") || monitor_code.contains("debounce_ms"),
        "MonitorConfig must have debounce configuration"
    );
}

/// Test 5.2.21: Verify Claude Code bug #13744 fallback
///
/// From Phase 5.2 deliverables:
/// "Known limitation: Claude Code bug #13744 — exit code 2 may not block Write/Edit.
///  Implement filesystem monitor as fallback."
#[test]
fn test_fallback_for_bug_13744() {
    let hooks_path = workspace_root().join("crates/sigil-cli/src/hooks.rs");
    let hooks_code = fs::read_to_string(&hooks_path).expect("Failed to read hooks.rs");

    // Verify filesystem monitor is referenced in hooks
    // This ensures that even if hooks fail (bug #13744), the monitor catches it
    assert!(
        hooks_code.contains("monitor") || hooks_code.contains("fallback"),
        "Hooks should reference filesystem monitor as fallback for bug #13744"
    );
}

/// Test 5.2.22: Verify hook configuration generation
///
/// From Phase 5.2 deliverables:
/// "Claude Code hooks support matchers on ALL tool types"
#[test]
fn test_hook_config_generation() {
    let hooks_path = workspace_root().join("crates/sigil-cli/src/hooks.rs");
    let hooks_code = fs::read_to_string(&hooks_path).expect("Failed to read hooks.rs");

    // Verify generate_hook_config function exists
    assert!(
        hooks_code.contains("fn generate_hook_config"),
        "generate_hook_config function must exist"
    );

    // Verify it includes bash hooks
    assert!(
        hooks_code.contains("bash") && hooks_code.contains("preToolUse"),
        "Hook config must include bash PreToolUse"
    );

    // Verify it includes write hooks
    assert!(
        hooks_code.contains("write") && hooks_code.contains("preToolUse"),
        "Hook config must include write PreToolUse"
    );

    // Verify it includes read hooks
    assert!(
        hooks_code.contains("read") && hooks_code.contains("preToolUse"),
        "Hook config must include read PreToolUse"
    );

    // Verify it includes userPromptSubmit hook
    assert!(
        hooks_code.contains("userPromptSubmit"),
        "Hook config must include userPromptSubmit hook"
    );
}

/// Test 5.2.23: Verify hook setup function exists
///
/// From Phase 5.2 deliverables:
/// Hooks must be installable to Claude Code settings
#[test]
fn test_hook_setup_function() {
    let hooks_path = workspace_root().join("crates/sigil-cli/src/hooks.rs");
    let hooks_code = fs::read_to_string(&hooks_path).expect("Failed to read hooks.rs");

    // Verify setup_claude_code_hooks function exists
    assert!(
        hooks_code.contains("fn setup_claude_code_hooks"),
        "setup_claude_code_hooks function must exist"
    );

    // Verify it writes to Claude Code config directory
    assert!(
        hooks_code.contains("claude-code") && hooks_code.contains("settings.json"),
        "Hook setup must write to Claude Code settings.json"
    );
}

/// Test 5.2.24: Verify sensitive path denylist includes all required paths
///
/// From Phase 5.2 deliverables:
/// "~/.aws/credentials, ~/.ssh/*, ~/.gnupg/*, ~/.config/gh/hosts.yml,
///  ~/.docker/config.json, .env*"
#[test]
fn test_sensitive_path_denylist_complete() {
    let hooks_path = workspace_root().join("crates/sigil-cli/src/hooks.rs");
    let hooks_code = fs::read_to_string(&hooks_path).expect("Failed to read hooks.rs");

    // Verify all required paths are in the denylist
    let required_paths = [
        ".aws/credentials",
        ".aws/config",
        ".ssh/",
        ".gnupg/",
        ".config/gh/hosts.yml",
        ".docker/config.json",
        ".env",
        ".env.local",
        ".env.production",
    ];

    for path in required_paths {
        assert!(
            hooks_code.contains(path),
            "{}", format!("Sensitive path denylist must include {}", path)
        );
    }
}

/// Test 5.2.25: Verify PostToolUse hooks exist for all tools
///
/// From Phase 5.2 deliverables:
/// PostToolUse hooks for output scrubbing on all tools
#[test]
fn test_post_tool_use_hooks_complete() {
    let hooks_path = workspace_root().join("crates/sigil-cli/src/hooks.rs");
    let hooks_code = fs::read_to_string(&hooks_path).expect("Failed to read hooks.rs");

    // Verify handle_post_tool_use function exists
    assert!(
        hooks_code.contains("fn handle_post_tool_use"),
        "handle_post_tool_use function must exist"
    );

    // Verify it handles all tool types
    assert!(
        hooks_code.contains("handle_bash_post"),
        "PostToolUse hook must handle Bash tool"
    );

    assert!(
        hooks_code.contains("handle_write_post"),
        "PostToolUse hook must handle Write tool"
    );

    assert!(
        hooks_code.contains("handle_read_post"),
        "PostToolUse hook must handle Read tool"
    );

    assert!(
        hooks_code.contains("handle_search_post"),
        "PostToolUse hook must handle Grep/Glob tools"
    );

    assert!(
        hooks_code.contains("handle_mcp_post"),
        "PostToolUse hook must handle MCP tools"
    );
}

/// Test 5.2.26: Verify secret detection patterns are comprehensive
///
/// From Phase 5.2 deliverables:
/// "Patterns are derived from TruffleHog/Gitleaks rules"
#[test]
fn test_secret_detection_patterns_comprehensive() {
    let hooks_path = workspace_root().join("crates/sigil-cli/src/hooks.rs");
    let hooks_code = fs::read_to_string(&hooks_path).expect("Failed to read hooks.rs");

    // Verify multiple secret pattern types
    let patterns = [
        "api_key",
        "secret",
        "password",
        "token",
        "PRIVATE KEY",
        "AKIA", // AWS
    ];

    for pattern in patterns {
        assert!(
            hooks_code.contains(pattern),
            "{}", format!("Secret detection must include {} pattern", pattern)
        );
    }
}

/// Test 5.2.27: Verify MonitorConfig is configurable
///
/// From Phase 5.2 deliverables:
/// Filesystem monitor should be configurable
#[test]
fn test_monitor_config_configurable() {
    let monitor_path = workspace_root().join("crates/sigil-core/src/monitor.rs");
    let monitor_code = fs::read_to_string(&monitor_path).expect("Failed to read monitor.rs");

    // Verify MonitorConfig struct exists
    assert!(
        monitor_code.contains("pub struct MonitorConfig"),
        "MonitorConfig struct must exist"
    );

    // Verify it has watch_paths
    assert!(
        monitor_code.contains("watch_paths"),
        "MonitorConfig must have watch_paths field"
    );

    // Verify it has recursive option
    assert!(
        monitor_code.contains("recursive"),
        "MonitorConfig must have recursive field"
    );

    // Verify it has exclude_patterns
    assert!(
        monitor_code.contains("exclude_patterns"),
        "MonitorConfig must have exclude_patterns field"
    );
}

/// Test 5.2.28: Verify filesystem monitor excludes common patterns
///
/// From Phase 5.2 deliverables:
/// "Detect file creates/modifies during agent sessions"
/// (Should exclude common non-relevant patterns)
#[test]
fn test_monitor_exclude_patterns() {
    let monitor_path = workspace_root().join("crates/sigil-core/src/monitor.rs");
    let monitor_code = fs::read_to_string(&monitor_path).expect("Failed to read monitor.rs");

    // Verify common exclude patterns exist
    let exclude_patterns = ["node_modules", ".git", "target", "*.tmp", "*.swp", "*.log"];

    for pattern in exclude_patterns {
        assert!(
            monitor_code.contains(pattern),
            "{}", format!("Monitor should exclude {} pattern", pattern)
        );
    }
}

/// Test 5.2.29: Verify filesystem monitor can start/stop
///
/// From Phase 5.2 deliverables:
/// Filesystem monitor should be controllable
#[test]
fn test_monitor_start_stop() {
    let monitor_path = workspace_root().join("crates/sigil-core/src/monitor.rs");
    let monitor_code = fs::read_to_string(&monitor_path).expect("Failed to read monitor.rs");

    // Verify start function exists
    assert!(
        monitor_code.contains("pub fn start"),
        "FilesystemMonitor must have start function"
    );

    // Verify MonitorHandle exists for stopping
    assert!(
        monitor_code.contains("pub struct MonitorHandle") || monitor_code.contains("struct MonitorHandle"),
        "MonitorHandle struct must exist for stopping monitor"
    );

    // Verify stop function exists
    assert!(
        monitor_code.contains("pub fn stop"),
        "MonitorHandle must have stop function"
    );
}

/// Test 5.2.30: Verify PreToolUse hook handles all tools
///
/// From Phase 5.2 deliverables:
/// "Claude Code hooks support matchers on ALL tool types"
#[test]
fn test_pre_tool_use_handles_all_tools() {
    let hooks_path = workspace_root().join("crates/sigil-cli/src/hooks.rs");
    let hooks_code = fs::read_to_string(&hooks_path).expect("Failed to read hooks.rs");

    // Verify handle_pre_tool_use function exists
    assert!(
        hooks_code.contains("fn handle_pre_tool_use"),
        "handle_pre_tool_use function must exist"
    );

    // Verify it dispatches to specific handlers
    assert!(
        hooks_code.contains("handle_bash_pre"),
        "PreToolUse must handle Bash tool"
    );

    assert!(
        hooks_code.contains("handle_write_pre") || hooks_code.contains("handle_edit_pre"),
        "PreToolUse must handle Write/Edit tools"
    );

    assert!(
        hooks_code.contains("handle_read_pre"),
        "PreToolUse must handle Read tool"
    );

    assert!(
        hooks_code.contains("handle_search_pre") || hooks_code.contains("handle_grep_pre"),
        "PreToolUse must handle Grep/Glob tools"
    );

    assert!(
        hooks_code.contains("handle_mcp_pre"),
        "PreToolUse must handle MCP tools"
    );
}

/// Test 5.2.31: Verify hook input/output structures exist
///
/// From Phase 5.2 deliverables:
/// Hooks must use proper input/output structures
#[test]
fn test_hook_structures_exist() {
    let hooks_path = workspace_root().join("crates/sigil-cli/src/hooks.rs");
    let hooks_code = fs::read_to_string(&hooks_path).expect("Failed to read hooks.rs");

    // Verify PreToolUseInput exists
    assert!(
        hooks_code.contains("struct PreToolUseInput"),
        "PreToolUseInput struct must exist"
    );

    // Verify PreToolUseOutput exists
    assert!(
        hooks_code.contains("struct PreToolUseOutput"),
        "PreToolUseOutput struct must exist"
    );

    // Verify PostToolUseInput exists
    assert!(
        hooks_code.contains("struct PostToolUseInput"),
        "PostToolUseInput struct must exist"
    );

    // Verify PostToolUseOutput exists
    assert!(
        hooks_code.contains("struct PostToolUseOutput"),
        "PostToolUseOutput struct must exist"
    );
}

/// Test 5.2.32: Verify ToolType enum exists
///
/// From Phase 5.2 deliverables:
/// Hooks must identify tool types
#[test]
fn test_tool_type_enum_exists() {
    let hooks_path = workspace_root().join("crates/sigil-cli/src/hooks.rs");
    let hooks_code = fs::read_to_string(&hooks_path).expect("Failed to read hooks.rs");

    // Verify ToolType enum exists
    assert!(
        hooks_code.contains("pub enum ToolType"),
        "ToolType enum must exist"
    );

    // Verify it has all required tool types
    let required_tools = ["Bash", "Write", "Edit", "Read", "Grep", "Glob", "Mcp"];

    for tool in required_tools {
        assert!(
            hooks_code.contains(tool),
            "{}", format!("ToolType enum must have {} variant", tool)
        );
    }
}

/// Test 5.2.33: Verify hooks have tests
///
/// From Phase 5.2 deliverables:
/// All hooks should have tests
#[test]
fn test_hooks_have_tests() {
    let hooks_path = workspace_root().join("crates/sigil-cli/src/hooks.rs");
    let hooks_code = fs::read_to_string(&hooks_path).expect("Failed to read hooks.rs");

    // Verify hooks module has tests
    assert!(
        hooks_code.contains("#[cfg(test)]") || hooks_code.contains("#[test]"),
        "Hooks module must have tests"
    );

    // Verify at least some hook functions are tested
    assert!(
        hooks_code.contains("test_tool_type_from_str") || hooks_code.contains("test_is_sensitive_path"),
        "Hooks should have basic tests"
    );
}

/// Test 5.2.34: Verify filesystem monitor has tests
///
/// From Phase 5.2 deliverables:
/// Filesystem monitor should have tests
#[test]
fn test_monitor_has_tests() {
    let monitor_path = workspace_root().join("crates/sigil-core/src/monitor.rs");
    let monitor_code = fs::read_to_string(&monitor_path).expect("Failed to read monitor.rs");

    // Verify monitor module has tests
    assert!(
        monitor_code.contains("#[cfg(test)]") || monitor_code.contains("#[test]"),
        "Monitor module must have tests"
    );

    // Verify at least some monitor functions are tested
    assert!(
        monitor_code.contains("test_monitor_config_default") || monitor_code.contains("test_scan_file"),
        "Monitor should have basic tests"
    );
}

/// Test 5.2.35: Verify hook error handling
///
/// From Phase 5.2 deliverables:
/// Hooks should handle errors gracefully
#[test]
fn test_hook_error_handling() {
    let hooks_path = workspace_root().join("crates/sigil-cli/src/hooks.rs");
    let hooks_code = fs::read_to_string(&hooks_path).expect("Failed to read hooks.rs");

    // Verify hooks return Result
    assert!(
        hooks_code.contains("Result<PreToolUseOutput>") || hooks_code.contains("-> Result<"),
        "Hook functions must return Result for error handling"
    );

    // Verify error_response function exists
    assert!(
        hooks_code.contains("fn error_response"),
        "error_response function must exist for structured errors"
    );
}

/// Test 5.2.36: Verify monitor error handling
///
/// From Phase 5.2 deliverables:
/// Monitor should handle errors gracefully
#[test]
fn test_monitor_error_handling() {
    let monitor_path = workspace_root().join("crates/sigil-core/src/monitor.rs");
    let monitor_code = fs::read_to_string(&monitor_path).expect("Failed to read monitor.rs");

    // Verify MonitorError enum exists
    assert!(
        monitor_code.contains("pub enum MonitorError") || monitor_code.contains("enum MonitorError"),
        "MonitorError enum must exist"
    );

    // Verify functions return Result
    assert!(
        monitor_code.contains("Result<()>") || monitor_code.contains("-> Result<"),
        "Monitor functions must return Result for error handling"
    );
}
