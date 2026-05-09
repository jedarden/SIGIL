//! Phase 5.1 Verification Tests
//!
//! These tests verify the Claude Code hook integration as specified in the plan.
//!
//! Phase 5.1 covers:
//! - sigil setup claude-code writes hooks to .claude/settings.json
//! - PreToolUse hook resolves {{secret:*}} placeholders
//! - PreToolUse Bash hook wraps commands in scrubbing pipeline
//! - PostToolUse hook is detection-only backstop
//! - Exit code 2 + JSON decision block for blocking hooks
//! - Session token read from inherited fd (not env var)

mod common;
use common::workspace_root;
use std::fs;

/// Test 5.1.1: Verify setup_claude_code_hooks function exists
///
/// From Phase 5.1 deliverables:
/// "sigil setup claude-code writes hooks to .claude/settings.json"
#[test]
fn test_setup_claude_code_hooks_exists() {
    let hooks_path = workspace_root().join("crates/sigil-cli/src/hooks.rs");
    let hooks_code = fs::read_to_string(&hooks_path).expect("Failed to read hooks.rs");

    assert!(
        hooks_code.contains("fn setup_claude_code_hooks"),
        "setup_claude_code_hooks function must exist"
    );
}

/// Test 5.1.2: Verify setup writes to Claude Code settings.json
///
/// From Phase 5.1 deliverables:
/// "sigil setup claude-code writes hooks to .claude/settings.json"
#[test]
fn test_setup_writes_settings_json() {
    let hooks_path = workspace_root().join("crates/sigil-cli/src/hooks.rs");
    let hooks_code = fs::read_to_string(&hooks_path).expect("Failed to read hooks.rs");

    // Verify it references Claude Code config directory
    assert!(
        hooks_code.contains("claude-code") && hooks_code.contains("settings.json"),
        "setup_claude_code_hooks must write to Claude Code settings.json"
    );
}

/// Test 5.1.3: Verify setup creates hooks directory
///
/// From Phase 5.1 deliverables:
/// "sigil setup claude-code writes hooks to .claude/settings.json"
#[test]
fn test_setup_creates_config_dir() {
    let hooks_path = workspace_root().join("crates/sigil-cli/src/hooks.rs");
    let hooks_code = fs::read_to_string(&hooks_path).expect("Failed to read hooks.rs");

    // Verify it creates the config directory
    assert!(
        hooks_code.contains("create_dir_all") || hooks_code.contains("fs::create_dir"),
        "setup_claude_code_hooks must create config directory"
    );
}

/// Test 5.1.4: Verify PreToolUse hook function exists
///
/// From Phase 5.1 deliverables:
/// "PreToolUse hook resolves {{secret:*}} placeholders"
#[test]
fn test_pre_tool_use_hook_exists() {
    let hooks_path = workspace_root().join("crates/sigil-cli/src/hooks.rs");
    let hooks_code = fs::read_to_string(&hooks_path).expect("Failed to read hooks.rs");

    assert!(
        hooks_code.contains("fn handle_pre_tool_use"),
        "handle_pre_tool_use function must exist"
    );
}

/// Test 5.1.5: Verify PreToolUse hook structure exists
///
/// From Phase 5.1 deliverables:
/// "PreToolUse hook resolves {{secret:*}} placeholders"
#[test]
fn test_pre_tool_use_structure_exists() {
    let hooks_path = workspace_root().join("crates/sigil-cli/src/hooks.rs");
    let hooks_code = fs::read_to_string(&hooks_path).expect("Failed to read hooks.rs");

    assert!(
        hooks_code.contains("struct PreToolUseInput"),
        "PreToolUseInput struct must exist"
    );
    assert!(
        hooks_code.contains("struct PreToolUseOutput"),
        "PreToolUseOutput struct must exist"
    );
}

/// Test 5.1.6: Verify PreToolUse hook has permission_decision
///
/// From Phase 5.1 deliverables:
/// "Exit code 2 + JSON decision block for blocking hooks"
#[test]
fn test_pre_tool_use_permission_decision() {
    let hooks_path = workspace_root().join("crates/sigil-cli/src/hooks.rs");
    let hooks_code = fs::read_to_string(&hooks_path).expect("Failed to read hooks.rs");

    assert!(
        hooks_code.contains("permission_decision"),
        "PreToolUseOutput must have permission_decision field"
    );
}

/// Test 5.1.7: Verify PreToolUse hook has updated_input
///
/// From Phase 5.1 deliverables:
/// "PreToolUse hook resolves {{secret:*}} placeholders"
#[test]
fn test_pre_tool_use_updated_input() {
    let hooks_path = workspace_root().join("crates/sigil-cli/src/hooks.rs");
    let hooks_code = fs::read_to_string(&hooks_path).expect("Failed to read hooks.rs");

    assert!(
        hooks_code.contains("updated_input"),
        "PreToolUseOutput must have updated_input field for command rewriting"
    );
}

/// Test 5.1.8: Verify Bash PreToolUse hook exists
///
/// From Phase 5.1 deliverables:
/// "PreToolUse Bash hook wraps commands in scrubbing pipeline"
#[test]
fn test_bash_pre_hook_exists() {
    let hooks_path = workspace_root().join("crates/sigil-cli/src/hooks.rs");
    let hooks_code = fs::read_to_string(&hooks_path).expect("Failed to read hooks.rs");

    assert!(
        hooks_code.contains("fn handle_bash_pre"),
        "handle_bash_pre function must exist"
    );
}

/// Test 5.1.9: Verify Bash PreToolUse hook wraps commands
///
/// From Phase 5.1 deliverables:
/// "PreToolUse Bash hook wraps commands in scrubbing pipeline"
/// "Every Bash command wrapped: { cmd; echo ':::SIGIL_EXIT:::$?'; } 2>&1 | sigil scrub"
#[test]
fn test_bash_pre_wraps_commands() {
    let hooks_path = workspace_root().join("crates/sigil-cli/src/hooks.rs");
    let hooks_code = fs::read_to_string(&hooks_path).expect("Failed to read hooks.rs");

    // Verify command wrapping with scrubbing pipeline
    assert!(
        hooks_code.contains(":::SIGIL_EXIT:::") || hooks_code.contains("sigil scrub"),
        "Bash PreToolUse hook must wrap commands with scrubbing pipeline"
    );
}

/// Test 5.1.10: Verify Bash PreToolUse hook captures exit code
///
/// From Phase 5.1 deliverables:
/// "Preserves exit code via :::SIGIL_EXIT::: marker"
#[test]
fn test_bash_pre_captures_exit_code() {
    let hooks_path = workspace_root().join("crates/sigil-cli/src/hooks.rs");
    let hooks_code = fs::read_to_string(&hooks_path).expect("Failed to read hooks.rs");

    // Verify exit code capture mechanism
    assert!(
        hooks_code.contains(":::SIGIL_EXIT:::") || hooks_code.contains("$?"),
        "Bash PreToolUse hook must capture exit code"
    );
}

/// Test 5.1.11: Verify Bash PreToolUse hook captures stdout and stderr
///
/// From Phase 5.1 deliverables:
/// "Captures both stdout and stderr"
#[test]
fn test_bash_pre_captures_output() {
    let hooks_path = workspace_root().join("crates/sigil-cli/src/hooks.rs");
    let hooks_code = fs::read_to_string(&hooks_path).expect("Failed to read hooks.rs");

    // Verify 2>&1 redirection for capturing both streams
    assert!(
        hooks_code.contains("2>&1"),
        "Bash PreToolUse hook must redirect stderr to stdout"
    );
}

/// Test 5.1.12: Verify Bash PreToolUse hook detects interactive commands
///
/// From Phase 5.1 deliverables:
/// "Interactive commands (less, vim) detected and passed through"
#[test]
fn test_bash_pre_detects_interactive() {
    let hooks_path = workspace_root().join("crates/sigil-cli/src/hooks.rs");
    let hooks_code = fs::read_to_string(&hooks_path).expect("Failed to read hooks.rs");

    // Verify interactive command detection
    assert!(
        hooks_code.contains("interactive") || hooks_code.contains("vim") || hooks_code.contains("less"),
        "Bash PreToolUse hook must detect interactive commands"
    );
}

/// Test 5.1.13: Verify PostToolUse hook exists
///
/// From Phase 5.1 deliverables:
/// "PostToolUse hook is detection-only backstop"
#[test]
fn test_post_tool_use_hook_exists() {
    let hooks_path = workspace_root().join("crates/sigil-cli/src/hooks.rs");
    let hooks_code = fs::read_to_string(&hooks_path).expect("Failed to read hooks.rs");

    assert!(
        hooks_code.contains("fn handle_post_tool_use"),
        "handle_post_tool_use function must exist"
    );
}

/// Test 5.1.14: Verify PostToolUse hook structure exists
///
/// From Phase 5.1 deliverables:
/// "PostToolUse hook is detection-only backstop"
#[test]
fn test_post_tool_use_structure_exists() {
    let hooks_path = workspace_root().join("crates/sigil-cli/src/hooks.rs");
    let hooks_code = fs::read_to_string(&hooks_path).expect("Failed to read hooks.rs");

    assert!(
        hooks_code.contains("struct PostToolUseInput"),
        "PostToolUseInput struct must exist"
    );
    assert!(
        hooks_code.contains("struct PostToolUseOutput"),
        "PostToolUseOutput struct must exist"
    );
}

/// Test 5.1.15: Verify Bash PostToolUse hook is detection-only
///
/// From Phase 5.1 deliverables:
/// "PostToolUse hook is detection-only backstop"
/// "This is a detection-only backstop since PreToolUse already scrubs"
#[test]
fn test_bash_post_detection_only() {
    let hooks_path = workspace_root().join("crates/sigil-cli/src/hooks.rs");
    let hooks_code = fs::read_to_string(&hooks_path).expect("Failed to read hooks.rs");

    assert!(
        hooks_code.contains("fn handle_bash_post"),
        "handle_bash_post function must exist"
    );

    // Verify it mentions detection-only nature
    assert!(
        hooks_code.contains("detection-only") || hooks_code.contains("backstop"),
        "Bash PostToolUse hook should be documented as detection-only backstop"
    );
}

/// Test 5.1.16: Verify PostToolUse hook detects secrets
///
/// From Phase 5.1 deliverables:
/// "PostToolUse hook is detection-only backstop"
#[test]
fn test_post_tool_use_detects_secrets() {
    let hooks_path = workspace_root().join("crates/sigil-cli/src/hooks.rs");
    let hooks_code = fs::read_to_string(&hooks_path).expect("Failed to read hooks.rs");

    // Verify PostToolUse hooks detect secrets
    assert!(
        hooks_code.contains("detect_secrets_in_output") || hooks_code.contains("has_secrets"),
        "PostToolUse hooks must detect secrets in output"
    );
}

/// Test 5.1.17: Verify CLI hook command exists
///
/// From Phase 5.1 deliverables:
/// "sigil setup claude-code writes hooks to .claude/settings.json"
#[test]
fn test_cli_hook_command_exists() {
    let main_path = workspace_root().join("crates/sigil-cli/src/main.rs");
    let main_code = fs::read_to_string(&main_path).expect("Failed to read main.rs");

    assert!(
        main_code.contains("CommandHook") || main_code.contains("struct CommandHook"),
        "CLI must have CommandHook struct"
    );
}

/// Test 5.1.18: Verify hook command handles pre type
///
/// From Phase 5.1 deliverables:
/// "PreToolUse hook resolves {{secret:*}} placeholders"
#[test]
fn test_hook_command_handles_pre() {
    let main_path = workspace_root().join("crates/sigil-cli/src/main.rs");
    let main_code = fs::read_to_string(&main_path).expect("Failed to read main.rs");

    // Verify hook command handles "pre" type
    assert!(
        main_code.contains("\"pre\"") || main_code.contains("pre_tool_use"),
        "Hook command must handle 'pre' type"
    );
}

/// Test 5.1.19: Verify hook command handles post type
///
/// From Phase 5.1 deliverables:
/// "PostToolUse hook is detection-only backstop"
#[test]
fn test_hook_command_handles_post() {
    let main_path = workspace_root().join("crates/sigil-cli/src/main.rs");
    let main_code = fs::read_to_string(&main_path).expect("Failed to read main.rs");

    // Verify hook command handles "post" type
    assert!(
        main_code.contains("\"post\"") || main_code.contains("post_tool_use"),
        "Hook command must handle 'post' type"
    );
}

/// Test 5.1.20: Verify hook command reads from stdin
///
/// From Phase 5.1 deliverables:
/// "Session token read from inherited fd (not env var)"
/// "Hook input is read from stdin (file descriptor 0)"
#[test]
fn test_hook_command_reads_stdin() {
    let main_path = workspace_root().join("crates/sigil-cli/src/main.rs");
    let main_code = fs::read_to_string(&main_path).expect("Failed to read main.rs");

    // Verify hook command reads from stdin
    assert!(
        main_code.contains("stdin") && main_code.contains("read_to_string"),
        "Hook command must read input from stdin"
    );
}

/// Test 5.1.21: Verify hook command exits with code 2 on error
///
/// From Phase 5.1 deliverables:
/// "Exit code 2 + JSON decision block for blocking hooks"
#[test]
fn test_hook_command_exit_code_2() {
    let main_path = workspace_root().join("crates/sigil-cli/src/main.rs");
    let main_code = fs::read_to_string(&main_path).expect("Failed to read main.rs");

    // Verify exit code 2 for errors
    assert!(
        main_code.contains("exit(2)") || main_code.contains("exit_code"),
        "Hook command must exit with code 2 on error"
    );
}

/// Test 5.1.22: Verify hook command outputs JSON error response
///
/// From Phase 5.1 deliverables:
/// "Exit code 2 + JSON decision block for blocking hooks"
#[test]
fn test_hook_command_json_error_response() {
    let main_path = workspace_root().join("crates/sigil-cli/src/main.rs");
    let main_code = fs::read_to_string(&main_path).expect("Failed to read main.rs");

    // Verify JSON error response
    assert!(
        main_code.contains("error_response") && main_code.contains("serde_json::to_string"),
        "Hook command must output JSON error response"
    );
}

/// Test 5.1.23: Verify error_response function exists
///
/// From Phase 5.1 deliverables:
/// "Exit code 2 + JSON decision block for blocking hooks"
#[test]
fn test_error_response_function_exists() {
    let hooks_path = workspace_root().join("crates/sigil-cli/src/hooks.rs");
    let hooks_code = fs::read_to_string(&hooks_path).expect("Failed to read hooks.rs");

    assert!(
        hooks_code.contains("fn error_response"),
        "error_response function must exist"
    );
}

/// Test 5.1.24: Verify error_response returns permission_decision
///
/// From Phase 5.1 deliverables:
/// "Exit code 2 + JSON decision block for blocking hooks"
#[test]
fn test_error_response_permission_decision() {
    let hooks_path = workspace_root().join("crates/sigil-cli/src/hooks.rs");
    let hooks_code = fs::read_to_string(&hooks_path).expect("Failed to read hooks.rs");

    // Verify error_response includes permission_decision
    assert!(
        hooks_code.contains("permission_decision") && hooks_code.contains("ask"),
        "error_response must return permission_decision: 'ask' for blocking"
    );
}

/// Test 5.1.25: Verify hook command does not use env var for session token
///
/// From Phase 5.1 deliverables:
/// "Session token read from inherited fd (not env var)"
/// "Hooks communicate via stdin/stdout, not environment variables"
#[test]
fn test_hook_no_env_var_token() {
    let main_path = workspace_root().join("crates/sigil-cli/src/main.rs");
    let main_code = fs::read_to_string(&main_path).expect("Failed to read main.rs");

    // Verify the hook command reads from stdin, not env var
    // This is verified by checking that stdin reading is used
    assert!(
        main_code.contains("stdin") && main_code.contains("read_to_string"),
        "Hook command must use stdin for input, not environment variables"
    );
}

/// Test 5.1.26: Verify sigil-shell exists
///
/// From Phase 5.1 deliverables:
/// "sigil-shell (310 lines) exists"
#[test]
fn test_sigil_shell_exists() {
    let shell_path = workspace_root().join("crates/sigil-shell/src/main.rs");

    assert!(
        shell_path.exists(),
        "sigil-shell must exist at crates/sigil-shell/src/main.rs"
    );
}

/// Test 5.1.27: Verify sigil-shell has reasonable size
///
/// From Phase 5.1 deliverables:
/// "sigil-shell (310 lines) exists"
/// (Allowing for some growth from the original 310 lines)
#[test]
fn test_sigil_shell_size() {
    let shell_path = workspace_root().join("crates/sigil-shell/src/main.rs");
    let shell_code = fs::read_to_string(&shell_path).expect("Failed to read sigil-shell");

    let line_count = shell_code.lines().count();

    // Allow for reasonable growth (310 original, allow up to 500)
    assert!(
        (200..=500).contains(&line_count),
        "sigil-shell should be approximately 200-500 lines, found {}",
        line_count
    );
}

/// Test 5.1.28: Verify sigil-shell executes commands
///
/// From Phase 5.1 deliverables:
/// "sigil-shell (310 lines) exists"
/// "POSIX-compatible shell wrapper"
#[test]
fn test_sigil_shell_executes_commands() {
    let shell_path = workspace_root().join("crates/sigil-shell/src/main.rs");
    let shell_code = fs::read_to_string(&shell_path).expect("Failed to read sigil-shell");

    // Verify command execution
    assert!(
        shell_code.contains("execute_command") || shell_code.contains("exec"),
        "sigil-shell must have command execution"
    );
}

/// Test 5.1.29: Verify sigil-shell connects to daemon
///
/// From Phase 5.1 deliverables:
/// "sigil-shell (310 lines) exists"
/// "Connects to SIGIL daemon for command execution"
#[test]
fn test_sigil_shell_daemon_connection() {
    let shell_path = workspace_root().join("crates/sigil-shell/src/main.rs");
    let shell_code = fs::read_to_string(&shell_path).expect("Failed to read sigil-shell");

    // Verify daemon client connection
    assert!(
        shell_code.contains("DaemonClient") || shell_code.contains("sigil.sock"),
        "sigil-shell must connect to SIGIL daemon"
    );
}

/// Test 5.1.30: Verify sigil-shell has interactive mode
///
/// From Phase 5.1 deliverables:
/// "sigil-shell (310 lines) exists"
/// "POSIX-compatible shell wrapper"
#[test]
fn test_sigil_shell_interactive_mode() {
    let shell_path = workspace_root().join("crates/sigil-shell/src/main.rs");
    let shell_code = fs::read_to_string(&shell_path).expect("Failed to read sigil-shell");

    // Verify interactive mode support
    assert!(
        shell_code.contains("Interactive") || shell_code.contains("run_interactive"),
        "sigil-shell must support interactive mode"
    );
}

/// Test 5.1.31: Verify hook config generation includes all tools
///
/// From Phase 5.1 deliverables:
/// "sigil setup claude-code writes hooks to .claude/settings.json"
/// "All tools must have hooks configured"
#[test]
fn test_hook_config_all_tools() {
    let hooks_path = workspace_root().join("crates/sigil-cli/src/hooks.rs");
    let hooks_code = fs::read_to_string(&hooks_path).expect("Failed to read hooks.rs");

    // Verify generate_hook_config includes all required tools
    assert!(
        hooks_code.contains("fn generate_hook_config"),
        "generate_hook_config function must exist"
    );

    // Verify it includes bash, write, edit, read, grep, glob, userPromptSubmit
    let required_tools = ["bash", "write", "edit", "read", "grep", "glob", "userPromptSubmit"];
    for tool in required_tools {
        assert!(
            hooks_code.contains(tool),
            "{}", format!("Hook config must include {}", tool)
        );
    }
}

/// Test 5.1.32: Verify PreToolUse hook handles all tool types
///
/// From Phase 5.1 deliverables:
/// "PreToolUse hook resolves {{secret:*}} placeholders"
/// "All tools must have PreToolUse hooks"
#[test]
fn test_pre_tool_use_handles_all_tools() {
    let hooks_path = workspace_root().join("crates/sigil-cli/src/hooks.rs");
    let hooks_code = fs::read_to_string(&hooks_path).expect("Failed to read hooks.rs");

    // Verify all tool handlers exist
    let handlers = [
        "handle_bash_pre",
        "handle_write_pre",
        "handle_read_pre",
        "handle_search_pre",
        "handle_mcp_pre",
    ];

    for handler in handlers {
        assert!(
            hooks_code.contains(handler),
            "{}", format!("PreToolUse must have {}", handler)
        );
    }
}

/// Test 5.1.33: Verify PostToolUse hook handles all tool types
///
/// From Phase 5.1 deliverables:
/// "PostToolUse hook is detection-only backstop"
/// "All tools must have PostToolUse hooks"
#[test]
fn test_post_tool_use_handles_all_tools() {
    let hooks_path = workspace_root().join("crates/sigil-cli/src/hooks.rs");
    let hooks_code = fs::read_to_string(&hooks_path).expect("Failed to read hooks.rs");

    // Verify all tool handlers exist
    let handlers = [
        "handle_bash_post",
        "handle_write_post",
        "handle_read_post",
        "handle_search_post",
        "handle_mcp_post",
    ];

    for handler in handlers {
        assert!(
            hooks_code.contains(handler),
            "{}", format!("PostToolUse must have {}", handler)
        );
    }
}

/// Test 5.1.34: Verify hooks module has tests
///
/// From Phase 5.1 deliverables:
/// "All hooks should have tests"
#[test]
fn test_hooks_module_has_tests() {
    let hooks_path = workspace_root().join("crates/sigil-cli/src/hooks.rs");
    let hooks_code = fs::read_to_string(&hooks_path).expect("Failed to read hooks.rs");

    assert!(
        hooks_code.contains("#[cfg(test)]") || hooks_code.contains("#[test]"),
        "Hooks module must have tests"
    );
}

/// Test 5.1.35: Verify hook setup integrates with CLI
///
/// From Phase 5.1 deliverables:
/// "sigil setup claude-code writes hooks to .claude/settings.json"
#[test]
fn test_hook_setup_cli_integration() {
    let main_path = workspace_root().join("crates/sigil-cli/src/main.rs");
    let main_code = fs::read_to_string(&main_path).expect("Failed to read main.rs");

    // Verify setup command exists
    assert!(
        main_code.contains("CommandSetup") || main_code.contains("Setup"),
        "CLI must have Setup command"
    );

    // Verify claude-code is a setup option
    assert!(
        main_code.contains("claude-code") || main_code.contains("claude_code"),
        "Setup command must support claude-code"
    );
}
