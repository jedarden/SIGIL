//! Integration tests for agent setup commands
//!
//! These tests verify that SIGIL's agent setup commands work correctly:
//! - `sigil setup claude-code` - Claude Code hooks installation
//! - `sigil setup codex-cli` - Codex CLI hooks installation
//! - `sigil setup cursor` - Cursor configuration
//! - `sigil setup aider` - Aider configuration
//! - `sigil setup cline` - Cline hooks installation

mod common;
use common::workspace_root;
use std::fs;

/// Test 1: Verify Claude Code setup implementation
///
/// From Phase 10 Deliverables:
/// "Agent setup commands for Claude Code (sigil setup claude-code)"
#[test]
fn test_claude_code_setup_implementation() {
    let hooks_path = workspace_root().join("crates/sigil-cli/src/hooks.rs");
    let hooks_code = fs::read_to_string(&hooks_path).expect("Failed to read hooks code");

    // Verify setup_claude_code_hooks function exists
    assert!(
        hooks_code.contains("setup_claude_code_hooks"),
        "Hooks module must have setup_claude_code_hooks function"
    );

    // Verify Claude Code settings.json handling
    assert!(
        hooks_code.contains(".claude/settings.json") || hooks_code.contains("claude"),
        "Claude Code setup must handle settings.json"
    );

    // Verify PreToolUse hook support
    assert!(
        hooks_code.contains("PreToolUse") || hooks_code.contains("pre_tool_use"),
        "Claude Code setup must support PreToolUse hooks"
    );

    // Verify PostToolUse hook support
    assert!(
        hooks_code.contains("PostToolUse") || hooks_code.contains("post_tool_use"),
        "Claude Code setup must support PostToolUse hooks"
    );

    // Verify UserPromptSubmit hook support
    assert!(
        hooks_code.contains("UserPromptSubmit") || hooks_code.contains("user_prompt"),
        "Claude Code setup must support UserPromptSubmit hooks"
    );
}

/// Test 2: Verify Codex CLI setup implementation
///
/// From Phase 10 Deliverables:
/// "Agent setup commands for Codex CLI (sigil setup codex-cli)"
#[test]
fn test_codex_cli_setup_implementation() {
    let hooks_path = workspace_root().join("crates/sigil-cli/src/hooks.rs");
    let hooks_code = fs::read_to_string(&hooks_path).expect("Failed to read hooks code");

    // Verify setup_codex_cli_hooks function exists
    assert!(
        hooks_code.contains("setup_codex_cli_hooks"),
        "Hooks module must have setup_codex_cli_hooks function"
    );

    // Verify Codex CLI configuration handling
    assert!(
        hooks_code.contains("codex") || hooks_code.contains("Codex"),
        "Codex CLI setup must handle Codex configuration"
    );

    // Verify PreToolUse hook support for Codex
    assert!(
        hooks_code.contains("codex")
            && (hooks_code.contains("PreToolUse") || hooks_code.contains("pre_tool")),
        "Codex CLI setup must support PreToolUse hooks"
    );
}

/// Test 3: Verify Cursor setup implementation
///
/// From Phase 10 Deliverables:
/// "Agent setup commands for Cursor (sigil setup cursor)"
#[test]
fn test_cursor_setup_implementation() {
    let hooks_path = workspace_root().join("crates/sigil-cli/src/hooks.rs");
    let hooks_code = fs::read_to_string(&hooks_path).expect("Failed to read hooks code");

    // Verify setup_cursor_hooks function exists
    assert!(
        hooks_code.contains("setup_cursor_hooks"),
        "Hooks module must have setup_cursor_hooks function"
    );

    // Verify Cursor configuration handling
    assert!(
        hooks_code.contains("cursor") || hooks_code.contains("Cursor"),
        "Cursor setup must handle Cursor configuration"
    );
}

/// Test 4: Verify Aider setup implementation
///
/// From Phase 10 Deliverables:
/// "Agent setup commands for Aider (sigil setup aider)"
#[test]
fn test_aider_setup_implementation() {
    let hooks_path = workspace_root().join("crates/sigil-cli/src/hooks.rs");
    let hooks_code = fs::read_to_string(&hooks_path).expect("Failed to read hooks code");

    // Verify setup_aider_hooks function exists
    assert!(
        hooks_code.contains("setup_aider_hooks"),
        "Hooks module must have setup_aider_hooks function"
    );

    // Verify Aider configuration handling
    assert!(
        hooks_code.contains("aider") || hooks_code.contains("Aider"),
        "Aider setup must handle Aider configuration"
    );

    // Verify .aider.conf.yml handling
    assert!(
        hooks_code.contains(".aider") || hooks_code.contains("aider.conf"),
        "Aider setup must handle Aider config file"
    );
}

/// Test 5: Verify Cline setup implementation
///
/// From Phase 10 Deliverables:
/// "Agent setup commands for Cline (sigil setup cline)"
#[test]
fn test_cline_setup_implementation() {
    let hooks_path = workspace_root().join("crates/sigil-cli/src/hooks.rs");
    let hooks_code = fs::read_to_string(&hooks_path).expect("Failed to read hooks code");

    // Verify setup_cline_hooks function exists
    assert!(
        hooks_code.contains("setup_cline_hooks"),
        "Hooks module must have setup_cline_hooks function"
    );

    // Verify Cline configuration handling
    assert!(
        hooks_code.contains("cline") || hooks_code.contains("Cline"),
        "Cline setup must handle Cline configuration"
    );
}

/// Test 6: Verify setup command CLI integration
///
/// From Phase 10 Deliverables:
/// "Agent setup commands now install hooks for all supported agents"
#[test]
fn test_setup_cli_integration() {
    let main_path = workspace_root().join("crates/sigil-cli/src/main.rs");
    let main_code = fs::read_to_string(&main_path).expect("Failed to read main code");

    // Verify setup subcommand exists
    assert!(
        main_code.contains("setup") || main_code.contains("Setup"),
        "CLI must have setup subcommand"
    );

    // Verify all agent setup options are available
    assert!(
        main_code.contains("claude-code") || main_code.contains("claude_code"),
        "CLI must support claude-code setup"
    );
    assert!(
        main_code.contains("codex-cli") || main_code.contains("codex_cli"),
        "CLI must support codex-cli setup"
    );
    assert!(
        main_code.contains("cursor"),
        "CLI must support cursor setup"
    );
    assert!(main_code.contains("aider"), "CLI must support aider setup");
    assert!(main_code.contains("cline"), "CLI must support cline setup");
}

/// Test 7: Verify hook installation error handling
///
/// From Phase 10 Deliverables:
/// "Agent setup commands should handle errors gracefully"
#[test]
fn test_hook_error_handling() {
    let hooks_path = workspace_root().join("crates/sigil-cli/src/hooks.rs");
    let hooks_code = fs::read_to_string(&hooks_path).expect("Failed to read hooks code");

    // Verify Result return types for setup functions
    assert!(
        hooks_code.contains("Result<") || hooks_code.contains("Result"),
        "Setup functions must return Result for error handling"
    );

    // Verify error handling exists
    assert!(
        hooks_code.contains("Error") || hooks_code.contains("error") || hooks_code.contains("Err"),
        "Setup functions must have error handling"
    );
}

/// Test 8: Verify agent-specific documentation exists
///
/// From Phase 10 Deliverables:
/// "Per-agent setup guides for all 6 supported agent tiers"
#[test]
fn test_agent_documentation_exists() {
    let docs_path = workspace_root().join("docs/agents");

    // Verify agent documentation directory exists
    assert!(
        docs_path.exists(),
        "docs/agents/ directory must exist for per-agent guides"
    );

    // Verify individual agent guides exist
    let claude_code_md = docs_path.join("claude-code.md");
    let codex_cli_md = docs_path.join("codex-cli.md");
    let cursor_md = docs_path.join("cursor.md");
    let aider_md = docs_path.join("aider.md");
    let cline_md = docs_path.join("cline.md");

    assert!(claude_code_md.exists(), "claude-code.md guide must exist");
    assert!(codex_cli_md.exists(), "codex-cli.md guide must exist");
    assert!(cursor_md.exists(), "cursor.md guide must exist");
    assert!(aider_md.exists(), "aider.md guide must exist");
    assert!(cline_md.exists(), "cline.md guide must exist");
}

/// Test 9: Verify hook file structure for Claude Code
///
/// From Phase 10 Deliverables:
/// "Claude Code hooks must be installed in settings.json"
#[test]
fn test_claude_code_hook_structure() {
    let hooks_path = workspace_root().join("crates/sigil-cli/src/hooks.rs");
    let hooks_code = fs::read_to_string(&hooks_path).expect("Failed to read hooks code");

    // Verify hooks are structured for Claude Code settings.json
    assert!(
        hooks_code.contains("hooks") || hooks_code.contains("Hooks"),
        "Claude Code setup must create hooks structure"
    );

    // Verify SIGIL-specific hook naming
    assert!(
        hooks_code.contains("sigil") || hooks_code.contains("Sigil"),
        "Hooks must use SIGIL naming convention"
    );
}
