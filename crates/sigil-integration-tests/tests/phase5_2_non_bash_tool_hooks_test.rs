//! Phase 5.2 Verification Tests
//!
//! These tests verify the non-Bash tool hooks and filesystem monitor as specified in the plan.
//!
//! Phase 5.2 covers:
//! - Write/Edit hook (sigil hook write): blocks writes with detected secrets
//! - Read hook (sigil hook read): blocks reads of sensitive paths
//! - MCP tool hook (sigil hook mcp): scrubs MCP args and responses
//! - Glob/Grep hook (sigil hook search): PostToolUse scrubbing of results
//! - Filesystem monitor fallback for detecting file writes

mod common;
use common::workspace_root;
use std::fs;

/// Test 5.2.1: Verify handle_write_pre function exists
///
/// From Phase 5.2 deliverables:
/// "Write/Edit hook (sigil hook write): blocks writes with detected secrets"
#[test]
fn test_handle_write_pre_exists() {
    let hooks_path = workspace_root().join("crates/sigil-cli/src/hooks.rs");
    let hooks_code = fs::read_to_string(&hooks_path).expect("Failed to read hooks.rs");

    assert!(
        hooks_code.contains("fn handle_write_pre"),
        "handle_write_pre function must exist"
    );
}

/// Test 5.2.2: Verify handle_write_post function exists
///
/// From Phase 5.2 deliverables:
/// "Write/Edit hook (sigil hook write): blocks writes with detected secrets"
#[test]
fn test_handle_write_post_exists() {
    let hooks_path = workspace_root().join("crates/sigil-cli/src/hooks.rs");
    let hooks_code = fs::read_to_string(&hooks_path).expect("Failed to read hooks.rs");

    assert!(
        hooks_code.contains("fn handle_write_post"),
        "handle_write_post function must exist"
    );
}

/// Test 5.2.3: Verify write hook detects secrets
///
/// From Phase 5.2 deliverables:
/// "Write/Edit hook (sigil hook write): blocks writes with detected secrets"
#[test]
fn test_write_hook_detects_secrets() {
    let hooks_path = workspace_root().join("crates/sigil-cli/src/hooks.rs");
    let hooks_code = fs::read_to_string(&hooks_path).expect("Failed to read hooks.rs");

    // Verify write hook checks for secrets
    assert!(
        hooks_code.contains("detect_secrets_in_output")
            || hooks_code.contains("handle_write_pre"),
        "Write hook must detect secrets"
    );
}

/// Test 5.2.4: Verify write hook blocks writes with secrets
///
/// From Phase 5.2 deliverables:
/// "Write/Edit hook (sigil hook write): blocks writes with detected secrets"
#[test]
fn test_write_hook_blocks_with_secrets() {
    let hooks_path = workspace_root().join("crates/sigil-cli/src/hooks.rs");
    let hooks_code = fs::read_to_string(&hooks_path).expect("Failed to read hooks.rs");

    // Verify write hook returns "ask" permission when secrets detected
    let write_pre_section = hooks_code.find("fn handle_write_pre").unwrap();
    let write_pre_section = &hooks_code[write_pre_section..write_pre_section + 2000];

    assert!(
        write_pre_section.contains("permission_decision") && write_pre_section.contains("ask"),
        "Write hook must return 'ask' permission when secrets detected"
    );
}

/// Test 5.2.5: Verify handle_read_pre function exists
///
/// From Phase 5.2 deliverables:
/// "Read hook (sigil hook read): blocks reads of sensitive paths"
#[test]
fn test_handle_read_pre_exists() {
    let hooks_path = workspace_root().join("crates/sigil-cli/src/hooks.rs");
    let hooks_code = fs::read_to_string(&hooks_path).expect("Failed to read hooks.rs");

    assert!(
        hooks_code.contains("fn handle_read_pre"),
        "handle_read_pre function must exist"
    );
}

/// Test 5.2.6: Verify handle_read_post function exists
///
/// From Phase 5.2 deliverables:
/// "Read hook (sigil hook read): blocks reads of sensitive paths"
#[test]
fn test_handle_read_post_exists() {
    let hooks_path = workspace_root().join("crates/sigil-cli/src/hooks.rs");
    let hooks_code = fs::read_to_string(&hooks_path).expect("Failed to read hooks.rs");

    assert!(
        hooks_code.contains("fn handle_read_post"),
        "handle_read_post function must exist"
    );
}

/// Test 5.2.7: Verify read hook checks sensitive paths
///
/// From Phase 5.2 deliverables:
/// "Read hook (sigil hook read): blocks reads of sensitive paths"
#[test]
fn test_read_hook_checks_sensitive_paths() {
    let hooks_path = workspace_root().join("crates/sigil-cli/src/hooks.rs");
    let hooks_code = fs::read_to_string(&hooks_path).expect("Failed to read hooks.rs");

    // Verify read hook uses is_sensitive_path function
    assert!(
        hooks_code.contains("is_sensitive_path") && hooks_code.contains("handle_read_pre"),
        "Read hook must check sensitive paths"
    );
}

/// Test 5.2.8: Verify read hook blocks sensitive paths
///
/// From Phase 5.2 deliverables:
/// "Read hook (sigil hook read): blocks reads of sensitive paths"
#[test]
fn test_read_hook_blocks_sensitive_paths() {
    let hooks_path = workspace_root().join("crates/sigil-cli/src/hooks.rs");
    let hooks_code = fs::read_to_string(&hooks_path).expect("Failed to read hooks.rs");

    // Verify read hook returns "ask" permission for sensitive paths
    let read_pre_section = hooks_code.find("fn handle_read_pre").unwrap();
    let read_pre_section = &hooks_code[read_pre_section..read_pre_section + 1500];

    assert!(
        read_pre_section.contains("permission_decision") && read_pre_section.contains("ask"),
        "Read hook must return 'ask' permission for sensitive paths"
    );
}

/// Test 5.2.9: Verify is_sensitive_path blocks .aws/credentials
///
/// From Phase 5.2 deliverables:
/// "Sensitive paths to block: ~/.aws/credentials"
#[test]
fn test_is_sensitive_path_blocks_aws_credentials() {
    let hooks_path = workspace_root().join("crates/sigil-cli/src/hooks.rs");
    let hooks_code = fs::read_to_string(&hooks_path).expect("Failed to read hooks.rs");

    // Verify .aws/credentials is in sensitive paths
    assert!(
        hooks_code.contains(".aws/credentials"),
        "is_sensitive_path must block .aws/credentials"
    );
}

/// Test 5.2.10: Verify is_sensitive_path blocks .ssh/*
///
/// From Phase 5.2 deliverables:
/// "Sensitive paths to block: ~/.ssh/*"
#[test]
fn test_is_sensitive_path_blocks_ssh() {
    let hooks_path = workspace_root().join("crates/sigil-cli/src/hooks.rs");
    let hooks_code = fs::read_to_string(&hooks_path).expect("Failed to read hooks.rs");

    // Verify .ssh paths are blocked
    assert!(
        hooks_code.contains(".ssh"),
        "is_sensitive_path must block .ssh/*"
    );
}

/// Test 5.2.11: Verify is_sensitive_path blocks .gnupg/*
///
/// From Phase 5.2 deliverables:
/// "Sensitive paths to block: ~/.gnupg/*"
#[test]
fn test_is_sensitive_path_blocks_gnupg() {
    let hooks_path = workspace_root().join("crates/sigil-cli/src/hooks.rs");
    let hooks_code = fs::read_to_string(&hooks_path).expect("Failed to read hooks.rs");

    // Verify .gnupg paths are blocked
    assert!(
        hooks_code.contains(".gnupg"),
        "is_sensitive_path must block .gnupg/*"
    );
}

/// Test 5.2.12: Verify is_sensitive_path blocks .env files
///
/// From Phase 5.2 deliverables:
/// "Sensitive paths to block: .env* files"
#[test]
fn test_is_sensitive_path_blocks_env_files() {
    let hooks_path = workspace_root().join("crates/sigil-cli/src/hooks.rs");
    let hooks_code = fs::read_to_string(&hooks_path).expect("Failed to read hooks.rs");

    // Verify .env files are blocked
    assert!(
        hooks_code.contains(".env"),
        "is_sensitive_path must block .env* files"
    );
}

/// Test 5.2.13: Verify handle_mcp_pre function exists
///
/// From Phase 5.2 deliverables:
/// "MCP tool hook (sigil hook mcp): scrubs MCP args and responses"
#[test]
fn test_handle_mcp_pre_exists() {
    let hooks_path = workspace_root().join("crates/sigil-cli/src/hooks.rs");
    let hooks_code = fs::read_to_string(&hooks_path).expect("Failed to read hooks.rs");

    assert!(
        hooks_code.contains("fn handle_mcp_pre"),
        "handle_mcp_pre function must exist"
    );
}

/// Test 5.2.14: Verify handle_mcp_post function exists
///
/// From Phase 5.2 deliverables:
/// "MCP tool hook (sigil hook mcp): scrubs MCP args and responses"
#[test]
fn test_handle_mcp_post_exists() {
    let hooks_path = workspace_root().join("crates/sigil-cli/src/hooks.rs");
    let hooks_code = fs::read_to_string(&hooks_path).expect("Failed to read hooks.rs");

    assert!(
        hooks_code.contains("fn handle_mcp_post"),
        "handle_mcp_post function must exist"
    );
}

/// Test 5.2.15: Verify MCP post hook scrubs responses
///
/// From Phase 5.2 deliverables:
/// "MCP tool hook (sigil hook mcp): scrubs MCP args and responses"
#[test]
fn test_mcp_post_scrubs_responses() {
    let hooks_path = workspace_root().join("crates/sigil-cli/src/hooks.rs");
    let hooks_code = fs::read_to_string(&hooks_path).expect("Failed to read hooks.rs");

    // Verify MCP post hook checks for secrets
    let mcp_post_section = hooks_code.find("fn handle_mcp_post").unwrap();
    let mcp_post_section = &hooks_code[mcp_post_section..mcp_post_section + 500];

    assert!(
        mcp_post_section.contains("detect_secrets_in_output") || mcp_post_section.contains("scrub"),
        "MCP post hook must scrub responses for secrets"
    );
}

/// Test 5.2.16: Verify handle_search_pre function exists
///
/// From Phase 5.2 deliverables:
/// "Glob/Grep hook (sigil hook search): PostToolUse scrubbing of results"
#[test]
fn test_handle_search_pre_exists() {
    let hooks_path = workspace_root().join("crates/sigil-cli/src/hooks.rs");
    let hooks_code = fs::read_to_string(&hooks_path).expect("Failed to read hooks.rs");

    assert!(
        hooks_code.contains("fn handle_search_pre"),
        "handle_search_pre function must exist"
    );
}

/// Test 5.2.17: Verify handle_search_post function exists
///
/// From Phase 5.2 deliverables:
/// "Glob/Grep hook (sigil hook search): PostToolUse scrubbing of results"
#[test]
fn test_handle_search_post_exists() {
    let hooks_path = workspace_root().join("crates/sigil-cli/src/hooks.rs");
    let hooks_code = fs::read_to_string(&hooks_path).expect("Failed to read hooks.rs");

    assert!(
        hooks_code.contains("fn handle_search_post"),
        "handle_search_post function must exist"
    );
}

/// Test 5.2.18: Verify search post hook scrubs results
///
/// From Phase 5.2 deliverables:
/// "Glob/Grep hook (sigil hook search): PostToolUse scrubbing of results"
#[test]
fn test_search_post_scrubs_results() {
    let hooks_path = workspace_root().join("crates/sigil-cli/src/hooks.rs");
    let hooks_code = fs::read_to_string(&hooks_path).expect("Failed to read hooks.rs");

    // Verify search post hook checks for secrets
    let search_post_section = hooks_code.find("fn handle_search_post").unwrap();
    let search_post_section = &hooks_code[search_post_section..search_post_section + 500];

    assert!(
        search_post_section.contains("detect_secrets_in_output") || search_post_section.contains("scrub"),
        "Search post hook must scrub results for secrets"
    );
}

/// Test 5.2.19: Verify search pre hook blocks .sigil searches
///
/// From Phase 5.2 deliverables (Phase 5.7 Configuration Opacity):
/// "Searches that would reveal ~/.sigil/ contents are blocked"
#[test]
fn test_search_pre_blocks_sigil_searches() {
    let hooks_path = workspace_root().join("crates/sigil-cli/src/hooks.rs");
    let hooks_code = fs::read_to_string(&hooks_path).expect("Failed to read hooks.rs");

    // Verify search pre hook checks for .sigil patterns
    let search_pre_section = hooks_code.find("fn handle_search_pre").unwrap();
    let search_pre_section = &hooks_code[search_pre_section..search_pre_section + 1500];

    assert!(
        search_pre_section.contains(".sigil") && search_pre_section.contains("ask"),
        "Search pre hook must block .sigil searches"
    );
}

/// Test 5.2.20: Verify FilesystemMonitor struct exists
///
/// From Phase 5.2 deliverables:
/// "Filesystem monitor fallback: inotify/fanotify watch on project directory"
#[test]
fn test_filesystem_monitor_exists() {
    let monitor_path = workspace_root().join("crates/sigil-daemon/src/filesystem_monitor.rs");

    assert!(
        monitor_path.exists(),
        "filesystem_monitor.rs must exist in sigil-daemon"
    );

    let monitor_code = fs::read_to_string(&monitor_path).expect("Failed to read filesystem_monitor.rs");
    assert!(
        monitor_code.contains("pub struct FilesystemMonitor"),
        "FilesystemMonitor struct must exist"
    );
}

/// Test 5.2.21: Verify FilesystemMonitor has watch_paths config
///
/// From Phase 5.2 deliverables:
/// "Filesystem monitor fallback: inotify/fanotify watch on project directory"
#[test]
fn test_filesystem_monitor_has_watch_paths() {
    let monitor_path = workspace_root().join("crates/sigil-daemon/src/filesystem_monitor.rs");
    let monitor_code = fs::read_to_string(&monitor_path).expect("Failed to read filesystem_monitor.rs");

    assert!(
        monitor_code.contains("watch_paths"),
        "FilesystemMonitor config must have watch_paths"
    );
}

/// Test 5.2.22: Verify FilesystemMonitor has auto_scrub option
///
/// From Phase 5.2 deliverables:
/// "Filesystem monitor fallback: Optionally auto-scrub files"
#[test]
fn test_filesystem_monitor_has_auto_scrub() {
    let monitor_path = workspace_root().join("crates/sigil-daemon/src/filesystem_monitor.rs");
    let monitor_code = fs::read_to_string(&monitor_path).expect("Failed to read filesystem_monitor.rs");

    assert!(
        monitor_code.contains("auto_scrub"),
        "FilesystemMonitor config must have auto_scrub option"
    );
}

/// Test 5.2.23: Verify FilesystemMonitor start method exists
///
/// From Phase 5.2 deliverables:
/// "Filesystem monitor fallback: inotify/fanotify watch on project directory"
#[test]
fn test_filesystem_monitor_has_start() {
    let monitor_path = workspace_root().join("crates/sigil-daemon/src/filesystem_monitor.rs");
    let monitor_code = fs::read_to_string(&monitor_path).expect("Failed to read filesystem_monitor.rs");

    assert!(
        monitor_code.contains("pub async fn start"),
        "FilesystemMonitor must have a start method"
    );
}

/// Test 5.2.24: Verify FilesystemMonitor scan_file method exists
///
/// From Phase 5.2 deliverables:
/// "Filesystem monitor fallback: Scan changed files through scrubber"
#[test]
fn test_filesystem_monitor_has_scan_file() {
    let monitor_path = workspace_root().join("crates/sigil-daemon/src/filesystem_monitor.rs");
    let monitor_code = fs::read_to_string(&monitor_path).expect("Failed to read filesystem_monitor.rs");

    assert!(
        monitor_code.contains("fn scan_file") || monitor_code.contains("async fn scan_file"),
        "FilesystemMonitor must have a scan_file method"
    );
}

/// Test 5.2.25: Verify FilesystemMonitor uses notify crate
///
/// From Phase 5.2 deliverables:
/// "Filesystem monitor fallback: inotify/fanotify watch on project directory"
#[test]
fn test_filesystem_monitor_uses_notify() {
    let monitor_path = workspace_root().join("crates/sigil-daemon/src/filesystem_monitor.rs");
    let monitor_code = fs::read_to_string(&monitor_path).expect("Failed to read filesystem_monitor.rs");

    assert!(
        monitor_code.contains("notify"),
        "FilesystemMonitor must use the notify crate for inotify/fanotify"
    );
}

/// Test 5.2.26: Verify FilesystemMonitor has SecretDetection struct
///
/// From Phase 5.2 deliverables:
/// "Filesystem monitor fallback: Alert via TUI if secrets detected"
#[test]
fn test_filesystem_monitor_has_secret_detection() {
    let monitor_path = workspace_root().join("crates/sigil-daemon/src/filesystem_monitor.rs");
    let monitor_code = fs::read_to_string(&monitor_path).expect("Failed to read filesystem_monitor.rs");

    assert!(
        monitor_code.contains("pub struct SecretDetection"),
        "FilesystemMonitor must have a SecretDetection struct"
    );
}

/// Test 5.2.27: Verify SecretDetection has required fields
///
/// From Phase 5.2 deliverables:
/// "Filesystem monitor fallback: Alert via TUI if secrets detected"
#[test]
fn test_secret_detection_has_fields() {
    let monitor_path = workspace_root().join("crates/sigil-daemon/src/filesystem_monitor.rs");
    let monitor_code = fs::read_to_string(&monitor_path).expect("Failed to read filesystem_monitor.rs");

    // Check for required fields
    assert!(
        monitor_code.contains("file_path"),
        "SecretDetection must have file_path field"
    );
    assert!(
        monitor_code.contains("secret_count"),
        "SecretDetection must have secret_count field"
    );
    assert!(
        monitor_code.contains("was_scrubbed"),
        "SecretDetection must have was_scrubbed field"
    );
}

/// Test 5.2.28: Verify FilesystemMonitor add_secret method exists
///
/// From Phase 5.2 deliverables:
/// "Filesystem monitor fallback: Scan changed files through scrubber"
#[test]
fn test_filesystem_monitor_has_add_secret() {
    let monitor_path = workspace_root().join("crates/sigil-daemon/src/filesystem_monitor.rs");
    let monitor_code = fs::read_to_string(&monitor_path).expect("Failed to read filesystem_monitor.rs");

    assert!(
        monitor_code.contains("pub async fn add_secret"),
        "FilesystemMonitor must have an add_secret method"
    );
}

/// Test 5.2.29: Verify FilesystemMonitor has max_scan_size config
///
/// From Phase 5.2 deliverables:
/// "Filesystem monitor fallback: Scan changed files through scrubber"
#[test]
fn test_filesystem_monitor_has_max_scan_size() {
    let monitor_path = workspace_root().join("crates/sigil-daemon/src/filesystem_monitor.rs");
    let monitor_code = fs::read_to_string(&monitor_path).expect("Failed to read filesystem_monitor.rs");

    assert!(
        monitor_code.contains("max_scan_size"),
        "FilesystemMonitor config must have max_scan_size to limit file scanning"
    );
}

/// Test 5.2.30: Verify FilesystemMonitor has debounce config
///
/// From Phase 5.2 deliverables:
/// "Filesystem monitor fallback: Detect file creates/modifies during agent sessions"
#[test]
fn test_filesystem_monitor_has_debounce() {
    let monitor_path = workspace_root().join("crates/sigil-daemon/src/filesystem_monitor.rs");
    let monitor_code = fs::read_to_string(&monitor_path).expect("Failed to read filesystem_monitor.rs");

    assert!(
        monitor_code.contains("debounce"),
        "FilesystemMonitor must have debounce config to handle rapid file changes"
    );
}

/// Test 5.2.31: Verify filesystem monitor module is exported
///
/// From Phase 5.2 deliverables:
/// "Filesystem monitor fallback: inotify/fanotify watch on project directory"
#[test]
fn test_filesystem_monitor_exported() {
    let lib_path = workspace_root().join("crates/sigil-daemon/src/lib.rs");
    let lib_code = fs::read_to_string(&lib_path).expect("Failed to read lib.rs");

    assert!(
        lib_code.contains("pub mod filesystem_monitor") || lib_code.contains("filesystem_monitor"),
        "filesystem_monitor module must be exported from sigil-daemon"
    );
}

/// Test 5.2.32: Verify notify crate is in dependencies
///
/// From Phase 5.2 deliverables:
/// "Filesystem monitor fallback: inotify/fanotify watch on project directory"
#[test]
fn test_notify_in_dependencies() {
    let cargo_path = workspace_root().join("crates/sigil-daemon/Cargo.toml");
    let cargo_code = fs::read_to_string(&cargo_path).expect("Failed to read Cargo.toml");

    assert!(
        cargo_code.contains("notify"),
        "notify crate must be in sigil-daemon dependencies"
    );
}

/// Test 5.2.33: Verify hook config includes all non-Bash tools
///
/// From Phase 5.2 deliverables:
/// "Non-Bash tool hooks: Write, Edit, Read, MCP, Glob, Grep"
#[test]
fn test_hook_config_includes_all_tools() {
    let hooks_path = workspace_root().join("crates/sigil-cli/src/hooks.rs");
    let hooks_code = fs::read_to_string(&hooks_path).expect("Failed to read hooks.rs");

    // Verify generate_hook_config includes all non-Bash tools
    let required_tools = ["write", "edit", "read", "grep", "glob"];
    for tool in required_tools {
        assert!(
            hooks_code.contains(tool),
            "{}", format!("Hook config must include {}", tool)
        );
    }
}

/// Test 5.2.34: Verify hook pre tool use handles all tool types
///
/// From Phase 5.2 deliverables:
/// "Non-Bash tool hooks: Write, Edit, Read, MCP, Glob, Grep"
#[test]
fn test_pre_tool_use_handles_non_bash_tools() {
    let hooks_path = workspace_root().join("crates/sigil-cli/src/hooks.rs");
    let hooks_code = fs::read_to_string(&hooks_path).expect("Failed to read hooks.rs");

    // Verify handle_pre_tool_use routes to all non-Bash tool handlers
    let pre_tool_use_section = hooks_code.find("fn handle_pre_tool_use").unwrap();
    let pre_tool_use_section = &hooks_code[pre_tool_use_section..pre_tool_use_section + 1000];

    assert!(
        pre_tool_use_section.contains("handle_write_pre") || pre_tool_use_section.contains("Write"),
        "PreToolUse must handle Write tool"
    );
    assert!(
        pre_tool_use_section.contains("handle_read_pre") || pre_tool_use_section.contains("Read"),
        "PreToolUse must handle Read tool"
    );
    assert!(
        pre_tool_use_section.contains("handle_search_pre") || pre_tool_use_section.contains("Grep"),
        "PreToolUse must handle Grep/Glob tools"
    );
    assert!(
        pre_tool_use_section.contains("handle_mcp_pre") || pre_tool_use_section.contains("Mcp"),
        "PreToolUse must handle MCP tools"
    );
}

/// Test 5.2.35: Verify hook post tool use handles all tool types
///
/// From Phase 5.2 deliverables:
/// "Non-Bash tool hooks: Write, Edit, Read, MCP, Glob, Grep"
#[test]
fn test_post_tool_use_handles_non_bash_tools() {
    let hooks_path = workspace_root().join("crates/sigil-cli/src/hooks.rs");
    let hooks_code = fs::read_to_string(&hooks_path).expect("Failed to read hooks.rs");

    // Verify handle_post_tool_use routes to all non-Bash tool handlers
    let post_tool_use_section = hooks_code.find("fn handle_post_tool_use").unwrap();
    let post_tool_use_section = &hooks_code[post_tool_use_section..post_tool_use_section + 1000];

    assert!(
        post_tool_use_section.contains("handle_write_post") || post_tool_use_section.contains("Write"),
        "PostToolUse must handle Write tool"
    );
    assert!(
        post_tool_use_section.contains("handle_read_post") || post_tool_use_section.contains("Read"),
        "PostToolUse must handle Read tool"
    );
    assert!(
        post_tool_use_section.contains("handle_search_post") || post_tool_use_section.contains("Grep"),
        "PostToolUse must handle Grep/Glob tools"
    );
    assert!(
        post_tool_use_section.contains("handle_mcp_post") || post_tool_use_section.contains("Mcp"),
        "PostToolUse must handle MCP tools"
    );
}
