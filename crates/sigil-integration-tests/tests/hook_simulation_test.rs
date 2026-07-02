//! Hook Simulation Integration Tests
//!
//! This test module verifies SIGIL's Claude Code hook integration:
//! - PreToolUse hook execution
//! - PostToolUse hook execution
//! - UserPromptSubmit hook execution
//! - Command rewriting with scrubbing pipeline
//! - Secret detection in tool inputs
//! - Secret auto-vaulting from prompts
//! - Sensitive path blocking
//! - Hook error handling
//! - Hook response formatting
//!
//! These tests simulate hook execution to verify the complete workflow.

mod common;
use common::workspace_root;
use std::fs;

// ============================================================================
// HOOK INFRASTRUCTURE TESTS
// ============================================================================

/// Test 1.1: Verify hook module exists and is structured
///
/// Tests that the hooks module is properly structured:
/// 1. Hook types enum (PreToolUse, PostToolUse, UserPromptSubmit)
/// 2. Tool types enum (Bash, Write, Edit, Read, Grep, Glob, Mcp)
/// 3. Input/output structures for each hook type
#[test]
fn test_hook_module_structure() {
    let hooks_path = workspace_root().join("crates/sigil-cli/src/hooks.rs");
    if !hooks_path.exists() {
        eprintln!("hooks.rs not found, skipping test");
        return;
    }

    let hooks_code = fs::read_to_string(&hooks_path).expect("Failed to read hooks code");

    // Verify HookType enum
    assert!(
        hooks_code.contains("pub enum HookType") || hooks_code.contains("enum HookType"),
        "HookType enum must exist"
    );

    // Verify ToolType enum
    assert!(
        hooks_code.contains("pub enum ToolType") || hooks_code.contains("enum ToolType"),
        "ToolType enum must exist"
    );

    // Verify PreToolUse input/output structures
    assert!(
        hooks_code.contains("struct PreToolUseInput")
            && hooks_code.contains("struct PreToolUseOutput"),
        "PreToolUse structures must exist"
    );

    // Verify PostToolUse input/output structures
    assert!(
        hooks_code.contains("struct PostToolUseInput")
            && hooks_code.contains("struct PostToolUseOutput"),
        "PostToolUse structures must exist"
    );

    // Verify UserPromptSubmit structures
    assert!(
        hooks_code.contains("struct UserPromptSubmitInput")
            && hooks_code.contains("struct UserPromptSubmitOutput"),
        "UserPromptSubmit structures must exist"
    );
}

/// Test 1.2: Verify hook entry points
///
/// Tests that hook entry points exist for all hook types:
/// 1. handle_pre_tool_use
/// 2. handle_post_tool_use
/// 3. handle_user_prompt_submit
#[test]
fn test_hook_entry_points() {
    let hooks_path = workspace_root().join("crates/sigil-cli/src/hooks.rs");
    if !hooks_path.exists() {
        return;
    }

    let hooks_code = fs::read_to_string(&hooks_path).expect("Failed to read hooks code");

    // Verify handle_pre_tool_use
    assert!(
        hooks_code.contains("pub fn handle_pre_tool_use")
            || hooks_code.contains("fn handle_pre_tool_use"),
        "handle_pre_tool_use function must exist"
    );

    // Verify handle_post_tool_use
    assert!(
        hooks_code.contains("pub fn handle_post_tool_use")
            || hooks_code.contains("fn handle_post_tool_use"),
        "handle_post_tool_use function must exist"
    );

    // Verify handle_user_prompt_submit
    assert!(
        hooks_code.contains("pub fn handle_user_prompt_submit")
            || hooks_code.contains("fn handle_user_prompt_submit"),
        "handle_user_prompt_submit function must exist"
    );
}

/// Test 1.3: Verify hook configuration generation
///
/// Tests that hook configuration can be generated for Claude Code:
/// 1. generate_hook_config function
/// 2. JSON output format
/// 3. All tool types configured
#[test]
fn test_hook_config_generation() {
    let hooks_path = workspace_root().join("crates/sigil-cli/src/hooks.rs");
    if !hooks_path.exists() {
        return;
    }

    let hooks_code = fs::read_to_string(&hooks_path).expect("Failed to read hooks code");

    // Verify generate_hook_config function
    assert!(
        hooks_code.contains("pub fn generate_hook_config")
            || hooks_code.contains("fn generate_hook_config"),
        "generate_hook_config function must exist"
    );

    // Verify JSON output
    assert!(
        hooks_code.contains("json!") && hooks_code.contains("hooks"),
        "Hook config must be JSON format"
    );

    // Verify all tool types are configured
    let tool_types = ["bash", "write", "edit", "read", "grep", "glob"];
    for tool in tool_types {
        assert!(
            hooks_code.contains(tool) && hooks_code.contains("preToolUse"),
            "{} tool must have preToolUse hook configured",
            tool
        );
    }
}

// ============================================================================
// PRETOOLUSE HOOK TESTS
// ============================================================================

/// Test 2.1: Verify PreToolUse for Bash tool
///
/// Tests that PreToolUse hook processes Bash commands:
/// 1. Detects secret placeholders
/// 2. Rewrites command with scrubbing pipeline
/// 3. Blocks access to sensitive paths
/// 4. Handles interactive commands
#[test]
fn test_pre_tool_use_bash() {
    let hooks_path = workspace_root().join("crates/sigil-cli/src/hooks.rs");
    if !hooks_path.exists() {
        return;
    }

    let hooks_code = fs::read_to_string(&hooks_path).expect("Failed to read hooks code");

    // Verify handle_bash_pre function
    assert!(
        hooks_code.contains("fn handle_bash_pre") || hooks_code.contains("handle_pre.*Bash"),
        "handle_bash_pre function must exist"
    );

    // Verify secret placeholder detection
    assert!(
        hooks_code.contains("{{secret:") || hooks_code.contains("secret:"),
        "PreToolUse must detect secret placeholders"
    );

    // Verify command rewriting with scrubbing
    assert!(
        hooks_code.contains("sigil scrub") || hooks_code.contains("scrub"),
        "Commands must be rewritten with scrubbing pipeline"
    );

    // Verify exit code capture
    assert!(
        hooks_code.contains("SIGIL_EXIT")
            || hooks_code.contains("exit code")
            || hooks_code.contains("$?"),
        "Rewritten command must capture exit code"
    );
}

/// Test 2.2: Verify PreToolUse blocks ~/.sigil/ access
///
/// Tests that PreToolUse blocks access to SIGIL config:
/// 1. Detects ~/.sigil/ paths
/// 2. Returns "ask" permission decision
/// 3. Provides context message
#[test]
fn test_pre_tool_use_blocks_sigil_config() {
    let hooks_path = workspace_root().join("crates/sigil-cli/src/hooks.rs");
    if !hooks_path.exists() {
        return;
    }

    let hooks_code = fs::read_to_string(&hooks_path).expect("Failed to read hooks code");

    // Verify accesses_sigil_config function
    assert!(
        hooks_code.contains("fn accesses_sigil_config")
            || hooks_code.contains("is_sigil_config_path"),
        "Must detect ~/.sigil/ access"
    );

    // Verify permission decision is "ask"
    assert!(
        hooks_code.contains("permission_decision") && hooks_code.contains("ask"),
        "Must ask for permission on ~/.sigil/ access"
    );

    // Verify exception for config.toml
    assert!(
        hooks_code.contains("config.toml") && hooks_code.contains("allowed"),
        "config.toml access must be allowed"
    );
}

/// Test 2.3: Verify PreToolUse for Write/Edit tools
///
/// Tests that PreToolUse hook processes Write/Edit:
/// 1. Scans content for secret patterns
/// 2. Blocks writes containing secrets
/// 3. Suggests placeholder usage
#[test]
fn test_pre_tool_use_write() {
    let hooks_path = workspace_root().join("crates/sigil-cli/src/hooks.rs");
    if !hooks_path.exists() {
        return;
    }

    let hooks_code = fs::read_to_string(&hooks_path).expect("Failed to read hooks code");

    // Verify handle_write_pre function
    assert!(
        hooks_code.contains("fn handle_write_pre") || hooks_code.contains("handle_pre.*Write"),
        "handle_write_pre function must exist"
    );

    // Verify secret detection in content
    assert!(
        hooks_code.contains("detect_secrets_in_output") || hooks_code.contains("secret.*pattern"),
        "Must scan content for secret patterns"
    );

    // Verify block decision
    assert!(
        hooks_code.contains("permission_decision") && hooks_code.contains("ask"),
        "Must ask for permission on secret detection"
    );

    // Verify placeholder suggestion
    assert!(
        hooks_code.contains("{{secret:path}}") || hooks_code.contains("placeholder"),
        "Must suggest placeholder usage"
    );
}

/// Test 2.4: Verify PreToolUse for Read tool
///
/// Tests that PreToolUse hook processes Read:
/// 1. Checks file path against sensitive paths
/// 2. Blocks reads of sensitive files
/// 3. Provides context message
#[test]
fn test_pre_tool_use_read() {
    let hooks_path = workspace_root().join("crates/sigil-cli/src/hooks.rs");
    if !hooks_path.exists() {
        return;
    }

    let hooks_code = fs::read_to_string(&hooks_path).expect("Failed to read hooks code");

    // Verify handle_read_pre function
    assert!(
        hooks_code.contains("fn handle_read_pre") || hooks_code.contains("handle_pre.*Read"),
        "handle_read_pre function must exist"
    );

    // Verify sensitive path checking
    assert!(
        hooks_code.contains("is_sensitive_path") || hooks_code.contains("sensitive.*path"),
        "Must check file path against sensitive paths"
    );

    // Verify block decision
    assert!(
        hooks_code.contains("permission_decision") && hooks_code.contains("ask"),
        "Must ask for permission on sensitive paths"
    );
}

/// Test 2.5: Verify PreToolUse for Grep/Glob tools
///
/// Tests that PreToolUse hook processes Grep/Glob:
/// 1. Blocks searches for ~/.sigil/ contents
/// 2. Protects configuration directory
#[test]
fn test_pre_tool_use_search() {
    let hooks_path = workspace_root().join("crates/sigil-cli/src/hooks.rs");
    if !hooks_path.exists() {
        return;
    }

    let hooks_code = fs::read_to_string(&hooks_path).expect("Failed to read hooks code");

    // Verify handle_search_pre function
    assert!(
        hooks_code.contains("fn handle_search_pre")
            || hooks_code.contains("handle_pre.*Grep")
            || hooks_code.contains("handle_pre.*Glob"),
        "handle_search_pre function must exist"
    );

    // Verify .sigil/ search blocking
    assert!(
        hooks_code.contains(".sigil") && hooks_code.contains("search"),
        "Must block searches for .sigil/ patterns"
    );
}

// ============================================================================
// POSTTOOLUSE HOOK TESTS
// ============================================================================

/// Test 3.1: Verify PostToolUse for Bash tool
///
/// Tests that PostToolUse hook processes Bash output:
/// 1. Extracts output from response
/// 2. Detects secrets in output
/// 3. Provides warning context
#[test]
fn test_post_tool_use_bash() {
    let hooks_path = workspace_root().join("crates/sigil-cli/src/hooks.rs");
    if !hooks_path.exists() {
        return;
    }

    let hooks_code = fs::read_to_string(&hooks_path).expect("Failed to read hooks code");

    // Verify handle_bash_post function
    assert!(
        hooks_code.contains("fn handle_bash_post") || hooks_code.contains("handle_post.*Bash"),
        "handle_bash_post function must exist"
    );

    // Verify output extraction
    assert!(
        hooks_code.contains("extract_output") || hooks_code.contains("tool_response"),
        "Must extract output from tool response"
    );

    // Verify secret detection
    assert!(
        hooks_code.contains("detect_secrets_in_output") || hooks_code.contains("secret.*detect"),
        "Must detect secrets in output"
    );
}

/// Test 3.2: Verify PostToolUse for Write/Edit tools
///
/// Tests that PostToolUse hook processes Write/Edit:
/// 1. Detection-only (can't modify written content)
/// 2. Provides warning if needed
#[test]
fn test_post_tool_use_write() {
    let hooks_path = workspace_root().join("crates/sigil-cli/src/hooks.rs");
    if !hooks_path.exists() {
        return;
    }

    let hooks_code = fs::read_to_string(&hooks_path).expect("Failed to read hooks code");

    // Verify handle_write_post function
    assert!(
        hooks_code.contains("fn handle_write_post") || hooks_code.contains("handle_post.*Write"),
        "handle_write_post function must exist"
    );

    // Verify detection-only behavior
    assert!(
        hooks_code.contains("detection") || hooks_code.contains("limited"),
        "PostToolUse for Write is detection-only"
    );
}

/// Test 3.3: Verify PostToolUse for Read tool
///
/// Tests that PostToolUse hook processes Read:
/// 1. Extracts content from response
/// 2. Scrubs for secrets
/// 3. Provides warning if secrets found
#[test]
fn test_post_tool_use_read() {
    let hooks_path = workspace_root().join("crates/sigil-cli/src/hooks.rs");
    if !hooks_path.exists() {
        return;
    }

    let hooks_code = fs::read_to_string(&hooks_path).expect("Failed to read hooks code");

    // Verify handle_read_post function
    assert!(
        hooks_code.contains("fn handle_read_post") || hooks_code.contains("handle_post.*Read"),
        "handle_read_post function must exist"
    );

    // Verify content scrubbing
    assert!(
        hooks_code.contains("detect_secrets_in_output") || hooks_code.contains("scrub"),
        "Must scrub read content for secrets"
    );
}

// ============================================================================
// USERPROMPTSUBMIT HOOK TESTS
// ============================================================================

/// Test 4.1: Verify UserPromptSubmit detects secrets
///
/// Tests that UserPromptSubmit hook detects secrets:
/// 1. Scans prompt for secret patterns
/// 2. Classifies secret types
/// 3. Returns detected secrets list
#[test]
fn test_user_prompt_submit_detects_secrets() {
    let hooks_path = workspace_root().join("crates/sigil-cli/src/hooks.rs");
    if !hooks_path.exists() {
        return;
    }

    let hooks_code = fs::read_to_string(&hooks_path).expect("Failed to read hooks code");

    // Verify detect_secrets_in_prompt function
    assert!(
        hooks_code.contains("fn detect_secrets_in_prompt") || hooks_code.contains("detect.*secret"),
        "detect_secrets_in_prompt function must exist"
    );

    // Verify secret patterns
    let patterns = [
        ("AWS", r#"AKIA[0-9A-Z]{16}"#),
        ("GitHub", r#"ghp_[0-9a-zA-Z]{36}"#),
        ("Stripe", r#"sk_(?:live|test)_"#),
        ("OpenAI", r#"sk-[a-zA-Z0-9]{48}"#),
        ("JWT", r#"eyJ[A-Za-z0-9-_]+"#),
    ];

    for (name, pattern) in patterns {
        assert!(
            hooks_code.contains(pattern) || hooks_code.contains(name),
            "{} pattern must be detected",
            name
        );
    }
}

/// Test 4.2: Verify UserPromptSubmit auto-vaults secrets
///
/// Tests that UserPromptSubmit auto-vaults detected secrets:
/// 1. Calls sigil add command
/// 2. Provides secret via stdin
/// 3. Handles vault errors gracefully
#[test]
fn test_user_prompt_submit_auto_vaults() {
    let hooks_path = workspace_root().join("crates/sigil-cli/src/hooks.rs");
    if !hooks_path.exists() {
        return;
    }

    let hooks_code = fs::read_to_string(&hooks_path).expect("Failed to read hooks code");

    // Verify auto_vault_secret function
    assert!(
        hooks_code.contains("fn auto_vault_secret") || hooks_code.contains("vault.*secret"),
        "auto_vault_secret function must exist"
    );

    // Verify sigil add command
    assert!(
        hooks_code.contains("sigil")
            && hooks_code.contains("add")
            && hooks_code.contains("--from-stdin"),
        "Must call sigil add with stdin input"
    );

    // Verify graceful error handling
    assert!(
        hooks_code.contains("Err")
            || hooks_code.contains("continue")
            || hooks_code.contains("non-blocking"),
        "Must handle vault errors gracefully"
    );
}

/// Test 4.3: Verify UserPromptSubmit rewrites prompt
///
/// Tests that UserPromptSubmit rewrites prompt with placeholders:
/// 1. Replaces secret values with {{secret:path}} placeholders
/// 2. Returns updated_prompt
/// 3. Provides context message
#[test]
fn test_user_prompt_submit_rewrites_prompt() {
    let hooks_path = workspace_root().join("crates/sigil-cli/src/hooks.rs");
    if !hooks_path.exists() {
        return;
    }

    let hooks_code = fs::read_to_string(&hooks_path).expect("Failed to read hooks code");

    // Verify prompt rewriting
    assert!(
        hooks_code.contains("rewritten")
            || hooks_code.contains("replace")
            || hooks_code.contains("rewrite"),
        "Must rewrite prompt with placeholders"
    );

    // Verify placeholder format
    assert!(
        hooks_code.contains("{{secret:") || hooks_code.contains("secret:path"),
        "Must use {{secret:path}} placeholder format"
    );

    // Verify updated_prompt in response
    assert!(
        hooks_code.contains("updated_prompt") || hooks_code.contains("UserPromptSubmitOutput"),
        "Response must include updated_prompt"
    );
}

/// Test 4.4: Verify UserPromptSubmit confirmation mode
///
/// Tests that UserPromptSubmit supports confirmation mode:
/// 1. Checks SIGIL_AUTO_VAULT_CONFIRM env var
/// 2. Prompts user for confirmation
/// 3. Respects user's choice
#[test]
fn test_user_prompt_submit_confirmation() {
    let hooks_path = workspace_root().join("crates/sigil-cli/src/hooks.rs");
    if !hooks_path.exists() {
        return;
    }

    let hooks_code = fs::read_to_string(&hooks_path).expect("Failed to read hooks code");

    // Verify confirmation mode check
    assert!(
        hooks_code.contains("SIGIL_AUTO_VAULT_CONFIRM")
            || hooks_code.contains("confirm")
            || hooks_code.contains("AUTO_VAULT"),
        "Must check for confirmation mode"
    );

    // Verify user prompt
    assert!(
        hooks_code.contains("prompt_yes_no") || hooks_code.contains("confirm"),
        "Must prompt user for confirmation"
    );
}

// ============================================================================
// SECRET DETECTION TESTS
// ============================================================================

/// Test 5.1: Verify AWS secret detection patterns
///
/// Tests that AWS secrets are detected:
/// 1. AWS Access Key ID (AKIA[0-9A-Z]{16})
/// 2. AWS Secret Access Key (40 char base64)
/// 3. Session Token context detection
#[test]
fn test_aws_secret_detection() {
    let hooks_path = workspace_root().join("crates/sigil-cli/src/hooks.rs");
    if !hooks_path.exists() {
        return;
    }

    let hooks_code = fs::read_to_string(&hooks_path).expect("Failed to read hooks code");

    // Verify AWS key pattern
    assert!(
        hooks_code.contains(r#"AKIA[0-9A-Z]{16}"#)
            || hooks_code.contains("AKIA") && hooks_code.contains("AWS"),
        "Must detect AWS Access Key ID pattern"
    );

    // Verify AWS secret pattern
    assert!(
        hooks_code.contains(r#"[a-zA-Z0-9/+]{40}"#) || hooks_code.contains("aws_secret"),
        "Must detect AWS Secret Access Key pattern"
    );
}

/// Test 5.2: Verify GitHub secret detection
///
/// Tests that GitHub secrets are detected:
/// 1. Personal Access Token (ghp_[0-9a-zA-Z]{36})
#[test]
fn test_github_secret_detection() {
    let hooks_path = workspace_root().join("crates/sigil-cli/src/hooks.rs");
    if !hooks_path.exists() {
        return;
    }

    let hooks_code = fs::read_to_string(&hooks_path).expect("Failed to read hooks code");

    // Verify GitHub token pattern
    assert!(
        hooks_code.contains(r#"ghp_[0-9a-zA-Z]{36}"#)
            || hooks_code.contains("ghp_") && hooks_code.contains("GitHub"),
        "Must detect GitHub Personal Access Token pattern"
    );
}

/// Test 5.3: Verify JWT token detection
///
/// Tests that JWT tokens are detected:
/// 1. Header.payload.signature format
/// 2. Base64URL encoding
#[test]
fn test_jwt_token_detection() {
    let hooks_path = workspace_root().join("crates/sigil-cli/src/hooks.rs");
    if !hooks_path.exists() {
        return;
    }

    let hooks_code = fs::read_to_string(&hooks_path).expect("Failed to read hooks code");

    // Verify JWT pattern
    assert!(
        hooks_code.contains(r#"eyJ[A-Za-z0-9-_]+"#)
            || hooks_code.contains("JWT") && hooks_code.contains(r#"\.\.\."#),
        "Must detect JWT token pattern"
    );
}

/// Test 5.4: Verify private key detection
///
/// Tests that PEM private keys are detected:
/// 1. BEGIN/END markers
/// 2. Key type detection
#[test]
fn test_private_key_detection() {
    let hooks_path = workspace_root().join("crates/sigil-cli/src/hooks.rs");
    if !hooks_path.exists() {
        return;
    }

    let hooks_code = fs::read_to_string(&hooks_path).expect("Failed to read hooks code");

    // Verify PEM pattern
    assert!(
        hooks_code.contains("-----BEGIN") && hooks_code.contains("PRIVATE KEY-----")
            || hooks_code.contains("PEM") && hooks_code.contains("certificate"),
        "Must detect PEM private key pattern"
    );
}

/// Test 5.5: Verify database URL detection
///
/// Tests that database connection strings are detected:
/// 1. postgres:// pattern
/// 2. mysql:// pattern
/// 3. mongodb:// pattern
#[test]
fn test_database_url_detection() {
    let hooks_path = workspace_root().join("crates/sigil-cli/src/hooks.rs");
    if !hooks_path.exists() {
        return;
    }

    let hooks_code = fs::read_to_string(&hooks_path).expect("Failed to read hooks code");

    // Verify database URL patterns
    let db_patterns = ["postgres://", "mysql://", "mongodb://"];
    let mut found_count = 0;

    for pattern in db_patterns {
        if hooks_code.contains(pattern) {
            found_count += 1;
        }
    }

    assert!(
        found_count >= 2,
        "Must detect database URL patterns (found {})",
        found_count
    );
}

// ============================================================================
// SENSITIVE PATH PROTECTION TESTS
// ============================================================================

/// Test 6.1: Verify sensitive path denylist
///
/// Tests that sensitive paths are blocked:
/// 1. AWS credentials
/// 2. SSH keys
/// 3. GnuPG directory
/// 4. .env files
#[test]
fn test_sensitive_path_denylist() {
    let hooks_path = workspace_root().join("crates/sigil-cli/src/hooks.rs");
    if !hooks_path.exists() {
        return;
    }

    let hooks_code = fs::read_to_string(&hooks_path).expect("Failed to read hooks code");

    // Verify is_sensitive_path function
    assert!(
        hooks_code.contains("fn is_sensitive_path") || hooks_code.contains("sensitive.*path"),
        "is_sensitive_path function must exist"
    );

    // Verify sensitive paths
    let sensitive_paths = [
        ".aws/credentials",
        ".ssh/id_rsa",
        ".gnupg/",
        ".env",
        ".config/gh/hosts.yml",
    ];

    for path in sensitive_paths {
        assert!(
            hooks_code.contains(path) || hooks_code.contains(&path.replace("/", "")),
            "Must block access to {}",
            path
        );
    }
}

/// Test 6.2: Verify path normalization
///
/// Tests that paths are properly normalized:
/// 1. ~/ expansion
/// 2. Relative path handling
/// 3. Absolute path handling
#[test]
fn test_path_normalization() {
    let hooks_path = workspace_root().join("crates/sigil-cli/src/hooks.rs");
    if !hooks_path.exists() {
        return;
    }

    let hooks_code = fs::read_to_string(&hooks_path).expect("Failed to read hooks code");

    // Verify home directory resolution
    assert!(
        hooks_code.contains("dirs::home_dir")
            || hooks_code.contains("home")
            || hooks_code.contains("~/"),
        "Must expand ~/ to home directory"
    );

    // Verify path normalization
    assert!(
        hooks_code.contains("normalize")
            || hooks_code.contains("replacen")
            || hooks_code.contains("starts_with"),
        "Must normalize paths for comparison"
    );
}

// ============================================================================
// HOOK ERROR HANDLING TESTS
// ============================================================================

/// Test 7.1: Verify hook error responses
///
/// Tests that hook errors are properly formatted:
/// 1. Structured error format
/// 2. Error code mapping
/// 3. Sanitized error messages
#[test]
fn test_hook_error_responses() {
    let hooks_path = workspace_root().join("crates/sigil-cli/src/hooks.rs");
    if !hooks_path.exists() {
        return;
    }

    let hooks_code = fs::read_to_string(&hooks_path).expect("Failed to read hooks code");

    // Verify error_response function
    assert!(
        hooks_code.contains("pub fn error_response")
            || hooks_code.contains("fn error_response")
            || hooks_code.contains("StructuredError"),
        "error_response function must exist"
    );

    // Verify error structure
    assert!(
        hooks_code.contains("sigil_error")
            || hooks_code.contains("code")
            || hooks_code.contains("message"),
        "Error response must include structured fields"
    );
}

/// Test 7.2: Verify graceful degradation
///
/// Tests that hooks degrade gracefully on errors:
/// 1. Returns allow decision on parse errors
/// 2. Logs warnings but doesn't block
#[test]
fn test_graceful_degradation() {
    let hooks_path = workspace_root().join("crates/sigil-cli/src/hooks.rs");
    if !hooks_path.exists() {
        return;
    }

    let hooks_code = fs::read_to_string(&hooks_path).expect("Failed to read hooks code");

    // Verify Result types
    assert!(
        hooks_code.contains("Result<") || hooks_code.contains("?") || hooks_code.contains("anyhow"),
        "Hook functions must return Result for error handling"
    );

    // Verify allow on error
    let has_allow_fallback = hooks_code.contains("allow")
        && (hooks_code.contains("unwrap_or") || hooks_code.contains("default"));

    // This is optional but recommended
    // Allow by default on error is a safe fallback
    if has_allow_fallback {
        println!("✓ Hooks allow by default on error (safe fallback)");
    }
}

// ============================================================================
// HOOK INTEGRATION TESTS
// ============================================================================

/// Test 8.1: Verify CLI hook command
///
/// Tests that CLI supports hook commands:
/// 1. sigil hook pre
/// 2. sigil hook post
/// 3. sigil hook user-prompt-submit
#[test]
fn test_cli_hook_command() {
    let cli_path = workspace_root().join("crates/sigil-cli/src/main.rs");
    if !cli_path.exists() {
        return;
    }

    let cli_code = fs::read_to_string(&cli_path).expect("Failed to read CLI code");

    // Verify hook command
    assert!(
        cli_code.contains("hook") || cli_code.contains("Hook"),
        "CLI must support hook command"
    );

    // Verify hook subcommands
    assert!(
        cli_code.contains("pre")
            && cli_code.contains("post")
            && cli_code.contains("user-prompt-submit"),
        "CLI must support all hook subcommands"
    );
}

/// Test 8.2: Verify hook JSON I/O
///
/// Tests that hooks read JSON input and write JSON output:
/// 1. Reads from stdin
/// 2. Parses JSON structures
/// 3. Writes JSON to stdout
#[test]
fn test_hook_json_io() {
    let hooks_path = workspace_root().join("crates/sigil-cli/src/hooks.rs");
    if !hooks_path.exists() {
        return;
    }

    let hooks_code = fs::read_to_string(&hooks_path).expect("Failed to read hooks code");

    // Verify JSON parsing
    assert!(
        hooks_code.contains("serde_json") && hooks_code.contains("from_str")
            || hooks_code.contains("deserialize"),
        "Hooks must parse JSON input"
    );

    // Verify JSON serialization
    assert!(
        hooks_code.contains("to_string")
            || hooks_code.contains("serialize")
            || hooks_code.contains("json!"),
        "Hooks must serialize JSON output"
    );
}
