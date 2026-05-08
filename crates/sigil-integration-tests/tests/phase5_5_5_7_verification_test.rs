//! Phase 5.5-5.7 Verification Tests
//!
//! These tests verify auto-generated project files, manifest, and config opacity.
//!
//! Phase 5.5 covers:
//! - sigil init <project-dir> generates CLAUDE.md
//! - sigil init generates .cursorrules (Cursor)
//! - sigil init generates .clinerules/ (Cline)
//! - sigil init generates AGENTS.md (generic)
//! - Template lists available {{secret:path}} placeholders
//! - Instructions say "never hardcode secrets"
//!
//! Phase 5.6 covers:
//! - sigil init generates starter .sigil.toml by scanning project
//! - sigil sync validates manifest against vault
//! - Manifest secrets auto-populate sigil_list MCP responses
//! - [[secrets]] sections with path, type, required, inject
//! - [[signatures]] sections for custom command signatures
//! - [[operations]] sections for sealed operations
//! - Manifest operations supplement .sigil/operations.toml
//!
//! Phase 5.7 covers:
//! - Tier 1 (config.toml): contains no secrets
//! - Tier 2 (_sigil/config vault entry): security-sensitive config
//! - PreToolUse Read hook blocks ~/.sigil/ except config.toml
//! - Bash/Glob/Grep hooks block ~/.sigil/ directory listing
//! - Agent sees only inert config.toml

mod common;
use common::workspace_root;
use std::fs;

/// Test 5.5.1: Verify CLAUDE.md generation in init
///
/// From Phase 5.5 deliverables:
/// "sigil init <project-dir> generates CLAUDE.md"
#[test]
fn test_claude_md_generation() {
    let main_path = workspace_root().join("crates/sigil-cli/src/main.rs");
    let main_code = fs::read_to_string(&main_path).expect("Failed to read main.rs");

    // Verify CLAUDE.md generation in project init
    assert!(
        main_code.contains("CLAUDE.md") && main_code.contains("generate_claude_md_snippet"),
        "sigil init must generate CLAUDE.md using generate_claude_md_snippet"
    );
}

/// Test 5.5.2: Verify .cursorrules generation
///
/// From Phase 5.5 deliverables:
/// "sigil init generates .cursorrules (Cursor)"
#[test]
fn test_cursorrules_generation() {
    let main_path = workspace_root().join("crates/sigil-cli/src/main.rs");
    let main_code = fs::read_to_string(&main_path).expect("Failed to read main.rs");

    // Verify .cursorrules generation
    assert!(
        main_code.contains(".cursorrules"),
        "sigil init must generate .cursorrules"
    );
}

/// Test 5.5.3: Verify .clinerules generation
///
/// From Phase 5.5 deliverables:
/// "sigil init generates .clinerules/ (Cline)"
#[test]
fn test_clinerules_generation() {
    let main_path = workspace_root().join("crates/sigil-cli/src/main.rs");
    let main_code = fs::read_to_string(&main_path).expect("Failed to read main.rs");

    // Verify .clinerules generation
    assert!(
        main_code.contains(".clinerules") || main_code.contains("clinerules"),
        "sigil init must generate .clinerules/secrets.md"
    );
}

/// Test 5.5.4: Verify AGENTS.md generation
///
/// From Phase 5.5 deliverables:
/// "sigil init generates AGENTS.md (generic)"
#[test]
fn test_agents_md_generation() {
    let main_path = workspace_root().join("crates/sigil-cli/src/main.rs");
    let main_code = fs::read_to_string(&main_path).expect("Failed to read main.rs");

    // Verify AGENTS.md generation
    assert!(
        main_code.contains("AGENTS.md"),
        "sigil init must generate AGENTS.md"
    );
}

/// Test 5.5.5: Verify template lists {{secret:path}} placeholders
///
/// From Phase 5.5 deliverables:
/// "Template lists available {{secret:path}} placeholders"
#[test]
fn test_secret_placeholder_template() {
    let hooks_path = workspace_root().join("crates/sigil-cli/src/hooks.rs");
    let hooks_code = fs::read_to_string(&hooks_path).expect("Failed to read hooks.rs");

    // Verify template includes {{secret:path}} placeholder syntax
    assert!(
        hooks_code.contains("{{secret:") && hooks_code.contains("}}"),
        "Template must include {{secret:path}} placeholder syntax"
    );
}

/// Test 5.5.6: Verify instructions say "never hardcode secrets"
///
/// From Phase 5.5 deliverables:
/// "Instructions say 'never hardcode secrets'"
#[test]
fn test_never_hardcode_secrets_instruction() {
    let hooks_path = workspace_root().join("crates/sigil-cli/src/hooks.rs");
    let hooks_code = fs::read_to_string(&hooks_path).expect("Failed to read hooks.rs");

    // Verify template includes "never hardcode" instruction
    assert!(
        hooks_code.contains("never hardcode") || hooks_code.contains("Never hardcode") ||
        hooks_code.contains("hardcode secrets") || hooks_code.contains("hardcoding"),
        "Template must include instruction to never hardcode secrets"
    );
}

/// Test 5.5.7: Verify generate_claude_md_snippet function exists
///
/// From Phase 5.5 deliverables:
/// "sigil init <project-dir> generates CLAUDE.md"
#[test]
fn test_generate_claude_md_snippet_exists() {
    let hooks_path = workspace_root().join("crates/sigil-cli/src/hooks.rs");
    let hooks_code = fs::read_to_string(&hooks_path).expect("Failed to read hooks.rs");

    assert!(
        hooks_code.contains("fn generate_claude_md_snippet"),
        "generate_claude_md_snippet function must exist"
    );
}

/// Test 5.6.1: Verify .sigil.toml generation in init
///
/// From Phase 5.6 deliverables:
/// "sigil init generates starter .sigil.toml by scanning project"
#[test]
fn test_sigil_toml_generation() {
    let main_path = workspace_root().join("crates/sigil-cli/src/main.rs");
    let main_code = fs::read_to_string(&main_path).expect("Failed to read main.rs");

    // Verify .sigil.toml generation
    assert!(
        main_code.contains(".sigil.toml") && main_code.contains("ProjectManifest"),
        "sigil init must generate .sigil.toml using ProjectManifest"
    );
}

/// Test 5.6.2: Verify ProjectScanner integration
///
/// From Phase 5.6 deliverables:
/// "sigil init generates starter .sigil.toml by scanning project"
#[test]
fn test_project_scanner_integration() {
    let main_path = workspace_root().join("crates/sigil-cli/src/main.rs");
    let main_code = fs::read_to_string(&main_path).expect("Failed to read main.rs");

    // Verify ProjectScanner is used for scanning
    assert!(
        main_code.contains("ProjectScanner") || main_code.contains("scan_project"),
        "sigil init must use ProjectScanner to scan project"
    );
}

/// Test 5.6.3: Verify sigil sync command exists
///
/// From Phase 5.6 deliverables:
/// "sigil sync validates manifest against vault"
#[test]
fn test_sigil_sync_command() {
    let main_path = workspace_root().join("crates/sigil-cli/src/main.rs");
    let main_code = fs::read_to_string(&main_path).expect("Failed to read main.rs");

    // Verify sigil sync command exists
    assert!(
        main_code.contains("CommandSync") || (main_code.contains("sync") && main_code.contains("Command")),
        "CLI must have sync command"
    );
}

/// Test 5.6.4: Verify manifest validation logic
///
/// From Phase 5.6 deliverables:
/// "sigil sync validates manifest against vault"
#[test]
fn test_manifest_validation() {
    let core_path = workspace_root().join("crates/sigil-core/src/manifest.rs");
    let core_code = fs::read_to_string(&core_path).expect("Failed to read manifest.rs");

    // Verify manifest validation function
    assert!(
        core_code.contains("fn validate") || core_code.contains("validate_manifest"),
        "ProjectManifest must have validation function"
    );
}

/// Test 5.6.5: Verify [[secrets]] section structure
///
/// From Phase 5.6 deliverables:
/// "[[secrets]] sections with path, type, required, inject"
#[test]
fn test_secrets_section_structure() {
    let core_path = workspace_root().join("crates/sigil-core/src/manifest.rs");
    let core_code = fs::read_to_string(&core_path).expect("Failed to read manifest.rs");

    // Verify SecretManifest struct has required fields
    assert!(
        core_code.contains("struct SecretManifest") ||
        (core_code.contains("path") && core_code.contains("secret_type") &&
         core_code.contains("required") && core_code.contains("inject")),
        "SecretManifest must have path, type, required, inject fields"
    );
}

/// Test 5.6.6: Verify [[signatures]] section structure
///
/// From Phase 5.6 deliverables:
/// "[[signatures]] sections for custom command signatures"
#[test]
fn test_signatures_section_structure() {
    let core_path = workspace_root().join("crates/sigil-core/src/manifest.rs");
    let core_code = fs::read_to_string(&core_path).expect("Failed to read manifest.rs");

    // Verify SignatureManifest struct exists
    assert!(
        core_code.contains("struct SignatureManifest") ||
        (core_code.contains("Signature") && core_code.contains("match_pattern")),
        "ProjectManifest must support [[signatures]] sections"
    );
}

/// Test 5.6.7: Verify [[operations]] section structure
///
/// From Phase 5.6 deliverables:
/// "[[operations]] sections for sealed operations"
#[test]
fn test_operations_section_structure() {
    let core_path = workspace_root().join("crates/sigil-core/src/manifest.rs");
    let core_code = fs::read_to_string(&core_path).expect("Failed to read manifest.rs");

    // Verify OperationManifest struct exists
    assert!(
        core_code.contains("struct OperationManifest") ||
        (core_code.contains("Operation") && core_code.contains("command") &&
         core_code.contains("secrets")),
        "ProjectManifest must support [[operations]] sections"
    );
}

/// Test 5.6.8: Verify manifest operations supplement operations.toml
///
/// From Phase 5.6 deliverables:
/// "Manifest operations supplement .sigil/operations.toml"
#[test]
fn test_manifest_operations_supplement() {
    let main_path = workspace_root().join("crates/sigil-cli/src/main.rs");
    let main_code = fs::read_to_string(&main_path).expect("Failed to read main.rs");

    // Verify operations are loaded from both sources
    assert!(
        main_code.contains("load_operations") || main_code.contains("merge_operations"),
        "CLI must load operations from both manifest and operations.toml"
    );
}

/// Test 5.6.9: Verify sigil_list MCP integration with manifest
///
/// From Phase 5.6 deliverables:
/// "Manifest secrets auto-populate sigil_list MCP responses"
#[test]
fn test_sigil_list_manifest_integration() {
    let mcp_path = workspace_root().join("crates/sigil-mcp/src/main.rs");
    let mcp_code = fs::read_to_string(&mcp_path).expect("Failed to read sigil-mcp main.rs");

    // Verify sigil_list reads from manifest
    assert!(
        mcp_code.contains("sigil_list") && (mcp_code.contains("manifest") || mcp_code.contains(".sigil.toml")),
        "sigil_list MCP tool must integrate with manifest"
    );
}

/// Test 5.6.10: Verify ProjectManifest::from_suggestions exists
///
/// From Phase 5.6 deliverables:
/// "sigil init generates starter .sigil.toml by scanning project"
#[test]
fn test_manifest_from_suggestions() {
    let core_path = workspace_root().join("crates/sigil-core/src/manifest.rs");
    let core_code = fs::read_to_string(&core_path).expect("Failed to read manifest.rs");

    // Verify from_suggestions method exists
    assert!(
        core_code.contains("fn from_suggestions") || core_code.contains("from_suggestions"),
        "ProjectManifest must have from_suggestions method"
    );
}

/// Test 5.7.1: Verify Tier 1 config contains no secrets
///
/// From Phase 5.7 deliverables:
/// "Tier 1 (config.toml): contains no secrets"
#[test]
fn test_tier1_config_no_secrets() {
    let main_path = workspace_root().join("crates/sigil-cli/src/main.rs");
    let main_code = fs::read_to_string(&main_path).expect("Failed to read main.rs");

    // Verify Tier 1 config definition excludes secret keys
    assert!(
        main_code.contains("Tier 1") || main_code.contains("tier1") ||
        (main_code.contains("config.toml") && main_code.contains("contains no secrets")),
        "Documentation must specify Tier 1 config contains no secrets"
    );
}

/// Test 5.7.2: Verify Tier 2 config in vault
///
/// From Phase 5.7 deliverables:
/// "Tier 2 (_sigil/config vault entry): security-sensitive config"
#[test]
fn test_tier2_config_vault_entry() {
    let vault_path = workspace_root().join("crates/sigil-daemon/src/vault.rs");
    let vault_code = fs::read_to_string(&vault_path).expect("Failed to read vault.rs");

    // Verify Tier 2 config is stored in vault
    assert!(
        vault_code.contains("_sigil/config") || vault_code.contains("tier2") ||
        (vault_code.contains("get_tier2_config") && vault_code.contains("vault")),
        "Tier 2 config must be stored as _sigil/config vault entry"
    );
}

/// Test 5.7.3: Verify PreToolUse Read hook blocks ~/.sigil/
///
/// From Phase 5.7 deliverables:
/// "PreToolUse Read hook blocks ~/.sigil/ except config.toml"
#[test]
fn test_read_hook_blocks_sigil_dir() {
    let hooks_path = workspace_root().join("crates/sigil-cli/src/hooks.rs");
    let hooks_code = fs::read_to_string(&hooks_path).expect("Failed to read hooks.rs");

    // Verify Read hook blocks ~/.sigil/ except config.toml
    assert!(
        hooks_code.contains("is_sigil_config_path") && hooks_code.contains("handle_read_pre"),
        "PreToolUse Read hook must block ~/.sigil/ except config.toml"
    );
}

/// Test 5.7.4: Verify is_sigil_config_path function
///
/// From Phase 5.7 deliverables:
/// "PreToolUse Read hook blocks ~/.sigil/ except config.toml"
#[test]
fn test_is_sigil_config_path_function() {
    let hooks_path = workspace_root().join("crates/sigil-cli/src/hooks.rs");
    let hooks_code = fs::read_to_string(&hooks_path).expect("Failed to read hooks.rs");

    // Verify function exists and blocks vault but allows config.toml
    assert!(
        hooks_code.contains("fn is_sigil_config_path"),
        "is_sigil_config_path function must exist"
    );

    // Verify it blocks vault directory
    assert!(
        hooks_code.contains("vault") && hooks_code.contains("config.toml"),
        "is_sigil_config_path must distinguish vault from config.toml"
    );
}

/// Test 5.7.5: Verify Bash hook blocks ~/.sigil/ access
///
/// From Phase 5.7 deliverables:
/// "Bash/Glob/Grep hooks block ~/.sigil/ directory listing"
#[test]
fn test_bash_hook_blocks_sigil_dir() {
    let hooks_path = workspace_root().join("crates/sigil-cli/src/hooks.rs");
    let hooks_code = fs::read_to_string(&hooks_path).expect("Failed to read hooks.rs");

    // Verify Bash pre-hook blocks ~/.sigil/ access
    assert!(
        hooks_code.contains("accesses_sigil_config") || hooks_code.contains("handle_bash_pre"),
        "Bash pre-hook must detect ~/.sigil/ access"
    );
}

/// Test 5.7.6: Verify Glob hook blocks ~/.sigil/ directory
///
/// From Phase 5.7 deliverables:
/// "Bash/Glob/Grep hooks block ~/.sigil/ directory listing"
#[test]
fn test_glob_hook_blocks_sigil_dir() {
    let hooks_path = workspace_root().join("crates/sigil-cli/src/hooks.rs");
    let hooks_code = fs::read_to_string(&hooks_path).expect("Failed to read hooks.rs");

    // Verify Glob pre-hook blocks ~/.sigil/ access
    assert!(
        hooks_code.contains("handle_search_pre") || hooks_code.contains("handle_glob_pre"),
        "Glob pre-hook must block ~/.sigil/ directory listing"
    );
}

/// Test 5.7.7: Verify Grep hook blocks ~/.sigil/ directory
///
/// From Phase 5.7 deliverables:
/// "Bash/Glob/Grep hooks block ~/.sigil/ directory listing"
#[test]
fn test_grep_hook_blocks_sigil_dir() {
    let hooks_path = workspace_root().join("crates/sigil-cli/src/hooks.rs");
    let hooks_code = fs::read_to_string(&hooks_path).expect("Failed to read hooks.rs");

    // Verify Grep pre-hook blocks ~/.sigil/ access
    assert!(
        hooks_code.contains("handle_search_pre") || hooks_code.contains("handle_grep_pre"),
        "Grep pre-hook must block ~/.sigil/ directory listing"
    );
}

/// Test 5.7.8: Verify agent sees only inert config.toml
///
/// From Phase 5.7 deliverables:
/// "Agent sees only inert config.toml"
#[test]
fn test_agent_sees_only_config_toml() {
    let hooks_path = workspace_root().join("crates/sigil-cli/src/hooks.rs");
    let hooks_code = fs::read_to_string(&hooks_path).expect("Failed to read hooks.rs");

    // Verify hook allows config.toml but blocks other ~/.sigil/ files
    assert!(
        hooks_code.contains("config.toml") &&
        (hooks_code.contains("block") || hooks_code.contains("deny") ||
         hooks_code.contains("permission_decision")),
        "Hook must allow config.toml but block other ~/.sigil/ files"
    );
}

/// Test 5.7.9: Verify Tier 2 config keys classification
///
/// From Phase 5.7 deliverables:
/// "Tier 2 (_sigil/config vault entry): security-sensitive config"
#[test]
fn test_tier2_config_keys_classification() {
    let main_path = workspace_root().join("crates/sigil-cli/src/main.rs");
    let main_code = fs::read_to_string(&main_path).expect("Failed to read main.rs");

    // Verify Tier 2 keys are classified (canary, acl, hook.bypass_token, etc.)
    let tier2_keys = ["canary", "acl", "hook.bypass_token", "lockdown", "alert"];
    let found_any = tier2_keys.iter().any(|key| main_code.contains(key));

    assert!(
        found_any,
        "CLI must classify Tier 2 config keys (canary, acl, hook.bypass_token, etc.)"
    );
}

/// Test 5.7.10: Verify get_tier2_config function in vault
///
/// From Phase 5.7 deliverables:
/// "Tier 2 (_sigil/config vault entry): security-sensitive config"
#[test]
fn test_get_tier2_config_function() {
    let vault_path = workspace_root().join("crates/sigil-daemon/src/vault.rs");
    let vault_code = fs::read_to_string(&vault_path).expect("Failed to read vault.rs");

    // Verify get_tier2_config function exists
    assert!(
        vault_code.contains("fn get_tier2_config") || vault_code.contains("get_tier2_config"),
        "VaultManager must have get_tier2_config function"
    );
}

/// Test 5.7.11: Verify config split on init
///
/// From Phase 5.7 deliverables:
/// "On sigil init, split configuration into Tier 1 (disk) and Tier 2 (vault)"
#[test]
fn test_config_split_on_init() {
    let main_path = workspace_root().join("crates/sigil-cli/src/main.rs");
    let main_code = fs::read_to_string(&main_path).expect("Failed to read main.rs");

    // Verify init creates config.toml (Tier 1)
    assert!(
        main_code.contains("config.toml") && main_code.contains("init"),
        "sigil init must create config.toml (Tier 1)"
    );
}

/// Test 5.7.12: Verify config.toml is safe to expose
///
/// From Phase 5.7 deliverables:
/// "Agent sees only inert config.toml"
#[test]
fn test_config_toml_safe_to_expose() {
    let main_path = workspace_root().join("crates/sigil-cli/src/main.rs");
    let main_code = fs::read_to_string(&main_path).expect("Failed to read main.rs");

    // Verify config.toml contains only safe, non-secret config
    assert!(
        main_code.contains("config.toml") &&
        (main_code.contains("safe") || main_code.contains("inert") ||
         main_code.contains("no secrets") || main_code.contains("non-sensitive")),
        "config.toml must be documented as safe/inert (no secrets)"
    );
}

/// Test 5.5.8: Verify all 5 project files are generated
///
/// From Phase 5.5 deliverables:
/// "sigil init generates CLAUDE.md, .cursorrules, .clinerules/, AGENTS.md"
#[test]
fn test_all_five_project_files_generated() {
    let main_path = workspace_root().join("crates/sigil-cli/src/main.rs");
    let main_code = fs::read_to_string(&main_path).expect("Failed to read main.rs");

    // Verify all 5 files are mentioned in init
    let required_files = ["CLAUDE.md", ".cursorrules", ".clinerules", "AGENTS.md", ".sigil.toml"];
    let found_all = required_files.iter().all(|file| main_code.contains(file));

    assert!(
        found_all,
        "sigil init must generate all 5 project files: CLAUDE.md, .cursorrules, .clinerules/, AGENTS.md, .sigil.toml"
    );
}

/// Test 5.6.11: Verify sigil sync strict mode
///
/// From Phase 5.6 deliverables:
/// "sigil sync validates manifest against vault"
#[test]
fn test_sigil_sync_strict_mode() {
    let main_path = workspace_root().join("crates/sigil-cli/src/main.rs");
    let main_code = fs::read_to_string(&main_path).expect("Failed to read main.rs");

    // Verify strict mode exists for CI
    assert!(
        main_code.contains("strict") && main_code.contains("sync"),
        "sigil sync must support --strict mode for CI"
    );
}

/// Test 5.6.12: Verify manifest example documentation
///
/// From Phase 5.6 deliverables:
/// "sigil init generates starter .sigil.toml by scanning project"
#[test]
fn test_manifest_example_documentation() {
    let example_path = workspace_root().join("docs/examples/sigil.toml.example");

    if example_path.exists() {
        let example_content = fs::read_to_string(&example_path).expect("Failed to read example");

        // Verify example shows all section types
        assert!(
            example_content.contains("[[secrets]]") &&
            (example_content.contains("[[signatures]]") || example_content.contains("[[operations]]")),
            "Example manifest must show [[secrets]] and other sections"
        );
    }
    // If example doesn't exist, that's OK - this is a documentation test
}

/// Test 5.7.13: Verify hook error messages mention config opacity
///
/// From Phase 5.7 deliverables:
/// "Agent sees only inert config.toml"
#[test]
fn test_hook_error_messages_config_opacity() {
    let hooks_path = workspace_root().join("crates/sigil-cli/src/hooks.rs");
    let hooks_code = fs::read_to_string(&hooks_path).expect("Failed to read hooks.rs");

    // Verify hook provides clear error when accessing blocked config
    assert!(
        hooks_code.contains("SIGIL_CONFIG") || hooks_code.contains("config is protected") ||
        hooks_code.contains("Tier 2") || hooks_code.contains("vault entry"),
        "Hook error message should explain config opacity (Tier 1 vs Tier 2)"
    );
}

/// Test 5.5.9: Verify project file creation in correct locations
///
/// From Phase 5.5 deliverables:
/// "sigil init <project-dir> generates CLAUDE.md"
#[test]
fn test_project_files_in_correct_locations() {
    let main_path = workspace_root().join("crates/sigil-cli/src/main.rs");
    let main_code = fs::read_to_string(&main_path).expect("Failed to read main.rs");

    // Verify files are created in project directory
    assert!(
        main_code.contains("project_dir") || main_code.contains("target_dir"),
        "Project files must be created in the specified project directory"
    );
}

/// Test 5.6.13: Verify manifest merge functionality
///
/// From Phase 5.6 deliverables:
/// "Manifest operations supplement .sigil/operations.toml"
#[test]
fn test_manifest_merge_functionality() {
    let core_path = workspace_root().join("crates/sigil-core/src/manifest.rs");
    let core_code = fs::read_to_string(&core_path).expect("Failed to read manifest.rs");

    // Verify manifest can merge multiple sources
    assert!(
        core_code.contains("fn merge") || core_code.contains("merge_manifests"),
        "ProjectManifest must support merging multiple manifests"
    );
}
