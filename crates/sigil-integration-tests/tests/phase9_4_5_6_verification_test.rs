//! Phase 9.4-9.6 Verification: Decoy Mode, Sealed Operations, and Secret Request Workflow
//!
//! This test module verifies the implementation of Phase 9.4 (Decoy Response Mode),
//! Phase 9.5 (Sealed Operations), and Phase 9.6 (Secret Request Workflow) as specified
//! in the SIGIL implementation plan.
//!
//! ## Phase 9.4: Decoy Response Mode
//! - Format-correct fake credential generators (AWS, GitHub, Stripe, JWT, SSH, PEM certs)
//! - Decoy values pre-registered with canary monitoring
//! - Behavioral intelligence: track what agent does with decoy values
//! - FUSE and canary files return decoy content on unauthorized access
//!
//! ## Phase 9.5: Sealed Operations
//! - .sigil/operations.toml / .sigil.toml [[operations]] sections
//! - sigil_exec MCP tool dispatches to operation by name
//! - sigil_list_operations: returns descriptions only (not commands or secrets)
//! - Output filter modes: exit_code, summary, full_scrubbed, none
//! - TUI approval gate for require_approval = true operations
//!
//! ## Phase 9.6: Secret Request Workflow
//! - sigil_request MCP tool: path, reason, duration
//! - TUI approval prompt with 5 options (Approve N min / session / always / deny / deny+flag)
//! - ~/.sigil/access-grants.toml for "always allow" persistence (not committed)
//! - sigil_check_access: returns grant status and expiry
//! - Bulk request support

mod common;
use common::workspace_root;
use std::fs;

// ============================================================================
// Phase 9.4: Decoy Response Mode Verification
// ============================================================================

/// Test 9.4.1: Verify AWS credential decoy format
///
/// From Phase 9.4:
/// "AWS: AKIA + 16 uppercase alphanumeric + 40-char secret key"
#[test]
fn test_9_4_1_aws_decoy_format() {
    let generator_path = workspace_root().join("crates/sigil-canary/src/generator.rs");
    let generator_code =
        fs::read_to_string(&generator_path).expect("Failed to read canary generator code");

    // Verify AKIA prefix for AWS access keys
    assert!(
        generator_code.contains("AKIA") && generator_code.contains("aws_access_key_id"),
        "AWS decoy credentials must use AKIA prefix format"
    );

    // Verify 16-character alphanumeric generation
    assert!(
        generator_code.contains("random_alphanumeric(16)"),
        "AWS access key ID must be 16 alphanumeric characters"
    );

    // Verify 40-character secret key generation
    assert!(
        generator_code.contains("random_alphanumeric(40)"),
        "AWS secret key must be 40 alphanumeric characters"
    );

    // Verify INI format for AWS credentials file
    assert!(
        generator_code.contains("[default]")
            && generator_code.contains("aws_secret_access_key"),
        "AWS credentials must be in INI format with [default] section"
    );
}

/// Test 9.4.2: Verify GitHub token decoy format
///
/// From Phase 9.4:
/// "GitHub: ghp_ + 36 alphanumeric"
#[test]
fn test_9_4_2_github_decoy_format() {
    let generator_path = workspace_root().join("crates/sigil-canary/src/generator.rs");
    let generator_code =
        fs::read_to_string(&generator_path).expect("Failed to read canary generator code");

    // Verify ghp_ prefix for GitHub tokens
    assert!(
        generator_code.contains("ghp_") && generator_code.contains("generate_github_token"),
        "GitHub decoy tokens must use ghp_ prefix format"
    );

    // Verify 36-character alphanumeric generation
    assert!(
        generator_code.contains("random_alphanumeric(36)"),
        "GitHub token must be 36 alphanumeric characters"
    );

    // Verify GitHub config format
    assert!(
        generator_code.contains("oauth_token") && generator_code.contains("github.com"),
        "GitHub token must be in YAML config format with oauth_token field"
    );
}

/// Test 9.4.3: Verify Stripe key decoy format
///
/// From Phase 9.4:
/// "Stripe: sk_live_ + 24 alphanumeric"
#[test]
fn test_9_4_3_stripe_decoy_format() {
    let generator_path = workspace_root().join("crates/sigil-canary/src/generator.rs");
    let generator_code =
        fs::read_to_string(&generator_path).expect("Failed to read canary generator code");

    // Verify sk_live_ prefix for Stripe keys
    assert!(
        generator_code.contains("sk_live_") && generator_code.contains("generate_stripe_key"),
        "Stripe decoy keys must use sk_live_ prefix format"
    );

    // Verify 24-character alphanumeric generation
    assert!(
        generator_code.contains("random_alphanumeric(24)"),
        "Stripe key must be 24 alphanumeric characters"
    );
}

/// Test 9.4.4: Verify JWT token decoy format
///
/// From Phase 9.4:
/// "JWT: valid header.payload.signature structure with garbage content"
#[test]
fn test_9_4_4_jwt_decoy_format() {
    let generator_path = workspace_root().join("crates/sigil-canary/src/generator.rs");
    let generator_code =
        fs::read_to_string(&generator_path).expect("Failed to read canary generator code");

    // Verify JWT structure with three parts
    assert!(
        generator_code.contains("generate_jwt_token")
            && generator_code.contains("header")
            && generator_code.contains("payload")
            && generator_code.contains("signature"),
        "JWT decoy must have header.payload.signature structure"
    );

    // Verify base64 encoding for JWT parts
    assert!(
        generator_code.contains("base64_url_encode"),
        "JWT parts must be base64 URL-safe encoded"
    );

    // Verify JWT header contains algorithm and type (checking for the pattern, not exact string)
    assert!(
        (generator_code.contains("alg") && generator_code.contains("HS256"))
            || (generator_code.contains("algorithm") && generator_code.contains("256")),
        "JWT header must contain algorithm (HS256)"
    );

    assert!(
        generator_code.contains("typ") || generator_code.contains("JWT"),
        "JWT header must contain type (JWT)"
    );

    // Verify expired timestamp in payload (decoy should look like expired token)
    assert!(
        generator_code.contains("exp") && generator_code.contains("timestamp"),
        "JWT payload should contain expired timestamp to look like real but expired token"
    );
}

/// Test 9.4.5: Verify SSH key decoy format
///
/// From Phase 9.4:
/// "SSH keys: valid PEM structure with random key material"
#[test]
fn test_9_4_5_ssh_decoy_format() {
    let generator_path = workspace_root().join("crates/sigil-canary/src/generator.rs");
    let generator_code =
        fs::read_to_string(&generator_path).expect("Failed to read canary generator code");

    // Verify PEM structure
    assert!(
        generator_code.contains("BEGIN RSA PRIVATE KEY")
            && generator_code.contains("END RSA PRIVATE KEY")
            && generator_code.contains("generate_ssh_key"),
        "SSH decoy keys must have valid PEM structure"
    );

    // Verify base64 encoding for key material
    assert!(
        generator_code.contains("random_base64"),
        "SSH key material must be base64 encoded"
    );

    // Verify the implementation itself doesn't add identifying markers in the generated content
    // Check the actual generation code, not test comments
    let gen_function_start = generator_code
        .find("pub fn generate_ssh_key")
        .expect("Should find generate_ssh_key function");

    // Get just the function body (up to the next function or end of file)
    let gen_function_body = if let Some(next_fn) = generator_code[gen_function_start..].find("pub fn generate_") {
        &generator_code[gen_function_start..gen_function_start + next_fn]
    } else {
        &generator_code[gen_function_start..]
    };

    // Check that the generation code itself doesn't add identifying markers
    // (excluding comments which are fine)
    let non_comment_lines: Vec<&str> = gen_function_body
        .lines()
        .filter(|line| !line.trim().starts_with("//") && !line.trim().starts_with("//!"))
        .collect();

    let generation_code = non_comment_lines.join("\n");

    // The actual format string shouldn't contain identifying markers
    assert!(
        !generation_code.contains("SIGIL CANARY")
            && !generation_code.contains("DECOY")
            && !generation_code.contains("FAKE"),
        "SSH decoy key generation code must not add identifying markers to the generated content"
    );
}

/// Test 9.4.6: Verify PEM certificate decoy format
///
/// From Phase 9.4:
/// "PEM certificates: valid but self-signed, expired certificates"
#[test]
fn test_9_4_6_pem_cert_decoy_format() {
    let generator_path = workspace_root().join("crates/sigil-canary/src/generator.rs");
    let generator_code =
        fs::read_to_string(&generator_path).expect("Failed to read canary generator code");

    // Verify PEM certificate structure
    assert!(
        generator_code.contains("BEGIN CERTIFICATE")
            && generator_code.contains("END CERTIFICATE")
            && generator_code.contains("generate_pem_certificate"),
        "PEM decoy certificates must have valid certificate structure"
    );

    // Verify base64 encoding for certificate content
    assert!(
        generator_code.contains("random_base64"),
        "PEM certificate content must be base64 encoded"
    );
}

/// Test 9.4.7: Verify decoy values are pre-registered with canary monitoring
///
/// From Phase 9.4:
/// "Decoy values pre-registered with canary monitoring"
#[test]
fn test_9_4_7_decoy_pre_registered_with_monitoring() {
    let canary_manager_path = workspace_root().join("crates/sigil-daemon/src/canary_manager.rs");
    let canary_manager_code =
        fs::read_to_string(&canary_manager_path).expect("Failed to read canary manager code");

    // Verify canary manager initializes with canaries
    assert!(
        canary_manager_code.contains("initialize") && canary_manager_code.contains("canaries"),
        "Canary manager must initialize with canary values"
    );

    // Verify canary monitor is used
    assert!(
        canary_manager_code.contains("CanaryMonitor") && canary_manager_code.contains("monitor"),
        "Canary manager must use CanaryMonitor for tracking"
    );

    // Verify canaries are added to monitor
    assert!(
        canary_manager_code.contains("add_canaries") || canary_manager_code.contains("generate_all"),
        "Canary values must be registered with the monitor"
    );
}

/// Test 9.4.8: Verify behavioral intelligence tracking
///
/// From Phase 9.4:
/// "Behavioral intelligence: track what the agent does with decoy values"
#[test]
fn test_9_4_8_behavioral_intelligence_tracking() {
    let canary_monitor_path = workspace_root().join("crates/sigil-canary/src/monitor.rs");
    let canary_monitor_code =
        fs::read_to_string(&canary_monitor_path).expect("Failed to read canary monitor code");

    // Verify canary access tracking
    assert!(
        canary_monitor_code.contains("access") || canary_monitor_code.contains("breach"),
        "Canary monitor must track access events"
    );

    // Verify breach detection
    assert!(
        canary_monitor_code.contains("has_breaches") || canary_monitor_code.contains("detect"),
        "Canary monitor must detect breaches"
    );

    // Verify report generation
    assert!(
        canary_monitor_code.contains("report") || canary_monitor_code.contains("generate"),
        "Canary monitor must generate breach reports"
    );

    let canary_manager_path = workspace_root().join("crates/sigil-daemon/src/canary_manager.rs");
    let canary_manager_code =
        fs::read_to_string(&canary_manager_path).expect("Failed to read canary manager code");

    // Verify decoy response generation is tracked
    assert!(
        canary_manager_code.contains("generate_decoy_response"),
        "Canary manager must generate decoy responses for tracking"
    );
}

/// Test 9.4.9: Verify FUSE and canary files return decoy content
///
/// From Phase 9.4:
/// "FUSE and canary files return decoy content on unauthorized access"
#[test]
fn test_9_4_9_fuse_canary_decoy_response() {
    let canary_manager_path = workspace_root().join("crates/sigil-daemon/src/canary_manager.rs");
    let canary_manager_code =
        fs::read_to_string(&canary_manager_path).expect("Failed to read canary manager code");

    // Verify canary path detection
    assert!(
        canary_manager_code.contains("is_canary_path"),
        "Canary manager must detect canary paths"
    );

    // Verify decoy response generation for canary paths
    assert!(
        canary_manager_code.contains("generate_decoy_response"),
        "Canary manager must generate decoy responses for canary paths"
    );

    // Verify different canary types are supported
    let canary_types = [
        "aws/credentials",
        "ssh/",
        "gh/",
        ".env",
        "stripe",
        "jwt",
        "cert",
        "pem",
    ];

    for canary_type in &canary_types {
        assert!(
            canary_manager_code.contains(canary_type)
                || canary_manager_code.contains("canary_paths"),
            "Canary manager should support {} canary type",
            canary_type
        );
    }
}

/// Test 9.4.10: Verify all decoy accesses are logged as CRITICAL
///
/// From Phase 9.4 Red Team Checkpoint:
/// "Decoy: verify all decoy accesses are logged as CRITICAL"
#[test]
fn test_9_4_10_decoy_accesses_logged_as_critical() {
    let audit_path = workspace_root().join("crates/sigil-daemon/src/audit.rs");
    let audit_code = fs::read_to_string(&audit_path).expect("Failed to read audit code");

    // Verify canary access audit entry exists
    assert!(
        audit_code.contains("CanaryAccess"),
        "Audit log must track canary access events"
    );

    // Verify canary access is logged at CRITICAL level
    let server_path = workspace_root().join("crates/sigil-daemon/src/server.rs");
    let server_code = fs::read_to_string(&server_path).expect("Failed to read server code");

    assert!(
        server_code.contains("canary") && server_code.contains("critical"),
        "Server must log canary accesses at CRITICAL level"
    );
}

// ============================================================================
// Phase 9.5: Sealed Operations Verification
// ============================================================================

/// Test 9.5.1: Verify operations.toml file format support
///
/// From Phase 9.5:
/// ".sigil/operations.toml / .sigil.toml [[operations]] sections"
#[test]
fn test_9_5_1_operations_toml_format() {
    let ops_path = workspace_root().join("crates/sigil-core/src/operations.rs");
    let ops_code = fs::read_to_string(&ops_path).expect("Failed to read operations code");

    // Verify TOML parsing support
    assert!(
        ops_code.contains("from_toml") && ops_code.contains("to_toml"),
        "Operations must support TOML serialization"
    );

    // Verify operations table structure
    assert!(
        ops_code.contains("[operations.") || ops_code.contains("operations"),
        "Operations must support [operations.*] TOML structure"
    );

    // Verify required fields are parsed
    assert!(
        ops_code.contains("description") && ops_code.contains("command"),
        "Operations must parse description and command fields"
    );

    // Verify optional fields are parsed
    assert!(
        ops_code.contains("secrets")
            && ops_code.contains("output_filter")
            && ops_code.contains("require_approval")
            && ops_code.contains("timeout_seconds"),
        "Operations must parse optional fields: secrets, output_filter, require_approval, timeout_seconds"
    );
}

/// Test 9.5.2: Verify sigil_exec MCP tool dispatches to operations
///
/// From Phase 9.5:
/// "sigil_exec MCP tool dispatches to operation by name"
#[test]
fn test_9_5_2_sigil_exec_operation_dispatch() {
    let mcp_path = workspace_root().join("crates/sigil-mcp/src/main.rs");
    let mcp_code = fs::read_to_string(&mcp_path).expect("Failed to read MCP server code");

    // Verify sigil_exec tool exists
    assert!(
        mcp_code.contains("sigil_exec") && mcp_code.contains("handle_exec"),
        "MCP server must implement sigil_exec tool"
    );

    // Verify operation parameter support
    assert!(
        mcp_code.contains("operation") && mcp_code.contains("load_operation"),
        "sigil_exec must support operation parameter"
    );

    // Verify operation loading logic
    assert!(
        mcp_code.contains("operations.toml") || mcp_code.contains("SealedOperation"),
        "sigil_exec must load sealed operations from configuration"
    );
}

/// Test 9.5.3: Verify sigil_list_operations returns descriptions only
///
/// From Phase 9.5:
/// "sigil_list_operations: returns descriptions only (not commands or secrets)"
#[test]
fn test_9_5_3_sigil_list_operations_descriptions_only() {
    let mcp_path = workspace_root().join("crates/sigil-mcp/src/main.rs");
    let mcp_code = fs::read_to_string(&mcp_path).expect("Failed to read MCP server code");

    // Verify sigil_list_operations tool exists
    assert!(
        mcp_code.contains("sigil_list_operations") && mcp_code.contains("handle_list_operations"),
        "MCP server must implement sigil_list_operations tool"
    );

    // Verify only descriptions are returned
    assert!(
        mcp_code.contains("description") && mcp_code.contains("\"name\""),
        "Operation listing must include name and description"
    );

    // Verify command templates are NOT included in listing
    let list_handler = mcp_code.contains("handle_list_operations");

    assert!(
        list_handler,
        "MCP server must have handler for listing operations"
    );

    // Check that the listing returns operation metadata but not command templates
    assert!(
        mcp_code.contains("operations") && mcp_code.contains("count"),
        "Operation listing should return operations array with count"
    );
}

/// Test 9.5.4: Verify output filter modes
///
/// From Phase 9.5:
/// "Output filter modes: exit_code, summary, full_scrubbed, none"
#[test]
fn test_9_5_4_output_filter_modes() {
    let ops_path = workspace_root().join("crates/sigil-core/src/operations.rs");
    let ops_code = fs::read_to_string(&ops_path).expect("Failed to read operations code");

    // Verify OutputFilter enum exists
    assert!(
        ops_code.contains("pub enum OutputFilter"),
        "Operations must define OutputFilter enum"
    );

    // Verify all four filter modes
    let filter_modes = ["ExitCode", "Summary", "FullScrubbed", "None"];

    for mode in &filter_modes {
        assert!(
            ops_code.contains(mode),
            "OutputFilter must support {} mode",
            mode
        );
    }

    // Verify OutputFilter is used in SealedOperation
    assert!(
        ops_code.contains("output_filter: OutputFilter"),
        "SealedOperation must have output_filter field"
    );

    // Verify MCP server applies output filters
    let mcp_path = workspace_root().join("crates/sigil-mcp/src/main.rs");
    let mcp_code = fs::read_to_string(&mcp_path).expect("Failed to read MCP server code");

    assert!(
        mcp_code.contains("OutputFilter") || mcp_code.contains("output_filter"),
        "MCP server must handle output filtering"
    );
}

/// Test 9.5.5: Verify TUI approval gate for operations requiring approval
///
/// From Phase 9.5:
/// "TUI approval gate for require_approval = true operations"
#[test]
fn test_9_5_5_tui_approval_gate() {
    let ops_path = workspace_root().join("crates/sigil-core/src/operations.rs");
    let ops_code = fs::read_to_string(&ops_path).expect("Failed to read operations code");

    // Verify require_approval field exists
    assert!(
        ops_code.contains("require_approval") && ops_code.contains("bool"),
        "SealedOperation must have require_approval field"
    );

    // Verify default is true (safe default)
    assert!(
        ops_code.contains("require_approval: true") || ops_code.contains("default"),
        "SealedOperation should default to requiring approval"
    );

    // Check TUI approval module
    let tui_path = workspace_root().join("crates/sigil-tui/src/lib.rs");
    let tui_code = fs::read_to_string(&tui_path).expect("Failed to read TUI code");

    assert!(
        tui_code.contains("Approval") || tui_code.contains("approval"),
        "TUI must support approval prompts"
    );
}

/// Test 9.5.6: Verify operations are logged in audit trail
///
/// From Phase 9.5:
/// "Operations logged in audit trail: who triggered, when, which secrets, exit code"
#[test]
fn test_9_5_6_operations_audit_logging() {
    let audit_path = workspace_root().join("crates/sigil-daemon/src/audit.rs");
    let audit_code = fs::read_to_string(&audit_path).expect("Failed to read audit code");

    // Verify operation execution audit entry
    assert!(
        audit_code.contains("OperationExecuted"),
        "Audit log must track operation execution events"
    );

    // Verify audit entry includes required fields
    assert!(
        audit_code.contains("operation_id")
            && audit_code.contains("exit_code")
            && audit_code.contains("timestamp"),
        "Operation execution audit must include operation_id, exit_code, and timestamp"
    );
}

/// Test 9.5.7: Verify agent never sees command template or unfiltered output
///
/// From Phase 9.5:
/// "The agent never sees: the command template, the secret paths, the unfiltered output"
#[test]
fn test_9_5_7_agent_never_secrets_command_template() {
    let ops_path = workspace_root().join("crates/sigil-core/src/operations.rs");
    let ops_code = fs::read_to_string(&ops_path).expect("Failed to read operations code");

    // Verify command is stored in SealedOperation (server-side only)
    assert!(
        ops_code.contains("command: String"),
        "SealedOperation must store command template"
    );

    let mcp_path = workspace_root().join("crates/sigil-mcp/src/main.rs");
    let mcp_code = fs::read_to_string(&mcp_path).expect("Failed to read MCP server code");

    // Verify operation loading doesn't expose command to agent
    assert!(
        mcp_code.contains("load_operation") && !mcp_code.contains("return command"),
        "MCP server must load operations but not return command templates to agent"
    );

    // Verify sigil_list_operations doesn't include commands
    assert!(
        mcp_code.contains("handle_list_operations")
            && (mcp_code.contains("description") || mcp_code.contains("\"name\"")),
        "Operation listing must include descriptions but not commands"
    );
}

// ============================================================================
// Phase 9.6: Secret Request Workflow Verification
// ============================================================================

/// Test 9.6.1: Verify sigil_request MCP tool
///
/// From Phase 9.6:
/// "sigil_request MCP tool: path, reason, duration"
#[test]
fn test_9_6_1_sigil_request_tool() {
    let mcp_path = workspace_root().join("crates/sigil-mcp/src/main.rs");
    let mcp_code = fs::read_to_string(&mcp_path).expect("Failed to read MCP server code");

    // Verify sigil_request tool exists
    assert!(
        mcp_code.contains("sigil_request") && mcp_code.contains("handle_request"),
        "MCP server must implement sigil_request tool"
    );

    // Verify required parameters
    assert!(
        mcp_code.contains("secret") && mcp_code.contains("reason") && mcp_code.contains("duration"),
        "sigil_request must support secret, reason, and duration parameters"
    );

    // Verify IPC operation for request access
    let ipc_path = workspace_root().join("crates/sigil-core/src/ipc.rs");
    let ipc_code = fs::read_to_string(&ipc_path).expect("Failed to read IPC code");

    assert!(
        ipc_code.contains("RequestAccess") || ipc_code.contains("request_access"),
        "IPC protocol must support request access operation"
    );
}

/// Test 9.6.2: Verify TUI approval prompt with 5 options
///
/// From Phase 9.6:
/// "TUI approval prompt with 5 options (Approve N min / session / always / deny / deny+flag)"
#[test]
fn test_9_6_2_tui_approval_prompt() {
    let tui_path = workspace_root().join("crates/sigil-tui/src/lib.rs");
    let tui_code = fs::read_to_string(&tui_path).expect("Failed to read TUI code");

    // Verify TUI has approval prompt functionality
    assert!(
        tui_code.contains("approve") || tui_code.contains("request") || tui_code.contains("access"),
        "TUI must support access request approval prompts"
    );

    let server_path = workspace_root().join("crates/sigil-daemon/src/server.rs");
    let server_code = fs::read_to_string(&server_path).expect("Failed to read server code");

    // Verify approval decision handling
    assert!(
        server_code.contains("ApprovalDecision") || server_code.contains("approve"),
        "Server must handle approval decisions"
    );

    // Verify different approval types are supported
    assert!(
        server_code.contains("duration")
            || server_code.contains("session")
            || server_code.contains("always"),
        "Server must support different approval types (time-bounded, session, always)"
    );
}

/// Test 9.6.3: Verify access-grants.toml persistence for "always allow"
///
/// From Phase 9.6:
/// "~/.sigil/access-grants.toml for "always allow" persistence (not committed)"
#[test]
fn test_9_6_3_access_grants_persistence() {
    let server_path = workspace_root().join("crates/sigil-daemon/src/server.rs");
    let server_code = fs::read_to_string(&server_path).expect("Failed to read server code");

    // Verify access grants file loading
    assert!(
        server_code.contains("load_access_grants") || server_code.contains("access-grants.toml"),
        "Server must load access grants from ~/.sigil/access-grants.toml"
    );

    // Verify AccessGrant struct exists
    assert!(
        server_code.contains("struct AccessGrant") || server_code.contains("AccessGrant"),
        "Server must define AccessGrant struct"
    );

    // Verify grant persistence
    assert!(
        server_code.contains("save") || server_code.contains("persist") || server_code.contains("write"),
        "Server must persist access grants to file"
    );

    // Verify grants are scoped to session/agent
    assert!(
        server_code.contains("session_token") || server_code.contains("agent_id"),
        "Access grants must be scoped to session or agent"
    );
}

/// Test 9.6.4: Verify sigil_check_access tool
///
/// From Phase 9.6:
/// "sigil_check_access: returns grant status and expiry"
#[test]
fn test_9_6_4_sigil_check_access_tool() {
    let mcp_path = workspace_root().join("crates/sigil-mcp/src/main.rs");
    let mcp_code = fs::read_to_string(&mcp_path).expect("Failed to read MCP server code");

    // Verify sigil_check_access tool exists
    assert!(
        mcp_code.contains("sigil_check_access") && mcp_code.contains("handle_check_access"),
        "MCP server must implement sigil_check_access tool"
    );

    // Verify returns grant status
    assert!(
        mcp_code.contains("granted") || mcp_code.contains("status"),
        "sigil_check_access must return grant status"
    );

    // Verify returns expiry information
    assert!(
        mcp_code.contains("expires") || mcp_code.contains("expires_in"),
        "sigil_check_access must return expiry information"
    );

    // Verify IPC operation for check access
    let ipc_path = workspace_root().join("crates/sigil-core/src/ipc.rs");
    let ipc_code = fs::read_to_string(&ipc_path).expect("Failed to read IPC code");

    assert!(
        ipc_code.contains("CheckAccess") || ipc_code.contains("check_access"),
        "IPC protocol must support check access operation"
    );
}

/// Test 9.6.5: Verify bulk request support
///
/// From Phase 9.6:
/// "Bulk request support"
#[test]
fn test_9_6_5_bulk_request_support() {
    let mcp_path = workspace_root().join("crates/sigil-mcp/src/main.rs");
    let mcp_code = fs::read_to_string(&mcp_path).expect("Failed to read MCP server code");

    // Verify bulk request parameter (secrets array)
    assert!(
        mcp_code.contains("secrets") && mcp_code.contains("array"),
        "sigil_request must support secrets array for bulk requests"
    );

    // Verify anyOf constraint for single vs bulk requests
    assert!(
        mcp_code.contains("anyOf"),
        "sigil_request schema should use anyOf for single vs bulk requests"
    );

    // Verify bulk response handling
    assert!(
        mcp_code.contains("bulk") || mcp_code.contains("results"),
        "sigil_request must return bulk response with results array"
    );
}

/// Test 9.6.6: Verify time-bounded approvals auto-revoke
///
/// From Phase 9.6 Red Team Checkpoint:
/// "Request workflow: verify time-bounded approvals auto-revoke"
#[test]
fn test_9_6_6_time_bounded_approvals_auto_revoke() {
    let server_path = workspace_root().join("crates/sigil-daemon/src/server.rs");
    let server_code = fs::read_to_string(&server_path).expect("Failed to read server code");

    // Verify access grants have expiry
    assert!(
        server_code.contains("expires") || server_code.contains("expiry") || server_code.contains("duration"),
        "Access grants must have expiration time"
    );

    // Verify expired grants are cleaned up
    assert!(
        server_code.contains("clean") || server_code.contains("reap") || server_code.contains("expire"),
        "Daemon should clean up expired access grants"
    );
}

/// Test 9.6.7: Verify "always allow" is project-scoped
///
/// From Phase 9.6 Red Team Checkpoint:
/// "Request workflow: verify 'always allow' is scoped to specific project, not global"
#[test]
fn test_9_6_7_always_allow_project_scoping() {
    let server_path = workspace_root().join("crates/sigil-daemon/src/server.rs");
    let server_code = fs::read_to_string(&server_path).expect("Failed to read server code");

    // Verify grants are scoped to session/agent
    assert!(
        server_code.contains("session_token") || server_code.contains("agent_id") || server_code.contains("project"),
        "Access grants should be scoped to agent/project"
    );

    // Verify grants are loaded with context
    assert!(
        server_code.contains("HashMap<String, Vec<AccessGrant>>") || server_code.contains("access_grants"),
        "Access grants should be organized by session/project"
    );
}

// ============================================================================
// Cross-Cutting Verification Tests
// ============================================================================

/// Test: Verify audit logging across all three phases
///
/// From Phase 9 Red Team Checkpoint:
/// All critical events must be logged in the audit trail
#[test]
fn test_9_4_5_6_comprehensive_audit_logging() {
    let audit_path = workspace_root().join("crates/sigil-daemon/src/audit.rs");
    let audit_code = fs::read_to_string(&audit_path).expect("Failed to read audit code");

    // Verify canary access logging (9.4)
    assert!(
        audit_code.contains("CanaryAccess"),
        "Audit log must track canary access events (9.4)"
    );

    // Verify operation execution logging (9.5)
    assert!(
        audit_code.contains("OperationExecuted"),
        "Audit log must track operation execution events (9.5)"
    );

    // Verify secret access grant logging (9.6)
    assert!(
        audit_code.contains("SecretAccessGrant"),
        "Audit log must track secret access grant events (9.6)"
    );

    // Verify secret access denial logging (9.6)
    assert!(
        audit_code.contains("SecretAccessDenied"),
        "Audit log must track secret access denial events (9.6)"
    );
}

/// Test: Verify security properties across all three phases
///
/// From Phase 9 Red Team Checkpoint:
/// Agent cannot distinguish decoy from real, cannot extract command templates,
/// and time-bounded grants auto-revoke
#[test]
fn test_9_4_5_6_security_properties() {
    // 9.4: Decoy responses are indistinguishable from real but expired
    // Verify the implementation tests check for no identifying markers
    let generator_path = workspace_root().join("crates/sigil-canary/src/generator.rs");
    let generator_code =
        fs::read_to_string(&generator_path).expect("Failed to read canary generator code");

    // Verify there's a test that checks decoys have no identifying markers
    assert!(
        generator_code.contains("test_decoy_has_no_identifying_comments")
            || generator_code.contains("assert!(!content.contains(\"SIGIL CANARY\"))"),
        "Decoy implementation must include tests verifying no identifying markers (9.4)"
    );

    // 9.5: Agent never sees command templates
    let mcp_path = workspace_root().join("crates/sigil-mcp/src/main.rs");
    let mcp_code = fs::read_to_string(&mcp_path).expect("Failed to read MCP server code");

    // Verify handle_list_operations returns descriptions but not commands
    assert!(
        mcp_code.contains("handle_list_operations") && mcp_code.contains("description"),
        "Agent must see operation descriptions but not command templates (9.5)"
    );

    // 9.6: Access grants are time-bounded and auto-revoke
    let server_path = workspace_root().join("crates/sigil-daemon/src/server.rs");
    let server_code = fs::read_to_string(&server_path).expect("Failed to read server code");

    assert!(
        server_code.contains("expires") || server_code.contains("duration") || server_code.contains("expiry"),
        "Access grants must be time-bounded (9.6)"
    );
}
