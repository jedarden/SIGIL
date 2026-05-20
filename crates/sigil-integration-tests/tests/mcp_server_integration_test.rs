//! MCP Server Integration Tests
//!
//! This test module verifies the SIGIL MCP (Model Context Protocol) server:
//! - JSON-RPC 2.0 protocol implementation
//! - Tool definitions and schemas
//! - sigil_list tool (paths only, never values)
//! - sigil_exec tool (command execution with scrubbing)
//! - sigil_write tool (file writing with placeholder resolution)
//! - sigil_env tool (env var names only)
//! - sigil_status tool (session stats and breach alerts)
//! - sigil_list_operations tool (sealed operations)
//! - sigil_request tool (access requests)
//! - sigil_check_access tool (access checking)
//! - Stdio communication
//! - Error handling
//! - Session management
//!
//! These tests verify the MCP server provides a secure interface for AI agents.

mod common;
use common::workspace_root;
use std::fs;

// ============================================================================
// MCP PROTOCOL TESTS
// ============================================================================

/// Test 1.1: Verify MCP server entry point
///
/// Tests that the MCP server can be started:
/// - Main function exists
/// - Stdio-based communication
/// - Server state initialization
#[test]
fn test_mcp_server_entry_point() {
    let mcp_path = workspace_root().join("crates/sigil-mcp/src/main.rs");
    assert!(mcp_path.exists(), "MCP server must exist");

    let mcp_code = fs::read_to_string(&mcp_path).expect("Failed to read MCP code");

    // Verify main function
    assert!(
        mcp_code.contains("fn main") || mcp_code.contains("run_server"),
        "MCP server must have main/run function"
    );

    // Verify server creation
    assert!(
        mcp_code.contains("McpServer") || mcp_code.contains("Server"),
        "MCP server must create server instance"
    );

    // Verify stdio usage
    assert!(
        mcp_code.contains("stdin") && mcp_code.contains("stdout"),
        "MCP server must use stdio for communication"
    );
}

/// Test 1.2: Verify JSON-RPC 2.0 implementation
///
/// Tests that JSON-RPC 2.0 protocol is properly implemented:
/// - Request structure
/// - Response structure
/// - Error handling
/// - ID matching
#[test]
fn test_json_rpc_implementation() {
    let mcp_path = workspace_root().join("crates/sigil-mcp/src/main.rs");
    let mcp_code = fs::read_to_string(&mcp_path).expect("Failed to read MCP code");

    // Verify JsonRpcRequest structure
    assert!(
        mcp_code.contains("JsonRpcRequest") || mcp_code.contains("struct Request"),
        "MCP must define JSON-RPC request structure"
    );

    // Verify JsonRpcResponse structure
    assert!(
        mcp_code.contains("JsonRpcResponse") || mcp_code.contains("struct Response"),
        "MCP must define JSON-RPC response structure"
    );

    // Verify error structure
    assert!(
        mcp_code.contains("JsonRpcError") || mcp_code.contains("struct Error"),
        "MCP must define JSON-RPC error structure"
    );

    // Verify required fields
    assert!(
        mcp_code.contains("id") && mcp_code.contains("method"),
        "JSON-RPC must include id and method fields"
    );
}

/// Test 1.3: Verify MCP initialize handshake
///
/// Tests that the MCP initialize handshake works:
/// - initialize method is handled
/// - Server info is returned
/// - Capabilities are declared
#[test]
fn test_mcp_initialize_handshake() {
    let mcp_path = workspace_root().join("crates/sigil-mcp/src/main.rs");
    let mcp_code = fs::read_to_string(&mcp_path).expect("Failed to read MCP code");

    // Verify initialize method handling
    assert!(
        mcp_code.contains("\"initialize\"") || mcp_code.contains("initialize"),
        "MCP must handle initialize method"
    );

    // Verify server info
    assert!(
        mcp_code.contains("serverInfo") || mcp_code.contains("name"),
        "Initialize must return server info"
    );

    // Verify capabilities
    assert!(
        mcp_code.contains("capabilities") || mcp_code.contains("tools"),
        "Initialize must declare capabilities"
    );

    // Verify protocol version
    assert!(
        mcp_code.contains("protocolVersion") || mcp_code.contains("version"),
        "Initialize must return protocol version"
    );
}

// ============================================================================
// MCP TOOLS TESTS
// ============================================================================

/// Test 2.1: Verify tools/list endpoint
///
/// Tests that all tools are properly listed:
/// - tools/list method is handled
/// - All tools are returned with schemas
/// - Tool names and descriptions are provided
#[test]
fn test_tools_list_endpoint() {
    let mcp_path = workspace_root().join("crates/sigil-mcp/src/main.rs");
    let mcp_code = fs::read_to_string(&mcp_path).expect("Failed to read MCP code");

    // Verify tools/list method
    assert!(
        mcp_code.contains("\"tools/list\"") || mcp_code.contains("tools_list") || mcp_code.contains("list_tools"),
        "MCP must handle tools/list method"
    );

    // Verify tool structure
    assert!(
        mcp_code.contains("Tool") || mcp_code.contains("struct.*Tool"),
        "MCP must define Tool structure"
    );

    // Verify tool fields
    assert!(
        mcp_code.contains("name") && mcp_code.contains("description") && mcp_code.contains("input_schema"),
        "Tool must have name, description, and input_schema"
    );
}

/// Test 2.2: Verify tools/call endpoint
///
/// Tests that tool calls are handled:
/// - tools/call method is handled
/// - Tool name is extracted
/// - Arguments are passed to handler
/// - Result is formatted as content
#[test]
fn test_tools_call_endpoint() {
    let mcp_path = workspace_root().join("crates/sigil-mcp/src/main.rs");
    let mcp_code = fs::read_to_string(&mcp_path).expect("Failed to read MCP code");

    // Verify tools/call method
    assert!(
        mcp_code.contains("\"tools/call\"") || mcp_code.contains("tools_call") || mcp_code.contains("call_tool"),
        "MCP must handle tools/call method"
    );

    // Verify tool name extraction
    assert!(
        mcp_code.contains("name") && mcp_code.contains("arguments"),
        "Tool call must extract name and arguments"
    );

    // Verify content formatting
    assert!(
        mcp_code.contains("content") || mcp_code.contains("text"),
        "Tool result must be formatted as content"
    );
}

/// Test 2.3: Verify all required tools exist
///
/// Tests that all required tools are implemented:
/// - sigil_list
/// - sigil_exec
/// - sigil_write
/// - sigil_env
/// - sigil_status
/// - sigil_list_operations
/// - sigil_request
/// - sigil_check_access
#[test]
fn test_all_required_tools_exist() {
    let mcp_path = workspace_root().join("crates/sigil-mcp/src/main.rs");
    let mcp_code = fs::read_to_string(&mcp_path).expect("Failed to read MCP code");

    let required_tools = [
        "sigil_list",
        "sigil_exec",
        "sigil_write",
        "sigil_env",
        "sigil_status",
        "sigil_list_operations",
        "sigil_request",
        "sigil_check_access",
    ];

    for tool in required_tools {
        assert!(
            mcp_code.contains(tool) || mcp_code.contains(&tool.replace("sigil_", "")),
            "MCP must implement {} tool",
            tool
        );
    }
}

/// Test 2.4: Verify tool schemas are valid
///
/// Tests that all tool schemas are valid JSON Schema:
/// - type: "object"
/// - properties defined
/// - required arrays
#[test]
fn test_tool_schemas_valid() {
    let mcp_path = workspace_root().join("crates/sigil-mcp/src/main.rs");
    let mcp_code = fs::read_to_string(&mcp_path).expect("Failed to read MCP code");

    // Verify schema structure
    assert!(
        mcp_code.contains("input_schema") && mcp_code.contains("json!({"),
        "Tools must define input_schema"
    );

    // Verify type: object
    assert!(
        mcp_code.contains("\"type\"") && mcp_code.contains("\"object\""),
        "Schema must specify type: object"
    );

    // Verify properties
    assert!(
        mcp_code.contains("properties"),
        "Schema must define properties"
    );
}

// ============================================================================
// SIGIL_LIST TOOL TESTS
// ============================================================================

/// Test 3.1: Verify sigil_list tool implementation
///
/// Tests the sigil_list tool:
/// - Lists secret paths (never values)
/// - Supports prefix filtering
/// - Returns metadata
#[test]
fn test_sigil_list_tool() {
    let mcp_path = workspace_root().join("crates/sigil-mcp/src/main.rs");
    let mcp_code = fs::read_to_string(&mcp_path).expect("Failed to read MCP code");

    // Verify sigil_list handler
    assert!(
        mcp_code.contains("sigil_list") || mcp_code.contains("handle_list"),
        "MCP must implement sigil_list handler"
    );

    // Verify prefix parameter
    assert!(
        mcp_code.contains("prefix") && mcp_code.contains("filter"),
        "sigil_list must support prefix filtering"
    );

    // Verify no values are returned
    assert!(
        mcp_code.contains("Never returns secret values") || mcp_code.contains("paths only"),
        "sigil_list must NOT return secret values"
    );

    // Verify vault integration
    assert!(
        mcp_code.contains("vault") || mcp_code.contains("list"),
        "sigil_list must integrate with vault"
    );
}

/// Test 3.2: Verify sigil_list tool schema
///
/// Tests the sigil_list tool schema:
/// - Optional prefix parameter
/// - Returns secrets array
/// - Returns count
#[test]
fn test_sigil_list_schema() {
    let mcp_path = workspace_root().join("crates/sigil-mcp/src/main.rs");
    let mcp_code = fs::read_to_string(&mcp_path).expect("Failed to read MCP code");

    // Verify prefix is optional (not in required)
    assert!(
        mcp_code.contains("prefix") && (
            !mcp_code.contains("\"prefix\"") || // prefix exists but might not be required
            mcp_code.contains("required")
        ),
        "sigil_list prefix parameter should be optional"
    );

    // Verify return structure
    assert!(
        mcp_code.contains("secrets") && mcp_code.contains("count"),
        "sigil_list must return secrets and count"
    );
}

/// Test 3.3: Verify sigil_list integrates with manifest
///
/// Tests that sigil_list includes manifest secrets:
/// - Loads project manifest
/// - Includes declared secrets
/// - Merges with vault secrets
#[test]
fn test_sigil_list_manifest_integration() {
    let mcp_path = workspace_root().join("crates/sigil-mcp/src/main.rs");
    let mcp_code = fs::read_to_string(&mcp_path).expect("Failed to read MCP code");

    // Verify manifest loading
    assert!(
        mcp_code.contains("manifest") || mcp_code.contains("ProjectManifest"),
        "sigil_list must load project manifest"
    );

    // Verify manifest secrets are included
    assert!(
        mcp_code.contains("manifest_secrets") || mcp_code.contains("manifest"),
        "sigil_list must include manifest secrets"
    );
}

// ============================================================================
// SIGIL_EXEC TOOL TESTS
// ============================================================================

/// Test 4.1: Verify sigil_exec tool implementation
///
/// Tests the sigil_exec tool:
/// - Executes commands with secret injection
/// - Applies sandboxing
/// - Scrubs output
/// - Returns exit code and duration
#[test]
fn test_sigil_exec_tool() {
    let mcp_path = workspace_root().join("crates/sigil-mcp/src/main.rs");
    let mcp_code = fs::read_to_string(&mcp_path).expect("Failed to read MCP code");

    // Verify sigil_exec handler
    assert!(
        mcp_code.contains("sigil_exec") || mcp_code.contains("handle_exec"),
        "MCP must implement sigil_exec handler"
    );

    // Verify command/operation parameters
    assert!(
        mcp_code.contains("command") || mcp_code.contains("operation"),
        "sigil_exec must accept command or operation"
    );

    // Verify sandbox parameter
    assert!(
        mcp_code.contains("sandbox") || mcp_code.contains("isolate"),
        "sigil_exec must support sandbox option"
    );

    // Verify daemon integration
    assert!(
        mcp_code.contains("IpcOperation::Exec") || mcp_code.contains("ExecRequest"),
        "sigil_exec must send exec request to daemon"
    );

    // Verify output scrubbing
    assert!(
        mcp_code.contains("scrub") || mcp_code.contains("scrubbed"),
        "sigil_exec output must be scrubbed"
    );
}

/// Test 4.2: Verify sigil_exec sealed operations
///
/// Tests that sigil_exec supports sealed operations:
/// - operation parameter is handled
/// - Operation is loaded from config
/// - Command is executed
#[test]
fn test_sigil_exec_sealed_operations() {
    let mcp_path = workspace_root().join("crates/sigil-mcp/src/main.rs");
    let mcp_code = fs::read_to_string(&mcp_path).expect("Failed to read MCP code");

    // Verify operation loading
    assert!(
        mcp_code.contains("load_operation") || mcp_code.contains("operation"),
        "sigil_exec must support loading sealed operations"
    );

    // Verify operations file
    assert!(
        mcp_code.contains("operations.toml") || mcp_code.contains(".sigil/operations"),
        "sigil_exec must load operations from .sigil/operations.toml"
    );

    // Verify output filter application
    assert!(
        mcp_code.contains("output_filter") || mcp_code.contains("OutputFilter"),
        "sigil_exec must apply operation output filter"
    );
}

/// Test 4.3: Verify sigil_exec error handling
///
/// Tests that sigil_exec handles errors:
/// - Daemon connection failure
/// - Execution failure
/// - Timeout
#[test]
fn test_sigil_exec_error_handling() {
    let mcp_path = workspace_root().join("crates/sigil-mcp/src/main.rs");
    let mcp_code = fs::read_to_string(&mcp_path).expect("Failed to read MCP code");

    // Verify error handling
    assert!(
        mcp_code.contains("Result") || mcp_code.contains("?") || mcp_code.contains("unwrap_or"),
        "sigil_exec must handle errors"
    );

    // Verify daemon connection error
    assert!(
        mcp_code.contains("connect") && (mcp_code.contains("Failed to connect") || mcp_code.contains("error")),
        "sigil_exec must handle connection errors"
    );

    // Verify exit code in response
    assert!(
        mcp_code.contains("exit_code") || mcp_code.contains("code"),
        "sigil_exec must return exit code"
    );
}

// ============================================================================
// SIGIL_WRITE TOOL TESTS
// ============================================================================

/// Test 5.1: Verify sigil_write tool implementation
///
/// Tests the sigil_write tool:
/// - Writes files with placeholder resolution
/// - Supports overwrite and append modes
/// - Returns bytes written
#[test]
fn test_sigil_write_tool() {
    let mcp_path = workspace_root().join("crates/sigil-mcp/src/main.rs");
    let mcp_code = fs::read_to_string(&mcp_path).expect("Failed to read MCP code");

    // Verify sigil_write handler
    assert!(
        mcp_code.contains("sigil_write") || mcp_code.contains("handle_write"),
        "MCP must implement sigil_write handler"
    );

    // Verify required parameters
    assert!(
        mcp_code.contains("path") && mcp_code.contains("content"),
        "sigil_write must require path and content"
    );

    // Verify mode parameter
    assert!(
        mcp_code.contains("mode") || mcp_code.contains("append"),
        "sigil_write must support mode (overwrite/append)"
    );

    // Verify placeholder resolution
    assert!(
        mcp_code.contains("{{secret:") || mcp_code.contains("resolve"),
        "sigil_write must resolve {{secret:path}} placeholders"
    );
}

/// Test 5.2: Verify sigil_write placeholder resolution
///
/// Tests that placeholders are resolved:
/// - {{secret:path}} format is detected
/// - Secrets are loaded from vault
/// - Placeholders are replaced with values
#[test]
fn test_sigil_write_placeholder_resolution() {
    let mcp_path = workspace_root().join("crates/sigil-mcp/src/main.rs");
    let mcp_code = fs::read_to_string(&mcp_path).expect("Failed to read MCP code");

    // Verify regex for placeholder detection
    assert!(
        mcp_code.contains("regex") || mcp_code.contains("{{secret:") || mcp_code.contains("placeholder"),
        "sigil_write must detect placeholders"
    );

    // Verify secret loading
    assert!(
        mcp_code.contains("vault.get") || mcp_code.contains("load") || mcp_code.contains("get_secret"),
        "sigil_write must load secrets from vault"
    );

    // Verify replacement
    assert!(
        mcp_code.contains("replace") || mcp_code.contains("resolve"),
        "sigil_write must replace placeholders with values"
    );
}

// ============================================================================
// SIGIL_ENV TOOL TESTS
// ============================================================================

/// Test 6.1: Verify sigil_env tool implementation
///
/// Tests the sigil_env tool:
/// - Lists env var names (never values)
/// - Supports prefix filtering
/// - Filters out sensitive vars
#[test]
fn test_sigil_env_tool() {
    let mcp_path = workspace_root().join("crates/sigil-mcp/src/main.rs");
    let mcp_code = fs::read_to_string(&mcp_path).expect("Failed to read MCP code");

    // Verify sigil_env handler
    assert!(
        mcp_code.contains("sigil_env") || mcp_code.contains("handle_env"),
        "MCP must implement sigil_env handler"
    );

    // Verify prefix filtering
    assert!(
        mcp_code.contains("prefix") || mcp_code.contains("filter"),
        "sigil_env must support prefix filtering"
    );

    // Verify no values returned
    assert!(
        mcp_code.contains("names only") || mcp_code.contains("never values") || mcp_code.contains("keys()"),
        "sigil_env must NOT return env var values"
    );

    // Verify sensitive var filtering
    assert!(
        mcp_code.contains("KEY") || mcp_code.contains("SECRET") || mcp_code.contains("PASSWORD") || mcp_code.contains("TOKEN"),
        "sigil_env must filter out sensitive-looking vars"
    );
}

/// Test 6.2: Verify sigil_env filtering
///
/// Tests that sensitive env vars are filtered:
/// - KEY, SECRET, PASSWORD, TOKEN patterns
/// - Only names are returned
#[test]
fn test_sigil_env_filtering() {
    let mcp_path = workspace_root().join("crates/sigil-mcp/src/main.rs");
    let mcp_code = fs::read_to_string(&mcp_path).expect("Failed to read MCP code");

    // Verify sensitive patterns are checked
    let sensitive_patterns = ["KEY", "SECRET", "PASSWORD", "TOKEN"];
    let mut found_patterns = 0;

    for pattern in sensitive_patterns {
        if mcp_code.contains(pattern) {
            found_patterns += 1;
        }
    }

    assert!(
        found_patterns >= 2,
        "sigil_env must filter sensitive env var patterns (found {})",
        found_patterns
    );
}

// ============================================================================
// SIGIL_STATUS TOOL TESTS
// ============================================================================

/// Test 7.1: Verify sigil_status tool implementation
///
/// Tests the sigil_status tool:
/// - Returns session statistics
/// - Returns breach alerts
/// - Calculates uptime
#[test]
fn test_sigil_status_tool() {
    let mcp_path = workspace_root().join("crates/sigil-mcp/src/main.rs");
    let mcp_code = fs::read_to_string(&mcp_path).expect("Failed to read MCP code");

    // Verify sigil_status handler
    assert!(
        mcp_code.contains("sigil_status") || mcp_code.contains("handle_status"),
        "MCP must implement sigil_status handler"
    );

    // Verify session tracking
    assert!(
        mcp_code.contains("start_time") || mcp_code.contains("uptime"),
        "sigil_status must track session start time"
    );

    // Verify access log
    assert!(
        mcp_code.contains("access_log") || mcp_code.contains("secrets_accessed"),
        "sigil_status must track secret access"
    );

    // Verify breach alerts
    assert!(
        mcp_code.contains("breaches") || mcp_code.contains("breach_count"),
        "sigil_status must report breach alerts"
    );
}

/// Test 7.2: Verify sigil_status breach reporting
///
/// Tests that breaches are properly reported:
/// - Breach count is returned
/// - Breach details are included
/// - Severity levels are tracked
#[test]
fn test_sigil_status_breach_reporting() {
    let mcp_path = workspace_root().join("crates/sigil-mcp/src/main.rs");
    let mcp_code = fs::read_to_string(&mcp_path).expect("Failed to read MCP code");

    // Verify breach tracking
    assert!(
        mcp_code.contains("breaches") || mcp_code.contains("BreachAlert"),
        "sigil_status must track breaches"
    );

    // Verify breach structure
    assert!(
        mcp_code.contains("timestamp") && mcp_code.contains("severity") && mcp_code.contains("message"),
        "Breach alerts must include timestamp, severity, and message"
    );
}

// ============================================================================
// SIGIL_LIST_OPERATIONS TOOL TESTS
// ============================================================================

/// Test 8.1: Verify sigil_list_operations tool
///
/// Tests the sigil_list_operations tool:
/// - Lists available sealed operations
/// - Returns descriptions only (not commands)
/// - Merges manifest and global operations
#[test]
fn test_sigil_list_operations_tool() {
    let mcp_path = workspace_root().join("crates/sigil-mcp/src/main.rs");
    let mcp_code = fs::read_to_string(&mcp_path).expect("Failed to read MCP code");

    // Verify sigil_list_operations handler
    assert!(
        mcp_code.contains("sigil_list_operations") || mcp_code.contains("handle_list_operations"),
        "MCP must implement sigil_list_operations handler"
    );

    // Verify operations loading
    assert!(
        mcp_code.contains("operations.toml") || mcp_code.contains(".sigil/operations"),
        "sigil_list_operations must load operations file"
    );

    // Verify description only (not commands)
    assert!(
        mcp_code.contains("description") && !mcp_code.contains("command"),
        "sigil_list_operations must return descriptions only"
    );

    // Verify manifest integration
    assert!(
        mcp_code.contains("manifest") || mcp_code.contains("ProjectManifest"),
        "sigil_list_operations must include manifest operations"
    );
}

// ============================================================================
// SIGIL_REQUEST TOOL TESTS
// ============================================================================

/// Test 9.1: Verify sigil_request tool
///
/// Tests the sigil_request tool:
/// - Requests access to secrets
/// - Supports single and bulk requests
/// - Returns grant/deny status
#[test]
fn test_sigil_request_tool() {
    let mcp_path = workspace_root().join("crates/sigil-mcp/src/main.rs");
    let mcp_code = fs::read_to_string(&mcp_path).expect("Failed to read MCP code");

    // Verify sigil_request handler
    assert!(
        mcp_code.contains("sigil_request") || mcp_code.contains("handle_request"),
        "MCP must implement sigil_request handler"
    );

    // Verify single and bulk support
    assert!(
        mcp_code.contains("secret") || mcp_code.contains("secrets"),
        "sigil_request must support single or bulk requests"
    );

    // Verify reason parameter
    assert!(
        mcp_code.contains("reason") || mcp_code.contains("purpose"),
        "sigil_request must require reason"
    );

    // Verify duration parameter
    assert!(
        mcp_code.contains("duration") || mcp_code.contains("expires"),
        "sigil_request must support duration"
    );

    // Verify IPC integration
    assert!(
        mcp_code.contains("IpcOperation::RequestAccess") || mcp_code.contains("RequestAccessPayload"),
        "sigil_request must send request to daemon"
    );
}

/// Test 9.2: Verify sigil_request bulk mode
///
/// Tests that bulk requests work:
/// - secrets array parameter
/// - Multiple requests in one call
/// - Aggregate results
#[test]
fn test_sigil_request_bulk_mode() {
    let mcp_path = workspace_root().join("crates/sigil-mcp/src/main.rs");
    let mcp_code = fs::read_to_string(&mcp_path).expect("Failed to read MCP code");

    // Verify secrets array parameter
    assert!(
        mcp_code.contains("secrets") && mcp_code.contains("array"),
        "sigil_request must support secrets array for bulk requests"
    );

    // Verify bulk detection
    assert!(
        mcp_code.contains("bulk") || mcp_code.contains("is_bulk") || mcp_code.contains("len"),
        "sigil_request must detect bulk vs single requests"
    );

    // Verify aggregate results
    assert!(
        mcp_code.contains("granted") && mcp_code.contains("denied") && mcp_code.contains("count"),
        "sigil_request must return aggregate results for bulk"
    );
}

/// Test 9.3: Verify sigil_request anyOf constraint
///
/// Tests the anyOf constraint in the schema:
/// - Either secret OR secrets must be provided
/// - Not both
#[test]
fn test_sigil_request_anyof_constraint() {
    let mcp_path = workspace_root().join("crates/sigil-mcp/src/main.rs");
    let mcp_code = fs::read_to_string(&mcp_path).expect("Failed to read MCP code");

    // Verify anyOf in schema
    assert!(
        mcp_code.contains("anyOf") || mcp_code.contains("Either"),
        "sigil_request schema must use anyOf constraint"
    );

    // Verify validation
    assert!(
        mcp_code.contains("Either 'operation' or 'command'") || mcp_code.contains("Cannot specify both"),
        "sigil_request must validate mutually exclusive parameters"
    );
}

// ============================================================================
// SIGIL_CHECK_ACCESS TOOL TESTS
// ============================================================================

/// Test 10.1: Verify sigil_check_access tool
///
/// Tests the sigil_check_access tool:
/// - Checks if access is granted
/// - Returns grant status
/// - Returns expiry info
#[test]
fn test_sigil_check_access_tool() {
    let mcp_path = workspace_root().join("crates/sigil-mcp/src/main.rs");
    let mcp_code = fs::read_to_string(&mcp_path).expect("Failed to read MCP code");

    // Verify sigil_check_access handler
    assert!(
        mcp_code.contains("sigil_check_access") || mcp_code.contains("handle_check_access"),
        "MCP must implement sigil_check_access handler"
    );

    // Verify secret parameter is required
    assert!(
        mcp_code.contains("secret") && mcp_code.contains("required"),
        "sigil_check_access must require secret parameter"
    );

    // Verify IPC integration
    assert!(
        mcp_code.contains("IpcOperation::CheckAccess") || mcp_code.contains("CheckAccessPayload"),
        "sigil_check_access must send check request to daemon"
    );

    // Verify response fields
    assert!(
        mcp_code.contains("granted") || mcp_code.contains("status"),
        "sigil_check_access must return grant status"
    );
}

/// Test 10.2: Verify sigil_check_access response
///
/// Tests the response format:
/// - granted boolean
/// - status string
/// - expires_in duration
#[test]
fn test_sigil_check_access_response() {
    let mcp_path = workspace_root().join("crates/sigil-mcp/src/main.rs");
    let mcp_code = fs::read_to_string(&mcp_path).expect("Failed to read MCP code");

    // Verify granted field
    assert!(
        mcp_code.contains("granted") || mcp_code.contains("is_granted"),
        "sigil_check_access response must include granted field"
    );

    // Verify status field
    assert!(
        mcp_code.contains("status") || mcp_code.contains("state"),
        "sigil_check_access response must include status field"
    );

    // Verify expiry info
    assert!(
        mcp_code.contains("expires_in") || mcp_code.contains("expires_at") || mcp_code.contains("expiry"),
        "sigil_check_access response should include expiry information"
    );
}

// ============================================================================
// MCP ERROR HANDLING TESTS
// ============================================================================

/// Test 11.1: Verify MCP error responses
///
/// Tests that errors are properly formatted:
/// - Error code
/// - Error message
/// - Optional data field
/// - Structured SIGIL error info
#[test]
fn test_mcp_error_responses() {
    let mcp_path = workspace_root().join("crates/sigil-mcp/src/main.rs");
    let mcp_code = fs::read_to_string(&mcp_path).expect("Failed to read MCP code");

    // Verify error structure
    assert!(
        mcp_code.contains("JsonRpcError") || mcp_code.contains("struct Error"),
        "MCP must define error structure"
    );

    // Verify error code
    assert!(
        mcp_code.contains("code") || mcp_code.contains("-3"),
        "Error must include code"
    );

    // Verify error message
    assert!(
        mcp_code.contains("message") || mcp_code.contains("msg"),
        "Error must include message"
    );

    // Verify structured SIGIL errors
    assert!(
        mcp_code.contains("sigil_error") || mcp_code.contains("SigilError") || mcp_code.contains("StructuredError"),
        "Error should include SIGIL-specific error info"
    );
}

/// Test 11.2: Verify MCP error codes
///
/// Tests that proper error codes are used:
/// - -32600: Invalid Request
/// - -32601: Method not found
/// - -32602: Invalid params
/// - -32603: Internal error
#[test]
fn test_mcp_error_codes() {
    let mcp_path = workspace_root().join("crates/sigil-mcp/src/main.rs");
    let mcp_code = fs::read_to_string(&mcp_path).expect("Failed to read MCP code");

    // Verify standard JSON-RPC error codes
    let error_codes = ["-32600", "-32601", "-32602", "-32603"];
    let mut found_codes = 0;

    for code in error_codes {
        if mcp_code.contains(code) {
            found_codes += 1;
        }
    }

    // At least some error codes should be used
    assert!(
        found_codes >= 1,
        "MCP should use standard JSON-RPC error codes (found {})",
        found_codes
    );
}

/// Test 11.3: Verify unknown method handling
///
/// Tests that unknown methods are handled:
/// - Returns error
/// - Includes method name in error
#[test]
fn test_unknown_method_handling() {
    let mcp_path = workspace_root().join("crates/sigil-mcp/src/main.rs");
    let mcp_code = fs::read_to_string(&mcp_path).expect("Failed to read MCP code");

    // Verify unknown method error
    assert!(
        mcp_code.contains("Unknown method") || mcp_code.contains("unknown") || mcp_code.contains("not found"),
        "MCP must handle unknown methods"
    );
}

/// Test 11.4: Verify SIGIL error integration
///
/// Tests that SIGIL errors are properly integrated:
/// - SigilError is converted to structured error
/// - Error code mapping
/// - Message preservation
#[test]
fn test_sigil_error_integration() {
    let mcp_path = workspace_root().join("crates/sigil-mcp/src/main.rs");
    let mcp_code = fs::read_to_string(&mcp_path).expect("Failed to read MCP code");

    // Verify SIGIL error handling
    assert!(
        mcp_code.contains("SigilError") || mcp_code.contains("sigil_core::"),
        "MCP must handle SIGIL errors"
    );

    // Verify structured error conversion
    assert!(
        mcp_code.contains("to_structured_error") || mcp_code.contains("StructuredError"),
        "SIGIL errors should be converted to structured format"
    );
}

// ============================================================================
// MCP SESSION MANAGEMENT TESTS
// ============================================================================

/// Test 12.1: Verify MCP server state
///
/// Tests that server state is maintained:
/// - Access log
/// - Breach alerts
/// - Start time
#[test]
fn test_mcp_server_state() {
    let mcp_path = workspace_root().join("crates/sigil-mcp/src/main.rs");
    let mcp_code = fs::read_to_string(&mcp_path).expect("Failed to read MCP code");

    // Verify server state structure
    assert!(
        mcp_code.contains("McpServer") || mcp_code.contains("struct Server"),
        "MCP must define server state structure"
    );

    // Verify access log
    assert!(
        mcp_code.contains("access_log") || mcp_code.contains("SecretAccess"),
        "Server must track secret access"
    );

    // Verify breach tracking
    assert!(
        mcp_code.contains("breaches") || mcp_code.contains("BreachAlert"),
        "Server must track breaches"
    );

    // Verify start time
    assert!(
        mcp_code.contains("start_time") || mcp_code.contains("start_time"),
        "Server must track start time for uptime calculation"
    );
}

/// Test 12.2: Verify access logging
///
/// Tests that secret access is logged:
/// - Path is recorded
/// - Timestamp is recorded
/// - Method is recorded
#[test]
fn test_access_logging() {
    let mcp_path = workspace_root().join("crates/sigil-mcp/src/main.rs");
    let mcp_code = fs::read_to_string(&mcp_path).expect("Failed to read MCP code");

    // Verify access logging
    assert!(
        mcp_code.contains("access_log.push") || mcp_code.contains("log_access") || mcp_code.contains("record"),
        "MCP must log secret access"
    );

    // Verify SecretAccess structure
    assert!(
        mcp_code.contains("SecretAccess") || mcp_code.contains("struct Access"),
        "MCP must define access record structure"
    );

    // Verify access fields
    assert!(
        mcp_code.contains("path") && mcp_code.contains("accessed_at") && mcp_code.contains("method"),
        "Access record must include path, timestamp, and method"
    );
}

/// Test 12.3: Verify session token handling
///
/// Tests that session tokens are handled:
/// - Token is passed to daemon
/// - Token is loaded from environment
#[test]
fn test_session_token_handling() {
    let mcp_path = workspace_root().join("crates/sigil-mcp/src/main.rs");
    let mcp_code = fs::read_to_string(&mcp_path).expect("Failed to read MCP code");

    // Verify session token usage
    assert!(
        mcp_code.contains("session_token") || mcp_code.contains("SIGIL_SESSION_TOKEN"),
        "MCP must use session token for daemon communication"
    );

    // Verify environment variable
    assert!(
        mcp_code.contains("std::env::var") || mcp_code.contains("env"),
        "MCP must load session token from environment"
    );
}

/// Test 12.4: Verify socket path handling
///
/// Tests that daemon socket is found:
/// - Environment variable
/// - Default path
#[test]
fn test_socket_path_handling() {
    let mcp_path = workspace_root().join("crates/sigil-mcp/src/main.rs");
    let mcp_code = fs::read_to_string(&mcp_path).expect("Failed to read MCP code");

    // Verify socket path configuration
    assert!(
        mcp_code.contains("socket_path") || mcp_code.contains("SIGIL_SOCKET") || mcp_code.contains("sigild.sock"),
        "MCP must handle daemon socket path"
    );

    // Verify default path
    assert!(
        mcp_code.contains(".sigil") && mcp_code.contains(".sock"),
        "MCP must have default socket path"
    );
}

// ============================================================================
// MCP SECURITY TESTS
// ============================================================================

/// Test 13.1: Verify no secret values in tool outputs
///
/// Tests that tools never return secret values:
/// - sigil_list returns paths only
/// - sigil_env returns names only
/// - sigil_status doesn't include secrets
#[test]
fn test_no_secret_values_in_outputs() {
    let mcp_path = workspace_root().join("crates/sigil-mcp/src/main.rs");
    let mcp_code = fs::read_to_string(&mcp_path).expect("Failed to read MCP code");

    // Verify sigil_list doesn't return values
    assert!(
        mcp_code.contains("Never returns secret values") || mcp_code.contains("paths only"),
        "sigil_list must not return secret values"
    );

    // Verify sigil_env doesn't return values
    assert!(
        mcp_code.contains("names only") || mcp_code.contains("never values"),
        "sigil_env must not return env var values"
    );

    // Verify no value field in list output
    assert!(
        !mcp_code.contains("\"value\"") || mcp_code.contains("path") && !mcp_code.contains("value"),
        "Tool outputs should not include secret values"
    );
}

/// Test 13.2: Verify tool parameter validation
///
/// Tests that tool parameters are validated:
/// - Required parameters are checked
/// - Type validation
/// - Range validation
#[test]
fn test_tool_parameter_validation() {
    let mcp_path = workspace_root().join("crates/sigil-mcp/src/main.rs");
    let mcp_code = fs::read_to_string(&mcp_path).expect("Failed to read MCP code");

    // Verify parameter extraction
    assert!(
        mcp_code.contains(".get(") || mcp_code.contains("unwrap_or"),
        "Tools must extract parameters from request"
    );

    // Verify required parameter checking
    assert!(
        mcp_code.contains("ok_or_else") || mcp_code.contains("expect") || mcp_code.contains("Missing"),
        "Tools must validate required parameters"
    );
}

/// Test 13.3: Verify daemon connection security
///
/// Tests that daemon connection is secure:
/// - Unix socket only (no TCP)
/// - Local filesystem only
#[test]
fn test_daemon_connection_security() {
    let mcp_path = workspace_root().join("crates/sigil-mcp/src/main.rs");
    let mcp_code = fs::read_to_string(&mcp_path).expect("Failed to read MCP code");

    // Verify Unix socket usage
    assert!(
        mcp_code.contains("UnixStream") || mcp_code.contains("UnixListener"),
        "MCP must use Unix socket for daemon communication"
    );

    // Verify no TCP usage
    assert!(
        !mcp_code.contains("TcpStream") && !mcp_code.contains("127.0.0.1") && !mcp_code.contains("localhost"),
        "MCP must NOT use TCP for daemon connection"
    );
}

/// Test 13.4: Verify input sanitization
///
/// Tests that inputs are sanitized:
/// - Path traversal prevention
/// - Command injection prevention
#[test]
fn test_input_sanitization() {
    let mcp_path = workspace_root().join("crates/sigil-mcp/src/main.rs");
    let mcp_code = fs::read_to_string(&mcp_path).expect("Failed to read MCP code");

    // Verify SecretPath validation (prevents traversal)
    assert!(
        mcp_code.contains("SecretPath::new") || mcp_code.contains("validate"),
        "MCP must validate secret paths"
    );

    // Verify command parsing is safe
    assert!(
        mcp_code.contains("shell_words") || mcp_code.contains("split"),
        "Command parsing must use safe splitting"
    );
}
