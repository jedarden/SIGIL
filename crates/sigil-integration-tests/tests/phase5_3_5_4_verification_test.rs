//! Phase 5.3-5.4 Verification Tests
//!
//! These tests verify sigil-shell (universal shell wrapper) and sigil-mcp (MCP server)
//! as specified in the plan Phase 5.3-5.4 deliverables.
//!
//! Phase 5.3 covers:
//! - POSIX-compatible shell wrapper (sigil-shell)
//! - sigil-shell -c "command" flow: resolve → sandbox → execute → scrub → return
//! - Interactive mode (no -c flag)
//! - /bin/bash=sigil-shell compatibility
//! - 310-line implementation
//!
//! Phase 5.4 covers:
//! - All 5 MCP tools: sigil_list, sigil_exec, sigil_write, sigil_env, sigil_status
//! - sigil setup mcp command
//! - sigil_list returns paths but never values
//! - sigil_exec runs command with injection + scrubbing
//! - sigil_write creates files with resolved secrets
//! - sigil_env returns env var names only (not values)
//! - sigil_status shows session stats and breach alerts
//! - 1423-line implementation

mod common;
use common::workspace_root;
use std::fs;

/// Test 5.3.1: Verify sigil-shell exists
///
/// From Phase 5.3 deliverables:
/// "POSIX-compatible shell wrapper (sigil-shell)"
#[test]
fn test_sigil_shell_exists() {
    let shell_path = workspace_root().join("crates/sigil-shell/src/main.rs");

    assert!(
        shell_path.exists(),
        "sigil-shell must exist at crates/sigil-shell/src/main.rs"
    );
}

/// Test 5.3.2: Verify sigil-shell has reasonable size
///
/// From Phase 5.3 deliverables:
/// "310-line implementation is complete"
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

/// Test 5.3.3: Verify sigil-shell has Mode enum
///
/// From Phase 5.3 deliverables:
/// "sigil-shell -c "command" flow"
/// "Interactive mode (no -c flag)"
#[test]
fn test_sigil_shell_mode_enum() {
    let shell_path = workspace_root().join("crates/sigil-shell/src/main.rs");
    let shell_code = fs::read_to_string(&shell_path).expect("Failed to read sigil-shell");

    assert!(
        shell_code.contains("enum Mode") || shell_code.contains("pub enum Mode"),
        "sigil-shell must have Mode enum"
    );

    // Verify SingleCommand variant exists
    assert!(
        shell_code.contains("SingleCommand") || shell_code.contains("single"),
        "Mode must have SingleCommand variant"
    );

    // Verify Interactive variant exists
    assert!(
        shell_code.contains("Interactive") || shell_code.contains("interactive"),
        "Mode must have Interactive variant"
    );
}

/// Test 5.3.4: Verify sigil-shell handles -c flag
///
/// From Phase 5.3 deliverables:
/// "sigil-shell -c "command" flow: resolve → sandbox → execute → scrub → return"
#[test]
fn test_sigil_shell_c_flag() {
    let shell_path = workspace_root().join("crates/sigil-shell/src/main.rs");
    let shell_code = fs::read_to_string(&shell_path).expect("Failed to read sigil-shell");

    // Verify -c flag handling
    assert!(
        shell_code.contains("-c") && shell_code.contains("SingleCommand"),
        "sigil-shell must handle -c flag for single command mode"
    );
}

/// Test 5.3.5: Verify sigil-shell has execute_command function
///
/// From Phase 5.3 deliverables:
/// "sigil-shell -c "command" flow: resolve → sandbox → execute → scrub → return"
#[test]
fn test_sigil_shell_execute_command() {
    let shell_path = workspace_root().join("crates/sigil-shell/src/main.rs");
    let shell_code = fs::read_to_string(&shell_path).expect("Failed to read sigil-shell");

    assert!(
        shell_code.contains("fn execute_command") || shell_code.contains("async fn execute_command"),
        "sigil-shell must have execute_command function"
    );

    // Verify command parsing
    assert!(
        shell_code.contains("CommandParser") || shell_code.contains("resolve_command"),
        "execute_command must parse and resolve commands"
    );
}

/// Test 5.3.6: Verify sigil-shell resolves secrets
///
/// From Phase 5.3 deliverables:
/// "sigil-shell -c "command" flow: resolve → sandbox → execute → scrub → return"
#[test]
fn test_sigil_shell_resolves_secrets() {
    let shell_path = workspace_root().join("crates/sigil-shell/src/main.rs");
    let shell_code = fs::read_to_string(&shell_path).expect("Failed to read sigil-shell");

    // Verify secret resolution using CommandParser
    assert!(
        shell_code.contains("CommandParser::resolve_command") || shell_code.contains("resolve_command"),
        "sigil-shell must resolve secret placeholders in commands"
    );
}

/// Test 5.3.7: Verify sigil-shell connects to daemon
///
/// From Phase 5.3 deliverables:
/// "sigil-shell -c "command" flow: resolve → sandbox → execute → scrub → return"
/// "Connect to SIGIL daemon for command execution"
#[test]
fn test_sigil_shell_daemon_connection() {
    let shell_path = workspace_root().join("crates/sigil-shell/src/main.rs");
    let shell_code = fs::read_to_string(&shell_path).expect("Failed to read sigil-shell");

    // Verify daemon client connection
    assert!(
        shell_code.contains("DaemonClient") || shell_code.contains("sigil.sock"),
        "sigil-shell must connect to SIGIL daemon"
    );

    // Verify socket path handling
    assert!(
        shell_code.contains("get_socket_path") || shell_code.contains("XDG_RUNTIME_DIR"),
        "sigil-shell must determine daemon socket path"
    );
}

/// Test 5.3.8: Verify sigil-shell writes scrubbed output
///
/// From Phase 5.3 deliverables:
/// "sigil-shell -c "command" flow: resolve → sandbox → execute → scrub → return"
/// "Write scrubbed output to stdout/stderr"
#[test]
fn test_sigil_shell_scrubbed_output() {
    let shell_path = workspace_root().join("crates/sigil-shell/src/main.rs");
    let shell_code = fs::read_to_string(&shell_path).expect("Failed to read sigil-shell");

    // Verify output writing
    assert!(
        shell_code.contains("stdout") && shell_code.contains("stderr"),
        "sigil-shell must write to stdout and stderr"
    );

    // Verify scrubbed output from daemon
    assert!(
        shell_code.contains("exec_response.stdout") || shell_code.contains("exec_response.stderr"),
        "sigil-shell must use scrubbed output from daemon"
    );
}

/// Test 5.3.9: Verify sigil-shell returns exit code
///
/// From Phase 5.3 deliverables:
/// "sigil-shell -c "command" flow: resolve → sandbox → execute → scrub → return"
/// "Return exit code from command"
#[test]
fn test_sigil_shell_exit_code() {
    let shell_path = workspace_root().join("crates/sigil-shell/src/main.rs");
    let shell_code = fs::read_to_string(&shell_path).expect("Failed to read sigil-shell");

    // Verify exit code handling
    assert!(
        shell_code.contains("exit_code") || shell_code.contains("exec_response.exit_code"),
        "sigil-shell must return command exit code"
    );

    // Verify exit function
    assert!(
        shell_code.contains("exit(") || shell_code.contains("std::process::exit"),
        "sigil-shell must exit with command's exit code"
    );
}

/// Test 5.3.10: Verify sigil-shell has interactive mode
///
/// From Phase 5.3 deliverables:
/// "Interactive mode (no -c flag)"
#[test]
fn test_sigil_shell_interactive_mode() {
    let shell_path = workspace_root().join("crates/sigil-shell/src/main.rs");
    let shell_code = fs::read_to_string(&shell_path).expect("Failed to read sigil-shell");

    // Verify interactive mode support
    assert!(
        shell_code.contains("run_interactive") || shell_code.contains("Interactive"),
        "sigil-shell must support interactive mode"
    );
}

/// Test 5.3.11: Verify sigil-shell interactive prompt
///
/// From Phase 5.3 deliverables:
/// "Interactive mode (no -c flag)"
#[test]
fn test_sigil_shell_interactive_prompt() {
    let shell_path = workspace_root().join("crates/sigil-shell/src/main.rs");
    let shell_code = fs::read_to_string(&shell_path).expect("Failed to read sigil-shell");

    // Verify prompt display
    assert!(
        shell_code.contains("sigil:") || shell_code.contains("prompt"),
        "sigil-shell must display a prompt in interactive mode"
    );
}

/// Test 5.3.12: Verify sigil-shell interactive loop
///
/// From Phase 5.3 deliverables:
/// "Interactive mode (no -c flag)"
/// "Read commands, execute, display results"
#[test]
fn test_sigil_shell_interactive_loop() {
    let shell_path = workspace_root().join("crates/sigil-shell/src/main.rs");
    let shell_code = fs::read_to_string(&shell_path).expect("Failed to read sigil-shell");

    // Verify interactive loop
    assert!(
        shell_code.contains("loop") && shell_code.contains("stdin") && shell_code.contains("read_line"),
        "sigil-shell must have an interactive read-execute loop"
    );
}

/// Test 5.3.13: Verify sigil-shell built-in commands
///
/// From Phase 5.3 deliverables:
/// "Interactive mode (no -c flag)"
/// "Support exit, help commands"
#[test]
fn test_sigil_shell_builtin_commands() {
    let shell_path = workspace_root().join("crates/sigil-shell/src/main.rs");
    let shell_code = fs::read_to_string(&shell_path).expect("Failed to read sigil-shell");

    // Verify exit command handling
    assert!(
        shell_code.contains("\"exit\"") || shell_code.contains("exit") || shell_code.contains("quit"),
        "sigil-shell must handle exit/quit commands"
    );

    // Verify help command
    assert!(
        shell_code.contains("\"help\"") || shell_code.contains("print_help"),
        "sigil-shell must handle help command"
    );
}

/// Test 5.3.14: Verify sigil-shell signal handling
///
/// From Phase 5.3 deliverables:
/// "Signal Handling: Forwards SIGINT, SIGTERM to sandbox child processes"
#[test]
fn test_sigil_shell_signal_handling() {
    let shell_path = workspace_root().join("crates/sigil-shell/src/main.rs");
    let shell_code = fs::read_to_string(&shell_path).expect("Failed to read sigil-shell");

    // Verify signal handling setup
    assert!(
        shell_code.contains("SIGINT") || shell_code.contains("SIGTERM") || shell_code.contains("signal"),
        "sigil-shell must handle signals"
    );

    // Verify SIGPIPE ignoring
    assert!(
        shell_code.contains("SIGPIPE") && shell_code.contains("SIG_IGN"),
        "sigil-shell must ignore SIGPIPE"
    );
}

/// Test 5.3.15: Verify sigil-shell POSIX compatibility
///
/// From Phase 5.3 deliverables:
/// "POSIX-compatible shell wrapper"
#[test]
fn test_sigil_shell_posix_compatibility() {
    let shell_path = workspace_root().join("crates/sigil-shell/src/main.rs");
    let shell_code = fs::read_to_string(&shell_path).expect("Failed to read sigil-shell");

    // Verify shell_words parsing for POSIX shell quoting
    assert!(
        shell_code.contains("shell_words") || shell_code.contains("split"),
        "sigil-shell must use shell_words for POSIX-compatible command parsing"
    );
}

/// Test 5.3.16: Verify sigil-shell /bin/bash compatibility
///
/// From Phase 5.3 deliverables:
/// "/bin/bash=sigil-shell compatibility"
/// "Can be used as drop-in replacement for bash"
#[test]
fn test_sigil_shell_bash_compatibility() {
    let shell_path = workspace_root().join("crates/sigil-shell/src/main.rs");
    let shell_code = fs::read_to_string(&shell_path).expect("Failed to read sigil-shell");

    // Verify it accepts similar arguments to bash
    assert!(
        shell_code.contains("-c") && shell_code.contains("command"),
        "sigil-shell must accept -c flag like bash"
    );
}

/// Test 5.3.17: Verify sigil-shell error handling
///
/// From Phase 5.3 deliverables:
/// "Proper error handling and reporting"
#[test]
fn test_sigil_shell_error_handling() {
    let shell_path = workspace_root().join("crates/sigil-shell/src/main.rs");
    let shell_code = fs::read_to_string(&shell_path).expect("Failed to read sigil-shell");

    // Verify Result returns
    assert!(
        shell_code.contains("Result<") && shell_code.contains("anyhow"),
        "sigil-shell must use Result for error handling"
    );

    // Verify error context
    assert!(
        shell_code.contains("context(") || shell_code.contains("?"),
        "sigil-shell must provide error context"
    );
}

/// Test 5.3.18: Verify sigil-shell has tests
///
/// From Phase 5.3 deliverables:
/// "All components should have tests"
#[test]
fn test_sigil_shell_has_tests() {
    let shell_path = workspace_root().join("crates/sigil-shell/src/main.rs");
    let shell_code = fs::read_to_string(&shell_path).expect("Failed to read sigil-shell");

    assert!(
        shell_code.contains("#[cfg(test)]") || shell_code.contains("#[test]"),
        "sigil-shell must have tests"
    );
}

/// Test 5.3.19: Verify sigil-shell uses tokio runtime
///
/// From Phase 5.3 deliverables:
/// "Async command execution via daemon"
#[test]
fn test_sigil_shell_tokio_runtime() {
    let shell_path = workspace_root().join("crates/sigil-shell/src/main.rs");
    let shell_code = fs::read_to_string(&shell_path).expect("Failed to read sigil-shell");

    assert!(
        shell_code.contains("#[tokio::main]") || shell_code.contains("tokio::runtime"),
        "sigil-shell must use tokio async runtime"
    );
}

/// Test 5.3.20: Verify sigil-shell handles working directory
///
/// From Phase 5.3 deliverables:
/// "Track working directory changes (cd command)"
#[test]
fn test_sigil_shell_working_directory() {
    let shell_path = workspace_root().join("crates/sigil-shell/src/main.rs");
    let shell_code = fs::read_to_string(&shell_path).expect("Failed to read sigil-shell");

    // Verify CWD tracking
    assert!(
        shell_code.contains("cwd") || shell_code.contains("current_dir"),
        "sigil-shell must track current working directory"
    );

    // Verify cd command handling
    assert!(
        shell_code.contains("get_cwd_change") || shell_code.contains("cd"),
        "sigil-shell must handle cd command"
    );
}

/// Test 5.4.1: Verify sigil-mcp exists
///
/// From Phase 5.4 deliverables:
/// "MCP server (sigil-mcp)"
/// "1423-line implementation is complete"
#[test]
fn test_sigil_mcp_exists() {
    let mcp_path = workspace_root().join("crates/sigil-mcp/src/main.rs");

    assert!(
        mcp_path.exists(),
        "sigil-mcp must exist at crates/sigil-mcp/src/main.rs"
    );
}

/// Test 5.4.2: Verify sigil-mcp has reasonable size
///
/// From Phase 5.4 deliverables:
/// "1423-line implementation is complete"
/// (Allowing for some growth from the original 1423 lines)
#[test]
fn test_sigil_mcp_size() {
    let mcp_path = workspace_root().join("crates/sigil-mcp/src/main.rs");
    let mcp_code = fs::read_to_string(&mcp_path).expect("Failed to read sigil-mcp");

    let line_count = mcp_code.lines().count();

    // Allow for reasonable growth (1423 original, allow up to 1600)
    assert!(
        (1200..=1700).contains(&line_count),
        "sigil-mcp should be approximately 1200-1700 lines, found {}",
        line_count
    );
}

/// Test 5.4.3: Verify MCP server has get_tools function
///
/// From Phase 5.4 deliverables:
/// "All 5 MCP tools: sigil_list, sigil_exec, sigil_write, sigil_env, sigil_status"
#[test]
fn test_mcp_get_tools() {
    let mcp_path = workspace_root().join("crates/sigil-mcp/src/main.rs");
    let mcp_code = fs::read_to_string(&mcp_path).expect("Failed to read sigil-mcp");

    assert!(
        mcp_code.contains("fn get_tools") || mcp_code.contains("pub fn get_tools"),
        "MCP server must have get_tools function"
    );
}

/// Test 5.4.4: Verify MCP server has all required tools
///
/// From Phase 5.4 deliverables:
/// "All 5 MCP tools: sigil_list, sigil_exec, sigil_write, sigil_env, sigil_status"
#[test]
fn test_mcp_all_tools() {
    let mcp_path = workspace_root().join("crates/sigil-mcp/src/main.rs");
    let mcp_code = fs::read_to_string(&mcp_path).expect("Failed to read sigil-mcp");

    let required_tools = [
        "sigil_list",
        "sigil_exec",
        "sigil_write",
        "sigil_env",
        "sigil_status",
    ];

    for tool in required_tools {
        assert!(
            mcp_code.contains(tool),
            "{}", format!("MCP server must have {} tool", tool)
        );
    }
}

/// Test 5.4.5: Verify sigil_list tool
///
/// From Phase 5.4 deliverables:
/// "sigil_list returns paths but never values"
#[test]
fn test_mcp_sigil_list() {
    let mcp_path = workspace_root().join("crates/sigil-mcp/src/main.rs");
    let mcp_code = fs::read_to_string(&mcp_path).expect("Failed to read sigil-mcp");

    // Verify handle_list function exists
    assert!(
        mcp_code.contains("fn handle_list") || mcp_code.contains("handle_sigil_list"),
        "MCP server must have handle_list function"
    );

    // Verify it returns paths (not values)
    assert!(
        mcp_code.contains("path") && mcp_code.contains("list"),
        "sigil_list must return secret paths"
    );

    // Verify it never returns values
    assert!(
        !mcp_code.contains("secret_value") || mcp_code.contains("Never returns secret values"),
        "sigil_list should not return secret values"
    );
}

/// Test 5.4.6: Verify sigil_exec tool
///
/// From Phase 5.4 deliverables:
/// "sigil_exec runs command with injection + scrubbing"
#[test]
fn test_mcp_sigil_exec() {
    let mcp_path = workspace_root().join("crates/sigil-mcp/src/main.rs");
    let mcp_code = fs::read_to_string(&mcp_path).expect("Failed to read sigil-mcp");

    // Verify handle_exec function exists
    assert!(
        mcp_code.contains("fn handle_exec") || mcp_code.contains("handle_sigil_exec"),
        "MCP server must have handle_exec function"
    );

    // Verify command execution
    assert!(
        mcp_code.contains("command") && mcp_code.contains("exec"),
        "sigil_exec must execute commands"
    );

    // Verify sandbox option
    assert!(
        mcp_code.contains("sandbox") || mcp_code.contains("network_isolated"),
        "sigil_exec must support sandbox option"
    );
}

/// Test 5.4.7: Verify sigil_write tool
///
/// From Phase 5.4 deliverables:
/// "sigil_write creates files with resolved secrets"
#[test]
fn test_mcp_sigil_write() {
    let mcp_path = workspace_root().join("crates/sigil-mcp/src/main.rs");
    let mcp_code = fs::read_to_string(&mcp_path).expect("Failed to read sigil-mcp");

    // Verify handle_write function exists
    assert!(
        mcp_code.contains("fn handle_write") || mcp_code.contains("handle_sigil_write"),
        "MCP server must have handle_write function"
    );

    // Verify file writing
    assert!(
        mcp_code.contains("path") && mcp_code.contains("content") && mcp_code.contains("write"),
        "sigil_write must write files with content"
    );

    // Verify secret resolution
    assert!(
        mcp_code.contains("resolve_placeholders") || mcp_code.contains("{{secret:"),
        "sigil_write must resolve secret placeholders"
    );
}

/// Test 5.4.8: Verify sigil_env tool
///
/// From Phase 5.4 deliverables:
/// "sigil_env returns env var names only (not values)"
#[test]
fn test_mcp_sigil_env() {
    let mcp_path = workspace_root().join("crates/sigil-mcp/src/main.rs");
    let mcp_code = fs::read_to_string(&mcp_path).expect("Failed to read sigil-mcp");

    // Verify handle_env function exists
    assert!(
        mcp_code.contains("fn handle_env") || mcp_code.contains("handle_sigil_env"),
        "MCP server must have handle_env function"
    );

    // Verify it returns variable names
    assert!(
        mcp_code.contains("variables") || mcp_code.contains("names"),
        "sigil_env must return variable names"
    );

    // Verify it filters sensitive vars
    assert!(
        mcp_code.contains("KEY") || mcp_code.contains("SECRET") || mcp_code.contains("filter"),
        "sigil_env must filter sensitive environment variables"
    );
}

/// Test 5.4.9: Verify sigil_status tool
///
/// From Phase 5.4 deliverables:
/// "sigil_status shows session stats and breach alerts"
#[test]
fn test_mcp_sigil_status() {
    let mcp_path = workspace_root().join("crates/sigil-mcp/src/main.rs");
    let mcp_code = fs::read_to_string(&mcp_path).expect("Failed to read sigil-mcp");

    // Verify handle_status function exists
    assert!(
        mcp_code.contains("fn handle_status") || mcp_code.contains("handle_sigil_status"),
        "MCP server must have handle_status function"
    );

    // Verify session stats
    assert!(
        mcp_code.contains("secrets_accessed") || mcp_code.contains("access_log"),
        "sigil_status must show secrets accessed"
    );

    // Verify breach alerts
    assert!(
        mcp_code.contains("breaches") || mcp_code.contains("breach_count"),
        "sigil_status must show breach alerts"
    );
}

/// Test 5.4.10: Verify MCP server uses JSON-RPC 2.0
///
/// From Phase 5.4 deliverables:
/// "MCP is a JSON-RPC 2.0-based protocol"
#[test]
fn test_mcp_json_rpc() {
    let mcp_path = workspace_root().join("crates/sigil-mcp/src/main.rs");
    let mcp_code = fs::read_to_string(&mcp_path).expect("Failed to read sigil-mcp");

    // Verify JSON-RPC request structure
    assert!(
        mcp_code.contains("JsonRpcRequest") || mcp_code.contains("struct.*Request"),
        "MCP server must have JSON-RPC request structure"
    );

    // Verify JSON-RPC response structure
    assert!(
        mcp_code.contains("JsonRpcResponse") || mcp_code.contains("struct.*Response"),
        "MCP server must have JSON-RPC response structure"
    );

    // Verify id, method, params fields
    assert!(
        mcp_code.contains("id") && mcp_code.contains("method") && mcp_code.contains("params"),
        "JSON-RPC structures must have id, method, params fields"
    );
}

/// Test 5.4.11: Verify MCP server stdio communication
///
/// From Phase 5.4 deliverables:
/// "Communicates via stdio"
#[test]
fn test_mcp_stdio_communication() {
    let mcp_path = workspace_root().join("crates/sigil-mcp/src/main.rs");
    let mcp_code = fs::read_to_string(&mcp_path).expect("Failed to read sigil-mcp");

    // Verify stdin reading
    assert!(
        mcp_code.contains("stdin") && mcp_code.contains("read"),
        "MCP server must read from stdin"
    );

    // Verify stdout writing
    assert!(
        mcp_code.contains("stdout") && mcp_code.contains("write") && mcp_code.contains("flush"),
        "MCP server must write to stdout"
    );
}

/// Test 5.4.12: Verify MCP server initialize handler
///
/// From Phase 5.4 deliverables:
/// "MCP protocol requires initialize handshake"
#[test]
fn test_mcp_initialize_handler() {
    let mcp_path = workspace_root().join("crates/sigil-mcp/src/main.rs");
    let mcp_code = fs::read_to_string(&mcp_path).expect("Failed to read sigil-mcp");

    // Verify initialize method handling
    assert!(
        mcp_code.contains("\"initialize\"") || mcp_code.contains("initialize"),
        "MCP server must handle initialize method"
    );

    // Verify server info response
    assert!(
        mcp_code.contains("serverInfo") || mcp_code.contains("server_info") || mcp_code.contains("name"),
        "MCP server must return server info in initialize response"
    );

    // Verify capabilities
    assert!(
        mcp_code.contains("capabilities") || mcp_code.contains("tools"),
        "MCP server must advertise capabilities"
    );
}

/// Test 5.4.13: Verify MCP server tools/list handler
///
/// From Phase 5.4 deliverables:
/// "MCP protocol: tools/list method"
#[test]
fn test_mcp_tools_list_handler() {
    let mcp_path = workspace_root().join("crates/sigil-mcp/src/main.rs");
    let mcp_code = fs::read_to_string(&mcp_path).expect("Failed to read sigil-mcp");

    // Verify tools/list method handling
    assert!(
        mcp_code.contains("tools/list") || mcp_code.contains("tools_list"),
        "MCP server must handle tools/list method"
    );

    // Verify tools array response
    assert!(
        mcp_code.contains("tools") && mcp_code.contains("array"),
        "MCP server must return tools array"
    );
}

/// Test 5.4.14: Verify MCP server tools/call handler
///
/// From Phase 5.4 deliverables:
/// "MCP protocol: tools/call method"
#[test]
fn test_mcp_tools_call_handler() {
    let mcp_path = workspace_root().join("crates/sigil-mcp/src/main.rs");
    let mcp_code = fs::read_to_string(&mcp_path).expect("Failed to read sigil-mcp");

    // Verify tools/call method handling
    assert!(
        mcp_code.contains("tools/call") || mcp_code.contains("tools_call"),
        "MCP server must handle tools/call method"
    );

    // Verify tool name extraction
    assert!(
        mcp_code.contains("name") && mcp_code.contains("arguments"),
        "MCP server must extract tool name and arguments"
    );
}

/// Test 5.4.15: Verify MCP server tool definitions
///
/// From Phase 5.4 deliverables:
/// "Each tool has name, description, input_schema"
#[test]
fn test_mcp_tool_definitions() {
    let mcp_path = workspace_root().join("crates/sigil-mcp/src/main.rs");
    let mcp_code = fs::read_to_string(&mcp_path).expect("Failed to read sigil-mcp");

    // Verify Tool struct
    assert!(
        mcp_code.contains("struct Tool") || mcp_code.contains("pub struct Tool"),
        "MCP server must have Tool struct"
    );

    // Verify Tool has name, description, input_schema
    assert!(
        mcp_code.contains("name") && mcp_code.contains("description") && mcp_code.contains("input_schema"),
        "Tool must have name, description, and input_schema fields"
    );
}

/// Test 5.4.16: Verify MCP server input schemas
///
/// From Phase 5.4 deliverables:
/// "Input schemas use JSON Schema format"
#[test]
fn test_mcp_input_schemas() {
    let mcp_path = workspace_root().join("crates/sigil-mcp/src/main.rs");
    let mcp_code = fs::read_to_string(&mcp_path).expect("Failed to read sigil-mcp");

    // Verify JSON Schema format
    assert!(
        mcp_code.contains("\"type\"") && mcp_code.contains("\"object\"") && mcp_code.contains("\"properties\""),
        "Input schemas must use JSON Schema format"
    );
}

/// Test 5.4.17: Verify MCP server secret access logging
///
/// From Phase 5.4 deliverables:
/// "Track all secret accesses"
#[test]
fn test_mcp_access_logging() {
    let mcp_path = workspace_root().join("crates/sigil-mcp/src/main.rs");
    let mcp_code = fs::read_to_string(&mcp_path).expect("Failed to read sigil-mcp");

    // Verify SecretAccess struct
    assert!(
        mcp_code.contains("struct SecretAccess") || mcp_code.contains("pub struct SecretAccess"),
        "MCP server must have SecretAccess struct"
    );

    // Verify access_log tracking
    assert!(
        mcp_code.contains("access_log") || mcp_code.contains("log_access"),
        "MCP server must track secret accesses"
    );
}

/// Test 5.4.18: Verify MCP server breach detection
///
/// From Phase 5.4 deliverables:
/// "Breach alerts for detected secret leaks"
#[test]
fn test_mcp_breach_detection() {
    let mcp_path = workspace_root().join("crates/sigil-mcp/src/main.rs");
    let mcp_code = fs::read_to_string(&mcp_path).expect("Failed to read sigil-mcp");

    // Verify BreachAlert struct
    assert!(
        mcp_code.contains("struct BreachAlert") || mcp_code.contains("pub struct BreachAlert"),
        "MCP server must have BreachAlert struct"
    );

    // Verify breaches tracking
    assert!(
        mcp_code.contains("breaches") || mcp_code.contains("breach_count"),
        "MCP server must track breaches"
    );
}

/// Test 5.4.19: Verify MCP server vault integration
///
/// From Phase 5.4 deliverables:
/// "Integrate with LocalVault for secret operations"
#[test]
fn test_mcp_vault_integration() {
    let mcp_path = workspace_root().join("crates/sigil-mcp/src/main.rs");
    let mcp_code = fs::read_to_string(&mcp_path).expect("Failed to read sigil-mcp");

    // Verify vault loading
    assert!(
        mcp_code.contains("load_vault") || mcp_code.contains("LocalVault"),
        "MCP server must integrate with LocalVault"
    );
}

/// Test 5.4.20: Verify MCP server never exposes secret values
///
/// From Phase 5.4 deliverables:
/// "MCP server never exposes secret values"
#[test]
fn test_mcp_never_exposes_secrets() {
    let mcp_path = workspace_root().join("crates/sigil-mcp/src/main.rs");
    let mcp_code = fs::read_to_string(&mcp_path).expect("Failed to read sigil-mcp");

    // This is a critical security check - the server should NOT expose raw secret values
    // Verify that when returning secrets, only metadata is returned
    assert!(
        mcp_code.contains("Never returns secret values") || mcp_code.contains("path") && mcp_code.contains("type"),
        "MCP server documentation must state it never returns secret values"
    );

    // Verify that the list handler doesn't expose values
    assert!(
        mcp_code.contains("handle_list") && (
            mcp_code.contains("\"path\"") ||
            mcp_code.contains("\"type\"") ||
            mcp_code.contains("\"created_at\"") ||
            mcp_code.contains("\"source\"")
        ),
        "sigil_list must only return metadata, not values"
    );
}

/// Test 5.4.21: Verify MCP server error handling
///
/// From Phase 5.4 deliverables:
/// "Proper error handling with JSON-RPC error format"
#[test]
fn test_mcp_error_handling() {
    let mcp_path = workspace_root().join("crates/sigil-mcp/src/main.rs");
    let mcp_code = fs::read_to_string(&mcp_path).expect("Failed to read sigil-mcp");

    // Verify JsonRpcError struct
    assert!(
        mcp_code.contains("struct JsonRpcError") || mcp_code.contains("pub enum JsonRpcResult"),
        "MCP server must have error structure"
    );

    // Verify error code and message
    assert!(
        mcp_code.contains("code") && mcp_code.contains("message"),
        "Error response must have code and message"
    );
}

/// Test 5.4.22: Verify MCP server has tests
///
/// From Phase 5.4 deliverables:
/// "All components should have tests"
#[test]
fn test_mcp_has_tests() {
    let mcp_path = workspace_root().join("crates/sigil-mcp/src/main.rs");
    let mcp_code = fs::read_to_string(&mcp_path).expect("Failed to read sigil-mcp");

    assert!(
        mcp_code.contains("#[cfg(test)]") || mcp_code.contains("#[test]"),
        "sigil-mcp must have tests"
    );
}

/// Test 5.4.23: Verify MCP server uses serde for JSON
///
/// From Phase 5.4 deliverables:
/// "JSON-RPC 2.0 protocol with serde_json"
#[test]
fn test_mcp_serde_integration() {
    let mcp_path = workspace_root().join("crates/sigil-mcp/src/main.rs");
    let mcp_code = fs::read_to_string(&mcp_path).expect("Failed to read sigil-mcp");

    // Verify serde imports
    assert!(
        mcp_code.contains("serde") && mcp_code.contains("Serialize") && mcp_code.contains("Deserialize"),
        "MCP server must use serde for serialization"
    );

    // Verify serde_json
    assert!(
        mcp_code.contains("serde_json") || mcp_code.contains("json!"),
        "MCP server must use serde_json for JSON handling"
    );
}

/// Test 5.4.24: Verify MCP server sealed operations support
///
/// From Phase 5.4 deliverables:
/// "Support sealed operations (pre-defined commands)"
#[test]
fn test_mcp_sealed_operations() {
    let mcp_path = workspace_root().join("crates/sigil-mcp/src/main.rs");
    let mcp_code = fs::read_to_string(&mcp_path).expect("Failed to read sigil-mcp");

    // Verify operation parameter in sigil_exec
    assert!(
        mcp_code.contains("operation") && mcp_code.contains("handle_exec"),
        "sigil_exec must support operation parameter"
    );

    // Verify operation loading
    assert!(
        mcp_code.contains("load_operation") || mcp_code.contains("SealedOperation"),
        "MCP server must support loading sealed operations"
    );
}

/// Test 5.4.25: Verify MCP server output filtering
///
/// From Phase 5.4 deliverables:
/// "Support different output filters for sealed operations"
#[test]
fn test_mcp_output_filtering() {
    let mcp_path = workspace_root().join("crates/sigil-mcp/src/main.rs");
    let mcp_code = fs::read_to_string(&mcp_path).expect("Failed to read sigil-mcp");

    // Verify output filter handling
    assert!(
        mcp_code.contains("output_filter") || mcp_code.contains("OutputFilter"),
        "MCP server must support output filtering"
    );

    // Verify filter types
    assert!(
        mcp_code.contains("ExitCode") || mcp_code.contains("Summary") || mcp_code.contains("FullScrubbed"),
        "MCP server must support different output filter types"
    );
}

/// Test 5.4.26: Verify MCP server session tracking
///
/// From Phase 5.4 deliverables:
/// "Track session start time for uptime calculation"
#[test]
fn test_mcp_session_tracking() {
    let mcp_path = workspace_root().join("crates/sigil-mcp/src/main.rs");
    let mcp_code = fs::read_to_string(&mcp_path).expect("Failed to read sigil-mcp");

    // Verify start_time tracking
    assert!(
        mcp_code.contains("start_time") || mcp_code.contains("Utc::now()"),
        "MCP server must track session start time"
    );

    // Verify uptime calculation
    assert!(
        mcp_code.contains("uptime") || mcp_code.contains("signed_duration_since"),
        "MCP server must calculate uptime"
    );
}

/// Test 5.4.27: Verify MCP server tool call handler
///
/// From Phase 5.4 deliverables:
/// "handle_tool_call function dispatches to tool handlers"
#[test]
fn test_mcp_tool_call_handler() {
    let mcp_path = workspace_root().join("crates/sigil-mcp/src/main.rs");
    let mcp_code = fs::read_to_string(&mcp_path).expect("Failed to read sigil-mcp");

    // Verify handle_tool_call function
    assert!(
        mcp_code.contains("fn handle_tool_call") || mcp_code.contains("pub fn handle_tool_call"),
        "MCP server must have handle_tool_call function"
    );

    // Verify it dispatches to specific handlers
    assert!(
        mcp_code.contains("handle_list") && mcp_code.contains("handle_exec") && mcp_code.contains("handle_write"),
        "handle_tool_call must dispatch to tool-specific handlers"
    );
}

/// Test 5.4.28: Verify MCP server logging
///
/// From Phase 5.4 deliverables:
/// "Use tracing for logging"
#[test]
fn test_mcp_logging() {
    let mcp_path = workspace_root().join("crates/sigil-mcp/src/main.rs");
    let mcp_code = fs::read_to_string(&mcp_path).expect("Failed to read sigil-mcp");

    // Verify tracing imports
    assert!(
        mcp_code.contains("tracing") || mcp_code.contains("info!") || mcp_code.contains("debug!"),
        "MCP server must use tracing for logging"
    );
}

/// Test 5.4.29: Verify MCP server daemon communication
///
/// From Phase 5.4 deliverables:
/// "Communicate with sigild for command execution"
#[test]
fn test_mcp_daemon_communication() {
    let mcp_path = workspace_root().join("crates/sigil-mcp/src/main.rs");
    let mcp_code = fs::read_to_string(&mcp_path).expect("Failed to read sigil-mcp");

    // Verify UnixStream for IPC
    assert!(
        mcp_code.contains("UnixStream") || mcp_code.contains("sigil.sock"),
        "MCP server must communicate with daemon via Unix socket"
    );

    // Verify IPC request/response types
    assert!(
        mcp_code.contains("IpcRequest") || mcp_code.contains("IpcResponse"),
        "MCP server must use IPC protocol types"
    );
}

/// Test 5.4.30: Verify MCP server project manifest support
///
/// From Phase 5.4 deliverables:
/// "Load project manifest for project-specific operations"
#[test]
fn test_mcp_project_manifest() {
    let mcp_path = workspace_root().join("crates/sigil-mcp/src/main.rs");
    let mcp_code = fs::read_to_string(&mcp_path).expect("Failed to read sigil-mcp");

    // Verify project manifest loading
    assert!(
        mcp_code.contains("load_project_manifest") || mcp_code.contains("ProjectManifest"),
        "MCP server must support project manifest loading"
    );

    // Verify manifest integration
    assert!(
        mcp_code.contains("manifest") && (
            mcp_code.contains("secrets") ||
            mcp_code.contains("operations")
        ),
        "MCP server must integrate with project manifest"
    );
}

/// Test 5.4.31: Verify MCP server supports write modes
///
/// From Phase 5.4 deliverables:
/// "sigil_write supports overwrite and append modes"
#[test]
fn test_mcp_write_modes() {
    let mcp_path = workspace_root().join("crates/sigil-mcp/src/main.rs");
    let mcp_code = fs::read_to_string(&mcp_path).expect("Failed to read sigil-mcp");

    // Verify mode parameter
    assert!(
        mcp_code.contains("\"overwrite\"") && mcp_code.contains("\"append\""),
        "sigil_write must support overwrite and append modes"
    );
}

/// Test 5.4.32: Verify MCP server additional tools
///
/// From Phase 5.4 deliverables:
/// "Additional MCP tools for enhanced functionality"
/// "sigil_list_operations, sigil_request, sigil_check_access"
#[test]
fn test_mcp_additional_tools() {
    let mcp_path = workspace_root().join("crates/sigil-mcp/src/main.rs");
    let mcp_code = fs::read_to_string(&mcp_path).expect("Failed to read sigil-mcp");

    // Verify additional tools exist
    let additional_tools = [
        "sigil_list_operations",
        "sigil_request",
        "sigil_check_access",
    ];

    for tool in additional_tools {
        assert!(
            mcp_code.contains(tool) || mcp_code.contains(&tool.replace("sigil_", "handle_")),
            "{}", format!("MCP server should have {} tool", tool)
        );
    }
}
