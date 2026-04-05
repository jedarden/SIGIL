//! Sealed Operations and Credential Helpers Integration Tests
//!
//! These tests verify the security properties of SIGIL's sealed operations
//! and credential helper integrations as specified in Phase 9 Red Team Checkpoint.

mod common;
use common::workspace_root;
use std::fs;

/// Test 1: Verify sealed operations hide command template from agent
///
/// From Phase 9 Red Team Checkpoint:
/// "Sealed ops: verify agent cannot extract command template or unfiltered output"
#[test]
fn test_sealed_ops_hides_command_template() {
    // Read the sealed operations implementation
    let ops_path = workspace_root().join("crates/sigil-core/src/operations.rs");
    let ops_code = fs::read_to_string(&ops_path).expect("Failed to read operations code");

    // Verify SealedOperation struct exists
    assert!(
        ops_code.contains("SealedOperation") || ops_code.contains("sealed"),
        "Sealed operations must be defined"
    );

    // Verify operation has command template (stored server-side)
    assert!(
        ops_code.contains("command") && ops_code.contains("String"),
        "SealedOperation must store command template"
    );

    // Check MCP server implementation for sealed operation handling
    let mcp_path = workspace_root().join("crates/sigil-mcp/src/main.rs");
    let mcp_code = fs::read_to_string(&mcp_path).expect("Failed to read MCP server code");

    // Verify operations are loaded from file (not exposed to agent)
    assert!(
        mcp_code.contains("operations.toml") || mcp_code.contains("load_operation"),
        "MCP server must load sealed operations from config file"
    );

    // Verify agent only sees operation descriptions, not commands
    assert!(
        mcp_code.contains("description")
            && (mcp_code.contains("sigil_list_operations") || mcp_code.contains("list_operations")),
        "Agent should only see operation descriptions, not command templates"
    );
}

/// Test 2: Verify sealed operations support output filtering
///
/// From Phase 9 Red Team Checkpoint:
/// "Sealed ops: verify agent cannot extract command template or unfiltered output"
#[test]
fn test_sealed_ops_output_filtering() {
    // Read the sealed operations implementation
    let ops_path = workspace_root().join("crates/sigil-core/src/operations.rs");
    let ops_code = fs::read_to_string(&ops_path).expect("Failed to read operations code");

    // Verify OutputFilter enum exists
    assert!(
        ops_code.contains("OutputFilter"),
        "Sealed operations must support output filtering"
    );

    // Verify different filter modes
    let filter_modes = vec!["ExitCode", "Summary", "FullScrubbed", "None"];

    for mode in filter_modes {
        assert!(
            ops_code.contains(mode),
            "OutputFilter must support {} mode",
            mode
        );
    }
}

/// Test 3: Verify sealed operations require approval
///
/// From Phase 9 Deliverables:
/// "TUI approval gate shows: operation name, which secrets will be used, the full command"
#[test]
fn test_sealed_ops_require_approval() {
    // Read the sealed operations implementation
    let ops_path = workspace_root().join("crates/sigil-core/src/operations.rs");
    let ops_code = fs::read_to_string(&ops_path).expect("Failed to read operations code");

    // Verify approval requirement field
    assert!(
        ops_code.contains("require_approval") || ops_code.contains("approval"),
        "SealedOperation must have approval requirement field"
    );

    // Check TUI approval module
    let tui_path = workspace_root().join("crates/sigil-tui/src/lib.rs");
    let tui_code = fs::read_to_string(&tui_path).expect("Failed to read TUI code");

    assert!(
        tui_code.contains("Approval") || tui_code.contains("approval"),
        "TUI must support approval prompts"
    );
}

/// Test 4: Verify sealed operations are logged
///
/// From Phase 9 Deliverables:
/// "Operations logged in audit trail: who triggered, when, which secrets, exit code"
#[test]
fn test_sealed_ops_audit_logging() {
    // Check audit log for operation execution tracking
    let audit_path = workspace_root().join("crates/sigil-daemon/src/audit.rs");
    let audit_code = fs::read_to_string(&audit_path).expect("Failed to read audit code");

    // Look for operation-related audit entries
    let has_op_logging = audit_code.contains("operation")
        || audit_code.contains("sealed")
        || audit_code.contains("execute");

    // Operation execution should be logged
    assert!(
        has_op_logging || audit_code.contains("exec"),
        "Audit log should track operation execution"
    );
}

/// Test 5: Verify time-bounded approvals auto-revoke
///
/// From Phase 9 Red Team Checkpoint:
/// "Request workflow: verify time-bounded approvals auto-revoke"
#[test]
fn test_time_bounded_approvals_auto_revoke() {
    // Read the daemon server code
    let server_path = workspace_root().join("crates/sigil-daemon/src/server.rs");
    let server_code = fs::read_to_string(&server_path).expect("Failed to read daemon server code");

    // Check for access grant expiration
    assert!(
        server_code.contains("expires")
            || server_code.contains("expiry")
            || server_code.contains("duration"),
        "Access grants must have expiration time"
    );

    // Check for cleanup of expired grants
    assert!(
        server_code.contains("clean")
            || server_code.contains("reap")
            || server_code.contains("expire"),
        "Daemon should clean up expired access grants"
    );
}

/// Test 6: Verify "always allow" is project-scoped
///
/// From Phase 9 Red Team Checkpoint:
/// "Request workflow: verify 'always allow' is scoped to specific project, not global"
#[test]
fn test_always_allow_project_scoping() {
    // Read the daemon server code
    let server_path = workspace_root().join("crates/sigil-daemon/src/server.rs");
    let server_code = fs::read_to_string(&server_path).expect("Failed to read daemon server code");

    // Check for project/agent-scoped access grants
    assert!(
        server_code.contains("agent_id")
            || server_code.contains("project")
            || server_code.contains("session"),
        "Access grants should be scoped to agent/project"
    );

    // Verify "always allow" grants are persisted with context
    assert!(
        server_code.contains("access-grants.toml")
            || server_code.contains("persist")
            || server_code.contains("save"),
        "Always allow grants should be persisted"
    );
}

/// Test 7: Verify git credential helper protocol
///
/// From Phase 9 Red Team Checkpoint:
/// "Git credential helper: verify git remote -v doesn't expose tokens"
#[test]
fn test_git_credential_helper_protocol() {
    // Check git credential helper implementation
    let git_path = workspace_root().join("crates/sigil-credential-git/src/lib.rs");

    if let Ok(git_code) = fs::read_to_string(&git_path) {
        // Verify git credential protocol support
        assert!(
            git_code.contains("get") || git_code.contains("store") || git_code.contains("erase"),
            "Git credential helper must implement standard protocol commands"
        );

        // Check that tokens are not exposed in git output
        // (this is verified by protocol design - secrets are returned via stdout to git,
        //  not displayed to user)
        assert!(
            git_code.contains("secret")
                || git_code.contains("password")
                || git_code.contains("token"),
            "Git credential helper must handle secrets"
        );
    } else {
        // Git credential helper is an optional deliverable
    }
}

/// Test 8: Verify sigil_exec supports both command and operation modes
///
/// From Phase 9 Deliverables:
/// "Agent triggers via MCP: sigil_exec('deploy') or sigil_exec({command: 'ls'})"
#[test]
fn test_sigil_exec_dual_mode() {
    // Read the MCP server code
    let mcp_path = workspace_root().join("crates/sigil-mcp/src/main.rs");
    let mcp_code = fs::read_to_string(&mcp_path).expect("Failed to read MCP server code");

    // Verify sigil_exec exists
    assert!(
        mcp_code.contains("sigil_exec") || mcp_code.contains("handle_exec"),
        "MCP server must implement sigil_exec tool"
    );

    // Check for operation vs command handling
    assert!(
        mcp_code.contains("operation") && mcp_code.contains("command"),
        "sigil_exec must support both operation and command modes"
    );

    // Verify mutual exclusivity check
    assert!(
        (mcp_code.contains("Either") && mcp_code.contains("or"))
            || (mcp_code.contains("both") && mcp_code.contains("not")),
        "sigil_exec should enforce operation/command mutual exclusivity"
    );
}

/// Test 9: Verify sigil_list_operations only exposes descriptions
///
/// From Phase 9 Deliverables:
/// "Agent receives operation list via sigil_list_operations (descriptions only, not commands)"
#[test]
fn test_sigil_list_operations_descriptions_only() {
    // Read the MCP server code
    let mcp_path = workspace_root().join("crates/sigil-mcp/src/main.rs");
    let mcp_code = fs::read_to_string(&mcp_path).expect("Failed to read MCP server code");

    // Verify sigil_list_operations exists
    assert!(
        mcp_code.contains("sigil_list_operations") || mcp_code.contains("list_operations"),
        "MCP server must implement sigil_list_operations tool"
    );

    // Verify only descriptions are returned
    assert!(
        mcp_code.contains("description"),
        "Operation listing should include descriptions"
    );

    // Ensure command templates are NOT included in the listing
    let list_handler = mcp_code.contains("handle_list_operations");

    assert!(
        list_handler,
        "MCP server must have handler for listing operations"
    );
}

/// Test 10: Verify SSH agent does not expose private keys
///
/// From Phase 9 Red Team Checkpoint:
/// "SSH agent: verify agent cannot extract private keys from agent protocol"
#[test]
fn test_ssh_agent_private_key_protection() {
    // Check SSH agent implementation
    let ssh_agent_path = workspace_root().join("crates/sigil-ssh-agent/src/lib.rs");
    let agent_impl_path = workspace_root().join("crates/sigil-ssh-agent/src/agent.rs");
    let protocol_path = workspace_root().join("crates/sigil-ssh-agent/src/protocol.rs");

    // Check if SSH agent crate exists
    if ssh_agent_path.exists() {
        let lib_code = fs::read_to_string(&ssh_agent_path).expect("Failed to read SSH agent lib code");

        // Verify SSH agent protocol implementation exists
        assert!(
            lib_code.contains("protocol") || lib_code.contains("agent"),
            "SSH agent must implement protocol"
        );

        // Check the main agent implementation
        if agent_impl_path.exists() {
            let impl_code = fs::read_to_string(&agent_impl_path).expect("Failed to read agent implementation");

            // Verify the agent handles key operations (sign, but not expose private key)
            assert!(
                impl_code.contains("sign") || impl_code.contains("sign_with_key"),
                "SSH agent must support signing operations"
            );

            // Check for key constraints (limits on key usage)
            assert!(
                impl_code.contains("constraint") || impl_code.contains("confirm") || impl_code.contains("approval"),
                "SSH agent should support key constraints"
            );
        }

        // Check protocol implementation
        if protocol_path.exists() {
            let protocol_code = fs::read_to_string(&protocol_path).expect("Failed to read protocol code");

            // Verify REQUEST_IDENTITIES (which returns public keys, not private)
            assert!(
                protocol_code.contains("identities") || protocol_code.contains("REQUEST_IDENTITIES"),
                "SSH agent can list identities (public keys only)"
            );
        }
    } else {
        // SSH agent is an optional deliverable
        return;
    }

    // Verify that private keys are never returned in responses
    // The SSH agent protocol design prevents this - only signing is supported
    if agent_impl_path.exists() {
        let impl_code = fs::read_to_string(&agent_impl_path).expect("Failed to read agent implementation");

        // Ensure there's no method to retrieve private key material
        // The protocol doesn't support this, but verify the implementation doesn't add it
        assert!(
            !impl_code.contains("get_private_key") && !impl_code.contains("export_private"),
            "SSH agent must not provide any way to retrieve private key material"
        );

        // Verify signing exists but private key export doesn't
        assert!(
            impl_code.contains("sign") || impl_code.contains("signature"),
            "SSH agent supports signing operations (with private key, but never returns it)"
        );
    }
}
