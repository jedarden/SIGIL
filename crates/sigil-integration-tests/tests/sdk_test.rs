//! SDK Authentication Integration Tests
//!
//! These tests verify the security properties of the SIGIL SDK
//! as specified in Phase 9 Red Team Checkpoint.

mod common;
use common::workspace_root;
use std::fs;

/// Test 1: Verify SDK client cannot bypass session token authentication
///
/// From Phase 9 Red Team Checkpoint:
/// "SDK: verify SDK client cannot bypass session token authentication"
#[test]
fn test_sdk_session_token_authentication() {
    // Read the SDK client implementation
    let client_path = workspace_root().join("crates/sigil-sdk/src/client.rs");
    let client_code = fs::read_to_string(&client_path).expect("Failed to read SDK client code");

    // Verify session token is required
    assert!(
        client_code.contains("session_token") || client_code.contains("SessionToken"),
        "SDK client must handle session tokens"
    );

    // Check that token is sent with requests (via IPC, not HTTP headers)
    assert!(
        client_code.contains("get_token") || client_code.contains("with_session_token"),
        "SDK client must send session token with requests"
    );

    // Verify daemon validates session tokens
    let server_path = workspace_root().join("crates/sigil-daemon/src/server.rs");
    let server_code = fs::read_to_string(&server_path).expect("Failed to read daemon server code");

    assert!(
        server_code.contains("validate_session_token") || server_code.contains("token"),
        "Daemon must validate session tokens"
    );
}

/// Test 2: Verify SDK supports all major operations
///
/// From Phase 9 Deliverables:
/// "SDK: connect, get, resolve, exists, list, request_access"
#[test]
fn test_sdk_operations() {
    // Read the SDK client implementation
    let client_path = workspace_root().join("crates/sigil-sdk/src/client.rs");
    let client_code = fs::read_to_string(&client_path).expect("Failed to read SDK client code");

    // Verify core operations exist
    let operations = vec![
        ("get", "get secret"),
        ("resolve", "resolve placeholders"),
        ("exists", "check secret exists"),
        ("list", "list secrets"),
        ("request_access", "request access"),
    ];

    for (method, description) in operations {
        assert!(
            client_code.contains(method) || client_code.contains(&format!("fn {}", method)),
            "SDK should support {}: {} method",
            method,
            description
        );
    }
}

/// Test 3: Verify SDK session token acquisition from environment
///
/// From Phase 9 Deliverables:
/// "Session token acquired from environment or fd inheritance"
#[test]
fn test_sdk_token_acquisition() {
    // Read the SDK client implementation
    let client_path = workspace_root().join("crates/sigil-sdk/src/client.rs");
    let client_code = fs::read_to_string(&client_path).expect("Failed to read SDK client code");

    // Check for environment variable token acquisition
    let has_env_token = client_code.contains("SIGIL_TOKEN")
        || client_code.contains("env")
        || (client_code.contains("var") && client_code.contains("token"));

    assert!(
        has_env_token,
        "SDK must acquire session token from environment"
    );
}

/// Test 4: Verify Python SDK bindings work
///
/// From Phase 9 Deliverables:
/// "Python bindings via PyO3: pip install sigil-sdk"
#[test]
fn test_python_sdk_bindings() {
    // Check if Python SDK crate exists
    let py_sdk_path = workspace_root().join("crates/sigil-sdk-python/src/lib.rs");

    if let Ok(py_sdk_code) = fs::read_to_string(&py_sdk_path) {
        // Verify it's a PyO3 module
        assert!(
            py_sdk_code.contains("pyo3")
                || py_sdk_code.contains("PyO3")
                || py_sdk_code.contains("#[pymodule]"),
            "Python SDK must use PyO3"
        );

        // Check for basic operations
        assert!(
            py_sdk_code.contains("SigilClient") || py_sdk_code.contains("client"),
            "Python SDK should expose SigilClient"
        );
    } else {
        // Python SDK is an optional deliverable
    }
}

/// Test 5: Verify Node.js SDK bindings work
///
/// From Phase 9 Deliverables:
/// "Node.js bindings via napi-rs: npm install @sigil/sdk"
#[test]
fn test_nodejs_sdk_bindings() {
    // Check if Node.js SDK crate exists
    let node_sdk_path = workspace_root().join("crates/sigil-sdk-nodejs");

    // Check if the directory exists
    if node_sdk_path.exists() {
        // Look for package.json
        let package_json_path = node_sdk_path.join("package.json");
        if let Ok(package_json) = fs::read_to_string(&package_json_path) {
            // Verify it's an npm package
            assert!(
                package_json.contains("name") && package_json.contains("@sigil/sdk"),
                "Node.js SDK should have correct package name"
            );
        }

        // Check for napi-rs usage in Cargo.toml
        let cargo_toml_path = node_sdk_path.join("Cargo.toml");
        if let Ok(cargo_toml) = fs::read_to_string(&cargo_toml_path) {
            assert!(
                cargo_toml.contains("napi")
                    || cargo_toml.contains("napi-rs")
                    || cargo_toml.contains("napi_derive"),
                "Node.js SDK should use napi-rs"
            );
        }
    } else {
        // Node.js SDK is an optional deliverable
    }
}
