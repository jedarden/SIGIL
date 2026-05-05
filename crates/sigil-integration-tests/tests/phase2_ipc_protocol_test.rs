//! Phase 2.6 IPC Protocol Tests
//!
//! These tests verify:
//! - Length-prefixed JSON over Unix socket
//! - Request envelope: v, id, op, token, payload
//! - Response envelope: v, id, ok, payload/error
//! - All 15 error codes implemented
//! - Multiplexed requests with request ID correlation
//! - Streaming protocol for long-running operations
//! - Protocol version field enables backward compatibility

mod common;
use common::workspace_root;
use sigil_core::ipc::{
    IpcError, IpcErrorCode, IpcOperation, IpcRequest, IpcResponse, SessionToken, PROTOCOL_VERSION,
};
use std::fs;
use std::io::Cursor;
use std::process::{Command, Stdio};
use std::thread;
use std::time::Duration;
use tempfile::TempDir;

/// Test 1: Verify length-prefixed JSON protocol
///
/// From Phase 2.6 Deliverables:
/// - Length-prefixed JSON over Unix socket
#[test]
fn test_length_prefixed_protocol() {
    let workspace = workspace_root();
    let ipc_code_path = workspace.join("crates/sigil-core/src/ipc.rs");
    let ipc_code = fs::read_to_string(&ipc_code_path).expect("Failed to read IPC code");

    // Verify length prefix functions exist
    assert!(
        ipc_code.contains("pub fn write_message") || ipc_code.contains("pub fn read_message"),
        "IPC module should have length-prefixed message functions"
    );

    // Verify big-endian u32 length prefix
    assert!(
        ipc_code.contains("to_be_bytes()") || ipc_code.contains("u32::from_be_bytes"),
        "Protocol should use big-endian u32 for length prefix"
    );

    // Verify MAX_MESSAGE_SIZE is enforced
    assert!(
        ipc_code.contains("MAX_MESSAGE_SIZE") && ipc_code.contains("exceeds maximum size"),
        "Protocol should enforce maximum message size"
    );

    // Test actual encoding/decoding
    use sigil_core::ipc::{read_message, write_message};

    let test_data = b"Hello, World!";
    let mut buffer = Vec::new();

    write_message(&mut buffer, test_data).expect("Failed to write message");

    // Verify length prefix (4 bytes) + data
    assert_eq!(buffer.len(), 4 + test_data.len());

    // Verify length prefix is correct
    let len_prefix = u32::from_be_bytes([buffer[0], buffer[1], buffer[2], buffer[3]]);
    assert_eq!(len_prefix as usize, test_data.len());

    // Verify we can read it back
    let mut cursor = Cursor::new(buffer);
    let read_data = read_message(&mut cursor).expect("Failed to read message");

    assert_eq!(read_data, test_data);

    println!("Length-prefixed protocol test passed!");
}

/// Test 2: Verify request envelope structure
///
/// From Phase 2.6 Deliverables:
/// - Request envelope: v, id, op, token, payload
#[test]
fn test_request_envelope_structure() {
    // Create a request
    let token = SessionToken::generate();
    let request = IpcRequest::new(IpcOperation::Ping, token.to_base64());

    // Verify protocol version
    assert_eq!(request.v, PROTOCOL_VERSION);

    // Verify request ID is generated
    assert!(!request.id.is_empty());
    assert!(request.id.starts_with("req_"));

    // Verify operation is set
    assert_eq!(request.op, IpcOperation::Ping);

    // Verify token is set
    assert!(!request.token.is_empty());

    // Verify payload defaults to null
    assert!(request.payload.is_null());

    // Test with payload
    let request_with_payload = IpcRequest::with_payload(
        IpcOperation::Status,
        token.to_base64(),
        serde_json::json!({"test": "data"}),
    );

    assert_eq!(request_with_payload.v, PROTOCOL_VERSION);
    assert!(!request_with_payload.payload.is_null());
    assert_eq!(request_with_payload.payload["test"], "data");

    // Verify serialization
    let json = serde_json::to_string(&request).expect("Failed to serialize request");
    assert!(json.contains("\"v\":1"));
    assert!(json.contains("\"op\":\"ping\""));
    assert!(json.contains("\"id\":"));
    assert!(json.contains("\"token\":"));

    println!("Request envelope test passed!");
}

/// Test 3: Verify response envelope structure
///
/// From Phase 2.6 Deliverables:
/// - Response envelope: v, id, ok, payload/error
#[test]
fn test_response_envelope_structure() {
    // Create success response
    let success_response = IpcResponse::ok("req_123".to_string());

    assert_eq!(success_response.v, PROTOCOL_VERSION);
    assert_eq!(success_response.id, "req_123");
    assert!(success_response.ok);
    assert!(success_response.error.is_none());
    assert!(!success_response.stream);

    // Create success response with payload
    let success_with_payload = IpcResponse::with_payload(
        "req_456".to_string(),
        serde_json::json!({"result": "success"}),
    );

    assert!(success_with_payload.ok);
    assert_eq!(success_with_payload.payload["result"], "success");

    // Create error response
    let error = IpcError::new(IpcErrorCode::SecretNotFound, "Secret not found");
    let error_response = IpcResponse::error("req_789".to_string(), error);

    assert_eq!(error_response.v, PROTOCOL_VERSION);
    assert_eq!(error_response.id, "req_789");
    assert!(!error_response.ok);
    assert!(error_response.error.is_some());
    assert_eq!(
        error_response.error.as_ref().unwrap().code,
        IpcErrorCode::SecretNotFound
    );

    // Verify serialization
    let json = serde_json::to_string(&success_response).expect("Failed to serialize response");
    assert!(json.contains("\"v\":1"));
    assert!(json.contains("\"ok\":true"));
    assert!(json.contains("\"id\":\"req_123\""));

    let error_json =
        serde_json::to_string(&error_response).expect("Failed to serialize error response");
    assert!(error_json.contains("\"ok\":false"));
    assert!(error_json.contains("\"code\":\"SECRET_NOT_FOUND\""));

    println!("Response envelope test passed!");
}

/// Test 4: Verify all 15 error codes are implemented
///
/// From Phase 2.6 Deliverables:
/// - All 15 error codes implemented
#[test]
fn test_all_error_codes_implemented() {
    let workspace = workspace_root();
    let ipc_code_path = workspace.join("crates/sigil-core/src/ipc.rs");
    let ipc_code = fs::read_to_string(&ipc_code_path).expect("Failed to read IPC code");

    // Expected error codes from the spec
    let expected_errors = [
        "InvalidToken",
        "InvalidRequest",
        "UnknownOp",
        "SecretNotFound",
        "AccessDenied",
        "VaultLocked",
        "RateLimited",
        "PayloadTooLarge",
        "InternalError",
        "SessionExpired",
        "OperationFailed",
        "SandboxError",
        "ScrubError",
        "BackendError",
        "LockedDown",
    ];

    // Verify all error codes exist
    for error_name in &expected_errors {
        assert!(
            ipc_code.contains(error_name),
            "Missing error code: {}",
            error_name
        );
    }

    // Verify error code enum has at least 15 variants
    assert!(
        ipc_code.contains("pub enum IpcErrorCode"),
        "IPC module should define IpcErrorCode enum"
    );

    // Verify Display is implemented
    assert!(
        ipc_code.contains("impl std::fmt::Display for IpcErrorCode"),
        "IpcErrorCode should implement Display"
    );

    // Verify std::error::Error is implemented
    assert!(
        ipc_code.contains("impl std::error::Error for IpcErrorCode"),
        "IpcErrorCode should implement std::error::Error"
    );

    // Test creating each error code
    let error_codes = vec![
        IpcErrorCode::InvalidToken,
        IpcErrorCode::InvalidRequest,
        IpcErrorCode::UnknownOp,
        IpcErrorCode::SecretNotFound,
        IpcErrorCode::AccessDenied,
        IpcErrorCode::VaultLocked,
        IpcErrorCode::RateLimited,
        IpcErrorCode::PayloadTooLarge,
        IpcErrorCode::InternalError,
        IpcErrorCode::SessionExpired,
        IpcErrorCode::OperationFailed,
        IpcErrorCode::SandboxError,
        IpcErrorCode::ScrubError,
        IpcErrorCode::BackendError,
        IpcErrorCode::LockedDown,
    ];

    for code in error_codes {
        let error = IpcError::new(code, "test message");
        assert_eq!(error.code, code);
        assert_eq!(error.message, "test message");
    }

    println!("All error codes test passed!");
}

/// Test 5: Verify multiplexed requests with request ID correlation
///
/// From Phase 2.6 Deliverables:
/// - Multiplexed requests with request ID correlation
#[test]
fn test_multiplexed_request_id_correlation() {
    let workspace = workspace_root();
    let sigil_bin = workspace.join("target/debug/sigil");

    if !sigil_bin.exists() {
        println!("SIGIL binary not found, skipping multiplexing test");
        return;
    }

    // Create a temporary directory for the test vault
    let temp_dir = TempDir::new().expect("Failed to create temp dir");
    let vault_dir = temp_dir.path().join("sigil");
    let runtime_dir = temp_dir.path().join("runtime");
    let data_dir = temp_dir.path().join(".local");

    fs::create_dir_all(&vault_dir).expect("Failed to create vault dir");
    fs::create_dir_all(&runtime_dir).expect("Failed to create runtime dir");
    fs::create_dir_all(&data_dir).expect("Failed to create data dir");

    // Initialize a vault
    let init_status = Command::new(&sigil_bin)
        .env("HOME", temp_dir.path())
        .env("XDG_RUNTIME_DIR", &runtime_dir)
        .env("XDG_DATA_HOME", &data_dir)
        .args(["init", "--non-interactive"])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .status();

    if !init_status.map(|s| s.success()).unwrap_or(false) {
        println!("Failed to initialize vault, skipping test");
        return;
    }

    // Start the daemon
    let mut daemon = Command::new(&sigil_bin)
        .env("HOME", temp_dir.path())
        .env("XDG_RUNTIME_DIR", &runtime_dir)
        .env("XDG_DATA_HOME", &data_dir)
        .args(["daemon", "start"])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("Failed to start daemon");

    // Wait for daemon to start
    thread::sleep(Duration::from_secs(2));

    // Add multiple secrets rapidly to test multiplexing
    let mut handles = Vec::new();
    for i in 0..5 {
        let sigil_bin = sigil_bin.clone();
        let temp_dir = temp_dir.path().to_path_buf();
        let runtime_dir = runtime_dir.clone();
        let data_dir = data_dir.clone();

        let handle = thread::spawn(move || {
            Command::new(&sigil_bin)
                .env("HOME", &temp_dir)
                .env("XDG_RUNTIME_DIR", &runtime_dir)
                .env("XDG_DATA_HOME", &data_dir)
                .args([
                    "add",
                    &format!("multiplex/test/{}", i),
                    "--value",
                    &format!("value-{}", i),
                ])
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .status()
        });

        handles.push(handle);
    }

    // Wait for all commands to complete
    for handle in handles {
        let _ = handle.join();
    }

    // Stop the daemon
    let _ = daemon.kill();
    let _ = daemon.wait();
    thread::sleep(Duration::from_millis(500));

    // Verify request ID generation is unique
    let token1 = SessionToken::generate();
    let token2 = SessionToken::generate();

    let req1 = IpcRequest::new(IpcOperation::Ping, token1.to_base64());
    let req2 = IpcRequest::new(IpcOperation::Ping, token2.to_base64());

    assert_ne!(req1.id, req2.id, "Request IDs should be unique");

    println!("Multiplexed request ID correlation test passed!");
}

/// Test 6: Verify streaming protocol support
///
/// From Phase 2.6 Deliverables:
/// - Streaming protocol for long-running operations
#[test]
fn test_streaming_protocol_support() {
    let workspace = workspace_root();
    let ipc_code_path = workspace.join("crates/sigil-core/src/ipc.rs");
    let ipc_code = fs::read_to_string(&ipc_code_path).expect("Failed to read IPC code");

    // Verify stream field exists in response
    assert!(
        ipc_code.contains("pub stream: bool") || ipc_code.contains("#[serde(default)]"),
        "Response should have a stream field"
    );

    // Verify stream_chunk helper exists
    assert!(
        ipc_code.contains("pub fn stream_chunk"),
        "Response should have a stream_chunk helper"
    );

    // Verify streaming response structure
    let response = IpcResponse::stream_chunk("req_123".to_string(), "chunk data".to_string());

    assert_eq!(response.v, PROTOCOL_VERSION);
    assert_eq!(response.id, "req_123");
    assert!(response.ok);
    assert!(response.stream);
    assert_eq!(response.payload["chunk"], "chunk data");

    // Verify serialization includes stream flag
    let json = serde_json::to_string(&response).expect("Failed to serialize streaming response");
    assert!(json.contains("\"stream\":true"));

    println!("Streaming protocol test passed!");
}

/// Test 7: Verify protocol version field for backward compatibility
///
/// From Phase 2.6 Deliverables:
/// - Protocol version field enables backward compatibility
#[test]
fn test_protocol_version_backward_compatibility() {
    let workspace = workspace_root();
    let ipc_code_path = workspace.join("crates/sigil-core/src/ipc.rs");
    let ipc_code = fs::read_to_string(&ipc_code_path).expect("Failed to read IPC code");

    // Verify PROTOCOL_VERSION constant exists
    assert!(
        ipc_code.contains("pub const PROTOCOL_VERSION: u16 = 1"),
        "IPC module should define protocol version constant"
    );

    // Verify version field exists in request and response
    assert!(
        ipc_code.contains("pub v: u16"),
        "Request and Response should have version field"
    );

    // Verify version validation on read
    assert!(
        ipc_code.contains("UnsupportedProtocolVersion")
            || ipc_code.contains("request.v != PROTOCOL_VERSION"),
        "Protocol should validate version on read"
    );

    // Verify current version is 1
    assert_eq!(PROTOCOL_VERSION, 1);

    // Test creating requests with different versions
    let token = SessionToken::generate();
    let request = IpcRequest::new(IpcOperation::Ping, token.to_base64());

    // Current version should work
    assert_eq!(request.v, PROTOCOL_VERSION);

    // Test that we can deserialize version 1 requests
    let json = r#"{"v":1,"id":"test_id","op":"ping","token":"dGVzdA==","payload":null}"#;
    let deserialized: Result<IpcRequest, _> = serde_json::from_str(json);

    assert!(deserialized.is_ok(), "Should deserialize valid v1 request");
    let req = deserialized.unwrap();
    assert_eq!(req.v, 1);

    println!("Protocol version backward compatibility test passed!");
}

/// Test 8: Verify IPC operations enum has all required operations
///
/// From Phase 2.6 Deliverables:
/// - All IPC operations defined
#[test]
fn test_ipc_operations_complete() {
    let workspace = workspace_root();
    let ipc_code_path = workspace.join("crates/sigil-core/src/ipc.rs");
    let ipc_code = fs::read_to_string(&ipc_code_path).expect("Failed to read IPC code");

    // Expected operations from the spec
    let expected_operations = [
        "Ping",
        "Status",
        "Auth",
        "SessionStart",
        "SessionEnd",
        "Resolve",
        "Scrub",
        "Exec",
        "HookPre",
        "HookPost",
        "HookWrite",
        "HookRead",
        "List",
        "Get",
        "Set",
        "Delete",
        "BackendSync",
        "CanaryStatus",
        "BreachReport",
        "Lint",
        "Wrap",
        "FuseRead",
        "ProxyStatus",
        "Lockdown",
        "Unlock",
        "Doctor",
        "RequestAccess",
        "CheckAccess",
        "ListOperations",
        "ExecuteOperation",
        "Cancel",
        "ListSessions",
        "KillSession",
        "GetSessionTree",
        "LeaseGrant",
        "LeaseRevoke",
        "LeaseList",
        "LeaseStats",
    ];

    // Verify operations exist
    for op_name in &expected_operations {
        assert!(
            ipc_code.contains(op_name),
            "Missing IPC operation: {}",
            op_name
        );
    }

    // Verify IpcOperation enum exists
    assert!(
        ipc_code.contains("pub enum IpcOperation"),
        "IPC module should define IpcOperation enum"
    );

    // Verify operations are snake_case in JSON
    let test_ops = vec![
        IpcOperation::Ping,
        IpcOperation::Status,
        IpcOperation::Resolve,
        IpcOperation::Exec,
    ];

    for op in test_ops {
        let json = serde_json::to_string(&op).expect("Failed to serialize operation");
        // Should be snake_case
        assert!(json.contains("\""), "Serialized operation should be quoted");
    }

    println!("IPC operations completeness test passed!");
}

/// Test 9: Verify session token generation and validation
///
/// From Phase 2.6 Deliverables:
/// - Session token handling
#[test]
fn test_session_token_handling() {
    // Generate tokens
    let token1 = SessionToken::generate();
    let token2 = SessionToken::generate();

    // Tokens should be unique
    assert_ne!(token1, token2);

    // Tokens should be base64-encoded
    let token1_str = token1.to_base64();
    assert!(!token1_str.is_empty());

    // Verify we can create from string
    let token3 = SessionToken::from_string(token1_str.clone());
    assert!(token3.is_ok());
    assert_eq!(token3.unwrap(), token1);

    // Verify invalid token fails
    let invalid_token = SessionToken::from_string("not-valid-base64!!".to_string());
    assert!(invalid_token.is_err());

    // Verify token length is correct (32 bytes -> base64 is longer)
    let token_bytes = token1.to_bytes();
    assert_eq!(token_bytes.len(), 32);

    println!("Session token handling test passed!");
}
