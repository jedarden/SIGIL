#![no_main]
use libfuzzer_sys::fuzz_target;
use sigil_core::ipc::*;

fuzz_target!(|data: &[u8]| {
    // Test IPC protocol parsing with potentially malformed data

    let input = String::from_utf8_lossy(data).to_string();

    // Test 1: IpcRequest parsing should not panic
    let _ = serde_json::from_str::<IpcRequest>(&input);

    // Test 2: IpcResponse parsing should not panic
    let _ = serde_json::from_str::<IpcResponse>(&input);

    // Test 3: IpcOperation parsing should not panic
    let _ = serde_json::from_str::<IpcOperation>(&input);

    // Test 4: IpcErrorCode parsing should not panic
    let _ = serde_json::from_str::<IpcErrorCode>(&input);

    // Test 5: IpcError parsing should not panic
    let _ = serde_json::from_str::<IpcError>(&input);

    // Test 6: Test with valid but edge-case requests
    if let Ok(op) = serde_json::from_str::<IpcOperation>(&input) {
        // Create request with fuzzed operation
        let request = IpcRequest::new(op, "test_token".to_string());
        // Serialize and deserialize should not panic
        let json = serde_json::to_string(&request);
        let _ = serde_json::from_str::<IpcRequest>(&json.unwrap_or_default());

        // Test with_payload
        let _ = IpcRequest::with_payload(op, "test_token".to_string(), serde_json::json!({}));
    }

    // Test 7: Test response creation
    let test_id = "test_request_id".to_string();
    let response = IpcResponse::ok(test_id.clone());
    let json = serde_json::to_string(&response);
    let _ = serde_json::from_str::<IpcResponse>(&json.unwrap_or_default());

    let error_response = IpcResponse::error(test_id, IpcError::new(IpcErrorCode::InternalError, "test"));
    let json = serde_json::to_string(&error_response);
    let _ = serde_json::from_str::<IpcResponse>(&json.unwrap_or_default());

    // Test 8: Test oversized messages
    if data.len() > MAX_MESSAGE_SIZE {
        // Ensure size validation handles oversized messages
        let oversized = input.clone();
        let _ = serde_json::from_str::<IpcRequest>(&oversized);
    }

    // Test 9: Test token validation (session tokens are base64)
    use base64::prelude::*;
    let _ = BASE64_STANDARD.decode(data);

    // Test 11: Test specific request/response types
    let _ = serde_json::from_str::<ResolveRequest>(&input);
    let _ = serde_json::from_str::<ResolveResponse>(&input);
    let _ = serde_json::from_str::<ExecRequest>(&input);
    let _ = serde_json::from_str::<ExecResponse>(&input);
    let _ = serde_json::from_str::<ScrubRequest>(&input);
    let _ = serde_json::from_str::<ScrubResponse>(&input);
    let _ = serde_json::from_str::<PingResponse>(&input);

    // Test 12: Test DaemonStatus parsing
    let _ = serde_json::from_str::<DaemonStatus>(&input);
});
