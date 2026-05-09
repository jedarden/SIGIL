//! IPC roundtrip benchmarks
//!
//! Measures performance of daemon communication:
//! - Request serialization/deserialization
//! - Response serialization/deserialization
//! - Unix socket roundtrip time (simulated)
//! - Session token validation

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};
use sigil_core::ipc::*;
use std::time::Duration;

fn bench_request_serialization(c: &mut Criterion) {
    let mut group = c.benchmark_group("ipc_serialize_request");

    let request_types = vec![
        ("resolve", IpcRequest::new(
            IpcOperation::Resolve,
            "test_token".to_string()
        )),
        ("exec", IpcRequest::new(
            IpcOperation::Exec,
            "test_token".to_string()
        )),
        ("scrub", IpcRequest::new(
            IpcOperation::Scrub,
            "test_token".to_string()
        )),
    ];

    for (name, request) in request_types {
        group.bench_with_input(BenchmarkId::new("serialize", name), &request, |b, req| {
            b.iter(|| serde_json::to_string(black_box(req)).unwrap());
        });
    }

    group.finish();
}

fn bench_response_serialization(c: &mut Criterion) {
    let mut group = c.benchmark_group("ipc_serialize_response");

    let resolve_response = IpcResponse::ok(
        IpcOperation::Resolve,
        serde_json::json!({"value": "secret_value"})
    );

    let exec_response = IpcResponse::ok(
        IpcOperation::Exec,
        serde_json::json!({"exit_code": 0, "stdout": "output", "stderr": ""})
    );

    let scrub_response = IpcResponse::ok(
        IpcOperation::Scrub,
        serde_json::json!({"scrubbed": "scrubbed_output", "matches_found": true})
    );

    let responses = vec![
        ("resolve", resolve_response),
        ("exec", exec_response),
        ("scrub", scrub_response),
    ];

    for (name, response) in responses {
        group.bench_with_input(BenchmarkId::new("serialize", name), &response, |b, resp| {
            b.iter(|| serde_json::to_string(black_box(resp)).unwrap());
        });
    }

    group.finish();
}

fn bench_request_deserialization(c: &mut Criterion) {
    let mut group = c.benchmark_group("ipc_deserialize_request");

    let resolve_json = serde_json::to_string(&IpcRequest::new(
        IpcOperation::Resolve,
        "test_token".to_string()
    )).unwrap();

    let exec_json = serde_json::to_string(&IpcRequest::new(
        IpcOperation::Exec,
        "test_token".to_string()
    )).unwrap();

    let scrub_json = serde_json::to_string(&IpcRequest::new(
        IpcOperation::Scrub,
        "test_token".to_string()
    )).unwrap();

    let requests = vec![
        ("resolve", resolve_json),
        ("exec", exec_json),
        ("scrub", scrub_json),
    ];

    for (name, json) in requests {
        group.bench_with_input(BenchmarkId::new("deserialize", name), &json, |b, j| {
            b.iter(|| serde_json::from_str::<IpcRequest>(black_box(j)).unwrap());
        });
    }

    group.finish();
}

fn bench_response_deserialization(c: &mut Criterion) {
    let mut group = c.benchmark_group("ipc_deserialize_response");

    let resolve_json = serde_json::to_string(&IpcResponse::ok(
        IpcOperation::Resolve,
        serde_json::json!({"value": "secret_value"})
    )).unwrap();

    let exec_json = serde_json::to_string(&IpcResponse::ok(
        IpcOperation::Exec,
        serde_json::json!({"exit_code": 0, "stdout": "output", "stderr": ""})
    )).unwrap();

    let scrub_json = serde_json::to_string(&IpcResponse::ok(
        IpcOperation::Scrub,
        serde_json::json!({"scrubbed": "scrubbed_output", "matches_found": true})
    )).unwrap();

    let responses = vec![
        ("resolve", resolve_json),
        ("exec", exec_json),
        ("scrub", scrub_json),
    ];

    for (name, json) in responses {
        group.bench_with_input(BenchmarkId::new("deserialize", name), &json, |b, j| {
            b.iter(|| serde_json::from_str::<IpcResponse>(black_box(j)).unwrap());
        });
    }

    group.finish();
}

fn bench_ipc_roundtrip(c: &mut Criterion) {
    let mut group = c.benchmark_group("ipc_roundtrip");

    // Simulate a full roundtrip: serialize -> deserialize -> process -> serialize -> deserialize
    let original_request = IpcRequest::with_payload(
        IpcOperation::Resolve,
        "test_token".to_string(),
        serde_json::json!({"path": "test/secret"})
    );

    group.bench_function("resolve_full_roundtrip", |b| {
        b.iter(|| {
            // Serialize request
            let request_json = serde_json::to_string(&black_box(&original_request)).unwrap();

            // Deserialize request
            let request: IpcRequest = serde_json::from_str(&request_json).unwrap();

            // Process (create response)
            let response = IpcResponse::ok(
                request.operation,
                serde_json::json!({"value": "secret_value"})
            );

            // Serialize response
            let response_json = serde_json::to_string(&black_box(&response)).unwrap();

            // Deserialize response
            let _response: IpcResponse = serde_json::from_str(&response_json).unwrap();

            // Return for black_box
            response_json
        });
    });

    group.finish();
}

fn bench_session_token_validation(c: &mut Criterion) {
    let mut group = c.benchmark_group("ipc_session_token");

    // Test with valid tokens (base64 encoded)
    let valid_tokens = vec![
        "dGVzdF90b2tlbl8xMjM0NTY3ODkw", // base64 of "test_token_1234567890"
        "YW5vdGhlcl92YWxpZF90b2tlbg==", // base64 of "another_valid_token"
        "YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXo=", // base64 of alphabet
    ];

    for token in valid_tokens {
        group.bench_with_input(BenchmarkId::new("valid_base64", token.len()), token, |b, t| {
            b.iter(|| {
                // Simulate token validation (check format, decode base64)
                let _decoded = base64::prelude::BASE64_STANDARD.decode(black_box(t.as_bytes()));
            });
        });
    }

    group.finish();
}

/// Phase 5 Red Team Checkpoint: IPC roundtrip time
///
/// From Phase 5 Red Team Checkpoint:
/// "Verify IPC roundtrip is < 1ms for resolve operation"
///
/// This benchmark measures the serialization/deserialization overhead
/// of IPC communication. The actual socket communication would add
/// more latency, but the JSON processing should be minimal.
fn bench_phase5_checkpoint_ipc_roundtrip(c: &mut Criterion) {
    let mut group = c.benchmark_group("phase5_checkpoint");

    group.measurement_time(Duration::from_secs(10));
    group.sample_size(1000);

    // Create a realistic resolve request
    let request = IpcRequest::with_payload(
        IpcOperation::Resolve,
        "session_token_abc123".to_string(),
        serde_json::json!({"path": "production/api/key"})
    );

    group.bench_function("ipc_resolve_roundtrip", |b| {
        b.iter(|| {
            // Serialize request
            let request_json = serde_json::to_string(&black_box(&request)).unwrap();

            // Deserialize request
            let _req: IpcRequest = serde_json::from_str(&request_json).unwrap();

            // Create response
            let response = IpcResponse::ok(
                IpcOperation::Resolve,
                serde_json::json!({"value": "sk_live_abc123xyz"})
            );

            // Serialize response
            let response_json = serde_json::to_string(&black_box(&response)).unwrap();

            // Deserialize response
            let _resp: IpcResponse = serde_json::from_str(&response_json).unwrap();

            // Return for timing
            (request_json.len(), response_json.len())
        });
    });

    group.finish();
}

criterion_group!(
    benches,
    bench_request_serialization,
    bench_response_serialization,
    bench_request_deserialization,
    bench_response_deserialization,
    bench_ipc_roundtrip,
    bench_session_token_validation,
    bench_phase5_checkpoint_ipc_roundtrip,
);
criterion_main!(benches);
