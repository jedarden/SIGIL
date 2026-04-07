//! Sandbox operation benchmarks
//!
//! Measures performance of sandbox execution:
//! - Command wrapping overhead
//! - Sandbox setup/teardown time
//! - File injection overhead
//! - Phase 4 Red Team Checkpoint: < 30ms overhead with cached secrets

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};
use sigil_core::ResolvedCommand;
use sigil_sandbox::{BubblewrapSandbox, SandboxConfig, SandboxProvider};

/// Simple test command
fn test_command() -> ResolvedCommand {
    ResolvedCommand {
        original: "echo hello".to_string(),
        placeholders: Vec::new(),
        resolved: "echo hello".to_string(),
        env_injections: Vec::new(),
        file_injections: Vec::new(),
        stdin_secret: None,
        use_stdin: false,
    }
}

/// Test command with environment injection
fn test_command_with_env() -> ResolvedCommand {
    ResolvedCommand {
        original: "echo $TEST_VAR".to_string(),
        placeholders: Vec::new(),
        resolved: "echo $TEST_VAR".to_string(),
        env_injections: vec![("TEST_VAR".to_string(), "test_value".to_string())],
        file_injections: Vec::new(),
        stdin_secret: None,
        use_stdin: false,
    }
}

/// Test command with file injection
fn test_command_with_file() -> ResolvedCommand {
    ResolvedCommand {
        original: "cat /tmp/test_secret".to_string(),
        placeholders: Vec::new(),
        resolved: "cat /tmp/test_secret".to_string(),
        env_injections: Vec::new(),
        file_injections: vec![("test_secret".to_string(), "/tmp/test_secret".to_string())],
        stdin_secret: None,
        use_stdin: false,
    }
}

fn bench_sandbox_wrap_overhead(c: &mut Criterion) {
    let mut group = c.benchmark_group("sandbox_wrap");

    let sandbox = BubblewrapSandbox::new().unwrap();
    let config = SandboxConfig::default();

    // Benchmark the wrap_command operation (not actual execution)
    // This measures the overhead of building the sandbox command
    group.bench_function("wrap_simple_command", |b| {
        let cmd = test_command();
        b.iter(|| black_box(sandbox.wrap_command(&cmd, &config)));
    });

    group.bench_function("wrap_with_env", |b| {
        let cmd = test_command_with_env();
        b.iter(|| black_box(sandbox.wrap_command(&cmd, &config)));
    });

    group.bench_function("wrap_with_file", |b| {
        let cmd = test_command_with_file();
        b.iter(|| black_box(sandbox.wrap_command(&cmd, &config)));
    });

    group.finish();
}

fn bench_sandbox_config_building(c: &mut Criterion) {
    let mut group = c.benchmark_group("sandbox_config");

    // Benchmark creating sandbox configs with different complexity
    group.bench_function("config_default", |b| {
        b.iter(SandboxConfig::default);
    });

    group.bench_function("config_with_project_dir", |b| {
        b.iter(|| SandboxConfig::with_project_dir(std::path::PathBuf::from("/test/project")));
    });

    group.bench_function("config_with_env", |b| {
        b.iter(|| {
            SandboxConfig::default().with_env("TEST_VAR".to_string(), "test_value".to_string())
        });
    });

    group.bench_function("config_with_file_injection", |b| {
        b.iter(|| {
            SandboxConfig::default().with_file_injection(
                "secret/path".to_string(),
                std::path::PathBuf::from("/target/path"),
            )
        });
    });

    group.finish();
}

fn bench_sandbox_with_multiple_injections(c: &mut Criterion) {
    let mut group = c.benchmark_group("sandbox_injections");

    for injection_count in [1, 5, 10, 20].iter() {
        group.bench_with_input(
            BenchmarkId::from_parameter(injection_count),
            injection_count,
            |b, &count| {
                let sandbox = BubblewrapSandbox::new().unwrap();
                let mut config = SandboxConfig::default();

                // Add multiple environment injections
                for i in 0..count {
                    config = config.with_env(format!("VAR_{}", i), format!("value_{}", i));
                }

                let cmd = test_command();

                b.iter(|| black_box(sandbox.wrap_command(&cmd, &config)));
            },
        );
    }

    group.finish();
}

/// Phase 4 Red Team Checkpoint: Sandbox execution time
///
/// From Phase 4 Red Team Checkpoint:
/// "Verify the sandbox adds < 30ms overhead (cached secrets)"
///
/// This benchmark measures the time it takes to wrap a command
/// in the sandbox. The actual execution time depends on the
/// command being run, but the sandbox wrapping overhead should
/// be minimal.
fn bench_phase4_checkpoint_sandbox_overhead(c: &mut Criterion) {
    let mut group = c.benchmark_group("phase4_checkpoint");

    let sandbox = BubblewrapSandbox::new().unwrap();
    let config = SandboxConfig::default();

    // Measure wrap_command overhead for typical command
    // This should complete in well under 30ms
    group.bench_function("sandbox_overhead_simple", |b| {
        let cmd = test_command();
        b.iter(|| {
            let result = sandbox.wrap_command(&cmd, &config);
            // We're measuring the time to wrap, not execute
            // The actual command execution would add more time
            black_box(result)
        });
    });

    // Measure with environment injection (simulating secret injection)
    group.bench_function("sandbox_overhead_with_secret", |b| {
        let mut cmd = test_command();
        cmd.env_injections = vec![
            ("API_KEY".to_string(), "sk_live_test_key".to_string()),
            (
                "DATABASE_URL".to_string(),
                "postgresql://localhost/db".to_string(),
            ),
        ];
        b.iter(|| {
            let result = sandbox.wrap_command(&cmd, &config);
            black_box(result)
        });
    });

    group.finish();
}

/// Benchmark sandbox capability detection
///
/// Measures the overhead of checking if sandbox is available
fn bench_sandbox_availability_check(c: &mut Criterion) {
    let mut group = c.benchmark_group("sandbox_checks");

    group.bench_function("is_available", |b| {
        let sandbox = BubblewrapSandbox::new().unwrap();
        b.iter(|| black_box(sandbox.is_available()));
    });

    group.bench_function("capabilities", |b| {
        let sandbox = BubblewrapSandbox::new().unwrap();
        b.iter(|| black_box(sandbox.capabilities()));
    });

    group.bench_function("provider_name", |b| {
        let sandbox = BubblewrapSandbox::new().unwrap();
        b.iter(|| black_box(sandbox.provider_name()));
    });

    group.finish();
}

criterion_group!(
    benches,
    bench_sandbox_wrap_overhead,
    bench_sandbox_config_building,
    bench_sandbox_with_multiple_injections,
    bench_phase4_checkpoint_sandbox_overhead,
    bench_sandbox_availability_check,
);
criterion_main!(benches);
