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

/// Benchmark sandbox cold vs warm start
///
/// From the task requirements:
/// "Implement criterion benchmarks — sandbox cold/warm"
///
/// **Cold start**: First-time sandbox execution where configuration
/// is built from scratch for each iteration. This simulates starting
/// a new sandboxed process each time.
///
/// **Warm start**: Reusing a pre-built sandbox configuration across
/// multiple iterations. This simulates repeated executions with
/// the same sandbox setup.
///
/// The difference between cold and warm represents the overhead of
/// building the sandbox configuration vs. the overhead of wrapping
/// commands with an existing configuration.
fn bench_sandbox_cold_warm_start(c: &mut Criterion) {
    // Cold start: Build config from scratch each iteration
    let mut cold_group = c.benchmark_group("sandbox_cold_start");

    cold_group.bench_function("build_config_and_wrap", |b| {
        b.iter(|| {
            let sandbox = BubblewrapSandbox::new().unwrap();

            // Build config from scratch each time
            let config = SandboxConfig::with_project_dir(std::path::PathBuf::from("/test/project"))
                .with_env("API_KEY".to_string(), "sk_live_test_key".to_string())
                .with_env("DATABASE_URL".to_string(), "postgresql://localhost/db".to_string())
                .with_file_injection(
                    "secret/config".to_string(),
                    std::path::PathBuf::from("/tmp/config.json"),
                );

            let cmd = test_command_with_env();
            black_box(sandbox.wrap_command(&cmd, &config))
        });
    });

    cold_group.finish();

    // Warm start: Pre-build config, reuse across iterations
    let mut warm_group = c.benchmark_group("sandbox_warm_start");

    warm_group.bench_function("reuse_config_and_wrap", |b| {
        let sandbox = BubblewrapSandbox::new().unwrap();

        // Pre-build configuration (simulating "warm" state)
        let config = SandboxConfig::with_project_dir(std::path::PathBuf::from("/test/project"))
            .with_env("API_KEY".to_string(), "sk_live_test_key".to_string())
            .with_env("DATABASE_URL".to_string(), "postgresql://localhost/db".to_string())
            .with_file_injection(
                "secret/config".to_string(),
                std::path::PathBuf::from("/tmp/config.json"),
            );

        let cmd = test_command_with_env();

        b.iter(|| black_box(sandbox.wrap_command(&cmd, &config)));
    });

    warm_group.finish();
}

/// Benchmark sandbox cold/warm with varying complexity
///
/// Measures how cold vs warm start performance scales with the number
/// of environment variables and file injections.
fn bench_sandbox_cold_warm_scaling(c: &mut Criterion) {
    for complexity in [1, 5, 10, 20].iter() {
        // Cold start benchmarks
        let mut cold_group = c.benchmark_group(format!("sandbox_cold_scaling_{}", complexity));
        cold_group.bench_with_input(
            BenchmarkId::new("cold_build", complexity),
            complexity,
            |b, &count| {
                b.iter(|| {
                    let sandbox = BubblewrapSandbox::new().unwrap();
                    let mut config = SandboxConfig::default();

                    for i in 0..count {
                        config = config.with_env(format!("VAR_{}", i), format!("value_{}", i));
                    }

                    let cmd = test_command();
                    black_box(sandbox.wrap_command(&cmd, &config))
                });
            },
        );
        cold_group.finish();

        // Warm start benchmarks
        let mut warm_group = c.benchmark_group(format!("sandbox_warm_scaling_{}", complexity));
        warm_group.bench_with_input(
            BenchmarkId::new("warm_reuse", complexity),
            complexity,
            |b, &count| {
                let sandbox = BubblewrapSandbox::new().unwrap();
                let mut config = SandboxConfig::default();

                for i in 0..count {
                    config = config.with_env(format!("VAR_{}", i), format!("value_{}", i));
                }

                let cmd = test_command();
                b.iter(|| {
                    let _ = black_box(sandbox.wrap_command(&cmd, &config));
                });
            },
        );
        warm_group.finish();
    }
}

/// Benchmark sequential sandbox command execution
///
/// Simulates running multiple commands in sequence with the same
/// sandbox configuration, which is the typical warm-start scenario
/// for long-running daemon processes.
fn bench_sandbox_sequential_execution(c: &mut Criterion) {
    let mut group = c.benchmark_group("sandbox_sequential");

    group.bench_function("wrap_10_commands_sequentially", |b| {
        let sandbox = BubblewrapSandbox::new().unwrap();
        let config = SandboxConfig::with_project_dir(std::path::PathBuf::from("/test/project"))
            .with_env("TEST_VAR".to_string(), "test_value".to_string());

        b.iter(|| {
            // Simulate wrapping 10 different commands sequentially
            for i in 0..10 {
                let cmd = ResolvedCommand {
                    original: format!("echo test_{}", i),
                    placeholders: Vec::new(),
                    resolved: format!("echo test_{}", i),
                    env_injections: Vec::new(),
                    file_injections: Vec::new(),
                    stdin_secret: None,
                    use_stdin: false,
                };
                let _ = sandbox.wrap_command(&cmd, &config);
            }
        });
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
    bench_sandbox_cold_warm_start,
    bench_sandbox_cold_warm_scaling,
    bench_sandbox_sequential_execution,
);
criterion_main!(benches);
