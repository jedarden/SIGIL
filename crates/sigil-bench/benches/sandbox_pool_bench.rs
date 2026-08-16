//! Sandbox pool benchmarks
//!
//! Measures the performance improvement from using pre-warmed sandbox pools:
//! - Cold start vs. warm pool comparison
//! - Pool overhead and scaling
//! - Sequential execution performance
//! - Target: warm pool p50 close to ~2-3ms (vs. ~15-30ms cold start)

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use sigil_core::ResolvedCommand;
use sigil_sandbox::{BubblewrapSandbox, PoolConfig, SandboxConfig, SandboxPool, SandboxProvider};

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
        header_injections: Vec::new(),
    }
}

/// Test command with environment injection (simulating secret injection)
fn test_command_with_env() -> ResolvedCommand {
    ResolvedCommand {
        original: "echo $TEST_VAR".to_string(),
        placeholders: Vec::new(),
        resolved: "echo $TEST_VAR".to_string(),
        env_injections: vec![("TEST_VAR".to_string(), "test_value".to_string())],
        file_injections: Vec::new(),
        stdin_secret: None,
        use_stdin: false,
        header_injections: Vec::new(),
    }
}

/// Test command with multiple injections (typical secret usage scenario)
fn test_command_with_multiple_injections() -> ResolvedCommand {
    ResolvedCommand {
        original: "curl -H \"Authorization: Bearer $TOKEN\" $API_URL".to_string(),
        placeholders: Vec::new(),
        resolved: "curl -H \"Authorization: Bearer $TOKEN\" $API_URL".to_string(),
        env_injections: vec![
            ("TOKEN".to_string(), "sk_live_test_key".to_string()),
            ("API_URL".to_string(), "https://api.example.com".to_string()),
        ],
        file_injections: vec![("config.json".to_string(), "/tmp/config.json".to_string())],
        stdin_secret: None,
        use_stdin: false,
        header_injections: Vec::new(),
    }
}

/// Benchmark: Cold start vs. Warm pool performance
///
/// This is the primary benchmark showing the performance improvement
/// from using pre-warmed sandbox pools.
///
/// **Target**: Warm pool execution should be ~2-3ms vs. ~15-30ms cold start
fn bench_pool_cold_vs_warm(c: &mut Criterion) {
    let mut group = c.benchmark_group("pool_cold_vs_warm");

    let config = SandboxConfig::default();

    // Cold start: No pool, create new sandbox each time
    group.bench_function("cold_start_no_pool", |b| {
        let provider = BubblewrapSandbox::new().unwrap();
        let cmd = test_command_with_env();
        b.iter(|| {
            let result = provider.wrap_command(&cmd, &config);
            black_box(result)
        });
    });

    // Warm pool: Reuse pre-warmed sandboxes
    group.bench_function("warm_pool_reuse", |b| {
        let provider = BubblewrapSandbox::new().unwrap();
        let mut pool = SandboxPool::with_default_config(provider);
        let cmd = test_command_with_env();

        // Pre-warm the pool by executing once
        let _ = pool.execute_pooled(&cmd, &config);

        b.iter(|| {
            let result = pool.execute_pooled(&cmd, &config);
            black_box(result)
        });
    });

    // Baseline: Direct execution without any wrapping
    group.bench_function("baseline_no_sandbox", |b| {
        let cmd = test_command_with_env();
        b.iter(|| {
            let mut std_cmd = std::process::Command::new("echo");
            std_cmd.arg(&cmd.resolved);
            black_box(std_cmd)
        });
    });

    group.finish();
}

/// Benchmark: Pool scaling with different pool sizes
///
/// Measures how pool size affects performance and hit rate.
fn bench_pool_scaling(c: &mut Criterion) {
    for pool_size in [1, 2, 4, 8, 16].iter() {
        let mut group = c.benchmark_group(format!("pool_size_{}", pool_size));

        group.bench_function("wrap_command_with_pool", |b| {
            let provider = BubblewrapSandbox::new().unwrap();
            let config = PoolConfig::with_pool_size(*pool_size);
            let mut pool = SandboxPool::new(provider, config);
            let sandbox_config = SandboxConfig::default();
            let cmd = test_command_with_env();

            // Pre-warm the pool
            for _ in 0..*pool_size {
                let _ = pool.execute_pooled(&cmd, &sandbox_config);
            }

            b.iter(|| {
                let result = pool.execute_pooled(&cmd, &sandbox_config);
                black_box(result)
            });
        });

        group.finish();
    }
}

/// Benchmark: Pool performance under load
///
/// Simulates concurrent access to the pool with multiple commands.
fn bench_pool_under_load(c: &mut Criterion) {
    let mut group = c.benchmark_group("pool_under_load");

    for concurrent_ops in [1, 2, 4, 8, 16].iter() {
        group.throughput(Throughput::Elements(*concurrent_ops as u64));

        group.bench_with_input(
            BenchmarkId::new("concurrent_operations", concurrent_ops),
            concurrent_ops,
            |b, &count| {
                let provider = BubblewrapSandbox::new().unwrap();
                let config = PoolConfig::with_pool_size(4);
                let mut pool = SandboxPool::new(provider, config);
                let sandbox_config = SandboxConfig::default();
                let cmd = test_command();

                // Pre-warm the pool
                for _ in 0..4 {
                    let _ = pool.execute_pooled(&cmd, &sandbox_config);
                }

                b.iter(|| {
                    // Simulate concurrent operations
                    for _ in 0..count {
                        let result = pool.execute_pooled(&cmd, &sandbox_config);
                        black_box(result);
                    }
                });
            },
        );
    }

    group.finish();
}

/// Benchmark: Sequential command execution with pool
///
/// Simulates the typical use case of running multiple commands in sequence,
/// which is common in agent sessions.
fn bench_pool_sequential_execution(c: &mut Criterion) {
    let mut group = c.benchmark_group("pool_sequential");

    for command_count in [1, 5, 10, 20, 50].iter() {
        group.bench_with_input(
            BenchmarkId::new("sequential_commands", command_count),
            command_count,
            |b, &count| {
                let provider = BubblewrapSandbox::new().unwrap();
                let config = PoolConfig::with_pool_size(4);
                let mut pool = SandboxPool::new(provider, config);
                let sandbox_config = SandboxConfig::default();

                b.iter(|| {
                    for i in 0..count {
                        let cmd = ResolvedCommand {
                            original: format!("echo test_{}", i),
                            placeholders: Vec::new(),
                            resolved: format!("echo test_{}", i),
                            env_injections: Vec::new(),
                            file_injections: Vec::new(),
                            stdin_secret: None,
                            use_stdin: false,
                            header_injections: Vec::new(),
                        };
                        let _ = pool.execute_pooled(&cmd, &sandbox_config);
                    }
                });
            },
        );
    }

    group.finish();
}

/// Benchmark: Pool hit rate and efficiency
///
/// Measures how well the pool is being utilized under different patterns.
fn bench_pool_efficiency(c: &mut Criterion) {
    let mut group = c.benchmark_group("pool_efficiency");

    // Perfect hit rate: Always reuse from pool
    group.bench_function("perfect_hit_rate", |b| {
        let provider = BubblewrapSandbox::new().unwrap();
        let config = PoolConfig::with_pool_size(4);
        let mut pool = SandboxPool::new(provider, config);
        let sandbox_config = SandboxConfig::default();
        let cmd = test_command();

        // Pre-warm pool
        for _ in 0..4 {
            let _ = pool.execute_pooled(&cmd, &sandbox_config);
        }

        b.iter(|| {
            let _ = pool.execute_pooled(&cmd, &sandbox_config);
            // Hit rate should be close to 100%
            assert!(pool.hit_rate() > 0.9, "Pool hit rate should be > 90%");
        });
    });

    // Mixed workload: Different configurations
    group.bench_function("mixed_workload", |b| {
        let provider = BubblewrapSandbox::new().unwrap();
        let config = PoolConfig::with_pool_size(4);
        let mut pool = SandboxPool::new(provider, config);

        b.iter(|| {
            // Alternate between different command types
            let simple_cmd = test_command();
            let env_cmd = test_command_with_env();
            let multi_cmd = test_command_with_multiple_injections();

            let configs = vec![
                SandboxConfig::default(),
                SandboxConfig::default().with_env("VAR".to_string(), "value".to_string()),
            ];

            for (i, cmd) in [simple_cmd, env_cmd, multi_cmd].iter().enumerate() {
                let config = &configs[i % configs.len()];
                let _ = pool.execute_pooled(cmd, config);
            }

            // Hit rate should still be reasonable even with mixed workload
        });
    });

    group.finish();
}

/// Benchmark: Pool overhead measurement
///
/// Isolates and measures the overhead introduced by the pool itself
/// (acquisition, statistics tracking, etc.).
fn bench_pool_overhead(c: &mut Criterion) {
    let mut group = c.benchmark_group("pool_overhead");

    // Measure just the acquisition overhead
    group.bench_function("pool_acquire_only", |b| {
        let provider = BubblewrapSandbox::new().unwrap();
        let _config = PoolConfig::default();
        let pool = SandboxPool::with_default_config(provider);

        b.iter(|| {
            let _ = pool.config();
            let _ = pool.stats();
            let _ = pool.is_enabled();
        });
    });

    // Measure statistics tracking overhead
    group.bench_function("pool_stats_tracking", |b| {
        let provider = BubblewrapSandbox::new().unwrap();
        let mut pool = SandboxPool::with_default_config(provider);
        let sandbox_config = SandboxConfig::default();
        let cmd = test_command();

        b.iter(|| {
            let _ = pool.execute_pooled(&cmd, &sandbox_config);
            let _ = pool.hit_rate();
            let _ = pool.stats();
        });
    });

    group.finish();
}

/// Benchmark: Comparison table for different injection complexities
///
/// Creates a comprehensive comparison showing how the pool performs
/// across different levels of command complexity.
fn bench_pool_complexity_comparison(c: &mut Criterion) {
    let complexities = [
        ("simple", test_command as fn() -> ResolvedCommand),
        ("with_env", test_command_with_env as fn() -> ResolvedCommand),
        (
            "multi_injection",
            test_command_with_multiple_injections as fn() -> ResolvedCommand,
        ),
    ];

    for (name, cmd_fn) in complexities.iter() {
        let mut group = c.benchmark_group(format!("complexity_{}", name));

        // Without pool
        group.bench_function("no_pool", |b| {
            let provider = BubblewrapSandbox::new().unwrap();
            let config = SandboxConfig::default();
            let cmd = cmd_fn();

            b.iter(|| {
                let result = provider.wrap_command(&cmd, &config);
                black_box(result)
            });
        });

        // With pool
        group.bench_function("with_pool", |b| {
            let provider = BubblewrapSandbox::new().unwrap();
            let mut pool = SandboxPool::with_default_config(provider);
            let config = SandboxConfig::default();
            let cmd = cmd_fn();

            // Pre-warm
            let _ = pool.execute_pooled(&cmd, &config);

            b.iter(|| {
                let result = pool.execute_pooled(&cmd, &config);
                black_box(result)
            });
        });

        group.finish();
    }
}

/// Benchmark: Pool size impact on hit rate
///
/// Shows how pool size affects the pool efficiency.
fn bench_pool_size_impact(c: &mut Criterion) {
    let mut group = c.benchmark_group("pool_size_impact");

    for pool_size in [2, 4, 8, 16].iter() {
        group.bench_with_input(
            BenchmarkId::new("hit_rate", pool_size),
            pool_size,
            |b, &size| {
                let provider = BubblewrapSandbox::new().unwrap();
                let config = PoolConfig::with_pool_size(size);
                let mut pool = SandboxPool::new(provider, config);
                let sandbox_config = SandboxConfig::default();
                let cmd = test_command();

                // Execute a sequence of commands
                for _ in 0..20 {
                    let _ = pool.execute_pooled(&cmd, &sandbox_config);
                }

                // Measure hit rate
                b.iter(|| pool.hit_rate());
            },
        );
    }

    group.finish();
}

criterion_group!(
    benches,
    bench_pool_cold_vs_warm,
    bench_pool_scaling,
    bench_pool_under_load,
    bench_pool_sequential_execution,
    bench_pool_efficiency,
    bench_pool_overhead,
    bench_pool_complexity_comparison,
    bench_pool_size_impact
);
criterion_main!(benches);
