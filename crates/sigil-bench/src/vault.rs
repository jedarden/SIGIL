//! Additional vault operation benchmarks
//!
//! Extended benchmarks for vault operations with larger workloads

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};
use sigil_core::{SecretBackend, SecretMetadata, SecretPath, SecretType, SecretValue};
use sigil_vault::LocalVault;
use tempfile::TempDir;

/// Create a test vault with N secrets
fn create_vault_with_secrets(count: usize, secret_size: usize) -> (TempDir, LocalVault) {
    let temp_dir = TempDir::new().unwrap();
    let vault_path = temp_dir.path().join("vault");
    let identity_path = temp_dir.path().join("identity.age");

    let mut vault = LocalVault::new(vault_path, identity_path).unwrap();
    vault.init(Some("test-passphrase")).unwrap();

    let rt = tokio::runtime::Runtime::new().unwrap();

    // Add secrets
    for i in 0..count {
        let path = SecretPath::new(format!("secret/{}", i)).unwrap();
        let value = SecretValue::new(vec![b'x'; secret_size]);

        let mut meta = SecretMetadata::new(path.clone());
        meta.secret_type = SecretType::ApiKey;

        rt.block_on(vault.set(&path, &value, &meta)).unwrap();
    }

    (temp_dir, vault)
}

fn bench_vault_batch_operations(c: &mut Criterion) {
    let mut group = c.benchmark_group("vault_batch_operations");

    // Benchmark bulk secret retrieval
    for secret_count in [50, 100, 500].iter() {
        let (_temp_dir, vault) = create_vault_with_secrets(*secret_count, 64);
        let rt = tokio::runtime::Runtime::new().unwrap();

        group.bench_with_input(
            BenchmarkId::new("get_batch", secret_count),
            secret_count,
            |b, _| {
                b.iter(|| {
                    for i in 0..*secret_count {
                        let path = SecretPath::new(format!("secret/{}", i)).unwrap();
                        black_box(rt.block_on(vault.get(&path)));
                    }
                })
            },
        );
    }

    group.finish();
}

fn bench_vault_large_secrets(c: &mut Criterion) {
    let mut group = c.benchmark_group("vault_large_secrets");

    // Test with larger secret sizes
    for secret_size in [8192, 16384, 32768].iter() {
        let (_temp_dir, vault) = create_vault_with_secrets(10, *secret_size);
        let rt = tokio::runtime::Runtime::new().unwrap();

        let path = SecretPath::new("secret/large").unwrap();

        group.bench_with_input(
            BenchmarkId::from_parameter(secret_size),
            secret_size,
            |b, _| {
                b.iter(|| black_box(rt.block_on(vault.get(black_box(&path)))))
            },
        );
    }

    group.finish();
}

fn bench_vault_list_performance(c: &mut Criterion) {
    let mut group = c.benchmark_group("vault_list_performance");

    // Test listing with different vault sizes
    for secret_count in [100, 500, 1000].iter() {
        let (_temp_dir, vault) = create_vault_with_secrets(*secret_count, 32);
        let rt = tokio::runtime::Runtime::new().unwrap();

        group.bench_with_input(
            BenchmarkId::from_parameter(secret_count),
            secret_count,
            |b, _| {
                b.iter(|| black_box(rt.block_on(vault.list(black_box("")))))
            },
        );
    }

    group.finish();
}

fn bench_vault_concurrent_access(c: &mut Criterion) {
    let mut group = c.benchmark_group("vault_concurrent_access");

    // Simulate concurrent access patterns
    for secret_count in [50, 100].iter() {
        group.bench_with_input(
            BenchmarkId::new("concurrent_reads", secret_count),
            secret_count,
            |b, _| {
                b.iter(|| {
                    let (_temp_dir, vault) = create_vault_with_secrets(*secret_count, 64);
                    let rt = tokio::runtime::Runtime::new().unwrap();

                    // Perform sequential reads (LocalVault is not thread-safe for concurrent writes)
                    for i in 0..100 {
                        let path = SecretPath::new(format!("secret/{}", i % secret_count)).unwrap();
                        black_box(rt.block_on(vault.get(&path)));
                    }
                })
            },
        );
    }

    group.finish();
}

criterion_group!(
    benches,
    bench_vault_batch_operations,
    bench_vault_large_secrets,
    bench_vault_list_performance,
    bench_vault_concurrent_access
);
criterion_main!(benches);
