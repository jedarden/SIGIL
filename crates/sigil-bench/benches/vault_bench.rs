//! Vault operation benchmarks
//!
//! Measures performance of critical vault operations:
//! - Secret addition (set) and retrieval (get)
//! - Secret listing
//! - Secret deletion

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use sigil_core::{SecretBackend, SecretMetadata, SecretPath, SecretValue};
use sigil_vault::LocalVault;
use std::fs;
use tempfile::TempDir;

/// Create a test vault
fn create_test_vault() -> (TempDir, LocalVault) {
    let temp_dir = TempDir::new().unwrap();
    let vault_path = temp_dir.path().join("vault");
    let identity_path = temp_dir.path().join("identity.age");

    fs::create_dir(&vault_path).unwrap();

    // Create a simple identity file (in real usage, this would be encrypted)
    fs::write(
        &identity_path,
        "AGE-SECRET-KEY-1TEST-KEY-FOR-BENCHMARKING-PURPOSES-ONLY",
    )
    .unwrap();

    let mut vault = LocalVault::new(vault_path, identity_path).unwrap();

    // Load the vault (synchronous, not async)
    vault.load(None).unwrap();

    (temp_dir, vault)
}

fn bench_set_secret(c: &mut Criterion) {
    let mut group = c.benchmark_group("vault_set");

    for size in [16, 64, 256, 1024, 4096].iter() {
        let value = SecretValue::new(vec![b'x'; *size]);

        group.throughput(Throughput::Bytes(*size as u64));
        group.bench_with_input(BenchmarkId::from_parameter(size), size, |b, &_size| {
            let (temp_dir, vault) = create_test_vault();
            let rt = tokio::runtime::Runtime::new().unwrap();

            b.iter(|| {
                let path = SecretPath::new(format!("secret/{}", rand::random::<u64>())).unwrap();
                let meta = SecretMetadata::new(path.clone());
                rt.block_on(vault.set(black_box(&path), black_box(&value), black_box(&meta)))
            });

            drop(temp_dir);
        });
    }

    group.finish();
}

fn bench_get_secret(c: &mut Criterion) {
    let mut group = c.benchmark_group("vault_get");

    // Setup vault with a secret
    let (temp_dir, vault) = create_test_vault();
    let rt = tokio::runtime::Runtime::new().unwrap();

    // Add a test secret
    let path = SecretPath::new("secret/test/50").unwrap();
    let value = SecretValue::new(b"test-value-50".to_vec());
    let meta = SecretMetadata::new(path.clone());
    rt.block_on(vault.set(&path, &value, &meta)).unwrap();

    group.bench_function("get_existing", |b| {
        b.iter(|| rt.block_on(vault.get(black_box(&path))));
    });

    let missing_path = SecretPath::new("secret/missing").unwrap();
    group.bench_function("get_missing", |b| {
        b.iter(|| rt.block_on(vault.get(black_box(&missing_path))));
    });

    drop(temp_dir);
    group.finish();
}

fn bench_list_secrets(c: &mut Criterion) {
    let mut group = c.benchmark_group("vault_list");

    for count in [10, 50, 100].iter() {
        group.bench_with_input(BenchmarkId::from_parameter(count), count, |b, &_count| {
            let (temp_dir, vault) = create_test_vault();
            let rt = tokio::runtime::Runtime::new().unwrap();

            // Add secrets
            for i in 0..*count {
                let path = SecretPath::new(format!("secret/path/{}", i)).unwrap();
                let value = SecretValue::new(format!("value-{}", i).into_bytes());
                let meta = SecretMetadata::new(path.clone());
                rt.block_on(vault.set(&path, &value, &meta)).unwrap();
            }

            b.iter(|| rt.block_on(vault.list(black_box(""))));

            drop(temp_dir);
        });
    }

    group.finish();
}

fn bench_delete_secret(c: &mut Criterion) {
    let mut group = c.benchmark_group("vault_delete");

    let (temp_dir, vault) = create_test_vault();
    let rt = tokio::runtime::Runtime::new().unwrap();

    group.bench_function("delete_existing", |b| {
        // Add a secret to delete in each iteration
        b.iter(|| {
            let path =
                SecretPath::new(format!("secret/to_delete/{}", rand::random::<u64>())).unwrap();
            let value = SecretValue::new(b"test-value".to_vec());
            let meta = SecretMetadata::new(path.clone());
            rt.block_on(vault.set(&path, &value, &meta)).unwrap();
            rt.block_on(vault.delete(black_box(&path)))
        });
    });

    drop(temp_dir);
    group.finish();
}

criterion_group!(
    benches,
    bench_set_secret,
    bench_get_secret,
    bench_list_secrets,
    bench_delete_secret,
);
criterion_main!(benches);
