//! Cryptographic operation benchmarks
//!
//! Measures performance of crypto operations:
//! - Key derivation (Argon2id)
//! - Hashing (SHA-256)
//! - HMAC
//! - Secret zeroization

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use rand::Rng;

/// Generate random data
fn random_data(size: usize) -> Vec<u8> {
    rand::thread_rng()
        .sample_iter(&rand::distributions::Standard)
        .take(size)
        .collect()
}

fn bench_argon2id_key_derivation(c: &mut Criterion) {
    let mut group = c.benchmark_group("argon2id");
    group.measurement_time(std::time::Duration::from_secs(10));

    // Test different Argon2id parameters
    let params = [
        (19456, 2, 1),   // Fast (interactive)
        (65536, 3, 4),   // Medium
        (1048576, 3, 4), // Strong (recommended)
    ];

    for (m_cost, t_cost, p_cost) in params {
        group.bench_with_input(
            BenchmarkId::new("params", format!("{}_{}_{}", m_cost, t_cost, p_cost)),
            &(m_cost, t_cost, p_cost),
            |b, &(m_cost, t_cost, p_cost)| {
                let password = b"test-password-12345";
                let salt = random_data(32);

                b.iter(|| {
                    argon2::Argon2::new(
                        argon2::Algorithm::Argon2id,
                        argon2::Version::V0x13,
                        argon2::Params::new(m_cost, t_cost, p_cost, None).unwrap(),
                    )
                    .hash_password_into(
                        black_box(password),
                        black_box(&salt),
                        &mut [0u8; 32],
                    )
                });
            },
        );
    }

    group.finish();
}

fn bench_sha256_hashing(c: &mut Criterion) {
    let mut group = c.benchmark_group("sha256");

    for data_size in [32, 256, 1024, 8192, 65536].iter() {
        group.throughput(Throughput::Bytes(*data_size as u64));
        group.bench_with_input(
            BenchmarkId::from_parameter(data_size),
            data_size,
            |b, &_size| {
                let data = random_data(*data_size);
                let mut output = [0u8; 32];

                b.iter(|| {
                    use sha2::Digest;
                    let mut hasher = sha2::Sha256::new();
                    hasher.update(black_box(&data));
                    output.copy_from_slice(&hasher.finalize());
                });
            },
        );
    }

    group.finish();
}

fn bench_hmac_sha256(c: &mut Criterion) {
    let mut group = c.benchmark_group("hmac_sha256");

    for data_size in [32, 256, 1024, 8192].iter() {
        group.throughput(Throughput::Bytes(*data_size as u64));
        group.bench_with_input(
            BenchmarkId::from_parameter(data_size),
            data_size,
            |b, &_size| {
                let data = random_data(*data_size);
                let key = random_data(32);

                b.iter(|| {
                    use hmac::Mac;
                    let mut mac = hmac::Hmac::<sha2::Sha256>::new_from_slice(&key).unwrap();
                    mac.update(black_box(&data));
                    mac.finalize()
                });
            },
        );
    }

    group.finish();
}

fn bench_zeroize(c: &mut Criterion) {
    let mut group = c.benchmark_group("zeroize");

    for data_size in [32, 256, 1024, 8192, 65536].iter() {
        group.throughput(Throughput::Bytes(*data_size as u64));
        group.bench_with_input(
            BenchmarkId::from_parameter(data_size),
            data_size,
            |b, &_size| {
                b.iter(|| {
                    use zeroize::Zeroize;
                    let mut data = black_box(random_data(*data_size));
                    data.zeroize();
                    data
                });
            },
        );
    }

    group.finish();
}

criterion_group!(
    benches,
    bench_argon2id_key_derivation,
    bench_sha256_hashing,
    bench_hmac_sha256,
    bench_zeroize,
);
criterion_main!(benches);
