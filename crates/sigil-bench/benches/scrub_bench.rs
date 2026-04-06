//! Scrubber operation benchmarks
//!
//! Measures performance of secret scrubbing:
//! - Exact-match scrubbing
//! - Multiple encodings
//! - Aho-Corasick pattern matching
//! - Large output handling

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use rand::Rng;
use sigil_core::SecretPath;
use sigil_scrub::Scrubber;

/// Generate random secret value
fn generate_secret(size: usize) -> String {
    rand::thread_rng()
        .sample_iter(&rand::distributions::Alphanumeric)
        .take(size)
        .map(char::from)
        .collect()
}

/// Generate output with secrets embedded
fn generate_output_with_secrets(secrets: &[(String, String)], output_size: usize) -> String {
    let mut output = String::new();
    let secret_count = secrets.len();

    // Build output with secrets distributed throughout
    let chunk_size = output_size / (secret_count + 1);
    for (_path, secret) in secrets.iter() {
        // Add some padding text
        let padding = "x".repeat(chunk_size);
        output.push_str(&padding);

        // Add the secret
        output.push_str(&format!(" API_KEY={}", secret));
    }

    // Add final padding
    let remaining = output_size - output.len();
    output.push_str(&"x".repeat(remaining.max(0)));

    output
}

fn bench_scrub_single_secret(c: &mut Criterion) {
    let mut group = c.benchmark_group("scrub_single");

    for secret_size in [16, 32, 64, 128].iter() {
        let secret = generate_secret(*secret_size);

        group.throughput(Throughput::Bytes(secret.len() as u64));
        group.bench_with_input(
            BenchmarkId::from_parameter(secret_size),
            secret_size,
            |b, &_size| {
                let mut scrubber = Scrubber::new();
                scrubber.add_secret(SecretPath::new("api_key").unwrap(), secret.as_bytes());

                let output = format!("Authorization: Bearer {}", secret);

                b.iter(|| scrubber.scrub(black_box(&output)));
            },
        );
    }

    group.finish();
}

fn bench_scrub_multiple_secrets(c: &mut Criterion) {
    let mut group = c.benchmark_group("scrub_multiple");

    for secret_count in [1, 5, 10, 20, 50].iter() {
        group.bench_with_input(
            BenchmarkId::from_parameter(secret_count),
            secret_count,
            |b, &_count| {
                // Generate secrets
                let secrets: Vec<(String, String)> = (0..*secret_count)
                    .map(|i| {
                        let path = format!("secret/{}", i);
                        let value = generate_secret(32);
                        (path, value)
                    })
                    .collect();

                // Build scrubber
                let mut scrubber = Scrubber::new();
                for (path, secret) in &secrets {
                    scrubber.add_secret(SecretPath::new(path).unwrap(), secret.as_bytes());
                }

                // Generate output with all secrets
                let output = generate_output_with_secrets(&secrets, 10000);

                b.iter(|| scrubber.scrub(black_box(&output)));
            },
        );
    }

    group.finish();
}

fn bench_scrub_large_output(c: &mut Criterion) {
    let mut group = c.benchmark_group("scrub_large_output");

    for output_size in [1024, 10_240, 102_400, 1_048_576].iter() {
        group.throughput(Throughput::Bytes(*output_size as u64));
        group.bench_with_input(
            BenchmarkId::from_parameter(output_size),
            output_size,
            |b, &_size| {
                // Create a few secrets
                let secrets = vec![
                    ("key1".to_string(), generate_secret(32)),
                    ("key2".to_string(), generate_secret(32)),
                    ("key3".to_string(), generate_secret(32)),
                ];

                // Build scrubber
                let mut scrubber = Scrubber::new();
                for (path, secret) in &secrets {
                    scrubber.add_secret(SecretPath::new(path).unwrap(), secret.as_bytes());
                }

                // Generate large output
                let output = generate_output_with_secrets(&secrets, *output_size);

                b.iter(|| scrubber.scrub(black_box(&output)));
            },
        );
    }

    group.finish();
}

fn bench_scrub_no_secrets(c: &mut Criterion) {
    let mut group = c.benchmark_group("scrub_clean");

    for output_size in [1024, 10_240, 102_400].iter() {
        group.throughput(Throughput::Bytes(*output_size as u64));
        group.bench_with_input(
            BenchmarkId::from_parameter(output_size),
            output_size,
            |b, &_size| {
                // Create scrubber with patterns but no secrets in output
                let mut scrubber = Scrubber::new();
                scrubber.add_secret(SecretPath::new("key1").unwrap(), b"secret-value-123");

                // Generate clean output
                let output = "x".repeat(*output_size);

                b.iter(|| scrubber.scrub(black_box(&output)));
            },
        );
    }

    group.finish();
}

fn bench_scrubber_build(c: &mut Criterion) {
    let mut group = c.benchmark_group("scrubber_build");

    for pattern_count in [10, 50, 100, 500, 1000].iter() {
        group.bench_with_input(
            BenchmarkId::from_parameter(pattern_count),
            pattern_count,
            |b, &_count| {
                let secrets: Vec<(String, String)> = (0..*pattern_count)
                    .map(|i| {
                        let path = format!("secret/{}", i);
                        let value = generate_secret(32);
                        (path, value)
                    })
                    .collect();

                b.iter(|| {
                    let mut scrubber = Scrubber::new();
                    for (path, secret) in &secrets {
                        scrubber.add_secret(
                            SecretPath::new(black_box(path)).unwrap(),
                            black_box(secret.as_bytes()),
                        );
                    }
                    scrubber
                });
            },
        );
    }

    group.finish();
}

criterion_group!(
    benches,
    bench_scrub_single_secret,
    bench_scrub_multiple_secrets,
    bench_scrub_large_output,
    bench_scrub_no_secrets,
    bench_scrubber_build
);
criterion_main!(benches);
