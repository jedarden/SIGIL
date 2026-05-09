//! Parser operation benchmarks
//!
//! Measures performance of command parsing:
//! - Placeholder extraction at various command lengths
//! - Command resolution with injection modes
//! - Command validation

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use sigil_core::parser::CommandParser;

fn bench_extract_placeholders_simple(c: &mut Criterion) {
    let mut group = c.benchmark_group("parser_extract_simple");

    let commands = vec![
        ("no_placeholders", "echo hello world"),
        ("one_placeholder", "curl -H 'Authorization: Bearer {{secret:api/key}}' https://api.example.com"),
        ("two_placeholders", "curl -u {{secret:api/user}}:{{secret:api/pass}} https://api.example.com"),
        ("three_placeholders", "export DB_HOST={{secret:db/host}} DB_USER={{secret:db/user}} DB_PASS={{secret:db/pass}}"),
    ];

    for (name, command) in commands {
        group.bench_with_input(BenchmarkId::from_parameter(name), command, |b, cmd| {
            b.iter(|| CommandParser::extract_placeholders(black_box(cmd)));
        });
    }

    group.finish();
}

fn bench_extract_placeholders_by_length(c: &mut Criterion) {
    let mut group = c.benchmark_group("parser_extract_by_length");

    for command_length in [100, 500, 1000, 5000, 10000].iter() {
        group.throughput(Throughput::Bytes(*command_length as u64));

        group.bench_with_input(
            BenchmarkId::from_parameter(command_length),
            command_length,
            |b, len: &usize| {
                // Create a command of the specified length with placeholders
                let base_cmd = "curl -H 'Authorization: Bearer {{secret:api/key}}' https://api.example.com";
                let padding = " x".repeat(len.saturating_sub(base_cmd.len()) / 3);
                let command = format!("{}{}{}", base_cmd, padding, " echo done");

                b.iter(|| CommandParser::extract_placeholders(black_box(&command)));
            },
        );
    }

    group.finish();
}

fn bench_extract_placeholders_by_count(c: &mut Criterion) {
    let mut group = c.benchmark_group("parser_extract_by_count");

    for placeholder_count in [1, 5, 10, 20, 50].iter() {
        group.bench_with_input(
            BenchmarkId::from_parameter(placeholder_count),
            placeholder_count,
            |b, &count| {
                // Create a command with the specified number of placeholders
                let mut command_parts = Vec::new();
                for i in 0..count {
                    command_parts.push(format!("{{{{secret:api/key{}}}}}", i));
                }
                let command = format!("echo {}", command_parts.join(" "));

                b.iter(|| CommandParser::extract_placeholders(black_box(&command)));
            },
        );
    }

    group.finish();
}

fn bench_extract_with_injection_modes(c: &mut Criterion) {
    let mut group = c.benchmark_group("parser_extract_modes");

    let commands = vec![
        ("inline", "curl https://api.example.com/{{secret:api/path}}"),
        ("env", "API_KEY={{secret:api/key:env}} curl https://api.example.com"),
        ("file", "cat {{secret:api/key:file:/tmp/api_key}}"),
        ("stdin", "echo '{{secret:api/key:stdin}}' | openssl aes-256-cbc -d"),
        ("mixed", "export KEY={{secret:api/key:env}} && curl -H @{{secret:api/header:file:/tmp/h}} https://api.example.com/{{secret:api/path}}"),
    ];

    for (name, command) in commands {
        group.bench_with_input(BenchmarkId::from_parameter(name), command, |b, cmd| {
            b.iter(|| CommandParser::extract_placeholders(black_box(cmd)));
        });
    }

    group.finish();
}

fn bench_resolve_command(c: &mut Criterion) {
    let mut group = c.benchmark_group("parser_resolve");

    let commands = vec![
        ("simple", "echo hello"),
        ("with_placeholder", "echo {{secret:test/value}}"),
        ("multiple", "echo {{secret:a}} and {{secret:b}}"),
        ("with_env", "KEY={{secret:key:env}} echo test"),
        ("with_file", "cat {{secret:file:file:/tmp/out}}"),
    ];

    for (name, command) in commands {
        group.bench_with_input(BenchmarkId::from_parameter(name), command, |b, cmd| {
            b.iter(|| CommandParser::resolve_command(black_box(cmd)));
        });
    }

    group.finish();
}

fn bench_validate_command(c: &mut Criterion) {
    let mut group = c.benchmark_group("parser_validate");

    let commands = vec![
        ("valid_simple", "echo hello"),
        ("valid_with_placeholder", "echo {{secret:test/value}}"),
        ("invalid_nested", "echo {{secret:test/{{secret:nested}}}}"),
        ("invalid_mismatched", "echo {{secret:test/value"),
        ("invalid_empty", "echo {{secret:}}"),
    ];

    for (name, command) in commands {
        group.bench_with_input(BenchmarkId::from_parameter(name), command, |b, cmd| {
            b.iter(|| CommandParser::validate_command(black_box(cmd)));
        });
    }

    group.finish();
}

fn bench_parser_with_complex_commands(c: &mut Criterion) {
    let mut group = c.benchmark_group("parser_complex");

    // Realistic complex commands
    let complex_commands = vec![
        (
            "docker_compose",
            r#"docker-compose -f {{secret:config/file:file:/tmp/docker-compose.yml}} up -d --env-file {{secret:env/file:file:/tmp/.env}}"#,
        ),
        (
            "kubectl",
            r#"kubectl apply -f {{secret:k8s/config:file:/tmp/deployment.yaml}} --namespace={{secret:k8s/ns}}"#,
        ),
        (
            "aws_cli",
            r#"AWS_ACCESS_KEY_ID={{secret:aws/key:env}} AWS_SECRET_ACCESS_KEY={{secret:aws/secret:env}} aws s3 cp s3://{{secret:aws/bucket}}/file.txt /tmp/file.txt"#,
        ),
        (
            "gpg",
            r#"echo '{{secret:gpg/message:stdin}}' | gpg --passphrase '{{secret:gpg/passphrase}}' --decrypt --output {{secret:gpg/output:file:/tmp/decrypted}}"#,
        ),
        (
            "ssh",
            r#"ssh -i {{secret:ssh/key:file:/tmp/key}} {{secret:ssh/user}}@{{secret:ssh/host}} 'cat {{secret:remote/path}}'"#,
        ),
    ];

    for (name, command) in complex_commands {
        group.bench_with_input(BenchmarkId::from_parameter(name), command, |b, cmd| {
            b.iter(|| {
                let placeholders = CommandParser::extract_placeholders(black_box(cmd));
                let resolved = CommandParser::resolve_command(black_box(cmd));
                let validated = CommandParser::validate_command(black_box(cmd));
                (placeholders, resolved, validated)
            });
        });
    }

    group.finish();
}

/// Benchmark: Placeholder extraction at various command lengths
///
/// From the plan requirements:
/// "Parser: placeholder extraction at various command lengths"
///
/// This ensures the parser performs well across a range of realistic
/// command lengths, from short one-liners to complex multi-part commands.
fn bench_placeholder_extraction_by_length(c: &mut Criterion) {
    let mut group = c.benchmark_group("placeholder_extraction_length");

    for length in [50, 100, 250, 500, 1000, 2500, 5000].iter() {
        group.throughput(Throughput::Bytes(*length as u64));

        group.bench_with_input(BenchmarkId::from_parameter(length), length, |b, len: &usize| {
            // Create a command of approximately the target length
            let placeholder = "{{secret:test/api_key}}";
            let base = "curl -H 'Authorization: Bearer ";
            let suffix = "' https://api.example.com/endpoint";

            let padding_len = len.saturating_sub(base.len() + placeholder.len() + suffix.len());
            let padding = "X".repeat(padding_len);

            let command = format!("{}{}{}{}", base, padding, placeholder, suffix);

            b.iter(|| CommandParser::extract_placeholders(black_box(&command)));
        });
    }

    group.finish();
}

criterion_group!(
    benches,
    bench_extract_placeholders_simple,
    bench_extract_placeholders_by_length,
    bench_extract_placeholders_by_count,
    bench_extract_with_injection_modes,
    bench_resolve_command,
    bench_validate_command,
    bench_parser_with_complex_commands,
    bench_placeholder_extraction_by_length,
);
criterion_main!(benches);
