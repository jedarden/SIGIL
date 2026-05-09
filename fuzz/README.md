# SIGIL Fuzz Testing

This directory contains fuzz targets for testing SIGIL's core components using `cargo-fuzz` and libFuzzer.

## Prerequisites

Install cargo-fuzz:
```bash
cargo install cargo-fuzz
```

## Fuzz Targets

### command_parser
Fuzzes the command parser with adversarial inputs including:
- Nested quotes (single, double, mixed)
- Null bytes and escape sequences
- Command substitution
- Heredocs
- Special characters and unicode

**Run:**
```bash
cargo fuzz run command_parser -- -max_total_time=60
```

### output_scrubber
Fuzzes the output scrubber with:
- Cross-chunk boundary patterns
- Multiple encoding variants
- Adversarial output trying to bypass scrubbing
- Binary data and null bytes

**Run:**
```bash
cargo fuzz run output_scrubber -- -max_total_time=60
```

### archive_format
Fuzzes vault operations and archive parsing:
- SecretPath validation (directory traversal attempts)
- SecretValue creation
- Metadata parsing
- Base64/hex decoding
- Age key parsing

**Run:**
```bash
cargo fuzz run archive_format -- -max_total_time=60
```

### ipc_protocol
Fuzzes the IPC protocol:
- Malformed JSON messages
- Oversized messages (DoS attempts)
- Invalid request IDs
- Invalid session tokens
- Unknown operations

**Run:**
```bash
cargo fuzz run ipc_protocol -- -max_total_time=60
```

## Running All Fuzzers

Run each target for 60 seconds:
```bash
for target in command_parser output_scrubber archive_format ipc_protocol; do
    echo "Fuzzing $target..."
    cargo fuzz run $target -- -max_total_time=60 || true
done
```

## Corpus and Artifacts

The fuzzer will generate:
- `fuzz/corpus/<target>/` - Interesting inputs found during fuzzing
- `fuzz/artifacts/<target>/` - Crash inputs (if any)

## Continuous Fuzzing

For longer runs (e.g., overnight):
```bash
cargo fuzz run command_parser -- -max_total_time=3600
```

## CI Integration

These fuzz targets should be run periodically (e.g., weekly) as part of the security testing pipeline.
