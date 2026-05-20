# Fuzzing Corpus

This directory contains fuzzing corpus for the SIGIL project using `cargo-fuzz`.

## Corpus Structure

```
fuzz/
├── corpus/                    # Generated corpus (DO NOT COMMIT)
│   ├── command_parser/        # Auto-generated from fuzzing runs
│   ├── output_scrubber/       # Auto-generated from fuzzing runs
│   ├── archive_format/        # Auto-generated from fuzzing runs
│   └── ipc_protocol/          # Auto-generated from fuzzing runs
├── corpus_seed/               # Seed corpus (COMMITTED)
│   ├── command_parser_seed/   # Initial inputs for parser fuzzing
│   ├── output_scrubber_seed/  # Initial inputs for scrubber fuzzing
│   ├── archive_format_seed/   # Initial inputs for archive fuzzing
│   └── ipc_protocol_seed/     # Initial inputs for IPC fuzzing
└── artifacts/                 # Crash/timeout inputs (DO NOT COMMIT)
```

## Seed Corpus Files

### command_parser_seed/
- `basic_echo` - Simple echo command
- `placeholder_basic` - Basic `{{secret:path}}` placeholder
- `placeholder_nested_quotes` - Placeholder with quotes
- `multiple_placeholders` - Multiple placeholders in one command
- `pipe_chain` - Piped commands
- `malformed_utf8` - Invalid UTF-8 sequences

### output_scrubber_seed/
- `empty_input` - Empty string (known timeout case)
- `basic_secret` - Simple secret value
- `multiline_secret` - Multi-line output with secrets
- `base64_encoded` - Base64-encoded secret

### archive_format_seed/
- `empty` - Empty input
- `valid_archive_minimal` - Valid SIGIL archive header
- `single_byte_ff` - Single 0xff byte (known timeout case)

### ipc_protocol_seed/
- `empty_request` - Minimal ping request
- `resolve_request` - Secret resolution request
- `exec_request` - Command execution request
- `scrub_request` - Output scrubbing request
- `ok_response` - Success response
- `error_response` - Error response

## Fuzzing Targets

| Target | Purpose | Entry Points |
|--------|---------|--------------|
| `command_parser` | Command parser logic | `CommandParser::extract_placeholders`, `resolve_command`, `validate_command` |
| `output_scrubber` | Output scrubbing logic | `Scrubber::scrub`, `StreamingScrubber::scrub_chunk` |
| `archive_format` | Archive format handling | `create_archive`, `extract_archive` |
| `ipc_protocol` | IPC protocol parsing | `IpcRequest`, `IpcResponse`, and all IPC types |

## Running Fuzzers

```bash
# Run fuzzer for 60 seconds
cargo +nightly fuzz run command_parser -- -max_total_time=60

# Run with seed corpus
cargo +nightly fuzz run command_parser -- -max_total_time=60 corpus_seed/command_parser_seed

# Minimize corpus
cargo +nightly fuzz cmin command_parser

# Reproduce crash
cargo +nightly fuzz run output_scrubber fuzz/artifacts/output_scrubber/crash-xxx
```

## Known Issues

### Output Scrubber Timeout
- **Input**: Empty string
- **Issue**: Scrubber hangs on empty input
- **Status**: High priority fix needed

### Archive Format Timeout
- **Input**: Single byte `0xff`
- **Issue**: Archive extraction hangs
- **Status**: High priority fix needed

### Command Parser Crashes
- **Input**: Malformed UTF-8 with placeholder patterns
- **Issue**: Assertion failures in regex matching
- **Status**: Medium priority fix needed

## Corpus Management

The `corpus/` directories contain auto-generated inputs from fuzzing runs. These are **not committed** to git.

The `corpus_seed/` directories contain minimal, hand-crafted inputs that serve as starting points for fuzzing. These **are committed** to git.

To update the seed corpus from generated findings:

```bash
# Copy interesting inputs from corpus to corpus_seed
cp fuzz/corpus/command_parser/crash-xxx fuzz/corpus_seed/command_parser_seed/

# Add to git
git add fuzz/corpus_seed/
git commit -m "fuzz: add seed corpus inputs"
```
