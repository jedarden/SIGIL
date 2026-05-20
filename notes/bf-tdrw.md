# cargo-fuzz Setup and Corpus Documentation

## Summary

Set up cargo-fuzz for SIGIL with four targets (parser, scrubber, archive, IPC). Ran each fuzzer for 60 seconds and documented corpus state.

## Fuzz Targets

### 1. command_parser
- **Purpose**: Fuzz command parsing logic
- **Entry Points**: `CommandParser::extract_placeholders`, `resolve_command`, `validate_command`
- **Duration**: 60 seconds
- **Executions**: ~69,000 runs
- **Coverage**: 2791 edges, 6455 features
- **Corpus Size**: 4088 files
- **Artifacts**: 3 crashes (malformed UTF-8 with placeholder patterns)

### 2. output_scrubber
- **Purpose**: Fuzz output scrubbing logic
- **Entry Points**: `Scrubber::scrub`, `StreamingScrubber::scrub_chunk`
- **Duration**: 60 seconds
- **Executions**: ~14,000 runs
- **Coverage**: 1746 edges, 3952 features
- **Corpus Size**: 2 files
- **Artifacts**: 2 timeouts (empty input, newline-only input)

### 3. archive_format
- **Purpose**: Fuzz SIGIL archive format handling
- **Entry Points**: `create_archive`, `extract_archive`
- **Duration**: 60 seconds
- **Executions**: ~2,800 runs
- **Coverage**: 1052 edges, 2584 features
- **Corpus Size**: 381 files
- **Artifacts**: 2 timeouts (0xff byte sequences, malformed headers)

### 4. ipc_protocol
- **Purpose**: Fuzz IPC protocol parsing
- **Entry Points**: `IpcRequest`, `IpcResponse`, and all IPC types
- **Duration**: 60 seconds
- **Executions**: ~189,000 runs
- **Coverage**: 3909 edges, 12161 features
- **Corpus Size**: 8574 files
- **Artifacts**: None

## Corpus Structure

```
fuzz/
├── corpus/                    # Generated corpus (DO NOT COMMIT)
│   ├── command_parser/        # 4088 files
│   ├── output_scrubber/       # 2 files
│   ├── archive_format/        # 381 files
│   └── ipc_protocol/          # 8574 files
├── corpus_seed/               # Seed corpus (COMMITTED)
│   ├── command_parser_seed/   # 6 files
│   ├── output_scrubber_seed/  # 4 files
│   ├── archive_format_seed/   # 3 files
│   └── ipc_protocol_seed/     # 6 files
└── artifacts/                 # Crash/timeout inputs (DO NOT COMMIT)
    ├── command_parser/        # 3 crashes
    ├── output_scrubber/       # 2 timeouts
    ├── archive_format/        # 2 timeouts
    └── ipc_protocol/          # (empty)
```

## Known Issues

### Command Parser Crashes
- **Input**: Malformed UTF-8 with placeholder patterns
- **Issue**: Assertion failures in regex matching
- **Status**: Medium priority fix needed

### Output Scrubber Timeouts
- **Input**: Empty string, newline-only
- **Issue**: Scrubber hangs on empty/minimal input
- **Status**: High priority fix needed

### Archive Format Timeouts
- **Input**: Single byte `0xff`, malformed headers
- **Issue**: Archive extraction hangs on invalid input
- **Status**: High priority fix needed

## Running Fuzzers

```bash
# Run fuzzer for 60 seconds
cargo +nightly fuzz run <target> -- -max_total_time=60

# Run with seed corpus
cargo +nightly fuzz run <target> -- -max_total_time=60 fuzz/corpus_seed/<target>_seed

# Minimize corpus
cargo +nightly fuzz cmin <target>

# Reproduce crash
cargo +nightly fuzz run <target> fuzz/artifacts/<target>/crash-xxx
```

## Dictionary

The IPC protocol fuzzer automatically generated a dictionary of common patterns:
- JSON keys: "values", "paths", "id"
- Error codes: "INVALID_REQUEST", "get"
- Binary patterns: Various multi-byte sequences for coverage

## Next Steps

1. Fix high-priority timeouts in output_scrubber and archive_format
2. Add seed corpus inputs for crash cases to prevent regression
3. Consider longer fuzz runs (overnight/weekend) for better coverage
4. Add CI integration for continuous fuzzing
