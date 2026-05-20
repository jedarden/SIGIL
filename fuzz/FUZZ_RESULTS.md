# SIGIL Fuzzing Results

## Summary

Four fuzzing targets were set up and run for 60 seconds each using `cargo-fuzz`:

1. **command_parser** - Fuzzes the command parser (`CommandParser::extract_placeholders`, `resolve_command`, `validate_command`)
2. **output_scrubber** - Fuzzes the output scrubber (`Scrubber::scrub`, `StreamingScrubber::scrub_chunk`)
3. **archive_format** - Fuzzes the archive format (`create_archive`, `extract_archive`)
4. **ipc_protocol** - Fuzzes the IPC protocol (JSON serialization/deserialization of all IPC types)

## Results

### command_parser
- **Status**: Found 3 crashes
- **Runs**: 68,078
- **Coverage**: 1,508 edges, 6,433 features
- **Corpus size**: 4,088 files (17 MB)
- **Crashes**:
  - `crash-29a4491abcccdd7fcdd5d59717bc3f06f5fdf7fc`
  - `crash-deca86b390cd7c92670f26a738633eecf2016104`
  - `crash-ea9878cd1a65f570de74af1b935a1d504d45f6a4`
- **Sample crash input**: `feff ffff ffff ccff 7c` (malformed UTF-8 with placeholder-like patterns)
- **Recommended dictionary entries**:
  - `"---------------"` (dash sequences)
  - `"stdin"` (injection mode keyword)
  - `"\x80\x00"` (non-ASCII bytes)

### output_scrubber
- **Status**: Found 2 timeouts
- **Runs**: N/A (timeout on initial run)
- **Coverage**: N/A
- **Corpus size**: 2 files (12 KB)
- **Timeouts**:
  - `timeout-da39a3ee5e6b4b0d3255bfef95601890afd80709` (empty input)
  - `timeout-adc83b19e793491b1c6ea0fd8b46cd9f32e592fc` (another variant)
- **Slow units**: 2 slow units identified
- **Issue**: Empty input causes scrubber to hang (infinite loop or slow path)

### archive_format
- **Status**: Found 1 timeout
- **Runs**: N/A (timeout on initial run)
- **Coverage**: N/A
- **Corpus size**: 381 files (1.6 MB)
- **Timeout**:
  - `timeout-85e53271e14006f0265921d02d4d736cdc580b0b` (single byte 0xff)
- **Issue**: Input `[255]` (0xff) causes archive extraction to hang

### ipc_protocol
- **Status**: No crashes found
- **Runs**: 293,471
- **Coverage**: Excellent
- **Corpus size**: 8,130 files (33 MB)
- **Recommended dictionary entries**:
  - `"socket_path"`, `"project_dir"`, `"payload"` (common field names)
  - `"\xff\xff\xff\xff"` (max u32)
  - `"\x00\x00\x00\x00"` (null bytes)
  - `"unlock"`, `"error"`, `"count"` (common string values)

## Issues Found

### 1. Command Parser Crashes
The parser crashes on certain malformed inputs with non-ASCII bytes and partial placeholder patterns. These appear to be assertion failures or panics in the regex matching logic.

**Severity**: Medium (parser should handle invalid UTF-8 and malformed patterns gracefully)

### 2. Output Scrubber Timeout (Empty Input)
The scrubber times out on empty input, suggesting either an infinite loop or a very slow code path when processing empty strings.

**Severity**: High (DoS potential with empty/short inputs)

**Reproduction**: `Scrubber::new().scrub("")`

### 3. Archive Format Timeout (0xff byte)
The archive extraction hangs on a single 0xff byte input, likely in the age decryption or msgpack deserialization code.

**Severity**: High (DoS potential with single-byte inputs)

**Reproduction**: `extract_archive(&[0xff], None)`

## Recommendations

1. **Fix scrubber empty input timeout**: Add early return for empty input in `Scrubber::scrub()`
2. **Fix archive 0xff timeout**: Add input validation before attempting age decryption
3. **Fix parser crashes**: Add better error handling for invalid UTF-8 and malformed placeholders
4. **Add corpus files**: The generated corpus files should be committed to provide better coverage for future runs
5. **Increase timeout**: Consider using `-timeout=5` instead of `-timeout=2` for slower operations

## Running Fuzzers

```bash
# Run individual fuzzer
cargo +nightly fuzz run command_parser -- -max_total_time=60 -timeout=2

# Run with reproduction of crash
cargo +nightly fuzz run output_scrubber fuzz/artifacts/output_scrubber/timeout-da39a3ee5e6b4b0d3255bfef95601890afd80709

# Minimize crash input
cargo +nightly fuzz tmin output_scrubber fuzz/artifacts/output_scrubber/timeout-da39a3ee5e6b4b0d3255bfef95601890afd80709
```

## Corpus Management

The corpus directories contain interesting inputs found during fuzzing:
- `fuzz/corpus/command_parser/` - 4,088 files
- `fuzz/corpus/output_scrubber/` - 2 files
- `fuzz/corpus/archive_format/` - 381 files
- `fuzz/corpus/ipc_protocol/` - 8,130 files

These should be periodically updated and can be committed to the repository to improve CI coverage.
