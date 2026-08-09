# Binary Test Fixtures

## Purpose

This directory contains utilities and examples for creating test binary fixtures with specific permission bits for security testing. These fixtures are used to validate SIGIL's detection capabilities for privileged binaries (setuid/setgid).

## Fixture Location

Test binaries are created in a temporary directory managed by the `binary_fixture` module:

**Location**: `/tmp/sigil-test-binaries-{process-id}/`

The directory is automatically created when test fixtures are initialized and cleaned up after tests complete.

## Available Functions

The `sigil_integration_tests::binary_fixture` module provides these functions:

### `create_setgid_binary(name, content)`

Creates a test binary with the setgid bit (mode 0o2755).

**Example**:
```rust
use sigil_integration_tests::binary_fixture::*;

let setgid_bin = create_setgid_binary(
    "test_setgid",
    b"#!/bin/sh\necho 'setgid test'\n"
)?;
```

**Result**: Binary with permissions `-rwxr-sr-x` (setgid bit shown as 's')

### `create_setuid_binary(name, content)`

Creates a test binary with the setuid bit (mode 0o4755).

**Result**: Binary with permissions `-rwsr-xr-x` (setuid bit shown as 's')

### `create_executable_binary(name, content)`

Creates a regular executable binary without special permission bits (mode 0o755).

**Result**: Binary with permissions `-rwxr-xr-x`

### `create_setuid_setgid_binary(name, content)`

Creates a binary with both setuid and setgid bits (mode 0o6755).

**Result**: Binary with permissions `-rwsr-sr-x`

### `is_setgid(path)`

Checks if a binary has the setgid bit set.

**Returns**: `true` if setgid bit is present, `false` otherwise

### `is_setuid(path)`

Checks if a binary has the setuid bit set.

**Returns**: `true` if setuid bit is present, `false` otherwise

## Verification

To verify the setgid bit is properly set:

```bash
# Using ls -l (look for 's' in group execute position)
ls -l /tmp/sigil-test-binaries-*/test_setgid
# Output: -rwxr-sr-x 1 user users ... test_setgid
#                 ^
#                 The 's' indicates setgid bit

# Using stat (octal format)
stat -c '%a %n' /tmp/sigil-test-binaries-*/test_setgid
# Output: 2755 /tmp/sigil-test-binaries-*/test_setgid
#           ^
#           The '2' indicates setgid bit (0o2000)
```

## Example Usage

Run the example to see setgid fixture creation in action:

```bash
cargo run --example create_setgid_fixture
```

This demonstrates:
1. Creating a setgid binary
2. Verifying the setgid bit using `ls -l` and `stat`
3. Programmatic verification with `is_setgid()`
4. Comparison with regular (non-setgid) binaries
5. Combined setuid+setgid binaries

## Cleanup

The `BinaryFixtureGuard` provides RAII-style automatic cleanup:

```rust
let _guard = BinaryFixtureGuard::new();

// Create test binaries...
let bin = create_setgid_binary("test", b"...")?;

// When _guard goes out of scope, all binaries are automatically cleaned up
```

For manual cleanup:

```rust
cleanup_test_binaries()?;
```

## Use Cases

These fixtures are primarily used in:

- **Sandbox security tests**: Verify SIGIL detects and blocks setgid binaries
- **Permission detection tests**: Validate setgid/setuid bit detection
- **Integration tests**: Test full pipeline with privileged binaries
- **Red team exercises**: Simulate privilege escalation attempts

## Security Context

The setgid bit (mode bit 0o2000) causes a binary to execute with the effective group ID (EGID) of the file's group rather than the user's group. This is used for group-level privilege escalation (e.g., write access to shared directories).

SIGIL's sandbox should detect and block setgid binaries to prevent:
- Group privilege escalation
- Access to group-writable resources
- Lateral movement within a group

## Related Files

- `src/binary_fixture.rs` - Fixture creation utilities
- `src/env_detect.rs` - Permission bit detection functions
- `tests/setuid_detection_test.rs` - Tests using these fixtures
- `examples/create_setgid_fixture.rs` - Demonstration example
