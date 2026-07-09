# Pulse Strand False Positive: bf-6d8r

**Bead ID:** bf-6d8r  
**Scanner:** pulse strand  
**Severity:** 2/5  
**Status:** False positive

## Finding

The pulse strand scanner flagged the test output:
```
test error::tests::test_structured_error_with_message ... ok
```

## Analysis

The test `test_structured_error_with_message` in `crates/sigil-core/src/error.rs` (lines 314-320) is a straightforward test for the `StructuredError::with_message` method:

```rust
#[test]
fn test_structured_error_with_message() {
    let error = StructuredError::with_message(
        ErrorCode::OperationFailed,
        "Command failed with exit code 1".to_string(),
    );
    assert_eq!(error.message, "Command failed with exit code 1");
}
```

The test passes correctly. The pulse strand appears to have incorrectly flagged this as a finding.

## Conclusion

This is a false positive from the pulse strand scanner. No action required.
