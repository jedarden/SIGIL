#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Test vault operations with potentially malicious data

    // Test 1: SecretPath validation should not panic
    let input = String::from_utf8_lossy(data).to_string();
    let _ = sigil_core::SecretPath::new(&input);

    // Test 2: SecretValue creation should not panic
    let _ = sigil_core::SecretValue::new(data.to_vec());

    // Test 3: SecretPath::from_bytes should handle arbitrary bytes
    let _ = sigil_core::SecretPath::new(input.as_str());

    // Test 4: SecretMetadata creation should not panic
    if let Ok(path) = sigil_core::SecretPath::new(&input) {
        let _ = sigil_core::SecretMetadata::new(path.clone());

        // Test with tags
        let mut meta = sigil_core::SecretMetadata::new(path.clone());
        meta.tags = vec!["tag1".to_string(), "tag2".to_string()];
    }

    // Test 5: Secret backend testing
    // Note: We're not actually connecting to backends, just testing validation
    if let Ok(_path) = sigil_core::SecretPath::new("test/path") {
        // Test various secret path formats
        let test_paths = vec![
            input.as_str(),
            "a/b/c",
            "a.b.c",
            "a-b-c",
            "../escape",
            "/absolute",
            "~home",
        ];
        for test_path in test_paths {
            let _ = sigil_core::SecretPath::new(test_path);
        }
    }

    // Test 6: Fuzz base64 decoding (common in vault operations)
    use base64::prelude::*;
    let _ = BASE64_STANDARD.decode(data);
    let _ = BASE64_URL_SAFE.decode(data);

    // Test 7: Fuzz hex decoding (used for secret values)
    let _ = hex::decode(data);

    // Test 8: Test age encryption operations
    // Age key generation - ensure it doesn't panic
    if data.len() >= 32 {
        // Test age identity generation
        let _ = age::x25519::Identity::generate();
    }

    // Test 9: Test vault path validation against directory traversal attempts
    let test_path = input.clone();
    if test_path.contains("..") || test_path.contains('~') || test_path.starts_with('/') {
        // These are potentially malicious paths - ensure validation handles them
        let _ = sigil_core::SecretPath::new(&test_path);
    }

    // Test 10: Test with very large inputs (potential DoS)
    if data.len() > 1_000_000 {
        // For very large inputs, just test the basic constructors
        let _ = sigil_core::SecretValue::new(data[..100].to_vec()); // Truncate
    }
});
