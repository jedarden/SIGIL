#![no_main]
use libfuzzer_sys::fuzz_target;
use sigil_core::{SecretMetadata, SecretPath, SecretValue, SecretType};

fuzz_target!(|data: &[u8]| {
    // Test SIGIL archive format with potentially malicious data

    // Test 1: Create archive with fuzzed data
    // Build a list of test secrets
    let test_secrets = vec![
        (
            SecretPath::new("test/basic").unwrap(),
            SecretValue::new(b"basic_secret".to_vec()),
            {
                let mut meta = SecretMetadata::new(SecretPath::new("test/basic").unwrap());
                meta.secret_type = SecretType::Generic;
                meta
            },
        ),
        (
            SecretPath::new("test/special").unwrap(),
            SecretValue::new(b"special\n\t\x00\r".to_vec()),
            {
                let mut meta = SecretMetadata::new(SecretPath::new("test/special").unwrap());
                meta.secret_type = SecretType::ApiKey;
                meta
            },
        ),
    ];

    // Test create_archive with no passphrase (for speed)
    let _ = sigil_core::create_archive(
        test_secrets.clone(),
        "test-vault-id",
        None, // No passphrase for faster fuzzing
    );

    // Test 2: Extract archive with fuzzed data as input
    // First, try to use the fuzzed data directly as an archive
    let extract_result = sigil_core::extract_archive(data, None);
    if let Ok(payload) = extract_result {
        // Verify payload structure is valid
        for secret in &payload.secrets {
            // Secret paths should be non-empty
            assert!(!secret.path.is_empty());
            // Values should be valid base64
            use base64::prelude::*;
            let _ = BASE64_STANDARD.decode(&secret.value);
        }
    }

    // Test 3: Create and extract round-trip with fuzzed passphrase
    if data.len() > 10 && data.len() < 1000 {
        // Use first part of data as passphrase
        let passphrase_len = data.len().min(50);
        let passphrase = String::from_utf8_lossy(&data[..passphrase_len]).to_string();

        let archive = sigil_core::create_archive(
            test_secrets.clone(),
            "test-vault-id",
            Some(&passphrase),
        );

        if let Ok(archive_data) = archive {
            // Try to extract with same passphrase
            let _ = sigil_core::extract_archive(&archive_data, Some(&passphrase));

            // Try to extract with wrong passphrase (should fail gracefully)
            let _ = sigil_core::extract_archive(&archive_data, Some("wrong-passphrase"));
        }
    }

    // Test 4: Test with malformed archive headers
    // Create invalid magic bytes
    if data.len() >= 10 {
        let mut malformed = Vec::new();
        malformed.extend_from_slice(b"INVALID\x00");
        malformed.extend_from_slice(&data[..8]); // version + partial payload
        let _ = sigil_core::extract_archive(&malformed, None);
    }

    // Test 5: Test with oversized data
    if data.len() > 16_000_000 {
        // Oversized archive should be rejected
        let _ = sigil_core::extract_archive(data, None);
    }

    // Test 6: Test msgpack serialization directly
    if data.len() > 0 && data.len() < 100_000 {
        use sigil_core::ArchivePayload;
        // Try to deserialize fuzzed data as ArchivePayload
        let _ = rmp_serde::from_slice::<ArchivePayload>(data);
    }

    // Test 7: Test with empty or minimal archives
    let empty_result = sigil_core::extract_archive(&[], None);
    assert!(empty_result.is_err());

    let tiny_result = sigil_core::extract_archive(b"SIGIL\x00\x01\x00", None);
    // Empty payload should deserialize to empty secrets list
    if let Ok(payload) = tiny_result {
        assert_eq!(payload.secrets.len(), 0);
    }

    // Test 8: Test version validation
    if data.len() >= 8 {
        let mut version_test = Vec::new();
        version_test.extend_from_slice(b"SIGIL\x00");
        // Use fuzzed data as version number
        version_test.extend_from_slice(&data[..2]);
        version_test.extend_from_slice(b"{}");
        let _ = sigil_core::extract_archive(&version_test, None);
    }

    // Test 9: Age encryption edge cases
    // Test with various passphrase lengths
    for pass_len in [0, 1, 8, 32, 100, 1000] {
        if data.len() >= pass_len {
            let pass = &data[..pass_len.min(data.len())];
            let pass_str = String::from_utf8_lossy(pass).to_string();
            let _ = sigil_core::create_archive(
                test_secrets.clone(),
                "test",
                Some(&pass_str),
            );
        }
    }
});
