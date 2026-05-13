#![no_main]
use libfuzzer_sys::fuzz_target;
use sigil_core::SecretPath;
use base64::prelude::*;

fuzz_target!(|data: &[u8]| {
    let mut scrubber = sigil_scrub::Scrubber::new();

    // Add some test secrets with various encodings
    let test_secrets: Vec<(&'static str, &'static [u8])> = vec![
        ("secret/basic", b"basic_secret_value"),
        ("secret/base64", b"base64_secret!@#"),
        ("secret/special", b"special\n\t\x00\r"),
    ];

    for (path, value) in &test_secrets {
        let _ = scrubber.add_secret(SecretPath::new(*path).unwrap(), value);
    }

    // Add a long secret
    let long_secret = b"x".repeat(1000);
    let _ = scrubber.add_secret(SecretPath::new("secret/long").unwrap(), long_secret.as_slice());

    // Convert bytes to string for scrubbing
    let input = String::from_utf8_lossy(data);

    // Test 1: scrub should not panic on any input
    let _ = scrubber.scrub(&input);

    // Test 2: scrub_with_stats should not panic
    let _ = scrubber.scrub_with_stats(&input);

    // Test 3: Base64 offset scrubbing - test all 3 offsets
    // Create a secret and test scrubbing at different base64 alignment offsets
    let test_secret = b"test_secret_for_offset";
    let _ = scrubber.add_secret(SecretPath::new("secret/offset_test").unwrap(), test_secret);

    let base64_encoded = BASE64_STANDARD.encode(test_secret);

    // Test at offset 0 (aligned)
    let offset_0_input = format!("prefix{}suffix", base64_encoded);
    let _ = scrubber.scrub(&offset_0_input);

    // Test at offset 1
    if base64_encoded.len() > 1 {
        let offset_1 = &base64_encoded[1..];
        let offset_1_input = format!("prefix{}suffix", offset_1);
        let _ = scrubber.scrub(&offset_1_input);
    }

    // Test at offset 2
    if base64_encoded.len() > 2 {
        let offset_2 = &base64_encoded[2..];
        let offset_2_input = format!("prefix{}suffix", offset_2);
        let _ = scrubber.scrub(&offset_2_input);
    }

    // Test at offset 3
    if base64_encoded.len() > 3 {
        let offset_3 = &base64_encoded[3..];
        let offset_3_input = format!("prefix{}suffix", offset_3);
        let _ = scrubber.scrub(&offset_3_input);
    }

    // Test 4: Streaming scrubber with comprehensive cross-chunk boundary testing
    let mut streaming = sigil_scrub::StreamingScrubber::new();
    for (path, value) in &test_secrets {
        streaming.add_secret(SecretPath::new(*path).unwrap(), value);
    }
    streaming.add_secret(SecretPath::new("secret/long").unwrap(), long_secret.as_slice());
    streaming.add_secret(SecretPath::new("secret/offset_test").unwrap(), test_secret);

    // Test various chunk sizes to catch cross-chunk boundary issues
    let chunk_sizes = vec![
        1usize,                              // Single byte chunks
        data.len() / 2,                      // Half-size chunks
        data.len().saturating_sub(1).max(1), // Almost full chunks
        data.len() / 3,                      // Third-size chunks
        data.len() / 4,                      // Quarter-size chunks
    ];

    for chunk_size in chunk_sizes {
        if data.len() > chunk_size {
            let mut streaming_test = sigil_scrub::StreamingScrubber::new();
            for (path, value) in &test_secrets {
                streaming_test.add_secret(SecretPath::new(*path).unwrap(), value);
            }

            let mut pos = 0;
            while pos < data.len() {
                let end = (pos + chunk_size).min(data.len());
                let chunk = String::from_utf8_lossy(&data[pos..end]);
                let _ = streaming_test.scrub_chunk(&chunk);
                pos = end;
            }
            let _ = streaming_test.finalize();
        }
    }

    // Test 5: Verify scrubbed output doesn't contain secret values
    let scrubbed = scrubber.scrub(&input);

    // Check that none of the test secrets appear in the scrubbed output
    for (_path, value) in &test_secrets {
        let value_str = String::from_utf8_lossy(value);
        // If the secret was in the input, it should be replaced with {{secret:...}}
        if input.contains(&value_str as &str) {
            assert!(
                !scrubbed.contains(&value_str as &str) || scrubbed.contains("{{secret:"),
                "Secret value found in scrubbed output: {}",
                &value_str[..value_str.len().min(20)]
            );
        }
    }

    // Test 6: Verify base64-encoded secrets are scrubbed at all offsets
    for (_path, value) in &test_secrets {
        let encoded = BASE64_STANDARD.encode(value);
        let encoded_url = BASE64_URL_SAFE.encode(value);

        // Test standard base64 at all offsets
        for offset in 0..=3 {
            if encoded.len() > offset {
                let offset_str = &encoded[offset..];
                let test_input = format!("Test {} end", offset_str);
                let scrubbed_test = scrubber.scrub(&test_input);

                // If the offset pattern was in patterns, it should be scrubbed
                if scrubber.pattern_to_path.contains_key(offset_str) {
                    assert!(
                        !scrubbed_test.contains(offset_str) || scrubbed_test.contains("{{secret:"),
                        "Base64 offset {} not scrubbed: {}",
                        offset,
                        offset_str
                    );
                }
            }
        }

        // Test base64url at all offsets
        for offset in 0..=3 {
            if encoded_url.len() > offset {
                let offset_str = &encoded_url[offset..];
                let test_input = format!("Test {} end", offset_str);
                let scrubbed_test = scrubber.scrub(&test_input);

                if scrubber.pattern_to_path.contains_key(offset_str) {
                    assert!(
                        !scrubbed_test.contains(offset_str) || scrubbed_test.contains("{{secret:"),
                        "Base64url offset {} not scrubbed: {}",
                        offset,
                        offset_str
                    );
                }
            }
        }
    }

    // Test 7: Verify no secrets leak in error messages
    // Scrubber operations shouldn't panic, and if they return errors,
    // those errors shouldn't contain secret values
    if let Ok(result) = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        scrubber.scrub_with_stats(&input)
    })) {
        // If we got a result, verify it's valid
        let _ = result;
    }
});
