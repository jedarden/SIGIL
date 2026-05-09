#![no_main]
use libfuzzer_sys::fuzz_target;
use sigil_core::SecretPath;

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

    // Test 3: Streaming scrubber should handle chunk boundaries
    let mut streaming = sigil_scrub::StreamingScrubber::new();
    for (path, value) in &test_secrets {
        streaming.add_secret(SecretPath::new(*path).unwrap(), value);
    }
    streaming.add_secret(SecretPath::new("secret/long").unwrap(), long_secret.as_slice());

    // Split input into chunks and test streaming
    let chunk_size = data.len().saturating_sub(1).max(1);
    if data.len() > chunk_size {
        let chunk1 = String::from_utf8_lossy(&data[..chunk_size]);
        let chunk2 = String::from_utf8_lossy(&data[chunk_size..]);

        let _ = streaming.scrub_chunk(&chunk1);
        let _ = streaming.scrub_chunk(&chunk2);
        let _ = streaming.finalize();
    }
});
