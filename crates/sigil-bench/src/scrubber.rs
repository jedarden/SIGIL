//! Scrubber benchmark utilities

use sigil_core::SecretPath;
use sigil_scrub::Scrubber;

/// Create a test scrubber with N patterns
pub fn create_scrubber_with_patterns(count: usize, secret_size: usize) -> Scrubber {
    let mut scrubber = Scrubber::new();

    for i in 0..count {
        let path = SecretPath::new(format!("secret/{}", i)).unwrap();
        let value = "x".repeat(secret_size);
        scrubber.add_secret(path, value.as_bytes());
    }

    scrubber
}

/// Generate random secret value
pub fn generate_secret(size: usize) -> String {
    use rand::Rng;
    rand::thread_rng()
        .sample_iter(&rand::distributions::Alphanumeric)
        .take(size)
        .map(char::from)
        .collect()
}
