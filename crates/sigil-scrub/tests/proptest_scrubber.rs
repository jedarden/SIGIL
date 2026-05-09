//! Property-based tests for the output scrubber
//!
//! These tests use proptest to verify that the scrubber maintains
//! important invariants across a wide range of inputs.

use proptest::prelude::*;
use sigil_core::SecretPath;
use sigil_scrub::Scrubber;

/// Property: Scrubber never returns scrubbed output containing known secret value
///
/// This is the most important property: after scrubbing, the output
/// should never contain the original secret value.
proptest! {
    #[test]
    fn prop_scrubber_removes_secret(
        prefix in "[a-zA-Z0-9]{0,100}",
        secret in "[a-zA-Z0-9]{10,50}",
        suffix in "[a-zA-Z0-9]{0,100}"
    ) {
        let mut scrubber = Scrubber::new();
        scrubber.add_secret(SecretPath::new("test/secret").unwrap(), secret.as_bytes());

        let output = format!("{}{}{}", prefix, secret, suffix);
        let scrubbed = scrubber.scrub(&output);

        // The scrubbed output should NOT contain the secret
        prop_assert!(!scrubbed.contains(&secret));
    }
}

/// Property: Scrubber is idempotent
///
/// Scrubbing already-scrubbed output should be a no-op (the output
/// should remain unchanged).
proptest! {
    #[test]
    fn prop_scrubber_is_idempotent(
        prefix in "[a-zA-Z0-9]{0,100}",
        secret in "[a-zA-Z0-9]{10,50}",
        suffix in "[a-zA-Z0-9]{0,100}"
    ) {
        let mut scrubber = Scrubber::new();
        scrubber.add_secret(SecretPath::new("test/secret").unwrap(), secret.as_bytes());

        let output = format!("{}{}{}", prefix, secret, suffix);
        let scrubbed_once = scrubber.scrub(&output);
        let scrubbed_twice = scrubber.scrub(&scrubbed_once);

        // Scrubbing twice should give the same result as scrubbing once
        prop_assert_eq!(scrubbed_once, scrubbed_twice);
    }
}

/// Property: Scrubber handles multiple secrets correctly
///
/// When multiple secrets are added, all should be scrubbed from the output.
proptest! {
    #[test]
    fn prop_scrubber_handles_multiple_secrets(
        secret1 in "[a-zA-Z0-9]{8,20}",
        secret2 in "[a-zA-Z0-9]{8,20}",
        secret3 in "[a-zA-Z0-9]{8,20}"
    ) {
        let mut scrubber = Scrubber::new();
        scrubber.add_secret(SecretPath::new("test/secret1").unwrap(), secret1.as_bytes());
        scrubber.add_secret(SecretPath::new("test/secret2").unwrap(), secret2.as_bytes());
        scrubber.add_secret(SecretPath::new("test/secret3").unwrap(), secret3.as_bytes());

        let output = format!("s1={} s2={} s3={}", secret1, secret2, secret3);
        let scrubbed = scrubber.scrub(&output);

        // None of the secrets should appear in the scrubbed output
        prop_assert!(!scrubbed.contains(&secret1));
        prop_assert!(!scrubbed.contains(&secret2));
        prop_assert!(!scrubbed.contains(&secret3));
    }
}

/// Property: Scrubber never panics on arbitrary input
///
/// The scrubber should handle any input without panicking.
proptest! {
    #[test]
    fn prop_scrubber_never_panics(input in ".{0,10000}") {
        let mut scrubber = Scrubber::new();
        scrubber.add_secret(SecretPath::new("test/secret").unwrap(), b"test_secret");

        let _ = scrubber.scrub(&input);
        let _ = scrubber.scrub_with_stats(&input);
    }
}

/// Property: Scrubber handles Unicode input
///
/// The scrubber should handle Unicode characters without panicking.
proptest! {
    #[test]
    fn prop_scrubber_handles_unicode(s in "\\PC{0,1000}") {
        let mut scrubber = Scrubber::new();
        scrubber.add_secret(SecretPath::new("test/secret").unwrap(), b"secret_value");

        let _ = scrubber.scrub(&s);
    }
}

/// Property: Empty input produces empty or consistent output
///
/// Scrubbing an empty string should not produce unexpected results.
proptest! {
    #[test]
    fn prop_scrubber_empty_input(empty in "") {
        let mut scrubber = Scrubber::new();
        scrubber.add_secret(SecretPath::new("test/secret").unwrap(), b"secret");

        let result = scrubber.scrub(&empty);
        prop_assert_eq!(result, "");
    }
}

/// Property: Scrubber with no secrets returns input unchanged
///
/// If no secrets are added to the scrubber, the input should be returned unchanged.
proptest! {
    #[test]
    fn prop_scrubber_no_secrets_unchanged(input in "[a-zA-Z0-9]{0,500}") {
        let mut scrubber = Scrubber::new();
        let result = scrubber.scrub(&input);
        prop_assert_eq!(result, input);
    }
}

/// Property: Scrubber handles clean output (no secrets to scrub)
///
/// If the output doesn't contain any secrets, it should be returned unchanged.
proptest! {
    #[test]
    fn prop_scrubber_clean_output_unchanged(clean_output in "[a-zA-Z0-9]{0,500}") {
        let mut scrubber = Scrubber::new();
        scrubber.add_secret(SecretPath::new("test/secret").unwrap(), b"secret_not_in_output");

        let result = scrubber.scrub(&clean_output);
        prop_assert_eq!(result, clean_output);
    }
}

/// Property: Scrubber preserves output length
///
/// The scrubbed output should have the same length as the input
/// (we replace with placeholders of the same length).
proptest! {
    #[test]
    fn prop_scrubber_preserves_length(
        prefix in "[a-zA-Z0-9]{0,100}",
        secret in "[a-zA-Z0-9]{10,50}",
        suffix in "[a-zA-Z0-9]{0,100}"
    ) {
        let mut scrubber = Scrubber::new();
        scrubber.add_secret(SecretPath::new("test/secret").unwrap(), secret.as_bytes());

        let output = format!("{}{}{}", prefix, secret, suffix);
        let scrubbed = scrubber.scrub(&output);

        prop_assert_eq!(scrubbed.len(), output.len());
    }
}

/// Property: Scrubber stats report correct match count
///
/// When a secret appears in the output, the stats should report at least one match.
proptest! {
    #[test]
    fn prop_scrubber_stats_match_count(
        secret in "[a-zA-Z0-9]{10,50}"
    ) {
        let mut scrubber = Scrubber::new();
        scrubber.add_secret(SecretPath::new("test/secret").unwrap(), secret.as_bytes());

        let output = format!("The secret is: {}", secret);
        let stats = scrubber.scrub_with_stats(&output);

        // Should have found at least one match
        prop_assert!(stats.matches_found);
    }
}

/// Property: Scrubber handles binary/null bytes
///
/// The scrubber should handle binary data including null bytes.
proptest! {
    #[test]
    fn prop_scrubber_handles_null_bytes(
        before in "[a-zA-Z0-9]{0,10}",
        after in "[a-zA-Z0-9]{0,10}"
    ) {
        let mut scrubber = Scrubber::new();
        scrubber.add_secret(SecretPath::new("test/secret").unwrap(), b"secret\x00value");

        let output = format!("{}secret\x00value{}", before, after);
        let _ = scrubber.scrub(&output);
    }
}

/// Property: Scrubber handles secret at various positions
///
/// Secrets should be scrubbed regardless of their position in the output.
proptest! {
    #[test]
    fn prop_scrubber_position_independent(
        padding1 in "[a-zA-Z0-9]{0,100}",
        padding2 in "[a-zA-Z0-9]{0,100}",
        secret in "[a-zA-Z0-9]{10,30}",
        padding3 in "[a-zA-Z0-9]{0,100}"
    ) {
        let mut scrubber = Scrubber::new();
        scrubber.add_secret(SecretPath::new("test/secret").unwrap(), secret.as_bytes());

        let output = format!("{}{}{}{}", padding1, padding2, secret, padding3);
        let scrubbed = scrubber.scrub(&output);

        prop_assert!(!scrubbed.contains(&secret));
    }
}

/// Property: Scrubber handles overlapping secrets
///
/// When one secret is a substring of another, both should be handled.
proptest! {
    #[test]
    fn prop_scrubber_overlapping_secrets(
        base in "[a-zA-Z0-9]{10,20}"
    ) {
        let mut scrubber = Scrubber::new();
        let short_secret = format!("{}{}", &base[..5], &base[10..]);
        let long_secret = format!("{}XX{}", base, base);

        scrubber.add_secret(SecretPath::new("test/short").unwrap(), short_secret.as_bytes());
        scrubber.add_secret(SecretPath::new("test/long").unwrap(), long_secret.as_bytes());

        let output = format!("{} {}", short_secret, long_secret);
        let scrubbed = scrubber.scrub(&output);

        // At minimum, the long secret should not appear
        prop_assert!(!scrubbed.contains(&long_secret));
    }
}

/// Property: Scrubber is consistent across multiple calls
///
/// Scrubbing the same input multiple times should produce consistent results.
proptest! {
    #[test]
    fn prop_scrubber_consistent(
        secret in "[a-zA-Z0-9]{10,30}",
        output in "[a-zA-Z0-9]{0,200}"
    ) {
        let mut scrubber1 = Scrubber::new();
        let mut scrubber2 = Scrubber::new();

        scrubber1.add_secret(SecretPath::new("test/secret").unwrap(), secret.as_bytes());
        scrubber2.add_secret(SecretPath::new("test/secret").unwrap(), secret.as_bytes());

        let result1 = scrubber1.scrub(&output);
        let result2 = scrubber2.scrub(&output);

        prop_assert_eq!(result1, result2);
    }
}

/// Property: Scrubber handles special characters
///
/// The scrubber should handle special characters in output.
proptest! {
    #[test]
    fn prop_scrubber_special_chars(
        special in "[!@#$%^&*()\\-_=+\\[\\]{}|;:'\",.<>?/`~]{0,20}",
        secret in "[a-zA-Z0-9]{10,30}"
    ) {
        let mut scrubber = Scrubber::new();
        scrubber.add_secret(SecretPath::new("test/secret").unwrap(), secret.as_bytes());

        let output = format!("{}{}{}", special, secret, special);
        let scrubbed = scrubber.scrub(&output);

        prop_assert!(!scrubbed.contains(&secret));
    }
}

/// Property: Scrubber with stats returns consistent results
///
/// scrub() and scrub_with_stats() should return the same scrubbed output.
proptest! {
    #[test]
    fn prop_scrubber_stats_consistent(
        secret in "[a-zA-Z0-9]{10,30}",
        output in "[a-zA-Z0-9]{0,200}"
    ) {
        let mut scrubber1 = Scrubber::new();
        let mut scrubber2 = Scrubber::new();

        scrubber1.add_secret(SecretPath::new("test/secret").unwrap(), secret.as_bytes());
        scrubber2.add_secret(SecretPath::new("test/secret").unwrap(), secret.as_bytes());

        let result1 = scrubber1.scrub(&output);
        let result2 = scrubber2.scrub_with_stats(&output).scrubbed;

        prop_assert_eq!(result1, result2);
    }
}
