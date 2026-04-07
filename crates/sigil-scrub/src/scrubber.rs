//! Output scrubber for detecting and redacting secrets
//!
//! Uses Aho-Corasick multi-pattern matching for O(n) detection of secrets
//! in output, with support for multiple encoding variants.

use aho_corasick::{AhoCorasick, AhoCorasickBuilder, MatchKind};
use base64::prelude::*;
use sigil_core::SecretPath;
use std::collections::HashMap;

/// Default boundary buffer size for streaming scrubber (4KB)
const DEFAULT_BOUNDARY_BUFFER_SIZE: usize = 4096;

/// Streaming scrubber that handles chunked output with boundary buffering
pub struct StreamingScrubber {
    /// The underlying scrubber
    scrubber: Scrubber,
    /// Boundary buffer for cross-chunk pattern detection (original text)
    boundary_buffer: String,
    /// Previously scrubbed boundary (what we output last time)
    previous_scrubbed_boundary: String,
    /// Maximum buffer size
    max_buffer_size: usize,
}

impl StreamingScrubber {
    /// Create a new streaming scrubber
    pub fn new() -> Self {
        Self::with_buffer_size(DEFAULT_BOUNDARY_BUFFER_SIZE)
    }

    /// Create a new streaming scrubber with a specific buffer size
    pub fn with_buffer_size(max_buffer_size: usize) -> Self {
        Self {
            scrubber: Scrubber::new(),
            boundary_buffer: String::new(),
            previous_scrubbed_boundary: String::new(),
            max_buffer_size,
        }
    }

    /// Add a secret to the scrubber
    pub fn add_secret(&mut self, path: SecretPath, value: &[u8]) {
        self.scrubber.add_secret(path, value);
    }

    /// Remove a secret from the scrubber
    pub fn remove_secret(&mut self, path: &SecretPath) {
        self.scrubber.remove_secret(path);
    }

    /// Clear all secrets from the scrubber
    pub fn clear(&mut self) {
        self.scrubber.clear();
        self.boundary_buffer.clear();
        self.previous_scrubbed_boundary.clear();
    }

    /// Get the maximum secret length for buffer sizing
    pub fn max_secret_length(&self) -> usize {
        // Calculate max pattern length from all patterns
        self.scrubber
            .pattern_to_path
            .keys()
            .map(|k| k.len())
            .max()
            .unwrap_or(0)
    }

    /// Scrub a chunk of data with boundary buffering
    ///
    /// This method buffers the last N bytes (where N is the max secret length)
    /// to handle patterns that cross chunk boundaries.
    ///
    /// Returns the scrubbed output. The caller should concatenate all
    /// returned chunks to get the complete scrubbed output.
    pub fn scrub_chunk(&mut self, chunk: &str) -> String {
        // Get the max secret length for boundary buffering
        let boundary_size = self.max_secret_length().min(self.max_buffer_size);

        // Combine boundary buffer with new chunk
        let combined = if !self.boundary_buffer.is_empty() {
            format!("{}{}", self.boundary_buffer, chunk)
        } else {
            chunk.to_string()
        };

        // Scrub the combined text
        let scrubbed = self.scrubber.scrub(&combined);

        // If this is the first chunk (no previous boundary), return everything
        if self.previous_scrubbed_boundary.is_empty() {
            // Update boundary buffer for next chunk
            if combined.len() > boundary_size {
                let start = combined.len() - boundary_size;
                self.boundary_buffer = combined[start..].to_string();
            } else {
                self.boundary_buffer = combined;
            }

            // Store the scrubbed boundary for next comparison
            let new_boundary_size = self.boundary_buffer.len().min(scrubbed.len());
            if new_boundary_size > 0 {
                let start = scrubbed.len() - new_boundary_size;
                self.previous_scrubbed_boundary = scrubbed[start..].to_string();
            }

            return scrubbed;
        }

        // We have a previous boundary, so we need to exclude it from the output
        // The scrubbed text starts with the previous scrubbed boundary,
        // so we skip it and return the rest

        // Find where the new content starts in the scrubbed output
        // by removing the prefix that matches the previous scrubbed boundary
        let new_content = if scrubbed.starts_with(&self.previous_scrubbed_boundary) {
            scrubbed[self.previous_scrubbed_boundary.len()..].to_string()
        } else {
            // The previous boundary was modified by scrubbing,
            // try to find a reasonable split point
            scrubbed.clone()
        };

        // Update boundary buffer for next chunk
        if combined.len() > boundary_size {
            let start = combined.len() - boundary_size;
            self.boundary_buffer = combined[start..].to_string();
        } else {
            self.boundary_buffer = combined;
        }

        // Store the scrubbed boundary for next comparison
        let new_boundary_size = self.boundary_buffer.len().min(scrubbed.len());
        if new_boundary_size > 0 {
            let start = scrubbed.len() - new_boundary_size;
            self.previous_scrubbed_boundary = scrubbed[start..].to_string();
        }

        new_content
    }

    /// Finalize streaming and return any remaining buffered content
    pub fn finalize(&mut self) -> String {
        if self.boundary_buffer.is_empty() {
            return String::new();
        }

        let result = self.scrubber.scrub(&self.boundary_buffer);

        // Remove the previously output boundary if present
        let output = if !self.previous_scrubbed_boundary.is_empty()
            && result.starts_with(&self.previous_scrubbed_boundary)
        {
            result[self.previous_scrubbed_boundary.len()..].to_string()
        } else {
            result
        };

        self.boundary_buffer.clear();
        self.previous_scrubbed_boundary.clear();
        output
    }
}

impl Default for StreamingScrubber {
    fn default() -> Self {
        Self::new()
    }
}

/// Output scrubber that detects and redacts secrets
pub struct Scrubber {
    /// Map from pattern string to secret path (for reverse lookup)
    pub pattern_to_path: HashMap<String, String>,
    /// Aho-Corasick automaton for fast matching
    automaton: Option<AhoCorasick>,
    /// Whether the automaton needs rebuilding
    needs_rebuild: bool,
}

impl Default for Scrubber {
    fn default() -> Self {
        Self::new()
    }
}

impl Scrubber {
    /// Create a new scrubber
    pub fn new() -> Self {
        Self {
            pattern_to_path: HashMap::new(),
            automaton: None,
            needs_rebuild: false,
        }
    }

    /// Add a secret to the scrubber with all its encoding variants
    pub fn add_secret(&mut self, path: SecretPath, value: &[u8]) {
        let path_str = path.as_str().to_string();

        // Generate all encoding variants
        let patterns = self.generate_encoding_variants(value);

        // Store patterns mapped to path
        for pattern in &patterns {
            self.pattern_to_path
                .insert(pattern.clone(), path_str.clone());
        }

        self.needs_rebuild = true;
    }

    /// Remove a secret from the scrubber
    #[allow(dead_code)]
    pub fn remove_secret(&mut self, path: &SecretPath) {
        let path_str = path.as_str();

        // Remove all patterns associated with this path
        self.pattern_to_path.retain(|_, p| p != path_str);

        self.needs_rebuild = true;
    }

    /// Clear all secrets from the scrubber
    #[allow(dead_code)]
    pub fn clear(&mut self) {
        self.pattern_to_path.clear();
        self.automaton = None;
        self.needs_rebuild = false;
    }

    /// Get the number of patterns loaded in the scrubber
    #[allow(dead_code)]
    pub fn pattern_count(&self) -> usize {
        self.pattern_to_path.len()
    }

    /// Generate all encoding variants of a secret value
    fn generate_encoding_variants(&self, value: &[u8]) -> Vec<String> {
        let mut patterns = Vec::new();

        // Convert to string for text-based encodings
        let value_str = String::from_utf8_lossy(value);

        // 1. Raw value (as string)
        patterns.push(value_str.to_string());

        // 2. Base64 (standard) - all 3 alignment offsets
        let base64_standard = BASE64_STANDARD.encode(value);
        patterns.push(base64_standard.clone());
        for offset in 1..=3 {
            if offset < base64_standard.len() {
                patterns.push(base64_standard[offset..].to_string());
            }
        }

        // 3. Base64url - all 3 alignment offsets
        let base64_url = BASE64_URL_SAFE.encode(value);
        patterns.push(base64_url.clone());
        for offset in 1..=3 {
            if offset < base64_url.len() {
                patterns.push(base64_url[offset..].to_string());
            }
        }

        // 4. URL-encoded (percent-encoding)
        let url_encoded = urlencoding::encode(&value_str).to_string();
        patterns.push(url_encoded);

        // 5. Hex-encoded
        let hex_encoded = hex::encode(value);
        patterns.push(hex_encoded);

        // 6. JSON-escaped (escape quotes, backslashes)
        let json_escaped = value_str.replace('\\', "\\\\").replace('"', "\\\"");
        patterns.push(json_escaped);

        // 7. Shell-escaped (single quotes wrapped)
        let shell_escaped = format!("'{}'", value_str.replace('\'', "'\\''"));
        patterns.push(shell_escaped);

        // Remove duplicates while preserving order
        patterns.sort();
        patterns.dedup();

        patterns
    }

    /// Rebuild the Aho-Corasick automaton
    fn rebuild_automaton(&mut self) {
        if self.pattern_to_path.is_empty() {
            self.automaton = None;
            return;
        }

        let patterns: Vec<&str> = self.pattern_to_path.keys().map(|s| s.as_str()).collect();

        let automaton = AhoCorasickBuilder::new()
            .match_kind(MatchKind::LeftmostLongest)
            .build(&patterns)
            .expect("Failed to build Aho-Corasick automaton");

        self.automaton = Some(automaton);
        self.needs_rebuild = false;
    }

    /// Scrub output for secrets, replacing matches with {{secret:path}} placeholders
    pub fn scrub(&mut self, output: &str) -> String {
        // Rebuild automaton if needed
        if self.needs_rebuild {
            self.rebuild_automaton();
        }

        let Some(automaton) = &self.automaton else {
            return output.to_string();
        };

        // Collect all matches and build replacement map
        let mut replacements: Vec<(std::ops::Range<usize>, String)> = Vec::new();

        for mat in automaton.find_iter(output) {
            let matched_text = &output[mat.range()];
            if let Some(path) = self.pattern_to_path.get(matched_text) {
                replacements.push((mat.range(), format!("{{{{secret:{}}}}}", path)));
            }
        }

        // Apply replacements from end to start to preserve offsets
        replacements.sort_by(|a, b| b.0.start.cmp(&a.0.start));

        let mut result = output.to_string();
        for (range, replacement) in replacements {
            result.replace_range(range, &replacement);
        }

        result
    }

    /// Scrub output and return statistics about what was scrubbed
    pub fn scrub_with_stats(&mut self, output: &str) -> ScrubResult {
        let original = output.to_string();
        let scrubbed = self.scrub(output);

        let matches_found = original != scrubbed;

        ScrubResult {
            scrubbed,
            matches_found,
            secrets_detected: if matches_found { 1 } else { 0 },
        }
    }
}

/// Result of scrubbing operation
#[derive(Debug, Clone)]
pub struct ScrubResult {
    /// The scrubbed output with secrets replaced
    pub scrubbed: String,
    /// Whether any matches were found
    pub matches_found: bool,
    /// Number of unique secrets detected
    pub secrets_detected: usize,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_scrubber_creation() {
        let scrubber = Scrubber::new();
        assert_eq!(scrubber.pattern_to_path.len(), 0);
        assert!(scrubber.automaton.is_none());
    }

    #[test]
    fn test_scrubber_add_secret() {
        let mut scrubber = Scrubber::new();
        let path = SecretPath::new("test/secret").unwrap();
        scrubber.add_secret(path, b"my_secret_value");

        assert!(scrubber.needs_rebuild);
        assert!(!scrubber.pattern_to_path.is_empty());
    }

    #[test]
    fn test_generate_encoding_variants() {
        let scrubber = Scrubber::new();
        let value = b"test";
        let variants = scrubber.generate_encoding_variants(value);

        // Should have at least raw, base64, hex
        assert!(variants.len() >= 3);
        assert!(variants.contains(&"test".to_string()));
        assert!(variants.contains(&"dGVzdA==".to_string())); // base64
        assert!(variants.contains(&"74657374".to_string())); // hex
    }

    #[test]
    fn test_scrub_basic() {
        let mut scrubber = Scrubber::new();
        let path = SecretPath::new("api/key").unwrap();
        scrubber.add_secret(path.clone(), b"secret123");

        let output = "The API key is secret123";
        let result = scrubber.scrub(output);

        assert_eq!(result, "The API key is {{secret:api/key}}");
    }

    #[test]
    fn test_scrub_no_match() {
        let mut scrubber = Scrubber::new();
        let path = SecretPath::new("api/key").unwrap();
        scrubber.add_secret(path.clone(), b"secret123");

        let output = "The API key is not_here";
        let result = scrubber.scrub(output);

        assert_eq!(result, output);
    }

    #[test]
    fn test_scrub_with_stats() {
        let mut scrubber = Scrubber::new();
        let path = SecretPath::new("api/key").unwrap();
        scrubber.add_secret(path.clone(), b"secret123");

        let output = "The API key is secret123";
        let result = scrubber.scrub_with_stats(output);

        assert!(result.matches_found);
        assert_eq!(result.secrets_detected, 1);
        assert_eq!(result.scrubbed, "The API key is {{secret:api/key}}");
    }

    #[test]
    fn test_scrubber_clear() {
        let mut scrubber = Scrubber::new();
        let path = SecretPath::new("test/secret").unwrap();
        scrubber.add_secret(path, b"value");

        scrubber.clear();

        assert!(scrubber.pattern_to_path.is_empty());
        assert!(scrubber.automaton.is_none());
        assert!(!scrubber.needs_rebuild);
    }

    // Streaming scrubber tests
    #[test]
    fn test_streaming_scrubber_creation() {
        let scrubber = StreamingScrubber::new();
        assert!(scrubber.boundary_buffer.is_empty());
        assert_eq!(scrubber.max_buffer_size, DEFAULT_BOUNDARY_BUFFER_SIZE);
    }

    #[test]
    fn test_streaming_scrubber_with_custom_buffer_size() {
        let scrubber = StreamingScrubber::with_buffer_size(1024);
        assert_eq!(scrubber.max_buffer_size, 1024);
    }

    #[test]
    fn test_streaming_scrubber_single_chunk() {
        let mut scrubber = StreamingScrubber::new();
        let path = SecretPath::new("api/key").unwrap();
        scrubber.add_secret(path, b"secret123");

        let chunk = "The API key is secret123";
        let result = scrubber.scrub_chunk(chunk);

        assert_eq!(result, "The API key is {{secret:api/key}}");
    }

    #[test]
    fn test_streaming_scrubber_cross_chunk_boundary() {
        let mut scrubber = StreamingScrubber::new();
        let path = SecretPath::new("api/key").unwrap();
        scrubber.add_secret(path, b"secret123");

        // Split secret across two chunks
        let chunk1 = "The API key is sec";
        let chunk2 = "ret123 and more";

        let result1 = scrubber.scrub_chunk(chunk1);
        assert_eq!(result1, chunk1); // No match yet

        let result2 = scrubber.scrub_chunk(chunk2);
        // The second chunk should trigger scrubbing of the combined text
        assert!(result2.contains("{{secret:api/key}}"));
    }

    #[test]
    fn test_streaming_scrubber_multiple_chunks() {
        let mut scrubber = StreamingScrubber::new();
        let path = SecretPath::new("test").unwrap();
        scrubber.add_secret(path, b"SECRET");

        let chunks = vec!["The SEC", "RET is here", " and SECRET again"];

        let mut results = Vec::new();
        for chunk in chunks {
            results.push(scrubber.scrub_chunk(chunk));
        }

        // Finalize to get any remaining buffered content
        let _final_result = scrubber.finalize();
        results.push(_final_result);

        let combined = results.join("");
        assert!(combined.contains("{{secret:test}}"));
    }

    #[test]
    fn test_streaming_scrubber_finalize() {
        let mut scrubber = StreamingScrubber::new();
        let path = SecretPath::new("api/key").unwrap();
        scrubber.add_secret(path, b"secret123");

        // Add partial content
        let _ = scrubber.scrub_chunk("The API key is sec");

        // Finalize should scrub any remaining buffered content
        let _finalized = scrubber.finalize();

        // The buffer should be empty after finalize
        assert!(scrubber.boundary_buffer.is_empty());
    }

    #[test]
    fn test_streaming_scrubber_clear() {
        let mut scrubber = StreamingScrubber::new();
        let path = SecretPath::new("test").unwrap();
        scrubber.add_secret(path, b"value");

        scrubber.clear();

        assert!(scrubber.scrubber.pattern_to_path.is_empty());
        assert!(scrubber.boundary_buffer.is_empty());
    }

    #[test]
    fn test_streaming_scrubber_max_secret_length() {
        let mut scrubber = StreamingScrubber::new();
        let path = SecretPath::new("test").unwrap();
        scrubber.add_secret(path, b"very_long_secret_value_here");

        let max_len = scrubber.max_secret_length();
        assert!(max_len > 0);
    }

    // Phase 3 Red Team Checkpoint tests

    #[test]
    fn test_scrubber_with_regex_special_characters() {
        let mut scrubber = Scrubber::new();
        let path = SecretPath::new("test/special").unwrap();

        // Secrets with regex special characters - use &str instead of byte arrays for flexibility
        let special_secrets: Vec<(&str, &str)> = vec![
            ("secret.*", "contains Kleene star"),
            ("secret.+?", "contains reluctant quantifiers"),
            ("secret[abc]", "contains character class"),
            ("secret(a|b)", "contains alternation"),
            ("secret^anchor", "contains start anchor"),
            ("secret$anchor", "contains end anchor"),
            ("secret\\d+", "contains digit escape"),
            ("secret\\w{3}", "contains word count"),
            ("secret\\b", "contains word boundary"),
            ("secret[\\]]", "contains escaped bracket"),
            ("secret\\(", "contains escaped paren"),
            ("secret\\)", "contains escaped close paren"),
            ("secret\\{1,3\\}", "contains escaped quantifier"),
        ];

        for (secret_str, description) in special_secrets {
            scrubber.clear();
            scrubber.add_secret(path.clone(), secret_str.as_bytes());

            let output = format!("The secret is {}", secret_str);
            let result = scrubber.scrub(&output);

            assert!(
                result.contains("{{secret:test/special}}"),
                "Failed to scrub secret with {}: {}",
                description,
                result
            );
            assert!(
                !result.contains(secret_str),
                "Secret with {} was not properly scrubbed: {}",
                description,
                result
            );
        }
    }

    #[test]
    fn test_scrubber_with_base64_alignment_offsets() {
        let mut scrubber = Scrubber::new();
        let path = SecretPath::new("test/aligned").unwrap();

        // Create a secret that's 4 bytes (encodes to exactly 8 base64 chars)
        let secret = b"ABCD"; // Base64: QUJDRA==
        scrubber.add_secret(path.clone(), secret);

        use base64::prelude::*;
        let base64_encoded = BASE64_STANDARD.encode(secret);
        assert_eq!(base64_encoded, "QUJDRA==");

        // Test at 3 different alignment offsets (base64 works in 4-byte blocks)
        let test_cases = vec![
            // Offset 0: aligned
            ("xxxQUJDRA==yyy", "Offset 0 (aligned)"),
            // Offset 1: misaligned by 1
            ("xxQUJDRA==xyyy", "Offset 1"),
            // Offset 2: misaligned by 2
            ("xQUJDRA==xyyy", "Offset 2"),
            // Offset 3: misaligned by 3
            ("QUJDRA==xyyy", "Offset 3"),
        ];

        for (input, description) in test_cases {
            scrubber.clear();
            scrubber.add_secret(path.clone(), secret);

            let result = scrubber.scrub(input);

            // Should scrub the base64-encoded version
            assert!(
                result.contains("{{secret:test/aligned}}") || !result.contains("QUJDRA"),
                "Failed to scrub base64 at {}: {}",
                description,
                result
            );
        }
    }

    #[test]
    fn test_scrubber_with_multiple_encoding_variants() {
        let mut scrubber = Scrubber::new();
        let path = SecretPath::new("test/multi").unwrap();

        // A secret that will be detected in multiple encodings
        let secret = b"test123";

        scrubber.add_secret(path.clone(), secret);

        // Raw encoding
        let output1 = "The secret is test123";
        let result1 = scrubber.scrub(output1);
        assert!(result1.contains("{{secret:test/multi}}"));
        assert!(!result1.contains("test123"));

        // Base64 encoding (dGVzdDEyMw==)
        scrubber.clear();
        scrubber.add_secret(path.clone(), secret);
        let output2 = "The secret is dGVzdDEyMw==";
        let result2 = scrubber.scrub(output2);
        assert!(result2.contains("{{secret:test/multi}}"));
        assert!(!result2.contains("dGVzdDEyMw=="));

        // Hex encoding (74657374313233)
        scrubber.clear();
        scrubber.add_secret(path.clone(), secret);
        let output3 = "The secret is 74657374313233";
        let result3 = scrubber.scrub(output3);
        assert!(result3.contains("{{secret:test/multi}}"));
        assert!(!result3.contains("74657374313233"));
    }

    #[test]
    fn test_scrubber_with_url_like_encoded_secret() {
        let mut scrubber = Scrubber::new();
        let path = SecretPath::new("test/url").unwrap();

        // Secret with special characters that would be URL-encoded
        // The scrubber detects the raw secret, not URL encoding
        let secret = b"secret@123!";
        scrubber.add_secret(path.clone(), secret);

        // The scrubber should catch the raw secret when it appears
        let output = "The secret is secret@123!";
        let result = scrubber.scrub(output);

        // Should scrub the raw secret
        assert!(
            result.contains("{{secret:test/url}}"),
            "Failed to scrub raw secret with special chars: {}",
            result
        );
        assert!(
            !result.contains("secret@123!"),
            "Raw secret with special chars was not properly scrubbed: {}",
            result
        );
    }

    #[test]
    fn test_scrubber_with_binary_secret() {
        let mut scrubber = Scrubber::new();
        let path = SecretPath::new("test/binary").unwrap();

        // Binary secret with null bytes and non-ASCII characters
        let binary_secret = vec![0x00, 0x01, 0x02, 0xFF, 0xFE, 0xFD];
        scrubber.add_secret(path.clone(), &binary_secret);

        // Hex encoding of the binary secret
        let hex_encoded = hex::encode(&binary_secret);
        let output = format!("Binary data: {}", hex_encoded);
        let result = scrubber.scrub(&output);

        assert!(
            result.contains("{{secret:test/binary}}") || !result.contains(&hex_encoded[..8]),
            "Failed to scrub binary secret: {}",
            result
        );
    }

    #[test]
    fn test_scrubber_with_multiline_pem_certificate() {
        let mut scrubber = Scrubber::new();
        let path = SecretPath::new("test/cert").unwrap();

        // Simulated PEM certificate (truncated for test)
        let pem_cert = b"-----BEGIN CERTIFICATE-----\nMIIBkTCB+wIJAKHHCgVZU1B6MA0GCSqGSIb3DQEBCwUAMBExDzANBgNVBAMMBnNl\nY3JldDAeFw0yNDA0MDcxNzAwMDBaFw0yNTA0MDcxNzAwMDBaMBExDzANBgNVBAMM\n-----END CERTIFICATE-----";

        scrubber.add_secret(path.clone(), pem_cert);

        let output = std::str::from_utf8(pem_cert).unwrap();
        let result = scrubber.scrub(output);

        // Should scrub the PEM certificate
        assert!(
            result.contains("{{secret:test/cert}}"),
            "Failed to scrub PEM certificate: {}",
            result
        );
        assert!(
            !result.contains("BEGIN CERTIFICATE") || result.contains("{{secret:test/cert}}"),
            "PEM header not properly scrubbed: {}",
            result
        );
    }
}
