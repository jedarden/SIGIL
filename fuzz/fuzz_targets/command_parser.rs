#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Convert bytes to string, handling invalid UTF-8 gracefully
    let input = String::from_utf8_lossy(data);

    // Test 1: extract_placeholders should not panic on any input
    let _ = sigil_core::parser::CommandParser::extract_placeholders(&input);

    // Test 2: resolve_command should not panic on any input
    let _ = sigil_core::parser::CommandParser::resolve_command(&input);

    // Test 3: validate_command should not panic on any input
    let _ = sigil_core::parser::CommandParser::validate_command(&input);

    // Test 4: Verify no secret values leak in error messages
    // If parsing/resolve fails, check the error message doesn't contain potential secrets
    if let Err(e) = sigil_core::parser::CommandParser::extract_placeholders(&input) {
        let error_msg = e.to_string();
        // Error messages should not contain the raw input (which might contain secrets)
        // Check that error message is sanitized and doesn't echo large portions of input
        let safe_prefix = input.chars().take(50).collect::<String>();
        assert!(
            error_msg.len() < 200 || !error_msg.contains(&safe_prefix),
            "Error message potentially leaks input: error={}, input={}",
            error_msg,
            safe_prefix
        );
    }

    // Test 5: Adversarial input patterns - nested quotes
    // Safely truncate to character boundary
    let safe_prefix = input.chars().take(20).collect::<String>();
    let adversarial_patterns = vec![
        format!("echo '{{secret:{}}}'", safe_prefix),
        format!("echo \"{{secret:{}}}\"", safe_prefix),
        format!("echo '{{secret:{}}}' | cat", safe_prefix),
    ];

    for pattern in adversarial_patterns {
        let _ = sigil_core::parser::CommandParser::extract_placeholders(&pattern);
        let _ = sigil_core::parser::CommandParser::resolve_command(&pattern);
    }

    // Test 6: Verify resolved command structure is consistent
    if let Ok(resolved) = sigil_core::parser::CommandParser::resolve_command(&input) {
        // If we have placeholders, verify structure consistency
        if !resolved.placeholders.is_empty() {
            // All placeholders should have valid positions
            for placeholder in &resolved.placeholders {
                assert!(placeholder.position.0 < placeholder.position.1);
                assert!(placeholder.position.1 <= input.len());
            }

            // Verify secret paths are non-empty
            for path in resolved.secret_paths() {
                assert!(!path.is_empty());
            }
        }
    }

    // Note: sanitize_env_name and sanitize_path are private functions,
    // they are tested indirectly through resolve_command
});
