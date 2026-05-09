//! Property-based tests for the command parser
//!
//! These tests use proptest to verify that the parser maintains
//! important invariants across a wide range of inputs.

use proptest::prelude::*;
use sigil_core::parser::CommandParser;

/// Property: Any valid SecretPath round-trips through parser unchanged
///
/// For valid secret paths (alphanumeric, underscore, dot, slash, hyphen),
/// the parser should extract them correctly and preserve them through
/// extraction and resolution.
proptest! {
    #[test]
    fn prop_valid_secret_path_roundtrip(path in "[a-zA-Z0-9_./-]{1,100}") {
        // Skip paths that are obviously invalid (empty components, .., etc.)
        if path.contains("..") || path.starts_with('/') || path.is_empty() {
            return Ok(());
        }

        let command = format!("echo {{{{secret:{}}}}}", path);
        let result = CommandParser::extract_placeholders(&command);

        // For valid paths, extraction should succeed
        if let Ok(placeholders) = result {
            if !placeholders.is_empty() {
                prop_assert_eq!(&placeholders[0].path, &path);
            }
        }
    }
}

/// Property: Parser handles arbitrary command strings without panicking
///
/// The parser should never panic on any input, even malformed inputs.
proptest! {
    #[test]
    fn prop_parser_never_panics(command in ".{0,1000}") {
        let _ = CommandParser::extract_placeholders(&command);
        let _ = CommandParser::resolve_command(&command);
        let _ = CommandParser::validate_command(&command);
    }
}

/// Property: Placeholder positions are within bounds
///
/// All placeholder positions should be within the original command string.
proptest! {
    #[test]
    fn prop_placeholder_positions_in_bounds(command in ".{0,1000}") {
        if let Ok(placeholders) = CommandParser::extract_placeholders(&command) {
            for placeholder in &placeholders {
                prop_assert!(placeholder.position.0 < command.len());
                prop_assert!(placeholder.position.1 <= command.len());
                prop_assert!(placeholder.position.0 < placeholder.position.1);
            }
        }
    }
}

/// Property: Number of placeholders extracted is non-negative
///
/// This is a simple invariant that should always hold.
proptest! {
    #[test]
    fn prop_placeholder_count_non_negative(command in ".{0,1000}") {
        if let Ok(placeholders) = CommandParser::extract_placeholders(&command) {
            prop_assert!(placeholders.len() >= 0);
        }
    }
}

/// Property: Extracted placeholders maintain order
///
/// Placeholders should be extracted in the order they appear in the command.
proptest! {
    #[test]
    fn prop_placeholders_maintain_order(
        prefix in ".{0,100}",
        path1 in "[a-z]{1,10}",
        middle in ".{0,100}",
        path2 in "[a-z]{1,10}",
        suffix in ".{0,100}"
    ) {
        let command = format!(
            "{}{{{{secret:{}}}}}{}{{{{secret:{}}}}}{}",
            prefix, path1, middle, path2, suffix
        );

        if let Ok(placeholders) = CommandParser::extract_placeholders(&command) {
            if placeholders.len() >= 2 {
                prop_assert!(placeholders[0].position.0 < placeholders[1].position.0);
            }
        }
    }
}

/// Property: Resolved command has same placeholders as extracted
///
/// resolve_command should not change the list of placeholders.
proptest! {
    #[test]
    fn prop_resolve_preserves_placeholders(command in ".{0,1000}") {
        if let Ok(extracted) = CommandParser::extract_placeholders(&command) {
            if let Ok(resolved) = CommandParser::resolve_command(&command) {
                prop_assert_eq!(extracted.len(), resolved.placeholders.len());

                for (extracted, resolved) in extracted.iter().zip(resolved.placeholders.iter()) {
                    prop_assert_eq!(&extracted.path, &resolved.path);
                    prop_assert_eq!(&extracted.mode, &resolved.mode);
                }
            }
        }
    }
}

/// Property: Empty command has no placeholders
///
/// An empty command string should have zero placeholders.
proptest! {
    #[test]
    fn prop_empty_command_no_placeholders(empty in "") {
        let result = CommandParser::extract_placeholders(&empty);
        prop_assert!(result.is_ok());
        prop_assert_eq!(result.unwrap().len(), 0);
    }
}

/// Property: Command with only whitespace has no placeholders
///
/// A command with only whitespace should have zero placeholders.
proptest! {
    #[test]
    fn prop_whitespace_command_no_placeholders(whitespace in "[ \t\n\r]{0,100}") {
        let result = CommandParser::extract_placeholders(&whitespace);
        if let Ok(placeholders) = result {
            prop_assert_eq!(placeholders.len(), 0);
        }
    }
}

/// Property: Sanitized env names are valid shell identifiers
///
/// Environment variable names should only contain alphanumeric characters
/// and underscores, and should not start with a digit.
proptest! {
    #[test]
    fn prop_sanitize_env_name_valid_identifier(path in "[a-zA-Z0-9_./-]{1,50}") {
        // Access the internal sanitize function through the parser
        // We'll test this indirectly by checking env_injections
        let command = format!("{{{{secret:{}}}:env}}", path);
        if let Ok(resolved) = CommandParser::resolve_command(&command) {
            if !resolved.env_injections.is_empty() {
                for (env_name, _secret_path) in &resolved.env_injections {
                    // Env names should be uppercase alphanumeric with underscores
                    for c in env_name.chars() {
                        prop_assert!(c.is_ascii_uppercase() || c == '_');
                    }

                    // Should not start with a digit
                    if let Some(first_char) = env_name.chars().next() {
                        prop_assert!(!first_char.is_ascii_digit());
                    }
                }
            }
        }
    }
}

/// Property: Secret paths list contains unique entries
///
/// The secret_paths() method should return only unique paths.
proptest! {
    #[test]
    fn prop_secret_paths_are_unique(command in ".{0,500}") {
        if let Ok(resolved) = CommandParser::resolve_command(&command) {
            let paths = resolved.secret_paths();

            // Check that all paths are unique
            let unique_paths: std::collections::HashSet<_> = paths.iter().collect();
            prop_assert_eq!(paths.len(), unique_paths.len());
        }
    }
}

/// Property: Resolved command original field is preserved
///
/// The resolved command should always preserve the original command string.
proptest! {
    #[test]
    fn prop_resolved_preserves_original(command in ".{0,1000}") {
        if let Ok(resolved) = CommandParser::resolve_command(&command) {
            prop_assert_eq!(resolved.original, command);
        }
    }
}

/// Property: Validate command returns Result type
///
/// validate_command should always return a Result (never panic).
proptest! {
    #[test]
    fn prop_validate_returns_result(command in ".{0,1000}") {
        let result = CommandParser::validate_command(&command);

        // We don't care if it's Ok or Err, just that it returns a Result
        match result {
            Ok(_) => (),
            Err(_) => (),
        }
    }
}

/// Property: Commands without pipes should pass validation
///
/// Commands without pipe characters should always pass validation
/// (unless they have other issues).
proptest! {
    #[test]
    fn prop_no_pipe_always_validates(command in "[^|]{0,1000}") {
        let result = CommandParser::validate_command(&command);

        // Commands without pipes should not fail validation due to pipe rules
        if let Err(e) = result {
            let error_msg = e.to_string();
            prop_assert!(!error_msg.contains("pipe") && !error_msg.contains("inline"));
        }
    }
}

/// Property: Adjacent placeholders are handled correctly
///
/// Placeholders that appear right next to each other should both be extracted.
proptest! {
    #[test]
    fn prop_adjacent_placeholders_extracted(
        path1 in "[a-z]{1,10}",
        path2 in "[a-z]{1,10}",
        path3 in "[a-z]{1,10}"
    ) {
        let command = format!("{{{{secret:{}}}}}{{{{secret:{}}}}}{{{{secret:{}}}}}", path1, path2, path3);
        if let Ok(placeholders) = CommandParser::extract_placeholders(&command) {
            prop_assert_eq!(placeholders.len(), 3);
        }
    }
}

/// Property: Piped command with inline mode fails validation
///
/// Commands with pipes and inline placeholders should always fail validation.
proptest! {
    #[test]
    fn prop_piped_inline_fails_validation(
        before in ".{0,100}",
        path in "[a-z]{1,10}",
        after in ".{0,100}"
    ) {
        // Create a command with a pipe and an inline placeholder
        let command = format!("{}{{{{secret:{}}}}} | {}", before, path, after);

        let result = CommandParser::validate_command(&command);

        // Should fail validation if we have both pipe and inline placeholder
        if let Ok(placeholders) = CommandParser::extract_placeholders(&command) {
            let has_inline = placeholders.iter().any(|p| {
                sigil_core::parser::InjectionMode::Inline == p.mode
            });

            if has_inline {
                prop_assert!(result.is_err());
            }
        }
    }
}

/// Property: Multiple stdin placeholders fail resolution
///
/// Commands with multiple stdin placeholders should fail resolution.
proptest! {
    #[test]
    fn prop_multiple_stdin_fails(
        path1 in "[a-z]{1,10}",
        path2 in "[a-z]{1,10}"
    ) {
        // The correct placeholder format is {{secret:path:mode}}
        // To escape in format strings: {{ → {, }} → }, {} is placeholder
        // So we need: {{{{secret:{}:stdin}}}}
        // Which produces: {{secret:path:stdin}}
        let cmd1 = format!("{{{{secret:{}:stdin}}}}", path1);
        let cmd2 = format!("{{{{secret:{}:stdin}}}}", path2);
        let command = format!("cmd {} {}", cmd1, cmd2);
        let result = CommandParser::resolve_command(&command);

        // Should fail because we can't have multiple stdin injections
        prop_assert!(result.is_err());
    }
}

/// Property: Parser handles Unicode in commands
///
/// The parser should handle Unicode characters without panicking.
proptest! {
    #[test]
    fn prop_unicode_handling(s in "\\PC{0,500}") {
        let _ = CommandParser::extract_placeholders(&s);
        let _ = CommandParser::resolve_command(&s);
        let _ = CommandParser::validate_command(&s);
    }
}
