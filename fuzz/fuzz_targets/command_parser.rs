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

    // Note: sanitize_env_name and sanitize_path are private functions,
    // they are tested indirectly through resolve_command
});
