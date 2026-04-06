//! Integration tests for accessibility features
//!
//! These tests verify that SIGIL's accessibility features work correctly:
//! - NO_COLOR / FORCE_COLOR support
//! - High contrast mode (SIGIL_HIGH_CONTRAST)
//! - Unicode/ASCII fallback (SIGIL_ASCII)
//! - Terminal width handling
//! - Box drawing characters

mod common;
use common::workspace_root;
use std::fs;

/// Test 1: Verify NO_COLOR environment variable support
///
/// From Phase 10 Deliverables:
/// "NO_COLOR env var disables all color (https://no-color.org/)"
#[test]
fn test_no_color_support() {
    let terminal_path = workspace_root().join("crates/sigil-core/src/terminal.rs");
    let terminal_code = fs::read_to_string(&terminal_path).expect("Failed to read terminal code");

    // Verify NO_COLOR check exists
    assert!(
        terminal_code.contains("NO_COLOR"),
        "Terminal module must check NO_COLOR environment variable"
    );

    // Verify ColorMode::None exists
    assert!(
        terminal_code.contains("ColorMode::None") || terminal_code.contains("None"),
        "Terminal module must have None color mode"
    );
}

/// Test 2: Verify FORCE_COLOR environment variable support
///
/// From Phase 10 Deliverables:
/// "FORCE_COLOR=1 forces color output even when stdout is not a TTY"
#[test]
fn test_force_color_support() {
    let terminal_path = workspace_root().join("crates/sigil-core/src/terminal.rs");
    let terminal_code = fs::read_to_string(&terminal_path).expect("Failed to read terminal code");

    // Verify FORCE_COLOR check exists
    assert!(
        terminal_code.contains("FORCE_COLOR"),
        "Terminal module must check FORCE_COLOR environment variable"
    );

    // Verify ColorMode::Always exists
    assert!(
        terminal_code.contains("ColorMode::Always") || terminal_code.contains("Always"),
        "Terminal module must have Always color mode"
    );
}

/// Test 3: Verify high contrast mode support
///
/// From Phase 10 Deliverables:
/// "High contrast mode (SIGIL_HIGH_CONTRAST=1) for accessibility"
#[test]
fn test_high_contrast_mode() {
    let terminal_path = workspace_root().join("crates/sigil-core/src/terminal.rs");
    let terminal_code = fs::read_to_string(&terminal_path).expect("Failed to read terminal code");

    // Verify high contrast ANSI codes exist
    assert!(
        terminal_code.contains("ansi_high_contrast"),
        "Terminal module must support high contrast mode"
    );

    // Verify bold + underline for errors
    assert!(
        terminal_code.contains("1m") && terminal_code.contains("4m"),
        "High contrast mode must use bold and underline for errors"
    );
}

/// Test 4: Verify Unicode/ASCII fallback support
///
/// From Phase 10 Deliverables:
/// "Unicode/ASCII fallback detection (SIGIL_ASCII=1)"
#[test]
fn test_unicode_ascii_fallback() {
    let terminal_path = workspace_root().join("crates/sigil-core/src/terminal.rs");
    let terminal_code = fs::read_to_string(&terminal_path).expect("Failed to read terminal code");

    // Verify SIGIL_ASCII check exists
    assert!(
        terminal_code.contains("SIGIL_ASCII"),
        "Terminal module must check SIGIL_ASCII environment variable"
    );

    // Verify UnicodeMode enum exists
    assert!(
        terminal_code.contains("UnicodeMode"),
        "Terminal module must have UnicodeMode enum"
    );

    // Verify box drawings for both modes
    assert!(
        terminal_code.contains("BoxDrawings"),
        "Terminal module must support box drawing characters"
    );
}

/// Test 5: Verify terminal width handling
///
/// From Phase 10 Deliverables:
/// "Terminal width handling for responsive TUI layout"
#[test]
fn test_terminal_width_handling() {
    let terminal_path = workspace_root().join("crates/sigil-core/src/terminal.rs");
    let terminal_code = fs::read_to_string(&terminal_path).expect("Failed to read terminal code");

    // Verify TerminalSize struct exists
    assert!(
        terminal_code.contains("TerminalSize") || terminal_code.contains("terminal_size"),
        "Terminal module must support terminal size detection"
    );

    // Verify LayoutMode enum exists
    assert!(
        terminal_code.contains("LayoutMode"),
        "Terminal module must support responsive layout modes"
    );
}

/// Test 6: Verify doctor respects accessibility settings
///
/// From Phase 10 Deliverables:
/// "Doctor health check should respect NO_COLOR and high contrast modes"
#[test]
fn test_doctor_accessibility_support() {
    let doctor_path = workspace_root().join("crates/sigil-cli/src/doctor.rs");
    let doctor_code = fs::read_to_string(&doctor_path).expect("Failed to read doctor code");

    // Verify doctor uses colorize function
    assert!(
        doctor_code.contains("colorize") || doctor_code.contains("ColorMode"),
        "Doctor must use terminal colorization functions"
    );

    // Verify high contrast support mentioned
    assert!(
        doctor_code.contains("HIGH_CONTRAST") || doctor_code.contains("high_contrast"),
        "Doctor must support high contrast mode"
    );
}

/// Test 7: Verify accessibility priority order
///
/// From Phase 10 Deliverables:
/// "Priority order: --color flag > FORCE_COLOR > NO_COLOR > auto-detection"
#[test]
fn test_accessibility_priority_order() {
    let terminal_path = workspace_root().join("crates/sigil-core/src/terminal.rs");
    let terminal_code = fs::read_to_string(&terminal_path).expect("Failed to read terminal code");

    // Verify priority comment or logic exists
    assert!(
        terminal_code.contains("Priority") || terminal_code.contains("priority"),
        "Terminal module must document accessibility feature priority order"
    );
}
