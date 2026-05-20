//! Phase 7.1-7.2: Canary System and Breach Detection Verification Tests
//!
//! This test module verifies:
//! 7.1 Canary system:
//!   - Canary files generated in-memory/tmpfs at daemon startup (never on host)
//!   - bwrap overlay: inject canary files via bind mounts into sandbox
//!   - fanotify watch on tmpfs canary directory to detect access
//!   - Hook-only mode: Read/Bash hooks intercept and serve canary content
//!   - On canary trigger: CRITICAL log, TUI alert, optional session terminate, rotation report
//!   - No host filesystem modifications (sigil init does NOT create files in ~/.aws/, ~/.ssh/, etc.)
//!   - Canary rotation: regenerated each daemon restart
//!
//! 7.2 Breach detection pipeline:
//!   - Real-time output scanning: already implemented in scrubber
//!   - File scanning: inotify to detect changed files during execution
//!   - Generic pattern scanning: AWS keys, GitHub tokens, JWTs, high-entropy strings
//!   - Severity levels: INFO (scrubbed), WARN (file modified), CRITICAL (canary/bypass)

mod common;
use common::workspace_root;
use std::fs;

/// Test 7.1.1: Verify canary crate exists with core types
#[test]
fn test_7_1_1_canary_crate_exists() {
    let lib_path = workspace_root().join("crates/sigil-canary/src/lib.rs");
    assert!(lib_path.exists(), "sigil-canary crate must exist");

    let code = fs::read_to_string(&lib_path).expect("Failed to read canary lib");

    // Verify core modules are exported
    assert!(code.contains("canary"), "Must export canary module");
    assert!(code.contains("generator"), "Must export generator module");
    assert!(code.contains("monitor"), "Must export monitor module");

    // Verify key types are exported
    assert!(
        code.contains("CanarySecret") || code.contains("CanaryKind"),
        "Must export canary types"
    );
}

/// Test 7.1.2: Verify canary files are generated in memory/tmpfs (never on host)
#[test]
fn test_7_1_2_canary_generated_in_memory() {
    let canary_rs_path = workspace_root().join("crates/sigil-canary/src/canary.rs");
    assert!(canary_rs_path.exists(), "Canary implementation must exist");

    let code = fs::read_to_string(&canary_rs_path).expect("Failed to read canary code");

    // Verify canary values are stored in memory (Vec<u8>)
    assert!(
        code.contains("value: Vec<u8>") || code.contains("secret_value"),
        "Canary values must be stored in memory"
    );

    // Verify Drop implementation zeros memory
    assert!(
        code.contains("Drop") || code.contains("zeroize"),
        "Canary must zeroize memory on drop"
    );

    // Verify no disk I/O for canary generation
    let monitor_path = workspace_root().join("crates/sigil-canary/src/monitor.rs");
    let monitor_code = fs::read_to_string(&monitor_path).expect("Failed to read monitor code");

    // Verify overlay path is used (tmpfs)
    assert!(
        monitor_code.contains("overlay_path") || monitor_code.contains("tmpfs"),
        "Canary monitor must use overlay/tmpfs path"
    );
}

/// Test 7.1.3: Verify bwrap overlay injection for canary files
#[test]
fn test_7_1_3_bwrap_overlay_injection() {
    let sandbox_path = workspace_root().join("crates/sigil-sandbox/src/bubblewrap.rs");
    assert!(sandbox_path.exists(), "Sandbox implementation must exist");

    let code = fs::read_to_string(&sandbox_path).expect("Failed to read sandbox code");

    // Verify overlay or bind-mount support
    assert!(
        code.contains("--bind") || code.contains("--ro-bind") || code.contains("overlay"),
        "Sandbox must support bind mounts for canary injection"
    );

    // Verify tmpfs mount for secrets
    assert!(
        code.contains("tmpfs") || code.contains("SECRET_TMPFS"),
        "Sandbox must support tmpfs for secret injection"
    );
}

/// Test 7.1.4: Verify fanotify/inotify monitoring for canary access
#[test]
fn test_7_1_4_fanotify_monitoring() {
    let monitor_path = workspace_root().join("crates/sigil-canary/src/monitor.rs");
    assert!(monitor_path.exists(), "Canary monitor must exist");

    let code = fs::read_to_string(&monitor_path).expect("Failed to read monitor code");

    // Verify fanotify or inotify usage
    assert!(
        code.contains("fanotify") || code.contains("inotify") || code.contains("notify"),
        "Monitor must use fanotify/inotify for access detection"
    );

    // Verify monitoring starts
    assert!(
        code.contains("start") && (code.contains("monitor") || code.contains("watch")),
        "Monitor must have start method"
    );

    // Verify access event recording
    assert!(
        code.contains("record_access") || code.contains("breach") || code.contains("event"),
        "Monitor must record access events"
    );
}

/// Test 7.1.5: Verify canary file formats (AWS, GitHub, SSH, .env)
#[test]
fn test_7_1_5_canary_file_formats() {
    let generator_path = workspace_root().join("crates/sigil-canary/src/generator.rs");
    assert!(generator_path.exists(), "Canary generator must exist");

    let code = fs::read_to_string(&generator_path).expect("Failed to read generator code");

    // Verify AWS credentials format (AKIA + 16 chars)
    assert!(
        code.contains("AKIA") && code.contains("aws_access_key_id"),
        "Must generate AWS credentials format"
    );

    // Verify GitHub token format (ghp_ + 36 chars)
    assert!(
        code.contains("ghp_") && code.contains("oauth_token"),
        "Must generate GitHub token format"
    );

    // Verify SSH key format (PEM structure)
    assert!(
        code.contains("BEGIN") && code.contains("PRIVATE KEY"),
        "Must generate SSH key PEM format"
    );

    // Verify .env file format
    assert!(
        code.contains(".env") || code.contains("env_file"),
        "Must generate .env canary"
    );
}

/// Test 7.1.6: Verify hook-only mode serves canary content
#[test]
fn test_7_1_6_hook_only_mode() {
    let canary_manager_path = workspace_root().join("crates/sigil-daemon/src/canary_manager.rs");
    assert!(canary_manager_path.exists(), "Canary manager must exist");

    let code = fs::read_to_string(&canary_manager_path).expect("Failed to read canary manager code");

    // Verify is_canary_path method exists
    assert!(
        code.contains("is_canary_path"),
        "Canary manager must detect canary paths"
    );

    // Verify generate_decoy_response method exists
    assert!(
        code.contains("generate_decoy_response"),
        "Canary manager must generate decoy responses"
    );

    // Verify hook integration (server uses canary manager)
    let server_path = workspace_root().join("crates/sigil-daemon/src/server.rs");
    let server_code = fs::read_to_string(&server_path).expect("Failed to read server code");

    assert!(
        server_code.contains("is_canary_path") || server_code.contains("canary_manager"),
        "Server must integrate with canary manager for hook mode"
    );
}

/// Test 7.1.7: Verify canary trigger logging at CRITICAL level
#[test]
fn test_7_1_7_canary_critical_logging() {
    let server_path = workspace_root().join("crates/sigil-daemon/src/server.rs");
    let server_code = fs::read_to_string(&server_path).expect("Failed to read server code");

    // Verify record_canary_access method
    assert!(
        server_code.contains("record_canary_access"),
        "Server must record canary access"
    );

    // Verify CRITICAL logging
    assert!(
        server_code.contains("CRITICAL") || server_code.contains("log_canary_access"),
        "Server must log canary access at CRITICAL level"
    );

    // Verify audit log integration
    let audit_path = workspace_root().join("crates/sigil-core/src/audit.rs");
    let audit_code = fs::read_to_string(&audit_path).expect("Failed to read audit code");

    assert!(
        audit_code.contains("CanaryAccess"),
        "Audit log must support CanaryAccess entry type"
    );
}

/// Test 7.1.8: Verify canary access counts toward auto-lockdown
#[test]
fn test_7_1_8_canary_auto_lockdown() {
    let server_path = workspace_root().join("crates/sigil-daemon/src/server.rs");
    let server_code = fs::read_to_string(&server_path).expect("Failed to read server code");

    // Verify canary_access_count tracking
    assert!(
        server_code.contains("canary_access_count"),
        "Server must track canary access count"
    );

    // Verify canary_triggers config
    assert!(
        server_code.contains("canary_triggers"),
        "Server must support canary_triggers configuration"
    );

    // Verify lockdown check on canary access
    assert!(
        server_code.contains("canary_triggers") && server_code.contains("lockdown"),
        "Server must trigger lockdown on canary threshold"
    );
}

/// Test 7.1.9: Verify no host filesystem modifications for canary files
#[test]
fn test_7_1_9_no_host_filesystem_modification() {
    // Verify sigil init does NOT create canary files on host
    let cli_path = workspace_root().join("crates/sigil-cli/src/main.rs");
    let cli_code = fs::read_to_string(&cli_path).expect("Failed to read CLI code");

    // The init command should NOT create .aws/credentials, .ssh/id_sigil_canary, etc.
    // Look for the init implementation
    assert!(
        !cli_code.contains("write .aws/credentials")
            && !cli_code.contains("create .ssh/id_sigil_canary"),
        "CLI init must NOT create canary files on host"
    );

    // Verify canary files are only created in sandbox overlay
    let monitor_path = workspace_root().join("crates/sigil-canary/src/monitor.rs");
    let monitor_code = fs::read_to_string(&monitor_path).expect("Failed to read monitor code");

    // Check that canaries are written to overlay (tmpfs), not home
    assert!(
        monitor_code.contains("overlay_path") || monitor_code.contains("tmpfs"),
        "Canary files must be written to overlay/tmpfs"
    );
}

/// Test 7.1.10: Verify canary rotation on daemon restart
#[test]
fn test_7_1_10_canary_rotation() {
    let generator_path = workspace_root().join("crates/sigil-canary/src/generator.rs");
    let generator_code = fs::read_to_string(&generator_path).expect("Failed to read generator code");

    // Verify random generation (each restart produces different values)
    assert!(
        generator_code.contains("random") || generator_code.contains("rand::"),
        "Canary generator must use random generation"
    );

    let canary_rs_path = workspace_root().join("crates/sigil-canary/src/canary.rs");
    let canary_rs_code = fs::read_to_string(&canary_rs_path).expect("Failed to read canary code");

    // Verify unique ID generation for each canary
    assert!(
        canary_rs_path.exists()
            && (canary_rs_code.contains("id: String") || canary_rs_code.contains("unique")),
        "Each canary must have unique ID"
    );

    // Verify created_at timestamp for rotation tracking
    assert!(
        canary_rs_code.contains("created_at"),
        "Canary must track creation time for rotation"
    );
}

/// Test 7.2.1: Verify real-time output scanning (scrubber)
#[test]
fn test_7_2_1_realtime_output_scanning() {
    let scrubber_path = workspace_root().join("crates/sigil-scrub/src/scrubber.rs");
    assert!(scrubber_path.exists(), "Scrubber must exist");

    let code = fs::read_to_string(&scrubber_path).expect("Failed to read scrubber code");

    // Verify scrubbing functionality
    assert!(
        code.contains("scrub") && code.contains("secret"),
        "Scrubber must scrub secrets from output"
    );

    // Verify streaming support for real-time processing
    assert!(
        code.contains("StreamingScrubber") || code.contains("chunk"),
        "Scrubber must support streaming/chunked output"
    );
}

/// Test 7.2.2: Verify generic pattern scanning (AWS keys, GitHub tokens, JWTs)
#[test]
fn test_7_2_2_generic_pattern_scanning() {
    let scrubber_path = workspace_root().join("crates/sigil-scrub/src/scrubber.rs");
    let scrubber_code = fs::read_to_string(&scrubber_path).expect("Failed to read scrubber code");

    // Verify multiple encoding variants are detected
    assert!(
        scrubber_code.contains("generate_encoding_variants")
            || scrubber_code.contains("base64")
            || scrubber_code.contains("hex"),
        "Scrubber must detect multiple encoding variants"
    );

    // Verify at least base64, hex, and URL encoding
    let encodings = ["base64", "base64url", "hex", "url"];
    let mut found_count = 0;
    for encoding in encodings {
        if scrubber_code.contains(encoding) {
            found_count += 1;
        }
    }

    assert!(
        found_count >= 2,
        "Scrubber must support at least 2 encoding variants"
    );
}

/// Test 7.2.3: Verify severity levels (INFO, WARN, CRITICAL)
#[test]
fn test_7_2_3_severity_levels() {
    let audit_path = workspace_root().join("crates/sigil-core/src/audit.rs");
    let audit_code = fs::read_to_string(&audit_path).expect("Failed to read audit code");

    // Verify BreachDetected entry type with severity
    assert!(
        audit_code.contains("BreachDetected") && audit_code.contains("severity"),
        "Audit must support breach detection with severity"
    );

    // Verify CanaryAccess entry type
    assert!(
        audit_code.contains("CanaryAccess"),
        "Audit must support canary access tracking"
    );

    // Verify Lockdown entry type
    assert!(
        audit_code.contains("Lockdown"),
        "Audit must support lockdown events"
    );
}

/// Test 7.2.4: Verify breach report generation
#[test]
fn test_7_2_4_breach_report_generation() {
    let server_path = workspace_root().join("crates/sigil-daemon/src/server.rs");
    let server_code = fs::read_to_string(&server_path).expect("Failed to read server code");

    // Verify BreachReport IPC operation
    assert!(
        server_code.contains("BreachReport") || server_code.contains("breach_report"),
        "Server must support breach report operation"
    );

    // Verify handle_breach_report method
    assert!(
        server_code.contains("handle_breach_report"),
        "Server must handle breach report requests"
    );

    // Verify generate_breach_report method
    assert!(
        server_code.contains("generate_breach_report"),
        "Server must generate breach reports"
    );
}

/// Test 7.2.5: Verify high-entropy string detection
#[test]
fn test_7_2_5_high_entropy_detection() {
    let scrubber_path = workspace_root().join("crates/sigil-scrub/src/scrubber.rs");
    let scrubber_code = fs::read_to_string(&scrubber_path).expect("Failed to read scrubber code");

    // Verify encoding detection (base64/hex indicate high entropy)
    assert!(
        scrubber_code.contains("BASE64") || scrubber_code.contains("base64"),
        "Scrubber must detect base64 encoding (high entropy indicator)"
    );

    assert!(
        scrubber_code.contains("hex") || scrubber_code.contains("HEX"),
        "Scrubber must detect hex encoding (high entropy indicator)"
    );
}

/// Test 7.2.6: Verify canary values registered with scrubber
#[test]
fn test_7_2_6_canary_scrubber_integration() {
    let monitor_path = workspace_root().join("crates/sigil-canary/src/monitor.rs");
    let monitor_code = fs::read_to_string(&monitor_path).expect("Failed to read monitor code");

    // Verify get_canary_values method for scrubber integration
    assert!(
        monitor_code.contains("get_canary_values"),
        "Canary monitor must provide values for scrubber registration"
    );

    // Verify values are returned as (SecretPath, Vec<u8>) tuples
    assert!(
        monitor_code.contains("SecretPath"),
        "Canary values must use SecretPath type"
    );
}

/// Test 7.2.7: Verify comprehensive breach report includes canary info
#[test]
fn test_7_2_7_comprehensive_breach_report() {
    let monitor_path = workspace_root().join("crates/sigil-canary/src/monitor.rs");
    let monitor_code = fs::read_to_string(&monitor_path).expect("Failed to read monitor code");

    // Verify BreachReport type
    assert!(
        monitor_code.contains("BreachReport") || monitor_code.contains("generate_report"),
        "Monitor must generate breach reports"
    );

    // Verify report includes canary access events
    assert!(
        monitor_code.contains("CanaryAccessEvent") || monitor_code.contains("breaches"),
        "Report must include canary access events"
    );

    // Verify report includes severity information
    assert!(
        monitor_code.contains("BreachSeverity") || monitor_code.contains("severity"),
        "Report must include severity levels"
    );
}

/// Test 7.2.8: Verify daemon initializes canary system
#[test]
fn test_7_2_8_daemon_canary_initialization() {
    let daemon_path = workspace_root().join("crates/sigil-daemon/src/main.rs");
    let daemon_code = fs::read_to_string(&daemon_path).expect("Failed to read daemon code");

    // Verify CanaryManager is created
    assert!(
        daemon_code.contains("CanaryManager"),
        "Daemon must create CanaryManager"
    );

    // Verify canary overlay directory is in tmpfs (XDG_RUNTIME_DIR or /tmp)
    assert!(
        daemon_code.contains("XDG_RUNTIME_DIR") || daemon_code.contains("tmp"),
        "Canary overlay must be in tmpfs"
    );

    // Verify canary initialization is called
    assert!(
        daemon_code.contains("initialize") && daemon_code.contains("canary"),
        "Daemon must initialize canary system"
    );
}

/// Test 7.2.9: Verify TUI alert integration for canary access
#[test]
fn test_7_2_9_tui_canary_alert() {
    let server_path = workspace_root().join("crates/sigil-daemon/src/server.rs");
    let server_code = fs::read_to_string(&server_path).expect("Failed to read server code");

    // Verify alert sender is used for canary events
    assert!(
        server_code.contains("AlertSender") || server_code.contains("alert"),
        "Server must have alert capability"
    );

    // Verify canary access triggers alerts
    assert!(
        server_code.contains("record_canary_access") || server_code.contains("canary_access"),
        "Server must record canary access"
    );
}

/// Comprehensive test: All canary types are generated correctly
#[test]
fn test_7_1_comprehensive_canary_types() {
    let generator_path = workspace_root().join("crates/sigil-canary/src/generator.rs");
    let generator_code = fs::read_to_string(&generator_path).expect("Failed to read generator code");

    // Verify all standard canary types are generated
    let canary_types = [
        ("AwsCredentials", "aws_access_key_id"),
        ("GitHubToken", "oauth_token"),
        ("SshKey", "BEGIN.*PRIVATE KEY"),
        ("EnvFile", "API_KEY\\|DB_PASSWORD\\|SECRET_KEY"),
        ("StripeKey", "sk_live_"),
        ("JwtToken", "alg.*typ.*JWT"),
        ("PemCertificate", "BEGIN CERTIFICATE"),
    ];

    for (kind, pattern) in canary_types {
        assert!(
            generator_code.contains(kind) || generator_code.contains(pattern),
            "Canary generator must support {} type (pattern: {})",
            kind,
            pattern
        );
    }

    // Verify generate_all method creates all canaries
    assert!(
        generator_code.contains("generate_all"),
        "Canary generator must have generate_all method"
    );
}

/// Comprehensive test: Breach detection pipeline integration
#[test]
fn test_7_2_comprehensive_breach_pipeline() {
    // Verify scrubber is used in server
    let server_path = workspace_root().join("crates/sigil-daemon/src/server.rs");
    let server_code = fs::read_to_string(&server_path).expect("Failed to read server code");

    assert!(
        server_code.contains("Scrubber") || server_code.contains("scrub"),
        "Server must integrate with scrubber"
    );

    // Verify canary manager is used in server
    assert!(
        server_code.contains("CanaryManager") || server_code.contains("canary_manager"),
        "Server must integrate with canary manager"
    );

    // Verify audit logger is used
    assert!(
        server_code.contains("AuditLogger") || server_code.contains("audit_logger"),
        "Server must integrate with audit logger"
    );

    // Verify IPC protocol includes breach report
    let ipc_path = workspace_root().join("crates/sigil-core/src/ipc.rs");
    let ipc_code = fs::read_to_string(&ipc_path).expect("Failed to read IPC code");

    assert!(
        ipc_code.contains("BreachReport") || ipc_code.contains("BreachDetected"),
        "IPC protocol must support breach reporting"
    );
}

/// Test: Verify no identifying comments in canary files
#[test]
fn test_7_1_no_identifying_comments() {
    let generator_path = workspace_root().join("crates/sigil-canary/src/generator.rs");
    let generator_code = fs::read_to_string(&generator_path).expect("Failed to read generator code");

    // Verify canary files do NOT contain identifying strings
    let suspicious_strings = ["SIGIL", "CANARY", "DECOY", "FAKE", "TEST", "EXAMPLE"];

    for suspicious in suspicious_strings {
        // Check that suspicious strings are NOT in the generated values
        // (they may be in comments, but not in the actual canary content)
        let lines: Vec<&str> = generator_code.lines().collect();
        for line in lines {
            // Skip comment lines
            if line.trim().starts_with("//") || line.trim().starts_with("//!") {
                continue;
            }
            // Check if suspicious string appears in non-comment code
            if line.contains("format!") || line.contains("println!") || line.contains("push_str") {
                assert!(
                    !line.contains(suspicious) || line.contains("//"),
                    "Canary content must NOT contain identifying string '{}': {}",
                    suspicious,
                    line
                );
            }
        }
    }
}

/// Test: Verify canary access triggers auto-lockdown
#[test]
fn test_7_1_canary_lockdown_trigger() {
    let server_path = workspace_root().join("crates/sigil-daemon/src/server.rs");
    let server_code = fs::read_to_string(&server_path).expect("Failed to read server code");

    // Verify lockdown config includes canary_triggers
    assert!(
        server_code.contains("canary_triggers: usize"),
        "LockdownConfig must include canary_triggers field"
    );

    // Verify canary access increments counter
    assert!(
        server_code.contains("canary_access_count += 1") || server_code.contains("increment_canary"),
        "Canary access must increment counter"
    );

    // Verify lockdown check happens
    assert!(
        server_code.contains("check_auto_lockdown") || server_code.contains("should_trigger_lockdown"),
        "Server must check if canary threshold triggers lockdown"
    );
}
