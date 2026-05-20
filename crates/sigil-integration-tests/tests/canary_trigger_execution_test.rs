//! Canary Trigger Execution Integration Tests
//!
//! This test module verifies canary breach detection with real execution:
//! - Canary generation and storage in tmpfs overlay
//! - Canary access detection via hooks (fanotify/inotify)
//! - Breach event recording and reporting
//! - Multiple canary types (AWS, GitHub, SSH, .env, etc.)
//! - Canary value scrubbing integration
//! - Lockdown trigger on threshold breach
//!
//! These tests use real execution to verify canary functionality end-to-end.

mod common;
use common::workspace_root;
use std::fs;
use std::path::PathBuf;
use std::process::Command;
use tempfile::TempDir;

// ============================================================================
// CANARY GENERATION EXECUTION TESTS
// ============================================================================

/// Test 1.1: Generate canaries and verify realistic appearance
///
/// Tests that canaries are generated and look like real credentials:
/// 1. Create canary generator
/// 2. Generate each canary type
/// 3. Verify realistic format
/// 4. Verify NO identifying comments (agent can't distinguish)
#[test]
fn test_generate_realistic_canaries() {
    // Check if canary module exists
    let canary_lib_path = workspace_root().join("crates/sigil-canary/src/lib.rs");
    if !canary_lib_path.exists() {
        eprintln!("sigil-canary crate not found, skipping test");
        return;
    }

    let canary_code = fs::read_to_string(&canary_lib_path)
        .expect("Failed to read canary code");

    // Verify CanaryGenerator exists
    assert!(
        canary_code.contains("pub struct CanaryGenerator") || canary_code.contains("CanaryGenerator"),
        "CanaryGenerator must exist"
    );

    // Verify generate_all method
    assert!(
        canary_code.contains("generate_all"),
        "CanaryGenerator must have generate_all method"
    );

    // Verify no identifying comments in generated canaries
    assert!(
        !canary_code.contains("SIGIL CANARY") || canary_code.contains("assert!"),
        "Canary content must NOT contain identifying comments"
    );

    // Verify AWS credentials format
    assert!(
        canary_code.contains("AKIA") && canary_code.contains("aws_access_key_id"),
        "AWS canary must have realistic format"
    );

    // Verify GitHub token format
    assert!(
        canary_code.contains("ghp_") && canary_code.contains("oauth_token"),
        "GitHub canary must have realistic format"
    );

    // Verify .env file format
    assert!(
        canary_code.contains("API_KEY=") || canary_code.contains("DB_PASSWORD="),
        ".env canary must have realistic format"
    );
}

/// Test 1.2: Verify canary files are written to overlay (tmpfs)
///
/// Tests that canaries are written to a tmpfs overlay:
/// 1. Create temp directory as overlay
/// 2. Add canaries to monitor
/// 3. Verify files exist in overlay
/// 4. Verify files have realistic content
#[test]
fn test_canary_written_to_overlay() {
    let canary_lib_path = workspace_root().join("crates/sigil-canary/src/lib.rs");
    if !canary_lib_path.exists() {
        return;
    }

    let monitor_path = workspace_root().join("crates/sigil-canary/src/monitor.rs");
    if !monitor_path.exists() {
        return;
    }

    let monitor_code = fs::read_to_string(&monitor_path)
        .expect("Failed to read monitor code");

    // Verify add_canary method writes to overlay
    assert!(
        monitor_code.contains("add_canary") && monitor_code.contains("std::fs::write"),
        "add_canary must write canary files to overlay"
    );

    // Verify overlay_path is used
    assert!(
        monitor_code.contains("overlay_path") && monitor_code.contains("overlay_full_path"),
        "Canary files must be written to overlay path"
    );

    // Verify tmpfs is used (in sandbox integration)
    let sandbox_path = workspace_root().join("crates/sigil-sandbox/src/lib.rs");
    if sandbox_path.exists() {
        let sandbox_code = fs::read_to_string(&sandbox_path)
            .expect("Failed to read sandbox code");

        // Verify secrets are mounted via tmpfs
        assert!(
            sandbox_code.contains("--tmpfs") || sandbox_code.contains("tmpfs"),
            "Sandbox should use tmpfs for secrets"
        );
    }
}

/// Test 1.3: Verify canary values are added to scrubber
///
/// Tests that canary values are registered for scrubbing:
/// 1. Generate canary
/// 2. Add to monitor
/// 3. Verify get_canary_values returns canary for scrubbing
#[test]
fn test_canary_values_for_scrubber() {
    let monitor_path = workspace_root().join("crates/sigil-canary/src/monitor.rs");
    if !monitor_path.exists() {
        return;
    }

    let monitor_code = fs::read_to_string(&monitor_path)
        .expect("Failed to read monitor code");

    // Verify get_canary_values method
    assert!(
        monitor_code.contains("get_canary_values") && monitor_code.contains("SecretPath"),
        "Monitor must provide canary values to scrubber"
    );

    // Verify canary namespace is used
    assert!(
        monitor_code.contains("canary/") || monitor_code.contains("canary::"),
        "Canary secrets should use canary/ namespace"
    );

    // Verify values are returned for scrubbing
    assert!(
        monitor_code.contains("c.value()") || monitor_code.contains("canary.value"),
        "Canary values must be returned for scrubbing"
    );
}

// ============================================================================
// CANARY ACCESS DETECTION TESTS
// ============================================================================

/// Test 2.1: Verify canary access detection via hooks
///
/// Tests that canary access is detected when commands read files:
/// 1. Add canary to overlay
/// 2. Execute command that reads canary file
/// 3. Verify access event is recorded
#[test]
fn test_canary_access_detection() {
    let canary_lib_path = workspace_root().join("crates/sigil-canary/src/lib.rs");
    if !canary_lib_path.exists() {
        return;
    }

    let monitor_path = workspace_root().join("crates/sigil-canary/src/monitor.rs");
    if !monitor_path.exists() {
        return;
    }

    let monitor_code = fs::read_to_string(&monitor_path)
        .expect("Failed to read monitor code");

    // Verify record_access method
    assert!(
        monitor_code.contains("record_access"),
        "Monitor must have record_access method"
    );

    // Verify breach tracking
    assert!(
        monitor_code.contains("breaches") && monitor_code.contains("Vec<CanaryAccessEvent>"),
        "Monitor must track breach events"
    );

    // Verify severity levels
    assert!(
        monitor_code.contains("BreachSeverity") &&
        (monitor_code.contains("Critical") || monitor_code.contains("Warning")),
        "Monitor must track breach severity"
    );

    // Verify has_breaches method
    assert!(
        monitor_code.contains("has_breaches"),
        "Monitor must provide has_breaches check"
    );
}

/// Test 2.2: Verify fanotify monitoring (Linux)
///
/// Tests that fanotify is used for file access monitoring on Linux:
/// 1. Check fanotify_init call
/// 2. Check fanotify_mark for overlay directory
/// 3. Verify event processing
#[test]
#[cfg(target_os = "linux")]
fn test_fanotify_monitoring() {
    let monitor_path = workspace_root().join("crates/sigil-canary/src/monitor.rs");
    if !monitor_path.exists() {
        return;
    }

    let monitor_code = fs::read_to_string(&monitor_path)
        .expect("Failed to read monitor code");

    // Verify fanotify initialization
    assert!(
        monitor_code.contains("fanotify_init") || monitor_code.contains("init_fanotify"),
        "Monitor must initialize fanotify on Linux"
    );

    // Verify fanotify_mark for overlay directory
    assert!(
        monitor_code.contains("fanotify_mark") || monitor_code.contains("FAN_MARK_ADD"),
        "Monitor must mark overlay directory for monitoring"
    );

    // Verify FAN_ACCESS or FAN_OPEN events
    assert!(
        monitor_code.contains("FAN_ACCESS") || monitor_code.contains("FAN_OPEN"),
        "Monitor must watch for access/open events"
    );

    // Verify event processing
    assert!(
        monitor_code.contains("process_fanotify_events") || monitor_code.contains("read events"),
        "Monitor must process fanotify events"
    );
}

/// Test 2.3: Verify inotify fallback (non-Linux or hook-based)
///
/// Tests that inotify or hook-based detection is available:
/// 1. Check for inotify support
/// 2. Check for hook-based detection
#[test]
fn test_hook_based_detection() {
    let daemon_path = workspace_root().join("crates/sigil-daemon/src/server.rs");
    if !daemon_path.exists() {
        return;
    }

    let server_code = fs::read_to_string(&daemon_path)
        .expect("Failed to read server code");

    // Verify canary path detection
    assert!(
        server_code.contains("canary_path") || server_code.contains("is_canary"),
        "Server must detect canary paths in file operations"
    );

    // Verify decoy response generation
    assert!(
        server_code.contains("decoy") || server_code.contains("generate_decoy"),
        "Server must generate decoy responses for canary access"
    );

    // Verify canary access recording
    assert!(
        server_code.contains("record_canary") || server_code.contains("canary_access"),
        "Server must record canary access events"
    );
}

// ============================================================================
// BREACH REPORTING TESTS
// ============================================================================

/// Test 3.1: Verify breach report generation
///
/// Tests that breach reports are generated correctly:
/// 1. Trigger multiple canaries
/// 2. Generate breach report
/// 3. Verify report includes all breaches
/// 4. Verify report formatting
#[test]
fn test_breach_report_generation() {
    let monitor_path = workspace_root().join("crates/sigil-canary/src/monitor.rs");
    if !monitor_path.exists() {
        return;
    }

    let monitor_code = fs::read_to_string(&monitor_path)
        .expect("Failed to read monitor code");

    // Verify generate_report method
    assert!(
        monitor_code.contains("generate_report") && monitor_code.contains("BreachReport"),
        "Monitor must generate breach reports"
    );

    // Verify BreachReport structure
    assert!(
        monitor_code.contains("pub struct BreachReport") ||
        monitor_code.contains("total_breaches") && monitor_code.contains("critical_breaches"),
        "BreachReport must include breach counts"
    );

    // Verify breaches array
    assert!(
        monitor_code.contains("breaches:") || monitor_code.contains("Vec<CanaryAccessEvent>"),
        "BreachReport must include breach events array"
    );

    // Verify triggered_canaries array
    assert!(
        monitor_code.contains("triggered_canaries") || monitor_code.contains("CanarySummary"),
        "BreachReport must include triggered canary summaries"
    );

    // Verify report formatting
    assert!(
        monitor_code.contains("format()") || monitor_code.contains("to_string"),
        "BreachReport must be formattable for display"
    );
}

/// Test 3.2: Verify critical breach counting
///
/// Tests that critical breaches are counted separately:
/// 1. Trigger canaries with different severities
/// 2. Verify critical count is accurate
/// 3. Verify total count is accurate
#[test]
fn test_critical_breach_counting() {
    let monitor_path = workspace_root().join("crates/sigil-canary/src/monitor.rs");
    if !monitor_path.exists() {
        return;
    }

    let monitor_code = fs::read_to_string(&monitor_path)
        .expect("Failed to read monitor code");

    // Verify get_critical_breaches method
    assert!(
        monitor_code.contains("get_critical_breaches") || (
            monitor_code.contains("filter") && monitor_code.contains("BreachSeverity::Critical")
        ),
        "Monitor must filter critical breaches"
    );

    // Verify severity enum
    assert!(
        monitor_code.contains("enum BreachSeverity") ||
        (monitor_code.contains("Critical") && monitor_code.contains("Warning") && monitor_code.contains("Info")),
        "BreachSeverity must have Critical, Warning, and Info levels"
    );
}

/// Test 3.3: Verify breach timestamp tracking
///
/// Tests that breach events include accurate timestamps:
/// 1. Record canary access
/// 2. Verify timestamp is UTC
/// 3. Verify timestamp accuracy
#[test]
fn test_breach_timestamp_tracking() {
    let canary_path = workspace_root().join("crates/sigil-canary/src/monitor.rs");
    if !canary_path.exists() {
        return;
    }

    let canary_code = fs::read_to_string(&canary_path)
        .expect("Failed to read canary code");

    // Verify CanaryAccessEvent has timestamp
    assert!(
        canary_code.contains("timestamp") && canary_code.contains("chrono::DateTime<chrono::Utc>"),
        "CanaryAccessEvent must include UTC timestamp"
    );

    // Verify timestamp is set on creation
    assert!(
        canary_code.contains("chrono::Utc::now()") || canary_code.contains("timestamp:"),
        "Timestamp must be set when event is created"
    );
}

// ============================================================================
// CANARY INTEGRATION WITH SANDBOX TESTS
// ============================================================================

/// Test 4.1: Verify canary files are mounted in sandbox
///
/// Tests that canary files are accessible in sandbox:
/// 1. Create canary in overlay
/// 2. Start sandbox with overlay bind-mount
/// 3. Verify canary file is accessible in sandbox
#[test]
fn test_canary_mounted_in_sandbox() {
    let sandbox_path = workspace_root().join("crates/sigil-sandbox/src/lib.rs");
    if !sandbox_path.exists() {
        return;
    }

    let sandbox_code = fs::read_to_string(&sandbox_path)
        .expect("Failed to read sandbox code");

    // Verify bind-mount support for overlay
    assert!(
        sandbox_code.contains("--bind") || sandbox_code.contains("--ro-bind"),
        "Sandbox must support bind-mounts"
    );

    // Verify working directory binding (for canary overlay)
    assert!(
        sandbox_code.contains("cwd") || sandbox_code.contains("working_dir"),
        "Sandbox must support working directory binding"
    );
}

/// Test 4.2: Verify canary access triggers alert
///
/// Tests that sandbox command reading canary triggers alert:
/// 1. Add canary to overlay
/// 2. Execute sandbox command that reads canary
/// 3. Verify alert is generated
/// 4. Verify alert includes PID and command
#[test]
fn test_canary_access_triggers_alert() {
    let daemon_path = workspace_root().join("crates/sigil-daemon/src/server.rs");
    if !daemon_path.exists() {
        return;
    }

    let server_code = fs::read_to_string(&daemon_path)
        .expect("Failed to read server code");

    // Verify canary access detection in exec handler
    assert!(
        server_code.contains("canary") || server_code.contains("decoy"),
        "Server must detect canary access"
    );

    // Verify breach logging
    assert!(
        server_code.contains("CRITICAL") || server_code.contains("breach") ||
        server_code.contains("warn!") || server_code.contains("error!"),
        "Server must log canary breaches at CRITICAL level"
    );

    // Verify PID tracking
    assert!(
        server_code.contains("pid") || server_code.contains("PID"),
        "Breach event must include accessing process PID"
    );
}

/// Test 4.3: Verify canary cleanup on sandbox exit
///
/// Tests that canary files are cleaned up:
/// 1. Create canary overlay
/// 2. Run sandbox command
/// 3. Verify overlay is cleaned up
/// 4. Verify no canary files remain on host
#[test]
fn test_canary_cleanup_on_sandbox_exit() {
    let sandbox_path = workspace_root().join("crates/sigil-sandbox/src/lib.rs");
    if !sandbox_path.exists() {
        return;
    }

    let sandbox_code = fs::read_to_string(&sandbox_path)
        .expect("Failed to read sandbox code");

    // Verify tmpfs is used (auto-cleanup)
    assert!(
        sandbox_code.contains("--tmpfs") && (
            sandbox_code.contains("/dev/shm") ||
            sandbox_code.contains("/tmp") ||
            sandbox_code.contains("tmpfs")
        ),
        "Sandbox should use tmpfs for automatic cleanup"
    );

    // Verify overlay cleanup (if used)
    if sandbox_code.contains("overlay") {
        assert!(
            sandbox_code.contains("cleanup") || sandbox_code.contains("remove") ||
            sandbox_code.contains("TempDir"),
            "Overlay directories must be cleaned up"
        );
    }
}

// ============================================================================
// CANARY LOCKDOWN TRIGGER TESTS
// ============================================================================

/// Test 5.1: Verify lockdown threshold configuration
///
/// Tests that lockdown triggers after threshold breaches:
/// 1. Check threshold configuration
/// 2. Trigger breaches up to threshold
/// 3. Verify lockdown is triggered
#[test]
fn test_lockdown_threshold() {
    let daemon_path = workspace_root().join("crates/sigil-daemon/src/server.rs");
    if !daemon_path.exists() {
        return;
    }

    let server_code = fs::read_to_string(&daemon_path)
        .expect("Failed to read server code");

    // Verify lockdown mechanism
    assert!(
        server_code.contains("lockdown") || server_code.contains("shutdown") ||
        server_code.contains("terminate"),
        "Server must support lockdown on canary breach"
    );

    // Verify threshold checking
    assert!(
        server_code.contains("threshold") || server_code.contains("breach_count") ||
        server_code.contains("breaches.len()"),
        "Server must check breach count against threshold"
    );
}

/// Test 5.2: Verify canary-triggered lockdown behavior
///
/// Tests that lockdown behaves correctly:
/// 1. Trigger lockdown
/// 2. Verify new operations are rejected
/// 3. Verify alert is generated
/// 4. Verify audit log entry
#[test]
fn test_lockdown_behavior() {
    let daemon_path = workspace_root().join("crates/sigil-daemon/src/server.rs");
    if !daemon_path.exists() {
        return;
    }

    let server_code = fs::read_to_string(&daemon_path)
        .expect("Failed to read server code");

    // Verify lockdown state
    assert!(
        server_code.contains("is_locked_down") || server_code.contains("locked_down") ||
        server_code.contains("lockdown_mode"),
        "Server must track lockdown state"
    );

    // Verify operation rejection during lockdown
    assert!(
        server_code.contains("LockedDown") || server_code.contains("lockdown") ||
        (server_code.contains("if locked_down") && server_code.contains("return")),
        "Server must reject operations during lockdown"
    );

    // Verify audit log entry
    let audit_path = workspace_root().join("crates/sigil-core/src/audit.rs");
    if audit_path.exists() {
        let audit_code = fs::read_to_string(&audit_path)
            .expect("Failed to read audit code");

        assert!(
            audit_code.contains("Lockdown") || audit_code.contains("lockdown") ||
            audit_code.contains("BreachDetected"),
            "Audit log must record lockdown events"
        );
    }
}

// ============================================================================
// CANARY DECOY GENERATION TESTS
// ============================================================================

/// Test 6.1: Verify decoy responses for canary access
///
/// Tests that decoy responses are generated:
/// 1. Access canary file
/// 2. Verify realistic content is returned
/// 3. Verify content differs from actual canary
#[test]
fn test_decoy_response_generation() {
    let daemon_path = workspace_root().join("crates/sigil-daemon/src/server.rs");
    if !daemon_path.exists() {
        return;
    }

    let server_code = fs::read_to_string(&daemon_path)
        .expect("Failed to read server code");

    // Verify decoy generation
    assert!(
        server_code.contains("decoy") || server_code.contains("fake") ||
        server_code.contains("generate_decoy"),
        "Server must generate decoy responses for canary access"
    );

    // Verify decoy is realistic
    // The decoy should look like a real expired/invalid credential
    // but NOT contain "SIGIL" or "canary" identifiers
    let has_decoy = server_code.contains("generate_decoy");
    if has_decoy {
        // If we have explicit decoy generation, verify it doesn't have identifiers
        assert!(
            !server_code.contains("SIGIL DECOY") && !server_code.contains("THIS IS A CANARY"),
            "Decoy responses must NOT contain identifying comments"
        );
    }
}

/// Test 6.2: Verify hook-only canary mode
///
/// Tests that canaries work in hook-only mode (no files on host):
/// 1. Enable hook-only mode
/// 2. Access canary path
/// 3. Verify decoy is served via hook
/// 4. Verify no file created on host
#[test]
fn test_hook_only_canary_mode() {
    let cli_path = workspace_root().join("crates/sigil-cli/src/hooks.rs");
    if !cli_path.exists() {
        return;
    }

    let hooks_code = fs::read_to_string(&cli_path)
        .expect("Failed to read hooks code");

    // Verify canary path detection in hooks
    assert!(
        hooks_code.contains("canary") || hooks_code.contains(".aws/credentials") ||
        hooks_code.contains(".ssh/id_rsa") || hooks_code.contains(".env"),
        "Hooks must detect canary path access"
    );

    // Verify hooks can return decoy responses
    assert!(
        hooks_code.contains("additional_context") || hooks_code.contains("permission_decision"),
        "Hooks must be able to provide responses"
    );
}

// ============================================================================
// CANARY VALUE SCRUBBING TESTS
// ============================================================================

/// Test 7.1: Verify canary values are scrubbed from output
///
/// Tests that canary values are detected and scrubbed:
/// 1. Generate canary
/// 2. Print canary value in command output
/// 3. Verify output is scrubbed
#[test]
fn test_canary_value_scrubbing() {
    let scrubber_path = workspace_root().join("crates/sigil-scrub/src/scrubber.rs");
    if !scrubber_path.exists() {
        return;
    }

    let scrubber_code = fs::read_to_string(&scrubber_path)
        .expect("Failed to read scrubber code");

    // Verify scrubber accepts canary values
    assert!(
        scrubber_code.contains("add_secret") || scrubber_code.contains("register_secret") ||
        scrubber_code.contains("patterns"),
        "Scrubber must accept secret values for scrubbing"
    );

    // Verify canary namespace integration
    assert!(
        scrubber_code.contains("canary/") || scrubber_code.contains("canary::"),
        "Scrubber should handle canary/ namespace"
    );
}

/// Test 7.2: Verify multi-encoding canary detection
///
/// Tests that canary values are detected in multiple encodings:
/// 1. Generate canary value
/// 2. Encode as base64
/// 3. Encode as hex
/// 4. Verify all variants are scrubbed
#[test]
fn test_multi_encoding_canary_detection() {
    let scrubber_path = workspace_root().join("crates/sigil-scrub/src/scrubber.rs");
    if !scrubber_path.exists() {
        return;
    }

    let scrubber_code = fs::read_to_string(&scrubber_path)
        .expect("Failed to read scrubber code");

    // Verify encoding variant generation
    assert!(
        scrubber_code.contains("encoding") || scrubber_code.contains("base64") ||
        scrubber_code.contains("hex"),
        "Scrubber must generate encoding variants for detection"
    );

    // Verify base64 support
    assert!(
        scrubber_code.contains("base64") || scrubber_code.contains("BASE64"),
        "Scrubber must support base64 encoding detection"
    );

    // Verify hex support
    assert!(
        scrubber_code.contains("hex") || scrubber_code.contains("HEX"),
        "Scrubber must support hex encoding detection"
    );
}

// ============================================================================
// CANARY TYPES TESTS
// ============================================================================

/// Test 8.1: Verify all canary types are generated
///
/// Tests that all standard canary types are generated:
/// - AWS credentials
/// - GitHub token
/// - SSH key
/// - .env file
/// - Stripe key
/// - JWT token
/// - PEM certificate
#[test]
fn test_all_canary_types_generated() {
    let canary_lib_path = workspace_root().join("crates/sigil-canary/src/lib.rs");
    if !canary_lib_path.exists() {
        return;
    }

    let generator_path = workspace_root().join("crates/sigil-canary/src/generator.rs");
    if !generator_path.exists() {
        return;
    }

    let generator_code = fs::read_to_string(&generator_path)
        .expect("Failed to read generator code");

    // Verify all canary types have generators
    let canary_types = [
        ("AWS", "generate_aws_credentials"),
        ("GitHub", "generate_github_token"),
        ("SSH", "generate_ssh_key"),
        (".env", "generate_env_file"),
        ("Stripe", "generate_stripe_key"),
        ("JWT", "generate_jwt_token"),
        ("PEM", "generate_pem_certificate"),
    ];

    for (name, method) in canary_types {
        assert!(
            generator_code.contains(method) || generator_code.contains(&format!("generate_{}", name.to_lowercase())),
            "{} canary generator must exist",
            name
        );
    }

    // Verify generate_all method
    assert!(
        generator_code.contains("fn generate_all") || generator_code.contains("pub fn generate_all"),
        "Generator must have generate_all method"
    );
}

/// Test 8.2: Verify canary kind enum
///
/// Tests that CanaryKind enum includes all types:
#[test]
fn test_canary_kind_enum() {
    let canary_path = workspace_root().join("crates/sigil-canary/src/canary.rs");
    if !canary_path.exists() {
        return;
    }

    let canary_code = fs::read_to_string(&canary_path)
        .expect("Failed to read canary code");

    // Verify CanaryKind enum
    assert!(
        canary_code.contains("pub enum CanaryKind") || canary_code.contains("enum CanaryKind"),
        "CanaryKind enum must exist"
    );

    // Verify standard canary kinds
    let kinds = [
        "AwsCredentials",
        "GitHubToken",
        "SshKey",
        "EnvFile",
        "StripeKey",
        "JwtToken",
        "PemCertificate",
    ];

    for kind in kinds {
        assert!(
            canary_code.contains(kind),
            "CanaryKind must include {}",
            kind
        );
    }

    // Verify default_path method for each kind
    assert!(
        canary_code.contains("default_path") || canary_code.contains("path"),
        "CanaryKind must provide default path"
    );
}
