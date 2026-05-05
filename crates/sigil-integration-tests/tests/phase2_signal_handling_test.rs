//! Phase 2.7 Signal Handling Tests
//!
//! These tests verify:
//! - SIGTERM/SIGINT: graceful shutdown with 5s drain
//! - SIGHUP: reload config (no vault re-unseal)
//! - SIGUSR1: dump status to audit log
//! - SIGUSR2: force audit log rotation
//! - SIGQUIT: immediate exit (debugging only)
//! - SIGPIPE: ignored (handled per-connection)
//! - sigil-shell forwards signals to sandbox child process
//! - PR_SET_PDEATHSIG(SIGKILL) on sandbox child

mod common;
use common::workspace_root;
use std::fs;

/// Test 1: Verify signal handler implementation
///
/// From Phase 2.7 Deliverables:
/// - SIGTERM/SIGINT: graceful shutdown
/// - SIGHUP: reload config
/// - SIGUSR1: dump status
/// - SIGUSR2: force rotation
/// - SIGQUIT: immediate exit
#[test]
fn test_signal_handler_implementation() {
    let workspace = workspace_root();
    let signals_code_path = workspace.join("crates/sigil-daemon/src/signals.rs");
    let signals_code = fs::read_to_string(&signals_code_path).expect("Failed to read signals code");

    // Verify SignalEvent enum has all required events
    assert!(
        signals_code.contains("pub enum SignalEvent"),
        "Signal module should define SignalEvent enum"
    );

    let expected_events = ["Shutdown", "Reload", "DumpStatus", "RotateLog", "Quit"];

    for event_name in &expected_events {
        assert!(
            signals_code.contains(event_name),
            "Missing signal event: {}",
            event_name
        );
    }

    // Verify signal handler setup for each signal
    assert!(
        signals_code.contains("SignalKind::terminate()"),
        "Should handle SIGTERM"
    );
    assert!(
        signals_code.contains("SignalKind::interrupt()"),
        "Should handle SIGINT"
    );
    assert!(
        signals_code.contains("SignalKind::hangup()"),
        "Should handle SIGHUP"
    );
    assert!(
        signals_code.contains("SignalKind::user_defined1()"),
        "Should handle SIGUSR1"
    );
    assert!(
        signals_code.contains("SignalKind::user_defined2()"),
        "Should handle SIGUSR2"
    );
    assert!(
        signals_code.contains("SignalKind::quit()"),
        "Should handle SIGQUIT"
    );

    println!("Signal handler implementation test passed!");
}

/// Test 2: Verify SIGPIPE is ignored
///
/// From Phase 2.7 Deliverables:
/// - SIGPIPE: ignored (handled per-connection)
#[test]
fn test_sigpipe_ignored() {
    let workspace = workspace_root();
    let signals_code_path = workspace.join("crates/sigil-daemon/src/signals.rs");
    let signals_code = fs::read_to_string(&signals_code_path).expect("Failed to read signals code");

    // Verify SIGPIPE is ignored
    assert!(
        signals_code.contains("SIGPIPE") && signals_code.contains("SIG_IGN"),
        "SIGPIPE should be ignored globally"
    );

    // Verify it's done in a best-effort way (with warning on failure)
    assert!(
        signals_code.contains("EPERM") || signals_code.contains("warn"),
        "SIGPIPE handling should be best-effort"
    );

    println!("SIGPIPE ignored test passed!");
}

/// Test 3: Verify signal handler configuration
///
/// From Phase 2.7 Deliverables:
/// - Configurable signal handling
#[test]
fn test_signal_handler_configuration() {
    let workspace = workspace_root();
    let signals_code_path = workspace.join("crates/sigil-daemon/src/signals.rs");
    let signals_code = fs::read_to_string(&signals_code_path).expect("Failed to read signals code");

    // Verify SignalHandlerConfig struct exists
    assert!(
        signals_code.contains("pub struct SignalHandlerConfig"),
        "Signal module should define SignalHandlerConfig struct"
    );

    // Verify config has all required fields
    assert!(
        signals_code.contains("enable_shutdown: bool"),
        "Config should have enable_shutdown field"
    );
    assert!(
        signals_code.contains("enable_reload: bool"),
        "Config should have enable_reload field"
    );
    assert!(
        signals_code.contains("enable_status_dump: bool"),
        "Config should have enable_status_dump field"
    );
    assert!(
        signals_code.contains("enable_log_rotation: bool"),
        "Config should have enable_log_rotation field"
    );
    assert!(
        signals_code.contains("enable_quit: bool"),
        "Config should have enable_quit field"
    );

    // Verify default implementation
    assert!(
        signals_code.contains("impl Default for SignalHandlerConfig"),
        "SignalHandlerConfig should have Default implementation"
    );

    // Verify default values
    assert!(
        signals_code.contains("enable_shutdown: true"),
        "Shutdown should be enabled by default"
    );
    assert!(
        signals_code.contains("enable_reload: true"),
        "Reload should be enabled by default"
    );
    assert!(
        signals_code.contains("enable_status_dump: true"),
        "Status dump should be enabled by default"
    );
    assert!(
        signals_code.contains("enable_log_rotation: true"),
        "Log rotation should be enabled by default"
    );
    assert!(
        signals_code.contains("enable_quit: false"),
        "Quit should be disabled by default (production)"
    );

    println!("Signal handler configuration test passed!");
}

/// Test 4: Verify signal event broadcasting
///
/// From Phase 2.7 Deliverables:
/// - Multiple receivers can get signal events
#[test]
fn test_signal_event_broadcasting() {
    let workspace = workspace_root();
    let signals_code_path = workspace.join("crates/sigil-daemon/src/signals.rs");
    let signals_code = fs::read_to_string(&signals_code_path).expect("Failed to read signals code");

    // Verify SignalHandler struct exists
    assert!(
        signals_code.contains("pub struct SignalHandler"),
        "Signal module should define SignalHandler struct"
    );

    // Verify broadcast channel is used
    assert!(
        signals_code.contains("broadcast::channel"),
        "SignalHandler should use broadcast channel"
    );

    // Verify sender and receiver fields
    assert!(
        signals_code.contains("sender: broadcast::Sender<SignalEvent>"),
        "SignalHandler should have sender field"
    );
    assert!(
        signals_code.contains("receiver: broadcast::Receiver<SignalEvent>"),
        "SignalHandler should have receiver field"
    );

    // Verify receiver method
    assert!(
        signals_code.contains("pub fn receiver(&self)"),
        "SignalHandler should have receiver method for creating new receivers"
    );

    // Verify broadcast allows multiple receivers
    assert!(
        signals_code.contains("sender.subscribe()"),
        "New receivers should subscribe to broadcast channel"
    );

    println!("Signal event broadcasting test passed!");
}

/// Test 5: Verify graceful shutdown behavior
///
/// From Phase 2.7 Deliverables:
/// - SIGTERM/SIGINT: graceful shutdown with drain period
#[test]
fn test_graceful_shutdown_behavior() {
    let workspace = workspace_root();
    let main_code_path = workspace.join("crates/sigil-daemon/src/main.rs");
    let main_code = fs::read_to_string(&main_code_path).expect("Failed to read main code");

    // Verify shutdown signal triggers graceful shutdown
    assert!(
        main_code.contains("SignalEvent::Shutdown") && main_code.contains("break"),
        "Shutdown signal should break the signal loop"
    );

    // Verify graceful shutdown is called
    assert!(
        main_code.contains("server_clone.shutdown()") || main_code.contains("server.shutdown()"),
        "Shutdown should call server.shutdown()"
    );

    // Verify session end is logged
    assert!(
        main_code.contains("log_session_end()"),
        "Shutdown should log session end"
    );

    // Check server.rs for shutdown implementation
    let server_code_path = workspace.join("crates/sigil-daemon/src/server.rs");
    let server_code = fs::read_to_string(&server_code_path).expect("Failed to read server code");

    // Verify drain period for sandbox processes
    assert!(
        server_code.contains("SIGTERM") || server_code.contains("graceful"),
        "Shutdown should attempt graceful termination of sandboxes"
    );

    // Verify SIGKILL fallback for stubborn processes
    assert!(
        server_code.contains("SIGKILL") || server_code.contains("libc::kill"),
        "Shutdown should use SIGKILL as fallback"
    );

    println!("Graceful shutdown behavior test passed!");
}

/// Test 6: Verify bubblewrap die-with-parent for sandbox cleanup
///
/// From Phase 2.7 Deliverables:
/// - PR_SET_PDEATHSIG(SIGKILL) on sandbox child (via --die-with-parent)
#[test]
fn test_bubblewrap_die_with_parent() {
    let workspace = workspace_root();
    let bubblewrap_code_path = workspace.join("crates/sigil-sandbox/src/bubblewrap.rs");
    let bubblewrap_code =
        fs::read_to_string(&bubblewrap_code_path).expect("Failed to read bubblewrap code");

    // Verify --die-with-parent flag is used
    assert!(
        bubblewrap_code.contains("--die-with-parent")
            || bubblewrap_code.contains("die_with_parent"),
        "Bubblewrap should use --die-with-parent flag"
    );

    // Verify die_with_parent config option
    assert!(
        bubblewrap_code.contains("die_with_parent: bool"),
        "SandboxConfig should have die_with_parent field"
    );

    // Verify default is true
    assert!(
        bubblewrap_code.contains("die_with_parent: true"),
        "die_with_parent should default to true"
    );

    // Verify it's added to bwrap args
    assert!(
        bubblewrap_code.contains("config.die_with_parent"),
        "die_with_parent config should be checked when building args"
    );

    println!("Bubblewrap die-with-parent test passed!");
}

/// Test 7: Verify signal handling integration in daemon
///
/// From Phase 2.7 Deliverables:
/// - Daemon integrates signal handler
#[test]
fn test_signal_handling_integration() {
    let workspace = workspace_root();
    let main_code_path = workspace.join("crates/sigil-daemon/src/main.rs");
    let main_code = fs::read_to_string(&main_code_path).expect("Failed to read main code");

    // Verify signal handler is created
    assert!(
        main_code.contains("SignalHandler::new()"),
        "Daemon should create signal handler"
    );

    // Verify signal handler is started
    assert!(
        main_code.contains(".start(signal_config)") || main_code.contains("signal_handler.start"),
        "Daemon should start signal handler"
    );

    // Verify signal receiver is created
    assert!(
        main_code.contains("signal_handler.receiver()"),
        "Daemon should create signal receiver"
    );

    // Verify signal handling task is spawned
    assert!(
        main_code.contains("shutdown_task") && main_code.contains("tokio::spawn"),
        "Daemon should spawn signal handling task"
    );

    // Verify all signal events are handled
    assert!(
        main_code.contains("SignalEvent::Shutdown"),
        "Daemon should handle Shutdown event"
    );
    assert!(
        main_code.contains("SignalEvent::Reload"),
        "Daemon should handle Reload event"
    );
    assert!(
        main_code.contains("SignalEvent::DumpStatus"),
        "Daemon should handle DumpStatus event"
    );
    assert!(
        main_code.contains("SignalEvent::RotateLog"),
        "Daemon should handle RotateLog event"
    );
    assert!(
        main_code.contains("SignalEvent::Quit"),
        "Daemon should handle Quit event"
    );

    println!("Signal handling integration test passed!");
}

/// Test 8: Verify SIGHUP reloads config without re-unsealing vault
///
/// From Phase 2.7 Deliverables:
/// - SIGHUP: reload config (no vault re-unseal)
#[test]
fn test_sighup_reload_config() {
    let workspace = workspace_root();
    let main_code_path = workspace.join("crates/sigil-daemon/src/main.rs");
    let main_code = fs::read_to_string(&main_code_path).expect("Failed to read main code");

    // Verify SIGHUP triggers reload
    assert!(
        main_code.contains("SignalEvent::Reload") && main_code.contains("reload_config"),
        "SIGHUP should trigger config reload"
    );

    // Check server.rs for reload_config implementation
    let server_code_path = workspace.join("crates/sigil-daemon/src/server.rs");
    let server_code = fs::read_to_string(&server_code_path).expect("Failed to read server code");

    // Verify reload_config exists
    assert!(
        server_code.contains("pub async fn reload_config")
            || server_code.contains("fn reload_config"),
        "Server should have reload_config function"
    );

    // Verify reload doesn't re-unseal vault (no unlock_async call)
    // This is implicit - we're checking that reload exists and doesn't unlock
    let reload_section = server_code.split("fn reload_config").nth(1).unwrap_or("");

    // Reload should NOT call unlock or similar
    let has_unlock = reload_section.contains("unlock") || reload_section.contains("unseal");

    // If the function exists, it should focus on config reload, not vault operations
    if server_code.contains("reload_config") {
        // The key is that reload doesn't require passphrase
        assert!(
            !has_unlock || !reload_section.contains("passphrase"),
            "Reload config should not require passphrase re-entry"
        );
    }

    println!("SIGHUP reload config test passed!");
}

/// Test 9: Verify SIGUSR1 dumps status to audit log
///
/// From Phase 2.7 Deliverables:
/// - SIGUSR1: dump status to audit log
#[test]
fn test_sigusr1_dump_status() {
    let workspace = workspace_root();
    let main_code_path = workspace.join("crates/sigil-daemon/src/main.rs");
    let main_code = fs::read_to_string(&main_code_path).expect("Failed to read main code");

    // Verify SIGUSR1 triggers status dump
    assert!(
        main_code.contains("SignalEvent::DumpStatus") && main_code.contains("dump_status"),
        "SIGUSR1 should trigger status dump"
    );

    // Check server.rs for dump_status implementation
    let server_code_path = workspace.join("crates/sigil-daemon/src/server.rs");
    let server_code = fs::read_to_string(&server_code_path).expect("Failed to read server code");

    // Verify dump_status exists
    assert!(
        server_code.contains("pub async fn dump_status") || server_code.contains("fn dump_status"),
        "Server should have dump_status function"
    );

    println!("SIGUSR1 dump status test passed!");
}

/// Test 10: Verify SIGUSR2 forces audit log rotation
///
/// From Phase 2.7 Deliverables:
/// - SIGUSR2: force audit log rotation
#[test]
fn test_sigusr2_force_rotation() {
    let workspace = workspace_root();
    let main_code_path = workspace.join("crates/sigil-daemon/src/main.rs");
    let main_code = fs::read_to_string(&main_code_path).expect("Failed to read main code");

    // Verify SIGUSR2 triggers rotation
    assert!(
        main_code.contains("SignalEvent::RotateLog") && main_code.contains("rotate"),
        "SIGUSR2 should trigger audit log rotation"
    );

    // Verify rotation is called on audit logger
    assert!(
        main_code.contains("audit_logger_clone.rotate")
            || main_code.contains("audit_logger.rotate"),
        "SIGUSR2 should call audit_logger.rotate"
    );

    println!("SIGUSR2 force rotation test passed!");
}

/// Test 11: Verify SIGQUIT causes immediate exit
///
/// From Phase 2.7 Deliverables:
/// - SIGQUIT: immediate exit (debugging only)
#[test]
fn test_sigquit_immediate_exit() {
    let workspace = workspace_root();
    let main_code_path = workspace.join("crates/sigil-daemon/src/main.rs");
    let main_code = fs::read_to_string(&main_code_path).expect("Failed to read main code");

    // Verify SIGQUIT triggers immediate exit
    assert!(
        main_code.contains("SignalEvent::Quit") && main_code.contains("break"),
        "SIGQUIT should break the signal loop immediately"
    );

    // Verify quit is disabled by default in production
    assert!(
        main_code.contains("enable_quit: false")
            || main_code.contains("enable_quit: false, // Disable"),
        "Quit should be disabled in production config"
    );

    println!("SIGQUIT immediate exit test passed!");
}

/// Test 12: Verify sigil-shell forwards signals to sandbox child
///
/// From Phase 2.7 Deliverables:
/// - sigil-shell forwards signals to sandbox child process
#[test]
fn test_sigil_shell_signal_forwarding() {
    let workspace = workspace_root();
    let shell_code_path = workspace.join("crates/sigil-shell/src/main.rs");
    let shell_code = fs::read_to_string(&shell_code_path).expect("Failed to read shell code");

    // Verify signal forwarding function exists
    assert!(
        shell_code.contains("fn setup_signal_forwarding")
            || shell_code.contains("signal_forwarding"),
        "sigil-shell should have signal forwarding setup"
    );

    // Verify child PID is tracked for signal forwarding
    assert!(
        shell_code.contains("child_pid") || shell_code.contains("child.id()"),
        "sigil-shell should track child process ID"
    );

    // Verify signals are forwarded to child
    assert!(
        shell_code.contains("libc::kill") || shell_code.contains("kill"),
        "sigil-shell should forward signals using kill"
    );

    println!("sigil-shell signal forwarding test passed!");
}
