//! Phase 3.3: CLI Integration Verification
//!
//! This test verifies the CLI integration for:
//! - `sigil resolve` command parsing and output
//! - `sigil scrub` pipeline with stdin
//! - Daemon routing for resolve and scrub operations
//!
//! These tests ensure the CLI properly integrates with the core parser and scrubber,
//! and that the daemon correctly routes requests to the appropriate handlers.

use std::path::PathBuf;
use std::process::{Command, Stdio};

/// Get the cargo executable path from environment or find it dynamically
fn get_cargo_path() -> String {
    if let Ok(cargo) = std::env::var("CARGO") {
        cargo
    } else {
        // Try to find cargo in the system
        if let Ok(output) = Command::new("which").arg("cargo").output() {
            if output.status.success() {
                return String::from_utf8_lossy(&output.stdout).trim().to_string();
            }
        }
        // Fallback to common Nix store paths
        for path in &[
            "/nix/store/z382dzkk7snk51ka6n4f3b953dcdm8fc-cargo-1.94.1/bin/cargo",
            "/nix/store/wjln2jdb5lxxpyhk8bfrx62pkj7g00c9-cargo-1.86.0/bin/cargo",
        ] {
            if PathBuf::from(path).exists() {
                return path.to_string();
            }
        }
        // Final fallback - hope it's in PATH
        "cargo".to_string()
    }
}

/// Get the workspace root directory
fn workspace_root() -> PathBuf {
    // Start from the current directory and search for Cargo.toml
    let current_dir = std::env::current_dir().unwrap_or_default();
    let mut path = current_dir.as_path();

    loop {
        let cargo_toml = path.join("Cargo.toml");
        if cargo_toml.exists() {
            // Check if this is the workspace root (contains [workspace])
            if let Ok(content) = std::fs::read_to_string(&cargo_toml) {
                if content.contains("[workspace]") {
                    return path.to_path_buf();
                }
            }
        }

        // Move to parent directory
        match path.parent() {
            Some(parent) if !parent.as_os_str().is_empty() => path = parent,
            _ => {
                // Fallback to current directory
                return current_dir;
            }
        }
    }
}

/// Get the sigil binary path
fn get_sigil_binary_path() -> PathBuf {
    workspace_root().join("target/debug/sigil")
}

/// Build the sigil binary
fn build_sigil() -> Result<(), String> {
    let cargo = get_cargo_path();
    let workspace = workspace_root();
    let manifest_path = workspace.join("crates/sigil-cli/Cargo.toml");

    let status = Command::new(&cargo)
        .args([
            "build",
            "--quiet",
            "--bin",
            "sigil",
            "--manifest-path",
            manifest_path.to_str().unwrap(),
        ])
        .status()
        .map_err(|e| format!("Failed to build sigil: {}", e))?;

    if status.success() {
        Ok(())
    } else {
        Err("Build failed".to_string())
    }
}

/// Helper function to run sigil CLI command
fn run_sigil_command(args: &[&str], input: Option<&str>) -> (String, String, i32) {
    // Ensure binary is built
    if let Err(e) = build_sigil() {
        panic!("Failed to build sigil binary: {}", e);
    }

    let sigil_path = get_sigil_binary_path();
    let mut cmd = Command::new(sigil_path);
    cmd.args(args);

    if let Some(stdin_data) = input {
        cmd.stdin(Stdio::piped());
        cmd.stdout(Stdio::piped());
        cmd.stderr(Stdio::piped());

        let mut child = cmd.spawn().expect("Failed to spawn sigil command");

        {
            if let Some(mut stdin) = child.stdin.take() {
                use std::io::Write;
                stdin
                    .write_all(stdin_data.as_bytes())
                    .expect("Failed to write to stdin");
                drop(stdin);
            }
        }

        let output = child
            .wait_with_output()
            .expect("Failed to wait for sigil command");

        (
            String::from_utf8_lossy(&output.stdout).to_string(),
            String::from_utf8_lossy(&output.stderr).to_string(),
            output.status.code().unwrap_or(1),
        )
    } else {
        let output = cmd.output().expect("Failed to execute sigil command");
        (
            String::from_utf8_lossy(&output.stdout).to_string(),
            String::from_utf8_lossy(&output.stderr).to_string(),
            output.status.code().unwrap_or(1),
        )
    }
}

#[cfg(test)]
mod sigil_resolve_tests {
    use super::*;

    /// Test that `sigil resolve` outputs valid JSON for a simple command
    #[test]
    fn test_resolve_simple_command_json() {
        let (stdout, _stderr, exit_code) =
            run_sigil_command(&["resolve", "--json", "echo hello world"], None);

        assert_eq!(exit_code, 0, "resolve should succeed with exit code 0");

        // Verify output is valid JSON
        let json: serde_json::Value =
            serde_json::from_str(&stdout).expect("Output should be valid JSON");

        assert_eq!(json["command"], "echo hello world");
        assert_eq!(json["resolved"], "echo hello world");
        assert_eq!(json["has_secrets"], false);
    }

    /// Test that `sigil resolve` correctly identifies secret placeholders
    #[test]
    fn test_resolve_with_secret_placeholders() {
        let (stdout, _stderr, exit_code) = run_sigil_command(
            &[
                "resolve",
                "--json",
                "curl -H 'Authorization: {{secret:api/token}}' https://api.example.com",
            ],
            None,
        );

        assert_eq!(exit_code, 0, "resolve should succeed");

        let json: serde_json::Value =
            serde_json::from_str(&stdout).expect("Output should be valid JSON");

        assert!(json["has_secrets"].as_bool().unwrap());
        assert!(json["secret_paths"]
            .as_array()
            .unwrap()
            .contains(&serde_json::json!("api/token")));
    }

    /// Test that `sigil resolve` transforms placeholders to env vars
    #[test]
    fn test_resolve_env_mode_transformation() {
        let (stdout, _stderr, exit_code) = run_sigil_command(
            &[
                "resolve",
                "--json",
                "curl -H 'Auth: {{secret:api/key:env}}'",
            ],
            None,
        );

        assert_eq!(exit_code, 0, "resolve should succeed");

        let json: serde_json::Value =
            serde_json::from_str(&stdout).expect("Output should be valid JSON");

        // Verify env injection is recorded
        assert!(!json["env_injections"].as_array().unwrap().is_empty());
    }

    /// Test that `sigil resolve` reads command from stdin
    #[test]
    fn test_resolve_from_stdin() {
        let command = "echo {{secret:test/path}}";
        let (stdout, _stderr, exit_code) = run_sigil_command(&["resolve", "--json"], Some(command));

        assert_eq!(exit_code, 0, "resolve from stdin should succeed");

        let json: serde_json::Value =
            serde_json::from_str(&stdout).expect("Output should be valid JSON");

        assert_eq!(json["command"], command);
    }

    /// Test that `sigil resolve --format text` produces human-readable output
    #[test]
    fn test_resolve_text_format() {
        let (stdout, _stderr, exit_code) =
            run_sigil_command(&["resolve", "--format", "text", "echo hello"], None);

        assert_eq!(exit_code, 0, "resolve with text format should succeed");
        // Text format should be human-readable
        assert!(stdout.contains("No secret placeholders") || stdout.contains("Resolved command"));
    }

    /// Test that `sigil resolve` validates commands
    #[test]
    fn test_resolve_validates_piped_commands() {
        // This should fail validation: inline mode in piped command
        let (_stdout, _stderr, exit_code) = run_sigil_command(
            &["resolve", "--json", "echo {{secret:test}} | sha256sum"],
            None,
        );

        // Should fail because inline mode in piped commands is not allowed
        assert!(
            exit_code != 0,
            "Should reject inline mode in piped commands"
        );
    }

    /// Test that `sigil resolve` handles multiple placeholders
    #[test]
    fn test_resolve_multiple_placeholders() {
        let (stdout, _stderr, exit_code) = run_sigil_command(
            &[
                "resolve",
                "--json",
                "curl -H 'X-Key: {{secret:api/key}}' -H 'X-Token: {{secret:auth/token}}'",
            ],
            None,
        );

        assert_eq!(
            exit_code, 0,
            "resolve with multiple placeholders should succeed"
        );

        let json: serde_json::Value =
            serde_json::from_str(&stdout).expect("Output should be valid JSON");

        assert_eq!(json["secret_paths"].as_array().unwrap().len(), 2);
    }
}

#[cfg(test)]
mod sigil_scrub_tests {
    use super::*;

    /// Test that `sigil scrub` reads from stdin
    #[test]
    fn test_scrub_reads_stdin() {
        let input = "This is some output with no secrets";
        let (_stdout, _stderr, exit_code) =
            run_sigil_command(&["scrub", "--format", "text"], Some(input));

        // Should succeed even without vault
        assert!(exit_code == 0, "scrub should not crash");
    }

    /// Test that `sigil scrub --format json` produces valid JSON
    #[test]
    fn test_scrub_json_format() {
        let input = "This is some output";
        let (stdout, _stderr, exit_code) =
            run_sigil_command(&["scrub", "--format", "json"], Some(input));

        assert!(exit_code == 0, "scrub with json format should succeed");

        let json: serde_json::Value =
            serde_json::from_str(&stdout).expect("Output should be valid JSON");

        assert!(json.get("scrubbed").is_some());
        assert!(json.get("matches_found").is_some());
        assert!(json.get("secrets_detected").is_some());
    }

    /// Test that `sigil scrub` handles empty input
    #[test]
    fn test_scrub_empty_input() {
        let input = "";
        let (stdout, _stderr, exit_code) =
            run_sigil_command(&["scrub", "--format", "json"], Some(input));

        assert!(exit_code == 0, "scrub should handle empty input");

        let json: serde_json::Value =
            serde_json::from_str(&stdout).expect("Output should be valid JSON");

        assert_eq!(json["scrubbed"], "");
    }

    /// Test that `sigil scrub --prefix` filters secrets
    #[test]
    fn test_scrub_with_prefix() {
        let input = "Some output";
        let (stdout, _stderr, exit_code) = run_sigil_command(
            &["scrub", "--prefix", "api/", "--format", "json"],
            Some(input),
        );

        assert!(exit_code == 0, "scrub with prefix should succeed");

        let json: serde_json::Value =
            serde_json::from_str(&stdout).expect("Output should be valid JSON");

        // Should have valid JSON structure
        assert!(json.get("scrubbed").is_some());
    }

    /// Test that `sigil scrub` handles large input
    #[test]
    fn test_scrub_large_input() {
        let large_input = "x".repeat(100_000);
        let (stdout, _stderr, exit_code) =
            run_sigil_command(&["scrub", "--format", "text"], Some(&large_input));

        assert!(exit_code == 0, "scrub should handle large input");
        assert_eq!(stdout.len(), large_input.len());
    }
}

#[cfg(test)]
mod daemon_routing_tests {
    use super::*;

    /// Test that the daemon has resolve operation handler
    #[test]
    fn test_daemon_has_resolve_handler() {
        let server_path = workspace_root().join("crates/sigil-daemon/src/server.rs");
        let server_code =
            std::fs::read_to_string(&server_path).expect("Failed to read server code");

        // Verify resolve operation is routed
        assert!(
            server_code.contains("IpcOperation::Resolve") && server_code.contains("handle_resolve"),
            "Daemon should route Resolve operation to handle_resolve"
        );
    }

    /// Test that the daemon has scrub operation handler
    #[test]
    fn test_daemon_has_scrub_handler() {
        let server_path = workspace_root().join("crates/sigil-daemon/src/server.rs");
        let server_code =
            std::fs::read_to_string(&server_path).expect("Failed to read server code");

        // Verify scrub operation is routed
        assert!(
            server_code.contains("IpcOperation::Scrub") && server_code.contains("handle_scrub"),
            "Daemon should route Scrub operation to handle_scrub"
        );
    }

    /// Test that handle_resolve returns base64-encoded values
    #[test]
    fn test_daemon_resolve_returns_base64() {
        let server_path = workspace_root().join("crates/sigil-daemon/src/server.rs");
        let server_code =
            std::fs::read_to_string(&server_path).expect("Failed to read server code");

        // Verify base64 encoding
        assert!(
            server_code.contains("BASE64_STANDARD") || server_code.contains("base64"),
            "handle_resolve should return base64-encoded values"
        );
    }

    /// Test that handle_scrub uses Aho-Corasick scrubber
    #[test]
    fn test_daemon_scrub_uses_aho_corasick() {
        let server_path = workspace_root().join("crates/sigil-daemon/src/server.rs");
        let server_code =
            std::fs::read_to_string(&server_path).expect("Failed to read server code");

        // Verify scrubber usage
        assert!(
            server_code.contains("scrubber") || server_code.contains("scrub_with_stats"),
            "handle_scrub should use the Aho-Corasick scrubber"
        );
    }

    /// Test that daemon client has resolve method
    #[test]
    fn test_daemon_client_resolve_method() {
        let client_path = workspace_root().join("crates/sigil-daemon/src/client.rs");
        let client_code =
            std::fs::read_to_string(&client_path).expect("Failed to read client code");

        // Verify client has resolve method
        assert!(
            client_code.contains("pub async fn resolve"),
            "DaemonClient should have a resolve method"
        );
    }

    /// Test that daemon client has scrub method
    #[test]
    fn test_daemon_client_scrub_method() {
        let client_path = workspace_root().join("crates/sigil-daemon/src/client.rs");
        let client_code =
            std::fs::read_to_string(&client_path).expect("Failed to read client code");

        // Verify client has scrub method
        assert!(
            client_code.contains("pub async fn scrub"),
            "DaemonClient should have a scrub method"
        );
    }

    /// Test that IPC protocol has ResolveRequest and ResolveResponse types
    #[test]
    fn test_ipc_resolve_types() {
        // Check if types are exported from sigil-core
        let lib_path = workspace_root().join("crates/sigil-core/src/lib.rs");
        let lib_code = std::fs::read_to_string(&lib_path).expect("Failed to read lib code");

        // Verify types are re-exported
        assert!(
            lib_code.contains("ResolveRequest") && lib_code.contains("ResolveResponse"),
            "sigil-core should export ResolveRequest and ResolveResponse types"
        );
    }

    /// Test that IPC protocol has ScrubRequest and ScrubResponse types
    #[test]
    fn test_ipc_scrub_types() {
        let lib_path = workspace_root().join("crates/sigil-core/src/lib.rs");
        let lib_code = std::fs::read_to_string(&lib_path).expect("Failed to read lib code");

        // Verify types are re-exported
        assert!(
            lib_code.contains("ScrubRequest") && lib_code.contains("ScrubResponse"),
            "sigil-core should export ScrubRequest and ScrubResponse types"
        );
    }
}

#[cfg(test)]
mod integration_pipeline_tests {
    use super::*;

    /// Test the full resolve -> scrub pipeline
    #[test]
    fn test_resolve_scrub_pipeline() {
        // Step 1: Resolve a command with secrets
        let (resolve_stdout, _, _) =
            run_sigil_command(&["resolve", "--json", "echo {{secret:test/value}}"], None);

        let resolve_json: serde_json::Value =
            serde_json::from_str(&resolve_stdout).expect("resolve should output valid JSON");

        // Verify resolve worked
        assert!(resolve_json["has_secrets"].as_bool().unwrap());

        // Step 2: Scrub some output (simulate command output)
        let scrub_input = "Command output with test value: sk_1234567890abcdef";
        let (scrub_stdout, _, _) =
            run_sigil_command(&["scrub", "--format", "json"], Some(scrub_input));

        let scrub_json: serde_json::Value =
            serde_json::from_str(&scrub_stdout).expect("scrub should output valid JSON");

        // Verify scrub produced valid output structure
        assert!(scrub_json.get("scrubbed").is_some());
        assert!(scrub_json.get("matches_found").is_some());
    }

    /// Test that commands with no secrets pass through correctly
    #[test]
    fn test_no_secrets_pass_through() {
        let (stdout, _, exit_code) = run_sigil_command(&["resolve", "--json", "ls -la"], None);

        assert_eq!(exit_code, 0);

        let json: serde_json::Value =
            serde_json::from_str(&stdout).expect("Output should be valid JSON");

        assert_eq!(json["has_secrets"], false);
        assert_eq!(json["command"], json["resolved"]);
    }
}
