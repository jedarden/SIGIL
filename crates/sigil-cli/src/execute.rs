//! Execution pipeline for secure command execution
//!
//! This module implements the full execution pipeline:
//! parse → auto-detect → resolve → sandbox → execute → scrub → return
//!
//! The auto-detect step uses command signatures to automatically inject
//! secrets for known tools without explicit placeholders.

use crate::load_vault;
use anyhow::{anyhow, Context, Result};
use sigil_core::{CommandParser, ResolvedCommand, SecretBackend, SecretPath, SigilError};
use sigil_sandbox::secure_fd::SecureFile;
use sigil_sandbox::{SandboxConfig, SandboxProvider, ShellState};
use sigil_scrub::Scrubber;
use sigil_signatures::{InjectionType, MatchedSignature, SignatureMatcher};
use std::path::PathBuf;
use std::process::{Command, Output, Stdio};
use std::time::Instant;
use tracing::{debug, info, warn};

/// Audit log entry for auto-injected secrets
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct AutoInjectionLog {
    /// The signature that matched
    pub signature_name: String,
    /// The secret path that was injected
    pub secret_path: String,
    /// The injection type (env, file, header)
    pub injection_type: String,
    /// The target name/path
    pub target: String,
    /// Whether the injection was optional
    pub optional: bool,
    /// Timestamp of the injection
    pub timestamp: chrono::DateTime<chrono::Utc>,
}

/// Configuration for the execution pipeline
#[derive(Debug, Clone)]
pub struct ExecuteConfig {
    /// Whether to enable sandboxing
    pub sandbox_enabled: bool,
    /// Project directory for sandbox bind mount
    pub project_dir: Option<PathBuf>,
    /// Whether to enable network isolation in sandbox
    pub network_isolated: bool,
    /// Whether to enable output scrubbing
    pub scrub_enabled: bool,
    /// Whether to fail on secret detection in output (defense-in-depth)
    pub fail_on_leak: bool,
    /// Previous shell state (for multi-command sessions)
    pub previous_state: Option<ShellState>,
    /// Whether to enable transparent command recognition for auto-injection
    pub auto_inject_enabled: bool,
    /// Project directory for loading project-specific signatures
    pub signatures_project_dir: Option<PathBuf>,
}

impl Default for ExecuteConfig {
    fn default() -> Self {
        Self {
            sandbox_enabled: true,
            project_dir: None,
            network_isolated: true,
            scrub_enabled: true,
            fail_on_leak: false,
            previous_state: None,
            auto_inject_enabled: true,
            signatures_project_dir: None,
        }
    }
}

/// Result of command execution
#[derive(Debug)]
#[allow(dead_code)]
pub struct ExecuteResult {
    /// The command that was executed
    pub command: String,
    /// Exit code from the command
    pub exit_code: i32,
    /// Scrubbed stdout output
    pub stdout: String,
    /// Scrubbed stderr output
    pub stderr: String,
    /// Whether secrets were detected and scrubbed
    pub secrets_scrubbed: bool,
    /// Number of secrets detected
    pub secrets_detected: usize,
    /// Execution time in milliseconds
    pub execution_time_ms: u64,
    /// New shell state (if state tracking is enabled)
    pub new_state: Option<ShellState>,
    /// Auto-injected secrets via command signatures
    pub auto_injections: Vec<AutoInjectionLog>,
}

/// Execute a command with the full SIGIL pipeline
///
/// # Pipeline
/// 1. Parse: Validate command format
/// 2. Auto-detect: Match command against signatures for auto-injection
/// 3. Resolve: Resolve secret placeholders via sigild
/// 4. Sandbox: Wrap in sandbox if enabled
/// 5. Execute: Run the command
/// 6. Scrub: Remove secrets from output
/// 7. Return: Return result with new shell state
pub fn execute(command: &str, config: &ExecuteConfig) -> Result<ExecuteResult> {
    let start_time = Instant::now();

    info!("Executing command: {}", command);

    // Step 1: Parse and resolve the command
    debug!("Parsing command...");
    let resolved = CommandParser::resolve_command(command).context("Failed to parse command")?;

    // Step 2: Auto-detect signatures for transparent injection
    let mut auto_injections = Vec::new();
    let resolved = if config.auto_inject_enabled {
        debug!("Checking for matching command signatures...");
        let matcher = SignatureMatcher::with_project_dir(
            config
                .signatures_project_dir
                .clone()
                .or_else(|| std::env::current_dir().ok()),
        )
        .context("Failed to create signature matcher")?;

        let matched = matcher.match_command(command);
        if !matched.is_empty() {
            info!(
                "Command matched {} signature(s), enabling auto-injection",
                matched.len()
            );

            // Apply auto-injections to the resolved command
            apply_auto_injections(&resolved, &matched, &mut auto_injections)?
        } else {
            debug!("No matching signatures found");
            resolved
        }
    } else {
        debug!("Auto-injection disabled");
        resolved
    };

    // Step 3: Check if we have secrets to resolve
    let resolved = if resolved.has_secrets() {
        debug!("Command has secret placeholders, resolving...");
        resolve_secrets(&resolved)?
    } else {
        debug!("No secret placeholders found");
        resolved
    };

    // Step 4: Build the command with sandbox if enabled
    let mut cmd = if config.sandbox_enabled {
        debug!("Building sandboxed command...");
        build_sandbox_command(&resolved, config)?
    } else {
        debug!("Building non-sandboxed command...");
        build_plain_command(&resolved)?
    };

    // Set up output capture
    cmd.stdout(Stdio::piped());
    cmd.stderr(Stdio::piped());

    // Step 5: Execute the command
    debug!("Executing command...");
    let execution = cmd.spawn().context("Failed to spawn command")?;

    // Read output
    let Output {
        stdout: stdout_bytes,
        stderr: stderr_bytes,
        status,
    } = execution
        .wait_with_output()
        .context("Failed to wait for command")?;

    let exit_code = status.code().unwrap_or(1);

    // Convert to strings
    let stdout = String::from_utf8_lossy(&stdout_bytes).to_string();
    let stderr = String::from_utf8_lossy(&stderr_bytes).to_string();

    // Step 6: Scrub secrets from output if enabled
    let (scrubbed_stdout, scrubbed_stderr, secrets_scrubbed, secrets_detected) =
        if config.scrub_enabled {
            debug!("Scrubbing secrets from output...");
            scrub_output(&stdout, &stderr)?
        } else {
            (stdout, stderr, false, 0)
        };

    // Step 7: Capture shell state
    let new_state = config
        .previous_state
        .as_ref()
        .map(|prev| capture_shell_state(&scrubbed_stdout, exit_code, prev));

    let execution_time_ms = start_time.elapsed().as_millis() as u64;

    // Log results
    if !auto_injections.is_empty() {
        info!(
            "Auto-injected {} secret(s) via command signatures",
            auto_injections.len()
        );
        for injection in &auto_injections {
            debug!(
                "  [{}] {} -> {}",
                injection.signature_name, injection.secret_path, injection.target
            );
        }
    }

    if secrets_scrubbed {
        warn!(
            "Scrubbed {} secret(s) from command output",
            secrets_detected
        );
    }

    if config.fail_on_leak && secrets_scrubbed {
        return Err(anyhow!(
            "Secrets detected in output ({} secret(s) scrubbed)",
            secrets_detected
        ));
    }

    info!(
        "Command completed with exit code {} in {}ms",
        exit_code, execution_time_ms
    );

    Ok(ExecuteResult {
        command: command.to_string(),
        exit_code,
        stdout: scrubbed_stdout,
        stderr: scrubbed_stderr,
        secrets_scrubbed,
        secrets_detected,
        execution_time_ms,
        new_state,
        auto_injections,
    })
}

/// Apply auto-injections from matched signatures to a resolved command
///
/// This function modifies the resolved command to include injections from
/// matching signatures, creating audit log entries for each injection.
fn apply_auto_injections(
    resolved: &ResolvedCommand,
    matched_signatures: &[MatchedSignature],
    audit_log: &mut Vec<AutoInjectionLog>,
) -> Result<ResolvedCommand> {
    let mut result = resolved.clone();

    for signature in matched_signatures {
        for injection in &signature.injections {
            // Create audit log entry
            let (injection_type, target) = match &injection.injection_type {
                InjectionType::Env(name) => ("env".to_string(), name.clone()),
                InjectionType::File(path) => ("file".to_string(), path.display().to_string()),
                InjectionType::Header(name, _) => ("header".to_string(), name.clone()),
            };

            audit_log.push(AutoInjectionLog {
                signature_name: signature.signature_name.clone(),
                secret_path: injection.secret_path.as_str().to_string(),
                injection_type,
                target,
                optional: injection.optional,
                timestamp: chrono::Utc::now(),
            });

            // Apply the injection based on type
            match &injection.injection_type {
                InjectionType::Env(name) => {
                    // Add to environment injections
                    result
                        .env_injections
                        .push((name.clone(), injection.secret_path.as_str().to_string()));
                }
                InjectionType::File(path) => {
                    // Add to file injections
                    result.file_injections.push((
                        injection.secret_path.as_str().to_string(),
                        path.display().to_string(),
                    ));
                }
                InjectionType::Header(name, format) => {
                    // For headers, we'd need to rewrite the command to include the header
                    // This is more complex and would require command rewriting
                    debug!(
                        "Header injection requested: {}={}, requires command rewriting",
                        name, format
                    );
                    // For now, log that header injection requires command rewriting
                    warn!(
                        "Header injection '{}' requires command rewriting (not yet implemented)",
                        name
                    );
                }
            }
        }
    }

    Ok(result)
}

/// Resolve secret placeholders in a command
fn resolve_secrets(parsed: &ResolvedCommand) -> Result<ResolvedCommand> {
    // In a full implementation, this would:
    // 1. Load secrets from the vault
    // 2. Substitute placeholders with actual values
    // 3. Handle env injections, file injections, and stdin

    // For now, return the resolved command as-is
    // The CommandParser::resolve_command already does the parsing
    Ok(parsed.clone())
}

/// Build a sandboxed command
fn build_sandbox_command(resolved: &ResolvedCommand, config: &ExecuteConfig) -> Result<Command> {
    #[cfg(target_os = "linux")]
    {
        use sigil_sandbox::BubblewrapSandbox;

        let sandbox = BubblewrapSandbox::new().context("Failed to create sandbox")?;

        if !sandbox.is_available() {
            warn!("Bubblewrap not available, falling back to non-sandboxed execution");
            return build_plain_command(resolved);
        }

        // Build sandbox config
        let mut sandbox_config = SandboxConfig {
            network_isolated: config.network_isolated,
            working_dir: std::env::current_dir().ok(),
            ..Default::default()
        };

        if let Some(project_dir) = &config.project_dir {
            sandbox_config.project_dir = Some(project_dir.clone());
        }

        // Track secure files for cleanup (they'll be deleted when dropped)
        let mut _secure_files: Vec<SecureFile> = Vec::new();

        // Add file injections
        for (secret_path_str, target_path) in &resolved.file_injections {
            debug!(
                "File injection requested: {} -> {}",
                secret_path_str, target_path
            );

            // Load secret value from vault
            let secret_path = SecretPath::new(secret_path_str.as_str())
                .context("Invalid secret path for file injection")?;

            let vault = load_vault().context("Failed to load vault for file injection")?;
            let rt = tokio::runtime::Runtime::new().context("Failed to create async runtime")?;

            let secret_value = rt.block_on(vault.get(&secret_path)).with_context(|| {
                format!(
                    "Failed to load secret {} for file injection",
                    secret_path_str
                )
            })?;

            // Get secret bytes and create a secure file using memfd_create (Linux) or secure tempfile (macOS)
            secret_value.expose(|bytes| {
                // Create a secure file using memfd_create on Linux (TOCTOU-safe, no filesystem path)
                // On macOS, uses mkstemp + immediate unlink with 0700 temp directory
                let mut secure_file = SecureFile::create(secret_path_str)
                    .context("Failed to create secure file for secret injection")?;

                // Write secret to secure file
                secure_file
                    .write(bytes)
                    .context("Failed to write secret to secure file")?;

                // Seal the file to prevent further modifications (defense-in-depth)
                secure_file.seal().context("Failed to seal secure file")?;

                // Get the path to the secure file (None on Linux for memfd, Some path on macOS)
                let secure_path = secure_file
                    .path()
                    .map(|p| p.display().to_string())
                    .unwrap_or_else(|| format!("/proc/self/fd/{}", secure_file.as_raw_fd()));

                // Keep the secure file alive so it's not deleted before the command runs
                _secure_files.push(secure_file);

                // Add bind mount from secure file to target path
                // On Linux: uses /proc/self/fd/{fd} for memfd
                // On macOS: uses the unlinked temp file path
                sandbox_config
                    .file_injections
                    .push((secure_path.clone(), PathBuf::from(target_path)));

                debug!(
                    "Injected secret {} into secure file {}",
                    secret_path_str, secure_path
                );

                Ok::<(), anyhow::Error>(())
            })?;
        }

        // Add environment injections
        for (name, secret_path) in &resolved.env_injections {
            sandbox_config = sandbox_config.with_env(name.clone(), secret_path.clone());
        }

        // Wrap the command
        sandbox
            .wrap_command(resolved, &sandbox_config)
            .context("Failed to wrap command in sandbox")
    }

    #[cfg(target_os = "macos")]
    {
        use sigil_sandbox::SeatbeltSandbox;
        use std::io::Write;

        let sandbox = SeatbeltSandbox::new().context("Failed to create Seatbelt sandbox")?;

        if !sandbox.is_available() {
            warn!("Seatbelt not available, falling back to non-sandboxed execution");
            return build_plain_command(resolved);
        }

        // Build sandbox config
        let sandbox_config = SandboxConfig {
            network_isolated: config.network_isolated,
            ..Default::default()
        };

        // Track secure files for cleanup
        let mut _secure_files: Vec<SecureFile> = Vec::new();

        // Add file injections for macOS
        for (secret_path_str, target_path) in &resolved.file_injections {
            debug!(
                "File injection requested: {} -> {}",
                secret_path_str, target_path
            );

            // Load secret value from vault
            let secret_path = SecretPath::new(secret_path_str.as_str())
                .context("Invalid secret path for file injection")?;

            let vault = load_vault().context("Failed to load vault for file injection")?;
            let rt = tokio::runtime::Runtime::new().context("Failed to create async runtime")?;

            let secret_value = rt.block_on(vault.get(&secret_path)).with_context(|| {
                format!(
                    "Failed to load secret {} for file injection",
                    secret_path_str
                )
            })?;

            // Get secret bytes and create a secure file using mkstemp + immediate unlink (macOS)
            secret_value.expose(|bytes| {
                // Create a secure file using mkstemp + immediate unlink (macOS secure temp file)
                // The file is unlinked immediately, so it has no filesystem path
                let mut secure_file = SecureFile::create(secret_path_str)
                    .context("Failed to create secure file for secret injection")?;

                // Write secret to secure file
                secure_file
                    .write(bytes)
                    .context("Failed to write secret to secure file")?;

                // Seal the file to prevent further modifications
                secure_file.seal().context("Failed to seal secure file")?;

                // Get the path to the secure file (unlinked on macOS, but accessible via fd)
                let secure_path = secure_file
                    .path()
                    .map(|p| p.display().to_string())
                    .unwrap_or_else(|| format!("/dev/fd/{}", secure_file.as_raw_fd()));

                // Keep the secure file alive so it's not deleted before the command runs
                _secure_files.push(secure_file);

                sandbox_config
                    .file_injections
                    .push((secure_path.clone(), PathBuf::from(target_path)));

                debug!(
                    "Injected secret {} into secure file {}",
                    secret_path_str, secure_path
                );

                Ok::<(), anyhow::Error>(())
            })?;
        }

        sandbox
            .wrap_command(resolved, &sandbox_config)
            .context("Failed to wrap command in Seatbelt sandbox")
    }

    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        warn!("Sandboxing not supported on this platform, using plain execution");
        build_plain_command(resolved)
    }
}

/// Build a plain (non-sandboxed) command
fn build_plain_command(resolved: &ResolvedCommand) -> Result<Command> {
    // Parse the resolved command into arguments
    let parts = shell_words::split(&resolved.resolved)
        .map_err(|e| SigilError::InvalidConfig(format!("Invalid command: {}", e)))?;

    if parts.is_empty() {
        return Err(SigilError::InvalidConfig("Empty command".to_string()).into());
    }

    let mut cmd = Command::new(&parts[0]);
    for arg in &parts[1..] {
        cmd.arg(arg);
    }

    Ok(cmd)
}

/// Scrub secrets from command output
fn scrub_output(stdout: &str, stderr: &str) -> Result<(String, String, bool, usize)> {
    // Build scrubber with loaded secrets
    let mut scrubber = Scrubber::new();

    // Load all secrets from vault for scrubbing
    let vault = load_vault().context("Failed to load vault for scrubbing")?;

    let rt = tokio::runtime::Runtime::new().context("Failed to create async runtime")?;

    // Get all secrets to build scrubber patterns
    let secrets = rt
        .block_on(vault.list(""))
        .context("Failed to list secrets")?;

    for meta in secrets {
        let path = SecretPath::new(meta.path.as_str().to_string())?;
        let value = rt.block_on(vault.get(&path))?;
        value.expose(|bytes| {
            scrubber.add_secret(path, bytes);
            Ok::<(), anyhow::Error>(())
        })?;
    }

    // Scrub stdout
    let stdout_result = scrubber.scrub_with_stats(stdout);

    // Scrub stderr
    let stderr_result = scrubber.scrub_with_stats(stderr);

    let secrets_scrubbed = stdout_result.matches_found || stderr_result.matches_found;
    let secrets_detected = stdout_result.secrets_detected + stderr_result.secrets_detected;

    Ok((
        stdout_result.scrubbed,
        stderr_result.scrubbed,
        secrets_scrubbed,
        secrets_detected,
    ))
}

/// Capture shell state from command output
fn capture_shell_state(output: &str, _exit_code: i32, previous: &ShellState) -> ShellState {
    // Parse state capture markers from output
    let mut new_state = previous.clone();

    for line in output.lines() {
        if let Some(cwd) = line.strip_prefix(":::SIGIL_CWD:::") {
            new_state.cwd = PathBuf::from(cwd);
        } else if let Some(exit_str) = line.strip_prefix(":::SIGIL_EXIT:::") {
            if let Ok(code) = exit_str.parse::<i32>() {
                new_state.last_exit_code = Some(code);
            }
        }
    }

    new_state
}

/// Execute a command string and return the result
///
/// This is a convenience function for simple use cases.
#[allow(dead_code)]
pub fn execute_command(command: &str) -> Result<ExecuteResult> {
    execute(command, &ExecuteConfig::default())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_execute_config_default() {
        let config = ExecuteConfig::default();
        assert!(config.sandbox_enabled);
        assert!(config.network_isolated);
        assert!(config.scrub_enabled);
        assert!(!config.fail_on_leak);
    }

    #[test]
    fn test_build_plain_command() {
        let resolved = ResolvedCommand {
            original: "echo hello".to_string(),
            placeholders: Vec::new(),
            resolved: "echo hello".to_string(),
            env_injections: Vec::new(),
            file_injections: Vec::new(),
            stdin_secret: None,
            use_stdin: false,
        };

        let cmd = build_plain_command(&resolved).unwrap();
        assert_eq!(cmd.get_program(), "echo");
    }

    #[test]
    fn test_capture_shell_state() {
        let previous = ShellState::default();
        let output = "some output\n:::SIGIL_CWD:::/new/dir\n:::SIGIL_EXIT:::0\n";

        let new_state = capture_shell_state(output, 0, &previous);
        assert_eq!(new_state.cwd, PathBuf::from("/new/dir"));
        assert_eq!(new_state.last_exit_code, Some(0));
    }
}
