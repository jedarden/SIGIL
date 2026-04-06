//! SIGIL Daemon - Long-running daemon for secret management
//!
//! The daemon (sigild) holds decrypted secrets in memory and serves requests
//! via Unix domain socket with session token authentication.

#![warn(missing_docs)]
#![warn(clippy::all)]

mod alerts;
mod audit;
mod canary_manager;
mod ci_bridge;
mod client;
mod lease_tracker;
mod memory;
mod ondemand;
mod proxy;
mod server;
mod signals;
mod vault;

use anyhow::Result;
use ci_bridge::CiBridge;
use clap::{Parser, Subcommand};
use nix::unistd::Uid;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use tracing::{error, info, warn};

use audit::AuditLogger;
use canary_manager::CanaryManager;
use memory::enable_memory_protection;
use server::DaemonServer;
use signals::{SignalEvent, SignalHandler, SignalHandlerConfig};
use vault::VaultManager;

/// SIGIL daemon (sigild)
#[derive(Parser, Debug)]
#[command(name = "sigild")]
#[command(about = "SIGIL daemon for secret management", long_about = None)]
#[command(version)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Start the daemon
    Start {
        /// Socket path (default: $XDG_RUNTIME_DIR/sigil.sock)
        #[arg(short, long)]
        socket: Option<PathBuf>,

        /// Idle timeout before shutdown (e.g., "30m", "1h", "never")
        #[arg(short, long, default_value = "30m")]
        idle_timeout: String,

        /// Vault path (default: ~/.sigil/vault)
        #[arg(short, long)]
        vault: Option<PathBuf>,

        /// Run as systemd socket-activated service
        #[arg(long)]
        systemd: bool,

        /// Run as launchd service (macOS)
        #[arg(long)]
        launchd: bool,

        /// Skip health check on startup
        #[arg(long)]
        skip_doctor: bool,

        /// CI mode (non-interactive, loads from SIGIL_SECRET_* env vars)
        #[arg(long)]
        ci: bool,
    },

    /// Stop the daemon
    Stop {
        /// Socket path (default: $XDG_RUNTIME_DIR/sigil.sock)
        #[arg(short, long)]
        socket: Option<PathBuf>,
    },

    /// Check if daemon is running
    Status {
        /// Socket path (default: $XDG_RUNTIME_DIR/sigil.sock)
        #[arg(short, long)]
        socket: Option<PathBuf>,
    },

    /// Restart the daemon
    Restart {
        /// Socket path (default: $XDG_RUNTIME_DIR/sigil.sock)
        #[arg(short, long)]
        socket: Option<PathBuf>,

        /// Idle timeout before shutdown
        #[arg(short, long, default_value = "30m")]
        idle_timeout: String,

        /// Skip health check on startup
        #[arg(long)]
        skip_doctor: bool,

        /// CI mode (non-interactive, loads from SIGIL_SECRET_* env vars)
        #[arg(long)]
        ci: bool,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    // Check for CI mode before setting up tracing
    // We check the env var directly since we haven't processed the --ci flag yet
    let is_ci_env = CiBridge::is_ci_mode();

    // Initialize tracing with JSON formatting in CI mode
    if is_ci_env {
        tracing_subscriber::fmt()
            .json()
            .with_env_filter(
                tracing_subscriber::EnvFilter::from_default_env()
                    .add_directive(tracing::Level::INFO.into()),
            )
            .init();
    } else {
        tracing_subscriber::fmt()
            .with_env_filter(
                tracing_subscriber::EnvFilter::from_default_env()
                    .add_directive(tracing::Level::INFO.into()),
            )
            .init();
    }

    match cli.command {
        Commands::Start {
            socket,
            idle_timeout,
            vault,
            systemd,
            launchd,
            skip_doctor,
            ci,
        } => {
            // Parse idle timeout
            let timeout_duration = parse_duration(&idle_timeout)?;

            // Determine socket path
            let socket_path = socket.unwrap_or_else(default_socket_path);

            // Determine vault path
            let vault_path = vault.unwrap_or_else(default_vault_path);

            // Start daemon
            start_daemon(
                socket_path,
                timeout_duration,
                vault_path,
                systemd,
                launchd,
                skip_doctor,
                ci,
            )
            .await
        }
        Commands::Stop { socket } => {
            let socket_path = socket.unwrap_or_else(default_socket_path);
            stop_daemon(socket_path).await
        }
        Commands::Status { socket } => {
            let socket_path = socket.unwrap_or_else(default_socket_path);
            status_daemon(socket_path).await
        }
        Commands::Restart {
            socket,
            idle_timeout,
            skip_doctor,
            ci,
        } => {
            let socket_path = socket.unwrap_or_else(default_socket_path);
            let timeout_duration = parse_duration(&idle_timeout)?;
            restart_daemon(socket_path, timeout_duration, skip_doctor, ci).await
        }
    }
}

/// Start the daemon
async fn start_daemon(
    socket_path: PathBuf,
    idle_timeout: Duration,
    vault_path: PathBuf,
    _systemd: bool,
    _launchd: bool,
    skip_doctor: bool,
    ci_mode: bool,
) -> Result<()> {
    // Enable memory protection FIRST, before loading any secrets
    enable_memory_protection()?;

    info!("Starting SIGIL daemon v{}", env!("CARGO_PKG_VERSION"));
    info!("Socket path: {}", socket_path.display());
    info!("Idle timeout: {:?}", idle_timeout);

    // Run health check on startup (unless skipped)
    if !skip_doctor {
        info!("Running startup health check...");
        if let Err(e) = run_startup_health_check().await {
            warn!("Startup health check completed with warnings: {}", e);
            // Log warnings but don't prevent startup - admin may have reasons
        } else {
            info!("Startup health check passed");
        }
    } else {
        info!("Skipping startup health check (--skip-doctor flag set)");
    }

    // Check if daemon is already running
    if socket_path.exists() {
        // Try to connect to see if it's alive
        if let Ok(mut client) = client::DaemonClient::connect(&socket_path).await {
            match client.ping().await {
                Ok(_) => {
                    warn!("Daemon is already running");
                    return Ok(());
                }
                Err(_) => {
                    // Stale socket file, remove it
                    info!("Removing stale socket file");
                    std::fs::remove_file(&socket_path)?;
                }
            }
        }
    }

    // Initialize audit logger
    let audit_logger = Arc::new(
        AuditLogger::new(vault_path.join("audit.jsonl"))
            .map_err(|e| anyhow::anyhow!("Failed to initialize audit logger: {}", e))?,
    );

    // Create canary overlay directory in tmpfs
    let canary_overlay = if let Ok(runtime_dir) = std::env::var("XDG_RUNTIME_DIR") {
        PathBuf::from(runtime_dir).join("sigil-canary-overlay")
    } else {
        PathBuf::from("/tmp").join(format!("sigil-canary-{}", std::process::id()))
    };

    // Create canary manager (enabled by default)
    let canary_manager = Arc::new(CanaryManager::new(canary_overlay, true));

    // Initialize canaries
    canary_manager.initialize().await?;

    // Determine CI mode (from flag or environment variable)
    let is_ci = ci_mode || CiBridge::is_ci_mode();

    // Create daemon server (with protected secrets store and canary manager)
    let server = DaemonServer::new_with_mode(
        socket_path.clone(),
        idle_timeout,
        vault_path.clone(),
        audit_logger.clone(),
        canary_manager,
        is_ci,
        _systemd || _launchd,
    )?;

    // Unlock the vault and load secrets into protected memory
    let token_file_path = if is_ci {
        info!("CI mode enabled - loading secrets from SIGIL_SECRET_* environment variables");

        // Load CI secrets from environment variables
        let ci_secrets_loaded = CiBridge::load_ci_secrets(server.protected_secrets())
            .await
            .map_err(|e| anyhow::anyhow!("Failed to load CI secrets: {}", e))?;

        info!("Loaded {} CI secrets from environment", ci_secrets_loaded);

        // Try to unlock vault if it exists, but don't fail if it doesn't
        let mut vault_manager = VaultManager::new(vault_path.clone())
            .map_err(|e| anyhow::anyhow!("Failed to create vault manager: {}", e))?;

        if vault_manager.exists() {
            info!("Vault found, unlocking...");
            let _session_token = vault_manager
                .unlock_async(server.protected_secrets())
                .await
                .map_err(|e| anyhow::anyhow!("Failed to unlock vault: {}", e))?;
            info!("Vault unlocked successfully");
            Some(vault_manager.session_token_file().path().clone())
        } else {
            info!("No vault found, running with CI secrets only");
            None
        }
    } else {
        info!("Unlocking vault...");
        let mut vault_manager = VaultManager::new(vault_path.clone())
            .map_err(|e| anyhow::anyhow!("Failed to create vault manager: {}", e))?;
        let _session_token = vault_manager
            .unlock_async(server.protected_secrets())
            .await
            .map_err(|e| anyhow::anyhow!("Failed to unlock vault: {}", e))?;
        Some(vault_manager.session_token_file().path().clone())
    };

    // Sync loaded secrets to the output scrubber
    server
        .sync_secrets_to_scrubber()
        .await
        .map_err(|e| anyhow::anyhow!("Failed to sync secrets to scrubber: {}", e))?;
    info!("Secrets synced to scrubber");

    // Load proxy configuration from vault if available
    let proxy_rules_path = vault_path.join("_sigil").join("proxy_rules");
    if proxy_rules_path.exists() {
        info!("Loading proxy configuration from vault...");
        match std::fs::read_to_string(&proxy_rules_path) {
            Ok(rules_toml) => {
                if let Err(e) = server
                    .proxy_manager()
                    .load_rules_from_vault(&rules_toml)
                    .await
                {
                    warn!("Failed to load proxy configuration: {}", e);
                } else {
                    info!("Proxy configuration loaded successfully");

                    // Start the proxy server
                    if let Err(e) = server.proxy_manager().start().await {
                        warn!("Failed to start proxy server: {}", e);
                    } else {
                        info!("Proxy server started successfully");
                    }
                }
            }
            Err(e) => {
                warn!("Failed to read proxy configuration file: {}", e);
            }
        }
    } else {
        info!("No proxy configuration found in vault");
    }

    // Log session start
    audit_logger.log_session_start().await;

    // Set up signal handlers
    let signal_handler = SignalHandler::new();
    let mut signal_receiver = signal_handler.receiver();

    // Configure signal handling (enable all except quit for production)
    let signal_config = SignalHandlerConfig {
        enable_shutdown: true,
        enable_reload: true,
        enable_status_dump: true,
        enable_log_rotation: true,
        enable_quit: false, // Disable quit in production
    };

    signal_handler
        .start(signal_config)
        .await
        .map_err(|e| anyhow::anyhow!("Failed to start signal handler: {}", e))?;

    let server_clone = server.clone();
    let audit_logger_clone = audit_logger.clone();

    // Spawn signal handling task
    let shutdown_task = tokio::spawn(async move {
        loop {
            match signal_receiver.recv().await {
                Ok(SignalEvent::Shutdown) => {
                    info!("Received shutdown signal");
                    break;
                }
                Ok(SignalEvent::Reload) => {
                    info!("Reloading configuration");
                    // Reload configuration from file
                    if let Err(e) = server_clone.reload_config().await {
                        error!("Failed to reload configuration: {}", e);
                    } else {
                        info!("Configuration reloaded successfully");
                    }
                }
                Ok(SignalEvent::DumpStatus) => {
                    info!("Dumping status to audit log");
                    // Dump detailed daemon status
                    match server_clone.dump_status().await {
                        Ok(status) => {
                            info!(
                                "Status dump: {}",
                                serde_json::to_string_pretty(&status)
                                    .unwrap_or_else(|_| "Failed to serialize".to_string())
                            );
                        }
                        Err(e) => {
                            error!("Failed to dump status: {}", e);
                        }
                    }
                }
                Ok(SignalEvent::RotateLog) => {
                    info!("Forcing audit log rotation");
                    // Rotate the audit log with default configuration
                    let config = audit::AuditConfig::default();
                    if let Err(e) = audit_logger_clone.rotate(&config).await {
                        error!("Failed to rotate audit log: {}", e);
                    } else {
                        info!("Audit log rotated successfully");
                    }
                }
                Ok(SignalEvent::Quit) => {
                    warn!("Received SIGQUIT, immediate exit");
                    break;
                }
                Err(e) => {
                    error!("Error receiving signal event: {}", e);
                    break;
                }
            }
        }

        // Graceful shutdown
        if let Err(e) = server_clone.shutdown().await {
            error!("Error during shutdown: {}", e);
        }
    });

    // Start the server
    info!("Daemon started, listening on {}", socket_path.display());

    // Notify systemd that we're ready (if running under systemd)
    #[cfg(target_os = "linux")]
    {
        if _systemd || _launchd {
            info!("Sending READY=1 notification to systemd");
            server.notify_ready().await;
        }
    }

    // Wait for shutdown
    match shutdown_task.await {
        Ok(()) => {}
        Err(e) => error!("Shutdown task join error: {}", e),
    }

    // Log session end
    audit_logger.log_session_end().await;

    // Clean up session token file (if exists)
    if let Some(path) = token_file_path {
        if let Err(e) = std::fs::remove_file(&path) {
            warn!("Failed to remove session token file: {}", e);
        } else {
            info!("Session token file removed");
        }
    }

    info!("Daemon stopped");

    Ok(())
}

/// Run startup health check
async fn run_startup_health_check() -> Result<()> {
    use std::process::Command;

    let mut issues = Vec::new();

    // Check bubblewrap availability
    #[cfg(target_os = "linux")]
    {
        if !Command::new("bwrap")
            .arg("--version")
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false)
        {
            issues.push("bubblewrap not found - sandbox unavailable".to_string());
        }
    }

    // Check vault directory exists
    let home =
        std::env::var("HOME").map_err(|_| anyhow::anyhow!("Cannot determine home directory"))?;
    let sigil_dir = std::path::PathBuf::from(home).join(".sigil");
    let vault_path = sigil_dir.join("vault");
    let identity_path = sigil_dir.join("identity.age");

    if !sigil_dir.exists() {
        issues.push("Vault not initialized (run 'sigil init')".to_string());
    } else if !vault_path.exists() {
        issues.push("Vault directory not found".to_string());
    } else if !identity_path.exists() {
        issues.push("Vault identity file not found".to_string());
    }

    // Report issues
    if !issues.is_empty() {
        let error_msg = issues.join("; ");
        return Err(anyhow::anyhow!("Health check issues: {}", error_msg));
    }

    Ok(())
}

/// Stop the daemon
async fn stop_daemon(socket_path: PathBuf) -> Result<()> {
    if !socket_path.exists() {
        println!("Daemon is not running (socket not found)");
        return Ok(());
    }

    // Try to connect and send shutdown request
    match client::DaemonClient::connect(&socket_path).await {
        Ok(mut client) => {
            println!("Stopping daemon...");
            client.send_shutdown().await?;
            println!("Daemon stopped");
            Ok(())
        }
        Err(_) => {
            // Can't connect, try to remove stale socket
            println!("Removing stale socket file");
            std::fs::remove_file(&socket_path)?;
            Ok(())
        }
    }
}

/// Check daemon status
async fn status_daemon(socket_path: PathBuf) -> Result<()> {
    if !socket_path.exists() {
        println!("Daemon is not running (socket not found)");
        return Ok(());
    }

    match client::DaemonClient::connect(&socket_path).await {
        Ok(mut client) => {
            let status = client.status().await?;
            println!("Daemon status:");
            println!("  Version: {}", status.version);
            println!("  Unlocked: {}", status.unlocked);
            println!("  Secrets loaded: {}", status.secret_count);
            println!("  Active sessions: {}", status.session_count);
            println!("  Uptime: {}s", status.uptime_secs);
            if let Some(timeout) = status.idle_timeout_secs {
                println!("  Idle timeout: {}s", timeout);
            } else {
                println!("  Idle timeout: never");
            }
            println!("  Backend: {}", status.backend_type);
            Ok(())
        }
        Err(_) => {
            println!("Daemon is not responding");
            Ok(())
        }
    }
}

/// Restart the daemon
async fn restart_daemon(
    socket_path: PathBuf,
    idle_timeout: Duration,
    skip_doctor: bool,
    ci: bool,
) -> Result<()> {
    // Stop if running
    if socket_path.exists() {
        if let Ok(mut client) = client::DaemonClient::connect(&socket_path).await {
            let _ = client.send_shutdown().await;
            tokio::time::sleep(Duration::from_millis(500)).await;
        }
    }

    // Start daemon
    let vault_path = default_vault_path();
    start_daemon(
        socket_path,
        idle_timeout,
        vault_path,
        false,
        false,
        skip_doctor,
        ci,
    )
    .await
}

/// Get default socket path
///
/// Returns $XDG_RUNTIME_DIR/sigil.sock if available,
/// otherwise falls back to /tmp/sigil-$UID.sock for compatibility
/// with environments lacking XDG_RUNTIME_DIR (e.g., minimal WSL configs).
fn default_socket_path() -> PathBuf {
    if let Ok(runtime_dir) = std::env::var("XDG_RUNTIME_DIR") {
        PathBuf::from(runtime_dir).join("sigil.sock")
    } else {
        // Fallback to /tmp/sigil-UID.sock
        // Use UID (not PID) so all processes for the same user share the same socket
        let uid = Uid::effective();
        PathBuf::from("/tmp").join(format!("sigil-{}.sock", uid))
    }
}

/// Get default vault path
///
/// Returns the .sigil directory (e.g., ~/.sigil), not the vault subdirectory.
/// The VaultManager will construct the actual paths from this.
fn default_vault_path() -> PathBuf {
    if let Ok(home) = std::env::var("HOME") {
        PathBuf::from(home).join(".sigil")
    } else {
        PathBuf::from("/var/lib/sigil")
    }
}

/// Parse duration string (e.g., "30m", "1h", "never")
fn parse_duration(s: &str) -> Result<Duration> {
    let s = s.trim().to_lowercase();

    if s == "never" {
        return Ok(Duration::from_secs(u64::MAX));
    }

    // Find the first non-digit character
    let split_pos = s
        .find(|c: char| !c.is_ascii_digit() && c != '.')
        .unwrap_or(s.len());

    let num_str = &s[..split_pos];
    let suffix = &s[split_pos..];

    let num: f64 = num_str
        .parse()
        .map_err(|_| anyhow::anyhow!("Invalid duration: {}", s))?;

    let secs = match suffix {
        "s" | "sec" | "second" | "seconds" => num,
        "m" | "min" | "minute" | "minutes" => num * 60.0,
        "h" | "hour" | "hours" => num * 3600.0,
        "d" | "day" | "days" => num * 86400.0,
        _ => return Err(anyhow::anyhow!("Unknown duration suffix: {}", suffix)),
    };

    Ok(Duration::from_secs_f64(secs))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_duration() {
        assert_eq!(parse_duration("30s").unwrap(), Duration::from_secs(30));
        assert_eq!(parse_duration("5m").unwrap(), Duration::from_secs(300));
        assert_eq!(parse_duration("2h").unwrap(), Duration::from_secs(7200));
        assert_eq!(parse_duration("1d").unwrap(), Duration::from_secs(86400));
        assert_eq!(
            parse_duration("never").unwrap(),
            Duration::from_secs(u64::MAX)
        );
    }

    #[test]
    fn test_parse_duration_invalid() {
        assert!(parse_duration("invalid").is_err());
        assert!(parse_duration("30x").is_err());
    }
}
