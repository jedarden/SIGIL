//! SIGIL FUSE - FUSE virtual filesystem for secret exposure

#![warn(missing_docs)]
#![warn(clippy::all)]

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use sigil_fuse::{mount_sigil, unmount_sigil, FuseConfig};
use std::path::PathBuf;
use tracing::{error, info};
use tracing_subscriber::EnvFilter;

/// SIGIL FUSE - FUSE virtual filesystem for secret exposure
#[derive(Parser, Debug)]
#[command(name = "sigil-fuse")]
#[command(author = "SIGIL Contributors")]
#[command(version = env!("CARGO_PKG_VERSION"))]
#[command(about = "FUSE virtual filesystem for SIGIL secret exposure", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Mount the SIGIL FUSE filesystem
    Mount {
        /// Mount point (default: /sigil)
        #[arg(short, long, default_value = "/sigil")]
        mount_point: PathBuf,

        /// Path to SIGIL daemon socket
        #[arg(short, long, default_value = "~/.sigil/sigild.sock")]
        socket: PathBuf,

        /// Session token for daemon authentication
        #[arg(short, long)]
        token: Option<String>,

        /// Allow only this PID to access the filesystem
        #[arg(short = 'p', long)]
        sandbox_pid: Option<u32>,

        /// Allow only this UID to access the filesystem
        #[arg(short = 'u', long)]
        sandbox_uid: Option<u32>,

        /// Allow this GID to access the filesystem (can be specified multiple times)
        #[arg(short = 'g', long)]
        allowed_gid: Vec<u32>,

        /// Disable automatic file generation (aws/credentials, k8s/kubeconfig, etc.)
        #[arg(long)]
        no_auto_generate: bool,

        /// Run in foreground (don't daemonize)
        #[arg(short, long)]
        foreground: bool,
    },

    /// Unmount the SIGIL FUSE filesystem
    Unmount {
        /// Mount point to unmount
        #[arg(short, long, default_value = "/sigil")]
        mount_point: PathBuf,
    },

    /// Check if the FUSE filesystem is mounted
    Status {
        /// Mount point to check
        #[arg(short, long, default_value = "/sigil")]
        mount_point: PathBuf,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    // Initialize logging
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();

    match cli.command {
        Commands::Mount {
            mount_point,
            socket,
            token,
            sandbox_pid,
            sandbox_uid,
            allowed_gid,
            no_auto_generate,
            foreground,
        } => {
            // Expand tilde in socket path
            let socket_path = expand_tilde(&socket);

            // Get session token from env var or argument
            let session_token = token
                .or_else(|| std::env::var("SIGIL_SESSION_TOKEN").ok())
                .unwrap_or_else(|| {
                    // Try to get from running daemon
                    info!("No session token provided, will authenticate with daemon");
                    String::new()
                });

            // Create configuration
            let mut config = FuseConfig::new(mount_point.clone(), socket_path, session_token)
                .with_auto_generate(!no_auto_generate);

            if let Some(pid) = sandbox_pid {
                config = config.with_sandbox_pid(pid);
            }

            if let Some(uid) = sandbox_uid {
                config = config.with_sandbox_uid(uid);
            }

            for gid in allowed_gid {
                config = config.with_allowed_gid(gid);
            }

            // Mount the filesystem
            let mut session = mount_sigil(config.clone())
                .await
                .context("Failed to mount FUSE filesystem")?;

            info!(
                "SIGIL FUSE mounted at {} (PID: {})",
                mount_point.display(),
                std::process::id()
            );

            // Run in foreground
            if foreground {
                info!("Running in foreground. Press Ctrl+C to unmount and exit.");
                tokio::select! {
                    _ = tokio::signal::ctrl_c() => {
                        info!("Received Ctrl+C, unmounting...");
                    }
                    result = session.run() => {
                        if let Err(e) = result {
                            error!("FUSE session error: {}", e);
                        }
                    }
                }
            } else {
                // Run in background
                info!("Running in background...");
                if let Err(e) = session.run().await {
                    error!("FUSE session error: {}", e);
                }
            }
        }

        Commands::Unmount { mount_point } => {
            info!("Unmounting SIGIL FUSE at {}", mount_point.display());
            unmount_sigil(&mount_point)
                .context("Failed to unmount FUSE filesystem")?;
            info!("Successfully unmounted");
        }

        Commands::Status { mount_point } => {
            if mount_point.exists() {
                // Check if actually mounted by reading /proc/mounts
                if Path::new("/proc/mounts").exists() {
                    let mounts = std::fs::read_to_string("/proc/mounts")?;
                    let path_str = mount_point.to_str().unwrap_or("");
                    let mounted = mounts.lines().any(|line| {
                        let parts: Vec<&str> = line.split_whitespace().collect();
                        if parts.len() >= 2 {
                            parts[1] == path_str
                        } else {
                            false
                        }
                    });

                    if mounted {
                        println!("Mounted at {}", mount_point.display());
                        return Ok(());
                    }
                }
                println!("Not mounted (mount point exists but no filesystem mounted)");
            } else {
                println!("Not mounted (mount point does not exist)");
            }
        }
    }

    Ok(())
}

/// Expand tilde in a path
fn expand_tilde(path: &PathBuf) -> PathBuf {
    if let Some(s) = path.to_str() {
        if s.starts_with("~/") {
            if let Some(home) = std::env::var("HOME").ok() {
                return PathBuf::from(format!("{}{}", home, &s[1..]));
            }
        }
    }
    path.clone()
}
