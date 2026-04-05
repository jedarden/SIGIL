//! SIGIL SSH Agent - SSH agent binary
//!
//! This is the main entry point for the SIGIL SSH agent binary.

#![warn(missing_docs)]
#![warn(clippy::all)]

use anyhow::Result;
use clap::{Parser, Subcommand};
use sigil_ssh_agent::{Config, SshAgent};
use std::path::PathBuf;
use tracing::info;

/// SIGIL SSH agent - Serve SSH keys from SIGIL vault
#[derive(Parser, Debug)]
#[command(name = "sigil-ssh-agent")]
#[command(about = "SSH agent for SIGIL vault", long_about = None)]
#[command(version)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Start the SSH agent server
    Start {
        /// Socket path (default: $XDG_RUNTIME_DIR/sigil-ssh-agent.sock)
        #[arg(short, long)]
        socket: Option<PathBuf>,

        /// SIGIL daemon socket path
        #[arg(short, long)]
        sigil_socket: Option<PathBuf>,

        /// Session token for SIGIL daemon
        #[arg(short, long)]
        token: Option<String>,

        /// Require confirmation before each key use
        #[arg(long)]
        confirm: bool,

        /// Maximum key lifetime in seconds
        #[arg(short = 'l', long)]
        lifetime: Option<u64>,

        /// Enable verbose logging
        #[arg(short, long)]
        verbose: bool,
    },

    /// Print the socket path (for shell integration)
    PrintSocket {
        /// Socket path (default: $XDG_RUNTIME_DIR/sigil-ssh-agent.sock)
        #[arg(short, long)]
        socket: Option<PathBuf>,
    },

    /// Stop a running SSH agent
    Stop {
        /// Socket path (default: $XDG_RUNTIME_DIR/sigil-ssh-agent.sock)
        #[arg(short, long)]
        socket: Option<PathBuf>,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Start {
            socket,
            sigil_socket,
            token,
            confirm,
            lifetime,
            verbose,
        } => {
            // Initialize tracing
            if verbose {
                tracing_subscriber::fmt()
                    .with_max_level(tracing::Level::DEBUG)
                    .init();
            } else {
                tracing_subscriber::fmt()
                    .with_max_level(tracing::Level::INFO)
                    .init();
            }

            // Build configuration
            let mut config = if let Some(socket_path) = socket {
                let sigil_sock = sigil_socket.unwrap_or_else(|| {
                    PathBuf::from(std::env::var("SIGIL_SOCKET").unwrap_or_else(|_| {
                        format!(
                            "{}/.sigil/sigild.sock",
                            std::env::var("HOME").unwrap_or_else(|_| ".".to_string())
                        )
                    }))
                });

                let session_token = token
                    .unwrap_or_else(|| std::env::var("SIGIL_SESSION_TOKEN").unwrap_or_default());

                Config::new(socket_path, sigil_sock, session_token)
            } else {
                Config::default()
            };

            config.confirm_before_use = confirm;
            if let Some(max_lifetime) = lifetime {
                config.max_key_lifetime = Some(max_lifetime);
            }
            config.verbose = verbose;

            // Start agent
            let mut agent = SshAgent::new(config);
            agent.run().await?;
        }
        Commands::PrintSocket { socket } => {
            let socket_path = socket.unwrap_or_else(|| {
                let runtime_dir = std::env::var("XDG_RUNTIME_DIR")
                    .or_else(|_| std::env::var("TMPDIR"))
                    .unwrap_or_else(|_| "/tmp".to_string());
                PathBuf::from(format!("{}/sigil-ssh-agent.sock", runtime_dir))
            });

            println!("{}", socket_path.display());
        }
        Commands::Stop { socket } => {
            let socket_path = socket.unwrap_or_else(|| {
                let runtime_dir = std::env::var("XDG_RUNTIME_DIR")
                    .or_else(|_| std::env::var("TMPDIR"))
                    .unwrap_or_else(|_| "/tmp".to_string());
                PathBuf::from(format!("{}/sigil-ssh-agent.sock", runtime_dir))
            });

            // Remove socket file to stop agent
            if socket_path.exists() {
                std::fs::remove_file(&socket_path)?;
                info!("Stopped SSH agent at {}", socket_path.display());
            } else {
                eprintln!("SSH agent not running at {}", socket_path.display());
                std::process::exit(1);
            }
        }
    }

    Ok(())
}
