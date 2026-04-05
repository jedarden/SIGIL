//! SIGIL Proxy - HTTP forward proxy binary

#![warn(missing_docs)]
#![warn(clippy::all)]

use anyhow::Result;
use clap::Parser;
use sigil_proxy::ProxyConfig;
use std::path::PathBuf;
use tracing::{info, Level};
use tracing_subscriber::FmtSubscriber;

/// SIGIL HTTP forward proxy with auth header injection
#[derive(Parser, Debug)]
#[command(name = "sigil-proxy")]
#[command(author = "SIGIL Project")]
#[command(version = env!("CARGO_PKG_VERSION"))]
#[command(about = "HTTP forward proxy for SIGIL with auth header injection", long_about = None)]
struct Args {
    /// Path to proxy configuration file
    #[arg(short, long, default_value = "_sigil/proxy_rules")]
    config: PathBuf,

    /// Listen address (overrides config file)
    #[arg(short, long)]
    listen: Option<String>,

    /// Verbose logging
    #[arg(short, long)]
    verbose: bool,
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

    // Initialize logging
    let subscriber = FmtSubscriber::builder()
        .with_max_level(if args.verbose {
            Level::DEBUG
        } else {
            Level::INFO
        })
        .finish();

    tracing::subscriber::set_global_default(subscriber).expect("setting default subscriber failed");

    info!("Starting SIGIL proxy v{}", env!("CARGO_PKG_VERSION"));

    // Load configuration
    let config = if args.config.exists() {
        let toml_content = std::fs::read_to_string(&args.config)?;
        ProxyConfig::from_toml(&toml_content)?
    } else {
        ProxyConfig::default()
    };

    // Override listen address if specified
    let listen = args.listen.unwrap_or_else(|| config.listen.clone());

    info!("Proxy configured with {} rules", config.rules.len());

    // Print allowed domains
    if !config.rules.is_empty() {
        info!("Allowed domains:");
        for rule in &config.rules {
            info!("  - {}", rule.domain);
        }
    }

    info!("Starting proxy on {}", listen);

    // Create and start the proxy server
    let _server = sigil_proxy::ProxyServer::new(config.clone())?;

    // For now, just print a message since we need daemon integration
    println!("SIGIL Proxy v{}", env!("CARGO_PKG_VERSION"));
    println!();
    println!("Configuration:");
    println!("  Listen address: {}", listen);
    println!("  Rules: {}", config.rules.len());
    println!();
    println!("The proxy will be integrated with the daemon in Phase 9.2.");
    println!("For now, this is a standalone implementation.");

    Ok(())
}
