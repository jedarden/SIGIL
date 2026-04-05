//! Signal handling for SIGIL daemon
//!
//! Provides comprehensive signal handling for daemon lifecycle management:
//! - SIGTERM/SIGINT: Graceful shutdown
//! - SIGHUP: Reload configuration and rotate audit log
//! - SIGUSR1: Dump status to audit log
//! - SIGUSR2: Force audit log rotation
//! - SIGQUIT: Immediate exit for debugging
//! - SIGPIPE: Ignored (handled per-connection)

use anyhow::Result;
use std::sync::Arc;
use tokio::sync::broadcast;
use tokio::sync::RwLock;
use tracing::{info, warn};

/// Signal events that can be received
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignalEvent {
    /// Graceful shutdown requested (SIGTERM, SIGINT)
    Shutdown,
    /// Reload configuration (SIGHUP)
    Reload,
    /// Dump status to audit log (SIGUSR1)
    DumpStatus,
    /// Force audit log rotation (SIGUSR2)
    RotateLog,
    /// Immediate exit for debugging (SIGQUIT)
    Quit,
}

/// Signal handler configuration
#[derive(Clone)]
pub struct SignalHandlerConfig {
    /// Enable graceful shutdown on SIGTERM/SIGINT
    pub enable_shutdown: bool,
    /// Enable configuration reload on SIGHUP
    pub enable_reload: bool,
    /// Enable status dump on SIGUSR1
    pub enable_status_dump: bool,
    /// Enable log rotation on SIGUSR2
    pub enable_log_rotation: bool,
    /// Enable quit on SIGQUIT (debug mode)
    pub enable_quit: bool,
}

impl Default for SignalHandlerConfig {
    fn default() -> Self {
        Self {
            enable_shutdown: true,
            enable_reload: true,
            enable_status_dump: true,
            enable_log_rotation: true,
            enable_quit: false, // Disabled by default for production
        }
    }
}

/// Signal handler for the daemon
#[allow(dead_code)]
pub struct SignalHandler {
    /// Sender for signal events
    sender: broadcast::Sender<SignalEvent>,
    /// Receiver for signal events
    receiver: broadcast::Receiver<SignalEvent>,
    /// Running state
    running: Arc<RwLock<bool>>,
}

impl SignalHandler {
    /// Create a new signal handler
    pub fn new() -> Self {
        let (sender, receiver) = broadcast::channel(32);

        Self {
            sender,
            receiver,
            running: Arc::new(RwLock::new(false)),
        }
    }

    /// Get a receiver for signal events
    pub fn receiver(&self) -> broadcast::Receiver<SignalEvent> {
        self.sender.subscribe()
    }

    /// Get the running state
    #[allow(dead_code)]
    pub fn running(&self) -> Arc<RwLock<bool>> {
        self.running.clone()
    }

    /// Start the signal handler
    ///
    /// This spawns a background task that listens for signals and broadcasts events.
    pub async fn start(&self, config: SignalHandlerConfig) -> Result<()> {
        let mut sigterm =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
        let mut sigint = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::interrupt())?;
        let mut sighup = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::hangup())?;
        let mut sigusr1 =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::user_defined1())?;
        let mut sigusr2 =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::user_defined2())?;
        let mut sigquit = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::quit())?;

        let sender = self.sender.clone();
        let running = self.running.clone();

        // Mark as running
        *running.write().await = true;

        tokio::spawn(async move {
            info!("Signal handler started");

            loop {
                tokio::select! {
                    // SIGTERM - Graceful shutdown
                    _ = sigterm.recv() => {
                        if config.enable_shutdown {
                            info!("Received SIGTERM, initiating graceful shutdown");
                            let _ = sender.send(SignalEvent::Shutdown);
                            break;
                        }
                    }

                    // SIGINT - Same as SIGTERM (Ctrl+C)
                    _ = sigint.recv() => {
                        if config.enable_shutdown {
                            info!("Received SIGINT, initiating graceful shutdown");
                            let _ = sender.send(SignalEvent::Shutdown);
                            break;
                        }
                    }

                    // SIGHUP - Reload configuration
                    _ = sighup.recv() => {
                        if config.enable_reload {
                            info!("Received SIGHUP, reloading configuration");
                            let _ = sender.send(SignalEvent::Reload);
                        }
                    }

                    // SIGUSR1 - Dump status to audit log
                    _ = sigusr1.recv() => {
                        if config.enable_status_dump {
                            info!("Received SIGUSR1, dumping status to audit log");
                            let _ = sender.send(SignalEvent::DumpStatus);
                        }
                    }

                    // SIGUSR2 - Force audit log rotation
                    _ = sigusr2.recv() => {
                        if config.enable_log_rotation {
                            info!("Received SIGUSR2, forcing audit log rotation");
                            let _ = sender.send(SignalEvent::RotateLog);
                        }
                    }

                    // SIGQUIT - Immediate exit (debug mode)
                    _ = sigquit.recv() => {
                        if config.enable_quit {
                            warn!("Received SIGQUIT, immediate exit (debug mode)");
                            let _ = sender.send(SignalEvent::Quit);
                            break;
                        }
                    }
                }
            }

            // Mark as not running
            *running.write().await = false;
            info!("Signal handler stopped");
        });

        // Ignore SIGPIPE - handled per-connection
        #[cfg(unix)]
        {
            unsafe {
                // Ignore SIGPIPE globally
                let ret = libc::signal(libc::SIGPIPE, libc::SIG_IGN);
                if ret == libc::SIG_ERR {
                    warn!(
                        "Failed to ignore SIGPIPE: {}",
                        std::io::Error::last_os_error()
                    );
                } else {
                    info!("SIGPIPE ignored (handled per-connection)");
                }
            }
        }

        Ok(())
    }

    /// Request shutdown programmatically
    #[allow(dead_code)]
    pub fn shutdown(&self) -> Result<()> {
        self.sender
            .send(SignalEvent::Shutdown)
            .map_err(|e| anyhow::anyhow!("Failed to send shutdown signal: {}", e))?;
        Ok(())
    }

    /// Check if the signal handler is still running
    #[allow(dead_code)]
    pub async fn is_running(&self) -> bool {
        *self.running.read().await
    }

    /// Wait for the next signal event
    #[allow(dead_code)]
    pub async fn recv(&mut self) -> Result<SignalEvent> {
        self.receiver
            .recv()
            .await
            .map_err(|e| anyhow::anyhow!("Failed to receive signal event: {}", e))
    }
}

impl Default for SignalHandler {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[tokio::test]
    async fn test_signal_handler_creation() {
        let handler = SignalHandler::new();
        assert!(!handler.is_running().await);
    }

    #[tokio::test]
    async fn test_signal_handler_config_default() {
        let config = SignalHandlerConfig::default();
        assert!(config.enable_shutdown);
        assert!(config.enable_reload);
        assert!(config.enable_status_dump);
        assert!(config.enable_log_rotation);
        assert!(!config.enable_quit);
    }

    #[tokio::test]
    async fn test_signal_handler_shutdown() {
        let handler = SignalHandler::new();
        let mut receiver = handler.receiver();

        // Send shutdown signal
        handler.shutdown().unwrap();

        // Receive the signal
        let event = tokio::time::timeout(Duration::from_millis(100), receiver.recv())
            .await
            .unwrap()
            .unwrap();

        assert_eq!(event, SignalEvent::Shutdown);
    }

    #[tokio::test]
    async fn test_multiple_receivers() {
        let handler = SignalHandler::new();
        let mut receiver1 = handler.receiver();
        let mut receiver2 = handler.receiver();

        // Send shutdown signal
        handler.shutdown().unwrap();

        // Both receivers should get the signal
        let event1 = tokio::time::timeout(Duration::from_millis(100), receiver1.recv())
            .await
            .unwrap()
            .unwrap();
        let event2 = tokio::time::timeout(Duration::from_millis(100), receiver2.recv())
            .await
            .unwrap()
            .unwrap();

        assert_eq!(event1, SignalEvent::Shutdown);
        assert_eq!(event2, SignalEvent::Shutdown);
    }
}
