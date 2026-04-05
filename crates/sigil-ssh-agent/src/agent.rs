//! SSH agent server implementation
//!
//! This module implements the SSH agent server that listens on a Unix domain socket
//! and responds to SSH agent protocol requests.

use crate::keys::{KeyConstraint, KeyManager};
use crate::protocol::{parse_request, serialize_response, IdentityEntry, Request, Response};
use crate::Config;
use anyhow::{Context, Result};
use sigil_tui::approval::{ApprovalPrompt, ApprovalRequest};
use std::path::PathBuf;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::mpsc;
use tracing::{debug, error, info, warn};

/// SSH agent configuration
pub type SshAgentConfig = Config;

/// SSH agent server
pub struct SshAgent {
    /// Agent configuration
    config: Config,
    /// Key manager for loading and signing keys
    key_manager: KeyManager,
    /// Shutdown channel sender
    shutdown_tx: Option<mpsc::Sender<()>>,
}

impl SshAgent {
    /// Create a new SSH agent
    pub fn new(config: Config) -> Self {
        let key_manager =
            KeyManager::new(config.sigil_socket.clone(), config.session_token.clone());

        Self {
            config,
            key_manager,
            shutdown_tx: None,
        }
    }

    /// Start the SSH agent server
    pub async fn run(&mut self) -> Result<()> {
        // Remove existing socket file if present
        if self.config.socket_path.exists() {
            std::fs::remove_file(&self.config.socket_path)?;
        }

        // Create parent directory if needed
        if let Some(parent) = self.config.socket_path.parent() {
            std::fs::create_dir_all(parent)?;
        }

        // Bind to socket
        let listener = UnixListener::bind(&self.config.socket_path)
            .context("Failed to bind SSH agent socket")?;

        // Set socket permissions to 0600
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perms = std::fs::metadata(&self.config.socket_path)?.permissions();
            perms.set_mode(0o600);
            std::fs::set_permissions(&self.config.socket_path, perms)?;
        }

        info!(
            "SSH agent listening on {}",
            self.config.socket_path.display()
        );

        // Load keys from vault
        if let Err(e) = self.key_manager.load_keys_from_vault().await {
            warn!("Failed to load keys from vault: {}", e);
            info!("SSH agent started with no keys loaded");
        } else {
            info!(
                "Loaded {} SSH keys from vault",
                self.key_manager.get_identities().len()
            );
        }

        // Create shutdown channel
        let (shutdown_tx, mut shutdown_rx) = mpsc::channel::<()>(1);
        self.shutdown_tx = Some(shutdown_tx);

        // Accept connections
        loop {
            tokio::select! {
                result = listener.accept() => {
                    match result {
                        Ok((stream, addr)) => {
                            debug!("SSH agent client connected: {:?}", addr);
                            let key_manager = self.key_manager.clone();
                            tokio::spawn(async move {
                                if let Err(e) = handle_client(stream, key_manager).await {
                                    error!("Error handling SSH agent client: {}", e);
                                }
                            });
                        }
                        Err(e) => {
                            error!("Failed to accept SSH agent connection: {}", e);
                        }
                    }
                }
                _ = shutdown_rx.recv() => {
                    info!("SSH agent shutdown requested");
                    break;
                }
            }
        }

        // Clean up socket file
        if self.config.socket_path.exists() {
            std::fs::remove_file(&self.config.socket_path)?;
        }

        Ok(())
    }

    /// Stop the SSH agent server
    pub async fn stop(&self) -> Result<()> {
        if let Some(tx) = &self.shutdown_tx {
            tx.send(())
                .await
                .map_err(|e| anyhow::anyhow!("Failed to send shutdown: {}", e))?;
        }
        Ok(())
    }

    /// Get the socket path for this agent
    pub fn socket_path(&self) -> &PathBuf {
        &self.config.socket_path
    }
}

/// Handle a single SSH agent client connection
async fn handle_client(mut stream: UnixStream, key_manager: KeyManager) -> Result<()> {
    let mut buffer = vec![0u8; 8192];

    loop {
        // Read message length (4 bytes)
        let mut len_buf = [0u8; 4];
        if stream.read_exact(&mut len_buf).await.is_err() {
            // Client disconnected
            break;
        }

        let msg_len = u32::from_be_bytes(len_buf) as usize;
        if msg_len == 0 || msg_len > 8192 {
            warn!("Invalid message length: {}", msg_len);
            break;
        }

        // Read message body
        if msg_len > buffer.len() {
            buffer.resize(msg_len, 0);
        }

        stream.read_exact(&mut buffer[..msg_len]).await?;

        // Parse request
        let request = match parse_request(&buffer[..msg_len]) {
            Ok(req) => req,
            Err(e) => {
                warn!("Failed to parse SSH agent request: {}", e);
                // Send failure response
                let response = crate::protocol::failure_response();
                send_response(&mut stream, &response).await?;
                continue;
            }
        };

        // Process request
        let response = match process_request(request, &key_manager).await {
            Ok(resp) => resp,
            Err(e) => {
                error!("Failed to process SSH agent request: {}", e);
                Response::Failure
            }
        };

        // Serialize and send response
        let response_bytes = serialize_response(&response)?;
        send_response(&mut stream, &response_bytes).await?;
    }

    Ok(())
}

/// Process an SSH agent request and return a response
async fn process_request(request: Request, key_manager: &KeyManager) -> Result<Response> {
    match request {
        Request::RequestIdentities => {
            debug!("SSH_AGENTC_REQUEST_IDENTITIES");

            let identities = key_manager.get_identities();
            let entries: Vec<IdentityEntry> = identities
                .into_iter()
                .map(|id| IdentityEntry {
                    key_blob: id.key_blob,
                    comment: id.comment,
                })
                .collect();

            debug!("Returning {} identities", entries.len());
            Ok(Response::IdentitiesAnswer(entries))
        }
        Request::SignRequest {
            key_blob,
            data,
            flags,
        } => {
            debug!("SSH_AGENTC_SIGN_REQUEST (data length: {})", data.len());

            // Find the identity by key blob
            let identity = key_manager
                .find_identity_by_blob(&key_blob)
                .ok_or_else(|| anyhow::anyhow!("Key not found"))?;

            debug!("Signing with key: {}", identity.vault_path);

            // Check constraints
            for constraint in &identity.constraints {
                if constraint.is_expired(identity.loaded_at) {
                    return Ok(Response::Failure);
                }

                // Handle confirmation constraint
                if let KeyConstraint::Confirm { message } = constraint {
                    debug!("Confirmation required for key: {}", identity.vault_path);

                    // Build the approval request
                    let prompt_message = message.clone().unwrap_or_else(|| {
                        format!("Confirm SSH key usage: {}", identity.vault_path)
                    });

                    let request = ApprovalRequest {
                        agent_id: "ssh-agent".to_string(),
                        secret_path: identity.vault_path.clone(),
                        reason: prompt_message,
                        working_dir: None,
                        requested_duration: "one-time".to_string(),
                    };

                    // Show approval prompt
                    match ApprovalPrompt::approve(request) {
                        Ok(Some(decision)) if decision.is_approval() => {
                            debug!("SSH key use approved");
                            // Continue with signing
                        }
                        _ => {
                            info!("SSH key use denied by user");
                            return Ok(Response::Failure);
                        }
                    }
                }
            }

            // Perform signing
            let signature = key_manager
                .sign_with_key(&identity.vault_path, &data, flags)
                .await?;

            Ok(Response::SignResponse { signature })
        }
        Request::AddIdentity => {
            debug!("SSH_AGENTC_ADD_IDENTITY (not supported)");
            Ok(Response::Failure)
        }
        Request::RemoveIdentity { .. } => {
            debug!("SSH_AGENTC_REMOVE_IDENTITY (not supported)");
            Ok(Response::Failure)
        }
        Request::RemoveAllIdentities => {
            debug!("SSH_AGENTC_REMOVE_ALL_IDENTITIES (not supported)");
            Ok(Response::Failure)
        }
    }
}

/// Send a response to the client
async fn send_response(stream: &mut UnixStream, response: &[u8]) -> Result<()> {
    // Send message length
    let len = response.len() as u32;
    stream.write_all(&len.to_be_bytes()).await?;

    // Send message body
    stream.write_all(response).await?;

    Ok(())
}

/// Clone implementation for KeyManager (shallow clone)
impl Clone for KeyManager {
    fn clone(&self) -> Self {
        Self {
            identities: self.identities.clone(),
            session_token: self.session_token.clone(),
            sigil_socket: self.sigil_socket.clone(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_agent_config_default() {
        let config = Config::default();
        assert!(config.socket_path.ends_with("sigil-ssh-agent.sock"));
    }

    #[tokio::test]
    async fn test_agent_config_builder() {
        let config = Config::new(
            PathBuf::from("/tmp/test.sock"),
            PathBuf::from("/tmp/sigild.sock"),
            "test-token".to_string(),
        )
        .with_confirmation(true)
        .with_max_lifetime(3600)
        .with_verbose(true);

        assert!(config.confirm_before_use);
        assert_eq!(config.max_key_lifetime, Some(3600));
        assert!(config.verbose);
    }
}
