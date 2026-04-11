//! Daemon client for communicating with sigild

use crate::ondemand::OnDemandCoordinator;
use sigil_core::{
    ipc::{ExecRequest, ExecResponse},
    read_message_async, write_message_async, DaemonStatus, IpcError, IpcErrorCode, IpcOperation,
    IpcRequest, IpcResponse, PingResponse, ResolveRequest, ResolveResponse, ScrubRequest,
    ScrubResponse, SessionToken,
};
use std::io;
use std::path::Path;
use tokio::net::UnixStream;

/// Daemon client
pub struct DaemonClient {
    stream: UnixStream,
    session_token: SessionToken,
}

impl DaemonClient {
    /// Connect to the daemon socket
    ///
    /// This method will attempt to start the daemon automatically if it's not running.
    /// It uses on-demand startup with lockfile coordination to ensure only one daemon
    /// instance is started even when multiple clients connect simultaneously.
    pub async fn connect(socket_path: &Path) -> io::Result<Self> {
        // Create on-demand coordinator
        let coordinator = OnDemandCoordinator::new(socket_path, None).map_err(io::Error::other)?;

        // Ensure daemon is running (start it if necessary)
        if let Err(e) = coordinator.ensure_daemon_running().await {
            return Err(io::Error::new(io::ErrorKind::ConnectionRefused, e));
        }

        // Now connect to the daemon
        let stream = UnixStream::connect(socket_path).await?;

        // Read session token from kernel keyring (or file fallback)
        let session_token = Self::read_session_token().map_err(io::Error::other)?;

        Ok(Self {
            stream,
            session_token,
        })
    }

    /// Read the session token from the kernel keyring or file fallback
    fn read_session_token() -> Result<SessionToken, String> {
        // Try kernel keyring first
        if sigil_core::is_keyring_available() {
            match sigil_core::read_session_token() {
                Ok(token_str) => {
                    return SessionToken::from_string(token_str)
                        .map_err(|e| format!("Invalid session token in keyring: {}", e));
                }
                Err(e) => {
                    tracing::debug!("Failed to read from keyring: {}, trying file fallback", e);
                }
            }
        }

        // Fallback to file-based storage
        let runtime_dir = std::env::var("XDG_RUNTIME_DIR")
            .map_err(|_| "XDG_RUNTIME_DIR not set and kernel keyring unavailable".to_string())?;

        let token_path = std::path::PathBuf::from(runtime_dir).join("sigil-session-token");

        if !token_path.exists() {
            return Err("Session token not found in keyring or file".to_string());
        }

        let token_str = std::fs::read_to_string(&token_path)
            .map_err(|e| format!("Failed to read token file: {}", e))?;

        SessionToken::from_string(token_str.trim().to_string())
            .map_err(|e| format!("Invalid session token in file: {}", e))
    }

    /// Send a request and wait for response
    async fn send_request(&mut self, request: IpcRequest) -> Result<IpcResponse, IpcError> {
        // Serialize request
        let json = serde_json::to_vec(&request)
            .map_err(|e| IpcError::new(IpcErrorCode::InternalError, e.to_string()))?;

        // Write length-prefixed message
        write_message_async(&mut self.stream, &json)
            .await
            .map_err(|e| IpcError::new(IpcErrorCode::InternalError, e.to_string()))?;

        // Read response
        let response_data = read_message_async(&mut self.stream)
            .await
            .map_err(|e| IpcError::new(IpcErrorCode::InternalError, e.to_string()))?;

        let response: IpcResponse = serde_json::from_slice(&response_data)
            .map_err(|e| IpcError::new(IpcErrorCode::InternalError, e.to_string()))?;

        Ok(response)
    }

    /// Ping the daemon
    pub async fn ping(&mut self) -> Result<PingResponse, IpcError> {
        let request = IpcRequest::with_payload(
            IpcOperation::Ping,
            self.session_token.to_base64(),
            serde_json::json!({}),
        );

        let response = self.send_request(request).await?;

        if !response.ok {
            return Err(response.error.unwrap_or_else(|| {
                IpcError::new(IpcErrorCode::InternalError, "Unknown error".to_string())
            }));
        }

        let ping: PingResponse = serde_json::from_value(response.payload)
            .map_err(|e| IpcError::new(IpcErrorCode::InternalError, e.to_string()))?;

        Ok(ping)
    }

    /// Get daemon status
    pub async fn status(&mut self) -> Result<DaemonStatus, IpcError> {
        let request = IpcRequest::with_payload(
            IpcOperation::Status,
            self.session_token.to_base64(),
            serde_json::json!({}),
        );

        let response = self.send_request(request).await?;

        if !response.ok {
            return Err(response.error.unwrap_or_else(|| {
                IpcError::new(IpcErrorCode::InternalError, "Unknown error".to_string())
            }));
        }

        let status: DaemonStatus = serde_json::from_value(response.payload)
            .map_err(|e| IpcError::new(IpcErrorCode::InternalError, e.to_string()))?;

        Ok(status)
    }

    /// Send shutdown request to daemon
    pub async fn send_shutdown(&mut self) -> Result<(), IpcError> {
        let request = IpcRequest::with_payload(
            IpcOperation::SessionEnd,
            self.session_token.to_base64(),
            serde_json::json!({"shutdown": true}),
        );

        let response = self.send_request(request).await?;

        if !response.ok {
            return Err(response.error.unwrap_or_else(|| {
                IpcError::new(IpcErrorCode::InternalError, "Unknown error".to_string())
            }));
        }

        Ok(())
    }

    /// Resolve secrets
    #[allow(dead_code)]
    pub async fn resolve(
        &mut self,
        paths: Vec<String>,
    ) -> Result<std::collections::HashMap<String, String>, IpcError> {
        let payload = serde_json::to_value(ResolveRequest { paths })
            .map_err(|e| IpcError::new(IpcErrorCode::InternalError, e.to_string()))?;

        let request = IpcRequest::with_payload(
            IpcOperation::Resolve,
            self.session_token.to_base64(),
            payload,
        );

        let response = self.send_request(request).await?;

        if !response.ok {
            return Err(response.error.unwrap_or_else(|| {
                IpcError::new(IpcErrorCode::InternalError, "Unknown error".to_string())
            }));
        }

        let resolve_response: ResolveResponse = serde_json::from_value(response.payload)
            .map_err(|e| IpcError::new(IpcErrorCode::InternalError, e.to_string()))?;

        Ok(resolve_response.values)
    }

    /// Scrub output for secrets
    #[allow(dead_code)]
    pub async fn scrub(&mut self, output: String) -> Result<(String, usize), IpcError> {
        let payload = serde_json::to_value(ScrubRequest { output })
            .map_err(|e| IpcError::new(IpcErrorCode::InternalError, e.to_string()))?;

        let request =
            IpcRequest::with_payload(IpcOperation::Scrub, self.session_token.to_base64(), payload);

        let response = self.send_request(request).await?;

        if !response.ok {
            return Err(response.error.unwrap_or_else(|| {
                IpcError::new(IpcErrorCode::InternalError, "Unknown error".to_string())
            }));
        }

        let scrub_response: ScrubResponse = serde_json::from_value(response.payload)
            .map_err(|e| IpcError::new(IpcErrorCode::InternalError, e.to_string()))?;

        Ok((scrub_response.output, scrub_response.count))
    }

    /// Execute a command through the daemon with sandboxing and output scrubbing
    #[allow(dead_code)]
    pub async fn exec(
        &mut self,
        command: String,
        args: Vec<String>,
    ) -> Result<ExecResponse, IpcError> {
        let exec_request = ExecRequest {
            command,
            args,
            working_dir: std::env::current_dir()
                .ok()
                .and_then(|p| p.to_str().map(|s| s.to_string())),
            network_isolated: false,
            project_dir: std::env::var("PROJECT_DIR").ok(),
            timeout_secs: 300, // 5 minutes default
        };

        let payload = serde_json::to_value(exec_request)
            .map_err(|e| IpcError::new(IpcErrorCode::InternalError, e.to_string()))?;

        let request =
            IpcRequest::with_payload(IpcOperation::Exec, self.session_token.to_base64(), payload);

        let response = self.send_request(request).await?;

        if !response.ok {
            return Err(response.error.unwrap_or_else(|| {
                IpcError::new(IpcErrorCode::InternalError, "Unknown error".to_string())
            }));
        }

        let exec_response: ExecResponse = serde_json::from_value(response.payload)
            .map_err(|e| IpcError::new(IpcErrorCode::InternalError, e.to_string()))?;

        Ok(exec_response)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::NamedTempFile;

    #[tokio::test]
    async fn test_client_connection_fails_without_server() {
        let temp_file = NamedTempFile::new().unwrap();
        let result = DaemonClient::connect(temp_file.path()).await;
        assert!(result.is_err());
    }
}
