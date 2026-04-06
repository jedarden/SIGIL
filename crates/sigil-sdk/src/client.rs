//! SIGIL SDK Client - Embeddable client for SIGIL secret management
//!
//! This client communicates with the sigild daemon via the IPC protocol
//! using Unix socket communication.

use sigil_core::{
    write_message_async, IpcErrorCode, IpcOperation, IpcRequest, IpcResponse, Result, SecretPath,
    SecretValue, SessionToken, SigilError,
};
use std::path::PathBuf;
use tokio::net::UnixStream;

/// Client for communicating with the SIGIL daemon
pub struct SigilClient {
    /// Path to the Unix socket
    socket_path: PathBuf,
    /// Optional session token for authenticated requests
    session_token: Option<SessionToken>,
    /// Request timeout in seconds
    timeout: u64,
}

impl SigilClient {
    /// Create a new client
    pub fn new(socket_path: PathBuf) -> Result<Self> {
        Ok(Self {
            socket_path,
            session_token: None,
            timeout: 30,
        })
    }

    /// Create a new client with the default socket path
    pub fn default_path() -> Result<PathBuf> {
        if let Ok(runtime_dir) = std::env::var("XDG_RUNTIME_DIR") {
            Ok(PathBuf::from(runtime_dir).join("sigil.sock"))
        } else {
            Ok(PathBuf::from("/tmp").join(format!("sigil-{}.sock", std::process::id())))
        }
    }

    /// Create a client with the default socket path
    pub fn connect_default() -> Result<Self> {
        Self::new(Self::default_path()?)
    }

    /// Set the session token for authenticated requests
    pub fn with_session_token(mut self, token: SessionToken) -> Self {
        self.session_token = Some(token);
        self
    }

    /// Set the request timeout
    pub fn with_timeout(mut self, timeout_secs: u64) -> Self {
        self.timeout = timeout_secs;
        self
    }

    /// Connect to the daemon and verify it's running
    pub async fn connect(&self) -> Result<()> {
        let mut stream = self.connect_stream().await?;

        // Send a ping request
        let token = self.get_token();
        let request = IpcRequest::new(IpcOperation::Ping, token);
        let response = self.send_request(&mut stream, request).await?;

        if !response.ok {
            return Err(SigilError::Backend(format!(
                "Daemon ping failed: {}",
                response.error.map(|e| e.message).unwrap_or_default()
            )));
        }

        Ok(())
    }

    /// Resolve a single secret by path
    pub async fn get(&self, path: &str) -> Result<SecretValue> {
        let mut stream = self.connect_stream().await?;
        let token = self.get_token();

        let secret_path = SecretPath::new(path.to_string())?;
        let payload = serde_json::json!({ "path": secret_path.as_str() });

        let request = IpcRequest::with_payload(IpcOperation::Get, token, payload);
        let response = self.send_request(&mut stream, request).await?;

        if !response.ok {
            return Err(self.error_from_response(&response));
        }

        // Extract the secret value from the response
        let value_str = response
            .payload
            .get("value")
            .and_then(|v| v.as_str())
            .ok_or_else(|| SigilError::Backend("Missing value in response".into()))?;

        Ok(SecretValue::new(value_str.as_bytes().to_vec()))
    }

    /// Check if a secret exists
    pub async fn exists(&self, path: &str) -> Result<bool> {
        match self.get(path).await {
            Ok(_) => Ok(true),
            Err(SigilError::SecretNotFound(_)) => Ok(false),
            Err(e) => Err(e),
        }
    }

    /// List secrets with optional prefix filter
    pub async fn list(&self, prefix: &str) -> Result<Vec<SecretMetadata>> {
        let mut stream = self.connect_stream().await?;
        let token = self.get_token();

        let payload = serde_json::json!({ "prefix": prefix });
        let request = IpcRequest::with_payload(IpcOperation::List, token, payload);
        let response = self.send_request(&mut stream, request).await?;

        if !response.ok {
            return Err(self.error_from_response(&response));
        }

        // Parse the secrets list from the response
        let secrets_array = response
            .payload
            .get("secrets")
            .and_then(|v| v.as_array())
            .ok_or_else(|| SigilError::Backend("Missing secrets array in response".into()))?;

        let mut secrets = Vec::new();
        for secret_value in secrets_array {
            let meta: SecretMetadata = serde_json::from_value(secret_value.clone())
                .map_err(|e| SigilError::SerializationError(e.to_string()))?;
            secrets.push(meta);
        }

        Ok(secrets)
    }

    /// Resolve a string containing secret placeholders
    pub async fn resolve(&self, input: &str) -> Result<String> {
        let mut stream = self.connect_stream().await?;
        let token = self.get_token();

        let payload = serde_json::json!({ "command": input });
        let request = IpcRequest::with_payload(IpcOperation::Resolve, token, payload);
        let response = self.send_request(&mut stream, request).await?;

        if !response.ok {
            return Err(self.error_from_response(&response));
        }

        // Extract the resolved command from the response
        let resolved = response
            .payload
            .get("resolved")
            .and_then(|v| v.as_str())
            .ok_or_else(|| SigilError::Backend("Missing resolved command in response".into()))?;

        Ok(resolved.to_string())
    }

    /// Request access to a secret (triggers TUI approval workflow)
    pub async fn request_access(
        &self,
        path: &str,
        reason: &str,
        duration_secs: Option<u32>,
    ) -> Result<AccessGrant> {
        let mut stream = self.connect_stream().await?;
        let token = self.get_token();

        let secret_path = SecretPath::new(path.to_string())?;
        let mut payload = serde_json::json!({
            "path": secret_path.as_str(),
            "reason": reason,
        });

        if let Some(duration) = duration_secs {
            payload["duration_secs"] = serde_json::json!(duration);
        }

        let request = IpcRequest::with_payload(IpcOperation::RequestAccess, token, payload);
        let response = self.send_request(&mut stream, request).await?;

        if !response.ok {
            return Err(self.error_from_response(&response));
        }

        // Parse the access grant from the response
        let granted = response
            .payload
            .get("granted")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);

        let expires_at = response
            .payload
            .get("expires_at")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string());

        Ok(AccessGrant {
            granted,
            expires_at,
        })
    }

    /// Scrub secrets from output
    pub async fn scrub(&self, output: &str) -> Result<String> {
        let mut stream = self.connect_stream().await?;
        let token = self.get_token();

        let payload = serde_json::json!({ "output": output });
        let request = IpcRequest::with_payload(IpcOperation::Scrub, token, payload);
        let response = self.send_request(&mut stream, request).await?;

        if !response.ok {
            return Err(self.error_from_response(&response));
        }

        // Extract the scrubbed output from the response
        let scrubbed = response
            .payload
            .get("scrubbed")
            .and_then(|v| v.as_str())
            .ok_or_else(|| SigilError::Backend("Missing scrubbed output in response".into()))?;

        Ok(scrubbed.to_string())
    }

    /// Get daemon status
    pub async fn status(&self) -> Result<DaemonStatusInfo> {
        let mut stream = self.connect_stream().await?;
        let token = self.get_token();

        let request = IpcRequest::new(IpcOperation::Status, token);
        let response = self.send_request(&mut stream, request).await?;

        if !response.ok {
            return Err(self.error_from_response(&response));
        }

        // Parse the status from the response
        serde_json::from_value(response.payload)
            .map_err(|e| SigilError::SerializationError(e.to_string()))
    }

    /// Connect to the Unix socket
    async fn connect_stream(&self) -> Result<UnixStream> {
        tokio::time::timeout(
            tokio::time::Duration::from_secs(self.timeout),
            UnixStream::connect(&self.socket_path),
        )
        .await
        .map_err(|_| SigilError::Backend("Connection timeout".into()))?
        .map_err(|e| SigilError::Backend(format!("Failed to connect: {}", e)))
    }

    /// Send a request and receive a response
    async fn send_request(
        &self,
        stream: &mut UnixStream,
        request: IpcRequest,
    ) -> Result<IpcResponse> {
        let request_bytes = serde_json::to_vec(&request)
            .map_err(|e| SigilError::SerializationError(e.to_string()))?;

        // Write the request
        write_message_async(stream, &request_bytes)
            .await
            .map_err(|e| SigilError::IoError(e.to_string()))?;

        // Read the response with timeout
        let response_bytes = tokio::time::timeout(
            tokio::time::Duration::from_secs(self.timeout),
            sigil_core::read_message_async(stream),
        )
        .await
        .map_err(|_| SigilError::Backend("Request timeout".into()))?
        .map_err(|e| SigilError::IoError(e.to_string()))?;

        // Parse the response
        let response: IpcResponse = serde_json::from_slice(&response_bytes)
            .map_err(|e| SigilError::SerializationError(e.to_string()))?;

        // Validate protocol version
        if response.v != sigil_core::PROTOCOL_VERSION {
            return Err(SigilError::UnsupportedProtocolVersion(response.v));
        }

        // Match request ID
        if response.id != request.id {
            return Err(SigilError::Backend("Request ID mismatch".into()));
        }

        Ok(response)
    }

    /// Get the session token for requests
    fn get_token(&self) -> String {
        self.session_token
            .as_ref()
            .map(|t| t.as_str().to_string())
            .unwrap_or_default()
    }

    /// Convert an error response to a SigilError
    fn error_from_response(&self, response: &IpcResponse) -> SigilError {
        if let Some(ref error) = response.error {
            match error.code {
                IpcErrorCode::SecretNotFound => SigilError::SecretNotFound(error.message.clone()),
                IpcErrorCode::AccessDenied => SigilError::AccessDenied(error.message.clone()),
                IpcErrorCode::VaultLocked => SigilError::VaultLocked,
                IpcErrorCode::LockedDown => {
                    SigilError::Backend(format!("Daemon in lockdown: {}", error.message))
                }
                _ => SigilError::Backend(error.message.clone()),
            }
        } else {
            SigilError::Backend("Unknown error".into())
        }
    }
}

/// Metadata about a secret
#[derive(Debug, Clone, serde::Deserialize)]
pub struct SecretMetadata {
    /// Secret path
    pub path: String,
    /// Secret type
    #[serde(rename = "type")]
    pub secret_type: String,
    /// When the secret was created
    pub created_at: String,
    /// When the secret was last updated
    pub updated_at: String,
    /// Tags
    pub tags: Vec<String>,
    /// Notes
    pub notes: Option<String>,
}

/// Result of an access request
#[derive(Debug, Clone)]
pub struct AccessGrant {
    /// Whether access was granted
    pub granted: bool,
    /// When the grant expires (if applicable)
    pub expires_at: Option<String>,
}

/// Daemon status information
#[derive(Debug, Clone, serde::Deserialize)]
pub struct DaemonStatusInfo {
    /// Whether the daemon is running
    pub running: bool,
    /// Daemon uptime in seconds
    pub uptime_secs: u64,
    /// Number of active sessions
    pub active_sessions: u32,
    /// Number of secrets loaded
    pub secrets_loaded: u32,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_socket_path() {
        // Set XDG_RUNTIME_DIR for consistent test behavior across environments
        std::env::set_var("XDG_RUNTIME_DIR", "/tmp/test-runtime");
        let path = SigilClient::default_path().unwrap();
        assert!(path.ends_with("sigil.sock"));
        assert_eq!(path, PathBuf::from("/tmp/test-runtime/sigil.sock"));
    }

    #[test]
    fn test_client_creation() {
        let client = SigilClient::new(PathBuf::from("/tmp/test.sock"));
        assert!(client.is_ok());
        let client = client.unwrap();
        assert_eq!(client.socket_path, PathBuf::from("/tmp/test.sock"));
        assert_eq!(client.timeout, 30);
    }

    #[test]
    fn test_client_with_timeout() {
        let client = SigilClient::new(PathBuf::from("/tmp/test.sock"))
            .unwrap()
            .with_timeout(60);
        assert_eq!(client.timeout, 60);
    }

    #[test]
    fn test_client_with_session_token() {
        let token = SessionToken::generate();
        let client = SigilClient::new(PathBuf::from("/tmp/test.sock"))
            .unwrap()
            .with_session_token(token.clone());
        assert!(client.session_token.is_some());
        assert_eq!(
            client.session_token.as_ref().unwrap().as_str(),
            token.as_str()
        );
    }

    #[test]
    fn test_default_socket_path_fallback() {
        // Test fallback path when XDG_RUNTIME_DIR is not set
        // This test is environment-dependent and only validates the fallback behavior
        // when XDG_RUNTIME_DIR is actually not set in the test environment
        if std::env::var("XDG_RUNTIME_DIR").is_ok() {
            // Skip this test if XDG_RUNTIME_DIR is set by the test harness
            return;
        }
        let path = SigilClient::default_path().unwrap();
        // Fallback path is /tmp/sigil-{pid}.sock
        assert!(path.starts_with("/tmp/sigil-"));
        assert!(path.ends_with(".sock"));
        // Extract PID from path and verify it's numeric
        let path_str = path.to_string_lossy();
        let pid_part = path_str
            .strip_prefix("/tmp/sigil-")
            .unwrap()
            .strip_suffix(".sock")
            .unwrap();
        assert!(pid_part.parse::<u32>().is_ok(), "PID should be numeric");
    }
}
