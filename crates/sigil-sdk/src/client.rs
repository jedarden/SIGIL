//! SIGIL SDK Client - Embeddable client for SIGIL secret management
//!
//! This client communicates with the sigild daemon via the IPC protocol
//! using Unix socket communication with connection pooling and automatic
//! reconnection with exponential backoff.

use sigil_core::{
    write_message_async, IpcErrorCode, IpcOperation, IpcRequest, IpcResponse, Result, SecretPath,
    SecretValue, SessionToken, SigilError,
};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::net::UnixStream;
use tokio::sync::{Mutex, Semaphore};

/// Default maximum number of retries for connection attempts
const DEFAULT_MAX_RETRIES: u32 = 5;
/// Base backoff duration in milliseconds
const BASE_BACKOFF_MS: u64 = 100;
/// Maximum backoff duration in seconds
const MAX_BACKOFF_SECS: u64 = 30;

/// Pooled connection with metadata
struct PooledConnection {
    /// The Unix stream
    stream: UnixStream,
    /// When the connection was last used
    last_used: Instant,
}

impl PooledConnection {
    /// Create a new pooled connection
    fn new(stream: UnixStream) -> Self {
        let now = Instant::now();
        Self {
            stream,
            last_used: now,
        }
    }

    /// Update the last used timestamp
    fn touch(&mut self) {
        self.last_used = Instant::now();
    }

    /// Check if the connection is stale (older than 5 minutes)
    fn is_stale(&self) -> bool {
        self.last_used.elapsed() > Duration::from_secs(300)
    }
}

/// Connection pool for reusing Unix socket connections
struct ConnectionPool {
    /// Optional pooled connection (single persistent connection per client)
    connection: Option<PooledConnection>,
    /// Semaphore to ensure single access to the connection
    semaphore: Arc<Semaphore>,
}

impl ConnectionPool {
    /// Create a new connection pool
    fn new() -> Self {
        Self {
            connection: None,
            semaphore: Arc::new(Semaphore::new(1)),
        }
    }

    /// Get or create a connection
    async fn acquire(&mut self, socket_path: &PathBuf, timeout: u64) -> Result<PooledConnection> {
        let _permit = self
            .semaphore
            .acquire()
            .await
            .map_err(|e| SigilError::Backend(format!("Semaphore error: {}", e)))?;

        // Remove stale connection if exists
        if let Some(conn) = &self.connection {
            if conn.is_stale() {
                self.connection = None;
            }
        }

        // Return existing connection or create new one
        if let Some(mut conn) = self.connection.take() {
            conn.touch();
            Ok(conn)
        } else {
            // Create new connection with timeout and retry
            Self::connect_with_retry(socket_path, timeout).await
        }
    }

    /// Return a connection to the pool
    fn return_connection(&mut self, conn: PooledConnection) {
        self.connection = Some(conn);
    }

    /// Connect with exponential backoff retry
    async fn connect_with_retry(
        socket_path: &PathBuf,
        timeout_secs: u64,
    ) -> Result<PooledConnection> {
        let mut last_error = None;

        for attempt in 0..DEFAULT_MAX_RETRIES {
            // Calculate backoff duration with exponential increase
            let backoff_ms = BASE_BACKOFF_MS * 2_u64.pow(attempt);
            let backoff = Duration::from_millis(backoff_ms.min(MAX_BACKOFF_SECS * 1000));

            // Try to connect with timeout
            let result = tokio::time::timeout(
                Duration::from_secs(timeout_secs),
                UnixStream::connect(socket_path),
            )
            .await;

            match result {
                Ok(Ok(stream)) => return Ok(PooledConnection::new(stream)),
                Ok(Err(e)) => {
                    last_error = Some(SigilError::Backend(format!("Connection failed: {}", e)));
                }
                Err(_) => {
                    last_error = Some(SigilError::Backend("Connection timeout".into()));
                }
            }

            // Wait before retry (except on last attempt)
            if attempt < DEFAULT_MAX_RETRIES - 1 {
                tokio::time::sleep(backoff).await;
            }
        }

        Err(last_error
            .unwrap_or_else(|| SigilError::Backend("Connection failed after retries".into())))
    }

    /// Close all connections in the pool
    fn close(&mut self) {
        self.connection = None;
    }
}

impl Default for ConnectionPool {
    fn default() -> Self {
        Self::new()
    }
}

/// Client for communicating with the SIGIL daemon
pub struct SigilClient {
    /// Path to the Unix socket
    socket_path: PathBuf,
    /// Optional session token for authenticated requests
    session_token: Option<SessionToken>,
    /// Request timeout in seconds
    timeout: u64,
    /// Connection pool for reusing connections
    pool: Arc<Mutex<ConnectionPool>>,
    /// Maximum number of retries for requests
    max_retries: u32,
}

impl SigilClient {
    /// Create a new client
    pub fn new(socket_path: PathBuf) -> Result<Self> {
        Ok(Self {
            socket_path,
            session_token: None,
            timeout: 30,
            pool: Arc::new(Mutex::new(ConnectionPool::new())),
            max_retries: DEFAULT_MAX_RETRIES,
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

    /// Create a client and automatically load session token from file
    ///
    /// This attempts to read the session token from the standard location
    /// ($XDG_RUNTIME_DIR/sigil-session-token) and configure the client with it.
    /// If the token file doesn't exist or can't be read, the client is created
    /// without a token (which will need to be set via `with_session_token`).
    pub fn connect_with_token() -> Result<Self> {
        let socket_path = Self::default_path()?;
        let mut client = Self::new(socket_path)?;

        // Try to load session token from file
        if let Ok(token) = Self::load_token_from_file() {
            client.session_token = Some(token);
        }

        Ok(client)
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

    /// Set the maximum number of retries for failed requests
    pub fn with_max_retries(mut self, max_retries: u32) -> Self {
        self.max_retries = max_retries;
        self
    }

    /// Connect to the daemon and verify it's running
    ///
    /// This uses a pooled connection if available, or creates a new one with
    /// automatic retry and exponential backoff.
    pub async fn connect(&self) -> Result<()> {
        let mut pool = self.pool.lock().await;
        let mut conn = pool.acquire(&self.socket_path, self.timeout).await?;

        // Send a ping request
        let token = self.get_token();
        let request = IpcRequest::new(IpcOperation::Ping, token);
        match self.send_request_internal(&mut conn.stream, request).await {
            Ok(response) => {
                if !response.ok {
                    pool.return_connection(conn);
                    return Err(SigilError::Backend(format!(
                        "Daemon ping failed: {}",
                        response.error.map(|e| e.message).unwrap_or_default()
                    )));
                }
                pool.return_connection(conn);
                Ok(())
            }
            Err(e) => {
                // Connection failed, don't return to pool
                Err(e)
            }
        }
    }

    /// Close all pooled connections
    pub async fn close(&self) {
        let mut pool = self.pool.lock().await;
        pool.close();
    }

    /// Execute a request with automatic retry on connection failure
    async fn execute_with_retry(
        &self,
        operation: IpcOperation,
        payload: serde_json::Value,
    ) -> Result<IpcResponse> {
        let mut last_error = None;

        for attempt in 0..self.max_retries {
            let mut pool = self.pool.lock().await;

            // Try to get a connection (will retry with backoff internally)
            let mut conn = match pool.acquire(&self.socket_path, self.timeout).await {
                Ok(c) => c,
                Err(e) => {
                    last_error = Some(e);
                    if attempt < self.max_retries - 1 {
                        // Wait before retry with exponential backoff
                        let backoff_ms = BASE_BACKOFF_MS * 2_u64.pow(attempt);
                        drop(pool); // Release lock before sleeping
                        tokio::time::sleep(Duration::from_millis(
                            backoff_ms.min(MAX_BACKOFF_SECS * 1000),
                        ))
                        .await;
                        continue;
                    } else {
                        return Err(last_error.unwrap());
                    }
                }
            };

            let token = self.get_token();
            let request = IpcRequest::with_payload(operation, token, payload.clone());

            match self.send_request_internal(&mut conn.stream, request).await {
                Ok(response) => {
                    pool.return_connection(conn);
                    return Ok(response);
                }
                Err(e) => {
                    last_error = Some(e);
                    // Don't return failed connection to pool
                    if attempt < self.max_retries - 1 {
                        // Wait before retry with exponential backoff
                        let backoff_ms = BASE_BACKOFF_MS * 2_u64.pow(attempt);
                        drop(pool); // Release lock before sleeping
                        tokio::time::sleep(Duration::from_millis(
                            backoff_ms.min(MAX_BACKOFF_SECS * 1000),
                        ))
                        .await;
                    }
                }
            }
        }

        Err(last_error
            .unwrap_or_else(|| SigilError::Backend("Request failed after retries".into())))
    }

    /// Resolve a single secret by path
    pub async fn get(&self, path: &str) -> Result<SecretValue> {
        let secret_path = SecretPath::new(path.to_string())?;
        let payload = serde_json::json!({ "path": secret_path.as_str() });

        let response = self.execute_with_retry(IpcOperation::Get, payload).await?;

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
        let payload = serde_json::json!({ "prefix": prefix });
        let response = self.execute_with_retry(IpcOperation::List, payload).await?;

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
        let payload = serde_json::json!({ "command": input });
        let response = self
            .execute_with_retry(IpcOperation::Resolve, payload)
            .await?;

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
        let secret_path = SecretPath::new(path.to_string())?;
        let mut payload = serde_json::json!({
            "path": secret_path.as_str(),
            "reason": reason,
        });

        if let Some(duration) = duration_secs {
            payload["duration_secs"] = serde_json::json!(duration);
        }

        let response = self
            .execute_with_retry(IpcOperation::RequestAccess, payload)
            .await?;

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
        let payload = serde_json::json!({ "output": output });
        let response = self
            .execute_with_retry(IpcOperation::Scrub, payload)
            .await?;

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
        let response = self
            .execute_with_retry(IpcOperation::Status, serde_json::json!({}))
            .await?;

        if !response.ok {
            return Err(self.error_from_response(&response));
        }

        // Parse the status from the response
        serde_json::from_value(response.payload)
            .map_err(|e| SigilError::SerializationError(e.to_string()))
    }

    /// Send a request and receive a response (internal)
    async fn send_request_internal(
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

    /// Load session token from the standard token file location
    ///
    /// Attempts to read the session token from $XDG_RUNTIME_DIR/sigil-session-token.
    /// Returns Ok(None) if the file doesn't exist (daemon not running).
    fn load_token_from_file() -> Result<SessionToken> {
        use sigil_core::SigilError;
        use std::fs;

        let runtime_dir = std::env::var("XDG_RUNTIME_DIR")
            .map_err(|_| SigilError::IoError("XDG_RUNTIME_DIR not set".into()))?;

        let token_path = PathBuf::from(runtime_dir).join("sigil-session-token");

        // Read token from file
        let token_str = fs::read_to_string(&token_path)
            .map_err(|e| SigilError::IoError(format!("Failed to read token file: {}", e)))?;

        SessionToken::from_string(token_str.trim().to_string())
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
    use serial_test::serial;

    #[test]
    #[serial]
    fn test_default_socket_path() {
        // Set XDG_RUNTIME_DIR for consistent test behavior across environments
        // Remove any existing value first to ensure clean state
        std::env::remove_var("XDG_RUNTIME_DIR");
        std::env::set_var("XDG_RUNTIME_DIR", "/tmp/test-runtime");
        let path = SigilClient::default_path().unwrap();
        assert!(path.ends_with("sigil.sock"));
        assert_eq!(path, PathBuf::from("/tmp/test-runtime/sigil.sock"));
        // Clean up
        std::env::remove_var("XDG_RUNTIME_DIR");
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
    #[serial]
    fn test_default_socket_path_fallback() {
        // Test fallback path when XDG_RUNTIME_DIR is not set
        // Temporarily unset XDG_RUNTIME_DIR to test the fallback behavior
        let original_value = std::env::var("XDG_RUNTIME_DIR").ok();
        std::env::remove_var("XDG_RUNTIME_DIR");

        let path = SigilClient::default_path().unwrap();
        // Fallback path is /tmp/sigil-{pid}.sock
        // Note: PathBuf::starts_with compares path components, not string prefixes
        let path_str = path.to_string_lossy();
        assert!(path_str.starts_with("/tmp/sigil-"));
        assert!(path_str.ends_with(".sock"));
        // Extract PID from path and verify it's numeric
        let pid_part = path_str
            .strip_prefix("/tmp/sigil-")
            .unwrap()
            .strip_suffix(".sock")
            .unwrap();
        assert!(pid_part.parse::<u32>().is_ok(), "PID should be numeric");

        // Restore original value
        if let Some(value) = original_value {
            std::env::set_var("XDG_RUNTIME_DIR", value);
        }
    }

    #[test]
    #[serial]
    fn test_connect_with_token_reads_token_file() {
        // Set up XDG_RUNTIME_DIR for testing
        let temp_dir = tempfile::tempdir().unwrap();
        let runtime_dir = temp_dir.path();
        std::env::set_var("XDG_RUNTIME_DIR", runtime_dir.display().to_string());

        // Create a test token file
        let token_path = runtime_dir.join("sigil-session-token");
        let test_token = SessionToken::generate();
        std::fs::write(&token_path, test_token.to_base64()).unwrap();

        // Create client with token loading
        let client = SigilClient::connect_with_token().unwrap();

        // Verify token was loaded
        assert!(client.session_token.is_some());
        assert_eq!(
            client.session_token.as_ref().unwrap().as_str(),
            test_token.as_str()
        );

        // Clean up
        std::env::remove_var("XDG_RUNTIME_DIR");
    }

    #[test]
    #[serial]
    fn test_connect_with_token_no_file() {
        // Set up XDG_RUNTIME_DIR but don't create a token file
        let temp_dir = tempfile::tempdir().unwrap();
        std::env::set_var("XDG_RUNTIME_DIR", temp_dir.path().display().to_string());

        // Create client without token file (should succeed but without token)
        let client = SigilClient::connect_with_token().unwrap();

        // Verify no token was loaded
        assert!(client.session_token.is_none());

        // Clean up
        std::env::remove_var("XDG_RUNTIME_DIR");
    }
}
