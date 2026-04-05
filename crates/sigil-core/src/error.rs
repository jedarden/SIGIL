//! Error types for SIGIL

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Result type for SIGIL operations
pub type Result<T> = std::result::Result<T, SigilError>;

/// Agent-facing error codes for structured error responses
///
/// These codes are designed to be informative for debugging while never
/// revealing internal architecture or secret values to the agent.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ErrorCode {
    /// Requested secret path does not exist
    SecretNotFound,
    /// Command matched a deny rule
    CommandBlocked,
    /// File path access denied (Read/Write hook)
    PathRestricted,
    /// Cannot connect to sigild
    DaemonUnavailable,
    /// Vault requires authentication
    VaultLocked,
    /// Session token invalid or expired
    SessionExpired,
    /// Secret exists but agent lacks permission
    AccessDenied,
    /// Command execution failed inside sandbox
    OperationFailed,
    /// Unexpected SIGIL error
    InternalError,
}

impl ErrorCode {
    /// Get the agent-visible message for this error code
    pub fn message(&self) -> &'static str {
        match self {
            ErrorCode::SecretNotFound => "The referenced credential could not be resolved.",
            ErrorCode::CommandBlocked => "This command is not permitted by security policy",
            ErrorCode::PathRestricted => "Access to this path is restricted",
            ErrorCode::DaemonUnavailable => {
                "SIGIL daemon is not running. Start with 'sigil daemon start'"
            }
            ErrorCode::VaultLocked => "Vault is locked. Authenticate via SIGIL TUI",
            ErrorCode::SessionExpired => "Session expired. Reconnect required",
            ErrorCode::AccessDenied => "Access denied for this secret. Request via sigil_request",
            ErrorCode::OperationFailed => "Command execution failed",
            ErrorCode::InternalError => "Internal error. Check sigil daemon logs",
        }
    }

    /// Get the plain text format for this error
    pub fn format_plain(&self) -> String {
        format!("SIGIL ERROR [{}]: {}", self, self.message())
    }
}

impl std::fmt::Display for ErrorCode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let code = serde_json::to_string(self).unwrap_or_default();
        // Remove quotes from the JSON representation
        let code = code.trim_matches('"');
        write!(f, "{}", code)
    }
}

/// Structured error response for agent-facing errors
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StructuredError {
    /// Error marker
    pub error: bool,
    /// Error code
    pub code: ErrorCode,
    /// Human-readable error message (sanitized)
    pub message: String,
    /// Optional request ID for tracking
    #[serde(skip_serializing_if = "Option::is_none")]
    pub request_id: Option<String>,
}

impl StructuredError {
    /// Create a new structured error
    pub fn new(code: ErrorCode) -> Self {
        Self {
            error: true,
            code,
            message: code.message().to_string(),
            request_id: None,
        }
    }

    /// Create a new structured error with a custom message
    pub fn with_message(code: ErrorCode, message: String) -> Self {
        Self {
            error: true,
            code,
            message,
            request_id: None,
        }
    }

    /// Set the request ID
    pub fn with_request_id(mut self, request_id: String) -> Self {
        self.request_id = Some(request_id);
        self
    }

    /// Convert to JSON string
    pub fn to_json(&self) -> Result<String> {
        serde_json::to_string(self).map_err(|e| SigilError::SerializationError(e.to_string()))
    }

    /// Convert to plain text format
    pub fn to_plain(&self) -> String {
        self.code.format_plain()
    }
}

impl From<ErrorCode> for StructuredError {
    fn from(code: ErrorCode) -> Self {
        Self::new(code)
    }
}

impl std::fmt::Display for StructuredError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.to_plain())
    }
}

impl std::error::Error for StructuredError {}

/// Core error type for SIGIL
#[derive(Error, Debug)]
pub enum SigilError {
    /// Invalid secret path format
    #[error("invalid secret path: {0}")]
    InvalidPath(String),

    /// Secret not found
    #[error("secret not found: {0}")]
    SecretNotFound(String),

    /// Cryptographic error
    #[error("cryptographic error: {0}")]
    Crypto(String),

    /// IO error
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),

    /// IO error (string variant)
    #[error("io error: {0}")]
    IoError(String),

    /// Serialization error
    #[error("serialization error: {0}")]
    Serialization(#[from] serde_json::Error),

    /// Serialization error (string variant)
    #[error("serialization error: {0}")]
    SerializationError(String),

    /// Vault locked
    #[error("vault is locked")]
    VaultLocked,

    /// Backend error
    #[error("backend error: {0}")]
    Backend(String),

    /// Invalid configuration
    #[error("invalid configuration: {0}")]
    InvalidConfig(String),

    /// Invalid session token
    #[error("invalid session token: {0}")]
    InvalidSessionToken(String),

    /// Unsupported protocol version
    #[error("unsupported protocol version: {0}")]
    UnsupportedProtocolVersion(u16),

    /// Authentication failed
    #[error("authentication failed")]
    AuthenticationFailed,

    /// Access denied
    #[error("access denied: {0}")]
    AccessDenied(String),

    /// Session expired
    #[error("session expired")]
    SessionExpired,

    /// Lockdown mode active
    #[error("daemon is in lockdown mode")]
    LockedDown,

    /// Rate limited
    #[error("rate limited: too many requests")]
    RateLimited,
}

impl SigilError {
    /// Convert this error to an agent-facing error code
    ///
    /// This method maps internal errors to agent-facing error codes,
    /// following the security-conscious messaging rules.
    pub fn to_error_code(&self) -> ErrorCode {
        match self {
            SigilError::SecretNotFound(_) => ErrorCode::SecretNotFound,
            SigilError::AccessDenied(_) => ErrorCode::AccessDenied,
            SigilError::VaultLocked => ErrorCode::VaultLocked,
            SigilError::SessionExpired | SigilError::InvalidSessionToken(_) => {
                ErrorCode::SessionExpired
            }
            SigilError::AuthenticationFailed => ErrorCode::AccessDenied,
            SigilError::InvalidPath(_) => ErrorCode::InternalError,
            _ => ErrorCode::InternalError,
        }
    }

    /// Convert this error to a structured error response
    ///
    /// This creates a sanitized error message for agent consumption,
    /// following the security-conscious messaging rules.
    pub fn to_structured_error(&self) -> StructuredError {
        let code = self.to_error_code();
        // Use the predefined message for the error code, not the internal error message
        StructuredError::new(code)
    }

    /// Convert this error to a structured error with a request ID
    pub fn to_structured_error_with_id(&self, request_id: String) -> StructuredError {
        self.to_structured_error().with_request_id(request_id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_code_messages() {
        assert_eq!(
            ErrorCode::SecretNotFound.message(),
            "The referenced credential could not be resolved."
        );
        assert_eq!(
            ErrorCode::CommandBlocked.message(),
            "This command is not permitted by security policy"
        );
        assert_eq!(
            ErrorCode::PathRestricted.message(),
            "Access to this path is restricted"
        );
    }

    #[test]
    fn test_error_code_display() {
        assert_eq!(format!("{}", ErrorCode::SecretNotFound), "SECRET_NOT_FOUND");
        assert_eq!(format!("{}", ErrorCode::VaultLocked), "VAULT_LOCKED");
    }

    #[test]
    fn test_error_code_format_plain() {
        let error = ErrorCode::SecretNotFound.format_plain();
        assert!(error.contains("SIGIL ERROR"));
        assert!(error.contains("SECRET_NOT_FOUND"));
        assert!(error.contains("could not be resolved"));
    }

    #[test]
    fn test_structured_error_new() {
        let error = StructuredError::new(ErrorCode::SecretNotFound);
        assert!(error.error);
        assert_eq!(error.code, ErrorCode::SecretNotFound);
        assert_eq!(
            error.message,
            "The referenced credential could not be resolved."
        );
        assert!(error.request_id.is_none());
    }

    #[test]
    fn test_structured_error_with_message() {
        let error = StructuredError::with_message(
            ErrorCode::OperationFailed,
            "Command failed with exit code 1".to_string(),
        );
        assert_eq!(error.message, "Command failed with exit code 1");
    }

    #[test]
    fn test_structured_error_with_request_id() {
        let error =
            StructuredError::new(ErrorCode::InternalError).with_request_id("req_123".to_string());
        assert_eq!(error.request_id, Some("req_123".to_string()));
    }

    #[test]
    fn test_structured_error_to_json() {
        let error = StructuredError::new(ErrorCode::SecretNotFound);
        let json = error.to_json().unwrap();
        assert!(json.contains("\"error\":true"));
        assert!(json.contains("\"code\":\"SECRET_NOT_FOUND\""));
    }

    #[test]
    fn test_structured_error_to_plain() {
        let error = StructuredError::new(ErrorCode::VaultLocked);
        let plain = error.to_plain();
        assert!(plain.contains("SIGIL ERROR"));
        assert!(plain.contains("VAULT_LOCKED"));
    }

    #[test]
    fn test_structured_error_from_error_code() {
        let error: StructuredError = ErrorCode::AccessDenied.into();
        assert_eq!(error.code, ErrorCode::AccessDenied);
    }

    #[test]
    fn test_sigil_error_to_error_code() {
        assert_eq!(
            SigilError::SecretNotFound("test".to_string()).to_error_code(),
            ErrorCode::SecretNotFound
        );
        assert_eq!(
            SigilError::AccessDenied("test".to_string()).to_error_code(),
            ErrorCode::AccessDenied
        );
        assert_eq!(
            SigilError::VaultLocked.to_error_code(),
            ErrorCode::VaultLocked
        );
        assert_eq!(
            SigilError::SessionExpired.to_error_code(),
            ErrorCode::SessionExpired
        );
        assert_eq!(
            SigilError::InvalidPath("test".to_string()).to_error_code(),
            ErrorCode::InternalError
        );
    }

    #[test]
    fn test_sigil_error_to_structured_error() {
        let sigil_error = SigilError::SecretNotFound("api/key".to_string());
        let structured = sigil_error.to_structured_error();

        assert_eq!(structured.code, ErrorCode::SecretNotFound);
        assert_eq!(
            structured.message,
            "The referenced credential could not be resolved."
        );
        // Note: the internal error message is NOT exposed to the agent
        assert!(!structured.message.contains("api/key"));
    }

    #[test]
    fn test_sigil_error_to_structured_error_with_id() {
        let sigil_error = SigilError::VaultLocked;
        let structured = sigil_error.to_structured_error_with_id("req_abc".to_string());

        assert_eq!(structured.code, ErrorCode::VaultLocked);
        assert_eq!(structured.request_id, Some("req_abc".to_string()));
    }

    #[test]
    fn test_error_codes_serialization() {
        // Test that all error codes serialize correctly
        let codes = vec![
            ErrorCode::SecretNotFound,
            ErrorCode::CommandBlocked,
            ErrorCode::PathRestricted,
            ErrorCode::DaemonUnavailable,
            ErrorCode::VaultLocked,
            ErrorCode::SessionExpired,
            ErrorCode::AccessDenied,
            ErrorCode::OperationFailed,
            ErrorCode::InternalError,
        ];

        for code in codes {
            let json = serde_json::to_string(&code).unwrap();
            assert!(json.contains("\"")); // Should be quoted JSON string
        }
    }

    #[test]
    fn test_structured_error_serialization() {
        let error = StructuredError {
            error: true,
            code: ErrorCode::SecretNotFound,
            message: "Test message".to_string(),
            request_id: Some("req_123".to_string()),
        };

        let json = serde_json::to_string(&error).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();

        assert_eq!(parsed["error"], true);
        assert_eq!(parsed["code"], "SECRET_NOT_FOUND");
        assert_eq!(parsed["message"], "Test message");
        assert_eq!(parsed["request_id"], "req_123");
    }
}
