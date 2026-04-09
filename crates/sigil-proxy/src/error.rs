//! Error types for the SIGIL proxy

use thiserror::Error;

/// Result type for proxy operations
pub type ProxyResult<T> = Result<T, ProxyError>;

/// Errors that can occur in the proxy
#[derive(Error, Debug)]
pub enum ProxyError {
    /// Invalid proxy configuration
    #[error("invalid proxy configuration: {0}")]
    InvalidConfig(String),

    /// No matching rule for domain
    #[error("no rule configured for domain: {0}")]
    NoRuleForDomain(String),

    /// Domain not in allowlist
    #[error("domain not in allowlist: {0}")]
    DomainNotAllowed(String),

    /// Secret not found
    #[error("secret not found: {0}")]
    SecretNotFound(String),

    /// HTTP error
    #[error("HTTP error: {0}")]
    HttpError(#[from] hyper::Error),

    /// HTTP error with status
    #[error("HTTP error: {0}")]
    HttpStatus(u16, String),

    /// Connection error
    #[error("connection error to {0}: {1}")]
    ConnectionError(String, String),

    /// TLS error
    #[error("TLS error: {0}")]
    TlsError(String),

    /// Signing error (e.g., AWS SigV4)
    #[error("signing error: {0}")]
    SigningError(String),

    /// Scrubbing error
    #[error("scrubbing error: {0}")]
    ScrubbingError(String),

    /// I/O error
    #[error("I/O error: {0}")]
    IoError(#[from] std::io::Error),

    /// Invalid URI
    #[error("invalid URI: {0}")]
    InvalidUri(String),

    /// Missing required header
    #[error("missing required header: {0}")]
    MissingHeader(String),

    /// Unsupported method
    #[error("unsupported HTTP method: {0}")]
    UnsupportedMethod(String),

    /// Invalid request body
    #[error("invalid request body: {0}")]
    InvalidBody(String),
}

/// Convert from hyper::http::Error
impl From<hyper::http::Error> for ProxyError {
    fn from(e: hyper::http::Error) -> Self {
        ProxyError::InvalidConfig(format!("HTTP error: {}", e))
    }
}

/// Convert from hyper_util client error
impl From<hyper_util::client::legacy::Error> for ProxyError {
    fn from(e: hyper_util::client::legacy::Error) -> Self {
        ProxyError::ConnectionError("unknown".to_string(), format!("{}", e))
    }
}

/// Convert from aho_corasick BuildError
impl From<aho_corasick::BuildError> for ProxyError {
    fn from(e: aho_corasick::BuildError) -> Self {
        ProxyError::InvalidConfig(format!("failed to build scrubber: {}", e))
    }
}

/// Convert from rcgen::Error
impl From<rcgen::Error> for ProxyError {
    fn from(e: rcgen::Error) -> Self {
        ProxyError::TlsError(format!("certificate generation error: {}", e))
    }
}

/// Convert from pem::PemError
impl From<pem::PemError> for ProxyError {
    fn from(e: pem::PemError) -> Self {
        ProxyError::TlsError(format!("PEM parsing error: {}", e))
    }
}
