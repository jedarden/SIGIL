//! SIGIL Proxy - HTTP forward proxy with auth header injection
//!
//! This crate provides a forward HTTP(S) proxy that injects authentication
//! headers based on domain rules. It supports:
//!
//! - Bearer token injection
//! - AWS SigV4 request signing
//! - Custom header injection
//! - Response body scrubbing
//! - Domain allowlist (default-deny)
//! - Audit logging

#![warn(missing_docs)]
#![warn(clippy::all)]

mod config;
mod error;
mod proxy;
mod rules;
mod scrubber;
mod signing;

pub use config::{ProxyConfig, ProxyRule, ProxyRuleType};
pub use error::{ProxyError, ProxyResult};
pub use proxy::ProxyServer;
pub use rules::MatchedRule;
pub use scrubber::{ResponseScrubber, ScrubContext};
pub use signing::{AwsSigV4Signer, SignResult};
