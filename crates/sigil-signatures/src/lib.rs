//! SIGIL Command Signatures — Transparent secret injection via command recognition
//!
//! This crate provides command signature matching for automatic secret injection.
//! When a command matches a known signature, SIGIL automatically injects the
//! required secrets as environment variables, files, or headers without the agent
//! explicitly requesting them.
//!
//! # Example
//!
//! ```rust
//! use sigil_signatures::SignatureMatcher;
//!
//! let matcher = SignatureMatcher::new().unwrap();
//! let injections = matcher.match_command("aws s3 ls");
//!
//! // injections will contain:
//! // - AWS_ACCESS_KEY_ID → aws/access_key_id
//! // - AWS_SECRET_ACCESS_KEY → aws/secret_access_key
//! ```

#![warn(missing_docs)]
#![warn(clippy::all)]

mod builtins;
mod config;
mod matcher;
mod update;

pub use builtins::BUILTIN_SIGNATURES;
pub use config::{
    InjectionConfig, InjectionType as ConfigInjectionType, Signature, SignatureConfig,
    SignaturesToml,
};
pub use matcher::{InjectionType, MatchedInjection, MatchedSignature, SignatureMatcher};
pub use update::{
    SignatureFile, SignatureManifest, SignatureSet, SignatureUpdater, UpdateConfig, UpdateInfo,
    UpdateResult, DEFAULT_REPO_URL, GITHUB_RAW_BASE,
};

/// Default signature directory for user-defined signatures
pub const USER_SIGNATURES_DIR: &str = ".sigil/signatures.d";

/// Default project-level signature file
pub const PROJECT_SIGNATURES_FILE: &str = ".sigil/signatures.toml";

/// Global signature directory
pub const GLOBAL_SIGNATURES_DIR: &str = "~/.sigil/signatures.d";
