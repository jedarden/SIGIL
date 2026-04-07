//! SIGIL Vault - Local vault implementation
//!
//! This crate provides the local vault implementation for SIGIL, using age-encrypted files.

#![warn(missing_docs)]
#![warn(clippy::all)]

pub mod config;
pub mod local;
pub mod recovery;
pub mod sealed;
pub mod version_manager;

pub use config::{
    AuthFactorsConfig, KdfParams, ProjectConfig, SigilConfig, SigilConfigManager, SignatureMapping,
};
pub use local::LocalVault;
pub use sealed::{AuthFactor, SealedVault, VaultHeader};
pub use version_manager::VersionManager;
