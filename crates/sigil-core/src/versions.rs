//! Secret version history types
//!
//! This module provides types for tracking secret version history,
//! enabling rollback and audit trails.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Metadata for a single version of a secret
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecretVersion {
    /// Version number
    pub version: u32,
    /// When this version was created
    pub created_at: DateTime<Utc>,
    /// Fingerprint of the secret value (SHA256[0..6])
    pub fingerprint: String,
    /// Reason for this version (initial, rotation, etc.)
    pub reason: String,
    /// Previous version number (if any)
    pub previous: Option<u32>,
}

impl SecretVersion {
    /// Create a new secret version
    pub fn new(
        version: u32,
        value_bytes: &[u8],
        reason: impl Into<String>,
        previous: Option<u32>,
    ) -> Self {
        // Calculate fingerprint: SHA256(value)[0..6]
        let hash = Sha256::digest(value_bytes);
        let fingerprint = hex::encode(&hash[..3]); // 3 bytes = 6 hex chars

        Self {
            version,
            created_at: Utc::now(),
            fingerprint,
            reason: reason.into(),
            previous,
        }
    }

    /// Create an initial version
    pub fn initial(version: u32, value_bytes: &[u8]) -> Self {
        Self::new(version, value_bytes, "initial", None)
    }

    /// Create a rotation version
    pub fn rotation(version: u32, value_bytes: &[u8], previous: u32) -> Self {
        Self::new(version, value_bytes, "rotation", Some(previous))
    }

    /// Create a manual edit version
    pub fn edit(version: u32, value_bytes: &[u8], previous: u32) -> Self {
        Self::new(version, value_bytes, "edit", Some(previous))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fingerprint_generation() {
        let value = b"my-secret-value";
        let version = SecretVersion::initial(1, value);
        assert_eq!(version.fingerprint.len(), 6);
        assert_eq!(version.version, 1);
        assert_eq!(version.reason, "initial");
        assert!(version.previous.is_none());
    }

    #[test]
    fn test_rotation_version() {
        let value = b"my-new-secret";
        let version = SecretVersion::rotation(2, value, 1);
        assert_eq!(version.version, 2);
        assert_eq!(version.reason, "rotation");
        assert_eq!(version.previous, Some(1));
    }
}
