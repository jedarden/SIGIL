//! SIGIL archive format for export/import
//!
//! Archive format:
//! ```text
//! magic: "SIGIL\x00"
//! version: u16 (big-endian)
//! payload: age-encrypted(msgpack({
//!     secrets: [{path, value, metadata}],
//!     exported_at: DateTime,
//!     source_vault_id: String,
//! }))
//! ```

use age::{secrecy::Secret, Decryptor, Encryptor};
use anyhow::Result;
use base64::prelude::*;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sigil_core::{SecretMetadata, SecretPath, SecretValue};
use std::io::{Read, Write};

/// Magic bytes for SIGIL archive format
const ARCHIVE_MAGIC: &[u8] = b"SIGIL\x00";
/// Archive format version (current)
const ARCHIVE_VERSION: u16 = 1;

/// Archive payload (encrypted contents)
#[derive(Debug, Serialize, Deserialize)]
pub struct ArchivePayload {
    /// Secrets in the archive
    pub secrets: Vec<ArchivedSecret>,
    /// When the archive was created
    pub exported_at: DateTime<Utc>,
    /// Source vault identifier
    pub source_vault_id: String,
}

/// A secret in the archive
#[derive(Debug, Serialize, Deserialize)]
pub struct ArchivedSecret {
    /// Secret path
    pub path: String,
    /// Secret value (base64-encoded)
    pub value: String,
    /// Secret metadata
    pub metadata: SecretMetadata,
}

/// Create a SIGIL archive from secrets
pub fn create_archive(
    secrets: Vec<(SecretPath, SecretValue, SecretMetadata)>,
    vault_id: &str,
    passphrase: Option<&str>,
) -> Result<Vec<u8>> {
    // Build the payload
    let archived_secrets = secrets
        .into_iter()
        .map(|(path, value, metadata)| {
            let value_base64 = value.expose(|bytes| BASE64_STANDARD.encode(bytes));
            ArchivedSecret {
                path: path.as_str().to_string(),
                value: value_base64,
                metadata,
            }
        })
        .collect();

    let payload = ArchivePayload {
        secrets: archived_secrets,
        exported_at: Utc::now(),
        source_vault_id: vault_id.to_string(),
    };

    // Serialize to msgpack
    let msgpack_bytes = rmp_serde::to_vec_named(&payload)?;

    // Encrypt the payload
    let encrypted = if let Some(pass) = passphrase {
        // Passphrase-based encryption
        let encryptor = Encryptor::with_user_passphrase(Secret::new(pass.to_owned()));
        let mut encrypted = Vec::new();
        {
            let mut writer = encryptor
                .wrap_output(&mut encrypted)
                .map_err(|e| anyhow::anyhow!("Encryption error: {}", e))?;
            writer.write_all(&msgpack_bytes)?;
            writer.finish()?;
        }
        encrypted
    } else {
        // No encryption (not recommended, but supported for testing)
        msgpack_bytes
    };

    // Build the archive header
    let mut archive = Vec::new();
    archive.extend_from_slice(ARCHIVE_MAGIC);
    archive.extend_from_slice(&ARCHIVE_VERSION.to_be_bytes());
    archive.extend_from_slice(&encrypted);

    Ok(archive)
}

/// Extract secrets from a SIGIL archive
pub fn extract_archive(archive_data: &[u8], passphrase: Option<&str>) -> Result<ArchivePayload> {
    // Verify magic bytes
    if archive_data.len() < ARCHIVE_MAGIC.len() + 2 {
        anyhow::bail!("Invalid archive: too small");
    }

    let magic = &archive_data[..ARCHIVE_MAGIC.len()];
    if magic != ARCHIVE_MAGIC {
        anyhow::bail!("Invalid archive: wrong magic bytes");
    }

    // Read version
    let version_bytes = &archive_data[ARCHIVE_MAGIC.len()..ARCHIVE_MAGIC.len() + 2];
    let version = u16::from_be_bytes([version_bytes[0], version_bytes[1]]);

    if version != ARCHIVE_VERSION {
        anyhow::bail!("Unsupported archive version: {}", version);
    }

    // Extract encrypted payload
    let encrypted = &archive_data[ARCHIVE_MAGIC.len() + 2..];

    // Decrypt the payload
    let msgpack_bytes = if let Some(pass) = passphrase {
        // Try passphrase-based decryption
        let decryptor =
            Decryptor::new(encrypted).map_err(|e| anyhow::anyhow!("Decryptor error: {}", e))?;

        let mut decrypted = Vec::new();
        match decryptor {
            Decryptor::Passphrase(d) => {
                let mut reader = d
                    .decrypt(&Secret::new(pass.to_owned()), None)
                    .map_err(|e| anyhow::anyhow!("Decryption error: {}", e))?;
                reader.read_to_end(&mut decrypted)?;
            }
            _ => anyhow::bail!("Unexpected decryptor type"),
        }
        decrypted
    } else {
        // No encryption
        encrypted.to_vec()
    };

    // Deserialize from msgpack
    let payload: ArchivePayload = rmp_serde::from_slice(&msgpack_bytes)
        .map_err(|e| anyhow::anyhow!("Deserialization error: {}", e))?;

    Ok(payload)
}

/// Import conflict resolution mode
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ImportMode {
    /// Skip existing secrets (default)
    Merge,
    /// Overwrite existing secrets
    Overwrite,
    /// Interactive prompting for each conflict
    Interactive,
}

impl ImportMode {
    pub fn from_str(s: &str) -> Result<Self> {
        match s.to_lowercase().as_str() {
            "merge" => Ok(Self::Merge),
            "overwrite" => Ok(Self::Overwrite),
            "interactive" => Ok(Self::Interactive),
            _ => anyhow::bail!(
                "Invalid import mode: {}. Use: merge, overwrite, or interactive",
                s
            ),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sigil_core::SecretType;

    #[test]
    fn test_archive_roundtrip() {
        let secrets = vec![(
            SecretPath::new("test/api_key").unwrap(),
            SecretValue::from_string("my-secret-key".to_string()),
            {
                let mut meta = SecretMetadata::new(SecretPath::new("test/api_key").unwrap());
                meta.secret_type = SecretType::ApiKey;
                meta.tags = vec!["prod".to_string(), "api".to_string()];
                meta
            },
        )];

        // Create archive
        let archive = create_archive(secrets, "test-vault", Some("test-pass")).unwrap();

        // Extract and verify
        let payload = extract_archive(&archive, Some("test-pass")).unwrap();
        assert_eq!(payload.secrets.len(), 1);
        assert_eq!(payload.secrets[0].path, "test/api_key");

        // Decode and verify the secret value
        let decoded = BASE64_STANDARD.decode(&payload.secrets[0].value).unwrap();
        assert_eq!(String::from_utf8_lossy(&decoded), "my-secret-key");
    }

    #[test]
    fn test_archive_magic_validation() {
        let invalid_data = b"INVALID\x00\x01\x00";
        assert!(extract_archive(invalid_data, None).is_err());
    }

    #[test]
    fn test_archive_version_validation() {
        let mut data = Vec::new();
        data.extend_from_slice(ARCHIVE_MAGIC);
        data.extend_from_slice(&9999u16.to_be_bytes()); // Wrong version
        data.extend_from_slice(b"payload");

        assert!(extract_archive(&data, None).is_err());
    }
}
