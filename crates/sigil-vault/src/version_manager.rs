//! Secret version management
//!
//! This module provides functionality for managing secret version history,
//! including storing multiple versions, tracking history, and rolling back.

use age::{Decryptor, Encryptor};
use sigil_core::{Result, SecretValue, SecretVersion, SigilError};
use std::fs;
use std::io::{BufRead, Read, Write};
use std::path::PathBuf;

/// Permissions for secret files (user read/write only)
#[allow(dead_code)]
const VAULT_FILE_PERMS: u32 = 0o600;

/// Set file permissions to user-only read/write (0600)
#[allow(dead_code)]
fn set_secret_file_permissions(path: &PathBuf) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = fs::metadata(path)
            .map_err(|e| SigilError::IoError(format!("Failed to read metadata: {}", e)))?
            .permissions();
        perms.set_mode(VAULT_FILE_PERMS);
        fs::set_permissions(path, perms)
            .map_err(|e| SigilError::IoError(format!("Failed to set file permissions: {}", e)))?;
    }
    #[cfg(not(unix))]
    {
        let perms = fs::metadata(path)
            .map_err(|e| SigilError::IoError(format!("Failed to read metadata: {}", e)))?
            .permissions();
        fs::set_permissions(path, perms)
            .map_err(|e| SigilError::IoError(format!("Failed to set file permissions: {}", e)))?;
    }
    Ok(())
}

/// Write data to a file with secure permissions (0600)
#[allow(dead_code)]
fn write_secret_file(path: &PathBuf, data: &[u8]) -> Result<()> {
    fs::write(path, data)
        .map_err(|e| SigilError::IoError(format!("Failed to write file: {}", e)))?;
    set_secret_file_permissions(path)?;
    Ok(())
}

/// Version manager for secret history
pub struct VersionManager {
    /// Namespace directory (e.g., ~/.sigil/vault/kalshi/)
    namespace_dir: PathBuf,
    /// Age identity for encryption
    identity: age::x25519::Identity,
}

impl VersionManager {
    /// Create a new version manager
    pub fn new(namespace_dir: PathBuf, identity: age::x25519::Identity) -> Self {
        Self {
            namespace_dir,
            identity,
        }
    }

    /// Get the path to a versioned secret file
    fn version_path(&self, secret_name: &str, version: u32) -> PathBuf {
        self.namespace_dir
            .join(format!("{}.v{}.age", secret_name, version))
    }

    /// Get the path to the current secret symlink
    fn current_path(&self, secret_name: &str) -> PathBuf {
        self.namespace_dir.join(format!("{}.age", secret_name))
    }

    /// Get the path to the history file
    fn history_path(&self, secret_name: &str) -> PathBuf {
        self.namespace_dir
            .join(format!("{}.history.jsonl.age", secret_name))
    }

    /// Get the next version number for a secret
    pub fn next_version(&self, secret_name: &str) -> Result<u32> {
        let mut max_version = 0;

        // Find existing version files
        let entries = fs::read_dir(&self.namespace_dir)?;
        for entry in entries {
            let entry = entry?;
            let file_name = entry.file_name();
            let file_name_str = file_name.to_string_lossy();

            // Match pattern: secret_name.vN.age
            if let Some(rest) = file_name_str.strip_prefix(&format!("{}.", secret_name)) {
                if let Some(version_str) = rest.strip_suffix(".age") {
                    if let Some(v_str) = version_str.strip_prefix("v") {
                        if let Ok(v) = v_str.parse::<u32>() {
                            max_version = max_version.max(v);
                        }
                    }
                }
            }
        }

        Ok(max_version + 1)
    }

    /// Save a new version of a secret
    pub fn save_version(
        &self,
        secret_name: &str,
        value: &SecretValue,
        version_meta: &SecretVersion,
    ) -> Result<()> {
        // Encrypt the value
        let plaintext = value.expose(|v| v.to_vec());
        let recipient = self.identity.to_public();
        let encryptor = Encryptor::with_recipients(vec![Box::new(recipient)])
            .ok_or_else(|| SigilError::Crypto("No recipients specified".into()))?;

        let mut encrypted = Vec::new();
        {
            let mut writer = encryptor
                .wrap_output(&mut encrypted)
                .map_err(|e| SigilError::Crypto(format!("Encryption error: {}", e)))?;
            writer.write_all(&plaintext)?;
            writer.finish()?;
        }

        // Write the version file with secure permissions
        let version_path = self.version_path(secret_name, version_meta.version);
        write_secret_file(&version_path, &encrypted)?;

        // Update the current symlink
        self.update_current_symlink(secret_name, version_meta.version)?;

        // Update history
        self.append_history(secret_name, version_meta)?;

        Ok(())
    }

    /// Update the current symlink to point to the specified version
    fn update_current_symlink(&self, secret_name: &str, version: u32) -> Result<()> {
        let current_path = self.current_path(secret_name);
        let version_path = self.version_path(secret_name, version);

        // Remove existing symlink if present
        if current_path.exists() {
            if current_path.is_symlink() {
                fs::remove_file(&current_path)?;
            } else {
                // If it's a regular file, back it up as v1
                let v1_path = self.version_path(secret_name, 1);
                if !v1_path.exists() {
                    fs::rename(&current_path, &v1_path)?;
                } else {
                    // v1 already exists, remove the old file
                    fs::remove_file(&current_path)?;
                }
            }
        }

        // Create symlink
        #[cfg(unix)]
        {
            std::os::unix::fs::symlink(&version_path, &current_path)
                .map_err(|e| std::io::Error::other(format!("Failed to create symlink: {}", e)))?;
        }

        #[cfg(windows)]
        {
            // On Windows, use a junction or copy for now
            // A proper implementation would use junctions
            fs::copy(&version_path, &current_path)
                .map_err(|e| SigilError::Io(format!("Failed to copy file: {}", e)))?;
        }

        Ok(())
    }

    /// Append a version entry to the history file
    fn append_history(&self, secret_name: &str, version_meta: &SecretVersion) -> Result<()> {
        let history_path = self.history_path(secret_name);

        // Read existing history if present
        let mut history = if history_path.exists() {
            self.read_history(secret_name)?
        } else {
            Vec::new()
        };

        // Add new entry
        history.push(version_meta.clone());

        // Serialize to JSONL
        let history_jsonl = history
            .iter()
            .map(|v| serde_json::to_string(v).unwrap())
            .collect::<Vec<_>>()
            .join("\n");

        // Encrypt and write
        let recipient = self.identity.to_public();
        let encryptor = Encryptor::with_recipients(vec![Box::new(recipient)])
            .ok_or_else(|| SigilError::Crypto("No recipients specified".into()))?;

        let mut encrypted = Vec::new();
        {
            let mut writer = encryptor
                .wrap_output(&mut encrypted)
                .map_err(|e| SigilError::Crypto(format!("Encryption error: {}", e)))?;
            writer.write_all(history_jsonl.as_bytes())?;
            writer.finish()?;
        }

        write_secret_file(&history_path, &encrypted)?;

        Ok(())
    }

    /// Read the history file
    pub fn read_history(&self, secret_name: &str) -> Result<Vec<SecretVersion>> {
        let history_path = self.history_path(secret_name);

        if !history_path.exists() {
            return Ok(Vec::new());
        }

        // Decrypt the history file
        let encrypted = fs::read(&history_path)?;
        let decryptor = Decryptor::new(&*encrypted)
            .map_err(|e| SigilError::Crypto(format!("Decryptor error: {}", e)))?;

        let mut decrypted = Vec::new();
        match decryptor {
            Decryptor::Recipients(d) => {
                let mut reader = d
                    .decrypt(std::iter::once(&self.identity as &dyn age::Identity))
                    .map_err(|e| SigilError::Crypto(format!("Decryption error: {}", e)))?;
                reader.read_to_end(&mut decrypted)?;
            }
            _ => return Err(SigilError::Crypto("Unexpected decryptor type".into())),
        }

        // Parse JSONL
        let mut history = Vec::new();
        for line in decrypted.lines() {
            let line = line.map_err(|e| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!("Invalid history data: {}", e),
                )
            })?;
            if line.is_empty() {
                continue;
            }
            let version: SecretVersion = serde_json::from_str(&line).map_err(|e| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!("Invalid history entry: {}", e),
                )
            })?;
            history.push(version);
        }

        Ok(history)
    }

    /// Get the current version number
    pub fn current_version(&self, secret_name: &str) -> Result<Option<u32>> {
        let current_path = self.current_path(secret_name);

        if !current_path.exists() {
            return Ok(None);
        }

        // Read symlink target
        if current_path.is_symlink() {
            let target = fs::read_link(&current_path)?;
            let file_name = target.file_name().and_then(|n| n.to_str()).ok_or_else(|| {
                std::io::Error::new(std::io::ErrorKind::NotFound, "Invalid symlink target")
            })?;

            // Extract version number
            if let Some(rest) = file_name.strip_prefix(&format!("{}.", secret_name)) {
                if let Some(version_str) = rest.strip_suffix(".age") {
                    if let Some(v_str) = version_str.strip_prefix("v") {
                        if let Ok(v) = v_str.parse::<u32>() {
                            return Ok(Some(v));
                        }
                    }
                }
            }
        }

        // If it's a regular file, treat it as version 1
        Ok(Some(1))
    }

    /// Rollback to a specific version
    pub fn rollback(&self, secret_name: &str, target_version: u32) -> Result<()> {
        // Verify the target version exists
        let version_path = self.version_path(secret_name, target_version);
        if !version_path.exists() {
            return Err(SigilError::SecretNotFound(format!(
                "Version {} of {} not found",
                target_version, secret_name
            )));
        }

        // Update the symlink
        self.update_current_symlink(secret_name, target_version)?;

        Ok(())
    }

    /// Delete old versions beyond retention
    pub fn prune(&self, secret_name: &str, keep_count: usize) -> Result<usize> {
        let history = self.read_history(secret_name)?;
        let current_version = self.current_version(secret_name)?.ok_or_else(|| {
            SigilError::SecretNotFound(format!("Secret {} has no versions", secret_name))
        })?;

        let mut deleted = 0;

        // Delete old version files (but keep the current and recent ones)
        for entry in fs::read_dir(&self.namespace_dir)? {
            let entry = entry?;
            let file_name = entry.file_name();
            let file_name_str = file_name.to_string_lossy();

            // Match pattern: secret_name.vN.age
            if let Some(rest) = file_name_str.strip_prefix(&format!("{}.", secret_name)) {
                if let Some(version_str) = rest.strip_suffix(".age") {
                    if let Some(v_str) = version_str.strip_prefix("v") {
                        if let Ok(version) = v_str.parse::<u32>() {
                            // Don't delete the current version
                            if version == current_version {
                                continue;
                            }

                            // Check if this version is within the keep window
                            let version_index = history
                                .iter()
                                .position(|v| v.version == version)
                                .unwrap_or(usize::MAX);

                            if version_index >= keep_count {
                                // Delete this version file
                                let path = entry.path();
                                fs::remove_file(&path)?;
                                deleted += 1;
                            }
                        }
                    }
                }
            }
        }

        Ok(deleted)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use age::x25519::Identity;
    use tempfile::tempdir;

    #[test]
    fn test_next_version() {
        let temp_dir = tempdir().unwrap();
        let namespace_dir = temp_dir.path().join("test");
        fs::create_dir_all(&namespace_dir).unwrap();

        let identity = Identity::generate();
        let manager = VersionManager::new(namespace_dir.clone(), identity);

        // Initially should be 1
        assert_eq!(manager.next_version("test").unwrap(), 1);

        // Create some version files
        fs::write(namespace_dir.join("test.v1.age"), b"v1").unwrap();
        fs::write(namespace_dir.join("test.v2.age"), b"v2").unwrap();

        // Should now be 3
        assert_eq!(manager.next_version("test").unwrap(), 3);
    }
}
