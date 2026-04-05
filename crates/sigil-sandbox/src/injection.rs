//! File injection pipeline for secret values
//!
//! Provides secure temporary file creation on tmpfs with proper cleanup.

use crate::secure_fd::SecureFile;
use sigil_core::{Result, SecretPath, SecretValue, SigilError};
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

/// Default tmpfs base directory for secret injection
const SECRET_TMPFS_BASE: &str = "/run/user/%UID%/sigil";

/// File injection handle for a single secret file
///
/// This handle manages the lifecycle of an injected secret file.
/// When dropped, the file is securely deleted (overwritten with zeros then unlinked).
pub struct FileInjection {
    /// Path to the injected file
    path: PathBuf,
    /// Whether cleanup has been performed
    cleaned: bool,
}

impl FileInjection {
    /// Create a new file injection with the given secret value
    ///
    /// The file is created on tmpfs with 0400 permissions (owner read-only).
    pub fn create(secret_path: &SecretPath, value: &SecretValue) -> Result<Self> {
        // Get the current user's UID for the tmpfs path
        let uid = nix::unistd::Uid::effective();
        let tmpfs_base = SECRET_TMPFS_BASE.replace("%UID%", &uid.to_string());

        // Create the tmpfs directory if it doesn't exist
        let tmpfs_dir = PathBuf::from(tmpfs_base);
        if !tmpfs_dir.exists() {
            fs::create_dir_all(&tmpfs_dir).map_err(|e| {
                SigilError::IoError(format!("Failed to create tmpfs directory: {}", e))
            })?;
        }

        // Create a sanitized filename from the secret path
        let filename = sanitize_filename(secret_path.as_str());
        let file_path = tmpfs_dir.join(&filename);

        // Write the secret value to the file
        value.expose(|bytes| {
            fs::write(&file_path, bytes)
                .map_err(|e| SigilError::IoError(format!("Failed to write secret file: {}", e)))?;
            Ok::<(), SigilError>(())
        })?;

        // Set file permissions to 0400 (owner read-only)
        let mut perms = fs::metadata(&file_path)
            .map_err(|e| SigilError::IoError(format!("Failed to get file metadata: {}", e)))?
            .permissions();
        perms.set_mode(0o400);
        fs::set_permissions(&file_path, perms)
            .map_err(|e| SigilError::IoError(format!("Failed to set file permissions: {}", e)))?;

        Ok(Self {
            path: file_path,
            cleaned: false,
        })
    }

    /// Get the path to the injected file
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Securely delete the injected file
    ///
    /// This overwrites the file with zeros before unlinking it.
    pub fn cleanup(&mut self) -> Result<()> {
        if self.cleaned {
            return Ok(());
        }

        // Overwrite the file with zeros
        if self.path.exists() {
            // Get the file size
            let metadata = fs::metadata(&self.path)
                .map_err(|e| SigilError::IoError(format!("Failed to get file metadata: {}", e)))?;
            let file_size = metadata.len() as usize;

            // Write zeros to the file
            let zeros = vec![0u8; file_size];
            fs::write(&self.path, &zeros)
                .map_err(|e| SigilError::IoError(format!("Failed to overwrite file: {}", e)))?;

            // Sync to ensure the write is flushed to disk
            fs::File::open(&self.path)
                .and_then(|f| f.sync_all())
                .map_err(|e| SigilError::IoError(format!("Failed to sync file: {}", e)))?;

            // Unlink the file
            fs::remove_file(&self.path)
                .map_err(|e| SigilError::IoError(format!("Failed to remove file: {}", e)))?;
        }

        self.cleaned = true;
        Ok(())
    }
}

impl Drop for FileInjection {
    fn drop(&mut self) {
        // Best-effort cleanup on drop
        let _ = self.cleanup();
    }
}

/// TOCTOU-safe file injection using memfd (Linux) or secure tempfile (macOS)
///
/// This uses memfd_create on Linux (in-memory file descriptors with no
/// filesystem path) and mkstemp + immediate unlink on macOS. This eliminates
/// TOCTOU vulnerabilities in the tmpfs secret injection pipeline (Phase 4.5).
pub struct SecureFileInjection {
    /// The secure file handle
    secure_file: SecureFile,
    /// The secret path (for metadata/debugging)
    secret_path: String,
    /// Whether the file is sealed
    sealed: bool,
}

impl SecureFileInjection {
    /// Create a new TOCTOU-safe file injection
    ///
    /// On Linux: uses memfd_create for in-memory file storage
    /// On macOS: uses mkstemp + immediate unlink
    pub fn create(secret_path: &SecretPath, value: &SecretValue) -> Result<Self> {
        let mut secure_file = SecureFile::create(secret_path.as_str())?;

        // Write the secret value
        value.expose(|bytes| {
            secure_file.write(bytes)
                .map_err(|e| SigilError::IoError(format!("Failed to write secret: {}", e)))?;
            Ok::<(), SigilError>(())
        })?;

        // Seal the file to prevent further modifications (defense-in-depth)
        secure_file.seal()?;

        Ok(Self {
            secure_file,
            secret_path: secret_path.as_str().to_string(),
            sealed: true,
        })
    }

    /// Get the file descriptor number for passing to child processes
    ///
    /// This fd can be used with fd inheritance or /proc/self/fd/N paths
    pub fn fd(&self) -> i32 {
        self.secure_file.as_raw_fd()
    }

    /// Get a /proc/self/fd path for use with bubblewrap bind mounts
    ///
    /// This allows passing memfd files to bwrap without filesystem exposure.
    pub fn proc_fd_path(&self) -> String {
        format!("/proc/self/fd/{}", self.fd())
    }

    /// Get the secret path
    pub fn secret_path(&self) -> &str {
        &self.secret_path
    }

    /// Check if the file is sealed
    pub fn is_sealed(&self) -> bool {
        self.sealed
    }

    /// Get the underlying secure file
    pub fn secure_file(&self) -> &SecureFile {
        &self.secure_file
    }
}

/// Manager for multiple file injections
///
/// Tracks all injected files and ensures they're cleaned up.
pub struct InjectionManager {
    injections: Vec<FileInjection>,
}

impl InjectionManager {
    /// Create a new injection manager
    pub fn new() -> Self {
        Self {
            injections: Vec::new(),
        }
    }

    /// Inject a secret value as a file
    ///
    /// Returns the path to the injected file.
    pub fn inject(&mut self, secret_path: &SecretPath, value: &SecretValue) -> Result<PathBuf> {
        let injection = FileInjection::create(secret_path, value)?;
        let path = injection.path().to_path_buf();
        self.injections.push(injection);
        Ok(path)
    }

    /// Inject multiple secrets for file-based placeholders
    ///
    /// Takes a list of (secret_path, value) tuples and returns a map of
    /// secret_path -> injected_file_path.
    pub fn inject_all(
        &mut self,
        secrets: &[(SecretPath, SecretValue)],
    ) -> Result<Vec<(String, PathBuf)>> {
        let mut result = Vec::new();
        for (secret_path, value) in secrets {
            let path = self.inject(secret_path, value)?;
            result.push((secret_path.as_str().to_string(), path));
        }
        Ok(result)
    }

    /// Clean up all injected files
    pub fn cleanup_all(&mut self) -> Result<()> {
        for injection in &mut self.injections {
            injection.cleanup()?;
        }
        self.injections.clear();
        Ok(())
    }

    /// Get the number of active injections
    pub fn len(&self) -> usize {
        self.injections.len()
    }

    /// Check if there are any active injections
    pub fn is_empty(&self) -> bool {
        self.injections.is_empty()
    }
}

impl Default for InjectionManager {
    fn default() -> Self {
        Self::new()
    }
}

impl Drop for InjectionManager {
    fn drop(&mut self) {
        // Best-effort cleanup on drop
        let _ = self.cleanup_all();
    }
}

/// Sanitize a secret path for use as a filename
fn sanitize_filename(path: &str) -> String {
    path.chars()
        .map(|c| {
            if c.is_alphanumeric() || c == '_' || c == '-' || c == '.' {
                c
            } else {
                '_'
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sanitize_filename() {
        assert_eq!(sanitize_filename("api/key"), "api_key");
        assert_eq!(sanitize_filename("test-path"), "test-path");
        assert_eq!(sanitize_filename("my.secret"), "my.secret");
        assert_eq!(sanitize_filename("weird/path/here"), "weird_path_here");
    }

    #[test]
    fn test_injection_manager_creation() {
        let manager = InjectionManager::new();
        assert_eq!(manager.len(), 0);
        assert!(manager.is_empty());
    }

    #[test]
    fn test_injection_manager_default() {
        let manager = InjectionManager::default();
        assert_eq!(manager.len(), 0);
    }

    #[test]
    fn test_file_injection_cleanup_idempotent() {
        // This test requires actual file creation, so we'll test the logic
        // without actually creating files in the unit test
        let path = PathBuf::from("/tmp/test_sigil_injection");
        let mut injection = FileInjection {
            path: path.clone(),
            cleaned: false,
        };

        // Simulate cleanup
        injection.cleaned = true;
        assert!(injection.cleanup().is_ok());
        assert!(injection.cleaned);
    }
}
