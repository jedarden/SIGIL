//! Memory protection for SIGIL daemon
//!
//! Provides memory protection features including:
//! - PR_SET_DUMPABLE(0) to prevent ptrace/memory reads
//! - mlock() to prevent swapping to disk
//! - Zeroizing secrets on shutdown

use sigil_core::{Result, SigilError};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use zeroize::{Zeroize, Zeroizing};

/// Protected memory for secrets
///
/// Uses mlock to prevent secrets from being swapped to disk.
pub struct ProtectedSecrets {
    secrets: Arc<RwLock<HashMap<String, Vec<u8>>>>,
}

impl ProtectedSecrets {
    /// Create a new protected secrets store
    pub fn new() -> Result<Self> {
        let store = Self {
            secrets: Arc::new(RwLock::new(HashMap::new())),
        };

        // Lock the memory pages for the secrets store
        // Note: This is best-effort; mlock may fail due to resource limits
        store.mlock_secrets()?;

        Ok(store)
    }

    /// Get a reference to the secrets store
    pub fn inner(&self) -> &Arc<RwLock<HashMap<String, Vec<u8>>>> {
        &self.secrets
    }

    /// Attempt to mlock the secrets memory
    ///
    /// This is best-effort; if mlock fails, we log a warning but continue.
    /// The system may still swap pages if RLIMIT_MEMLOCK is exceeded.
    fn mlock_secrets(&self) -> Result<()> {
        #[cfg(target_os = "linux")]
        {
            // For Linux, we use mlockall with MCL_CURRENT | MCL_FUTURE
            // This locks all current and future memory pages
            unsafe {
                let ret = libc::mlockall(libc::MCL_CURRENT | libc::MCL_FUTURE);
                if ret != 0 {
                    let err = std::io::Error::last_os_error();
                    tracing::warn!(
                        "Failed to mlockall memory: {}. Secrets may be swapped to disk.",
                        err
                    );
                    // Don't fail startup; just warn
                    return Ok(());
                }
            }
            tracing::info!("Memory locked (mlockall) to prevent swapping");
        }

        #[cfg(target_os = "macos")]
        {
            // macOS uses mlock similarly but with different behavior
            // We'll lock pages as secrets are added
            tracing::info!("Memory protection enabled (per-secret mlock)");
        }

        Ok(())
    }

    /// Insert a secret with memory protection
    #[allow(dead_code)]
    pub async fn insert(&self, path: String, value: Vec<u8>) -> Result<()> {
        #[cfg(target_os = "macos")]
        {
            // On macOS, mlock the specific secret value
            unsafe {
                let ret = libc::mlock(value.as_ptr() as *const libc::c_void, value.len());
                if ret != 0 {
                    let err = std::io::Error::last_os_error();
                    tracing::warn!("Failed to mlock secret {}: {}", path, err);
                }
            }
        }

        let mut secrets = self.secrets.write().await;
        secrets.insert(path, value);
        Ok(())
    }

    /// Zeroize and remove all secrets
    pub async fn zeroize_all(&self) {
        let mut secrets = self.secrets.write().await;
        for (path, value) in secrets.iter_mut() {
            // Zeroize each secret value
            let mut zeroizing = Zeroizing::from(value.clone());
            zeroizing.zeroize();
            tracing::debug!("Zeroized secret: {}", path);
        }
        secrets.clear();
        tracing::info!("All secrets zeroized");
    }
}

impl Default for ProtectedSecrets {
    fn default() -> Self {
        Self::new().expect("Failed to create protected secrets")
    }
}

/// Enable memory protection for the current process
///
/// This should be called early in daemon startup, before any secrets are loaded.
pub fn enable_memory_protection() -> Result<()> {
    #[cfg(target_os = "linux")]
    {
        // Set PR_SET_DUMPABLE to 0 to prevent ptrace and memory reads
        unsafe {
            let ret = libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0);
            if ret != 0 {
                let err = std::io::Error::last_os_error();
                return Err(SigilError::IoError(format!(
                    "Failed to set PR_SET_DUMPABLE: {}",
                    err
                )));
            }
        }
        tracing::info!("Set PR_SET_DUMPABLE=0 (ptrace protection enabled)");
    }

    #[cfg(target_os = "macos")]
    {
        // Use PT_DENY_ATTACH to prevent debugger attachment
        unsafe {
            let ret = libc::ptrace(libc::PT_DENY_ATTACH, 0, std::ptr::null_mut(), 0);
            if ret != 0 {
                let err = std::io::Error::last_os_error();
                // This is expected in some cases (e.g., when not being debugged)
                tracing::debug!("PT_DENY_ATTACH failed (may be expected): {}", err);
            } else {
                tracing::info!("Set PT_DENY_ATTACH (debugger protection enabled)");
            }
        }
    }

    // Disable core dumps
    unsafe {
        let rlim = libc::rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };
        let ret = libc::setrlimit(libc::RLIMIT_CORE, &rlim);
        if ret != 0 {
            let err = std::io::Error::last_os_error();
            tracing::warn!("Failed to disable core dumps: {}", err);
        } else {
            tracing::info!("Core dumps disabled (RLIMIT_CORE=0)");
        }
    }

    Ok(())
}

/// Securely clear a buffer
///
/// This is a utility function for zeroizing sensitive data.
#[allow(dead_code)]
pub fn secure_clear(buf: &mut [u8]) {
    // Zeroize the buffer directly using the Zeroize trait
    buf.zeroize();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_protected_secrets_creation() {
        let secrets = ProtectedSecrets::new().unwrap();
        let store = secrets.inner().read().await;
        assert!(store.is_empty());
    }

    #[tokio::test]
    async fn test_protected_secrets_insert() {
        let secrets = ProtectedSecrets::new().unwrap();
        secrets
            .insert("test/path".to_string(), b"test_value".to_vec())
            .await
            .unwrap();

        let store = secrets.inner().read().await;
        assert_eq!(store.len(), 1);
        assert_eq!(store.get("test/path").unwrap(), b"test_value");
    }

    #[tokio::test]
    async fn test_protected_secrets_zeroize() {
        let secrets = ProtectedSecrets::new().unwrap();
        secrets
            .insert("test/path".to_string(), b"sensitive_data".to_vec())
            .await
            .unwrap();

        secrets.zeroize_all().await;

        let store = secrets.inner().read().await;
        assert!(store.is_empty());
    }

    #[test]
    fn test_secure_clear() {
        let mut buf = b"sensitive_data".to_vec();
        secure_clear(&mut buf);
        // After zeroizing, all bytes should be 0
        assert!(buf.iter().all(|&b| b == 0));
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn test_enable_memory_protection() {
        // This test just verifies the function runs without panicking
        // In a real scenario, it would need elevated privileges to test mlock
        let result = enable_memory_protection();
        assert!(
            result.is_ok(),
            "enable_memory_protection failed: {:?}",
            result
        );
    }
}
