//! Kernel keyring support for secure session token storage
//!
//! This module provides Linux kernel keyring support for storing session tokens.
//! The kernel keyring provides several security advantages over file-based storage:
//!
//! - Keys are stored in kernel memory, never written to disk
//! - Keys are inherited by child processes but not by processes in a new session
//! - Keys can be revoked or have timeouts set
//! - Keys are not accessible via filesystem reads
//!
//! # Platform Support
//!
//! This module is Linux-specific. On non-Linux platforms, the functions return
//! appropriate errors to allow fallback to file-based storage.

#![allow(missing_docs)]

use crate::{Result, SigilError};
#[cfg(target_os = "linux")]
use nix::libc;
#[cfg(target_os = "linux")]
use std::ffi::CString;

/// Key type for session tokens
pub const KEY_TYPE_USER: &str = "user";

/// Key description for SIGIL session token
pub const KEY_DESCRIPTION: &str = "sigil_session";

/// Session keyring constant (Linux-specific)
#[cfg(target_os = "linux")]
pub const KEY_SPEC_SESSION_KEYRING: i32 = -3;

/// Add the session token to the kernel session keyring
///
/// This stores the token in the kernel's session keyring, which:
/// - Is inherited by child processes
/// - Is NOT accessible to processes in a new session (like agent workers)
/// - Never touches the disk
/// - Can be revoked or expire
///
/// # Arguments
///
/// * `token` - The session token to store (base64-encoded string)
///
/// # Returns
///
/// Returns the key ID if successful
///
/// # Errors
///
/// Returns an error if:
/// - The platform is not Linux
/// - The keyctl syscall fails
/// - The token is too large for the key payload
pub fn add_session_token(token: &str) -> Result<u32> {
    #[cfg(target_os = "linux")]
    {
        // Convert the key type and description to C strings
        let key_type = CString::new(KEY_TYPE_USER)
            .map_err(|e| SigilError::IoError(format!("Failed to create key type string: {}", e)))?;

        let description = CString::new(KEY_DESCRIPTION).map_err(|e| {
            SigilError::IoError(format!("Failed to create key description string: {}", e))
        })?;

        // The key payload is the token bytes
        let token_bytes = token.as_bytes();

        // Make the keyctl syscall: add_key("user", "sigil:session", token, strlen(token), KEY_SPEC_SESSION_KEYRING)
        let key_id = unsafe {
            libc::syscall(
                libc::SYS_add_key,
                key_type.as_ptr(),
                description.as_ptr(),
                token_bytes.as_ptr(),
                token_bytes.len(),
                KEY_SPEC_SESSION_KEYRING,
            )
        };

        if key_id < 0 {
            let err = std::io::Error::last_os_error();
            return Err(SigilError::IoError(format!(
                "Failed to add session token to keyring: {} (errno: {})",
                err,
                err.raw_os_error().unwrap_or(0)
            )));
        }

        tracing::info!(
            "Session token stored in kernel keyring (key ID: {})",
            key_id
        );

        Ok(key_id as u32)
    }

    #[cfg(not(target_os = "linux"))]
    {
        Err(SigilError::IoError(
            "Kernel keyring is only supported on Linux".to_string(),
        ))
    }
}

/// Read the session token from the kernel session keyring
///
/// This reads the token from the kernel's session keyring.
///
/// # Returns
///
/// Returns the session token string if found
///
/// # Errors
///
/// Returns an error if:
/// - The platform is not Linux
/// - The keyctl syscall fails
/// - The key is not found
pub fn read_session_token() -> Result<String> {
    #[cfg(target_os = "linux")]
    {
        // First, find the key ID
        let key_id = find_session_key()?;

        // Read the key payload
        let mut buffer = vec![0u8; 256]; // Base64-encoded 32-byte token fits in 256 bytes

        let ret = unsafe {
            libc::syscall(
                libc::SYS_keyctl,
                libc::KEYCTL_READ,
                key_id,
                buffer.as_mut_ptr(),
                buffer.len(),
            )
        };

        if ret < 0 {
            let err = std::io::Error::last_os_error();
            return Err(SigilError::IoError(format!(
                "Failed to read session token from keyring: {}",
                err
            )));
        }

        // Truncate the buffer to the actual data length
        buffer.truncate(ret as usize);

        // Convert to string
        let token = String::from_utf8(buffer)
            .map_err(|e| SigilError::IoError(format!("Failed to convert token to UTF-8: {}", e)))?;

        Ok(token)
    }

    #[cfg(not(target_os = "linux"))]
    {
        Err(SigilError::IoError(
            "Kernel keyring is only supported on Linux".to_string(),
        ))
    }
}

/// Remove the session token from the kernel session keyring
///
/// This revokes the session token, making it unusable.
///
/// # Errors
///
/// Returns an error if:
/// - The platform is not Linux
/// - The keyctl syscall fails
/// - The key is not found
pub fn remove_session_token() -> Result<()> {
    #[cfg(target_os = "linux")]
    {
        let key_id = find_session_key()?;

        // Revoke the key
        let ret = unsafe { libc::syscall(libc::SYS_keyctl, libc::KEYCTL_REVOKE, key_id) };

        if ret < 0 {
            let err = std::io::Error::last_os_error();
            return Err(SigilError::IoError(format!(
                "Failed to revoke session token: {}",
                err
            )));
        }

        tracing::info!("Session token revoked from kernel keyring");

        Ok(())
    }

    #[cfg(not(target_os = "linux"))]
    {
        Err(SigilError::IoError(
            "Kernel keyring is only supported on Linux".to_string(),
        ))
    }
}

/// Find the session token key in the kernel keyring
///
/// # Errors
///
/// Returns an error if:
/// - The platform is not Linux
/// - The keyctl syscall fails
/// - The key is not found
#[cfg(target_os = "linux")]
fn find_session_key() -> Result<u32> {
    use std::io::Error;

    let key_type = CString::new(KEY_TYPE_USER)
        .map_err(|e| SigilError::IoError(format!("Failed to create key type string: {}", e)))?;

    let description = CString::new(KEY_DESCRIPTION).map_err(|e| {
        SigilError::IoError(format!("Failed to create key description string: {}", e))
    })?;

    // Search for the key in the session keyring
    let key_id = unsafe {
        libc::syscall(
            libc::SYS_keyctl,
            libc::KEYCTL_SEARCH,
            KEY_SPEC_SESSION_KEYRING,
            key_type.as_ptr(),
            description.as_ptr(),
            0,
        )
    };

    if key_id < 0 {
        let err = Error::last_os_error();
        // ENOKEY means the key was not found
        if err.raw_os_error() == Some(libc::ENOKEY) {
            return Err(SigilError::IoError(
                "Session token not found in keyring".to_string(),
            ));
        }
        return Err(SigilError::IoError(format!(
            "Failed to find session token: {}",
            err
        )));
    }

    Ok(key_id as u32)
}

/// Check if kernel keyring is available on this system
///
/// This function tests whether the kernel keyring operations are available.
/// It can be used to determine if keyring-based session token storage is viable.
///
/// # Returns
///
/// Returns `true` if keyring operations are available, `false` otherwise
pub fn is_keyring_available() -> bool {
    #[cfg(target_os = "linux")]
    {
        // Try to read the session keyring using syscall
        let ret = unsafe {
            libc::syscall(
                libc::SYS_keyctl,
                libc::KEYCTL_GET_KEYRING_ID,
                KEY_SPEC_SESSION_KEYRING,
                0,
            )
        };

        ret >= 0
    }

    #[cfg(not(target_os = "linux"))]
    {
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[cfg(target_os = "linux")]
    fn test_keyring_availability() {
        // On Linux, the keyring should be available
        assert!(is_keyring_available());
    }

    #[test]
    #[cfg(not(target_os = "linux"))]
    fn test_keyring_not_available() {
        // On non-Linux, the keyring should not be available
        assert!(!is_keyring_available());
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn test_session_token_roundtrip() {
        // Skip this test in CI environments where keyring might not work
        if std::env::var("SIGIL_CI").is_ok() {
            return;
        }

        // Skip if running in a container without proper keyring support
        if !is_keyring_available() {
            return;
        }

        let test_token = "test_token_value_12345678";

        // Add the token
        let key_id = match add_session_token(test_token) {
            Ok(id) => id,
            Err(e) => {
                // Keyring operations might fail in some environments (e.g., containers)
                eprintln!("Skipping test: keyring add failed: {}", e);
                return;
            }
        };

        assert!(key_id > 0);

        // Read the token back
        let read_token = match read_session_token() {
            Ok(token) => token,
            Err(e) => {
                // Clean up the key we added
                let _ = remove_session_token();
                panic!("Failed to read session token: {}", e);
            }
        };

        assert_eq!(read_token, test_token);

        // Remove the token
        remove_session_token().unwrap();

        // Verify it's gone
        assert!(read_session_token().is_err());
    }

    #[test]
    #[cfg(not(target_os = "linux"))]
    fn test_keyring_errors_on_non_linux() {
        let test_token = "test_token";

        assert!(add_session_token(test_token).is_err());
        assert!(read_session_token().is_err());
        assert!(remove_session_token().is_err());
    }
}
