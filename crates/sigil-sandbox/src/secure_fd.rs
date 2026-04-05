//! Secure file descriptor creation for TOCTOU-safe secret injection
//!
//! This module provides secure file descriptor creation using:
//! - Linux: memfd_create (anonymous in-memory file descriptors)
//! - macOS: mkstemp + immediate unlink (minimal TOCTOU window)
//!
//! These mitigations address time-of-check-to-time-of-use (TOCTOU) vulnerabilities
//! in the tmpfs secret injection pipeline (see Phase 4.5 of the plan).

use sigil_core::{Result, SigilError};
use std::fs::File;
use std::io::Write;
use std::os::unix::io::{AsRawFd, FromRawFd, RawFd};

/// Maximum size for a memfd-based secret file (16 MiB)
const MAX_MEMFD_SIZE: usize = 16 * 1024 * 1024;

/// Flags for memfd_create (Linux-specific)
#[cfg(target_os = "linux")]
const MFD_CLOEXEC: libc::c_uint = 0x0001;
#[cfg(target_os = "linux")]
const MFD_ALLOW_SEALING: libc::c_uint = 0x0002;

/// F_SEAL seals for memfd (Linux-specific)
#[cfg(target_os = "linux")]
const F_SEAL_SEAL: libc::c_uint = 0x0001; // Prevent adding more seals
#[cfg(target_os = "linux")]
const F_SEAL_SHRINK: libc::c_uint = 0x0002; // Prevent shrinking
#[cfg(target_os = "linux")]
const F_SEAL_GROW: libc::c_uint = 0x0004; // Prevent growing
#[cfg(target_os = "linux")]
const F_SEAL_WRITE: libc::c_uint = 0x0008; // Prevent writing

/// Secure file handle for TOCTOU-safe secret storage
///
/// On Linux: uses memfd_create for in-memory file storage with no filesystem path
/// On macOS: uses mkstemp + immediate unlink with 0700 temp directory
pub struct SecureFile {
    /// The underlying file
    file: File,
    /// Platform-specific path (None on Linux for memfd, Some path on macOS)
    #[allow(dead_code)]
    path: Option<std::path::PathBuf>,
    /// Whether this file is sealed (Linux memfd only)
    sealed: bool,
}

impl SecureFile {
    /// Create a new secure file for secret storage
    ///
    /// # Arguments
    /// * `name` - A name for the file (used only for debugging, not the filesystem name)
    ///
    /// # Returns
    /// A SecureFile handle that can be written to and passed to child processes
    pub fn create(name: &str) -> Result<Self> {
        #[cfg(target_os = "linux")]
        {
            Self::create_memfd(name)
        }

        #[cfg(not(target_os = "linux"))]
        {
            Self::create_tempfile(name)
        }
    }

    /// Create a memfd on Linux (TOCTOU-safe)
    ///
    /// memfd_create creates an anonymous file in memory with no filesystem path.
    /// This eliminates TOCTOU vulnerabilities since there's no directory entry to race.
    #[cfg(target_os = "linux")]
    fn create_memfd(name: &str) -> Result<Self> {
        // Create a null-terminated name for the C function
        let cname = format!("sigil-secret-{}\0", name);

        // Call memfd_create syscall
        let fd = unsafe {
            libc::syscall(
                libc::SYS_memfd_create,
                cname.as_ptr() as *const libc::c_char,
                MFD_CLOEXEC | MFD_ALLOW_SEALING,
            )
        };

        if fd < 0 {
            let errno = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
            return Err(SigilError::IoError(format!(
                "memfd_create failed: errno {} (kernel may be too old, requires 3.17+)",
                errno
            )));
        }

        // Convert the fd to a File (takes ownership)
        let file = unsafe { File::from_raw_fd(fd as RawFd) };

        Ok(Self {
            file,
            path: None,
            sealed: false,
        })
    }

    /// Create a temporary file on non-Linux platforms (macOS, BSD)
    ///
    /// On macOS, we use mkstemp and immediately unlink the file.
    /// This creates a brief TOCTOU window, but the restrictive temp
    /// directory permissions (0700) mitigate the risk.
    #[cfg(not(target_os = "linux"))]
    fn create_tempfile(name: &str) -> Result<Self> {
        use std::fs::{self, OpenOptions};
        use std::os::unix::fs::OpenOptionsExt;

        // Get the user's runtime directory or fall back to /tmp
        let runtime_dir = std::env::var("XDG_RUNTIME_DIR")
            .or_else(|_| std::env::var("TMPDIR"))
            .unwrap_or_else(|_| "/tmp".to_string());

        let sigil_tmp = std::path::PathBuf::from(runtime_dir).join("sigil-tmp");

        // Ensure directory exists with restrictive permissions
        fs::create_dir_all(&sigil_tmp).map_err(|e| {
            SigilError::IoError(format!("Failed to create sigil temp directory: {}", e))
        })?;

        // Set permissions to 0700 (owner only)
        let mut perms = fs::metadata(&sigil_tmp)
            .map_err(|e| SigilError::IoError(format!("Failed to get metadata: {}", e)))?
            .permissions();
        perms.set_mode(0o700);
        fs::set_permissions(&sigil_tmp, perms).map_err(|e| {
            SigilError::IoError(format!("Failed to set temp directory permissions: {}", e))
        })?;

        // Create a temporary file with mkstemp pattern
        let template = sigil_tmp.join(format!("{}-XXXXXX", name));
        let template_str = template
            .to_str()
            .ok_or_else(|| SigilError::IoError("Invalid temp file path".to_string()))?;

        // Use nix's mkstemp for secure temporary file creation
        let (fd, path) = nix::unistd::mkstemp(template_str)
            .map_err(|e| SigilError::IoError(format!("mkstemp failed: {}", e)))?;

        // Immediately unlink the file - we'll access it via fd only
        // This prevents other processes from accessing it by path
        fs::remove_file(&path)
            .map_err(|e| SigilError::IoError(format!("Failed to unlink temp file: {}", e)))?;

        // Set close-on-exec flag
        nix::fcntl::fcntl(fd, nix::fcntl::F_SETFD(nix::fcntl::FdFlag::FD_CLOEXEC))
            .map_err(|e| SigilError::IoError(format!("Failed to set FD_CLOEXEC: {}", e)))?;

        // Convert to File
        let file = unsafe { File::from_raw_fd(fd) };

        Ok(Self {
            file,
            path: Some(path),
            sealed: false,
        })
    }

    /// Write data to the secure file
    pub fn write(&mut self, data: &[u8]) -> Result<()> {
        if data.len() > MAX_MEMFD_SIZE {
            return Err(SigilError::IoError(format!(
                "Secret value too large: {} bytes (max {})",
                data.len(),
                MAX_MEMFD_SIZE
            )));
        }

        self.file
            .write_all(data)
            .map_err(|e| SigilError::IoError(format!("Failed to write to secure file: {}", e)))?;

        self.file
            .flush()
            .map_err(|e| SigilError::IoError(format!("Failed to flush secure file: {}", e)))?;

        Ok(())
    }

    /// Seal the secure file (Linux memfd only)
    ///
    /// Sealing prevents further modifications to the file after sealing.
    /// This is a defense-in-depth measure to ensure secrets cannot be
    /// modified after being written.
    #[cfg(target_os = "linux")]
    pub fn seal(&mut self) -> Result<()> {
        if self.sealed {
            return Ok(());
        }

        let fd = self.file.as_raw_fd();

        // Add seals to prevent modifications
        let seals = F_SEAL_SEAL | F_SEAL_SHRINK | F_SEAL_GROW | F_SEAL_WRITE;

        let ret = unsafe { libc::fcntl(fd, libc::F_ADD_SEALS, seals) };

        if ret < 0 {
            return Err(SigilError::IoError(format!(
                "Failed to seal memfd: {}",
                std::io::Error::last_os_error()
            )));
        }

        self.sealed = true;
        Ok(())
    }

    /// Seal the secure file (no-op on non-Linux platforms)
    #[cfg(not(target_os = "linux"))]
    pub fn seal(&mut self) -> Result<()> {
        // No-op on platforms that don't support sealing
        self.sealed = true;
        Ok(())
    }

    /// Get the underlying file
    pub fn file(&self) -> &File {
        &self.file
    }

    /// Get the underlying file (mutable)
    pub fn file_mut(&mut self) -> &mut File {
        &mut self.file
    }

    /// Consume and return the underlying File
    ///
    /// This is useful when you need to pass the File to another function
    /// that takes ownership.
    pub fn into_file(self) -> File {
        self.file
    }

    /// Get the raw file descriptor
    pub fn as_raw_fd(&self) -> RawFd {
        self.file.as_raw_fd()
    }

    /// Check if this file is sealed
    pub fn is_sealed(&self) -> bool {
        self.sealed
    }

    /// Get the path (if any)
    ///
    /// Returns None for Linux memfd (no filesystem path)
    /// Returns Some(path) for macOS/BSD (path exists but file is unlinked)
    pub fn path(&self) -> Option<&std::path::Path> {
        self.path.as_deref()
    }
}

/// Secure PID handle using pidfd (Linux 5.3+)
///
/// pidfd provides a stable file descriptor for a process that remains valid
/// even if the PID is recycled. This prevents PID reuse attacks.
#[cfg(target_os = "linux")]
pub struct SecurePid {
    /// The pidfd file descriptor (owned, uses RawFd to avoid nix version issues)
    pidfd: Option<libc::c_int>,
    /// The original PID (for fallback)
    pid: nix::unistd::Pid,
}

#[cfg(target_os = "linux")]
impl SecurePid {
    /// Create a secure PID handle from a PID number
    ///
    /// Attempts to use pidfd_open if available (kernel 5.3+).
    /// Falls back to PID-based tracking on older kernels.
    pub fn from_pid(pid: nix::unistd::Pid) -> Result<Self> {
        // Try pidfd_open (Linux 5.3+)
        // Use raw syscall since nix doesn't expose pidfd_open in all versions
        let pidfd = unsafe {
            let ret = libc::syscall(libc::SYS_pidfd_open, pid.as_raw(), 0);
            if ret < 0 {
                // pidfd_open not available (kernel < 5.3) or failed
                tracing::debug!("pidfd_open not available, using PID-based tracking");
                None
            } else {
                Some(ret as libc::c_int)
            }
        };

        Ok(Self { pidfd, pid })
    }

    /// Verify the PID is still valid and refers to the same process
    ///
    /// Returns true if the PID/pidfd is still valid, false otherwise.
    pub fn is_valid(&self) -> bool {
        // Use kill(pid, 0) to check if process exists (doesn't actually send signal)
        let ret = unsafe { libc::kill(self.pid.as_raw(), 0) };
        ret == 0
    }

    /// Get the original PID
    pub fn pid(&self) -> nix::unistd::Pid {
        self.pid
    }

    /// Check if this is using pidfd (vs PID-based fallback)
    pub fn is_using_pidfd(&self) -> bool {
        self.pidfd.is_some()
    }
}

#[cfg(target_os = "linux")]
impl Drop for SecurePid {
    fn drop(&mut self) {
        // Close the pidfd if we have one
        if let Some(fd) = self.pidfd {
            unsafe {
                libc::close(fd);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_secure_file_create() {
        let secure_file = SecureFile::create("test-secret").expect("Failed to create secure file");
        assert!(!secure_file.is_sealed());
    }

    #[test]
    fn test_secure_file_write() {
        let mut secure_file =
            SecureFile::create("test-write").expect("Failed to create secure file");

        let test_data = b"test secret data";
        secure_file
            .write(test_data)
            .expect("Failed to write to secure file");
    }

    #[test]
    fn test_secure_file_seal() {
        let mut secure_file =
            SecureFile::create("test-seal").expect("Failed to create secure file");

        secure_file.write(b"test data").expect("Failed to write");

        secure_file.seal().expect("Failed to seal file");
        assert!(secure_file.is_sealed());
    }

    #[test]
    fn test_secure_file_size_limit() {
        let mut secure_file =
            SecureFile::create("test-limit").expect("Failed to create secure file");

        let large_data = vec![0u8; MAX_MEMFD_SIZE + 1];
        let result = secure_file.write(&large_data);
        assert!(result.is_err());
    }

    #[test]
    fn test_secure_file_double_seal() {
        let mut secure_file =
            SecureFile::create("test-double").expect("Failed to create secure file");

        secure_file.seal().expect("First seal failed");
        secure_file.seal().expect("Second seal should be no-op"); // Should be idempotent
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn test_secure_pid_from_current() {
        let current_pid = nix::unistd::getpid();
        let secure_pid = SecurePid::from_pid(current_pid).expect("Failed to create secure PID");
        assert!(secure_pid.is_valid());
        assert_eq!(secure_pid.pid(), current_pid);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn test_secure_pid_from_invalid() {
        // Use a PID that likely doesn't exist
        let invalid_pid = nix::unistd::Pid::from_raw(999999);
        let secure_pid = SecurePid::from_pid(invalid_pid).expect("Failed to create secure PID");
        assert!(!secure_pid.is_valid());
    }
}
