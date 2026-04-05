//! Audit logger for SIGIL daemon
//!
//! Provides append-only, hash-chained logging of all daemon operations.

use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::sync::Mutex;

use sigil_core::{Result, SigilError};

/// Audit log configuration
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct AuditConfig {
    /// Maximum size before rotation (e.g., 50MB)
    pub max_size: usize,
    /// Maximum age before pruning (e.g., 90 days)
    pub max_age: Duration,
    /// Number of rotated logs to keep
    pub keep: usize,
    /// Whether to compress rotated logs
    pub compress: bool,
}

impl Default for AuditConfig {
    fn default() -> Self {
        Self {
            max_size: 50 * 1024 * 1024, // 50MB
            max_age: Duration::days(90),
            keep: 5,
            compress: true,
        }
    }
}

/// Audit log statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
#[allow(dead_code)]
pub struct AuditStats {
    /// Path to the log file
    pub log_path: PathBuf,
    /// File size in bytes
    pub size_bytes: u64,
    /// Number of entries
    pub entry_count: usize,
    /// Date range of entries
    pub date_range: Option<(DateTime<Utc>, DateTime<Utc>)>,
    /// Current hash chain status
    pub chain_valid: bool,
    /// List of rotated log files
    pub rotated_logs: Vec<PathBuf>,
}

/// Audit log entry
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
#[serde(rename_all = "snake_case")]
pub enum AuditEntry {
    /// Session started
    SessionStart {
        timestamp: DateTime<Utc>,
        previous_hash: Option<String>,
    },
    /// Session ended
    SessionEnd {
        timestamp: DateTime<Utc>,
        previous_hash: String,
    },
    /// Secret was resolved
    SecretResolve {
        timestamp: DateTime<Utc>,
        previous_hash: String,
        path: String,
        fingerprint: String,
        pid: u32,
        uid: u32,
    },
    /// Secret was added
    SecretAdd {
        timestamp: DateTime<Utc>,
        previous_hash: String,
        path: String,
        fingerprint: String,
    },
    /// Secret was deleted
    SecretDelete {
        timestamp: DateTime<Utc>,
        previous_hash: String,
        path: String,
    },
    /// Secret was edited
    SecretEdit {
        timestamp: DateTime<Utc>,
        previous_hash: String,
        path: String,
        old_fingerprint: String,
        new_fingerprint: String,
    },
    /// Authentication failed
    AuthFailure {
        timestamp: DateTime<Utc>,
        previous_hash: String,
        reason: String,
        pid: u32,
        uid: u32,
    },
    /// Breach detected
    BreachDetected {
        timestamp: DateTime<Utc>,
        previous_hash: String,
        severity: String,
        description: String,
    },
    /// Log rotation
    Rotation {
        timestamp: DateTime<Utc>,
        previous_hash: String,
        previous_file: String,
        previous_file_hash: String,
    },
    /// FUSE filesystem read
    FuseRead {
        timestamp: DateTime<Utc>,
        previous_hash: String,
        path: String,
        pid: u32,
        uid: u32,
        gid: u32,
    },
    /// Canary file access (potential breach)
    CanaryAccess {
        timestamp: DateTime<Utc>,
        previous_hash: String,
        path: String,
        pid: u32,
        uid: u32,
    },
    /// Emergency lockdown activated
    Lockdown {
        timestamp: DateTime<Utc>,
        previous_hash: String,
        reason: String,
    },
    /// Lockdown lifted (unlock)
    Unlock {
        timestamp: DateTime<Utc>,
        previous_hash: String,
    },
    /// Secret access granted via request workflow
    SecretAccessGrant {
        timestamp: DateTime<Utc>,
        previous_hash: String,
        secret_path: String,
        reason: String,
        expires_at: Option<DateTime<Utc>>,
    },
    /// Secret access denied via request workflow
    SecretAccessDenied {
        timestamp: DateTime<Utc>,
        previous_hash: String,
        secret_path: String,
        reason: String,
        denial_reason: Option<String>,
    },
    /// Command executed with signature-based auto-injection
    CommandExecuted {
        timestamp: DateTime<Utc>,
        previous_hash: String,
        command: String,
        exit_code: i32,
        duration_ms: u64,
        matched_signatures: Vec<String>,
        secrets_scrubbed: usize,
    },
    /// Sealed operation executed
    OperationExecuted {
        timestamp: DateTime<Utc>,
        previous_hash: String,
        operation_id: String,
        command: String,
        exit_code: i32,
        duration_ms: u64,
        secret_paths: Vec<String>,
        output_size: usize,
    },
}

impl AuditEntry {
    /// Get the timestamp of the entry
    #[allow(dead_code)]
    pub fn timestamp(&self) -> DateTime<Utc> {
        match self {
            AuditEntry::SessionStart { timestamp, .. } => *timestamp,
            AuditEntry::SessionEnd { timestamp, .. } => *timestamp,
            AuditEntry::SecretResolve { timestamp, .. } => *timestamp,
            AuditEntry::SecretAdd { timestamp, .. } => *timestamp,
            AuditEntry::SecretDelete { timestamp, .. } => *timestamp,
            AuditEntry::SecretEdit { timestamp, .. } => *timestamp,
            AuditEntry::AuthFailure { timestamp, .. } => *timestamp,
            AuditEntry::BreachDetected { timestamp, .. } => *timestamp,
            AuditEntry::Rotation { timestamp, .. } => *timestamp,
            AuditEntry::FuseRead { timestamp, .. } => *timestamp,
            AuditEntry::CanaryAccess { timestamp, .. } => *timestamp,
            AuditEntry::Lockdown { timestamp, .. } => *timestamp,
            AuditEntry::Unlock { timestamp, .. } => *timestamp,
            AuditEntry::SecretAccessGrant { timestamp, .. } => *timestamp,
            AuditEntry::SecretAccessDenied { timestamp, .. } => *timestamp,
            AuditEntry::CommandExecuted { timestamp, .. } => *timestamp,
            AuditEntry::OperationExecuted { timestamp, .. } => *timestamp,
        }
    }

    /// Get the previous hash of the entry
    pub fn previous_hash(&self) -> Option<&str> {
        match self {
            AuditEntry::SessionStart { previous_hash, .. } => previous_hash.as_deref(),
            AuditEntry::SessionEnd { previous_hash, .. } => Some(previous_hash),
            AuditEntry::SecretResolve { previous_hash, .. } => Some(previous_hash),
            AuditEntry::SecretAdd { previous_hash, .. } => Some(previous_hash),
            AuditEntry::SecretDelete { previous_hash, .. } => Some(previous_hash),
            AuditEntry::SecretEdit { previous_hash, .. } => Some(previous_hash),
            AuditEntry::AuthFailure { previous_hash, .. } => Some(previous_hash),
            AuditEntry::BreachDetected { previous_hash, .. } => Some(previous_hash),
            AuditEntry::Rotation { previous_hash, .. } => Some(previous_hash),
            AuditEntry::FuseRead { previous_hash, .. } => Some(previous_hash),
            AuditEntry::CanaryAccess { previous_hash, .. } => Some(previous_hash),
            AuditEntry::Lockdown { previous_hash, .. } => Some(previous_hash),
            AuditEntry::Unlock { previous_hash, .. } => Some(previous_hash),
            AuditEntry::SecretAccessGrant { previous_hash, .. } => Some(previous_hash),
            AuditEntry::SecretAccessDenied { previous_hash, .. } => Some(previous_hash),
            AuditEntry::CommandExecuted { previous_hash, .. } => Some(previous_hash),
            AuditEntry::OperationExecuted { previous_hash, .. } => Some(previous_hash),
        }
    }

    /// Compute the hash of this entry
    pub fn compute_hash(&self, previous_hash: &str) -> String {
        let json = serde_json::to_string(self).expect("Failed to serialize audit entry");
        let input = format!("{}{}", previous_hash, json);
        let hash = Sha256::digest(input.as_bytes());
        hex::encode(hash)
    }
}

/// Audit logger
pub struct AuditLogger {
    log_path: PathBuf,
    current_hash: Arc<Mutex<Option<String>>>,
}

impl AuditLogger {
    /// Create a new audit logger
    pub fn new(log_path: PathBuf) -> Result<Self> {
        // Ensure parent directory exists
        if let Some(parent) = log_path.parent() {
            std::fs::create_dir_all(parent)?;
        }

        // Initialize hash from existing log or create new
        let current_hash = if log_path.exists() {
            // Read last entry to get current hash
            Self::read_last_hash(&log_path)?
        } else {
            None
        };

        Ok(Self {
            log_path,
            current_hash: Arc::new(Mutex::new(current_hash)),
        })
    }

    /// Read the hash of the last entry in the log
    fn read_last_hash(path: &PathBuf) -> Result<Option<String>> {
        let content = std::fs::read_to_string(path)?;
        let lines: Vec<&str> = content.lines().collect();

        if let Some(last_line) = lines.last() {
            if let Ok(entry) = serde_json::from_str::<AuditEntry>(last_line) {
                let hash = entry.compute_hash(entry.previous_hash().unwrap_or(""));
                return Ok(Some(hash));
            }
        }

        Ok(None)
    }

    /// Write an audit entry
    async fn write_entry(&self, entry: AuditEntry) -> Result<()> {
        // Get current hash
        let mut hash_guard = self.current_hash.lock().await;
        let previous_hash = hash_guard.as_deref().unwrap_or("");

        // Compute new hash
        let new_hash = entry.compute_hash(previous_hash);

        // Serialize entry
        let json = serde_json::to_string(&entry)
            .map_err(|e| SigilError::SerializationError(e.to_string()))?;

        // Append to log file
        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.log_path)
            .map_err(|e| SigilError::IoError(e.to_string()))?;

        writeln!(file, "{}", json).map_err(|e| SigilError::IoError(e.to_string()))?;

        // Try to set append-only flag (best-effort, requires root)
        self.set_append_only_flag(&file).await;

        // Update current hash
        *hash_guard = Some(new_hash);

        Ok(())
    }

    /// Log session start
    pub async fn log_session_start(&self) {
        let entry = AuditEntry::SessionStart {
            timestamp: Utc::now(),
            previous_hash: self.current_hash.lock().await.clone(),
        };
        let _ = self.write_entry(entry).await;
    }

    /// Log session end
    pub async fn log_session_end(&self) {
        let previous_hash = self.current_hash.lock().await.clone().unwrap_or_default();
        let entry = AuditEntry::SessionEnd {
            timestamp: Utc::now(),
            previous_hash,
        };
        let _ = self.write_entry(entry).await;
    }

    /// Log secret resolve
    #[allow(dead_code)]
    pub async fn log_secret_resolve(&self, path: String, fingerprint: String, pid: u32, uid: u32) {
        let previous_hash = self.current_hash.lock().await.clone().unwrap_or_default();
        let entry = AuditEntry::SecretResolve {
            timestamp: Utc::now(),
            previous_hash,
            path,
            fingerprint,
            pid,
            uid,
        };
        let _ = self.write_entry(entry).await;
    }

    /// Log secret add
    #[allow(dead_code)]
    pub async fn log_secret_add(&self, path: String, fingerprint: String) {
        let previous_hash = self.current_hash.lock().await.clone().unwrap_or_default();
        let entry = AuditEntry::SecretAdd {
            timestamp: Utc::now(),
            previous_hash,
            path,
            fingerprint,
        };
        let _ = self.write_entry(entry).await;
    }

    /// Log secret delete
    #[allow(dead_code)]
    pub async fn log_secret_delete(&self, path: String) {
        let previous_hash = self.current_hash.lock().await.clone().unwrap_or_default();
        let entry = AuditEntry::SecretDelete {
            timestamp: Utc::now(),
            previous_hash,
            path,
        };
        let _ = self.write_entry(entry).await;
    }

    /// Log secret edit
    #[allow(dead_code)]
    pub async fn log_secret_edit(
        &self,
        path: String,
        old_fingerprint: String,
        new_fingerprint: String,
    ) {
        let previous_hash = self.current_hash.lock().await.clone().unwrap_or_default();
        let entry = AuditEntry::SecretEdit {
            timestamp: Utc::now(),
            previous_hash,
            path,
            old_fingerprint,
            new_fingerprint,
        };
        let _ = self.write_entry(entry).await;
    }

    /// Log authentication failure
    #[allow(dead_code)]
    pub async fn log_auth_failure(&self, reason: String, pid: u32, uid: u32) {
        let previous_hash = self.current_hash.lock().await.clone().unwrap_or_default();
        let entry = AuditEntry::AuthFailure {
            timestamp: Utc::now(),
            previous_hash,
            reason,
            pid,
            uid,
        };
        let _ = self.write_entry(entry).await;
    }

    /// Log breach detected
    #[allow(dead_code)]
    pub async fn log_breach_detected(&self, severity: String, description: String) {
        let previous_hash = self.current_hash.lock().await.clone().unwrap_or_default();
        let entry = AuditEntry::BreachDetected {
            timestamp: Utc::now(),
            previous_hash,
            severity,
            description,
        };
        let _ = self.write_entry(entry).await;
    }

    /// Log FUSE filesystem read
    #[allow(dead_code)]
    pub async fn log_fuse_read(&self, path: String, pid: u32, uid: u32, gid: u32) {
        let previous_hash = self.current_hash.lock().await.clone().unwrap_or_default();
        let entry = AuditEntry::FuseRead {
            timestamp: Utc::now(),
            previous_hash,
            path,
            pid,
            uid,
            gid,
        };
        let _ = self.write_entry(entry).await;
    }

    /// Log canary file access (potential breach)
    #[allow(dead_code)]
    pub async fn log_canary_access(&self, path: String, pid: u32, uid: u32) {
        let previous_hash = self.current_hash.lock().await.clone().unwrap_or_default();
        let entry = AuditEntry::CanaryAccess {
            timestamp: Utc::now(),
            previous_hash,
            path,
            pid,
            uid,
        };
        let _ = self.write_entry(entry).await;
    }

    /// Log emergency lockdown activation
    #[allow(dead_code)]
    pub async fn log_lockdown(&self) -> Result<()> {
        let previous_hash = self.current_hash.lock().await.clone().unwrap_or_default();
        let entry = AuditEntry::Lockdown {
            timestamp: Utc::now(),
            previous_hash,
            reason: "Manual lockdown request".to_string(),
        };
        self.write_entry(entry).await?;
        Ok(())
    }

    /// Log lockdown lifted (unlock)
    #[allow(dead_code)]
    pub async fn log_unlock(&self) -> Result<()> {
        let previous_hash = self.current_hash.lock().await.clone().unwrap_or_default();
        let entry = AuditEntry::Unlock {
            timestamp: Utc::now(),
            previous_hash,
        };
        self.write_entry(entry).await?;
        Ok(())
    }

    /// Log secret access granted via request workflow
    #[allow(dead_code)]
    pub async fn log_secret_access_grant(
        &self,
        secret_path: String,
        reason: String,
        expires_at: Option<chrono::DateTime<chrono::Utc>>,
    ) -> Result<()> {
        let previous_hash = self.current_hash.lock().await.clone().unwrap_or_default();
        let entry = AuditEntry::SecretAccessGrant {
            timestamp: Utc::now(),
            previous_hash,
            secret_path,
            reason,
            expires_at,
        };
        self.write_entry(entry).await?;
        Ok(())
    }

    /// Log secret access denied via request workflow
    #[allow(dead_code)]
    pub async fn log_secret_access_denied(
        &self,
        secret_path: String,
        reason: String,
        denial_reason: Option<String>,
    ) -> Result<()> {
        let previous_hash = self.current_hash.lock().await.clone().unwrap_or_default();
        let entry = AuditEntry::SecretAccessDenied {
            timestamp: Utc::now(),
            previous_hash,
            secret_path,
            reason,
            denial_reason,
        };
        self.write_entry(entry).await?;
        Ok(())
    }

    /// Log breach report generated during lockdown
    #[allow(dead_code)]
    pub async fn log_breach_report(&self, report: &str) -> Result<()> {
        let previous_hash = self.current_hash.lock().await.clone().unwrap_or_default();
        let entry = AuditEntry::BreachDetected {
            timestamp: Utc::now(),
            previous_hash,
            severity: "critical".to_string(),
            description: format!("Lockdown breach report: {}", report),
        };
        self.write_entry(entry).await?;
        Ok(())
    }

    /// Log a command execution with signature-based auto-injection
    pub async fn log_command_execution(
        &self,
        command: String,
        exit_code: i32,
        duration_ms: u64,
        matched_signatures: Vec<String>,
        secrets_scrubbed: usize,
    ) {
        let previous_hash = self.current_hash.lock().await.clone().unwrap_or_default();
        let entry = AuditEntry::CommandExecuted {
            timestamp: Utc::now(),
            previous_hash,
            command,
            exit_code,
            duration_ms,
            matched_signatures,
            secrets_scrubbed,
        };
        // Don't fail on audit log errors for command execution
        let _ = self.write_entry(entry).await;
    }

    /// Log a sealed operation execution
    pub async fn log_operation_execution(
        &self,
        operation_id: String,
        command: String,
        exit_code: i32,
        duration_ms: u64,
        secret_paths: Vec<String>,
        output_size: usize,
    ) {
        let previous_hash = self.current_hash.lock().await.clone().unwrap_or_default();
        let entry = AuditEntry::OperationExecuted {
            timestamp: Utc::now(),
            previous_hash,
            operation_id,
            command,
            exit_code,
            duration_ms,
            secret_paths,
            output_size,
        };
        // Don't fail on audit log errors for operation execution
        let _ = self.write_entry(entry).await;
    }

    /// Get the current hash
    #[allow(dead_code)]
    pub async fn current_hash(&self) -> Option<String> {
        self.current_hash.lock().await.clone()
    }

    /// Get the log path
    #[allow(dead_code)]
    pub fn log_path(&self) -> &Path {
        &self.log_path
    }

    /// Check if rotation is needed based on file size
    #[allow(dead_code)]
    pub fn needs_rotation(&self, config: &AuditConfig) -> bool {
        if let Ok(metadata) = std::fs::metadata(&self.log_path) {
            metadata.len() as usize > config.max_size
        } else {
            false
        }
    }

    /// Rotate the audit log
    ///
    /// This method:
    /// 1. Removes append-only flag if set (best-effort)
    /// 2. Renames current log to .1
    /// 3. Records rotation event with hash bridge
    /// 4. Creates new audit log
    /// 5. Optionally compresses old log
    #[allow(dead_code)]
    pub async fn rotate(&self, config: &AuditConfig) -> Result<()> {
        if !self.log_path.exists() {
            return Ok(());
        }

        // Read the current hash before rotation
        let current_hash = self.current_hash.lock().await.clone().unwrap_or_default();

        // Compute hash of the entire file for verification
        let file_hash = self.compute_file_hash(&self.log_path)?;

        // Try to remove append-only flag before renaming (best-effort)
        self.clear_append_only_flag().await;

        // Rotate existing logs (.1 -> .2, .2 -> .3, etc.)
        self.rotate_existing_files(config.keep)?;

        // Rename current log to .1
        let rotated_path = self.log_path.with_extension("jsonl.1");
        std::fs::rename(&self.log_path, &rotated_path)
            .map_err(|e| SigilError::IoError(format!("Failed to rotate log: {}", e)))?;

        // Compress if configured
        if config.compress {
            if let Err(e) = self.compress_log(&rotated_path) {
                tracing::warn!("Failed to compress rotated log: {}", e);
            }
        }

        // Write rotation entry as first entry in new log
        let rotation_entry = AuditEntry::Rotation {
            timestamp: Utc::now(),
            previous_hash: current_hash.clone(),
            previous_file: rotated_path.display().to_string(),
            previous_file_hash: file_hash,
        };

        // Write the rotation entry to the new log
        let json = serde_json::to_string(&rotation_entry)
            .map_err(|e| SigilError::SerializationError(e.to_string()))?;

        let mut file = File::create(&self.log_path)
            .map_err(|e| SigilError::IoError(format!("Failed to create new log: {}", e)))?;

        writeln!(file, "{}", json)
            .map_err(|e| SigilError::IoError(format!("Failed to write rotation entry: {}", e)))?;

        // Update current hash
        let new_hash = rotation_entry.compute_hash(&current_hash);
        *self.current_hash.lock().await = Some(new_hash);

        tracing::info!("Audit log rotated: {}", self.log_path.display());

        Ok(())
    }

    /// Rotate existing log files (.1 -> .2, .2 -> .3, etc.)
    #[allow(dead_code)]
    fn rotate_existing_files(&self, keep: usize) -> Result<()> {
        for i in (1..keep).rev() {
            let current = self.log_path.with_extension(format!("jsonl.{}", i));
            let next = self.log_path.with_extension(format!("jsonl.{}", i + 1));

            // Also check for compressed versions
            let current_gz = self.log_path.with_extension(format!("jsonl.{}.gz", i));
            let next_gz = self.log_path.with_extension(format!("jsonl.{}.gz", i + 1));

            if current_gz.exists() {
                std::fs::rename(&current_gz, &next_gz)
                    .map_err(|e| SigilError::IoError(format!("Failed to rotate log: {}", e)))?;
            } else if current.exists() {
                std::fs::rename(&current, &next)
                    .map_err(|e| SigilError::IoError(format!("Failed to rotate log: {}", e)))?;
            }
        }

        Ok(())
    }

    /// Compress a log file using gzip
    #[allow(dead_code)]
    fn compress_log(&self, path: &Path) -> Result<()> {
        let compressed_path = path.with_extension(format!(
            "{}.gz",
            path.extension().unwrap_or_default().to_str().unwrap()
        ));

        let input = std::fs::read(path).map_err(|e| {
            SigilError::IoError(format!("Failed to read log for compression: {}", e))
        })?;

        let compressed = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        let mut encoder = compressed;
        encoder
            .write_all(&input)
            .map_err(|e| SigilError::IoError(format!("Failed to compress log: {}", e)))?;

        let compressed_bytes = encoder
            .finish()
            .map_err(|e| SigilError::IoError(format!("Failed to finish compression: {}", e)))?;

        std::fs::write(&compressed_path, compressed_bytes)
            .map_err(|e| SigilError::IoError(format!("Failed to write compressed log: {}", e)))?;

        // Remove uncompressed file
        std::fs::remove_file(path).map_err(|e| {
            SigilError::IoError(format!("Failed to remove uncompressed log: {}", e))
        })?;

        Ok(())
    }

    /// Compute the hash of an entire file
    #[allow(dead_code)]
    fn compute_file_hash(&self, path: &Path) -> Result<String> {
        let content = std::fs::read(path)
            .map_err(|e| SigilError::IoError(format!("Failed to read file for hashing: {}", e)))?;

        let hash = Sha256::digest(&content);
        Ok(hex::encode(hash))
    }

    /// Set the append-only flag on the audit log file (best-effort, requires root)
    ///
    /// On Linux: uses FS_IOC_SETFLAGS ioctl with FS_APPEND_FL
    /// On macOS: uses chflags system call with UF_APPEND
    /// Falls back gracefully if the operation fails (requires root privileges)
    async fn set_append_only_flag(&self, file: &File) {
        #[cfg(target_os = "linux")]
        {
            use std::os::unix::io::AsRawFd;

            const FS_APPEND_FL: u32 = 0x00000020; // Append-only flag
            const FS_IOC_SETFLAGS: u64 = 0x40046602; // ioctl code for setflags

            let fd = file.as_raw_fd();

            unsafe {
                let mut flags: u32 = FS_APPEND_FL;
                let result = libc::ioctl(fd as libc::c_int, FS_IOC_SETFLAGS, &mut flags);

                if result != 0 {
                    let err = std::io::Error::last_os_error();
                    // EPERM (Operation not permitted) is expected if not running as root
                    // Other errors might indicate actual problems
                    if err.raw_os_error() == Some(libc::EPERM) {
                        tracing::warn!(
                            "Cannot set append-only flag on audit log (requires root). \
                             Audit log will not be protected at filesystem level."
                        );
                    } else {
                        tracing::warn!(
                            "Failed to set append-only flag on audit log: {}. \
                             Run with sudo to enable filesystem-level protection.",
                            err
                        );
                    }
                } else {
                    tracing::debug!("Append-only flag set on audit log");
                }
            }
        }

        #[cfg(target_os = "macos")]
        {
            use std::os::unix::io::AsRawFd;

            const UF_APPEND: u32 = 0x00000004; // User append-only flag (immutable)

            let fd = file.as_raw_fd();

            unsafe {
                let result = libc::fchflags(fd as libc::c_int, UF_APPEND as libc::c_int);

                if result != 0 {
                    let err = std::io::Error::last_os_error();
                    // EPERM is expected if not running as root
                    if err.raw_os_error() == Some(libc::EPERM) {
                        tracing::warn!(
                            "Cannot set append-only flag on audit log (requires root). \
                             Audit log will not be protected at filesystem level."
                        );
                    } else {
                        tracing::warn!(
                            "Failed to set append-only flag on audit log: {}. \
                             Run with sudo to enable filesystem-level protection.",
                            err
                        );
                    }
                } else {
                    tracing::debug!("Append-only flag set on audit log");
                }
            }
        }

        #[cfg(not(any(target_os = "linux", target_os = "macos")))]
        {
            tracing::warn!(
                "Append-only flag not supported on this platform. \
                 Audit log protection relies on file permissions only."
            );
        }
    }

    /// Clear the append-only flag on the audit log file (best-effort, requires root)
    ///
    /// This is called before rotating the log file, since files with append-only
    /// flag cannot be renamed or deleted.
    async fn clear_append_only_flag(&self) {
        #[cfg(target_os = "linux")]
        {
            use std::os::unix::io::AsRawFd;

            const FS_IOC_SETFLAGS: u64 = 0x40046602; // ioctl code for setflags

            // Open the file to get its fd
            if let Ok(file) = File::open(&self.log_path) {
                let fd = file.as_raw_fd();

                unsafe {
                    // Clear all flags (set to 0) to remove append-only
                    let mut flags: u32 = 0;
                    let result = libc::ioctl(fd as libc::c_int, FS_IOC_SETFLAGS, &mut flags);

                    if result != 0 {
                        let err = std::io::Error::last_os_error();
                        tracing::debug!("Failed to clear append-only flag: {} (ignored)", err);
                    } else {
                        tracing::debug!("Append-only flag cleared on audit log");
                    }
                }
            }
        }

        #[cfg(target_os = "macos")]
        {
            use std::os::unix::io::AsRawFd;

            // Open the file to get its fd
            if let Ok(file) = File::open(&self.log_path) {
                let fd = file.as_raw_fd();

                unsafe {
                    // Clear all flags (set to 0) to remove append-only
                    let result = libc::fchflags(fd as libc::c_int, 0);

                    if result != 0 {
                        let err = std::io::Error::last_os_error();
                        tracing::debug!("Failed to clear append-only flag: {} (ignored)", err);
                    } else {
                        tracing::debug!("Append-only flag cleared on audit log");
                    }
                }
            }
        }

        #[cfg(not(any(target_os = "linux", target_os = "macos")))]
        {
            // No-op on unsupported platforms
        }
    }

    /// Verify the hash chain of the current log file
    #[allow(dead_code)]
    pub fn verify_chain(&self) -> Result<bool> {
        if !self.log_path.exists() {
            return Ok(true); // Empty log is valid
        }

        let file = File::open(&self.log_path)
            .map_err(|e| SigilError::IoError(format!("Failed to open log: {}", e)))?;

        let reader = BufReader::new(file);
        let mut lines = reader.lines();

        let mut previous_hash = String::new();
        let mut line_num = 0;

        while let Some(Ok(line)) = lines.next() {
            line_num += 1;

            match serde_json::from_str::<AuditEntry>(&line) {
                Ok(entry) => {
                    let expected_hash = entry.compute_hash(&previous_hash);

                    // Check if the previous_hash field matches
                    if let Some(stored_previous) = entry.previous_hash() {
                        if stored_previous != previous_hash {
                            tracing::error!(
                                "Hash chain broken at line {}: previous_hash mismatch",
                                line_num
                            );
                            return Ok(false);
                        }
                    }

                    // Update previous_hash for next iteration
                    previous_hash = expected_hash;
                }
                Err(e) => {
                    tracing::error!("Failed to parse entry at line {}: {}", line_num, e);
                    return Ok(false);
                }
            }
        }

        Ok(true)
    }

    /// Get statistics about the audit log
    #[allow(dead_code)]
    pub fn stats(&self, _config: &AuditConfig) -> Result<AuditStats> {
        let mut entry_count = 0;
        let mut first_timestamp: Option<DateTime<Utc>> = None;
        let mut last_timestamp: Option<DateTime<Utc>> = None;
        let mut chain_valid = true;
        let mut rotated_logs = Vec::new();

        // Get file size
        let size_bytes = std::fs::metadata(&self.log_path)
            .map(|m| m.len())
            .unwrap_or(0);

        // Read entries
        if self.log_path.exists() {
            let file = File::open(&self.log_path)
                .map_err(|e| SigilError::IoError(format!("Failed to open log: {}", e)))?;

            let reader = BufReader::new(file);

            for line in reader.lines() {
                let line =
                    line.map_err(|e| SigilError::IoError(format!("Failed to read line: {}", e)))?;

                if let Ok(entry) = serde_json::from_str::<AuditEntry>(&line) {
                    entry_count += 1;

                    let timestamp = entry.timestamp();
                    if first_timestamp.is_none() {
                        first_timestamp = Some(timestamp);
                    }
                    last_timestamp = Some(timestamp);
                }
            }

            // Verify chain
            chain_valid = self.verify_chain()?;
        }

        // Find rotated logs
        let log_dir = self.log_path.parent().unwrap_or(Path::new("."));
        let log_name = self
            .log_path
            .file_stem()
            .unwrap_or_default()
            .to_str()
            .unwrap_or("");

        for entry in std::fs::read_dir(log_dir)
            .map_err(|e| SigilError::IoError(format!("Failed to read log directory: {}", e)))?
            .flatten()
        {
            let path = entry.path();
            if let Some(name) = path.file_name() {
                let name_str = name.to_str().unwrap_or("");
                if name_str.starts_with(log_name)
                    && (name_str.ends_with(".gz") || name_str.contains(".jsonl."))
                {
                    rotated_logs.push(path);
                }
            }
        }

        // Sort rotated logs by modification time (newest first)
        rotated_logs.sort_by(|a, b| {
            let a_time = std::fs::metadata(a)
                .and_then(|m| m.modified())
                .unwrap_or(std::time::SystemTime::UNIX_EPOCH);
            let b_time = std::fs::metadata(b)
                .and_then(|m| m.modified())
                .unwrap_or(std::time::SystemTime::UNIX_EPOCH);
            b_time.cmp(&a_time)
        });

        Ok(AuditStats {
            log_path: self.log_path.clone(),
            size_bytes,
            entry_count,
            date_range: first_timestamp.zip(last_timestamp),
            chain_valid,
            rotated_logs,
        })
    }

    /// Prune old log files based on retention policy
    #[allow(dead_code)]
    pub fn prune(&self, config: &AuditConfig) -> Result<usize> {
        let stats = self.stats(config)?;
        let mut pruned = 0;

        // Remove rotated logs that exceed the retention limit
        for (i, log_path) in stats.rotated_logs.iter().enumerate() {
            if i >= config.keep {
                if let Err(e) = std::fs::remove_file(log_path) {
                    tracing::warn!("Failed to remove old log {}: {}", log_path.display(), e);
                } else {
                    pruned += 1;
                    tracing::info!("Pruned old log: {}", log_path.display());
                }
            } else {
                // Check age-based pruning
                if let Ok(metadata) = std::fs::metadata(log_path) {
                    if let Ok(modified) = metadata.modified() {
                        let age = std::time::SystemTime::now()
                            .duration_since(modified)
                            .unwrap_or_default();

                        let age_days = age.as_secs() / 86400;
                        let max_age_days = config.max_age.num_seconds() / 86400;

                        if age_days as i64 > max_age_days {
                            if let Err(e) = std::fs::remove_file(log_path) {
                                tracing::warn!(
                                    "Failed to remove old log {}: {}",
                                    log_path.display(),
                                    e
                                );
                            } else {
                                pruned += 1;
                                tracing::info!("Pruned old log (age): {}", log_path.display());
                            }
                        }
                    }
                }
            }
        }

        Ok(pruned)
    }

    /// Export audit log entries within a date range
    #[allow(dead_code)]
    pub fn export(
        &self,
        from: Option<DateTime<Utc>>,
        to: Option<DateTime<Utc>>,
        format: ExportFormat,
    ) -> Result<String> {
        let mut entries = Vec::new();

        if self.log_path.exists() {
            let file = File::open(&self.log_path)
                .map_err(|e| SigilError::IoError(format!("Failed to open log: {}", e)))?;

            let reader = BufReader::new(file);

            for line in reader.lines() {
                let line =
                    line.map_err(|e| SigilError::IoError(format!("Failed to read line: {}", e)))?;

                if let Ok(entry) = serde_json::from_str::<AuditEntry>(&line) {
                    let timestamp = entry.timestamp();

                    // Filter by date range
                    if let Some(from_date) = from {
                        if timestamp < from_date {
                            continue;
                        }
                    }

                    if let Some(to_date) = to {
                        if timestamp > to_date {
                            continue;
                        }
                    }

                    entries.push(entry);
                }
            }
        }

        match format {
            ExportFormat::Json => serde_json::to_string_pretty(&entries)
                .map_err(|e| SigilError::SerializationError(e.to_string())),
            ExportFormat::Csv => {
                // Simple CSV export with selected fields
                let mut output = String::from("type,timestamp,path,fingerprint,pid,uid\n");

                for entry in entries {
                    let row = match &entry {
                        AuditEntry::SecretResolve {
                            timestamp,
                            path,
                            fingerprint,
                            pid,
                            uid,
                            ..
                        } => format!(
                            "secret_resolve,{},{},{},{},{}\n",
                            timestamp.format("%Y-%m-%d %H:%M:%S"),
                            path,
                            fingerprint,
                            pid,
                            uid
                        ),
                        AuditEntry::SecretAdd {
                            timestamp,
                            path,
                            fingerprint,
                            ..
                        } => format!(
                            "secret_add,{},{},{}\n",
                            timestamp.format("%Y-%m-%d %H:%M:%S"),
                            path,
                            fingerprint
                        ),
                        _ => continue,
                    };

                    output.push_str(&row);
                }

                Ok(output)
            }
        }
    }
}

/// Export format for audit log entries
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(dead_code)]
pub enum ExportFormat {
    /// JSON format
    Json,
    /// CSV format
    Csv,
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[tokio::test]
    async fn test_audit_logger() {
        let temp_dir = TempDir::new().unwrap();
        let log_path = temp_dir.path().join("test-audit.jsonl");

        let logger = AuditLogger::new(log_path.clone()).unwrap();

        // Log session start
        logger.log_session_start().await;

        // Log secret resolve
        logger
            .log_secret_resolve("test/path".to_string(), "abc123".to_string(), 123, 456)
            .await;

        // Verify log file exists
        assert!(log_path.exists());

        // Verify entries
        let content = std::fs::read_to_string(&log_path).unwrap();
        let lines: Vec<&str> = content.lines().collect();
        assert_eq!(lines.len(), 2);

        // Verify hash chaining
        let entry1: AuditEntry = serde_json::from_str(lines[0]).unwrap();
        let entry2: AuditEntry = serde_json::from_str(lines[1]).unwrap();

        assert_eq!(
            entry2.previous_hash(),
            Some(entry1.compute_hash("").as_str())
        );
    }
}
