//! Canary access monitoring
//!
//! Monitors for canary file access attempts and logs breach events.

use crate::canary::{CanaryKind, CanarySecret};
use serde::{Deserialize, Serialize};
use sigil_core::SecretPath;
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::sync::{Mutex, RwLock};
use tracing::{error, info, warn};

/// A canary access event (breach detection)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CanaryAccessEvent {
    /// ID of the triggered canary
    pub canary_id: String,
    /// Kind of canary that was triggered
    pub kind: CanaryKind,
    /// File path that was accessed
    pub file_path: PathBuf,
    /// PID of the process that accessed the canary
    pub pid: u32,
    /// Command line of the accessing process
    pub cmdline: String,
    /// When the access occurred
    pub timestamp: chrono::DateTime<chrono::Utc>,
    /// Severity level
    pub severity: BreachSeverity,
}

/// Severity level of a canary breach
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum BreachSeverity {
    /// Informational - canary was checked but no exfiltration detected
    Info,
    /// Warning - potential unauthorized access
    Warning,
    /// Critical - confirmed canary breach, possible exfiltration
    Critical,
}

impl CanaryAccessEvent {
    /// Create a new canary access event
    pub fn new(canary: &CanarySecret, pid: u32, cmdline: String, severity: BreachSeverity) -> Self {
        Self {
            canary_id: canary.id.clone(),
            kind: canary.kind.clone(),
            file_path: canary.relative_path(),
            pid,
            cmdline,
            timestamp: chrono::Utc::now(),
            severity,
        }
    }

    /// Get a human-readable description
    pub fn description(&self) -> String {
        format!(
            "Canary breach: {:?} at {} by PID {} ({})",
            self.kind,
            self.file_path.display(),
            self.pid,
            self.cmdline
        )
    }
}

/// Monitors canary files for access attempts
pub struct CanaryMonitor {
    /// Canary secrets being monitored
    canaries: Arc<RwLock<HashMap<String, CanarySecret>>>,
    /// Recorded breach events
    breaches: Arc<Mutex<Vec<CanaryAccessEvent>>>,
    /// Whether monitoring is active
    active: Arc<Mutex<bool>>,
    /// Path to the sandbox overlay (where canaries are written)
    overlay_path: PathBuf,
}

impl CanaryMonitor {
    /// Create a new canary monitor
    pub fn new(overlay_path: PathBuf) -> Self {
        Self {
            canaries: Arc::new(RwLock::new(HashMap::new())),
            breaches: Arc::new(Mutex::new(Vec::new())),
            active: Arc::new(Mutex::new(false)),
            overlay_path,
        }
    }

    /// Add a canary to monitor
    pub async fn add_canary(&self, canary: CanarySecret) -> anyhow::Result<()> {
        let mut canaries: tokio::sync::RwLockWriteGuard<'_, HashMap<String, CanarySecret>> =
            self.canaries.write().await;

        // Write canary to overlay (tmpfs, never on host)
        let overlay_full_path = self.overlay_path.join(&canary.path);
        if let Some(parent) = overlay_full_path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(&overlay_full_path, canary.value())?;

        tracing::debug!("Added canary: {:?} at {:?}", canary.kind, canary.path);
        canaries.insert(canary.id.clone(), canary);
        Ok(())
    }

    /// Add multiple canaries
    pub async fn add_canaries(&self, canaries: Vec<CanarySecret>) -> anyhow::Result<()> {
        for canary in canaries {
            self.add_canary(canary).await?;
        }
        Ok(())
    }

    /// Record a canary access event
    pub async fn record_access(
        &self,
        canary_id: &str,
        pid: u32,
        cmdline: String,
        severity: BreachSeverity,
    ) -> anyhow::Result<()> {
        let canaries: tokio::sync::RwLockReadGuard<'_, HashMap<String, CanarySecret>> =
            self.canaries.read().await;
        let canary = canaries
            .get(canary_id)
            .ok_or_else(|| anyhow::anyhow!("Canary not found: {}", canary_id))?;

        let event = CanaryAccessEvent::new(canary, pid, cmdline, severity);
        tracing::warn!("Canary breach detected: {}", event.description());

        // Record the breach
        let mut breaches: tokio::sync::MutexGuard<'_, Vec<CanaryAccessEvent>> =
            self.breaches.lock().await;
        breaches.push(event.clone());

        // Mark the canary as triggered
        drop(canaries); // Release read lock
        let mut canaries: tokio::sync::RwLockWriteGuard<'_, HashMap<String, CanarySecret>> =
            self.canaries.write().await;
        if let Some(c) = canaries.get_mut(canary_id) {
            c.mark_triggered();
        }

        Ok(())
    }

    /// Get all recorded breaches
    pub async fn get_breaches(&self) -> Vec<CanaryAccessEvent> {
        self.breaches.lock().await.clone()
    }

    /// Get critical breaches
    pub async fn get_critical_breaches(&self) -> Vec<CanaryAccessEvent> {
        self.breaches
            .lock()
            .await
            .iter()
            .filter(|b| b.severity == BreachSeverity::Critical)
            .cloned()
            .collect()
    }

    /// Check if any canary has been triggered
    pub async fn has_breaches(&self) -> bool {
        !self.breaches.lock().await.is_empty()
    }

    /// Get all canary values for scrubber integration
    pub async fn get_canary_values(&self) -> Vec<(SecretPath, Vec<u8>)> {
        let canaries: tokio::sync::RwLockReadGuard<'_, HashMap<String, CanarySecret>> =
            self.canaries.read().await;
        canaries
            .values()
            .map(|c| {
                // Use a special canary namespace
                let path = SecretPath::new(format!("canary/{}", c.kind.to_string().to_lowercase()))
                    .unwrap_or_else(|_| SecretPath::new("canary/unknown").unwrap());
                (path, c.value().to_vec())
            })
            .collect()
    }

    /// Start monitoring with fanotify for the overlay directory
    #[cfg(target_os = "linux")]
    pub async fn start(&self) -> anyhow::Result<()> {
        let mut active = self.active.lock().await;
        if *active {
            return Ok(());
        }
        *active = true;
        drop(active);

        // Ensure overlay directory exists
        if !self.overlay_path.exists() {
            std::fs::create_dir_all(&self.overlay_path)?;
        }

        // Clone the Arcs for the background task
        let canaries = self.canaries.clone();
        let breaches = self.breaches.clone();
        let active_flag = self.active.clone();
        let overlay_path = self.overlay_path.clone();

        // Spawn fanotify monitoring task
        tokio::spawn(async move {
            if let Err(e) =
                Self::run_fanotify_monitor(canaries, breaches, active_flag, overlay_path).await
            {
                error!("Fanotify monitoring error: {}", e);
            }
        });

        info!(
            "Canary monitoring started for overlay: {:?}",
            self.overlay_path
        );
        Ok(())
    }

    /// Run the fanotify event loop (static method for use in spawned task)
    #[cfg(target_os = "linux")]
    async fn run_fanotify_monitor(
        canaries: Arc<RwLock<HashMap<String, CanarySecret>>>,
        breaches: Arc<Mutex<Vec<CanaryAccessEvent>>>,
        active_flag: Arc<Mutex<bool>>,
        overlay_path: PathBuf,
    ) -> anyhow::Result<()> {
        use std::os::unix::io::AsRawFd;

        // Initialize fanotify
        let fanotify_fd = Self::init_fanotify(&overlay_path).await?;

        info!("Fanotify monitoring active on: {:?}", overlay_path);

        // Event loop
        let mut buffer = vec![0u8; 4096];
        loop {
            // Check if still active
            if !*active_flag.lock().await {
                info!("Fanotify monitoring stopping");
                break;
            }

            // Read events (non-blocking)
            match nix::unistd::read(fanotify_fd.as_raw_fd(), &mut buffer) {
                Ok(n) => {
                    if n == 0 {
                        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
                        continue;
                    }
                    Self::process_fanotify_events(
                        &buffer[..n],
                        &canaries,
                        &breaches,
                        &overlay_path,
                    )
                    .await?;
                }
                Err(nix::errno::Errno::EAGAIN) => {
                    // No events available, sleep briefly
                    tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
                    continue;
                }
                Err(e) => {
                    error!("Error reading fanotify events: {}", e);
                    tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;
                    continue;
                }
            }
        }

        // Clean up
        let _ = nix::unistd::close(fanotify_fd.as_raw_fd());
        Ok(())
    }

    /// Initialize fanotify for the overlay directory
    #[cfg(target_os = "linux")]
    async fn init_fanotify(overlay_path: &Path) -> anyhow::Result<std::os::fd::OwnedFd> {
        use std::os::fd::{FromRawFd, OwnedFd};

        // Fanotify flags
        const FAN_CLOEXEC: u32 = 0x00001;
        const FAN_CLASS_NOTIF: u32 = 0x00000;
        const FAN_NONBLOCK: u32 = 0x00002;

        // Event flags
        const FAN_ACCESS: u64 = 0x00001;
        const FAN_OPEN: u64 = 0x00020;

        // Mark flags
        const FAN_MARK_ADD: u32 = 0x00001;
        const FAN_MARK_MOUNT: u32 = 0x00010;

        unsafe {
            // Initialize fanotify
            let fd = nix::libc::fanotify_init(
                FAN_CLOEXEC | FAN_CLASS_NOTIF | FAN_NONBLOCK,
                nix::libc::O_RDONLY as u32,
            );

            if fd < 0 {
                return Err(anyhow::anyhow!(
                    "Failed to initialize fanotify: {}",
                    std::io::Error::last_os_error()
                ));
            }

            // Mark the overlay directory for monitoring
            let path_cstr = std::ffi::CString::new(overlay_path.to_str().unwrap())
                .map_err(|e| anyhow::anyhow!("Failed to convert path to CString: {}", e))?;

            let ret = nix::libc::fanotify_mark(
                fd,
                FAN_MARK_ADD | FAN_MARK_MOUNT,
                FAN_ACCESS | FAN_OPEN,
                0, // No directory fd
                path_cstr.as_ptr(),
            );

            if ret < 0 {
                warn!(
                    "Failed to add fanotify mark for overlay: {}",
                    std::io::Error::last_os_error()
                );
                // Continue anyway - we'll use hook-based detection as fallback
            }

            Ok(OwnedFd::from_raw_fd(fd))
        }
    }

    /// Process fanotify events and detect canary access
    #[cfg(target_os = "linux")]
    async fn process_fanotify_events(
        buffer: &[u8],
        canaries: &Arc<RwLock<HashMap<String, CanarySecret>>>,
        breaches: &Arc<Mutex<Vec<CanaryAccessEvent>>>,
        overlay_path: &Path,
    ) -> anyhow::Result<()> {
        use std::mem::size_of;

        // Fanotify event metadata structure
        #[repr(C)]
        struct FanotifyEventMetadata {
            event_len: u32,
            vers: u8,
            reserved: u8,
            metadata_len: u16,
            mask: u64,
            fd: i32,
            pid: i32,
        }

        let mut offset = 0;
        let canaries_guard = canaries.read().await;

        while offset + size_of::<FanotifyEventMetadata>() <= buffer.len() {
            let metadata =
                unsafe { &*(buffer.as_ptr().add(offset) as *const FanotifyEventMetadata) };

            if metadata.event_len == 0 {
                break;
            }

            // For permission events, we would need to respond, but for now we just log
            // Check if this could be a canary access based on the path
            if metadata.fd >= 0 {
                // Get the file path from fd
                if let Ok(path) = Self::get_path_from_fd(metadata.fd) {
                    if let Some(canary_id) =
                        Self::check_canary_access(&path, overlay_path, &canaries_guard)
                    {
                        // Get the canary details
                        if let Some(canary) = canaries_guard.get(&canary_id) {
                            // Record the breach
                            let cmdline = Self::read_process_cmdline(metadata.pid as u32).await;
                            let severity = BreachSeverity::Critical;

                            let event = CanaryAccessEvent {
                                canary_id: canary.id.clone(),
                                kind: canary.kind.clone(),
                                file_path: path,
                                pid: metadata.pid as u32,
                                cmdline,
                                timestamp: chrono::Utc::now(),
                                severity,
                            };

                            warn!(
                                "Canary breach detected via fanotify: {}",
                                event.description()
                            );

                            let mut breaches_guard = breaches.lock().await;
                            breaches_guard.push(event);
                        }
                    }
                }

                // Close the fd
                let _ = nix::unistd::close(metadata.fd);
            }

            // Move to next event
            offset += metadata.event_len as usize;
        }

        Ok(())
    }

    /// Get file path from file descriptor
    #[cfg(target_os = "linux")]
    fn get_path_from_fd(fd: i32) -> anyhow::Result<PathBuf> {
        // Read /proc/self/fd/<fd> to get the path
        let path = std::fs::read_link(format!("/proc/self/fd/{}", fd))
            .map_err(|e| anyhow::anyhow!("Failed to read path from fd {}: {}", fd, e))?;
        Ok(path)
    }

    /// Check if a file path corresponds to a canary
    #[cfg(target_os = "linux")]
    fn check_canary_access(
        path: &Path,
        overlay_path: &Path,
        canaries: &HashMap<String, CanarySecret>,
    ) -> Option<String> {
        // Get the relative path from overlay
        if let Ok(relative) = path.strip_prefix(overlay_path) {
            let path_str = relative.to_str()?;
            for canary in canaries.values() {
                let canary_path = canary.path.to_str()?;
                if canary_path == path_str || path_str.contains(canary_path) {
                    return Some(canary.id.clone());
                }
            }
        }
        None
    }

    /// Read process command line from /proc
    async fn read_process_cmdline(pid: u32) -> String {
        let cmdline_path = format!("/proc/{}/cmdline", pid);
        match std::fs::read_to_string(&cmdline_path) {
            Ok(cmdline) => {
                // cmdline has null bytes separating arguments
                cmdline.replace('\0', " ").trim().to_string()
            }
            Err(_) => format!("<unknown pid {}>", pid),
        }
    }

    /// Start monitoring (placeholder for non-Linux)
    #[cfg(not(target_os = "linux"))]
    pub async fn start(&self) -> anyhow::Result<()> {
        let mut active = self.active.lock().await;
        *active = true;

        tracing::info!("Canary monitoring started (hook-based detection only)");
        Ok(())
    }

    /// Stop monitoring
    pub async fn stop(&self) -> anyhow::Result<()> {
        let mut active = self.active.lock().await;
        *active = false;

        tracing::info!("Canary monitoring stopped");
        Ok(())
    }

    /// Check if monitoring is active
    pub async fn is_active(&self) -> bool {
        *self.active.lock().await
    }

    /// Generate a breach report
    pub async fn generate_report(&self) -> BreachReport {
        let breaches = self.get_breaches().await;
        let canaries: tokio::sync::RwLockReadGuard<'_, HashMap<String, CanarySecret>> =
            self.canaries.read().await;

        let triggered_canaries: Vec<_> = canaries
            .values()
            .filter(|c| c.is_triggered())
            .map(|c| CanarySummary {
                id: c.id.clone(),
                kind: c.kind.clone(),
                path: c.relative_path(),
                created_at: c.created_at,
                triggered_at: c.triggered_at,
            })
            .collect();

        BreachReport {
            generated_at: chrono::Utc::now(),
            total_breaches: breaches.len(),
            critical_breaches: breaches
                .iter()
                .filter(|b| b.severity == BreachSeverity::Critical)
                .count(),
            breaches,
            triggered_canaries,
        }
    }

    /// Clear all breach records (for testing)
    #[cfg(test)]
    pub async fn clear_breaches(&self) {
        self.breaches.lock().await.clear();
    }
}

/// Summary of a triggered canary
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CanarySummary {
    /// Unique identifier
    pub id: String,
    /// Kind of canary
    pub kind: CanaryKind,
    /// File path
    pub path: PathBuf,
    /// When created
    pub created_at: chrono::DateTime<chrono::Utc>,
    /// When triggered (if applicable)
    pub triggered_at: Option<chrono::DateTime<chrono::Utc>>,
}

/// A breach report summarizing all canary access events
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BreachReport {
    /// When report was generated
    pub generated_at: chrono::DateTime<chrono::Utc>,
    /// Total number of breaches
    pub total_breaches: usize,
    /// Number of critical breaches
    pub critical_breaches: usize,
    /// All breach events
    pub breaches: Vec<CanaryAccessEvent>,
    /// Summary of triggered canaries
    pub triggered_canaries: Vec<CanarySummary>,
}

impl BreachReport {
    /// Format as a human-readable report
    pub fn format(&self) -> String {
        let mut output = String::new();

        output.push_str(&format!(
            "SIGIL Breach Report\n\
             Generated: {}\n\
             Total Breaches: {}\n\
             Critical Breaches: {}\n\n",
            self.generated_at.format("%Y-%m-%d %H:%M:%S UTC"),
            self.total_breaches,
            self.critical_breaches
        ));

        if self.breaches.is_empty() {
            output.push_str("No canary breaches detected. Good!\n");
        } else {
            output.push_str("Detected Breaches:\n");
            for breach in &self.breaches {
                let severity = match breach.severity {
                    BreachSeverity::Info => "INFO",
                    BreachSeverity::Warning => "WARN",
                    BreachSeverity::Critical => "CRITICAL",
                };
                output.push_str(&format!(
                    "  [{}] {:?} at {}\n    PID: {} ({})\n    Time: {}\n\n",
                    severity,
                    breach.kind,
                    breach.file_path.display(),
                    breach.pid,
                    breach.cmdline,
                    breach.timestamp.format("%Y-%m-%d %H:%M:%S UTC")
                ));
            }
        }

        output
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_canary_monitor_creation() {
        let overlay = tempfile::tempdir().unwrap();
        let monitor = CanaryMonitor::new(overlay.path().to_path_buf());

        assert!(!monitor.is_active().await);
        assert!(!monitor.has_breaches().await);
    }

    #[tokio::test]
    async fn test_add_canary() {
        let overlay = tempfile::tempdir().unwrap();
        let monitor = CanaryMonitor::new(overlay.path().to_path_buf());

        let canary = CanarySecret::new(
            CanaryKind::EnvFile,
            b"TEST=value".to_vec(),
            PathBuf::from(".env"),
        );

        monitor.add_canary(canary).await.unwrap();

        // Check file was written to overlay
        let overlay_file = overlay.path().join(".env");
        assert!(overlay_file.exists());
        assert_eq!(
            std::fs::read_to_string(&overlay_file).unwrap(),
            "TEST=value"
        );
    }

    #[tokio::test]
    async fn test_record_access() {
        let overlay = tempfile::tempdir().unwrap();
        let monitor = CanaryMonitor::new(overlay.path().to_path_buf());

        let canary = CanarySecret::new(
            CanaryKind::AwsCredentials,
            b"fake creds".to_vec(),
            PathBuf::from(".aws/credentials"),
        );

        let canary_id = canary.id.clone();
        monitor.add_canary(canary).await.unwrap();

        monitor
            .record_access(
                &canary_id,
                12345,
                "cat".to_string(),
                BreachSeverity::Critical,
            )
            .await
            .unwrap();

        assert!(monitor.has_breaches().await);
        let breaches = monitor.get_breaches().await;
        assert_eq!(breaches.len(), 1);
        assert_eq!(breaches[0].pid, 12345);
    }

    #[tokio::test]
    async fn test_breach_report() {
        let overlay = tempfile::tempdir().unwrap();
        let monitor = CanaryMonitor::new(overlay.path().to_path_buf());

        let canary = CanarySecret::new(
            CanaryKind::GitHubToken,
            b"fake token".to_vec(),
            PathBuf::from(".config/gh/hosts.yml"),
        );

        let canary_id = canary.id.clone();
        monitor.add_canary(canary).await.unwrap();

        monitor
            .record_access(
                &canary_id,
                9999,
                "less".to_string(),
                BreachSeverity::Warning,
            )
            .await
            .unwrap();

        let report = monitor.generate_report().await;
        assert_eq!(report.total_breaches, 1);
        assert_eq!(report.critical_breaches, 0);
        assert_eq!(report.triggered_canaries.len(), 1);

        let formatted = report.format();
        assert!(formatted.contains("SIGIL Breach Report"));
        assert!(formatted.contains("Total Breaches: 1"));
    }

    #[tokio::test]
    async fn test_get_canary_values() {
        let overlay = tempfile::tempdir().unwrap();
        let monitor = CanaryMonitor::new(overlay.path().to_path_buf());

        let canary = CanarySecret::new(
            CanaryKind::EnvFile,
            b"SECRET=value".to_vec(),
            PathBuf::from(".env"),
        );

        monitor.add_canary(canary).await.unwrap();

        let values = monitor.get_canary_values().await;
        assert_eq!(values.len(), 1);
        assert_eq!(values[0].0.as_str(), "canary/env_file");
        assert_eq!(values[0].1, b"SECRET=value");
    }

    #[tokio::test]
    async fn test_start_stop() {
        let overlay = tempfile::tempdir().unwrap();
        let monitor = CanaryMonitor::new(overlay.path().to_path_buf());

        monitor.start().await.unwrap();
        assert!(monitor.is_active().await);

        monitor.stop().await.unwrap();
        assert!(!monitor.is_active().await);
    }
}
