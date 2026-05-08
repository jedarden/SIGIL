//! Filesystem monitor for detecting secret writes
//!
//! This module implements a filesystem monitor using inotify (Linux) or similar
//! mechanisms to detect file creations and modifications that might contain secrets.
//!
//! The monitor watches the project directory and scans changed files through
//! the scrubber. If secrets are detected, it alerts via TUI and optionally
//! auto-scrubs the files.

use anyhow::{Context, Result};
use notify::{event::ModifyKind, Event, EventKind, RecursiveMode, Watcher};
use sigil_scrub::Scrubber;
use sigil_core::SecretPath;
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Mutex;
use tracing::{debug, error, info, warn};

/// Filesystem monitor configuration
#[derive(Debug, Clone)]
pub struct MonitorConfig {
    /// Paths to watch (project directories)
    pub watch_paths: Vec<PathBuf>,
    /// Whether to auto-scrub detected secrets
    pub auto_scrub: bool,
    /// Debounce delay for file events (ms)
    pub debounce_ms: u64,
    /// Maximum file size to scan (bytes)
    pub max_scan_size: usize,
}

impl Default for MonitorConfig {
    fn default() -> Self {
        Self {
            watch_paths: Vec::new(),
            auto_scrub: false,
            debounce_ms: 100,
            max_scan_size: 10 * 1024 * 1024, // 10MB
        }
    }
}

/// Secret detection result from scanning a file
#[derive(Debug, Clone)]
pub struct SecretDetection {
    /// File path where secrets were detected
    pub file_path: PathBuf,
    /// Number of secrets detected
    pub secret_count: usize,
    /// Whether the file was auto-scrubbed
    pub was_scrubbed: bool,
    /// Timestamp of detection
    pub detected_at: chrono::DateTime<chrono::Utc>,
}

/// Filesystem monitor for secret detection
pub struct FilesystemMonitor {
    /// Monitor configuration
    config: MonitorConfig,
    /// Scrubber for detecting secrets
    scrubber: Arc<Mutex<Scrubber>>,
    /// Detected secrets (file path -> detection info)
    detections: Arc<Mutex<HashMap<PathBuf, SecretDetection>>>,
    /// Whether the monitor is running
    running: Arc<Mutex<bool>>,
    /// Debounce map (file path -> last event time)
    debounce_map: Arc<Mutex<HashMap<PathBuf, std::time::Instant>>>,
}

impl FilesystemMonitor {
    /// Create a new filesystem monitor
    pub fn new(config: MonitorConfig) -> Self {
        Self {
            config,
            scrubber: Arc::new(Mutex::new(Scrubber::new())),
            detections: Arc::new(Mutex::new(HashMap::new())),
            running: Arc::new(Mutex::new(false)),
            debounce_map: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// Add a secret to monitor for
    pub async fn add_secret(&self, path: SecretPath, value: &[u8]) {
        let mut scrubber = self.scrubber.lock().await;
        scrubber.add_secret(path, value);
        debug!("Added secret {} to filesystem monitor", path.as_str());
    }

    /// Remove a secret from monitoring
    pub async fn remove_secret(&self, path: &SecretPath) {
        let mut scrubber = self.scrubber.lock().await;
        scrubber.remove_secret(path);
        debug!("Removed secret {} from filesystem monitor", path.as_str());
    }

    /// Get all detections
    pub async fn get_detections(&self) -> Vec<SecretDetection> {
        let detections = self.detections.lock().await;
        detections.values().cloned().collect()
    }

    /// Clear all detections
    pub async fn clear_detections(&self) {
        let mut detections = self.detections.lock().await;
        detections.clear();
    }

    /// Start the filesystem monitor
    pub async fn start(&self) -> Result<()> {
        let mut running = self.running.lock().await;
        if *running {
            return Ok(());
        }
        *running = true;
        drop(running);

        info!("Starting filesystem monitor");

        // Create a channel for receiving events
        let (tx, mut rx) = tokio::sync::mpsc::channel::<Event>(100);

        // Create the watcher
        let mut watcher = notify::recommended_watcher(move |res: Result<Event, _>| {
            if let Ok(event) = res {
                let _ = tx.blocking_send(event);
            }
        })
        .context("Failed to create filesystem watcher")?;

        // Add watch paths
        for watch_path in &self.config.watch_paths {
            if watch_path.exists() {
                watcher
                    .watch(watch_path, RecursiveMode::Recursive)
                    .with_context(|| format!("Failed to watch path: {:?}", watch_path))?;
                info!("Watching path: {:?}", watch_path);
            } else {
                warn!("Watch path does not exist: {:?}", watch_path);
            }
        }

        // Spawn the event handler task
        let scrubber = self.scrubber.clone();
        let detections = self.detections.clone();
        let debounce_map = self.debounce_map.clone();
        let auto_scrub = self.config.auto_scrub;
        let max_scan_size = self.config.max_scan_size;
        let debounce_duration = Duration::from_millis(self.config.debounce_ms);
        let running = self.running.clone();

        tokio::spawn(async move {
            info!("Filesystem monitor event handler started");

            while *running.lock().await {
                // Check for events with timeout
                match tokio::time::timeout(Duration::from_secs(1), rx.recv()).await {
                    Ok(Some(event)) => {
                        if let Err(e) = Self::handle_event(
                            event,
                            &scrubber,
                            &detections,
                            &debounce_map,
                            auto_scrub,
                            max_scan_size,
                            debounce_duration,
                        )
                        .await
                        {
                            error!("Error handling filesystem event: {}", e);
                        }
                    }
                    Ok(None) => {
                        // Channel closed
                        break;
                    }
                    Err(_) => {
                        // Timeout - continue
                    }
                }
            }

            info!("Filesystem monitor event handler stopped");
        });

        Ok(())
    }

    /// Stop the filesystem monitor
    pub async fn stop(&self) {
        let mut running = self.running.lock().await;
        *running = false;
    }

    /// Handle a filesystem event
    async fn handle_event(
        event: Event,
        scrubber: &Arc<Mutex<Scrubber>>,
        detections: &Arc<Mutex<HashMap<PathBuf, SecretDetection>>>,
        debounce_map: &Arc<Mutex<HashMap<PathBuf, std::time::Instant>>>,
        auto_scrub: bool,
        max_scan_size: usize,
        debounce_duration: Duration,
    ) -> Result<()> {
        // Filter for relevant events (create, modify, close write)
        let relevant = matches!(
            event.kind,
            EventKind::Create(_) | EventKind::Modify(ModifyKind::Data | ModifyKind::Any)
        );

        if !relevant {
            return Ok(());
        }

        for path in event.paths {
            // Skip directories
            if path.is_dir() {
                continue;
            }

            // Skip binary files and common non-text extensions
            if let Some(ext) = path.extension() {
                let ext_str = ext.to_string_lossy().to_lowercase();
                let skip_extensions = [
                    "png", "jpg", "jpeg", "gif", "ico", "pdf", "zip", "tar", "gz", "bz2", "xz",
                    "7z", "rar", "exe", "dll", "so", "dylib", "bin", "dat", "db", "sqlite",
                ];
                if skip_extensions.contains(&ext_str.as_str()) {
                    debug!("Skipping binary file: {:?}", path);
                    continue;
                }
            }

            // Debounce events
            {
                let mut debounce = debounce_map.lock().await;
                let now = std::time::Instant::now();

                if let Some(last_time) = debounce.get(&path) {
                    if now.duration_since(*last_time) < debounce_duration {
                        continue; // Skip this event, too soon after the last one
                    }
                }

                debounce.insert(path.clone(), now);
            }

            // Scan the file for secrets
            let detection = Self::scan_file(&path, scrubber, auto_scrub, max_scan_size).await?;

            if let Some(detection) = detection {
                warn!(
                    "Secrets detected in file: {:?} ({} secrets)",
                    path, detection.secret_count
                );

                // Store the detection
                let mut detections_guard = detections.lock().await;
                detections_guard.insert(path.clone(), detection);
            }
        }

        Ok(())
    }

    /// Scan a file for secrets
    async fn scan_file(
        path: &Path,
        scrubber: &Arc<Mutex<Scrubber>>,
        auto_scrub: bool,
        max_scan_size: usize,
    ) -> Result<Option<SecretDetection>> {
        // Read file content
        let metadata = tokio::fs::metadata(path)
            .await
            .context("Failed to get file metadata")?;

        if metadata.len() as usize > max_scan_size {
            debug!(
                "File too large to scan: {:?} ({} bytes)",
                path,
                metadata.len()
            );
            return Ok(None);
        }

        let content = tokio::fs::read(path)
            .await
            .context("Failed to read file")?;

        // Try to convert to UTF-8
        let content_str = String::from_utf8_lossy(&content);

        // Scrub the content
        let mut scrubber_guard = scrubber.lock().await;
        let scrubbed = scrubber_guard.scrub(&content_str);

        // Check if anything was scrubbed
        let secret_count = if scrubbed != content_str {
            // Count occurrences of {{secret: in the scrubbed output
            scrubbed.matches("{{secret:").count()
        } else {
            0
        };

        if secret_count == 0 {
            return Ok(None);
        }

        // Auto-scrub if enabled
        let was_scrubbed = if auto_scrub {
            match tokio::fs::write(path, scrubbed).await {
                Ok(_) => {
                    info!("Auto-scrubbed file: {:?}", path);
                    true
                }
                Err(e) => {
                    error!("Failed to auto-scrub file {:?}: {}", path, e);
                    false
                }
            }
        } else {
            false
        };

        Ok(Some(SecretDetection {
            file_path: path.to_path_buf(),
            secret_count,
            was_scrubbed,
            detected_at: chrono::Utc::now(),
        }))
    }

    /// Check if the monitor is running
    pub async fn is_running(&self) -> bool {
        *self.running.lock().await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::TempDir;

    #[test]
    fn test_monitor_config_default() {
        let config = MonitorConfig::default();
        assert!(config.watch_paths.is_empty());
        assert!(!config.auto_scrub);
        assert_eq!(config.debounce_ms, 100);
        assert_eq!(config.max_scan_size, 10 * 1024 * 1024);
    }

    #[test]
    fn test_secret_detection_creation() {
        let detection = SecretDetection {
            file_path: PathBuf::from("/test/file.txt"),
            secret_count: 3,
            was_scrubbed: true,
            detected_at: chrono::Utc::now(),
        };

        assert_eq!(detection.file_path, PathBuf::from("/test/file.txt"));
        assert_eq!(detection.secret_count, 3);
        assert!(detection.was_scrubbed);
    }

    #[tokio::test]
    async fn test_filesystem_monitor_creation() {
        let config = MonitorConfig::default();
        let monitor = FilesystemMonitor::new(config);

        assert!(!monitor.is_running().await);
        assert!(monitor.get_detections().await.is_empty());
    }

    #[tokio::test]
    async fn test_add_secret_to_monitor() {
        let config = MonitorConfig::default();
        let monitor = FilesystemMonitor::new(config);

        let path = SecretPath::new("test/secret").unwrap();
        monitor.add_secret(path, b"test_secret").await;

        // Secret should be added (no error)
        assert!(!monitor.is_running().await);
    }

    #[tokio::test]
    async fn test_clear_detections() {
        let config = MonitorConfig::default();
        let monitor = FilesystemMonitor::new(config);

        // Add a fake detection
        let mut detections = monitor.detections.lock().await;
        detections.insert(
            PathBuf::from("/test/file.txt"),
            SecretDetection {
                file_path: PathBuf::from("/test/file.txt"),
                secret_count: 1,
                was_scrubbed: false,
                detected_at: chrono::Utc::now(),
            },
        );
        drop(detections);

        assert_eq!(monitor.get_detections().await.len(), 1);

        monitor.clear_detections().await;

        assert!(monitor.get_detections().await.is_empty());
    }

    #[tokio::test]
    async fn test_scan_file_with_secrets() {
        let temp_dir = TempDir::new().unwrap();
        let test_file = temp_dir.path().join("test.txt");

        // Write a file with a secret
        fs::write(&test_file, "API_KEY=secret123456").unwrap();

        // Create a scrubber with the secret
        let scrubber = Arc::new(Mutex::new(Scrubber::new()));
        {
            let mut s = scrubber.lock().await;
            s.add_secret(SecretPath::new("api/key").unwrap(), b"secret123456");
        }

        // Scan the file
        let detection = FilesystemMonitor::scan_file(
            &test_file,
            &scrubber,
            false, // auto_scrub
            1024 * 1024,
        )
        .await
        .unwrap()
        .unwrap();

        assert_eq!(detection.file_path, test_file);
        assert!(detection.secret_count > 0);
        assert!(!detection.was_scrubbed);

        // File should still contain the secret (auto_scrub=false)
        let content = fs::read_to_string(&test_file).unwrap();
        assert!(content.contains("secret123456"));
    }

    #[tokio::test]
    async fn test_scan_file_with_auto_scrub() {
        let temp_dir = TempDir::new().unwrap();
        let test_file = temp_dir.path().join("test.txt");

        // Write a file with a secret
        fs::write(&test_file, "API_KEY=secret123456").unwrap();

        // Create a scrubber with the secret
        let scrubber = Arc::new(Mutex::new(Scrubber::new()));
        {
            let mut s = scrubber.lock().await;
            s.add_secret(SecretPath::new("api/key").unwrap(), b"secret123456");
        }

        // Scan the file with auto_scrub enabled
        let detection = FilesystemMonitor::scan_file(
            &test_file,
            &scrubber,
            true, // auto_scrub
            1024 * 1024,
        )
        .await
        .unwrap()
        .unwrap();

        assert_eq!(detection.file_path, test_file);
        assert!(detection.secret_count > 0);
        assert!(detection.was_scrubbed);

        // File should be scrubbed
        let content = fs::read_to_string(&test_file).unwrap();
        assert!(!content.contains("secret123456"));
        assert!(content.contains("{{secret:api/key}}"));
    }

    #[tokio::test]
    async fn test_scan_file_too_large() {
        let temp_dir = TempDir::new().unwrap();
        let test_file = temp_dir.path().join("large.txt");

        // Write a large file (> 1MB)
        let large_content = "x".repeat(2_000_000);
        fs::write(&test_file, &large_content).unwrap();

        let scrubber = Arc::new(Mutex::new(Scrubber::new()));

        // Scan with max size of 1MB
        let detection = FilesystemMonitor::scan_file(
            &test_file,
            &scrubber,
            false,
            1_000_000, // max_scan_size
        )
        .await
        .unwrap();

        // Should return None (file too large)
        assert!(detection.is_none());
    }

    #[tokio::test]
    async fn test_scan_file_no_secrets() {
        let temp_dir = TempDir::new().unwrap();
        let test_file = temp_dir.path().join("test.txt");

        // Write a file without secrets
        fs::write(&test_file, "Hello, world!").unwrap();

        let scrubber = Arc::new(Mutex::new(Scrubber::new()));

        // Scan the file
        let detection = FilesystemMonitor::scan_file(
            &test_file,
            &scrubber,
            false,
            1024 * 1024,
        )
        .await
        .unwrap();

        // Should return None (no secrets detected)
        assert!(detection.is_none());
    }
}
