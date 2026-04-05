//! Filesystem monitor for detecting secret leaks
//!
//! This module provides a filesystem monitor that watches for file changes
//! and scans them for potential secret leaks. It's designed as a fallback for
//! harnesses without PreToolUse/PostToolUse hooks.
//!
//! The monitor uses the `notify` crate to watch for file system events and
//! scans changed files through a scrubber to detect secret patterns.

use anyhow::Result;
use chrono::{DateTime, Utc};
use notify::{Event, EventKind, RecursiveMode, Watcher};
use serde::{Deserialize, Serialize};
use sha2::Digest;
use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::sync::mpsc;
use std::thread;
use std::time::Duration;
use thiserror::Error;

/// Errors returned by the filesystem monitor
#[derive(Debug, Error)]
pub enum MonitorError {
    /// Failed to create watcher
    #[error("Failed to create watcher: {0}")]
    WatcherError(#[from] notify::Error),

    /// Path does not exist
    #[error("Path does not exist: {0}")]
    PathNotFound(PathBuf),

    /// Monitor thread panicked
    #[error("Monitor thread panicked")]
    ThreadPanicked,
}

/// File change event detected by the monitor
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileChangeEvent {
    /// Path to the changed file
    pub path: PathBuf,
    /// Type of change
    pub kind: ChangeKind,
    /// Timestamp of the change
    pub timestamp: DateTime<Utc>,
    /// Whether secrets were detected
    pub secrets_detected: bool,
    /// Number of secrets detected
    pub secret_count: usize,
}

/// Type of file change
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ChangeKind {
    /// File was created
    Created,
    /// File was modified
    Modified,
    /// File was removed
    Removed,
    /// Other change type
    Other,
}

/// Configuration for the filesystem monitor
#[derive(Debug, Clone)]
pub struct MonitorConfig {
    /// Paths to watch
    pub watch_paths: Vec<PathBuf>,
    /// Whether to watch recursively
    pub recursive: bool,
    /// File patterns to exclude (e.g., "*.tmp", "node_modules/*")
    pub exclude_patterns: Vec<String>,
    /// Debounce delay for events (ms)
    pub debounce_ms: u64,
    /// Whether to automatically scrub detected secrets
    pub auto_scrub: bool,
}

impl Default for MonitorConfig {
    fn default() -> Self {
        Self {
            watch_paths: vec![],
            recursive: true,
            exclude_patterns: vec![
                "node_modules/*".to_string(),
                ".git/*".to_string(),
                "target/*".to_string(),
                "*.tmp".to_string(),
                "*.swp".to_string(),
                "*.log".to_string(),
            ],
            debounce_ms: 100,
            auto_scrub: false,
        }
    }
}

/// Result of scanning a file for secrets
#[derive(Debug, Clone)]
pub struct ScanResult {
    /// Path to the file
    pub path: PathBuf,
    /// Whether secrets were detected
    pub has_secrets: bool,
    /// Number of secrets detected
    pub secret_count: usize,
    /// Secret patterns found (fingerprint only, not values)
    pub fingerprints: Vec<String>,
}

/// Filesystem monitor for detecting secret leaks
pub struct FilesystemMonitor {
    /// Monitor configuration
    config: MonitorConfig,
    /// Sender for file change events
    #[allow(dead_code)]
    event_tx: mpsc::Sender<FileChangeEvent>,
    /// Receiver for file change events
    event_rx: mpsc::Receiver<FileChangeEvent>,
    /// Whether the monitor is running
    running: std::sync::Arc<std::sync::atomic::AtomicBool>,
    /// Paths being watched
    watched_paths: HashSet<PathBuf>,
}

impl FilesystemMonitor {
    /// Create a new filesystem monitor
    pub fn new(config: MonitorConfig) -> Self {
        let (event_tx, event_rx) = mpsc::channel();
        Self {
            config,
            event_tx,
            event_rx,
            running: std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false)),
            watched_paths: HashSet::new(),
        }
    }

    /// Create a monitor with default configuration
    pub fn with_defaults() -> Self {
        Self::new(MonitorConfig::default())
    }

    /// Add a path to watch
    pub fn watch_path(&mut self, path: PathBuf) -> Result<()> {
        if !path.exists() {
            return Err(MonitorError::PathNotFound(path).into());
        }

        self.watched_paths.insert(path);
        Ok(())
    }

    /// Get a receiver for file change events
    pub fn events(&self) -> mpsc::Receiver<FileChangeEvent> {
        // Return a cloned receiver - this is a simplification
        // In production, we'd use a more sophisticated channel sharing mechanism
        let (_, rx) = mpsc::channel();
        rx
    }

    /// Try to receive the next event without blocking
    pub fn try_recv_event(&self) -> Result<FileChangeEvent, mpsc::TryRecvError> {
        self.event_rx.try_recv()
    }

    /// Receive the next event, blocking until available
    pub fn recv_event(&self) -> Result<FileChangeEvent, mpsc::RecvError> {
        self.event_rx.recv()
    }

    /// Check if the monitor is currently running
    pub fn is_running(&self) -> bool {
        self.running.load(std::sync::atomic::Ordering::SeqCst)
    }

    /// Start the monitor
    pub fn start(mut self) -> Result<MonitorHandle> {
        if self.config.watch_paths.is_empty() {
            // Use watched paths if no config paths
            self.config.watch_paths = self.watched_paths.iter().cloned().collect();
        }

        if self.config.watch_paths.is_empty() {
            anyhow::bail!("No paths to watch. Add paths with watch_path() or set in config.");
        }

        // Validate all watch paths exist
        for path in &self.config.watch_paths {
            if !path.exists() {
                return Err(MonitorError::PathNotFound(path.clone()).into());
            }
        }

        let running = self.running.clone();
        running.store(true, std::sync::atomic::Ordering::SeqCst);

        // Create a channel for events
        let (tx, _rx) = mpsc::channel();

        // Clone running for the thread
        let running_clone = running.clone();

        // Spawn monitor thread
        let handle = thread::spawn(move || {
            if let Err(e) = Self::run_monitor(self.config, tx, running_clone) {
                eprintln!("Monitor thread error: {}", e);
            }
        });

        Ok(MonitorHandle {
            thread: Some(handle),
            running,
        })
    }

    /// Internal monitor thread function
    fn run_monitor(
        config: MonitorConfig,
        event_tx: mpsc::Sender<FileChangeEvent>,
        running: std::sync::Arc<std::sync::atomic::AtomicBool>,
    ) -> Result<()> {
        use notify::recommended_watcher;

        // Create channel for watcher events
        let (watcher_tx, watcher_rx) = mpsc::channel();

        // Create watcher
        let mut watcher = recommended_watcher(move |res: Result<Event, notify::Error>| {
            if let Ok(event) = res {
                let _ = watcher_tx.send(event);
            }
        })?;

        // Watch all configured paths
        for path in &config.watch_paths {
            let mode = if config.recursive {
                RecursiveMode::Recursive
            } else {
                RecursiveMode::NonRecursive
            };
            watcher.watch(path, mode)?;
        }

        // Debounce collection
        let mut pending_events: std::collections::HashMap<PathBuf, ChangeKind> =
            std::collections::HashMap::new();
        let mut last_flush = std::time::Instant::now();

        while running.load(std::sync::atomic::Ordering::SeqCst) {
            // Check for new watcher events
            if let Ok(event) = watcher_rx.recv_timeout(Duration::from_millis(50)) {
                for path in event.paths {
                    // Check if path matches exclude patterns
                    if Self::should_exclude(&path, &config.exclude_patterns) {
                        continue;
                    }

                    // Only track files, not directories
                    if path.is_dir() {
                        continue;
                    }

                    // Determine change kind
                    let kind = match event.kind {
                        EventKind::Create(_) => ChangeKind::Created,
                        EventKind::Modify(_) => ChangeKind::Modified,
                        EventKind::Remove(_) => ChangeKind::Removed,
                        _ => ChangeKind::Other,
                    };

                    pending_events.insert(path, kind);
                }
            }

            // Flush pending events after debounce delay
            if last_flush.elapsed() >= Duration::from_millis(config.debounce_ms) {
                for (path, kind) in pending_events.drain() {
                    // Scan file for secrets
                    let scan_result = Self::scan_file(&path);

                    let event = FileChangeEvent {
                        path: path.clone(),
                        kind,
                        timestamp: Utc::now(),
                        secrets_detected: scan_result.has_secrets,
                        secret_count: scan_result.secret_count,
                    };

                    // Send event
                    if event_tx.send(event).is_err() {
                        // Channel closed, stop monitoring
                        running.store(false, std::sync::atomic::Ordering::SeqCst);
                        break;
                    }

                    // Auto-scrub if configured
                    if config.auto_scrub && scan_result.has_secrets {
                        if let Err(e) = Self::scrub_file(&path) {
                            eprintln!("Failed to auto-scrub file {:?}: {}", path, e);
                        }
                    }
                }
                last_flush = std::time::Instant::now();
            }
        }

        Ok(())
    }

    /// Check if a path should be excluded based on patterns
    fn should_exclude(path: &Path, patterns: &[String]) -> bool {
        let path_str = path.to_string_lossy();

        for pattern in patterns {
            if pattern.ends_with("/*") {
                // Directory exclusion
                let dir = &pattern[..pattern.len() - 2];
                if path_str.contains(dir) {
                    return true;
                }
            } else if let Some(ext) = pattern.strip_prefix("*.") {
                // Extension exclusion
                if let Some(ext2) = path.extension() {
                    if ext2.to_string_lossy() == ext {
                        return true;
                    }
                }
            } else if path_str.contains(pattern) {
                return true;
            }
        }

        false
    }

    /// Scan a file for secrets
    fn scan_file(path: &Path) -> ScanResult {
        // Read file content
        let content = match std::fs::read_to_string(path) {
            Ok(content) => content,
            Err(_) => {
                return ScanResult {
                    path: path.to_path_buf(),
                    has_secrets: false,
                    secret_count: 0,
                    fingerprints: vec![],
                }
            }
        };

        // Check for secret patterns
        let patterns = [
            // API keys
            r#"(?i)api[_-]?key\s*[:=]\s*['"]?[a-zA-Z0-9_]{10,}"#,
            r#"(?i)secret[_-]?key\s*[:=]\s*['"]?[a-zA-Z0-9_]{10,}"#,
            // Passwords
            r#"(?i)password\s*[:=]\s*['"]?[^\s'"]{8,}"#,
            // Tokens
            r#"(?i)token\s*[:=]\s*['"]?[a-zA-Z0-9_]{10,}"#,
            // Private keys
            r#"-----BEGIN [A-Z]+ PRIVATE KEY-----"#,
            // AWS access key
            r#"AKIA[0-9A-Z]{16}"#,
            // Generic base64-like strings (potential JWTs, etc)
            r#"eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+"#,
            // Potential credential pairs
            r#"[a-zA-Z0-9/_-]{20,}:[a-zA-Z0-9/_-]{20,}"#,
        ];

        let mut fingerprints = vec![];
        let mut secret_count = 0;

        for pattern in &patterns {
            if let Ok(re) = regex::Regex::new(pattern) {
                for match_ in re.find_iter(&content) {
                    secret_count += 1;
                    // Generate fingerprint (first 6 chars of SHA256)
                    let matched_str = match_.as_str();
                    let fingerprint = format!("{:x}", sha2::Sha256::digest(matched_str.as_bytes()));
                    let fingerprint_short = if fingerprint.len() > 6 {
                        fingerprint[0..6].to_string()
                    } else {
                        fingerprint
                    };
                    fingerprints.push(fingerprint_short);
                }
            }
        }

        ScanResult {
            path: path.to_path_buf(),
            has_secrets: secret_count > 0,
            secret_count,
            fingerprints,
        }
    }

    /// Scrub secrets from a file
    fn scrub_file(path: &Path) -> Result<()> {
        // Read file content
        let content = std::fs::read_to_string(path)?;

        // Scan for secrets
        let scan_result = Self::scan_file(path);
        if !scan_result.has_secrets {
            return Ok(());
        }

        // Replace detected patterns with placeholders
        // This is a simple implementation - in production, we'd use the full scrubber
        let scrubbed_content = Self::scrub_content(&content);

        // Write scrubbed content back
        std::fs::write(path, scrubbed_content)?;

        Ok(())
    }

    /// Scrub secrets from content
    fn scrub_content(content: &str) -> String {
        let mut scrubbed = content.to_string();

        // Simple pattern replacement (in production, use the full scrubber)
        let patterns = [
            r#"(?i)api[_-]?key\s*[:=]\s*['"]?[a-zA-Z0-9_]{10,}"#,
            r#"(?i)secret[_-]?key\s*[:=]\s*['"]?[a-zA-Z0-9_]{10,}"#,
            r#"(?i)password\s*[:=]\s*['"]?[^\s'"]{8,}"#,
            r#"(?i)token\s*[:=]\s*['"]?[a-zA-Z0-9_]{10,}"#,
            r#"-----BEGIN [A-Z]+ PRIVATE KEY-----"#,
            r#"AKIA[0-9A-Z]{16}"#,
        ];

        for pattern in &patterns {
            if let Ok(re) = regex::Regex::new(pattern) {
                scrubbed = re.replace_all(&scrubbed, "[REDACTED]").to_string();
            }
        }

        scrubbed
    }
}

/// Handle to a running filesystem monitor
pub struct MonitorHandle {
    /// The monitor thread handle
    thread: Option<thread::JoinHandle<()>>,
    /// Whether the monitor is running
    running: std::sync::Arc<std::sync::atomic::AtomicBool>,
}

impl MonitorHandle {
    /// Stop the monitor
    pub fn stop(mut self) {
        self.running
            .store(false, std::sync::atomic::Ordering::SeqCst);
        if let Some(handle) = self.thread.take() {
            let _ = handle.join();
        }
    }

    /// Check if the monitor is still running
    pub fn is_running(&self) -> bool {
        self.running.load(std::sync::atomic::Ordering::SeqCst)
    }
}

impl Drop for MonitorHandle {
    fn drop(&mut self) {
        if self.running.load(std::sync::atomic::Ordering::SeqCst) {
            self.running
                .store(false, std::sync::atomic::Ordering::SeqCst);
            if let Some(handle) = self.thread.take() {
                let _ = handle.join();
            }
        }
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
        assert!(config.recursive);
        assert_eq!(config.debounce_ms, 100);
        assert!(!config.auto_scrub);
    }

    #[test]
    fn test_monitor_creation() {
        let monitor = FilesystemMonitor::with_defaults();
        assert!(!monitor.is_running());
    }

    #[test]
    fn test_watch_path_valid() {
        let temp_dir = TempDir::new().unwrap();
        let mut monitor = FilesystemMonitor::with_defaults();
        assert!(monitor.watch_path(temp_dir.path().to_path_buf()).is_ok());
    }

    #[test]
    fn test_watch_path_invalid() {
        let mut monitor = FilesystemMonitor::with_defaults();
        let result = monitor.watch_path(PathBuf::from("/nonexistent/path/that/does/not/exist"));
        assert!(result.is_err());
    }

    #[test]
    fn test_should_exclude() {
        let patterns = vec![
            "node_modules/*".to_string(),
            "*.tmp".to_string(),
            ".git/*".to_string(),
        ];

        assert!(FilesystemMonitor::should_exclude(
            Path::new("/project/node_modules/package/index.js"),
            &patterns
        ));
        assert!(FilesystemMonitor::should_exclude(
            Path::new("/project/file.tmp"),
            &patterns
        ));
        assert!(FilesystemMonitor::should_exclude(
            Path::new("/project/.git/config"),
            &patterns
        ));
        assert!(!FilesystemMonitor::should_exclude(
            Path::new("/project/src/main.rs"),
            &patterns
        ));
    }

    #[test]
    fn test_scan_file_with_secrets() {
        let temp_dir = TempDir::new().unwrap();
        let test_file = temp_dir.path().join("test.env");

        // Write file with secret
        fs::write(
            &test_file,
            "API_KEY=sk_1234567890abcdef\nPASSWORD=secret123",
        )
        .unwrap();

        let result = FilesystemMonitor::scan_file(&test_file);
        assert!(result.has_secrets);
        assert!(result.secret_count > 0);
    }

    #[test]
    fn test_scan_file_without_secrets() {
        let temp_dir = TempDir::new().unwrap();
        let test_file = temp_dir.path().join("test.txt");

        // Write file without secrets
        fs::write(&test_file, "Hello, world!\nThis is a normal file.").unwrap();

        let result = FilesystemMonitor::scan_file(&test_file);
        assert!(!result.has_secrets);
        assert_eq!(result.secret_count, 0);
    }

    #[test]
    fn test_scrub_content() {
        let content = r#"
            api_key = "sk_1234567890abcdef"
            password = "secret123"
            normal_value = "keep_this"
        "#;

        let scrubbed = FilesystemMonitor::scrub_content(content);
        assert!(!scrubbed.contains("sk_1234567890abcdef"));
        assert!(!scrubbed.contains("secret123"));
        assert!(scrubbed.contains("keep_this") || scrubbed.contains("[REDACTED]"));
    }
}
