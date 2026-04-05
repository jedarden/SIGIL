//! Audit log utilities for SIGIL
//!
//! This module provides read-only access to SIGIL's audit log for CLI commands.
//! The actual audit logging is done by the daemon (sigil-daemon crate).

use crate::error::{Result, SigilError};
use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};

/// Audit log entry types
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

/// Audit log configuration
#[derive(Debug, Clone)]
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

/// Export format for audit log entries
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExportFormat {
    /// JSON format
    Json,
    /// CSV format
    Csv,
}

/// Read-only audit log reader for CLI commands
pub struct AuditLogReader {
    log_path: PathBuf,
}

impl AuditLogReader {
    /// Create a new audit log reader
    pub fn new(log_path: PathBuf) -> Result<Self> {
        if !log_path.exists() {
            return Err(SigilError::IoError(format!(
                "Audit log not found: {}",
                log_path.display()
            )));
        }
        Ok(Self { log_path })
    }

    /// Read all entries from the audit log
    pub fn read_entries(&self) -> Result<Vec<AuditEntry>> {
        let file = File::open(&self.log_path)
            .map_err(|e| SigilError::IoError(format!("Failed to open log: {}", e)))?;

        let reader = BufReader::new(file);
        let mut entries = Vec::new();

        for line in reader.lines() {
            let line =
                line.map_err(|e| SigilError::IoError(format!("Failed to read line: {}", e)))?;

            if !line.trim().is_empty() {
                let entry = serde_json::from_str::<AuditEntry>(&line).map_err(|e| {
                    SigilError::SerializationError(format!("Failed to parse entry: {}", e))
                })?;
                entries.push(entry);
            }
        }

        Ok(entries)
    }

    /// Read entries within a date range
    pub fn read_entries_filtered(
        &self,
        from: Option<DateTime<Utc>>,
        to: Option<DateTime<Utc>>,
    ) -> Result<Vec<AuditEntry>> {
        let entries = self.read_entries()?;
        let filtered = entries
            .into_iter()
            .filter(|entry| {
                let timestamp = entry.timestamp();
                if let Some(from_date) = from {
                    if timestamp < from_date {
                        return false;
                    }
                }
                if let Some(to_date) = to {
                    if timestamp > to_date {
                        return false;
                    }
                }
                true
            })
            .collect();
        Ok(filtered)
    }

    /// Verify the hash chain of the audit log
    pub fn verify_chain(&self) -> Result<bool> {
        let entries = self.read_entries()?;

        if entries.is_empty() {
            return Ok(true); // Empty log is valid
        }

        let mut previous_hash = String::new();

        for (_i, entry) in entries.iter().enumerate() {
            // Check if the previous_hash field matches
            if let Some(stored_previous) = entry.previous_hash() {
                if stored_previous != previous_hash {
                    return Ok(false);
                }
            }

            // Update previous_hash for next iteration
            previous_hash = entry.compute_hash(&previous_hash);
        }

        Ok(true)
    }

    /// Get statistics about the audit log
    pub fn stats(&self) -> Result<AuditStats> {
        let entries = self.read_entries()?;

        let entry_count = entries.len();
        let first_timestamp = entries.first().map(|e| e.timestamp());
        let last_timestamp = entries.last().map(|e| e.timestamp());

        let size_bytes = std::fs::metadata(&self.log_path)
            .map(|m| m.len())
            .unwrap_or(0);

        // Verify chain
        let chain_valid = self.verify_chain()?;

        // Find rotated logs
        let mut rotated_logs = Vec::new();
        let log_dir = self.log_path.parent().unwrap_or(Path::new("."));
        let log_name = self
            .log_path
            .file_stem()
            .unwrap_or_default()
            .to_str()
            .unwrap_or("");

        if let Ok(dir_entries) = std::fs::read_dir(log_dir) {
            for entry in dir_entries.flatten() {
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

    /// Export audit log entries
    pub fn export(
        &self,
        from: Option<DateTime<Utc>>,
        to: Option<DateTime<Utc>>,
        format: ExportFormat,
    ) -> Result<String> {
        let entries = self.read_entries_filtered(from, to)?;

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
                            "secret_add,{},{},{},,\n",
                            timestamp.format("%Y-%m-%d %H:%M:%S"),
                            path,
                            fingerprint
                        ),
                        AuditEntry::SecretDelete {
                            timestamp, path, ..
                        } => format!(
                            "secret_delete,{},{},,\n",
                            timestamp.format("%Y-%m-%d %H:%M:%S"),
                            path
                        ),
                        AuditEntry::AuthFailure {
                            timestamp,
                            reason,
                            pid,
                            uid,
                            ..
                        } => format!(
                            "auth_failure,{},{},{},{},{}\n",
                            timestamp.format("%Y-%m-%d %H:%M:%S"),
                            reason,
                            "",
                            pid,
                            uid
                        ),
                        AuditEntry::BreachDetected {
                            timestamp,
                            severity,
                            description,
                            ..
                        } => format!(
                            "breach_detected,{},{},{},,\n",
                            timestamp.format("%Y-%m-%d %H:%M:%S"),
                            severity,
                            description
                        ),
                        AuditEntry::CanaryAccess {
                            timestamp,
                            path,
                            pid,
                            uid,
                            ..
                        } => format!(
                            "canary_access,{},{},{},{},{}\n",
                            timestamp.format("%Y-%m-%d %H:%M:%S"),
                            path,
                            "",
                            pid,
                            uid
                        ),
                        _ => continue,
                    };

                    output.push_str(&row);
                }

                Ok(output)
            }
        }
    }

    /// Get the default audit log path for SIGIL
    pub fn default_path() -> Result<PathBuf> {
        let home = std::env::var("HOME")
            .map_err(|_| SigilError::IoError("Cannot determine home directory".to_string()))?;
        Ok(PathBuf::from(home).join(".sigil/vault/audit.jsonl"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_audit_entry_timestamp() {
        let entry = AuditEntry::SessionStart {
            timestamp: Utc::now(),
            previous_hash: None,
        };
        assert!(entry.previous_hash().is_none());
    }

    #[test]
    fn test_export_format() {
        assert_eq!(ExportFormat::Json, ExportFormat::Json);
        assert_eq!(ExportFormat::Csv, ExportFormat::Csv);
    }
}
