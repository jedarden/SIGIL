//! SIGIL Audit CLI commands
//!
//! Provides commands for viewing and managing audit logs.

use anyhow::{Context, Result};
use chrono::{DateTime, Duration, Utc};
use clap::{Parser, Subcommand};
use sigil_core::{AuditLogReader, ExportFormat};
use std::io::Write;

/// Audit log management commands
#[derive(Subcommand, Clone)]
pub enum AuditCommand {
    /// Export audit log entries
    Export(CommandAuditExport),

    /// Verify audit log hash chain integrity
    Verify(CommandAuditVerify),

    /// Remove audit logs exceeding retention policy
    Prune(CommandAuditPrune),

    /// Show audit log statistics
    Stats(CommandAuditStats),
}

impl AuditCommand {
    pub fn run(&self) -> Result<()> {
        match self {
            AuditCommand::Export(cmd) => cmd.run(),
            AuditCommand::Verify(cmd) => cmd.run(),
            AuditCommand::Prune(cmd) => cmd.run(),
            AuditCommand::Stats(cmd) => cmd.run(),
        }
    }
}

/// Export audit log entries
#[derive(Parser, Clone)]
pub struct CommandAuditExport {
    /// Start date (ISO 8601 format, e.g., 2026-01-01T00:00:00Z)
    #[arg(short, long)]
    from: Option<String>,

    /// End date (ISO 8601 format, e.g., 2026-12-31T23:59:59Z)
    #[arg(short, long)]
    to: Option<String>,

    /// Output format
    #[arg(long, value_enum, default_value = "json")]
    format: OutputFormat,

    /// Output file (defaults to stdout)
    #[arg(short, long)]
    output: Option<String>,

    /// Audit log path (defaults to ~/.sigil/vault/audit.jsonl)
    #[arg(short, long)]
    path: Option<String>,
}

#[derive(clap::ValueEnum, Clone, Debug)]
enum OutputFormat {
    Json,
    Csv,
}

impl From<OutputFormat> for ExportFormat {
    fn from(val: OutputFormat) -> Self {
        match val {
            OutputFormat::Json => ExportFormat::Json,
            OutputFormat::Csv => ExportFormat::Csv,
        }
    }
}

impl CommandAuditExport {
    fn run(&self) -> Result<()> {
        // Get audit log path
        let log_path = if let Some(p) = &self.path {
            std::path::PathBuf::from(p)
        } else {
            AuditLogReader::default_path()?
        };

        // Create reader
        let reader = AuditLogReader::new(log_path)?;

        // Parse dates
        let from = if let Some(ref from_str) = self.from {
            Some(parse_date(from_str)?)
        } else {
            None
        };

        let to = if let Some(ref to_str) = self.to {
            Some(parse_date(to_str)?)
        } else {
            None
        };

        // Export entries
        let format: ExportFormat = self.format.clone().into();
        let output = reader.export(from, to, format)?;

        // Write output
        if let Some(ref output_path) = self.output {
            std::fs::write(output_path, output).context("Failed to write export file")?;
            println!("Exported to: {}", output_path);
        } else {
            print!("{}", output);
        }

        Ok(())
    }
}

/// Verify audit log hash chain integrity
#[derive(Parser, Clone)]
pub struct CommandAuditVerify {
    /// Audit log path (defaults to ~/.sigil/vault/audit.jsonl)
    #[arg(short, long)]
    path: Option<String>,
}

impl CommandAuditVerify {
    fn run(&self) -> Result<()> {
        // Get audit log path
        let log_path = if let Some(p) = &self.path {
            std::path::PathBuf::from(p)
        } else {
            AuditLogReader::default_path()?
        };

        // Create reader
        let reader = AuditLogReader::new(log_path)?;

        // Verify chain
        println!("Verifying audit log hash chain...");
        let valid = reader.verify_chain()?;

        if valid {
            println!("✓ Hash chain is valid");
            Ok(())
        } else {
            anyhow::bail!("✗ Hash chain is broken - tampering detected");
        }
    }
}

/// Remove audit logs exceeding retention policy
#[derive(Parser, Clone)]
pub struct CommandAuditPrune {
    /// Maximum number of rotated logs to keep (default: 5)
    #[arg(short, long, default_value = "5")]
    keep: usize,

    /// Maximum age of logs to keep (e.g., 90d, 1y)
    #[arg(short, long)]
    max_age: Option<String>,

    /// Dry run - show what would be pruned without actually pruning
    #[arg(long)]
    dry_run: bool,

    /// Audit log directory (defaults to ~/.sigil/vault)
    #[arg(short, long)]
    path: Option<String>,
}

impl CommandAuditPrune {
    fn run(&self) -> Result<()> {
        // Get audit log path
        let log_dir = if let Some(p) = &self.path {
            std::path::PathBuf::from(p)
        } else {
            let home = dirs::home_dir()
                .ok_or_else(|| anyhow::anyhow!("Cannot determine home directory"))?;
            home.join(".sigil/vault")
        };

        // Create stats reader to get rotated logs
        let log_path = log_dir.join("audit.jsonl");
        let reader = AuditLogReader::new(log_path.clone())?;
        let stats = reader.stats()?;

        // Parse max_age
        let max_age_duration = if let Some(ref age_str) = self.max_age {
            Some(parse_duration(age_str)?)
        } else {
            None
        };

        // Determine which logs to prune
        let mut to_prune = Vec::new();
        for (i, rotated_log) in stats.rotated_logs.iter().enumerate() {
            // Check count-based retention
            if i >= self.keep {
                to_prune.push(("count", rotated_log));
                continue;
            }

            // Check age-based retention
            if let Some(max_age) = max_age_duration {
                if let Ok(metadata) = std::fs::metadata(rotated_log) {
                    if let Ok(modified) = metadata.modified() {
                        let age = std::time::SystemTime::now()
                            .duration_since(modified)
                            .unwrap_or_default();
                        let max_age_secs = max_age.num_seconds() as u64;

                        if age.as_secs() > max_age_secs {
                            to_prune.push(("age", rotated_log));
                        }
                    }
                }
            }
        }

        if to_prune.is_empty() {
            println!("No logs to prune (retention policy satisfied)");
            return Ok(());
        }

        // Show what would be pruned
        println!("Logs to prune:");
        for (reason, log) in &to_prune {
            println!("  [{}] {}", reason, log.display());
        }

        if self.dry_run {
            println!("\nDry run complete - no files were deleted");
            return Ok(());
        }

        // Confirm pruning
        print!("Delete {} log files? [y/N] ", to_prune.len());
        std::io::stdout().flush()?;
        let mut input = String::new();
        std::io::stdin().read_line(&mut input)?;
        if !input.trim().to_lowercase().starts_with('y') {
            println!("Pruning cancelled");
            return Ok(());
        }

        // Prune logs
        let mut pruned = 0;
        for (_, log) in &to_prune {
            if let Err(e) = std::fs::remove_file(log) {
                eprintln!("Failed to remove {}: {}", log.display(), e);
            } else {
                pruned += 1;
                println!("Pruned: {}", log.display());
            }
        }

        println!("\nPruned {} log file(s)", pruned);
        Ok(())
    }
}

/// Show audit log statistics
#[derive(Parser, Clone)]
pub struct CommandAuditStats {
    /// Audit log path (defaults to ~/.sigil/vault/audit.jsonl)
    #[arg(short, long)]
    path: Option<String>,
}

impl CommandAuditStats {
    fn run(&self) -> Result<()> {
        // Get audit log path
        let log_path = if let Some(p) = &self.path {
            std::path::PathBuf::from(p)
        } else {
            AuditLogReader::default_path()?
        };

        // Create reader
        let reader = AuditLogReader::new(log_path)?;
        let stats = reader.stats()?;

        // Print stats
        println!("Audit Log Statistics");
        println!("====================");
        println!();
        println!("Log file: {}", stats.log_path.display());
        println!("File size: {} bytes", stats.size_bytes);
        println!("Entries: {}", stats.entry_count);

        if let Some((first, last)) = stats.date_range {
            println!(
                "Date range: {} to {}",
                first.format("%Y-%m-%d %H:%M:%S"),
                last.format("%Y-%m-%d %H:%M:%S")
            );
        }

        println!(
            "Chain status: {}",
            if stats.chain_valid {
                "✓ Valid"
            } else {
                "✗ Broken"
            }
        );
        println!("Rotated logs: {}", stats.rotated_logs.len());

        if !stats.rotated_logs.is_empty() {
            println!();
            println!("Rotated logs:");
            for log in &stats.rotated_logs {
                if let Ok(metadata) = std::fs::metadata(log) {
                    let size = metadata.len();
                    println!("  {} ({} bytes)", log.display(), size);
                } else {
                    println!("  {}", log.display());
                }
            }
        }

        Ok(())
    }
}

/// Parse an ISO 8601 date string
fn parse_date(s: &str) -> Result<DateTime<Utc>> {
    s.parse::<DateTime<Utc>>()
        .context("Invalid date format (use ISO 8601, e.g., 2026-01-01T00:00:00Z)")
}

/// Parse a duration string (e.g., "90d", "1y")
fn parse_duration(s: &str) -> Result<Duration> {
    let num_str = s.trim_end_matches(|c: char| !c.is_ascii_digit());
    let unit = s.trim_start_matches(num_str);

    let num: i64 = num_str.parse().context("Invalid duration format")?;

    let duration = match unit {
        "s" | "sec" | "second" | "seconds" => Duration::seconds(num),
        "m" | "min" | "minute" | "minutes" => Duration::minutes(num),
        "h" | "hour" | "hours" => Duration::hours(num),
        "d" | "day" | "days" => Duration::days(num),
        "w" | "week" | "weeks" => Duration::weeks(num),
        "y" | "year" | "years" => Duration::days(num * 365),
        _ => anyhow::bail!("Unknown duration unit: {}", unit),
    };

    Ok(duration)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_duration() {
        assert_eq!(parse_duration("90d").unwrap(), Duration::days(90));
        assert_eq!(parse_duration("1h").unwrap(), Duration::hours(1));
        assert_eq!(parse_duration("30m").unwrap(), Duration::minutes(30));
        assert_eq!(parse_duration("1y").unwrap(), Duration::days(365));
    }

    #[test]
    fn test_output_format_to_export_format() {
        assert!(matches!(OutputFormat::Json.into(), ExportFormat::Json));
        assert!(matches!(OutputFormat::Csv.into(), ExportFormat::Csv));
    }
}
