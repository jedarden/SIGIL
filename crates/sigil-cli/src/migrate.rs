//! Migration infrastructure for SIGIL data formats
//!
//! This module handles version upgrades for all persistent formats:
//! - Vault directory metadata
//! - vault.sealed header
//! - IPC protocol
//! - .sigil archive
//! - config.toml
//! - audit.jsonl

use anyhow::Result;
use chrono::Utc;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

/// Current format versions
#[allow(dead_code)]
pub mod versions {
    /// Vault directory metadata format version
    pub const VAULT_METADATA: u16 = 1;

    /// vault.sealed format version
    pub const VAULT_SEALED: u16 = 1;

    /// IPC protocol version
    pub const IPC_PROTOCOL: u16 = 1;

    /// .sigil archive format version
    pub const ARCHIVE: u16 = 1;

    /// config.toml format version
    pub const CONFIG: u16 = 1;

    /// audit.jsonl schema version
    pub const AUDIT: u16 = 1;
}

/// Migration status for a format
#[derive(Debug, Clone)]
pub struct MigrationStatus {
    /// Format name
    pub name: String,
    /// Current version (0 if format doesn't exist)
    pub current_version: u16,
    /// Target version
    pub target_version: u16,
    /// Whether migration is needed
    pub needs_migration: bool,
}

/// Migration result
#[derive(Debug)]
#[allow(dead_code)]
pub struct MigrationResult {
    /// Formats that were migrated
    pub migrated: Vec<String>,
    /// Formats that were already up to date
    pub up_to_date: Vec<String>,
    /// Formats that failed to migrate
    pub failed: Vec<(String, String)>,
    /// Backup path (if created)
    pub backup_path: Option<PathBuf>,
}

/// Create a backup of the vault directory
fn create_backup(vault_path: &Path) -> Result<PathBuf> {
    let sigil_dir = vault_path
        .parent()
        .ok_or_else(|| anyhow::anyhow!("Cannot determine SIGIL directory"))?;

    let backups_dir = sigil_dir.join("backups");
    fs::create_dir_all(&backups_dir)?;

    let timestamp = Utc::now().format("%Y%m%dT%H%M%S");
    let backup_name = format!("pre-migrate-{}", timestamp);
    let backup_path = backups_dir.join(&backup_name);

    // Copy the vault directory recursively
    if vault_path.exists() {
        fs_extra::dir::copy(vault_path, &backup_path, &fs_extra::dir::CopyOptions::new())
            .map_err(|e| anyhow::anyhow!("Failed to create backup: {}", e))?;
    } else {
        // If vault doesn't exist, create an empty backup marker
        fs::create_dir(&backup_path)?;
    }

    println!("Created backup: {}", backup_path.display());
    Ok(backup_path)
}

/// Check migration status for all formats
pub fn check_migration_status(vault_path: &Path) -> Result<Vec<MigrationStatus>> {
    let mut statuses = Vec::new();

    // Check vault metadata format
    let metadata_path = vault_path.join("metadata.json.age");
    let current_vault_version = if metadata_path.exists() {
        versions::VAULT_METADATA
    } else {
        0
    };
    statuses.push(MigrationStatus {
        name: "vault metadata".to_string(),
        current_version: current_vault_version,
        target_version: versions::VAULT_METADATA,
        needs_migration: false, // Currently at v1, no migration needed
    });

    // Check config format
    let sigil_dir = vault_path
        .parent()
        .ok_or_else(|| anyhow::anyhow!("Cannot determine SIGIL directory"))?;
    let config_path = sigil_dir.join("config.toml");
    let current_config_version = if config_path.exists() {
        versions::CONFIG
    } else {
        0
    };
    statuses.push(MigrationStatus {
        name: "config.toml".to_string(),
        current_version: current_config_version,
        target_version: versions::CONFIG,
        needs_migration: false, // Currently at v1, no migration needed
    });

    Ok(statuses)
}

/// Run migrations for all formats
pub fn run_migrations(
    vault_path: &Path,
    dry_run: bool,
    auto_mode: bool,
) -> Result<MigrationResult> {
    let statuses = check_migration_status(vault_path)?;

    let mut result = MigrationResult {
        migrated: Vec::new(),
        up_to_date: Vec::new(),
        failed: Vec::new(),
        backup_path: None,
    };

    // Check if any migrations are needed
    let needs_migration: Vec<_> = statuses.iter().filter(|s| s.needs_migration).collect();

    if needs_migration.is_empty() {
        println!("All formats are up to date. No migration needed.");
        for status in statuses {
            result.up_to_date.push(status.name);
        }
        return Ok(result);
    }

    // Show what needs migration
    println!("Migration status:");
    for status in &statuses {
        if status.needs_migration {
            println!(
                "  {}: v{} → v{} (needs migration)",
                status.name, status.current_version, status.target_version
            );
        } else {
            println!(
                "  {}: v{} (up to date)",
                status.name, status.current_version
            );
        }
    }
    println!();

    if dry_run {
        println!("Dry run mode - no changes will be made.");
        println!("Run 'sigil migrate' to apply migrations.");
        return Ok(result);
    }

    // Auto mode: skip confirmation if no destructive changes
    let has_destructive = needs_migration
        .iter()
        .any(|s| s.target_version > s.current_version + 1);

    if !auto_mode || has_destructive {
        println!("This will create a backup and migrate the formats listed above.");
        print!("Continue? [y/N]: ");
        std::io::stdout().flush()?;
        let mut input = String::new();
        std::io::stdin().read_line(&mut input)?;
        if !input.trim().to_lowercase().starts_with('y') {
            println!("Migration cancelled.");
            return Ok(result);
        }
    }

    // Create backup
    result.backup_path = Some(create_backup(vault_path)?);

    // Run migrations (dependency order: vault before config, config before audit)
    // Currently no migrations to run, but the infrastructure is in place
    println!("No migrations to run (all formats at current version).");

    for status in statuses {
        if status.needs_migration {
            result.migrated.push(status.name);
        } else {
            result.up_to_date.push(status.name);
        }
    }

    println!("\nMigration completed successfully!");
    println!("Backup: {}", result.backup_path.as_ref().unwrap().display());

    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_migration_status_on_nonexistent_vault() {
        let temp_dir = tempfile::tempdir().unwrap();
        let vault_path = temp_dir.path().join("vault");

        let statuses = check_migration_status(&vault_path).unwrap();
        assert!(!statuses.is_empty());

        // Vault metadata should not exist
        let vault_status = statuses
            .iter()
            .find(|s| s.name == "vault metadata")
            .unwrap();
        assert_eq!(vault_status.current_version, 0);
    }
}
