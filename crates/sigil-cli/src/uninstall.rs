//! Lifecycle management for SIGIL installation
//!
//! This module handles uninstallation and cleanup of SIGIL components.

use anyhow::{Context, Result};
use serde_json::Value;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::Command;

/// Uninstall options
#[derive(Default)]
pub struct UninstallOptions {
    /// Preview what would be removed without making changes
    pub dry_run: bool,
    /// Remove only hooks (keep vault and daemon)
    pub hooks_only: bool,
    /// Remove only runtime artifacts (socket, lockfile, tmpfs)
    pub runtime_only: bool,
    /// Remove only vault data
    pub vault_only: bool,
    /// Remove everything EXCEPT vault data
    #[allow(dead_code)]
    pub keep_vault: bool,
    /// Remove everything including vault (requires passphrase)
    pub purge: bool,
}

/// Uninstall SIGIL components
pub fn uninstall(opts: UninstallOptions) -> Result<UninstallResult> {
    let mut result = UninstallResult::default();

    // Get SIGIL directory
    let home =
        dirs::home_dir().ok_or_else(|| anyhow::anyhow!("Cannot determine home directory"))?;
    let sigil_dir = home.join(".sigil");

    if !sigil_dir.exists() {
        println!("No SIGIL installation found at {}", sigil_dir.display());
        return Ok(result);
    }

    // Handle different uninstall modes
    if opts.vault_only {
        return uninstall_vault_only(&sigil_dir, opts.dry_run, &mut result);
    }

    if opts.runtime_only {
        return uninstall_runtime_only(&home, opts.dry_run, &mut result);
    }

    if opts.hooks_only {
        return uninstall_hooks_only(&home, opts.dry_run, &mut result);
    }

    if opts.purge {
        return uninstall_purge(&sigil_dir, &home, opts.dry_run, &mut result);
    }

    // Default: remove everything except vault
    uninstall_keep_vault(&sigil_dir, &home, opts.dry_run, &mut result)
}

/// Remove only the vault
fn uninstall_vault_only(
    sigil_dir: &Path,
    dry_run: bool,
    result: &mut UninstallResult,
) -> Result<UninstallResult> {
    let vault_path = sigil_dir.join("vault");

    if vault_path.exists() {
        if dry_run {
            println!("Would remove: {}", vault_path.display());
            result
                .would_remove
                .push(vault_path.to_string_lossy().to_string());
        } else {
            fs::remove_dir_all(&vault_path)?;
            println!("Removed vault: {}", vault_path.display());
            result
                .removed
                .push(vault_path.to_string_lossy().to_string());
        }
    }

    Ok(result.clone())
}

/// Remove only runtime artifacts
fn uninstall_runtime_only(
    _home: &Path,
    dry_run: bool,
    result: &mut UninstallResult,
) -> Result<UninstallResult> {
    // Remove socket (if it exists)
    if let Some(runtime_dir) = std::env::var_os("XDG_RUNTIME_DIR") {
        let runtime_dir = PathBuf::from(runtime_dir);
        let socket_path = runtime_dir.join("sigil.sock");

        if socket_path.exists() {
            if dry_run {
                println!("Would remove: {}", socket_path.display());
                result
                    .would_remove
                    .push(socket_path.to_string_lossy().to_string());
            } else {
                fs::remove_file(&socket_path)?;
                println!("Removed socket: {}", socket_path.display());
                result
                    .removed
                    .push(socket_path.to_string_lossy().to_string());
            }
        }

        let lockfile_path = runtime_dir.join("sigil.lock");
        if lockfile_path.exists() {
            if dry_run {
                println!("Would remove: {}", lockfile_path.display());
                result
                    .would_remove
                    .push(lockfile_path.to_string_lossy().to_string());
            } else {
                fs::remove_file(&lockfile_path)?;
                println!("Removed lockfile: {}", lockfile_path.display());
                result
                    .removed
                    .push(lockfile_path.to_string_lossy().to_string());
            }
        }
    }

    Ok(result.clone())
}

/// Remove only hooks (Claude Code, git credential helper, SSH config)
fn uninstall_hooks_only(
    home: &Path,
    dry_run: bool,
    result: &mut UninstallResult,
) -> Result<UninstallResult> {
    // Remove Claude Code hooks
    remove_claude_code_hooks(dry_run, result)?;

    // Remove git credential helper
    remove_git_credential_helper(dry_run, result)?;

    // Remove SSH config entries
    remove_ssh_config_entries(home, dry_run, result)?;

    Ok(result.clone())
}

/// Remove Claude Code hooks from settings.json
fn remove_claude_code_hooks(dry_run: bool, result: &mut UninstallResult) -> Result<()> {
    let config_dir = dirs::config_local_dir()
        .ok_or_else(|| anyhow::anyhow!("Cannot determine config directory"))?
        .join("claude-code");

    let settings_path = config_dir.join("settings.json");

    if !settings_path.exists() {
        return Ok(());
    }

    // Read existing settings
    let content = fs::read_to_string(&settings_path).context("Failed to read settings.json")?;

    let mut settings: Value =
        serde_json::from_str(&content).context("Failed to parse settings.json")?;

    // Check if hooks exist
    let has_hooks = settings.get("hooks").is_some();

    if has_hooks {
        if dry_run {
            println!(
                "Would remove: Claude Code hooks from {}",
                settings_path.display()
            );
            result.would_remove.push("claude-code hooks".to_string());
        } else {
            // Remove the hooks key
            if let Some(obj) = settings.as_object_mut() {
                obj.remove("hooks");
            }

            // Write back the settings
            let settings_content = if settings.as_object().is_some_and(|o| !o.is_empty()) {
                serde_json::to_string_pretty(&settings).context("Failed to serialize settings")?
            } else {
                // If empty, write empty object
                "{}".to_string()
            };

            fs::write(&settings_path, settings_content).context("Failed to write settings.json")?;

            println!(
                "Removed: Claude Code hooks from {}",
                settings_path.display()
            );
            result.removed.push("claude-code hooks".to_string());
        }
    }

    Ok(())
}

/// Remove git credential helper configuration
fn remove_git_credential_helper(dry_run: bool, result: &mut UninstallResult) -> Result<()> {
    // Check if SIGIL is configured as the credential helper
    let output = Command::new("git")
        .args(["config", "--global", "credential.helper"])
        .output();

    let is_sigil_helper = match output {
        Ok(out) => {
            if out.status.success() {
                let helper = String::from_utf8_lossy(&out.stdout);
                helper.trim().contains("sigil-credential-git")
            } else {
                false
            }
        }
        Err(_) => false,
    };

    if is_sigil_helper {
        if dry_run {
            println!("Would remove: git credential helper configuration");
            result
                .would_remove
                .push("git credential helper".to_string());
        } else {
            // Unset the credential helper
            let output = Command::new("git")
                .args(["config", "--global", "--unset", "credential.helper"])
                .output()?;

            if output.status.success() {
                println!("Removed: git credential helper configuration");
                result.removed.push("git credential helper".to_string());
            } else {
                println!("Warning: Failed to remove git credential helper");
            }
        }
    }

    Ok(())
}

/// Remove SIGIL SSH agent entries from SSH config
fn remove_ssh_config_entries(
    home: &Path,
    dry_run: bool,
    result: &mut UninstallResult,
) -> Result<()> {
    let ssh_dir = home.join(".ssh");
    let config_file = ssh_dir.join("config");

    if !config_file.exists() {
        return Ok(());
    }

    // Read existing config
    let existing_config = fs::read_to_string(&config_file).context("Failed to read SSH config")?;

    // Check if SIGIL entry exists
    if !existing_config.contains("# SIGIL SSH agent") {
        return Ok(());
    }

    if dry_run {
        println!(
            "Would remove: SIGIL SSH agent entries from {}",
            config_file.display()
        );
        result.would_remove.push("ssh config entries".to_string());
        return Ok(());
    }

    // Remove SIGIL section (from marker to end of that section)
    let lines: Vec<&str> = existing_config.lines().collect();
    let mut new_lines = Vec::new();
    let mut skipping = false;
    let mut found_sigil_section = false;

    for line in lines {
        if line.contains("# SIGIL SSH agent") {
            skipping = true;
            found_sigil_section = true;
            continue;
        }

        // Skip until we hit another Host directive or empty line followed by non-empty
        if skipping {
            if line.starts_with("Host ") || (line.is_empty() && !skipping) {
                skipping = false;
                new_lines.push(line);
            }
            // Continue skipping while in SIGIL section
        } else {
            new_lines.push(line);
        }
    }

    if found_sigil_section {
        // Remove trailing empty lines
        while new_lines.last().is_some_and(|l| l.is_empty()) {
            new_lines.pop();
        }

        let new_config = new_lines.join("\n");

        // Write back the config
        fs::write(
            &config_file,
            if new_config.is_empty() {
                ""
            } else {
                &new_config
            },
        )
        .context("Failed to write SSH config")?;

        println!(
            "Removed: SIGIL SSH agent entries from {}",
            config_file.display()
        );
        result.removed.push("ssh config entries".to_string());
    }

    Ok(())
}

/// Remove everything including vault
fn uninstall_purge(
    sigil_dir: &Path,
    home: &Path,
    dry_run: bool,
    result: &mut UninstallResult,
) -> Result<UninstallResult> {
    println!("WARNING: This will remove ALL SIGIL data including your vault!");
    println!("This cannot be undone.");

    if !dry_run {
        print!("Type 'yes' to confirm: ");
        std::io::stdout().flush()?;
        let mut input = String::new();
        std::io::stdin().read_line(&mut input)?;
        if input.trim() != "yes" {
            println!("Aborted.");
            return Ok(result.clone());
        }
    }

    // Remove runtime artifacts first
    uninstall_runtime_only(home, dry_run, result)?;

    // Remove the entire .sigil directory
    if dry_run {
        println!("Would remove: {}", sigil_dir.display());
        result
            .would_remove
            .push(sigil_dir.to_string_lossy().to_string());
    } else {
        fs::remove_dir_all(sigil_dir)?;
        println!("Removed SIGIL directory: {}", sigil_dir.display());
        result.removed.push(sigil_dir.to_string_lossy().to_string());
    }

    Ok(result.clone())
}

/// Remove everything except vault
fn uninstall_keep_vault(
    sigil_dir: &Path,
    home: &Path,
    dry_run: bool,
    result: &mut UninstallResult,
) -> Result<UninstallResult> {
    // Remove runtime artifacts
    uninstall_runtime_only(home, dry_run, result)?;

    // Remove everything except vault
    if sigil_dir.exists() {
        let entries = fs::read_dir(sigil_dir)?;

        for entry in entries {
            let entry = entry?;
            let path = entry.path();

            // Skip vault directory
            if path.ends_with("vault") {
                continue;
            }

            if dry_run {
                println!("Would remove: {}", path.display());
                result.would_remove.push(path.to_string_lossy().to_string());
            } else {
                if path.is_dir() {
                    fs::remove_dir_all(&path)?;
                } else {
                    fs::remove_file(&path)?;
                }
                println!("Removed: {}", path.display());
                result.removed.push(path.to_string_lossy().to_string());
            }
        }
    }

    Ok(result.clone())
}

/// Result of an uninstall operation
#[derive(Debug, Clone, Default)]
pub struct UninstallResult {
    /// Items that were removed
    pub removed: Vec<String>,
    /// Items that would be removed (dry-run mode)
    pub would_remove: Vec<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_uninstall_options_default() {
        let opts = UninstallOptions::default();
        assert!(!opts.dry_run);
        assert!(!opts.hooks_only);
        assert!(!opts.runtime_only);
        assert!(!opts.vault_only);
        assert!(!opts.keep_vault);
        assert!(!opts.purge);
    }
}
