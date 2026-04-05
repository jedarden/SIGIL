//! FUSE mount/unmount utilities
//!
//! This module provides utilities for mounting and unmounting the SIGIL FUSE filesystem.

use crate::filesystem::SigilFs;
use crate::FuseConfig;
use anyhow::{Context, Result};
use fuser::{MountOption, Session};
use std::path::Path;
use tracing::{info, warn};

/// Mount the SIGIL FUSE filesystem
///
/// # Arguments
///
/// * `config` - FUSE configuration
///
/// # Returns
///
/// Returns a FUSE session that can be used to unmount later
pub async fn mount_sigil(config: FuseConfig) -> Result<Session> {
    let mount_point = &config.mount_point;

    // Create mount point if it doesn't exist
    if !mount_point.exists() {
        std::fs::create_dir_all(mount_point)
            .with_context(|| format!("Failed to create mount point {}", mount_point.display()))?;
    }

    // Verify mount point is a directory
    if !mount_point.is_dir() {
        return Err(anyhow::anyhow!(
            "Mount point {} is not a directory",
            mount_point.display()
        ));
    }

    // Check if already mounted
    if is_mounted(mount_point)? {
        warn!(
            "Mount point {} is already mounted, attempting to unmount first",
            mount_point.display()
        );
        unmount_sigil(mount_point)?;
    }

    // Create the filesystem
    let fs = SigilFs::new(config.clone())
        .await
        .context("Failed to create FUSE filesystem")?;

    // Configure mount options
    let mut options = vec![
        MountOption::RO,             // Read-only
        MountOption::FSName("sigil".to_string()), // Filesystem name
        MountOption::NoAtime,        // Don't update access time
    ];

    // Add allow_other if allowed GIDs are specified
    if !config.allowed_gids.is_empty() {
        options.push(MountOption::AllowOther);
        for gid in &config.allowed_gids {
            options.push(MountOption::GID(*gid));
        }
    }

    // Add UID/GID restrictions if specified
    if let Some(uid) = config.sandbox_uid {
        options.push(MountOption::UID(uid));
    }

    // Mount the filesystem
    info!("Mounting SIGIL FUSE at {}", mount_point.display());

    let session = Session::new(fs, mount_point, &options)
        .with_context(|| format!("Failed to mount FUSE at {}", mount_point.display()))?;

    info!("SIGIL FUSE mounted successfully at {}", mount_point.display());

    Ok(session)
}

/// Unmount the SIGIL FUSE filesystem
///
/// # Arguments
///
/// * `mount_point` - Path to the mount point
///
/// # Returns
///
/// Returns Ok(()) if unmount succeeded or was not mounted
pub fn unmount_sigil(mount_point: &Path) -> Result<()> {
    if !mount_point.exists() {
        warn!(
            "Mount point {} does not exist, nothing to unmount",
            mount_point.display()
        );
        return Ok(());
    }

    // Check if mounted
    if !is_mounted(mount_point)? {
        info!(
            "Mount point {} is not mounted",
            mount_point.display()
        );
        return Ok(());
    }

    info!("Unmounting SIGIL FUSE at {}", mount_point.display());

    // Use fuser's unmount function
    fuser::unmount(mount_point)
        .with_context(|| format!("Failed to unmount {}", mount_point.display()))?;

    info!("SIGIL FUSE unmounted successfully");

    Ok(())
}

/// Check if a path is currently mounted
///
/// # Arguments
///
/// * `path` - Path to check
///
/// # Returns
///
/// Returns true if the path is a mount point
fn is_mounted(path: &Path) -> Result<bool> {
    // Read /proc/mounts on Linux
    if Path::new("/proc/mounts").exists() {
        let mounts = std::fs::read_to_string("/proc/mounts")?;
        let path_str = path.to_str().unwrap_or("");
        return Ok(mounts.lines().any(|line| {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 2 {
                parts[1] == path_str
            } else {
                false
            }
        }));
    }

    // Fallback: try to get mount info from stat
    // This is less reliable but works on non-Linux systems
    if let Ok(metadata) = std::fs::metadata(path) {
        // Check if device is different from parent
        if let Some(parent) = path.parent() {
            if let Ok(parent_metadata) = std::fs::metadata(parent) {
                // Use std::os::unix::fs::MetadataExt to get device numbers
                #[cfg(unix)]
                {
                    use std::os::unix::fs::MetadataExt;
                    return Ok(metadata.dev() != parent_metadata.dev());
                }
            }
        }
    }

    Ok(false)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn test_is_mounted_nonexistent() {
        assert!(!is_mounted(Path::new("/nonexistent/path")).unwrap());
    }

    #[test]
    fn test_is_mounted_temp_dir() {
        let temp_dir = TempDir::new().unwrap();
        // Temp dir is not a mount point
        assert!(!is_mounted(temp_dir.path()).unwrap());
    }
}
