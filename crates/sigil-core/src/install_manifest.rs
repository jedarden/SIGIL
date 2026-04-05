//! Install manifest tracking for SIGIL lifecycle management
//!
//! This module provides the install manifest structure and operations
//! for tracking all SIGIL artifacts (hooks, configs, binaries, etc.)
//! for proper uninstallation.

use crate::error::{Result, SigilError};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};

/// Install manifest tracking all SIGIL artifacts
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct InstallManifest {
    /// Binary installation info
    #[serde(default)]
    pub binary: BinaryInfo,
    /// Hook configurations
    #[serde(default)]
    pub hooks: HookInfo,
    /// Canary monitoring state
    #[serde(default)]
    pub canaries: CanaryInfo,
    /// Runtime artifacts
    #[serde(default)]
    pub runtime: RuntimeInfo,
    /// Vault information
    #[serde(default)]
    pub vault: VaultInfo,
}

/// Binary installation information
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct BinaryInfo {
    /// Path to the main binary
    pub path: Option<String>,
    /// Symlinks created
    #[serde(default)]
    pub symlinks: Vec<String>,
    /// Installation timestamp
    pub installed_at: Option<DateTime<Utc>>,
}

/// Hook configuration information
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct HookInfo {
    /// Claude Code settings path
    pub claude_code: Option<String>,
    /// systemd socket unit path
    pub systemd_socket: Option<String>,
    /// systemd service unit path
    pub systemd_service: Option<String>,
    /// launchd plist path
    pub launchd_plist: Option<String>,
    /// Git credential helper configured
    pub git_credential: bool,
    /// SSH config modified
    pub ssh_config: bool,
    /// Docker config modified
    pub docker_config: bool,
}

/// Canary monitoring information
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct CanaryInfo {
    /// Whether canary monitoring is active
    pub monitoring_active: bool,
}

/// Runtime artifact information
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct RuntimeInfo {
    /// Unix socket path
    pub socket: Option<String>,
    /// Lockfile path
    pub lockfile: Option<String>,
    /// Tmpfs directory path
    pub tmpfs_dir: Option<String>,
    /// FUSE mount path
    pub fuse_mount: Option<String>,
}

/// Vault information
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct VaultInfo {
    /// Vault directory path
    pub path: Option<String>,
    /// Sealed vault path
    pub sealed_path: Option<String>,
    /// Device key path
    pub device_key: Option<String>,
}

impl InstallManifest {
    /// Get the default manifest path
    pub fn default_path() -> Result<PathBuf> {
        let home = std::env::var("HOME")
            .map_err(|_| SigilError::IoError("Cannot determine home directory".to_string()))?;
        Ok(PathBuf::from(home).join(".sigil/install-manifest.toml"))
    }

    /// Load the manifest from the default path
    pub fn load() -> Result<Self> {
        let path = Self::default_path()?;
        Self::load_from(&path)
    }

    /// Load the manifest from a specific path
    pub fn load_from(path: &Path) -> Result<Self> {
        if !path.exists() {
            return Ok(Self::default());
        }

        let content = fs::read_to_string(path).map_err(|e| {
            SigilError::IoError(format!(
                "Failed to read manifest from {}: {}",
                path.display(),
                e
            ))
        })?;

        toml::from_str(&content)
            .map_err(|e| SigilError::SerializationError(format!("Failed to parse manifest: {}", e)))
    }

    /// Save the manifest to the default path
    pub fn save(&self) -> Result<()> {
        let path = Self::default_path()?;
        self.save_to(&path)
    }

    /// Save the manifest to a specific path
    pub fn save_to(&self, path: &Path) -> Result<()> {
        // Ensure parent directory exists
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).map_err(|e| {
                SigilError::IoError(format!(
                    "Failed to create manifest directory {}: {}",
                    parent.display(),
                    e
                ))
            })?;
        }

        let content = toml::to_string_pretty(self).map_err(|e| {
            SigilError::SerializationError(format!("Failed to serialize manifest: {}", e))
        })?;

        fs::write(path, content).map_err(|e| {
            SigilError::IoError(format!(
                "Failed to write manifest to {}: {}",
                path.display(),
                e
            ))
        })?;

        Ok(())
    }

    /// Update binary installation info
    pub fn update_binary(&mut self, path: String) {
        self.binary.path = Some(path);
        self.binary.installed_at = Some(Utc::now());
    }

    /// Add a symlink to the manifest
    pub fn add_symlink(&mut self, symlink: String) {
        if !self.binary.symlinks.contains(&symlink) {
            self.binary.symlinks.push(symlink);
        }
    }

    /// Update hook configuration
    pub fn update_hook(&mut self, hook_type: HookType, path: Option<String>) {
        match hook_type {
            HookType::ClaudeCode => self.hooks.claude_code = path,
            HookType::SystemdSocket => self.hooks.systemd_socket = path,
            HookType::SystemdService => self.hooks.systemd_service = path,
            HookType::Launchd => self.hooks.launchd_plist = path,
            HookType::GitCredential => self.hooks.git_credential = path.is_some(),
            HookType::SshConfig => self.hooks.ssh_config = path.is_some(),
            HookType::DockerConfig => self.hooks.docker_config = path.is_some(),
        }
    }

    /// Update runtime artifact path
    pub fn update_runtime(&mut self, artifact: RuntimeArtifact, path: String) {
        match artifact {
            RuntimeArtifact::Socket => self.runtime.socket = Some(path),
            RuntimeArtifact::Lockfile => self.runtime.lockfile = Some(path),
            RuntimeArtifact::TmpfsDir => self.runtime.tmpfs_dir = Some(path),
            RuntimeArtifact::FuseMount => self.runtime.fuse_mount = Some(path),
        }
    }

    /// Update vault information
    pub fn update_vault(&mut self, path: String) {
        self.vault.path = Some(path);
    }

    /// Set canary monitoring state
    pub fn set_canary_monitoring(&mut self, active: bool) {
        self.canaries.monitoring_active = active;
    }

    /// Check if the manifest indicates a complete installation
    pub fn is_installed(&self) -> bool {
        self.binary.path.is_some() || self.vault.path.is_some()
    }
}

/// Hook type identifiers
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HookType {
    /// Claude Code settings.json
    ClaudeCode,
    /// systemd socket unit
    SystemdSocket,
    /// systemd service unit
    SystemdService,
    /// launchd plist
    Launchd,
    /// Git credential helper
    GitCredential,
    /// SSH config modification
    SshConfig,
    /// Docker config modification
    DockerConfig,
}

/// Runtime artifact identifiers
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuntimeArtifact {
    /// Unix domain socket
    Socket,
    /// Lockfile
    Lockfile,
    /// Temporary filesystem directory
    TmpfsDir,
    /// FUSE mount point
    FuseMount,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_manifest_default() {
        let manifest = InstallManifest::default();
        assert!(!manifest.is_installed());
    }

    #[test]
    fn test_manifest_binary_update() {
        let mut manifest = InstallManifest::default();
        manifest.update_binary("/usr/local/bin/sigil".to_string());
        assert!(manifest.is_installed());
        assert_eq!(
            manifest.binary.path,
            Some("/usr/local/bin/sigil".to_string())
        );
    }

    #[test]
    fn test_manifest_symlink() {
        let mut manifest = InstallManifest::default();
        manifest.add_symlink("/usr/local/bin/sigil-shell".to_string());
        assert_eq!(manifest.binary.symlinks.len(), 1);
        // Adding same symlink twice should not duplicate
        manifest.add_symlink("/usr/local/bin/sigil-shell".to_string());
        assert_eq!(manifest.binary.symlinks.len(), 1);
    }

    #[test]
    fn test_manifest_hooks() {
        let mut manifest = InstallManifest::default();
        manifest.update_hook(
            HookType::ClaudeCode,
            Some("/home/user/.claude/settings.json".to_string()),
        );
        assert_eq!(
            manifest.hooks.claude_code,
            Some("/home/user/.claude/settings.json".to_string())
        );
    }

    #[test]
    fn test_manifest_vault() {
        let mut manifest = InstallManifest::default();
        manifest.update_vault("/home/user/.sigil/vault".to_string());
        assert!(manifest.is_installed());
        assert_eq!(
            manifest.vault.path,
            Some("/home/user/.sigil/vault".to_string())
        );
    }
}
