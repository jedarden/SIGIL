//! Signature update functionality
//!
//! Fetches and updates command signatures from a remote repository.
//! Supports:
//! - Fetching from GitHub repositories
//! - Checksum verification
//! - Version checking
//! - Curated set installation

use anyhow::{anyhow, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;

/// Default signature repository URL
pub const DEFAULT_REPO_URL: &str = "https://github.com/jedarden/sigil-signatures";

/// Raw content URL base for GitHub
pub const GITHUB_RAW_BASE: &str =
    "https://raw.githubusercontent.com/jedarden/sigil-signatures/main";

/// Signature manifest structure
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct SignatureManifest {
    /// Version of the signature database
    pub version: String,

    /// Signature sets available
    #[serde(default)]
    pub sets: HashMap<String, SignatureSet>,

    /// Individual signature files with checksums
    #[serde(default)]
    pub signatures: HashMap<String, SignatureFile>,
}

/// A curated set of signatures (e.g., "cloud", "databases")
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct SignatureSet {
    /// Display name
    pub name: String,

    /// Description
    pub description: String,

    /// List of signature files in this set
    pub files: Vec<String>,
}

/// Metadata about a signature file
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct SignatureFile {
    /// Relative path in the repository
    pub path: String,

    /// SHA256 checksum of the file contents
    pub checksum: String,

    /// Category (cloud, databases, devtools, etc.)
    #[serde(default)]
    pub category: String,

    /// Display name
    #[serde(default)]
    pub name: String,

    /// Description
    #[serde(default)]
    pub description: String,
}

/// Configuration for signature updates
#[derive(Debug, Clone)]
pub struct UpdateConfig {
    /// Repository URL
    pub repo_url: String,

    /// Base URL for raw content
    pub raw_base: String,

    /// Local directory for storing signatures
    pub local_dir: PathBuf,

    /// Whether to verify checksums
    pub verify_checksums: bool,

    /// Force update even if version is same
    pub force: bool,

    /// Dry run - don't actually download
    pub dry_run: bool,
}

impl Default for UpdateConfig {
    fn default() -> Self {
        let home = dirs::home_dir().unwrap_or_else(|| PathBuf::from("."));
        Self {
            repo_url: DEFAULT_REPO_URL.to_string(),
            raw_base: GITHUB_RAW_BASE.to_string(),
            local_dir: home.join(".sigil").join("signatures.d"),
            verify_checksums: true,
            force: false,
            dry_run: false,
        }
    }
}

impl UpdateConfig {
    /// Create a new update config
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the repository URL
    pub fn with_repo_url(mut self, url: String) -> Self {
        // Derive raw base URL from repo URL
        if let Some(stripped) = url.strip_prefix("https://github.com/") {
            self.raw_base = format!("https://raw.githubusercontent.com/{}/main", stripped);
        }
        self.repo_url = url;
        self
    }

    /// Set the local directory
    pub fn with_local_dir(mut self, dir: PathBuf) -> Self {
        self.local_dir = dir;
        self
    }

    /// Enable or disable checksum verification
    pub fn with_verify_checksums(mut self, verify: bool) -> Self {
        self.verify_checksums = verify;
        self
    }

    /// Set force mode
    pub fn with_force(mut self, force: bool) -> Self {
        self.force = force;
        self
    }

    /// Set dry run mode
    pub fn with_dry_run(mut self, dry_run: bool) -> Self {
        self.dry_run = dry_run;
        self
    }
}

/// Signature update manager
pub struct SignatureUpdater {
    config: UpdateConfig,
}

impl SignatureUpdater {
    /// Create a new updater with default config
    pub fn new() -> Result<Self> {
        Ok(Self {
            config: UpdateConfig::default(),
        })
    }

    /// Create a new updater with custom config
    pub fn with_config(config: UpdateConfig) -> Self {
        Self { config }
    }

    /// Fetch the manifest from the remote repository
    pub fn fetch_manifest(&self) -> Result<SignatureManifest> {
        let manifest_url = format!("{}/manifest.toml", self.config.raw_base);

        tracing::debug!("Fetching manifest from: {}", manifest_url);

        let response = ureq::get(&manifest_url)
            .timeout(std::time::Duration::from_secs(30))
            .call()
            .map_err(|e| anyhow!("Failed to fetch manifest: {}", e))?;

        let status = response.status();
        if !(200..300).contains(&status) {
            return Err(anyhow!("Failed to fetch manifest: HTTP {}", status));
        }

        let body = response.into_string()?;
        let manifest: SignatureManifest =
            toml::from_str(&body).map_err(|e| anyhow!("Failed to parse manifest: {}", e))?;

        Ok(manifest)
    }

    /// Check if an update is available
    pub fn check_update(&self) -> Result<UpdateInfo> {
        let remote_manifest = self.fetch_manifest()?;

        // Read local manifest if it exists
        let local_manifest = self.read_local_manifest()?;

        let local_version = local_manifest.as_ref().map(|m| m.version.clone());
        let remote_version = remote_manifest.version.clone();

        let needs_update = match (&local_version, &remote_version) {
            (Some(local), remote) => {
                // Parse versions
                let local_v = semver::Version::parse(local).ok();
                let remote_v = semver::Version::parse(remote).ok();

                match (local_v, remote_v) {
                    (Some(l), Some(r)) => r > l,
                    _ => local != remote,
                }
            }
            (None, _) => true,
        };

        Ok(UpdateInfo {
            local_version,
            remote_version,
            needs_update,
            manifest: remote_manifest,
        })
    }

    /// Read the local manifest file
    fn read_local_manifest(&self) -> Result<Option<SignatureManifest>> {
        let manifest_path = self.config.local_dir.join("manifest.toml");

        if !manifest_path.exists() {
            return Ok(None);
        }

        let content = fs::read_to_string(&manifest_path)?;
        let manifest: SignatureManifest = toml::from_str(&content)?;

        Ok(Some(manifest))
    }

    /// Write the local manifest file
    fn write_local_manifest(&self, manifest: &SignatureManifest) -> Result<()> {
        let manifest_path = self.config.local_dir.join("manifest.toml");

        // Create directory if it doesn't exist
        if let Some(parent) = manifest_path.parent() {
            fs::create_dir_all(parent)?;
        }

        let content = toml::to_string_pretty(manifest)?;
        fs::write(&manifest_path, content)?;

        Ok(())
    }

    /// Download a single signature file
    fn download_signature(&self, file: &SignatureFile) -> Result<String> {
        let file_url = format!("{}/{}", self.config.raw_base, file.path);

        tracing::debug!("Downloading signature from: {}", file_url);

        let response = ureq::get(&file_url)
            .timeout(std::time::Duration::from_secs(30))
            .call()
            .map_err(|e| anyhow!("Failed to download {}: {}", file.path, e))?;

        let status = response.status();
        if !(200..300).contains(&status) {
            return Err(anyhow!("Failed to download {}: HTTP {}", file.path, status));
        }

        let content = response.into_string()?;

        // Verify checksum if enabled
        if self.config.verify_checksums {
            let checksum = Self::compute_checksum(&content);
            if checksum != file.checksum {
                return Err(anyhow!(
                    "Checksum mismatch for {}: expected {}, got {}",
                    file.path,
                    file.checksum,
                    checksum
                ));
            }
        }

        Ok(content)
    }

    /// Compute SHA256 checksum of content
    fn compute_checksum(content: &str) -> String {
        let mut hasher = Sha256::new();
        hasher.update(content.as_bytes());
        hex::encode(hasher.finalize())
    }

    /// Write a signature file to the local directory
    fn write_signature(&self, filename: &str, content: &str) -> Result<()> {
        let file_path = self.config.local_dir.join(filename);

        // Create directory if it doesn't exist
        if let Some(parent) = file_path.parent() {
            fs::create_dir_all(parent)?;
        }

        fs::write(&file_path, content)?;

        Ok(())
    }

    /// Update all signatures
    pub fn update_all(&self) -> Result<UpdateResult> {
        let update_info = self.check_update()?;

        if !update_info.needs_update && !self.config.force {
            return Ok(UpdateResult {
                updated: vec![],
                skipped: update_info.manifest.signatures.keys().cloned().collect(),
                version: update_info.local_version.unwrap_or_default(),
            });
        }

        if self.config.dry_run {
            println!(
                "🔍 Dry run - would update to version: {}",
                update_info.remote_version
            );
            println!(
                "   Files to download: {}",
                update_info.manifest.signatures.len()
            );
            return Ok(UpdateResult {
                updated: vec![],
                skipped: vec![],
                version: update_info.remote_version.clone(),
            });
        }

        let mut updated = vec![];
        let mut skipped = vec![];

        for (name, file) in &update_info.manifest.signatures {
            match self.download_signature(file) {
                Ok(content) => {
                    // Use the filename from the path (last component)
                    let filename = file.path.rsplit('/').next().unwrap_or(name);

                    if let Err(e) = self.write_signature(filename, &content) {
                        tracing::warn!("Failed to write {}: {}", filename, e);
                        skipped.push(name.clone());
                        continue;
                    }

                    updated.push(name.clone());
                }
                Err(e) => {
                    tracing::warn!("Failed to download {}: {}", name, e);
                    skipped.push(name.clone());
                }
            }
        }

        // Write the manifest
        self.write_local_manifest(&update_info.manifest)?;

        Ok(UpdateResult {
            updated,
            skipped,
            version: update_info.remote_version,
        })
    }

    /// Install a curated set of signatures
    pub fn install_set(&self, set_name: &str) -> Result<UpdateResult> {
        let update_info = self.check_update()?;

        let set = update_info
            .manifest
            .sets
            .get(set_name)
            .ok_or_else(|| anyhow!("Signature set '{}' not found", set_name))?;

        if self.config.dry_run {
            println!("🔍 Dry run - would install set: {}", set_name);
            println!("   Files: {}", set.files.len());
            return Ok(UpdateResult {
                updated: vec![],
                skipped: vec![],
                version: update_info.remote_version.clone(),
            });
        }

        let mut updated = vec![];
        let mut skipped = vec![];

        for filename in &set.files {
            if let Some(file) = update_info.manifest.signatures.get(filename) {
                match self.download_signature(file) {
                    Ok(content) => {
                        let out_filename = file.path.rsplit('/').next().unwrap_or(filename);

                        if let Err(e) = self.write_signature(out_filename, &content) {
                            tracing::warn!("Failed to write {}: {}", out_filename, e);
                            skipped.push(filename.clone());
                            continue;
                        }

                        updated.push(filename.clone());
                    }
                    Err(e) => {
                        tracing::warn!("Failed to download {}: {}", filename, e);
                        skipped.push(filename.clone());
                    }
                }
            } else {
                skipped.push(filename.clone());
            }
        }

        Ok(UpdateResult {
            updated,
            skipped,
            version: update_info.remote_version,
        })
    }

    /// List available signature sets
    pub fn list_sets(&self) -> Result<Vec<(String, SignatureSet)>> {
        let manifest = self.fetch_manifest()?;

        let mut sets: Vec<_> = manifest.sets.into_iter().collect();
        sets.sort_by(|a, b| a.0.cmp(&b.0));

        Ok(sets)
    }
}

impl Default for SignatureUpdater {
    fn default() -> Self {
        Self::new().unwrap()
    }
}

/// Information about available updates
#[derive(Debug, Clone)]
pub struct UpdateInfo {
    /// Local version (if installed)
    pub local_version: Option<String>,

    /// Remote version
    pub remote_version: String,

    /// Whether an update is available
    pub needs_update: bool,

    /// The remote manifest
    pub manifest: SignatureManifest,
}

/// Result of an update operation
#[derive(Debug, Clone)]
pub struct UpdateResult {
    /// Files that were successfully updated
    pub updated: Vec<String>,

    /// Files that were skipped
    pub skipped: Vec<String>,

    /// New version
    pub version: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_compute_checksum() {
        let content = "test content";
        let checksum = SignatureUpdater::compute_checksum(content);

        // SHA256 of "test content"
        assert_eq!(checksum.len(), 64);
        assert!(checksum.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn test_update_config_default() {
        let config = UpdateConfig::default();

        assert_eq!(config.repo_url, DEFAULT_REPO_URL);
        assert_eq!(config.raw_base, GITHUB_RAW_BASE);
        assert!(config.verify_checksums);
        assert!(!config.force);
        assert!(!config.dry_run);
    }

    #[test]
    fn test_update_config_builder() {
        let config = UpdateConfig::new()
            .with_repo_url("https://github.com/test/repo".to_string())
            .with_verify_checksums(false)
            .with_force(true)
            .with_dry_run(true);

        assert_eq!(config.repo_url, "https://github.com/test/repo");
        assert_eq!(
            config.raw_base,
            "https://raw.githubusercontent.com/test/repo/main"
        );
        assert!(!config.verify_checksums);
        assert!(config.force);
        assert!(config.dry_run);
    }
}
