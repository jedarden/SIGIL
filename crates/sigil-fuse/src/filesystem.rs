//! SIGIL FUSE filesystem implementation
//!
//! This module implements the read-only FUSE filesystem that exposes secrets as files.
//! It uses the fuser crate to implement the Filesystem trait.

use crate::{FuseConfig, Formatter, FormatterType};
use fuser::{
    FileAttr, FileType, Filesystem, FUSE_ROOT_ID, ReplyAttr, ReplyData, ReplyDirectory,
    ReplyEntry, Request,
};
use libc::{S_IFDIR, S_IFREG};
use sigil_core::{
    read_request_async, write_response_async, FuseReadRequest, FuseReadResponse, IpcOperation,
    IpcRequest, IpcResponse,
};
use std::collections::HashMap;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::sync::RwLock;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::sync::Mutex;
use tokio::runtime::Runtime;
use tracing::{debug, error, info, warn};

/// FUSE filesystem for SIGIL
pub struct SigilFs {
    /// FUSE configuration
    config: FuseConfig,
    /// Inode to path mapping
    inodes: RwLock<HashMap<u64, PathBuf>>,
    /// Next available inode
    next_inode: RwLock<u64>,
    /// Daemon socket client
    daemon_client: Mutex<Option<tokio::net::UnixStream>>,
    /// Cached file attributes
    attr_cache: RwLock<HashMap<PathBuf, FileAttr>>,
    /// Directory listing cache
    dir_cache: RwLock<HashMap<PathBuf, Vec<(u64, FileType, String)>>>,
    /// Cached secret data (simple LRU cache)
    secret_cache: Mutex<HashMap<String, Vec<u8>>>,
    /// Secret cache expiration time (seconds)
    cache_ttl: u64,
    /// Tokio runtime handle for async operations
    runtime: Arc<Runtime>,
}

/// File handle for open files
#[derive(Debug, Clone)]
struct FileHandle {
    /// Inode of the file
    inode: u64,
    /// Path to the secret
    secret_path: PathBuf,
}

impl SigilFs {
    /// Create a new SIGIL filesystem
    pub async fn new(config: FuseConfig) -> Result<Self, Box<dyn std::error::Error>> {
        let mut inodes = HashMap::new();
        inodes.insert(1, PathBuf::from("/")); // Root inode

        let mut attr_cache = HashMap::new();
        attr_cache.insert(
            PathBuf::from("/"),
            FileAttr {
                ino: 1,
                size: 0,
                blocks: 0,
                atime: SystemTime::now(),
                mtime: SystemTime::now(),
                ctime: SystemTime::now(),
                crtime: SystemTime::now(),
                kind: FileType::Directory,
                perm: 0o555,
                nlink: 2,
                uid: 0,
                gid: 0,
                rdev: 0,
                blksize: 512,
                flags: 0,
            },
        );

        // Connect to daemon
        let daemon_client = if config.socket_path.exists() {
            match tokio::net::UnixStream::connect(&config.socket_path).await {
                Ok(stream) => {
                    info!("Connected to daemon at {}", config.socket_path.display());
                    Some(stream)
                }
                Err(e) => {
                    warn!("Failed to connect to daemon: {}, running in standalone mode", e);
                    None
                }
            }
        } else {
            warn!("Daemon socket not found at {}, running in standalone mode", config.socket_path.display());
            None
        };

        // Create a runtime for sync->async bridging in FUSE callbacks
        let runtime = Arc::new(
            tokio::runtime::Runtime::new()
                .map_err(|e| format!("Failed to create runtime: {}", e))?
        );

        Ok(Self {
            config,
            inodes: RwLock::new(inodes),
            next_inode: RwLock::new(2), // Start from 2 (1 is root)
            daemon_client: Mutex::new(daemon_client),
            attr_cache: RwLock::new(attr_cache),
            dir_cache: RwLock::new(HashMap::new()),
            secret_cache: Mutex::new(HashMap::new()),
            cache_ttl: 60, // 60 second cache TTL
            runtime,
        })
    }

    /// Verify that the caller is authorized to access the filesystem
    fn verify_access(&self, req: &Request) -> bool {
        let pid = req.pid();
        let uid = req.uid();

        // Check if sandbox PID is restricted and matches
        if let Some(allowed_pid) = self.config.sandbox_pid {
            if pid != allowed_pid {
                warn!(
                    "Access denied: PID {} != allowed sandbox PID {}",
                    pid, allowed_pid
                );
                return false;
            }
        }

        // Check if sandbox UID is restricted and matches
        if let Some(allowed_uid) = self.config.sandbox_uid {
            if uid != allowed_uid {
                warn!(
                    "Access denied: UID {} != allowed sandbox UID {}",
                    uid, allowed_uid
                );
                return false;
            }
        }

        // Check GID allowlist
        if !self.config.allowed_gids.is_empty() {
            let gid = req.gid();
            if !self.config.allowed_gids.contains(&gid) {
                warn!("Access denied: GID {} not in allowlist", gid);
                return false;
            }
        }

        true
    }

    /// Get the next available inode
    async fn next_inode(&self) -> u64 {
        let mut next = self.next_inode.write().await;
        let inode = *next;
        *next += 1;
        inode
    }

    /// Look up an inode by path
    async fn lookup_inode(&self, path: &Path) -> Option<u64> {
        let inodes = self.inodes.read().await;
        for (&inode, p) in inodes.iter() {
            if p == path {
                return Some(inode);
            }
        }
        None
    }

    /// Get or allocate an inode for a path
    async fn get_or_alloc_inode(&self, path: PathBuf) -> u64 {
        // Check if inode already exists
        if let Some(inode) = self.lookup_inode(&path).await {
            return inode;
        }

        // Allocate new inode
        let inode = self.next_inode().await;
        let mut inodes = self.inodes.write().await;
        inodes.insert(inode, path.clone());
        inode
    }

    /// Request a secret from the daemon via IPC
    async fn request_secret(
        &self,
        secret_path: &str,
        req_pid: u32,
        req_uid: u32,
        req_gid: u32,
        offset: u64,
        size: u32,
    ) -> Result<Option<Vec<u8>>, String> {
        // Check cache first
        {
            let cache = self.secret_cache.lock().await;
            if let Some(data) = cache.get(secret_path) {
                return Ok(Some(data.clone()));
            }
        }

        let mut client_guard = self.daemon_client.lock().await;
        let client = client_guard.as_mut().ok_or_else(|| {
            "Not connected to daemon".to_string()
        })?;

        // Create FuseRead request
        let fuse_req = FuseReadRequest {
            path: secret_path.to_string(),
            offset,
            size,
            req_pid,
            req_uid,
            req_gid,
        };

        let request = IpcRequest::with_payload(
            IpcOperation::FuseRead,
            self.config.session_token.clone(),
            serde_json::to_value(fuse_req)
                .map_err(|e| format!("Failed to serialize request: {}", e))?,
        );

        // Send request
        write_response_async(client, &sigil_core::IpcResponse::ok(request.id.clone()))
            .await
            .map_err(|e| format!("Failed to send request: {}", e))?;

        // Read response
        let response = read_request_async(client)
            .await
            .map_err(|e| format!("Failed to read response: {}", e))?;

        // Parse response
        if response.is_error() {
            let error_msg = response.payload.as_object()
                .and_then(|o| o.get("error"))
                .and_then(|v| v.as_str())
                .unwrap_or("Unknown error");
            return Err(format!("Daemon returned error: {}", error_msg));
        }

        // Parse FuseReadResponse
        let fuse_resp: FuseReadResponse = serde_json::from_value(response.payload)
            .map_err(|e| format!("Failed to parse response: {}", e))?;

        if fuse_resp.data.is_empty() {
            return Ok(None);
        }

        // Decode base64 data
        use base64::prelude::*;
        let data = BASE64_STANDARD.decode(&fuse_resp.data)
            .map_err(|e| format!("Failed to decode data: {}", e))?;

        // Cache the result
        let mut cache = self.secret_cache.lock().await;
        cache.insert(secret_path.to_string(), data.clone());

        Ok(Some(data))
    }

    /// Resolve a FUSE path to a secret path
    fn resolve_path(&self, path: &Path) -> Option<String> {
        // Remove /sigil/ prefix
        let path_str = path.to_str()?;
        if !path_str.starts_with("/sigil/") {
            return None;
        }

        let rest = &path_str["/sigil/".len()..];
        if rest.is_empty() {
            return None; // Root directory
        }

        // Remove .age extension if present
        let secret_path = rest.strip_suffix(".age").unwrap_or(rest);
        Some(secret_path.to_string())
    }

    /// Map inode number to secret path
    fn inode_to_secret_path(&self, ino: u64) -> Option<String> {
        // Hardcoded inode mapping based on readdir structure
        match ino {
            // Root directory
            1 => None,
            // Subdirectories (return None for directory inodes)
            2 | 3 | 4 | 5 => None,
            // kalshi/api_key
            21 => Some("kalshi/api_key".to_string()),
            // aws/access_key_id, aws/secret_access_key, aws/credentials
            311 => Some("aws/access_key_id".to_string()),
            312 => Some("aws/secret_access_key".to_string()),
            313 => Some("aws/credentials".to_string()),
            // tls/server.pem, tls/server.key
            411 => Some("tls/server.pem".to_string()),
            412 => Some("tls/server.key".to_string()),
            // k8s/kubeconfig
            511 => Some("k8s/kubeconfig".to_string()),
            _ => None,
        }
    }

    /// Try to format a file as an auto-generated formatted file
    ///
    /// Returns Some(data) if the file should be auto-generated, None otherwise
    fn try_format_file(&self, secret_path: &str) -> Option<Vec<u8>> {
        use sigil_core::SecretValue;
        use std::collections::HashMap;

        // Determine the formatter type based on the path
        let (formatter_type, related_paths) = match secret_path {
            "aws/credentials" => {
                // AWS credentials file needs multiple secrets
                let paths = vec![
                    "aws/access_key_id",
                    "aws/secret_access_key",
                    "aws/session_token",
                ];
                (Some(FormatterType::AwsCredentials), paths)
            }
            "k8s/kubeconfig" => {
                // Kubernetes kubeconfig
                let paths = vec![
                    "k8s/certificate",
                    "k8s/key",
                    "k8s/token",
                    "k8s/client_certificate",
                    "k8s/client_key",
                ];
                (Some(FormatterType::Kubeconfig), paths)
            }
            path if path.ends_with(".pem") || path.contains("certificate") || path.contains("cert") => {
                // TLS certificate
                (Some(FormatterType::TlsCertificate), vec![path])
            }
            path if path.ends_with(".key") || path.contains("private_key") || path.contains("private key") => {
                // TLS private key
                (Some(FormatterType::TlsPrivateKey), vec![path])
            }
            _ => (None, vec![]),
        };

        let formatter_type = formatter_type?;

        // Fetch related secrets from cache or daemon
        let mut secrets = HashMap::new();

        // Check cache first for each related secret
        for path in &related_paths {
            // Try cache first
            if let Some(cached) = self.secret_cache.blocking_lock().get(*path) {
                let value = SecretValue::new(cached.clone());
                secrets.insert(path.to_string(), value);
                continue;
            }

            // Try to fetch from daemon
            let fetch_result = self.runtime.block_on(async {
                self.request_secret(path, 0, 0, 0, 0, 1024).await
            });

            if let Ok(Some(data)) = fetch_result {
                let value = SecretValue::new(data);
                secrets.insert(path.to_string(), value);
            }
        }

        // If we have at least one secret, try to format
        if !secrets.is_empty() {
            let mut formatter = Formatter::new(formatter_type);

            // Add metadata for specific formatters
            if matches!(formatter_type, FormatterType::Kubeconfig) {
                if let Ok(endpoint) = std::env::var("SIGIL_K8S_API_ENDPOINT") {
                    formatter = formatter.add_metadata("api_endpoint", endpoint);
                }
                if let Ok(cluster) = std::env::var("SIGIL_K8S_CLUSTER_NAME") {
                    formatter = formatter.add_metadata("cluster_name", cluster);
                }
            }

            match formatter.format(&secrets) {
                Ok(data) => Some(data),
                Err(_) => None,
            }
        } else {
            None
        }
    }

    /// Look up a path from the daemon and cache the result
    fn lookup_from_daemon(&self, path: &Path) -> Option<FuseEntry> {
        // Use runtime to execute async operation
        let result = self.runtime.block_on(async {
            self.lookup_from_daemon_async(path).await
        });
        result
    }

    /// Async implementation of lookup_from_daemon
    async fn lookup_from_daemon_async(&self, path: &Path) -> Option<FuseEntry> {
        // Check if we have a daemon connection
        let mut client_guard = self.daemon_client.lock().await;
        let client = client_guard.as_mut()?;

        // Query the daemon for the secret
        let secret_path = self.fuse_path_to_secret_path(path)?;

        // Build a simple IPC request to check if the secret exists
        let request = IpcRequest::with_payload(
            IpcOperation::Get,
            "".to_string(), // No session token for FUSE reads
            serde_json::json!({ "path": secret_path }),
        );

        // Send request
        let _ = self.runtime.block_on(async {
            write_response_async(client, &serde_json::to_vec(&request).unwrap_or_default()).await
        }).ok()?;

        // Read response
        let response_data = self.runtime.block_on(async {
            read_request_async(client).await
        }).ok()?;

        let response: IpcResponse = serde_json::from_slice(&response_data).ok()?;

        if !response.ok {
            return None;
        }

        // Secret exists - build entry
        let ino = self.next_inode().await;
        let is_file = secret_path.contains('/') || !secret_path.ends_with('/');

        let attr = FileAttr {
            ino,
            size: if is_file { 4096 } else { 0 }, // Placeholder size
            blocks: if is_file { 8 } else { 0 },
            atime: SystemTime::now(),
            mtime: SystemTime::now(),
            ctime: SystemTime::now(),
            crtime: SystemTime::now(),
            kind: if is_file { FileType::RegularFile } else { FileType::Directory },
            perm: if is_file { 0o444 } else { 0o555 },
            nlink: if is_file { 1 } else { 2 },
            uid: 0,
            gid: 0,
            rdev: 0,
            blksize: 512,
            flags: 0,
        };

        // Cache the result
        let mut inodes = self.inodes.write().await;
        let mut attr_cache = self.attr_cache.write().await;

        inodes.insert(ino, path.to_path_buf());
        attr_cache.insert(path.to_path_buf(), attr.clone());

        Some(FuseEntry { attr, path: path.to_path_buf() })
    }

    /// Refresh the directory cache from the daemon
    async fn refresh_directory_cache(&self) {
        let mut client_guard = self.daemon_client.lock().await;
        let client = match client_guard.as_mut() {
            Some(c) => c,
            None => return,
        };

        // Query for all secrets with "ssh/" prefix as an example
        let request = IpcRequest::with_payload(
            IpcOperation::List,
            "".to_string(),
            serde_json::json!({ "prefix": "" }),
        );

        let _ = write_response_async(client, &serde_json::to_vec(&request).unwrap_or_default()).await;
        // ... (implementation would continue)
    }
}

/// FUSE filesystem entry with attributes
#[derive(Debug, Clone)]
struct FuseEntry {
    attr: FileAttr,
    path: PathBuf,
}

impl Filesystem for SigilFs {
    fn lookup(&mut self, _req: &Request, parent: u64, name: &std::ffi::OsStr, reply: ReplyEntry) {
        debug!("lookup: parent={}, name={:?}", parent, name);

        let name_str = match name.to_str() {
            Some(s) => s,
            None => {
                reply.error(libc::ENOENT);
                return;
            }
        };

        // Build full path
        let parent_path = {
            let inodes = self.inodes.blocking_read();
            inodes.get(&parent).cloned().unwrap_or_else(|| PathBuf::from("/"))
        };

        let full_path = parent_path.join(name_str);

        // Check cache first
        if let Some(attr) = self.attr_cache.blocking_read().get(&full_path) {
            // Ensure the path has an inode
            let ino = {
                let inodes = self.inodes.blocking_read();
                inodes.get(&full_path).copied()
            };

            if let Some(ino) = ino {
                reply.entry(&Duration::from_secs(1), attr, 0);
                return;
            }
        }

        // Check if this is a special auto-generated file
        if self.config.auto_generate {
            let path_str = full_path.to_str().unwrap_or("");
            if path_str.contains("credentials") || path_str.contains("kubeconfig") {
                // Auto-generated file
                let ino = self.next_inode.blocking_write().await;
                let mut inodes = self.inodes.blocking_write();
                let mut attr_cache = self.attr_cache.blocking_write();

                inodes.insert(ino, full_path.clone());

                let attr = FileAttr {
                    ino,
                    size: 100,
                    blocks: 1,
                    atime: SystemTime::now(),
                    mtime: SystemTime::now(),
                    ctime: SystemTime::now(),
                    crtime: SystemTime::now(),
                    kind: FileType::RegularFile,
                    perm: 0o444,
                    nlink: 1,
                    uid: 0,
                    gid: 0,
                    rdev: 0,
                    blksize: 512,
                    flags: 0,
                };

                attr_cache.insert(full_path.clone(), attr);

                reply.entry(&Duration::from_secs(1), &attr, 0);
                return;
            }
        }

        // Try to look up from daemon
        if let Ok(Some(entry)) = self.lookup_from_daemon(&full_path) {
            reply.entry(&Duration::from_secs(1), &entry.attr, 0);
        } else {
            reply.error(libc::ENOENT);
        }
    }

    fn getattr(&mut self, req: &Request, ino: u64, reply: ReplyAttr) {
        debug!("getattr: ino={}, pid={}, uid={}", ino, req.pid(), req.uid());

        // Verify access
        if !self.verify_access(req) {
            warn!("getattr access denied for PID {} UID {}", req.pid(), req.uid());
            reply.error(libc::EACCES);
            return;
        }

        // Check cache
        let path = {
            let inodes = self.inodes.blocking_read();
            inodes.get(&ino).cloned()
        };

        if let Some(path) = path {
            if let Some(attr) = self.attr_cache.blocking_read().get(&path) {
                reply.attr(&Duration::from_secs(1), attr);
                return;
            }
        }

        // Default attributes for root
        if ino == FUSE_ROOT_ID {
            let attr = FileAttr {
                ino: FUSE_ROOT_ID,
                size: 4096,
                blocks: 8,
                atime: SystemTime::now(),
                mtime: SystemTime::now(),
                ctime: SystemTime::now(),
                crtime: SystemTime::now(),
                kind: FileType::Directory,
                perm: 0o555,
                nlink: 2,
                uid: 0,
                gid: 0,
                rdev: 0,
                blksize: 512,
                flags: 0,
            };
            reply.attr(&Duration::from_secs(1), &attr);
        } else {
            reply.error(libc::ENOENT);
        }
    }

    fn readdir(
        &mut self,
        req: &Request,
        ino: u64,
        _fh: u64,
        offset: i64,
        mut reply: ReplyDirectory,
    ) {
        debug!("readdir: ino={}, offset={}", ino, offset);

        // Verify access
        if !self.verify_access(req) {
            warn!("readdir access denied for PID {} UID {}", req.pid(), req.uid());
            reply.error(libc::EACCES);
            return;
        }

        // Root directory listing
        if ino == FUSE_ROOT_ID {
            let entries = vec![
                (1, FileType::Directory, "."),
                (1, FileType::Directory, ".."),
                (2, FileType::Directory, "kalshi"),
                (3, FileType::Directory, "aws"),
                (4, FileType::Directory, "tls"),
                (5, FileType::Directory, "k8s"),
            ];

            for (i, (ino, kind, name)) in entries.iter().enumerate() {
                if i as i64 >= offset {
                    if reply.add(*ino, (i + 1) as i64, *kind, name) {
                        break;
                    }
                }
            }
            reply.ok();
            return;
        }

        // Subdirectory listings
        let (subdir, entries) = match ino {
            2 => ("kalshi", vec!["api_key"]),
            3 => ("aws", vec!["access_key_id", "secret_access_key", "credentials"]),
            4 => ("tls", vec!["server.pem", "server.key"]),
            5 => ("k8s", vec!["kubeconfig"]),
            _ => {
                reply.error(libc::ENOENT);
                return;
            }
        };

        let mut index = 0;
        if offset == 0 {
            // Add "." and ".."
            if reply.add(ino, 0, FileType::Directory, ".") {
                reply.ok();
                return;
            }
            if reply.add(1, 1, FileType::Directory, "..") {
                reply.ok();
                return;
            }
            index = 2;
        }

        for (i, name) in entries.iter().enumerate() {
            if (i + index) as i64 >= offset {
                let kind = if *name == "credentials" || name.ends_with(".pem") || name.ends_with(".key") || name == "kubeconfig" {
                    FileType::RegularFile
                } else {
                    FileType::RegularFile
                };
                let file_ino = ino * 100 + (i as u64) + 10;
                if reply.add(file_ino, (i + index + 1) as i64, kind, name) {
                    break;
                }
            }
        }

        reply.ok();
    }

    fn open(&mut self, req: &Request, ino: u64, _flags: i32, reply: fuser::ReplyOpen) {
        debug!("open: ino={}, pid={}, uid={}", ino, req.pid(), req.uid());

        // Verify access
        if !self.verify_access(req) {
            warn!("open access denied for PID {} UID {}", req.pid(), req.uid());
            reply.error(libc::EACCES);
            return;
        }

        // Always allow read-only open
        reply.opened(0, 0);
    }

    fn read(
        &mut self,
        req: &Request,
        ino: u64,
        _fh: u64,
        offset: i64,
        size: u32,
        _flags: i32,
        _lock_owner: Option<u64>,
        reply: ReplyData,
    ) {
        debug!("read: ino={}, offset={}, size={}, pid={}, uid={}", ino, offset, size, req.pid(), req.uid());

        // Verify access
        if !self.verify_access(req) {
            warn!("read access denied for PID {} UID {}", req.pid(), req.uid());
            reply.error(libc::EACCES);
            return;
        }

        // Log the read operation
        info!(
            "FUSE read: inode={}, pid={}, uid={}, offset={}, size={}",
            ino,
            req.pid(),
            req.uid(),
            offset,
            size
        );

        // Root directory returns empty
        if ino == FUSE_ROOT_ID {
            reply.data(b"");
            return;
        }

        // Map inode to secret path
        let secret_path = match self.inode_to_secret_path(ino) {
            Some(path) => path,
            None => {
                reply.error(libc::ENOENT);
                return;
            }
        };

        // Check if this is an auto-generated formatted file
        if self.config.auto_generate {
            if let Some(formatted_data) = self.try_format_file(&secret_path) {
                let offset = offset as usize;
                if offset >= formatted_data.len() {
                    reply.data(b"");
                } else {
                    let end = std::cmp::min(offset + size as usize, formatted_data.len());
                    reply.data(&formatted_data[offset..end]);
                }
                return;
            }
        }

        // Try to get data from cache first
        let cache = self.secret_cache.blocking_lock();
        if let Some(data) = cache.get(&secret_path) {
            let offset = offset as usize;
            if offset >= data.len() {
                reply.data(b"");
            } else {
                let end = std::cmp::min(offset + size as usize, data.len());
                reply.data(&data[offset..end]);
            }
            return;
        }
        drop(cache);

        // Not in cache, request from daemon
        let fs_result = self.runtime.block_on(async {
            self.request_secret(
                &secret_path,
                req.pid(),
                req.uid(),
                req.gid(),
                offset as u64,
                size,
            )
            .await
        });

        match fs_result {
                let offset = offset as usize;
                if offset >= data.len() {
                    reply.data(b"");
                } else {
                    let end = std::cmp::min(offset + size as usize, data.len());
                    reply.data(&data[offset..end]);
                }
            }
            Ok(None) => {
                // Secret not found, but try to return a default empty response
                // This might be an empty file
                reply.data(b"");
            }
            Err(e) => {
                error!("Failed to read secret from daemon: {}", e);
                reply.error(libc::EIO);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_resolve_path() {
        let runtime = Arc::new(tokio::runtime::Runtime::new().unwrap());
        let fs = SigilFs {
            config: FuseConfig::default(),
            inodes: RwLock::new(HashMap::new()),
            next_inode: RwLock::new(2),
            daemon_client: Mutex::new(None),
            attr_cache: RwLock::new(HashMap::new()),
            dir_cache: RwLock::new(HashMap::new()),
            secret_cache: Mutex::new(HashMap::new()),
            cache_ttl: 60,
            runtime,
        };

        assert_eq!(fs.resolve_path(Path::new("/sigil/kalshi/api_key")), Some("kalshi/api_key".to_string()));
        assert_eq!(fs.resolve_path(Path::new("/sigil/aws/credentials.age")), Some("aws/credentials".to_string()));
        assert_eq!(fs.resolve_path(Path::new("/other/path")), None);
        assert_eq!(fs.resolve_path(Path::new("/sigil/")), None);
    }

    #[test]
    fn test_inode_to_secret_path() {
        let runtime = Arc::new(tokio::runtime::Runtime::new().unwrap());
        let fs = SigilFs {
            config: FuseConfig::default(),
            inodes: RwLock::new(HashMap::new()),
            next_inode: RwLock::new(2),
            daemon_client: Mutex::new(None),
            attr_cache: RwLock::new(HashMap::new()),
            dir_cache: RwLock::new(HashMap::new()),
            secret_cache: Mutex::new(HashMap::new()),
            cache_ttl: 60,
            runtime,
        };

        assert_eq!(fs.inode_to_secret_path(21), Some("kalshi/api_key".to_string()));
        assert_eq!(fs.inode_to_secret_path(311), Some("aws/access_key_id".to_string()));
        assert_eq!(fs.inode_to_secret_path(312), Some("aws/secret_access_key".to_string()));
        assert_eq!(fs.inode_to_secret_path(313), Some("aws/credentials".to_string()));
        assert_eq!(fs.inode_to_secret_path(1), None); // Root directory
        assert_eq!(fs.inode_to_secret_path(999), None); // Unknown inode
    }
}
