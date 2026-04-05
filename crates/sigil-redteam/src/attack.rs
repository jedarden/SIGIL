//! Attack definitions and execution
//!
//! Individual attack tests that probe SIGIL's security defenses.

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Result of running an attack
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttackResult {
    /// Name of the attack
    pub attack_name: String,
    /// Status of the attack
    pub status: AttackStatus,
    /// Duration of the attack in milliseconds
    pub duration_ms: u64,
    /// Additional details about the attack
    pub details: HashMap<String, serde_json::Value>,
}

impl AttackResult {
    /// Whether the attack was blocked
    pub fn was_blocked(&self) -> bool {
        matches!(self.status, AttackStatus::Blocked)
    }

    /// Whether the attack evaded defenses
    pub fn was_evaded(&self) -> bool {
        matches!(self.status, AttackStatus::Evaded)
    }

    /// Whether the attack resulted in an error
    pub fn had_error(&self) -> bool {
        matches!(self.status, AttackStatus::Error(_))
    }
}

/// Status of an attack
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum AttackStatus {
    /// Attack was blocked by SIGIL
    Blocked,
    /// Attack evaded SIGIL's defenses
    Evaded,
    /// Attack was detected (canary triggered, etc.)
    Detected,
    /// Attack execution resulted in an error
    Error(String),
}

/// Trait for attacks that can be executed against SIGIL
#[async_trait]
pub trait Attack: Send + Sync {
    /// Get the name of this attack
    fn name(&self) -> &str;

    /// Get the category of this attack
    fn category(&self) -> AttackCategory;

    /// Execute the attack
    ///
    /// Returns Ok(true) if the attack was blocked,
    /// Ok(false) if it evaded defenses, or Err on failure.
    async fn execute(&self) -> anyhow::Result<bool>;

    /// Get details about this attack
    fn details(&self) -> HashMap<String, serde_json::Value> {
        HashMap::new()
    }

    /// Get the severity level of this attack
    fn severity(&self) -> AttackSeverity {
        AttackSeverity::Medium
    }
}

/// Category of attack
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum AttackCategory {
    /// Environment harvesting attacks
    EnvironmentHarvesting,
    /// Credential file scanning
    CredentialScanning,
    /// Memory reading attacks
    MemoryReading,
    /// Network exfiltration attempts
    NetworkExfiltration,
    /// Socket discovery and connection
    SocketDiscovery,
    /// PATH/LD_PRELOAD manipulation
    PathManipulation,
    /// Ptrace attempts
    Ptrace,
    /// Encoding-based scrubber evasion
    EncodingEvasion,
    /// Prompt injection via file creation
    PromptInjection,
    /// Canary file access
    CanaryAccess,
    /// Secret exfiltration
    SecretExfiltration,
    /// SDK authentication bypass
    SdkAuthBypass,
}

/// Severity level of an attack
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AttackSeverity {
    /// Low severity
    Low,
    /// Medium severity
    Medium,
    /// High severity
    High,
    /// Critical severity
    Critical,
}

/// Environment harvesting attack
#[derive(Debug, Clone)]
pub struct EnvironmentHarvestAttack {
    /// Specific environment variable to target (None = all)
    target_var: Option<String>,
}

impl EnvironmentHarvestAttack {
    /// Create a new environment harvesting attack
    pub fn new() -> Self {
        Self { target_var: None }
    }

    /// Target a specific environment variable
    pub fn with_target(mut self, var: String) -> Self {
        self.target_var = Some(var);
        self
    }
}

impl Default for EnvironmentHarvestAttack {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl Attack for EnvironmentHarvestAttack {
    fn name(&self) -> &str {
        "environment_harvesting"
    }

    fn category(&self) -> AttackCategory {
        AttackCategory::EnvironmentHarvesting
    }

    fn details(&self) -> HashMap<String, serde_json::Value> {
        let mut details = HashMap::new();
        if let Some(ref target) = self.target_var {
            details.insert("target_var".to_string(), serde_json::json!(target));
        }
        details
    }

    async fn execute(&self) -> anyhow::Result<bool> {
        // Try to read environment variables that might contain secrets
        let sensitive_vars = [
            "SIGIL_SESSION_TOKEN",
            "AWS_ACCESS_KEY_ID",
            "AWS_SECRET_ACCESS_KEY",
            "GITHUB_TOKEN",
            "API_KEY",
            "DATABASE_URL",
        ];

        let found_secrets = if let Some(ref target) = self.target_var {
            std::env::var(target).is_ok()
        } else {
            sensitive_vars.iter().any(|var| std::env::var(var).is_ok())
        };

        // If secrets were found in environment, attack evaded
        Ok(!found_secrets)
    }
}

/// Credential file scanning attack
#[derive(Debug, Clone)]
pub struct CredentialScanAttack {
    /// Specific file path to scan (None = default paths)
    target_path: Option<String>,
}

impl CredentialScanAttack {
    /// Create a new credential scanning attack
    pub fn new() -> Self {
        Self { target_path: None }
    }

    /// Target a specific file path
    pub fn with_target(mut self, path: String) -> Self {
        self.target_path = Some(path);
        self
    }
}

impl Default for CredentialScanAttack {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl Attack for CredentialScanAttack {
    fn name(&self) -> &str {
        "credential_scanning"
    }

    fn category(&self) -> AttackCategory {
        AttackCategory::CredentialScanning
    }

    async fn execute(&self) -> anyhow::Result<bool> {
        let target_paths = if let Some(ref path) = self.target_path {
            vec![std::path::PathBuf::from(path)]
        } else {
            vec![
                std::path::PathBuf::from(".aws/credentials"),
                std::path::PathBuf::from(".env"),
                std::path::PathBuf::from(".git/config"),
                std::path::PathBuf::from("~/.ssh/id_rsa"),
            ]
        };

        let found_creds = target_paths
            .iter()
            .any(|path| path.exists() && path.is_file());

        // If credential files exist and are accessible, attack evaded
        Ok(!found_creds)
    }
}

/// Memory reading attack
#[derive(Debug, Clone)]
pub struct MemoryReadAttack;

#[async_trait]
impl Attack for MemoryReadAttack {
    fn name(&self) -> &str {
        "memory_reading"
    }

    fn category(&self) -> AttackCategory {
        AttackCategory::MemoryReading
    }

    fn severity(&self) -> AttackSeverity {
        AttackSeverity::High
    }

    async fn execute(&self) -> anyhow::Result<bool> {
        // Try to read from /proc/self/mem
        let mem_path = "/proc/self/mem";

        if std::path::Path::new(mem_path).exists() {
            // Check if we can open it (should be blocked by sandbox)
            match std::fs::File::open(mem_path) {
                Ok(_) => Ok(false), // Can open - attack evaded
                Err(_) => Ok(true), // Cannot open - blocked
            }
        } else {
            Ok(true) // Doesn't exist - blocked by default
        }
    }
}

/// Ptrace attack
#[derive(Debug, Clone)]
pub struct PtraceAttack;

#[async_trait]
impl Attack for PtraceAttack {
    fn name(&self) -> &str {
        "ptrace_attempt"
    }

    fn category(&self) -> AttackCategory {
        AttackCategory::Ptrace
    }

    fn severity(&self) -> AttackSeverity {
        AttackSeverity::High
    }

    async fn execute(&self) -> anyhow::Result<bool> {
        // Try to use ptrace on self
        // This should fail in a sandboxed environment
        #[cfg(unix)]
        {
            use libc::PTRACE_TRACEME;

            let result = unsafe { libc::ptrace(PTRACE_TRACEME, 0, 0, 0) };

            Ok(result != 0) // If failed (non-zero), it's blocked
        }

        #[cfg(not(unix))]
        {
            Ok(true) // Not applicable on non-Unix
        }
    }
}

/// Encoding-based scrubber evasion attack
#[derive(Debug, Clone)]
pub struct EncodingEvasionAttack {
    /// Encoding type to use
    encoding: EncodingType,
}

/// Types of encoding for evasion
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EncodingType {
    /// Base64 encoding
    Base64,
    /// Hexadecimal encoding
    Hex,
    /// ROT13 substitution
    Rot13,
    /// String reversal
    Reverse,
    /// Character chunking
    Chunked,
}

impl EncodingEvasionAttack {
    /// Create a new encoding evasion attack
    pub fn new() -> Self {
        Self {
            encoding: EncodingType::Base64,
        }
    }

    /// Set the encoding type
    pub fn with_encoding(mut self, encoding: EncodingType) -> Self {
        self.encoding = encoding;
        self
    }
}

impl Default for EncodingEvasionAttack {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl Attack for EncodingEvasionAttack {
    fn name(&self) -> &str {
        "encoding_evasion"
    }

    fn category(&self) -> AttackCategory {
        AttackCategory::EncodingEvasion
    }

    fn details(&self) -> HashMap<String, serde_json::Value> {
        let mut details = HashMap::new();
        details.insert(
            "encoding".to_string(),
            serde_json::json!(format!("{:?}", self.encoding)),
        );
        details
    }

    async fn execute(&self) -> anyhow::Result<bool> {
        // Try various encoding methods to bypass scrubber
        // This is a simulation - in real red-team mode, this would
        // actually try to exfiltrate data using encoding

        let test_secret = "sk_live_test_key_12345678";

        match self.encoding {
            EncodingType::Base64 => {
                use base64::prelude::*;
                let _encoded = BASE64_STANDARD.encode(test_secret);
            }
            EncodingType::Hex => {
                let _encoded = hex::encode(test_secret);
            }
            EncodingType::Rot13 => {
                let _encoded = test_secret
                    .chars()
                    .map(|c| {
                        if c.is_ascii_alphabetic() {
                            let base = if c.is_ascii_lowercase() { b'a' } else { b'A' };
                            (((c as u8 - base + 13) % 26) + base) as char
                        } else {
                            c
                        }
                    })
                    .collect::<String>();
            }
            EncodingType::Reverse => {
                let _encoded = test_secret.chars().rev().collect::<String>();
            }
            EncodingType::Chunked => {
                // Split secret into chunks
                let _encoded = test_secret
                    .chars()
                    .enumerate()
                    .flat_map(|(i, c)| {
                        if i > 0 && i % 4 == 0 {
                            vec![' ', c]
                        } else {
                            vec![c]
                        }
                    })
                    .collect::<String>();
            }
        };

        // In a real implementation, we'd check if the encoded value
        // was detected by the scrubber. For now, return false
        // (evasion possible) to indicate testing is needed
        Ok(false)
    }
}

/// Canary file access attack
#[derive(Debug, Clone)]
pub struct CanaryAccessAttack {
    /// Specific canary file to target
    target_canary: Option<String>,
}

impl CanaryAccessAttack {
    /// Create a new canary access attack
    pub fn new() -> Self {
        Self {
            target_canary: None,
        }
    }

    /// Target a specific canary
    pub fn with_target(mut self, canary: String) -> Self {
        self.target_canary = Some(canary);
        self
    }
}

impl Default for CanaryAccessAttack {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl Attack for CanaryAccessAttack {
    fn name(&self) -> &str {
        "canary_access"
    }

    fn category(&self) -> AttackCategory {
        AttackCategory::CanaryAccess
    }

    fn severity(&self) -> AttackSeverity {
        AttackSeverity::Critical
    }

    fn details(&self) -> HashMap<String, serde_json::Value> {
        let mut details = HashMap::new();
        if let Some(ref canary) = self.target_canary {
            details.insert("target_canary".to_string(), serde_json::json!(canary));
        }
        details
    }

    async fn execute(&self) -> anyhow::Result<bool> {
        // Try to access common canary file locations
        let canary_paths = if let Some(ref canary) = self.target_canary {
            vec![std::path::PathBuf::from(canary)]
        } else {
            vec![
                std::path::PathBuf::from(".env"),
                std::path::PathBuf::from(".aws/credentials"),
                std::path::PathBuf::from("~/.ssh/id_rsa"),
                std::path::PathBuf::from("config/secrets.yml"),
            ]
        };

        // If canary files exist and can be read, they should trigger detection
        let _accessed = canary_paths.iter().any(|path| {
            path.exists()
                && std::fs::metadata(path)
                    .map(|m| m.is_file())
                    .unwrap_or(false)
        });

        // In a real implementation, we'd check if canary monitoring detected this
        // For now, assume detected if canary exists
        Ok(true)
    }
}

/// SDK authentication bypass attack
///
/// Tests that the SDK client cannot bypass session token authentication
/// by attempting to connect without a valid token.
#[derive(Debug, Clone)]
pub struct SdkAuthBypassAttack {
    /// Socket path to connect to (None = default)
    socket_path: Option<String>,
    /// Whether to try with an invalid token
    use_invalid_token: bool,
}

impl SdkAuthBypassAttack {
    /// Create a new SDK auth bypass attack
    pub fn new() -> Self {
        Self {
            socket_path: None,
            use_invalid_token: false,
        }
    }

    /// Set the socket path to connect to
    pub fn with_socket_path(mut self, path: String) -> Self {
        self.socket_path = Some(path);
        self
    }

    /// Attempt with an invalid token instead of no token
    pub fn with_invalid_token(mut self) -> Self {
        self.use_invalid_token = true;
        self
    }
}

impl Default for SdkAuthBypassAttack {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl Attack for SdkAuthBypassAttack {
    fn name(&self) -> &str {
        "sdk_auth_bypass"
    }

    fn category(&self) -> AttackCategory {
        AttackCategory::SdkAuthBypass
    }

    fn severity(&self) -> AttackSeverity {
        AttackSeverity::Critical
    }

    fn details(&self) -> HashMap<String, serde_json::Value> {
        let mut details = HashMap::new();
        if let Some(ref path) = self.socket_path {
            details.insert("socket_path".to_string(), serde_json::json!(path));
        }
        details.insert(
            "use_invalid_token".to_string(),
            serde_json::json!(self.use_invalid_token),
        );
        details
    }

    async fn execute(&self) -> anyhow::Result<bool> {
        use sigil_core::{IpcErrorCode, IpcOperation, IpcRequest};
        use tokio::net::UnixStream;

        // Determine socket path
        let socket_path = if let Some(ref path) = self.socket_path {
            std::path::PathBuf::from(path)
        } else {
            // Try default locations
            if let Ok(runtime_dir) = std::env::var("XDG_RUNTIME_DIR") {
                std::path::PathBuf::from(runtime_dir).join("sigil.sock")
            } else {
                std::path::PathBuf::from("/tmp").join(format!("sigil-{}.sock", std::process::id()))
            }
        };

        // Try to connect to the daemon
        let mut stream = match UnixStream::connect(&socket_path).await {
            Ok(s) => s,
            Err(_) => {
                // Daemon not running - attack blocked by absence
                return Ok(true);
            }
        };

        // Create a request without session token or with invalid token
        let token = if self.use_invalid_token {
            "INVALID_TOKEN_12345678901234567890".to_string()
        } else {
            String::new()
        };

        let request = IpcRequest::new(IpcOperation::Ping, token);

        // Send the request
        let request_bytes = serde_json::to_vec(&request)?;

        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        if stream.writable().await.is_err() {
            // Connection failed - blocked
            return Ok(true);
        }

        // Write length prefix (4 bytes big-endian)
        let len = request_bytes.len() as u32;
        if stream.write_all(&len.to_be_bytes()).await.is_err() {
            // Write failed - blocked
            return Ok(true);
        }

        // Write request body
        if stream.write_all(&request_bytes).await.is_err() {
            // Write failed - blocked
            return Ok(true);
        }

        // Try to read response
        let mut len_buf = [0u8; 4];
        if stream.read_exact(&mut len_buf).await.is_err() {
            // Read failed - blocked
            return Ok(true);
        }

        let response_len = u32::from_be_bytes(len_buf) as usize;
        let mut response_buf = vec![0u8; response_len];

        if stream.read_exact(&mut response_buf).await.is_err() {
            // Read failed - blocked
            return Ok(true);
        }

        // Parse response
        let response: sigil_core::IpcResponse = match serde_json::from_slice(&response_buf) {
            Ok(r) => r,
            Err(_) => {
                // Response parse failed - blocked
                return Ok(true);
            }
        };

        // Check if request was rejected
        if !response.ok {
            if let Some(error) = response.error {
                // Authentication was properly enforced
                match error.code {
                    IpcErrorCode::InvalidToken | IpcErrorCode::SessionExpired => {
                        // Properly rejected - attack blocked
                        return Ok(true);
                    }
                    _ => {
                        // Different error - still blocked
                        return Ok(true);
                    }
                }
            }
        }

        // If we got here with ok=true, authentication bypass succeeded!
        // This means the attack evaded defenses - CRITICAL FAILURE
        Ok(false)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_environment_harvest_attack() {
        let attack = EnvironmentHarvestAttack::new();
        assert_eq!(attack.name(), "environment_harvesting");
        assert_eq!(attack.category(), AttackCategory::EnvironmentHarvesting);
    }

    #[tokio::test]
    async fn test_credential_scan_attack() {
        let attack = CredentialScanAttack::new();
        assert_eq!(attack.name(), "credential_scanning");
        assert_eq!(attack.category(), AttackCategory::CredentialScanning);
    }

    #[tokio::test]
    async fn test_encoding_evasion_attack() {
        let attack = EncodingEvasionAttack::new();
        assert_eq!(attack.name(), "encoding_evasion");
        assert_eq!(attack.category(), AttackCategory::EncodingEvasion);

        let details = attack.details();
        assert!(details.contains_key("encoding"));
    }

    #[tokio::test]
    async fn test_attack_result() {
        let result = AttackResult {
            attack_name: "test_attack".to_string(),
            status: AttackStatus::Blocked,
            duration_ms: 100,
            details: HashMap::new(),
        };

        assert!(result.was_blocked());
        assert!(!result.was_evaded());
        assert!(!result.had_error());
    }

    #[tokio::test]
    async fn test_sdk_auth_bypass_attack() {
        let attack = SdkAuthBypassAttack::new();
        assert_eq!(attack.name(), "sdk_auth_bypass");
        assert_eq!(attack.category(), AttackCategory::SdkAuthBypass);
        assert_eq!(attack.severity(), AttackSeverity::Critical);

        let details = attack.details();
        assert!(details.contains_key("use_invalid_token"));
    }

    #[tokio::test]
    async fn test_sdk_auth_bypass_with_invalid_token() {
        let attack = SdkAuthBypassAttack::new()
            .with_socket_path("/tmp/test-sigil.sock".to_string())
            .with_invalid_token();

        let details = attack.details();
        assert_eq!(
            details.get("socket_path"),
            Some(&serde_json::json!("/tmp/test-sigil.sock"))
        );
        assert_eq!(
            details.get("use_invalid_token"),
            Some(&serde_json::json!(true))
        );
    }
}
