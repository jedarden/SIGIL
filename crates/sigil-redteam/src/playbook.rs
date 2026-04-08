//! Attack playbook definitions
//!
//! Structured YAML format for defining attack sequences.

use crate::attack::{
    Attack, AttackCategory, AttackSeverity, CanaryAccessAttack, CredentialScanAttack,
    DecoyDistinguishabilityAttack, DoctorMisconfigDetectionAttack, EncodingEvasionAttack,
    EncodingType, EnvironmentHarvestAttack, FuseMountAccessAttack, GitCredentialExposureAttack,
    LockdownVerificationAttack, MemoryReadAttack, ProxyAuthVisibilityAttack,
    ProxyDomainBypassAttack, PtraceAttack, RequestAutoRevokeAttack, SdkAuthBypassAttack,
    SealedOpExtractionAttack, SshKeyExtractionAttack,
};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::Path;
use std::sync::Arc;

/// Collection of attacks organized as a playbook
#[derive(Clone)]
pub struct AttackPlaybook {
    /// Name of the playbook
    name: String,
    /// Description of the playbook
    description: String,
    /// Version of the playbook format
    version: String,
    /// Attacks in the playbook
    attacks: Vec<Arc<dyn Attack>>,
}

impl AttackPlaybook {
    /// Create a new empty playbook
    pub fn new(name: String, description: String) -> Self {
        Self {
            name,
            description,
            version: "1.0".to_string(),
            attacks: Vec::new(),
        }
    }

    /// Load the built-in default playbook
    pub fn builtin() -> anyhow::Result<Self> {
        let mut playbook = Self::new(
            "SIGIL Default Attack Playbook".to_string(),
            "Built-in adversarial testing attacks for SIGIL security validation".to_string(),
        );

        // Phase 7: Breach Detection and Canary Access
        playbook.add_attack(Arc::new(EnvironmentHarvestAttack::new()));
        playbook.add_attack(Arc::new(CredentialScanAttack::new()));
        playbook.add_attack(Arc::new(MemoryReadAttack));
        playbook.add_attack(Arc::new(PtraceAttack));
        playbook.add_attack(Arc::new(CanaryAccessAttack::new()));

        // Add encoding evasion variants
        for encoding in [
            EncodingType::Base64,
            EncodingType::Hex,
            EncodingType::Rot13,
            EncodingType::Reverse,
            EncodingType::Chunked,
        ] {
            playbook.add_attack(Arc::new(
                EncodingEvasionAttack::new().with_encoding(encoding),
            ));
        }

        // Phase 8: SDK Authentication
        playbook.add_attack(Arc::new(SdkAuthBypassAttack::new()));

        // Phase 9: Platform Features
        playbook.add_attack(Arc::new(FuseMountAccessAttack::new()));
        playbook.add_attack(Arc::new(
            FuseMountAccessAttack::new().with_target("/sigil/aws/credentials".to_string()),
        ));
        playbook.add_attack(Arc::new(ProxyAuthVisibilityAttack::new()));
        playbook.add_attack(Arc::new(ProxyDomainBypassAttack::new()));
        playbook.add_attack(Arc::new(GitCredentialExposureAttack));
        playbook.add_attack(Arc::new(SshKeyExtractionAttack));
        playbook.add_attack(Arc::new(DecoyDistinguishabilityAttack::new()));
        playbook.add_attack(Arc::new(
            DecoyDistinguishabilityAttack::new().with_secret_type("aws".to_string()),
        ));
        playbook.add_attack(Arc::new(SealedOpExtractionAttack::new()));
        playbook.add_attack(Arc::new(RequestAutoRevokeAttack::new()));
        playbook.add_attack(Arc::new(LockdownVerificationAttack::new()));
        playbook.add_attack(Arc::new(DoctorMisconfigDetectionAttack::new()));

        Ok(playbook)
    }

    /// Load a playbook from a YAML file
    pub fn from_yaml_file(path: &Path) -> anyhow::Result<Self> {
        let content = std::fs::read_to_string(path)?;
        Self::from_yaml(&content)
    }

    /// Load a playbook from a YAML string
    pub fn from_yaml(yaml_str: &str) -> anyhow::Result<Self> {
        let yaml: PlaybookFormat = serde_yaml::from_str(yaml_str)?;
        yaml.into_playbook()
    }

    /// Add an attack to the playbook
    pub fn add_attack(&mut self, attack: Arc<dyn Attack>) {
        self.attacks.push(attack);
    }

    /// Get all attacks in the playbook
    pub fn attacks(&self) -> Vec<Arc<dyn Attack>> {
        self.attacks.clone()
    }

    /// Find an attack by name
    pub fn find_attack(&self, name: &str) -> Option<Arc<dyn Attack>> {
        self.attacks.iter().find(|a| a.name() == name).cloned()
    }

    /// Get the playbook name
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Get the playbook description
    pub fn description(&self) -> &str {
        &self.description
    }

    /// Export to YAML format
    pub fn to_yaml(&self) -> anyhow::Result<String> {
        let mut format = PlaybookFormat {
            name: self.name.clone(),
            description: self.description.clone(),
            version: self.version.clone(),
            attacks: Vec::new(),
        };

        for attack in &self.attacks {
            format.attacks.push(AttackDefinition {
                name: attack.name().to_string(),
                category: format!("{:?}", attack.category()),
                severity: format!("{:?}", attack.severity()),
                enabled: true,
                params: attack.details(),
            });
        }

        serde_yaml::to_string(&format).map_err(Into::into)
    }
}

/// YAML format for attack playbooks
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PlaybookFormat {
    /// Name of the playbook
    pub name: String,
    /// Description of what the playbook tests
    pub description: String,
    /// Version of the playbook format
    pub version: String,
    /// Attack definitions
    #[serde(default)]
    pub attacks: Vec<AttackDefinition>,
}

impl PlaybookFormat {
    /// Convert the YAML format to a playbook
    pub fn into_playbook(self) -> anyhow::Result<AttackPlaybook> {
        let mut playbook = AttackPlaybook::new(self.name, self.description);

        for def in self.attacks {
            if !def.enabled {
                continue;
            }

            // Convert attack definition to actual Attack
            let attack: Arc<dyn Attack> = match def.name.as_str() {
                "environment_harvesting" => Arc::new(EnvironmentHarvestAttack::new()),
                "credential_scanning" => Arc::new(CredentialScanAttack::new()),
                "memory_reading" => Arc::new(MemoryReadAttack),
                "ptrace_attempt" => Arc::new(PtraceAttack),
                "encoding_evasion" => {
                    let encoding = def
                        .params
                        .get("encoding")
                        .and_then(|v| v.as_str())
                        .and_then(|s| match s {
                            "Base64" => Some(EncodingType::Base64),
                            "Hex" => Some(EncodingType::Hex),
                            "Rot13" => Some(EncodingType::Rot13),
                            "Reverse" => Some(EncodingType::Reverse),
                            "Chunked" => Some(EncodingType::Chunked),
                            _ => None,
                        })
                        .unwrap_or(EncodingType::Base64);

                    Arc::new(EncodingEvasionAttack::new().with_encoding(encoding))
                }
                "canary_access" => Arc::new(CanaryAccessAttack::new()),
                "sdk_auth_bypass" => Arc::new(SdkAuthBypassAttack::new()),
                "fuse_mount_access" => {
                    let mut attack = FuseMountAccessAttack::new();
                    if let Some(path) = def.params.get("target_path").and_then(|v| v.as_str()) {
                        attack = attack.with_target(path.to_string());
                    }
                    Arc::new(attack)
                }
                "proxy_auth_visibility" => Arc::new(ProxyAuthVisibilityAttack::new()),
                "proxy_domain_bypass" => Arc::new(ProxyDomainBypassAttack::new()),
                "git_credential_exposure" => Arc::new(GitCredentialExposureAttack),
                "ssh_key_extraction" => Arc::new(SshKeyExtractionAttack),
                "decoy_distinguishability" => {
                    let mut attack = DecoyDistinguishabilityAttack::new();
                    if let Some(secret_type) =
                        def.params.get("secret_type").and_then(|v| v.as_str())
                    {
                        attack = attack.with_secret_type(secret_type.to_string());
                    }
                    Arc::new(attack)
                }
                "sealed_op_extraction" => Arc::new(SealedOpExtractionAttack::new()),
                "request_auto_revoke" => Arc::new(RequestAutoRevokeAttack::new()),
                "lockdown_verification" => Arc::new(LockdownVerificationAttack::new()),
                "doctor_misconfig_detection" => Arc::new(DoctorMisconfigDetectionAttack::new()),
                _ => {
                    return Err(anyhow::anyhow!("Unknown attack type: {}", def.name));
                }
            };

            playbook.add_attack(attack);
        }

        Ok(playbook)
    }
}

/// Attack definition in YAML format
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttackDefinition {
    /// Name of the attack
    pub name: String,
    /// Category of the attack
    pub category: String,
    /// Severity level
    pub severity: String,
    /// Whether the attack is enabled
    #[serde(default = "default_enabled")]
    pub enabled: bool,
    /// Attack-specific parameters
    #[serde(default)]
    pub params: HashMap<String, serde_json::Value>,
}

fn default_enabled() -> bool {
    true
}

impl AttackDefinition {
    /// Get the attack category
    pub fn category(&self) -> AttackCategory {
        match self.category.as_str() {
            "EnvironmentHarvesting" => AttackCategory::EnvironmentHarvesting,
            "CredentialScanning" => AttackCategory::CredentialScanning,
            "MemoryReading" => AttackCategory::MemoryReading,
            "NetworkExfiltration" => AttackCategory::NetworkExfiltration,
            "SocketDiscovery" => AttackCategory::SocketDiscovery,
            "PathManipulation" => AttackCategory::PathManipulation,
            "Ptrace" => AttackCategory::Ptrace,
            "EncodingEvasion" => AttackCategory::EncodingEvasion,
            "PromptInjection" => AttackCategory::PromptInjection,
            "CanaryAccess" => AttackCategory::CanaryAccess,
            "SecretExfiltration" => AttackCategory::SecretExfiltration,
            "SdkAuthBypass" => AttackCategory::SdkAuthBypass,
            "FuseMountAccess" => AttackCategory::FuseMountAccess,
            "ProxyAuthVisibility" => AttackCategory::ProxyAuthVisibility,
            "ProxyDomainBypass" => AttackCategory::ProxyDomainBypass,
            "GitCredentialExposure" => AttackCategory::GitCredentialExposure,
            "SshKeyExtraction" => AttackCategory::SshKeyExtraction,
            "DecoyDistinguishability" => AttackCategory::DecoyDistinguishability,
            "SealedOpExtraction" => AttackCategory::SealedOpExtraction,
            "RequestAutoRevoke" => AttackCategory::RequestAutoRevoke,
            "LockdownVerification" => AttackCategory::LockdownVerification,
            "DoctorMisconfigDetection" => AttackCategory::DoctorMisconfigDetection,
            _ => AttackCategory::EnvironmentHarvesting,
        }
    }

    /// Get the attack severity
    pub fn severity(&self) -> AttackSeverity {
        match self.severity.as_str() {
            "Low" => AttackSeverity::Low,
            "Medium" => AttackSeverity::Medium,
            "High" => AttackSeverity::High,
            "Critical" => AttackSeverity::Critical,
            _ => AttackSeverity::Medium,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_builtin_playbook() {
        let playbook = AttackPlaybook::builtin().unwrap();
        assert_eq!(playbook.name(), "SIGIL Default Attack Playbook");
        assert!(!playbook.attacks().is_empty());
    }

    #[test]
    fn test_playbook_yaml_roundtrip() {
        let playbook = AttackPlaybook::builtin().unwrap();
        let yaml = playbook.to_yaml().unwrap();

        // Parse it back
        let parsed = AttackPlaybook::from_yaml(&yaml).unwrap();
        assert_eq!(parsed.name(), playbook.name());
        assert!(!parsed.attacks().is_empty());
    }

    #[test]
    fn test_attack_definition() {
        let def = AttackDefinition {
            name: "test_attack".to_string(),
            category: "EnvironmentHarvesting".to_string(),
            severity: "High".to_string(),
            enabled: true,
            params: HashMap::new(),
        };

        assert_eq!(def.category(), AttackCategory::EnvironmentHarvesting);
        assert_eq!(def.severity(), AttackSeverity::High);
    }

    #[test]
    fn test_yaml_format() {
        let yaml = r#"
name: "Test Playbook"
description: "A test playbook"
version: "1.0"
attacks:
  - name: "environment_harvesting"
    category: "EnvironmentHarvesting"
    severity: "High"
    enabled: true
    params: {}
  - name: "canary_access"
    category: "CanaryAccess"
    severity: "Critical"
    enabled: true
    params: {}
"#;

        let playbook = AttackPlaybook::from_yaml(yaml).unwrap();
        assert_eq!(playbook.name(), "Test Playbook");
        assert_eq!(playbook.attacks().len(), 2);
    }
}
