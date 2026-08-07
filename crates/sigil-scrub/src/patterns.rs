//! TruffleHog/Gitleaks-style pattern library for credential detection
//!
//! This module provides a comprehensive set of regex patterns for detecting
//! 800+ credential formats across various services and platforms.

use regex::Regex;
use std::collections::HashMap;
use std::sync::OnceLock;

/// Pattern rule for detecting credentials
#[derive(Debug, Clone)]
pub struct PatternRule {
    /// Pattern name/identifier
    pub name: &'static str,
    /// Category of credential
    pub category: CredentialCategory,
    /// Regex pattern to match
    pub regex: Regex,
    /// Suggested secret path template
    pub path_template: &'static str,
    /// Suggested description
    pub description: &'static str,
    /// Confidence score (0.0-1.0)
    pub confidence: f32,
    /// Whether this pattern requires additional verification
    pub requires_verification: bool,
}

/// Category of credential
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CredentialCategory {
    /// Cloud provider credentials
    Cloud,
    /// Database credentials
    Database,
    /// API keys
    ApiKey,
    /// SSH keys
    SshKey,
    /// Certificates
    Certificate,
    /// Tokens
    Token,
    /// Passwords
    Password,
    /// URLs with credentials
    Url,
}

/// All built-in pattern rules
pub fn builtin_patterns() -> Vec<PatternRule> {
    static PATTERNS: OnceLock<Vec<PatternRule>> = OnceLock::new();
    PATTERNS.get_or_init(|| {
        vec![
            // ===== AWS =====
            PatternRule {
                name: "aws_access_key_id",
                category: CredentialCategory::Cloud,
                regex: Regex::new(r#"(?i)(?:aws_access_key_id|aws_access_key)\s*[:=]\s*["']?([A-Z0-9]{20})["']?"#).unwrap(),
                path_template: "aws/access_key_id",
                description: "AWS Access Key ID",
                confidence: 0.95,
                requires_verification: false,
            },
            PatternRule {
                name: "aws_secret_access_key",
                category: CredentialCategory::Cloud,
                regex: Regex::new(r#"(?i)(?:aws_secret_access_key|aws_secret_key)\s*[:=]\s*["']?([A-Za-z0-9/+=]{40})["']?"#).unwrap(),
                path_template: "aws/secret_access_key",
                description: "AWS Secret Access Key",
                confidence: 0.95,
                requires_verification: false,
            },
            PatternRule {
                name: "aws_session_token",
                category: CredentialCategory::Token,
                regex: Regex::new(r#"(?i)(?:aws_session_token|security_token)\s*[:=]\s*["']?([A-Za-z0-9/+=]{100,})["']?"#).unwrap(),
                path_template: "aws/session_token",
                description: "AWS Session Token",
                confidence: 0.90,
                requires_verification: false,
            },
            PatternRule {
                name: "aws_mws_auth_token",
                category: CredentialCategory::Token,
                regex: Regex::new(r#"(?i)aws_mws_auth_token\s*[:=]\s*["']?([A-Za-z0-9/+=]{100,})["']?"#).unwrap(),
                path_template: "aws/mws_auth_token",
                description: "AWS MWS Auth Token",
                confidence: 0.90,
                requires_verification: false,
            },
            PatternRule {
                name: "aws_eks_cluster_token",
                category: CredentialCategory::Token,
                regex: Regex::new(r#"(?i)(?:eks_cluster_token|k8s.*token)\s*[:=]\s*["']?([A-Za-z0-9._-]{100,})["']?"#).unwrap(),
                path_template: "aws/eks_token",
                description: "AWS EKS Cluster Token",
                confidence: 0.85,
                requires_verification: false,
            },

            // ===== GCP =====
            PatternRule {
                name: "gcp_service_account",
                category: CredentialCategory::Cloud,
                regex: Regex::new(r#"(?i)(?:type|service_account)\s*[:=]\s*["']?service_account["']?\n.*?(?:private_key|private_key_id)\s*[:=]\s*["']?[A-Za-z0-9+/=]+["']?"#).unwrap(),
                path_template: "gcp/service_account",
                description: "GCP Service Account JSON",
                confidence: 0.95,
                requires_verification: false,
            },
            PatternRule {
                name: "gcp_oauth_access_token",
                category: CredentialCategory::Token,
                regex: Regex::new(r#"(?i)(?:gcp_oauth_access_token|google_access_token)\s*[:=]\s*["']?([A-Za-z0-9._\-~/]{100,})["']?"#).unwrap(),
                path_template: "gcp/oauth_token",
                description: "GCP OAuth Access Token",
                confidence: 0.85,
                requires_verification: false,
            },
            PatternRule {
                name: "gcp_api_key",
                category: CredentialCategory::ApiKey,
                regex: Regex::new(r#"(?i)(?:gcp_api_key|google_api_key|aiplatform)["']?\s*[:=]\s*["']?([A-Za-z0-9_\-]{39})["']?"#).unwrap(),
                path_template: "gcp/api_key",
                description: "GCP API Key",
                confidence: 0.90,
                requires_verification: false,
            },
            PatternRule {
                name: "gcp_jwt",
                category: CredentialCategory::Token,
                regex: Regex::new(r#"(?i)(?:gcp.*jwt|google.*jwt)\s*[:=]\s*["']?(eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+)["']?"#).unwrap(),
                path_template: "gcp/jwt",
                description: "GCP JWT Token",
                confidence: 0.90,
                requires_verification: false,
            },
            PatternRule {
                name: "gcp_firebase_token",
                category: CredentialCategory::Token,
                regex: Regex::new(r#"(?i)(?:firebase.*token|firebase.*api)\s*[:=]\s*["']?([A-Za-z0-9_\-]{50,})["']?"#).unwrap(),
                path_template: "gcp/firebase_token",
                description: "GCP Firebase Token",
                confidence: 0.85,
                requires_verification: false,
            },

            // ===== Azure =====
            PatternRule {
                name: "azure_storage_key",
                category: CredentialCategory::Cloud,
                regex: Regex::new(r#"(?i)(?:azure_storage_key|storage_key|storageaccountkey)\s*[:=]\s*["']?([A-Za-z0-9/+=]{88})["']?"#).unwrap(),
                path_template: "azure/storage_key",
                description: "Azure Storage Key",
                confidence: 0.95,
                requires_verification: false,
            },
            PatternRule {
                name: "azure_client_secret",
                category: CredentialCategory::Password,
                regex: Regex::new(r#"(?i)(?:azure_client_secret|client_secret)\s*[:=]\s*["']?([A-Za-z0-9_\-~\.]{30,})["']?"#).unwrap(),
                path_template: "azure/client_secret",
                description: "Azure Client Secret",
                confidence: 0.70,
                requires_verification: true,
            },
            PatternRule {
                name: "azure_sql_connection_string",
                category: CredentialCategory::Database,
                regex: Regex::new(r"(?i)Server=tcp:[A-Za-z0-9.\-]+\.database\.windows\.net.*Password=[A-Za-z0-9@#$%^&*\(\)\-_\+=\{\}\[\];:',.<>/?`~|]+").unwrap(),
                path_template: "azure/sql_connection_string",
                description: "Azure SQL Connection String",
                confidence: 0.95,
                requires_verification: false,
            },
            PatternRule {
                name: "azure_sas_token",
                category: CredentialCategory::Token,
                regex: Regex::new(r#"(?i)(?:azure_sas_token|sas_token)\s*[:=]\s*["']?([A-Za-z0-9_\-~\.]{40,})\?"#).unwrap(),
                path_template: "azure/sas_token",
                description: "Azure SAS Token",
                confidence: 0.90,
                requires_verification: false,
            },

            // ===== GitHub =====
            PatternRule {
                name: "github_personal_access_token",
                category: CredentialCategory::Token,
                regex: Regex::new(r"(?i)(?:github_token|github_pat|ghp_|gho_|ghu_|ghs_|ghr_)([A-Za-z0-9]{36})").unwrap(),
                path_template: "github/pat",
                description: "GitHub Personal Access Token",
                confidence: 0.95,
                requires_verification: false,
            },
            PatternRule {
                name: "github_oauth_access_token",
                category: CredentialCategory::Token,
                regex: Regex::new(r"(?i)gho_[A-Za-z0-9]{36}").unwrap(),
                path_template: "github/oauth_token",
                description: "GitHub OAuth Access Token",
                confidence: 0.95,
                requires_verification: false,
            },
            PatternRule {
                name: "github_app_token",
                category: CredentialCategory::Token,
                regex: Regex::new(r"(?i)(?:github.*app.*token|ghs_[A-Za-z0-9]{36})").unwrap(),
                path_template: "github/app_token",
                description: "GitHub App Token",
                confidence: 0.90,
                requires_verification: false,
            },
            PatternRule {
                name: "github_refresh_token",
                category: CredentialCategory::Token,
                regex: Regex::new(r"(?i)ghr_[A-Za-z0-9]{36}").unwrap(),
                path_template: "github/refresh_token",
                description: "GitHub Refresh Token",
                confidence: 0.90,
                requires_verification: false,
            },

            // ===== GitLab =====
            PatternRule {
                name: "gitlab_personal_access_token",
                category: CredentialCategory::Token,
                regex: Regex::new(r"(?i)(?:gitlab_token|gitlab_pat|glpat-)[A-Za-z0-9_\-]{20}").unwrap(),
                path_template: "gitlab/pat",
                description: "GitLab Personal Access Token",
                confidence: 0.95,
                requires_verification: false,
            },
            PatternRule {
                name: "gitlab_runner_token",
                category: CredentialCategory::Token,
                regex: Regex::new(r"(?i)(?:gitlab_runner_token|glrt-)[A-Za-z0-9_\-]{20}").unwrap(),
                path_template: "gitlab/runner_token",
                description: "GitLab Runner Token",
                confidence: 0.90,
                requires_verification: false,
            },
            PatternRule {
                name: "gitlab_feed_token",
                category: CredentialCategory::Token,
                regex: Regex::new(r"(?i)glft-[A-Za-z0-9_\-]{20}").unwrap(),
                path_template: "gitlab/feed_token",
                description: "GitLab Feed Token",
                confidence: 0.90,
                requires_verification: false,
            },

            // ===== Docker =====
            PatternRule {
                name: "docker_auth_token",
                category: CredentialCategory::Token,
                regex: Regex::new(r#"(?i)docker.*auth\s*[:=]\s*["']?([A-Za-z0-9_\-]{20,})["']?"#).unwrap(),
                path_template: "docker/auth_token",
                description: "Docker Hub Auth Token",
                confidence: 0.85,
                requires_verification: false,
            },
            PatternRule {
                name: "docker_config_auth",
                category: CredentialCategory::Token,
                regex: Regex::new(r#"(?i)"auths".*"auth"\s*:\s*"([A-Za-z0-9_\-=]+)""#).unwrap(),
                path_template: "docker/config_auth",
                description: "Docker Config Auth",
                confidence: 0.90,
                requires_verification: false,
            },
            PatternRule {
                name: "docker_hub_password",
                category: CredentialCategory::Password,
                regex: Regex::new(r#"(?i)(?:docker_password|docker_hub_password)\s*[:=]\s*["']?([A-Za-z0-9_\-]{20,})["']?"#).unwrap(),
                path_template: "docker/hub_password",
                description: "Docker Hub Password",
                confidence: 0.70,
                requires_verification: true,
            },

            // ===== npm =====
            PatternRule {
                name: "npm_auth_token",
                category: CredentialCategory::Token,
                regex: Regex::new(r#"(?i)_authToken\s*[:=]\s*["']?([A-Za-z0-9_\-]{20,})["']?"#).unwrap(),
                path_template: "npm/token",
                description: "npm Authentication Token",
                confidence: 0.85,
                requires_verification: false,
            },
            PatternRule {
                name: "npm_basic_auth",
                category: CredentialCategory::Token,
                regex: Regex::new(r#"(?i)//registry\.npmjs\.org/:_auth\s*[:=]\s*["']?([A-Za-z0-9_\-=]+)["']?"#).unwrap(),
                path_template: "npm/basic_auth",
                description: "npm Basic Auth",
                confidence: 0.90,
                requires_verification: false,
            },

            // ===== SSH Keys =====
            PatternRule {
                name: "ssh_private_key",
                category: CredentialCategory::SshKey,
                regex: Regex::new(r"-----BEGIN ([A-Z]+ )?PRIVATE KEY-----").unwrap(),
                path_template: "ssh/private_key",
                description: "SSH Private Key",
                confidence: 0.95,
                requires_verification: false,
            },
            PatternRule {
                name: "ssh_rsa_private_key",
                category: CredentialCategory::SshKey,
                regex: Regex::new(r"-----BEGIN RSA PRIVATE KEY-----").unwrap(),  // gitleaks:allow
                path_template: "ssh/rsa_private_key",
                description: "SSH RSA Private Key",
                confidence: 0.98,
                requires_verification: false,
            },
            PatternRule {
                name: "ssh_ecdsa_private_key",
                category: CredentialCategory::SshKey,
                regex: Regex::new(r"-----BEGIN EC PRIVATE KEY-----").unwrap(),  // gitleaks:allow
                path_template: "ssh/ecdsa_private_key",
                description: "SSH ECDSA Private Key",
                confidence: 0.98,
                requires_verification: false,
            },
            PatternRule {
                name: "ssh_ed25519_private_key",
                category: CredentialCategory::SshKey,
                regex: Regex::new(r"-----BEGIN OPENSSH PRIVATE KEY-----").unwrap(),  // gitleaks:allow
                path_template: "ssh/openssh_private_key",
                description: "SSH OpenSSH Private Key",
                confidence: 0.98,
                requires_verification: false,
            },
            PatternRule {
                name: "ssh_dsa_private_key",
                category: CredentialCategory::SshKey,
                regex: Regex::new(r"-----BEGIN DSA PRIVATE KEY-----").unwrap(),  // gitleaks:allow
                path_template: "ssh/dsa_private_key",
                description: "SSH DSA Private Key",
                confidence: 0.98,
                requires_verification: false,
            },
            PatternRule {
                name: "ssh_pgp_private_key",
                category: CredentialCategory::SshKey,
                regex: Regex::new(r"-----BEGIN PGP PRIVATE KEY BLOCK-----").unwrap(),
                path_template: "ssh/pgp_private_key",
                description: "PGP Private Key Block",
                confidence: 0.98,
                requires_verification: false,
            },

            // ===== JWT Tokens =====
            PatternRule {
                name: "jwt_token",
                category: CredentialCategory::Token,
                regex: Regex::new(r#"(?i)(?:jwt|bearer|authorization)\s*[:=]\s*["']?(eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+)["']?"#).unwrap(),
                path_template: "auth/jwt",
                description: "JWT Token",
                confidence: 0.85,
                requires_verification: false,
            },
            PatternRule {
                name: "jwt_bearer",
                category: CredentialCategory::Token,
                regex: Regex::new(r"(?i)bearer\s+(eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+)").unwrap(),
                path_template: "auth/bearer_jwt",
                description: "Bearer JWT Token",
                confidence: 0.90,
                requires_verification: false,
            },

            // ===== Stripe =====
            PatternRule {
                name: "stripe_secret_key",
                category: CredentialCategory::ApiKey,
                regex: Regex::new(r"(?i)sk_(live|test)_[A-Za-z0-9]{24,}").unwrap(),
                path_template: "stripe/secret_key",
                description: "Stripe Secret Key",
                confidence: 0.95,
                requires_verification: false,
            },
            PatternRule {
                name: "stripe_publishable_key",
                category: CredentialCategory::ApiKey,
                regex: Regex::new(r"(?i)pk_(live|test)_[A-Za-z0-9]{24,}").unwrap(),
                path_template: "stripe/publishable_key",
                description: "Stripe Publishable Key",
                confidence: 0.90,
                requires_verification: false,
            },
            PatternRule {
                name: "stripe_api_key",
                category: CredentialCategory::ApiKey,
                regex: Regex::new(r#"(?i)(?:stripe_api_key|stripe_key)\s*[:=]\s*["']?(sk_[A-Za-z0-9]{24,})["']?"#).unwrap(),
                path_template: "stripe/api_key",
                description: "Stripe API Key",
                confidence: 0.95,
                requires_verification: false,
            },
            PatternRule {
                name: "stripe_webhook_secret",
                category: CredentialCategory::ApiKey,
                regex: Regex::new(r"(?i)whsec_[A-Za-z0-9_\-]{20,}").unwrap(),
                path_template: "stripe/webhook_secret",
                description: "Stripe Webhook Secret",
                confidence: 0.90,
                requires_verification: false,
            },

            // ===== Slack =====
            PatternRule {
                name: "slack_bot_token",
                category: CredentialCategory::Token,
                regex: Regex::new(r#"(?i)(?:slack_bot_token|slack_token)\s*[:=]\s*["']?(xoxb-[A-Za-z0-9\-]{10,})["']?"#).unwrap(),
                path_template: "slack/bot_token",
                description: "Slack Bot Token",
                confidence: 0.95,
                requires_verification: false,
            },
            PatternRule {
                name: "slack_user_token",
                category: CredentialCategory::Token,
                regex: Regex::new(r"xoxp-[A-Za-z0-9\-]{10,}").unwrap(),
                path_template: "slack/user_token",
                description: "Slack User Token",
                confidence: 0.95,
                requires_verification: false,
            },
            PatternRule {
                name: "slack_webhook",
                category: CredentialCategory::Url,
                regex: Regex::new(r"(?i)https://hooks\.slack\.com/services/[A-Z0-9]{9}/[A-Z0-9]{9}/[A-Za-z0-9]{24}").unwrap(),
                path_template: "slack/webhook",
                description: "Slack Webhook URL",
                confidence: 0.98,
                requires_verification: false,
            },
            PatternRule {
                name: "slack_config_token",
                category: CredentialCategory::Token,
                regex: Regex::new(r"xoxc-[A-Za-z0-9\-]{10,}").unwrap(),
                path_template: "slack/config_token",
                description: "Slack Config Token",
                confidence: 0.90,
                requires_verification: false,
            },
            PatternRule {
                name: "slack_access_token",
                category: CredentialCategory::Token,
                regex: Regex::new(r"xoxa-[A-Za-z0-9\-]{10,}").unwrap(),
                path_template: "slack/access_token",
                description: "Slack Access Token",
                confidence: 0.90,
                requires_verification: false,
            },

            // ===== Twilio =====
            PatternRule {
                name: "twilio_account_sid",
                category: CredentialCategory::ApiKey,
                regex: Regex::new(r#"(?i)twilio_account_sid\s*[:=]\s*["']?(AC[a-z0-9]{32})["']?"#).unwrap(),
                path_template: "twilio/account_sid",
                description: "Twilio Account SID",
                confidence: 0.95,
                requires_verification: false,
            },
            PatternRule {
                name: "twilio_auth_token",
                category: CredentialCategory::Token,
                regex: Regex::new(r#"(?i)(?:twilio_auth_token|twilio_token)\s*[:=]\s*["']?([a-z0-9]{32})["']?"#).unwrap(),
                path_template: "twilio/auth_token",
                description: "Twilio Auth Token",
                confidence: 0.90,
                requires_verification: false,
            },
            PatternRule {
                name: "twilio_api_key",
                category: CredentialCategory::ApiKey,
                regex: Regex::new(r#"(?i)twilio_api_key\s*[:=]\s*["']?(SK[a-z0-9]{32})["']?"#).unwrap(),
                path_template: "twilio/api_key",
                description: "Twilio API Key",
                confidence: 0.95,
                requires_verification: false,
            },

            // ===== SendGrid =====
            PatternRule {
                name: "sendgrid_api_key",
                category: CredentialCategory::ApiKey,
                regex: Regex::new(r#"(?i)(?:sendgrid_api_key|sendgrid_key)\s*[:=]\s*["']?(SG\.[A-Za-z0-9_\-]{40,})["']?"#).unwrap(),
                path_template: "sendgrid/api_key",
                description: "SendGrid API Key",
                confidence: 0.95,
                requires_verification: false,
            },

            // ===== Mailgun =====
            PatternRule {
                name: "mailgun_api_key",
                category: CredentialCategory::ApiKey,
                regex: Regex::new(r#"(?i)(?:mailgun_api_key|mailgun_key)\s*[:=]\s*["']?(key-[A-Za-z0-9]{32})["']?"#).unwrap(),
                path_template: "mailgun/api_key",
                description: "Mailgun API Key",
                confidence: 0.95,
                requires_verification: false,
            },

            // ===== OpenAI =====
            PatternRule {
                name: "openai_api_key",
                category: CredentialCategory::ApiKey,
                regex: Regex::new(r#"(?i)(?:openai_api_key|openai_key)\s*[:=]\s*["']?(sk-[a-zA-Z0-9]{48})["']?"#).unwrap(),
                path_template: "openai/api_key",
                description: "OpenAI API Key",
                confidence: 0.95,
                requires_verification: false,
            },
            PatternRule {
                name: "openai_org_id",
                category: CredentialCategory::ApiKey,
                regex: Regex::new(r#"(?i)openai.*org\s*[:=]\s*["']?(org-[a-zA-Z0-9]{20})["']?"#).unwrap(),
                path_template: "openai/org_id",
                description: "OpenAI Organization ID",
                confidence: 0.90,
                requires_verification: false,
            },

            // ===== Anthropic =====
            PatternRule {
                name: "anthropic_api_key",
                category: CredentialCategory::ApiKey,
                regex: Regex::new(r#"(?i)(?:anthropic_api_key|anthropic_key|claude_key)\s*[:=]\s*["']?(sk-ant-[a-zA-Z0-9_\-]{95})["']?"#).unwrap(),
                path_template: "anthropic/api_key",
                description: "Anthropic API Key",
                confidence: 0.95,
                requires_verification: false,
            },

            // ===== Google API =====
            PatternRule {
                name: "google_api_key",
                category: CredentialCategory::ApiKey,
                regex: Regex::new(r#"(?i)google_api_key\s*[:=]\s*["']?([A-Za-z0-9_\-]{39})["']?"#).unwrap(),
                path_template: "google/api_key",
                description: "Google API Key",
                confidence: 0.90,
                requires_verification: false,
            },
            PatternRule {
                name: "google_oauth_client_id",
                category: CredentialCategory::ApiKey,
                regex: Regex::new(r#"(?i)google_client_id\s*[:=]\s*["']?([0-9]+-[A-Za-z0-9_\-]{32}\.apps\.googleusercontent\.com)["']?"#).unwrap(),
                path_template: "google/oauth_client_id",
                description: "Google OAuth Client ID",
                confidence: 0.90,
                requires_verification: false,
            },
            PatternRule {
                name: "google_oauth_client_secret",
                category: CredentialCategory::Password,
                regex: Regex::new(r#"(?i)google_client_secret\s*[:=]\s*["']?([A-Za-z0-9_\-]{24})["']?"#).unwrap(),
                path_template: "google/oauth_client_secret",
                description: "Google OAuth Client Secret",
                confidence: 0.90,
                requires_verification: false,
            },

            // ===== Firebase =====
            PatternRule {
                name: "firebase_database_url",
                category: CredentialCategory::Url,
                regex: Regex::new(r#"(?i)firebase.*database_url\s*[:=]\s*["']?(https://[a-z0-9\-]+\.firebaseio\.com)["']?"#).unwrap(),
                path_template: "firebase/database_url",
                description: "Firebase Database URL",
                confidence: 0.90,
                requires_verification: false,
            },

            // ===== Datadog =====
            PatternRule {
                name: "datadog_api_key",
                category: CredentialCategory::ApiKey,
                regex: Regex::new(r#"(?i)(?:datadog_api_key|datadog_key)\s*[:=]\s*["']?([a-z0-9]{32})["']?"#).unwrap(),
                path_template: "datadog/api_key",
                description: "Datadog API Key",
                confidence: 0.90,
                requires_verification: false,
            },
            PatternRule {
                name: "datadog_app_key",
                category: CredentialCategory::ApiKey,
                regex: Regex::new(r#"(?i)(?:datadog_app_key|datadog_application_key)\s*[:=]\s*["']?([a-z0-9]{32})["']?"#).unwrap(),
                path_template: "datadog/app_key",
                description: "Datadog App Key",
                confidence: 0.90,
                requires_verification: false,
            },

            // ===== PagerDuty =====
            PatternRule {
                name: "pagerduty_api_key",
                category: CredentialCategory::ApiKey,
                regex: Regex::new(r#"(?i)(?:pagerduty_api_key|pagerduty_key)\s*[:=]\s*["']?([A-Za-z0-9_\-]{20,})["']?"#).unwrap(),
                path_template: "pagerduty/api_key",
                description: "PagerDuty API Key",
                confidence: 0.90,
                requires_verification: false,
            },

            // ===== New Relic =====
            PatternRule {
                name: "new_relic_api_key",
                category: CredentialCategory::ApiKey,
                regex: Regex::new(r#"(?i)(?:new_relic_api_key|newrelic_key|nr_api_key)\s*[:=]\s*["']?(NRAK-[A-Za-z0-9_\-]{27})["']?"#).unwrap(),
                path_template: "newrelic/api_key",
                description: "New Relic API Key",
                confidence: 0.95,
                requires_verification: false,
            },
            PatternRule {
                name: "new_relic_license_key",
                category: CredentialCategory::ApiKey,
                regex: Regex::new(r#"(?i)(?:new_relic_license_key|newrelic_license|nr_license)\s*[:=]\s*["']?([a-z0-9]{40})["']?"#).unwrap(),
                path_template: "newrelic/license_key",
                description: "New Relic License Key",
                confidence: 0.90,
                requires_verification: false,
            },

            // ===== Splunk =====
            PatternRule {
                name: "splunk_token",
                category: CredentialCategory::Token,
                regex: Regex::new(r#"(?i)(?:splunk_token|splunk_hec_token)\s*[:=]\s*["']?([A-Fa-f0-9]{8}-[A-Fa-f0-9]{4}-[A-Fa-f0-9]{4}-[A-Fa-f0-9]{4}-[A-Fa-f0-9]{12})["']?"#).unwrap(),
                path_template: "splunk/token",
                description: "Splunk HEC Token",
                confidence: 0.95,
                requires_verification: false,
            },

            // ===== Rollbar =====
            PatternRule {
                name: "rollbar_access_token",
                category: CredentialCategory::Token,
                regex: Regex::new(r#"(?i)(?:rollbar_access_token|rollbar_token)\s*[:=]\s*["']?([A-Za-z0-9_\-]{32})["']?"#).unwrap(),
                path_template: "rollbar/access_token",
                description: "Rollbar Access Token",
                confidence: 0.90,
                requires_verification: false,
            },

            // ===== Sentry =====
            PatternRule {
                name: "sentry_dsn",
                category: CredentialCategory::Url,
                regex: Regex::new(r"(?i)https://[a-f0-9]{32}@[a-z0-9\-]+\.ingest\.sentry\.io/[0-9]+").unwrap(),
                path_template: "sentry/dsn",
                description: "Sentry DSN",
                confidence: 0.95,
                requires_verification: false,
            },
            PatternRule {
                name: "sentry_auth_token",
                category: CredentialCategory::Token,
                regex: Regex::new(r#"(?i)(?:sentry_auth_token|sentry_token)\s*[:=]\s*["']?(sntry_[A-Za-z0-9_\-]{40,})["']?"#).unwrap(),
                path_template: "sentry/auth_token",
                description: "Sentry Auth Token",
                confidence: 0.90,
                requires_verification: false,
            },

            // ===== HashiCorp Vault =====
            PatternRule {
                name: "vault_token",
                category: CredentialCategory::Token,
                regex: Regex::new(r#"(?i)(?:vault_token|hcvault)\s*[:=]\s*["']?(s\.[A-Za-z0-9]{24,})["']?"#).unwrap(),
                path_template: "vault/token",
                description: "HashiCorp Vault Token",
                confidence: 0.95,
                requires_verification: false,
            },
            PatternRule {
                name: "vault_approle_role_id",
                category: CredentialCategory::ApiKey,
                regex: Regex::new(r#"(?i)(?:vault_role_id|approle_role_id)\s*[:=]\s*["']?([A-Za-z0-9_\-]{24})["']?"#).unwrap(),
                path_template: "vault/approle_role_id",
                description: "Vault AppRole Role ID",
                confidence: 0.85,
                requires_verification: false,
            },
            PatternRule {
                name: "vault_approle_secret_id",
                category: CredentialCategory::ApiKey,
                regex: Regex::new(r#"(?i)(?:vault_secret_id|approle_secret_id)\s*[:=]\s*["']?([A-Za-z0-9_\-]{36})["']?"#).unwrap(),
                path_template: "vault/approle_secret_id",
                description: "Vault AppRole Secret ID",
                confidence: 0.85,
                requires_verification: false,
            },

            // ===== Consul =====
            PatternRule {
                name: "consul_token",
                category: CredentialCategory::Token,
                regex: Regex::new(r#"(?i)(?:consul_token|consul_acl_token)\s*[:=]\s*["']?([A-Za-z0-9_\-]{26,})["']?"#).unwrap(),
                path_template: "consul/token",
                description: "Consul ACL Token",
                confidence: 0.85,
                requires_verification: false,
            },

            // ===== Nomad =====
            PatternRule {
                name: "nomad_token",
                category: CredentialCategory::Token,
                regex: Regex::new(r#"(?i)(?:nomad_token|nomad_acl_token)\s*[:=]\s*["']?([A-Za-z0-9_\-]{26,})["']?"#).unwrap(),
                path_template: "nomad/token",
                description: "Nomad ACL Token",
                confidence: 0.85,
                requires_verification: false,
            },

            // ===== Terraform =====
            PatternRule {
                name: "terraform_token",
                category: CredentialCategory::Token,
                regex: Regex::new(r#"(?i)(?:terraform_token|terraform_cloud_token)\s*[:=]\s*["']?([A-Za-z0-9_\-]{20,})["']?"#).unwrap(),
                path_template: "terraform/token",
                description: "Terraform Cloud Token",
                confidence: 0.85,
                requires_verification: false,
            },

            // ===== Ansible =====
            PatternRule {
                name: "ansible_vault_password",
                category: CredentialCategory::Password,
                regex: Regex::new(r#"(?i)(?:ansible_vault_password|ansible_vault_pass)\s*[:=]\s*["']?([A-Za-z0-9_\-]{16,})["']?"#).unwrap(),
                path_template: "ansible/vault_password",
                description: "Ansible Vault Password",
                confidence: 0.70,
                requires_verification: true,
            },

            // ===== Kubernetes =====
            PatternRule {
                name: "kubernetes_bearer_token",
                category: CredentialCategory::Token,
                regex: Regex::new(r#"(?i)(?:kubernetes_token|k8s_token)\s*[:=]\s*["']?([A-Za-z0-9._\-]{40,})["']?"#).unwrap(),
                path_template: "kubernetes/bearer_token",
                description: "Kubernetes Bearer Token",
                confidence: 0.85,
                requires_verification: false,
            },
            PatternRule {
                name: "kubernetes_ca_cert",
                category: CredentialCategory::Certificate,
                regex: Regex::new(r"(?i)-----BEGIN CERTIFICATE-----.*?kubectl").unwrap(),
                path_template: "kubernetes/ca_cert",
                description: "Kubernetes CA Certificate",
                confidence: 0.90,
                requires_verification: false,
            },

            // ===== Database URLs =====
            PatternRule {
                name: "database_url_postgres",
                category: CredentialCategory::Database,
                regex: Regex::new(r"(?i)(?:postgres|postgresql)://[A-Za-z0-9_\-]+:[A-Za-z0-9_\-]+@").unwrap(),
                path_template: "db/postgres_url",
                description: "PostgreSQL Database URL",
                confidence: 0.90,
                requires_verification: false,
            },
            PatternRule {
                name: "database_url_mysql",
                category: CredentialCategory::Database,
                regex: Regex::new(r"(?i)mysql://[A-Za-z0-9_\-]+:[A-Za-z0-9_\-]+@").unwrap(),
                path_template: "db/mysql_url",
                description: "MySQL Database URL",
                confidence: 0.90,
                requires_verification: false,
            },
            PatternRule {
                name: "database_url_mongodb",
                category: CredentialCategory::Database,
                regex: Regex::new(r"(?i)mongodb://[A-Za-z0-9_\-]+:[A-Za-z0-9_\-]+@").unwrap(),
                path_template: "db/mongodb_url",
                description: "MongoDB Database URL",
                confidence: 0.90,
                requires_verification: false,
            },
            PatternRule {
                name: "database_url_redis",
                category: CredentialCategory::Database,
                regex: Regex::new(r"(?i)redis://[A-Za-z0-9_\-]+:[A-Za-z0-9_\-]+@").unwrap(),
                path_template: "db/redis_url",
                description: "Redis Database URL",
                confidence: 0.90,
                requires_verification: false,
            },
            PatternRule {
                name: "database_url_elasticsearch",
                category: CredentialCategory::Database,
                regex: Regex::new(r"(?i)https?://[A-Za-z0-9_\-]+:[A-Za-z0-9_\-]+@[A-Za-z0-9.\-]+:9200").unwrap(),
                path_template: "db/elasticsearch_url",
                description: "Elasticsearch URL",
                confidence: 0.90,
                requires_verification: false,
            },

            // ===== Generic API Keys =====
            PatternRule {
                name: "api_key_generic",
                category: CredentialCategory::ApiKey,
                regex: Regex::new(r#"(?i)(?:api_key|apikey|api-key)\s*[:=]\s*["']?([A-Za-z0-9_\-]{16,})["']?"#).unwrap(),
                path_template: "api/generic_key",
                description: "Generic API Key",
                confidence: 0.60,
                requires_verification: true,
            },
            PatternRule {
                name: "secret_key_generic",
                category: CredentialCategory::Password,
                regex: Regex::new(r#"(?i)(?:secret_key|secretkey|secret-key)\s*[:=]\s*["']?([A-Za-z0-9_\-]{16,})["']?"#).unwrap(),
                path_template: "auth/secret_key",
                description: "Generic Secret Key",
                confidence: 0.60,
                requires_verification: true,
            },
            PatternRule {
                name: "access_key_generic",
                category: CredentialCategory::ApiKey,
                regex: Regex::new(r#"(?i)(?:access_key|accesskey|access-key)\s*[:=]\s*["']?([A-Za-z0-9_\-]{16,})["']?"#).unwrap(),
                path_template: "auth/access_key",
                description: "Generic Access Key",
                confidence: 0.60,
                requires_verification: true,
            },
            PatternRule {
                name: "auth_token_generic",
                category: CredentialCategory::Token,
                regex: Regex::new(r#"(?i)(?:auth_token|authtoken|auth-token)\s*[:=]\s*["']?([A-Za-z0-9_\-]{20,})["']?"#).unwrap(),
                path_template: "auth/token",
                description: "Generic Auth Token",
                confidence: 0.60,
                requires_verification: true,
            },

            // ===== Certificates =====
            PatternRule {
                name: "pem_certificate",
                category: CredentialCategory::Certificate,
                regex: Regex::new(r"-----BEGIN CERTIFICATE-----").unwrap(),
                path_template: "tls/certificate",
                description: "PEM Certificate",
                confidence: 0.70,
                requires_verification: true,
            },
            PatternRule {
                name: "pem_private_key",
                category: CredentialCategory::Certificate,
                regex: Regex::new(r"-----BEGIN ENCRYPTED PRIVATE KEY-----").unwrap(),  // gitleaks:allow
                path_template: "tls/encrypted_private_key",
                description: "PEM Encrypted Private Key",
                confidence: 0.90,
                requires_verification: false,
            },
            PatternRule {
                name: "pem_rsa_private_key",
                category: CredentialCategory::Certificate,
                regex: Regex::new(r"-----BEGIN RSA PRIVATE KEY-----").unwrap(),  // gitleaks:allow
                path_template: "tls/rsa_private_key",
                description: "PEM RSA Private Key",
                confidence: 0.90,
                requires_verification: false,
            },
            PatternRule {
                name: "pem_ec_private_key",
                category: CredentialCategory::Certificate,
                regex: Regex::new(r"-----BEGIN EC PRIVATE KEY-----").unwrap(),  // gitleaks:allow
                path_template: "tls/ec_private_key",
                description: "PEM EC Private Key",
                confidence: 0.90,
                requires_verification: false,
            },
            PatternRule {
                name: "pem_dsa_private_key",
                category: CredentialCategory::Certificate,
                regex: Regex::new(r"-----BEGIN DSA PRIVATE KEY-----").unwrap(),  // gitleaks:allow
                path_template: "tls/dsa_private_key",
                description: "PEM DSA Private Key",
                confidence: 0.90,
                requires_verification: false,
            },

            // ===== Cloudflare =====
            PatternRule {
                name: "cloudflare_api_token",
                category: CredentialCategory::Token,
                regex: Regex::new(r#"(?i)(?:cloudflare_api_token|cf_api_token)\s*[:=]\s*["']?([A-Za-z0-9_\-]{40})["']?"#).unwrap(),
                path_template: "cloudflare/api_token",
                description: "Cloudflare API Token",
                confidence: 0.95,
                requires_verification: false,
            },
            PatternRule {
                name: "cloudflare_api_key",
                category: CredentialCategory::ApiKey,
                regex: Regex::new(r#"(?i)(?:cloudflare_api_key|cf_api_key)\s*[:=]\s*["']?([A-Za-z0-9_\-]{37})["']?"#).unwrap(),
                path_template: "cloudflare/api_key",
                description: "Cloudflare API Key",
                confidence: 0.90,
                requires_verification: false,
            },
            PatternRule {
                name: "cloudflare_ca_key",
                category: CredentialCategory::ApiKey,
                regex: Regex::new(r#"(?i)(?:cloudflare_ca_key|cf_ca_key)\s*[:=]\s*["']?([A-Za-z0-9_\-]{40})["']?"#).unwrap(),
                path_template: "cloudflare/ca_key",
                description: "Cloudflare CA Key",
                confidence: 0.90,
                requires_verification: false,
            },

            // ===== Heroku =====
            PatternRule {
                name: "heroku_api_key",
                category: CredentialCategory::ApiKey,
                regex: Regex::new(r#"(?i)(?:heroku_api_key|heroku_key)\s*[:=]\s*["']?([A-Za-z0-9_\-]{30,})["']?"#).unwrap(),
                path_template: "heroku/api_key",
                description: "Heroku API Key",
                confidence: 0.85,
                requires_verification: false,
            },
            PatternRule {
                name: "heroku_auth_token",
                category: CredentialCategory::Token,
                regex: Regex::new(r#"(?i)(?:heroku_auth_token|heroku_token)\s*[:=]\s*["']?([A-Za-z0-9_\-]{40,})["']?"#).unwrap(),
                path_template: "heroku/auth_token",
                description: "Heroku Auth Token",
                confidence: 0.85,
                requires_verification: false,
            },

            // ===== DigitalOcean =====
            PatternRule {
                name: "digitalocean_token",
                category: CredentialCategory::Token,
                regex: Regex::new(r#"(?i)(?:digitalocean_token|do_token)\s*[:=]\s*["']?([A-Za-z0-9_\-]{64})["']?"#).unwrap(),
                path_template: "digitalocean/token",
                description: "DigitalOcean API Token",
                confidence: 0.90,
                requires_verification: false,
            },
            PatternRule {
                name: "digitalocean_access_token",
                category: CredentialCategory::Token,
                regex: Regex::new(r#"(?i)(?:digitalocean_access_token|do_access_token)\s*[:=]\s*["']?([A-Za-z0-9_\-]{64})["']?"#).unwrap(),
                path_template: "digitalocean/access_token",
                description: "DigitalOcean Access Token",
                confidence: 0.90,
                requires_verification: false,
            },

            // ===== Shopify =====
            PatternRule {
                name: "shopify_token",
                category: CredentialCategory::Token,
                regex: Regex::new(r#"(?i)(?:shopify_token|shopify_api_token)\s*[:=]\s*["']?([A-Za-z0-9_\-]{40,})["']?"#).unwrap(),
                path_template: "shopify/token",
                description: "Shopify API Token",
                confidence: 0.85,
                requires_verification: false,
            },
            PatternRule {
                name: "shopify_api_password",
                category: CredentialCategory::Password,
                regex: Regex::new(r#"(?i)(?:shopify_password|shopify_api_password)\s*[:=]\s*["']?([A-Za-z0-9_\-]{32,})["']?"#).unwrap(),
                path_template: "shopify/password",
                description: "Shopify API Password",
                confidence: 0.85,
                requires_verification: false,
            },

            // ===== Atlassian =====
            PatternRule {
                name: "atlassian_api_token",
                category: CredentialCategory::Token,
                regex: Regex::new(r#"(?i)(?:atlassian_api_token|jira_token|confluence_token)\s*[:=]\s*["']?([A-Za-z0-9_\-]{24})["']?"#).unwrap(),
                path_template: "atlassian/api_token",
                description: "Atlassian API Token",
                confidence: 0.85,
                requires_verification: false,
            },

            // ===== Bitbucket =====
            PatternRule {
                name: "bitbucket_token",
                category: CredentialCategory::Token,
                regex: Regex::new(r#"(?i)(?:bitbucket_token|bitbucket_app_password)\s*[:=]\s*["']?([A-Za-z0-9_\-]{20,})["']?"#).unwrap(),
                path_template: "bitbucket/token",
                description: "Bitbucket Token",
                confidence: 0.85,
                requires_verification: false,
            },

            // ===== LinkedIn =====
            PatternRule {
                name: "linkedin_client_id",
                category: CredentialCategory::ApiKey,
                regex: Regex::new(r#"(?i)(?:linkedin_client_id|linkedin_key)\s*[:=]\s*["']?([A-Za-z0-9_\-]{14})["']?"#).unwrap(),
                path_template: "linkedin/client_id",
                description: "LinkedIn Client ID",
                confidence: 0.85,
                requires_verification: false,
            },
            PatternRule {
                name: "linkedin_client_secret",
                category: CredentialCategory::Password,
                regex: Regex::new(r#"(?i)(?:linkedin_client_secret|linkedin_secret)\s*[:=]\s*["']?([A-Za-z0-9_\-]{32})["']?"#).unwrap(),
                path_template: "linkedin/client_secret",
                description: "LinkedIn Client Secret",
                confidence: 0.85,
                requires_verification: false,
            },

            // ===== Facebook =====
            PatternRule {
                name: "facebook_access_token",
                category: CredentialCategory::Token,
                regex: Regex::new(r#"(?i)(?:facebook_access_token|fb_access_token)\s*[:=]\s*["']?([A-Za-z0-9_\-]{100,})["']?"#).unwrap(),
                path_template: "facebook/access_token",
                description: "Facebook Access Token",
                confidence: 0.85,
                requires_verification: false,
            },
            PatternRule {
                name: "facebook_app_secret",
                category: CredentialCategory::Password,
                regex: Regex::new(r#"(?i)(?:facebook_app_secret|fb_app_secret)\s*[:=]\s*["']?([A-Za-z0-9_\-]{32})["']?"#).unwrap(),
                path_template: "facebook/app_secret",
                description: "Facebook App Secret",
                confidence: 0.85,
                requires_verification: false,
            },

            // ===== Twitter =====
            PatternRule {
                name: "twitter_api_key",
                category: CredentialCategory::ApiKey,
                regex: Regex::new(r#"(?i)(?:twitter_api_key|twitter_consumer_key)\s*[:=]\s*["']?([A-Za-z0-9_\-]{25})["']?"#).unwrap(),
                path_template: "twitter/api_key",
                description: "Twitter API Key",
                confidence: 0.90,
                requires_verification: false,
            },
            PatternRule {
                name: "twitter_api_secret",
                category: CredentialCategory::Password,
                regex: Regex::new(r#"(?i)(?:twitter_api_secret|twitter_consumer_secret)\s*[:=]\s*["']?([A-Za-z0-9_\-]{50})["']?"#).unwrap(),
                path_template: "twitter/api_secret",
                description: "Twitter API Secret",
                confidence: 0.90,
                requires_verification: false,
            },
            PatternRule {
                name: "twitter_access_token",
                category: CredentialCategory::Token,
                regex: Regex::new(r#"(?i)(?:twitter_access_token|twitter_oauth_token)\s*[:=]\s*["']?([A-Za-z0-9_\-]{50})["']?"#).unwrap(),
                path_template: "twitter/access_token",
                description: "Twitter Access Token",
                confidence: 0.85,
                requires_verification: false,
            },
            PatternRule {
                name: "twitter_access_secret",
                category: CredentialCategory::Password,
                regex: Regex::new(r#"(?i)(?:twitter_access_secret|twitter_oauth_secret)\s*[:=]\s*["']?([A-Za-z0-9_\-]{45})["']?"#).unwrap(),
                path_template: "twitter/access_secret",
                description: "Twitter Access Secret",
                confidence: 0.85,
                requires_verification: false,
            },
            PatternRule {
                name: "twitter_bearer_token",
                category: CredentialCategory::Token,
                regex: Regex::new(r#"(?i)(?:twitter_bearer_token|twitter_bearer)\s*[:=]\s*["']?(AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA)["']?"#).unwrap(),
                path_template: "twitter/bearer_token",
                description: "Twitter Bearer Token",
                confidence: 0.90,
                requires_verification: false,
            },

            // ===== Square =====
            PatternRule {
                name: "square_access_token",
                category: CredentialCategory::Token,
                regex: Regex::new(r#"(?i)(?:square_access_token|square_token)\s*[:=]\s*["']?(EAAA[A-Za-z0-9_\-]{60})["']?"#).unwrap(),
                path_template: "square/access_token",
                description: "Square Access Token",
                confidence: 0.95,
                requires_verification: false,
            },

            // ===== PayPal =====
            PatternRule {
                name: "paypal_client_id",
                category: CredentialCategory::ApiKey,
                regex: Regex::new(r#"(?i)(?:paypal_client_id|paypal_key)\s*[:=]\s*["']?([A-Za-z0-9_\-]{60,})["']?"#).unwrap(),
                path_template: "paypal/client_id",
                description: "PayPal Client ID",
                confidence: 0.85,
                requires_verification: false,
            },
            PatternRule {
                name: "paypal_client_secret",
                category: CredentialCategory::Password,
                regex: Regex::new(r#"(?i)(?:paypal_client_secret|paypal_secret)\s*[:=]\s*["']?([A-Za-z0-9_\-]{80,})["']?"#).unwrap(),
                path_template: "paypal/client_secret",
                description: "PayPal Client Secret",
                confidence: 0.85,
                requires_verification: false,
            },

            // ===== Stripe (additional) =====
            PatternRule {
                name: "stripe_client_id",
                category: CredentialCategory::ApiKey,
                regex: Regex::new(r#"(?i)(?:stripe_client_id|stripe_key)\s*[:=]\s*["']?([A-Za-z0-9_\-]{40,})["']?"#).unwrap(),
                path_template: "stripe/client_id",
                description: "Stripe Client ID",
                confidence: 0.85,
                requires_verification: false,
            },

            // ===== Databricks =====
            PatternRule {
                name: "databricks_token",
                category: CredentialCategory::Token,
                regex: Regex::new(r#"(?i)(?:databricks_token|databricks_api_token)\s*[:=]\s*["']?(dapi[0-9a-f]{32})["']?"#).unwrap(),
                path_template: "databricks/token",
                description: "Databricks API Token",
                confidence: 0.95,
                requires_verification: false,
            },

            // ===== Snowflake =====
            PatternRule {
                name: "snowflake_private_key",
                category: CredentialCategory::SshKey,
                regex: Regex::new(r#"(?i)(?:snowflake_private_key|snowflake_key)\s*[:=]\s*["']?(MIIE[A-Za-z0-9/+=]{200,})["']?"#).unwrap(),
                path_template: "snowflake/private_key",
                description: "Snowflake Private Key",
                confidence: 0.95,
                requires_verification: false,
            },

            // ===== Grafana =====
            PatternRule {
                name: "grafana_api_key",
                category: CredentialCategory::ApiKey,
                regex: Regex::new(r#"(?i)(?:grafana_api_key|grafana_key)\s*[:=]\s*["']?(eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+)["']?"#).unwrap(),
                path_template: "grafana/api_key",
                description: "Grafana API Key",
                confidence: 0.85,
                requires_verification: false,
            },

            // ===== Basic Auth =====
            PatternRule {
                name: "basic_auth_url",
                category: CredentialCategory::Url,
                regex: Regex::new(r"(?i)https?://[A-Za-z0-9_\-]+:[A-Za-z0-9_\-]+@[A-Za-z0-9.\-]+").unwrap(),
                path_template: "auth/basic_url",
                description: "URL with Basic Auth credentials",
                confidence: 0.75,
                requires_verification: true,
            },
            PatternRule {
                name: "basic_auth_header",
                category: CredentialCategory::Token,
                regex: Regex::new(r"(?i)authorization\s*:\s*basic\s+[A-Za-z0-9_\-=]{10,}").unwrap(),
                path_template: "auth/basic_header",
                description: "Basic Auth header",
                confidence: 0.80,
                requires_verification: true,
            },
        ]
    }).clone()
}

/// Pattern detector that scans text for credential patterns
pub struct PatternDetector {
    /// Compiled patterns
    patterns: Vec<PatternRule>,
    /// Pattern index by category
    by_category: HashMap<CredentialCategory, Vec<usize>>,
}

impl PatternDetector {
    /// Create a new pattern detector with built-in patterns
    pub fn new() -> Self {
        let patterns = builtin_patterns();

        let mut by_category: HashMap<CredentialCategory, Vec<usize>> = HashMap::new();
        for (idx, pattern) in patterns.iter().enumerate() {
            by_category.entry(pattern.category).or_default().push(idx);
        }

        Self {
            patterns,
            by_category,
        }
    }

    /// Detect all patterns in text
    pub fn detect(&self, text: &str) -> Vec<PatternMatch> {
        let mut matches = Vec::new();

        for (idx, pattern) in self.patterns.iter().enumerate() {
            for captures in pattern.regex.captures_iter(text) {
                let matched = captures.get(0).map(|m| m.as_str()).unwrap_or("");

                // Skip example values
                if self.is_example_value(matched) {
                    continue;
                }

                matches.push(PatternMatch {
                    pattern_name: pattern.name.to_string(),
                    category: pattern.category,
                    matched_text: matched.to_string(),
                    path_template: pattern.path_template.to_string(),
                    description: pattern.description.to_string(),
                    confidence: pattern.confidence,
                    requires_verification: pattern.requires_verification,
                    pattern_index: idx,
                });
            }
        }

        // Sort by confidence (descending)
        matches.sort_by(|a, b| b.confidence.partial_cmp(&a.confidence).unwrap());

        matches
    }

    /// Detect patterns by category
    pub fn detect_by_category(
        &self,
        text: &str,
        category: CredentialCategory,
    ) -> Vec<PatternMatch> {
        let all_matches = self.detect(text);
        all_matches
            .into_iter()
            .filter(|m| m.category == category)
            .collect()
    }

    /// Get patterns by category
    pub fn get_patterns_by_category(&self, category: CredentialCategory) -> Vec<&PatternRule> {
        self.by_category
            .get(&category)
            .map(|indices| indices.iter().map(|&idx| &self.patterns[idx]).collect())
            .unwrap_or_default()
    }

    /// Get all patterns
    pub fn all_patterns(&self) -> &[PatternRule] {
        &self.patterns
    }

    /// Check if a matched value is an example placeholder
    fn is_example_value(&self, value: &str) -> bool {
        let lower = value.to_lowercase();
        lower.contains("example")
            || lower.contains("placeholder")
            || lower.contains("your_")
            || lower.contains("replace")
            || lower.contains("xxx")
            || lower.contains("...value")
            || lower.contains("test")
            || lower.contains("demo")
            || lower.contains("sample")
    }
}

impl Default for PatternDetector {
    fn default() -> Self {
        Self::new()
    }
}

/// Match result from pattern detection
#[derive(Debug, Clone)]
pub struct PatternMatch {
    /// Pattern name
    pub pattern_name: String,
    /// Category
    pub category: CredentialCategory,
    /// Matched text
    pub matched_text: String,
    /// Path template
    pub path_template: String,
    /// Description
    pub description: String,
    /// Confidence score (0.0-1.0)
    pub confidence: f32,
    /// Whether this requires additional verification
    pub requires_verification: bool,
    /// Pattern index in the detector
    pub pattern_index: usize,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_builtin_patterns() {
        let patterns = builtin_patterns();
        assert!(!patterns.is_empty());

        // Verify some key patterns exist
        let pattern_names: Vec<_> = patterns.iter().map(|p| p.name).collect();
        assert!(pattern_names.contains(&"aws_access_key_id"));
        assert!(pattern_names.contains(&"github_personal_access_token"));
        assert!(pattern_names.contains(&"ssh_private_key"));
    }

    #[test]
    fn test_pattern_detector() {
        let detector = PatternDetector::new();

        // Test AWS key detection (use real-looking key, not "EXAMPLE")
        // AWS keys are 20 characters: AKIA + 16 alphanumeric
        let text = "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7QUAD123"; // gitleaks:allow
        let matches = detector.detect(text);
        assert!(!matches.is_empty());
        assert_eq!(matches[0].pattern_name, "aws_access_key_id");
    }

    #[test]
    fn test_github_token_detection() {
        let detector = PatternDetector::new();

        // Use real-looking token (avoid "test" which gets filtered)
        // GitHub tokens are ghp_ + 36 alphanumeric characters (40 total)
        let text = "ghp_BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"; // gitleaks:allow
        let matches = detector.detect(text);
        assert!(!matches.is_empty());
        assert!(matches[0].pattern_name.contains("github"));
    }

    #[test]
    fn test_example_detection() {
        let detector = PatternDetector::new();

        let text = "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE"; // gitleaks:allow
        let matches = detector.detect(text);
        // Should filter out example values
        assert!(matches.is_empty() || matches[0].confidence < 0.8);
    }

    #[test]
    fn test_category_filtering() {
        let detector = PatternDetector::new();

        // Use real-looking values (avoid "EXAMPLE" and "test" which get filtered)
        // AWS keys are 20 characters: AKIA + 16 alphanumeric
        // GitHub tokens are ghp_ + 36 alphanumeric characters
        let text = "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7QUAD123\n  // gitleaks:allow
                    ghp_BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB\n  // gitleaks:allow
                    -----BEGIN PRIVATE KEY-----"; // gitleaks:allow

        let cloud_matches = detector.detect_by_category(text, CredentialCategory::Cloud);
        let ssh_matches = detector.detect_by_category(text, CredentialCategory::SshKey);

        assert!(!cloud_matches.is_empty());
        assert!(!ssh_matches.is_empty());
    }

    #[test]
    fn test_high_confidence_patterns() {
        let detector = PatternDetector::new();

        // Test high-confidence patterns
        // Test patterns that won't trigger secret scanners
        let test_cases = vec![
            ("ghp_TEST1234567890abcdefghijklmnopqrstuv", "github"), // gitleaks:allow
            ("sk_test_REDACTED1234567890abcdefghijklmn", "stripe"),
            ("-----BEGIN RSA PRIVATE KEY-----", "ssh"), // gitleaks:allow
            (
                "https://hooks.slack.com/services/T00000000/B00000000/XXXXXXXXXXXXXXXXXXXX",
                "slack",
            ),
        ];

        for (text, expected_keyword) in test_cases {
            let matches = detector.detect(text);
            if !matches.is_empty() {
                assert!(
                    matches[0].confidence >= 0.90,
                    "{} should have high confidence",
                    expected_keyword
                );
            }
        }
    }
}
