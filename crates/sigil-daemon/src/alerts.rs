//! Alert configuration and sending for lockdown events
//!
//! This module provides functionality for sending alerts to configured
//! channels when a lockdown event occurs.

use serde::{Deserialize, Serialize};
use std::time::Duration;

/// Alert configuration for lockdown events
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct AlertConfig {
    /// Webhook alert configurations
    #[serde(default)]
    pub webhooks: Vec<WebhookConfig>,
    /// Whether alerts are enabled
    #[serde(default)]
    pub enabled: bool,
}

/// Webhook configuration for sending alerts
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebhookConfig {
    /// Webhook URL
    pub url: String,
    /// Webhook type (determines payload format)
    #[serde(rename = "type")]
    pub webhook_type: WebhookType,
    /// Optional custom headers
    #[serde(default)]
    pub headers: Vec<(String, String)>,
}

/// Webhook type that determines the payload format
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum WebhookType {
    /// Slack webhook
    Slack,
    /// Discord webhook
    Discord,
    /// Generic JSON webhook
    Generic,
    /// Microsoft Teams webhook
    Teams,
}

/// Lockdown event data for alert payloads
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LockdownEvent {
    /// Timestamp when lockdown was initiated
    pub timestamp: String,
    /// Number of sandbox processes killed
    pub sandboxes_killed: usize,
    /// Number of session tokens revoked
    pub sessions_revoked: usize,
    /// Number of dynamic leases revoked
    pub leases_revoked: usize,
    /// Whether the vault was locked
    pub vault_locked: bool,
    /// Any errors that occurred during lockdown
    pub errors: Vec<String>,
    /// Hostname where lockdown occurred
    pub hostname: String,
}

impl LockdownEvent {
    /// Create a new lockdown event from a lockdown report
    pub fn from_report(report: &crate::server::LockdownReport, hostname: String) -> Self {
        Self {
            timestamp: report
                .timestamp
                .map(|t| t.to_rfc3339())
                .unwrap_or_else(|| chrono::Utc::now().to_rfc3339()),
            sandboxes_killed: report.sandboxes_killed,
            sessions_revoked: report.sessions_revoked,
            leases_revoked: report.leases_revoked,
            vault_locked: report.vault_locked,
            errors: report.errors.clone(),
            hostname,
        }
    }
}

/// Alert sender for dispatching alerts to configured channels
#[derive(Clone)]
pub struct AlertSender {
    /// Alert configuration
    config: AlertConfig,
    /// HTTP client for sending webhooks
    client: reqwest::Client,
    /// Request timeout
    timeout: Duration,
}

impl AlertSender {
    /// Create a new alert sender
    pub fn new(config: AlertConfig) -> Self {
        let timeout = Duration::from_secs(10);
        let client = reqwest::Client::builder()
            .timeout(timeout)
            .build()
            .unwrap_or_else(|_| reqwest::Client::new());

        Self {
            config,
            client,
            timeout,
        }
    }

    /// Send alerts for a lockdown event
    ///
    /// Returns the number of alerts successfully sent
    pub async fn send_lockdown_alert(
        &self,
        event: &LockdownEvent,
    ) -> Result<usize, Box<dyn std::error::Error>> {
        if !self.config.enabled || self.config.webhooks.is_empty() {
            return Ok(0);
        }

        let mut sent = 0;
        let mut errors = Vec::new();

        for webhook in &self.config.webhooks {
            match self.send_webhook(webhook, event).await {
                Ok(()) => {
                    sent += 1;
                    tracing::info!("Successfully sent lockdown alert to {}", webhook.url);
                }
                Err(e) => {
                    let error_msg = format!("Failed to send alert to {}: {}", webhook.url, e);
                    tracing::error!("{}", error_msg);
                    errors.push(error_msg);
                }
            }
        }

        if !errors.is_empty() {
            tracing::warn!("Encountered {} errors while sending alerts", errors.len());
        }

        Ok(sent)
    }

    /// Send a single webhook alert
    async fn send_webhook(
        &self,
        webhook: &WebhookConfig,
        event: &LockdownEvent,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let payload = self.build_payload(webhook, event)?;
        let url = &webhook.url;

        let mut request = self.client.post(url);

        // Add custom headers
        for (key, value) in &webhook.headers {
            request = request.header(key, value);
        }

        // Set content type based on webhook type
        let content_type = match webhook.webhook_type {
            WebhookType::Slack | WebhookType::Discord | WebhookType::Teams => "application/json",
            WebhookType::Generic => "application/json",
        };
        request = request.header("Content-Type", content_type);

        let response = tokio::time::timeout(self.timeout, request.json(&payload).send())
            .await
            .map_err(|_| {
                std::io::Error::new(std::io::ErrorKind::TimedOut, "Webhook request timed out")
            })?
            .map_err(|e| Box::new(e) as Box<dyn std::error::Error>)?;

        if response.status().is_success() {
            Ok(())
        } else {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            Err(format!("Webhook returned error status {}: {}", status, body).into())
        }
    }

    /// Build the payload for a webhook based on its type
    fn build_payload(
        &self,
        webhook: &WebhookConfig,
        event: &LockdownEvent,
    ) -> Result<serde_json::Value, Box<dyn std::error::Error>> {
        match webhook.webhook_type {
            WebhookType::Slack => self.build_slack_payload(event),
            WebhookType::Discord => self.build_discord_payload(event),
            WebhookType::Teams => self.build_teams_payload(event),
            WebhookType::Generic => self.build_generic_payload(event),
        }
    }

    /// Build a Slack webhook payload
    fn build_slack_payload(
        &self,
        event: &LockdownEvent,
    ) -> Result<serde_json::Value, Box<dyn std::error::Error>> {
        let color = if event.errors.is_empty() {
            "#36a64f"
        } else {
            "#ff0000"
        };
        let error_text = if event.errors.is_empty() {
            String::new()
        } else {
            format!("\n*Errors:*\n{}", event.errors.join("\n"))
        };

        let payload = serde_json::json!({
            "username": "SIGIL Security",
            "icon_emoji": ":rotating_light:",
            "attachments": [{
                "color": color,
                "title": "SIGIL Lockdown Activated",
                "fields": [
                    {
                        "title": "Hostname",
                        "value": event.hostname,
                        "short": true
                    },
                    {
                        "title": "Timestamp",
                        "value": event.timestamp,
                        "short": true
                    },
                    {
                        "title": "Sandboxes Killed",
                        "value": event.sandboxes_killed,
                        "short": true
                    },
                    {
                        "title": "Sessions Revoked",
                        "value": event.sessions_revoked,
                        "short": true
                    },
                    {
                        "title": "Vault Locked",
                        "value": if event.vault_locked { "Yes" } else { "No" },
                        "short": true
                    }
                ],
                "text": error_text,
                "footer": "SIGIL Security",
                "ts": chrono::Utc::now().timestamp()
            }]
        });

        Ok(payload)
    }

    /// Build a Discord webhook payload
    fn build_discord_payload(
        &self,
        event: &LockdownEvent,
    ) -> Result<serde_json::Value, Box<dyn std::error::Error>> {
        let color = if event.errors.is_empty() {
            3581519
        } else {
            16711680
        }; // Green or Red
        let error_text = if event.errors.is_empty() {
            String::new()
        } else {
            format!("\n**Errors:**\n{}", event.errors.join("\n"))
        };

        let payload = serde_json::json!({
            "username": "SIGIL Security",
            "avatar_url": "https://github.githubassets.com/images/modules/logos_page/GitHub-Mark.png",
            "embeds": [{
                "title": "🚨 SIGIL Lockdown Activated",
                "color": color,
                "fields": [
                    {
                        "name": "Hostname",
                        "value": event.hostname,
                        "inline": true
                    },
                    {
                        "name": "Timestamp",
                        "value": event.timestamp,
                        "inline": true
                    },
                    {
                        "name": "Sandboxes Killed",
                        "value": event.sandboxes_killed.to_string(),
                        "inline": true
                    },
                    {
                        "name": "Sessions Revoked",
                        "value": event.sessions_revoked.to_string(),
                        "inline": true
                    },
                    {
                        "name": "Vault Locked",
                        "value": if event.vault_locked { "Yes" } else { "No" },
                        "inline": true
                    }
                ],
                "description": error_text,
                "timestamp": event.timestamp
            }]
        });

        Ok(payload)
    }

    /// Build a Microsoft Teams webhook payload
    fn build_teams_payload(
        &self,
        event: &LockdownEvent,
    ) -> Result<serde_json::Value, Box<dyn std::error::Error>> {
        let error_text = if event.errors.is_empty() {
            String::new()
        } else {
            format!("<br><b>Errors:</b><br>{}", event.errors.join("<br>"))
        };

        let payload = serde_json::json!({
            "@type": "MessageCard",
            "@context": "https://schema.org/extensions",
            "summary": "SIGIL Lockdown Activated",
            "themeColor": if event.errors.is_empty() { "36a64f" } else { "ff0000" },
            "title": "🚨 SIGIL Lockdown Activated",
            "sections": [{
                "facts": [
                    {
                        "name": "Hostname",
                        "value": event.hostname
                    },
                    {
                        "name": "Timestamp",
                        "value": event.timestamp
                    },
                    {
                        "name": "Sandboxes Killed",
                        "value": event.sandboxes_killed.to_string()
                    },
                    {
                        "name": "Sessions Revoked",
                        "value": event.sessions_revoked.to_string()
                    },
                    {
                        "name": "Vault Locked",
                        "value": if event.vault_locked { "Yes" } else { "No" }
                    }
                ],
                "text": error_text
            }]
        });

        Ok(payload)
    }

    /// Build a generic JSON webhook payload
    fn build_generic_payload(
        &self,
        event: &LockdownEvent,
    ) -> Result<serde_json::Value, Box<dyn std::error::Error>> {
        let payload = serde_json::json!({
            "event": "lockdown",
            "timestamp": event.timestamp,
            "hostname": event.hostname,
            "sandboxes_killed": event.sandboxes_killed,
            "sessions_revoked": event.sessions_revoked,
            "leases_revoked": event.leases_revoked,
            "vault_locked": event.vault_locked,
            "errors": event.errors,
        });

        Ok(payload)
    }

    /// Load alert configuration from a TOML file
    #[allow(dead_code)]
    pub fn load_from_file(
        path: &std::path::Path,
    ) -> Result<AlertConfig, Box<dyn std::error::Error>> {
        let contents = std::fs::read_to_string(path)?;
        let config: AlertConfig = toml::from_str(&contents)?;
        Ok(config)
    }

    /// Save alert configuration to a TOML file
    #[allow(dead_code)]
    pub fn save_to_file(
        config: &AlertConfig,
        path: &std::path::Path,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let contents = toml::to_string_pretty(config)?;
        std::fs::write(path, contents)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_alert_config_default() {
        let config = AlertConfig::default();
        assert!(!config.enabled);
        assert!(config.webhooks.is_empty());
    }

    #[test]
    fn test_webhook_type_serialization() {
        let slack = WebhookType::Slack;
        let serialized = serde_json::to_string(&slack).unwrap();
        assert_eq!(serialized, "\"slack\"");
    }

    #[test]
    fn test_lockdown_event_from_report() {
        let report = crate::server::LockdownReport {
            timestamp: Some(chrono::Utc::now()),
            sandboxes_killed: 3,
            sessions_revoked: 5,
            leases_revoked: 2,
            vault_locked: true,
            alerts_sent: 0,
            errors: vec!["Test error".to_string()],
        };

        let event = LockdownEvent::from_report(&report, "test-host".to_string());
        assert_eq!(event.sandboxes_killed, 3);
        assert_eq!(event.hostname, "test-host");
        assert!(event.vault_locked);
    }

    #[test]
    fn test_build_slack_payload() {
        let sender = AlertSender::new(AlertConfig::default());
        let event = LockdownEvent {
            timestamp: "2024-01-01T00:00:00Z".to_string(),
            sandboxes_killed: 1,
            sessions_revoked: 2,
            leases_revoked: 0,
            vault_locked: true,
            errors: vec![],
            hostname: "test".to_string(),
        };

        let payload = sender.build_slack_payload(&event).unwrap();
        assert!(payload.is_object());
        let obj = payload.as_object().unwrap();
        assert!(obj.contains_key("attachments"));
    }

    #[test]
    fn test_build_generic_payload() {
        let sender = AlertSender::new(AlertConfig::default());
        let event = LockdownEvent {
            timestamp: "2024-01-01T00:00:00Z".to_string(),
            sandboxes_killed: 1,
            sessions_revoked: 2,
            leases_revoked: 0,
            vault_locked: true,
            errors: vec![],
            hostname: "test".to_string(),
        };

        let payload = sender.build_generic_payload(&event).unwrap();
        assert!(payload.is_object());
        let obj = payload.as_object().unwrap();
        assert_eq!(obj.get("event").unwrap().as_str().unwrap(), "lockdown");
    }
}
