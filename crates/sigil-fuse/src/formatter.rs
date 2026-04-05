//! Auto-generated formatted file support
//!
//! This module provides formatters for generating structured files from secrets.
//! It supports:
//! - AWS credentials in INI format
//! - Kubernetes kubeconfig in YAML format
//! - TLS certificates and keys in PEM format

use anyhow::{Context, Result};
use sigil_core::SecretValue;
use std::collections::HashMap;

/// Formatter type for auto-generated files
#[derive(Debug, Clone, Copy)]
pub enum FormatterType {
    /// AWS credentials file (~/.aws/credentials format)
    AwsCredentials,
    /// Kubernetes kubeconfig file
    Kubeconfig,
    /// TLS certificate in PEM format
    TlsCertificate,
    /// TLS private key in PEM format
    TlsPrivateKey,
    /// Generic INI file
    Ini,
    /// Generic YAML file
    Yaml,
    /// Generic JSON file
    Json,
}

/// Formatter for auto-generated files
pub struct Formatter {
    /// Formatter type
    formatter_type: FormatterType,
    /// Secret paths to include in the formatted file
    secret_paths: Vec<String>,
    /// Additional metadata for formatting
    metadata: HashMap<String, String>,
}

impl Formatter {
    /// Create a new formatter
    pub fn new(formatter_type: FormatterType) -> Self {
        Self {
            formatter_type,
            secret_paths: Vec::new(),
            metadata: HashMap::new(),
        }
    }

    /// Add a secret path to include in the formatted file
    pub fn add_secret(mut self, path: impl Into<String>) -> Self {
        self.secret_paths.push(path.into());
        self
    }

    /// Add metadata for formatting
    pub fn add_metadata(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.metadata.insert(key.into(), value.into());
        self
    }

    /// Format the file content from secrets
    ///
    /// # Arguments
    ///
    /// * `secrets` - Map of secret paths to their values
    ///
    /// # Returns
    ///
    /// Formatted file content as bytes
    pub fn format(&self, secrets: &HashMap<String, SecretValue>) -> Result<Vec<u8>> {
        match self.formatter_type {
            FormatterType::AwsCredentials => self.format_aws_credentials(secrets),
            FormatterType::Kubeconfig => self.format_kubeconfig(secrets),
            FormatterType::TlsCertificate => self.format_tls_cert(secrets),
            FormatterType::TlsPrivateKey => self.format_tls_key(secrets),
            FormatterType::Ini => self.format_ini(secrets),
            FormatterType::Yaml => self.format_yaml(secrets),
            FormatterType::Json => self.format_json(secrets),
        }
    }

    /// Format AWS credentials file
    fn format_aws_credentials(&self, secrets: &HashMap<String, SecretValue>) -> Result<Vec<u8>> {
        let profile = self.metadata.get("profile").cloned().unwrap_or_else(|| "default".to_string());
        let access_key_id = self.get_secret(secrets, &["aws/access_key_id", "aws/accessKeyId"])
            .context("AWS access key ID not found")?;
        let secret_access_key = self.get_secret(secrets, &["aws/secret_access_key", "aws/secretAccessKey"])
            .context("AWS secret access key not found")?;
        let session_token = self.get_secret_optional(secrets, &["aws/session_token", "aws/sessionToken"]);

        let mut content = format!(
            "[{}]\naws_access_key_id = {}\n",
            profile,
            access_key_id.as_str()
        );

        content.push_str(&format!(
            "aws_secret_access_key = {}\n",
            secret_access_key.as_str()
        ));

        if let Some(token) = session_token {
            content.push_str(&format!("aws_session_token = {}\n", token.as_str()));
        }

        Ok(content.into_bytes())
    }

    /// Format Kubernetes kubeconfig file
    fn format_kubeconfig(&self, secrets: &HashMap<String, SecretValue>) -> Result<Vec<u8>> {
        let cluster_name = self.metadata.get("cluster_name")
            .cloned()
            .unwrap_or_else(|| "kubernetes".to_string());
        let context_name = self.metadata.get("context_name")
            .cloned()
            .unwrap_or_else(|| "default".to_string());
        let user_name = self.metadata.get("user_name")
            .cloned()
            .unwrap_or_else(|| "sigil-user".to_string());

        // Get kubeconfig file if it exists
        if let Some(kubeconfig) = self.get_secret_optional(secrets, &["k8s/kubeconfig", "k8s/kubeConfig"]) {
            return Ok(kubeconfig.as_bytes().to_vec());
        }

        // Generate minimal kubeconfig from certificate and key
        let certificate = self.get_secret_optional(secrets, &["k8s/certificate", "k8s/cert", "k8s/client_certificate"]);
        let key = self.get_secret_optional(secrets, &["k8s/key", "k8s/client_key"]);
        let token = self.get_secret_optional(secrets, &["k8s/token", "k8s/bearer_token"]);
        let api_endpoint = self.metadata.get("api_endpoint")
            .cloned()
            .unwrap_or_else(|| "https://kubernetes.default.svc".to_string());

        let mut content = format!(
            r#"apiVersion: v1
kind: Config
clusters:
- cluster:
    server: {}
"#,
            api_endpoint
        );

        if let Some(cert) = certificate {
            content.push_str(&format!("    certificate-authority-data: {}\n", cert.as_str()));
        }

        content.push_str(&format!("  name: {}\n", cluster_name));

        content.push_str("users:\n");
        content.push_str(&format!("- user: {}\n", user_name));

        if let Some(client_cert) = self.get_secret_optional(secrets, &["k8s/client_certificate", "k8s/clientCert"]) {
            content.push_str(&format!("  user: {}\n", user_name));
            content.push_str("  client-certificate-data: ");
            content.push_str(client_cert.as_str());
            content.push_str("\n");
        }

        if let Some(client_key) = key {
            content.push_str("  client-key-data: ");
            content.push_str(client_key.as_str());
            content.push_str("\n");
        }

        if let Some(t) = token {
            content.push_str("  token: ");
            content.push_str(t.as_str());
            content.push_str("\n");
        }

        content.push_str(&format!(
            "contexts:\n- context:\n    cluster: {}\n    user: {}\n  name: {}\n",
            cluster_name, user_name, context_name
        ));

        content.push_str(&format!("current-context: {}\n", context_name));

        Ok(content.into_bytes())
    }

    /// Format TLS certificate in PEM format
    fn format_tls_cert(&self, secrets: &HashMap<String, SecretValue>) -> Result<Vec<u8>> {
        let cert = self.get_secret(secrets, &["tls/certificate", "tls/cert", "tls/server_certificate"])
            .context("TLS certificate not found")?;

        // If already in PEM format, return as-is
        let cert_str = cert.as_str();
        if cert_str.contains("-----BEGIN CERTIFICATE-----") {
            return Ok(cert_str.as_bytes().to_vec());
        }

        // Otherwise, wrap in PEM format
        let content = format!(
            "-----BEGIN CERTIFICATE-----\n{}\n-----END CERTIFICATE-----\n",
            cert_str
        );
        Ok(content.into_bytes())
    }

    /// Format TLS private key in PEM format
    fn format_tls_key(&self, secrets: &HashMap<String, SecretValue>) -> Result<Vec<u8>> {
        let key = self.get_secret(secrets, &["tls/private_key", "tls/key", "tls/server_key"])
            .context("TLS private key not found")?;

        // If already in PEM format, return as-is
        let key_str = key.as_str();
        if key_str.contains("-----BEGIN") {
            return Ok(key_str.as_bytes().to_vec());
        }

        // Detect key type and wrap appropriately
        let content = if key_str.len() > 1000 {
            // Likely RSA key
            format!(
                "-----BEGIN RSA PRIVATE KEY-----\n{}\n-----END RSA PRIVATE KEY-----\n",
                key_str
            )
        } else {
            // Likely EC key or PKCS8
            format!(
                "-----BEGIN PRIVATE KEY-----\n{}\n-----END PRIVATE KEY-----\n",
                key_str
            )
        };
        Ok(content.into_bytes())
    }

    /// Format generic INI file
    fn format_ini(&self, secrets: &HashMap<String, SecretValue>) -> Result<Vec<u8>> {
        let mut content = String::new();

        for (path, value) in secrets.iter() {
            // Convert path to INI section/key format
            let parts: Vec<&str> = path.split('/').collect();
            if parts.len() >= 2 {
                let section = parts[0];
                let key = parts[1..].join("_");
                content.push_str(&format!("[{}]\n", section));
                content.push_str(&format!("{} = {}\n\n", key, value.as_str()));
            }
        }

        Ok(content.into_bytes())
    }

    /// Format generic YAML file
    fn format_yaml(&self, secrets: &HashMap<String, SecretValue>) -> Result<Vec<u8>> {
        let mut content = String::new();

        for (path, value) in secrets.iter() {
            // Convert path to nested YAML structure
            let parts: Vec<&str> = path.split('/').collect();
            for (i, part) in parts.iter().enumerate() {
                content.push_str(&"  ".repeat(i));
                content.push_str(part);
                if i < parts.len() - 1 {
                    content.push_str(":\n");
                } else {
                    content.push_str(": ");
                    content.push_str(value.as_str());
                    content.push('\n');
                }
            }
        }

        Ok(content.into_bytes())
    }

    /// Format generic JSON file
    fn format_json(&self, secrets: &HashMap<String, SecretValue>) -> Result<Vec<u8>> {
        // Convert secrets to nested JSON structure
        let mut root: serde_json::Value = serde_json::json!({});

        for (path, value) in secrets.iter() {
            let parts: Vec<&str> = path.split('/').collect();
            let current = &mut root;

            for (i, part) in parts.iter().enumerate() {
                if i == parts.len() - 1 {
                    // Last part - set the value
                    if let Some(obj) = current.as_object_mut() {
                        obj.insert(part.to_string(), serde_json::Value::String(value.as_str().to_string()));
                    }
                } else {
                    // Intermediate part - ensure object exists
                    if let Some(obj) = current.as_object_mut() {
                        if !obj.contains_key(*part) {
                            obj.insert(part.to_string(), serde_json::Value::Object(serde_json::Map::new()));
                        }
                        // Navigate deeper
                    }
                }
            }
        }

        serde_json::to_vec_pretty(&root)
            .context("Failed to serialize JSON")
    }

    /// Get a secret value from multiple possible paths
    fn get_secret(&self, secrets: &HashMap<String, SecretValue>, paths: &[&str]) -> Result<SecretValue> {
        for path in paths {
            if let Some(value) = secrets.get(*path) {
                return Ok(value.clone());
            }
        }
        anyhow::bail!("Secret not found in any of the provided paths")
    }

    /// Get an optional secret value from multiple possible paths
    fn get_secret_optional(&self, secrets: &HashMap<String, SecretValue>, paths: &[&str]) -> Option<SecretValue> {
        for path in paths {
            if let Some(value) = secrets.get(*path) {
                return Some(value.clone());
            }
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sigil_core::SecretValue;

    #[test]
    fn test_formatter_aws_credentials() {
        let mut secrets = HashMap::new();
        secrets.insert(
            "aws/access_key_id".to_string(),
            SecretValue::new("AKIAIOSFODNN7EXAMPLE".as_bytes().to_vec()),
        );
        secrets.insert(
            "aws/secret_access_key".to_string(),
            SecretValue::new("wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY".as_bytes().to_vec()),
        );

        let formatter = Formatter::new(FormatterType::AwsCredentials);
        let result = formatter.format(&secrets).unwrap();

        let content = String::from_utf8(result).unwrap();
        assert!(content.contains("[default]"));
        assert!(content.contains("aws_access_key_id = AKIAIOSFODNN7EXAMPLE"));
        assert!(content.contains("aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"));
    }

    #[test]
    fn test_formatter_kubeconfig_minimal() {
        let mut secrets = HashMap::new();
        secrets.insert(
            "k8s/token".to_string(),
            SecretValue::new("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.test".as_bytes().to_vec()),
        );

        let mut formatter = Formatter::new(FormatterType::Kubeconfig);
        formatter = formatter.add_metadata("api_endpoint", "https://test-cluster.example.com");

        let result = formatter.format(&secrets).unwrap();

        let content = String::from_utf8(result).unwrap();
        assert!(content.contains("apiVersion: v1"));
        assert!(content.contains("server: https://test-cluster.example.com"));
        assert!(content.contains("token:"));
    }

    #[test]
    fn test_formatter_tls_certificate() {
        let mut secrets = HashMap::new();
        let cert_pem = "-----BEGIN CERTIFICATE-----\nMIIC9jCCAd4CCQD2rKXxBHxPtDANBgkqhkiG9w0BAQsFADA9MQswCQYDVQQGEwJV\nUzELMAkGA1UECAwCQ0ExFjAUBgNVBAcMDVNhbiBGcmFuY2lzY28wHhcNMjQwMTAx\nMDAwMDAwWhcNMjUwMTAxMDAwMDAwWjA5MQswCQYDVQQGEwJVUzELMAkGA1UECAwC\nQ0ExFjAUBgNVBAcMDVNhbiBGcmFuY2lzY2MwHhcNMjQwMTAxMDAwMDAwWhcNMjUw\n-----END CERTIFICATE-----";
        secrets.insert(
            "tls/certificate".to_string(),
            SecretValue::new(cert_pem.as_bytes().to_vec()),
        );

        let formatter = Formatter::new(FormatterType::TlsCertificate);
        let result = formatter.format(&secrets).unwrap();

        let content = String::from_utf8(result).unwrap();
        assert!(content.contains("-----BEGIN CERTIFICATE-----"));
        assert!(content.contains("-----END CERTIFICATE-----"));
    }

    #[test]
    fn test_formatter_json() {
        let mut secrets = HashMap::new();
        secrets.insert(
            "database/host".to_string(),
            SecretValue::new("localhost".as_bytes().to_vec()),
        );
        secrets.insert(
            "database/port".to_string(),
            SecretValue::new("5432".as_bytes().to_vec()),
        );

        let formatter = Formatter::new(FormatterType::Json);
        let result = formatter.format(&secrets).unwrap();

        let content = String::from_utf8(result).unwrap();
        assert!(content.contains("\"database\""));
        assert!(content.contains("\"host\""));
        assert!(content.contains("\"localhost\""));
        assert!(content.contains("\"port\""));
        assert!(content.contains("\"5432\""));
    }
}
