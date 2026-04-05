//! SIGIL SDK - Node.js bindings
//!
//! This crate provides Node.js native bindings for SIGIL using napi-rs.
//! It allows JavaScript/TypeScript code to interact with the SIGIL daemon.

#![warn(missing_docs)]
#![warn(clippy::all)]

use napi_derive::napi;

/// SIGIL SDK client for Node.js
///
/// This client connects to the SIGIL daemon via Unix socket and provides
/// methods for interacting with secrets.
#[napi]
pub struct SigilClient {
    /// Inner Rust client
    inner: Option<sigil_sdk::SigilClient>,
}

#[napi]
impl SigilClient {
    /// Create a new SIGIL client with default socket path
    #[napi(constructor)]
    pub fn new() -> napi::Result<Self> {
        let client = sigil_sdk::SigilClient::connect_default()
            .map_err(|e| napi::Error::from_reason(format!("Failed to create client: {}", e)))?;

        Ok(Self {
            inner: Some(client),
        })
    }

    /// Connect to the SIGIL daemon (verifies connection)
    #[napi]
    pub async fn connect(&self) -> napi::Result<()> {
        let client = self
            .inner
            .as_ref()
            .ok_or_else(|| napi::Error::from_reason("Client not initialized"))?;

        client
            .connect()
            .await
            .map_err(|e| napi::Error::from_reason(format!("Failed to connect to daemon: {}", e)))?;

        Ok(())
    }

    /// Get a secret value by path
    #[napi]
    pub async fn get(&self, path: String) -> napi::Result<String> {
        let client = self
            .inner
            .as_ref()
            .ok_or_else(|| napi::Error::from_reason("Client not initialized"))?;

        let secret_value = client
            .get(&path)
            .await
            .map_err(|e| napi::Error::from_reason(format!("Failed to get secret: {}", e)))?;

        secret_value.expose(|bytes| {
            String::from_utf8(bytes.to_vec())
                .map_err(|e| napi::Error::from_reason(format!("Secret is not valid UTF-8: {}", e)))
        })
    }

    /// Resolve placeholders in a string
    #[napi]
    pub async fn resolve(&self, input: String) -> napi::Result<String> {
        let client = self
            .inner
            .as_ref()
            .ok_or_else(|| napi::Error::from_reason("Client not initialized"))?;

        client
            .resolve(&input)
            .await
            .map_err(|e| napi::Error::from_reason(format!("Failed to resolve placeholders: {}", e)))
    }

    /// Check if a secret exists
    #[napi]
    pub async fn exists(&self, path: String) -> napi::Result<bool> {
        let client = self
            .inner
            .as_ref()
            .ok_or_else(|| napi::Error::from_reason("Client not initialized"))?;

        client.exists(&path).await.map_err(|e| {
            napi::Error::from_reason(format!("Failed to check secret existence: {}", e))
        })
    }

    /// List secrets with a given prefix
    #[napi]
    pub async fn list(&self, prefix: String) -> napi::Result<Vec<SecretMetadata>> {
        let client = self
            .inner
            .as_ref()
            .ok_or_else(|| napi::Error::from_reason("Client not initialized"))?;

        let secrets = client
            .list(&prefix)
            .await
            .map_err(|e| napi::Error::from_reason(format!("Failed to list secrets: {}", e)))?;

        // Convert SDK metadata to Node.js compatible metadata
        secrets
            .into_iter()
            .map(|meta| {
                Ok(SecretMetadata {
                    path: meta.path,
                    secret_type: meta.secret_type,
                    created_at: meta.created_at,
                    updated_at: meta.updated_at,
                    tags: meta.tags,
                    notes: meta.notes,
                })
            })
            .collect::<Result<Vec<SecretMetadata>, napi::Error>>()
    }
}

/// Secret metadata for Node.js
#[napi(object)]
pub struct SecretMetadata {
    /// Secret path
    pub path: String,
    /// Secret type
    pub secret_type: String,
    /// Creation timestamp (RFC3339)
    pub created_at: String,
    /// Last update timestamp (RFC3339)
    pub updated_at: String,
    /// Tags
    pub tags: Vec<String>,
    /// Notes
    pub notes: Option<String>,
}
