//! Docker credential helper for SIGIL
//!
//! This implements the Docker credential helper protocol, allowing Docker
//! to use SIGIL-managed credentials for container registry authentication.
//!
//! The protocol is a simple stdin/stdout JSON-based interface:
//! - `get`: Returns credentials for a given server URL
//! - `store`: Stores credentials for a given server URL
//! - `erase`: Removes credentials for a given server URL
//! - `list`: Lists all stored credentials
//!
//! Usage:
//! ```bash
//! # Configure Docker to use SIGIL
//! sigil setup docker
//!
//! # Docker will now call this helper for authentication
//! docker pull ghcr.io/example/image:latest
//! ```

#![warn(missing_docs)]
#![warn(clippy::all)]

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use sigil_core::SecretBackend;
use std::io::{self, Read};
use tracing::{debug, error, info};

/// Docker credential helper protocol - Get request
#[derive(Debug, Deserialize)]
#[allow(non_snake_case)]
struct GetRequest {
    /// Server URL (e.g., <https://ghcr.io>)
    ServerURL: String,
}

/// Docker credential helper protocol - Get response
#[derive(Debug, Serialize)]
#[allow(non_snake_case)]
#[allow(dead_code)]
struct GetResponse {
    /// Username (typically empty for token-based auth)
    Username: String,
    /// Secret (password or token)
    Secret: String,
}

/// Docker credential helper protocol - Store request
#[derive(Debug, Deserialize)]
#[allow(non_snake_case)]
#[allow(dead_code)]
struct StoreRequest {
    /// Server URL
    ServerURL: String,
    /// Username (typically empty for token-based auth)
    Username: String,
    /// Secret (password or token)
    Secret: String,
}

/// Docker credential helper protocol - Erase request
#[derive(Debug, Deserialize)]
#[allow(non_snake_case)]
struct EraseRequest {
    /// Server URL
    ServerURL: String,
}

/// Docker credential helper protocol - List response
#[derive(Debug, Serialize)]
struct ListResponse {
    /// Map of server URLs to usernames (empty for token auth)
    #[serde(flatten)]
    credentials: serde_json::Map<String, serde_json::Value>,
}

/// Mapping from Docker registry URLs to vault secret paths
fn map_registry_to_vault_path(server_url: &str) -> Option<String> {
    let url = server_url
        .trim_start_matches("https://")
        .trim_start_matches("http://");

    let vault_path = match url {
        "ghcr.io" => Some("docker/ghcr_token"),
        "index.docker.io" | "registry-1.docker.io" | "docker.io" => Some("docker/hub_token"),
        "gcr.io" => Some("docker/gcr_token"),
        "public.ecr.aws" => Some("docker/ecr_public_token"),
        // For private ECR registries (*.amazonaws.com)
        s if s.contains("amazonaws.com") && s.contains("ecr") => Some("docker/ecr_token"),
        // For Azure Container Registry (*.azurecr.io)
        s if s.contains("azurecr.io") => Some("docker/acr_token"),
        // For Google Container Registry (gcr.io, *.gcr.io)
        s if s.contains("gcr.io") => Some("docker/gcr_token"),
        _ => None,
    };

    vault_path.map(|p| p.to_string())
}

/// Handle the `get` command - retrieve credentials for a server
fn handle_get(request: GetRequest) -> Result<GetResponse> {
    info!("Docker get request for: {}", request.ServerURL);

    // Map server URL to vault path
    let vault_path = map_registry_to_vault_path(&request.ServerURL)
        .ok_or_else(|| anyhow::anyhow!("Unknown registry: {}", request.ServerURL))?;

    debug!("Mapped {} to vault path: {}", request.ServerURL, vault_path);

    // Load vault and get secret
    let vault = load_vault()?;
    let rt = tokio::runtime::Runtime::new().context("Failed to create async runtime")?;

    let secret_value = rt
        .block_on(vault.get(&sigil_core::SecretPath::new(vault_path)?))
        .map_err(|e| anyhow::anyhow!("Secret not found: {}", e))?;

    // Get the secret value as bytes using expose
    let secret_str = secret_value.expose(|bytes| {
        String::from_utf8(bytes.to_vec())
            .map_err(|e| anyhow::anyhow!("Secret is not valid UTF-8: {}", e))
    })?;

    info!(
        "Successfully retrieved credentials for: {}",
        request.ServerURL
    );

    Ok(GetResponse {
        Username: String::new(), // Token-based auth uses empty username
        Secret: secret_str,
    })
}

/// Handle the `store` command - store credentials for a server
fn handle_store(request: StoreRequest) -> Result<()> {
    info!("Docker store request for: {}", request.ServerURL);

    // Map server URL to vault path
    let vault_path = map_registry_to_vault_path(&request.ServerURL)
        .ok_or_else(|| anyhow::anyhow!("Unknown registry: {}", request.ServerURL))?;

    debug!(
        "Storing credentials for {} at vault path: {}",
        request.ServerURL, vault_path
    );

    // Load vault and store secret
    let vault = load_vault()?;
    let rt = tokio::runtime::Runtime::new().context("Failed to create async runtime")?;

    use sigil_core::{SecretMetadata, SecretValue};

    let vault_path_obj = sigil_core::SecretPath::new(vault_path.clone())?;

    let mut metadata = SecretMetadata::new(vault_path_obj.clone());
    metadata.notes = Some(format!("Docker credentials for {}", request.ServerURL));
    metadata.tags = vec!["docker".to_string(), "credential-helper".to_string()];

    let secret_value = SecretValue::new(request.Secret.into_bytes());

    rt.block_on(vault.set(&vault_path_obj, &secret_value, &metadata))
        .map_err(|e| anyhow::anyhow!("Failed to store secret: {}", e))?;

    info!("Successfully stored credentials for: {}", request.ServerURL);

    Ok(())
}

/// Handle the `erase` command - remove credentials for a server
fn handle_erase(request: EraseRequest) -> Result<()> {
    info!("Docker erase request for: {}", request.ServerURL);

    // Map server URL to vault path
    let vault_path = map_registry_to_vault_path(&request.ServerURL)
        .ok_or_else(|| anyhow::anyhow!("Unknown registry: {}", request.ServerURL))?;

    debug!(
        "Erasing credentials for {} at vault path: {}",
        request.ServerURL, vault_path
    );

    // Load vault and delete secret
    let vault = load_vault()?;
    let rt = tokio::runtime::Runtime::new().context("Failed to create async runtime")?;

    rt.block_on(vault.delete(&sigil_core::SecretPath::new(vault_path)?))
        .map_err(|e| anyhow::anyhow!("Failed to delete secret: {}", e))?;

    info!("Successfully erased credentials for: {}", request.ServerURL);

    Ok(())
}

/// Handle the `list` command - list all stored credentials
fn handle_list() -> Result<ListResponse> {
    info!("Docker list request");

    // Load vault and list secrets
    let vault = load_vault()?;
    let rt = tokio::runtime::Runtime::new().context("Failed to create async runtime")?;

    let secrets = rt
        .block_on(vault.list("docker/"))
        .map_err(|e| anyhow::anyhow!("Failed to list secrets: {}", e))?;

    // Build list response (server URL -> username map)
    let mut credentials = serde_json::Map::new();

    for secret_meta in secrets {
        // Map vault path back to server URL
        let server_url = match secret_meta.path.as_str() {
            "docker/ghcr_token" => "https://ghcr.io",
            "docker/hub_token" => "https://index.docker.io",
            "docker/gcr_token" => "https://gcr.io",
            "docker/ecr_public_token" => "https://public.ecr.aws",
            "docker/ecr_token" => "https://public.ecr.aws", // Placeholder for ECR
            "docker/acr_token" => "https://azurecr.io",     // Placeholder for ACR
            _ => continue,                                  // Skip unknown paths
        };

        // Token-based auth uses empty username
        credentials.insert(server_url.to_string(), serde_json::json!(""));
    }

    info!("Listed {} Docker credentials", credentials.len());

    Ok(ListResponse { credentials })
}

/// Load the SIGIL vault
fn load_vault() -> Result<sigil_vault::LocalVault> {
    let home =
        dirs::home_dir().ok_or_else(|| anyhow::anyhow!("Cannot determine home directory"))?;
    let sigil_dir = home.join(".sigil");
    let vault_path = sigil_dir.join("vault");
    let identity_path = sigil_dir.join("identity.age");

    if !sigil_dir.exists() {
        anyhow::bail!("SIGIL not initialized. Run `sigil init` first.");
    }

    let mut vault = sigil_vault::LocalVault::new(vault_path, identity_path)?;

    // Try to load without passphrase (will fail if vault is passphrase-protected)
    vault.load(None)?;

    Ok(vault)
}

/// Run the credential helper
fn run() -> Result<()> {
    // Initialize logging
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env()
                .add_directive(tracing::Level::INFO.into()),
        )
        .init();

    // Read command from stdin
    let mut input = String::new();
    io::stdin().read_to_string(&mut input)?;

    debug!("Received input: {}", input);

    // Parse command
    let args: Vec<&str> = input.split_whitespace().collect();
    if args.is_empty() {
        anyhow::bail!("No command provided");
    }

    let command = args[0];
    let rest = input[args[0].len()..].trim();

    match command {
        "get" => {
            let request: GetRequest =
                serde_json::from_str(rest).context("Failed to parse get request")?;
            let response = handle_get(request)?;
            println!("{}", serde_json::to_string(&response)?);
        }
        "store" => {
            let request: StoreRequest =
                serde_json::from_str(rest).context("Failed to parse store request")?;
            handle_store(request)?;
        }
        "erase" => {
            let request: EraseRequest =
                serde_json::from_str(rest).context("Failed to parse erase request")?;
            handle_erase(request)?;
        }
        "list" => {
            let response = handle_list()?;
            println!("{}", serde_json::to_string(&response)?);
        }
        _ => {
            error!("Unknown command: {}", command);
            anyhow::bail!("Unknown command: {}", command);
        }
    }

    Ok(())
}

fn main() -> Result<()> {
    if let Err(e) = run() {
        eprintln!("Error: {}", e);
        std::process::exit(1);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_map_registry_to_vault_path() {
        assert_eq!(
            map_registry_to_vault_path("https://ghcr.io"),
            Some("docker/ghcr_token".to_string())
        );
        assert_eq!(
            map_registry_to_vault_path("ghcr.io"),
            Some("docker/ghcr_token".to_string())
        );
        assert_eq!(
            map_registry_to_vault_path("https://index.docker.io"),
            Some("docker/hub_token".to_string())
        );
        assert_eq!(
            map_registry_to_vault_path("docker.io"),
            Some("docker/hub_token".to_string())
        );
        assert_eq!(
            map_registry_to_vault_path("https://gcr.io"),
            Some("docker/gcr_token".to_string())
        );
        assert_eq!(
            map_registry_to_vault_path("https://public.ecr.aws"),
            Some("docker/ecr_public_token".to_string())
        );
        // Unknown registry returns None
        assert_eq!(
            map_registry_to_vault_path("https://unknown-registry.example.com"),
            None
        );
    }

    #[test]
    fn test_get_request_serialization() {
        let json = r#"{"ServerURL":"https://ghcr.io"}"#;
        let request: GetRequest = serde_json::from_str(json).unwrap();
        assert_eq!(request.ServerURL, "https://ghcr.io");
    }

    #[test]
    fn test_get_response_serialization() {
        let response = GetResponse {
            Username: String::new(),
            Secret: "my-token".to_string(),
        };
        let json = serde_json::to_string(&response).unwrap();
        assert!(json.contains(r#""Username":""#));
        assert!(json.contains(r#""Secret":"my-token""#));
    }
}
