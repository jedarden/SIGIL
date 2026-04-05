//! List secrets example
//!
//! This example demonstrates how to list secrets from the vault
//! with optional filtering by prefix.

use sigil_sdk::SigilClient;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Create client and connect
    let client = SigilClient::connect_default()?;
    client.connect().await?;
    println!("✓ Connected to daemon\n");

    // List all secrets (empty prefix)
    println!("=== All Secrets ===");
    match list_secrets(&client, "").await {
        Ok(()) => {}
        Err(e) => println!("Error listing secrets: {}", e),
    }

    println!();

    // List only secrets starting with "aws/"
    println!("=== AWS Secrets ===");
    match list_secrets(&client, "aws/").await {
        Ok(()) => {}
        Err(e) => println!("Error listing AWS secrets: {}", e),
    }

    println!();

    // List only secrets starting with "github/"
    println!("=== GitHub Secrets ===");
    match list_secrets(&client, "github/").await {
        Ok(()) => {}
        Err(e) => println!("Error listing GitHub secrets: {}", e),
    }

    Ok(())
}

async fn list_secrets(
    client: &SigilClient,
    prefix: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let secrets = client.list(prefix).await?;

    if secrets.is_empty() {
        println!("No secrets found with prefix: '{}'", prefix);
        return Ok(());
    }

    println!("Found {} secret(s):\n", secrets.len());

    for secret in secrets {
        println!("  Path: {}", secret.path);
        println!("  Type: {}", secret.secret_type);
        println!("  Created: {}", secret.created_at);
        println!("  Updated: {}", secret.updated_at);

        if !secret.tags.is_empty() {
            println!("  Tags: {}", secret.tags.join(", "));
        }

        if let Some(notes) = &secret.notes {
            println!("  Notes: {}", notes);
        }

        println!();
    }

    Ok(())
}
