//! Basic SIGIL SDK example
//!
//! This example demonstrates how to connect to the SIGIL daemon
//! and retrieve a secret value.

use sigil_sdk::SigilClient;
use std::path::PathBuf;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Create a client with the default socket path
    let client = SigilClient::connect_default()?;

    // Connect to the daemon and verify it's running
    println!("Connecting to SIGIL daemon...");
    client.connect().await?;
    println!("✓ Connected to daemon");

    // Get a secret by path
    let secret_path = "example/api_key";
    println!("\nGetting secret: {}", secret_path);

    match client.get(secret_path).await {
        Ok(value) => {
            // Expose the secret value
            let secret_value = value.expose(|bytes| String::from_utf8_lossy(bytes).to_string());
            println!("✓ Secret value: {}", secret_value);
        }
        Err(e) => {
            println!("✗ Error: {}", e);
            println!("  (This is expected if the secret doesn't exist)");
        }
    }

    // Check if a secret exists
    println!("\nChecking if secret exists: {}", secret_path);
    match client.exists(secret_path).await {
        Ok(exists) => {
            if exists {
                println!("✓ Secret exists");
            } else {
                println!("✗ Secret does not exist");
            }
        }
        Err(e) => {
            println!("✗ Error: {}", e);
        }
    }

    Ok(())
}

/// Example: Create a client with a custom socket path
#[allow(dead_code)]
fn custom_socket_example() {
    use sigil_sdk::SigilClient;

    // Use a custom socket path
    let socket_path = PathBuf::from("/tmp/custom-sigil.sock");

    // Create a client with the custom path
    let client = SigilClient::new(socket_path);

    // The client can be configured with a timeout
    match client {
        Ok(_) => {
            println!("Client created with custom configuration");
            println!("  Custom socket path configured");
            println!("  Default timeout: 30 seconds");

            // You can also configure with a custom timeout:
            // let client = SigilClient::new(path)?
            //     .with_timeout(60) // 60 second timeout
            //     .with_session_token(token); // optional session token
        }
        Err(e) => {
            eprintln!("Failed to create client: {}", e);
        }
    }
}
