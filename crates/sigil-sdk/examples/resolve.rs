//! Resolve placeholders example
//!
//! This example demonstrates how to resolve strings containing
//! secret placeholders into their actual values.

use sigil_sdk::SigilClient;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Create client and connect
    let client = SigilClient::connect_default()?;
    client.connect().await?;
    println!("✓ Connected to daemon\n");

    // Example 1: Simple placeholder resolution
    println!("=== Example 1: Single Placeholder ===");
    let input = "Bearer {{secret:example/api_key}}";
    println!("Input:  {}", input);

    match client.resolve(input).await {
        Ok(resolved) => {
            println!("Output: {}", resolved);
        }
        Err(e) => {
            println!("Error: {}", e);
            println!("(This is expected if the secret doesn't exist)");
        }
    }

    println!();

    // Example 2: Multiple placeholders
    println!("=== Example 2: Multiple Placeholders ===");
    let input = "DB_HOST=localhost \
                  DB_USER={{secret:db/user}} \
                  DB_PASS={{secret:db/password}}";
    println!("Input:");
    println!("  {}", input);

    match client.resolve(input).await {
        Ok(resolved) => {
            println!("Output:");
            println!("  {}", resolved);
        }
        Err(e) => {
            println!("Error: {}", e);
        }
    }

    println!();

    // Example 3: Command with placeholders
    println!("=== Example 3: Command with Placeholders ===");
    let input = "curl -H 'Authorization: Bearer {{secret:api/token}}' \
                 https://api.example.com/data";
    println!("Command:");
    println!("  {}", input);

    match client.resolve(input).await {
        Ok(resolved) => {
            println!("Resolved command:");
            println!("  {}", resolved);
            println!("\nYou would then execute this command in the SIGIL sandbox");
        }
        Err(e) => {
            println!("Error: {}", e);
        }
    }

    println!();

    // Example 4: Configuration file template
    println!("=== Example 4: Configuration Template ===");
    let input = r#"
[database]
host = localhost
port = 5432
username = {{secret:db/username}}
password = {{secret:db/password}}

[api]
endpoint = https://api.example.com
key = {{secret:api/key}}
"#;
    println!("Template:");
    println!("{}", input);

    match client.resolve(input).await {
        Ok(resolved) => {
            println!("Resolved:");
            println!("{}", resolved);
        }
        Err(e) => {
            println!("Error: {}", e);
        }
    }

    Ok(())
}
