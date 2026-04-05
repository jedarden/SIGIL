//! Request access example
//!
//! This example demonstrates the secret request workflow.
//! Agents can request access to secrets they don't currently have,
//! with human approval via the TUI.

use sigil_sdk::SigilClient;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Create client and connect
    let client = SigilClient::connect_default()?;
    client.connect().await?;
    println!("✓ Connected to daemon\n");

    // Example 1: Request access for 5 minutes
    println!("=== Example 1: Time-Bounded Access (5 minutes) ===");
    let secret_path = "prod/database/password";
    let reason = "Need to run database migration";
    let duration = Some(300); // 5 minutes in seconds

    println!("Requesting access to: {}", secret_path);
    println!("Reason: {}", reason);
    println!("Duration: 5 minutes");

    match client.request_access(secret_path, reason, duration).await {
        Ok(grant) => {
            if grant.granted {
                println!("✓ Access granted!");
                if let Some(expires) = grant.expires_at {
                    println!("  Expires at: {}", expires);
                }

                // Now you can use the secret
                println!("\nFetching the secret...");
                match client.get(secret_path).await {
                    Ok(value) => {
                        let secret_value =
                            value.expose(|bytes| String::from_utf8_lossy(bytes).to_string());
                        println!("✓ Secret value: {}", secret_value);
                    }
                    Err(e) => {
                        println!("✗ Error fetching secret: {}", e);
                    }
                }
            } else {
                println!("✗ Access denied");
            }
        }
        Err(e) => {
            println!("✗ Error: {}", e);
            println!("(This is expected if the daemon/TUI is not running)");
        }
    }

    println!();

    // Example 2: Request session-level access
    println!("=== Example 2: Session-Level Access ===");
    let secret_path = "prod/api/key";
    let reason = "API testing for this session";
    let duration = None; // No timeout - lasts for the session

    println!("Requesting access to: {}", secret_path);
    println!("Reason: {}", reason);
    println!("Duration: Session (until agent disconnects)");

    match client.request_access(secret_path, reason, duration).await {
        Ok(grant) => {
            if grant.granted {
                println!("✓ Access granted for the session!");
                if let Some(expires) = grant.expires_at {
                    println!("  Expires at: {}", expires);
                } else {
                    println!("  No expiration - valid for this session");
                }
            } else {
                println!("✗ Access denied");
            }
        }
        Err(e) => {
            println!("✗ Error: {}", e);
        }
    }

    println!();

    // Example 3: Check daemon status
    println!("=== Example 3: Daemon Status ===");
    match client.status().await {
        Ok(status) => {
            println!("Daemon Status:");
            println!("  Running: {}", status.running);
            println!("  Uptime: {} seconds", status.uptime_secs);
            println!("  Active sessions: {}", status.active_sessions);
            println!("  Secrets loaded: {}", status.secrets_loaded);
        }
        Err(e) => {
            println!("✗ Error: {}", e);
        }
    }

    Ok(())
}

/// Example: Using access requests with retries
#[allow(dead_code)]
async fn request_with_retry_example() {
    use sigil_sdk::SigilClient;
    use tokio::time::{interval, Duration};

    let client = SigilClient::connect_default().unwrap();

    // Retry every 30 seconds until access is granted
    let mut retry_interval = interval(Duration::from_secs(30));
    let secret_path = "prod/secret";
    let reason = "Long-running job needs access";

    loop {
        match client.request_access(secret_path, reason, Some(3600)).await {
            Ok(grant) if grant.granted => {
                println!("Access granted! Proceeding with operation...");
                break;
            }
            Ok(_) => {
                println!("Access denied, will retry in 30 seconds...");
            }
            Err(e) => {
                println!("Error: {}, will retry in 30 seconds...", e);
            }
        }

        retry_interval.tick().await;
    }
}
