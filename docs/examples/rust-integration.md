# 🦀 Rust Integration

> Using SIGIL with Rust projects and applications.

---

## 📋 Prerequisites

- Rust 1.75+ (2021 edition)
- SIGIL daemon running (`sigild`)
- SIGIL SDK added to `Cargo.toml`

---

## 🚀 Getting Started

### Add SIGIL SDK to Your Project

```bash
# Add sigil-sdk to your project
cargo add sigil-sdk
```

Or manually add to `Cargo.toml`:

```toml
[dependencies]
sigil-sdk = "0.1"
tokio = { version = "1.40", features = ["full"] }
```

---

## 📦 Basic Usage

### Connecting to the Daemon

```rust
use sigil_sdk::SigilClient;
use std::path::PathBuf;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Connect with default socket path
    let client = SigilClient::connect_default()?;
    client.connect().await?;
    println!("Connected to SIGIL daemon");

    Ok(())
}
```

### Getting a Secret

```rust
use sigil_sdk::SigilClient;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let client = SigilClient::connect_default()?;
    client.connect().await?;

    // Get a secret by path
    let api_key = client.get("aws/access_key_id").await?;

    // Expose the secret value (only use when necessary)
    api_key.expose(|bytes| {
        let key = String::from_utf8_lossy(bytes);
        println!("API Key: {}", key);
        Ok(())
    })?;

    Ok(())
}
```

### Checking if a Secret Exists

```rust
use sigil_sdk::SigilClient;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let client = SigilClient::connect_default()?;
    client.connect().await?;

    let path = "prod/database_url";
    match client.exists(path).await? {
        true => println!("Secret '{}' exists", path),
        false => println!("Secret '{}' does not exist", path),
    }

    Ok(())
}
```

### Listing Secrets

```rust
use sigil_sdk::SigilClient;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let client = SigilClient::connect_default()?;
    client.connect().await?;

    // List all secrets
    let all_secrets = client.list("").await?;
    println!("Total secrets: {}", all_secrets.len());

    // List secrets with prefix
    let aws_secrets = client.list("aws/").await?;
    for secret in aws_secrets {
        println!("  - {}: {}", secret.path, secret.secret_type);
    }

    Ok(())
}
```

### Resolving Placeholders

```rust
use sigil_sdk::SigilClient;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let client = SigilClient::connect_default()?;
    client.connect().await?;

    let command = "curl -H 'Authorization: Bearer {{secret:api/key}}' https://api.example.com";
    let resolved = client.resolve(command).await?;

    println!("Resolved command: {}", resolved);

    Ok(())
}
```

---

## 🔒 Web Service Integration

### Actix-Web Example

```rust
use actix_web::{get, web, App, HttpResponse, HttpServer};
use sigil_sdk::SigilClient;
use std::sync::Arc;

struct AppState {
    sigil: Arc<SigilClient>,
}

#[get("/api/data")]
async fn get_data(state: web::Data<AppState>) -> HttpResponse {
    // Get API key from SIGIL
    let api_key = match state.sigil.get("external/api_key").await {
        Ok(key) => key,
        Err(e) => {
            return HttpResponse::InternalServerError()
                .json(format!("Failed to get API key: {}", e));
        }
    };

    // Use the key for external API call
    api_key.expose(|bytes| {
        let key_str = String::from_utf8_lossy(bytes);
        // Make API call with key_str
        HttpResponse::Ok().json(r#"{"data": "response from external API"}"#)
    }).map_err(|e| HttpResponse::InternalServerError().json(e.to_string()))?
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let sigil = Arc::new(SigilClient::connect_default()?);
    sigil.connect().await?;

    HttpServer::new(move || {
        App::new()
            .app_data(web::Data::new(AppState { sigil: sigil.clone() }))
            .service(get_data)
    })
    .bind("127.0.0.1:8080")?
    .run()
    .await?;

    Ok(())
}
```

### Axum Example

```rust
use axum::{extract::State, Json, Router};
use serde_json::Value;
use sigil_sdk::SigilClient;
use std::sync::Arc;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let sigil = Arc::new(SigilClient::connect_default()?);
    sigil.connect().await?;

    let app = Router::new()
        .route("/api/data", axum::routing::get(get_data))
        .with_state(sigil);

    let listener = tokio::net::TcpListener::bind("127.0.0.1:8080").await?;
    axum::serve(listener, app).await?;

    Ok(())
}

async fn get_data(State(sigil): State<Arc<SigilClient>>) -> Result<Json<Value>, String> {
    let api_key = sigil.get("external/api_key").await
        .map_err(|e| e.to_string())?;

    api_key.expose(|bytes| {
        let key_str = String::from_utf8_lossy(bytes);
        // Make API call with key_str
        Ok(Json(serde_json::json!({
            "data": "response from external API"
        })))
    }).map_err(|e| e.to_string())?
}
```

---

## 🧪 Testing with SIGIL

### Unit Tests

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use sigil_sdk::SigilClient;

    #[tokio::test]
    async fn test_secret_retrieval() {
        let client = SigilClient::connect_default().unwrap();
        client.connect().await.expect("Failed to connect to daemon");

        let result = client.get("test/secret").await;
        assert!(result.is_ok() || matches!(result.unwrap_err(), sigil_core::SigilError::SecretNotFound(_)));
    }

    #[tokio::test]
    async fn test_placeholder_resolution() {
        let client = SigilClient::connect_default().unwrap();
        client.connect().await.expect("Failed to connect to daemon");

        let input = "DB_HOST={{secret:db/host}}";
        let resolved = client.resolve(input).await;

        // Resolution should succeed even if secret doesn't exist
        assert!(resolved.is_ok());
    }
}
```

### Integration Tests with Test Secrets

```rust
// Use test-specific secret paths
const TEST_SECRET_PREFIX: &str = "test/my_app/";

async fn setup_test_secrets(client: &SigilClient) -> Result<(), Box<dyn std::error::Error>> {
    // In tests, you might create test secrets via CLI:
    // sigil add test/my_app/api_key
    Ok(())
}

#[tokio::test]
async fn test_with_test_secrets() -> Result<(), Box<dyn std::error::Error>> {
    let client = SigilClient::connect_default()?;
    client.connect().await?;

    // Use test-specific secrets
    let test_key = client.get("test/my_app/api_key").await;

    match test_key {
        Ok(key) => {
            key.expose(|bytes| {
                println!("Test key: {}", String::from_utf8_lossy(bytes));
                Ok(())
            })?;
        }
        Err(sigil_core::SigilError::SecretNotFound(_)) => {
            println!("Test secret not found - set it up with: sigil add test/my_app/api_key");
        }
        Err(e) => return Err(e.into()),
    }

    Ok(())
}
```

---

## 🔧 Configuration

### Custom Socket Path

```rust
use sigil_sdk::SigilClient;
use std::path::PathBuf;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let socket_path = PathBuf::from("/custom/path/to/sigil.sock");
    let client = SigilClient::new(socket_path)?;
    client.connect().await?;

    Ok(())
}
```

### Custom Timeout

```rust
use sigil_sdk::SigilClient;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let client = SigilClient::connect_default()?
        .with_timeout(60); // 60 second timeout

    client.connect().await?;
    Ok(())
}
```

### With Session Token

```rust
use sigil_sdk::SigilClient;
use sigil_core::SessionToken;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let token = SessionToken::generate();
    let client = SigilClient::connect_default()?
        .with_session_token(token);

    client.connect().await?;
    Ok(())
}
```

---

## 🐳 Docker Integration

### Dockerfile

```dockerfile
FROM rust:1.75 as builder

WORKDIR /app
COPY . .

# Build the application
RUN cargo build --release

# Runtime image
FROM debian:bookworm-slim

# Install SIGIL (assumes binary is available)
COPY --from=builder /app/target/release/myapp /usr/local/bin/myapp

# SIGIL will connect to daemon from host or separate container
ENTRYPOINT ["/usr/local/bin/myapp"]
```

### docker-compose.yml

```yaml
services:
  myapp:
    build: .
    environment:
      - SIGIL_SOCKET=/host/sigil.sock
    volumes:
      # Mount SIGIL socket from host
      - /run/user/1000/sigil.sock:/host/sigil.sock:ro
```

---

## 🔒 Security Best Practices

### 1. Never Log Secret Values

```rust
// ❌ BAD - logs the secret value
let api_key = client.get("api/key").await?;
println!("API Key: {:?}", api_key); // DON'T DO THIS

// ✅ GOOD - use expose only when necessary
api_key.expose(|bytes| {
    let key = String::from_utf8_lossy(bytes);
    make_api_call(&key).await?;
    Ok(())
})?;
```

### 2. Use Sealed Operations for Sensitive Commands

```rust
// Instead of executing commands directly, use sealed operations
// Define operation in .sigil.toml or via CLI
// sigil operations add deploy --command "kubectl apply -f manifests/" --secrets prod/kubeconfig

// Then in code:
let client = SigilClient::connect_default()?;
client.connect().await?;

// Execute sealed operation (returns only filtered output)
// This is safer than command execution with full secrets
```

### 3. Minimize Secret Lifetime in Memory

```rust
// Process secrets immediately and drop
async fn fetch_external_data(client: &SigilClient) -> Result<String, Box<dyn std::error::Error>> {
    let api_key = client.get("external/api_key").await?;

    api_key.expose(|bytes| {
        let key = String::from_utf8_lossy(bytes);
        let result = make_api_call(&key).await?;
        Ok(result) // api_key is zeroized after this block
    })?
}
```

---

## 🚧 Known Limitations

1. **Tokio Required**: The SDK uses async/await and requires tokio runtime
2. **Unix Socket Only**: IPC uses Unix domain sockets (Linux/macOS only)
3. **Daemon Required**: The sigild daemon must be running

---

## 📚 Additional Resources

- [SIGIL SDK Documentation](../../crates/sigil-sdk/)
- [Sealed Operations Guide](sealed-operations.md)
- [Security Best Practices](security-best-practices.md)
- [Basic Workflow Example](basic-workflow.md)

---

## 👉 Next Steps

- [Quickstart Guide](../quickstart.md) — Get SIGIL running
- [Agent Setup Guides](../agents/) — Configure for your AI agent
- [Examples Index](README.md) — More integration examples
