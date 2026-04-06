# 🔵 Go Integration Guide

> Using SIGIL with Go projects and services for secure secret management in AI-assisted development.

---

## 📋 Prerequisites

- SIGIL installed and initialized
- Go 1.18+ installed
- A Go project that uses API keys, database credentials, or other secrets

---

## 🚀 Quick Start

### Basic Go Program with SIGIL

Create a Go program that uses SIGIL placeholders for environment variables:

```go
// main.go
package main

import (
    "fmt"
    "net/http"
    "os"
)

func main() {
    // These will be resolved by SIGIL before the program runs
    apiKey := os.Getenv("MY_API_KEY")
    dbURL := os.Getenv("DATABASE_URL")

    if apiKey == "" || apiKey == "{{secret:my/api_key}}" {
        fmt.Println("Error: MY_API_KEY not set")
        fmt.Println("Run with: sigil exec -- go run main.go")
        os.Exit(1)
    }

    // Use the secret
    resp, err := http.Get("https://api.example.com/data?api_key=" + apiKey)
    if err != nil {
        fmt.Printf("Error: %v\n", err)
        os.Exit(1)
    }
    defer resp.Body.Close()

    fmt.Printf("Request completed with status: %d\n", resp.StatusCode)
    fmt.Printf("Database URL: %s\n", maskSecret(dbURL))
}

func maskSecret(s string) string {
    if len(s) < 10 {
        return "***"
    }
    return s[:4] + "***" + s[len(s)-4:]
}
```

Run with SIGIL:

```bash
# Add secrets to your vault first
sigil add my/api_key
sigil add database/url

# Execute with automatic secret injection
sigil exec -- go run main.go
```

---

## 🎯 Common Patterns

### Pattern 1: Direct Placeholder in Commands

```bash
# Single command with inline secret
sigil exec -- sh -c 'MY_API_KEY="{{secret:my/api_key}}" go run main.go'
```

### Pattern 2: Environment Variable Injection

```bash
# SIGIL automatically creates environment variables from secret paths
sigil exec -- MY_API_KEY={{secret:my/api_key}} go run main.go
```

### Pattern 3: Configuration File with Placeholders

Create a `config.go` that uses placeholders:

```go
// config/config.go
package config

import (
    "fmt"
    "os"
)

type Config struct {
    APIKey     string
    DatabaseURL string
    Port       string
}

func Load() (*Config, error) {
    cfg := &Config{
        APIKey:     os.Getenv("API_KEY"),
        DatabaseURL: os.Getenv("DATABASE_URL"),
        Port:       getEnv("PORT", "8080"),
    }

    // Validate that placeholders were resolved
    if err := cfg.validate(); err != nil {
        return nil, err
    }

    return cfg, nil
}

func (c *Config) validate() error {
    if c.APIKey == "" || c.APIKey == "{{secret:my/api_key}}" {
        return fmt.Errorf("API_KEY not resolved - run with SIGIL")
    }
    if c.DatabaseURL == "" || c.DatabaseURL == "{{secret:database/url}}" {
        return fmt.Errorf("DATABASE_URL not resolved - run with SIGIL")
    }
    return nil
}

func getEnv(key, defaultValue string) string {
    if value := os.Getenv(key); value != "" {
        return value
    }
    return defaultValue
}
```

```go
// main.go
package main

import (
    "fmt"
    "log"
    "myapp/config"
)

func main() {
    cfg, err := config.Load()
    if err != nil {
        log.Fatalf("Config error: %v", err)
    }

    fmt.Printf("Starting server on port %s\n", cfg.Port)
    // Start your service with the loaded config
}
```

Run with SIGIL:

```bash
sigil exec -- go run main.go
```

---

## 🔗 Framework Integration

### Standard Library HTTP Server

```go
// main.go
package main

import (
    "fmt"
    "log"
    "net/http"
    "os"
)

func handler(w http.ResponseWriter, r *http.Request) {
    apiKey := os.Getenv("API_KEY")
    if apiKey == "{{secret:my/api_key}}" {
        http.Error(w, "API_KEY not resolved", http.StatusInternalServerError)
        return
    }

    fmt.Fprintf(w, "Server running with SIGIL")
    fmt.Fprintf(w, "API Key (masked): %s", maskAPIKey(apiKey))
}

func main() {
    http.HandleFunc("/", handler)

    port := os.Getenv("PORT")
    if port == "" {
        port = "8080"
    }

    fmt.Printf("Server listening on :%s\n", port)
    log.Fatal(http.ListenAndServe(":"+port, nil))
}
```

### Gin Framework

```go
// main.go
package main

import (
    "net/http"

    "github.com/gin-gonic/gin"
)

func main() {
    r := gin.Default()

    r.GET("/", func(c *gin.Context) {
        apiKey := c.GetString("api_key")
        c.JSON(http.StatusOK, gin.H{
            "status":  "running",
            "sigil":   "active",
            "api_key": maskAPIKey(apiKey),
        })
    })

    r.GET("/external-api", func(c *gin.Context) {
        apiKey := c.GetString("api_key")
        // Make request to external API with the secret
        c.JSON(http.StatusOK, gin.H{
            "message": "Would call external API with key",
        })
    })

    r.Run(":8080")
}
```

```go
// middleware/middleware.go
package middleware

import (
    "github.com/gin-gonic/gin"
    "os"
)

func ConfigMiddleware() gin.HandlerFunc {
    return func(c *gin.Context) {
        apiKey := os.Getenv("API_KEY")
        if apiKey == "" || apiKey == "{{secret:my/api_key}}" {
            c.JSON(500, gin.H{"error": "API_KEY not resolved"})
            c.Abort()
            return
        }

        c.Set("api_key", apiKey)
        c.Next()
    }
}
```

### Echo Framework

```go
// main.go
package main

import (
    "net/http"

    "github.com/labstack/echo/v4"
    "github.com/labstack/echo/v4/middleware"
)

func main() {
    e := echo.New()

    // Use SIGIL-resolved environment variable
    apiKey := os.Getenv("API_KEY")
    if apiKey == "" || apiKey == "{{secret:my/api_key}}" {
        e.Logger.Fatal("API_KEY not resolved - run with SIGIL")
    }

    // Custom middleware to inject config
    e.Use(func(next echo.HandlerFunc) echo.HandlerFunc {
        return func(c echo.Context) error {
            c.Set("api_key", apiKey)
            return next(c)
        }
    })

    e.GET("/", func(c echo.Context) error {
        return c.JSON(http.StatusOK, map[string]string{
            "status": "running",
            "sigil":  "active",
        })
    })

    e.Logger.Fatal(e.Start(":8080"))
}
```

### gRPC Service

```go
// main.go
package main

import (
    "log"
    "net"
    "os"

    "google.golang.org/grpc"
)

type server struct {
    apiKey string
}

func (s *server) mustEmbedUnimplementedMyServiceServer() {}

func main() {
    apiKey := os.Getenv("API_KEY")
    if apiKey == "" || apiKey == "{{secret:my/api_key}}" {
        log.Fatal("API_KEY not resolved - run with SIGIL")
    }

    lis, err := net.Listen("tcp", ":50051")
    if err != nil {
        log.Fatalf("Failed to listen: %v", err)
    }

    s := grpc.NewServer()
    // Register your gRPC service here
    // pb.RegisterMyServiceServer(s, &server{apiKey: apiKey})

    log.Printf("Server listening on :50051")
    if err := s.Serve(lis); err != nil {
        log.Fatalf("Failed to serve: %v", err)
    }
}
```

---

## 🧪 Testing with SIGIL

### Table-Driven Tests

```go
// config_test.go
package config

import (
    "os"
    "testing"
)

func TestConfigLoad(t *testing.T) {
    tests := []struct {
        name    string
        setup   func()
        wantErr bool
    }{
        {
            name: "valid config",
            setup: func() {
                os.Setenv("API_KEY", "test-key-123")
                os.Setenv("DATABASE_URL", "postgresql://localhost/test")
            },
            wantErr: false,
        },
        {
            name: "missing API key",
            setup: func() {
                os.Unsetenv("API_KEY")
                os.Unsetenv("DATABASE_URL")
            },
            wantErr: true,
        },
        {
            name: "unresolved SIGIL placeholder",
            setup: func() {
                os.Setenv("API_KEY", "{{secret:my/api_key}}")
            },
            wantErr: true,
        },
    }

    for _, tt := range tests {
        t.Run(tt.name, func(t *testing.T) {
            // Setup
            tt.setup()

            // Test
            cfg, err := Load()
            if (err != nil) != tt.wantErr {
                t.Errorf("Load() error = %v, wantErr %v", err, tt.wantErr)
                return
            }

            if !tt.wantErr && cfg.APIKey == "" {
                t.Error("API_KEY should not be empty")
            }
        })
    }
}
```

Run tests with SIGIL:

```bash
# With SIGIL (resolves placeholders)
sigil exec -- go test ./...

# Without SIGIL (mock mode)
API_KEY=test-key DATABASE_URL=postgresql://localhost/test go test ./...
```

### Test Setup Function

```go
// testutil/testutil.go
package testutil

import (
    "fmt"
    "os"
)

// CheckSIGIL verifies that SIGIL is active
// Returns true if running under SIGIL, false otherwise
func CheckSIGIL() bool {
    // Check for common SIGIL indicators
    if os.Getenv("SIGIL_SESSION_TOKEN") != "" {
        return true
    }

    // Check if any env var contains unresolved placeholder
    for _, env := range os.Environ() {
        if containsPlaceholder(env) {
            return false
        }
    }

    return true
}

func containsPlaceholder(s string) bool {
    return len(s) > 10 && s[0:10] == "{{secret:"
}

// RequireSIGIL skips the test if SIGIL is not active
func RequireSIGIL(t *testing.T) {
    if !CheckSIGIL() {
        t.Skip("SIGIL not active - run with: sigil exec -- go test ./...")
    }
}

// SetTestEnv sets test environment variables
// Use this when not running under SIGIL
func SetTestEnv() {
    os.Setenv("API_KEY", "test-key-123")
    os.Setenv("DATABASE_URL", "postgresql://test:test@localhost/test_db")
}
```

Usage in tests:

```go
func TestWithSIGIL(t *testing.T) {
    testutil.RequireSIGIL(t)

    // Test code that requires SIGIL
    cfg, err := config.Load()
    if err != nil {
        t.Fatal(err)
    }

    // Assert on the loaded config
}
```

---

## 🐳 Docker Integration

### Dockerfile

```dockerfile
# Build stage
FROM golang:1.21-alpine AS builder

WORKDIR /app

# Install SIGIL in the container
RUN apk add --no-cache cargo
RUN cargo install sigil-cli

# Copy go mod files
COPY go.mod go.sum ./
RUN go mod download

# Copy source and build
COPY . .
RUN CGO_ENABLED=0 go build -o myapp .

# Runtime stage
FROM alpine:latest

WORKDIR /app

# Install SIGIL (or copy from builder)
RUN apk add --no-cache cargo
RUN cargo install sigil-cli

# Copy binary from builder
COPY --from=builder /app/myapp .

# SIGIL vault will be mounted as a volume
VOLUME ["/root/.sigil"]

# Default command - assumes secrets are in vault
CMD ["sigil", "exec", "--", "./myapp"]
```

### docker-compose.yml

```yaml
version: '3.8'

services:
  app:
    build: .
    volumes:
      # Mount SIGIL vault from host
      - ~/.sigil:/root/.sigil:ro
      # Mount application code (for development)
      - .:/app
    environment:
      - GO_ENV=production
      - SIGIL_VAULT_PATH=/root/.sigil/vault
    # SIGIL resolves secrets before Go app starts
    command: ["sigil", "exec", "--", "./myapp"]
    ports:
      - "8080:8080"
    depends_on:
      - db

  db:
    image: postgres:16
    environment:
      POSTGRES_DB: myapp
      POSTGRES_USER: test
      POSTGRES_PASSWORD: test
```

---

## 🔒 Security Best Practices

### 1. Never Hardcode Secrets

```go
// ❌ BAD - hardcoded in source
const APIKey = "sk-live-abc123xyz789"

// ✅ GOOD - placeholder for SIGIL
apiKey := os.Getenv("API_KEY")
if apiKey == "{{secret:my/api_key}}" {
    log.Fatal("API_KEY not resolved - run with SIGIL")
}
```

### 2. Validate Secrets at Startup

```go
// config/config.go
func requireEnv(key string) string {
    value := os.Getenv(key)
    if value == "" {
        log.Fatalf("%s not set", key)
    }
    if value[:10] == "{{secret:" {
        log.Fatalf("%s not resolved - run with: sigil exec -- go run main.go", key)
    }
    return value
}

type Config struct {
    APIKey     string
    DatabaseURL string
}

func Load() *Config {
    return &Config{
        APIKey:     requireEnv("API_KEY"),
        DatabaseURL: requireEnv("DATABASE_URL"),
    }
}
```

### 3. Use .sigil.toml for Project Secrets

Create `.sigil.toml` in your project root:

```toml
# .sigil.toml - SIGIL project manifest

[secrets]
# Required secrets for this project
my/api_key = "API key for external service"
database/url = "PostgreSQL connection string"
stripe/webhook_secret = "Stripe webhook verification secret"

[[operations]]
name = "test"
command = "go test ./..."
secrets = ["my/api_key"]

[[operations]]
name = "build"
command = "go build -o bin/myapp"
secrets = []

[[operations]]
name = "run"
command = "go run main.go"
secrets = ["my/api_key", "database/url"]
```

### 4. Structured Configuration

```go
// config/config.go
package config

import (
    "fmt"
    "os"
    "time"
)

type Config struct {
    // Server
    Host         string
    Port         string
    ReadTimeout  time.Duration
    WriteTimeout time.Duration

    // Secrets (loaded from environment via SIGIL)
    APIKey       string
    DatabaseURL  string
    JWTSecret    string

    // Feature flags
    Debug        bool
}

func Load() (*Config, error) {
    cfg := &Config{
        Host:         getEnv("HOST", "0.0.0.0"),
        Port:         getEnv("PORT", "8080"),
        ReadTimeout:  10 * time.Second,
        WriteTimeout: 10 * time.Second,
        APIKey:       requireEnv("API_KEY"),
        DatabaseURL:  requireEnv("DATABASE_URL"),
        JWTSecret:    requireEnv("JWT_SECRET"),
        Debug:        getEnvBool("DEBUG", false),
    }

    return cfg, nil
}

func (c *Config) Address() string {
    return fmt.Sprintf("%s:%s", c.Host, c.Port)
}
```

---

## 🚧 Known Limitations

- **Build tags**: Go build tags (like `//go:build`) don't interact with SIGIL. SIGIL operates at runtime, not compile time.
- **Generate commands**: Code generation tools like `go generate` run outside SIGIL unless wrapped: `sigil exec -- go generate ./...`
- **Race detector**: When using the race detector, SIGIL's interposition may have false positives. Run with `sigil exec -- go run -race main.go` if issues occur.
- **IDE debuggers**: IDE debuggers (Delve, VS Code) may bypass SIGIL if started directly. Use `sigil exec -- dlv debug main.go` instead.

---

## 🛠️ Development Workflow

### Makefile Integration

```makefile
# Makefile
.PHONY: run test build docker

run:
	sigil exec -- go run main.go

test:
	sigil exec -- go test -v ./...

test-coverage:
	sigil exec -- go test -cover -coverprofile=coverage.out ./...
	go tool cover -html=coverage.out -o coverage.html

build:
	CGO_ENABLED=0 go build -o bin/myapp .

docker-build:
	docker build -t myapp .

docker-run:
	docker run --rm -v ~/.sigil:/root/.sigil:ro myapp

deps:
	go mod download
	go mod tidy
```

### Air (Live Reload)

```bash
# Install Air
go install github.com/air-verse/air@latest

# Run with Air and SIGIL
sigil exec -- air
```

`.air.toml` configuration:

```toml
root = "."
tmp_dir = "tmp"

[build]
cmd = "go build -o ./tmp/main ."
bin = "sigil exec -- ./tmp/main"
include_ext = ["go"]
exclude_dir = ["tmp", "vendor"]
delay = 1000
```

---

## 📦 Module Integration

### Loading Secrets in `init()`

```go
package main

import (
    "log"
    "os"
)

var (
    apiKey     string
    databaseURL string
)

func init() {
    // Load secrets at package initialization
    apiKey = os.Getenv("API_KEY")
    if apiKey == "" || apiKey == "{{secret:my/api_key}}" {
        log.Fatal("API_KEY not resolved - run with: sigil exec -- go run main.go")
    }

    databaseURL = os.Getenv("DATABASE_URL")
    if databaseURL == "" || databaseURL == "{{secret:database/url}}" {
        log.Fatal("DATABASE_URL not resolved")
    }
}

func main() {
    // Use the loaded secrets
    log.Printf("Starting with API key: %s", maskAPIKey(apiKey))
}
```

### Custom `main` with Pre-flight Checks

```go
func main() {
    // Pre-flight checks
    if err := checkEnvironment(); err != nil {
        log.Fatalf("Environment check failed: %v", err)
    }

    // Load configuration
    cfg, err := config.Load()
    if err != nil {
        log.Fatalf("Config load failed: %v", err)
    }

    // Start application
    if err := run(cfg); err != nil {
        log.Fatalf("Application error: %v", err)
    }
}

func checkEnvironment() error {
    requiredEnvs := []string{"API_KEY", "DATABASE_URL"}
    for _, env := range requiredEnvs {
        if val := os.Getenv(env); val == "" || val[:10] == "{{secret:" {
            return fmt.Errorf("%s not set or not resolved", env)
        }
    }
    return nil
}
```

---

## 👉 Next Steps

- Return to [Examples Index](README.md)
- Read [Basic Workflow](basic-workflow.md) for SIGIL fundamentals
- Read [Security Best Practices](security-best-practices.md)
- Read [CI/CD Integration](ci-cd-integration.md) for pipeline setup
- Explore [Go Modules](https://golang.org/doc/modules/greating_module.html) for dependency management
