## ☕ Java Integration Guide

> Using SIGIL with Java projects and JVM applications for secure secret management in AI-assisted development.

---

## 📋 Prerequisites

- SIGIL installed and initialized
- Java 17+ installed (or Java 11+ with appropriate adjustments)
- Maven or Gradle build system
- A Java project that uses API keys, database credentials, or other secrets

---

## 🚀 Quick Start

### Basic Java Application with SIGIL

Create a Java application that uses SIGIL placeholders for environment variables:

```java
// src/main/java/com/example/App.java
package com.example;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;

public class App {
    public static void main(String[] args) {
        // These will be resolved by SIGIL before the program runs
        String apiKey = System.getenv("MY_API_KEY");
        String dbUrl = System.getenv("DATABASE_URL");

        if (apiKey == null || apiKey.isEmpty()) {
            System.err.println("Error: MY_API_KEY not set");
            System.err.println("Run with: sigil exec -- java App.java");
            System.exit(1);
        }

        // Use the secret
        try {
            HttpClient client = HttpClient.newHttpClient();
            HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create("https://api.example.com/data?api_key=" + apiKey))
                .GET()
                .build();

            HttpResponse<String> response = client.send(request,
                HttpResponse.BodyHandlers.ofString());

            System.out.println("Request completed with status: " + response.statusCode());
            System.out.println("Database URL: " + maskSecret(dbUrl));
        } catch (Exception e) {
            System.err.println("Error: " + e.getMessage());
            System.exit(1);
        }
    }

    private static String maskSecret(String secret) {
        if (secret == null || secret.length() < 10) {
            return "***";
        }
        return secret.substring(0, 4) + "***" + secret.substring(secret.length() - 4);
    }
}
```

Run with SIGIL:

```bash
# Add secrets to your vault first
sigil add my/api_key
sigil add database/url

# Compile and execute with automatic secret injection
javac App.java
sigil exec -- java App
```

---

## 🎯 Common Patterns

### Pattern 1: Direct Placeholder in Commands

```bash
# Single command with inline secret
sigil exec -- sh -c 'MY_API_KEY="{{secret:my/api_key}}" java App'
```

### Pattern 2: Environment Variable Injection

```bash
# SIGIL automatically creates environment variables from secret paths
sigil exec -- MY_API_KEY={{secret:my/api_key}} java App
```

### Pattern 3: Configuration Class

Create a `Config` class that loads secrets:

```java
// src/main/java/com/example/config/Config.java
package com.example.config;

import java.util.Objects;

public class Config {
    private final String apiKey;
    private final String databaseUrl;
    private final int port;

    private Config(String apiKey, String databaseUrl, int port) {
        this.apiKey = apiKey;
        this.databaseUrl = databaseUrl;
        this.port = port;
    }

    public static Config load() {
        String apiKey = requireEnv("API_KEY");
        String databaseUrl = requireEnv("DATABASE_URL");
        int port = Integer.parseInt(getEnv("PORT", "8080"));

        return new Config(apiKey, databaseUrl, port);
    }

    private static String requireEnv(String key) {
        String value = System.getenv(key);
        if (value == null || value.isEmpty()) {
            throw new IllegalStateException(key + " not set - run with SIGIL");
        }
        if (value.startsWith("{{secret:")) {
            throw new IllegalStateException(key + " not resolved - run with: sigil exec -- java App");
        }
        return value;
    }

    private static String getEnv(String key, String defaultValue) {
        String value = System.getenv(key);
        return Objects.requireNonNullElse(value, defaultValue);
    }

    // Getters
    public String getApiKey() { return apiKey; }
    public String getDatabaseUrl() { return databaseUrl; }
    public int getPort() { return port; }
}
```

```java
// src/main/java/com/example/App.java
package com.example;

import com.example.config.Config;

public class App {
    public static void main(String[] args) {
        Config config = Config.load();

        System.out.println("Starting server on port " + config.getPort());
        // Start your application with the loaded config
    }
}
```

Run with SIGIL:

```bash
sigil exec -- java App
```

---

## 🔗 Framework Integration

### Spring Boot Application

```java
// src/main/java/com/example/Application.java
package com.example;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@SpringBootApplication
@RestController
public class Application {

    private final String apiKey;

    public Application() {
        // Load API key from environment (resolved by SIGIL)
        this.apiKey = requireEnv("API_KEY");
    }

    @GetMapping("/")
    public String home() {
        return String.format("Server running with SIGIL%nAPI Key (masked): %s",
            maskAPIKey(apiKey));
    }

    @GetMapping("/external-api")
    public String callExternalApi() {
        // Make request to external API with the secret
        return "Would call external API with key";
    }

    public static void main(String[] args) {
        SpringApplication.run(Application.class, args);
    }

    private static String requireEnv(String key) {
        String value = System.getenv(key);
        if (value == null || value.isEmpty() || value.startsWith("{{secret:")) {
            throw new IllegalStateException(key + " not set - run with SIGIL");
        }
        return value;
    }

    private static String maskAPIKey(String key) {
        if (key == null || key.length() < 10) return "***";
        return key.substring(0, 4) + "***" + key.substring(key.length() - 4);
    }
}
```

`application.properties` (optional, for defaults):

```properties
server.port=${PORT:8080}
logging.level.root=INFO
```

Run with SIGIL:

```bash
# Maven
sigil exec -- mvn spring-boot:run

# Gradle
sigil exec -- gradle bootRun

# Or run the JAR directly
sigil exec -- java -jar target/myapp.jar
```

### Micronaut Application

```java
// src/main/java/com/example/Application.java
package com.example;

import io.micronaut.runtime.Micronaut;

public class Application {
    public static void main(String[] args) {
        // Validate environment before starting
        validateEnv();

        Micronaut.run(Application.class, args);
    }

    private static void validateEnv() {
        String apiKey = System.getenv("API_KEY");
        if (apiKey == null || apiKey.isEmpty()) {
            throw new IllegalStateException("API_KEY not set - run with SIGIL");
        }
        if (apiKey.startsWith("{{secret:")) {
            throw new IllegalStateException("API_KEY not resolved - run with: sigil exec -- java -jar build/libs/myapp.jar");
        }
    }
}
```

```java
// src/main/java/com/example/controller/ApiController.java
package com.example.controller;

import io.micronaut.http.annotation.Controller;
import io.micronaut.http.annotation.Get;

@Controller("/")
public class ApiController {

    @Get
    public String home() {
        return "Server running with SIGIL";
    }
}
```

### Quarkus Application

```java
// src/main/java/com/example/GreetingResource.java
package com.example;

import javax.inject.Singleton;
import javax.ws.rs.GET;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.core.MediaType;

@Path("/hello")
@Singleton
public class GreetingResource {

    private final String apiKey;

    public GreetingResource() {
        // Load API key from environment
        this.apiKey = requireEnv("API_KEY");
    }

    @GET
    @Produces(MediaType.TEXT_PLAIN)
    public String hello() {
        return "Server running with SIGIL";
    }

    private String requireEnv(String key) {
        String value = System.getenv(key);
        if (value == null || value.isEmpty() || value.startsWith("{{secret:")) {
            throw new IllegalStateException(key + " not set - run with: sigil exec -- ./mvnw quarkus:dev");
        }
        return value;
    }
}
```

### Vert.x Application

```java
// src/main/java/com/example/Main.java
package com.example;

import io.vertx.core.Vertx;
import io.vertx.core.http.HttpServer;
import io.vertx.core.http.HttpServerResponse;
import io.vertx.ext.web.Router;

public class Main {
    public static void main(String[] args) {
        // Validate environment before starting
        String apiKey = requireEnv("API_KEY");

        Vertx vertx = Vertx.vertx();
        HttpServer server = vertx.createHttpServer();

        Router router = Router.router(vertx);

        router.route().handler(ctx -> {
            HttpServerResponse response = ctx.response();
            response.putHeader("content-type", "text/plain");
            response.end("Server running with SIGIL");
        });

        server.requestHandler(router).listen(8080);
    }

    private static String requireEnv(String key) {
        String value = System.getenv(key);
        if (value == null || value.isEmpty() || value.startsWith("{{secret:")) {
            throw new IllegalStateException(key + " not set - run with SIGIL");
        }
        return value;
    }
}
```

---

## 🧪 Testing with SIGIL

### JUnit 5 Tests

```java
// src/test/java/com/example/ConfigTest.java
package com.example;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.BeforeEach;
import static org.junit.jupiter.api.Assertions.*;

class ConfigTest {
    private static final String SIGIL_PLACEHOLDER = "{{secret:my/api_key}}";

    @BeforeEach
    void setUp() {
        // Check if SIGIL is active
        if (!isSIGILActive()) {
            // Skip tests if SIGIL is not active
            // Or use test values instead
            System.err.println("WARNING: SIGIL not active - using test values");
        }
    }

    @Test
    void testConfigLoad() {
        if (!isSIGILActive()) {
            // Skip or use test configuration
            return;
        }

        Config config = Config.load();

        assertNotNull(config.getApiKey());
        assertFalse(config.getApiKey().startsWith("{{secret:"));
    }

    @Test
    void testUnresolvedPlaceholderThrowsException() {
        // Set an unresolved placeholder
        String originalValue = System.getenv("API_KEY");
        try {
            System.setProperty("API_KEY", SIGIL_PLACEHOLDER);

            assertThrows(IllegalStateException.class, () -> Config.load());
        } finally {
            // Restore original value
            if (originalValue != null) {
                System.setProperty("API_KEY", originalValue);
            } else {
                System.clearProperty("API_KEY");
            }
        }
    }

    private boolean isSIGILActive() {
        // Check for common SIGIL indicators
        return System.getenv("SIGIL_SESSION_TOKEN") != null
            || !containsPlaceholder(System.getenv("API_KEY"))
            || !containsPlaceholder(System.getenv("DATABASE_URL"));
    }

    private boolean containsPlaceholder(String value) {
        return value != null && value.startsWith("{{secret:");
    }
}
```

Run tests with SIGIL:

```bash
# Maven
sigil exec -- mvn test

# Gradle
sigil exec -- gradle test

# Without SIGIL (mock mode)
API_KEY=test-key-123 DATABASE_URL=postgresql://localhost/test mvn test
```

### Test Utilities

```java
// src/test/java/com/example/util/TestUtil.java
package com.example.util;

public class TestUtil {
    /**
     * Checks if SIGIL is active by looking for the session token
     * or checking if any environment variable contains an unresolved placeholder.
     */
    public static boolean isSIGILActive() {
        if (System.getenv("SIGIL_SESSION_TOKEN") != null) {
            return true;
        }

        // Check common environment variables for unresolved placeholders
        String[] envKeys = {"API_KEY", "DATABASE_URL", "JWT_SECRET"};
        for (String key : envKeys) {
            String value = System.getenv(key);
            if (value != null && value.startsWith("{{secret:")) {
                return false;
            }
        }

        return true;
    }

    /**
     * Skips the test if SIGIL is not active.
     * Use this in @BeforeEach or at the start of tests.
     */
    public static void requireSIGIL() {
        if (!isSIGILActive()) {
            throw new IllegalStateException("SIGIL not active - run with: sigil exec -- mvn test");
        }
    }

    /**
     * Sets test environment variables for use when SIGIL is not available.
     */
    public static void setTestEnv() {
        System.setProperty("API_KEY", "test-key-123");
        System.setProperty("DATABASE_URL", "postgresql://test:test@localhost/test_db");
        System.setProperty("JWT_SECRET", "test-jwt-secret");
    }
}
```

---

## 🐳 Docker Integration

### Dockerfile

```dockerfile
# Build stage
FROM maven:3.9-eclipse-temurin-17 AS builder

WORKDIR /app

# Install SIGIL in the container
RUN apt-get update && apt-get install -y cargo && \
    cargo install sigil-cli && \
    apt-get clean && rm -rf /var/lib/apt/lists/*

# Copy pom.xml and download dependencies
COPY pom.xml .
RUN mvn dependency:go-offline

# Copy source and build
COPY src ./src
RUN mvn package -DskipTests

# Runtime stage
FROM eclipse-temurin:17-jre-alpine

WORKDIR /app

# Install SIGIL (or copy from builder)
RUN apk add --no-cache cargo && \
    cargo install sigil-cli

# Copy JAR from builder
COPY --from=builder /app/target/*.jar app.jar

# SIGIL vault will be mounted as a volume
VOLUME ["/root/.sigil"]

# Default command - assumes secrets are in vault
CMD ["sigil", "exec", "--", "java", "-jar", "app.jar"]
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
      - SPRING_PROFILES_ACTIVE=production
      - SIGIL_VAULT_PATH=/root/.sigil/vault
    # SIGIL resolves secrets before Java app starts
    command: ["sigil", "exec", "--", "java", "-jar", "app.jar"]
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

```java
// ❌ BAD - hardcoded in source
public class Secrets {
    public static final String API_KEY = "sk-live-abc123xyz789";
}

// ✅ GOOD - placeholder for SIGIL
public class Secrets {
    public static String apiKey() {
        String key = System.getenv("API_KEY");
        if (key == null || key.startsWith("{{secret:")) {
            throw new IllegalStateException("API_KEY not resolved - run with SIGIL");
        }
        return key;
    }
}
```

### 2. Validate Secrets at Startup

```java
public class Application {
    public static void main(String[] args) {
        // Validate all required secrets before starting
        validateRequiredSecrets();

        // Start application
        SpringApplication.run(Application.class, args);
    }

    private static void validateRequiredSecrets() {
        String[] required = {"API_KEY", "DATABASE_URL", "JWT_SECRET"};

        for (String key : required) {
            String value = System.getenv(key);
            if (value == null || value.isEmpty()) {
                throw new IllegalStateException(key + " not set");
            }
            if (value.startsWith("{{secret:")) {
                throw new IllegalStateException(
                    key + " not resolved - run with: sigil exec -- java -jar app.jar");
            }
        }
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
jwt/secret = "JWT signing secret"

[[operations]]
name = "test"
command = "mvn test"
secrets = ["my/api_key"]

[[operations]]
name = "package"
command = "mvn package"
secrets = []

[[operations]]
name = "run"
command = "java -jar target/myapp.jar"
secrets = ["my/api_key", "database/url", "jwt/secret"]
```

### 4. Use Properties/YAML with Defaults

`application.properties`:

```properties
# SIGIL resolves these environment variables
app.api-key=${API_KEY:{{secret:my/api_key}}}
app.database-url=${DATABASE_URL:{{secret:database/url}}}
app.jwt.secret=${JWT_SECRET:{{secret:jwt/secret}}}

# Server configuration
server.port=${PORT:8080}
```

```java
@Component
public class SecretValidator {
    @Value("${app.api-key}")
    private String apiKey;

    @PostConstruct
    public void validate() {
        if (apiKey.startsWith("{{secret:")) {
            throw new IllegalStateException("API_KEY not resolved - run with SIGIL");
        }
    }
}
```

---

## 🚧 Known Limitations

- **JNI libraries**: Some JNI libraries may have issues with SIGIL's memory protection. Test thoroughly with native libraries.
- **Agents (Java agents)**: Java agents loaded via `-javaagent` run before SIGIL and may bypass certain protections.
- **Classloader isolation**: Complex classloader setups (OSGi, modular apps) may need special handling.
- **Resource files**: Secrets in `application.properties` or `application.yml` files in the classpath are only resolved if the file processing happens after SIGIL resolves environment variables.

---

## 🛠️ Build System Integration

### Maven

`pom.xml` configuration for SIGIL-aware builds:

```xml
<project>
    <!-- ... -->

    <build>
        <plugins>
            <plugin>
                <groupId>org.apache.maven.plugins</groupId>
                <artifactId>maven-surefire-plugin</artifactId>
                <version>3.0.0</version>
                <configuration>
                    <!-- Environment variables for tests -->
                    <environmentVariables>
                        <SIGIL_ACTIVE>true</SIGIL_ACTIVE>
                    </environmentVariables>
                </configuration>
            </plugin>
        </plugins>
    </build>

    <profiles>
        <profile>
            <id>sigil</id>
            <build>
                <plugins>
                    <plugin>
                        <groupId>org.codehaus.mojo</groupId>
                        <artifactId>exec-maven-plugin</artifactId>
                        <version>3.1.0</version>
                        <executions>
                            <execution>
                                <id>run-with-sigil</id>
                                <phase>process-classes</phase>
                                <goals>
                                    <goal>exec</goal>
                                </goals>
                                <configuration>
                                    <executable>sigil</executable>
                                    <arguments>
                                        <argument>exec</argument>
                                        <argument>--</argument>
                                        <argument>java</argument>
                                        <argument>-cp</argument>
                                        <classpath />
                                        <argument>com.example.Main</argument>
                                    </arguments>
                                </configuration>
                            </execution>
                        </executions>
                    </plugin>
                </plugins>
            </build>
        </profile>
    </profiles>
</project>
```

Run with SIGIL:

```bash
sigil exec -- mvn clean install
```

### Gradle

`build.gradle` configuration:

```groovy
plugins {
    id 'application'
}

application {
    mainClass = 'com.example.Main'
}

// SIGIL-aware run task
task runWithSigil(type: Exec) {
    dependsOn 'build'
    commandLine 'sigil', 'exec', '--', 'java', '-jar', tasks.jar.archiveFile.get()
}

// SIGIL-aware test task
task testWithSigil(type: Exec) {
    dependsOn 'build'
    environment 'SIGIL_ACTIVE': 'true'
    commandLine 'sigil', 'exec', '--', 'gradle', 'test'
}
```

Run with SIGIL:

```bash
sigil exec -- gradle build
```

---

## 👉 Next Steps

- Return to [Examples Index](README.md)
- Read [Basic Workflow](basic-workflow.md) for SIGIL fundamentals
- Read [Security Best Practices](security-best-practices.md)
- Read [CI/CD Integration](ci-cd-integration.md) for pipeline setup
- Explore [Spring Boot documentation](https://spring.io/projects/spring-boot)
- Explore [Micronaut documentation](https://micronaut.io/)
