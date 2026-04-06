# 📚 SIGIL Examples

> Practical examples and guides for using SIGIL in real-world scenarios.

---

## 🚀 Getting Started Examples

### [Basic Workflow](basic-workflow.md)

Step-by-step guide to your first SIGIL session:
- Initializing a vault
- Adding your first secret
- Using placeholders in commands
- Verifying scrubbing works

**Best for:** New users learning SIGIL fundamentals

---

## 🔒 Security Best Practices

### [Security Best Practices](security-best-practices.md)

Comprehensive security guide covering:
- Secret lifecycle management
- Audit log monitoring
- Canary deployment strategies
- Lockdown procedures
- Team access controls

**Best for:** Security-conscious users and production deployments

---

## 👥 Team Collaboration

### [Team Collaboration](team-collaboration.md)

Guide to using SIGIL in team environments:
- Team vault setup with Shamir's Secret Sharing
- Member onboarding and access management
- Audit log review practices
- Incident response procedures

**Best for:** Teams adopting SIGIL for shared secret management

---

## 🏗️ CI/CD Integration

### [CI/CD Integration](ci-cd-integration.md)

Integrating SIGIL into continuous integration pipelines:
- CI mode configuration
- Sealed vault for CI environments
- Argo Workflows integration
- GitHub Actions examples
- Pre-commit hooks for secret detection

**Best for:** DevOps engineers and CI/CD pipeline maintainers

---

## 🔄 Migration

### [Migration Guide](migration-guide.md)

Migrating to SIGIL from other secret management tools:
- From environment variables
- From `.env` files
- From other vaults (1Password, HashiCorp Vault)
- Automated migration workflows

**Best for:** Teams adopting SIGIL into existing infrastructure

---

## 📄 Configuration Examples

### [sigil.toml.example](sigil.toml.example)

Annotated project manifest example:
- Secret declarations
- Command signatures
- Operation templates
- Team vault settings

**Best for:** Reference when creating your own `.sigil.toml`

### [lockdown.toml.example](lockdown.toml.example)

Auto-lockdown configuration example:
- Canary trigger thresholds
- Unauthorized attempt limits
- Exfiltration detection rules

**Best for:** Production security hardening

---

## 🔐 Operational Security

### [Sealed Operations](sealed-operations.md)

Guide to using sealed operations for secure command execution:
- What sealed operations are and when to use them
- Operation configuration (TOML format)
- Output filter modes (exit_code, summary, full_scrubbed, none)
- Real-world examples (deployments, migrations, backups)
- Agent usage patterns (MCP, CLI, SDK)

**Best for:** Production deployments requiring human oversight

---

## 🐍 Language-Specific Guides

### [Python Integration](python-integration.md)

Using SIGIL with Python projects and frameworks:
- Basic Python scripts with SIGIL placeholders
- Django, Flask, and FastAPI integration patterns
- pytest configuration for SIGIL-aware testing
- Docker and docker-compose integration
- Security best practices for Python applications

**Best for:** Python developers using SIGIL with AI agents

### [Node.js Integration](nodejs-integration.md)

Using SIGIL with Node.js projects and frameworks:
- Basic Node.js scripts with SIGIL placeholders
- Express.js, NestJS, and Next.js integration patterns
- Jest and Vitest configuration for SIGIL-aware testing
- Docker and docker-compose integration
- SIGIL SDK for direct daemon access
- TypeScript and ts-node/tsx workflows

**Best for:** Node.js/TypeScript developers using SIGIL with AI agents

### [Go Integration](go-integration.md)

Using SIGIL with Go projects and services:
- Basic Go programs with SIGIL placeholders
- Standard library HTTP server integration
- Gin, Echo, and gRPC framework patterns
- Table-driven tests with SIGIL
- Docker and docker-compose integration
- Makefile and Air (live reload) workflows

**Best for:** Go backend developers using SIGIL with AI agents

### [Java Integration](java-integration.md)

Using SIGIL with Java projects and JVM applications:
- Basic Java applications with SIGIL placeholders
- Spring Boot, Micronaut, Quarkus, and Vert.x patterns
- JUnit 5 testing with SIGIL
- Docker and docker-compose integration
- Maven and Gradle build system integration

**Best for:** Java/JVM developers using SIGIL with AI agents

---

## 🎯 Usage by Scenario

| Scenario | Example |
|----------|---------|
| **First-time setup** | [Basic Workflow](basic-workflow.md) |
| **Local development** | [Basic Workflow](basic-workflow.md) |
| **Python development** | [Python Integration](python-integration.md) |
| **Node.js development** | [Node.js Integration](nodejs-integration.md) |
| **Go development** | [Go Integration](go-integration.md) |
| **Java development** | [Java Integration](java-integration.md) |
| **Team deployment** | [Team Collaboration](team-collaboration.md) |
| **Production security** | [Security Best Practices](security-best-practices.md) |
| **Secure operations** | [Sealed Operations](sealed-operations.md) |
| **CI/CD pipeline** | [CI/CD Integration](ci-cd-integration.md) |
| **Migration from other tools** | [Migration Guide](migration-guide.md) |
| **Project configuration** | [sigil.toml.example](sigil.toml.example) |
| **Lockdown hardening** | [lockdown.toml.example](lockdown.toml.example) |

---

## 🤝 Contributing Examples

Have a use case not covered here? Contributions are welcome!

1. Create a new example file in this directory
2. Follow the [documentation style guide](../STYLE.md)
3. Update this README with a link to your example
4. Submit a pull request

Example categories we'd love to see:
- **Language-specific guides** (Ruby, PHP, Rust, C#, etc.)
- **Framework integration** (Django, Rails, Laravel, Spring, etc.)
- **Cloud platform guides** (AWS, GCP, Azure specific patterns)
- **Kubernetes workflows** (secrets injection, sidecar patterns)
- **Development environment setup** (VS Code, IntelliJ, etc.)

---

## 👉 Next Steps

- Return to [Main Documentation](../)
- Read the [Quickstart Guide](../quickstart.md)
- Explore [Agent Setup Guides](../agents/)
