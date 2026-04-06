# 🏗️ Terraform Integration Guide

> Using SIGIL with Terraform for secure infrastructure provisioning and secret management.

**Best for:** DevOps engineers and infrastructure teams using Terraform with AI agents.

---

## 📋 Prerequisites

- Terraform 1.0+ installed
- SIGIL installed and initialized
- Basic understanding of Terraform variables and providers

---

## 🚀 Quickstart

### Step 1: Add Your Cloud Credentials

Store your Terraform provider credentials securely in SIGIL:

```bash
# AWS
sigil add aws/access_key_id
sigil add aws/secret_access_key

# Google Cloud
sigil add gcp/credentials.json --from-file path/to/service-account.json

# Azure
sigil add azure/client_id
sigil add azure/client_secret
sigil add azure/tenant_id
sigil add azure/subscription_id
```

### Step 2: Create a SIGIL-Aware Terraform Wrapper

Create `terraform-sigil.sh`:

```bash
#!/bin/bash
# SIGIL-aware Terraform wrapper

set -euo pipefail

# Export secrets as environment variables
export AWS_ACCESS_KEY_ID="$(sigil get aws/access_key_id)"
export AWS_SECRET_ACCESS_KEY="$(sigil get aws/secret_access_key)"

# Run terraform with all arguments
exec terraform "$@"
```

Make it executable:

```bash
chmod +x terraform-sigil.sh
```

### Step 3: Use with Your Agent

Your AI agent can now use `terraform-sigil.sh` instead of `terraform`:

```bash
# Instead of: terraform apply
./terraform-sigil.sh apply
```

---

## 🔧 Provider Configuration

### AWS Provider

```hcl
# providers.tf
provider "aws" {
  region = "us-east-1"

  # SIGIL sets these via terraform-sigil.sh
  access_key = var.aws_access_key_id
  secret_key = var.aws_secret_access_key
}

variable "aws_access_key_id" {
  type      = string
  sensitive = true
  default   = env("AWS_ACCESS_KEY_ID")
}

variable "aws_secret_access_key" {
  type      = string
  sensitive = true
  default   = env("AWS_SECRET_ACCESS_KEY")
}
```

### Google Cloud Provider

```hcl
provider "google" {
  project = "my-project-id"
  region  = "us-central1"

  # SIGIL sets GOOGLE_CREDENTIALS via terraform-sigil.sh
  credentials = var.google_credentials
}

variable "google_credentials" {
  type      = string
  sensitive = true
  default   = env("GOOGLE_CREDENTIALS")

  validation {
    condition     = can(jsondecode(var.google_credentials))
    error_message = "GOOGLE_CREDENTIALS must be valid JSON."
  }
}
```

### Azure Provider

```hcl
provider "azurerm" {
  features {}

  # SIGIL sets these via terraform-sigil.sh
  client_id       = var.azure_client_id
  client_secret   = var.azure_client_secret
  tenant_id       = var.azure_tenant_id
  subscription_id = var.azure_subscription_id
}

variable "azure_client_id" {
  type      = string
  sensitive = true
  default   = env("ARM_CLIENT_ID")
}

variable "azure_client_secret" {
  type      = string
  sensitive = true
  default   = env("ARM_CLIENT_SECRET")
}

variable "azure_tenant_id" {
  type      = string
  sensitive = true
  default   = env("ARM_TENANT_ID")
}

variable "azure_subscription_id" {
  type      = string
  sensitive = true
  default   = env("ARM_SUBSCRIPTION_ID")
}
```

---

## 🧪 Testing with SIGIL

### Unit Tests with Mock Secrets

```hcl
# test/mock_secrets.tf
variable "mock_aws_key" {
  type      = string
  sensitive = true
  default   = "AKIAIOSFODNN7EXAMPLE"
}

variable "mock_aws_secret" {
  type      = string
  sensitive = true
  default   = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
}

module "test_infrastructure" {
  source = "../modules/infrastructure"

  aws_access_key_id     = var.mock_aws_key
  aws_secret_access_key = var.mock_aws_secret

  # Use mock backend for tests
  backend_type = "local"
}
```

Run tests:

```bash
# SIGIL isn't needed for mock tests
terraform test -refresh=false
```

---

## 🔄 CI/CD Integration

### GitHub Actions

```yaml
# .github/workflows/terraform.yml
name: Terraform

on:
  push:
    paths: ['terraform/**']

permissions:
  contents: read

jobs:
  terraform:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Install SIGIL
        run: |
          curl -sSL https://github.com/sigil-rs/sigil/releases/latest/download/sigil-linux-amd64 -o sigil
          chmod +x sigil
          sudo mv sigil /usr/local/bin/

      - name: Import sealed vault
        run: |
          echo "${{ secrets.SIGIL_VAULT }}" | base64 -d | sigil import --merge
          sigil unseal <<< "${{ secrets.SIGIL_PASSPHRASE }}"

      - name: Apply Terraform
        run: |
          export AWS_ACCESS_KEY_ID="$(sigil get aws/access_key_id)"
          export AWS_SECRET_ACCESS_KEY="$(sigil get aws/secret_access_key)"
          terraform apply -auto-approve
        working-directory: ./terraform
```

### Argo Workflows

```yaml
# terraform-workflow.yaml
apiVersion: argoproj.io/v1alpha1
kind: Workflow
metadata:
  name: terraform-apply
spec:
  entrypoint: terraform-apply
  templates:
    - name: terraform-apply
      inputs:
        artifacts:
          - name: sigil-vault
            path: /tmp/vault.sigil
            s3:
              key: vault.sigil
      container:
        image: hashicorp/terraform:latest
        command: [sh, -c]
        args:
          - |
            apk add --no-cache curl
            curl -sSL https://github.com/sigil-rs/sigil/releases/latest/download/sigil-linux-amd64 -o /usr/local/bin/sigil
            chmod +x /usr/local/bin/sigil

            sigil import /tmp/vault.sigil --merge
            sigil unseal <<< "{{workflow.parameters.sigil_passphrase}}"

            export AWS_ACCESS_KEY_ID="$(sigil get aws/access_key_id)"
            export AWS_SECRET_ACCESS_KEY="$(sigil get aws/secret_access_key)"

            terraform init
            terraform apply -auto-approve
      env:
        - name: SIGIL_PASSPHRASE
          value: "{{workflow.parameters.sigil_passphrase}}"
```

---

## 📊 Secrets in Terraform State

> ⚠️ **Warning**: Terraform state files contain sensitive data by default. SIGIL protects credentials during runtime but does NOT encrypt Terraform state.

### Recommended: Remote State with Encryption

```hcl
# backend.tf
terraform {
  backend "s3" {
    bucket         = "my-terraform-state"
    key            = "prod/terraform.tfstate"
    region         = "us-east-1"
    encrypt        = true
    kms_key_id     = "alias/terraform-state-key"
    dynamodb_table = "terraform-state-lock"
  }
}
```

### Alternative: State Filtering

Use `terraform output -raw` with SIGIL for post-provisioning secrets:

```bash
# After terraform apply, capture generated secrets
terraform output -raw db_password | sigil add production/db_password
terraform output -raw api_key | sigil add production/api_key
```

---

## 🏭 Production Patterns

### Pattern 1: Environment-Specific Workspaces

```bash
# terraform-sigil.sh with workspace support
#!/bin/bash
set -euo pipefail

WORKSPACE=${1:-dev}

terraform workspace new "$WORKSPACE" 2>/dev/null || true
terraform workspace select "$WORKSPACE"

# Load workspace-specific secrets
case "$WORKSPACE" in
  prod)
    export AWS_ACCESS_KEY_ID="$(sigil get aws/prod_access_key)"
    export AWS_SECRET_ACCESS_KEY="$(sigil get aws/prod_secret_key)"
    ;;
  staging)
    export AWS_ACCESS_KEY_ID="$(sigil get aws/staging_access_key)"
    export AWS_SECRET_ACCESS_KEY="$(sigil get aws/staging_secret_key)"
    ;;
  *)
    export AWS_ACCESS_KEY_ID="$(sigil get aws/dev_access_key)"
    export AWS_SECRET_ACCESS_KEY="$(sigil get aws/dev_secret_key)"
    ;;
esac

shift
exec terraform "$@"
```

Usage:

```bash
./terraform-sigil.sh prod apply
./terraform-sigil.sh staging apply
./terraform-sigil.sh dev apply
```

### Pattern 2: Secret Rotation

```hcl
# locals.tf for derived secrets
locals {
  # Derive timestamps for secrets that need rotation
  rotation_date = formatdate("YYYY-MM-DD", timestamp())
}

# Resource tags for tracking
resource "aws_db_instance" "main" {
  # ... other config ...

  tags = {
    Name = "main-db"
    SecretsRotatedAt = local.rotation_date
  }
}
```

Rotation workflow:

```bash
# 1. Rotate credential in provider console
# 2. Update SIGIL vault
sigil add aws/prod_secret_key <<< "new-secret-key"

# 3. Re-run terraform (will use new credentials)
./terraform-sigil.sh prod apply
```

---

## 🔍 Troubleshooting

### ❌ "Error: error configuring Terraform AWS Backend"

**Problem**: SIGIL daemon isn't running or credentials aren't available.

**Fix**:

```bash
# Start daemon
sigild

# Verify credentials are accessible
sigil get aws/access_key_id
sigil get aws/secret_access_key

# Try again
./terraform-sigil.sh init
```

### ❌ "Invalid credentials"

**Problem**: Credential format is incorrect (newlines, encoding issues).

**Fix**:

```bash
# Re-add secret with proper formatting
echo -n "AKIAIOSFODNN7EXAMPLE" | sigil add aws/access_key_id
echo -n "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY" | sigil add aws/secret_access_key

# Verify no extra whitespace
sigil get aws/access_key_id | od -c
```

### ❌ "Terraform can't find environment variable"

**Problem**: Wrapper script doesn't export variables correctly.

**Fix**: Ensure your wrapper uses `export`:

```bash
# Correct
export AWS_ACCESS_KEY_ID="$(sigil get aws/access_key_id)"

# Wrong (won't be visible to terraform subprocess)
AWS_ACCESS_KEY_ID="$(sigil get aws/access_key_id)"
```

---

## 🚧 Known Limitations

1. **Terraform state is not encrypted** by SIGIL. Use remote state with encryption (S3 KMS, GCS encryption, Azure encryption).
2. **Terraform outputs containing secrets** will be logged. Use sensitive outputs or pipe to SIGIL immediately.
3. **Cross-platform providers** may have different credential mechanisms. Verify each provider's environment variable requirements.
4. **Terraform Cloud/Enterprise** integration requires different approach (use Terraform Cloud secret store with SIGIL for local development).

---

## 👉 Next Steps

- [Production Deployment Guide](production-deployment.md)
- [CI/CD Integration](ci-cd-integration.md)
- [Security Best Practices](security-best-practices.md)
- [Terraform Documentation](https://www.terraform.io/docs)
