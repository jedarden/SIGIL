# 🐚 Kubernetes Workflows with SIGIL

> Using SIGIL secrets in Kubernetes deployments with injection patterns and sidecar configurations.

---

## 📋 Prerequisites

- **Kubernetes cluster** (v1.25+ recommended)
- **kubectl** configured and authenticated
- **SIGIL installed** on your local machine
- **Container runtime** that supports SIGIL (Docker, containerd, CRI-O)

---

## 🚀 Overview

SIGIL provides three patterns for Kubernetes secret injection:

| Pattern | Complexity | Security | Use Case |
|---------|------------|----------|----------|
| **Build-time** | Low | Medium | CI/CD pipelines, immutable configs |
| **Init Container** | Medium | High | Runtime secrets without code changes |
| **Sidecar Proxy** | High | Very High | Dynamic secret rotation, zero code changes |

---

## 📦 Pattern 1: Build-Time Injection

Inject secrets during container build for CI/CD workflows.

### Example: Dockerfile with SIGIL

```dockerfile
FROM rust:1.75 as builder

# Install SIGIL
RUN cargo install sigil-cli

# Copy application code
WORKDIR /app
COPY . .

# Inject secrets at build time
ARG SIGIL_VAULT
RUN echo "$SIGIL_VAULT" | base64 -d > /tmp/vault.sigil
RUN sigil import /tmp/vault.sigil

# Build application with injected secrets
RUN sigil exec 'cargo build --release'

# Runtime stage
FROM debian:bookworm-slim
COPY --from=builder /app/target/release/app /usr/local/bin/app
CMD ["app"]
```

### GitHub Actions Workflow

```yaml
name: Build and Deploy

on:
  push:
    branches: [main]

jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3

      - name: Install SIGIL
        run: cargo install sigil-cli

      - name: Export vault
        env:
          VAULT_PASSPHRASE: ${{ secrets.VAULT_PASSPHRASE }}
        run: |
          echo "$VAULT_PASSPHRASE" | sigil export ci-vault.sigil

      - name: Build and push image
        run: |
          docker build -t myapp:v0.4.0 \
            --build-arg SIGIL_VAULT=$(base64 -w 0 ci-vault.sigil) \
            .
          docker push myapp:v0.4.0

      - name: Deploy to Kubernetes
        run: |
          kubectl set image deployment/myapp \
            app=myapp:v0.4.0
```

### Limitations

⚠️ **Secrets are baked into the image** - if the image is compromised, secrets are exposed. Use this pattern only for:
- CI/CD environments with scoped credentials
- Short-lived tokens that rotate frequently
- Non-production deployments

---

## 🎯 Pattern 2: Init Container Injection

Use an init container to inject secrets into the application container at runtime.

### Deployment Manifest

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: myapp
spec:
  replicas: 3
  selector:
    matchLabels:
      app: myapp
  template:
    metadata:
      labels:
        app: myapp
    spec:
      # Init container with SIGIL
      initContainers:
        - name: sigil-init
          image: rust:1.75
          command: [sh, -c]
          args:
            - |
              # Install SIGIL
              cargo install sigil-cli

              # Import vault from Kubernetes Secret
              sigil import /vault/vault.sigil

              # Inject secrets as environment files
              sigil get api_key --raw > /secrets/api_key
              sigil get database_url --raw > /secrets/database_url
              sigil get jwt_secret --raw > /secrets/jwt_secret

              chmod 600 /secrets/*
          volumeMounts:
            - name: vault
              mountPath: /vault
              readOnly: true
            - name: secrets
              mountPath: /secrets
          env:
            - name: SIGIL_PASSPHRASE
              valueFrom:
                secretKeyRef:
                  name: sigil-vault-passphrase
                  key: passphrase

      # Application container
      containers:
        - name: app
          image: myapp:v0.4.0
          envFrom:
            - secretRef:
                name: app-secrets
          volumeMounts:
            - name: secrets
              mountPath: /etc/secrets
              readOnly: true
          env:
            - name: API_KEY_FILE
              value: /etc/secrets/api_key
            - name: DATABASE_URL_FILE
              value: /etc/secrets/database_url

      volumes:
        - name: vault
          secret:
            secretName: sigil-vault
        - name: secrets
          emptyDir:
            medium: Memory
```

### Vault Secret

```yaml
apiVersion: v1
kind: Secret
metadata:
  name: sigil-vault
type: Opaque
data:
  # Base64-encoded encrypted vault
  vault.sigil: <base64-content>
---
apiVersion: v1
kind: Secret
metadata:
  name: sigil-vault-passphrase
type: Opaque
stringData:
  passphrase: <vault-passphrase>
```

### Advantages

✅ **Secrets never stored in the image** - injected at runtime only
✅ **Automatic rotation** - restart pods to refresh secrets
✅ **No code changes** - works with any application

---

## 🔐 Pattern 3: Sidecar Proxy with SIGIL Proxy

Run the SIGIL HTTP proxy as a sidecar for transparent secret injection.

### Deployment with Sidecar

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: myapp
spec:
  replicas: 3
  selector:
    matchLabels:
      app: myapp
  template:
    metadata:
      labels:
        app: myapp
    spec:
      # SIGIL proxy sidecar
      containers:
        - name: sigil-proxy
          image: sigil:latest
          command: ["sigil-proxy"]
          args:
            - --listen
            - 0.0.0.0:8080
            - --vault
            - /vault/vault.sigil
          ports:
            - containerPort: 8080
              name: proxy
          env:
            - name: SIGIL_PASSPHRASE
              valueFrom:
                secretKeyRef:
                  name: sigil-vault-passphrase
                  key: passphrase
          volumeMounts:
            - name: vault
              mountPath: /vault
              readOnly: true
          livenessProbe:
            httpGet:
              path: /health
              port: 8080
            initialDelaySeconds: 5
          readinessProbe:
            httpGet:
              path: /health
              port: 8080
            initialDelaySeconds: 5

        # Application container
        - name: app
          image: myapp:v0.4.0
          env:
            - name: HTTP_PROXY
              value: http://localhost:8080
            - name: HTTPS_PROXY
              value: http://localhost:8080
            - name: NO_PROXY
              value: localhost,127.0.0.1
          ports:
            - containerPort: 8081
              name: app

      volumes:
        - name: vault
          secret:
            secretName: sigil-vault
```

### Proxy Rules (in Vault)

Store proxy rules as encrypted vault entry `_sigil/proxy_rules`:

```toml
[proxy]
listen = "0.0.0.0:8080"

[[rules]]
domain = "api.example.com"
header = "Authorization"
value = "Bearer {{secret:api/example_com_token}}"

[[rules]]
domain = "*.amazonaws.com"
type = "aws_sigv4"
access_key = "{{secret:aws/access_key_id}}"
secret_key = "{{secret:aws/secret_access_key}}"
region = "us-east-1"

[[rules]]
domain = "github.com"
header = "Authorization"
value = "token {{secret:github/token}}"
```

### Advantages

✅ **Zero code changes** - application makes normal HTTP requests
✅ **Automatic injection** - proxy adds auth headers transparently
✅ **Response scrubbing** - prevents secrets from leaking in responses
✅ **Dynamic rules** - update rules without restarting application

---

## 🔄 Secret Rotation

### Manual Rotation

```bash
# On local machine
sigil rotate api_key
sigil export ci-vault.sigil

# Update Kubernetes Secret
kubectl create secret generic sigil-vault \
  --from-file=vault.sigil=ci-vault.sigl \
  --dry-run=client -o yaml | kubectl apply -f -

# Restart pods
kubectl rollout restart deployment/myapp
```

### Automated Rotation with CronJob

```yaml
apiVersion: batch/v1
kind: CronJob
metadata:
  name: sigil-rotate
spec:
  schedule: "0 2 * * *"  # Daily at 2 AM
  jobTemplate:
    spec:
      template:
        spec:
          containers:
            - name: rotator
              image: sigil:latest
              command:
                - sigil
                - exec
                - |
                  sigil get api_key --rotate
                  sigil export /tmp/vault.sigil
                  kubectl create secret generic sigil-vault \
                    --from-file=vault.sigil=/tmp/vault/vault.sigil \
                    --dry-run=client -o yaml | kubectl apply -f -
                  kubectl rollout restart deployment/myapp
              env:
                - name: SIGIL_PASSPHRASE
                  valueFrom:
                    secretKeyRef:
                      name: sigil-vault-passphrase
                      key: passphrase
          restartPolicy: OnFailure
```

---

## 🏥 Health Checks

### Readiness Probe

```yaml
readinessProbe:
  exec:
    command:
      - sigil
      - doctor
      - --ci
      - --min-score
      - "90"
  initialDelaySeconds: 5
  periodSeconds: 30
```

### Liveness Probe

```yaml
livenessProbe:
  exec:
    command:
      - sigil
      - status
      - --format
      - json
  initialDelaySeconds: 10
  periodSeconds: 60
```

---

## 🚧 Best Practices

1. **Use encrypted vaults** - never store plaintext secrets in Kubernetes Secrets
2. **Rotate regularly** - use short-lived credentials and automated rotation
3. **Separate environments** - use different vaults for dev/staging/prod
4. **Audit access** - enable SIGIL audit logging and ship logs to SIEM
5. **Network policies** - restrict pod-to-pod communication with NetworkPolicies
6. **RBAC** - limit Kubernetes service account permissions
7. **Secret versioning** - use SIGIL's version history for rollback capability

### Security Checklist

- [ ] Vault passphrase stored in separate Secret
- [ ] Network policies restrict egress traffic
- [ ] Pod Security Policy or Pod Security Standard enabled
- [ ] RBAC limits service account permissions
- [ ] Audit logging enabled and shipped to external system
- [ ] Secrets rotated according to compliance requirements
- [ ] No plaintext secrets in ConfigMaps or environment variables

---

## 👉 Next Steps

- [Production Deployment Guide](production-deployment.md)
- [Security Best Practices](security-best-practices.md)
- [CI/CD Integration](ci-cd-integration.md)

---

## 🔗 Resources

- [Kubernetes Secret Concepts](https://kubernetes.io/docs/concepts/configuration/secret/)
- [Pod Security Standards](https://kubernetes.io/docs/concepts/security/pod-security-standards/)
- [Network Policies](https://kubernetes.io/docs/concepts/services-networking/network-policies/)
- [SIGIL Architecture](../concepts.md)
