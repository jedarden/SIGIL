## Part 1: Offline Secret Managers and Vaults

This section evaluates tools that can manage secrets locally without cloud dependencies, assessing each on five criteria: offline capability, multi-line/certificate support, API/CLI interface, secret rotation, and encryption at rest.

---

### 1.1 age (filippo.io/age)

**Summary**: A simple, modern file encryption tool with small explicit keys, no config options, and Unix-style composability. Written in Go with a reference specification at C2SP/age.md.

**Offline capability**: Fully offline. age is a pure encryption tool with zero network dependencies. Key generation (`age-keygen`), encryption, and decryption all happen locally. No key servers, no config files, no accounts.

**Multi-line secrets and certificates**: Yes. age encrypts arbitrary byte streams -- it operates on files/stdin, not structured data. A PEM certificate, SSH private key, or multi-megabyte JSON credential file is encrypted identically to a one-line password. The `--armor` (`-a`) flag produces PEM-encoded ASCII output suitable for embedding in text files or pasting into terminals.

**CLI/API interface**:
- CLI: `age --encrypt -r <recipient> -o secret.age plaintext.txt` / `age --decrypt -i key.txt secret.age`
- Flags: `-r RECIPIENT` (repeatable), `-R FILE` (recipients file), `-i IDENTITY` (identity/key file), `-p` (passphrase mode), `-a` (armor/PEM output), `-o OUTPUT`
- Key generation: `age-keygen [-o FILE]`, with `-pq` flag for post-quantum hybrid keys (ML-KEM-768 + X25519)
- Inspection: `age-inspect` displays recipient types, PQ status, payload size without decrypting
- Go library: `filippo.io/age` provides `Encrypt()`, `Decrypt()`, `ParseIdentities()`, `ParseRecipients()` for programmatic use
- Plugin system: any binary named `age-plugin-*` in `$PATH` extends functionality (e.g., `age-plugin-yubikey`, `age-plugin-tpm`, `age-plugin-se`, `age-plugin-pq`)

**Secret rotation**: No built-in rotation concept. age is a stateless encryption primitive -- it encrypts and decrypts files. Rotation is a higher-level concern that must be implemented by the calling tool (re-encrypt with new keys, distribute new keys).

**Encryption at rest**: X25519 Diffie-Hellman key agreement (or scrypt key derivation for passphrase mode) to derive a per-file 128-bit symmetric file key. Payload encrypted with ChaCha20-Poly1305 in 64 KiB chunks, each with a 12-byte nonce (11-byte big-endian counter + 1-byte final flag). Post-quantum mode uses ML-KEM-768 + X25519 hybrid. HKDF-SHA-256 for key derivation. No config, no algorithm negotiation -- single cipher suite by design.

**SIGIL relevance**: age is the strongest candidate for SIGIL's local vault encryption layer. Its stateless, composable design maps perfectly to encrypting individual secret files in a local store. The Go library (or Rust port `rage`) can be embedded directly. The plugin system allows future YubiKey or TPM integration without changing the core.

---

### 1.2 SOPS (getsops/sops, originally Mozilla)

**Summary**: A file encryption tool that encrypts values within structured files (YAML, JSON, ENV, INI) while leaving keys in cleartext, enabling meaningful diffs and version control of encrypted secrets. Now a CNCF project.

**Offline capability**: Partially offline. When using age or PGP as the encryption backend, SOPS operates fully offline -- all crypto is local. When using AWS KMS, GCP KMS, Azure Key Vault, or HashiCorp Cloud KMS, SOPS requires network access to those services for key wrapping/unwrapping. The recommended offline pattern is age + SOPS.

**Multi-line secrets and certificates**: Yes. SOPS encrypts each value independently within structured files. A multi-line PEM certificate stored as a YAML value is encrypted as a single opaque blob. In BINARY mode, the entire file is treated as a single blob (base64-encoded and stored under `tree['data']` in JSON output), suitable for encrypting arbitrary binary content.

**CLI/API interface**:
- Supported formats: YAML, JSON, ENV, INI, BINARY (auto-detected from extension, overridable with `--input-type` / `--output-type`)
- Edit workflow: `sops edit myfile.yaml` -- decrypts, opens in `$EDITOR`, re-encrypts on save
- Encrypt: `sops encrypt --age <recipient> plaintext.yaml > encrypted.yaml`
- Decrypt: `sops decrypt encrypted.yaml > plaintext.yaml`
- Inline decrypt: `sops decrypt --extract '["path"]["to"]["key"]' encrypted.yaml`
- Configuration: `.sops.yaml` file defines creation rules mapping file path patterns to encryption keys
- Key management flags: `--add-age`, `--add-pgp`, `--add-kms`, `--add-gcp-kms`, `--add-azure-kv`, `--rm-*` variants
- Key groups: require multiple master keys (M-of-N) for decryption
- Go library: `github.com/getsops/sops/v3` for programmatic access
- Auditing: optional PostgreSQL audit logging of all decrypt operations

**Secret rotation**:
- `sops updatekeys <file>` -- reads `.sops.yaml`, adds/removes keys from the file metadata without re-encrypting values (useful for onboarding/offboarding team members)
- `sops rotate -i <file>` -- generates a new data encryption key and re-encrypts all values (true key rotation)
- Distinction is important: `updatekeys` changes who can decrypt; `rotate` changes the actual data key

**Encryption at rest**: Values encrypted with AES-256-GCM. The data key is wrapped per-recipient using the configured backend: age (X25519 + ChaCha20-Poly1305), PGP (RSA or ECDSA), AWS KMS (AES-256-GCM), GCP KMS, Azure Key Vault, or HashiCorp Cloud KMS. Each value has its own authentication context (the full JSON/YAML path), preventing value swapping attacks.

**SIGIL relevance**: SOPS is the natural format for storing secret manifests in Git alongside infrastructure code. SIGIL could use SOPS-encrypted files as a portable secret store format, especially for team/project secret sharing. However, for SIGIL's core local vault, raw age encryption of individual files provides simpler semantics.

---

### 1.3 pass (passwordstore.org)

**Summary**: The standard Unix password manager. Each password is a GPG-encrypted file in `~/.password-store/`, organized in a directory hierarchy. A 700-line shell script with no dependencies beyond GPG and optionally Git.

**Offline capability**: Fully offline. Everything is local GPG encryption and filesystem operations. Git sync is optional and user-initiated (`pass git push/pull`).

**Multi-line secrets and certificates**: Yes. `pass insert --multiline <name>` reads from stdin until EOF, storing arbitrary multi-line content. `pass edit <name>` opens the decrypted content in `$EDITOR`. There are no format restrictions -- PEM certificates, SSH keys, JSON blobs all work. The file is encrypted as a single GPG blob.

**CLI/API interface**:
- `pass init <gpg-id>` -- initialize store with GPG key
- `pass insert [-m] <name>` -- add secret (single-line or multi-line)
- `pass generate [-n] [-c] <name> <length>` -- generate random password (`-n` no symbols, `-c` copy to clipboard)
- `pass show <name>` -- decrypt and display
- `pass edit <name>` -- decrypt, edit in `$EDITOR`, re-encrypt
- `pass rm <name>` -- delete
- `pass find/grep <pattern>` -- search names/content
- `pass git <args>` -- passthrough to git in the store directory
- Extensions: `pass-*` scripts in `$PATH` extend functionality (e.g., `pass-otp`, `pass-import`, `pass-update`)
- No native library API -- programmatic access is via subprocess (`pass show <name>` captures stdout)

**Secret rotation**: Manual. `pass init <new-gpg-id>` with a different key will re-encrypt all existing passwords. Individual password regeneration via `pass generate --in-place <name> <length>`. No automatic rotation, no lease/TTL concept.

**Encryption at rest**: GPG (GnuPG) with the user's chosen algorithm. Typically RSA-2048/4096 or Ed25519 for asymmetric, AES-256 for symmetric. Multiple GPG keys supported per directory (team use). The entire file content is a single GPG-encrypted blob.

**SIGIL relevance**: pass provides a well-understood storage model (GPG-encrypted files in a directory tree) that SIGIL could adopt or interoperate with. The `pass show` command is trivially callable from a daemon. However, GPG's complexity (keyring management, trust model, agent) makes it less attractive than age for a new tool.

---

### 1.4 gopass

**Summary**: A pass-compatible password manager written in Go, targeting team workflows with multiple stores, structured secrets, and cross-platform support.

**Offline capability**: Fully offline for local operations. All encryption happens locally via GPG or age. Git sync is optional and user-initiated, with automatic push on secret modification (configurable).

**Multi-line secrets and certificates**: Yes. `gopass insert -m <name>` opens the default editor for multi-line input. Also supports binary file storage natively (`gopass binary cat/copy/move/sum`). SSH private keys, PEM certificates, and arbitrary binary blobs are first-class.

**CLI/API interface**:
- 100% API-compatible with pass (drop-in replacement)
- Additional commands: `gopass mounts` (manage multiple stores), `gopass recipients` (manage team members), `gopass audit` (check password strength/duplicates)
- Structured secrets: secrets can have key-value metadata beyond the first-line password
- Go library: `github.com/gopasspw/gopass/pkg/gopass` provides programmatic access:
  - `Get(ctx, name, revision)` returns decrypted secret
  - `Set(ctx, name, secret)` creates/updates
  - `List(ctx)` enumerates all entries
  - `Remove(ctx, name)` / `RemoveAll(ctx, prefix)` for deletion
  - `Rename(ctx, from, to)` for moves
  - `Secret` interface with `Password()`, `Body()`, `Get(key)`, `Set(key, value)`, `Delete(key)` for metadata
- Multiple encryption backends: GPG (default), age (configurable)
- Multiple storage backends: Git (default), Fossil, plain filesystem

**Secret rotation**: Manual, same as pass. No built-in rotation scheduling. Re-encryption on recipient change is automatic (`gopass recipients add/remove` triggers re-encryption of affected entries).

**Encryption at rest**: GPG (default) or age, depending on configuration. Same underlying algorithms as the respective tools.

**SIGIL relevance**: gopass is a strong candidate as an external backend for SIGIL. Its Go library provides clean programmatic access, and its recipient management model handles team use cases that raw age cannot. The structured secrets model (key-value metadata) aligns well with SIGIL's need to store secret metadata alongside the secret value.

---

### 1.5 HashiCorp Vault

**Summary**: Enterprise secret management platform with a rich API, multiple secret engines (KV, database, PKI, transit, SSH), and extensive auth methods.

**Offline capability**: Conditionally offline.
- **Dev mode** (`vault server -dev`): Fully local, in-memory storage, auto-initialized and auto-unsealed. Listens on `127.0.0.1:8200` without TLS. All data lost on restart. Suitable for development/testing only.
- **Production mode with Raft storage**: Fully local, persists to disk. The integrated Raft storage backend requires no external dependencies (no Consul, no cloud). Single-node Raft is supported. Data encrypted at rest by the barrier. Can operate air-gapped after initial unseal.
- **Production mode with cloud auto-unseal**: Requires network access to the auto-unseal provider (AWS KMS, GCP KMS, etc.) at startup. Can operate offline once unsealed.

**Multi-line secrets and certificates**: Yes. The KV secrets engine stores arbitrary key-value pairs where values can be any string, including multi-line PEM certificates. The PKI secrets engine generates and manages X.509 certificates natively. The SSH secrets engine manages SSH credentials.

**CLI/API interface**:
- Full HTTP REST API (every feature accessible via API)
- CLI: `vault kv put secret/myapp key=value`, `vault kv get secret/myapp`, `vault kv delete secret/myapp`
- KV v2 supports versioning, soft delete, metadata
- Auth: `vault login`, `vault token create`, supports 15+ auth methods (token, userpass, LDAP, OIDC, Kubernetes, AppRole, AWS IAM, etc.)
- Secrets engines: KV, Database, PKI, Transit, SSH, TOTP, AWS, GCP, Azure, Consul, Nomad, Transform, KMIP
- Policy language: HCL-based fine-grained ACLs on paths
- Client libraries: Official Go SDK; community SDKs for Python, Ruby, Java, .NET, Rust (`vaultrs` crate)

**Secret rotation**:
- **Dynamic secrets**: Database, AWS, GCP, Azure engines generate credentials on-demand with configurable TTLs. Automatic revocation on lease expiry.
- **Static role rotation**: 1-to-1 mapping of Vault role to database user with configurable `rotation_period` or `rotation_schedule`. Automatic rotation.
- **Manual rotation**: `vault kv put` overwrites with new value. KV v2 preserves version history.
- **Transit engine**: Supports key versioning and rotation for encryption keys without re-encrypting data.

**Encryption at rest**: AES-256-GCM with 96-bit random nonces for the storage barrier. The barrier key is encrypted with the root key, which is split via Shamir's Secret Sharing (configurable threshold). Auto-unseal delegates root key protection to an external KMS or transit engine.

**SIGIL relevance**: Vault is the most feature-complete option but the heaviest. For SIGIL, Vault is primarily relevant as an external backend (the user already runs it). SIGIL should support Vault's HTTP API for fetching secrets. Running a local Vault in dev mode as SIGIL's internal store is overkill -- age provides the needed encryption without a server process. However, Vault's dynamic secrets model (generating short-lived credentials) is a pattern SIGIL should expose when Vault is the backend.

---

### 1.6 OpenBao

**Summary**: Open-source fork of HashiCorp Vault (from the last MPL 2.0 release, v1.14.0), maintained by the Linux Foundation. Current version: 2.5.2 (March 2026). API-compatible with Vault with some additions.

**Offline capability**: Same as Vault. Supports Raft integrated storage for fully local operation. Dev mode available. Additionally supports a static key seal (`static` seal type) that uses a 32-byte key from the config file for auto-unseal, eliminating the need for any external KMS -- a significant advantage for air-gapped environments.

**Multi-line secrets and certificates**: Identical to Vault. KV engine stores arbitrary values. PKI engine for certificate management.

**CLI/API interface**:
- CLI: `bao` binary, command structure mirrors Vault (`bao kv put`, `bao kv get`, `bao secrets list`, `bao auth list`)
- Full HTTP API at `/v1/` prefix, compatible with Vault API clients
- Auth methods: Token, UserPass, LDAP, Kubernetes, AppRole, OIDC, and others
- Secrets engines: KV (v1, v2), Database, PKI, Transit, SSH, TOTP, Cubbyhole
- New in v2.5.0: Namespaces (previously Vault Enterprise only) and horizontal read scalability on HA standby nodes

**Secret rotation**: Identical to Vault. Dynamic secrets with leases and TTLs. Static role rotation for database engines. Transit key versioning.

**Encryption at rest**: AES-256-GCM-96 for the storage barrier. Supports Shamir seal, Transit auto-unseal, PKCS#11 auto-unseal, and static key seal.

**SIGIL relevance**: OpenBao is a direct Vault replacement with a true open-source license (MPL 2.0). For users already running OpenBao (as the SIGIL author does on ardenone-cluster), SIGIL should support it as an external backend using the same HTTP API integration as Vault. The static key seal makes OpenBao viable for a local, air-gapped secret server if SIGIL ever needs server-mode capabilities beyond file-level encryption.

---

### 1.7 Bitwarden Secrets Manager / CLI

**Summary**: Bitwarden's purpose-built secrets management product, separate from the password manager. Accessed via the `bws` CLI, using machine accounts and access tokens.

**Offline capability**: Limited offline. The `bws` CLI requires network connectivity to the Bitwarden server (cloud or self-hosted) for most operations. State files (encrypted with AES-256, PBKDF2-SHA-256 key derivation) cache authentication tokens locally to reduce API calls and rate limiting, but secret values themselves are not cached offline. Self-hosting the Bitwarden server on the same network provides "near-offline" capability but still requires the server to be running.

**Multi-line secrets and certificates**: Yes. Secrets are stored as key-value pairs with string values. Multi-line content is supported. No native structured certificate management.

**CLI/API interface**:
- CLI: `bws secret get <id>`, `bws secret create`, `bws secret list`, `bws secret update`, `bws secret delete`
- `bws run -- <command>` injects secrets as environment variables
- Authentication: `BWS_ACCESS_TOKEN` environment variable or `bws login`
- REST API: available for programmatic access
- SDKs: Official SDKs for multiple languages via the Bitwarden SDK

**Secret rotation**: No built-in automatic rotation. Manual rotation via `bws secret update`. Audit logging tracks access and changes.

**Encryption at rest**: Zero-knowledge, end-to-end AES-256-bit encryption with salted PBKDF2-SHA-256 hashing. Secrets encrypted client-side before transmission to the server. Server stores only ciphertext.

**SIGIL relevance**: Bitwarden SM is relevant as an external backend for teams already using Bitwarden. The `bws run` command has a similar injection model to SIGIL's `{{secret:path}}` approach. However, the lack of true offline capability and the requirement for a running server make it unsuitable as SIGIL's core local store.

---

### 1.8 1Password CLI (op)

**Summary**: 1Password's CLI tool for accessing vaults, items, and secrets programmatically. Supports personal accounts and service accounts.

**Offline capability**: Limited offline. The CLI requires network connectivity to 1Password servers (cloud) for secret retrieval. A daemon process caches encrypted items in memory between CLI invocations (enabled by default on Unix), improving performance but not enabling true offline access. The desktop app supports offline access, but the CLI does not. Third-party tools like `op-fast` provide encrypted local caching, but these are not officially supported.

**Multi-line secrets and certificates**: Yes. 1Password items support multiple fields including "notes" (arbitrary multi-line text), file attachments, and structured field types (password, TOTP, credit card, etc.). Certificates and SSH keys are stored as documents or secure notes.

**CLI/API interface**:
- Secret references: `op://<vault>/<item>[/<section>]/<field>` URI syntax
- `op read <reference>` -- read a single secret value
- `op run -- <command>` -- inject secrets into environment variables for a subprocess
- `op inject -i template.env -o output.env` -- replace secret references in config files
- `op item get/create/edit/delete` -- CRUD on items
- Service accounts: `OP_SERVICE_ACCOUNT_TOKEN` for headless/CI use, scoped to specific vaults with configurable permissions
- Connect server: self-hosted API server for Kubernetes and infrastructure integration
- Biometric unlock: integrates with system biometrics for developer UX

**Secret rotation**: No built-in automatic rotation. Items are versioned -- 1Password maintains history of changes. Rotation is manual via `op item edit`.

**Encryption at rest**: AES-256-GCM with a two-secret key derivation (account password + secret key). End-to-end encrypted. The server never has access to plaintext.

**SIGIL relevance**: 1Password is a high-value external backend for SIGIL. The `op://` secret reference syntax is conceptually identical to SIGIL's `{{secret:path}}` placeholders. `op run` demonstrates the injection-and-scrub pattern that SIGIL generalizes. SIGIL should support 1Password as a backend by shelling out to `op read` or using the Connect server API.

---

### 1.9 Doppler

**Summary**: Cloud-native secrets management platform with a strong CLI and API-first design. Organizes secrets by project, environment (development/staging/production), and config.

**Offline capability**: Partially offline via fallback files. The `doppler run` command automatically creates an encrypted fallback file (AES-256-GCM, PBKDF2 key derivation using the Doppler token) containing a snapshot of the current secrets. When network is unavailable, the CLI falls back to this cached file. `--fallback-only` flag forces offline-only mode. Fallback files have no expiration and can be used indefinitely.

**Multi-line secrets and certificates**: Yes. Secrets are key-value pairs with string values. Multi-line content is supported. No native structured certificate management.

**CLI/API interface**:
- `doppler run -- <command>` -- inject secrets as environment variables
- `doppler secrets get <name>` -- retrieve a single secret
- `doppler secrets set <name> <value>` -- create/update
- `doppler secrets download --format=<json|env|yaml>` -- export secrets
- REST API: fully featured, JSON-encoded, standard HTTP verbs
- Organization: projects > environments > configs
- Integrations: native sync to AWS, GCP, Azure, Vercel, GitHub, Terraform, Kubernetes

**Secret rotation**: Secret versioning and rollback built-in. Audit logs track all changes. No automatic rotation of secret values themselves -- that requires external integration.

**Encryption at rest**: TLS in transit. Secrets encrypted at rest on Doppler's servers. Fallback files encrypted with AES-256-GCM using PBKDF2-derived keys. The fallback file is tied to the Doppler token that created it by default (can be overridden with `--passphrase`).

**SIGIL relevance**: Doppler's fallback file mechanism is a good model for SIGIL's offline cache of remote secrets. The `doppler run` injection pattern is another validation of the env-var injection approach. Doppler is relevant as an external backend for teams using it.

---

### 1.10 Infisical

**Summary**: Open-source secrets management platform with CLI, agent, Kubernetes operator, and web dashboard. Can be self-hosted. Supports secret versioning, point-in-time recovery, dynamic secrets, and secret rotation.

**Offline capability**: Self-hosted instances can operate within a private network without internet access. The Infisical server requires PostgreSQL and Redis but no cloud dependencies when self-hosted with `ROOT_ENCRYPTION_KEY` set for local KMS. The CLI (`infisical run`) requires connectivity to an Infisical server (cloud or self-hosted). No local-only file-based mode.

**Multi-line secrets and certificates**: Yes. Secrets are key-value pairs. Multi-line values supported. Also has a built-in PKI (public key infrastructure) for certificate management, with CA hierarchies and certificate templates.

**CLI/API interface**:
- `infisical run -- <command>` -- inject secrets as environment variables
- `infisical secrets get <name>` -- retrieve a single secret
- `infisical secrets set <name> <value>` -- create/update
- `infisical export --format=<json|env|yaml|csv>` -- export secrets
- REST API: fully featured
- SDKs: Node, Python, Go, Ruby, Java, .NET
- Kubernetes Operator: `InfisicalSecret` CRD for syncing secrets to Kubernetes
- Agent: sidecar/standalone process for injecting secrets without code changes
- `InfisicalPushSecret` CRD: push runtime-generated secrets back to Infisical
- Auth methods: Universal (client ID/secret), Kubernetes, AWS, GCP, Azure, OIDC

**Secret rotation**: Built-in automatic rotation for PostgreSQL, MySQL, AWS IAM, SendGrid, and others. Dynamic secrets for PostgreSQL, MySQL, Cassandra, RabbitMQ, AWS IAM, and more (ephemeral credentials with TTLs). Secret versioning with point-in-time recovery.

**Encryption at rest**: AES-256-GCM. Zero-knowledge architecture: secrets encrypted client-side before transmission. Server stores only ciphertext. Self-hosted deployments use `ROOT_ENCRYPTION_KEY` environment variable for the KMS root key. Supports external KMS (AWS KMS, GCP KMS) for the root key.

**SIGIL relevance**: Infisical is a strong external backend candidate, especially for teams wanting an open-source, self-hosted secret manager with dynamic secrets and rotation. The Kubernetes operator and agent patterns are relevant references for SIGIL's own injection architecture. The push-secret pattern (runtime secrets flowing back to the manager) is interesting for SIGIL's breach detection reporting.

---

### 1.11 Chamber (Segment)

**Summary**: CLI for managing secrets stored in AWS Systems Manager Parameter Store or AWS Secrets Manager. Designed for AWS-native workflows.

**Offline capability**: Not offline. Requires AWS credentials and network connectivity to AWS services for all operations. No local storage, no caching, no fallback mode. Chamber is fundamentally a thin CLI wrapper around AWS APIs.

**Multi-line secrets and certificates**: Yes, with caveats. SSM Parameter Store supports string values up to 8 KB (standard) or 8 KB (advanced tier). Multi-line content is supported but size-limited. AWS Secrets Manager supports up to 64 KB per secret.

**CLI/API interface**:
- `chamber write <service> <key> <value>` -- store secret
- `chamber read <service> <key>` -- retrieve with metadata
- `chamber list <service> [-e]` -- list secrets (with or without values)
- `chamber exec <service> -- <command>` -- inject as environment variables
- `chamber export <service> --format=<json|yaml|csv|dotenv|tsv>` -- export
- `chamber import <service> <file>` -- bulk import
- `chamber history <service> <key>` -- audit trail
- `chamber find <pattern>` -- search across services
- `chamber tag <service> <key> <tag=value>` -- metadata tags
- Go library: `github.com/segmentio/chamber/v3` for programmatic access (v3 requires `context.Context` arguments)
- Backend selection: `--backend=ssm` (default), `--backend=secretsmanager`, `--backend=s3` (experimental), `--backend=null` (passthrough)

**Secret rotation**: No built-in rotation. Relies on AWS Secrets Manager's native rotation (Lambda-based) when using the Secrets Manager backend. SSM Parameter Store has no native rotation.

**Encryption at rest**: Delegated to AWS. SSM Parameter Store encrypts via AWS KMS (requires a KMS key with alias `parameter_store_key`). Secrets Manager uses its own KMS-backed encryption. Custom KMS key alias configurable via `CHAMBER_KMS_KEY_ALIAS`.

**SIGIL relevance**: Chamber validates the `exec` injection pattern (inject secrets as env vars for a subprocess). For AWS-centric users, SIGIL should support SSM/Secrets Manager as an external backend -- but via direct AWS SDK calls rather than wrapping Chamber, since Chamber adds no value beyond the AWS API calls themselves.

---

### 1.12 Comparative Summary

| Tool | Fully Offline | Multi-line/Certs | Programmatic API | Auto Rotation | Encryption |
|------|:---:|:---:|:---:|:---:|:---|
| **age** | Yes | Yes (arbitrary files) | Go library, CLI | No | X25519 + ChaCha20-Poly1305 |
| **SOPS** | Yes (with age/PGP) | Yes (structured + binary) | Go library, CLI | Key rotation only | AES-256-GCM (values) |
| **pass** | Yes | Yes (`-m` flag) | CLI only (subprocess) | Manual re-encrypt | GPG (RSA/Ed25519 + AES-256) |
| **gopass** | Yes | Yes (+ binary files) | Go library | Manual re-encrypt | GPG or age |
| **Vault** | Yes (Raft storage) | Yes (KV + PKI engine) | HTTP API, Go SDK | Dynamic secrets + TTL | AES-256-GCM barrier |
| **OpenBao** | Yes (Raft + static seal) | Yes (KV + PKI engine) | HTTP API (Vault-compat) | Dynamic secrets + TTL | AES-256-GCM barrier |
| **Bitwarden SM** | No (server required) | Yes | CLI, REST API, SDKs | No | AES-256 E2E |
| **1Password CLI** | No (cloud required) | Yes | CLI (`op read/run/inject`) | No | AES-256-GCM E2E |
| **Doppler** | Partial (fallback files) | Yes | CLI, REST API | Version history only | AES-256-GCM fallback |
| **Infisical** | Self-hosted only | Yes (+ built-in PKI) | CLI, REST API, SDKs | Yes (DB, IAM, dynamic) | AES-256-GCM E2E |
| **Chamber** | No (AWS required) | Yes (size-limited) | CLI, Go library | Via AWS SM only | AWS KMS |

---

## Part 2: TUI Frameworks for Secret Management

This section evaluates TUI frameworks suitable for building SIGIL's agent-inaccessible secret management interface, with particular attention to how terminal rendering works and how a TUI can be made resistant to observation by an AI agent operating in the same environment.

---

### 2.1 Bubble Tea (Go) -- charmbracelet/bubbletea

**Summary**: A functional, Elm-architecture TUI framework for Go. Uses a Model-Update-View loop where the model is immutable state, Update handles messages, and View renders the UI as a string.

**Rendering architecture**:
- The View function returns a string representation of the entire UI
- The framework diffs the current and previous View output and writes only changed portions to the terminal
- Supports alternate screen buffer via `tea.EnterAltScreen` command or `tea.WithAltScreen()` program option
- Uses synchronized output (Mode 2026 in BubbleTea v2) to eliminate screen tearing on supporting terminals
- High-performance cell-based renderer with built-in color downsampling

**Alternate screen buffer**: Yes, first-class support. `tea.WithAltScreen()` enters the alternate screen on startup. Content rendered to the alternate screen is not part of the main terminal scrollback. When the program exits, the alternate screen is cleared and the main screen is restored.

**Input/output model**: Bubble Tea assumes control of stdin and stdout. Options like `tea.WithInput(reader)` and `tea.WithOutput(writer)` allow redirecting I/O to custom sources (e.g., a PTY slave for SSH sessions). The `tea.WithoutCatchPanics()` option is available for debugging.

**Agent observability concerns**: When Bubble Tea runs in the same terminal session as an agent, the agent's parent process has access to the PTY master file descriptor. Any process with read access to the PTY master can observe all bytes written to the terminal, including alternate screen content. The alternate screen buffer provides no security isolation -- it is a display management feature, not a security boundary.

**SIGIL relevance**: Bubble Tea is an excellent framework but is Go-based. Since SIGIL targets Rust, Bubble Tea is relevant primarily as a reference architecture. Its Elm-architecture model (Model-Update-View) is mirrored by Ratatui's design. The `WithInput`/`WithOutput` options demonstrate how to attach a TUI to a separate PTY.

---

### 2.2 Ratatui (Rust) -- ratatui/ratatui

**Summary**: The primary TUI framework for Rust. Immediate-mode rendering with intermediate buffers. Uses crossterm (or termion/termwiz) as the terminal backend.

**Rendering architecture**:
- Immediate-mode: every frame, the application renders all widgets from scratch into a `Buffer`
- The `Terminal` struct maintains two buffers (current and previous)
- On each `draw()` call, only the diff between current and previous buffers is written to the terminal
- Uses the Cassowary constraint solver for layout
- Sub-millisecond rendering with zero-cost abstractions
- Version 0.30.0 (2025): modularized into workspace crates (`ratatui-core`, `ratatui-widgets`, backend crates), `no_std` support added

**Alternate screen buffer**: Yes, via crossterm backend. `crossterm::terminal::EnterAlternateScreen` / `LeaveAlternateScreen`. Typically activated in the `init()` function and deactivated in a cleanup/panic handler.

**Terminal backend abstraction**: Ratatui abstracts the terminal backend, supporting:
- **crossterm**: Cross-platform (Windows, macOS, Linux), async-compatible
- **termion**: Unix-only, simpler API
- **termwiz**: Wez Furlong's terminal library (used by wezterm)

This abstraction means the TUI can be connected to any file descriptor, not just the process's inherited stdin/stdout. A custom backend could write to a completely separate PTY.

**Agent observability concerns**: Same fundamental issue as Bubble Tea. Ratatui writes escape sequences and content to whatever file descriptor the backend is configured to use. If that FD is the same terminal the agent can observe, the content is visible. The alternate screen buffer is not a security boundary.

**SIGIL relevance**: Ratatui is the designated TUI framework for SIGIL (per requirements.md). Its backend abstraction is the key enabler: SIGIL can allocate a separate PTY (via `openpty()`), connect Ratatui's crossterm backend to that PTY's master FD, and have the user interact via a separate terminal emulator attached to the slave FD. This provides true process-level isolation.

---

### 2.3 Textual (Python) -- textualize/textual

**Summary**: A rapid application development framework for Python TUIs, built on the Rich library. Supports both terminal and web rendering.

**Rendering architecture**:
- CSS-like styling and layout system
- Widget-based with reactive attributes
- Achieves 60-120 FPS via Rich's segment trees, which delta-update only dirty regions
- Rendering pipeline: widgets produce Rich `Segment` lists (string + style), converted to ANSI escape codes at output
- Dual-mode: terminal rendering and web browser rendering (`textual serve`)

**Alternate screen buffer**: Yes. Textual apps run in the alternate screen by default. Content is not visible in main terminal scrollback.

**Agent observability concerns**: Same as other frameworks. The web serving mode (`textual serve`) is interesting for SIGIL -- it could serve the TUI over a local HTTP port with authentication, providing network-level isolation from the agent process. However, this adds a web server dependency.

**SIGIL relevance**: Python is not SIGIL's implementation language, but Textual's web-serve capability is an interesting alternative pattern. If process-level TUI isolation proves difficult, serving the management UI over a local authenticated HTTPS endpoint is a fallback approach.

---

### 2.4 Blessed / Neo-Blessed (Node.js)

**Summary**: A high-level terminal interface library for Node.js. blessed is the original (largely unmaintained); neo-blessed is the maintained fork.

**Rendering architecture**:
- Maintains two screen buffers (current and previous), rendering only changes
- Uses the painter's algorithm with CSR (change-scroll-region) and BCE (back-color-erase) optimizations
- Smart cursor movement to minimize escape sequence output
- Screen damage buffer tracks modified regions

**Alternate screen buffer**: Yes. blessed/neo-blessed uses the alternate screen by default for full-screen applications. `screen.destroy()` restores the main screen.

**Agent observability concerns**: Same fundamental issues as all other TUI frameworks operating on the same terminal.

**SIGIL relevance**: Not directly relevant (Node.js, not Rust). Included for completeness and as a reference for the double-buffering rendering pattern that all TUI frameworks share.

---

### 2.5 How TUIs Render: Alternate Screen Buffers

**Technical details**: Modern terminals support two screen buffers:
1. **Main screen buffer**: The normal scrollback buffer where command output accumulates
2. **Alternate screen buffer**: A separate, non-scrollable buffer activated by the escape sequence `\e[?47h` (or `\e[?1049h` for xterm alternate screen with save/restore cursor)

When a TUI enters the alternate screen:
- The current main screen content is preserved but hidden
- The terminal displays a fresh buffer
- All output goes to the alternate buffer
- On exit (`\e[?47l` or `\e[?1049l`), the alternate buffer is discarded and the main screen is restored

**What the alternate screen does NOT provide**:
- It does NOT prevent other processes from reading the terminal output
- It does NOT encrypt or protect the content in memory
- It does NOT prevent the terminal emulator process from accessing the buffer
- It does NOT prevent `ptrace()` from reading the TUI process's memory
- It is purely a display management feature for user convenience

**Can an agent running in the same terminal session read TUI state?**

Yes, through multiple vectors:

1. **PTY master FD**: If the agent and TUI share a terminal session, the terminal emulator holds the PTY master. Any process that can read from the PTY master sees all bytes written to the terminal, including alternate screen content. An AI agent that spawns subprocesses inherits the terminal's file descriptors.

2. **`/proc/<pid>/fd/`**: On Linux, if a process can access `/proc/<tui_pid>/fd/1` (the TUI's stdout), it can observe the output. This is gated by ptrace access controls.

3. **`/proc/<pid>/mem`**: Direct memory reading of the TUI process, gated by ptrace permissions.

4. **Screen scraping**: Tools like `tmux capture-pane`, `script`, or reading from `/dev/pts/*` can capture terminal content.

5. **Agent's own subprocess capture**: When an AI agent (like Claude Code) runs shell commands, it captures stdout/stderr via `subprocess.run(capture_output=True)`. If the agent can execute a command that reads the TUI's terminal, it can capture the content.

---

### 2.6 Making a TUI Agent-Proof: Isolation Strategies

Given that alternate screen buffers provide no security isolation, SIGIL must use stronger mechanisms:

#### Strategy 1: Separate PTY (Recommended for SIGIL)

Allocate a new pseudo-terminal pair using `openpty()` (or the Rust equivalent via the `nix` crate's `openpty()`):

1. SIGIL daemon calls `openpty()` to create a new PTY master/slave pair
2. The TUI process (or thread) attaches Ratatui's crossterm backend to the PTY master FD
3. The user connects to the PTY slave via a separate terminal emulator window (e.g., `screen /dev/pts/N` or a dedicated terminal emulator process)
4. The agent's terminal session has no file descriptors pointing to this PTY
5. The agent cannot observe the TUI's output because it has no access to the PTY's file descriptors

**Key requirement**: The PTY slave's `/dev/pts/N` device file must have restrictive permissions (owner-only read/write, which is the default behavior of `openpty()` -- it sets ownership to the real UID of the calling process and group "tty").

#### Strategy 2: Separate Process with ptrace Protection

Run the TUI as a separate process (not a child of the agent) with ptrace protection:

1. TUI process starts before the agent, or is started by a parent process that is not the agent
2. TUI process calls `prctl(PR_SET_DUMPABLE, 0)` to prevent ptrace attachment
3. System configured with `kernel.yama.ptrace_scope >= 1` (restricts ptrace to descendants only)
4. TUI process's `/proc/<pid>/mem` and `/proc/<pid>/fd/` become inaccessible to the agent

**Linux kernel.yama.ptrace_scope levels**:
- `0`: Classic -- any process can ptrace any same-UID process (INSECURE for SIGIL)
- `1`: Restricted -- only descendants can be ptraced (DEFAULT on most distros, GOOD for SIGIL if TUI is not a child of the agent)
- `2`: Admin-only -- only CAP_SYS_PTRACE can ptrace (BETTER)
- `3`: No attach -- ptrace completely disabled (MOST SECURE)

#### Strategy 3: Separate User/Session

Run the TUI as a different Unix user:

1. SIGIL TUI runs as `sigil-admin` user
2. Agent runs as the normal user
3. File permissions and ptrace restrictions prevent cross-user observation
4. Communication between agent's SIGIL client and the daemon uses a Unix domain socket with `SO_PEERCRED` for authentication

#### Strategy 4: Namespace Isolation

Use Linux namespaces to isolate the TUI:

1. TUI runs in a separate PID namespace (invisible in the agent's `/proc`)
2. TUI runs in a separate mount namespace (its `/dev/pts` entries are isolated)
3. This provides container-like isolation without a full container runtime

#### Strategy 5: Authenticated Local Web UI (Fallback)

Serve the TUI as a local web application:

1. SIGIL serves a management UI on `https://127.0.0.1:<random-port>`
2. Authentication via a token displayed only in the separate terminal at startup
3. The agent has no knowledge of the port or token
4. TLS with a self-signed certificate prevents eavesdropping even on localhost

**Recommended SIGIL approach**: Combine Strategies 1 and 2. The TUI runs as a separate process (started before the agent), allocates its own PTY, sets `PR_SET_DUMPABLE` to 0, and communicates with the SIGIL daemon via a Unix domain socket authenticated with a pre-shared session token. The user interacts with the TUI in a separate terminal window.

---

## Part 3: External Secret Backend Integration

This section documents how secret injection tools integrate with external providers, providing patterns that SIGIL can adopt or adapt.

---

### 3.1 Kubernetes External Secrets Operator (ESO)

**Architecture**: ESO is a Kubernetes operator that syncs secrets from external providers into native Kubernetes Secret objects. It uses three primary CRDs:

- **SecretStore** (namespaced): Defines authentication credentials and configuration for a specific external provider instance. Separates auth concerns from secret consumption.
- **ClusterSecretStore**: Cluster-wide variant of SecretStore, enabling cross-namespace references. Useful for centralized secret management.
- **ExternalSecret**: References a SecretStore and specifies which keys to fetch. The controller creates/updates a Kubernetes Secret based on this spec.

**Reconciliation loop**:
1. Controller watches ExternalSecret resources
2. Locates the referenced SecretStore via `spec.secretStoreRef`
3. Instantiates a provider client using the SecretStore's credentials
4. Fetches the requested secret data from the external API
5. Optionally decodes/transforms the data (base64, JSON parsing, templating)
6. Creates or updates the target Kubernetes Secret
7. Re-reconciles on a configurable interval (`spec.refreshInterval`)

**Supported providers (as of 2026)**:

*Stable*: AWS Secrets Manager, AWS Parameter Store, HashiCorp Vault, GCP Secret Manager, Azure Key Vault, IBM Cloud Secrets Manager, Oracle Vault, Akeyless, CyberArk Secrets Manager, Previder

*Beta*: Kubernetes (remote cluster), SecretServer

*Alpha*: Yandex Lockbox, GitLab Variables, 1Password, 1Password SDK, Generic Webhook, senhasegura DSM, Doppler, Keeper Security, Scaleway, Delinea, Beyondtrust, Pulumi ESC, Passbolt, Infisical, Bitwarden Secrets Manager, Cloud.ru, Volcengine, ngrok, Barbican, Devolutions Server, Nebius MysteryBox

**Provider interface pattern**: Each provider implements a `SecretsClient` interface with methods like `GetSecret()`, `GetSecretMap()`, and `PushSecret()`. This is the same trait/interface pattern SIGIL should adopt for its pluggable backend system.

**SIGIL relevance**: ESO's architecture is the most direct analog to SIGIL's backend system:
- `SecretStore` maps to SIGIL's backend configuration
- `ExternalSecret` maps to SIGIL's secret reference (`{{secret:path}}`)
- The reconciliation pattern maps to SIGIL's daemon fetching and caching secrets
- The provider interface is the pattern for SIGIL's `SecretBackend` trait

---

### 3.2 1Password Connect / CLI Integration

**Three integration patterns**:

#### Pattern 1: CLI Secret References (`op read/run/inject`)
- Secret references use URI syntax: `op://<vault>/<item>[/<section>]/<field>`
- `op run --env-file=.env -- ./myapp` replaces all `op://` references in the environment with actual values
- `op inject -i template.yaml -o output.yaml` replaces references in arbitrary files
- Secrets exist only in the subprocess environment or the output file -- they are not persisted

#### Pattern 2: Kubernetes Secrets Injector (Mutating Webhook)
- Annotate pods with `operator.1password.io/inject: <container-list>`
- Set environment variables with `op://` references as values
- The webhook mutates the pod spec to inject an init container that resolves references
- Secrets are available only for the command specified in the container's `command` field
- Does NOT create Kubernetes Secret objects (unlike the Kubernetes Operator)
- Requires `OP_CONNECT_HOST` and `OP_CONNECT_TOKEN` in the pod environment

#### Pattern 3: Kubernetes Operator (Connect Server)
- `OnePasswordItem` CRD specifies which 1Password items to sync
- Operator creates Kubernetes Secret objects from 1Password items
- Automatically restarts deployments when 1Password items are updated
- Requires a 1Password Connect server deployed in the cluster

**SIGIL relevance**: Pattern 1 (`op run/inject`) is the closest to SIGIL's injection model. SIGIL's `{{secret:path}}` is analogous to `op://vault/item/field`. SIGIL should support 1Password as a backend by invoking `op read "op://vault/item/field"` to retrieve individual secret values. The Connect server API is an alternative for environments where the CLI is not installed.

---

### 3.3 HashiCorp Vault Agent / Vault CSI Provider

**Two Kubernetes integration patterns**:

#### Pattern 1: Vault Agent Injector (Sidecar)
- **Mechanism**: Mutating admission webhook injects a Vault Agent sidecar container into pods
- **Authentication**: Supports ALL Vault auto-auth methods (Kubernetes, AWS IAM, AppRole, etc.)
- **Secret delivery**: Agent authenticates to Vault, fetches secrets, renders them to files in a shared `tmpfs` volume
- **Templating**: Full Go template support for rendering secrets into application-specific formats (JSON, properties files, connection strings)
- **Lifecycle**: Agent runs as a sidecar for the pod's lifetime, continuously renewing tokens and leases, re-fetching secrets on rotation
- **Init mode**: Optionally runs as an init container for one-shot secret delivery
- **Resource cost**: One sidecar container per pod (configurable CPU/memory limits)

#### Pattern 2: Vault CSI Provider (DaemonSet)
- **Mechanism**: Implements the Kubernetes Secrets Store CSI Driver interface
- **Authentication**: Kubernetes auth method ONLY
- **Secret delivery**: Secrets mounted as ephemeral CSI volumes
- **Templating**: Limited -- renders secrets to files, but no Go template support
- **Lifecycle**: Secrets fetched during `ContainerCreation` phase. Pod blocked until secrets available. No continuous renewal.
- **Sync to K8s Secrets**: Can optionally create Kubernetes Secret objects from CSI volumes
- **Resource cost**: One DaemonSet pod per node (shared across all pods on that node)

**Key trade-offs**:
- Agent Injector: more flexible auth, continuous renewal, higher per-pod resource cost
- CSI Provider: simpler per-pod overhead, earlier in pod lifecycle (avoids Istio sidecar ordering issues), but limited to Kubernetes auth

**SIGIL relevance**: The Vault Agent sidecar pattern is a close analog to SIGIL's daemon. Both are long-running processes that authenticate to a secret backend, cache secrets, and deliver them to application processes. SIGIL's daemon plays the same role as Vault Agent but at the developer workstation level rather than the Kubernetes pod level. The template rendering capability (converting secrets into application-specific formats) is relevant for SIGIL's multi-line certificate injection.

---

### 3.4 OpenBao Agent Injection

**Architecture**: Functionally identical to Vault Agent Injector. The `openbao-k8s` repository contains the agent injector as a Kubernetes mutating webhook.

**Key components**:
- **OpenBao Helm chart**: Primary installation method for both the OpenBao server and the agent injector
- **Agent injector**: Mutating webhook that injects OpenBao Agent sidecar containers into pods
- **Annotations**: `bao.openbao.org/agent-inject: "true"`, `bao.openbao.org/agent-inject-secret-<name>: <path>`
- **Persistent cache**: OpenBao Agent supports Kubernetes-specific persistent caching, allowing tokens and leases to survive pod restarts
- **TLS configuration**: Injector supports custom TLS certificates for webhook communication

**Differences from Vault Agent**:
- Command prefix: `bao` instead of `vault`
- Annotation prefix: `bao.openbao.org` instead of `vault.hashicorp.com`
- Static key seal support: OpenBao's static seal enables fully offline auto-unseal without any cloud KMS, relevant for air-gapped Kubernetes clusters
- Namespaces: OpenBao 2.5+ includes namespace support (previously Vault Enterprise only)

**SIGIL relevance**: For users running OpenBao (as the project author does), SIGIL should support OpenBao as a first-class backend. The HTTP API is compatible with Vault, so a single backend implementation can support both. The static key seal pattern is relevant for SIGIL's own encryption key management -- SIGIL could derive its local vault key from a user-provided passphrase using a similar mechanism.

---

### 3.5 AWS Secrets Manager / SSM Integration Patterns

**Four primary injection patterns**:

#### Pattern 1: SDK Direct Access
- Application uses AWS SDK to call `GetSecretValue()` at startup
- Caching library (`aws-secretsmanager-caching-*`) reduces API calls
- Secrets cached in-process for configurable TTL
- Supports automatic rotation via Lambda functions

#### Pattern 2: ECS Native Injection
- Task definition references secrets: `"secrets": [{"name": "DB_PASS", "valueFrom": "arn:aws:secretsmanager:..."}]`
- ECS agent fetches secrets and injects them as environment variables before container start
- Also supports SSM Parameter Store references
- Secrets available to the container process but not visible in the task definition at runtime

#### Pattern 3: Lambda Environment Variables
- Secrets referenced in Lambda function configuration
- AWS Secrets Manager extension layer provides local caching
- Best practice: fetch secret outside handler (persists across warm invocations), cache with TTL

#### Pattern 4: External Secrets Operator (Kubernetes)
- ESO with AWS provider fetches from Secrets Manager or Parameter Store
- Creates Kubernetes Secrets that pods mount as volumes or env vars
- Supports `dataFrom` to pull all keys from a secret as a map

**Rotation mechanism**: AWS Secrets Manager supports automatic rotation via Lambda functions. A rotation Lambda implements four steps: `createSecret`, `setSecret`, `testSecret`, `finishSecret`. Rotation schedules configured per-secret (e.g., every 30 days). Supports custom Lambda functions for non-standard secret types.

**SIGIL relevance**: AWS backends should be supported via the AWS SDK for Rust (`aws-sdk-secretsmanager`, `aws-sdk-ssm`). The caching pattern (fetch once, cache with TTL, refresh on demand) is directly applicable to SIGIL's daemon. The ECS injection pattern (resolve at process start, inject as env vars) is the same model SIGIL uses for `{{secret:path}}` resolution.

---

### 3.6 envchain, direnv, and Environment Variable Injection

#### envchain
- **Mechanism**: Stores secrets in the OS keychain (macOS Keychain or D-Bus Secret Service/gnome-keyring)
- **Usage**: `envchain <namespace> <command>` -- sets environment variables from the keychain for the subprocess
- **Storage**: No plaintext on disk. Secrets live in the OS secure enclave.
- **Limitation**: macOS and Linux with GNOME only. No cross-platform support. No team sharing.

#### direnv
- **Mechanism**: Shell extension that loads/unloads environment variables from `.envrc` files when entering/leaving directories
- **Usage**: `.envrc` file contains `export VAR=value` or calls to external tools
- **Security**: `.envrc` files are plaintext on disk (NO encryption). direnv has an allowlisting mechanism (`direnv allow`) to prevent loading untrusted `.envrc` files.
- **Integration patterns**: direnv is commonly combined with secret managers:
  - `export DB_PASS=$(op read "op://vault/db/password")` -- 1Password
  - `export DB_PASS=$(gopass show -o db/password)` -- gopass
  - `export DB_PASS=$(doppler secrets get DB_PASS --plain)` -- Doppler
  - `export DB_PASS=$(bws secret get <id> | jq -r .value)` -- Bitwarden SM
  - `export DB_PASS=$(vault kv get -field=password secret/db)` -- Vault
- **Risk**: The resolved secret values exist as environment variables in the shell process, visible via `/proc/<pid>/environ` to processes with appropriate permissions.

#### Just-in-Time (JIT) Secret Access Pattern
Combining direnv with a secret manager achieves "just-in-time" secret access:
1. Developer enters project directory
2. direnv triggers, executing `.envrc`
3. `.envrc` fetches secrets from the backend on demand
4. Secrets available as env vars only in that shell session
5. Leaving the directory unloads the variables

**Security limitations of the env var injection model**:
- Environment variables are inherited by all child processes
- `/proc/<pid>/environ` exposes them to same-user processes (depending on ptrace_scope)
- Environment variables appear in process listings (`ps eww`) on some systems
- Container runtimes may log env vars in debug mode
- Core dumps include the environment

**SIGIL relevance**: The direnv + secret manager pattern is the "current best practice" that SIGIL improves upon. SIGIL's key innovation is that secrets never become environment variables in the agent's process -- they exist only in the isolated execution environment. The direnv model (fetch on demand, scope to directory) is a good UX pattern, but the env var delivery mechanism is the security gap SIGIL addresses.

---

### 3.7 Integration Architecture Patterns Summary

Across all external secret backends, five injection patterns emerge:

| Pattern | Description | Secret Lifetime | SIGIL Analog |
|---------|-------------|----------------|--------------|
| **Env var injection** | Secrets set as environment variables for a subprocess | Process lifetime | `{{secret:path}}` resolved to env vars in isolated execution |
| **File injection** | Secrets written to tmpfs/volume, path provided to app | Until cleanup/unmount | Temporary file injection for certs/keys |
| **Sidecar/agent** | Long-running process fetches, caches, and delivers secrets | Pod/session lifetime | SIGIL daemon |
| **Mutating webhook** | Admission controller modifies pod spec to include secrets | Pod lifetime | SIGIL's PreToolCall hook |
| **SDK direct** | Application code fetches secrets at runtime | Configurable cache TTL | Backend trait `get_secret()` call |

**Universal backend trait** that SIGIL should implement:

```
trait SecretBackend {
    fn get_secret(&self, path: &str) -> Result<SecretValue>;
    fn list_secrets(&self, prefix: &str) -> Result<Vec<String>>;
    fn supports_rotation(&self) -> bool;
    fn rotate_secret(&self, path: &str) -> Result<SecretValue>;
    fn health_check(&self) -> Result<BackendStatus>;
}
```

Every backend (age local vault, Vault/OpenBao, 1Password, AWS, gopass, SOPS, Infisical, Doppler, Bitwarden) can implement this interface. The daemon holds a registry of configured backends and resolves `{{secret:backend/path}}` references by dispatching to the appropriate implementation.

---

### Sources

- [age - GitHub](https://github.com/FiloSottile/age)
- [age specification (C2SP)](https://github.com/C2SP/C2SP/blob/main/age.md)
- [age plugins](https://words.filippo.io/age-plugins/)
- [SOPS - GitHub](https://github.com/getsops/sops)
- [SOPS documentation](https://getsops.io/docs/)
- [pass - passwordstore.org](https://www.passwordstore.org/)
- [gopass - GitHub](https://github.com/gopasspw/gopass)
- [gopass Go API](https://pkg.go.dev/github.com/gopasspw/gopass/pkg/gopass)
- [Vault dev server](https://developer.hashicorp.com/vault/docs/concepts/dev-server)
- [Vault Raft storage](https://developer.hashicorp.com/vault/docs/configuration/storage/raft)
- [Vault Agent Injector vs CSI](https://developer.hashicorp.com/vault/docs/deploy/kubernetes/injector-csi)
- [OpenBao](https://openbao.org/)
- [OpenBao seal/unseal](https://openbao.org/docs/concepts/seal/)
- [OpenBao Kubernetes](https://openbao.org/docs/platform/k8s/)
- [Bitwarden Secrets Manager CLI](https://bitwarden.com/help/secrets-manager-cli/)
- [1Password CLI secret references](https://developer.1password.com/docs/cli/secret-references/)
- [1Password service accounts](https://developer.1password.com/docs/service-accounts/)
- [1Password Kubernetes Injector](https://developer.1password.com/docs/k8s/injector/)
- [Doppler fallback files](https://docs.doppler.com/docs/automatic-fallbacks)
- [Doppler CLI](https://docs.doppler.com/docs/cli)
- [Infisical - GitHub](https://github.com/Infisical/infisical)
- [Infisical Kubernetes Operator](https://infisical.com/docs/integrations/platforms/kubernetes)
- [Chamber - GitHub](https://github.com/segmentio/chamber)
- [Bubble Tea - GitHub](https://github.com/charmbracelet/bubbletea)
- [Ratatui](https://ratatui.rs/)
- [Ratatui alternate screen](https://ratatui.rs/concepts/backends/alternate-screen/)
- [Textual](https://textual.textualize.io/)
- [blessed - GitHub](https://github.com/chjj/blessed)
- [External Secrets Operator](https://external-secrets.io/latest/introduction/overview/)
- [ESO provider stability](https://external-secrets.io/latest/introduction/stability-support/)
- [envchain - GitHub](https://github.com/sorah/envchain)
- [direnv secrets management](https://www.papermtn.co.uk/secrets-management-managing-environment-variables-with-direnv/)
- [Linux Yama ptrace_scope](https://www.kernel.org/doc/Documentation/security/Yama.txt)
- [ptrace(2) man page](https://man7.org/linux/man-pages/man2/ptrace.2.html)
- [openpty(3) man page](https://man7.org/linux/man-pages/man3/openpty.3.html)
- [Claude Code bash tool architecture](https://platform.claude.com/docs/en/agents-and-tools/tool-use/bash-tool)
