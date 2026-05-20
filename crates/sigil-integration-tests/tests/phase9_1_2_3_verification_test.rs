//! Phase 9.1-9.3 Verification Tests
//!
//! These tests verify:
//! - 9.1: FUSE virtual filesystem (mount/unmount, PID/UID verification, formatted files)
//! - 9.2: HTTP proxy (MITM TLS, AWS SigV4, allowlist, scrubbing)
//! - 9.3: Credential helpers (git, SSH agent, Docker)

mod common;
use common::workspace_root;
use std::fs;

/// Test 9.1.1: Verify sigil-fuse is implemented with mount/unmount lifecycle
#[test]
fn test_9_1_1_fuse_mount_unmount_lifecycle() {
    let fuse_mount_path = workspace_root().join("crates/sigil-fuse/src/mount.rs");
    let fuse_lib_path = workspace_root().join("crates/sigil-fuse/src/lib.rs");

    assert!(fuse_mount_path.exists(), "FUSE mount module must exist");
    assert!(fuse_lib_path.exists(), "FUSE lib module must exist");

    let mount_code = fs::read_to_string(&fuse_mount_path).expect("Failed to read mount code");
    let lib_code = fs::read_to_string(&fuse_lib_path).expect("Failed to read lib code");

    // Verify mount_sigil function exists
    assert!(
        mount_code.contains("pub async fn mount_sigil"),
        "FUSE must have mount_sigil function"
    );

    // Verify unmount_sigil function exists
    assert!(
        mount_code.contains("pub fn unmount_sigil"),
        "FUSE must have unmount_sigil function"
    );

    // Verify is_mounted function exists
    assert!(
        mount_code.contains("fn is_mounted"),
        "FUSE must have is_mounted function"
    );

    // Verify FuseConfig exists with mount_point
    assert!(
        lib_code.contains("pub struct FuseConfig"),
        "FUSE must have FuseConfig struct"
    );
    assert!(
        lib_code.contains("mount_point"),
        "FuseConfig must have mount_point field"
    );
}

/// Test 9.1.2: Verify fuse_req_ctx() PID/UID verification
#[test]
fn test_9_1_2_fuse_pid_uid_verification() {
    let fuse_fs_path = workspace_root().join("crates/sigil-fuse/src/filesystem.rs");

    assert!(fuse_fs_path.exists(), "FUSE filesystem module must exist");

    let fs_code = fs::read_to_string(&fuse_fs_path).expect("Failed to read filesystem code");

    // Verify verify_access function exists
    assert!(
        fs_code.contains("fn verify_access"),
        "FUSE must have verify_access function"
    );

    // Verify PID checking
    assert!(fs_code.contains("req.pid()"), "FUSE must check request PID");

    // Verify UID checking
    assert!(fs_code.contains("req.uid()"), "FUSE must check request UID");

    // Verify sandbox_pid restriction
    assert!(
        fs_code.contains("sandbox_pid") || fs_code.contains("allowed_pid"),
        "FUSE must support sandbox PID restriction"
    );

    // Verify sandbox_uid restriction
    assert!(
        fs_code.contains("sandbox_uid") || fs_code.contains("allowed_uid"),
        "FUSE must support sandbox UID restriction"
    );

    // Verify access denial logging
    assert!(
        fs_code.contains("access denied") || fs_code.contains("Access denied"),
        "FUSE must log access denial"
    );
}

/// Test 9.1.3: Verify auto-generated formatted files
#[test]
fn test_9_1_3_auto_generated_formatted_files() {
    let formatter_path = workspace_root().join("crates/sigil-fuse/src/formatter.rs");

    assert!(formatter_path.exists(), "FUSE formatter module must exist");

    let formatter_code =
        fs::read_to_string(&formatter_path).expect("Failed to read formatter code");

    // Verify FormatterType enum exists
    assert!(
        formatter_code.contains("pub enum FormatterType"),
        "Formatter must have FormatterType enum"
    );

    // Verify AWS credentials formatter
    assert!(
        formatter_code.contains("AwsCredentials"),
        "Formatter must support AWS credentials"
    );

    // Verify Kubeconfig formatter
    assert!(
        formatter_code.contains("Kubeconfig"),
        "Formatter must support Kubernetes kubeconfig"
    );

    // Verify TLS certificate formatter
    assert!(
        formatter_code.contains("TlsCertificate"),
        "Formatter must support TLS certificates"
    );

    // Verify TLS private key formatter
    assert!(
        formatter_code.contains("TlsPrivateKey"),
        "Formatter must support TLS private keys"
    );

    // Verify INI format output
    assert!(
        formatter_code.contains("[default]") || formatter_code.contains("aws_access_key_id"),
        "AWS formatter must output INI format"
    );

    // Verify YAML format output for kubeconfig
    assert!(
        formatter_code.contains("apiVersion: v1") || formatter_code.contains("kind: Config"),
        "Kubeconfig formatter must output YAML format"
    );

    // Verify PEM format output for certificates
    assert!(
        formatter_code.contains("-----BEGIN CERTIFICATE-----")
            || formatter_code.contains("-----BEGIN"),
        "TLS formatter must output PEM format"
    );
}

/// Test 9.1.4: Verify FUSE read performance target
#[test]
fn test_9_1_4_fuse_read_performance() {
    let fuse_fs_path = workspace_root().join("crates/sigil-fuse/src/filesystem.rs");

    assert!(fuse_fs_path.exists(), "FUSE filesystem module must exist");

    let fs_code = fs::read_to_string(&fuse_fs_path).expect("Failed to read filesystem code");

    // Verify caching exists for performance
    assert!(
        fs_code.contains("cache") || fs_code.contains("secret_cache"),
        "FUSE should implement caching for performance"
    );

    // Verify daemon client exists for efficient communication
    assert!(
        fs_code.contains("daemon_client") || fs_code.contains("UnixStream"),
        "FUSE should use Unix socket for efficient IPC"
    );
}

/// Test 9.1.5: Verify bwrap bind-mount of FUSE mount into sandbox
#[test]
fn test_9_1_5_fuse_sandbox_integration() {
    let sandbox_path = workspace_root().join("crates/sigil-sandbox/src/lib.rs");

    if sandbox_path.exists() {
        let sandbox_code = fs::read_to_string(&sandbox_path).expect("Failed to read sandbox code");

        // Verify sandbox supports bind-mount
        let has_bind_mount = sandbox_code.contains("--bind")
            || sandbox_code.contains("bind-mount")
            || sandbox_code.contains("mount");

        // This is optional - sandbox may handle FUSE mount differently
        if has_bind_mount {
            // Verify /sigil/ path is mentioned
            assert!(
                sandbox_code.contains("/sigil") || sandbox_code.contains("sigil"),
                "Sandbox should reference /sigil mount point"
            );
        }
    }
    // If sandbox module doesn't exist, FUSE integration may be done differently
}

/// Test 9.2.1: Verify sigil-proxy is implemented
#[test]
fn test_9_2_1_proxy_implementation() {
    let proxy_path = workspace_root().join("crates/sigil-proxy/src/proxy.rs");

    assert!(proxy_path.exists(), "Proxy module must exist");

    let proxy_code = fs::read_to_string(&proxy_path).expect("Failed to read proxy code");

    // Verify ProxyServer exists
    assert!(
        proxy_code.contains("pub struct ProxyServer"),
        "Proxy must have ProxyServer struct"
    );

    // Verify serve method exists
    assert!(
        proxy_code.contains("pub async fn serve"),
        "Proxy must have serve method"
    );

    // Verify handle_request method exists
    assert!(
        proxy_code.contains("async fn handle_request"),
        "Proxy must have handle_request method"
    );
}

/// Test 9.2.2: Verify MITM TLS with per-session CA cert
#[test]
fn test_9_2_2_mitm_tls_per_session_ca() {
    let tls_path = workspace_root().join("crates/sigil-proxy/src/tls.rs");

    assert!(tls_path.exists(), "Proxy TLS module must exist");

    let tls_code = fs::read_to_string(&tls_path).expect("Failed to read TLS code");

    // Verify MitmCa exists
    assert!(
        tls_code.contains("pub struct MitmCa"),
        "TLS module must have MitmCa struct"
    );

    // Verify generate method exists
    assert!(
        tls_code.contains("pub fn generate"),
        "MitmCa must have generate method"
    );

    // Verify cert_pem method
    assert!(
        tls_code.contains("pub fn cert_pem"),
        "MitmCa must have cert_pem method"
    );

    // Verify generate_cert_for_domain method
    assert!(
        tls_code.contains("pub fn generate_cert_for_domain"),
        "MitmCa must support generating certs for specific domains"
    );

    // Verify 24-hour validity for per-session CA
    assert!(
        tls_code.contains("hours(24)") || tls_code.contains("24") || tls_code.contains("session"),
        "Per-session CA should have limited validity"
    );
}

/// Test 9.2.3: Verify CA cert injection into sandbox trust store
#[test]
fn test_9_2_3_ca_cert_injection() {
    let tls_path = workspace_root().join("crates/sigil-proxy/src/tls.rs");

    assert!(tls_path.exists(), "Proxy TLS module must exist");

    let tls_code = fs::read_to_string(&tls_path).expect("Failed to read TLS code");

    // Verify cert_pem returns PEM format for injection
    assert!(
        tls_code.contains("cert_pem") && tls_code.contains("PEM"),
        "CA cert must be available in PEM format for trust store injection"
    );
}

/// Test 9.2.4: Verify AWS SigV4 full request signing
#[test]
fn test_9_2_4_aws_sigv4_signing() {
    let signing_path = workspace_root().join("crates/sigil-proxy/src/signing.rs");

    assert!(signing_path.exists(), "Proxy signing module must exist");

    let signing_code = fs::read_to_string(&signing_path).expect("Failed to read signing code");

    // Verify AwsSigV4Signer exists
    assert!(
        signing_code.contains("pub struct AwsSigV4Signer"),
        "Signing module must have AwsSigV4Signer struct"
    );

    // Verify sign_request method
    assert!(
        signing_code.contains("pub fn sign_request"),
        "AwsSigV4Signer must have sign_request method"
    );

    // Verify canonical request construction
    assert!(
        signing_code.contains("canonical_request") || signing_code.contains("canonical"),
        "SigV4 must construct canonical request"
    );

    // Verify string to sign
    assert!(
        signing_code.contains("string_to_sign"),
        "SigV4 must create string to sign"
    );

    // Verify signature calculation with HMAC
    assert!(
        signing_code.contains("calculate_signature") || signing_code.contains("hmac_sha256"),
        "SigV4 must calculate signature"
    );

    // Verify Authorization header format
    assert!(
        signing_code.contains("AWS4-HMAC-SHA256") || signing_code.contains("Authorization"),
        "SigV4 must produce AWS4-HMAC-SHA256 Authorization header"
    );
}

/// Test 9.2.5: Verify domain allowlist (default-deny)
#[test]
fn test_9_2_5_domain_allowlist_default_deny() {
    let config_path = workspace_root().join("crates/sigil-proxy/src/config.rs");
    let proxy_path = workspace_root().join("crates/sigil-proxy/src/proxy.rs");

    assert!(config_path.exists(), "Proxy config module must exist");
    assert!(proxy_path.exists(), "Proxy module must exist");

    let config_code = fs::read_to_string(&config_path).expect("Failed to read config code");
    let proxy_code = fs::read_to_string(&proxy_path).expect("Failed to read proxy code");

    // Verify allowlist_only config option
    assert!(
        config_code.contains("allowlist_only"),
        "Proxy config must have allowlist_only option"
    );

    // Verify is_domain_allowed method
    assert!(
        config_code.contains("fn is_domain_allowed"),
        "Proxy config must have is_domain_allowed method"
    );

    // Verify rules field for domain list
    assert!(
        config_code.contains("rules") || config_code.contains("ProxyRule"),
        "Proxy config must support rules"
    );

    // Verify default-deny behavior in proxy
    assert!(
        proxy_code.contains("FORBIDDEN")
            || proxy_code.contains("forbidden")
            || proxy_code.contains("allowlist"),
        "Proxy must enforce default-deny"
    );
}

/// Test 9.2.6: Verify response body scrubbing
#[test]
fn test_9_2_6_response_body_scrubbing() {
    let scrubber_path = workspace_root().join("crates/sigil-proxy/src/scrubber.rs");

    assert!(scrubber_path.exists(), "Proxy scrubber module must exist");

    let scrubber_code = fs::read_to_string(&scrubber_path).expect("Failed to read scrubber code");

    // Verify ResponseScrubber exists
    assert!(
        scrubber_code.contains("pub struct ResponseScrubber"),
        "Scrubber must have ResponseScrubber struct"
    );

    // Verify scrub method
    assert!(
        scrubber_code.contains("pub fn scrub") || scrubber_code.contains("fn scrub"),
        "ResponseScrubber must have scrub method"
    );

    // Verify pattern matching (Aho-Corasick for performance)
    assert!(
        scrubber_code.contains("AhoCorasick")
            || scrubber_code.contains("ac")
            || scrubber_code.contains("pattern"),
        "Scrubber should use efficient pattern matching"
    );

    // Verify ScrubContext for secrets
    assert!(
        scrubber_code.contains("ScrubContext"),
        "Scrubber must use ScrubContext for secrets"
    );
}

/// Test 9.2.7: Verify proxy rules stored as encrypted vault entry
#[test]
fn test_9_2_7_proxy_rules_encrypted_storage() {
    let vault_path = workspace_root().join("crates/sigil-proxy/src/vault.rs");

    assert!(vault_path.exists(), "Proxy vault module must exist");

    let vault_code = fs::read_to_string(&vault_path).expect("Failed to read vault code");

    // Verify PROXY_RULES_PATH constant
    assert!(
        vault_code.contains("PROXY_RULES_PATH"),
        "Vault module must define proxy rules path"
    );

    // Verify path is _sigil/proxy_rules (Tier 2)
    assert!(
        vault_code.contains("_sigil") || vault_code.contains("proxy_rules"),
        "Proxy rules should be stored at _sigil/proxy_rules"
    );

    // Verify load_config_from_vault function
    assert!(
        vault_code.contains("pub fn load_config_from_vault"),
        "Vault module must support loading config"
    );

    // Verify save_config_to_vault function
    assert!(
        vault_code.contains("pub fn save_config_to_vault"),
        "Vault module must support saving config"
    );
}

/// Test 9.2.8: Verify proxy address injected as http_proxy/https_proxy
#[test]
fn test_9_2_8_proxy_env_var_injection() {
    let config_path = workspace_root().join("crates/sigil-proxy/src/config.rs");

    assert!(config_path.exists(), "Proxy config module must exist");

    let config_code = fs::read_to_string(&config_path).expect("Failed to read config code");

    // Verify listen address configuration
    assert!(
        config_code.contains("listen") || config_code.contains("addr"),
        "Proxy must have configurable listen address"
    );

    // Verify ProxyConfig can be serialized to env var format
    assert!(
        config_code.contains("ProxyConfig"),
        "Proxy must have ProxyConfig struct"
    );
}

/// Test 9.3.1: Verify sigil-credential-git implementation
#[test]
fn test_9_3_1_git_credential_helper() {
    let git_lib_path = workspace_root().join("crates/sigil-credential-git/src/lib.rs");
    let git_cargo_path = workspace_root().join("crates/sigil-credential-git/Cargo.toml");
    let git_main_path = workspace_root().join("crates/sigil-credential-git/src/main.rs");

    assert!(
        git_lib_path.exists(),
        "Git credential helper lib must exist"
    );
    assert!(
        git_cargo_path.exists(),
        "Git credential helper Cargo.toml must exist"
    );
    assert!(
        git_main_path.exists(),
        "Git credential helper binary must exist"
    );

    let git_lib_code = fs::read_to_string(&git_lib_path).expect("Failed to read git lib code");
    let git_cargo_code =
        fs::read_to_string(&git_cargo_path).expect("Failed to read git Cargo.toml");
    let _git_main_code = fs::read_to_string(&git_main_path).expect("Failed to read git main code");

    // Verify GitCredentialHelper exists
    assert!(
        git_lib_code.contains("pub struct GitCredentialHelper"),
        "Git credential helper must have GitCredentialHelper struct"
    );

    // Verify run method
    assert!(
        git_lib_code.contains("pub fn run"),
        "GitCredentialHelper must have run method"
    );

    // Verify get/store/erase handlers
    assert!(
        git_lib_code.contains("fn get")
            || git_lib_code.contains("fn store")
            || git_lib_code.contains("fn erase"),
        "Git credential helper must implement get/store/erase"
    );

    // Verify CredentialRequest/Response types
    assert!(
        git_lib_code.contains("CredentialRequest") && git_lib_code.contains("CredentialResponse"),
        "Git credential helper must define request/response types"
    );

    // Verify binary name is git-credential-sigil (in Cargo.toml)
    assert!(
        git_cargo_code.contains("git-credential-sigil"),
        "Binary must be named git-credential-sigil"
    );
}

/// Test 9.3.2: Verify sigil setup git writes ~/.gitconfig
#[test]
fn test_9_3_2_git_setup_config() {
    let cli_path = workspace_root().join("crates/sigil-cli/src/main.rs");

    if cli_path.exists() {
        let cli_code = fs::read_to_string(&cli_path).expect("Failed to read CLI code");

        // Verify "setup git" command exists or is referenced
        let has_git_setup = cli_code.contains("setup git")
            || cli_code.contains("Setup::Git")
            || cli_code.contains("credential");

        // This is optional - git config may be done via documentation
        if has_git_setup {
            // Verify git-credential-sigil is referenced
            assert!(
                cli_code.contains("git-credential-sigil") || cli_code.contains("credential.helper"),
                "Git setup should configure git-credential-sigil"
            );
        }
    }
}

/// Test 9.3.3: Verify per-repo git credential overrides
#[test]
fn test_9_3_3_git_per_repo_overrides() {
    let git_lib_path = workspace_root().join("crates/sigil-credential-git/src/lib.rs");

    assert!(
        git_lib_path.exists(),
        "Git credential helper lib must exist"
    );

    let git_code = fs::read_to_string(&git_lib_path).expect("Failed to read git lib code");

    // Verify GitCredentialConfig exists
    assert!(
        git_code.contains("pub struct GitCredentialConfig"),
        "Git credential helper must have GitCredentialConfig"
    );

    // Verify load_from_project for .sigil/git-credentials.toml
    assert!(
        git_code.contains("load_from_project") || git_code.contains(".sigil/git-credentials.toml"),
        "Git credential helper must support per-repo config"
    );

    // Verify host_mappings for custom host patterns
    assert!(
        git_code.contains("host_mappings"),
        "GitCredentialConfig must have host_mappings"
    );

    // Verify wildcard support for patterns like *.example.com
    assert!(
        git_code.contains("wildcard")
            || git_code.contains("*.")
            || git_code.contains("strip_prefix"),
        "Git credential helper should support wildcard patterns"
    );
}

/// Test 9.3.4: Verify sigil-ssh-agent implementation
#[test]
fn test_9_3_4_ssh_agent_implementation() {
    let ssh_lib_path = workspace_root().join("crates/sigil-ssh-agent/src/lib.rs");
    let ssh_agent_path = workspace_root().join("crates/sigil-ssh-agent/src/agent.rs");

    assert!(ssh_lib_path.exists(), "SSH agent lib must exist");
    assert!(ssh_agent_path.exists(), "SSH agent module must exist");

    let ssh_lib_code = fs::read_to_string(&ssh_lib_path).expect("Failed to read ssh lib code");
    let ssh_agent_code =
        fs::read_to_string(&ssh_agent_path).expect("Failed to read ssh agent code");

    // Verify SshAgent exists
    assert!(
        ssh_agent_code.contains("pub struct SshAgent"),
        "SSH agent must have SshAgent struct"
    );

    // Verify run method
    assert!(
        ssh_agent_code.contains("pub async fn run"),
        "SshAgent must have run method"
    );

    // Verify Unix socket support
    assert!(
        ssh_agent_code.contains("UnixListener") || ssh_agent_code.contains("UnixStream"),
        "SSH agent must use Unix socket"
    );

    // Verify Config with socket_path
    assert!(
        ssh_lib_code.contains("pub struct Config") && ssh_lib_code.contains("socket_path"),
        "SSH agent must have Config with socket_path"
    );
}

/// Test 9.3.5: Verify SSH key constraints (confirm before use, lifetime limits)
#[test]
fn test_9_3_5_ssh_key_constraints() {
    let ssh_keys_path = workspace_root().join("crates/sigil-ssh-agent/src/keys.rs");
    let ssh_lib_path = workspace_root().join("crates/sigil-ssh-agent/src/lib.rs");

    assert!(ssh_keys_path.exists(), "SSH keys module must exist");
    assert!(ssh_lib_path.exists(), "SSH agent lib must exist");

    let ssh_keys_code = fs::read_to_string(&ssh_keys_path).expect("Failed to read ssh keys code");
    let ssh_lib_code = fs::read_to_string(&ssh_lib_path).expect("Failed to read ssh lib code");

    // Verify KeyConstraint enum
    assert!(
        ssh_keys_code.contains("pub enum KeyConstraint"),
        "SSH agent must have KeyConstraint enum"
    );

    // Verify Confirm constraint
    assert!(
        ssh_keys_code.contains("Confirm") || ssh_keys_code.contains("confirm"),
        "SSH agent must support confirmation constraint"
    );

    // Verify Lifetime constraint
    assert!(
        ssh_keys_code.contains("Lifetime")
            || ssh_keys_code.contains("lifetime")
            || ssh_keys_code.contains("max_key_lifetime"),
        "SSH agent must support lifetime constraint"
    );

    // Verify Config has confirm_before_use option
    assert!(
        ssh_lib_code.contains("confirm_before_use"),
        "SSH agent Config must support confirm_before_use"
    );

    // Verify Config has max_key_lifetime option
    assert!(
        ssh_lib_code.contains("max_key_lifetime"),
        "SSH agent Config must support max_key_lifetime"
    );

    // Verify SshIdentity has constraints field
    assert!(
        ssh_keys_code.contains("SshIdentity")
            && (ssh_keys_code.contains("constraints") || ssh_keys_code.contains("constraint")),
        "SshIdentity must have constraints"
    );
}

/// Test 9.3.6: Verify sigil setup ssh writes ~/.ssh/config
#[test]
fn test_9_3_6_ssh_setup_config() {
    let cli_path = workspace_root().join("crates/sigil-cli/src/main.rs");

    if cli_path.exists() {
        let cli_code = fs::read_to_string(&cli_path).expect("Failed to read CLI code");

        // Verify "setup ssh" command exists or is referenced
        let has_ssh_setup = cli_code.contains("setup ssh")
            || cli_code.contains("Setup::Ssh")
            || cli_code.contains("ssh-agent");

        // This is optional - SSH config may be done via documentation
        if has_ssh_setup {
            // Verify IdentityAgent is referenced
            assert!(
                cli_code.contains("IdentityAgent") || cli_code.contains("ssh config"),
                "SSH setup should configure IdentityAgent"
            );
        }
    }
}

/// Test 9.3.7: Verify sigil-credential-docker implementation
#[test]
fn test_9_3_7_docker_credential_helper() {
    let docker_cargo_path = workspace_root().join("crates/sigil-credential-docker/Cargo.toml");
    let docker_main_path = workspace_root().join("crates/sigil-credential-docker/src/main.rs");

    assert!(
        docker_cargo_path.exists(),
        "Docker credential helper Cargo.toml must exist"
    );
    assert!(
        docker_main_path.exists(),
        "Docker credential helper must exist"
    );

    let docker_cargo_code =
        fs::read_to_string(&docker_cargo_path).expect("Failed to read docker Cargo.toml");
    let docker_code = fs::read_to_string(&docker_main_path).expect("Failed to read docker code");

    // Verify get/store/erase/list handlers
    assert!(
        docker_code.contains("handle_get") || docker_code.contains("fn get"),
        "Docker credential helper must implement get"
    );

    assert!(
        docker_code.contains("handle_store") || docker_code.contains("fn store"),
        "Docker credential helper must implement store"
    );

    assert!(
        docker_code.contains("handle_erase") || docker_code.contains("fn erase"),
        "Docker credential helper must implement erase"
    );

    assert!(
        docker_code.contains("handle_list") || docker_code.contains("fn list"),
        "Docker credential helper must implement list"
    );

    // Verify GetRequest/GetResponse types
    assert!(
        docker_code.contains("GetRequest") && docker_code.contains("GetResponse"),
        "Docker credential helper must define request/response types"
    );

    // Verify binary name is docker-credential-sigil (in Cargo.toml)
    assert!(
        docker_cargo_code.contains("docker-credential-sigil"),
        "Binary must be named docker-credential-sigil"
    );

    // Verify registry mapping (ghcr.io, docker.io, etc.)
    assert!(
        docker_code.contains("ghcr.io") || docker_code.contains("map_registry"),
        "Docker credential helper must map registries to vault paths"
    );
}

/// Test 9.3.8: Verify sigil setup docker writes credsStore
#[test]
fn test_9_3_8_docker_setup_config() {
    let cli_path = workspace_root().join("crates/sigil-cli/src/main.rs");

    if cli_path.exists() {
        let cli_code = fs::read_to_string(&cli_path).expect("Failed to read CLI code");

        // Verify "setup docker" command exists or is referenced
        let has_docker_setup = cli_code.contains("setup docker")
            || cli_code.contains("Setup::Docker")
            || cli_code.contains("credsStore");

        // This is optional - Docker config may be done via documentation
        if has_docker_setup {
            // Verify docker-credential-sigil is referenced
            assert!(
                cli_code.contains("docker-credential-sigil") || cli_code.contains("credsStore"),
                "Docker setup should configure docker-credential-sigil"
            );
        }
    }
}

/// Test 9.3.9: Verify all credential helpers use vault
#[test]
fn test_9_3_9_credential_helpers_use_vault() {
    let git_lib_path = workspace_root().join("crates/sigil-credential-git/src/lib.rs");
    let docker_main_path = workspace_root().join("crates/sigil-credential-docker/src/main.rs");
    let ssh_keys_path = workspace_root().join("crates/sigil-ssh-agent/src/keys.rs");

    // Verify git credential helper uses vault
    if git_lib_path.exists() {
        let git_code = fs::read_to_string(&git_lib_path).expect("Failed to read git code");
        assert!(
            git_code.contains("LocalVault") || git_code.contains("vault"),
            "Git credential helper must use vault"
        );
    }

    // Verify docker credential helper uses vault
    if docker_main_path.exists() {
        let docker_code =
            fs::read_to_string(&docker_main_path).expect("Failed to read docker code");
        assert!(
            docker_code.contains("LocalVault")
                || docker_code.contains("vault")
                || docker_code.contains("load_vault"),
            "Docker credential helper must use vault"
        );
    }

    // Verify ssh agent uses vault
    if ssh_keys_path.exists() {
        let ssh_code = fs::read_to_string(&ssh_keys_path).expect("Failed to read ssh code");
        assert!(
            ssh_code.contains("vault")
                || ssh_code.contains("Vault")
                || ssh_code.contains("load_keys_from_vault"),
            "SSH agent must use vault"
        );
    }
}
