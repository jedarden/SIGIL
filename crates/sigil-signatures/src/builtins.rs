//! Built-in command signatures for common CLI tools
//!
//! This module provides 50+ pre-configured signatures for popular
//! developer tools that require authentication.

use crate::config::{InjectionConfig, InjectionType, Signature, SignatureConfig};
use once_cell::sync::Lazy;
use sigil_core::Result;

/// Built-in signatures configuration
///
/// Contains signatures for 50+ common CLI tools organized by category.
pub static BUILTIN_SIGNATURES: Lazy<BuiltinSignatures> = Lazy::new(BuiltinSignatures::default);

/// Container for built-in signatures
pub struct BuiltinSignatures {
    config: SignatureConfig,
}

impl BuiltinSignatures {
    /// Get the signature configuration
    pub fn get_config(&self) -> Result<SignatureConfig> {
        Ok(self.config.clone())
    }
}

impl Default for BuiltinSignatures {
    fn default() -> Self {
        let mut config = SignatureConfig::new();

        // ===== Cloud Providers =====

        // AWS CLI
        config.add_signature(
            "aws".to_string(),
            Signature {
                match_pattern: r"^\s*aws\s".to_string(),
                inject: vec![
                    InjectionConfig {
                        injection_type: InjectionType::Env {
                            name: "AWS_ACCESS_KEY_ID".to_string(),
                        },
                        secret: "aws/access_key_id".to_string(),
                        optional: true,
                        cleanup: false,
                    },
                    InjectionConfig {
                        injection_type: InjectionType::Env {
                            name: "AWS_SECRET_ACCESS_KEY".to_string(),
                        },
                        secret: "aws/secret_access_key".to_string(),
                        optional: true,
                        cleanup: false,
                    },
                    InjectionConfig {
                        injection_type: InjectionType::Env {
                            name: "AWS_SESSION_TOKEN".to_string(),
                        },
                        secret: "aws/session_token".to_string(),
                        optional: true,
                        cleanup: false,
                    },
                    InjectionConfig {
                        injection_type: InjectionType::Env {
                            name: "AWS_DEFAULT_REGION".to_string(),
                        },
                        secret: "aws/region".to_string(),
                        optional: true,
                        cleanup: false,
                    },
                ],
                description: Some("AWS CLI - auto-inject AWS credentials".to_string()),
                enabled: true,
            },
        );

        // AWS CLI v2 (s3 subcommand specifically)
        config.add_signature(
            "aws-s3".to_string(),
            Signature {
                match_pattern: r"^\s*aws\s+s3\s".to_string(),
                inject: vec![InjectionConfig {
                    injection_type: InjectionType::Env {
                        name: "AWS_PROFILE".to_string(),
                    },
                    secret: "aws/profile".to_string(),
                    optional: true,
                    cleanup: false,
                }],
                description: Some("AWS S3 commands - profile support".to_string()),
                enabled: true,
            },
        );

        // Google Cloud (gcloud)
        config.add_signature(
            "gcloud".to_string(),
            Signature {
                match_pattern: r"^\s*gcloud\s".to_string(),
                inject: vec![
                    InjectionConfig {
                        injection_type: InjectionType::Env {
                            name: "CLOUDSDK_AUTH_ACCESS_TOKEN".to_string(),
                        },
                        secret: "gcloud/access_token".to_string(),
                        optional: true,
                        cleanup: false,
                    },
                    InjectionConfig {
                        injection_type: InjectionType::File {
                            path: "/tmp/gcloud_adc.json".to_string(),
                        },
                        secret: "gcloud/application_default_credentials".to_string(),
                        optional: true,
                        cleanup: true,
                    },
                ],
                description: Some("Google Cloud CLI".to_string()),
                enabled: true,
            },
        );

        // Google Cloud gsutil
        config.add_signature(
            "gsutil".to_string(),
            Signature {
                match_pattern: r"^\s*gsutil\s".to_string(),
                inject: vec![
                    InjectionConfig {
                        injection_type: InjectionType::Env {
                            name: "CLOUDSDK_AUTH_ACCESS_TOKEN".to_string(),
                        },
                        secret: "gcloud/access_token".to_string(),
                        optional: true,
                        cleanup: false,
                    },
                    InjectionConfig {
                        injection_type: InjectionType::Env {
                            name: "GSUTIL_PROJECT".to_string(),
                        },
                        secret: "gcloud/project_id".to_string(),
                        optional: true,
                        cleanup: false,
                    },
                ],
                description: Some("Google Cloud Storage utility".to_string()),
                enabled: true,
            },
        );

        // Azure CLI
        config.add_signature(
            "az".to_string(),
            Signature {
                match_pattern: r"^\s*az\s".to_string(),
                inject: vec![InjectionConfig {
                    injection_type: InjectionType::File {
                        path: "/tmp/az_access_tokens.json".to_string(),
                    },
                    secret: "azure/access_tokens".to_string(),
                    optional: true,
                    cleanup: true,
                }],
                description: Some("Azure CLI".to_string()),
                enabled: true,
            },
        );

        // IBM Cloud CLI
        config.add_signature(
            "ibmcloud".to_string(),
            Signature {
                match_pattern: r"^\s*ibmcloud\s".to_string(),
                inject: vec![InjectionConfig {
                    injection_type: InjectionType::Env {
                        name: "IBMCLOUD_API_KEY".to_string(),
                    },
                    secret: "ibmcloud/api_key".to_string(),
                    optional: true,
                    cleanup: false,
                }],
                description: Some("IBM Cloud CLI".to_string()),
                enabled: true,
            },
        );

        // Oracle Cloud CLI
        config.add_signature(
            "oci".to_string(),
            Signature {
                match_pattern: r"^\s*oci\s".to_string(),
                inject: vec![InjectionConfig {
                    injection_type: InjectionType::File {
                        path: "/tmp/oci_config".to_string(),
                    },
                    secret: "oraclecloud/config".to_string(),
                    optional: true,
                    cleanup: true,
                }],
                description: Some("Oracle Cloud Infrastructure CLI".to_string()),
                enabled: true,
            },
        );

        // DigitalOcean CLI (doctl)
        config.add_signature(
            "doctl".to_string(),
            Signature {
                match_pattern: r"^\s*doctl\s".to_string(),
                inject: vec![InjectionConfig {
                    injection_type: InjectionType::Env {
                        name: "DIGITALOCEAN_ACCESS_TOKEN".to_string(),
                    },
                    secret: "digitalocean/access_token".to_string(),
                    optional: true,
                    cleanup: false,
                }],
                description: Some("DigitalOcean CLI".to_string()),
                enabled: true,
            },
        );

        // Linode CLI
        config.add_signature(
            "linode-cli".to_string(),
            Signature {
                match_pattern: r"^\s*linode-cli\s".to_string(),
                inject: vec![InjectionConfig {
                    injection_type: InjectionType::Env {
                        name: "LINODE_CLI_TOKEN".to_string(),
                    },
                    secret: "linode/api_token".to_string(),
                    optional: true,
                    cleanup: false,
                }],
                description: Some("Linode CLI".to_string()),
                enabled: true,
            },
        );

        // Terraform
        config.add_signature(
            "terraform".to_string(),
            Signature {
                match_pattern: r"^\s*terraform\s".to_string(),
                inject: vec![
                    InjectionConfig {
                        injection_type: InjectionType::Env {
                            name: "TF_VAR_api_token".to_string(),
                        },
                        secret: "terraform/api_token".to_string(),
                        optional: true,
                        cleanup: false,
                    },
                    InjectionConfig {
                        injection_type: InjectionType::Env {
                            name: "TF_VAR_aws_access_key".to_string(),
                        },
                        secret: "aws/access_key_id".to_string(),
                        optional: true,
                        cleanup: false,
                    },
                    InjectionConfig {
                        injection_type: InjectionType::Env {
                            name: "TF_VAR_aws_secret_key".to_string(),
                        },
                        secret: "aws/secret_access_key".to_string(),
                        optional: true,
                        cleanup: false,
                    },
                ],
                description: Some("Terraform infrastructure as code".to_string()),
                enabled: true,
            },
        );

        // Packer
        config.add_signature(
            "packer".to_string(),
            Signature {
                match_pattern: r"^\s*packer\s".to_string(),
                inject: vec![InjectionConfig {
                    injection_type: InjectionType::Env {
                        name: "PACKER_AUTH_TOKEN".to_string(),
                    },
                    secret: "packer/auth_token".to_string(),
                    optional: true,
                    cleanup: false,
                }],
                description: Some("Packer image builder".to_string()),
                enabled: true,
            },
        );

        // ===== Container & Orchestration =====

        // Kubernetes (kubectl)
        config.add_signature(
            "kubectl".to_string(),
            Signature {
                match_pattern: r"^\s*kubectl\s".to_string(),
                inject: vec![InjectionConfig {
                    injection_type: InjectionType::Env {
                        name: "KUBECONFIG".to_string(),
                    },
                    secret: "k8s/kubeconfig".to_string(),
                    optional: true,
                    cleanup: false,
                }],
                description: Some("Kubernetes command-line tool".to_string()),
                enabled: true,
            },
        );

        // Helm
        config.add_signature(
            "helm".to_string(),
            Signature {
                match_pattern: r"^\s*helm\s".to_string(),
                inject: vec![
                    InjectionConfig {
                        injection_type: InjectionType::Env {
                            name: "KUBECONFIG".to_string(),
                        },
                        secret: "k8s/kubeconfig".to_string(),
                        optional: true,
                        cleanup: false,
                    },
                    InjectionConfig {
                        injection_type: InjectionType::Env {
                            name: "HELM_REPO_PASSWORD".to_string(),
                        },
                        secret: "helm/repo_password".to_string(),
                        optional: true,
                        cleanup: false,
                    },
                    InjectionConfig {
                        injection_type: InjectionType::Env {
                            name: "HELM_REPO_USERNAME".to_string(),
                        },
                        secret: "helm/repo_username".to_string(),
                        optional: true,
                        cleanup: false,
                    },
                ],
                description: Some("Helm package manager for Kubernetes".to_string()),
                enabled: true,
            },
        );

        // Docker (for registries requiring auth)
        config.add_signature(
            "docker".to_string(),
            Signature {
                match_pattern: r"^\s*docker\s+(pull|push|login|search)".to_string(),
                inject: vec![
                    InjectionConfig {
                        injection_type: InjectionType::Env {
                            name: "DOCKER_AUTH_TOKEN".to_string(),
                        },
                        secret: "docker/auth_token".to_string(),
                        optional: true,
                        cleanup: false,
                    },
                    InjectionConfig {
                        injection_type: InjectionType::File {
                            path: "/tmp/docker_config.json".to_string(),
                        },
                        secret: "docker/config_json".to_string(),
                        optional: true,
                        cleanup: true,
                    },
                ],
                description: Some("Docker container runtime".to_string()),
                enabled: true,
            },
        );

        // Podman
        config.add_signature(
            "podman".to_string(),
            Signature {
                match_pattern: r"^\s*podman\s+(pull|push|login|search)".to_string(),
                inject: vec![InjectionConfig {
                    injection_type: InjectionType::Env {
                        name: "REGISTRY_AUTH_FILE".to_string(),
                    },
                    secret: "podman/auth_file".to_string(),
                    optional: true,
                    cleanup: false,
                }],
                description: Some("Podman container runtime".to_string()),
                enabled: true,
            },
        );

        // ===== Version Control =====

        // GitHub CLI (gh)
        config.add_signature(
            "gh".to_string(),
            Signature {
                match_pattern: r"^\s*gh\s".to_string(),
                inject: vec![
                    InjectionConfig {
                        injection_type: InjectionType::Env {
                            name: "GH_TOKEN".to_string(),
                        },
                        secret: "github/token".to_string(),
                        optional: true,
                        cleanup: false,
                    },
                    InjectionConfig {
                        injection_type: InjectionType::Env {
                            name: "GH_ENTERPRISE_TOKEN".to_string(),
                        },
                        secret: "github/enterprise_token".to_string(),
                        optional: true,
                        cleanup: false,
                    },
                ],
                description: Some("GitHub CLI".to_string()),
                enabled: true,
            },
        );

        // GitLab CLI (glab)
        config.add_signature(
            "glab".to_string(),
            Signature {
                match_pattern: r"^\s*glab\s".to_string(),
                inject: vec![InjectionConfig {
                    injection_type: InjectionType::Env {
                        name: "GLAB_TOKEN".to_string(),
                    },
                    secret: "gitlab/token".to_string(),
                    optional: true,
                    cleanup: false,
                }],
                description: Some("GitLab CLI".to_string()),
                enabled: true,
            },
        );

        // Git with credential helper
        config.add_signature(
            "git-push".to_string(),
            Signature {
                match_pattern: r"^\s*git\s+push\s".to_string(),
                inject: vec![InjectionConfig {
                    injection_type: InjectionType::Env {
                        name: "GIT_ASKPASS".to_string(),
                    },
                    secret: "git/askpass_helper".to_string(),
                    optional: true,
                    cleanup: false,
                }],
                description: Some("Git push - credential helper".to_string()),
                enabled: true,
            },
        );

        // ===== CI/CD =====

        // GitHub Actions (gh CLI act)
        config.add_signature(
            "act".to_string(),
            Signature {
                match_pattern: r"^\s*act\s".to_string(),
                inject: vec![InjectionConfig {
                    injection_type: InjectionType::Env {
                        name: "GITHUB_TOKEN".to_string(),
                    },
                    secret: "github/token".to_string(),
                    optional: true,
                    cleanup: false,
                }],
                description: Some("Run GitHub Actions locally".to_string()),
                enabled: true,
            },
        );

        // Jenkins CLI
        config.add_signature(
            "jenkins-cli".to_string(),
            Signature {
                match_pattern: r"^\s*jenkins-cli\s".to_string(),
                inject: vec![
                    InjectionConfig {
                        injection_type: InjectionType::Env {
                            name: "JENKINS_TOKEN".to_string(),
                        },
                        secret: "jenkins/token".to_string(),
                        optional: true,
                        cleanup: false,
                    },
                    InjectionConfig {
                        injection_type: InjectionType::Env {
                            name: "JENKINS_USER_ID".to_string(),
                        },
                        secret: "jenkins/username".to_string(),
                        optional: true,
                        cleanup: false,
                    },
                ],
                description: Some("Jenkins CLI".to_string()),
                enabled: true,
            },
        );

        // ArgoCD CLI
        config.add_signature(
            "argocd".to_string(),
            Signature {
                match_pattern: r"^\s*argocd\s".to_string(),
                inject: vec![InjectionConfig {
                    injection_type: InjectionType::Env {
                        name: "ARGOCD_AUTH_TOKEN".to_string(),
                    },
                    secret: "argocd/auth_token".to_string(),
                    optional: true,
                    cleanup: false,
                }],
                description: Some("ArgoCD CLI".to_string()),
                enabled: true,
            },
        );

        // ===== Databases =====

        // PostgreSQL (psql)
        config.add_signature(
            "psql".to_string(),
            Signature {
                match_pattern: r"^\s*psql\s".to_string(),
                inject: vec![
                    InjectionConfig {
                        injection_type: InjectionType::Env {
                            name: "PGPASSWORD".to_string(),
                        },
                        secret: "db/postgres/password".to_string(),
                        optional: true,
                        cleanup: false,
                    },
                    InjectionConfig {
                        injection_type: InjectionType::Env {
                            name: "PGUSER".to_string(),
                        },
                        secret: "db/postgres/user".to_string(),
                        optional: true,
                        cleanup: false,
                    },
                ],
                description: Some("PostgreSQL interactive terminal".to_string()),
                enabled: true,
            },
        );

        // MySQL
        config.add_signature(
            "mysql".to_string(),
            Signature {
                match_pattern: r"^\s*mysql\s".to_string(),
                inject: vec![InjectionConfig {
                    injection_type: InjectionType::Env {
                        name: "MYSQL_PWD".to_string(),
                    },
                    secret: "db/mysql/password".to_string(),
                    optional: true,
                    cleanup: false,
                }],
                description: Some("MySQL client".to_string()),
                enabled: true,
            },
        );

        // MongoDB
        config.add_signature(
            "mongosh".to_string(),
            Signature {
                match_pattern: r"^\s*mongosh\s".to_string(),
                inject: vec![InjectionConfig {
                    injection_type: InjectionType::Env {
                        name: "MONGODB_URI".to_string(),
                    },
                    secret: "db/mongodb/connection_string".to_string(),
                    optional: true,
                    cleanup: false,
                }],
                description: Some("MongoDB Shell".to_string()),
                enabled: true,
            },
        );

        // Redis CLI
        config.add_signature(
            "redis-cli".to_string(),
            Signature {
                match_pattern: r"^\s*redis-cli\s".to_string(),
                inject: vec![InjectionConfig {
                    injection_type: InjectionType::Env {
                        name: "REDISCLI_AUTH".to_string(),
                    },
                    secret: "db/redis/password".to_string(),
                    optional: true,
                    cleanup: false,
                }],
                description: Some("Redis command-line interface".to_string()),
                enabled: true,
            },
        );

        // SQLite (no auth typically, but for encrypted databases)
        config.add_signature(
            "sqlcipher".to_string(),
            Signature {
                match_pattern: r"^\s*sqlcipher\s".to_string(),
                inject: vec![InjectionConfig {
                    injection_type: InjectionType::Env {
                        name: "SQLCIPHER_KEY".to_string(),
                    },
                    secret: "db/sqlcipher/key".to_string(),
                    optional: true,
                    cleanup: false,
                }],
                description: Some("SQLCipher encrypted database".to_string()),
                enabled: true,
            },
        );

        // ===== Monitoring & Observability =====

        // Prometheus CLI
        config.add_signature(
            "promtool".to_string(),
            Signature {
                match_pattern: r"^\s*promtool\s".to_string(),
                inject: vec![InjectionConfig {
                    injection_type: InjectionType::Env {
                        name: "PROMETHEUS_URL".to_string(),
                    },
                    secret: "prometheus/url".to_string(),
                    optional: true,
                    cleanup: false,
                }],
                description: Some("Prometheus utility tool".to_string()),
                enabled: true,
            },
        );

        // Grafana CLI
        config.add_signature(
            "grafana-cli".to_string(),
            Signature {
                match_pattern: r"^\s*grafana-cli\s".to_string(),
                inject: vec![InjectionConfig {
                    injection_type: InjectionType::Env {
                        name: "GRAFANA_API_KEY".to_string(),
                    },
                    secret: "grafana/api_key".to_string(),
                    optional: true,
                    cleanup: false,
                }],
                description: Some("Grafana CLI".to_string()),
                enabled: true,
            },
        );

        // Datadog CLI
        config.add_signature(
            "datadog-cli".to_string(),
            Signature {
                match_pattern: r"^\s*datadog-cli\s".to_string(),
                inject: vec![
                    InjectionConfig {
                        injection_type: InjectionType::Env {
                            name: "DD_API_KEY".to_string(),
                        },
                        secret: "datadog/api_key".to_string(),
                        optional: true,
                        cleanup: false,
                    },
                    InjectionConfig {
                        injection_type: InjectionType::Env {
                            name: "DD_APP_KEY".to_string(),
                        },
                        secret: "datadog/app_key".to_string(),
                        optional: true,
                        cleanup: false,
                    },
                ],
                description: Some("Datadog CLI".to_string()),
                enabled: true,
            },
        );

        // ===== Messaging & Queues =====

        // RabbitMQ CLI
        config.add_signature(
            "rabbitmqadmin".to_string(),
            Signature {
                match_pattern: r"^\s*rabbitmqadmin\s".to_string(),
                inject: vec![
                    InjectionConfig {
                        injection_type: InjectionType::Env {
                            name: "RABBITMQ_USERNAME".to_string(),
                        },
                        secret: "rabbitmq/username".to_string(),
                        optional: true,
                        cleanup: false,
                    },
                    InjectionConfig {
                        injection_type: InjectionType::Env {
                            name: "RABBITMQ_PASSWORD".to_string(),
                        },
                        secret: "rabbitmq/password".to_string(),
                        optional: true,
                        cleanup: false,
                    },
                ],
                description: Some("RabbitMQ management CLI".to_string()),
                enabled: true,
            },
        );

        // Kafka CLI
        config.add_signature(
            "kafka-console".to_string(),
            Signature {
                match_pattern: r"^\s*kafka-(console|producer|consumer)".to_string(),
                inject: vec![InjectionConfig {
                    injection_type: InjectionType::Env {
                        name: "KAFKA_SASL_JAAS_CONFIG".to_string(),
                    },
                    secret: "kafka/jaas_config".to_string(),
                    optional: true,
                    cleanup: false,
                }],
                description: Some("Kafka console tools".to_string()),
                enabled: true,
            },
        );

        // ===== API Tools =====

        // curl with API domains
        config.add_signature(
            "curl-api".to_string(),
            Signature {
                match_pattern:
                    r#"^\s*curl\s+.*https?://.*api\.|^\s*curl\s+.*-H\s+['"]Authorization"#
                        .to_string(),
                inject: vec![InjectionConfig {
                    injection_type: InjectionType::Header {
                        name: "Authorization".to_string(),
                        format: "Bearer {value}".to_string(),
                    },
                    secret: "api/default_token".to_string(),
                    optional: true,
                    cleanup: false,
                }],
                description: Some("curl with API endpoints".to_string()),
                enabled: true,
            },
        );

        // HTTPie
        config.add_signature(
            "http".to_string(),
            Signature {
                match_pattern: r#"^\s*https?\s"#.to_string(),
                inject: vec![InjectionConfig {
                    injection_type: InjectionType::Env {
                        name: "HTTPie_AUTH_TOKEN".to_string(),
                    },
                    secret: "httpie/auth_token".to_string(),
                    optional: true,
                    cleanup: false,
                }],
                description: Some("HTTPie - user-friendly cURL".to_string()),
                enabled: true,
            },
        );

        // wget
        config.add_signature(
            "wget-api".to_string(),
            Signature {
                match_pattern: r"^\s*wget\s+.*--header.*Authorization".to_string(),
                inject: vec![InjectionConfig {
                    injection_type: InjectionType::Header {
                        name: "Authorization".to_string(),
                        format: "Bearer {value}".to_string(),
                    },
                    secret: "api/default_token".to_string(),
                    optional: true,
                    cleanup: false,
                }],
                description: Some("wget with auth headers".to_string()),
                enabled: true,
            },
        );

        // GraphQL CLI
        config.add_signature(
            "gql".to_string(),
            Signature {
                match_pattern: r"^\s*gql\s".to_string(),
                inject: vec![InjectionConfig {
                    injection_type: InjectionType::Env {
                        name: "GRAPHQL_TOKEN".to_string(),
                    },
                    secret: "graphql/token".to_string(),
                    optional: true,
                    cleanup: false,
                }],
                description: Some("GraphQL CLI".to_string()),
                enabled: true,
            },
        );

        // ===== Package Managers =====

        // npm
        config.add_signature(
            "npm-publish".to_string(),
            Signature {
                match_pattern: r"^\s*npm\s+(publish|adduser|login)".to_string(),
                inject: vec![InjectionConfig {
                    injection_type: InjectionType::Env {
                        name: "NPM_TOKEN".to_string(),
                    },
                    secret: "npm/token".to_string(),
                    optional: true,
                    cleanup: false,
                }],
                description: Some("npm package manager (auth required)".to_string()),
                enabled: true,
            },
        );

        // yarn
        config.add_signature(
            "yarn-publish".to_string(),
            Signature {
                match_pattern: r"^\s*yarn\s+(publish|publish)".to_string(),
                inject: vec![InjectionConfig {
                    injection_type: InjectionType::Env {
                        name: "NPM_TOKEN".to_string(),
                    },
                    secret: "npm/token".to_string(),
                    optional: true,
                    cleanup: false,
                }],
                description: Some("Yarn package manager (auth required)".to_string()),
                enabled: true,
            },
        );

        // Python pip
        config.add_signature(
            "pip-upload".to_string(),
            Signature {
                match_pattern: r"^\s*pip\s+(upload|upload)".to_string(),
                inject: vec![InjectionConfig {
                    injection_type: InjectionType::Env {
                        name: "PYPI_TOKEN".to_string(),
                    },
                    secret: "pypi/token".to_string(),
                    optional: true,
                    cleanup: false,
                }],
                description: Some("pip package upload".to_string()),
                enabled: true,
            },
        );

        // Ruby gems
        config.add_signature(
            "gem-push".to_string(),
            Signature {
                match_pattern: r"^\s*gem\s+(push|push)".to_string(),
                inject: vec![InjectionConfig {
                    injection_type: InjectionType::Env {
                        name: "GEM_HOST_API_KEY".to_string(),
                    },
                    secret: "rubygems/api_key".to_string(),
                    optional: true,
                    cleanup: false,
                }],
                description: Some("RubyGems push".to_string()),
                enabled: true,
            },
        );

        // Cargo (Rust)
        config.add_signature(
            "cargo-publish".to_string(),
            Signature {
                match_pattern: r"^\s*cargo\s+publish\s".to_string(),
                inject: vec![InjectionConfig {
                    injection_type: InjectionType::Env {
                        name: "CARGO_REGISTRY_TOKEN".to_string(),
                    },
                    secret: "crates/token".to_string(),
                    optional: true,
                    cleanup: false,
                }],
                description: Some("Cargo package publish".to_string()),
                enabled: true,
            },
        );

        // Docker Hub login
        config.add_signature(
            "docker-login".to_string(),
            Signature {
                match_pattern: r"^\s*docker\s+login\s".to_string(),
                inject: vec![
                    InjectionConfig {
                        injection_type: InjectionType::Env {
                            name: "DOCKER_PASSWORD".to_string(),
                        },
                        secret: "docker/password".to_string(),
                        optional: true,
                        cleanup: false,
                    },
                    InjectionConfig {
                        injection_type: InjectionType::Env {
                            name: "DOCKER_USERNAME".to_string(),
                        },
                        secret: "docker/username".to_string(),
                        optional: true,
                        cleanup: false,
                    },
                ],
                description: Some("Docker registry login".to_string()),
                enabled: true,
            },
        );

        // ===== SSH & Remote Access =====

        // scp
        config.add_signature(
            "scp".to_string(),
            Signature {
                match_pattern: r"^\s*scp\s".to_string(),
                inject: vec![InjectionConfig {
                    injection_type: InjectionType::File {
                        path: "/tmp/ssh_id_sigil".to_string(),
                    },
                    secret: "ssh/private_key".to_string(),
                    optional: true,
                    cleanup: true,
                }],
                description: Some("Secure copy (SSH)".to_string()),
                enabled: true,
            },
        );

        // rsync
        config.add_signature(
            "rsync".to_string(),
            Signature {
                match_pattern: r"^\s*rsync\s+.*-e\s+ssh".to_string(),
                inject: vec![InjectionConfig {
                    injection_type: InjectionType::Env {
                        name: "RSYNC_PASSWORD".to_string(),
                    },
                    secret: "rsync/password".to_string(),
                    optional: true,
                    cleanup: false,
                }],
                description: Some("rsync with SSH".to_string()),
                enabled: true,
            },
        );

        // mosh
        config.add_signature(
            "mosh".to_string(),
            Signature {
                match_pattern: r"^\s*mosh\s".to_string(),
                inject: vec![InjectionConfig {
                    injection_type: InjectionType::File {
                        path: "/tmp/mosh_ssh_key".to_string(),
                    },
                    secret: "ssh/private_key".to_string(),
                    optional: true,
                    cleanup: true,
                }],
                description: Some("mosh mobile shell".to_string()),
                enabled: true,
            },
        );

        // ===== CDN & Edge =====

        // Cloudflare Wrangler
        config.add_signature(
            "wrangler".to_string(),
            Signature {
                match_pattern: r"^\s*wrangler\s".to_string(),
                inject: vec![
                    InjectionConfig {
                        injection_type: InjectionType::Env {
                            name: "CLOUDFLARE_API_TOKEN".to_string(),
                        },
                        secret: "cloudflare/api_token".to_string(),
                        optional: true,
                        cleanup: false,
                    },
                    InjectionConfig {
                        injection_type: InjectionType::Env {
                            name: "CLOUDFLARE_ACCOUNT_ID".to_string(),
                        },
                        secret: "cloudflare/account_id".to_string(),
                        optional: true,
                        cleanup: false,
                    },
                ],
                description: Some("Cloudflare Workers CLI".to_string()),
                enabled: true,
            },
        );

        // Vercel CLI
        config.add_signature(
            "vercel".to_string(),
            Signature {
                match_pattern: r"^\s*vercel\s".to_string(),
                inject: vec![InjectionConfig {
                    injection_type: InjectionType::Env {
                        name: "VERCEL_TOKEN".to_string(),
                    },
                    secret: "vercel/token".to_string(),
                    optional: true,
                    cleanup: false,
                }],
                description: Some("Vercel deployment CLI".to_string()),
                enabled: true,
            },
        );

        // Netlify CLI
        config.add_signature(
            "netlify".to_string(),
            Signature {
                match_pattern: r"^\s*netlify\s".to_string(),
                inject: vec![InjectionConfig {
                    injection_type: InjectionType::Env {
                        name: "NETLIFY_AUTH_TOKEN".to_string(),
                    },
                    secret: "netlify/token".to_string(),
                    optional: true,
                    cleanup: false,
                }],
                description: Some("Netlify CLI".to_string()),
                enabled: true,
            },
        );

        // ===== Security & Crypto =====

        // HashiCorp Vault
        config.add_signature(
            "vault".to_string(),
            Signature {
                match_pattern: r"^\s*vault\s".to_string(),
                inject: vec![
                    InjectionConfig {
                        injection_type: InjectionType::Env {
                            name: "VAULT_TOKEN".to_string(),
                        },
                        secret: "vault/token".to_string(),
                        optional: true,
                        cleanup: false,
                    },
                    InjectionConfig {
                        injection_type: InjectionType::Env {
                            name: "VAULT_ADDR".to_string(),
                        },
                        secret: "vault/addr".to_string(),
                        optional: true,
                        cleanup: false,
                    },
                ],
                description: Some("HashiCorp Vault CLI".to_string()),
                enabled: true,
            },
        );

        // AWS Secrets Manager extension
        config.add_signature(
            "aws-secrets".to_string(),
            Signature {
                match_pattern: r"^\s*aws\s+secretsmanager".to_string(),
                inject: vec![InjectionConfig {
                    injection_type: InjectionType::Env {
                        name: "AWS_SECRET_ID".to_string(),
                    },
                    secret: "aws/secrets/id".to_string(),
                    optional: true,
                    cleanup: false,
                }],
                description: Some("AWS Secrets Manager".to_string()),
                enabled: true,
            },
        );

        // 1Password CLI
        config.add_signature(
            "op".to_string(),
            Signature {
                match_pattern: r"^\s*op\s".to_string(),
                inject: vec![InjectionConfig {
                    injection_type: InjectionType::Env {
                        name: "OP_SESSION_".to_string(),
                    },
                    secret: "1password/session_token".to_string(),
                    optional: true,
                    cleanup: false,
                }],
                description: Some("1Password CLI".to_string()),
                enabled: true,
            },
        );

        // ===== Developer Tools =====

        // Stripe CLI
        config.add_signature(
            "stripe".to_string(),
            Signature {
                match_pattern: r"^\s*stripe\s".to_string(),
                inject: vec![InjectionConfig {
                    injection_type: InjectionType::Env {
                        name: "STRIPE_API_KEY".to_string(),
                    },
                    secret: "stripe/api_key".to_string(),
                    optional: true,
                    cleanup: false,
                }],
                description: Some("Stripe payment CLI".to_string()),
                enabled: true,
            },
        );

        // Twilio CLI
        config.add_signature(
            "twilio".to_string(),
            Signature {
                match_pattern: r"^\s*twilio\s".to_string(),
                inject: vec![
                    InjectionConfig {
                        injection_type: InjectionType::Env {
                            name: "TWILIO_ACCOUNT_SID".to_string(),
                        },
                        secret: "twilio/account_sid".to_string(),
                        optional: true,
                        cleanup: false,
                    },
                    InjectionConfig {
                        injection_type: InjectionType::Env {
                            name: "TWILIO_AUTH_TOKEN".to_string(),
                        },
                        secret: "twilio/auth_token".to_string(),
                        optional: true,
                        cleanup: false,
                    },
                ],
                description: Some("Twilio communications CLI".to_string()),
                enabled: true,
            },
        );

        // SendGrid CLI
        config.add_signature(
            "sendgrid".to_string(),
            Signature {
                match_pattern: r"^\s*sendgrid\s".to_string(),
                inject: vec![InjectionConfig {
                    injection_type: InjectionType::Env {
                        name: "SENDGRID_API_KEY".to_string(),
                    },
                    secret: "sendgrid/api_key".to_string(),
                    optional: true,
                    cleanup: false,
                }],
                description: Some("SendGrid email CLI".to_string()),
                enabled: true,
            },
        );

        // Slack CLI
        config.add_signature(
            "slack".to_string(),
            Signature {
                match_pattern: r"^\s*slack\s".to_string(),
                inject: vec![InjectionConfig {
                    injection_type: InjectionType::Env {
                        name: "SLACK_TOKEN".to_string(),
                    },
                    secret: "slack/token".to_string(),
                    optional: true,
                    cleanup: false,
                }],
                description: Some("Slack CLI".to_string()),
                enabled: true,
            },
        );

        // Auth0 CLI
        config.add_signature(
            "a0cli".to_string(),
            Signature {
                match_pattern: r"^\s*a0cli\s".to_string(),
                inject: vec![InjectionConfig {
                    injection_type: InjectionType::Env {
                        name: "AUTH0_API_TOKEN".to_string(),
                    },
                    secret: "auth0/api_token".to_string(),
                    optional: true,
                    cleanup: false,
                }],
                description: Some("Auth0 management CLI".to_string()),
                enabled: true,
            },
        );

        // Heroku CLI
        config.add_signature(
            "heroku".to_string(),
            Signature {
                match_pattern: r"^\s*heroku\s".to_string(),
                inject: vec![InjectionConfig {
                    injection_type: InjectionType::Env {
                        name: "HEROKU_API_KEY".to_string(),
                    },
                    secret: "heroku/api_key".to_string(),
                    optional: true,
                    cleanup: false,
                }],
                description: Some("Heroku platform CLI".to_string()),
                enabled: true,
            },
        );

        // ===== Data & Analytics =====

        // Snowflake CLI
        config.add_signature(
            "snowsql".to_string(),
            Signature {
                match_pattern: r"^\s*snowsql\s".to_string(),
                inject: vec![InjectionConfig {
                    injection_type: InjectionType::Env {
                        name: "SNOWSQL_PWD".to_string(),
                    },
                    secret: "snowflake/password".to_string(),
                    optional: true,
                    cleanup: false,
                }],
                description: Some("Snowflake data warehouse CLI".to_string()),
                enabled: true,
            },
        );

        // Databricks CLI
        config.add_signature(
            "databricks".to_string(),
            Signature {
                match_pattern: r"^\s*databricks\s".to_string(),
                inject: vec![InjectionConfig {
                    injection_type: InjectionType::Env {
                        name: "DATABRICKS_TOKEN".to_string(),
                    },
                    secret: "databricks/token".to_string(),
                    optional: true,
                    cleanup: false,
                }],
                description: Some("Databricks CLI".to_string()),
                enabled: true,
            },
        );

        // ===== Custom Service Signatures =====

        // Generic API call detection
        config.add_signature(
            "generic-api".to_string(),
            Signature {
                match_pattern: r"api\.|/api/v\d+|:\d{2,5}/v\d+".to_string(),
                inject: vec![InjectionConfig {
                    injection_type: InjectionType::Header {
                        name: "X-API-Key".to_string(),
                        format: "{value}".to_string(),
                    },
                    secret: "api/default_key".to_string(),
                    optional: true,
                    cleanup: false,
                }],
                description: Some("Generic API endpoint detection".to_string()),
                enabled: true,
            },
        );

        // Service-specific domain detection
        config.add_signature(
            "kalshi-api".to_string(),
            Signature {
                match_pattern: r"api\.kalshi\.com|trade\.kalshi\.com".to_string(),
                inject: vec![InjectionConfig {
                    injection_type: InjectionType::Header {
                        name: "Authorization".to_string(),
                        format: "Bearer {value}".to_string(),
                    },
                    secret: "kalshi/api_key".to_string(),
                    optional: true,
                    cleanup: false,
                }],
                description: Some("Kalshi trading platform API".to_string()),
                enabled: true,
            },
        );

        Self { config }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_builtin_signatures_count() {
        let config = BUILTIN_SIGNATURES.get_config().unwrap();
        // Verify we have at least 50 signatures
        assert!(config.get_all().len() >= 50);
    }

    #[test]
    fn test_aws_signature() {
        let config = BUILTIN_SIGNATURES.get_config().unwrap();
        let all = config.get_all();
        let aws_sig = all.iter().find(|(name, _)| name == "aws");
        assert!(aws_sig.is_some());
        let (_, sig) = aws_sig.unwrap();
        assert!(sig.matches("aws s3 ls").unwrap());
    }

    #[test]
    fn test_kubectl_signature() {
        let config = BUILTIN_SIGNATURES.get_config().unwrap();
        let all = config.get_all();
        let kubectl_sig = all.iter().find(|(name, _)| name == "kubectl");
        assert!(kubectl_sig.is_some());
        let (_, sig) = kubectl_sig.unwrap();
        assert!(sig.matches("kubectl get pods").unwrap());
    }

    #[test]
    fn test_github_signature() {
        let config = BUILTIN_SIGNATURES.get_config().unwrap();
        let all = config.get_all();
        let gh_sig = all.iter().find(|(name, _)| name == "gh");
        assert!(gh_sig.is_some());
        let (_, sig) = gh_sig.unwrap();
        assert!(sig.matches("gh pr list").unwrap());
    }

    #[test]
    fn test_psql_signature() {
        let config = BUILTIN_SIGNATURES.get_config().unwrap();
        let all = config.get_all();
        let psql_sig = all.iter().find(|(name, _)| name == "psql");
        assert!(psql_sig.is_some());
        let (_, sig) = psql_sig.unwrap();
        assert!(sig.matches("psql -h localhost").unwrap());
    }
}
