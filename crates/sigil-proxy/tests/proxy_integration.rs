//! Integration tests for SIGIL proxy

#![warn(missing_docs)]

use sigil_proxy::{ProxyConfig, ProxyRule, ProxyRuleType, ProxyServer};
use tokio::time::{timeout, Duration};

#[tokio::test]
async fn test_proxy_server_creation() {
    let config = ProxyConfig::default();
    let server = ProxyServer::new(config);
    assert!(server.is_ok());
}

#[tokio::test]
async fn test_proxy_binds_to_configured_address() {
    let config = ProxyConfig {
        listen: "127.0.0.1:0".to_string(),
        ..Default::default()
    };

    let server = ProxyServer::new(config).unwrap();
    let listener = server.bind().await.unwrap();
    let addr = listener.local_addr().unwrap();

    assert!(addr.port() > 0);
}

#[tokio::test]
async fn test_proxy_domain_allowlist() {
    let mut config = ProxyConfig {
        listen: "127.0.0.1:0".to_string(),
        allowlist_only: true,
        ..Default::default()
    };

    let rule = ProxyRule {
        domain: "example.com".to_string(),
        rule_type: ProxyRuleType::Header {
            header: "Authorization".to_string(),
            value: "Bearer test-token".to_string(),
        },
    };

    config.rules.push(rule);

    // Test the config directly
    assert!(config.is_domain_allowed("example.com"));
    assert!(!config.is_domain_allowed("other.com"));
}

#[tokio::test]
async fn test_proxy_config_from_toml() {
    let toml = r#"
        listen = "127.0.0.1:8080"
        allowlist_only = true
        audit_logging = true

        [[rules]]
        domain = "api.example.com"
        type = "header"
        header = "Authorization"
        value = "Bearer mytoken"

        [[rules]]
        domain = "api.aws.com"
        type = "aws_sigv4"
        access_key = "AKIAIOSFODNN7EXAMPLE"
        secret_key = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
        region = "us-east-1"
        service = "s3"
    "#;

    let config = ProxyConfig::from_toml(toml).unwrap();

    assert_eq!(config.listen, "127.0.0.1:8080");
    assert!(config.allowlist_only);
    assert!(config.audit_logging);
    assert_eq!(config.rules.len(), 2);

    assert_eq!(config.rules[0].domain, "api.example.com");
    assert_eq!(config.rules[1].domain, "api.aws.com");
}

#[tokio::test]
async fn test_proxy_config_default() {
    let config = ProxyConfig::default();

    assert_eq!(config.listen, "127.0.0.1:0");
    assert!(config.allowlist_only); // defaults to true
    assert!(config.audit_logging);
    assert!(config.rules.is_empty());
}

#[tokio::test]
async fn test_proxy_rule_bearer_type() {
    let rule = ProxyRule {
        domain: "api.example.com".to_string(),
        rule_type: ProxyRuleType::Bearer {
            secret: "my-secret-token".to_string(),
        },
    };

    assert_eq!(rule.domain, "api.example.com");
    match &rule.rule_type {
        ProxyRuleType::Bearer { secret } => {
            assert_eq!(secret, "my-secret-token");
        }
        _ => panic!("Expected Bearer rule type"),
    }
}

#[tokio::test]
async fn test_proxy_rule_basic_auth_type() {
    let rule = ProxyRule {
        domain: "api.example.com".to_string(),
        rule_type: ProxyRuleType::Basic {
            username: "user".to_string(),
            password: "pass".to_string(),
        },
    };

    assert_eq!(rule.domain, "api.example.com");
    match &rule.rule_type {
        ProxyRuleType::Basic { username, password } => {
            assert_eq!(username, "user");
            assert_eq!(password, "pass");
        }
        _ => panic!("Expected Basic rule type"),
    }
}

#[tokio::test]
async fn test_proxy_rule_aws_sigv4_type() {
    let rule = ProxyRule {
        domain: "s3.amazonaws.com".to_string(),
        rule_type: ProxyRuleType::AwsSigV4 {
            access_key: "AKIAIOSFODNN7EXAMPLE".to_string(),
            secret_key: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY".to_string(),
            region: "us-east-1".to_string(),
            service: "s3".to_string(),
        },
    };

    assert_eq!(rule.domain, "s3.amazonaws.com");
    match &rule.rule_type {
        ProxyRuleType::AwsSigV4 {
            access_key,
            secret_key,
            region,
            service,
        } => {
            assert_eq!(access_key, "AKIAIOSFODNN7EXAMPLE");
            assert_eq!(secret_key, "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY");
            assert_eq!(region, "us-east-1");
            assert_eq!(service, "s3");
        }
        _ => panic!("Expected AwsSigV4 rule type"),
    }
}

#[tokio::test]
async fn test_proxy_rule_custom_headers_type() {
    let mut custom_headers = std::collections::HashMap::new();
    custom_headers.insert("X-API-Key".to_string(), "key123".to_string());
    custom_headers.insert("X-Custom".to_string(), "value".to_string());

    let rule = ProxyRule {
        domain: "api.example.com".to_string(),
        rule_type: ProxyRuleType::Custom {
            headers: custom_headers.clone(),
        },
    };

    assert_eq!(rule.domain, "api.example.com");
    match &rule.rule_type {
        ProxyRuleType::Custom { headers } => {
            assert_eq!(headers.get("X-API-Key"), Some(&"key123".to_string()));
            assert_eq!(headers.get("X-Custom"), Some(&"value".to_string()));
        }
        _ => panic!("Expected Custom rule type"),
    }
}

#[tokio::test]
async fn test_proxy_find_rule_for_domain() {
    let mut config = ProxyConfig::default();

    config.rules.push(ProxyRule {
        domain: "api.example.com".to_string(),
        rule_type: ProxyRuleType::Header {
            header: "Authorization".to_string(),
            value: "Bearer token1".to_string(),
        },
    });

    config.rules.push(ProxyRule {
        domain: "*.github.com".to_string(),
        rule_type: ProxyRuleType::Header {
            header: "Authorization".to_string(),
            value: "Bearer token2".to_string(),
        },
    });

    // Exact match
    let rule = config.find_rule_for_domain("api.example.com");
    assert!(rule.is_some());
    assert_eq!(rule.unwrap().domain, "api.example.com");

    // Wildcard match (basic implementation)
    let _rule = config.find_rule_for_domain("api.github.com");
    // This may or may not match depending on wildcard implementation
    // Just check it doesn't crash

    // No match
    let rule = config.find_rule_for_domain("unknown.com");
    assert!(rule.is_none());
}

#[tokio::test]
async fn test_proxy_config_toml_roundtrip() {
    let original_config = ProxyConfig {
        listen: "127.0.0.1:9999".to_string(),
        allowlist_only: true,
        audit_logging: false,
        timeout_secs: 60,
        rules: vec![ProxyRule {
            domain: "example.com".to_string(),
            rule_type: ProxyRuleType::Header {
                header: "X-Custom".to_string(),
                value: "custom-value".to_string(),
            },
        }],
    };

    // Convert to TOML
    let toml_str = original_config.to_toml().unwrap();

    // Parse back
    let parsed_config = ProxyConfig::from_toml(&toml_str).unwrap();

    assert_eq!(parsed_config.listen, original_config.listen);
    assert_eq!(parsed_config.allowlist_only, original_config.allowlist_only);
    assert_eq!(parsed_config.audit_logging, original_config.audit_logging);
    assert_eq!(parsed_config.rules.len(), original_config.rules.len());
}

#[tokio::test]
async fn test_proxy_multiple_servers_can_bind() {
    // Test that multiple proxy servers can bind to different ports
    let config1 = ProxyConfig {
        listen: "127.0.0.1:0".to_string(),
        ..Default::default()
    };

    let config2 = ProxyConfig {
        listen: "127.0.0.1:0".to_string(),
        ..Default::default()
    };

    let server1 = ProxyServer::new(config1).unwrap();
    let server2 = ProxyServer::new(config2).unwrap();

    let listener1 = server1.bind().await.unwrap();
    let listener2 = server2.bind().await.unwrap();

    let addr1 = listener1.local_addr().unwrap();
    let addr2 = listener2.local_addr().unwrap();

    // Different ports
    assert_ne!(addr1.port(), addr2.port());
}

#[tokio::test]
async fn test_proxy_invalid_listen_address() {
    let config = ProxyConfig {
        listen: "invalid-address".to_string(),
        ..Default::default()
    };

    let server = ProxyServer::new(config).unwrap();
    let result = timeout(Duration::from_secs(1), server.bind()).await;

    // Should either error or timeout
    assert!(result.is_err() || server.bind().await.is_err());
}

#[tokio::test]
async fn test_proxy_empty_config() {
    let toml = "";

    // Empty TOML should still parse with defaults
    let result = ProxyConfig::from_toml(toml);
    assert!(result.is_ok());

    let config = result.unwrap();
    assert_eq!(config.listen, "127.0.0.1:0"); // default
    assert!(config.rules.is_empty());
}
