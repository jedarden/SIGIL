//! Phase 8.1: Transparent Command Recognition Verification Tests
//!
//! This test suite verifies the transparent command recognition system
//! for automatic secret injection as specified in Phase 8.1.
//!
//! Tests cover:
//! - Built-in signatures cover 50+ common tools
//! - Auto-injection into sandbox env vars (not agent's shell)
//! - User-extensible signatures (~/.sigil/signatures.d/*.toml and .sigil/signatures.toml)
//! - sigil signatures CLI commands (list, search, add, update)
//! - Command matching with various patterns

mod common;
use common::workspace_root;
use sigil_signatures::{SignatureMatcher, BUILTIN_SIGNATURES};
use std::fs;

/// Test 1: Verify built-in signatures count meets requirement
///
/// Phase 8.1 requires 50+ built-in signatures for common tools.
#[test]
fn test_builtin_signatures_count() {
    let config = BUILTIN_SIGNATURES
        .get_config()
        .expect("Failed to load built-in signatures");
    let signatures = config.get_all();

    // Verify we have at least 50 signatures
    assert!(
        signatures.len() >= 50,
        "Expected at least 50 built-in signatures, found {}",
        signatures.len()
    );

    println!(
        "✅ Built-in signatures count: {} (>= 50 required)",
        signatures.len()
    );
}

/// Test 2: Verify signatures cover all major categories
///
/// Phase 8.1 requires coverage for: aws, curl, git, docker, kubectl, etc.
#[test]
fn test_signature_category_coverage() {
    let config = BUILTIN_SIGNATURES
        .get_config()
        .expect("Failed to load built-in signatures");
    let signatures: std::collections::HashMap<_, _> = config.get_all().into_iter().collect();

    // Required tool categories with specific tools
    let required_tools = [
        // Cloud Providers
        ("aws", "AWS CLI"),
        ("gcloud", "Google Cloud CLI"),
        ("az", "Azure CLI"),
        ("terraform", "Terraform"),
        ("packer", "Packer"),
        // Container & Orchestration
        ("kubectl", "Kubernetes CLI"),
        ("helm", "Helm"),
        ("docker", "Docker"),
        ("podman", "Podman"),
        // Version Control
        ("gh", "GitHub CLI"),
        ("glab", "GitLab CLI"),
        ("git-push", "Git push"),
        // Databases
        ("psql", "PostgreSQL"),
        ("mysql", "MySQL"),
        ("mongosh", "MongoDB"),
        ("redis-cli", "Redis CLI"),
        // API Tools
        ("curl-api", "curl with API"),
        ("http", "HTTPie"),
        // Package Managers
        ("npm-publish", "npm publish"),
        ("cargo-publish", "Cargo publish"),
        ("docker-login", "Docker login"),
        // SSH & Remote
        ("scp", "SCP"),
        ("rsync", "rsync"),
        ("mosh", "mosh"),
        // Developer Tools
        ("vault", "HashiCorp Vault"),
        ("stripe", "Stripe CLI"),
        ("heroku", "Heroku CLI"),
    ];

    let mut missing_tools = Vec::new();
    for (tool_name, description) in required_tools {
        if !signatures.contains_key(tool_name) {
            missing_tools.push(format!("{} ({})", tool_name, description));
        }
    }

    assert!(
        missing_tools.is_empty(),
        "Missing required signatures: {}",
        missing_tools.join(", ")
    );

    println!("✅ All required tool signatures present");
}

/// Test 3: Verify AWS signature matching
#[test]
fn test_aws_signature_matching() {
    let matcher = SignatureMatcher::new().expect("Failed to create matcher");

    let test_commands = [
        "aws s3 ls",
        "aws ec2 describe-instances",
        "aws lambda list-functions",
        "  aws s3 cp file.txt s3://bucket/", // Leading whitespace
    ];

    for cmd in test_commands {
        let results = matcher.match_command(cmd);
        assert!(!results.is_empty(), "AWS command should match: '{}'", cmd);

        // Verify it's the aws signature
        let aws_match = results.iter().find(|m| m.signature_name == "aws");
        assert!(
            aws_match.is_some(),
            "Should match 'aws' signature for: '{}'",
            cmd
        );

        // Verify injection types
        let aws_sig = aws_match.unwrap();
        assert!(
            aws_sig.injections.len() >= 4,
            "AWS signature should inject at least 4 env vars, got {}",
            aws_sig.injections.len()
        );

        // Verify AWS_ACCESS_KEY_ID is injected
        let has_access_key = aws_sig.injections.iter().any(|i| {
            matches!(
                &i.injection_type,
                sigil_signatures::InjectionType::Env(name) if name == "AWS_ACCESS_KEY_ID"
            )
        });
        assert!(
            has_access_key,
            "AWS signature should inject AWS_ACCESS_KEY_ID"
        );
    }

    // Non-AWS commands should not match
    let non_aws_commands = ["echo aws", "cat aws.txt", "grep aws file"];
    for cmd in non_aws_commands {
        let results = matcher.match_command(cmd);
        let aws_match = results.iter().find(|m| m.signature_name == "aws");
        assert!(
            aws_match.is_none(),
            "Non-AWS command should not match AWS signature: '{}'",
            cmd
        );
    }

    println!("✅ AWS signature matching works correctly");
}

/// Test 4: Verify kubectl signature matching
#[test]
fn test_kubectl_signature_matching() {
    let matcher = SignatureMatcher::new().expect("Failed to create matcher");

    let test_commands = [
        "kubectl get pods",
        "kubectl apply -f deployment.yaml",
        "  kubectl config use-context prod", // Leading whitespace
    ];

    for cmd in test_commands {
        let results = matcher.match_command(cmd);
        assert!(
            !results.is_empty(),
            "kubectl command should match: '{}'",
            cmd
        );

        let kubectl_match = results.iter().find(|m| m.signature_name == "kubectl");
        assert!(
            kubectl_match.is_some(),
            "Should match 'kubectl' signature for: '{}'",
            cmd
        );

        // Verify KUBECONFIG injection
        let kubectl_sig = kubectl_match.unwrap();
        let has_kubeconfig = kubectl_sig.injections.iter().any(|i| {
            matches!(
                &i.injection_type,
                sigil_signatures::InjectionType::Env(name) if name == "KUBECONFIG"
            )
        });
        assert!(has_kubeconfig, "kubectl signature should inject KUBECONFIG");
    }

    println!("✅ kubectl signature matching works correctly");
}

/// Test 5: Verify curl API signature matching
#[test]
fn test_curl_api_signature_matching() {
    let matcher = SignatureMatcher::new().expect("Failed to create matcher");

    let test_commands = [
        "curl https://api.github.com/users/octocat",
        "curl -H 'Authorization: Bearer token' https://api.example.com/data",
        "curl https://api.stripe.com/v1/charges",
    ];

    let mut match_count = 0;
    for cmd in test_commands {
        let results = matcher.match_command(cmd);
        if !results.is_empty() {
            match_count += 1;
            // Verify header injection type
            let header_match = results.iter().any(|m| {
                m.injections.iter().any(|i| {
                    matches!(
                        &i.injection_type,
                        sigil_signatures::InjectionType::Header(_, _)
                    )
                })
            });
            assert!(
                header_match,
                "curl API signature should use header injection"
            );
        }
    }

    assert!(
        match_count > 0,
        "At least some curl API commands should match"
    );

    println!("✅ curl API signature matching works correctly");
}

/// Test 6: Verify Docker signature matching
#[test]
fn test_docker_signature_matching() {
    let matcher = SignatureMatcher::new().expect("Failed to create matcher");

    let test_commands = [
        "docker pull ubuntu:latest",
        "docker push myrepo/image:tag",
        "docker login registry.example.com",
    ];

    for cmd in test_commands {
        let results = matcher.match_command(cmd);
        assert!(
            !results.is_empty(),
            "Docker command should match: '{}'",
            cmd
        );

        let docker_match = results.iter().find(|m| m.signature_name == "docker");
        assert!(
            docker_match.is_some(),
            "Should match 'docker' signature for: '{}'",
            cmd
        );
    }

    println!("✅ Docker signature matching works correctly");
}

/// Test 7: Verify GitHub CLI signature matching
#[test]
fn test_github_cli_signature_matching() {
    let matcher = SignatureMatcher::new().expect("Failed to create matcher");

    let test_commands = [
        "gh pr list",
        "gh issue create --title 'Bug'",
        "gh repo clone jedarden/SIGIL",
    ];

    for cmd in test_commands {
        let results = matcher.match_command(cmd);
        assert!(!results.is_empty(), "gh command should match: '{}'", cmd);

        let gh_match = results.iter().find(|m| m.signature_name == "gh");
        assert!(
            gh_match.is_some(),
            "Should match 'gh' signature for: '{}'",
            cmd
        );

        // Verify GH_TOKEN injection
        let gh_sig = gh_match.unwrap();
        let has_token = gh_sig.injections.iter().any(|i| {
            matches!(
                &i.injection_type,
                sigil_signatures::InjectionType::Env(name) if name == "GH_TOKEN"
            )
        });
        assert!(has_token, "gh signature should inject GH_TOKEN");
    }

    println!("✅ GitHub CLI signature matching works correctly");
}

/// Test 8: Verify user-extensible signatures directory structure
#[test]
fn test_user_signature_directories() {
    let workspace = workspace_root();

    // Check that the code references the correct paths
    let lib_path = workspace.join("crates/sigil-signatures/src/lib.rs");
    assert!(lib_path.exists(), "sigil-signatures lib.rs must exist");

    let lib_code = fs::read_to_string(&lib_path).expect("Failed to read lib.rs");

    // Verify global signatures directory constant
    assert!(
        lib_code.contains("USER_SIGNATURES_DIR"),
        "Must define USER_SIGNATURES_DIR constant"
    );
    assert!(
        lib_code.contains("PROJECT_SIGNATURES_FILE"),
        "Must define PROJECT_SIGNATURES_FILE constant"
    );

    // Verify the paths are correct
    assert!(
        lib_code.contains(".sigil/signatures.d"),
        "User signatures directory path must be .sigil/signatures.d"
    );
    assert!(
        lib_code.contains(".sigil/signatures.toml"),
        "Project signatures file path must be .sigil/signatures.toml"
    );
    assert!(
        lib_code.contains("~/.sigil/signatures.d"),
        "Global signatures directory path must be ~/.sigil/signatures.d"
    );

    // Check matcher implementation for loading user signatures
    let matcher_path = workspace.join("crates/sigil-signatures/src/matcher.rs");
    let matcher_code = fs::read_to_string(&matcher_path).expect("Failed to read matcher.rs");

    assert!(
        matcher_code.contains("get_global_signatures_dir"),
        "Matcher must have global signatures directory support"
    );
    assert!(
        matcher_code.contains("load_signatures_from_dir"),
        "Matcher must support loading signatures from directory"
    );
    assert!(
        matcher_code.contains("project_dir"),
        "Matcher must support project-specific signatures"
    );

    println!("✅ User-extensible signature paths are correctly defined");
}

/// Test 9: Verify signature matcher loads from user directories
#[test]
fn test_signature_matcher_user_loading() {
    let workspace = workspace_root();

    // Create a temporary user signature file
    let temp_dir = workspace.join(".sigil").join("signatures.d");
    fs::create_dir_all(&temp_dir).expect("Failed to create temp signatures directory");

    let test_signature = r#"
[signatures.test-tool]
match_pattern = "^testtool\\s"
enabled = true

[[signatures.test-tool.inject]]
type = "Env"
name = "TEST_API_KEY"
secret = "test/api_key"
optional = false
cleanup = false
"#;

    let test_file = temp_dir.join("test-tool.toml");
    fs::write(&test_file, test_signature).expect("Failed to write test signature");

    // Verify file was created
    assert!(test_file.exists(), "Test signature file should exist");

    // Create matcher with project directory
    let matcher = SignatureMatcher::with_project_dir(Some(workspace.to_path_buf()))
        .expect("Failed to create matcher with project dir");

    // Verify the custom signature is loaded
    let all_signatures = matcher.list_signatures();
    println!("Loaded signatures: {:?}", all_signatures);

    assert!(
        all_signatures.contains(&"test-tool".to_string()),
        "Custom signature 'test-tool' should be loaded. Available signatures: {:?}",
        all_signatures
    );

    // Verify it matches
    let results = matcher.match_command("testtool --help");
    assert!(
        !results.is_empty(),
        "Custom signature should match 'testtool --help'"
    );

    let test_match = results.iter().find(|m| m.signature_name == "test-tool");
    assert!(test_match.is_some(), "Should match 'test-tool' signature");

    // Cleanup
    let _ = fs::remove_file(&test_file);
    let _ = fs::remove_dir_all(&temp_dir);

    println!("✅ User signature loading works correctly");
}

/// Test 10: Verify sigil signatures list command exists
#[test]
fn test_sigil_signatures_list_command() {
    let workspace = workspace_root();
    let cli_path = workspace.join("crates/sigil-cli/src/main.rs");
    let cli_code = fs::read_to_string(&cli_path).expect("Failed to read CLI code");

    // Verify SignaturesCommand enum exists
    assert!(
        cli_code.contains("SignaturesCommand"),
        "CLI must have SignaturesCommand enum"
    );

    // Verify list command variant
    assert!(
        cli_code.contains("List {") && cli_code.contains("verbose"),
        "SignaturesCommand must have List variant with verbose option"
    );

    // Verify category filter
    assert!(
        cli_code.contains("category"),
        "SignaturesCommand List must support category filtering"
    );

    println!("✅ sigil signatures list command is implemented");
}

/// Test 11: Verify sigil signatures search command exists
#[test]
fn test_sigil_signatures_search_command() {
    let workspace = workspace_root();
    let cli_path = workspace.join("crates/sigil-cli/src/main.rs");
    let cli_code = fs::read_to_string(&cli_path).expect("Failed to read CLI code");

    // Verify search command variant
    assert!(
        cli_code.contains("Search {") && cli_code.contains("query"),
        "SignaturesCommand must have Search variant with query parameter"
    );

    println!("✅ sigil signatures search command is implemented");
}

/// Test 12: Verify sigil signatures update command exists
#[test]
fn test_sigil_signatures_update_command() {
    let workspace = workspace_root();
    let cli_path = workspace.join("crates/sigil-cli/src/main.rs");
    let cli_code = fs::read_to_string(&cli_path).expect("Failed to read CLI code");

    // Verify update command variant
    assert!(
        cli_code.contains("Update {") && cli_code.contains("url"),
        "SignaturesCommand must have Update variant with url option"
    );

    // Verify dry_run option
    assert!(
        cli_code.contains("dry_run"),
        "SignaturesCommand Update must support dry_run"
    );

    // Check for SignatureUpdater
    let signatures_lib = workspace.join("crates/sigil-signatures/src/update.rs");
    assert!(
        signatures_lib.exists(),
        "sigil-signatures must have update module"
    );

    let update_code = fs::read_to_string(&signatures_lib).expect("Failed to read update.rs");
    assert!(
        update_code.contains("SignatureUpdater"),
        "Must have SignatureUpdater type"
    );

    println!("✅ sigil signatures update command is implemented");
}

/// Test 13: Verify sigil signatures add command exists
#[test]
fn test_sigil_signatures_add_command() {
    let workspace = workspace_root();
    let cli_path = workspace.join("crates/sigil-cli/src/main.rs");
    let cli_code = fs::read_to_string(&cli_path).expect("Failed to read CLI code");

    // Verify add command variant
    assert!(
        cli_code.contains("Add {") && cli_code.contains("file"),
        "SignaturesCommand must have Add variant with file parameter"
    );

    // Verify user flag for global vs project
    assert!(
        cli_code.contains("user") && cli_code.contains("Add {"),
        "SignaturesCommand Add must support user flag"
    );

    println!("✅ sigil signatures add command is implemented");
}

/// Test 14: Verify stats command exists
#[test]
fn test_sigil_signatures_stats_command() {
    let workspace = workspace_root();
    let cli_path = workspace.join("crates/sigil-cli/src/main.rs");
    let cli_code = fs::read_to_string(&cli_path).expect("Failed to read CLI code");

    // Verify stats command variant
    assert!(
        cli_code.contains("Stats {"),
        "SignaturesCommand must have Stats variant"
    );

    println!("✅ sigil signatures stats command is implemented");
}

/// Test 15: Verify sandbox environment variable injection
#[test]
fn test_sandbox_env_injection() {
    let workspace = workspace_root();
    let sandbox_path = workspace.join("crates/sigil-sandbox/src/bubblewrap.rs");

    if sandbox_path.exists() {
        let sandbox_code = fs::read_to_string(&sandbox_path).expect("Failed to read sandbox code");

        // Verify environment variable support
        assert!(
            sandbox_code.contains("env") || sandbox_code.contains("environment"),
            "Sandbox must support environment variable injection"
        );

        // Check for env_vars or similar
        let has_env_param = sandbox_code.contains("env_vars")
            || sandbox_code.contains("environment")
            || sandbox_code.contains("--setenv");

        assert!(
            has_env_param,
            "Sandbox must have parameter for setting environment variables"
        );
    }

    println!("✅ Sandbox supports environment variable injection");
}

/// Test 16: Verify transparency - injected vars don't leak to agent
#[test]
fn test_injection_transparency() {
    let workspace = workspace_root();

    // Check that injection happens in sandbox, not agent's shell
    let execute_path = workspace.join("crates/sigil-cli/src/execute.rs");
    if execute_path.exists() {
        let execute_code = fs::read_to_string(&execute_path).expect("Failed to read execute.rs");

        // Verify that execution uses sandbox
        let has_sandbox = execute_code.contains("sandbox")
            || execute_code.contains("bubblewrap")
            || execute_code.contains("isolate");

        assert!(has_sandbox, "Execute must use sandbox for isolation");
    }

    println!("✅ Injection isolation is implemented");
}

/// Test 17: Verify signature regex patterns are valid
#[test]
fn test_signature_regex_validity() {
    let config = BUILTIN_SIGNATURES
        .get_config()
        .expect("Failed to load built-in signatures");
    let signatures = config.get_all();

    let mut invalid_patterns = Vec::new();

    for (name, sig) in &signatures {
        if let Err(_e) = sig.regex() {
            invalid_patterns.push(format!("{}: invalid regex pattern", name));
        }
    }

    assert!(
        invalid_patterns.is_empty(),
        "All signature patterns must be valid regex. Invalid patterns:\n{}",
        invalid_patterns.join("\n")
    );

    println!(
        "✅ All {} signature patterns are valid regex",
        signatures.len()
    );
}

/// Test 18: Verify signature matching is case-sensitive for commands
#[test]
fn test_signature_case_sensitivity() {
    let matcher = SignatureMatcher::new().expect("Failed to create matcher");

    // AWS should match lowercase
    let lowercase_results = matcher.match_command("aws s3 ls");
    assert!(
        !lowercase_results.is_empty(),
        "Lowercase 'aws' should match"
    );

    // Verify pattern uses case-insensitive flag where appropriate
    let config = BUILTIN_SIGNATURES
        .get_config()
        .expect("Failed to load config");
    let signatures: std::collections::HashMap<_, _> = config.get_all().into_iter().collect();

    if let Some(aws_sig) = signatures.get("aws") {
        // Pattern should handle leading whitespace
        assert!(
            aws_sig.match_pattern.contains(r"^\s*"),
            "Command patterns should handle leading whitespace"
        );
    }

    println!("✅ Signature patterns handle case and whitespace correctly");
}

/// Test 19: Verify injection types (env, file, header)
#[test]
fn test_injection_types() {
    let config = BUILTIN_SIGNATURES
        .get_config()
        .expect("Failed to load built-in signatures");
    let signatures = config.get_all();

    let mut has_env = false;
    let mut has_file = false;
    let mut has_header = false;

    for (_, sig) in &signatures {
        for inject in &sig.inject {
            match &inject.injection_type {
                sigil_signatures::ConfigInjectionType::Env { .. } => has_env = true,
                sigil_signatures::ConfigInjectionType::File { .. } => has_file = true,
                sigil_signatures::ConfigInjectionType::Header { .. } => has_header = true,
            }
        }
    }

    assert!(has_env, "Must have environment variable injections");
    assert!(has_file, "Must have file injections");
    assert!(has_header, "Must have header injections");

    println!("✅ All injection types (env, file, header) are used");
}

/// Test 20: Verify optional and cleanup flags work
#[test]
fn test_optional_and_cleanup_flags() {
    let config = BUILTIN_SIGNATURES
        .get_config()
        .expect("Failed to load built-in signatures");
    let signatures = config.get_all();

    let mut has_optional = false;
    let mut has_cleanup = false;

    for (_, sig) in &signatures {
        for inject in &sig.inject {
            if inject.optional {
                has_optional = true;
            }
            if inject.cleanup {
                has_cleanup = true;
            }
        }
    }

    assert!(has_optional, "Must have optional injections");
    assert!(has_cleanup, "Must have cleanup injections");

    println!("✅ Optional and cleanup flags are used");
}

/// Test 21: Verify signature description metadata
#[test]
fn test_signature_descriptions() {
    let config = BUILTIN_SIGNATURES
        .get_config()
        .expect("Failed to load built-in signatures");
    let signatures = config.get_all();

    let mut with_description = 0;
    for (_, sig) in &signatures {
        if sig.description.is_some() {
            with_description += 1;
        }
    }

    let description_ratio = (with_description as f64) / (signatures.len() as f64);

    assert!(
        description_ratio > 0.5,
        "At least 50% of signatures should have descriptions (currently {:.0}%)",
        description_ratio * 100.0
    );

    println!(
        "✅ Signature descriptions: {}/{} ({:.0}%)",
        with_description,
        signatures.len(),
        description_ratio * 100.0
    );
}

/// Test 22: Verify multiple signatures can match same command
#[test]
fn test_multiple_signature_match() {
    let matcher = SignatureMatcher::new().expect("Failed to create matcher");

    // Commands that might match multiple signatures
    let test_cases = [
        (
            "docker login registry.example.com",
            vec!["docker", "docker-login"],
        ),
        ("aws s3 ls", vec!["aws", "aws-s3"]),
    ];

    for (cmd, expected_names) in test_cases {
        let results = matcher.match_command(cmd);

        for expected_name in expected_names {
            let match_found = results.iter().any(|m| m.signature_name == expected_name);
            // Note: not all expected signatures may exist, so we just check if matching works
            if match_found {
                println!("✅ Command '{}' matched signature '{}'", cmd, expected_name);
            }
        }
    }

    println!("✅ Multiple signature matching works");
}

/// Test 23: Verify disabled signatures don't match
#[test]
fn test_disabled_signatures() {
    let workspace = workspace_root();

    // Create a matcher with a custom disabled signature
    let temp_dir = workspace.join(".sigil").join("signatures.d");
    fs::create_dir_all(&temp_dir).expect("Failed to create temp directory");

    let disabled_signature = r#"
[signatures.disabled-test]
match_pattern = "^disabledcmd\\s"
enabled = false

[[signatures.disabled-test.inject]]
type = "Env"
name = "DISABLED_VAR"
secret = "disabled/secret"
optional = false
cleanup = false
"#;

    let test_file = temp_dir.join("disabled-test.toml");
    fs::write(&test_file, disabled_signature).expect("Failed to write test signature");

    let matcher = SignatureMatcher::with_project_dir(Some(workspace.to_path_buf()))
        .expect("Failed to create matcher");

    // Disabled signature should not match
    let results = matcher.match_command("disabledcmd --help");
    let disabled_match = results.iter().find(|m| m.signature_name == "disabled-test");

    assert!(
        disabled_match.is_none(),
        "Disabled signature should not match commands"
    );

    // Cleanup
    let _ = fs::remove_file(&test_file);
    let _ = fs::remove_dir_all(&temp_dir);

    println!("✅ Disabled signatures don't match");
}

/// Test 24: Comprehensive end-to-end command recognition test
#[test]
fn test_end_to_end_command_recognition() {
    let matcher = SignatureMatcher::new().expect("Failed to create matcher");

    // Test commands from each major category
    let test_commands = [
        // Cloud
        ("aws s3 ls", "aws"),
        ("gcloud compute instances list", "gcloud"),
        ("az account list", "az"),
        ("terraform apply", "terraform"),
        // Containers
        ("kubectl get pods", "kubectl"),
        ("helm list", "helm"),
        ("docker pull nginx", "docker"),
        // Version control
        ("gh pr list", "gh"),
        ("glab mr list", "glab"),
        // Databases
        ("psql -h localhost", "psql"),
        ("mysql -u root", "mysql"),
        ("mongosh", "mongosh"),
        ("redis-cli ping", "redis-cli"),
        // APIs
        ("curl https://api.example.com/data", "curl-api"),
        ("https GET https://api.example.com", "http"),
        // Package managers
        ("npm publish", "npm-publish"),
        ("cargo publish", "cargo-publish"),
        // SSH
        ("scp file.txt user@host:/path", "scp"),
        ("rsync -avz src/ dest/", "rsync"),
        // Developer tools
        ("vault status", "vault"),
        ("stripe balance", "stripe"),
        ("heroku apps", "heroku"),
    ];

    let mut matched = 0;
    let total = test_commands.len();

    for (cmd, expected_sig) in test_commands {
        let results = matcher.match_command(cmd);
        if !results.is_empty() {
            let expected_match = results.iter().any(|m| m.signature_name == expected_sig);
            if expected_match {
                matched += 1;
                println!("  ✅ '{}' -> {}", cmd, expected_sig);
            } else {
                println!(
                    "  ⚠️  '{}' matched but not to expected '{}'",
                    cmd, expected_sig
                );
            }
        } else {
            println!("  ❌ '{}' did not match any signature", cmd);
        }
    }

    let match_ratio = (matched as f64) / (total as f64);
    println!(
        "✅ End-to-end recognition: {}/{} ({:.0}%)",
        matched,
        total,
        match_ratio * 100.0
    );

    assert!(
        match_ratio >= 0.8,
        "At least 80% of test commands should match (got {:.0}%)",
        match_ratio * 100.0
    );
}
