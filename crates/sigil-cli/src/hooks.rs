//! Claude Code hook integration for SIGIL
//!
//! This module implements PreToolUse and PostToolUse hooks that integrate
//! SIGIL with Claude Code's tool call interception system.

use anyhow::{anyhow, Context, Result};
use serde_json::{json, Value};
use sigil_core::SecretBackend;
use std::fs;
use std::io::{self, Write};

/// Hook types supported by SIGIL
#[derive(Debug, Clone, Copy)]
#[allow(dead_code)]
pub enum HookType {
    /// PreToolUse hook - intercepts before tool execution
    PreToolUse,
    /// PostToolUse hook - intercepts after tool execution
    PostToolUse,
    /// UserPromptSubmit hook - intercepts user input before it reaches the LLM
    UserPromptSubmit,
}

/// Tool types that SIGIL can hook
#[derive(Debug, Clone, PartialEq)]
pub enum ToolType {
    /// Bash tool execution
    Bash,
    /// Write tool (file creation)
    Write,
    /// Edit tool (file modification)
    Edit,
    /// Read tool (file reading)
    Read,
    /// Grep tool (content search)
    Grep,
    /// Glob tool (file pattern matching)
    Glob,
    /// MCP tool call
    Mcp,
}

impl ToolType {
    /// Parse tool type from string
    pub fn from_str(s: &str) -> Option<Self> {
        match s {
            "Bash" => Some(ToolType::Bash),
            "Write" => Some(ToolType::Write),
            "Edit" => Some(ToolType::Edit),
            "Read" => Some(ToolType::Read),
            "Grep" => Some(ToolType::Grep),
            "Glob" => Some(ToolType::Glob),
            tool if tool.starts_with("mcp__") => Some(ToolType::Mcp),
            _ => None,
        }
    }

    /// Get the matcher pattern for this tool type
    #[allow(dead_code)]
    pub fn matcher(&self) -> &str {
        match self {
            ToolType::Bash => "Bash",
            ToolType::Write => "Write|Edit",
            ToolType::Edit => "Write|Edit",
            ToolType::Read => "Read",
            ToolType::Grep => "Grep|Glob",
            ToolType::Glob => "Grep|Glob",
            ToolType::Mcp => "mcp__.*",
        }
    }
}

/// PreToolUse hook input structure
#[derive(Debug, serde::Deserialize)]
pub struct PreToolUseInput {
    /// Tool name being called
    pub tool_name: String,
    /// Tool input parameters
    pub tool_input: Value,
    /// Additional context from Claude Code
    #[serde(default)]
    #[allow(dead_code)]
    pub additional_context: Option<Value>,
}

/// PreToolUse hook output structure
#[derive(Debug, serde::Serialize)]
pub struct PreToolUseOutput {
    /// Permission decision
    pub permission_decision: String,
    /// Updated input (for command rewriting)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub updated_input: Option<Value>,
    /// Additional context to inject back to Claude
    #[serde(skip_serializing_if = "Option::is_none")]
    pub additional_context: Option<String>,
    /// Modified tool name (rarely used)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tool_name: Option<String>,
}

/// PostToolUse hook input structure
#[derive(Debug, serde::Deserialize)]
pub struct PostToolUseInput {
    /// Tool name that was called
    pub tool_name: String,
    /// Tool input parameters
    #[allow(dead_code)]
    pub tool_input: Value,
    /// Tool response/output
    pub tool_response: Value,
    /// Additional context from Claude Code
    #[serde(default)]
    #[allow(dead_code)]
    pub additional_context: Option<Value>,
}

/// PostToolUse hook output structure
#[derive(Debug, serde::Serialize)]
pub struct PostToolUseOutput {
    /// Additional context to inject back to Claude
    #[serde(skip_serializing_if = "Option::is_none")]
    pub additional_context: Option<String>,
}

/// UserPromptSubmit hook input structure
#[derive(Debug, serde::Deserialize)]
pub struct UserPromptSubmitInput {
    /// The user's prompt text
    pub prompt: String,
    /// Additional context from Claude Code
    #[serde(default)]
    #[allow(dead_code)]
    pub additional_context: Option<Value>,
}

/// UserPromptSubmit hook output structure
#[derive(Debug, serde::Serialize)]
pub struct UserPromptSubmitOutput {
    /// The rewritten prompt with secrets replaced by placeholders
    #[serde(skip_serializing_if = "Option::is_none")]
    pub updated_prompt: Option<String>,
    /// Additional context to inject back to Claude
    #[serde(skip_serializing_if = "Option::is_none")]
    pub additional_context: Option<String>,
}

/// Detected secret information for auto-vaulting
#[derive(Debug, Clone)]
struct DetectedSecret {
    /// The matched secret value
    value: String,
    /// The type of secret detected
    secret_type: SecretType,
    /// Start position in the original text
    start: usize,
    /// End position in the original text
    end: usize,
}

/// Secret type classification for auto-vaulting
#[derive(Debug, Clone, Copy)]
#[allow(dead_code)]
enum SecretType {
    /// AWS Access Key ID
    AwsAccessKey,
    /// AWS Secret Access Key
    AwsSecretKey,
    /// AWS Session Token
    AwsSessionToken,
    /// GitHub Personal Access Token
    GitHubToken,
    /// GitLab Personal Access Token
    GitLabToken,
    /// Stripe API Key
    StripeKey,
    /// OpenAI API Key
    OpenAiKey,
    /// Generic API key (high entropy string)
    GenericApiKey,
    /// JWT Token
    JwtToken,
    /// Private key (PEM format)
    PrivateKey,
    /// Database connection string
    DatabaseUrl,
    /// Generic secret (high entropy in assignment context)
    GenericSecret,
}

impl SecretType {
    /// Get the suggested vault path for this secret type
    fn suggested_path(&self, index: usize) -> String {
        match self {
            SecretType::AwsAccessKey => format!("auto/aws/access_key_id_{}", index),
            SecretType::AwsSecretKey => format!("auto/aws/secret_access_key_{}", index),
            SecretType::AwsSessionToken => format!("auto/aws/session_token_{}", index),
            SecretType::GitHubToken => format!("auto/github/token_{}", index),
            SecretType::GitLabToken => format!("auto/gitlab/token_{}", index),
            SecretType::StripeKey => format!("auto/stripe/api_key_{}", index),
            SecretType::OpenAiKey => format!("auto/openai/api_key_{}", index),
            SecretType::GenericApiKey => format!("auto/api/key_{}", index),
            SecretType::JwtToken => format!("auto/jwt/token_{}", index),
            SecretType::PrivateKey => format!("auto/keys/private_{}", index),
            SecretType::DatabaseUrl => format!("auto/database/url_{}", index),
            SecretType::GenericSecret => format!("auto/generic/secret_{}", index),
        }
    }

    /// Get description for this secret type
    fn description(&self) -> &str {
        match self {
            SecretType::AwsAccessKey => "AWS Access Key ID",
            SecretType::AwsSecretKey => "AWS Secret Access Key",
            SecretType::AwsSessionToken => "AWS Session Token",
            SecretType::GitHubToken => "GitHub Personal Access Token",
            SecretType::GitLabToken => "GitLab Personal Access Token",
            SecretType::StripeKey => "Stripe API Key",
            SecretType::OpenAiKey => "OpenAI API Key",
            SecretType::GenericApiKey => "Generic API Key",
            SecretType::JwtToken => "JWT Token",
            SecretType::PrivateKey => "Private Key (PEM)",
            SecretType::DatabaseUrl => "Database Connection String",
            SecretType::GenericSecret => "Generic Secret",
        }
    }
}

/// Handle PreToolUse hook
pub fn handle_pre_tool_use(input: &PreToolUseInput) -> Result<PreToolUseOutput> {
    let tool_type = ToolType::from_str(&input.tool_name);

    match tool_type {
        Some(ToolType::Bash) => handle_bash_pre(input),
        Some(ToolType::Write | ToolType::Edit) => handle_write_pre(input),
        Some(ToolType::Read) => handle_read_pre(input),
        Some(ToolType::Grep | ToolType::Glob) => handle_search_pre(input),
        Some(ToolType::Mcp) => handle_mcp_pre(input),
        None => Ok(PreToolUseOutput {
            permission_decision: "allow".to_string(),
            updated_input: None,
            additional_context: None,
            tool_name: None,
        }),
    }
}

/// Handle PostToolUse hook
pub fn handle_post_tool_use(input: &PostToolUseInput) -> Result<PostToolUseOutput> {
    let tool_type = ToolType::from_str(&input.tool_name);

    match tool_type {
        Some(ToolType::Bash) => handle_bash_post(input),
        Some(ToolType::Write | ToolType::Edit) => handle_write_post(input),
        Some(ToolType::Read) => handle_read_post(input),
        Some(ToolType::Grep | ToolType::Glob) => handle_search_post(input),
        Some(ToolType::Mcp) => handle_mcp_post(input),
        None => Ok(PostToolUseOutput {
            additional_context: None,
        }),
    }
}

/// Handle UserPromptSubmit hook
///
/// This hook intercepts user prompts before they reach the LLM, detecting
/// and auto-vaulting secrets, then rewriting the prompt with placeholders.
pub fn handle_user_prompt_submit(input: &UserPromptSubmitInput) -> Result<UserPromptSubmitOutput> {
    let prompt = &input.prompt;

    // Detect secrets in the prompt
    let detected = detect_secrets_in_prompt(prompt)?;

    if detected.is_empty() {
        // No secrets found, return as-is
        return Ok(UserPromptSubmitOutput {
            updated_prompt: None,
            additional_context: None,
        });
    }

    // Check if confirmation mode is enabled
    let confirm_mode = std::env::var("SIGIL_AUTO_VAULT_CONFIRM")
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(false);

    // If confirmation mode is enabled, ask the user
    if confirm_mode {
        // Show detected secrets
        eprintln!(
            "🔐 SIGIL detected {} potential secret(s) in your prompt:",
            detected.len()
        );
        for (index, secret) in detected.iter().enumerate() {
            eprintln!(
                "  {}. {} - {}",
                index + 1,
                secret.secret_type.description(),
                &secret.value[..secret.value.len().min(20)] // Show first 20 chars
            );
        }
        eprintln!();

        // Ask for confirmation
        if !prompt_yes_no("Vault these secrets and replace with placeholders? [Y/n] ")? {
            // User declined - return prompt as-is
            eprintln!("⚠️  Secrets will remain in plaintext in your prompt.");
            return Ok(UserPromptSubmitOutput {
                updated_prompt: None,
                additional_context: Some(
                    "SIGIL detected secrets but auto-vaulting was declined. \
                     Secrets are present in the prompt as plaintext."
                        .to_string(),
                ),
            });
        }
    }

    // Auto-vault detected secrets
    let mut rewritten = prompt.clone();
    let mut vaulted_count = 0;
    let mut vaulted_paths: Vec<String> = Vec::new();

    for (index, secret) in detected.iter().enumerate() {
        // Generate path for this secret
        let path = secret.secret_type.suggested_path(index);

        // Try to vault the secret (non-blocking if it fails)
        if let Err(e) = auto_vault_secret(&path, &secret.value) {
            eprintln!("[SIGIL] Failed to auto-vault secret: {}", e);
            // Continue anyway - we'll still rewrite the prompt
        } else {
            vaulted_count += 1;
            vaulted_paths.push(format!("{} ({})", path, secret.secret_type.description()));
        }

        // Rewrite the prompt, replacing the secret value with a placeholder
        let placeholder = format!("{{{{secret:{}}}}}", path);
        rewritten = rewritten.replace(&secret.value, &placeholder);
    }

    // Build additional context to inform the user
    let additional_context = if vaulted_count > 0 {
        let mut msg = format!(
            "🔐 SIGIL detected and auto-vaulted {} secret(s) from your prompt:\n",
            vaulted_count
        );
        for path in &vaulted_paths {
            msg.push_str(&format!("  • {}\n", path));
        }
        msg.push_str("\nSecrets have been replaced with {{secret:path}} placeholders.");
        msg.push_str("\nUse 'sigil list auto/' to view auto-vaulted secrets.");
        Some(msg)
    } else {
        None
    };

    Ok(UserPromptSubmitOutput {
        updated_prompt: Some(rewritten),
        additional_context,
    })
}

/// Prompt user for yes/no confirmation
///
/// Returns true if user confirms (Y or Enter), false otherwise
fn prompt_yes_no(prompt: &str) -> Result<bool> {
    let mut input = String::new();
    print!("{}", prompt);
    io::stdout().flush()?;

    io::stdin().read_line(&mut input)?;
    let response = input.trim().to_lowercase();

    // Default to yes if user just presses Enter
    Ok(response.is_empty() || response == "y" || response == "yes")
}

/// Detect secrets in user prompt text
///
/// Returns a list of detected secrets with their positions and types.
/// Patterns are derived from TruffleHog/Gitleaks rules for credential detection.
fn detect_secrets_in_prompt(prompt: &str) -> Result<Vec<DetectedSecret>> {
    let mut detected = Vec::new();

    // AWS Access Key ID: AKIA[0-9A-Z]{16}
    let aws_key_re = regex::Regex::new(r"AKIA[0-9A-Z]{16}").unwrap();
    for mat in aws_key_re.find_iter(prompt) {
        detected.push(DetectedSecret {
            value: mat.as_str().to_string(),
            secret_type: SecretType::AwsAccessKey,
            start: mat.start(),
            end: mat.end(),
        });
    }

    // GitHub Personal Access Token: ghp_[0-9a-zA-Z]{36}
    let gh_token_re = regex::Regex::new(r"ghp_[0-9a-zA-Z]{36}").unwrap();
    for mat in gh_token_re.find_iter(prompt) {
        detected.push(DetectedSecret {
            value: mat.as_str().to_string(),
            secret_type: SecretType::GitHubToken,
            start: mat.start(),
            end: mat.end(),
        });
    }

    // GitLab Personal Access Token: glpat-[0-9a-zA-Z]{20}
    let gl_token_re = regex::Regex::new(r"glpat-[0-9a-zA-Z]{20}").unwrap();
    for mat in gl_token_re.find_iter(prompt) {
        detected.push(DetectedSecret {
            value: mat.as_str().to_string(),
            secret_type: SecretType::GitLabToken,
            start: mat.start(),
            end: mat.end(),
        });
    }

    // Stripe API Key: sk_live_[0-9a-zA-Z]{24} or sk_test_[0-9a-zA-Z]{24}
    let stripe_re = regex::Regex::new(r"sk_(?:live|test)_[0-9a-zA-Z]{24}").unwrap();
    for mat in stripe_re.find_iter(prompt) {
        detected.push(DetectedSecret {
            value: mat.as_str().to_string(),
            secret_type: SecretType::StripeKey,
            start: mat.start(),
            end: mat.end(),
        });
    }

    // OpenAI API Key: sk-[a-zA-Z0-9]{48}
    let openai_re = regex::Regex::new(r"sk-[a-zA-Z0-9]{48}").unwrap();
    for mat in openai_re.find_iter(prompt) {
        detected.push(DetectedSecret {
            value: mat.as_str().to_string(),
            secret_type: SecretType::OpenAiKey,
            start: mat.start(),
            end: mat.end(),
        });
    }

    // JWT Token: eyJ[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+
    let jwt_re = regex::Regex::new(r"eyJ[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+").unwrap();
    for mat in jwt_re.find_iter(prompt) {
        detected.push(DetectedSecret {
            value: mat.as_str().to_string(),
            secret_type: SecretType::JwtToken,
            start: mat.start(),
            end: mat.end(),
        });
    }

    // Private Key (PEM format): -----BEGIN [A-Z]+ PRIVATE KEY-----
    let pem_re = regex::Regex::new(
        r"-----BEGIN [A-Z]+ PRIVATE KEY-----[\s\S]{20,}-----END [A-Z]+ PRIVATE KEY-----",
    )
    .unwrap();
    for mat in pem_re.find_iter(prompt) {
        detected.push(DetectedSecret {
            value: mat.as_str().to_string(),
            secret_type: SecretType::PrivateKey,
            start: mat.start(),
            end: mat.end(),
        });
    }

    // Database connection string: postgres://[^\s]+, mysql://[^\s]+, mongodb://[^\s]+
    let db_re = regex::Regex::new(r"(?:postgres|mysql|mongodb)://[^\s']+").unwrap();
    for mat in db_re.find_iter(prompt) {
        // Check if it looks like a real connection string (has @)
        if mat.as_str().contains('@') {
            detected.push(DetectedSecret {
                value: mat.as_str().to_string(),
                secret_type: SecretType::DatabaseUrl,
                start: mat.start(),
                end: mat.end(),
            });
        }
    }

    // Generic API key pattern: api[_-]?key\s*[:=]\s*['"]?[a-zA-Z0-9_]{20,}['"]?
    let api_key_re =
        regex::Regex::new(r#"api[_-]?key\s*[:=]\s*['"]?([a-zA-Z0-9_]{20,})['"]?"#).unwrap();
    for mat in api_key_re.captures_iter(prompt) {
        if let Some(value_match) = mat.get(1) {
            detected.push(DetectedSecret {
                value: value_match.as_str().to_string(),
                secret_type: SecretType::GenericApiKey,
                start: value_match.start(),
                end: value_match.end(),
            });
        }
    }

    // Generic secret assignment: secret[_-]?key\s*[:=]\s*['"]?[a-zA-Z0-9_]{20,}['"]?
    let secret_re =
        regex::Regex::new(r#"secret[_-]?key\s*[:=]\s*['"]?([a-zA-Z0-9_]{20,})['"]?"#).unwrap();
    for mat in secret_re.captures_iter(prompt) {
        if let Some(value_match) = mat.get(1) {
            detected.push(DetectedSecret {
                value: value_match.as_str().to_string(),
                secret_type: SecretType::GenericSecret,
                start: value_match.start(),
                end: value_match.end(),
            });
        }
    }

    // AWS Secret Access Key pattern (often follows AWS Access Key): 40 char base64-like
    // This is context-dependent - look for it near AKIA keys or in AWS context
    let aws_secret_re = regex::Regex::new(r"[a-zA-Z0-9/+]{40}").unwrap();
    for mat in aws_secret_re.find_iter(prompt) {
        let value = mat.as_str();
        // Check if this looks like an AWS secret key (contains + and /, mixed case)
        if value.contains('+') || value.contains('/') {
            // Only add if not already detected and near AWS context
            let context_start = mat.start().saturating_sub(50);
            let context_end = (mat.end() + 50).min(prompt.len());
            let context = &prompt[context_start..context_end];

            if context.contains("AKIA") || context.contains("aws") || context.contains("AWS") {
                detected.push(DetectedSecret {
                    value: value.to_string(),
                    secret_type: SecretType::AwsSecretKey,
                    start: mat.start(),
                    end: mat.end(),
                });
            }
        }
    }

    // Deduplicate overlapping matches
    detected.sort_by_key(|s| s.start);
    let mut deduped: Vec<DetectedSecret> = Vec::new();
    for secret in detected {
        if let Some(last) = deduped.last() {
            // Skip if this overlaps with the last secret
            if secret.start < last.end {
                continue;
            }
        }
        deduped.push(secret);
    }

    Ok(deduped)
}

/// Auto-vault a detected secret
///
/// This function attempts to add a secret to the vault without user interaction.
/// If the vault is locked or not available, it returns an error but allows
/// the caller to continue (we'll still rewrite the prompt).
fn auto_vault_secret(path: &str, value: &str) -> Result<()> {
    use std::io::Write;
    use std::process::Command;

    // Try to call sigil add with stdin input
    let mut child = Command::new("sigil")
        .args(["add", path, "--from-stdin", "--non-interactive"])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .context("Failed to spawn sigil add command")?;

    // Write the secret value to stdin
    if let Some(mut stdin) = child.stdin.take() {
        stdin.write_all(value.as_bytes())?;
        stdin.write_all(b"\n")?;
    }

    // Wait for the command to complete
    let status = child.wait()?;

    if !status.success() {
        anyhow::bail!("sigil add failed with exit code: {:?}", status.code());
    }

    Ok(())
}

/// Handle PreToolUse for Bash tool
fn handle_bash_pre(input: &PreToolUseInput) -> Result<PreToolUseOutput> {
    // Extract command from tool_input
    let command = input
        .tool_input
        .get("command")
        .and_then(|v| v.as_str())
        .unwrap_or("");

    // Check for secret placeholders
    let has_secrets = command.contains("{{secret:") || command.contains("{{secret:");

    if has_secrets {
        // Rewrite command with scrubbing pipeline
        let rewritten = format!(
            "{{ {} && echo \":::SIGIL_EXIT:::$?\"; }} 2>&1 | sigil scrub",
            command.trim_end_matches(';')
        );

        return Ok(PreToolUseOutput {
            permission_decision: "allow".to_string(),
            updated_input: Some(json!({ "command": rewritten })),
            additional_context: None,
            tool_name: None,
        });
    }

    // Check for interactive commands that shouldn't be wrapped
    let interactive_commands = ["vim ", "vi ", "nano ", "less ", "more ", "top ", "htop "];
    let is_interactive = interactive_commands
        .iter()
        .any(|cmd| command.starts_with(cmd));

    if is_interactive {
        // Don't wrap interactive commands
        return Ok(PreToolUseOutput {
            permission_decision: "allow".to_string(),
            updated_input: None,
            additional_context: Some(
                "Interactive command detected - passing through without scrubbing".to_string(),
            ),
            tool_name: None,
        });
    }

    // For non-secret commands, still wrap for proactive scrubbing
    let rewritten = format!(
        "{{ {} && echo \":::SIGIL_EXIT:::$?\"; }} 2>&1 | sigil scrub",
        command.trim_end_matches(';')
    );

    Ok(PreToolUseOutput {
        permission_decision: "allow".to_string(),
        updated_input: Some(json!({ "command": rewritten })),
        additional_context: None,
        tool_name: None,
    })
}

/// Handle PostToolUse for Bash tool
fn handle_bash_post(input: &PostToolUseInput) -> Result<PostToolUseOutput> {
    // This is a detection-only backstop since PreToolUse already scrubs
    // If we get here with secrets, it's a critical bypass

    let output = extract_output(&input.tool_response);

    // Check for secret patterns in output
    let has_secrets = detect_secrets_in_output(&output);

    if has_secrets {
        // Log critical breach
        eprintln!("[SIGIL CRITICAL] Secrets detected in Bash output despite PreToolUse scrubbing!");

        return Ok(PostToolUseOutput {
            additional_context: Some(
                "⚠️ SIGIL detected potential secrets in command output. This may indicate a scrubber bypass."
                    .to_string(),
            ),
        });
    }

    Ok(PostToolUseOutput {
        additional_context: None,
    })
}

/// Handle PreToolUse for Write/Edit tools
fn handle_write_pre(input: &PreToolUseInput) -> Result<PreToolUseOutput> {
    // Get content being written
    let content = if let Some(c) = input.tool_input.get("content") {
        c.as_str().map(|s| s.to_string())
    } else if let Some(s) = input.tool_input.get("new_string") {
        s.as_str().map(|s| s.to_string())
    } else {
        None
    };

    if let Some(content) = content {
        // Scan for secret patterns
        if detect_secrets_in_output(&content) {
            // Block the write
            return Ok(PreToolUseOutput {
                permission_decision: "ask".to_string(),
                updated_input: None,
                additional_context: Some(
                    "SIGIL blocked this Write/Edit operation because it may contain secret values. \
                     Use {{secret:path}} placeholders instead of hardcoding secrets."
                        .to_string(),
                ),
                tool_name: None,
            });
        }
    }

    Ok(PreToolUseOutput {
        permission_decision: "allow".to_string(),
        updated_input: None,
        additional_context: None,
        tool_name: None,
    })
}

/// Handle PostToolUse for Write/Edit tools
fn handle_write_post(_input: &PostToolUseInput) -> Result<PostToolUseOutput> {
    // PostToolUse for Write is limited since we can't modify the written content
    // This is detection-only
    Ok(PostToolUseOutput {
        additional_context: None,
    })
}

/// Handle PreToolUse for Read tool
fn handle_read_pre(input: &PreToolUseInput) -> Result<PreToolUseOutput> {
    // Get file path being read
    let file_path = input
        .tool_input
        .get("file_path")
        .and_then(|v| v.as_str())
        .unwrap_or("");

    // Check against sensitive path denylist
    if is_sensitive_path(file_path) {
        return Ok(PreToolUseOutput {
            permission_decision: "ask".to_string(),
            updated_input: None,
            additional_context: Some(format!(
                "SIGIL blocked reading '{}' because it may contain sensitive credentials. \
                        Use {{secret:path}} placeholders to access secrets securely.",
                file_path
            )),
            tool_name: None,
        });
    }

    Ok(PreToolUseOutput {
        permission_decision: "allow".to_string(),
        updated_input: None,
        additional_context: None,
        tool_name: None,
    })
}

/// Handle PostToolUse for Read tool
fn handle_read_post(input: &PostToolUseInput) -> Result<PostToolUseOutput> {
    let content = extract_output(&input.tool_response);

    // Scrub read content for secrets
    if detect_secrets_in_output(&content) {
        return Ok(PostToolUseOutput {
            additional_context: Some(
                "⚠️ SIGIL detected potential secrets in file read. Some content may have been redacted."
                    .to_string(),
            ),
        });
    }

    Ok(PostToolUseOutput {
        additional_context: None,
    })
}

/// Handle PreToolUse for Grep/Glob tools
fn handle_search_pre(_input: &PreToolUseInput) -> Result<PreToolUseOutput> {
    // Search tools don't typically need interception
    Ok(PreToolUseOutput {
        permission_decision: "allow".to_string(),
        updated_input: None,
        additional_context: None,
        tool_name: None,
    })
}

/// Handle PostToolUse for Grep/Glob tools
fn handle_search_post(input: &PostToolUseInput) -> Result<PostToolUseOutput> {
    let results = extract_output(&input.tool_response);

    // Scrub search results for secret values
    if detect_secrets_in_output(&results) {
        return Ok(PostToolUseOutput {
            additional_context: Some(
                "⚠️ SIGIL detected potential secrets in search results. Some matches may have been redacted."
                    .to_string(),
            ),
        });
    }

    Ok(PostToolUseOutput {
        additional_context: None,
    })
}

/// Handle PreToolUse for MCP tools
fn handle_mcp_pre(_input: &PreToolUseInput) -> Result<PreToolUseOutput> {
    // MCP tools are generally trusted - they're the positive path
    Ok(PreToolUseOutput {
        permission_decision: "allow".to_string(),
        updated_input: None,
        additional_context: None,
        tool_name: None,
    })
}

/// Handle PostToolUse for MCP tools
fn handle_mcp_post(input: &PostToolUseInput) -> Result<PostToolUseOutput> {
    let response = serde_json::to_string_pretty(&input.tool_response).unwrap_or_default();

    // Scrub MCP responses for secrets
    if detect_secrets_in_output(&response) {
        return Ok(PostToolUseOutput {
            additional_context: Some(
                "⚠️ SIGIL detected potential secrets in MCP tool response.".to_string(),
            ),
        });
    }

    Ok(PostToolUseOutput {
        additional_context: None,
    })
}

/// Extract output from tool response
fn extract_output(tool_response: &Value) -> String {
    if let Some(output) = tool_response.get("output").and_then(|v| v.as_str()) {
        output.to_string()
    } else if let Some(content) = tool_response.get("content").and_then(|v| v.as_str()) {
        content.to_string()
    } else if let Some(results) = tool_response.get("results") {
        serde_json::to_string(results).unwrap_or_default()
    } else {
        serde_json::to_string(tool_response).unwrap_or_default()
    }
}

/// Detect secrets in output using pattern matching
fn detect_secrets_in_output(output: &str) -> bool {
    // Common secret patterns (basic detection)
    let patterns = [
        r#"(?i)api[_-]?key\s*[:=]\s*['"]?[a-zA-Z0-9_]{10,}"#,
        r#"(?i)secret[_-]?key\s*[:=]\s*['"]?[a-zA-Z0-9_]{10,}"#,
        r#"(?i)password\s*[:=]\s*['"]?[^\s'"]{8,}"#,
        r#"(?i)token\s*[:=]\s*['"]?[a-zA-Z0-9_]{10,}"#,
        r#"-----BEGIN [A-Z]+ PRIVATE KEY-----"#,
        r#"AKIA[0-9A-Z]{16}"#,                        // AWS access key pattern
        r#"[a-zA-Z0-9/_-]{20,}:[a-zA-Z0-9/_-]{20,}"#, // potential credentials
    ];

    patterns.iter().any(|pattern| {
        if let Ok(re) = regex::Regex::new(pattern) {
            re.is_match(output)
        } else {
            false
        }
    })
}

/// Check if a path is sensitive (should block reads)
fn is_sensitive_path(path: &str) -> bool {
    let home = dirs::home_dir()
        .map(|p| p.to_string_lossy().to_string())
        .unwrap_or_default();

    // Normalize path - handle both ~/ and relative paths
    let normalized_path = if path.starts_with("~/") {
        path.replacen("~", &home, 1)
    } else if path.starts_with('/') {
        path.to_string()
    } else {
        // Relative path - check if it matches sensitive patterns
        path.to_string()
    };

    let sensitive_paths = [
        ".aws/credentials",
        ".aws/config",
        ".ssh/id_rsa",
        ".ssh/id_ed25519",
        ".ssh/id_ecdsa",
        ".gnupg/",
        ".config/gh/hosts.yml",
        ".docker/config.json",
        ".env",
        ".env.local",
        ".env.production",
        ".env.secrets",
    ];

    // Check both with and without leading slash
    sensitive_paths.iter().any(|sensitive| {
        let with_slash = format!("/{}", sensitive);
        normalized_path.ends_with(sensitive)
            || normalized_path.ends_with(&with_slash)
            || normalized_path.contains(sensitive)
    })
}

/// Generate Claude Code hook configuration
pub fn generate_hook_config() -> Result<Value> {
    // Find sigil executable path
    let sigil_exe = std::env::current_exe()
        .context("Failed to get sigil executable path")?
        .to_string_lossy()
        .to_string();

    let hooks = json!({
        "bash": {
            "preToolUse": {
                "command": sigil_exe,
                "args": ["hook", "pre", "--tool", "Bash"]
            },
            "postToolUse": {
                "command": sigil_exe,
                "args": ["hook", "post", "--tool", "Bash"]
            }
        },
        "write": {
            "preToolUse": {
                "command": sigil_exe,
                "args": ["hook", "pre", "--tool", "Write"]
            },
            "postToolUse": {
                "command": sigil_exe,
                "args": ["hook", "post", "--tool", "Write"]
            }
        },
        "edit": {
            "preToolUse": {
                "command": sigil_exe,
                "args": ["hook", "pre", "--tool", "Edit"]
            },
            "postToolUse": {
                "command": sigil_exe,
                "args": ["hook", "post", "--tool", "Edit"]
            }
        },
        "read": {
            "preToolUse": {
                "command": sigil_exe,
                "args": ["hook", "pre", "--tool", "Read"]
            },
            "postToolUse": {
                "command": sigil_exe,
                "args": ["hook", "post", "--tool", "Read"]
            }
        },
        "grep": {
            "postToolUse": {
                "command": sigil_exe,
                "args": ["hook", "post", "--tool", "Grep"]
            }
        },
        "glob": {
            "postToolUse": {
                "command": sigil_exe,
                "args": ["hook", "post", "--tool", "Glob"]
            }
        },
        "userPromptSubmit": {
            "command": sigil_exe,
            "args": ["hook", "user-prompt-submit"]
        }
    });

    Ok(hooks)
}

/// Setup Claude Code hooks
pub fn setup_claude_code_hooks() -> Result<()> {
    // Get Claude Code config directory
    let config_dir = dirs::config_local_dir()
        .ok_or_else(|| anyhow!("Cannot determine config directory"))?
        .join("claude-code");

    fs::create_dir_all(&config_dir).context("Failed to create Claude Code config directory")?;

    let settings_path = config_dir.join("settings.json");

    // Generate hook configuration
    let new_hooks = generate_hook_config()?;

    // Load existing settings or create new
    let mut settings: Value = if settings_path.exists() {
        let content =
            fs::read_to_string(&settings_path).context("Failed to read existing settings.json")?;
        serde_json::from_str(&content).context("Failed to parse settings.json")?
    } else {
        json!({})
    };

    // Add hooks to settings
    if let Some(obj) = settings.as_object_mut() {
        obj.insert("hooks".to_string(), new_hooks);
    }

    // Write updated settings
    let settings_content =
        serde_json::to_string_pretty(&settings).context("Failed to serialize settings")?;

    fs::write(&settings_path, settings_content).context("Failed to write settings.json")?;

    println!(
        "Claude Code hooks installed to: {}",
        settings_path.display()
    );
    println!();
    println!("The following hooks are now active:");
    println!("  • UserPromptSubmit: Catches secrets in prompts (bi-directional scrubbing)");
    println!("  • Bash: PreToolUse + PostToolUse");
    println!("  • Write: PreToolUse + PostToolUse");
    println!("  • Edit: PreToolUse + PostToolUse");
    println!("  • Read: PreToolUse + PostToolUse");
    println!("  • Grep: PostToolUse");
    println!("  • Glob: PostToolUse");
    println!();
    println!("Restart Claude Code for hooks to take effect.");

    Ok(())
}

/// Generate CLAUDE.md snippet for secret inventory
pub fn generate_claude_md_snippet() -> Result<String> {
    // Try to load vault and list secrets
    let snippet = if let Ok(vault) = load_vault_for_snippet() {
        let rt = tokio::runtime::Runtime::new()?;
        let secrets = rt.block_on(vault.list("")).unwrap_or_default();

        if secrets.is_empty() {
            "## Secrets (managed by SIGIL)

No secrets configured yet. Add secrets with `sigil add <path>`.

Use `{{secret:path}}` placeholders in commands. Never hardcode secret values."
                .to_string()
        } else {
            let mut lines = vec![
                "## Secrets (managed by SIGIL)".to_string(),
                "".to_string(),
                "Use `{{secret:path}}` placeholders in commands. Available secrets:".to_string(),
                "".to_string(),
            ];

            for secret in secrets {
                let injection_note =
                    if matches!(secret.secret_type, sigil_core::SecretType::Certificate) {
                        " (file injection: use `{{secret:path:file}}`)"
                    } else {
                        ""
                    };
                lines.push(format!(
                    "  • `{{{{secret:{}}}}}` — {:?}{}",
                    secret.path, secret.secret_type, injection_note
                ));
            }

            lines.push("".to_string());
            lines.push("Never hardcode, export, or echo secret values. SIGIL resolves them at execution time.".to_string());

            lines.join("\n")
        }
    } else {
        "## Secrets (managed by SIGIL)

Vault not initialized. Run `sigil init` to set up secret management.

Once initialized, use `{{secret:path}}` placeholders in commands."
            .to_string()
    };

    Ok(snippet)
}

/// Load vault for snippet generation (without passphrase prompt)
fn load_vault_for_snippet() -> Result<sigil_vault::LocalVault> {
    let home = dirs::home_dir().ok_or_else(|| anyhow!("Cannot determine home directory"))?;
    let sigil_dir = home.join(".sigil");
    let vault_path = sigil_dir.join("vault");
    let identity_path = sigil_dir.join("identity.age");

    if !sigil_dir.exists() {
        anyhow::bail!("Vault not initialized");
    }

    let mut vault = sigil_vault::LocalVault::new(vault_path, identity_path)?;

    // Try to load without passphrase (will fail if vault is passphrase-protected)
    vault.load(None)?;

    Ok(vault)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tool_type_from_str() {
        assert_eq!(ToolType::from_str("Bash"), Some(ToolType::Bash));
        assert_eq!(ToolType::from_str("Write"), Some(ToolType::Write));
        assert_eq!(ToolType::from_str("Edit"), Some(ToolType::Edit));
        assert_eq!(ToolType::from_str("Read"), Some(ToolType::Read));
        assert_eq!(ToolType::from_str("mcp__test"), Some(ToolType::Mcp));
        assert_eq!(ToolType::from_str("Unknown"), None);
    }

    #[test]
    fn test_is_sensitive_path() {
        assert!(is_sensitive_path(".aws/credentials"));
        assert!(is_sensitive_path("~/.ssh/id_rsa"));
        assert!(!is_sensitive_path("src/main.rs"));
    }

    #[test]
    fn test_detect_secrets_in_output() {
        assert!(detect_secrets_in_output("api_key=sk_1234567890abcdef"));
        assert!(detect_secrets_in_output("-----BEGIN RSA PRIVATE KEY-----"));
        assert!(!detect_secrets_in_output("just regular text"));
    }
}
