//! SIGIL MCP Server - MCP server for secret management
//!
//! This module implements a Model Context Protocol (MCP) server that exposes
//! SIGIL's secret management capabilities to AI coding agents.
//!
//! MCP is a JSON-RPC 2.0-based protocol for tool integration. This server
//! communicates via stdio and provides the following tools:
//!
//! - `sigil_list` — List available secret paths and types (never values)
//! - `sigil_exec` — Execute command with secret injection + scrubbing
//! - `sigil_write` — Write file with secret placeholders resolved
//! - `sigil_env` — List available env var mappings (names only)
//! - `sigil_status` — Session stats and breach alerts

#![warn(missing_docs)]
#![warn(clippy::all)]

use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sigil_core::{operations::SealedOperation, SecretBackend};
use std::collections::HashMap;
use std::env;
use std::io::{self, Read, Write};
use tracing::{debug, error, info, warn};

/// JSON-RPC 2.0 request
#[derive(Debug, Deserialize)]
struct JsonRpcRequest {
    /// Request ID
    id: Value,
    /// Method name
    method: String,
    /// Parameters (optional)
    #[serde(default)]
    params: Value,
}

/// JSON-RPC 2.0 response
#[derive(Debug, Serialize)]
struct JsonRpcResponse {
    /// Request ID
    id: Value,
    /// Result or error
    #[serde(flatten)]
    result: JsonRpcResult,
}

/// JSON-RPC 2.0 result (success or error)
#[derive(Debug, Serialize)]
#[serde(untagged)]
enum JsonRpcResult {
    /// Success response
    Success { result: Value },
    /// Error response
    Error { error: JsonRpcError },
}

/// JSON-RPC 2.0 error
#[derive(Debug, Serialize)]
struct JsonRpcError {
    /// Error code
    code: i32,
    /// Error message
    message: String,
    /// Additional data (optional)
    #[serde(skip_serializing_if = "Option::is_none")]
    data: Option<Value>,
}

/// Tool definition for MCP
#[derive(Debug, Serialize)]
struct Tool {
    /// Tool name
    name: String,
    /// Tool description
    description: String,
    /// Input schema (JSON Schema)
    input_schema: Value,
}

/// MCP server state
#[derive(Debug)]
struct McpServer {
    /// Secret access log
    access_log: Vec<SecretAccess>,
    /// Breach alerts
    breaches: Vec<BreachAlert>,
    /// Start time
    start_time: DateTime<Utc>,
}

/// Secret access record
#[derive(Debug, Clone, Serialize)]
struct SecretAccess {
    /// Secret path
    path: String,
    /// Access timestamp
    accessed_at: DateTime<Utc>,
    /// Access method
    method: String,
}

/// Breach alert
#[derive(Debug, Clone, Serialize)]
struct BreachAlert {
    /// Alert timestamp
    timestamp: DateTime<Utc>,
    /// Alert severity
    severity: String,
    /// Alert message
    message: String,
}

impl Default for McpServer {
    fn default() -> Self {
        Self {
            access_log: Vec::new(),
            breaches: Vec::new(),
            start_time: Utc::now(),
        }
    }
}

impl McpServer {
    /// Create a new MCP server
    fn new() -> Self {
        Self::default()
    }

    /// Get available tools
    fn get_tools(&self) -> Vec<Tool> {
        vec![
            Tool {
                name: "sigil_list".to_string(),
                description: "List available secret paths and types. Never returns secret values.".to_string(),
                input_schema: json!({
                    "type": "object",
                    "properties": {
                        "prefix": {
                            "type": "string",
                            "description": "Filter secrets by prefix (e.g., 'aws/')"
                        }
                    }
                }),
            },
            Tool {
                name: "sigil_exec".to_string(),
                description: "Execute a command with secret injection, sandbox, and output scrubbing. Can execute arbitrary commands or pre-defined sealed operations.".to_string(),
                input_schema: json!({
                    "type": "object",
                    "properties": {
                        "command": {
                            "type": "string",
                            "description": "Command to execute. Use {{secret:path}} placeholders for secrets. Either 'command' or 'operation' must be provided."
                        },
                        "operation": {
                            "type": "string",
                            "description": "Sealed operation ID to execute. Either 'command' or 'operation' must be provided."
                        },
                        "sandbox": {
                            "type": "boolean",
                            "description": "Enable sandboxing (default: true)",
                            "default": true
                        }
                    }
                }),
            },
            Tool {
                name: "sigil_write".to_string(),
                description: "Write a file with secret placeholders resolved. Use for configs, certificates, etc.".to_string(),
                input_schema: json!({
                    "type": "object",
                    "properties": {
                        "path": {
                            "type": "string",
                            "description": "File path to write"
                        },
                        "content": {
                            "type": "string",
                            "description": "File content with {{secret:path}} placeholders"
                        },
                        "mode": {
                            "type": "string",
                            "enum": ["overwrite", "append"],
                            "description": "Write mode (default: overwrite)",
                            "default": "overwrite"
                        }
                    },
                    "required": ["path", "content"]
                }),
            },
            Tool {
                name: "sigil_env".to_string(),
                description: "List available environment variable mappings (names only, not values).".to_string(),
                input_schema: json!({
                    "type": "object",
                    "properties": {
                        "prefix": {
                            "type": "string",
                            "description": "Filter env vars by prefix"
                        }
                    }
                }),
            },
            Tool {
                name: "sigil_status".to_string(),
                description: "Show session statistics and breach alerts.".to_string(),
                input_schema: json!({
                    "type": "object",
                    "properties": {}
                }),
            },
            Tool {
                name: "sigil_list_operations".to_string(),
                description: "List available sealed operations (descriptions only, not commands).".to_string(),
                input_schema: json!({
                    "type": "object",
                    "properties": {}
                }),
            },
            Tool {
                name: "sigil_request".to_string(),
                description: "Request access to a secret with human approval (triggers TUI prompt).".to_string(),
                input_schema: json!({
                    "type": "object",
                    "properties": {
                        "secret": {
                            "type": "string",
                            "description": "Secret path to request access to"
                        },
                        "reason": {
                            "type": "string",
                            "description": "Reason for requesting access"
                        },
                        "duration": {
                            "type": "string",
                            "description": "Requested duration (e.g., '5m', '1h', 'session')"
                        }
                    },
                    "required": ["secret", "reason"]
                }),
            },
            Tool {
                name: "sigil_check_access".to_string(),
                description: "Check if access to a secret is currently granted.".to_string(),
                input_schema: json!({
                    "type": "object",
                    "properties": {
                        "secret": {
                            "type": "string",
                            "description": "Secret path to check"
                        }
                    },
                    "required": ["secret"]
                }),
            },
        ]
    }

    /// Handle a tool call
    fn handle_tool_call(&mut self, name: &str, args: Value) -> Result<Value> {
        match name {
            "sigil_list" => self.handle_list(args),
            "sigil_exec" => self.handle_exec(args),
            "sigil_write" => self.handle_write(args),
            "sigil_env" => self.handle_env(args),
            "sigil_status" => self.handle_status(args),
            "sigil_list_operations" => self.handle_list_operations(args),
            "sigil_request" => self.handle_request(args),
            "sigil_check_access" => self.handle_check_access(args),
            _ => Err(anyhow::anyhow!("Unknown tool: {}", name)),
        }
    }

    /// Handle sigil_list tool
    fn handle_list(&mut self, args: Value) -> Result<Value> {
        let prefix = args.get("prefix").and_then(|v| v.as_str()).unwrap_or("");

        info!("Listing secrets with prefix: '{}'", prefix);

        // Try to load vault and list secrets
        let result = match self.load_vault() {
            Ok(vault) => {
                let rt = tokio::runtime::Runtime::new()?;
                match rt.block_on(vault.list(prefix)) {
                    Ok(secrets_meta) => {
                        let secrets_json: Vec<Value> = secrets_meta
                            .iter()
                            .map(|meta| {
                                json!({
                                    "path": meta.path.as_str(),
                                    "type": format!("{:?}", meta.secret_type),
                                    "created_at": meta.created_at.to_rfc3339(),
                                    "updated_at": meta.updated_at.to_rfc3339(),
                                    "tags": meta.tags,
                                })
                            })
                            .collect();

                        json!({
                            "secrets": secrets_json,
                            "count": secrets_json.len()
                        })
                    }
                    Err(e) => {
                        warn!("Failed to list secrets: {}", e);
                        json!({
                            "secrets": [],
                            "count": 0,
                            "error": format!("Failed to list secrets: {}", e)
                        })
                    }
                }
            }
            Err(e) => {
                warn!("Vault not loaded: {}", e);
                json!({
                    "secrets": [],
                    "count": 0,
                    "error": format!("Vault not initialized: {}", e)
                })
            }
        };

        Ok(result)
    }

    /// Handle sigil_exec tool
    fn handle_exec(&mut self, args: Value) -> Result<Value> {
        let sandbox = args
            .get("sandbox")
            .and_then(|v| v.as_bool())
            .unwrap_or(true);

        // Check if operation or command is provided
        let operation_id = args.get("operation").and_then(|v| v.as_str());
        let command = args.get("command").and_then(|v| v.as_str());

        // Either operation or command must be provided, but not both
        let (command_to_execute, operation_name, output_filter) = match (operation_id, command) {
            (Some(op_id), None) => {
                // Load operation from file
                let op = self.load_operation(op_id)?;
                info!(
                    "Executing sealed operation '{}' (sandbox={})",
                    op_id, sandbox
                );
                (op.command, Some(op_id.to_string()), Some(op.output_filter))
            }
            (None, Some(cmd)) => {
                info!("Executing arbitrary command (sandbox={}): {}", sandbox, cmd);
                (cmd.to_string(), None, None)
            }
            (Some(_), Some(_)) => {
                return Err(anyhow::anyhow!(
                    "Cannot specify both 'operation' and 'command'. Use one or the other."
                ));
            }
            (None, None) => {
                return Err(anyhow::anyhow!(
                    "Either 'operation' or 'command' must be provided"
                ));
            }
        };

        // Execute through the daemon
        let rt = tokio::runtime::Runtime::new()?;
        rt.block_on(async {
            use sigil_core::{write_message_async, IpcOperation, IpcRequest};
            use tokio::net::UnixStream;

            // Get socket path from environment or use default
            let socket_path = std::env::var("XDG_RUNTIME_DIR")
                .map(|d| std::path::PathBuf::from(d).join("sigil.sock"))
                .unwrap_or_else(|_| {
                    std::path::PathBuf::from(format!(
                        "{}/.sigil/sigild.sock",
                        std::env::var("HOME").unwrap_or_else(|_| ".".to_string())
                    ))
                });

            // Parse command into program and args
            let parts: Vec<String> = shell_words::split(&command_to_execute)
                .map_err(|e| anyhow::anyhow!("Failed to parse command: {}", e))?;

            if parts.is_empty() {
                return Err(anyhow::anyhow!("Empty command"));
            }

            let program = parts[0].clone();
            let args = parts[1..].to_vec();

            // Connect to daemon
            let mut stream = UnixStream::connect(&socket_path).await.with_context(|| {
                format!(
                    "Failed to connect to daemon at {:?}. Is sigild running?",
                    socket_path
                )
            })?;

            // Get session token from environment or generate a temporary one
            let session_token = std::env::var("SIGIL_SESSION_TOKEN")
                .unwrap_or_else(|_| {
                    // For MCP server, we'll use a shared session token
                    // In production, this should be properly initialized
                    "mcp-session-token".to_string()
                });

            // Create exec request
            let exec_request = sigil_core::ipc::ExecRequest {
                command: program,
                args,
                working_dir: std::env::current_dir()
                    .ok()
                    .and_then(|p| p.to_str().map(|s| s.to_string())),
                network_isolated: !sandbox, // If sandbox is false, we might still want network isolation
                project_dir: std::env::var("PROJECT_DIR").ok(),
                timeout_secs: 300, // 5 minutes default
            };

            let request = IpcRequest::with_payload(
                IpcOperation::Exec,
                session_token,
                serde_json::to_value(exec_request)?,
            );

            // Send request
            let json = serde_json::to_vec(&request)?;
            write_message_async(&mut stream, &json).await?;

            // Read response
            let data = sigil_core::read_message_async(&mut stream).await?;
            let response: sigil_core::IpcResponse =
                serde_json::from_slice(&data).context("Invalid response from daemon")?;

            if response.ok {
                let exec_response: sigil_core::ipc::ExecResponse =
                    serde_json::from_value(response.payload)
                        .context("Invalid exec response from daemon")?;

                // Apply output filter if this is a sealed operation
                let output = match output_filter {
                    Some(sigil_core::OutputFilter::ExitCode) => {
                        format!("Exit code: {}", exec_response.exit_code)
                    }
                    Some(sigil_core::OutputFilter::Summary) => {
                        // Return a summary with exit code and duration
                        format!(
                            "Command completed in {}ms with exit code {}. Secrets scrububbed: {}.",
                            exec_response.duration_ms,
                            exec_response.exit_code,
                            exec_response.secrets_scrubbed
                        )
                    }
                    Some(sigil_core::OutputFilter::FullScrubbed) | None => {
                        // Combine stdout and stderr
                        let mut output = String::new();
                        if !exec_response.stdout.is_empty() {
                            output.push_str(&exec_response.stdout);
                        }
                        if !exec_response.stderr.is_empty() {
                            if !output.is_empty() {
                                output.push('\n');
                            }
                            output.push_str(&exec_response.stderr);
                        }
                        output
                    }
                    Some(sigil_core::OutputFilter::None) => {
                        // No output (for operations that only care about side effects)
                        String::new()
                    }
                };

                // Log the access
                self.access_log.push(SecretAccess {
                    path: operation_name.clone().unwrap_or_else(|| command_to_execute.clone()),
                    accessed_at: Utc::now(),
                    method: "sigil_exec".to_string(),
                });

                Ok(json!({
                    "output": output,
                    "exit_code": exec_response.exit_code,
                    "timed_out": exec_response.timed_out,
                    "duration_ms": exec_response.duration_ms,
                    "secrets_scrubbed": exec_response.secrets_scrubbed,
                    "sandbox": sandbox,
                    "operation": operation_name,
                    "matched_signatures": exec_response.matched_signatures
                }))
            } else {
                if let Some(error) = response.error {
                    Ok(json!({
                        "output": format!("Command execution failed: {}", error.message),
                        "exit_code": -1,
                        "error": error.code.to_string(),
                        "sandbox": sandbox,
                        "operation": operation_name
                    }))
                } else {
                    Ok(json!({
                        "output": "Command execution failed with unknown error",
                        "exit_code": -1,
                        "sandbox": sandbox,
                        "operation": operation_name
                    }))
                }
            }
        })
    }

    /// Load a sealed operation by ID
    fn load_operation(&self, operation_id: &str) -> Result<SealedOperation> {
        let home =
            dirs::home_dir().ok_or_else(|| anyhow::anyhow!("Cannot determine home directory"))?;
        let sigil_dir = home.join(".sigil");
        let operations_file = sigil_dir.join("operations.toml");

        if !operations_file.exists() {
            anyhow::bail!("Operations file not found. No sealed operations configured.");
        }

        // Read operations file
        let content = std::fs::read_to_string(&operations_file)
            .map_err(|e| anyhow::anyhow!("Failed to read operations file: {}", e))?;

        // Parse TOML
        let value: toml::Value = content
            .parse()
            .map_err(|e| anyhow::anyhow!("Failed to parse operations file: {}", e))?;

        // Extract the requested operation
        if let Some(ops) = value.get("operations") {
            if let Some(table) = ops.as_table() {
                if let Some(op_value) = table.get(operation_id) {
                    // Parse the operation
                    let description = op_value
                        .get("description")
                        .and_then(|v| v.as_str())
                        .unwrap_or("No description")
                        .to_string();

                    let command = op_value
                        .get("command")
                        .and_then(|v| v.as_str())
                        .ok_or_else(|| anyhow::anyhow!("Operation missing 'command' field"))?
                        .to_string();

                    // Parse secrets array
                    let secrets = op_value
                        .get("secrets")
                        .and_then(|v| v.as_array())
                        .map(|arr| {
                            arr.iter()
                                .filter_map(|v| v.as_str().map(|s| s.to_string()))
                                .collect()
                        })
                        .unwrap_or_default();

                    // Parse output_filter
                    let output_filter_str = op_value
                        .get("output_filter")
                        .and_then(|v| v.as_str())
                        .unwrap_or("exit_code");

                    let output_filter = match output_filter_str {
                        "exit_code" => sigil_core::OutputFilter::ExitCode,
                        "summary" => sigil_core::OutputFilter::Summary,
                        "full_scrubbed" => sigil_core::OutputFilter::FullScrubbed,
                        "none" => sigil_core::OutputFilter::None,
                        _ => sigil_core::OutputFilter::default(),
                    };

                    // Parse require_approval
                    let require_approval = op_value
                        .get("require_approval")
                        .and_then(|v| v.as_bool())
                        .unwrap_or(true);

                    // Parse timeout
                    let timeout_seconds = op_value
                        .get("timeout_seconds")
                        .and_then(|v| v.as_integer())
                        .map(|v| v as u64);

                    // Parse summary_regex
                    let summary_regex = op_value
                        .get("summary_regex")
                        .and_then(|v| v.as_str())
                        .map(|s| s.to_string());

                    return Ok(sigil_core::SealedOperation {
                        id: operation_id.to_string(),
                        description,
                        command,
                        secrets,
                        output_filter,
                        summary_regex,
                        require_approval,
                        timeout_seconds,
                    });
                }
            }
        }

        anyhow::bail!("Operation '{}' not found", operation_id)
    }

    /// Handle sigil_write tool
    fn handle_write(&mut self, args: Value) -> Result<Value> {
        let path = args
            .get("path")
            .and_then(|v| v.as_str())
            .ok_or_else(|| anyhow::anyhow!("Missing 'path' argument"))?;

        let content = args
            .get("content")
            .and_then(|v| v.as_str())
            .ok_or_else(|| anyhow::anyhow!("Missing 'content' argument"))?;

        let mode = args
            .get("mode")
            .and_then(|v| v.as_str())
            .unwrap_or("overwrite");

        info!("Writing to file: {} (mode: {})", path, mode);

        // Check for secret patterns in content
        let resolved_content = if content.contains("{{secret:") {
            // Has placeholders - resolve them using the vault
            match self.resolve_placeholders(content) {
                Ok(resolved) => resolved,
                Err(e) => {
                    warn!("Failed to resolve placeholders: {}", e);
                    // If resolution fails, write with placeholders intact
                    content.to_string()
                }
            }
        } else {
            // No placeholders - use content as-is
            content.to_string()
        };

        // Write the file
        match mode {
            "append" => {
                use std::fs::OpenOptions;
                let mut file = OpenOptions::new()
                    .create(true)
                    .append(true)
                    .open(path)?;
                use std::io::Write;
                writeln!(file, "{}", resolved_content)?;
            }
            _ => {
                std::fs::write(path, &resolved_content)?;
            }
        }

        Ok(json!({
            "path": path,
            "bytes_written": resolved_content.len(),
            "mode": mode
        }))
    }

    /// Resolve secret placeholders in content
    fn resolve_placeholders(&self, content: &str) -> Result<String> {
        use regex::Regex;
        use sigil_core::SecretPath;

        // Regex to match {{secret:path}} or {{secret:path:mode}} patterns
        let re = Regex::new(r"\{\{secret:([^}:]+)(?::([^}]+))?\}\}")?;

        let vault = self.load_vault()?;
        let rt = tokio::runtime::Runtime::new()?;

        let mut resolved = content.to_string();

        for cap in re.captures_iter(content) {
            let secret_path_str = cap.get(1).unwrap().as_str();
            let mode = cap.get(2).map(|m| m.as_str());

            // Create SecretPath
            let secret_path = SecretPath::new(secret_path_str)?;

            // Get secret value from vault
            let secret_value = rt.block_on(vault.get(&secret_path))?;

            // Decode the secret value using the expose method
            let value_str = secret_value.expose(|bytes| {
                String::from_utf8_lossy(bytes).to_string()
            });

            // Determine replacement based on mode
            let replacement = match mode {
                Some("file") => {
                    // For file mode, the placeholder is replaced with a file path reference
                    // In this context, we just use the value directly
                    value_str.clone()
                }
                _ => value_str,
            };

            // Replace the placeholder with the actual value
            let placeholder = cap.get(0).unwrap().as_str();
            resolved = resolved.replace(placeholder, &replacement);

            // Log the access
            // Note: We're using a mutable reference workaround here
            // In production, this should be handled differently
        }

        Ok(resolved)
    }

    /// Handle sigil_env tool
    fn handle_env(&mut self, args: Value) -> Result<Value> {
        let prefix = args.get("prefix").and_then(|v| v.as_str()).unwrap_or("");

        info!("Listing env vars with prefix: '{}'", prefix);

        // Return environment variables with given prefix
        let vars: HashMap<String, String> = env::vars()
            .filter(|(k, _)| {
                if prefix.is_empty() {
                    // Filter out sensitive-looking vars
                    !k.contains("KEY")
                        && !k.contains("SECRET")
                        && !k.contains("PASSWORD")
                        && !k.contains("TOKEN")
                } else {
                    k.starts_with(prefix)
                }
            })
            .collect();

        let names: Vec<&str> = vars.keys().map(|k| k.as_str()).collect();

        Ok(json!({
            "variables": names,
            "count": names.len()
        }))
    }

    /// Handle sigil_status tool
    fn handle_status(&self, _args: Value) -> Result<Value> {
        let uptime = Utc::now().signed_duration_since(self.start_time);

        Ok(json!({
            "uptime_seconds": uptime.num_seconds(),
            "uptime_human": format!("{}h {}m", uptime.num_hours(), uptime.num_minutes() % 60),
            "secrets_accessed": self.access_log.len(),
            "breach_count": self.breaches.len(),
            "breaches": self.breaches,
            "recent_access": self.access_log.iter().rev().take(10).collect::<Vec<_>>()
        }))
    }

    /// Handle sigil_list_operations tool
    fn handle_list_operations(&mut self, _args: Value) -> Result<Value> {
        info!("Listing sealed operations");

        // Try to load operations from config
        let home =
            dirs::home_dir().ok_or_else(|| anyhow::anyhow!("Cannot determine home directory"))?;
        let sigil_dir = home.join(".sigil");
        let operations_file = sigil_dir.join("operations.toml");

        if !operations_file.exists() {
            // No operations configured
            return Ok(json!({
                "operations": [],
                "count": 0
            }));
        }

        // Read operations file
        let content = std::fs::read_to_string(&operations_file)
            .map_err(|e| anyhow::anyhow!("Failed to read operations file: {}", e))?;

        // Parse TOML
        let value: toml::Value = content
            .parse()
            .map_err(|e| anyhow::anyhow!("Failed to parse operations file: {}", e))?;

        // Extract operations (descriptions only, not commands)
        let operations = if let Some(ops) = value.get("operations") {
            if let Some(table) = ops.as_table() {
                table
                    .iter()
                    .map(|(name, op)| {
                        let description = op
                            .get("description")
                            .and_then(|v| v.as_str())
                            .unwrap_or("No description");
                        json!({
                            "name": name,
                            "description": description
                        })
                    })
                    .collect()
            } else {
                Vec::new()
            }
        } else {
            Vec::new()
        };

        Ok(json!({
            "operations": operations,
            "count": operations.len()
        }))
    }

    /// Handle sigil_request tool
    fn handle_request(&mut self, args: Value) -> Result<Value> {
        let secret = args
            .get("secret")
            .and_then(|v| v.as_str())
            .ok_or_else(|| anyhow::anyhow!("Missing 'secret' argument"))?;

        let reason = args
            .get("reason")
            .and_then(|v| v.as_str())
            .ok_or_else(|| anyhow::anyhow!("Missing 'reason' argument"))?;

        let duration = args
            .get("duration")
            .and_then(|v| v.as_str())
            .unwrap_or("5m");

        info!(
            "Requesting access to secret '{}' (duration: {}, reason: {})",
            secret, duration, reason
        );

        // Connect to daemon and send request
        let rt = tokio::runtime::Runtime::new()?;
        rt.block_on(async {
            use sigil_core::{write_message_async, IpcOperation, IpcRequest};
            use tokio::net::UnixStream;

            // Connect to daemon
            let socket_path = std::env::var("SIGIL_SOCKET").unwrap_or_else(|_| {
                format!(
                    "{}/.sigil/sigild.sock",
                    std::env::var("HOME").unwrap_or_else(|_| ".".to_string())
                )
            });

            let mut stream = UnixStream::connect(&socket_path).await.with_context(|| {
                format!(
                    "Failed to connect to daemon at {}. Is sigild running?",
                    socket_path
                )
            })?;

            let session_token =
                std::env::var("SIGIL_SESSION_TOKEN").unwrap_or_else(|_| "test-token".to_string());

            // Create request access payload
            let payload = sigil_core::ipc::RequestAccessPayload {
                secret: secret.to_string(),
                reason: reason.to_string(),
                duration: duration.to_string(),
                agent_id: Some("mcp-server".to_string()),
            };

            let request = IpcRequest::with_payload(
                IpcOperation::RequestAccess,
                session_token,
                serde_json::to_value(payload)?,
            );

            // Send request
            let json = serde_json::to_vec(&request)?;
            write_message_async(&mut stream, &json).await?;

            // Read response
            let data = sigil_core::read_message_async(&mut stream).await?;
            let response: sigil_core::IpcResponse =
                serde_json::from_slice(&data).context("Invalid response from daemon")?;

            if response.ok {
                let result: sigil_core::ipc::RequestAccessResponse =
                    serde_json::from_value(response.payload)
                        .context("Invalid response payload from daemon")?;

                Ok(json!({
                    "status": if result.granted { "granted" } else { "denied" },
                    "message": result.message,
                    "secret": secret,
                    "reason": reason,
                    "duration": duration,
                    "expires_at": result.expires_at,
                    "grant_id": result.grant_id
                }))
            } else {
                if let Some(error) = response.error {
                    Ok(json!({
                        "status": "denied",
                        "message": error.message,
                        "secret": secret,
                        "error": error.code.to_string()
                    }))
                } else {
                    Ok(json!({
                        "status": "denied",
                        "message": "Request failed with unknown error",
                        "secret": secret
                    }))
                }
            }
        })
    }

    /// Handle sigil_check_access tool
    fn handle_check_access(&mut self, args: Value) -> Result<Value> {
        let secret = args
            .get("secret")
            .and_then(|v| v.as_str())
            .ok_or_else(|| anyhow::anyhow!("Missing 'secret' argument"))?;

        info!("Checking access to secret: '{}'", secret);

        // Connect to daemon and check access
        let rt = tokio::runtime::Runtime::new()?;
        rt.block_on(async {
            use sigil_core::{write_message_async, IpcOperation, IpcRequest};
            use tokio::net::UnixStream;

            // Connect to daemon
            let socket_path = std::env::var("SIGIL_SOCKET").unwrap_or_else(|_| {
                format!(
                    "{}/.sigil/sigild.sock",
                    std::env::var("HOME").unwrap_or_else(|_| ".".to_string())
                )
            });

            let mut stream = UnixStream::connect(&socket_path).await.with_context(|| {
                format!(
                    "Failed to connect to daemon at {}. Is sigild running?",
                    socket_path
                )
            })?;

            let session_token =
                std::env::var("SIGIL_SESSION_TOKEN").unwrap_or_else(|_| "test-token".to_string());

            // Create check access payload
            let payload = sigil_core::ipc::CheckAccessPayload {
                secret: secret.to_string(),
            };

            let request = IpcRequest::with_payload(
                IpcOperation::CheckAccess,
                session_token,
                serde_json::to_value(payload)?,
            );

            // Send request
            let json = serde_json::to_vec(&request)?;
            write_message_async(&mut stream, &json).await?;

            // Read response
            let data = sigil_core::read_message_async(&mut stream).await?;
            let response: sigil_core::IpcResponse =
                serde_json::from_slice(&data).context("Invalid response from daemon")?;

            if response.ok {
                let result: sigil_core::ipc::CheckAccessResponse =
                    serde_json::from_value(response.payload)
                        .context("Invalid response payload from daemon")?;

                Ok(json!({
                    "secret": secret,
                    "granted": result.granted,
                    "status": result.status,
                    "expires_in": result.expires_in
                }))
            } else {
                if let Some(error) = response.error {
                    Ok(json!({
                        "secret": secret,
                        "granted": false,
                        "status": error.message,
                        "error": error.code.to_string()
                    }))
                } else {
                    Ok(json!({
                        "secret": secret,
                        "granted": false,
                        "status": "Access check failed"
                    }))
                }
            }
        })
    }

    /// Load the vault
    fn load_vault(&self) -> Result<sigil_vault::LocalVault> {
        let home =
            dirs::home_dir().ok_or_else(|| anyhow::anyhow!("Cannot determine home directory"))?;
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

    /// Process a single JSON-RPC request
    fn process_request(&mut self, request: JsonRpcRequest) -> JsonRpcResponse {
        debug!("Processing request: method={}", request.method);

        let result = match request.method.as_str() {
            "initialize" => {
                info!("MCP server initialized");
                Ok(json!({
                    "protocolVersion": "2024-11-05",
                    "serverInfo": {
                        "name": "sigil-mcp",
                        "version": env!("CARGO_PKG_VERSION")
                    },
                    "capabilities": {
                        "tools": {}
                    }
                }))
            }
            "tools/list" => {
                let tools = self.get_tools();
                Ok(json!({ "tools": tools }))
            }
            "tools/call" => {
                let tool_name = request
                    .params
                    .get("name")
                    .and_then(|v| v.as_str())
                    .unwrap_or("");

                let arguments = request
                    .params
                    .get("arguments")
                    .cloned()
                    .unwrap_or(json!({}));

                match self.handle_tool_call(tool_name, arguments) {
                    Ok(result) => Ok(json!({
                        "content": [{
                            "type": "text",
                            "text": serde_json::to_string_pretty(&result).unwrap_or_default()
                        }]
                    })),
                    Err(e) => Err(e),
                }
            }
            _ => Err(anyhow::anyhow!("Unknown method: {}", request.method)),
        };

        JsonRpcResponse {
            id: request.id,
            result: match result {
                Ok(v) => JsonRpcResult::Success { result: v },
                Err(e) => JsonRpcResult::Error {
                    error: JsonRpcError {
                        code: -32603,
                        message: e.to_string(),
                        data: None,
                    },
                },
            },
        }
    }
}

/// Run the MCP server (stdio-based)
fn run_server() -> Result<()> {
    // Initialize logging
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env()
                .add_directive(tracing::Level::INFO.into()),
        )
        .init();

    let mut server = McpServer::new();
    let mut stdin = io::stdin();
    let mut stdout = io::stdout();

    info!("SIGIL MCP server starting");

    loop {
        // Read a line from stdin
        let mut line = String::new();
        let bytes_read = stdin.read_to_string(&mut line)?;

        if bytes_read == 0 {
            // EOF
            info!("MCP server shutting down (EOF)");
            break;
        }

        // Parse JSON-RPC request
        let request: JsonRpcRequest = match serde_json::from_str(&line) {
            Ok(req) => req,
            Err(e) => {
                error!("Failed to parse request: {}", e);
                continue;
            }
        };

        // Process request and send response
        let response = server.process_request(request);
        let response_json = serde_json::to_string(&response)?;

        writeln!(stdout, "{}", response_json)?;
        stdout.flush()?;
    }

    Ok(())
}

fn main() -> Result<()> {
    run_server()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mcp_server_creation() {
        let server = McpServer::new();
        assert_eq!(server.access_log.len(), 0);
        assert_eq!(server.breaches.len(), 0);
    }

    #[test]
    fn test_get_tools() {
        let server = McpServer::new();
        let tools = server.get_tools();
        assert_eq!(tools.len(), 8);

        let tool_names: Vec<&str> = tools.iter().map(|t| t.name.as_str()).collect();
        assert!(tool_names.contains(&"sigil_list"));
        assert!(tool_names.contains(&"sigil_exec"));
        assert!(tool_names.contains(&"sigil_write"));
        assert!(tool_names.contains(&"sigil_env"));
        assert!(tool_names.contains(&"sigil_status"));
        assert!(tool_names.contains(&"sigil_list_operations"));
        assert!(tool_names.contains(&"sigil_request"));
        assert!(tool_names.contains(&"sigil_check_access"));
    }

    #[test]
    fn test_handle_status() {
        let server = McpServer::new();
        let result = server.handle_status(json!({})).unwrap();
        assert_eq!(result["breach_count"], 0);
        assert_eq!(result["secrets_accessed"], 0);
    }
}
