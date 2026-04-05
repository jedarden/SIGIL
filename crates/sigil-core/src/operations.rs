//! Sealed Operations - Pre-defined command templates with output filtering
//!
//! Sealed operations allow users to define sensitive operations that agents can
//! trigger without seeing secrets, commands, or unfiltered output.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Output filter mode for sealed operations
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum OutputFilter {
    /// Agent sees only exit code and "succeeded"/"failed"
    #[default]
    ExitCode,
    /// Agent sees a one-line summary extracted by regex
    Summary,
    /// Agent sees complete scrubbed output (secrets redacted)
    FullScrubbed,
    /// Agent sees nothing (fire-and-forget)
    None,
}

/// A sealed operation definition
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SealedOperation {
    /// Unique identifier for this operation
    pub id: String,
    /// Human-readable description (shown to agent)
    pub description: String,
    /// Command template with {{secret:path}} placeholders
    pub command: String,
    /// List of secret paths required by this operation
    pub secrets: Vec<String>,
    /// Output filter mode
    #[serde(default)]
    pub output_filter: OutputFilter,
    /// Optional regex for extracting summary (used with OutputFilter::Summary)
    #[serde(default)]
    pub summary_regex: Option<String>,
    /// Whether this operation requires TUI approval before execution
    #[serde(default)]
    pub require_approval: bool,
    /// Maximum execution time in seconds (None for unlimited)
    #[serde(default)]
    pub timeout_seconds: Option<u64>,
}

impl SealedOperation {
    /// Create a new sealed operation
    pub fn new(id: String, description: String, command: String) -> Self {
        Self {
            id,
            description,
            command,
            secrets: Vec::new(),
            output_filter: OutputFilter::default(),
            summary_regex: None,
            require_approval: true,
            timeout_seconds: Some(300), // 5 minutes default
        }
    }

    /// Add a required secret
    pub fn with_secret(mut self, secret: String) -> Self {
        self.secrets.push(secret);
        self
    }

    /// Set the output filter mode
    pub fn with_output_filter(mut self, filter: OutputFilter) -> Self {
        self.output_filter = filter;
        self
    }

    /// Set the summary regex
    pub fn with_summary_regex(mut self, regex: String) -> Self {
        self.summary_regex = Some(regex);
        self
    }

    /// Set whether approval is required
    pub fn with_approval(mut self, require_approval: bool) -> Self {
        self.require_approval = require_approval;
        self
    }

    /// Set the timeout
    pub fn with_timeout(mut self, timeout_seconds: u64) -> Self {
        self.timeout_seconds = Some(timeout_seconds);
        self
    }

    /// Extract secrets from the command template
    pub fn extract_secrets(&self) -> Vec<String> {
        // Parse {{secret:path}} placeholders from command
        let mut secrets = Vec::new();
        let char_indices: Vec<(usize, char)> = self.command.char_indices().collect();
        let mut i = 0;

        while i < char_indices.len() {
            if char_indices[i].1 == '{'
                && i + 1 < char_indices.len()
                && char_indices[i + 1].1 == '{'
            {
                let mut placeholder = String::new();
                let mut j = i + 2;
                let mut found = false;

                while j < char_indices.len() {
                    if char_indices[j].1 == '}'
                        && j + 1 < char_indices.len()
                        && char_indices[j + 1].1 == '}'
                    {
                        found = true;
                        break;
                    }
                    placeholder.push(char_indices[j].1);
                    j += 1;
                }

                if found && placeholder.starts_with("secret:") {
                    secrets.push(placeholder[7..].to_string());
                }

                i = j + 2;
                continue;
            }
            i += 1;
        }

        secrets
    }

    /// Validate the operation
    pub fn validate(&self) -> Result<(), String> {
        if self.id.is_empty() {
            return Err("Operation ID cannot be empty".to_string());
        }

        if self.description.is_empty() {
            return Err("Operation description cannot be empty".to_string());
        }

        if self.command.is_empty() {
            return Err("Operation command cannot be empty".to_string());
        }

        // Validate summary regex if present
        if self.output_filter == OutputFilter::Summary && self.summary_regex.is_none() {
            return Err("Summary output filter requires summary_regex".to_string());
        }

        // Validate regex syntax
        if let Some(regex) = &self.summary_regex {
            if regex::Regex::new(regex).is_err() {
                return Err(format!("Invalid summary regex: {}", regex));
            }
        }

        Ok(())
    }
}

/// Collection of sealed operations
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct OperationsRegistry {
    /// Map of operation ID to operation definition
    operations: HashMap<String, SealedOperation>,
}

impl OperationsRegistry {
    /// Create a new empty registry
    pub fn new() -> Self {
        Self {
            operations: HashMap::new(),
        }
    }

    /// Add an operation to the registry
    pub fn add(&mut self, operation: SealedOperation) -> Result<(), String> {
        operation.validate()?;
        self.operations.insert(operation.id.clone(), operation);
        Ok(())
    }

    /// Get an operation by ID
    pub fn get(&self, id: &str) -> Option<&SealedOperation> {
        self.operations.get(id)
    }

    /// Remove an operation by ID
    pub fn remove(&mut self, id: &str) -> Option<SealedOperation> {
        self.operations.remove(id)
    }

    /// List all operation IDs
    pub fn list(&self) -> Vec<String> {
        self.operations.keys().cloned().collect()
    }

    /// Get the number of operations
    pub fn len(&self) -> usize {
        self.operations.len()
    }

    /// Check if the registry is empty
    pub fn is_empty(&self) -> bool {
        self.operations.is_empty()
    }

    /// Load operations from TOML
    pub fn from_toml(toml_str: &str) -> Result<Self, String> {
        // Parse as a generic Value to handle the flattened structure
        let value: toml::Value = toml::from_str(toml_str)
            .map_err(|e| format!("Failed to parse operations TOML: {}", e))?;

        let mut registry = Self::new();

        // The TOML is structured as:
        // [operations.operation_id]
        // description = "..."
        // command = "..."

        if let Some(table) = value.as_table() {
            for (key, nested) in table {
                if let Some(nested_table) = nested.as_table() {
                    let description = nested_table
                        .get("description")
                        .and_then(|v| v.as_str())
                        .ok_or_else(|| format!("Operation '{}' missing description", key))?;

                    let command = nested_table
                        .get("command")
                        .and_then(|v| v.as_str())
                        .ok_or_else(|| format!("Operation '{}' missing command", key))?;

                    let mut operation = SealedOperation::new(
                        key.clone(),
                        description.to_string(),
                        command.to_string(),
                    );

                    // Parse optional fields
                    if let Some(secrets) = nested_table.get("secrets").and_then(|v| v.as_array()) {
                        for secret in secrets {
                            if let Some(s) = secret.as_str() {
                                operation = operation.with_secret(s.to_string());
                            }
                        }
                    }

                    if let Some(filter) = nested_table.get("output_filter").and_then(|v| v.as_str())
                    {
                        let filter_type = match filter {
                            "exit_code" => OutputFilter::ExitCode,
                            "summary" => OutputFilter::Summary,
                            "full_scrubbed" => OutputFilter::FullScrubbed,
                            "none" => OutputFilter::None,
                            _ => return Err(format!("Invalid output_filter: {}", filter)),
                        };
                        operation = operation.with_output_filter(filter_type);
                    }

                    if let Some(regex) = nested_table.get("summary_regex").and_then(|v| v.as_str())
                    {
                        operation = operation.with_summary_regex(regex.to_string());
                    }

                    if let Some(approval) = nested_table
                        .get("require_approval")
                        .and_then(|v| v.as_bool())
                    {
                        operation = operation.with_approval(approval);
                    }

                    if let Some(timeout) = nested_table
                        .get("timeout_seconds")
                        .and_then(|v| v.as_integer())
                    {
                        operation = operation.with_timeout(timeout as u64);
                    }

                    registry.add(operation)?;
                }
            }
        }

        Ok(registry)
    }

    /// Export to TOML
    pub fn to_toml(&self) -> Result<String, String> {
        let mut table = toml::value::Table::new();

        for (id, op) in &self.operations {
            let mut op_table = toml::value::Table::new();
            op_table.insert(
                "description".to_string(),
                toml::Value::String(op.description.clone()),
            );
            op_table.insert(
                "command".to_string(),
                toml::Value::String(op.command.clone()),
            );

            if !op.secrets.is_empty() {
                let secrets_array: Vec<toml::Value> = op
                    .secrets
                    .iter()
                    .map(|s| toml::Value::String(s.clone()))
                    .collect();
                op_table.insert("secrets".to_string(), toml::Value::Array(secrets_array));
            }

            let filter_str = match op.output_filter {
                OutputFilter::ExitCode => "exit_code",
                OutputFilter::Summary => "summary",
                OutputFilter::FullScrubbed => "full_scrubbed",
                OutputFilter::None => "none",
            };
            op_table.insert(
                "output_filter".to_string(),
                toml::Value::String(filter_str.to_string()),
            );

            if let Some(regex) = &op.summary_regex {
                op_table.insert(
                    "summary_regex".to_string(),
                    toml::Value::String(regex.clone()),
                );
            }

            op_table.insert(
                "require_approval".to_string(),
                toml::Value::Boolean(op.require_approval),
            );

            if let Some(timeout) = op.timeout_seconds {
                op_table.insert(
                    "timeout_seconds".to_string(),
                    toml::Value::Integer(timeout as i64),
                );
            }

            table.insert(id.clone(), toml::Value::Table(op_table));
        }

        toml::to_string_pretty(&table).map_err(|e| format!("Failed to serialize operations: {}", e))
    }
}

/// Result of executing a sealed operation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OperationResult {
    /// Operation ID
    pub operation_id: String,
    /// Exit code
    pub exit_code: i32,
    /// Filtered output (if any)
    pub output: Option<String>,
    /// Whether the operation timed out
    pub timed_out: bool,
    /// Execution time in milliseconds
    pub duration_ms: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sealed_operation_creation() {
        let op = SealedOperation::new(
            "deploy".to_string(),
            "Deploy to production".to_string(),
            "kubectl apply -f manifests/".to_string(),
        )
        .with_secret("prod/kubeconfig".to_string())
        .with_output_filter(OutputFilter::Summary)
        .with_summary_regex(r"\d+ resources deployed".to_string());

        assert_eq!(op.id, "deploy");
        assert_eq!(op.description, "Deploy to production");
        assert_eq!(op.secrets, vec!["prod/kubeconfig"]);
        assert_eq!(op.output_filter, OutputFilter::Summary);
    }

    #[test]
    fn test_extract_secrets_from_command() {
        let op = SealedOperation::new(
            "test".to_string(),
            "Test operation".to_string(),
            "API_KEY={{secret:api/key}} DB_PASS={{secret:db/pass}} cargo test".to_string(),
        );

        let secrets = op.extract_secrets();
        assert_eq!(secrets, vec!["api/key", "db/pass"]);
    }

    #[test]
    fn test_operations_registry() {
        let mut registry = OperationsRegistry::new();

        let op1 = SealedOperation::new(
            "deploy".to_string(),
            "Deploy".to_string(),
            "kubectl apply -f manifests/".to_string(),
        );

        registry.add(op1).unwrap();

        assert_eq!(registry.len(), 1);
        assert!(registry.get("deploy").is_some());
        assert_eq!(registry.list(), vec!["deploy"]);
    }

    #[test]
    fn test_operations_toml_roundtrip() {
        let toml = r#"
[deploy]
description = "Deploy to production"
command = "kubectl --kubeconfig={{secret:prod/kubeconfig:file}} apply -f manifests/"
secrets = ["prod/kubeconfig"]
output_filter = "summary"
summary_regex = "(\\d+) resources deployed"
require_approval = true
timeout_seconds = 600
"#;

        let registry = OperationsRegistry::from_toml(toml).unwrap();
        assert_eq!(registry.len(), 1);

        let op = registry.get("deploy").unwrap();
        assert_eq!(op.description, "Deploy to production");
        assert_eq!(op.secrets.len(), 1);
        assert!(op.require_approval);

        // Export back to TOML
        let exported = registry.to_toml().unwrap();
        assert!(exported.contains("Deploy to production"));
    }
}
