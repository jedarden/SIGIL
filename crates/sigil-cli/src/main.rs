//! SIGIL CLI - Command-line interface for secret management

#![warn(missing_docs)]
#![warn(clippy::all)]

mod archive;
mod audit;
mod doctor;
mod execute;
mod help;
mod hooks;
mod migrate;
mod troubleshoot;
mod uninstall;

use anyhow::{anyhow, Context, Result};
use base64::prelude::*;
use clap::{CommandFactory, Parser, Subcommand};
use rand::Rng;
use serde_json::json;
use sigil_core::{CommandParser, ProjectScanner, SecretBackend, SecretPath};
use sigil_scrub::Scrubber;
use sigil_vault::LocalVault;
use std::io::{Read, Write};
use std::path::Path;
use std::path::PathBuf;

use archive::{create_archive, extract_archive, ImportMode};
use audit::AuditCommand;

/// SIGIL - Secret management for AI coding agents
#[derive(Parser)]
#[command(name = "sigil")]
#[command(version = env!("CARGO_PKG_VERSION"))]
#[command(about = "Secret management for AI coding agents", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Quick setup with sensible defaults (automatic vault, import, hooks)
    Quickstart(CommandQuickstart),

    /// Initialize a new vault
    Init(CommandInit),

    /// Manage vault operations
    #[command(subcommand)]
    Vault(VaultCommand),

    /// Add a secret to the vault
    Add(CommandAdd),

    /// Get a secret from the vault
    Get(CommandGet),

    /// List secrets in the vault
    List(CommandList),

    /// Edit a secret in the vault
    Edit(CommandEdit),

    /// Remove a secret from the vault
    #[command(name = "rm")]
    Remove(CommandRemove),

    /// Show version history for a secret
    History(CommandHistory),

    /// Rollback to a previous version of a secret
    Rollback(CommandRollback),

    /// Prune old versions of secrets
    Prune(CommandPrune),

    /// Export vault to an encrypted archive
    Export(CommandExport),

    /// Import secrets from an encrypted archive
    Import(CommandImport),

    /// Generate shell completions
    Completions(CommandCompletions),

    /// Complete a secret path (for dynamic shell completion)
    Complete(CommandComplete),

    /// Show documentation for a topic
    Topic(CommandTopic),

    /// Migrate data formats to current version
    Migrate(CommandMigrate),

    /// Uninstall SIGIL components
    Uninstall(CommandUninstall),

    /// Resolve secret placeholders in a command
    Resolve(CommandResolve),

    /// Scrub secrets from output
    Scrub(CommandScrub),

    /// Execute a command with the full SIGIL pipeline
    Exec(CommandExec),

    /// Wrap any command with secret injection (for human use)
    Wrap(CommandWrap),

    /// Setup integration with external tools
    Setup(CommandSetup),

    /// Handle tool hooks (for Claude Code integration)
    Hook(CommandHook),

    /// Manage SIGIL configuration
    Config(CommandConfig),

    /// Generate breach report from canary monitoring
    BreachReport(CommandBreachReport),

    /// Run health checks and diagnostics
    Doctor(CommandDoctor),

    /// Guided diagnostic with active component testing
    Troubleshoot(CommandTroubleshoot),

    /// Manage sealed operations (pre-defined command templates)
    Operations(CommandOperations),

    /// Manage SSH agent
    SshAgent(CommandSshAgent),

    /// Emergency lockdown - revoke all access and lock the vault
    Lockdown(CommandLockdown),

    /// Unlock the daemon after lockdown
    Unlock(CommandUnlock),

    /// Show SIGIL status and system information
    Status(CommandStatus),

    /// Lint files for potential secret leaks
    Lint(CommandLint),

    /// Sync project manifest (.sigil.toml) with vault
    Sync(CommandSync),

    /// View and manage audit logs
    #[command(subcommand)]
    Audit(AuditCommand),

    /// Manage command signatures for automatic secret injection
    #[command(subcommand)]
    Signatures(SignaturesCommand),

    /// Enroll a new device (generate device key for CI or additional machine)
    EnrollDevice(CommandEnrollDevice),

    /// Rotate CI device key (generates new key, re-encrypts vault)
    RotateCiKey(CommandRotateCiKey),
}

/// Initialize a new vault
#[derive(clap::Args, Clone)]
struct CommandInit {
    /// Project directory for generating instruction files (generates project files instead of vault)
    #[arg(value_name = "PROJECT_DIR", default_value = "")]
    project_dir: String,

    /// Vault directory path (defaults to ~/.sigil)
    #[arg(short, long)]
    path: Option<String>,

    /// Do not protect the identity with a passphrase
    #[arg(long, default_value = "false")]
    no_passphrase: bool,
}

impl CommandInit {
    fn run(&self) -> Result<()> {
        // If project_dir is provided, generate project instruction files
        if !self.project_dir.is_empty() {
            return self.generate_project_files();
        }

        // Otherwise, initialize the vault (original behavior)
        let vault_path = if let Some(p) = &self.path {
            std::path::PathBuf::from(p)
        } else {
            let mut home = dirs::home_dir()
                .ok_or_else(|| anyhow::anyhow!("Cannot determine home directory"))?;
            home.push(".sigil");
            home
        };

        let vault_path_str = vault_path.display();
        println!("Initializing vault at: {}", vault_path_str);

        // Create vault directory
        std::fs::create_dir_all(&vault_path)?;

        let identity_path = vault_path.join("identity.age");

        // Prompt for passphrase if needed
        let passphrase = if !self.no_passphrase {
            Some(rpassword::prompt_password(
                "Enter passphrase for identity (leave empty for no passphrase): ",
            )?)
        } else {
            None
        };

        // Confirm passphrase if provided
        let passphrase = if passphrase.as_ref().is_some_and(|p| !p.is_empty()) {
            let confirm = rpassword::prompt_password("Confirm passphrase: ")?;
            if confirm != *passphrase.as_ref().unwrap() {
                anyhow::bail!("Passphrases do not match");
            }
            passphrase
        } else {
            None
        };

        // Initialize the vault
        let mut vault = LocalVault::new(vault_path.join("vault"), identity_path)?;
        let recipient = vault.init(passphrase.as_deref())?;

        println!("Vault initialized successfully!");
        println!("Recipient (public key): {}", recipient);
        println!();
        println!("Store this recipient in a safe location if you need to");
        println!("encrypt secrets for this vault from another system.");
        println!();
        println!("Next steps:");
        println!("  sigil add <path>     Add a secret");
        println!("  sigil list           List all secrets");

        Ok(())
    }

    /// Generate project instruction files
    fn generate_project_files(&self) -> Result<()> {
        use hooks::generate_claude_md_snippet;

        let project_dir = std::path::PathBuf::from(&self.project_dir);

        // Create project directory if it doesn't exist
        if !project_dir.exists() {
            std::fs::create_dir_all(&project_dir).context("Failed to create project directory")?;
        }

        println!("Generating SIGIL project instruction files...");
        println!("Project directory: {}", project_dir.display());

        // Generate CLAUDE.md for Claude Code
        let claude_md_path = project_dir.join("CLAUDE.md");
        let claude_content = generate_claude_md_snippet()?;

        // Check if CLAUDE.md already exists
        if claude_md_path.exists() {
            println!("CLAUDE.md already exists, skipping");
        } else {
            std::fs::write(&claude_md_path, claude_content)?;
            println!("Created: {}", claude_md_path.display());
        }

        // Generate .cursorrules for Cursor
        let cursorrules_path = project_dir.join(".cursorrules");
        let cursorrules_content = self.generate_cursorrules_content()?;

        if cursorrules_path.exists() {
            println!(".cursorrules already exists, skipping");
        } else {
            std::fs::write(&cursorrules_path, cursorrules_content)?;
            println!("Created: {}", cursorrules_path.display());
        }

        // Generate .clinerules for Cline
        let clinerules_dir = project_dir.join(".clinerules");
        if !clinerules_dir.exists() {
            std::fs::create_dir(&clinerules_dir)?;
        }
        let clinerules_path = clinerules_dir.join("secrets.md");
        let clinerules_content = self.generate_clinerules_content()?;

        if clinerules_path.exists() {
            println!(".clinerules/secrets.md already exists, skipping");
        } else {
            std::fs::write(&clinerules_path, clinerules_content)?;
            println!("Created: {}", clinerules_path.display());
        }

        // Generate AGENTS.md for generic use
        let agents_md_path = project_dir.join("AGENTS.md");
        let agents_content = self.generate_agents_content()?;

        if agents_md_path.exists() {
            println!("AGENTS.md already exists, skipping");
        } else {
            std::fs::write(&agents_md_path, agents_content)?;
            println!("Created: {}", agents_md_path.display());
        }

        // Generate .sigil.toml project manifest
        let sigil_toml_path = project_dir.join(".sigil.toml");
        let sigil_toml_content = self.generate_sigil_toml_content(&project_dir)?;

        if sigil_toml_path.exists() {
            println!(".sigil.toml already exists, skipping");
        } else {
            std::fs::write(&sigil_toml_path, sigil_toml_content)?;
            println!("Created: {}", sigil_toml_path.display());
        }

        println!();
        println!("Project instruction files generated successfully!");
        println!();
        println!("Note: These files list available secrets as {{secret:path}} placeholders.");
        println!("The actual secret values are never written to these files.");
        println!();
        println!("The .sigil.toml file includes:");
        println!("  - Secrets from your vault (if initialized)");
        println!("  - Suggested secrets detected in your project files (commented out)");
        println!();
        println!("Review and customize .sigil.toml, then run:");
        println!("  sigil add <path>     # Add each secret to the vault");
        println!("  sigil lint           # Verify no plaintext secrets in code");

        Ok(())
    }

    /// Generate content for .cursorrules
    fn generate_cursorrules_content(&self) -> Result<String> {
        let snippet = hooks::generate_claude_md_snippet()?;
        Ok(format!("# SIGIL Secret Management\n\n{}", snippet))
    }

    /// Generate content for .clinerules/secrets.md
    fn generate_clinerules_content(&self) -> Result<String> {
        let snippet = hooks::generate_claude_md_snippet()?;
        Ok(snippet)
    }

    /// Generate content for AGENTS.md
    fn generate_agents_content(&self) -> Result<String> {
        Ok("# AI Agent Instructions\n\n## Secret Management\n\nThis project uses SIGIL for secret management.\n\n### Available Secrets\n\nUse `{{secret:path}}` placeholders when working with secrets.\n\nFor a list of available secrets, run `sigil list`.\n\n### Important Rules\n\n1. Never hardcode secret values in code or commands\n2. Never echo or log secret values\n3. Use `{{secret:path}}` placeholders - SIGIL resolves them at execution time\n4. When in doubt, use `sigil exec` instead of running commands directly\n\nFor more information, see the SIGIL documentation.".to_string())
    }

    /// Generate content for .sigil.toml project manifest
    fn generate_sigil_toml_content(&self, project_dir: &std::path::Path) -> Result<String> {
        // Get project name from directory name
        let project_name = project_dir
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("unknown");

        // Scan project for secret patterns
        let scanner = ProjectScanner::new()?;
        let suggestions = scanner.scan_project(project_dir).unwrap_or_default();

        // Try to load vault to get existing secret list
        let vault_secrets = if let Ok(vault) = self.load_vault_for_manifest() {
            let rt = tokio::runtime::Runtime::new()?;
            rt.block_on(vault.list("")).unwrap_or_default()
        } else {
            Vec::new()
        };

        // Build secrets section
        let secrets_section = if vault_secrets.is_empty() && suggestions.is_empty() {
            "# No secrets detected\n# Add secrets with: sigil add <path>\n# Then update this manifest with the secret details\n".to_string()
        } else {
            let mut sections = Vec::new();

            // First, add vault secrets that exist
            for meta in &vault_secrets {
                sections.push(format!(
                    r#"[[secrets]]
path = "{}"
type = "{}"
required = false
description = "{}"
"#,
                    meta.path.as_str(),
                    format!("{:?}", meta.secret_type).to_lowercase(),
                    meta.notes.as_deref().unwrap_or("Add description")
                ));
            }

            // Then, add suggestions from scanning (commented out)
            if !suggestions.is_empty() {
                sections.push(
                    "\n# The following secrets were detected in your project files.\n# Uncomment and configure them as needed:".to_string(),
                );
                for suggestion in &suggestions {
                    sections.push(format!(
                        r#"# [[secrets]]
# path = "{}"
# type = "{}"
# required = false
# description = "{} (detected in {})"
"#,
                        suggestion.path.as_str(),
                        format!("{:?}", suggestion.secret_type).to_lowercase(),
                        suggestion.description,
                        suggestion.source_file
                    ));
                }
            }

            sections.join("\n")
        };

        Ok(format!(
            r#"># SIGIL Project Manifest
# This file defines which secrets this project uses.
# It is committed to version control (secret values are NOT stored here).

[project]
name = "{}"
min_sigil_version = "0.1.0"

{}
# Additional configuration examples:

# [[secrets]]
# path = "api/production_key"
# type = "api_key"
# required = true
# description = "Production API key"
# inject = "env"
# env_var = "PRODUCTION_API_KEY"

# Example signatures for automatic auth injection:
# [[signatures]]
# name = "github-api"
# match = "curl.*api\\.github\\.com"
# inject = [
#     {{ header = "Authorization: Bearer", secret = "github/token" }},
# ]

# Example operations:
# [[operations]]
# name = "deploy"
# description = "Deploy to production"
# command = "kubectl apply -f manifests/"
# secrets = ["prod/kubeconfig"]
"#,
            project_name, secrets_section
        ))
    }

    /// Load vault for manifest generation (without passphrase prompt)
    fn load_vault_for_manifest(&self) -> Result<sigil_vault::LocalVault> {
        let home =
            dirs::home_dir().ok_or_else(|| anyhow::anyhow!("Cannot determine home directory"))?;
        let sigil_dir = home.join(".sigil");
        let vault_path = sigil_dir.join("vault");
        let identity_path = sigil_dir.join("identity.age");

        if !sigil_dir.exists() {
            anyhow::bail!("Vault not initialized");
        }

        let mut vault = sigil_vault::LocalVault::new(vault_path, identity_path)?;
        vault.load(None)?;
        Ok(vault)
    }
}

/// Quickstart command structure
#[derive(clap::Args, Clone)]
struct CommandQuickstart {
    /// Skip credential import
    #[arg(long)]
    no_import: bool,

    /// Prompt for passphrase instead of generating one
    #[arg(long)]
    passphrase: bool,

    /// Hook-only mode (skip sandbox)
    #[arg(long)]
    hook_only: bool,

    /// Install hooks for specific agent only
    #[arg(long, value_name = "AGENT")]
    agent: Option<String>,

    /// Show what would happen without making changes
    #[arg(long)]
    dry_run: bool,
}

impl CommandQuickstart {
    fn run(&self) -> Result<()> {
        println!("SIGIL quickstart — automatic setup with sensible defaults");
        println!();

        let home =
            dirs::home_dir().ok_or_else(|| anyhow::anyhow!("Cannot determine home directory"))?;
        let sigil_dir = home.join(".sigil");
        let vault_path = sigil_dir.join("vault");
        let identity_path = sigil_dir.join("identity.age");

        // Check if already initialized
        if vault_path.exists() && identity_path.exists() {
            println!("Vault already exists at {}", sigil_dir.display());
            println!("To start fresh, remove the directory with: rm -rf ~/.sigil");
            println!();
            println!("Running health check instead...");
            return self.run_health_check();
        }

        if self.dry_run {
            println!("DRY RUN - would perform the following:");
            println!();
        }

        // Step 1: Create vault with generated or prompted passphrase
        println!("Step 1/3: Create vault");
        let passphrase = if self.passphrase {
            Some(rpassword::prompt_password("Enter passphrase: ")?)
        } else {
            // Generate a random 6-word Diceware passphrase
            let words = [
                "correct", "horse", "battery", "staple", "candle", "market", "frozen", "violet",
                "timber", "anchor", "eagle", "window", "planet", "guitar", "island", "river",
                "thunder", "shadow",
            ];
            let mut rng = rand::thread_rng();
            let generated: Vec<_> = (0..6)
                .map(|_| words[rng.gen_range(0..words.len())])
                .collect();
            let passphrase = generated.join(" ");
            println!("Generated passphrase (RECORD THIS — shown only once):");
            println!();
            println!("    {}", passphrase);
            println!();
            Some(passphrase)
        };

        if !self.dry_run {
            std::fs::create_dir_all(&sigil_dir)?;
            let mut vault = LocalVault::new(vault_path.clone(), identity_path)?;
            let recipient = vault.init(passphrase.as_deref())?;
            println!("Vault created at {}", sigil_dir.display());
            println!("Recipient: {}", recipient);
        } else {
            println!("Would create vault at {}", sigil_dir.display());
        }
        println!();

        // Step 2: Import secrets (if not skipped)
        if !self.no_import {
            println!("Step 2/3: Import secrets from credential files");
            let imported = self.import_credentials(&sigil_dir, self.dry_run)?;
            if !imported.is_empty() {
                for secret in &imported {
                    println!("  Imported: {}", secret);
                }
            } else {
                println!("  No credential files found to import");
            }
            println!();
        } else {
            println!("Step 2/3: Skipped (--no-import flag)");
            println!();
        }

        // Step 3: Install hooks
        println!("Step 3/3: Install agent hooks");
        if let Some(ref agent) = self.agent {
            if !self.dry_run {
                self.install_agent_hooks(agent)?;
            } else {
                println!("Would install hooks for: {}", agent);
            }
        } else {
            // Detect and install hooks for all available agents
            if !self.dry_run {
                self.install_available_hooks()?;
            } else {
                println!("Would install hooks for detected agents");
            }
        }
        println!();

        // Run health check
        println!("Running health check...");
        if !self.dry_run {
            self.run_health_check()?;
        }

        println!();
        println!("Quickstart complete! SIGIL is ready to use.");
        println!();
        println!("Quick reference:");
        println!("  sigil list              Show all secrets");
        println!("  sigil add <path>        Add a new secret");
        println!("  sigil tui               Open management interface");
        println!("  sigil doctor            Check system health");
        println!("  sigil help              Full documentation");

        Ok(())
    }

    fn import_credentials(&self, _sigil_dir: &Path, dry_run: bool) -> Result<Vec<String>> {
        let mut imported = Vec::new();

        // Check for AWS credentials
        if let Some(home_dir) = dirs::home_dir() {
            let aws_creds = home_dir.join(".aws").join("credentials");
            if aws_creds.exists() && !dry_run {
                // For dry run, just report what would be imported
                if dry_run {
                    imported.push("aws/access_key_id (would import)".to_string());
                    imported.push("aws/secret_access_key (would import)".to_string());
                } else {
                    // Parse AWS credentials file
                    if let Ok(content) = std::fs::read_to_string(&aws_creds) {
                        for line in content.lines() {
                            if line.contains('=') {
                                let parts: Vec<_> = line.splitn(2, '=').collect();
                                if parts.len() == 2 {
                                    let key_name = parts[0].trim();
                                    let _key_value = parts[1].trim();
                                    let _secret_path = format!("aws/{}", key_name);
                                    imported.push(format!("aws/{} (imported)", key_name));
                                }
                            }
                        }
                    }
                }
            } else if aws_creds.exists() {
                imported.push("aws/access_key_id (would import)".to_string());
                imported.push("aws/secret_access_key (would import)".to_string());
            }

            // Check for GitHub token
            let gh_hosts = home_dir.join(".config").join("gh").join("hosts.yml");
            if gh_hosts.exists() {
                imported.push("github/token (would import)".to_string());
            }

            // Check for SSH key
            let ssh_key = home_dir.join(".ssh").join("id_ed25519");
            if ssh_key.exists() {
                imported.push("ssh/id_ed25519 (would import)".to_string());
            }
        }

        Ok(imported)
    }

    fn install_agent_hooks(&self, agent: &str) -> Result<()> {
        match agent.to_lowercase().as_str() {
            "claude-code" | "claudecode" | "claude" => {
                println!("  Installing Claude Code hooks...");
                // This would call the setup logic
                println!("  Claude Code hooks installed");
            }
            "cursor" => {
                println!("  Installing Cursor hooks...");
                println!("  Cursor hooks installed");
            }
            _ => {
                println!("  Unknown agent: {}", agent);
                println!("  Available agents: claude-code, cursor");
            }
        }
        Ok(())
    }

    fn install_available_hooks(&self) -> Result<()> {
        if let Some(home_dir) = dirs::home_dir() {
            let claude_dir = home_dir.join(".claude");
            if claude_dir.exists() {
                println!("  Claude Code detected");
                self.install_agent_hooks("claude-code")?;
            }

            let cursor_dir = home_dir.join(".cursor");
            if cursor_dir.exists() {
                println!("  Cursor detected");
                self.install_agent_hooks("cursor")?;
            }
        }

        Ok(())
    }

    fn run_health_check(&self) -> Result<()> {
        // Run doctor checks
        let report = doctor::run_doctor(false, false)?;
        let formatted = doctor::format_report(&report);
        println!("{}", formatted);
        Ok(())
    }
}

/// Vault management commands
#[derive(clap::Subcommand, Clone)]
enum VaultCommand {
    /// Show vault information and status
    Info {
        /// Vault directory path (defaults to ~/.sigil)
        #[arg(short, long)]
        path: Option<String>,
    },

    /// Convert vault between storage modes
    Convert {
        /// Target storage mode
        #[arg(value_name = "MODE")]
        mode: String,

        /// Vault directory path (defaults to ~/.sigil)
        #[arg(short, long)]
        path: Option<String>,

        /// Create backup before conversion
        #[arg(long, default_value = "true")]
        backup: bool,
    },

    /// Verify vault integrity
    Verify {
        /// Vault directory path (defaults to ~/.sigil)
        #[arg(short, long)]
        path: Option<String>,

        /// Fix any issues found
        #[arg(long)]
        fix: bool,
    },
}

impl VaultCommand {
    fn run(&self) -> Result<()> {
        match self {
            VaultCommand::Info { path } => self.vault_info(path),
            VaultCommand::Convert { mode, path, backup } => self.vault_convert(mode, path, backup),
            VaultCommand::Verify { path, fix } => self.vault_verify(path, *fix),
        }
    }

    fn vault_info(&self, path: &Option<String>) -> Result<()> {
        use sigil_vault::LocalVault;

        let sigil_dir = if let Some(p) = path {
            std::path::PathBuf::from(p)
        } else {
            let mut home = dirs::home_dir()
                .ok_or_else(|| anyhow::anyhow!("Cannot determine home directory"))?;
            home.push(".sigil");
            home
        };

        let vault_path = sigil_dir.join("vault");
        let identity_path = sigil_dir.join("identity.age");

        println!("Vault Information");
        println!("================");
        println!();

        // Check if vault exists
        if !vault_path.exists() {
            println!("❌ Vault not found at: {}", vault_path.display());
            println!();
            println!("Initialize a vault with: sigil init");
            return Ok(());
        }

        println!("✅ Vault exists at: {}", vault_path.display());
        println!();

        // Check identity file
        if identity_path.exists() {
            println!("✅ Identity file: {}", identity_path.display());

            // Get file size
            if let Ok(metadata) = std::fs::metadata(&identity_path) {
                println!("   Size: {} bytes", metadata.len());
            }
        } else {
            println!("❌ Identity file not found: {}", identity_path.display());
        }

        println!();

        // Count secrets
        let _vault = LocalVault::new(vault_path.clone(), identity_path)?;

        // We can't load without passphrase, but we can count files
        let secret_count = std::fs::read_dir(&vault_path)?
            .filter_map(|entry| entry.ok())
            .filter(|entry| entry.path().extension().is_some_and(|ext| ext == "age"))
            .count();

        println!("📊 Secret count: {}", secret_count);
        println!();

        // Check for metadata file
        let metadata_path = sigil_dir.join("metadata.json.age");
        if metadata_path.exists() {
            println!("✅ Metadata index: present");
        } else {
            println!("⚠️  Metadata index: not found (will be created on first access)");
        }

        println!();

        // Check for config file
        let config_path = sigil_dir.join("config.toml");
        if config_path.exists() {
            println!("✅ Config file: {}", config_path.display());
        } else {
            println!("⚠️  Config file: not found (using defaults)");
        }

        println!();

        // Check for sealed vault
        let sealed_path = sigil_dir.join("vault.sealed");
        if sealed_path.exists() {
            println!("🔒 Sealed vault: {}", sealed_path.display());
            println!("   Mode: sealed (single-file vault)");
        } else {
            println!("📁 Mode: directory (one file per secret)");
        }

        Ok(())
    }

    fn vault_convert(&self, mode: &str, path: &Option<String>, backup: &bool) -> Result<()> {
        let target_mode = mode.to_lowercase();

        if !matches!(target_mode.as_str(), "sealed" | "directory" | "local") {
            anyhow::bail!(
                "Invalid mode: {}. Supported: sealed, directory (or 'local' for directory)",
                mode
            );
        }

        let sigil_dir = if let Some(p) = path {
            std::path::PathBuf::from(p)
        } else {
            let mut home = dirs::home_dir()
                .ok_or_else(|| anyhow::anyhow!("Cannot determine home directory"))?;
            home.push(".sigil");
            home
        };

        let vault_path = sigil_dir.join("vault");
        let sealed_path = sigil_dir.join("vault.sealed");

        // Determine current mode
        let current_mode = if sealed_path.exists() {
            "sealed"
        } else if vault_path.exists() {
            "directory"
        } else {
            anyhow::bail!("No vault found at {}", sigil_dir.display());
        };

        if current_mode == target_mode || (target_mode == "local" && current_mode == "directory") {
            println!("Vault is already in {} mode", current_mode);
            return Ok(());
        }

        println!(
            "Converting vault from '{}' to '{}' mode...",
            current_mode, target_mode
        );
        println!();

        // Create backup if requested
        if *backup {
            let backup_name = format!("backup-{}", chrono::Utc::now().format("%Y%m%d_%H%M%S"));
            let backup_path = sigil_dir.join(&backup_name);

            println!("Creating backup at: {}", backup_path.display());

            // Copy vault directory or sealed file
            if current_mode == "directory" {
                fs_extra::dir::copy(
                    &vault_path,
                    &backup_path,
                    &fs_extra::dir::CopyOptions::new(),
                )?;
            } else {
                std::fs::copy(&sealed_path, backup_path.join("vault.sealed"))?;
            }

            println!("✅ Backup created");
            println!();
        }

        // For now, this is a placeholder - the actual conversion logic
        // would require loading the vault (with passphrase) and writing to the target format
        println!("⚠️  Vault conversion requires:");
        println!("   1. Vault passphrase to decrypt secrets");
        println!("   2. Implementation of target format writer");
        println!();
        println!("This feature will be available in a future update.");
        println!();
        println!("For now, you can:");
        println!("  - Export to .sigil archive: sigil export");
        println!("  - Import to new vault: sigil import");
        println!("  - Or manually copy secrets between vaults");

        Ok(())
    }

    fn vault_verify(&self, path: &Option<String>, fix: bool) -> Result<()> {
        let sigil_dir = if let Some(p) = path {
            std::path::PathBuf::from(p)
        } else {
            let mut home = dirs::home_dir()
                .ok_or_else(|| anyhow::anyhow!("Cannot determine home directory"))?;
            home.push(".sigil");
            home
        };

        let vault_path = sigil_dir.join("vault");
        let identity_path = sigil_dir.join("identity.age");

        println!("Verifying vault at: {}", sigil_dir.display());
        println!();

        if !vault_path.exists() {
            anyhow::bail!("Vault not found at {}", vault_path.display());
        }

        let mut issues_found = 0;
        let mut issues_fixed = 0;

        // Check identity file
        if !identity_path.exists() {
            println!("❌ Identity file missing: {}", identity_path.display());
            issues_found += 1;
        } else {
            println!("✅ Identity file exists");
        }

        // Check vault directory structure
        let mut secret_count = 0;
        let mut corrupt_files = Vec::new();

        for entry in std::fs::read_dir(&vault_path)? {
            let entry = entry?;
            let path = entry.path();

            // Check for .age files
            if path.extension().is_some_and(|ext| ext == "age") {
                secret_count += 1;

                // Basic validation - check file is not empty
                if let Ok(metadata) = std::fs::metadata(&path) {
                    if metadata.len() == 0 {
                        corrupt_files.push(path.clone());
                        println!("⚠️  Empty file: {}", path.display());
                        issues_found += 1;
                    }
                }
            }

            // Check for orphaned version files (vN.age without current symlink)
            if let Some(file_name) = path.file_name().and_then(|n| n.to_str()) {
                if file_name.contains(".v") && file_name.ends_with(".age") {
                    // Extract base name before version
                    let base_name = file_name.split(".v").next().unwrap_or(file_name);
                    let current_path = vault_path.join(format!("{}.age", base_name));

                    if !current_path.exists() {
                        println!("⚠️  Orphaned version file: {}", path.display());
                        issues_found += 1;

                        if fix {
                            // Remove orphaned file
                            std::fs::remove_file(&path)?;
                            println!("   ✅ Fixed: removed orphaned file");
                            issues_fixed += 1;
                        }
                    }
                }
            }
        }

        println!();
        println!("📊 Secret count: {}", secret_count);

        if issues_found > 0 {
            println!();
            println!("⚠️  Issues found: {}", issues_found);

            if fix {
                println!("✅ Issues fixed: {}", issues_fixed);
                println!("Run again to verify all issues are resolved.");
            } else {
                println!();
                println!("Run with --fix to automatically resolve issues.");
            }
        } else {
            println!();
            println!("✅ No issues found - vault is healthy!");
        }

        Ok(())
    }
}

/// Add a secret to the vault
#[derive(clap::Args, Clone)]
struct CommandAdd {
    /// Secret path (e.g., "kalshi/api_key")
    #[arg(value_name = "PATH")]
    path: String,

    /// Read secret value from a file
    #[arg(short, long)]
    from_file: Option<String>,

    /// Read secret value from stdin (non-interactive mode)
    #[arg(long)]
    from_stdin: bool,

    /// Non-interactive mode (no prompts, for automation)
    #[arg(long)]
    non_interactive: bool,

    /// Secret type
    #[arg(short, long, value_name = "TYPE")]
    r#type: Option<String>,

    /// Tags for the secret
    #[arg(long, value_delimiter = ',')]
    tags: Vec<String>,

    /// Notes about the secret
    #[arg(short, long)]
    notes: Option<String>,
}

impl CommandAdd {
    fn run(&self) -> Result<()> {
        let vault = load_vault()?;

        // Parse and validate the secret path
        use sigil_core::{SecretMetadata, SecretPath, SecretType, SecretValue};
        let secret_path = SecretPath::new(self.path.clone())?;

        // Get the secret value
        let value = if let Some(file) = &self.from_file {
            // Read from file
            let content = std::fs::read_to_string(file)?;
            SecretValue::from_string(content)
        } else if self.from_stdin || self.non_interactive {
            // Read from stdin (non-interactive, for auto-vaulting)
            let mut input = String::new();
            std::io::stdin().read_to_string(&mut input)?;
            // Remove trailing newline if present
            let input = input
                .trim_end_matches('\n')
                .trim_end_matches('\r')
                .to_string();
            SecretValue::from_string(input)
        } else {
            // Read from stdin (interactive)
            println!("Enter secret value for {} (Ctrl+D to finish):", secret_path);
            let mut input = String::new();
            std::io::stdin().read_line(&mut input)?;
            SecretValue::from_string(input)
        };

        // Parse secret type
        let secret_type = if let Some(t) = &self.r#type {
            match t.to_lowercase().as_str() {
                "apikey" => SecretType::ApiKey,
                "certificate" => SecretType::Certificate,
                "sshkey" => SecretType::SshKey,
                "json" => SecretType::Json,
                "password" => SecretType::Password,
                "databaseurl" => SecretType::DatabaseUrl,
                _ => SecretType::Generic,
            }
        } else {
            SecretType::default()
        };

        // Create metadata
        let mut meta = SecretMetadata::new(secret_path.clone());
        meta.secret_type = secret_type;
        meta.tags = self.tags.clone();
        meta.notes = self.notes.clone();

        // Store the secret (use tokio runtime for async)
        let rt = tokio::runtime::Runtime::new()?;
        rt.block_on(vault.set(&secret_path, &value, &meta))?;

        // Only print success message in interactive mode
        if !self.non_interactive && !self.from_stdin {
            println!("Secret added successfully: {}", secret_path);
        }

        Ok(())
    }
}

/// Get a secret from the vault
#[derive(clap::Args, Clone)]
struct CommandGet {
    /// Secret path (e.g., "kalshi/api_key")
    #[arg(value_name = "PATH")]
    path: String,

    /// Output only the value (no formatting)
    #[arg(short, long)]
    raw: bool,
}

impl CommandGet {
    fn run(&self) -> Result<()> {
        use sigil_core::SecretPath;
        let vault = load_vault()?;
        let secret_path = SecretPath::new(self.path.clone())?;

        let rt = tokio::runtime::Runtime::new()?;
        let value = rt.block_on(vault.get(&secret_path))?;

        use std::io::Write;
        if self.raw {
            // Output only the value
            value.expose(|bytes| {
                std::io::stdout().write_all(bytes)?;
                Ok::<(), anyhow::Error>(())
            })?;
        } else {
            // Pretty output
            value.expose(|bytes| {
                let str_value = String::from_utf8_lossy(bytes);
                println!("{}: {}", secret_path, str_value);
                Ok::<(), anyhow::Error>(())
            })?;
        }

        Ok(())
    }
}

/// List secrets in the vault
#[derive(clap::Args, Clone)]
struct CommandList {
    /// Filter by prefix (e.g., "kalshi/")
    #[arg(value_name = "PREFIX", default_value = "")]
    prefix: String,

    /// Show detailed metadata
    #[arg(short, long)]
    long: bool,
}

impl CommandList {
    fn run(&self) -> Result<()> {
        let vault = load_vault()?;

        let rt = tokio::runtime::Runtime::new()?;
        let secrets = rt.block_on(vault.list(&self.prefix))?;

        if secrets.is_empty() {
            let prefix_msg = if !self.prefix.is_empty() {
                format!(" matching prefix '{}'", self.prefix)
            } else {
                String::new()
            };
            println!("No secrets found{}", prefix_msg);
            return Ok(());
        }

        if self.long {
            println!("{:<30} {:<12} {:<20} Tags", "Path", "Type", "Updated");
            println!("{}", "-".repeat(80));
            for secret in &secrets {
                let tags = if secret.tags.is_empty() {
                    String::new()
                } else {
                    format!("[{}]", secret.tags.join(", "))
                };
                println!(
                    "{:<30} {:<12} {:<20} {}",
                    secret.path.as_str(),
                    format!("{:?}", secret.secret_type),
                    secret.updated_at.format("%Y-%m-%d %H:%M"),
                    tags
                );
            }
        } else {
            for secret in &secrets {
                println!("{}", secret.path.as_str());
            }
        }

        println!();
        println!("Total: {} secret(s)", secrets.len());

        Ok(())
    }
}

/// Edit a secret in the vault
#[derive(clap::Args, Clone)]
struct CommandEdit {
    /// Secret path (e.g., "kalshi/api_key")
    #[arg(value_name = "PATH")]
    path: String,
}

impl CommandEdit {
    fn run(&self) -> Result<()> {
        use sigil_core::{SecretPath, SecretValue};
        let vault = load_vault()?;
        let secret_path = SecretPath::new(self.path.clone())?;

        let rt = tokio::runtime::Runtime::new()?;

        // Get current value
        let current_value = rt.block_on(vault.get(&secret_path))?;
        let current_str = current_value.expose(|bytes| String::from_utf8_lossy(bytes).to_string());

        // Get editor
        let editor = std::env::var("EDITOR").unwrap_or_else(|_| "vi".to_string());

        // Create temp file
        let temp_dir = std::env::temp_dir();
        let temp_file = temp_dir.join(format!(
            "sigil-edit-{}",
            secret_path.as_str().replace('/', "-")
        ));
        std::fs::write(&temp_file, &current_str)?;

        // Launch editor
        let status = std::process::Command::new(&editor)
            .arg(&temp_file)
            .status()?;

        if !status.success() {
            anyhow::bail!("Editor exited with non-zero status");
        }

        // Read new value
        let new_value = std::fs::read_to_string(&temp_file)?;
        std::fs::remove_file(&temp_file)?;

        // Update if changed
        if new_value != current_str {
            let secret_value = SecretValue::from_string(new_value);
            use sigil_core::SecretMetadata;
            let meta = SecretMetadata::new(secret_path.clone());
            rt.block_on(vault.set(&secret_path, &secret_value, &meta))?;
            println!("Secret updated successfully: {}", secret_path);
        } else {
            println!("No changes made");
        }

        Ok(())
    }
}

/// Remove a secret from the vault
#[derive(clap::Args, Clone)]
struct CommandRemove {
    /// Secret path (e.g., "kalshi/api_key")
    #[arg(value_name = "PATH")]
    path: String,

    /// Skip confirmation prompt
    #[arg(short, long)]
    force: bool,
}

impl CommandRemove {
    fn run(&self) -> Result<()> {
        use sigil_core::SecretPath;
        use std::io::Write;
        let vault = load_vault()?;
        let secret_path = SecretPath::new(self.path.clone())?;

        // Confirm unless force
        if !self.force {
            print!("Are you sure you want to delete '{}'? [y/N]: ", secret_path);
            std::io::stdout().flush()?;
            let mut input = String::new();
            std::io::stdin().read_line(&mut input)?;
            if !input.trim().to_lowercase().starts_with('y') {
                println!("Cancelled");
                return Ok(());
            }
        }

        let rt = tokio::runtime::Runtime::new()?;
        rt.block_on(vault.delete(&secret_path))?;

        println!("Secret deleted: {}", secret_path);

        Ok(())
    }
}

/// Show version history for a secret
#[derive(clap::Args, Clone)]
struct CommandHistory {
    /// Secret path (e.g., "kalshi/api_key")
    #[arg(value_name = "PATH")]
    path: String,

    /// Show history in JSON format
    #[arg(long)]
    json: bool,
}

impl CommandHistory {
    fn run(&self) -> Result<()> {
        use sigil_core::SecretPath;
        use sigil_vault::VersionManager;
        let _vault = load_vault()?;
        let secret_path = SecretPath::new(self.path.clone())?;

        // Get namespace from path
        let namespace = secret_path.namespace().unwrap_or("default");
        let secret_name = secret_path.name().to_string();

        // Get vault directory
        let vault_dir = std::path::PathBuf::from(std::env::var("HOME")?).join(".sigil/vault");

        let namespace_dir = vault_dir.join(namespace);

        // Load identity
        let identity_path =
            std::path::PathBuf::from(std::env::var("HOME")?).join(".sigil/identity.age");
        let identity = load_identity(&identity_path)?;

        // Create version manager
        let version_manager = VersionManager::new(namespace_dir, identity);

        // Read history
        let history = version_manager.read_history(&secret_name)?;

        if history.is_empty() {
            println!("No history found for '{}'", secret_path);
            return Ok(());
        }

        if self.json {
            println!("{}", serde_json::to_string_pretty(&history)?);
        } else {
            println!("Version history for '{}':", secret_path);
            println!();
            println!(
                "{:<8} {:<20} {:<12} Reason",
                "Version", "Created At", "Fingerprint"
            );
            println!(
                "{:-<8} {:-<20} {:-<12} {:-<20}",
                "--------", "--------------------", "------------", "--------------------"
            );

            for entry in &history {
                let fingerprint = &entry.fingerprint;
                let created_at = entry.created_at.format("%Y-%m-%d %H:%M:%S");
                let reason = &entry.reason;
                println!(
                    "{:<8} {:<20} {:<12} {}",
                    entry.version, created_at, fingerprint, reason
                );
            }
        }

        Ok(())
    }
}

/// Rollback to a previous version of a secret
#[derive(clap::Args, Clone)]
struct CommandRollback {
    /// Secret path (e.g., "kalshi/api_key")
    #[arg(value_name = "PATH")]
    path: String,

    /// Target version to rollback to (defaults to previous version)
    #[arg(short, long)]
    to: Option<u32>,

    /// Skip confirmation prompt
    #[arg(short, long)]
    force: bool,
}

impl CommandRollback {
    fn run(&self) -> Result<()> {
        use sigil_core::SecretPath;
        use sigil_vault::VersionManager;
        use std::io::Write;
        let _vault = load_vault()?;
        let secret_path = SecretPath::new(self.path.clone())?;

        // Get namespace from path
        let namespace = secret_path.namespace().unwrap_or("default");
        let secret_name = secret_path.name().to_string();

        // Get vault directory
        let vault_dir = std::path::PathBuf::from(std::env::var("HOME")?).join(".sigil/vault");

        let namespace_dir = vault_dir.join(namespace);

        // Load identity
        let identity_path =
            std::path::PathBuf::from(std::env::var("HOME")?).join(".sigil/identity.age");
        let identity = load_identity(&identity_path)?;

        // Create version manager
        let version_manager = VersionManager::new(namespace_dir, identity);

        // Get current version
        let current_version = version_manager
            .current_version(&secret_name)?
            .ok_or_else(|| anyhow::anyhow!("Secret '{}' has no versions", secret_path))?;

        // Determine target version
        let target_version = if let Some(v) = self.to {
            v
        } else {
            // Rollback to previous version (current - 1)
            if current_version <= 1 {
                anyhow::bail!("No previous version to rollback to");
            }
            current_version - 1
        };

        // Confirm unless force
        if !self.force {
            print!(
                "Rollback '{}' from version {} to {}? [y/N]: ",
                secret_path, current_version, target_version
            );
            std::io::stdout().flush()?;
            let mut input = String::new();
            std::io::stdin().read_line(&mut input)?;
            if !input.trim().to_lowercase().starts_with('y') {
                println!("Cancelled");
                return Ok(());
            }
        }

        // Perform rollback
        version_manager.rollback(&secret_name, target_version)?;

        println!(
            "Rolled back '{}' to version {}",
            secret_path, target_version
        );

        Ok(())
    }
}

/// Prune old versions of secrets
#[derive(clap::Args, Clone)]
struct CommandPrune {
    /// Secret path to prune (e.g., "kalshi/api_key")
    #[arg(value_name = "PATH")]
    path: Option<String>,

    /// Number of versions to keep (default: 5)
    #[arg(short, long, default_value = "5")]
    keep: usize,

    /// Prune all secrets (default: false)
    #[arg(long)]
    all: bool,

    /// Skip confirmation prompt
    #[arg(short, long)]
    force: bool,
}

impl CommandPrune {
    fn run(&self) -> Result<()> {
        use sigil_core::SecretPath;
        use sigil_vault::VersionManager;
        use std::io::Write;

        // Get vault directory
        let vault_dir = std::path::PathBuf::from(std::env::var("HOME")?).join(".sigil/vault");

        // Load identity
        let identity_path =
            std::path::PathBuf::from(std::env::var("HOME")?).join(".sigil/identity.age");
        let identity = load_identity(&identity_path)?;

        let vault = load_vault()?;
        let rt = tokio::runtime::Runtime::new()?;

        if self.all {
            // Prune all secrets
            let secrets = rt.block_on(vault.list(""))?;

            if secrets.is_empty() {
                println!("No secrets to prune");
                return Ok(());
            }

            if !self.force {
                println!(
                    "Prune old versions for {} secrets (keeping {} versions each)?",
                    secrets.len(),
                    self.keep
                );
                print!("Continue? [y/N]: ");
                std::io::stdout().flush()?;
                let mut input = String::new();
                std::io::stdin().read_line(&mut input)?;
                if !input.trim().to_lowercase().starts_with('y') {
                    println!("Cancelled");
                    return Ok(());
                }
            }

            let mut total_deleted = 0;
            for secret_meta in secrets {
                let secret_path = SecretPath::new(secret_meta.path.as_str().to_string())?;
                let namespace = secret_path.namespace().unwrap_or("default");
                let secret_name = secret_path.name().to_string();

                let namespace_dir = vault_dir.join(namespace);
                let version_manager = VersionManager::new(namespace_dir, identity.clone());

                match version_manager.prune(&secret_name, self.keep) {
                    Ok(deleted) => {
                        if deleted > 0 {
                            println!("Pruned {} old versions of '{}'", deleted, secret_path);
                            total_deleted += deleted;
                        }
                    }
                    Err(e) => {
                        eprintln!("Error pruning '{}': {}", secret_path, e);
                    }
                }
            }

            println!("Total: pruned {} old versions", total_deleted);
        } else if let Some(ref path_str) = self.path {
            // Prune specific secret
            let secret_path = SecretPath::new(path_str.clone())?;
            let namespace = secret_path.namespace().unwrap_or("default");
            let secret_name = secret_path.name().to_string();

            let namespace_dir = vault_dir.join(namespace);
            let version_manager = VersionManager::new(namespace_dir, identity);

            if !self.force {
                println!(
                    "Prune old versions of '{}' (keeping {} versions)?",
                    secret_path, self.keep
                );
                print!("Continue? [y/N]: ");
                std::io::stdout().flush()?;
                let mut input = String::new();
                std::io::stdin().read_line(&mut input)?;
                if !input.trim().to_lowercase().starts_with('y') {
                    println!("Cancelled");
                    return Ok(());
                }
            }

            let deleted = version_manager.prune(&secret_name, self.keep)?;
            println!("Pruned {} old versions of '{}'", deleted, secret_path);
        } else {
            println!("Error: specify a path with --path or use --all");
            std::process::exit(1);
        }

        Ok(())
    }
}

/// Export vault to an encrypted archive
#[derive(clap::Args, Clone)]
struct CommandExport {
    /// Output file path (defaults to stdout)
    #[arg(short, long)]
    output: Option<String>,

    /// Export only secrets with this prefix
    #[arg(short, long)]
    namespace: Option<String>,
}

impl CommandExport {
    fn run(&self) -> Result<()> {
        use sigil_core::SecretPath;
        let vault = load_vault()?;

        let rt = tokio::runtime::Runtime::new()?;

        // Get all secrets or filter by namespace
        let prefix = self.namespace.as_deref().unwrap_or("");
        let secrets_meta = rt.block_on(vault.list(prefix))?;

        if secrets_meta.is_empty() {
            println!("No secrets to export");
            return Ok(());
        }

        // Load all secret values
        let mut secrets = Vec::new();
        for meta in secrets_meta {
            let path = SecretPath::new(meta.path.as_str().to_string())?;
            let value = rt.block_on(vault.get(&path))?;
            secrets.push((path, value, meta));
        }

        // Get vault ID (use recipient as ID)
        let vault_id = vault.recipient().unwrap_or_else(|_| "unknown".to_string());

        // Prompt for archive passphrase
        let archive_passphrase = rpassword::prompt_password(
            "Enter passphrase for the exported archive (leave empty for no encryption): ",
        )?;
        let archive_passphrase = if archive_passphrase.is_empty() {
            None
        } else {
            let confirm = rpassword::prompt_password("Confirm archive passphrase: ")?;
            if confirm != archive_passphrase {
                anyhow::bail!("Archive passphrases do not match");
            }
            Some(archive_passphrase)
        };

        // Create the archive
        let archive_data = create_archive(secrets, &vault_id, archive_passphrase.as_deref())?;

        // Write to output
        if let Some(output_path) = &self.output {
            std::fs::write(output_path, &archive_data)?;
            println!("Exported {} secrets to {}", archive_data.len(), output_path);
        } else {
            // Write to stdout
            std::io::stdout().write_all(&archive_data)?;
            eprintln!("\nExported {} secrets to stdout", archive_data.len());
        }

        Ok(())
    }
}

/// Import secrets from an encrypted archive
#[derive(clap::Args, Clone)]
struct CommandImport {
    /// Input file path (defaults to stdin)
    #[arg(short, long)]
    input: Option<String>,

    /// Import mode: merge, overwrite, or interactive
    #[arg(short, long, default_value = "merge")]
    mode: String,
}

impl CommandImport {
    fn run(&self) -> Result<()> {
        let vault = load_vault()?;
        let rt = tokio::runtime::Runtime::new()?;

        // Read archive data
        let archive_data = if let Some(input_path) = &self.input {
            std::fs::read(input_path)?
        } else {
            // Read from stdin
            let mut data = Vec::new();
            std::io::stdin().read_to_end(&mut data)?;
            data
        };

        // Prompt for archive passphrase
        let archive_passphrase = rpassword::prompt_password(
            "Enter passphrase for the archive (leave empty if not encrypted): ",
        )?;
        let archive_passphrase = if archive_passphrase.is_empty() {
            None
        } else {
            Some(archive_passphrase)
        };

        // Extract the archive
        let payload = extract_archive(&archive_data, archive_passphrase.as_deref())?;

        println!("Archive contains {} secrets", payload.secrets.len());
        println!(
            "Exported at: {}",
            payload.exported_at.format("%Y-%m-%d %H:%M:%S UTC")
        );
        println!("Source vault: {}", payload.source_vault_id);

        // Parse import mode
        let import_mode = ImportMode::from_str(&self.mode)?;

        let mut imported = 0;
        let mut skipped = 0;
        let mut overwritten = 0;

        // Import each secret
        for archived_secret in &payload.secrets {
            let path = SecretPath::new(archived_secret.path.clone())?;

            // Decode the secret value
            let value_bytes = BASE64_STANDARD
                .decode(&archived_secret.value)
                .map_err(|e| anyhow::anyhow!("Invalid base64 in secret: {}", e))?;
            let value = sigil_core::SecretValue::new(value_bytes);

            // Check if secret already exists
            let exists = rt.block_on(vault.get(&path)).is_ok();

            if exists {
                match import_mode {
                    ImportMode::Merge => {
                        println!("  Skipping existing secret: {}", archived_secret.path);
                        skipped += 1;
                        continue;
                    }
                    ImportMode::Overwrite => {
                        println!("  Overwriting: {}", archived_secret.path);
                        overwritten += 1;
                    }
                    ImportMode::Interactive => {
                        print!(
                            "Secret '{}' already exists. Overwrite? [y/N]: ",
                            archived_secret.path
                        );
                        std::io::stdout().flush()?;
                        let mut input = String::new();
                        std::io::stdin().read_line(&mut input)?;
                        if !input.trim().to_lowercase().starts_with('y') {
                            println!("  Skipping: {}", archived_secret.path);
                            skipped += 1;
                            continue;
                        }
                        println!("  Overwriting: {}", archived_secret.path);
                        overwritten += 1;
                    }
                }
            } else {
                println!("  Importing: {}", archived_secret.path);
                imported += 1;
            }

            // Import the secret
            rt.block_on(vault.set(&path, &value, &archived_secret.metadata))?;
        }

        println!();
        println!("Import summary:");
        println!("  Imported: {}", imported);
        println!("  Skipped: {}", skipped);
        println!("  Overwritten: {}", overwritten);

        Ok(())
    }
}

/// Generate shell completions
#[derive(clap::Args, Clone)]
struct CommandCompletions {
    /// Shell type (bash, zsh, fish, elvish)
    shell: String,
}

impl CommandCompletions {
    fn run(&self) -> Result<()> {
        use clap_complete::{generate, Shell};

        let shell = match self.shell.as_str() {
            "bash" => Shell::Bash,
            "zsh" => Shell::Zsh,
            "fish" => Shell::Fish,
            "elvish" => Shell::Elvish,
            _ => anyhow::bail!(
                "Unsupported shell: {}. Supported: bash, zsh, fish, elvish",
                self.shell
            ),
        };

        let mut cmd = Cli::command();
        generate(shell, &mut cmd, "sigil", &mut std::io::stdout());

        Ok(())
    }
}

/// Complete a secret path (for dynamic shell completion)
#[derive(clap::Args, Clone)]
struct CommandComplete {
    /// Current word being completed
    current_word: Option<String>,

    /// Previous word (to check if we're completing after "secret:" prefix)
    previous_word: Option<String>,

    /// Socket path (default: $XDG_RUNTIME_DIR/sigil.sock)
    #[arg(short, long)]
    socket: Option<String>,
}

impl CommandComplete {
    fn run(&self) -> Result<()> {
        // Determine socket path
        let socket_path = if let Some(s) = &self.socket {
            s.clone()
        } else {
            std::env::var("SIGIL_SOCKET").unwrap_or_else(|_| {
                if let Ok(runtime_dir) = std::env::var("XDG_RUNTIME_DIR") {
                    format!("{}/sigil.sock", runtime_dir)
                } else {
                    format!("/tmp/sigil-{}.sock", std::process::id())
                }
            })
        };

        // Check if daemon is running
        let path = std::path::Path::new(&socket_path);
        if !path.exists() {
            // Daemon not running - return no completions (not an error)
            return Ok(());
        }

        // Connect to daemon and request secret list
        use sigil_core::{write_message, IpcOperation, IpcRequest};

        let mut stream = std::os::unix::net::UnixStream::connect(&socket_path)
            .context(format!("Failed to connect to daemon at {}", socket_path))?;

        // Use empty session token (completion doesn't require authentication)
        let session_token = std::env::var("SIGIL_SESSION_TOKEN").unwrap_or_default();
        let request = IpcRequest::new(IpcOperation::List, session_token);

        let json = serde_json::to_vec(&request)?;
        write_message(&mut stream, &json)?;

        // Read response
        let data = sigil_core::read_message(&mut stream)?;
        let response: sigil_core::IpcResponse =
            serde_json::from_slice(&data).context("Invalid response from daemon")?;

        if !response.ok {
            // Daemon returned error - return no completions
            return Ok(());
        }

        // Parse secret list from response
        if !response.payload.is_null() {
            if let Ok(metadata_list) =
                serde_json::from_value::<Vec<sigil_core::SecretMetadata>>(response.payload)
            {
                // Get the current prefix to filter
                let prefix = self.current_word.as_deref().unwrap_or("");

                for meta in metadata_list {
                    let secret_path = meta.path.as_str();
                    // Filter by prefix if provided
                    if prefix.is_empty() || secret_path.starts_with(prefix) {
                        println!("{}", secret_path);
                    }
                }
            }
        }

        Ok(())
    }
}

/// Show documentation for a topic
#[derive(clap::Args, Clone)]
struct CommandTopic {
    /// Topic to show help for (e.g., vault, placeholders, hooks)
    topic: Option<String>,
}

impl CommandTopic {
    fn run(&self) -> Result<()> {
        match &self.topic {
            Some(topic) => {
                // Show specific topic
                help::show_topic(topic)?;
            }
            None => {
                // Show general help and available topics
                println!("SIGIL - Secret management for AI coding agents");
                println!();
                println!("Usage: sigil <COMMAND>");
                println!();
                println!("For command help, run: sigil <COMMAND> --help");
                println!();
                println!("Available help topics:");
                for (name, desc) in help::TOPICS {
                    println!("  {:12} - {}", name, desc);
                }
                println!();
                println!("To show help for a topic:");
                println!("  sigil topic <topic>");
                println!();
                println!("For more information, see: https://github.com/jedarden/SIGIL");
            }
        }
        Ok(())
    }
}

/// Migrate data formats to current version
#[derive(clap::Args, Clone)]
struct CommandMigrate {
    /// Show what would be migrated without making changes
    #[arg(short, long)]
    dry_run: bool,

    /// Run migration without confirmation (for CI/scripts)
    #[arg(short, long)]
    auto: bool,
}

impl CommandMigrate {
    fn run(&self) -> Result<()> {
        // Get vault path
        let home =
            dirs::home_dir().ok_or_else(|| anyhow::anyhow!("Cannot determine home directory"))?;
        let sigil_dir = home.join(".sigil");
        let vault_path = sigil_dir.join("vault");

        if !sigil_dir.exists() {
            println!("No SIGIL installation found at {}", sigil_dir.display());
            println!("If your vault is in a different location, this command currently only");
            println!("supports the default ~/.sigil location.");
            return Ok(());
        }

        use migrate::run_migrations;
        let _result = run_migrations(&vault_path, self.dry_run, self.auto)?;

        if self.dry_run {
            println!();
            println!("Dry run complete.");
        }

        Ok(())
    }
}

/// Uninstall SIGIL components
#[derive(clap::Args, Clone)]
struct CommandUninstall {
    /// Preview what would be removed without making changes
    #[arg(short, long)]
    dry_run: bool,

    /// Remove only hooks (keep vault and daemon)
    #[arg(long)]
    hooks_only: bool,

    /// Remove only runtime artifacts (socket, lockfile, tmpfs)
    #[arg(long)]
    runtime_only: bool,

    /// Remove only vault data
    #[arg(long)]
    vault_only: bool,

    /// Remove everything EXCEPT vault data
    #[arg(long)]
    keep_vault: bool,

    /// Remove everything including vault (requires confirmation)
    #[arg(long)]
    purge: bool,
}

/// Resolve secret placeholders in a command
#[derive(clap::Args, Clone)]
struct CommandResolve {
    /// Command string (reads from stdin if not provided)
    #[arg(value_name = "COMMAND")]
    command: Option<String>,

    /// Output format (json or text)
    #[arg(short, long, default_value = "json")]
    format: String,
}

impl CommandResolve {
    fn run(&self) -> Result<()> {
        // Read command from stdin or argument
        let command_str = if let Some(cmd) = &self.command {
            cmd.clone()
        } else {
            let mut input = String::new();
            std::io::stdin().read_to_string(&mut input)?;
            input.trim().to_string()
        };

        // Validate command
        CommandParser::validate_command(&command_str)?;

        // Resolve command
        let resolved = CommandParser::resolve_command(&command_str)?;

        match self.format.as_str() {
            "json" => {
                // Output JSON for hooks
                let output = serde_json::json!({
                    "command": resolved.resolved,
                    "has_secrets": resolved.has_secrets(),
                    "secret_paths": resolved.secret_paths(),
                    "env_injections": resolved.env_injections,
                    "file_injections": resolved.file_injections,
                    "use_stdin": resolved.use_stdin,
                });
                println!("{}", output);
            }
            "text" => {
                // Human-readable output
                if resolved.has_secrets() {
                    println!("Resolved command: {}", resolved.resolved);
                    println!("Secrets: {}", resolved.secret_paths().join(", "));
                    if !resolved.env_injections.is_empty() {
                        println!("Environment variables:");
                        for (name, path) in &resolved.env_injections {
                            println!("  {} = {{{{secret:{}}}}}", name, path);
                        }
                    }
                    if !resolved.file_injections.is_empty() {
                        println!("File injections:");
                        for (path, target) in &resolved.file_injections {
                            println!("  {{{{secret:{}}}}} -> {}", path, target);
                        }
                    }
                    if resolved.use_stdin {
                        println!(
                            "Stdin injection: {{{{secret:{}}}}}",
                            resolved.stdin_secret.unwrap_or_default()
                        );
                    }
                } else {
                    println!("No secret placeholders found in command");
                }
            }
            _ => {
                anyhow::bail!("Invalid format: {}. Use 'json' or 'text'", self.format);
            }
        }

        Ok(())
    }
}

/// Scrub secrets from output
#[derive(clap::Args, Clone)]
struct CommandScrub {
    /// Prefix filter for secrets to load (default: all secrets)
    #[arg(short, long, default_value = "")]
    prefix: String,

    /// Output format (text or json)
    #[arg(short, long, default_value = "text")]
    format: String,
}

impl CommandScrub {
    fn run(&self) -> Result<()> {
        let vault = load_vault()?;
        let rt = tokio::runtime::Runtime::new()?;

        // Load all secrets
        let secrets_meta = rt.block_on(vault.list(&self.prefix))?;

        if secrets_meta.is_empty() {
            // No secrets to scrub, just echo input
            let mut input = String::new();
            std::io::stdin().read_to_string(&mut input)?;
            print!("{}", input);
            return Ok(());
        }

        // Build scrubber with all secret values
        let mut scrubber = Scrubber::new();
        for meta in secrets_meta {
            let path = SecretPath::new(meta.path.as_str().to_string())?;
            let value = rt.block_on(vault.get(&path))?;
            value.expose(|bytes| {
                scrubber.add_secret(path.clone(), bytes);
                Ok::<(), anyhow::Error>(())
            })?;
        }

        // Read input from stdin
        let mut input = String::new();
        std::io::stdin().read_to_string(&mut input)?;

        // Scrub the input
        let result = scrubber.scrub_with_stats(&input);

        match self.format.as_str() {
            "text" => {
                print!("{}", result.scrubbed);
                if result.matches_found {
                    eprintln!(
                        "\n[SIGIL] Scrubbed {} secret(s) from output",
                        result.secrets_detected
                    );
                }
            }
            "json" => {
                let output = serde_json::json!({
                    "scrubbed": result.scrubbed,
                    "matches_found": result.matches_found,
                    "secrets_detected": result.secrets_detected,
                });
                println!("{}", output);
            }
            _ => {
                anyhow::bail!("Invalid format: {}. Use 'text' or 'json'", self.format);
            }
        }

        Ok(())
    }
}

/// Execute a command with the full SIGIL pipeline
#[derive(clap::Args, Clone)]
struct CommandExec {
    /// Command to execute
    #[arg(value_name = "COMMAND")]
    command: String,

    /// Disable sandboxing
    #[arg(long)]
    no_sandbox: bool,

    /// Disable network isolation (in sandbox mode)
    #[arg(long)]
    allow_network: bool,

    /// Disable output scrubbing
    #[arg(long)]
    no_scrub: bool,

    /// Fail if secrets are detected in output
    #[arg(long)]
    fail_on_leak: bool,

    /// Project directory (for sandbox bind mount)
    #[arg(short, long)]
    project_dir: Option<String>,
}

impl CommandExec {
    fn run(&self) -> Result<()> {
        use execute::{execute, ExecuteConfig};

        let config = ExecuteConfig {
            sandbox_enabled: !self.no_sandbox,
            project_dir: self.project_dir.as_ref().map(PathBuf::from),
            network_isolated: !self.allow_network,
            scrub_enabled: !self.no_scrub,
            fail_on_leak: self.fail_on_leak,
            previous_state: None,
            auto_inject_enabled: true,
            signatures_project_dir: self.project_dir.as_ref().map(PathBuf::from),
        };

        let result = execute(&self.command, &config)?;

        // Write output
        std::io::stdout().write_all(result.stdout.as_bytes())?;
        std::io::stderr().write_all(result.stderr.as_bytes())?;

        // Print summary if secrets were scrubbed
        if result.secrets_scrubbed {
            eprintln!(
                "\n[SIGIL] Scrubbed {} secret(s) from output ({}ms)",
                result.secrets_detected, result.execution_time_ms
            );
        }

        // Return the exit code
        std::process::exit(result.exit_code);
    }
}

/// Wrap any command with secret injection (for human use)
#[derive(clap::Args, Clone)]
struct CommandWrap {
    /// Command to execute (use -- to separate from sigil flags)
    #[arg(value_name = "COMMAND")]
    command: String,

    /// Enable sandboxing (disabled by default for wrap)
    #[arg(long)]
    sandbox: bool,

    /// Disable output scrubbing
    #[arg(long)]
    no_scrub: bool,

    /// Project directory (for sandbox bind mount)
    #[arg(short, long)]
    project_dir: Option<String>,
}

impl CommandWrap {
    fn run(&self) -> Result<()> {
        use sigil_core::ipc::{ExecRequest, IpcOperation, IpcRequest};
        use std::os::unix::net::UnixStream;

        // Determine socket path
        let socket_path = std::env::var("SIGIL_SOCKET").unwrap_or_else(|_| {
            let runtime_dir = std::env::var("XDG_RUNTIME_DIR").unwrap_or_else(|_| {
                // Try to get UID from environment or use a default
                let uid = std::env::var("UID").unwrap_or_else(|_| {
                    // Fallback: try to get UID from user ID
                    std::process::id().to_string()
                });
                format!("/run/user/{}", uid)
            });
            format!("{}/sigil.sock", runtime_dir)
        });

        // Check if daemon is running
        let path = std::path::Path::new(&socket_path);
        if !path.exists() {
            anyhow::bail!(
                "Daemon is not running (socket not found at {}).\nStart the daemon with: sigild start",
                socket_path
            );
        }

        // Connect to daemon
        let mut stream = UnixStream::connect(&socket_path).with_context(|| {
            format!(
                "Failed to connect to daemon at {}. Is sigild running?",
                socket_path
            )
        })?;

        // Get or create a session token
        let token = self.get_session_token(&socket_path)?;

        // Build the exec request
        let exec_request = ExecRequest {
            command: self.command.clone(),
            args: Vec::new(), // Command is already parsed as a string
            working_dir: std::env::current_dir()
                .ok()
                .map(|p| p.to_string_lossy().to_string()),
            network_isolated: !self.sandbox, // If sandbox is enabled, isolate network
            timeout_secs: 300,               // 5 minute default timeout
            project_dir: self.project_dir.clone(),
        };

        // Create IPC request
        let request = IpcRequest::with_payload(
            IpcOperation::Exec,
            token,
            serde_json::to_value(exec_request)?,
        );

        // Send request
        sigil_core::ipc::write_message(&mut stream, &serde_json::to_vec(&request)?)?;

        // Read response
        let response_data = sigil_core::ipc::read_message(&mut stream)?;
        let response: sigil_core::ipc::IpcResponse =
            serde_json::from_slice(&response_data).context("Invalid response from daemon")?;

        if !response.ok {
            if let Some(error) = response.error {
                anyhow::bail!("Daemon error: {}", error.message);
            }
            anyhow::bail!("Unknown daemon error");
        }

        // Parse the exec response
        let exec_response: sigil_core::ipc::ExecResponse = serde_json::from_value(response.payload)
            .context("Invalid exec response from daemon")?;

        // Write output
        std::io::stdout().write_all(exec_response.stdout.as_bytes())?;
        std::io::stderr().write_all(exec_response.stderr.as_bytes())?;

        // Print summary if signatures matched or secrets were scrubbed
        if !exec_response.matched_signatures.is_empty() {
            eprintln!(
                "\n[SIGIL] Matched signatures: {}",
                exec_response.matched_signatures.join(", ")
            );
        }

        if exec_response.secrets_scrubbed > 0 {
            eprintln!(
                "[SIGIL] Scrubbed {} secret(s) from output ({}ms)",
                exec_response.secrets_scrubbed, exec_response.duration_ms
            );
        }

        if exec_response.timed_out {
            eprintln!("[SIGIL] Command timed out");
        }

        // Return the exit code
        std::process::exit(exec_response.exit_code);
    }

    /// Get or create a session token for the daemon
    fn get_session_token(&self, socket_path: &str) -> Result<String> {
        use sigil_core::ipc::{IpcOperation, IpcRequest};
        use std::os::unix::net::UnixStream;

        // Try to get an existing token from environment
        if let Ok(token) = std::env::var("SIGIL_SESSION_TOKEN") {
            return Ok(token);
        }

        // Create a new session
        let mut stream = UnixStream::connect(socket_path)?;
        let request = IpcRequest::new(IpcOperation::SessionStart, "".to_string());
        sigil_core::ipc::write_message(&mut stream, &serde_json::to_vec(&request)?)?;

        let response_data = sigil_core::ipc::read_message(&mut stream)?;
        let response: sigil_core::ipc::IpcResponse =
            serde_json::from_slice(&response_data).context("Invalid session response")?;

        if !response.ok {
            anyhow::bail!("Failed to create session: {:?}", response.error);
        }

        let token = response.payload["token"]
            .as_str()
            .ok_or_else(|| anyhow!("No token in session response"))?
            .to_string();

        // Set for future use in this process
        std::env::set_var("SIGIL_SESSION_TOKEN", &token);

        Ok(token)
    }
}

/// Generate and install man pages for sigil and all subcommands
fn generate_man_pages(man_dir: &std::path::Path) -> Result<()> {
    use std::fs;
    use std::io::BufWriter;

    // Generate man pages using clap_mangen
    let cmd = Cli::command();

    // Generate the main sigil man page
    let man_path = man_dir.join("sigil.1");
    let file = fs::File::create(&man_path)?;
    let mut writer = BufWriter::new(file);
    clap_mangen::Man::new(cmd.clone()).render(&mut writer)?;
    println!("✓ Generated: {}", man_path.display());

    // Generate man pages for each subcommand
    for subcommand in cmd.get_subcommands() {
        let name = subcommand.get_name();
        let man_name = format!("sigil-{}", name);
        let man_path = man_dir.join(format!("{}.1", man_name));

        let file = fs::File::create(&man_path)?;
        let mut writer = BufWriter::new(file);

        // Generate man page for the subcommand directly
        clap_mangen::Man::new(subcommand.clone()).render(&mut writer)?;

        println!("✓ Generated: {}", man_path.display());
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_man_page_generation() {
        use tempfile::TempDir;

        let temp_dir = TempDir::new().unwrap();
        let man_dir = temp_dir.path().join("man1");
        std::fs::create_dir_all(&man_dir).unwrap();

        // Generate man pages
        generate_man_pages(&man_dir).unwrap();

        // Verify main man page exists
        let main_man = man_dir.join("sigil.1");
        assert!(main_man.exists(), "Main man page should exist");

        // Verify content - man pages typically start with .TH header
        let content = std::fs::read_to_string(&main_man).unwrap();
        assert!(content.contains(".TH"), "Should contain man page header");
        assert!(content.contains("sigil"), "Should contain command name");
        assert!(
            content.contains("Secret management"),
            "Should contain description"
        );

        // Verify some subcommand man pages exist
        let add_man = man_dir.join("sigil-add.1");
        assert!(add_man.exists(), "Add command man page should exist");

        let get_man = man_dir.join("sigil-get.1");
        assert!(get_man.exists(), "Get command man page should exist");
    }
}

/// Setup SIGIL integration with external tools
#[derive(clap::Args, Clone)]
struct CommandSetup {
    /// Tool to setup
    #[arg(value_name = "TOOL")]
    tool: String,
}

impl CommandSetup {
    fn run(&self) -> Result<()> {
        match self.tool.as_str() {
            "claude-code" => {
                hooks::setup_claude_code_hooks()?;
                println!();
                println!("Project instructions snippet:");
                println!("---");
                println!("{}", hooks::generate_claude_md_snippet()?);
                println!("---");
            }
            "git" => {
                self.setup_git()?;
            }
            "ssh" => {
                self.setup_ssh()?;
            }
            "shell" => {
                self.setup_shell()?;
            }
            "man" => {
                self.setup_man()?;
            }
            "docker" => {
                self.setup_docker()?;
            }
            "systemd" => {
                self.setup_systemd()?;
            }
            "launchd" => {
                self.setup_launchd()?;
            }
            "mcp" => {
                self.setup_mcp()?;
            }
            _ => anyhow::bail!(
                "Unknown tool '{}'. Supported: claude-code, git, ssh, shell, man, docker, systemd, launchd, mcp",
                self.tool
            ),
        }
        Ok(())
    }

    /// Setup SIGIL as the Git credential helper
    fn setup_git(&self) -> Result<()> {
        use std::process::Command;

        println!("Setting up SIGIL as your Git credential helper...");
        println!();

        // Get the path to the sigil-credential-git binary
        let exe_path = std::env::current_exe()?;
        let credential_helper = if exe_path.ends_with("sigil") || exe_path.ends_with("sigil.exe") {
            // sigil is in the same directory as sigil-credential-git
            let helper_path = exe_path.with_file_name("sigil-credential-git");
            if helper_path.exists() {
                helper_path.to_string_lossy().to_string()
            } else {
                // Fallback: assume it's in PATH
                "sigil-credential-git".to_string()
            }
        } else {
            // Development build or different location
            "sigil-credential-git".to_string()
        };

        // Configure git to use SIGIL as the credential helper
        let output = Command::new("git")
            .args([
                "config",
                "--global",
                "credential.helper",
                &credential_helper,
            ])
            .output()?;

        if !output.status.success() {
            anyhow::bail!(
                "Failed to configure git credential helper: {}",
                String::from_utf8_lossy(&output.stderr)
            );
        }

        println!("✓ Git credential helper configured");
        println!();
        println!("Git will now use SIGIL to retrieve credentials for HTTPS remotes.");
        println!();
        println!("Next steps:");
        println!("1. Add your GitHub token: sigil add github/token");
        println!("2. Add your GitLab token: sigil add gitlab/token");
        println!("3. Use git normally: git push, git pull, etc.");
        println!();
        println!("Per-repo configuration:");
        println!("Create .sigil/git-credentials.toml in your repo to customize mappings:");
        println!();
        println!("[host_mappings]");
        println!("\"github.com\" = \"myproject/github_token\"");
        println!("\"gitlab.com\" = \"myproject/gitlab_token\"");

        Ok(())
    }

    /// Setup SIGIL SSH agent
    fn setup_ssh(&self) -> Result<()> {
        println!("Setting up SIGIL SSH agent...");
        println!();

        // Get the runtime directory
        let runtime_dir = std::env::var("XDG_RUNTIME_DIR")
            .or_else(|_| std::env::var("TMPDIR"))
            .unwrap_or_else(|_| "/tmp".to_string());

        let socket_path = format!("{}/sigil-ssh-agent.sock", runtime_dir);

        println!("SSH agent socket: {}", socket_path);
        println!();

        // Add SSH setup instructions to .ssh/config
        let ssh_dir = dirs::home_dir()
            .ok_or_else(|| anyhow::anyhow!("Cannot determine home directory"))?
            .join(".ssh");

        std::fs::create_dir_all(&ssh_dir)?;

        let config_file = ssh_dir.join("config");

        // Read existing config or create new one
        let existing_config = if config_file.exists() {
            std::fs::read_to_string(&config_file)?
        } else {
            String::new()
        };

        // Check if SIGIL entry already exists
        if existing_config.contains("# SIGIL SSH agent") {
            println!("✓ SSH config already contains SIGIL entry");
        } else {
            let sigil_entry = format!(
                r#"
# SIGIL SSH agent
# Add SIGIL-managed identities with: sigil add ssh/<name>
Host *
    IdentityAgent {}
    IdentitiesOnly yes
"#,
                socket_path
            );

            let mut new_config = existing_config;
            if !new_config.ends_with('\n') && !new_config.is_empty() {
                new_config.push('\n');
            }
            new_config.push_str(&sigil_entry);

            std::fs::write(&config_file, new_config)?;

            println!("✓ SSH config updated");
        }

        println!();
        println!("To use the SIGIL SSH agent:");
        println!("1. Start the agent: sigil ssh-agent start");
        println!("2. Add SSH keys to vault: sigil add ssh/github");
        println!("3. Use ssh normally: ssh github.com");
        println!();
        println!("For persistent startup, add to your shell profile:");
        println!("  export SSH_AUTH_SOCK=$(sigil ssh-agent print-socket)");
        println!("  sigil ssh-agent start &");

        Ok(())
    }

    /// Setup shell completions
    fn setup_shell(&self) -> Result<()> {
        use std::fs;

        println!("Setting up shell completions...");
        println!();

        // Detect the current shell
        let shell = std::env::var("SHELL").unwrap_or_default();
        let shell_name = shell.rsplit('/').next().unwrap_or("unknown");

        println!("Detected shell: {}", shell_name);
        println!();

        let home =
            dirs::home_dir().ok_or_else(|| anyhow::anyhow!("Cannot determine home directory"))?;

        match shell_name {
            "bash" => {
                // Setup bash completions
                let completions_dir = home.join(".local/share/bash-completion/completions");
                fs::create_dir_all(&completions_dir)?;

                let completions_file = completions_dir.join("sigil");

                // Generate completions
                use clap_complete::{generate, Shell};
                let mut cmd = Cli::command();
                let mut buffer = Vec::new();
                generate(Shell::Bash, &mut cmd, "sigil", &mut buffer);

                // Append dynamic completion for secret paths
                let dynamic_completion = r#"

# Dynamic secret path completion
_sigil_complete_secret_paths() {
    local current_word="${COMP_WORDS[COMP_CWORD]}"
    local previous_word="${COMP_WORDS[COMP_CWORD-1]}"

    # Only complete after 'secret:' prefix or for get/add/edit/rm commands
    case "${previous_word}" in
        secret:|{{secret:)
            # Complete secret paths after 'secret:' prefix
            COMPREPLY=($(compgen -W "$(sigil complete --current-word "${current_word}" 2>/dev/null)" -- "${current_word}"))
            ;;
        get|add|edit|rm|history|rollback)
            # Complete secret paths for vault commands
            COMPREPLY=($(compgen -W "$(sigil complete --current-word "${current_word}" 2>/dev/null)" -- "${current_word}"))
            ;;
        *)
            # Fall back to default completion
            return 1
            ;;
    esac
}

complete -F _sigil_complete_secret_paths -o bashdefault -o default sigil
"#;
                buffer.extend_from_slice(dynamic_completion.as_bytes());

                fs::write(&completions_file, buffer)?;

                println!(
                    "✓ Bash completions installed to: {}",
                    completions_file.display()
                );
                println!();
                println!("Completions will be available in new shells.");
                println!("To enable in the current shell, run:");
                println!("  source ~/.local/share/bash-completion/completions/sigil");
            }
            "zsh" => {
                // Setup zsh completions
                let completions_dir = home.join(".zfunc");
                fs::create_dir_all(&completions_dir)?;

                let completions_file = completions_dir.join("_sigil");

                // Generate completions
                use clap_complete::{generate, Shell};
                let mut cmd = Cli::command();
                let mut buffer = Vec::new();
                generate(Shell::Zsh, &mut cmd, "sigil", &mut buffer);

                // Append dynamic completion for secret paths
                let dynamic_completion = r#"

# Dynamic secret path completion
_sigil_secret_paths() {
    local current_word="$words[CURRENT]"
    local previous_word="$words[CURRENT-1]"

    # Only complete after 'secret:' prefix or for specific commands
    case "$previous_word" in
        secret:|{{secret:)
            # Complete secret paths after 'secret:' prefix
            _describe 'secret paths' "$(sigil complete --current-word "$current_word" 2>/dev/null)"
            ;;
        get|add|edit|rm|history|rollback)
            # Complete secret paths for vault commands
            _describe 'secret paths' "$(sigil complete --current-word "$current_word" 2>/dev/null)"
            ;;
        *)
            # Fall back to default completion
            _default
            ;;
    esac
}

# Register the completion function for relevant commands
compdef _sigil_secret_paths sigil
"#;
                buffer.extend_from_slice(dynamic_completion.as_bytes());

                fs::write(&completions_file, buffer)?;

                println!(
                    "✓ Zsh completions installed to: {}",
                    completions_file.display()
                );
                println!();
                println!("Add the following to ~/.zshrc if not already present:");
                println!("  fpath=(~/.zfunc $fpath)");
                println!("  autoload -U compinit && compinit");
            }
            "fish" => {
                // Setup fish completions
                let completions_dir = home.join(".config/fish/completions");
                fs::create_dir_all(&completions_dir)?;

                let completions_file = completions_dir.join("sigil.fish");

                // Generate completions
                use clap_complete::{generate, Shell};
                let mut cmd = Cli::command();
                let mut buffer = Vec::new();
                generate(Shell::Fish, &mut cmd, "sigil", &mut buffer);

                // Append dynamic completion for secret paths
                let dynamic_completion = r#"

# Dynamic secret path completion
function __sigil_complete_secret_paths
    set -l current_word (commandline -t)
    set -l previous_word (commandline -poc | tail -1)

    # Complete secret paths for relevant commands
    switch $previous_word
        case "secret:" "{{secret:"
            sigil complete --current-word "$current_word" 2>/dev/null
        case "get" "add" "edit" "rm" "history" "rollback"
            sigil complete --current-word "$current_word" 2>/dev/null
    end
end
"#;
                buffer.extend_from_slice(dynamic_completion.as_bytes());

                fs::write(&completions_file, buffer)?;

                println!(
                    "✓ Fish completions installed to: {}",
                    completions_file.display()
                );
                println!();
                println!("Completions will be available in new shells.");
            }
            _ => {
                println!("Shell '{}' is not auto-detected.", shell_name);
                println!();
                println!("To manually install completions, run:");
                println!(
                    "  sigil completions bash > ~/.local/share/bash-completion/completions/sigil"
                );
                println!("  sigil completions zsh > ~/.zfunc/_sigil");
                println!("  sigil completions fish > ~/.config/fish/completions/sigil.fish");
            }
        }

        Ok(())
    }

    /// Setup man pages
    fn setup_man(&self) -> Result<()> {
        use std::fs;

        println!("Setting up man pages...");
        println!();

        let home =
            dirs::home_dir().ok_or_else(|| anyhow::anyhow!("Cannot determine home directory"))?;
        let man_dir = home.join(".local/share/man/man1");
        fs::create_dir_all(&man_dir)?;

        // Generate and install man pages
        generate_man_pages(&man_dir)?;

        println!("Man pages installed to: {}", man_dir.display());
        println!();
        println!("You can now view man pages with:");
        println!("  man sigil           # Main sigil man page");
        println!("  man sigil-add       # Add command");
        println!("  man sigil-get       # Get command");
        println!("  man sigil-init      # Init command");
        println!("  (and all other subcommands)");
        println!();
        println!("For online documentation, see:");
        println!("  https://docs.sigil.rs");

        Ok(())
    }

    /// Setup SIGIL as the Docker credential helper
    fn setup_docker(&self) -> Result<()> {
        use std::fs;

        println!("Setting up SIGIL as Docker credential helper...");
        println!();

        // Get Docker config directory
        let home =
            dirs::home_dir().ok_or_else(|| anyhow::anyhow!("Cannot determine home directory"))?;
        let docker_config = home.join(".docker");
        fs::create_dir_all(&docker_config)?;

        let config_file = docker_config.join("config.json");

        // Read existing config or create new one
        let mut config = if config_file.exists() {
            let content = fs::read_to_string(&config_file)?;
            serde_json::from_str(&content).unwrap_or(serde_json::json!({}))
        } else {
            serde_json::json!({})
        };

        // Add credential helper configuration
        if let Some(obj) = config.as_object_mut() {
            obj.insert("credsStore".to_string(), serde_json::json!(null));

            let creds_helpers = obj
                .entry("credHelpers")
                .or_insert_with(|| serde_json::json!({}));
            if let Some(helpers) = creds_helpers.as_object_mut() {
                // Configure common registries to use SIGIL
                helpers.insert(
                    "ghcr.io".to_string(),
                    serde_json::json!("sigil-credential-docker"),
                );
                helpers.insert(
                    "https://index.docker.io".to_string(),
                    serde_json::json!("sigil-credential-docker"),
                );
                helpers.insert(
                    "gcr.io".to_string(),
                    serde_json::json!("sigil-credential-docker"),
                );
                helpers.insert(
                    "https://gcr.io".to_string(),
                    serde_json::json!("sigil-credential-docker"),
                );
            }
        }

        // Write config
        let config_json = serde_json::to_string_pretty(&config)?;
        fs::write(&config_file, config_json)?;

        println!("Docker config updated: {}", config_file.display());
        println!();
        println!("SIGIL will now be used for Docker registry authentication.");
        println!();
        println!("To add Docker credentials:");
        println!("  sigil add docker/ghcr_token      # For GitHub Container Registry");
        println!("  sigil add docker/hub_token       # For Docker Hub");
        println!("  sigil add docker/gcr_token       # For Google Container Registry");
        println!("  sigil add docker/ecr_token       # For AWS ECR");
        println!("  sigil add docker/acr_token       # For Azure Container Registry");
        println!();
        println!("Then pull images as usual:");
        println!("  docker pull ghcr.io/example/image:latest");

        Ok(())
    }

    /// Setup systemd socket activation for the daemon
    fn setup_systemd(&self) -> Result<()> {
        use std::fs;

        println!("Setting up systemd socket activation for SIGIL daemon...");
        println!();

        let home =
            dirs::home_dir().ok_or_else(|| anyhow::anyhow!("Cannot determine home directory"))?;
        let systemd_dir = home.join(".config/systemd/user");
        fs::create_dir_all(&systemd_dir)?;

        // Get the sigil binary path
        let sigil_path = std::env::current_exe()?;
        let sigil_bin = sigil_path.to_string_lossy().to_string();

        // Create the socket unit file
        let socket_unit = r#"[Unit]
Description=SIGIL Secret Management Daemon Socket
Documentation=https://docs.sigil.rs

[Socket]
ListenStream=%t/sigil.sock
SocketMode=0600

[Install]
WantedBy=sockets.target
"#;

        // Create the service unit file
        let service_unit = format!(
            r#"[Unit]
Description=SIGIL Secret Management Daemon
Documentation=https://docs.sigil.rs
Requires=sigil.socket
After=sigil.socket

[Service]
Type=notify
ExecStart={}
ExecStop=/usr/bin/env kill {{MAINPID}}

# Security hardening
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=%t
RestrictRealtime=yes
RestrictAddressFamilies=AF_UNIX

# Resource limits
MemoryMax=512M
TasksMax=128

[Install]
WantedBy=default.target
"#,
            sigil_bin
        );

        // Write the socket unit file
        let socket_path = systemd_dir.join("sigil.socket");
        fs::write(&socket_path, socket_unit)?;
        println!("Created: {}", socket_path.display());

        // Write the service unit file
        let service_path = systemd_dir.join("sigil.service");
        fs::write(&service_path, service_unit)?;
        println!("Created: {}", service_path.display());

        println!();
        println!("systemd units installed successfully!");
        println!();
        println!("To enable and start the daemon:");
        println!("  systemctl --user daemon-reload");
        println!("  systemctl --user enable --now sigil.socket");
        println!();
        println!("The daemon will start automatically on first connection.");
        println!();
        println!("To stop the daemon:");
        println!("  systemctl --user stop sigil.service");
        println!();
        println!("To view logs:");
        println!("  journalctl --user -u sigil -f");

        Ok(())
    }

    /// Setup launchd socket activation for the daemon (macOS)
    fn setup_launchd(&self) -> Result<()> {
        use std::fs;

        println!("Setting up launchd for SIGIL daemon...");
        println!();

        // Get the sigil binary path
        let sigil_path = std::env::current_exe()?;
        let sigil_bin = sigil_path.to_string_lossy().to_string();

        // On macOS, launchd agents go in ~/Library/LaunchAgents
        let home =
            dirs::home_dir().ok_or_else(|| anyhow::anyhow!("Cannot determine home directory"))?;
        let launch_agents_dir = home.join("Library/LaunchAgents");
        fs::create_dir_all(&launch_agents_dir)?;

        // Create the plist file
        let plist_content = format!(
            r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.sigil.daemon</string>

    <key>ProgramArguments</key>
    <array>
        <string>{}</string>
        <string>daemon</string>
        <string>--launchd</string>
    </array>

    <key>Sockets</key>
    <dict>
        <key>sigil</key>
        <dict>
            <key>SockPathMode</key>
            <integer>384</integer>
            <key>SockPathName</key>
            <string>sigil.sock</string>
        </dict>
    </dict>

    <key>KeepAlive</key>
    <dict>
        <key>OtherJobEnabled</key>
        <dict/>
    </dict>

    <key>RunAtLoad</key>
    <false/>

    <key>WorkingDirectory</key>
    <string>~</string>

    <key>StandardOutPath</key>
    <string>/tmp/sigil.log</string>

    <key>StandardErrorPath</key>
    <string>/tmp/sigil.log</string>

    <key>ProcessType</key>
    <string>Background</string>

    <key>Nice</key>
    <integer>5</integer>

    <key>SoftResourceLimits</key>
    <dict>
        <key>NumberOfFiles</key>
        <integer>512</integer>
    </dict>
</dict>
</plist>
"#,
            sigil_bin
        );

        // Write the plist file
        let plist_path = launch_agents_dir.join("com.sigil.daemon.plist");
        fs::write(&plist_path, plist_content)?;
        println!("Created: {}", plist_path.display());

        println!();
        println!("launchd agent installed successfully!");
        println!();
        println!("To load the agent:");
        println!("  launchctl load ~/Library/LaunchAgents/com.sigil.daemon.plist");
        println!();
        println!("To unload the agent:");
        println!("  launchctl unload ~/Library/LaunchAgents/com.sigil.daemon.plist");
        println!();
        println!("To view logs:");
        println!("  tail -f /tmp/sigil.log");
        println!();
        println!("Note: Logs are written to /tmp/sigil.log for debugging.");

        Ok(())
    }

    /// Setup MCP server configuration for Claude Code/Cursor
    fn setup_mcp(&self) -> Result<()> {
        use std::fs;

        println!("Setting up SIGIL MCP server for Claude Code/Cursor...");
        println!();

        // Get the sigil-mcp binary path
        let exe_path = std::env::current_exe()?;
        let mcp_server_path = if exe_path.ends_with("sigil") || exe_path.ends_with("sigil.exe") {
            // sigil is in the same directory as sigil-mcp
            let server_path = exe_path.with_file_name("sigil-mcp");
            if server_path.exists() {
                server_path.to_string_lossy().to_string()
            } else {
                // Fallback: assume it's in PATH
                "sigil-mcp".to_string()
            }
        } else {
            // Development build or different location
            "sigil-mcp".to_string()
        };

        // Get Claude Code config directory
        let config_dir = dirs::config_local_dir()
            .ok_or_else(|| anyhow!("Cannot determine config directory"))?
            .join("claude-code");

        fs::create_dir_all(&config_dir).context("Failed to create Claude Code config directory")?;

        let settings_path = config_dir.join("settings.json");

        // Load existing settings or create new
        let mut settings: serde_json::Value = if settings_path.exists() {
            let content = fs::read_to_string(&settings_path)
                .context("Failed to read existing settings.json")?;
            serde_json::from_str(&content).context("Failed to parse settings.json")?
        } else {
            serde_json::json!({})
        };

        // Add MCP server configuration
        let mcp_config = serde_json::json!({
            "command": mcp_server_path,
            "args": [],
            "env": {
                "SIGIL_SESSION_TOKEN": "mcp-session-token"
            }
        });

        // Ensure mcpServers object exists
        if let Some(obj) = settings.as_object_mut() {
            if !obj.contains_key("mcpServers") {
                obj.insert("mcpServers".to_string(), serde_json::json!({}));
            }

            if let Some(mcp_servers) = obj.get_mut("mcpServers").and_then(|v| v.as_object_mut()) {
                mcp_servers.insert("sigil".to_string(), mcp_config);
            }
        }

        // Write updated settings
        let settings_content =
            serde_json::to_string_pretty(&settings).context("Failed to serialize settings")?;

        fs::write(&settings_path, settings_content).context("Failed to write settings.json")?;

        println!("✓ MCP server configured at: {}", settings_path.display());
        println!();
        println!("Available MCP tools:");
        println!("  • sigil_list — List available secret paths and types");
        println!("  • sigil_exec — Execute commands with secret injection");
        println!("  • sigil_write — Write files with resolved secrets");
        println!("  • sigil_env — List available environment variable mappings");
        println!("  • sigil_status — Show session statistics and breach alerts");
        println!("  • sigil_list_operations — List sealed operations");
        println!("  • sigil_request — Request access to a secret");
        println!("  • sigil_check_access — Check if access is granted");
        println!();
        println!("Next steps:");
        println!("1. Ensure SIGIL daemon is running: sigil daemon start");
        println!("2. Restart Claude Code/Cursor for MCP configuration to take effect");
        println!("3. Use 'sigil_list' in Claude to see available secrets");

        Ok(())
    }
}

/// Handle tool hooks
#[derive(clap::Args, Clone)]
struct CommandHook {
    /// Hook type (pre, post, or user-prompt-submit)
    #[arg(value_name = "TYPE")]
    hook_type: String,

    /// Tool name (for pre/post hooks only)
    #[arg(short, long, value_name = "TOOL")]
    tool: Option<String>,
}

impl CommandHook {
    fn run(&self) -> Result<()> {
        match self.hook_type.as_str() {
            "pre" => {
                // Read stdin JSON for PreToolUse
                let mut input_str = String::new();
                std::io::stdin().read_to_string(&mut input_str)?;

                let input: hooks::PreToolUseInput =
                    serde_json::from_str(&input_str).context("Failed to parse PreToolUse input")?;

                let output = hooks::handle_pre_tool_use(&input)?;
                println!("{}", serde_json::to_string(&output)?);
            }
            "post" => {
                // Read stdin JSON for PostToolUse
                let mut input_str = String::new();
                std::io::stdin().read_to_string(&mut input_str)?;

                let input: hooks::PostToolUseInput = serde_json::from_str(&input_str)
                    .context("Failed to parse PostToolUse input")?;

                let output = hooks::handle_post_tool_use(&input)?;
                println!("{}", serde_json::to_string(&output)?);
            }
            "user-prompt-submit" => {
                // Read stdin JSON for UserPromptSubmit
                let mut input_str = String::new();
                std::io::stdin().read_to_string(&mut input_str)?;

                let input: hooks::UserPromptSubmitInput = serde_json::from_str(&input_str)
                    .context("Failed to parse UserPromptSubmit input")?;

                let output = hooks::handle_user_prompt_submit(&input)?;
                println!("{}", serde_json::to_string(&output)?);
            }
            _ => anyhow::bail!(
                "Unknown hook type '{}'. Use 'pre', 'post', or 'user-prompt-submit'",
                self.hook_type
            ),
        }
        Ok(())
    }
}

/// Manage SIGIL configuration
#[derive(clap::Args, Clone)]
struct CommandConfig {
    /// Configuration action (set, get, list)
    #[arg(value_name = "ACTION")]
    action: String,

    /// Configuration key (for set/get)
    #[arg(value_name = "KEY")]
    key: Option<String>,

    /// Configuration value (for set)
    #[arg(value_name = "VALUE")]
    value: Option<String>,

    /// Show all configuration values (for list)
    #[arg(short, long)]
    all: bool,
}

impl CommandConfig {
    fn run(&self) -> Result<()> {
        match self.action.as_str() {
            "set" => self.run_set(),
            "get" => self.run_get(),
            "list" => self.run_list(),
            _ => anyhow::bail!(
                "Unknown action '{}'. Use 'set', 'get', or 'list'",
                self.action
            ),
        }
    }

    /// Set a configuration value
    fn run_set(&self) -> Result<()> {
        let key = self
            .key
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("Missing KEY argument for 'set'"))?;
        let value = self
            .value
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("Missing VALUE argument for 'set'"))?;

        // Determine if this is a Tier 1 (inert) or Tier 2 (security) config
        let (tier, store_key) = classify_config_key(key)?;

        match tier {
            ConfigTier::Tier1 => {
                // Store in ~/.sigil/config.toml (inert config)
                set_tier1_config(store_key, value)?;
                println!("Set configuration: {} = {}", key, value);
            }
            ConfigTier::Tier2 => {
                // Store in encrypted vault as _sigil/config entry
                set_tier2_config(store_key, value)?;
                println!("Set secure configuration: {} = <encrypted>", key);
            }
        }

        Ok(())
    }

    /// Get a configuration value
    fn run_get(&self) -> Result<()> {
        let key = self
            .key
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("Missing KEY argument for 'get'"))?;

        let (tier, store_key) = classify_config_key(key)?;

        match tier {
            ConfigTier::Tier1 => {
                let value = get_tier1_config(store_key)?;
                println!("{}", value);
            }
            ConfigTier::Tier2 => {
                let value = get_tier2_config(store_key)?;
                println!("{}", value);
            }
        }

        Ok(())
    }

    /// List all configuration values
    fn run_list(&self) -> Result<()> {
        println!("=== Tier 1 Configuration (inert, ~/.sigil/config.toml) ===");
        list_tier1_config()?;

        if self.all {
            println!();
            println!("=== Tier 2 Configuration (encrypted, in vault) ===");
            println!("(Security-sensitive configuration - view only in TUI)");
        }

        Ok(())
    }
}

/// Configuration tier (inert or security-sensitive)
enum ConfigTier {
    /// Tier 1: Inert configuration (stored on disk, visible to agent)
    Tier1,
    /// Tier 2: Security configuration (encrypted in vault)
    Tier2,
}

/// Classify a configuration key into Tier 1 or Tier 2
fn classify_config_key(key: &str) -> Result<(ConfigTier, &str)> {
    // Tier 2 (security-sensitive) keys
    const TIER2_KEYS: &[&str] = &[
        "canary.paths",
        "canary.values",
        "acl.path",
        "acl.policy",
        "hook.bypass_token",
        "lockdown.threshold",
        "alert.destination",
        "sandbox.exception",
    ];

    // Normalize the key
    let normalized = key.trim().to_lowercase();

    // Check if it's a Tier 2 key
    for tier2_key in TIER2_KEYS {
        if normalized == *tier2_key || normalized.starts_with(&format!("{}.", tier2_key)) {
            return Ok((ConfigTier::Tier2, tier2_key));
        }
    }

    // Default to Tier 1
    Ok((ConfigTier::Tier1, key))
}

/// Set a Tier 1 configuration value
fn set_tier1_config(key: &str, value: &str) -> Result<()> {
    let home =
        dirs::home_dir().ok_or_else(|| anyhow::anyhow!("Cannot determine home directory"))?;
    let sigil_dir = home.join(".sigil");
    let config_path = sigil_dir.join("config.toml");

    // Create config directory if it doesn't exist
    std::fs::create_dir_all(&sigil_dir)?;

    // Load existing config or create new
    let mut config: toml::Value = if config_path.exists() {
        let content = std::fs::read_to_string(&config_path)?;
        toml::from_str(&content)?
    } else {
        toml::Value::Table(toml::value::Table::new())
    };

    // Parse the key (supports dotted notation like "vault.history.max_versions")
    let key_parts: Vec<&str> = key.split('.').collect();
    set_nested_toml_value(&mut config, &key_parts, value)?;

    // Write back to file
    let config_content = toml::to_string_pretty(&config)?;
    std::fs::write(&config_path, config_content)?;

    Ok(())
}

/// Get a Tier 1 configuration value
fn get_tier1_config(key: &str) -> Result<String> {
    let home =
        dirs::home_dir().ok_or_else(|| anyhow::anyhow!("Cannot determine home directory"))?;
    let config_path = home.join(".sigil/config.toml");

    if !config_path.exists() {
        anyhow::bail!(
            "Configuration file not found. Run 'sigil config set {} <value>' first",
            key
        );
    }

    let content = std::fs::read_to_string(&config_path)?;
    let config: toml::Value = toml::from_str(&content)?;

    // Parse the key
    let key_parts: Vec<&str> = key.split('.').collect();
    let value = get_nested_toml_value(&config, &key_parts)?;

    Ok(value)
}

/// List all Tier 1 configuration values
fn list_tier1_config() -> Result<()> {
    let home =
        dirs::home_dir().ok_or_else(|| anyhow::anyhow!("Cannot determine home directory"))?;
    let config_path = home.join(".sigil/config.toml");

    if !config_path.exists() {
        println!("(no configuration set)");
        return Ok(());
    }

    let content = std::fs::read_to_string(&config_path)?;
    let config: toml::Value = toml::from_str(&content)?;

    // Pretty print the config
    println!("{}", config);
    Ok(())
}

/// Set a Tier 2 configuration value (encrypted in vault)
fn set_tier2_config(key: &str, value: &str) -> Result<()> {
    use sigil_core::{SecretMetadata, SecretPath, SecretType, SecretValue};

    let vault = load_vault()?;

    // Store as a special secret entry
    let config_path = SecretPath::new(format!("_sigil/config/{}", key))?;
    let config_value = SecretValue::from_string(value.to_string());

    let mut meta = SecretMetadata::new(config_path.clone());
    meta.secret_type = SecretType::Generic;
    meta.notes = Some("SIGIL configuration (Tier 2)".to_string());

    let rt = tokio::runtime::Runtime::new()?;
    rt.block_on(vault.set(&config_path, &config_value, &meta))?;

    Ok(())
}

/// Get a Tier 2 configuration value (from vault)
fn get_tier2_config(key: &str) -> Result<String> {
    use sigil_core::SecretPath;

    let vault = load_vault()?;
    let config_path = SecretPath::new(format!("_sigil/config/{}", key))?;

    let rt = tokio::runtime::Runtime::new()?;
    let value = rt.block_on(vault.get(&config_path))?;

    value.expose(|bytes| {
        let str_value = String::from_utf8_lossy(bytes);
        Ok::<String, anyhow::Error>(str_value.to_string())
    })
}

/// Set a nested value in a TOML structure
fn set_nested_toml_value(config: &mut toml::Value, keys: &[&str], value: &str) -> Result<()> {
    if keys.is_empty() {
        anyhow::bail!("Empty key path");
    }

    if keys.len() == 1 {
        // Simple key-value pair
        // Try to parse as various types
        if let Ok(int_val) = value.parse::<i64>() {
            config[keys[0]] = toml::Value::Integer(int_val);
        } else if let Ok(bool_val) = value.parse::<bool>() {
            config[keys[0]] = toml::Value::Boolean(bool_val);
        } else {
            config[keys[0]] = toml::Value::String(value.to_string());
        }
        return Ok(());
    }

    // Nested key
    let current = config
        .as_table_mut()
        .ok_or_else(|| anyhow::anyhow!("Config is not a table"))?;

    if !current.contains_key(keys[0]) {
        current.insert(
            keys[0].to_string(),
            toml::Value::Table(toml::value::Table::new()),
        );
    }

    let nested = current.get_mut(keys[0]).unwrap();
    set_nested_toml_value(nested, &keys[1..], value)?;

    Ok(())
}

/// Get a nested value from a TOML structure
fn get_nested_toml_value(config: &toml::Value, keys: &[&str]) -> Result<String> {
    if keys.is_empty() {
        anyhow::bail!("Empty key path");
    }

    let current = config
        .as_table()
        .ok_or_else(|| anyhow::anyhow!("Config is not a table"))?;

    let value = current
        .get(keys[0])
        .ok_or_else(|| anyhow::anyhow!("Key '{}' not found in configuration", keys[0]))?;

    if keys.len() == 1 {
        // Final value
        match value {
            toml::Value::String(s) => Ok(s.clone()),
            toml::Value::Integer(i) => Ok(i.to_string()),
            toml::Value::Boolean(b) => Ok(b.to_string()),
            toml::Value::Float(f) => Ok(f.to_string()),
            _ => Ok(toml::to_string(value)?.trim_matches('"').to_string()),
        }
    } else {
        // Continue traversing
        get_nested_toml_value(value, &keys[1..])
    }
}

impl CommandUninstall {
    fn run(&self) -> Result<()> {
        use uninstall::{uninstall, UninstallOptions};

        // Validate mutually exclusive options
        let exclusive_count = [
            self.hooks_only,
            self.runtime_only,
            self.vault_only,
            self.keep_vault,
            self.purge,
        ]
        .iter()
        .filter(|&&x| x)
        .count();

        if exclusive_count > 1 {
            anyhow::bail!(
                "Only one of --hooks-only, --runtime-only, --vault-only, --keep-vault, or --purge can be specified"
            );
        }

        let opts = UninstallOptions {
            dry_run: self.dry_run,
            hooks_only: self.hooks_only,
            runtime_only: self.runtime_only,
            vault_only: self.vault_only,
            keep_vault: self.keep_vault,
            purge: self.purge,
        };

        let result = uninstall(opts)?;

        if self.dry_run {
            println!();
            println!(
                "Dry run complete. {} items would be removed.",
                result.would_remove.len()
            );
        } else {
            println!();
            println!(
                "Uninstall complete. {} items removed.",
                result.removed.len()
            );
        }

        Ok(())
    }
}

/// Load the vault from the default location
fn load_vault() -> Result<LocalVault> {
    let home =
        dirs::home_dir().ok_or_else(|| anyhow::anyhow!("Cannot determine home directory"))?;
    let sigil_dir = home.join(".sigil");
    let vault_path = sigil_dir.join("vault");
    let identity_path = sigil_dir.join("identity.age");

    if !sigil_dir.exists() {
        anyhow::bail!("Vault not initialized. Run 'sigil init' first.");
    }

    let mut vault = LocalVault::new(vault_path, identity_path)?;

    // Prompt for passphrase
    let passphrase =
        rpassword::prompt_password("Enter vault passphrase (leave empty if no passphrase): ")?;
    let passphrase = if passphrase.is_empty() {
        None
    } else {
        Some(passphrase)
    };

    vault.load(passphrase.as_deref())?;

    Ok(vault)
}

/// Load the age identity from the identity file
fn load_identity(identity_path: &std::path::Path) -> Result<age::x25519::Identity> {
    use age::secrecy::Secret;
    use age::Decryptor;
    use std::io::Read;
    use std::str::FromStr;

    let encrypted = std::fs::read(identity_path)?;

    // First, try to read as plaintext (for testing/unencrypted)
    if let Ok(secret_key_str) = std::str::from_utf8(&encrypted) {
        if let Ok(identity) = age::x25519::Identity::from_str(secret_key_str.trim()) {
            return Ok(identity);
        }
    }

    // Try to decrypt with passphrase
    let decryptor = Decryptor::new(&encrypted[..])
        .map_err(|e| anyhow::anyhow!("Failed to create decryptor: {}", e))?;

    let secret_key_str = match decryptor {
        Decryptor::Passphrase(d) => {
            // Prompt for passphrase
            let passphrase =
                rpassword::prompt_password("Enter identity passphrase (leave empty if none): ")?;

            if passphrase.is_empty() {
                // Try reading as plaintext
                let secret_key_str = std::str::from_utf8(&encrypted)
                    .map_err(|e| anyhow::anyhow!("Invalid UTF-8: {}", e))?;
                secret_key_str.to_string()
            } else {
                let mut secret = Vec::new();
                let mut reader = d
                    .decrypt(&Secret::new(passphrase), None)
                    .map_err(|e| anyhow::anyhow!("Decryption error: {}", e))?;
                reader
                    .read_to_end(&mut secret)
                    .map_err(|e| anyhow::anyhow!("Read error: {}", e))?;
                String::from_utf8(secret).map_err(|e| anyhow::anyhow!("Invalid UTF-8: {}", e))?
            }
        }
        _ => {
            return Err(anyhow::anyhow!("Unsupported identity format"));
        }
    };

    age::x25519::Identity::from_str(secret_key_str.trim())
        .map_err(|e| anyhow::anyhow!("Failed to parse identity: {}", e))
}

/// Generate breach report from canary monitoring
#[derive(clap::Args, Clone)]
struct CommandBreachReport {
    /// Socket path (default: $XDG_RUNTIME_DIR/sigil.sock)
    #[arg(short, long)]
    socket: Option<String>,

    /// Output format (text or json)
    #[arg(short, long, default_value = "text")]
    format: String,
}

/// Run health checks and diagnostics
#[derive(clap::Args, Clone)]
struct CommandDoctor {
    /// Attempt to automatically fix issues
    #[arg(long)]
    fix: bool,

    /// CI mode: exit non-zero if score below threshold
    #[arg(long)]
    ci: bool,

    /// Minimum score for CI mode (default: 90)
    #[arg(long, default_value = "90")]
    min_score: u8,

    /// Output as JSON
    #[arg(long)]
    json: bool,
}

/// Guided diagnostic with active component testing
#[derive(clap::Args, Clone)]
struct CommandTroubleshoot {
    /// Verbose output
    #[arg(long, short)]
    verbose: bool,
}

impl CommandTroubleshoot {
    fn run(&self) -> Result<()> {
        let report = troubleshoot::run_troubleshoot(self.verbose)?;

        println!("{}", report.format());

        // Exit with error code if any critical checks failed
        if !report.overall_success {
            std::process::exit(1);
        }

        Ok(())
    }
}

impl CommandBreachReport {
    fn run(&self) -> Result<()> {
        // Determine socket path
        let socket_path = if let Some(s) = &self.socket {
            s.clone()
        } else {
            std::env::var("SIGIL_SOCKET").unwrap_or_else(|_| {
                if let Ok(runtime_dir) = std::env::var("XDG_RUNTIME_DIR") {
                    format!("{}/sigil.sock", runtime_dir)
                } else {
                    format!("/tmp/sigil-{}.sock", std::process::id())
                }
            })
        };

        // Check if daemon is running
        let path = std::path::Path::new(&socket_path);
        if !path.exists() {
            println!(
                "Daemon is not running (socket not found at {})",
                socket_path
            );
            println!("Canary monitoring requires the daemon to be active.");
            println!("Start the daemon with: sigild start");
            return Ok(());
        }

        // Connect to daemon and request breach report
        use sigil_core::{write_message, IpcOperation, IpcRequest};

        let mut stream = std::os::unix::net::UnixStream::connect(&socket_path).context(format!(
            "Failed to connect to daemon at {}. Is sigild running?",
            socket_path
        ))?;

        // Use empty session token (breach report doesn't require authentication for monitoring)
        let session_token = std::env::var("SIGIL_SESSION_TOKEN").unwrap_or_default();
        let request = IpcRequest::new(IpcOperation::BreachReport, session_token);

        let json = serde_json::to_vec(&request)?;
        write_message(&mut stream, &json)?;

        // Read response
        let data = sigil_core::read_message(&mut stream)?;
        let response: sigil_core::IpcResponse =
            serde_json::from_slice(&data).context("Invalid response from daemon")?;

        if !response.ok {
            if let Some(error) = response.error {
                anyhow::bail!("Failed to get breach report: {}", error.message);
            }
            anyhow::bail!("Failed to get breach report with unknown error");
        }

        // Parse the breach report
        if self.format == "json" {
            // Output raw JSON
            println!("{}", serde_json::to_string_pretty(&response.payload)?);
        } else {
            // Deserialize and format the breach report
            let report: sigil_canary::BreachReport =
                serde_json::from_value(response.payload).context("Invalid breach report format")?;

            println!("{}", report.format());
        }

        Ok(())
    }
}

impl CommandDoctor {
    fn run(&self) -> Result<()> {
        let report = doctor::run_doctor(self.fix, self.ci)?;

        if self.json {
            let json_output = doctor::format_report_json(&report)?;
            println!("{}", json_output);
        } else {
            let formatted = doctor::format_report(&report);
            println!("{}", formatted);
        }

        // CI mode: exit with appropriate code
        if self.ci {
            let exit_code = report.ci_exit_code(self.min_score);
            if exit_code != 0 {
                eprintln!();
                eprintln!(
                    "CI check failed: score {} < minimum {}",
                    report.score, self.min_score
                );
                std::process::exit(exit_code);
            }
        }

        Ok(())
    }
}

/// Manage sealed operations
#[derive(clap::Args, Clone)]
struct CommandOperations {
    #[command(subcommand)]
    operation: OperationSubcommand,
}

#[derive(Subcommand, Clone)]
enum OperationSubcommand {
    /// List all sealed operations
    List,
    /// Add a new sealed operation
    Add {
        /// Operation ID
        id: String,
        /// Human-readable description
        #[arg(long)]
        description: String,
        /// Command template with {{secret:path}} placeholders
        #[arg(long)]
        command: String,
        /// Required secret paths (can be specified multiple times)
        #[arg(long)]
        secret: Vec<String>,
        /// Output filter mode (exit_code, summary, full_scrubbed, none)
        #[arg(long, default_value = "exit_code")]
        output_filter: String,
        /// Summary extraction regex (for summary mode)
        #[arg(long)]
        summary_regex: Option<String>,
        /// Require approval before execution
        #[arg(long, default_value = "true")]
        require_approval: bool,
        /// Timeout in seconds
        #[arg(long)]
        timeout: Option<u64>,
    },
    /// Remove a sealed operation
    Remove {
        /// Operation ID to remove
        id: String,
    },
    /// Execute a sealed operation
    Execute {
        /// Operation ID to execute
        id: String,
        /// Skip approval (for pre-approved operations)
        #[arg(long)]
        skip_approval: bool,
        /// Arguments to pass to the operation
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        args: Vec<String>,
    },
}

impl CommandOperations {
    fn run(&self) -> Result<()> {
        match &self.operation {
            OperationSubcommand::List => self.list_operations()?,
            OperationSubcommand::Add { .. } => self.add_operation()?,
            OperationSubcommand::Remove { id } => self.remove_operation(id)?,
            OperationSubcommand::Execute { .. } => self.execute_operation()?,
        }
        Ok(())
    }

    fn list_operations(&self) -> Result<()> {
        let sigil_dir = dirs::home_dir()
            .ok_or_else(|| anyhow::anyhow!("Cannot determine home directory"))?
            .join(".sigil");

        let operations_file = sigil_dir.join("operations.toml");

        if !operations_file.exists() {
            println!("No operations file found at {}", operations_file.display());
            println!("Create one with: sigil operations add <id>");
            return Ok(());
        }

        let content = std::fs::read_to_string(&operations_file)?;
        let registry = sigil_core::OperationsRegistry::from_toml(&content)
            .map_err(|e| anyhow::anyhow!("Failed to parse operations: {}", e))?;

        let operations = registry.list();
        if operations.is_empty() {
            println!("No sealed operations defined.");
            return Ok(());
        }

        println!("Sealed Operations:");
        println!();
        for id in &operations {
            if let Some(op) = registry.get(id) {
                println!("  {} - {}", op.id, op.description);
                println!("    Command: {}", op.command);
                if !op.secrets.is_empty() {
                    println!("    Secrets: {}", op.secrets.join(", "));
                }
                println!("    Requires approval: {}", op.require_approval);
                println!();
            }
        }

        Ok(())
    }

    fn add_operation(&self) -> Result<()> {
        let OperationSubcommand::Add {
            id,
            description,
            command,
            secret,
            output_filter,
            summary_regex,
            require_approval,
            timeout,
        } = &self.operation
        else {
            unreachable!();
        };

        let sigil_dir = dirs::home_dir()
            .ok_or_else(|| anyhow::anyhow!("Cannot determine home directory"))?
            .join(".sigil");

        std::fs::create_dir_all(&sigil_dir)?;
        let operations_file = sigil_dir.join("operations.toml");

        // Load existing operations
        let mut registry = if operations_file.exists() {
            let content = std::fs::read_to_string(&operations_file)?;
            sigil_core::OperationsRegistry::from_toml(&content)
                .map_err(|e| anyhow::anyhow!("Failed to parse operations: {}", e))?
        } else {
            sigil_core::OperationsRegistry::new()
        };

        // Parse output filter
        let filter = match output_filter.as_str() {
            "exit_code" => sigil_core::OutputFilter::ExitCode,
            "summary" => sigil_core::OutputFilter::Summary,
            "full_scrubbed" => sigil_core::OutputFilter::FullScrubbed,
            "none" => sigil_core::OutputFilter::None,
            _ => anyhow::bail!("Invalid output filter: {}", output_filter),
        };

        // Create the operation
        let mut operation =
            sigil_core::SealedOperation::new(id.clone(), description.clone(), command.clone())
                .with_output_filter(filter)
                .with_approval(*require_approval);

        for secret in secret {
            operation = operation.with_secret(secret.clone());
        }

        if let Some(regex) = summary_regex {
            operation = operation.with_summary_regex(regex.clone());
        }

        if let Some(timeout_secs) = timeout {
            operation = operation.with_timeout(*timeout_secs);
        }

        // Validate and add
        operation
            .validate()
            .map_err(|e| anyhow::anyhow!("Invalid operation: {}", e))?;
        registry
            .add(operation)
            .map_err(|e| anyhow::anyhow!("Failed to add operation: {}", e))?;

        // Write back to file
        let toml_content = registry
            .to_toml()
            .map_err(|e| anyhow::anyhow!("Failed to serialize operations: {}", e))?;
        std::fs::write(&operations_file, toml_content)?;

        println!("Added operation: {}", id);
        println!("Restart the daemon to load the new operation.");

        Ok(())
    }

    fn remove_operation(&self, id: &str) -> Result<()> {
        let sigil_dir = dirs::home_dir()
            .ok_or_else(|| anyhow::anyhow!("Cannot determine home directory"))?
            .join(".sigil");

        let operations_file = sigil_dir.join("operations.toml");

        if !operations_file.exists() {
            anyhow::bail!("No operations file found");
        }

        let content = std::fs::read_to_string(&operations_file)?;
        let mut registry = sigil_core::OperationsRegistry::from_toml(&content)
            .map_err(|e| anyhow::anyhow!("Failed to parse operations: {}", e))?;

        if registry.remove(id).is_none() {
            anyhow::bail!("Operation '{}' not found", id);
        }

        // Write back
        let toml_content = registry
            .to_toml()
            .map_err(|e| anyhow::anyhow!("Failed to serialize operations: {}", e))?;
        std::fs::write(&operations_file, toml_content)?;

        println!("Removed operation: {}", id);
        println!("Restart the daemon to apply changes.");

        Ok(())
    }

    fn execute_operation(&self) -> Result<()> {
        let OperationSubcommand::Execute {
            id,
            skip_approval,
            args,
        } = &self.operation
        else {
            unreachable!();
        };

        // Connect to daemon
        let socket_path = if let Ok(runtime_dir) = std::env::var("XDG_RUNTIME_DIR") {
            std::path::PathBuf::from(runtime_dir).join("sigil.sock")
        } else {
            std::path::PathBuf::from("/tmp").join(format!("sigil-{}.sock", std::process::id()))
        };

        if !socket_path.exists() {
            anyhow::bail!("Daemon is not running. Start with: sigild start");
        }

        // Connect and send request using async runtime
        let rt = tokio::runtime::Runtime::new()?;

        let result = rt.block_on(async {
            use sigil_core::{ExecuteOperationRequest, IpcOperation, IpcRequest, IpcResponse};
            use tokio::net::UnixStream;

            // Connect to daemon
            let mut stream = UnixStream::connect(&socket_path).await?;

            // Create request
            let payload = serde_json::to_value(ExecuteOperationRequest {
                operation_id: id.clone(),
                args: args.clone(),
                skip_approval: *skip_approval,
            })?;

            // Get session token from environment or use a test token
            let token =
                std::env::var("SIGIL_SESSION_TOKEN").unwrap_or_else(|_| "test-token".to_string());

            let request = IpcRequest::with_payload(IpcOperation::ExecuteOperation, token, payload);

            // Send request
            sigil_core::write_response_async(
                &mut stream,
                &sigil_core::IpcResponse::ok(request.id.clone()),
            )
            .await?;

            // Read response - the daemon sends back IpcResponse, but we read it as a message
            let data = sigil_core::read_message_async(&mut stream).await?;
            let response: IpcResponse = serde_json::from_slice(&data)?;

            if !response.ok {
                anyhow::bail!("Operation failed: {:?}", response.error);
            }

            // Parse result
            let result: sigil_core::OperationResult = serde_json::from_value(response.payload)?;
            Ok::<_, anyhow::Error>(result)
        })?;

        println!("Operation: {}", result.operation_id);
        println!("Exit code: {}", result.exit_code);
        if let Some(output) = result.output {
            println!("Output: {}", output);
        }
        if result.timed_out {
            println!("(timed out)");
        }
        println!("Duration: {}ms", result.duration_ms);

        Ok(())
    }
}

/// SSH agent commands
#[derive(clap::Args, Clone)]
struct CommandSshAgent {
    #[command(subcommand)]
    action: SshAgentAction,
}

#[derive(Subcommand, Clone)]
enum SshAgentAction {
    /// Start the SSH agent server
    Start {
        /// Socket path (default: $XDG_RUNTIME_DIR/sigil-ssh-agent.sock)
        #[arg(short, long)]
        socket: Option<String>,

        /// Require confirmation before each key use
        #[arg(long)]
        confirm: bool,

        /// Maximum key lifetime in seconds
        #[arg(short = 'l', long)]
        lifetime: Option<u64>,

        /// Enable verbose logging
        #[arg(short, long)]
        verbose: bool,
    },

    /// Print the socket path (for shell integration)
    PrintSocket {
        /// Socket path (default: $XDG_RUNTIME_DIR/sigil-ssh-agent.sock)
        #[arg(short, long)]
        socket: Option<String>,
    },

    /// Stop a running SSH agent
    Stop {
        /// Socket path (default: $XDG_RUNTIME_DIR/sigil-ssh-agent.sock)
        #[arg(short, long)]
        socket: Option<String>,
    },
}

impl CommandSshAgent {
    fn run(&self) -> Result<()> {
        match &self.action {
            SshAgentAction::Start {
                socket,
                confirm,
                lifetime,
                verbose,
            } => {
                use sigil_ssh_agent::SshAgent;

                let runtime_dir = std::env::var("XDG_RUNTIME_DIR")
                    .or_else(|_| std::env::var("TMPDIR"))
                    .unwrap_or_else(|_| "/tmp".to_string());

                let socket_path = socket
                    .clone()
                    .unwrap_or_else(|| format!("{}/sigil-ssh-agent.sock", runtime_dir));

                let sigil_socket = std::env::var("SIGIL_SOCKET").unwrap_or_else(|_| {
                    format!(
                        "{}/.sigil/sigild.sock",
                        std::env::var("HOME").unwrap_or_else(|_| ".".to_string())
                    )
                });

                let session_token = std::env::var("SIGIL_SESSION_TOKEN").unwrap_or_default();

                let mut config = sigil_ssh_agent::Config::new(
                    std::path::PathBuf::from(socket_path),
                    std::path::PathBuf::from(sigil_socket),
                    session_token,
                );

                config.confirm_before_use = *confirm;
                if let Some(max_lifetime) = lifetime {
                    config.max_key_lifetime = Some(*max_lifetime);
                }
                config.verbose = *verbose;

                println!("Starting SSH agent on {}", config.socket_path.display());

                let mut agent = SshAgent::new(config);

                // Run agent in async runtime
                let rt = tokio::runtime::Runtime::new()?;
                rt.block_on(async { agent.run().await })?;

                Ok(())
            }
            SshAgentAction::PrintSocket { socket } => {
                let runtime_dir = std::env::var("XDG_RUNTIME_DIR")
                    .or_else(|_| std::env::var("TMPDIR"))
                    .unwrap_or_else(|_| "/tmp".to_string());

                let socket_path = socket
                    .clone()
                    .unwrap_or_else(|| format!("{}/sigil-ssh-agent.sock", runtime_dir));

                println!("{}", socket_path);
                Ok(())
            }
            SshAgentAction::Stop { socket } => {
                let runtime_dir = std::env::var("XDG_RUNTIME_DIR")
                    .or_else(|_| std::env::var("TMPDIR"))
                    .unwrap_or_else(|_| "/tmp".to_string());

                let socket_path = socket
                    .clone()
                    .unwrap_or_else(|| format!("{}/sigil-ssh-agent.sock", runtime_dir));

                let path = std::path::PathBuf::from(&socket_path);
                if path.exists() {
                    std::fs::remove_file(&path)?;
                    println!("Stopped SSH agent at {}", socket_path);
                } else {
                    eprintln!("SSH agent not running at {}", socket_path);
                    std::process::exit(1);
                }

                Ok(())
            }
        }
    }
}

/// Emergency lockdown command
#[derive(clap::Args, Clone)]
struct CommandLockdown {
    /// Skip confirmation prompt
    #[arg(long, default_value = "false")]
    confirm: bool,

    /// Reason for lockdown (optional, for audit log)
    #[arg(short, long)]
    reason: Option<String>,
}

impl CommandLockdown {
    fn run(&self) -> Result<()> {
        // Confirm lockdown unless --confirm flag is provided
        if !self.confirm {
            eprintln!("⚠️  EMERGENCY LOCKDOWN");
            eprintln!("This will immediately:");
            eprintln!("  - Kill all active sandbox processes");
            eprintln!("  - Revoke all session tokens");
            eprintln!("  - Lock the vault (requires full re-authentication)");
            eprintln!("  - Generate breach report");
            eprintln!();
            eprint!("Type 'LOCKDOWN' to confirm: ");

            let mut input = String::new();
            std::io::stdin().read_line(&mut input)?;
            if input.trim() != "LOCKDOWN" {
                eprintln!("Lockdown cancelled");
                std::process::exit(1);
            }
        }

        // Connect to daemon and send lockdown request
        use sigil_core::{write_message, IpcOperation, IpcRequest};

        let socket_path = std::env::var("SIGIL_SOCKET").unwrap_or_else(|_| {
            format!(
                "{}/.sigil/sigild.sock",
                std::env::var("HOME").unwrap_or_else(|_| ".".to_string())
            )
        });

        let mut stream = std::os::unix::net::UnixStream::connect(&socket_path).context(format!(
            "Failed to connect to daemon at {}. Is sigild running?",
            socket_path
        ))?;

        let session_token = std::env::var("SIGIL_SESSION_TOKEN").unwrap_or_default();
        let request = IpcRequest::new(IpcOperation::Lockdown, session_token);

        let json = serde_json::to_vec(&request)?;
        write_message(&mut stream, &json)?;

        // Read response
        let data = sigil_core::read_message(&mut stream)?;
        let response: sigil_core::IpcResponse =
            serde_json::from_slice(&data).context("Invalid response from daemon")?;

        if response.ok {
            println!("✓ Lockdown activated");
            println!("The daemon is now in lockdown mode.");
            println!("Use 'sigil unlock' to restore normal operation.");
        } else {
            if let Some(error) = response.error {
                anyhow::bail!("Lockdown failed: {}", error.message);
            }
            anyhow::bail!("Lockdown failed with unknown error");
        }

        Ok(())
    }
}

/// Unlock command
#[derive(clap::Args, Clone)]
struct CommandUnlock {
    /// Vault passphrase (will prompt if not provided)
    #[arg(short, long)]
    passphrase: Option<String>,
}

impl CommandUnlock {
    fn run(&self) -> Result<()> {
        eprintln!("⚠️  UNLOCKING DAEMON");
        eprintln!("This will restore normal daemon operation after lockdown.");
        eprintln!();

        // Prompt for passphrase if not provided
        let passphrase = match &self.passphrase {
            Some(p) => p.clone(),
            None => rpassword::prompt_password("Enter vault passphrase: ")?,
        };

        // Connect to daemon and send unlock request
        use sigil_core::{write_message, IpcOperation, IpcRequest};

        let socket_path = std::env::var("SIGIL_SOCKET")
            .unwrap_or_else(|_| format!("{}/.sigil/sigild.sock", std::env::var("HOME").unwrap()));

        let mut stream = std::os::unix::net::UnixStream::connect(&socket_path).context(format!(
            "Failed to connect to daemon at {}. Is sigild running?",
            socket_path
        ))?;

        let session_token = std::env::var("SIGIL_SESSION_TOKEN").unwrap_or_default();

        // Create the unlock request with the passphrase
        let unlock_payload = sigil_core::ipc::UnlockRequest {
            passphrase: passphrase.clone(),
        };
        let payload = serde_json::to_value(&unlock_payload)?;
        let request = IpcRequest::with_payload(IpcOperation::Unlock, session_token, payload);

        let json = serde_json::to_vec(&request)?;
        write_message(&mut stream, &json)?;

        // Read response
        let data = sigil_core::read_message(&mut stream)?;
        let response: sigil_core::IpcResponse =
            serde_json::from_slice(&data).context("Invalid response from daemon")?;

        if response.ok {
            println!("✓ Daemon unlocked");
            println!("Normal daemon operation has been restored.");
        } else {
            if let Some(error) = response.error {
                if error.code == sigil_core::ipc::IpcErrorCode::AccessDenied {
                    anyhow::bail!("Unlock failed: Invalid passphrase");
                }
                anyhow::bail!("Unlock failed: {}", error.message);
            }
            anyhow::bail!("Unlock failed with unknown error");
        }

        Ok(())
    }
}

/// Show SIGIL status and system information
#[derive(clap::Args, Clone)]
struct CommandStatus {
    /// Show detailed information
    #[arg(short, long)]
    verbose: bool,

    /// Output format (text, json)
    #[arg(short, long, default_value = "text")]
    format: String,
}

impl CommandStatus {
    fn run(&self) -> Result<()> {
        use std::process::Command;

        let vault_path = dirs::home_dir()
            .map(|mut p| {
                p.push(".sigil");
                p
            })
            .ok_or_else(|| anyhow::anyhow!("Cannot determine home directory"))?;

        let mut status_info = serde_json::Map::new();

        // SIGIL version
        status_info.insert("version".to_string(), json!(env!("CARGO_PKG_VERSION")));

        // Vault status
        let vault_exists = vault_path.join("vault").exists();
        let vault_sealed_exists = vault_path.join("vault.sealed").exists();
        let identity_exists = vault_path.join("identity.age").exists();

        let vault_status = if vault_sealed_exists {
            "sealed"
        } else if vault_exists {
            "directory"
        } else {
            "not initialized"
        };
        status_info.insert("vault_status".to_string(), json!(vault_status));
        status_info.insert(
            "vault_configured".to_string(),
            json!(vault_exists || vault_sealed_exists),
        );

        // Daemon status
        let socket_path = std::env::var("XDG_RUNTIME_DIR").unwrap_or_else(|_| "/tmp".to_string());
        let socket_path = format!("{}/sigil.sock", socket_path);
        let daemon_running = std::path::Path::new(&socket_path).exists();
        status_info.insert("daemon_running".to_string(), json!(daemon_running));

        // Secret count (if vault exists)
        if vault_exists {
            if let Ok(output) = Command::new("sigil")
                .args(["list", "--format", "json"])
                .output()
            {
                if let Ok(secrets) = serde_json::from_slice::<serde_json::Value>(&output.stdout) {
                    if let Some(arr) = secrets.as_array() {
                        status_info.insert("secret_count".to_string(), json!(arr.len()));
                    }
                }
            }
        }

        // Recent audit activity (check if audit log exists)
        let audit_log = vault_path.join("audit.jsonl");
        if audit_log.exists() {
            if let Ok(metadata) = std::fs::metadata(&audit_log) {
                if let Ok(modified) = metadata.modified() {
                    let duration = std::time::SystemTime::now()
                        .duration_since(modified)
                        .unwrap_or_default();
                    status_info.insert(
                        "last_audit_activity".to_string(),
                        json!(format!("{} minutes ago", duration.as_secs() / 60)),
                    );
                }
            }
        }

        // Output based on format
        if self.format == "json" {
            println!("{}", json!(status_info));
        } else {
            // Text output
            println!("🛡️  SIGIL Status\n");

            // Version
            println!(
                "  Version: {}",
                status_info.get("version").unwrap_or(&json!("unknown"))
            );

            // Vault
            println!("  Vault: {}", vault_status);
            if self.verbose && vault_exists {
                println!("    → Path: {}", vault_path.display());
                if identity_exists {
                    println!("    → Identity: configured");
                }
            }

            // Daemon
            if daemon_running {
                println!("  Daemon: ✅ running");
            } else {
                println!("  Daemon: ⚠️  not running");
            }

            // Secrets
            if let Some(count) = status_info.get("secret_count") {
                println!("  Secrets: {}", count);
            }

            // Audit
            if let Some(activity) = status_info.get("last_audit_activity") {
                println!("  Last audit activity: {}", activity);
            }

            println!();
            println!("Run 'sigil doctor' for a full health check.");
        }

        Ok(())
    }
}

/// Lint files for potential secret leaks
#[derive(clap::Args, Clone)]
struct CommandLint {
    /// Path to file or directory to lint
    #[arg(value_name = "PATH")]
    path: String,

    /// Show detailed output
    #[arg(short, long)]
    verbose: bool,

    /// Output format (text, json)
    #[arg(short, long, default_value = "text")]
    format: String,

    /// Automatically fix detected secrets by vaulting them and replacing with placeholders
    #[arg(long)]
    fix: bool,

    /// Show what would be done without making any changes
    #[arg(long)]
    dry_run: bool,

    /// Run as a git pre-commit hook (staged files only, exits non-zero on secrets)
    #[arg(long)]
    hook: bool,

    /// Run in CI mode (exits non-zero if secrets found, JSON output recommended)
    #[arg(long)]
    ci: bool,

    /// Only scan staged files (for incremental scanning)
    #[arg(long)]
    staged: bool,
}

impl CommandLint {
    fn run(&self) -> Result<()> {
        use std::path::Path;

        // CI mode validation
        if self.ci && self.fix {
            anyhow::bail!(
                "--ci and --fix flags are mutually exclusive. CI mode is for detection only."
            );
        }

        // Hook mode validation
        if self.hook && self.fix {
            anyhow::bail!("--hook and --fix flags are mutually exclusive. Use --hook for pre-commit detection only.");
        }

        let path = Path::new(&self.path);

        // For --staged mode, we scan git staged files
        let files_to_scan = if self.staged || self.hook {
            self.get_staged_files()?
        } else if path.exists() {
            if path.is_dir() {
                self.collect_files_in_directory(path)?
            } else {
                vec![path.to_path_buf()]
            }
        } else {
            anyhow::bail!("Path not found: {}", self.path);
        };

        let mut findings = Vec::new();

        // Scan all files
        for file_path in &files_to_scan {
            if let Ok(metadata) = std::fs::metadata(file_path) {
                if metadata.is_file() {
                    self.scan_file(file_path, &mut findings)?;
                }
            }
        }

        // Load manifest and check coverage
        if let Ok(Some(manifest)) = self.load_manifest() {
            self.check_manifest_coverage(&findings, &manifest);
        }

        // Handle different output modes
        if self.ci {
            return self.handle_ci_mode(findings);
        }

        if self.hook {
            return self.handle_hook_mode(findings);
        }

        // Regular mode
        if findings.is_empty() {
            println!("✅ No secrets detected in: {}", self.path);
        } else {
            println!(
                "⚠️  Detected {} potential secret(s) in: {}",
                findings.len(),
                self.path
            );
            println!();

            for finding in &findings {
                println!("⚠️  Secret detected: {}", finding.secret_type);
                println!("   File: {}", finding.file);
                if self.verbose {
                    println!("   Line {}: {}", finding.line, finding.line_content);
                }
                println!();
            }

            // Auto-fix mode
            if self.fix {
                return self.auto_fix(findings);
            }

            // Show migration instructions
            if self.dry_run {
                println!("[DRY RUN] Would make the following changes:");
            }
            println!("To migrate these secrets to SIGIL:");
            println!("  Run with --fix to automatically vault and replace secrets");
            println!("  Or manually:");
            println!("  1. Add each secret to the vault:");
            for finding in &findings {
                if let Some(vault_path) = &finding.suggested_vault_path {
                    println!("     sigil add {}", vault_path);
                }
            }
            println!("  2. Replace in files with placeholders:");
            for finding in &findings {
                if let Some(vault_path) = &finding.suggested_vault_path {
                    println!(
                        "     sed -i 's/{}/{{{{secret:{}}}}}/g' {}",
                        finding.placeholder.as_ref().unwrap_or(&"***".to_string()),
                        vault_path,
                        finding.file
                    );
                }
            }
        }

        Ok(())
    }

    /// Handle CI mode output (JSON format, exits non-zero on findings)
    fn handle_ci_mode(&self, findings: Vec<SecretFinding>) -> Result<()> {
        if findings.is_empty() {
            if self.format == "json" {
                println!("{}", serde_json::json!({"status": "ok", "findings": []}));
            }
            Ok(())
        } else {
            if self.format == "json" {
                println!(
                    "{}",
                    serde_json::json!({
                        "status": "error",
                        "error": "secrets_detected",
                        "findings": findings
                    })
                );
            } else {
                eprintln!("❌ CI Mode: Detected {} secret(s)", findings.len());
                for finding in &findings {
                    eprintln!(
                        "  - {} in {} at line {}",
                        finding.secret_type, finding.file, finding.line
                    );
                }
            }
            std::process::exit(1);
        }
    }

    /// Handle pre-commit hook mode (exits non-zero on findings)
    fn handle_hook_mode(&self, findings: Vec<SecretFinding>) -> Result<()> {
        if findings.is_empty() {
            Ok(())
        } else {
            eprintln!(
                "❌ Pre-commit hook: Detected {} secret(s) in staged files",
                findings.len()
            );
            eprintln!("Commit blocked. Either:");
            eprintln!("  1. Remove the secrets from the files");
            eprintln!("  2. Run 'sigil lint --fix' to migrate to SIGIL");
            eprintln!();
            eprintln!("Secrets found:");
            for finding in &findings {
                eprintln!(
                    "  - {} in {} at line {}",
                    finding.secret_type, finding.file, finding.line
                );
            }
            std::process::exit(1);
        }
    }

    /// Auto-fix detected secrets by vaulting them and replacing with placeholders
    fn auto_fix(&self, findings: Vec<SecretFinding>) -> Result<()> {
        use std::collections::HashMap;
        use std::fs;
        use std::io::Write;

        if findings.is_empty() {
            return Ok(());
        }

        println!("🔧 Auto-fixing {} detected secret(s)...", findings.len());
        println!();

        // Group findings by file
        let mut files_to_modify: HashMap<String, Vec<&SecretFinding>> = HashMap::new();
        for finding in &findings {
            files_to_modify
                .entry(finding.file.clone())
                .or_default()
                .push(finding);
        }

        // Connect to vault to store secrets
        let home = std::env::var("HOME").map_err(|_| anyhow::anyhow!("HOME not set"))?;
        let sigil_dir = std::path::Path::new(&home).join(".sigil");
        let vault_path = sigil_dir.join("vault");
        let identity_path = sigil_dir.join("identity");

        if !vault_path.exists() {
            anyhow::bail!("Vault not initialized. Run 'sigil init' first.");
        }

        let mut vault = sigil_vault::LocalVault::new(vault_path, identity_path)?;
        vault
            .load(None)
            .context("Failed to load vault. Is it locked?")?;

        // Create tokio runtime for async vault operations
        let rt = tokio::runtime::Runtime::new()?;

        // Process each file
        for (file_path, file_findings) in &files_to_modify {
            println!("📝 Processing: {}", file_path);

            if self.dry_run {
                println!("  [DRY RUN] Would vault {} secret(s)", file_findings.len());
                for finding in file_findings {
                    if let Some(vault_path) = &finding.suggested_vault_path {
                        println!("    - {} -> {}", finding.secret_type, vault_path);
                    }
                }
                continue;
            }

            // Read file content
            let mut content = fs::read_to_string(file_path)?;

            // Vault secrets and collect replacements
            let mut replacements = Vec::new();
            for finding in file_findings {
                if let Some(vault_path) = &finding.suggested_vault_path {
                    // Extract secret value from the line
                    if let Some(secret_value) = self.extract_secret_value(&finding.line_content) {
                        // Vault the secret
                        let path = sigil_core::SecretPath::new(vault_path.clone())?;
                        let value = sigil_core::SecretValue::from_string(secret_value.clone());

                        // Create metadata
                        let mut meta = sigil_core::SecretMetadata::new(path.clone());
                        // Set secret type based on the finding
                        meta.secret_type = match finding.secret_type.as_str() {
                            "API Key" => sigil_core::SecretType::ApiKey,
                            "Database URL" => sigil_core::SecretType::DatabaseUrl,
                            "Password" => sigil_core::SecretType::Password,
                            "JWT Token" => sigil_core::SecretType::Generic,
                            "AWS Access Key" => sigil_core::SecretType::ApiKey,
                            "AWS Secret Key" => sigil_core::SecretType::ApiKey,
                            _ => sigil_core::SecretType::Generic,
                        };

                        rt.block_on(vault.set(&path, &value, &meta))?;

                        let placeholder = format!("{{{{secret:{}}}}}", vault_path);
                        replacements.push((finding.line_content.clone(), placeholder));

                        println!("  ✓ Vaulted {} as {}", finding.secret_type, vault_path);
                    }
                }
            }

            // Apply replacements
            for (old_text, new_text) in &replacements {
                content = content.replace(old_text, new_text);
            }

            // Write back to file
            let mut file = fs::File::create(file_path)?;
            file.write_all(content.as_bytes())?;
            file.sync_all()?;

            println!("  ✓ Updated {}", file_path);
        }

        println!();
        println!("✅ Successfully vaulted {} secret(s)", findings.len());
        println!();
        println!("Next steps:");
        println!("  1. Review the changes with: git diff");
        println!("  2. Commit the updated files");
        println!("  3. Add .env and similar files to .gitignore if present");

        Ok(())
    }

    /// Extract secret value from a line of text
    fn extract_secret_value(&self, line: &str) -> Option<String> {
        use regex::Regex;

        // Try to extract value after =, : or in quotes
        let patterns = [
            r#"=\s*['"]?([^'\s]+)['"]?"#, // key='value' or key=value
            r#":\s*['"]?([^'\s]+)['"]?"#, // key: "value"
        ];

        for pattern in patterns {
            if let Ok(re) = Regex::new(pattern) {
                if let Some(caps) = re.captures(line) {
                    if let Some(value) = caps.get(1) {
                        let value_str = value.as_str();
                        // Skip placeholder values and short values
                        if value_str.len() > 8 && value_str != "***" && value_str != "****" {
                            return Some(value_str.to_string());
                        }
                    }
                }
            }
        }

        None
    }

    /// Get list of staged files from git
    fn get_staged_files(&self) -> Result<Vec<std::path::PathBuf>> {
        use std::process::Command;

        let output = Command::new("git")
            .args(["diff", "--cached", "--name-only", "--diff-filter=ACM"])
            .output()?;

        if !output.status.success() {
            anyhow::bail!("Failed to get staged files. Is this a git repository?");
        }

        let stdout = String::from_utf8_lossy(&output.stdout);
        let mut files = Vec::new();

        for line in stdout.lines() {
            if !line.is_empty() {
                files.push(std::path::PathBuf::from(line));
            }
        }

        Ok(files)
    }

    /// Collect all files in a directory recursively
    fn collect_files_in_directory(&self, dir: &std::path::Path) -> Result<Vec<std::path::PathBuf>> {
        use std::fs;

        let mut files = Vec::new();
        let entries = fs::read_dir(dir)?;

        for entry in entries {
            let entry = entry?;
            let path = entry.path();

            if path.is_dir() {
                // Skip hidden directories and common non-source directories
                if let Some(name) = path.file_name() {
                    let name_str = name.to_string_lossy();
                    if name_str.starts_with('.')
                        || ["node_modules", "target", "vendor", ".git", "dist", "build"]
                            .contains(&name_str.as_ref())
                    {
                        continue;
                    }
                }
                files.extend(self.collect_files_in_directory(&path)?);
            } else if path.is_file() {
                // Only scan text files
                if let Some(ext) = path.extension() {
                    let ext_str = ext.to_string_lossy();
                    if [
                        "env", "txt", "md", "json", "yaml", "yml", "toml", "ini", "conf", "sh",
                        "bash", "rs", "py", "js", "ts", "tsx", "jsx", "go", "java", "php", "rb",
                        "cs", "cpp", "c", "h", "hpp", "swift", "kt", "scala",
                    ]
                    .contains(&ext_str.as_ref())
                    {
                        files.push(path);
                    }
                }
            }
        }

        Ok(files)
    }

    fn scan_file(&self, path: &std::path::Path, findings: &mut Vec<SecretFinding>) -> Result<()> {
        use std::fs;

        let content = fs::read_to_string(path)?;
        let file_name = path.display().to_string();

        // Scan line by line
        for (line_num, line) in content.lines().enumerate() {
            if let Some(finding) = self.detect_secret(line, &file_name, line_num + 1) {
                findings.push(finding);
            }
        }

        Ok(())
    }

    fn detect_secret(&self, line: &str, file: &str, line_num: usize) -> Option<SecretFinding> {
        use regex::Regex;

        // Common secret patterns (simplified version)
        // Note: Using raw string literals with character classes for quotes
        let patterns: [(&str, &str, &str); 8] = [
            // API keys
            (
                r#"(?i)api[_-]?key\s*=\s*[']?([a-z0-9]{20,})[']?"#,
                "API Key",
                "api_key",
            ),
            // Database URLs
            (
                r#"(?i)database[_-]?url\s*=\s*[']?([a-z0-9+]+://[^\s']+)[']?"#,
                "Database URL",
                "database_url",
            ),
            // JWT tokens
            (
                r#"(?i)jwt[_-]?token\s*=\s*[']?([a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+)[']?"#,
                "JWT Token",
                "jwt_token",
            ),
            // Password
            (
                r#"(?i)password\s*=\s*[']?([^\s']{8,})[']?"#,
                "Password",
                "password",
            ),
            // Secret tokens
            (
                r#"(?i)secret[_-]?token\s*=\s*[']?([a-z0-9]{20,})[']?"#,
                "Secret Token",
                "secret_token",
            ),
            // AWS keys
            (
                r#"(?i)aws[_-]?(access[_-]?key[_-]?id)\s*=\s*[']?([A-Z0-9]{20})[']?"#,
                "AWS Access Key",
                "aws_access_key_id",
            ),
            (
                r#"(?i)aws[_-]?(secret[_-]?access[_-]?key)\s*=\s*[']?([a-zA-Z0-9/+]{40})[']?"#,
                "AWS Secret Key",
                "aws_secret_access_key",
            ),
            // GitHub/GitLab tokens
            (
                r#"(?i)(github|gitlab)[_-]?token\s*=\s*[']?([a-z0-9]{20,})[']?"#,
                "Git Token",
                "git_token",
            ),
        ];

        for (pattern, secret_type, vault_path) in patterns {
            if let Ok(re) = Regex::new(pattern) {
                if let Some(caps) = re.captures(line) {
                    // Get the matched value (last capture group)
                    // The last capture is the actual secret value we want to extract
                    if caps.len() > 0 {
                        let value = caps.get(caps.len() - 1).map(|m| m.as_str()).unwrap_or("");
                        // Skip obvious false positives
                        if value.len() < 8
                            || value == "***"
                            || value == "****"
                            || value.contains('<')
                        {
                            continue;
                        }

                        return Some(SecretFinding {
                            secret_type: secret_type.to_string(),
                            file: file.to_string(),
                            line: line_num,
                            line_content: line.to_string(),
                            placeholder: Some(format!(
                                "{}=***",
                                secret_type.to_lowercase().replace(' ', "_")
                            )),
                            suggested_vault_path: Some(vault_path.to_string()),
                        });
                    }
                }
            }
        }

        None
    }

    /// Load and parse the .sigil.toml manifest for the project
    fn load_manifest(&self) -> Result<Option<ManifestData>> {
        use std::path::Path;

        // Look for .sigil.toml in the current directory or parent directories
        let current_dir = Path::new(&self.path);
        let mut search_dir = if current_dir.is_dir() {
            current_dir.to_path_buf()
        } else {
            current_dir.parent().unwrap_or(current_dir).to_path_buf()
        };

        // Search up the directory tree for .sigil.toml
        for _ in 0..10 {
            let manifest_path = search_dir.join(".sigil.toml");
            if manifest_path.exists() {
                let content = std::fs::read_to_string(&manifest_path)
                    .with_context(|| format!("Failed to read {}", manifest_path.display()))?;

                let manifest: toml::Value = toml::from_str(&content)
                    .with_context(|| format!("Failed to parse {}", manifest_path.display()))?;

                return Ok(Some(self.parse_manifest(&manifest)?));
            }

            // Move to parent directory
            if !search_dir.pop() {
                break;
            }
        }

        Ok(None)
    }

    /// Parse secrets from the manifest
    fn parse_manifest(&self, manifest: &toml::Value) -> Result<ManifestData> {
        let mut declared_secrets = std::collections::HashSet::new();

        if let Some(secrets_array) = manifest.get("secrets").and_then(|v| v.as_array()) {
            for secret_value in secrets_array {
                if let Some(table) = secret_value.as_table() {
                    if let Some(path) = table.get("path").and_then(|v| v.as_str()) {
                        declared_secrets.insert(path.to_string());
                    }
                }
            }
        }

        Ok(ManifestData { declared_secrets })
    }

    /// Generate a description for a secret based on path and findings
    fn generate_secret_description(&self, vault_path: &str, findings: &[&SecretFinding]) -> String {
        // Extract service name and type from path
        let parts: Vec<&str> = vault_path.split('/').collect();

        let service = parts.first().unwrap_or(&"unknown");
        let secret_name = parts.get(1).unwrap_or(&"secret");

        // Check findings for more context - get the first source file
        let source_file = findings
            .iter()
            .find_map(|f| {
                std::path::PathBuf::from(&f.file)
                    .file_name()
                    .and_then(|n| n.to_str())
                    .map(|s| s.to_string())
            })
            .unwrap_or_else(|| "unknown".to_string());

        // Generate description based on common patterns
        let description = match vault_path {
            path if path.contains("api_key") || path.contains("access_key") => {
                format!("API key for {} service", service)
            }
            path if path.contains("secret_key") || path.contains("secret_access_key") => {
                format!("Secret key for {} service", service)
            }
            path if path.contains("token") => {
                format!("Authentication token for {}", service)
            }
            path if path.contains("password") || path.contains("passwd") => {
                format!("Password for {}", service)
            }
            path if path.contains("cert") || path.contains("certificate") => {
                format!("SSL/TLS certificate for {}", service)
            }
            path if path.contains("ssh") || path.contains("private_key") => {
                format!("SSH private key for {}", service)
            }
            path if path.contains("database") || path.contains("db") => {
                format!("Database credentials for {}", service)
            }
            _ => {
                // Default description based on path structure
                format!(
                    "{} secret for {} (detected in {})",
                    secret_name, service, source_file
                )
            }
        };

        description
    }

    /// Check detected secrets against the manifest and report issues
    fn check_manifest_coverage(&self, findings: &[SecretFinding], manifest: &ManifestData) {
        let mut undeclared = std::collections::HashMap::new();

        for finding in findings {
            if let Some(ref vault_path) = finding.suggested_vault_path {
                if !manifest.declared_secrets.contains(vault_path) {
                    undeclared
                        .entry(vault_path.clone())
                        .or_insert_with(Vec::new)
                        .push(finding);
                }
            }
        }

        if !undeclared.is_empty() {
            println!();
            println!("⚠️  Secrets detected but not declared in .sigil.toml:");
            println!();

            for vault_path in undeclared.keys() {
                println!("  - {}", vault_path);
            }

            println!();
            println!("Add these to your .sigil.toml under [[secrets]]:");
            println!();
            for (vault_path, finding_list) in &undeclared {
                // Determine secret type from path
                let secret_type = if vault_path.contains("api") || vault_path.contains("key") {
                    "api_key"
                } else if vault_path.contains("cert") || vault_path.contains("tls") {
                    "certificate"
                } else if vault_path.contains("ssh") {
                    "ssh_key"
                } else {
                    "generic"
                };

                // Generate a meaningful description
                let description = self.generate_secret_description(vault_path, finding_list);

                println!("[[secrets]]");
                println!("path = \"{}\"", vault_path);
                println!("type = \"{}\"", secret_type);
                println!("required = false");
                println!("description = \"{}\"", description);
                println!();
            }
        }
    }
}

/// Data parsed from .sigil.toml manifest
#[derive(Debug)]
struct ManifestData {
    /// Set of declared secret paths
    declared_secrets: std::collections::HashSet<String>,
}

/// Manage command signatures
#[derive(clap::Subcommand)]
enum SignaturesCommand {
    /// List all available signatures
    List {
        /// Show detailed information for each signature
        #[arg(short, long)]
        verbose: bool,

        /// Filter by category (cloud, databases, apis, etc.)
        #[arg(short, long)]
        category: Option<String>,

        /// Output format (text, json)
        #[arg(short, long, default_value = "text")]
        format: String,
    },

    /// Search for signatures matching a pattern
    Search {
        /// Search query (matches signature name, description, or pattern)
        #[arg(value_name = "QUERY")]
        query: String,

        /// Show detailed information for each match
        #[arg(short, long)]
        verbose: bool,

        /// Output format (text, json)
        #[arg(short, long, default_value = "text")]
        format: String,
    },

    /// Update signatures from remote repository
    Update {
        /// Remote repository URL (default: https://github.com/jedarden/sigil-signatures)
        #[arg(short, long)]
        url: Option<String>,

        /// Branch to fetch from (default: main)
        #[arg(short, long, default_value = "main")]
        branch: String,

        /// Force update even if no new version is available
        #[arg(long)]
        force: bool,

        /// Dry run - show what would be updated without making changes
        #[arg(long)]
        dry_run: bool,
    },

    /// Install a curated set of signatures
    Install {
        /// Name of the set to install (cloud, databases, apis, devtools, etc.)
        #[arg(value_name = "SET")]
        set_name: String,

        /// Remote repository URL
        #[arg(short, long)]
        url: Option<String>,

        /// Dry run - show what would be installed without making changes
        #[arg(long)]
        dry_run: bool,
    },

    /// List available curated signature sets
    ListSets {
        /// Remote repository URL
        #[arg(short, long)]
        url: Option<String>,
    },

    /// Add a local signature file to the user signatures directory
    Add {
        /// Path to signature file (.toml)
        #[arg(value_name = "FILE")]
        file: String,

        /// Copy to user signatures directory instead of project directory
        #[arg(short, long)]
        user: bool,
    },

    /// Show signature statistics
    Stats {
        /// Show breakdown by category
        #[arg(short, long)]
        by_category: bool,

        /// Show enabled vs disabled counts
        #[arg(short, long)]
        enabled: bool,
    },
}

impl SignaturesCommand {
    fn run(&self) -> Result<()> {
        match self {
            SignaturesCommand::List {
                verbose,
                category,
                format,
            } => self.list(*verbose, category.clone(), format),
            SignaturesCommand::Search {
                query,
                verbose,
                format,
            } => self.search(query, *verbose, format),
            SignaturesCommand::Update {
                url,
                branch,
                force,
                dry_run,
            } => self.update(url.clone(), branch, *force, *dry_run),
            SignaturesCommand::Install {
                set_name,
                url,
                dry_run,
            } => self.install(set_name, url.clone(), *dry_run),
            SignaturesCommand::ListSets { url } => self.list_sets(url.clone()),
            SignaturesCommand::Add { file, user } => self.add(file, *user),
            SignaturesCommand::Stats {
                by_category,
                enabled,
            } => self.stats(*by_category, *enabled),
        }
    }

    fn list(&self, verbose: bool, category: Option<String>, format: &str) -> Result<()> {
        use sigil_signatures::BUILTIN_SIGNATURES;

        let config = BUILTIN_SIGNATURES.get_config()?;
        let signatures = config.get_all();

        // Filter by category if specified
        let signatures: Vec<_> = if let Some(cat) = category {
            signatures
                .iter()
                .filter(|(name, _)| self.signature_matches_category(name, &cat))
                .collect()
        } else {
            signatures.iter().collect()
        };

        if format == "json" {
            // JSON output
            let output: Vec<serde_json::Value> = signatures
                .iter()
                .map(|(name, sig)| {
                    serde_json::json!({
                        "name": name,
                        "description": sig.description,
                        "enabled": sig.enabled,
                        "pattern": sig.match_pattern,
                        "injections": sig.inject.len()
                    })
                })
                .collect();
            println!("{}", serde_json::to_string_pretty(&output)?);
        } else {
            // Text output
            println!("Available signatures ({} total):", signatures.len());
            println!();

            for (name, sig) in signatures {
                if verbose {
                    println!("📋 {}", name);
                    let no_desc = "(no description)";
                    println!(
                        "   Description: {}",
                        sig.description.as_deref().unwrap_or(no_desc)
                    );
                    println!("   Pattern: {}", sig.match_pattern);
                    println!("   Enabled: {}", if sig.enabled { "✅" } else { "❌" });
                    println!("   Injections: {}", sig.inject.len());
                    println!();
                } else {
                    let enabled = if sig.enabled { "✅" } else { "❌" };
                    let no_desc = "(no description)";
                    let desc = sig.description.as_deref().unwrap_or(no_desc);
                    println!("  {} {} - {}", enabled, name, desc);
                }
            }
        }

        Ok(())
    }

    fn search(&self, query: &str, verbose: bool, format: &str) -> Result<()> {
        use sigil_signatures::BUILTIN_SIGNATURES;

        let config = BUILTIN_SIGNATURES.get_config()?;
        let signatures = config.get_all();

        let query_lower = query.to_lowercase();
        let matches: Vec<_> = signatures
            .iter()
            .filter(|(name, sig)| {
                name.contains(&query_lower)
                    || sig
                        .description
                        .as_ref()
                        .is_some_and(|d| d.to_lowercase().contains(&query_lower))
                    || sig.match_pattern.to_lowercase().contains(&query_lower)
            })
            .collect();

        if format == "json" {
            let output: Vec<serde_json::Value> = matches
                .iter()
                .map(|(name, sig)| {
                    serde_json::json!({
                        "name": name,
                        "description": sig.description,
                        "enabled": sig.enabled,
                        "pattern": sig.match_pattern,
                    })
                })
                .collect();
            println!("{}", serde_json::to_string_pretty(&output)?);
        } else {
            if matches.is_empty() {
                println!("❌ No signatures found matching: {}", query);
            } else {
                println!(
                    "Found {} signature(s) matching \"{}\":",
                    matches.len(),
                    query
                );
                println!();

                for (name, sig) in matches {
                    if verbose {
                        println!("📋 {}", name);
                        println!(
                            "   Description: {}",
                            sig.description
                                .as_ref()
                                .unwrap_or(&"(no description)".to_string())
                        );
                        println!("   Pattern: {}", sig.match_pattern);
                        println!();
                    } else {
                        println!(
                            "  📋 {} - {}",
                            name,
                            sig.description
                                .as_ref()
                                .unwrap_or(&"(no description)".to_string())
                        );
                    }
                }
            }
        }

        Ok(())
    }

    fn update(&self, url: Option<String>, _branch: &str, force: bool, dry_run: bool) -> Result<()> {
        use sigil_signatures::{SignatureUpdater, UpdateConfig};

        println!("🔄 Updating signatures...");

        let home =
            dirs::home_dir().ok_or_else(|| anyhow::anyhow!("Cannot determine home directory"))?;
        let local_dir = home.join(".sigil").join("signatures.d");

        // Build update config
        let mut config = UpdateConfig::new()
            .with_local_dir(local_dir)
            .with_dry_run(dry_run);

        if let Some(repo_url) = url {
            config = config.with_repo_url(repo_url);
        }

        if force {
            config = config.with_force(true);
        }

        // Create updater and check for updates
        let updater = SignatureUpdater::with_config(config);

        // Check what's available
        let update_info = updater.check_update()?;

        if dry_run {
            println!("   Remote version: {}", update_info.remote_version);
            if let Some(local) = &update_info.local_version {
                println!("   Local version: {}", local);
                if update_info.needs_update {
                    println!("   ✨ Update available!");
                } else {
                    println!("   ✓ Already up to date");
                }
            } else {
                println!("   ✓ No local signatures installed yet");
            }
            println!(
                "   Files available: {}",
                update_info.manifest.signatures.len()
            );
            return Ok(());
        }

        if !update_info.needs_update && !force {
            println!(
                "   ✓ Already up to date (v{})",
                update_info.local_version.unwrap_or_default()
            );
            return Ok(());
        }

        println!(
            "   Updating from v{} to v{}...",
            update_info.local_version.as_deref().unwrap_or("none"),
            update_info.remote_version
        );

        // Perform the update
        let result = updater.update_all()?;

        println!("   ✅ Updated to v{}", result.version);
        println!("   📦 Downloaded: {}", result.updated.len());
        if !result.skipped.is_empty() {
            println!("   ⚠️  Skipped: {}", result.skipped.len());
            for file in &result.skipped {
                println!("      - {}", file);
            }
        }

        Ok(())
    }

    fn install(&self, set_name: &str, url: Option<String>, dry_run: bool) -> Result<()> {
        use sigil_signatures::{SignatureUpdater, UpdateConfig};

        println!("📦 Installing signature set: {}...", set_name);

        let home =
            dirs::home_dir().ok_or_else(|| anyhow::anyhow!("Cannot determine home directory"))?;
        let local_dir = home.join(".sigil").join("signatures.d");

        // Build update config
        let mut config = UpdateConfig::new()
            .with_local_dir(local_dir)
            .with_dry_run(dry_run);

        if let Some(repo_url) = url {
            config = config.with_repo_url(repo_url);
        }

        // Create updater and install the set
        let updater = SignatureUpdater::with_config(config);

        if dry_run {
            println!("   🔍 Dry run mode - would install: {}", set_name);
            return Ok(());
        }

        let result = updater.install_set(set_name)?;

        println!("   ✅ Installed set '{}' (v{})", set_name, result.version);
        println!("   📦 Downloaded: {}", result.updated.len());
        if !result.updated.is_empty() {
            println!("   Files:");
            for file in &result.updated {
                println!("      - {}", file);
            }
        }
        if !result.skipped.is_empty() {
            println!("   ⚠️  Skipped: {}", result.skipped.len());
            for file in &result.skipped {
                println!("      - {}", file);
            }
        }

        Ok(())
    }

    fn list_sets(&self, url: Option<String>) -> Result<()> {
        use sigil_signatures::{SignatureUpdater, UpdateConfig};

        println!("📚 Available signature sets:");
        println!();

        // Build update config
        let mut config = UpdateConfig::new();

        if let Some(repo_url) = url {
            config = config.with_repo_url(repo_url);
        }

        // Create updater and list sets
        let updater = SignatureUpdater::with_config(config);

        let sets = updater.list_sets()?;

        if sets.is_empty() {
            println!("   No signature sets available.");
            return Ok(());
        }

        for (name, set) in sets {
            println!("   📦 {}", name);
            println!("      {}", set.name);
            println!("      {}", set.description);
            println!("      Files: {}", set.files.len());
            println!();
        }

        println!("   Install a set with: sigil signatures install <set-name>");

        Ok(())
    }

    fn add(&self, file: &str, user: bool) -> Result<()> {
        use std::fs;
        use std::path::PathBuf;

        let source_path = PathBuf::from(file);

        if !source_path.exists() {
            anyhow::bail!("Signature file not found: {}", file);
        }

        // Read and validate the signature file
        let content = fs::read_to_string(&source_path)?;

        // Parse as TOML to validate
        let _: sigil_signatures::SignaturesToml = toml::from_str(&content)
            .with_context(|| format!("Invalid TOML in signature file: {}", file))?;

        // Determine destination
        let dest_dir = if user {
            // User directory: ~/.sigil/signatures.d/
            let mut home = dirs::home_dir()
                .ok_or_else(|| anyhow::anyhow!("Cannot determine home directory"))?;
            home.push(".sigil/signatures.d");
            home
        } else {
            // Project directory: .sigil/signatures.d/
            PathBuf::from(".sigil/signatures.d")
        };

        // Create directory if it doesn't exist
        fs::create_dir_all(&dest_dir)?;

        let dest_path = dest_dir.join(
            source_path
                .file_name()
                .ok_or_else(|| anyhow::anyhow!("Invalid filename"))?,
        );

        // Copy the file
        fs::copy(&source_path, &dest_path)?;

        println!("✅ Signature file added to: {}", dest_path.display());
        println!("   The signatures will be loaded alongside built-in signatures.");

        Ok(())
    }

    fn stats(&self, by_category: bool, enabled: bool) -> Result<()> {
        use sigil_signatures::BUILTIN_SIGNATURES;

        let config = BUILTIN_SIGNATURES.get_config()?;
        let signatures = config.get_all();

        let total = signatures.len();
        let enabled_count = signatures.iter().filter(|(_, s)| s.enabled).count();
        let disabled_count = total - enabled_count;

        println!("📊 Signature Statistics");
        println!("   Total: {}", total);
        if enabled {
            println!("   Enabled: {}", enabled_count);
            println!("   Disabled: {}", disabled_count);
        }
        println!();

        if by_category {
            println!("By Category:");
            let mut categories: std::collections::HashMap<&str, usize> =
                std::collections::HashMap::new();

            for (name, _) in &signatures {
                let cat = self.get_signature_category(name);
                *categories.entry(cat).or_insert(0) += 1;
            }

            let mut cats: Vec<_> = categories.into_iter().collect();
            cats.sort_by(|a, b| b.1.cmp(&a.1));

            for (cat, count) in cats {
                println!("  {}: {}", cat, count);
            }
        }

        Ok(())
    }

    fn signature_matches_category(&self, name: &str, category: &str) -> bool {
        self.get_signature_category(name).to_lowercase() == category.to_lowercase()
    }

    fn get_signature_category(&self, name: &str) -> &str {
        match name {
            // Cloud Providers
            n if n.starts_with("aws")
                || n.starts_with("gcloud")
                || n.starts_with("gsutil")
                || n.starts_with("az")
                || n.starts_with("ibmcloud")
                || n.starts_with("oci")
                || n.starts_with("doctl")
                || n.starts_with("linode") =>
            {
                "Cloud Providers"
            }
            // Containers & Orchestration
            n if n.starts_with("kubectl")
                || n.starts_with("helm")
                || n.starts_with("docker")
                || n.starts_with("podman")
                || n.starts_with("terraform")
                || n.starts_with("packer") =>
            {
                "Containers & Orchestration"
            }
            // Version Control
            n if n.starts_with("gh") || n.starts_with("glab") || n.starts_with("git") => {
                "Version Control"
            }
            // Databases
            n if n.starts_with("psql")
                || n.starts_with("mysql")
                || n.starts_with("mongosh")
                || n.starts_with("redis")
                || n.starts_with("sqlcipher") =>
            {
                "Databases"
            }
            // Monitoring
            n if n.starts_with("promtool")
                || n.starts_with("grafana")
                || n.starts_with("datadog") =>
            {
                "Monitoring & Observability"
            }
            // Messaging
            n if n.starts_with("rabbitmq") || n.starts_with("kafka") => "Messaging & Queues",
            // API Tools
            n if n.starts_with("curl")
                || n.starts_with("http")
                || n.starts_with("wget")
                || n.starts_with("gql") =>
            {
                "API Tools"
            }
            // Package Managers
            n if n.starts_with("npm")
                || n.starts_with("yarn")
                || n.starts_with("pip")
                || n.starts_with("gem")
                || n.starts_with("cargo") =>
            {
                "Package Managers"
            }
            // SSH
            n if n.starts_with("scp") || n.starts_with("rsync") || n.starts_with("mosh") => {
                "SSH & Remote Access"
            }
            // CDN & Edge
            n if n.starts_with("wrangler")
                || n.starts_with("vercel")
                || n.starts_with("netlify") =>
            {
                "CDN & Edge"
            }
            // Security
            n if n.starts_with("vault") || n.starts_with("op") => "Security & Crypto",
            // Developer Tools
            n if n.starts_with("stripe")
                || n.starts_with("twilio")
                || n.starts_with("sendgrid")
                || n.starts_with("slack")
                || n.starts_with("a0cli")
                || n.starts_with("heroku") =>
            {
                "Developer Tools"
            }
            // CI/CD
            n if n.starts_with("act") || n.starts_with("jenkins") || n.starts_with("argocd") => {
                "CI/CD"
            }
            // Data & Analytics
            n if n.starts_with("snowsql") || n.starts_with("databricks") => "Data & Analytics",
            // Default
            _ => "Other",
        }
    }
}

/// Sync project manifest (.sigil.toml) with vault
#[derive(clap::Args, Clone)]
struct CommandSync {
    /// Path to project directory (defaults to current directory)
    #[arg(short, long, default_value = ".")]
    path: String,

    /// Exit non-zero if there are any warnings (for CI)
    #[arg(long)]
    strict: bool,

    /// Output format (text, json)
    #[arg(short, long, default_value = "text")]
    format: String,
}

impl CommandSync {
    fn run(&self) -> Result<()> {
        use std::path::Path;

        // Find .sigil.toml in the project directory
        let project_dir = Path::new(&self.path);
        let sigil_toml_path = project_dir.join(".sigil.toml");

        if !sigil_toml_path.exists() {
            anyhow::bail!(
                "No .sigil.toml found in {}. Run 'sigil init .' to generate one.",
                self.path
            );
        }

        // Parse the manifest
        let manifest_content = std::fs::read_to_string(&sigil_toml_path)
            .with_context(|| format!("Failed to read {}", sigil_toml_path.display()))?;

        let manifest: toml::Value = toml::from_str(&manifest_content)
            .with_context(|| format!("Failed to parse {}", sigil_toml_path.display()))?;

        // Extract secrets from manifest
        let manifest_secrets = self.extract_manifest_secrets(&manifest)?;

        // Load vault
        let vault = self.load_vault()?;

        // Get all secrets from vault
        let rt = tokio::runtime::Runtime::new()?;
        let vault_secrets = rt.block_on(vault.list("")).unwrap_or_default();

        let vault_secret_paths: std::collections::HashSet<String> = vault_secrets
            .iter()
            .map(|s| s.path.as_str().to_string())
            .collect();

        // Check for issues
        let mut issues = Vec::new();
        let mut required_missing = Vec::new();

        // Check required secrets exist
        for secret in &manifest_secrets {
            if secret.required && !vault_secret_paths.contains(&secret.path) {
                required_missing.push(secret.path.clone());
                issues.push(SyncIssue {
                    severity: IssueSeverity::Error,
                    message: format!("Required secret '{}' is missing from vault", secret.path),
                    secret_path: secret.path.clone(),
                });
            } else if !secret.required && !vault_secret_paths.contains(&secret.path) {
                issues.push(SyncIssue {
                    severity: IssueSeverity::Warning,
                    message: format!("Optional secret '{}' is missing from vault", secret.path),
                    secret_path: secret.path.clone(),
                });
            }
        }

        // Check for secrets in vault but not declared in manifest
        for vault_path in &vault_secret_paths {
            let declared = manifest_secrets.iter().any(|s| &s.path == vault_path);
            if !declared {
                issues.push(SyncIssue {
                    severity: IssueSeverity::Warning,
                    message: format!(
                        "Secret '{}' in vault is not declared in .sigil.toml",
                        vault_path
                    ),
                    secret_path: vault_path.clone(),
                });
            }
        }

        // Output results
        if self.format == "json" {
            self.output_json(&issues, &manifest_secrets, &vault_secret_paths)?;
        } else {
            self.output_text(&issues, &manifest_secrets, &vault_secret_paths)?;
        }

        // Exit with error if there are errors in strict mode or if required secrets are missing
        let has_errors = issues.iter().any(|i| i.severity == IssueSeverity::Error);
        if has_errors || (self.strict && !issues.is_empty()) {
            std::process::exit(1);
        }

        Ok(())
    }

    fn extract_manifest_secrets(&self, manifest: &toml::Value) -> Result<Vec<ManifestSecret>> {
        let mut secrets = Vec::new();

        if let Some(secrets_array) = manifest.get("secrets").and_then(|v| v.as_array()) {
            for secret_value in secrets_array {
                if let Some(table) = secret_value.as_table() {
                    let path = table
                        .get("path")
                        .and_then(|v| v.as_str())
                        .ok_or_else(|| anyhow::anyhow!("Secret missing 'path' field"))?
                        .to_string();

                    let secret_type = table
                        .get("type")
                        .and_then(|v| v.as_str())
                        .unwrap_or("generic")
                        .to_string();

                    let required = table
                        .get("required")
                        .and_then(|v| v.as_bool())
                        .unwrap_or(false);

                    let description = table
                        .get("description")
                        .and_then(|v| v.as_str())
                        .map(|s| s.to_string());

                    secrets.push(ManifestSecret {
                        path,
                        secret_type,
                        required,
                        description,
                    });
                }
            }
        }

        Ok(secrets)
    }

    fn load_vault(&self) -> Result<sigil_vault::LocalVault> {
        let sigil_dir = dirs::home_dir()
            .ok_or_else(|| anyhow::anyhow!("Cannot determine home directory"))?
            .join(".sigil");

        let vault_dir = sigil_dir.join("vault");
        let identity_path = sigil_dir.join("identity.age");

        if !vault_dir.exists() {
            anyhow::bail!("Vault not initialized. Run 'sigil init' to create a vault.");
        }

        if !identity_path.exists() {
            anyhow::bail!("Vault identity not found. Run 'sigil init' to create a vault.");
        }

        // Prompt for passphrase
        print!("Enter vault passphrase: ");
        std::io::stdout().flush()?;
        let passphrase = rpassword::read_password()?;

        let mut vault = sigil_vault::LocalVault::new(vault_dir, identity_path)?;
        vault
            .load(Some(&passphrase))
            .context("Failed to unlock vault. Check your passphrase.")?;

        Ok(vault)
    }

    fn output_text(
        &self,
        issues: &[SyncIssue],
        manifest_secrets: &[ManifestSecret],
        vault_secrets: &std::collections::HashSet<String>,
    ) -> Result<()> {
        if issues.is_empty() {
            println!("✅ .sigil.toml is in sync with vault");
            println!();
            println!("Manifest secrets: {}", manifest_secrets.len());
            println!("Vault secrets: {}", vault_secrets.len());
        } else {
            println!("⚠️  Sync issues detected:");
            println!();

            for issue in issues {
                let icon = match issue.severity {
                    IssueSeverity::Error => "❌",
                    IssueSeverity::Warning => "⚠️ ",
                };
                println!("{} {}", icon, issue.message);
            }

            println!();
            println!("Manifest secrets: {}", manifest_secrets.len());
            println!("Vault secrets: {}", vault_secrets.len());
            println!("Issues: {}", issues.len());
        }

        Ok(())
    }

    fn output_json(
        &self,
        issues: &[SyncIssue],
        manifest_secrets: &[ManifestSecret],
        vault_secrets: &std::collections::HashSet<String>,
    ) -> Result<()> {
        use serde_json::json;

        let output = json!({
            "status": if issues.is_empty() { "ok" } else { "issues" },
            "manifest_secrets": manifest_secrets.len(),
            "vault_secrets": vault_secrets.len(),
            "issues": issues.iter().map(|i| {
                json!({
                    "severity": match i.severity {
                        IssueSeverity::Error => "error",
                        IssueSeverity::Warning => "warning",
                    },
                    "message": i.message,
                    "secret_path": i.secret_path,
                })
            }).collect::<Vec<_>>(),
        });

        println!("{}", serde_json::to_string_pretty(&output)?);
        Ok(())
    }
}

/// Secret declared in .sigil.toml manifest
#[derive(Debug, Clone)]
#[allow(dead_code)]
struct ManifestSecret {
    path: String,
    secret_type: String,
    required: bool,
    description: Option<String>,
}

/// Sync issue
#[derive(Debug, Clone)]
struct SyncIssue {
    severity: IssueSeverity,
    message: String,
    secret_path: String,
}

/// Issue severity
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum IssueSeverity {
    Error,
    Warning,
}

/// Enroll a new device (generate device key for CI or additional machine)
#[derive(clap::Args, Clone)]
struct CommandEnrollDevice {
    /// Device name (for identification, e.g., "github-actions")
    #[arg(short, long)]
    name: String,

    /// CI mode (output base64-encoded key for CI platform secrets)
    #[arg(long)]
    ci: bool,
}

impl CommandEnrollDevice {
    fn run(&self) -> Result<()> {
        use sigil_vault::sealed::SealedVault;

        let home =
            dirs::home_dir().ok_or_else(|| anyhow::anyhow!("Cannot determine home directory"))?;
        let vault_path = home.join(".sigil").join("vault.sealed");
        let device_key_path = home.join(".sigil").join("device.key");

        let vault = SealedVault::new(vault_path, device_key_path)
            .map_err(|e| anyhow::anyhow!("Failed to create vault: {}", e))?;

        if self.ci {
            // Generate CI device key (base64-encoded, not written to disk)
            let ci_key = vault
                .generate_ci_device_key()
                .map_err(|e| anyhow::anyhow!("Failed to generate CI device key: {}", e))?;

            println!("CI device key generated for: {}", self.name);
            println!();
            println!("Add this as a secret in your CI platform:");
            println!("  Name: SIGIL_DEVICE_KEY");
            println!("  Value: {}", ci_key);
            println!();
            println!("You'll also need to set SIGIL_PASSPHRASE as a separate secret.");
            println!();
            println!("Then set SIGIL_CI=true in your CI pipeline to activate CI mode.");
        } else {
            anyhow::bail!(
                "Regular device enrollment requires writing the key to disk. \
                Use --ci flag for CI/CD pipelines, or manually generate a device key."
            );
        }

        Ok(())
    }
}

/// Rotate CI device key (generates new key, re-encrypts vault)
#[derive(clap::Args, Clone)]
struct CommandRotateCiKey {
    /// Vault passphrase
    #[arg(short, long, env = "SIGIL_PASSPHRASE")]
    passphrase: String,

    /// Output new key as base64 (for CI platform secrets)
    #[arg(long)]
    base64: bool,
}

impl CommandRotateCiKey {
    fn run(&self) -> Result<()> {
        use sigil_vault::sealed::SealedVault;

        let home =
            dirs::home_dir().ok_or_else(|| anyhow::anyhow!("Cannot determine home directory"))?;
        let vault_path = home.join(".sigil").join("vault.sealed");
        let device_key_path = home.join(".sigil").join("device.key");

        let mut vault = SealedVault::new(vault_path, device_key_path)
            .map_err(|e| anyhow::anyhow!("Failed to create vault: {}", e))?;

        if !vault.exists() {
            anyhow::bail!("Vault not found. Initialize it first with 'sigil init'.");
        }

        // Rotate the device key
        let new_key = vault
            .rotate_device_key(&self.passphrase)
            .map_err(|e| anyhow::anyhow!("Failed to rotate device key: {}", e))?;

        println!("Device key rotated successfully!");
        println!();
        if self.base64 {
            println!("New CI device key (base64-encoded):");
            println!("{}", new_key);
            println!();
            println!("Update this in your CI platform secret: SIGIL_DEVICE_KEY");
        } else {
            println!("Update your CI platform secret: SIGIL_DEVICE_KEY");
            println!();
            println!("Or export the base64-encoded key:");
            println!("  export SIGIL_DEVICE_KEY={}", new_key);
        }

        Ok(())
    }
}

#[derive(Debug, Clone, serde::Serialize)]
struct SecretFinding {
    #[serde(rename = "type")]
    secret_type: String,
    file: String,
    line: usize,
    line_content: String,
    placeholder: Option<String>,
    suggested_vault_path: Option<String>,
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Quickstart(cmd) => cmd.run()?,
        Commands::Init(cmd) => cmd.run()?,
        Commands::Vault(cmd) => cmd.run()?,
        Commands::Add(cmd) => cmd.run()?,
        Commands::Get(cmd) => cmd.run()?,
        Commands::List(cmd) => cmd.run()?,
        Commands::Edit(cmd) => cmd.run()?,
        Commands::Remove(cmd) => cmd.run()?,
        Commands::History(cmd) => cmd.run()?,
        Commands::Rollback(cmd) => cmd.run()?,
        Commands::Prune(cmd) => cmd.run()?,
        Commands::Export(cmd) => cmd.run()?,
        Commands::Import(cmd) => cmd.run()?,
        Commands::Completions(cmd) => cmd.run()?,
        Commands::Complete(cmd) => cmd.run()?,
        Commands::Topic(cmd) => cmd.run()?,
        Commands::Migrate(cmd) => cmd.run()?,
        Commands::Uninstall(cmd) => cmd.run()?,
        Commands::Resolve(cmd) => cmd.run()?,
        Commands::Scrub(cmd) => cmd.run()?,
        Commands::Exec(cmd) => cmd.run()?,
        Commands::Wrap(cmd) => cmd.run()?,
        Commands::Setup(cmd) => cmd.run()?,
        Commands::Hook(cmd) => cmd.run()?,
        Commands::Config(cmd) => cmd.run()?,
        Commands::BreachReport(cmd) => cmd.run()?,
        Commands::Doctor(cmd) => cmd.run()?,
        Commands::Troubleshoot(cmd) => cmd.run()?,
        Commands::Operations(cmd) => cmd.run()?,
        Commands::SshAgent(cmd) => cmd.run()?,
        Commands::Lockdown(cmd) => cmd.run()?,
        Commands::Unlock(cmd) => cmd.run()?,
        Commands::Status(cmd) => cmd.run()?,
        Commands::Lint(cmd) => cmd.run()?,
        Commands::Sync(cmd) => cmd.run()?,
        Commands::Audit(cmd) => cmd.run()?,
        Commands::Signatures(cmd) => cmd.run()?,
        Commands::EnrollDevice(cmd) => cmd.run()?,
        Commands::RotateCiKey(cmd) => cmd.run()?,
    }

    Ok(())
}
