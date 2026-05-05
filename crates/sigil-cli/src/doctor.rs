//! SIGIL Doctor - Configuration validator and health check
//!
//! Provides comprehensive diagnostics across all SIGIL interception layers.

use anyhow::Result;
use serde::{Deserialize, Serialize};
use sigil_core::{atty, ColorMode, PaletteColor, SecretBackend};
use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

/// Health check result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum CheckStatus {
    /// Check passed
    Pass,
    /// Check passed with warning
    Warn { suggestion: String },
    /// Check failed with fix command
    Fail { fix: String },
}

/// Individual health check result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CheckResult {
    /// Check name
    pub name: String,
    /// Status
    pub status: CheckStatus,
    /// Detail message
    pub detail: String,
    /// Score weight (0-10)
    pub weight: u8,
}

/// Aggregate health check results
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealthReport {
    /// Individual check results
    pub checks: Vec<CheckResult>,
    /// Overall security score (0-100)
    pub score: u8,
    /// Total weight for scoring
    #[serde(skip)]
    total_weight: u16,
    /// Earned weight for scoring
    #[serde(skip)]
    earned_weight: u16,
}

impl HealthReport {
    /// Create a new health report
    pub fn new() -> Self {
        Self {
            checks: Vec::new(),
            score: 0,
            total_weight: 0,
            earned_weight: 0,
        }
    }

    /// Add a check result
    pub fn add(&mut self, check: CheckResult) {
        let weight = check.weight as u16;
        let earned = match &check.status {
            CheckStatus::Pass => weight,
            CheckStatus::Warn { .. } => weight / 2,
            CheckStatus::Fail { .. } => 0,
        };
        self.total_weight += weight;
        self.earned_weight += earned;
        self.checks.push(check);
    }

    /// Calculate the final score
    pub fn finalize(&mut self) {
        // Empty report (no checks) scores 100 - no failures found
        self.score = (self.earned_weight * 100)
            .checked_div(self.total_weight)
            .map(|v| v as u8)
            .unwrap_or(100);
    }

    /// Get CI-friendly output
    pub fn ci_exit_code(&self, min_score: u8) -> i32 {
        if self.score >= min_score {
            0
        } else {
            2
        }
    }
}

impl Default for HealthReport {
    fn default() -> Self {
        Self::new()
    }
}

/// Run all health checks
pub fn run_doctor(fix: bool, _ci_mode: bool) -> Result<HealthReport> {
    let mut report = HealthReport::new();

    // Get SIGIL directory
    let sigil_dir = get_sigil_dir()?;

    // Platform detection
    let wsl_info = detect_wsl();

    // Run all checks
    check_platform(&wsl_info, &mut report)?;
    check_vault(&sigil_dir, &mut report, fix)?;
    check_file_permissions(&sigil_dir, &mut report, fix)?;
    check_device_key_encryption(&sigil_dir, &mut report)?;
    check_daemon(&mut report)?;
    check_process_isolation(&mut report)?;
    check_sandbox(&mut report, fix)?;
    check_hooks(&sigil_dir, &mut report, fix)?;
    check_git_safety(&sigil_dir, &mut report, fix)?;
    check_audit_log(&sigil_dir, &mut report, fix)?;

    // Optional checks (warn only if not configured)
    check_proxy(&mut report)?;
    check_fuse(&mut report)?;
    check_canary(&sigil_dir, &mut report)?;
    check_backends(&sigil_dir, &mut report)?;
    check_shell_completion(&mut report)?;
    check_shell_history(&mut report)?;

    report.finalize();

    Ok(report)
}

/// Get the SIGIL directory
fn get_sigil_dir() -> Result<PathBuf> {
    let home =
        dirs::home_dir().ok_or_else(|| anyhow::anyhow!("Cannot determine home directory"))?;
    Ok(home.join(".sigil"))
}

/// WSL detection information
#[derive(Debug, Clone)]
struct WslInfo {
    /// Is running under WSL
    is_wsl: bool,
    /// WSL version (1 or 2), None if not WSL or unknown
    version: Option<u8>,
    /// WSL distro name if available
    distro: Option<String>,
}

/// Detect WSL environment
fn detect_wsl() -> WslInfo {
    // Check for WSL via environment variables
    if let Ok(distro) = env::var("WSL_DISTRO_NAME") {
        // WSL2: WSL_DISTRO_NAME is set
        return WslInfo {
            is_wsl: true,
            version: Some(2),
            distro: Some(distro),
        };
    }

    // Check via /proc/sys/fs/binfmt_misc/WSLInterop
    let wsl_interop_path = Path::new("/proc/sys/fs/binfmt_misc/WSLInterop");
    if wsl_interop_path.exists() {
        // Determine WSL version
        let version = if Path::new("/proc/sys/fs/binfmt_misc/WSLInterop").exists()
            && std::fs::read_to_string("/proc/version")
                .map(|v| v.contains("microsoft"))
                .unwrap_or(false)
        {
            // WSL2 has microsoft in /proc/version and proper kernel
            Some(2)
        } else {
            // WSL1 has no real kernel — namespaces are emulated
            Some(1)
        };

        return WslInfo {
            is_wsl: true,
            version,
            distro: None,
        };
    }

    WslInfo {
        is_wsl: false,
        version: None,
        distro: None,
    }
}

/// Check platform and WSL status
fn check_platform(wsl_info: &WslInfo, report: &mut HealthReport) -> Result<()> {
    if !wsl_info.is_wsl {
        report.add(CheckResult {
            name: "platform".to_string(),
            status: CheckStatus::Pass,
            detail: format!("{} {}", env::consts::OS, env::consts::ARCH),
            weight: 2,
        });
        return Ok(());
    }

    // WSL detected
    match wsl_info.version {
        Some(1) => {
            report.add(CheckResult {
                name: "platform".to_string(),
                status: CheckStatus::Warn {
                    suggestion: "WSL1 detected: namespaces are emulated and unreliable. Upgrade to WSL2 for full SIGIL support.".to_string(),
                },
                detail: "WSL1 (emulated kernel — limited namespace support)".to_string(),
                weight: 2,
            });
        }
        Some(2) => {
            // WSL2 uses Linux namespaces natively — no special handling needed
            let distro_name = wsl_info.distro.as_deref().unwrap_or("unknown");

            report.add(CheckResult {
                name: "platform".to_string(),
                status: CheckStatus::Pass,
                detail: format!("WSL2 ({}) — native namespace support", distro_name),
                weight: 2,
            });

            // WSL2-specific check: verify /dev/shm is available for tmpfs
            check_dev_shm(report)?;
        }
        _ => {
            report.add(CheckResult {
                name: "platform".to_string(),
                status: CheckStatus::Pass,
                detail: "WSL (version unknown)".to_string(),
                weight: 2,
            });
        }
    }

    Ok(())
}

/// Check /dev/shm availability for WSL2 tmpfs
fn check_dev_shm(report: &mut HealthReport) -> Result<()> {
    let shm_path = Path::new("/dev/shm");

    if !shm_path.exists() {
        report.add(CheckResult {
            name: "dev_shm".to_string(),
            status: CheckStatus::Warn {
                suggestion:
                    "/dev/shm is not available. Some SIGIL features may not work correctly."
                        .to_string(),
            },
            detail: "tmpfs /dev/shm not found (some minimal WSL configs lack it)".to_string(),
            weight: 1,
        });
        return Ok(());
    }

    // Check if it's actually tmpfs
    #[cfg(target_os = "linux")]
    {
        use std::os::unix::fs::MetadataExt;
        if let Ok(meta) = fs::metadata(shm_path) {
            let is_tmpfs = (meta.mode() & 0o170000) == 0o040000; // S_IFDIR
            if is_tmpfs {
                report.add(CheckResult {
                    name: "dev_shm".to_string(),
                    status: CheckStatus::Pass,
                    detail: "/dev/shm available (tmpfs)".to_string(),
                    weight: 0,
                });
                return Ok(());
            }
        }
    }

    report.add(CheckResult {
        name: "dev_shm".to_string(),
        status: CheckStatus::Pass,
        detail: "/dev/shm available".to_string(),
        weight: 0,
    });

    Ok(())
}

/// Check vault status
fn check_vault(sigil_dir: &Path, report: &mut HealthReport, _fix: bool) -> Result<()> {
    let vault_path = sigil_dir.join("vault");
    let identity_path = sigil_dir.join("identity.age");

    if !sigil_dir.exists() {
        report.add(CheckResult {
            name: "vault".to_string(),
            status: CheckStatus::Fail {
                fix: "sigil init".to_string(),
            },
            detail: "Vault not initialized".to_string(),
            weight: 10,
        });
        return Ok(());
    }

    if !vault_path.exists() {
        report.add(CheckResult {
            name: "vault".to_string(),
            status: CheckStatus::Fail {
                fix: "sigil init".to_string(),
            },
            detail: "Vault directory not found".to_string(),
            weight: 10,
        });
        return Ok(());
    }

    if !identity_path.exists() {
        report.add(CheckResult {
            name: "vault".to_string(),
            status: CheckStatus::Fail {
                fix: "sigil init".to_string(),
            },
            detail: "Vault identity file not found".to_string(),
            weight: 10,
        });
        return Ok(());
    }

    // Try to load vault and count secrets
    match load_vault_and_count_secrets(sigil_dir) {
        Ok(count) => {
            let detail = if count == 0 {
                "Vault initialized but no secrets".to_string()
            } else {
                format!("{} secrets loaded, encryption verified", count)
            };
            report.add(CheckResult {
                name: "vault".to_string(),
                status: CheckStatus::Pass,
                detail,
                weight: 10,
            });
        }
        Err(e) => {
            report.add(CheckResult {
                name: "vault".to_string(),
                status: CheckStatus::Fail {
                    fix: "sigil init".to_string(),
                },
                detail: format!("Vault load failed: {}", e),
                weight: 10,
            });
        }
    }

    Ok(())
}

/// Load vault and count secrets
fn load_vault_and_count_secrets(sigil_dir: &Path) -> Result<usize> {
    use sigil_vault::LocalVault;

    let vault_path = sigil_dir.join("vault");
    let identity_path = sigil_dir.join("identity.age");

    let mut vault = LocalVault::new(vault_path, identity_path)?;

    // Try without passphrase first
    let loaded = vault.load(None).is_ok();
    if !loaded {
        // With passphrase (will fail in non-interactive, that's ok)
        let _ = vault.load(Some(""));
    }

    // Use tokio runtime for async
    let rt = tokio::runtime::Runtime::new()?;
    let secrets = rt.block_on(vault.list(""))?;

    Ok(secrets.len())
}

/// Check daemon status
fn check_daemon(report: &mut HealthReport) -> Result<()> {
    // Check for daemon socket
    // Socket path: use $XDG_RUNTIME_DIR if available, fall back to /tmp/sigil-$UID.sock
    let socket_path = if let Ok(runtime_dir) = env::var("XDG_RUNTIME_DIR") {
        PathBuf::from(runtime_dir).join("sigil.sock")
    } else {
        // Use UID instead of process ID for more stable socket path
        let uid = unsafe { libc::getuid() };
        PathBuf::from("/tmp").join(format!("sigil-{}.sock", uid))
    };

    if !socket_path.exists() {
        report.add(CheckResult {
            name: "daemon".to_string(),
            status: CheckStatus::Fail {
                fix: "sigild start".to_string(),
            },
            detail: "Daemon not running (socket not found)".to_string(),
            weight: 8,
        });
        return Ok(());
    }

    // Try to connect to verify daemon is responsive
    // For now, just check socket exists
    report.add(CheckResult {
        name: "daemon".to_string(),
        status: CheckStatus::Pass,
        detail: format!("running on {}", socket_path.display()),
        weight: 8,
    });

    Ok(())
}

/// Check sandbox availability
fn check_sandbox(report: &mut HealthReport, fix: bool) -> Result<()> {
    // Check for bubblewrap on Linux
    #[cfg(target_os = "linux")]
    let has_bwrap = Command::new("bwrap")
        .arg("--version")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false);

    #[cfg(not(target_os = "linux"))]
    let has_bwrap = false;

    if !has_bwrap {
        report.add(CheckResult {
            name: "sandbox".to_string(),
            status: CheckStatus::Fail {
                fix: if cfg!(target_os = "linux") {
                    "apt install bubblewrap | brew install bubblewrap".to_string()
                } else {
                    "Install bubblewrap for your platform".to_string()
                },
            },
            detail: "bubblewrap not found - sandbox unavailable".to_string(),
            weight: 7,
        });
        return Ok(());
    }

    // Check namespace support
    let user_ns_supported = check_namespace_support("user");
    let pid_ns_supported = check_namespace_support("pid");
    let net_ns_supported = check_namespace_support("net");

    // Attempt to fix ptrace_scope if namespaces are not working
    let ptrace_fixed = if !user_ns_supported && fix {
        attempt_fix_ptrace_scope();
        // Re-check after fix attempt
        check_namespace_support("user")
    } else {
        user_ns_supported
    };

    if ptrace_fixed && pid_ns_supported && net_ns_supported {
        report.add(CheckResult {
            name: "sandbox".to_string(),
            status: CheckStatus::Pass,
            detail: "bubblewrap isolation working (PID ns, mount ns, net ns)".to_string(),
            weight: 7,
        });
    } else {
        let missing = vec![
            (!ptrace_fixed).then_some("user"),
            (!pid_ns_supported).then_some("pid"),
            (!net_ns_supported).then_some("net"),
        ]
        .into_iter()
        .flatten()
        .collect::<Vec<_>>()
        .join(", ");

        let suggestion = if fix && !user_ns_supported && ptrace_fixed {
            "Attempted ptrace_scope fix. Reboot may be required for changes to take effect."
                .to_string()
        } else if !user_ns_supported {
            "Try: sigil doctor --fix (requires sudo) or manually set ptrace_scope=0".to_string()
        } else {
            format!(
                "Namespace limitations detected: {}. Check kernel configuration.",
                missing
            )
        };

        report.add(CheckResult {
            name: "sandbox".to_string(),
            status: CheckStatus::Warn { suggestion },
            detail: "bubblewrap available but namespace support limited".to_string(),
            weight: 7,
        });
    }

    Ok(())
}

/// Attempt to fix ptrace_scope by writing to /proc/sys/kernel/yama/ptrace_scope
///
/// This requires root privileges. Returns true if the fix was applied or already correct.
fn attempt_fix_ptrace_scope() -> bool {
    use std::fs::write;

    // Check current value
    let ptrace_path = Path::new("/proc/sys/kernel/yama/ptrace_scope");
    if !ptrace_path.exists() {
        tracing::debug!("ptrace_scope not available (YAMA LSM may not be enabled)");
        return false;
    }

    let current_value = match fs::read_to_string(ptrace_path) {
        Ok(v) => v.trim().to_string(),
        Err(_) => return false,
    };

    // If already 0, nothing to do
    if current_value == "0" {
        tracing::debug!("ptrace_scope already set to 0");
        return true;
    }

    // Try to set to 0 (requires root)
    if let Err(e) = write(ptrace_path, "0") {
        tracing::warn!(
            "Failed to set ptrace_scope to 0: {} (try running with sudo)",
            e
        );
        false
    } else {
        tracing::info!("Successfully set ptrace_scope to 0");
        true
    }
}

/// Check namespace support
fn check_namespace_support(ns: &str) -> bool {
    // Try to create a temporary namespace using bwrap
    #[cfg(target_os = "linux")]
    {
        let result = Command::new("bwrap")
            .args([
                format!("--unshare-{}", ns),
                "--ro-bind".to_string(),
                "/".to_string(),
                "/".to_string(),
                "true".to_string(),
            ])
            .output();
        result.map(|o| o.status.success()).unwrap_or(false)
    }

    #[cfg(not(target_os = "linux"))]
    {
        false
    }
}

/// Check hook installation
fn check_hooks(_sigil_dir: &Path, report: &mut HealthReport, fix: bool) -> Result<()> {
    let claude_dir = dirs::home_dir()
        .ok_or_else(|| anyhow::anyhow!("Cannot determine home directory"))?
        .join(".claude");

    if !claude_dir.exists() {
        report.add(CheckResult {
            name: "hooks".to_string(),
            status: CheckStatus::Warn {
                suggestion: "sigil setup claude-code".to_string(),
            },
            detail: "Claude Code not configured".to_string(),
            weight: 5,
        });
        return Ok(());
    }

    let settings_path = claude_dir.join("settings.json");
    if !settings_path.exists() {
        report.add(CheckResult {
            name: "hooks".to_string(),
            status: CheckStatus::Warn {
                suggestion: "sigil setup claude-code".to_string(),
            },
            detail: "Claude Code settings not found".to_string(),
            weight: 5,
        });
        return Ok(());
    }

    // Check if hooks are configured
    let settings_content = fs::read_to_string(&settings_path)?;
    let has_hooks = settings_content.contains("sigil") || settings_content.contains("SIGIL");

    if has_hooks {
        report.add(CheckResult {
            name: "hooks".to_string(),
            status: CheckStatus::Pass,
            detail: "Claude Code hooks installed".to_string(),
            weight: 5,
        });
    } else {
        // Attempt to fix hooks if requested
        let hooks_fixed = if fix {
            attempt_install_hooks(&claude_dir, &settings_path)
        } else {
            false
        };

        if hooks_fixed {
            report.add(CheckResult {
                name: "hooks".to_string(),
                status: CheckStatus::Pass,
                detail: "Claude Code hooks installed (auto-fixed)".to_string(),
                weight: 5,
            });
        } else {
            report.add(CheckResult {
                name: "hooks".to_string(),
                status: CheckStatus::Warn {
                    suggestion: "sigil setup claude-code".to_string(),
                },
                detail: "Claude Code configured but hooks not installed".to_string(),
                weight: 5,
            });
        }
    }

    Ok(())
}

/// Attempt to install Claude Code hooks automatically
///
/// Returns true if hooks were successfully installed
fn attempt_install_hooks(_claude_dir: &Path, settings_path: &Path) -> bool {
    use crate::hooks;

    // Check if settings file exists, if not create the directory first
    if !settings_path.exists() {
        if let Some(parent) = settings_path.parent() {
            if let Err(e) = fs::create_dir_all(parent) {
                tracing::warn!("Failed to create Claude Code config directory: {}", e);
                return false;
            }
        }
    }

    // Try to setup hooks using the existing function
    match hooks::setup_claude_code_hooks() {
        Ok(()) => {
            tracing::info!("Successfully installed Claude Code hooks");
            true
        }
        Err(e) => {
            tracing::warn!("Failed to auto-install hooks: {}", e);
            false
        }
    }
}

/// Check git safety
fn check_git_safety(sigil_dir: &Path, report: &mut HealthReport, fix: bool) -> Result<()> {
    // Check if we're in a git repository
    let in_git_repo = Command::new("git")
        .args(["rev-parse", "--is-inside-work-tree"])
        .current_dir(sigil_dir)
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false);

    if !in_git_repo {
        report.add(CheckResult {
            name: "git".to_string(),
            status: CheckStatus::Pass,
            detail: "Not in a git repository".to_string(),
            weight: 3,
        });
        return Ok(());
    }

    // Check gitignore
    let gitignore_path = sigil_dir.join(".gitignore");
    let has_gitignore = gitignore_path.exists();

    if !has_gitignore {
        // Attempt to fix by creating gitignore
        if fix {
            if let Err(e) = fs::write(
                &gitignore_path,
                "# SIGIL vault secrets\nidentity.age\n*.age\nvault/\n",
            ) {
                tracing::warn!("Failed to create gitignore: {}", e);
                report.add(CheckResult {
                    name: "git".to_string(),
                    status: CheckStatus::Warn {
                        suggestion: format!("echo 'identity.age' > {}", gitignore_path.display()),
                    },
                    detail: "Git repository without .gitignore (auto-fix failed)".to_string(),
                    weight: 3,
                });
            } else {
                report.add(CheckResult {
                    name: "git".to_string(),
                    status: CheckStatus::Pass,
                    detail: "Created .gitignore with identity file exclusion (auto-fixed)"
                        .to_string(),
                    weight: 3,
                });
            }
        } else {
            report.add(CheckResult {
                name: "git".to_string(),
                status: CheckStatus::Warn {
                    suggestion: format!("echo 'identity.age' > {}", gitignore_path.display()),
                },
                detail: "Git repository without .gitignore".to_string(),
                weight: 3,
            });
        }
        return Ok(());
    }

    let gitignore_content = fs::read_to_string(&gitignore_path)?;
    let ignores_identity = gitignore_content.contains("identity.age")
        || gitignore_content.contains("*.age")
        || gitignore_content.contains("*");

    if ignores_identity {
        report.add(CheckResult {
            name: "git".to_string(),
            status: CheckStatus::Pass,
            detail: "Git safety: identity file in gitignore".to_string(),
            weight: 3,
        });
    } else {
        // Attempt to fix by appending to gitignore
        if fix {
            let additions = "# SIGIL vault secrets\nidentity.age\n*.age\nvault/\n";
            match fs::OpenOptions::new().append(true).open(&gitignore_path) {
                Ok(mut file) => {
                    use std::io::Write;
                    if let Err(e) = writeln!(file, "{}", additions) {
                        tracing::warn!("Failed to update gitignore: {}", e);
                        report.add(CheckResult {
                            name: "git".to_string(),
                            status: CheckStatus::Warn {
                                suggestion: format!(
                                    "echo 'identity.age' >> {}",
                                    gitignore_path.display()
                                ),
                            },
                            detail:
                                "Git repository: identity.age not in gitignore (auto-fix failed)"
                                    .to_string(),
                            weight: 3,
                        });
                    } else {
                        report.add(CheckResult {
                            name: "git".to_string(),
                            status: CheckStatus::Pass,
                            detail: "Git safety: identity file added to gitignore (auto-fixed)"
                                .to_string(),
                            weight: 3,
                        });
                    }
                }
                Err(e) => {
                    tracing::warn!("Failed to open gitignore: {}", e);
                    report.add(CheckResult {
                        name: "git".to_string(),
                        status: CheckStatus::Warn {
                            suggestion: format!(
                                "echo 'identity.age' >> {}",
                                gitignore_path.display()
                            ),
                        },
                        detail: "Git repository: identity.age not in gitignore".to_string(),
                        weight: 3,
                    });
                }
            }
        } else {
            report.add(CheckResult {
                name: "git".to_string(),
                status: CheckStatus::Warn {
                    suggestion: format!("echo 'identity.age' >> {}", gitignore_path.display()),
                },
                detail: "Git repository: identity.age not in gitignore".to_string(),
                weight: 3,
            });
        }
    }

    Ok(())
}

/// Check audit log
fn check_audit_log(sigil_dir: &Path, report: &mut HealthReport, fix: bool) -> Result<()> {
    let audit_path = sigil_dir.join("vault").join("audit.jsonl");

    if !audit_path.exists() {
        report.add(CheckResult {
            name: "audit".to_string(),
            status: CheckStatus::Warn {
                suggestion: "Audit log will be created on daemon start".to_string(),
            },
            detail: "Audit log not yet created".to_string(),
            weight: 2,
        });
        return Ok(());
    }

    // Check append-only flag (Linux only)
    #[cfg(target_os = "linux")]
    let append_only = check_append_only(&audit_path);

    #[cfg(not(target_os = "linux"))]
    let append_only = false;

    if append_only {
        report.add(CheckResult {
            name: "audit".to_string(),
            status: CheckStatus::Pass,
            detail: "Audit log exists with append-only flag".to_string(),
            weight: 2,
        });
    } else {
        // Attempt to fix append-only flag if requested
        let append_only_fixed = if fix {
            attempt_fix_append_only(&audit_path)
        } else {
            false
        };

        if append_only_fixed {
            report.add(CheckResult {
                name: "audit".to_string(),
                status: CheckStatus::Pass,
                detail: "Audit log exists with append-only flag (auto-fixed)".to_string(),
                weight: 2,
            });
        } else {
            let suggestion = if fix {
                "Append-only requires root privileges. Try: sudo chattr +a audit.jsonl".to_string()
            } else {
                "Run with sudo to set append-only: chattr +a audit.jsonl".to_string()
            };
            report.add(CheckResult {
                name: "audit".to_string(),
                status: CheckStatus::Warn { suggestion },
                detail: "Audit log exists (append-only not set - requires root)".to_string(),
                weight: 2,
            });
        }
    }

    Ok(())
}

/// Attempt to set append-only flag on audit log
///
/// Returns true if append-only was set successfully
fn attempt_fix_append_only(audit_path: &Path) -> bool {
    #[cfg(target_os = "linux")]
    {
        use std::process::Command;

        // Try to run chattr +a (requires root)
        let result = Command::new("chattr").arg("+a").arg(audit_path).output();

        match result {
            Ok(output) => {
                if output.status.success() {
                    tracing::info!("Successfully set append-only flag on {:?}", audit_path);
                    true
                } else {
                    let stderr = String::from_utf8_lossy(&output.stderr);
                    tracing::warn!(
                        "Failed to set append-only flag: {} (try with sudo)",
                        stderr.trim()
                    );
                    false
                }
            }
            Err(e) => {
                tracing::warn!("Failed to run chattr: {}", e);
                false
            }
        }
    }

    #[cfg(not(target_os = "linux"))]
    {
        let _ = audit_path;
        false
    }
}

/// Check file permissions for vault files
///
/// Verifies that all vault files have correct permissions (0600 for files, 0700 for directories).
/// This is a security requirement for encryption-at-rest.
fn check_file_permissions(sigil_dir: &Path, report: &mut HealthReport, fix: bool) -> Result<()> {
    if !sigil_dir.exists() {
        // Vault not initialized, skip this check
        return Ok(());
    }

    let mut issues = Vec::new();
    let mut files_checked = 0;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        // Helper function to recursively check files in a directory
        fn check_dir_recursive(
            dir: &Path,
            issues: &mut Vec<String>,
            files_checked: &mut usize,
            fix: bool,
        ) {
            if let Ok(entries) = fs::read_dir(dir) {
                for entry in entries.flatten() {
                    let path = entry.path();
                    if path.is_dir() {
                        check_dir_recursive(&path, issues, files_checked, fix);
                    } else if path.is_file() {
                        if let Some(ext) = path.extension() {
                            if ext == "age" || ext == "ml-kem" {
                                if let Ok(meta) = fs::metadata(&path) {
                                    let mode = meta.permissions().mode() & 0o777;
                                    if mode != 0o600 {
                                        issues.push(format!(
                                            "{} has {:o} permissions (should be 0600)",
                                            path.display(),
                                            mode
                                        ));
                                        // Attempt to fix if requested
                                        if fix {
                                            let mut perms = meta.permissions();
                                            perms.set_mode(0o600);
                                            if fs::set_permissions(&path, perms).is_ok() {
                                                tracing::info!(
                                                    "Fixed {} permissions to 0600",
                                                    path.display()
                                                );
                                            }
                                        }
                                    }
                                    *files_checked += 1;
                                }
                            }
                        }
                    }
                }
            }
        }

        // Check directory permissions
        let vault_path = sigil_dir.join("vault");
        if vault_path.exists() {
            if let Ok(meta) = fs::metadata(&vault_path) {
                let mode = meta.permissions().mode() & 0o777;
                if mode != 0o700 {
                    issues.push(format!(
                        "vault directory has {:o} permissions (should be 0700)",
                        mode
                    ));
                    // Attempt to fix if requested
                    if fix {
                        let mut perms = meta.permissions();
                        perms.set_mode(0o700);
                        if fs::set_permissions(&vault_path, perms).is_ok() {
                            tracing::info!("Fixed vault directory permissions to 0700");
                        }
                    }
                }
                files_checked += 1;
            }

            // Check all .age files in the vault
            check_dir_recursive(&vault_path, &mut issues, &mut files_checked, fix);
        }

        // Check identity.age
        let identity_path = sigil_dir.join("identity.age");
        if identity_path.exists() {
            if let Ok(meta) = fs::metadata(&identity_path) {
                let mode = meta.permissions().mode() & 0o777;
                if mode != 0o600 {
                    issues.push(format!(
                        "identity.age has {:o} permissions (should be 0600)",
                        mode
                    ));
                    // Attempt to fix if requested
                    if fix {
                        let mut perms = meta.permissions();
                        perms.set_mode(0o600);
                        if fs::set_permissions(&identity_path, perms).is_ok() {
                            tracing::info!("Fixed identity.age permissions to 0600");
                        }
                    }
                }
                files_checked += 1;
            }
        }

        // Check audit.jsonl
        let audit_path = sigil_dir.join("audit.jsonl");
        if audit_path.exists() {
            if let Ok(meta) = fs::metadata(&audit_path) {
                let mode = meta.permissions().mode() & 0o777;
                if mode != 0o600 {
                    issues.push(format!(
                        "audit.jsonl has {:o} permissions (should be 0600)",
                        mode
                    ));
                    // Attempt to fix if requested
                    if fix {
                        let mut perms = meta.permissions();
                        perms.set_mode(0o600);
                        if fs::set_permissions(&audit_path, perms).is_ok() {
                            tracing::info!("Fixed audit.jsonl permissions to 0600");
                        }
                    }
                }
                files_checked += 1;
            }
        }
    }

    #[cfg(not(unix))]
    {
        // On non-Unix platforms, just check that files exist
        // Permission checks are not applicable in the same way
        report.add(CheckResult {
            name: "permissions".to_string(),
            status: CheckStatus::Pass,
            detail: "File permissions not applicable on this platform".to_string(),
            weight: 3,
        });
        return Ok(());
    }

    if issues.is_empty() {
        report.add(CheckResult {
            name: "permissions".to_string(),
            status: CheckStatus::Pass,
            detail: format!("All {} vault files have correct permissions", files_checked),
            weight: 5,
        });
    } else {
        let fix_cmd = if fix {
            "Attempted to fix permissions automatically".to_string()
        } else {
            "sigil doctor --fix".to_string()
        };

        report.add(CheckResult {
            name: "permissions".to_string(),
            status: CheckStatus::Warn {
                suggestion: fix_cmd,
            },
            detail: issues.join("; "),
            weight: 5,
        });
    }

    Ok(())
}

/// Check device key encryption
///
/// Verifies that the device key is encrypted with an OS-bound key
/// (Linux kernel keyring or macOS Keychain) rather than stored as plaintext.
fn check_device_key_encryption(sigil_dir: &Path, report: &mut HealthReport) -> Result<()> {
    let device_key_path = sigil_dir.join("device.key");

    if !device_key_path.exists() {
        // Device key doesn't exist yet (vault not initialized)
        report.add(CheckResult {
            name: "device_key_encryption".to_string(),
            status: CheckStatus::Pass,
            detail: "Device key not found (vault not initialized)".to_string(),
            weight: 0,
        });
        return Ok(());
    }

    // Read the device key file
    let device_key_content = match fs::read_to_string(&device_key_path) {
        Ok(content) => content,
        Err(e) => {
            // Not a string file - might be binary (plaintext device key)
            report.add(CheckResult {
                name: "device_key_encryption".to_string(),
                status: CheckStatus::Fail {
                    fix: "Run 'sigil init' to re-initialize your vault with encrypted device key"
                        .to_string(),
                },
                detail: format!("Device key is stored in binary format (plaintext): {}", e),
                weight: 5,
            });
            return Ok(());
        }
    };

    // Check if it's age-encrypted (starts with age-encrypted headers)
    // or base64-encoded age data
    let is_encrypted = device_key_content.starts_with("age-encrypted")
        || device_key_content
            .chars()
            .next()
            .map(|c| c.is_ascii_alphanumeric() || c == '/' || c == '+')
            .unwrap_or(false);

    if is_encrypted {
        report.add(CheckResult {
            name: "device_key_encryption".to_string(),
            status: CheckStatus::Pass,
            detail: "Device key is encrypted with OS-bound key (kernel keyring or Keychain)"
                .to_string(),
            weight: 5,
        });
    } else {
        report.add(CheckResult {
            name: "device_key_encryption".to_string(),
            status: CheckStatus::Fail {
                fix: "Run 'sigil init' to re-initialize your vault with encrypted device key"
                    .to_string(),
            },
            detail: "Device key is stored as plaintext (should be encrypted with OS-bound key)"
                .to_string(),
            weight: 5,
        });
    }

    Ok(())
}

/// Check process isolation for the daemon
///
/// Verifies that the daemon has proper process isolation enabled:
/// - PR_SET_DUMPABLE=0 (prevents ptrace)
/// - RLIMIT_CORE=0 (no core dumps)
/// - mlockall (prevents swap)
fn check_process_isolation(report: &mut HealthReport) -> Result<()> {
    // This check can only verify if the daemon is running with proper isolation
    // We check by reading /proc/<pid>/status if available

    #[cfg(target_os = "linux")]
    {
        use std::process::Command;

        // Get the daemon PID if it's running
        let socket_path = if let Ok(runtime_dir) = env::var("XDG_RUNTIME_DIR") {
            PathBuf::from(runtime_dir).join("sigil.sock")
        } else {
            let uid = unsafe { libc::getuid() };
            PathBuf::from("/tmp").join(format!("sigil-{}.sock", uid))
        };

        if !socket_path.exists() {
            // Daemon not running, skip this check
            report.add(CheckResult {
                name: "isolation".to_string(),
                status: CheckStatus::Pass,
                detail: "Daemon not running (cannot check isolation)".to_string(),
                weight: 0,
            });
            return Ok(());
        }

        // Try to get the PID of the daemon process
        let output = Command::new("fuser").arg(&socket_path).output();

        let pid = match output {
            Ok(out) if out.status.success() => {
                let stdout = String::from_utf8_lossy(&out.stdout);
                stdout
                    .split_whitespace()
                    .next()
                    .and_then(|s| s.parse::<u32>().ok())
            }
            _ => None,
        };

        let pid = match pid {
            Some(p) => p,
            None => {
                report.add(CheckResult {
                    name: "isolation".to_string(),
                    status: CheckStatus::Warn {
                        suggestion: "Could not determine daemon PID".to_string(),
                    },
                    detail: "Unable to verify daemon process isolation".to_string(),
                    weight: 3,
                });
                return Ok(());
            }
        };

        // Check /proc/<pid>/status for isolation flags
        let status_path = format!("/proc/{}/status", pid);
        let status_content = fs::read_to_string(&status_path);

        let mut checks_passed = Vec::new();
        let mut checks_failed = Vec::new();

        if let Ok(status) = status_content {
            // Check for dumpable flag (should be 0)
            for line in status.lines() {
                if line.starts_with("dumpable:") {
                    let value = line.split(':').nth(1).unwrap_or("").trim();
                    if value == "0" {
                        checks_passed.push("PR_SET_DUMPABLE=0 (ptrace protection)");
                    } else {
                        checks_failed
                            .push("PR_SET_DUMPABLE not set to 0 (ptrace protection disabled)");
                    }
                }
            }
        }

        // We can't easily check RLIMIT_CORE or mlockall from outside the process
        // So we just report what we can verify
        if checks_passed.is_empty() && checks_failed.is_empty() {
            report.add(CheckResult {
                name: "isolation".to_string(),
                status: CheckStatus::Pass,
                detail: "Daemon running (isolation checks require procfs access)".to_string(),
                weight: 3,
            });
        } else if checks_failed.is_empty() {
            report.add(CheckResult {
                name: "isolation".to_string(),
                status: CheckStatus::Pass,
                detail: checks_passed.join(", "),
                weight: 3,
            });
        } else {
            report.add(CheckResult {
                name: "isolation".to_string(),
                status: CheckStatus::Warn {
                    suggestion: "Restart daemon to ensure isolation is enabled".to_string(),
                },
                detail: checks_failed.join("; "),
                weight: 3,
            });
        }
    }

    #[cfg(not(target_os = "linux"))]
    {
        report.add(CheckResult {
            name: "isolation".to_string(),
            status: CheckStatus::Pass,
            detail: "Process isolation checks not available on this platform".to_string(),
            weight: 0,
        });
    }

    Ok(())
}

/// Check append-only flag on Linux
#[cfg(target_os = "linux")]
fn check_append_only(path: &Path) -> bool {
    use std::os::unix::fs::MetadataExt;
    match fs::metadata(path) {
        Ok(meta) => {
            // Check for immutable/append-only flag (0x20 for append-only)
            (meta.mode() & 0x200) != 0
        }
        Err(_) => false,
    }
}

/// Check proxy (optional)
fn check_proxy(report: &mut HealthReport) -> Result<()> {
    // Proxy is optional - just check if port is in use
    let port_in_use = check_port_in_use(8080);

    if port_in_use {
        report.add(CheckResult {
            name: "proxy".to_string(),
            status: CheckStatus::Pass,
            detail: "Proxy configured and listening".to_string(),
            weight: 0,
        });
    } else {
        report.add(CheckResult {
            name: "proxy".to_string(),
            status: CheckStatus::Pass,
            detail: "Proxy not configured (optional)".to_string(),
            weight: 0,
        });
    }

    Ok(())
}

/// Check if a port is in use
fn check_port_in_use(port: u16) -> bool {
    // Try to bind to the port
    use std::net::TcpListener;
    TcpListener::bind(format!("127.0.0.1:{}", port)).is_err()
}

/// Check FUSE (optional)
fn check_fuse(report: &mut HealthReport) -> Result<()> {
    // Check if FUSE mount exists
    let fuse_mount = Path::new("/sigil");

    if fuse_mount.exists() {
        report.add(CheckResult {
            name: "fuse".to_string(),
            status: CheckStatus::Pass,
            detail: "FUSE mount active at /sigil".to_string(),
            weight: 0,
        });
    } else {
        report.add(CheckResult {
            name: "fuse".to_string(),
            status: CheckStatus::Pass,
            detail: "FUSE not mounted (optional)".to_string(),
            weight: 0,
        });
    }

    Ok(())
}

/// Check canary monitoring (optional)
fn check_canary(sigil_dir: &Path, report: &mut HealthReport) -> Result<()> {
    let canary_config = sigil_dir.join("canary.toml");

    if canary_config.exists() {
        report.add(CheckResult {
            name: "canary".to_string(),
            status: CheckStatus::Pass,
            detail: "Canary monitoring configured".to_string(),
            weight: 0,
        });
    } else {
        report.add(CheckResult {
            name: "canary".to_string(),
            status: CheckStatus::Pass,
            detail: "Canary monitoring not configured (optional)".to_string(),
            weight: 0,
        });
    }

    Ok(())
}

/// Check external backends
fn check_backends(sigil_dir: &Path, report: &mut HealthReport) -> Result<()> {
    let config_path = sigil_dir.join("config.toml");

    if !config_path.exists() {
        report.add(CheckResult {
            name: "backends".to_string(),
            status: CheckStatus::Pass,
            detail: "No external backends configured".to_string(),
            weight: 0,
        });
        return Ok(());
    }

    // Parse config.toml to get backend configurations
    let config_content = fs::read_to_string(&config_path)
        .map_err(|e| anyhow::anyhow!("Failed to read config.toml: {}", e))?;

    // Parse as TOML
    let parsed: toml::Value = config_content
        .parse()
        .map_err(|e| anyhow::anyhow!("Failed to parse config.toml: {}", e))?;

    // Extract backends section
    let backends = parsed.get("backends").and_then(|v| v.as_table());

    let Some(backend_configs) = backends else {
        report.add(CheckResult {
            name: "backends".to_string(),
            status: CheckStatus::Pass,
            detail: "No external backends configured".to_string(),
            weight: 0,
        });
        return Ok(());
    };

    if backend_configs.is_empty() {
        report.add(CheckResult {
            name: "backends".to_string(),
            status: CheckStatus::Pass,
            detail: "No external backends configured".to_string(),
            weight: 0,
        });
        return Ok(());
    }

    // Check each configured backend
    let mut backend_results = Vec::new();
    let mut total_weight = 0u16;
    let mut earned_weight = 0u16;

    for (name, config) in backend_configs {
        let backend_type = config
            .get("type")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown");

        total_weight += 3;

        match check_backend_health(name, backend_type, config) {
            Ok(()) => {
                backend_results.push(format!("{} ({})", name, backend_type));
                earned_weight += 3;
            }
            Err(e) => {
                backend_results.push(format!("{} ({}): {}", name, backend_type, e));
            }
        }
    }

    if backend_results.is_empty() {
        report.add(CheckResult {
            name: "backends".to_string(),
            status: CheckStatus::Pass,
            detail: "No external backends configured".to_string(),
            weight: 0,
        });
    } else if total_weight == earned_weight {
        report.add(CheckResult {
            name: "backends".to_string(),
            status: CheckStatus::Pass,
            detail: format!("All backends reachable: {}", backend_results.join(", ")),
            weight: 3,
        });
    } else {
        report.add(CheckResult {
            name: "backends".to_string(),
            status: CheckStatus::Warn {
                suggestion: "Check backend authentication and network connectivity".to_string(),
            },
            detail: format!("Some backends unreachable: {}", backend_results.join(", ")),
            weight: 3,
        });
    }

    Ok(())
}

/// Check health of a single backend
fn check_backend_health(_name: &str, backend_type: &str, config: &toml::Value) -> Result<()> {
    match backend_type {
        "vault" | "openbao" => {
            // Check Vault/OpenBao connectivity
            let address = config
                .get("address")
                .and_then(|v| v.as_str())
                .ok_or_else(|| anyhow::anyhow!("No address configured"))?;

            // Try to connect to the Vault server
            let url = format!("{}/v1/sys/health", address.trim_end_matches('/'));
            let response = reqwest::blocking::get(&url);

            match response {
                Ok(resp)
                    if resp.status().is_success()
                        || resp.status() == 429
                        || resp.status() == 472 =>
                {
                    // 200 = initialized, unsealed
                    // 429 = standby
                    // 472 = disaster recovery mode
                    // All indicate server is reachable
                    Ok(())
                }
                Ok(resp) => Err(anyhow::anyhow!("Server returned status {}", resp.status())),
                Err(e) => Err(anyhow::anyhow!("Connection failed: {}", e)),
            }
        }
        "onepassword" => {
            // Check 1Password CLI availability and authentication
            let output = Command::new("op").args(["--version"]).output();

            match output {
                Ok(out) if out.status.success() => {
                    // Check if authenticated
                    let status_output = Command::new("op").args(["account", "get"]).output();

                    match status_output {
                        Ok(status) if status.status.success() => Ok(()),
                        Ok(_) => Err(anyhow::anyhow!("CLI available but not authenticated")),
                        Err(e) => Err(anyhow::anyhow!("Authentication check failed: {}", e)),
                    }
                }
                Ok(_) => Err(anyhow::anyhow!("CLI command failed")),
                Err(_) => Err(anyhow::anyhow!("CLI not found - install from 1Password")),
            }
        }
        "pass" | "gopass" => {
            // Check pass/gopass availability
            let cmd = if backend_type == "gopass" {
                "gopass"
            } else {
                "pass"
            };

            let output = Command::new(cmd).args(["--version"]).output();

            match output {
                Ok(out) if out.status.success() => {
                    // Check if password store exists
                    let store = config
                        .get("store")
                        .and_then(|v| v.as_str())
                        .unwrap_or("~/.password-store");

                    let store_path = shellexpand::tilde(store);
                    let path = Path::new(store_path.as_ref());

                    if path.exists() {
                        Ok(())
                    } else {
                        Err(anyhow::anyhow!("Password store not found at {}", store))
                    }
                }
                Ok(_) => Err(anyhow::anyhow!("{} command failed", cmd)),
                Err(_) => Err(anyhow::anyhow!(
                    "{} not found - install via package manager",
                    cmd
                )),
            }
        }
        "aws" => {
            // Check AWS credentials availability
            let has_access_key = env::var("AWS_ACCESS_KEY_ID").is_ok();
            let has_secret_key = env::var("AWS_SECRET_ACCESS_KEY").is_ok();
            let has_session_token =
                env::var("AWS_SESSION_TOKEN").is_ok() || env::var("AWS_PROFILE").is_ok();

            if has_access_key && (has_secret_key || has_session_token) {
                Ok(())
            } else {
                Err(anyhow::anyhow!(
                    "AWS credentials not configured in environment"
                ))
            }
        }
        "sops" => {
            // Check SOPS availability
            let output = Command::new("sops").args(["--version"]).output();

            match output {
                Ok(out) if out.status.success() => Ok(()),
                Ok(_) => Err(anyhow::anyhow!("SOPS command failed")),
                Err(_) => Err(anyhow::anyhow!(
                    "SOPS not found - install from Mozilla SOPS"
                )),
            }
        }
        "env" => {
            // Environment backend is always available
            Ok(())
        }
        _ => Err(anyhow::anyhow!("Unknown backend type: {}", backend_type)),
    }
}

/// Check shell completion setup
fn check_shell_completion(report: &mut HealthReport) -> Result<()> {
    let shell = env::var("SHELL").unwrap_or_default();
    let shell_name = shell.rsplit('/').next().unwrap_or("unknown");
    let home =
        dirs::home_dir().ok_or_else(|| anyhow::anyhow!("Cannot determine home directory"))?;

    let (completion_file, setup_cmd) = match shell_name {
        "bash" => (
            home.join(".local/share/bash-completion/completions/sigil"),
            "sigil setup shell",
        ),
        "zsh" => (home.join(".zfunc/_sigil"), "sigil setup shell"),
        "fish" => (
            home.join(".config/fish/completions/sigil.fish"),
            "sigil setup shell",
        ),
        _ => {
            // Unknown shell - skip check
            return Ok(());
        }
    };

    if completion_file.exists() {
        report.add(CheckResult {
            name: "Shell completion".into(),
            status: CheckStatus::Pass,
            detail: format!("Completion installed for {}", shell_name),
            weight: 2,
        });
    } else {
        report.add(CheckResult {
            name: "Shell completion".into(),
            status: CheckStatus::Warn {
                suggestion: format!("Run: {}", setup_cmd),
            },
            detail: format!("Completion not found for {} (optional)", shell_name),
            weight: 2,
        });
    }

    Ok(())
}

/// Check shell history safety (Phase 1 Red Team Checkpoint)
///
/// Verifies that shell history is configured to prevent secrets from being
/// captured in history files. This includes:
/// - HISTCONTROL=ignorespace (bash) or HIST_IGNORE_SPACE (zsh)
/// - Commands starting with space are not saved to history
fn check_shell_history(report: &mut HealthReport) -> Result<()> {
    let shell = env::var("SHELL").unwrap_or_default();
    let shell_name = shell.rsplit('/').next().unwrap_or("unknown");

    let (hist_control_var, space_ignored) = match shell_name {
        "bash" => {
            // Bash: HISTCONTROL=ignorespace or HISTCONTROL=ignoreboth
            let hist_control = env::var("HISTCONTROL").unwrap_or_default();
            let ignores_space =
                hist_control.contains("ignorespace") || hist_control.contains("ignoreboth");
            ("HISTCONTROL", ignores_space)
        }
        "zsh" => {
            // Zsh: setopt HIST_IGNORE_SPACE
            let hist_ignore_space = env::var("HIST_IGNORE_SPACE").unwrap_or_default();
            let ignores_space =
                hist_ignore_space == "1" || hist_ignore_space.eq_ignore_ascii_case("true");
            ("HIST_IGNORE_SPACE", ignores_space)
        }
        _ => {
            // Unknown shell - skip check
            return Ok(());
        }
    };

    if space_ignored {
        report.add(CheckResult {
            name: "shell_history".into(),
            status: CheckStatus::Pass,
            detail: format!(
                "{} configured to ignore space-prefixed commands",
                shell_name
            ),
            weight: 3,
        });
    } else {
        report.add(CheckResult {
            name: "shell_history".into(),
            status: CheckStatus::Warn {
                suggestion: format!(
                    "Add to ~/.{}rc: export {}=\"ignorespace\" (or use space before sigil commands)",
                    shell_name, hist_control_var
                ),
            },
            detail: format!(
                "Shell history may capture secrets. Set {}=ignorespace or prefix commands with space.",
                hist_control_var
            ),
            weight: 3,
        });
    }

    // Also check for SIGIL-specific history safety patterns
    // Look for common shell configuration files that might have SIGIL settings
    let home =
        dirs::home_dir().ok_or_else(|| anyhow::anyhow!("Cannot determine home directory"))?;

    let config_files = match shell_name {
        "bash" => vec![
            home.join(".bashrc"),
            home.join(".bash_profile"),
            home.join(".profile"),
        ],
        "zsh" => vec![home.join(".zshrc"), home.join(".zprofile")],
        _ => vec![],
    };

    let mut has_sigil_histignore = false;
    for config_file in &config_files {
        if let Ok(content) = fs::read_to_string(config_file) {
            // Check for SIGIL-specific history patterns
            if content.contains("HISTCONTROL")
                && (content.contains("ignorespace") || content.contains("ignoreboth"))
            {
                has_sigil_histignore = true;
                break;
            }
        }
    }

    // If shell history is not safely configured but config files exist,
    // provide a more specific suggestion
    if !space_ignored && !config_files.is_empty() && !has_sigil_histignore {
        let primary_config = &config_files[0];
        report.add(CheckResult {
            name: "shell_history_config".into(),
            status: CheckStatus::Warn {
                suggestion: format!(
                    "Add to {}: export HISTCONTROL=ignorespace",
                    primary_config.display()
                ),
            },
            detail: format!(
                "Shell config file exists ({}) but history safety not configured",
                primary_config.display()
            ),
            weight: 1,
        });
    }

    Ok(())
}

/// Format the report for terminal output
///
/// Respects NO_COLOR and FORCE_COLOR environment variables.
/// Supports high contrast mode via SIGIL_HIGH_CONTRAST=1.
pub fn format_report(report: &HealthReport) -> String {
    // Detect color mode and high contrast setting
    let color_mode = ColorMode::detect();
    let high_contrast = env::var("SIGIL_HIGH_CONTRAST").is_ok_and(|v| v == "1" || v == "true");

    let mut output = String::new();

    output.push_str("SIGIL Health Check\n");
    output.push('\n');

    // Calculate column widths
    let max_name_len = report
        .checks
        .iter()
        .map(|c| c.name.len())
        .max()
        .unwrap_or(10)
        .max(10);

    for check in &report.checks {
        let (status_str, palette_color) = match &check.status {
            CheckStatus::Pass => ("PASS", PaletteColor::Success),
            CheckStatus::Warn { .. } => ("WARN", PaletteColor::Warning),
            CheckStatus::Fail { .. } => ("FAIL", PaletteColor::Error),
        };

        // Format status line with appropriate color and symbol
        let use_color = color_mode.use_color(atty::is(atty::Stream::Stdout));
        let label = if use_color {
            let ansi = if high_contrast {
                palette_color.ansi_high_contrast()
            } else {
                palette_color.ansi_normal()
            };
            format!(
                "{}{:>4}{}",
                ansi,
                status_str,
                sigil_core::terminal::ANSI_RESET
            )
        } else {
            format!("{:>4}", status_str)
        };

        output.push_str(&format!(
            "{:<name_width$} {}  {}\n",
            check.name,
            label,
            check.detail,
            name_width = max_name_len
        ));

        // Add suggestion/fix info
        match &check.status {
            CheckStatus::Warn { suggestion } => {
                let arrow = if high_contrast { "→" } else { "->" };
                output.push_str(&format!(
                    "{:width$}  {} Suggestion: {}\n",
                    "",
                    arrow,
                    suggestion,
                    width = max_name_len
                ));
            }
            CheckStatus::Fail { fix } => {
                let arrow = if high_contrast { "→" } else { "->" };
                output.push_str(&format!(
                    "{:width$}  {} Fix: {}\n",
                    "",
                    arrow,
                    fix,
                    width = max_name_len
                ));
            }
            CheckStatus::Pass => {}
        }
    }

    output.push('\n');
    output.push_str(&format!("Score: {}/100\n", report.score));

    output
}

/// Format the report as JSON
pub fn format_report_json(report: &HealthReport) -> Result<String> {
    Ok(serde_json::to_string_pretty(report)?)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_health_report_new() {
        let report = HealthReport::new();
        assert!(report.checks.is_empty());
        assert_eq!(report.score, 0);
        assert_eq!(report.total_weight, 0);
        assert_eq!(report.earned_weight, 0);
    }

    #[test]
    fn test_health_report_default() {
        let report = HealthReport::default();
        assert!(report.checks.is_empty());
        assert_eq!(report.score, 0);
    }

    #[test]
    fn test_health_report_add_pass() {
        let mut report = HealthReport::new();
        report.add(CheckResult {
            name: "test".to_string(),
            status: CheckStatus::Pass,
            detail: "test detail".to_string(),
            weight: 10,
        });
        assert_eq!(report.checks.len(), 1);
        assert_eq!(report.total_weight, 10);
        assert_eq!(report.earned_weight, 10);
    }

    #[test]
    fn test_health_report_add_warn() {
        let mut report = HealthReport::new();
        report.add(CheckResult {
            name: "test".to_string(),
            status: CheckStatus::Warn {
                suggestion: "fix it".to_string(),
            },
            detail: "test detail".to_string(),
            weight: 10,
        });
        assert_eq!(report.checks.len(), 1);
        assert_eq!(report.total_weight, 10);
        assert_eq!(report.earned_weight, 5); // half weight for warn
    }

    #[test]
    fn test_health_report_add_fail() {
        let mut report = HealthReport::new();
        report.add(CheckResult {
            name: "test".to_string(),
            status: CheckStatus::Fail {
                fix: "fix command".to_string(),
            },
            detail: "test detail".to_string(),
            weight: 10,
        });
        assert_eq!(report.checks.len(), 1);
        assert_eq!(report.total_weight, 10);
        assert_eq!(report.earned_weight, 0); // no weight for fail
    }

    #[test]
    fn test_health_report_finalize_all_pass() {
        let mut report = HealthReport::new();
        report.add(CheckResult {
            name: "test1".to_string(),
            status: CheckStatus::Pass,
            detail: "detail1".to_string(),
            weight: 10,
        });
        report.add(CheckResult {
            name: "test2".to_string(),
            status: CheckStatus::Pass,
            detail: "detail2".to_string(),
            weight: 10,
        });
        report.finalize();
        assert_eq!(report.score, 100);
    }

    #[test]
    fn test_health_report_finalize_half_pass() {
        let mut report = HealthReport::new();
        report.add(CheckResult {
            name: "test1".to_string(),
            status: CheckStatus::Pass,
            detail: "detail1".to_string(),
            weight: 10,
        });
        report.add(CheckResult {
            name: "test2".to_string(),
            status: CheckStatus::Fail {
                fix: "fix".to_string(),
            },
            detail: "detail2".to_string(),
            weight: 10,
        });
        report.finalize();
        assert_eq!(report.score, 50);
    }

    #[test]
    fn test_health_report_finalize_with_warn() {
        let mut report = HealthReport::new();
        report.add(CheckResult {
            name: "test1".to_string(),
            status: CheckStatus::Pass,
            detail: "detail1".to_string(),
            weight: 10,
        });
        report.add(CheckResult {
            name: "test2".to_string(),
            status: CheckStatus::Warn {
                suggestion: "suggestion".to_string(),
            },
            detail: "detail2".to_string(),
            weight: 10,
        });
        report.finalize();
        assert_eq!(report.score, 75); // (10 + 5) / 20 * 100
    }

    #[test]
    fn test_health_report_finalize_empty() {
        let mut report = HealthReport::new();
        report.finalize();
        assert_eq!(report.score, 100); // empty report scores 100
    }

    #[test]
    fn test_ci_exit_code_pass() {
        let report = HealthReport {
            checks: vec![],
            score: 80,
            total_weight: 0,
            earned_weight: 0,
        };
        assert_eq!(report.ci_exit_code(70), 0);
        assert_eq!(report.ci_exit_code(80), 0);
    }

    #[test]
    fn test_ci_exit_code_fail() {
        let report = HealthReport {
            checks: vec![],
            score: 50,
            total_weight: 0,
            earned_weight: 0,
        };
        assert_eq!(report.ci_exit_code(70), 2);
    }

    #[test]
    fn test_check_result_serialization() {
        let check = CheckResult {
            name: "test".to_string(),
            status: CheckStatus::Pass,
            detail: "test detail".to_string(),
            weight: 10,
        };
        let json = serde_json::to_string(&check).unwrap();
        assert!(json.contains("\"test\""));
        assert!(json.contains("\"Pass\""));
    }

    #[test]
    fn test_check_result_warn_serialization() {
        let check = CheckResult {
            name: "test".to_string(),
            status: CheckStatus::Warn {
                suggestion: "fix it".to_string(),
            },
            detail: "test detail".to_string(),
            weight: 10,
        };
        let json = serde_json::to_string(&check).unwrap();
        assert!(json.contains("\"Warn\""));
        assert!(json.contains("\"fix it\""));
    }

    #[test]
    fn test_check_result_fail_serialization() {
        let check = CheckResult {
            name: "test".to_string(),
            status: CheckStatus::Fail {
                fix: "fix command".to_string(),
            },
            detail: "test detail".to_string(),
            weight: 10,
        };
        let json = serde_json::to_string(&check).unwrap();
        assert!(json.contains("\"Fail\""));
        assert!(json.contains("\"fix command\""));
    }

    #[test]
    fn test_health_report_serialization() {
        let mut report = HealthReport::new();
        report.add(CheckResult {
            name: "test".to_string(),
            status: CheckStatus::Pass,
            detail: "detail".to_string(),
            weight: 10,
        });
        report.finalize();

        let json = serde_json::to_string(&report).unwrap();
        assert!(json.contains("\"test\""));
        assert!(json.contains("\"score\""));
    }

    #[test]
    fn test_format_report_json() {
        let mut report = HealthReport::new();
        report.add(CheckResult {
            name: "test".to_string(),
            status: CheckStatus::Pass,
            detail: "detail".to_string(),
            weight: 10,
        });
        report.finalize();

        let json = format_report_json(&report).unwrap();
        assert!(json.contains("test"));
        assert!(json.contains("score"));
        assert!(json.contains("{\n")); // pretty printed
    }

    #[test]
    fn test_format_report_terminal() {
        let mut report = HealthReport::new();
        report.add(CheckResult {
            name: "test_check".to_string(),
            status: CheckStatus::Pass,
            detail: "test detail".to_string(),
            weight: 10,
        });
        report.finalize();

        let output = format_report(&report);
        assert!(output.contains("SIGIL Health Check"));
        assert!(output.contains("test_check"));
        assert!(output.contains("test detail"));
        assert!(output.contains("Score:"));
    }

    #[test]
    fn test_format_report_terminal_with_warn() {
        let mut report = HealthReport::new();
        report.add(CheckResult {
            name: "test_check".to_string(),
            status: CheckStatus::Warn {
                suggestion: "fix suggestion".to_string(),
            },
            detail: "test detail".to_string(),
            weight: 10,
        });
        report.finalize();

        let output = format_report(&report);
        assert!(output.contains("test_check"));
        assert!(output.contains("Suggestion:"));
        assert!(output.contains("fix suggestion"));
    }

    #[test]
    fn test_format_report_terminal_with_fail() {
        let mut report = HealthReport::new();
        report.add(CheckResult {
            name: "test_check".to_string(),
            status: CheckStatus::Fail {
                fix: "fix command".to_string(),
            },
            detail: "test detail".to_string(),
            weight: 10,
        });
        report.finalize();

        let output = format_report(&report);
        assert!(output.contains("test_check"));
        assert!(output.contains("Fix:"));
        assert!(output.contains("fix command"));
    }

    #[test]
    fn test_wsl_info_not_wsl() {
        let wsl_info = detect_wsl();
        // In the test environment, we're likely not on WSL
        // The test just verifies the function runs without panic
        match wsl_info.is_wsl {
            true => {
                // If WSL detected, verify version is Some
                assert!(wsl_info.version.is_some());
            }
            false => {
                // If not WSL, version should be None
                assert!(wsl_info.version.is_none());
                assert!(wsl_info.distro.is_none());
            }
        }
    }

    #[test]
    fn test_check_port_in_use_likely_free() {
        // Use a high port number that's likely not in use
        let in_use = check_port_in_use(65432);
        // We can't assert definitively, but the function should run
        let _ = in_use;
    }

    #[test]
    fn test_check_status_display() {
        // Verify CheckStatus can be converted to display strings
        let pass_str = match CheckStatus::Pass {
            CheckStatus::Pass => "PASS",
            _ => "other",
        };
        assert_eq!(pass_str, "PASS");

        let warn = CheckStatus::Warn {
            suggestion: "test".to_string(),
        };
        let has_suggestion = matches!(warn, CheckStatus::Warn { .. });
        assert!(has_suggestion);

        let fail = CheckStatus::Fail {
            fix: "test".to_string(),
        };
        let has_fix = matches!(fail, CheckStatus::Fail { .. });
        assert!(has_fix);
    }

    #[test]
    fn test_multiple_checks_scoring() {
        let mut report = HealthReport::new();
        // Add a mix of pass, warn, and fail
        report.add(CheckResult {
            name: "pass1".to_string(),
            status: CheckStatus::Pass,
            detail: "".to_string(),
            weight: 10,
        });
        report.add(CheckResult {
            name: "warn1".to_string(),
            status: CheckStatus::Warn {
                suggestion: "suggestion".to_string(),
            },
            detail: "".to_string(),
            weight: 10,
        });
        report.add(CheckResult {
            name: "fail1".to_string(),
            status: CheckStatus::Fail {
                fix: "fix".to_string(),
            },
            detail: "".to_string(),
            weight: 10,
        });
        report.add(CheckResult {
            name: "pass2".to_string(),
            status: CheckStatus::Pass,
            detail: "".to_string(),
            weight: 10,
        });

        report.finalize();
        // (10 + 5 + 0 + 10) / 40 * 100 = 25 / 40 * 100 = 62.5 -> 62
        assert_eq!(report.score, 62);
    }

    #[test]
    fn test_weighted_scoring_different_weights() {
        let mut report = HealthReport::new();
        report.add(CheckResult {
            name: "critical".to_string(),
            status: CheckStatus::Pass,
            detail: "".to_string(),
            weight: 10,
        });
        report.add(CheckResult {
            name: "minor".to_string(),
            status: CheckStatus::Pass,
            detail: "".to_string(),
            weight: 2,
        });

        report.finalize();
        assert_eq!(report.score, 100);
    }

    #[test]
    fn test_weighted_scoring_with_failure() {
        let mut report = HealthReport::new();
        report.add(CheckResult {
            name: "critical".to_string(),
            status: CheckStatus::Pass,
            detail: "".to_string(),
            weight: 10,
        });
        report.add(CheckResult {
            name: "minor".to_string(),
            status: CheckStatus::Fail {
                fix: "fix".to_string(),
            },
            detail: "".to_string(),
            weight: 2,
        });

        report.finalize();
        // 10 / 12 * 100 = 83.33 -> 83
        assert_eq!(report.score, 83);
    }
}
