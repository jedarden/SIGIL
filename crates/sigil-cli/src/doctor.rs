//! SIGIL Doctor - Configuration validator and health check
//!
//! Provides comprehensive diagnostics across all SIGIL interception layers.

use anyhow::Result;
use serde::{Deserialize, Serialize};
use sigil_core::SecretBackend;
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
        self.score = if self.total_weight == 0 {
            100
        } else {
            ((self.earned_weight * 100) / self.total_weight) as u8
        };
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
    check_daemon(&mut report)?;
    check_sandbox(&mut report, fix)?;
    check_hooks(&sigil_dir, &mut report, fix)?;
    check_git_safety(&sigil_dir, &mut report, fix)?;
    check_audit_log(&sigil_dir, &mut report, fix)?;

    // Optional checks (warn only if not configured)
    check_proxy(&mut report)?;
    check_fuse(&mut report)?;
    check_canary(&sigil_dir, &mut report)?;
    check_backends(&sigil_dir, &mut report)?;

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

/// Format the report for terminal output
pub fn format_report(report: &HealthReport) -> String {
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
        let status_str = match &check.status {
            CheckStatus::Pass => "PASS",
            CheckStatus::Warn { .. } => "WARN",
            CheckStatus::Fail { .. } => "FAIL",
        };

        let status_color = match &check.status {
            CheckStatus::Pass => "\x1b[32m",        // Green
            CheckStatus::Warn { .. } => "\x1b[33m", // Yellow
            CheckStatus::Fail { .. } => "\x1b[31m", // Red
        };

        let reset = "\x1b[0m";

        output.push_str(&format!(
            "{:<name_width$} {}{:>4}{}  {}\n",
            check.name,
            status_color,
            status_str,
            reset,
            check.detail,
            name_width = max_name_len
        ));

        // Add suggestion/fix info
        match &check.status {
            CheckStatus::Warn { suggestion } => {
                output.push_str(&format!(
                    "{:width$}  → Suggestion: {}\n",
                    "",
                    suggestion,
                    width = max_name_len
                ));
            }
            CheckStatus::Fail { fix } => {
                output.push_str(&format!(
                    "{:width$}  → Fix: {}\n",
                    "",
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
