//! SIGIL Troubleshoot - Guided diagnostic with active component testing
//!
//! Provides thorough diagnostics with actionable remediation steps.
//! Unlike `sigil doctor` which is a health check, troubleshoot actively
//! tests each component (daemon IPC, sandbox execution, hooks).

use anyhow::Result;
use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Duration;

#[cfg(unix)]
use std::os::unix::fs::{FileTypeExt, PermissionsExt};

/// Troubleshoot check result
#[derive(Debug, Clone)]
pub struct TroubleshootCheck {
    /// Check category (e.g., "daemon", "sandbox", "hooks")
    pub category: String,
    /// Check name
    pub name: String,
    /// Status
    pub status: TroubleshootStatus,
    /// Detailed description
    pub detail: String,
}

/// Troubleshoot status with remediation steps
#[derive(Debug, Clone)]
pub enum TroubleshootStatus {
    /// Check passed
    Pass {
        /// Additional info about the successful check
        info: Option<String>,
    },
    /// Check passed with warning
    Warn {
        /// Warning message
        message: String,
        /// Suggested action
        suggestion: String,
    },
    /// Check failed with remediation steps
    Fail {
        /// Error message
        error: String,
        /// Multiple remediation steps to try
        remediation: Vec<String>,
    },
}

/// Troubleshoot report with all check results
pub struct TroubleshootReport {
    /// All check results
    pub checks: Vec<TroubleshootCheck>,
    /// Overall status (true if all critical checks passed)
    pub overall_success: bool,
}

impl TroubleshootReport {
    /// Create a new troubleshoot report
    pub fn new() -> Self {
        Self {
            checks: Vec::new(),
            overall_success: true,
        }
    }

    /// Add a check result
    pub fn add(&mut self, check: TroubleshootCheck) {
        self.overall_success &= matches!(check.status, TroubleshootStatus::Pass { .. });
        self.checks.push(check);
    }

    /// Format the report for display
    pub fn format(&self) -> String {
        let mut output = String::new();

        output.push_str("  SIGIL Troubleshoot\n\n");

        let mut current_category = String::new();
        for check in &self.checks {
            if check.category != current_category {
                current_category = check.category.clone();
                output.push_str(&format!("  Checking {}...\n", current_category));
            }

            match &check.status {
                TroubleshootStatus::Pass { info } => {
                    output.push_str(&format!("    {}: PASS", check.name));
                    if let Some(info_text) = info {
                        output.push_str(&format!(" ({})", info_text));
                    }
                    output.push('\n');
                }
                TroubleshootStatus::Warn {
                    message,
                    suggestion,
                } => {
                    output.push_str(&format!("    {}: WARN - {}\n", check.name, message));
                    output.push_str(&format!("      Suggestion: {}\n", suggestion));
                }
                TroubleshootStatus::Fail { error, remediation } => {
                    output.push_str(&format!("    {}: FAIL - {}\n", check.name, error));
                    for (i, step) in remediation.iter().enumerate() {
                        output.push_str(&format!("      {}. {}\n", i + 1, step));
                    }
                }
            }

            output.push_str(&format!("      {}\n\n", check.detail));
        }

        // Add summary and next steps
        if self.overall_success {
            output.push_str("  All checks passed. If you're still having issues, run:\n");
            output.push_str("    sigil doctor --debug    Full diagnostic with verbose output\n");
            output.push_str("    sigil daemon restart    Restart daemon\n");
            output.push_str("    sigil setup claude-code Re-install hooks\n");
        } else {
            output.push_str("  Some checks failed. Follow the remediation steps above.\n");
            output.push_str("  For more information, run: sigil doctor --debug\n");
        }

        output
    }
}

impl Default for TroubleshootReport {
    fn default() -> Self {
        Self::new()
    }
}

/// Run the troubleshoot diagnostic
pub fn run_troubleshoot(verbose: bool) -> Result<TroubleshootReport> {
    let mut report = TroubleshootReport::new();

    let sigil_dir = get_sigil_dir()?;

    // Run all troubleshoot checks
    check_daemon(&mut report, verbose)?;
    check_vault(&sigil_dir, &mut report)?;
    check_sandbox(&mut report, verbose)?;
    check_hooks(&sigil_dir, &mut report)?;
    check_permissions(&sigil_dir, &mut report)?;

    Ok(report)
}

/// Get the SIGIL directory
fn get_sigil_dir() -> Result<PathBuf> {
    let home =
        dirs::home_dir().ok_or_else(|| anyhow::anyhow!("Cannot determine home directory"))?;
    Ok(home.join(".sigil"))
}

/// Check daemon status with active IPC test
fn check_daemon(report: &mut TroubleshootReport, verbose: bool) -> Result<()> {
    // Determine socket path
    let socket_path = if let Ok(runtime_dir) = env::var("XDG_RUNTIME_DIR") {
        PathBuf::from(runtime_dir).join("sigil.sock")
    } else {
        let uid = unsafe { libc::getuid() };
        PathBuf::from("/tmp").join(format!("sigil-{}.sock", uid))
    };

    // Check if socket exists
    if !socket_path.exists() {
        report.add(TroubleshootCheck {
            category: "daemon".to_string(),
            name: "Socket exists".to_string(),
            status: TroubleshootStatus::Fail {
                error: "Daemon not running".to_string(),
                remediation: vec![
                    format!("Start the daemon: sigild start"),
                    format!("Check if daemon is already running: ps aux | grep sigild"),
                    format!("Check system logs for startup errors"),
                ],
            },
            detail: format!("Socket not found at {}", socket_path.display()),
        });
        return Ok(());
    }

    // Check socket permissions
    let metadata = fs::metadata(&socket_path)?;
    let mode = metadata.permissions().mode();
    let is_socket_correct = metadata.file_type().is_socket() && (mode & 0o777) == 0o600;

    if !is_socket_correct {
        report.add(TroubleshootCheck {
            category: "daemon".to_string(),
            name: "Socket permissions".to_string(),
            status: TroubleshootStatus::Warn {
                message: format!("Socket has incorrect permissions: {:04o}", mode & 0o777),
                suggestion: "Remove the socket and restart the daemon".to_string(),
            },
            detail: format!("Expected 0600, got {:04o}", mode & 0o777),
        });
        return Ok(());
    }

    // Try to connect and send a ping request
    let daemon_responding = test_daemon_ipc(&socket_path, verbose)?;

    if !daemon_responding {
        report.add(TroubleshootCheck {
            category: "daemon".to_string(),
            name: "Daemon responding".to_string(),
            status: TroubleshootStatus::Fail {
                error: "Daemon not responding to IPC requests".to_string(),
                remediation: vec![
                    "Restart the daemon: sigild restart".to_string(),
                    "Check daemon logs for errors".to_string(),
                    "Verify no other process is blocking the socket".to_string(),
                ],
            },
            detail: "Socket exists but IPC ping failed".to_string(),
        });
        return Ok(());
    }

    report.add(TroubleshootCheck {
        category: "daemon".to_string(),
        name: "Daemon responding".to_string(),
        status: TroubleshootStatus::Pass {
            info: Some(format!("via {}", socket_path.display())),
        },
        detail: "Successfully sent ping request and received response".to_string(),
    });

    Ok(())
}

/// Test daemon IPC connectivity
fn test_daemon_ipc(socket_path: &Path, _verbose: bool) -> Result<bool> {
    use sigil_core::{write_message, IpcOperation, IpcRequest};

    // Try to connect with timeout
    let mut stream =
        match std::panic::catch_unwind(|| std::os::unix::net::UnixStream::connect(socket_path)) {
            Ok(Ok(s)) => s,
            Ok(Err(_)) => return Ok(false),
            Err(_) => return Ok(false),
        };

    // Set read timeout
    stream.set_read_timeout(Some(Duration::from_secs(2)))?;

    // Send ping request
    let request = IpcRequest::new(IpcOperation::Ping, String::new());
    let json = serde_json::to_vec(&request)?;

    if write_message(&mut stream, &json).is_err() {
        return Ok(false);
    }

    // Try to read response
    let data = match sigil_core::read_message(&mut stream) {
        Ok(d) => d,
        Err(_) => return Ok(false),
    };

    // Check if response is valid
    let response: sigil_core::IpcResponse = match serde_json::from_slice(&data) {
        Ok(r) => r,
        Err(_) => return Ok(false),
    };

    Ok(response.ok)
}

/// Check vault status
fn check_vault(sigil_dir: &Path, report: &mut TroubleshootReport) -> Result<()> {
    let vault_path = sigil_dir.join("vault");
    let identity_path = sigil_dir.join("identity.age");

    if !sigil_dir.exists() {
        report.add(TroubleshootCheck {
            category: "vault".to_string(),
            name: "Vault initialized".to_string(),
            status: TroubleshootStatus::Fail {
                error: "SIGIL directory not found".to_string(),
                remediation: vec![
                    "Initialize the vault: sigil init".to_string(),
                    "Or run quickstart: sigil quickstart".to_string(),
                ],
            },
            detail: format!("{} not found", sigil_dir.display()),
        });
        return Ok(());
    }

    if !vault_path.exists() || !identity_path.exists() {
        report.add(TroubleshootCheck {
            category: "vault".to_string(),
            name: "Vault initialized".to_string(),
            status: TroubleshootStatus::Fail {
                error: "Vault not properly initialized".to_string(),
                remediation: vec![
                    "Initialize the vault: sigil init".to_string(),
                    format!(
                        "Expected: {} and {}",
                        vault_path.display(),
                        identity_path.display()
                    ),
                ],
            },
            detail: "Vault directory or identity file missing".to_string(),
        });
        return Ok(());
    }

    // Try to load the vault to check if it's unsealed
    match sigil_vault::LocalVault::new(vault_path.clone(), identity_path) {
        Ok(_vault) => {
            // Count secrets
            let secret_count = count_secrets(&vault_path);
            report.add(TroubleshootCheck {
                category: "vault".to_string(),
                name: "Vault unsealed".to_string(),
                status: TroubleshootStatus::Pass {
                    info: Some(format!("{} secrets loaded", secret_count)),
                },
                detail: format!("Vault at {}", vault_path.display()),
            });
        }
        Err(e) => {
            report.add(TroubleshootCheck {
                category: "vault".to_string(),
                name: "Vault unsealed".to_string(),
                status: TroubleshootStatus::Fail {
                    error: format!("Failed to load vault: {}", e),
                    remediation: vec![
                        "Verify the vault passphrase is correct".to_string(),
                        "Check vault file permissions".to_string(),
                        "Try: sigil doctor --fix".to_string(),
                    ],
                },
                detail: "Vault exists but could not be loaded".to_string(),
            });
        }
    }

    Ok(())
}

/// Count secrets in the vault
fn count_secrets(vault_path: &Path) -> usize {
    fs::read_dir(vault_path)
        .map(|entries| {
            entries
                .filter_map(|e| e.ok())
                .filter(|e| e.path().extension() == Some(std::ffi::OsStr::new("age")))
                .count()
        })
        .unwrap_or(0)
}

/// Check sandbox with active test
fn check_sandbox(report: &mut TroubleshootReport, verbose: bool) -> Result<()> {
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
        report.add(TroubleshootCheck {
            category: "sandbox".to_string(),
            name: "bubblewrap installed".to_string(),
            status: TroubleshootStatus::Fail {
                error: "bubblewrap not found".to_string(),
                remediation: vec![
                    "Install bubblewrap:".to_string(),
                    "  Debian/Ubuntu: apt install bubblewrap".to_string(),
                    "  Fedora/RHEL: dnf install bubblewrap".to_string(),
                    "  Arch: pacman -S bubblewrap".to_string(),
                    "  macOS: Sandbox uses sandbox-exec (seatbelt)".to_string(),
                ],
            },
            detail: "Sandbox unavailable without bubblewrap".to_string(),
        });
        return Ok(());
    }

    // Get bubblewrap version
    let bwrap_version = Command::new("bwrap")
        .arg("--version")
        .output()
        .ok()
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .unwrap_or_else(|| "unknown".to_string());

    report.add(TroubleshootCheck {
        category: "sandbox".to_string(),
        name: "bubblewrap installed".to_string(),
        status: TroubleshootStatus::Pass {
            info: Some(bwrap_version.trim().to_string()),
        },
        detail: "bubblewrap found".to_string(),
    });

    // Check namespace support
    let user_ns = check_namespace_support("user");
    let pid_ns = check_namespace_support("pid");
    let net_ns = check_namespace_support("net");

    if !user_ns || !pid_ns || !net_ns {
        let missing = vec![
            (!user_ns).then_some("user"),
            (!pid_ns).then_some("pid"),
            (!net_ns).then_some("net"),
        ]
        .into_iter()
        .flatten()
        .collect::<Vec<_>>()
        .join(", ");

        report.add(TroubleshootCheck {
            category: "sandbox".to_string(),
            name: "Namespace support".to_string(),
            status: TroubleshootStatus::Fail {
                error: format!("Missing namespaces: {}", missing),
                remediation: vec![
                    "Check kernel configuration:".to_string(),
                    "  cat /proc/sys/kernel/unprivileged_userns_clone".to_string(),
                    "  Enable with: sysctl -w kernel.unprivileged_userns_clone=1".to_string(),
                    "  Persist with: echo 'kernel.unprivileged_userns_clone=1' >> /etc/sysctl.conf"
                        .to_string(),
                ],
            },
            detail: "Namespace support required for full isolation".to_string(),
        });
        return Ok(());
    }

    report.add(TroubleshootCheck {
        category: "sandbox".to_string(),
        name: "Namespace support".to_string(),
        status: TroubleshootStatus::Pass {
            info: Some("user, pid, net namespaces available".to_string()),
        },
        detail: "All required namespaces are available".to_string(),
    });

    // Active test: run a command in sandbox
    let test_result = test_sandbox_execution(verbose);

    match test_result {
        Ok(success) if success => {
            report.add(TroubleshootCheck {
                category: "sandbox".to_string(),
                name: "Test sandbox".to_string(),
                status: TroubleshootStatus::Pass {
                    info: Some("echo test executed in namespace".to_string()),
                },
                detail: "Successfully ran test command in isolated namespace".to_string(),
            });
        }
        Ok(_) => {
            report.add(TroubleshootCheck {
                category: "sandbox".to_string(),
                name: "Test sandbox".to_string(),
                status: TroubleshootStatus::Fail {
                    error: "Sandbox test failed".to_string(),
                    remediation: vec![
                        "Check bwrap installation: bwrap --version".to_string(),
                        "Try running bwrap manually: bwrap /bin/echo test".to_string(),
                        "Check for AppArmor/SELinux conflicts".to_string(),
                    ],
                },
                detail: "Test command did not execute successfully".to_string(),
            });
        }
        Err(e) => {
            report.add(TroubleshootCheck {
                category: "sandbox".to_string(),
                name: "Test sandbox".to_string(),
                status: TroubleshootStatus::Fail {
                    error: format!("Sandbox test error: {}", e),
                    remediation: vec![
                        "Check bubblewrap is installed and working".to_string(),
                        "Verify user namespace support".to_string(),
                        "Try: bwrap --ro-bind / / /bin/echo test".to_string(),
                    ],
                },
                detail: "Could not execute test command".to_string(),
            });
        }
    }

    Ok(())
}

/// Check if a specific namespace type is supported
fn check_namespace_support(ns_type: &str) -> bool {
    #[cfg(target_os = "linux")]
    {
        // Try to unshare the namespace
        Command::new("unshare")
            .arg(format!("--{}", ns_type))
            .arg("true")
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false)
    }

    #[cfg(not(target_os = "linux"))]
    {
        let _ = ns_type;
        false
    }
}

/// Test sandbox execution by running a simple command
fn test_sandbox_execution(_verbose: bool) -> Result<bool> {
    #[cfg(target_os = "linux")]
    {
        use std::os::unix::process::CommandExt;

        // Try to run echo in a minimal sandbox
        let result = Command::new("bwrap")
            .args([
                "--ro-bind",
                "/",
                "/",
                "--dev",
                "/dev",
                "--proc",
                "/proc",
                "echo",
                "test",
            ])
            .process_group(0)
            .output();

        match result {
            Ok(output) => Ok(output.status.success()),
            Err(e) => Err(e.into()),
        }
    }

    #[cfg(not(target_os = "linux"))]
    {
        let _ = _verbose;
        Ok(false)
    }
}

/// Check hooks installation
fn check_hooks(_sigil_dir: &Path, report: &mut TroubleshootReport) -> Result<()> {
    let claude_settings = dirs::home_dir()
        .ok_or_else(|| anyhow::anyhow!("Cannot determine home directory"))?
        .join(".claude")
        .join("settings.json");

    if !claude_settings.exists() {
        report.add(TroubleshootCheck {
            category: "hooks".to_string(),
            name: "Claude Code hooks".to_string(),
            status: TroubleshootStatus::Warn {
                message: "Claude Code settings not found".to_string(),
                suggestion: "Install hooks: sigil setup claude-code".to_string(),
            },
            detail: format!("{} not found", claude_settings.display()),
        });
        return Ok(());
    }

    // Check if settings.json is valid JSON
    let content = fs::read_to_string(&claude_settings)?;
    match serde_json::from_str::<serde_json::Value>(&content) {
        Ok(_) => {
            report.add(TroubleshootCheck {
                category: "hooks".to_string(),
                name: "Settings.json valid".to_string(),
                status: TroubleshootStatus::Pass { info: None },
                detail: format!("Found at {}", claude_settings.display()),
            });
        }
        Err(e) => {
            report.add(TroubleshootCheck {
                category: "hooks".to_string(),
                name: "Settings.json valid".to_string(),
                status: TroubleshootStatus::Fail {
                    error: format!("Invalid JSON: {}", e),
                    remediation: vec![
                        "Check settings.json syntax: cat ~/.claude/settings.json | jq".to_string(),
                        "Restore from backup if available".to_string(),
                        "Re-run setup: sigil setup claude-code".to_string(),
                    ],
                },
                detail: "Settings file exists but contains invalid JSON".to_string(),
            });
            return Ok(());
        }
    }

    // Check for SIGIL hooks in settings
    let has_hooks = content.contains("sigil hook") || content.contains("sigil-hook");

    if !has_hooks {
        report.add(TroubleshootCheck {
            category: "hooks".to_string(),
            name: "SIGIL hooks installed".to_string(),
            status: TroubleshootStatus::Warn {
                message: "SIGIL hooks not found in settings".to_string(),
                suggestion: "Install hooks: sigil setup claude-code".to_string(),
            },
            detail: "Settings.json exists but no SIGIL hooks detected".to_string(),
        });
    } else {
        report.add(TroubleshootCheck {
            category: "hooks".to_string(),
            name: "SIGIL hooks installed".to_string(),
            status: TroubleshootStatus::Pass { info: None },
            detail: "Found SIGIL hook references in settings.json".to_string(),
        });
    }

    Ok(())
}

/// Check file permissions
fn check_permissions(sigil_dir: &Path, report: &mut TroubleshootReport) -> Result<()> {
    let vault_path = sigil_dir.join("vault");
    let identity_path = sigil_dir.join("identity.age");

    // Check vault directory permissions
    if vault_path.exists() {
        let metadata = fs::metadata(&vault_path)?;
        let mode = metadata.permissions().mode();
        let correct_perms = (mode & 0o777) == 0o700;

        if !correct_perms {
            report.add(TroubleshootCheck {
                category: "permissions".to_string(),
                name: "Vault directory".to_string(),
                status: TroubleshootStatus::Warn {
                    message: format!("Vault has incorrect permissions: {:04o}", mode & 0o777),
                    suggestion: format!("Fix with: chmod 700 {}", vault_path.display()),
                },
                detail: "Expected 0700 (owner read/write/execute only)".to_string(),
            });
        } else {
            report.add(TroubleshootCheck {
                category: "permissions".to_string(),
                name: "Vault directory".to_string(),
                status: TroubleshootStatus::Pass {
                    info: Some("0700".to_string()),
                },
                detail: "Correct permissions".to_string(),
            });
        }
    }

    // Check identity file permissions
    if identity_path.exists() {
        let metadata = fs::metadata(&identity_path)?;
        let mode = metadata.permissions().mode();
        let correct_perms = (mode & 0o777) == 0o400 || (mode & 0o777) == 0o600;

        if !correct_perms {
            report.add(TroubleshootCheck {
                category: "permissions".to_string(),
                name: "Device key".to_string(),
                status: TroubleshootStatus::Warn {
                    message: format!(
                        "Identity file has incorrect permissions: {:04o}",
                        mode & 0o777
                    ),
                    suggestion: format!("Fix with: chmod 600 {}", identity_path.display()),
                },
                detail: "Expected 0600 or 0400 (owner read/write or read only)".to_string(),
            });
        } else {
            report.add(TroubleshootCheck {
                category: "permissions".to_string(),
                name: "Device key".to_string(),
                status: TroubleshootStatus::Pass {
                    info: Some(format!("{:04o}", mode & 0o777)),
                },
                detail: "Correct permissions".to_string(),
            });
        }
    }

    // Check socket permissions (already covered in daemon check)

    // Check audit log exists
    let audit_path = sigil_dir.join("audit.jsonl");
    if audit_path.exists() {
        report.add(TroubleshootCheck {
            category: "permissions".to_string(),
            name: "Audit log".to_string(),
            status: TroubleshootStatus::Pass {
                info: Some("Append-only recommended".to_string()),
            },
            detail: format!("Found at {}", audit_path.display()),
        });

        #[cfg(target_os = "linux")]
        {
            // Try to check append-only flag using chattr
            let check_result = Command::new("lsattr").arg("-l").arg(&audit_path).output();

            if let Ok(output) = check_result {
                let output_str = String::from_utf8_lossy(&output.stdout);
                if output_str.contains('a') {
                    report.add(TroubleshootCheck {
                        category: "permissions".to_string(),
                        name: "Audit log append-only".to_string(),
                        status: TroubleshootStatus::Pass { info: None },
                        detail: "Append-only flag set (a)".to_string(),
                    });
                } else {
                    report.add(TroubleshootCheck {
                        category: "permissions".to_string(),
                        name: "Audit log append-only".to_string(),
                        status: TroubleshootStatus::Warn {
                            message: "Audit log does not have append-only flag".to_string(),
                            suggestion: "Enable with: chattr +a ~/.sigil/audit.jsonl".to_string(),
                        },
                        detail: "Append-only flag prevents audit log tampering".to_string(),
                    });
                }
            }
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_troubleshoot_report_new() {
        let report = TroubleshootReport::new();
        assert!(report.checks.is_empty());
        assert!(report.overall_success);
    }

    #[test]
    fn test_troubleshoot_report_default() {
        let report = TroubleshootReport::default();
        assert!(report.checks.is_empty());
        assert!(report.overall_success);
    }

    #[test]
    fn test_troubleshoot_report_add_pass() {
        let mut report = TroubleshootReport::new();
        report.add(TroubleshootCheck {
            category: "test".to_string(),
            name: "test_check".to_string(),
            status: TroubleshootStatus::Pass {
                info: Some("info".to_string()),
            },
            detail: "detail".to_string(),
        });
        assert_eq!(report.checks.len(), 1);
        assert!(report.overall_success);
    }

    #[test]
    fn test_troubleshoot_report_add_warn() {
        let mut report = TroubleshootReport::new();
        report.add(TroubleshootCheck {
            category: "test".to_string(),
            name: "test_check".to_string(),
            status: TroubleshootStatus::Warn {
                message: "warning".to_string(),
                suggestion: "fix it".to_string(),
            },
            detail: "detail".to_string(),
        });
        assert_eq!(report.checks.len(), 1);
        assert!(!report.overall_success);
    }

    #[test]
    fn test_troubleshoot_report_add_fail() {
        let mut report = TroubleshootReport::new();
        report.add(TroubleshootCheck {
            category: "test".to_string(),
            name: "test_check".to_string(),
            status: TroubleshootStatus::Fail {
                error: "error".to_string(),
                remediation: vec!["step 1".to_string(), "step 2".to_string()],
            },
            detail: "detail".to_string(),
        });
        assert_eq!(report.checks.len(), 1);
        assert!(!report.overall_success);
    }

    #[test]
    fn test_troubleshoot_report_add_multiple_pass() {
        let mut report = TroubleshootReport::new();
        report.add(TroubleshootCheck {
            category: "test1".to_string(),
            name: "check1".to_string(),
            status: TroubleshootStatus::Pass { info: None },
            detail: "detail1".to_string(),
        });
        report.add(TroubleshootCheck {
            category: "test2".to_string(),
            name: "check2".to_string(),
            status: TroubleshootStatus::Pass {
                info: Some("info".to_string()),
            },
            detail: "detail2".to_string(),
        });
        assert_eq!(report.checks.len(), 2);
        assert!(report.overall_success);
    }

    #[test]
    fn test_troubleshoot_report_format_pass() {
        let mut report = TroubleshootReport::new();
        report.add(TroubleshootCheck {
            category: "daemon".to_string(),
            name: "Socket exists".to_string(),
            status: TroubleshootStatus::Pass {
                info: Some("/run/sigil.sock".to_string()),
            },
            detail: "Socket found at /run/sigil.sock".to_string(),
        });

        let output = report.format();
        assert!(output.contains("SIGIL Troubleshoot"));
        assert!(output.contains("daemon"));
        assert!(output.contains("Socket exists"));
        assert!(output.contains("PASS"));
        assert!(output.contains("/run/sigil.sock"));
    }

    #[test]
    fn test_troubleshoot_report_format_warn() {
        let mut report = TroubleshootReport::new();
        report.add(TroubleshootCheck {
            category: "vault".to_string(),
            name: "Vault initialized".to_string(),
            status: TroubleshootStatus::Warn {
                message: "Vault not found".to_string(),
                suggestion: "Run sigil init".to_string(),
            },
            detail: "~/.sigil/vault does not exist".to_string(),
        });

        let output = report.format();
        assert!(output.contains("SIGIL Troubleshoot"));
        assert!(output.contains("vault"));
        assert!(output.contains("Vault initialized"));
        assert!(output.contains("WARN"));
        assert!(output.contains("Suggestion:"));
        assert!(output.contains("Run sigil init"));
    }

    #[test]
    fn test_troubleshoot_report_format_fail() {
        let mut report = TroubleshootReport::new();
        report.add(TroubleshootCheck {
            category: "sandbox".to_string(),
            name: "Namespace support".to_string(),
            status: TroubleshootStatus::Fail {
                error: "Missing user namespace".to_string(),
                remediation: vec![
                    "Enable user namespaces".to_string(),
                    "Check kernel config".to_string(),
                ],
            },
            detail: "user namespace not available".to_string(),
        });

        let output = report.format();
        assert!(output.contains("SIGIL Troubleshoot"));
        assert!(output.contains("sandbox"));
        assert!(output.contains("Namespace support"));
        assert!(output.contains("FAIL"));
        assert!(output.contains("Missing user namespace"));
        assert!(output.contains("1. Enable user namespaces"));
        assert!(output.contains("2. Check kernel config"));
    }

    #[test]
    fn test_troubleshoot_report_format_success_summary() {
        let mut report = TroubleshootReport::new();
        report.add(TroubleshootCheck {
            category: "daemon".to_string(),
            name: "test".to_string(),
            status: TroubleshootStatus::Pass { info: None },
            detail: "detail".to_string(),
        });

        let output = report.format();
        assert!(output.contains("All checks passed"));
        assert!(output.contains("sigil doctor --debug"));
    }

    #[test]
    fn test_troubleshoot_report_format_failure_summary() {
        let mut report = TroubleshootReport::new();
        report.add(TroubleshootCheck {
            category: "daemon".to_string(),
            name: "test".to_string(),
            status: TroubleshootStatus::Fail {
                error: "error".to_string(),
                remediation: vec![],
            },
            detail: "detail".to_string(),
        });

        let output = report.format();
        assert!(output.contains("Some checks failed"));
        assert!(output.contains("Follow the remediation steps"));
    }

    #[test]
    fn test_troubleshoot_status_pass_with_info() {
        let status = TroubleshootStatus::Pass {
            info: Some("additional info".to_string()),
        };
        match status {
            TroubleshootStatus::Pass { info } => {
                assert_eq!(info, Some("additional info".to_string()));
            }
            _ => panic!("Expected Pass status"),
        }
    }

    #[test]
    fn test_troubleshoot_status_pass_without_info() {
        let status = TroubleshootStatus::Pass { info: None };
        match status {
            TroubleshootStatus::Pass { info } => {
                assert!(info.is_none());
            }
            _ => panic!("Expected Pass status"),
        }
    }

    #[test]
    fn test_troubleshoot_status_warn() {
        let status = TroubleshootStatus::Warn {
            message: "warning message".to_string(),
            suggestion: "suggested action".to_string(),
        };
        match status {
            TroubleshootStatus::Warn {
                message,
                suggestion,
            } => {
                assert_eq!(message, "warning message");
                assert_eq!(suggestion, "suggested action");
            }
            _ => panic!("Expected Warn status"),
        }
    }

    #[test]
    fn test_troubleshoot_status_fail() {
        let status = TroubleshootStatus::Fail {
            error: "error message".to_string(),
            remediation: vec!["step 1".to_string(), "step 2".to_string()],
        };
        match status {
            TroubleshootStatus::Fail { error, remediation } => {
                assert_eq!(error, "error message");
                assert_eq!(remediation.len(), 2);
                assert_eq!(remediation[0], "step 1");
                assert_eq!(remediation[1], "step 2");
            }
            _ => panic!("Expected Fail status"),
        }
    }

    #[test]
    fn test_troubleshoot_check_creation() {
        let check = TroubleshootCheck {
            category: "test_category".to_string(),
            name: "test_name".to_string(),
            status: TroubleshootStatus::Pass { info: None },
            detail: "test_detail".to_string(),
        };

        assert_eq!(check.category, "test_category");
        assert_eq!(check.name, "test_name");
        assert_eq!(check.detail, "test_detail");
    }

    #[test]
    fn test_multiple_categories_in_report() {
        let mut report = TroubleshootReport::new();
        report.add(TroubleshootCheck {
            category: "daemon".to_string(),
            name: "check1".to_string(),
            status: TroubleshootStatus::Pass { info: None },
            detail: "detail1".to_string(),
        });
        report.add(TroubleshootCheck {
            category: "vault".to_string(),
            name: "check2".to_string(),
            status: TroubleshootStatus::Pass { info: None },
            detail: "detail2".to_string(),
        });
        report.add(TroubleshootCheck {
            category: "sandbox".to_string(),
            name: "check3".to_string(),
            status: TroubleshootStatus::Pass { info: None },
            detail: "detail3".to_string(),
        });

        assert_eq!(report.checks.len(), 3);
        assert!(report.overall_success);

        let output = report.format();
        assert!(output.contains("daemon"));
        assert!(output.contains("vault"));
        assert!(output.contains("sandbox"));
    }

    #[test]
    fn test_overall_success_with_mixed_statuses() {
        let mut report = TroubleshootReport::new();
        report.add(TroubleshootCheck {
            category: "daemon".to_string(),
            name: "check1".to_string(),
            status: TroubleshootStatus::Pass { info: None },
            detail: "detail1".to_string(),
        });
        // A warn should make overall_success false
        report.add(TroubleshootCheck {
            category: "vault".to_string(),
            name: "check2".to_string(),
            status: TroubleshootStatus::Warn {
                message: "warning".to_string(),
                suggestion: "fix".to_string(),
            },
            detail: "detail2".to_string(),
        });

        assert!(!report.overall_success);
    }

    #[test]
    fn test_remediation_steps_ordering() {
        let status = TroubleshootStatus::Fail {
            error: "error".to_string(),
            remediation: vec![
                "first step".to_string(),
                "second step".to_string(),
                "third step".to_string(),
            ],
        };

        match status {
            TroubleshootStatus::Fail { remediation, .. } => {
                assert_eq!(remediation[0], "first step");
                assert_eq!(remediation[1], "second step");
                assert_eq!(remediation[2], "third step");
            }
            _ => panic!("Expected Fail status"),
        }
    }

    #[test]
    fn test_empty_remediation_steps() {
        let status = TroubleshootStatus::Fail {
            error: "error".to_string(),
            remediation: vec![],
        };

        match status {
            TroubleshootStatus::Fail { remediation, .. } => {
                assert!(remediation.is_empty());
            }
            _ => panic!("Expected Fail status"),
        }
    }

    #[test]
    fn test_format_with_newline_handling() {
        let mut report = TroubleshootReport::new();
        report.add(TroubleshootCheck {
            category: "test".to_string(),
            name: "line\nbreak".to_string(),
            status: TroubleshootStatus::Pass { info: None },
            detail: "detail with\nnewline".to_string(),
        });

        let output = report.format();
        // The format function should handle newlines in names/details
        assert!(output.contains("SIGIL Troubleshoot"));
    }
}
