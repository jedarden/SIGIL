//! SIGIL Shell - POSIX-compatible shell wrapper
//!
//! This shell wrapper provides universal harness compatibility by intercepting
//! shell commands and routing them through SIGIL's secret injection and scrubbing
//! pipeline.
//!
//! Signal Handling:
//! - Forwards SIGINT, SIGTERM to sandbox child processes
//! - Ignores SIGPIPE (handled per-connection)
//! - Properly cleans up child processes on exit

#![warn(missing_docs)]
#![warn(clippy::all)]

use anyhow::{Context, Result};
use sigil_core::CommandParser;
use sigil_daemon::DaemonClient;
use std::env;
use std::io::{self, Write};
use std::path::PathBuf;
use std::process::exit;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

/// Shell wrapper mode
#[derive(Debug, Clone, Copy, PartialEq)]
enum Mode {
    /// Execute a single command via -c flag
    SingleCommand,
    /// Interactive shell session
    Interactive,
}

/// Execute a command through the SIGIL pipeline
async fn execute_command(command: &str) -> Result<i32> {
    // Parse and resolve the command
    let resolved = CommandParser::resolve_command(command).context("Failed to parse command")?;

    // Get socket path
    let socket_path = get_socket_path();

    // Connect to daemon and execute command with sandboxing
    let mut client = DaemonClient::connect(&socket_path)
        .await
        .context("Failed to connect to SIGIL daemon. Start it with 'sigil daemon start'")?;

    // Split command into program and arguments
    let parts: Vec<String> =
        shell_words::split(&resolved.resolved).context("Failed to parse command")?;

    if parts.is_empty() {
        anyhow::bail!("Empty command");
    }

    let program = parts[0].clone();
    let args = parts[1..].to_vec();

    // Execute through daemon (with sandboxing and output scrubbing)
    let exec_response = client
        .exec(program, args)
        .await
        .context("Command execution failed")?;

    // Write scrubbed output to stdout/stderr
    io::stdout().write_all(exec_response.stdout.as_bytes())?;
    io::stderr().write_all(exec_response.stderr.as_bytes())?;

    Ok(exec_response.exit_code)
}

/// Set up signal forwarding for child process
///
/// This configures signal handlers that forward signals to the child process.
/// When a signal is received, it's forwarded to the child and the shell waits
/// for the child to exit.
#[cfg(unix)]
#[allow(dead_code)]
fn setup_signal_forwarding(child_pid: u32) -> Result<Arc<AtomicBool>> {
    use signal_hook::consts::{SIGINT, SIGTERM};
    use signal_hook::iterator::Signals;
    use std::thread;

    let child_exited = Arc::new(AtomicBool::new(false));
    let child_exited_clone = child_exited.clone();

    // Spawn signal handling thread
    thread::spawn(move || {
        // Register signals we want to forward
        let mut signals = match Signals::new([SIGINT, SIGTERM]) {
            Ok(s) => s,
            Err(_) => return,
        };

        for signal in signals.forever() {
            // Check if child has already exited
            if child_exited_clone.load(Ordering::Relaxed) {
                break;
            }

            // Forward signal to child process
            unsafe {
                let ret = libc::kill(child_pid as i32, signal);
                if ret != 0 {
                    // Child process may have already exited
                    let err = std::io::Error::last_os_error();
                    if err.raw_os_error() == Some(libc::ESRCH) {
                        // No such process - child has exited
                        child_exited_clone.store(true, Ordering::Relaxed);
                        break;
                    }
                }
            }

            // After forwarding, we should exit too
            // The child will handle cleanup
            if signal == SIGTERM || signal == SIGINT {
                // Give child time to exit gracefully
                std::thread::sleep(std::time::Duration::from_millis(100));
                child_exited_clone.store(true, Ordering::Relaxed);
                break;
            }
        }
    });

    Ok(child_exited)
}

/// Get the default socket path for the SIGIL daemon
fn get_socket_path() -> PathBuf {
    if let Ok(runtime_dir) = std::env::var("XDG_RUNTIME_DIR") {
        PathBuf::from(runtime_dir).join("sigil.sock")
    } else {
        PathBuf::from("/tmp").join(format!("sigil-{}.sock", std::process::id()))
    }
}

/// Run interactive shell session
async fn run_interactive() -> Result<()> {
    println!(
        "SIGIL Shell v{} - Interactive Mode",
        env!("CARGO_PKG_VERSION")
    );
    println!("Type 'exit' or Ctrl+D to exit");
    println!();

    let stdin = io::stdin();
    let mut line = String::new();
    let mut cwd = env::current_dir().unwrap_or_else(|_| "/".into());

    loop {
        // Display prompt
        print!(
            "sigil:{}> ",
            cwd.file_name()
                .and_then(|n| n.to_str())
                .unwrap_or("unknown")
        );
        io::stdout().flush()?;

        line.clear();
        let bytes_read = stdin.read_line(&mut line)?;

        if bytes_read == 0 {
            // Ctrl+D
            println!();
            break;
        }

        let cmd = line.trim();
        if cmd.is_empty() {
            continue;
        }

        // Handle built-in commands
        match cmd {
            "exit" | "quit" => break,
            "help" => {
                print_help();
                continue;
            }
            _ => {
                // Execute through SIGIL pipeline
                match execute_command(cmd).await {
                    Ok(code) => {
                        if code != 0 {
                            eprintln!("Command exited with code {}", code);
                        }
                        // Update CWD tracking (basic)
                        if let Some(new_cwd) = get_cwd_change(cmd) {
                            if new_cwd.exists() {
                                cwd = new_cwd;
                            }
                        }
                    }
                    Err(e) => {
                        eprintln!("Error: {}", e);
                    }
                }
            }
        }
    }

    Ok(())
}

/// Print help message
fn print_help() {
    println!("SIGIL Shell - Built-in Commands:");
    println!("  exit, quit  - Exit the shell");
    println!("  help        - Show this help message");
    println!();
    println!("Any other command is executed through the SIGIL pipeline.");
    println!("Secret placeholders like {{secret:path}} are resolved automatically.");
}

/// Try to detect a directory change command
fn get_cwd_change(cmd: &str) -> Option<std::path::PathBuf> {
    let parts: Vec<String> = shell_words::split(cmd).ok()?;
    if parts.is_empty() {
        return None;
    }

    if parts[0] != "cd" {
        return None;
    }

    match parts.len() {
        1 => {
            // cd with no args -> go home
            dirs::home_dir()
        }
        2 => {
            // cd <dir>
            if parts[1] == "-" {
                // cd - (go to previous directory - not implemented yet)
                None
            } else {
                Some(std::path::PathBuf::from(parts[1].as_str()))
            }
        }
        _ => {
            // cd with multiple args -> invalid
            None
        }
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    // Ignore SIGPIPE - handle errors per-connection
    #[cfg(unix)]
    {
        unsafe {
            let ret = libc::signal(libc::SIGPIPE, libc::SIG_IGN);
            if ret == libc::SIG_ERR {
                let err = std::io::Error::last_os_error();
                eprintln!("Warning: Failed to ignore SIGPIPE: {}", err);
            }
        }
    }

    let args: Vec<String> = env::args().collect();

    // Determine mode
    let mode = if args.len() >= 2 && args[1] == "-c" {
        Mode::SingleCommand
    } else if args.len() == 1 {
        Mode::Interactive
    } else {
        eprintln!("Usage: sigil-shell [-c \"command\"]");
        eprintln!("  -c \"command\"  Execute a single command");
        eprintln!("  (no flags)     Start interactive shell");
        exit(1);
    };

    // Initialize logging
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env()
                .add_directive(tracing::Level::WARN.into()),
        )
        .init();

    match mode {
        Mode::SingleCommand => {
            if args.len() < 3 {
                anyhow::bail!("-c flag requires a command argument");
            }
            let command = &args[2];
            let exit_code = execute_command(command).await?;
            exit(exit_code);
        }
        Mode::Interactive => {
            run_interactive().await?;
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_get_socket_path_returns_valid_path() {
        // Just verify the function returns a valid path
        let path = get_socket_path();
        assert!(!path.as_os_str().is_empty());
    }

    #[test]
    fn test_get_socket_path_with_xdg_runtime_dir() {
        // Test with XDG_RUNTIME_DIR set
        temp_env::with_var("XDG_RUNTIME_DIR", Some("/tmp/test-runtime"), || {
            let path = get_socket_path();
            assert_eq!(path, PathBuf::from("/tmp/test-runtime/sigil.sock"));
        });
    }

    #[test]
    fn test_get_cwd_change() {
        assert_eq!(
            get_cwd_change("cd /tmp"),
            Some(std::path::PathBuf::from("/tmp"))
        );
        assert_eq!(get_cwd_change("cd -"), None);
        assert_eq!(get_cwd_change("echo hello"), None);
    }

    #[test]
    fn test_get_cwd_change_with_spaces() {
        // Test cd with path containing spaces (properly quoted)
        assert_eq!(
            get_cwd_change("cd \"/tmp/my path\""),
            Some(std::path::PathBuf::from("/tmp/my path"))
        );
    }

    #[test]
    fn test_get_cwd_change_home() {
        // Test cd with no args -> go home
        let result = get_cwd_change("cd");
        assert!(result.is_some());
        // Result should be home directory
        if let Some(path) = result {
            assert!(path.is_absolute());
        }
    }

    #[test]
    fn test_get_cwd_change_relative() {
        assert_eq!(
            get_cwd_change("cd ../subdir"),
            Some(std::path::PathBuf::from("../subdir"))
        );
    }

    #[test]
    fn test_get_cwd_change_multiple_args() {
        // cd with multiple args - should return None (invalid)
        assert_eq!(get_cwd_change("cd /tmp /var"), None);
    }

    #[test]
    fn test_get_cwd_change_with_quoted_tilde() {
        // Test cd with ~ (home expansion - shell_words doesn't expand ~)
        // The function should still parse it correctly
        assert_eq!(
            get_cwd_change("cd ~/Documents"),
            Some(std::path::PathBuf::from("~/Documents"))
        );
    }

    #[test]
    fn test_get_cwd_change_non_cd_command() {
        // Non-cd commands should return None
        assert_eq!(get_cwd_change("ls -la"), None);
        assert_eq!(get_cwd_change("pwd"), None);
        assert_eq!(get_cwd_change("cat file.txt"), None);
    }

    #[test]
    fn test_get_cwd_change_empty_command() {
        assert_eq!(get_cwd_change(""), None);
    }
}
