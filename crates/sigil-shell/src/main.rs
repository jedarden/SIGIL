//! SIGIL Shell - POSIX-compatible shell wrapper
//!
//! This shell wrapper provides universal harness compatibility by intercepting
//! shell commands and routing them through SIGIL's secret injection and scrubbing
//! pipeline.

#![warn(missing_docs)]
#![warn(clippy::all)]

use anyhow::{Context, Result};
use sigil_core::CommandParser;
use sigil_daemon::DaemonClient;
use std::env;
use std::io::{self, Write};
use std::path::PathBuf;
use std::process::exit;

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
    let parts: Vec<String> = shell_words::split(&resolved.resolved)
        .context("Failed to parse command")?;

    if parts.is_empty() {
        anyhow::bail!("Empty command");
    }

    let program = parts[0].clone();
    let args = parts[1..].to_vec();

    // Execute through daemon (with sandboxing and output scrubbing)
    let exec_response = client.exec(program, args).await.context("Command execution failed")?;

    // Write scrubbed output to stdout/stderr
    io::stdout().write_all(exec_response.stdout.as_bytes())?;
    io::stderr().write_all(exec_response.stderr.as_bytes())?;

    Ok(exec_response.exit_code)
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
    if parts.len() >= 2 && parts[0] == "cd" {
        let target = if parts.len() == 2 {
            // cd <dir>
            if parts[1] == "-" {
                // cd - (go to previous directory - not implemented yet)
                None
            } else {
                Some(std::path::PathBuf::from(parts[1].as_str()))
            }
        } else {
            // cd with no args -> go home
            dirs::home_dir()
        };
        target
    } else {
        None
    }
}

#[tokio::main]
async fn main() -> Result<()> {
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
    fn test_get_cwd_change() {
        assert_eq!(
            get_cwd_change("cd /tmp"),
            Some(std::path::PathBuf::from("/tmp"))
        );
        assert_eq!(get_cwd_change("cd -"), None);
        assert_eq!(get_cwd_change("echo hello"), None);
    }
}
