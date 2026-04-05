//! SIGIL Shell - POSIX-compatible shell wrapper
//!
//! This shell wrapper provides universal harness compatibility by intercepting
//! shell commands and routing them through SIGIL's secret injection and scrubbing
//! pipeline.

#![warn(missing_docs)]
#![warn(clippy::all)]

use anyhow::{Context, Result};
use sigil_core::CommandParser;
use std::env;
use std::io::{self, Write};
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
fn execute_command(command: &str) -> Result<i32> {
    // Parse and resolve the command
    let resolved = CommandParser::resolve_command(command).context("Failed to parse command")?;

    // For now, execute without sandboxing (full sandbox requires daemon)
    // In production, this would connect to sigild via Unix socket
    let output = execute_plain(&resolved.resolved)?;

    // Write output to stdout
    io::stdout().write_all(output.stdout.as_bytes())?;
    io::stderr().write_all(output.stderr.as_bytes())?;

    Ok(output.exit_code)
}

/// Execute a plain command without sandboxing
fn execute_plain(command: &str) -> Result<CommandOutput> {
    use std::process::Command;

    let parts: Vec<String> =
        shell_words::split(command).map_err(|e| anyhow::anyhow!("Invalid command: {}", e))?;

    if parts.is_empty() {
        anyhow::bail!("Empty command");
    }

    let result = Command::new(&parts[0]).args(&parts[1..]).output()?;

    Ok(CommandOutput {
        stdout: String::from_utf8_lossy(&result.stdout).to_string(),
        stderr: String::from_utf8_lossy(&result.stderr).to_string(),
        exit_code: result.status.code().unwrap_or(1),
    })
}

/// Result of command execution
#[derive(Debug)]
struct CommandOutput {
    stdout: String,
    stderr: String,
    exit_code: i32,
}

/// Run interactive shell session
fn run_interactive() -> Result<()> {
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
                match execute_command(cmd) {
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

fn main() -> Result<()> {
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
            let exit_code = execute_command(command)?;
            exit(exit_code);
        }
        Mode::Interactive => {
            run_interactive()?;
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_execute_plain_simple() {
        let output = execute_plain("echo hello").unwrap();
        assert_eq!(output.stdout.trim(), "hello");
        assert_eq!(output.exit_code, 0);
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
