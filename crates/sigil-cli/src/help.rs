//! Help command for displaying long-form documentation
//!
//! Topic files are compiled into the binary at build time using include_str!().
//! The same source files serve double duty:
//! 1. Compiled into the binary for `sigil help <topic>` (this module)
//! 2. Rendered on the documentation site at docs/sigil.rs

use anyhow::{bail, Result};

/// Available help topics
pub const TOPICS: &[(&str, &str)] = &[
    ("sigil", "SIGIL overview and getting started"),
    ("vault", "Secret vault management and encryption"),
    (
        "placeholders",
        "Using {{secret:path}} placeholders in commands",
    ),
    ("hooks", "Claude Code hook integration"),
    ("migrate", "Data format migration"),
    ("security", "Security best practices and threat model"),
    ("team", "Team collaboration with sealed vaults"),
    ("sandbox", "Sandbox execution engine"),
    ("ci", "CI/CD integration"),
];

// Topic files are compiled into the binary at build time
// These are the same source files used for the documentation site
const TOPIC_SIGIL: &str = include_str!("../../../docs/topics/sigil.md");
const TOPIC_VAULT: &str = include_str!("../../../docs/topics/vault.md");
const TOPIC_PLACEHOLDERS: &str = include_str!("../../../docs/topics/placeholders.md");
const TOPIC_HOOKS: &str = include_str!("../../../docs/topics/hooks.md");
const TOPIC_MIGRATE: &str = include_str!("../../../docs/topics/migrate.md");
const TOPIC_SECURITY: &str = include_str!("../../../docs/topics/security.md");
const TOPIC_TEAM: &str = include_str!("../../../docs/topics/team.md");
const TOPIC_SANDBOX: &str = include_str!("../../../docs/topics/sandbox.md");
const TOPIC_CI: &str = include_str!("../../../docs/topics/ci.md");

/// Get the list of available help topics
#[allow(dead_code)]
pub fn list_topics() -> Vec<String> {
    TOPICS.iter().map(|(name, _)| name.to_string()).collect()
}

/// Display help for a specific topic
pub fn show_topic(topic: &str) -> Result<()> {
    // Check if the topic exists
    let _topic_desc = TOPICS
        .iter()
        .find(|(name, _)| *name == topic)
        .map(|(_, desc)| *desc);

    let _topic_desc = match _topic_desc {
        Some(desc) => desc,
        None => {
            show_available_topics();
            bail!(
                "Unknown topic '{}'. Available topics: {}",
                topic,
                TOPICS
                    .iter()
                    .map(|(name, _)| *name)
                    .collect::<Vec<_>>()
                    .join(", ")
            );
        }
    };

    // Get the topic content from the compiled-in files
    let topic_content = get_topic_content(topic)?;

    println!("{}", topic_content);
    println!();
    println!("For more information, see: https://docs.sigil.rs");

    Ok(())
}

/// Show available help topics
fn show_available_topics() {
    println!("Available help topics:");
    for (name, desc) in TOPICS {
        println!("  {:12} - {}", name, desc);
    }
}

/// Get topic content from the compiled-in topic files
fn get_topic_content(topic: &str) -> Result<String> {
    let content = match topic {
        "sigil" => TOPIC_SIGIL,
        "vault" => TOPIC_VAULT,
        "placeholders" => TOPIC_PLACEHOLDERS,
        "hooks" => TOPIC_HOOKS,
        "migrate" => TOPIC_MIGRATE,
        "security" => TOPIC_SECURITY,
        "team" => TOPIC_TEAM,
        "sandbox" => TOPIC_SANDBOX,
        "ci" => TOPIC_CI,
        _ => {
            bail!(
                "Topic '{}' not found. This should not happen - please report this bug.",
                topic
            );
        }
    };

    Ok(content.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_list_topics() {
        let topics = list_topics();
        assert!(!topics.is_empty());
        assert!(topics.contains(&"vault".to_string()));
    }

    #[test]
    fn test_get_topic_content() {
        let help = get_topic_content("vault").unwrap();
        // The actual topic content from vault.md
        assert!(help.contains("SIGIL stores secrets"));
    }

    #[test]
    fn test_all_topics_available() {
        // Ensure all topics can be loaded
        for (topic_name, _) in TOPICS {
            let content = get_topic_content(topic_name);
            assert!(
                content.is_ok(),
                "Topic '{}' should be available",
                topic_name
            );
            let content = content.unwrap();
            assert!(
                !content.is_empty(),
                "Topic '{}' should have content",
                topic_name
            );
        }
    }
}
