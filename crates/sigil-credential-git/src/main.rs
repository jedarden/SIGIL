//! SIGIL Git Credential Helper Binary
//!
//! This binary is invoked by Git to retrieve credentials for HTTPS remotes.
//!
//! # Installation
//!
//! ```bash
//! sigil setup git
//! ```
//!
//! This configures git to use `sigil-credential-git` as the credential helper.
//!
//! # Usage
//!
//! Git automatically invokes this binary. Direct invocation:
//!
//! ```bash
//! echo -e "protocol=https\nhost=github.com\n\n" | sigil-credential-git get
//! ```

use anyhow::Result;

fn main() -> Result<()> {
    // Get the subcommand from args (default to "get")
    let args: Vec<String> = std::env::args().collect();
    let subcommand = args.get(1).map(|s| s.as_str()).unwrap_or("get");

    sigil_credential_git::GitCredentialHelper::run(subcommand)
}
