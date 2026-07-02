//! Common utilities for SIGIL integration tests

use std::path::PathBuf;

/// Get the workspace root directory
pub fn workspace_root() -> PathBuf {
    let manifest_dir = std::env::var("CARGO_MANIFEST_DIR").unwrap();
    PathBuf::from(manifest_dir)
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .to_path_buf()
}

/// Get the path to a crate's source file
#[allow(dead_code)]
pub fn crate_source_path(crate_name: &str, file: &str) -> PathBuf {
    workspace_root()
        .join("crates")
        .join(crate_name)
        .join("src")
        .join(file)
}
