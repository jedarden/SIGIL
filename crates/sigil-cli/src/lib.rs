//! SIGIL CLI library - shared CLI functionality
//!
//! This library exposes CLI functionality that can be reused by other crates,
//! particularly the daemon for hook processing.

pub mod hooks;

// Re-export commonly used types from hooks
pub use hooks::{
    error_response, generate_claude_md_snippet, generate_hook_config, handle_post_tool_use,
    handle_pre_tool_use, handle_user_prompt_submit, PostToolUseInput, PostToolUseOutput,
    PreToolUseInput, PreToolUseOutput, ToolType, UserPromptSubmitInput, UserPromptSubmitOutput,
};
