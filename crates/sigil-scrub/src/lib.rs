//! SIGIL Scrub - Output scrubber for detecting and redacting secrets

#![warn(missing_docs)]
#![warn(clippy::all)]

pub mod patterns;
pub mod scrubber;

pub use patterns::{
    builtin_patterns, CredentialCategory, PatternDetector, PatternMatch, PatternRule,
};
pub use scrubber::{ScrubResult, Scrubber, StreamingScrubber};
