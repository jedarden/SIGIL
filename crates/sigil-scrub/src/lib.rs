//! SIGIL Scrub - Output scrubber for detecting and redacting secrets

#![warn(missing_docs)]
#![warn(clippy::all)]

pub mod patterns;
pub mod scrubber;

pub use patterns::{CredentialCategory, PatternDetector, PatternMatch, PatternRule, builtin_patterns};
pub use scrubber::{ScrubResult, Scrubber, StreamingScrubber};
