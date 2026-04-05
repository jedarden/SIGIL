//! SIGIL Scrub - Output scrubber for detecting and redacting secrets

#![warn(missing_docs)]
#![warn(clippy::all)]

pub mod scrubber;

pub use scrubber::{ScrubResult, Scrubber, StreamingScrubber};
