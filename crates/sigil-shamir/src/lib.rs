//! SIGIL Shamir's Secret Sharing with SLIP39
//!
//! This crate implements Shamir's Secret Sharing (SSS) with SLIP39 mnemonic encoding
//! for SIGIL's team vault feature. It allows splitting a master key into M-of-N shares
//! where any M shares can reconstruct the original secret.
//!
//! # Features
//!
//! - M-of-N threshold secret sharing (M ≥ 2, N ≤ 16)
//! - SLIP39 mnemonic encoding (BIP39 wordlist extended)
//! - Share integrity verification with checksums
//! - Share rotation without changing master key
//! - Group support for complex sharing schemes
//!
//! # Example
//!
//! ```rust
//! use sigil_shamir::{ShamirSecretSharing, Share};
//!
//! let sss = ShamirSecretSharing::new();
//!
//! // Split a 256-bit master key into 5 shares, requiring 3 to reconstruct
//! let master_key = [0u8; 32];
//! let shares = sss.split(&master_key, 3, 5).unwrap();
//!
//! // Reconstruct with any 3 shares
//! let reconstructed = sss.combine(&shares[0..3]).unwrap();
//! assert_eq!(reconstructed, master_key);
//!
//! // Encode as SLIP39 mnemonics
//! let mnemonic = shares[0].to_mnemonic().unwrap();
//! println!("Share 1: {}", mnemonic);
//!
//! // Decode from mnemonic
//! let decoded = Share::from_mnemonic(&mnemonic).unwrap();
//! ```

#![warn(missing_docs)]
#![warn(clippy::all)]

pub mod slip39;
mod sss;

pub use sss::{ShamirError, ShamirSecretSharing, Share};

/// Maximum number of shares (N)
pub const MAX_SHARES: usize = 16;

/// Minimum threshold (M)
pub const MIN_THRESHOLD: usize = 2;

/// Default wordlist for SLIP39 (BIP39 English wordlist)
pub const SLIP39_WORDLIST: &str = include_str!("wordlist.txt");

/// Result type for Shamir operations
pub type Result<T> = std::result::Result<T, ShamirError>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_constants() {
        assert_eq!(MAX_SHARES, 16, "MAX_SHARES should be 16");
        assert_eq!(MIN_THRESHOLD, 2, "MIN_THRESHOLD should be 2");
        const _: () = assert!(
            MIN_THRESHOLD <= MAX_SHARES,
            "MIN_THRESHOLD should not exceed MAX_SHARES"
        );
    }
}
