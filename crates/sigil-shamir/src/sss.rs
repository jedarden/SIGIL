//! Shamir's Secret Sharing implementation
//!
//! This module implements Shamir's Secret Sharing (SSS) scheme using
//! GF(256) arithmetic. It allows splitting a secret into N shares where
//! any M shares can reconstruct the original secret.

use crate::{slip39, Result};
use rand::RngCore;

/// A Shamir share containing the secret data
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Share {
    /// Share index (1-based)
    pub index: u8,
    /// Threshold (number of shares needed to reconstruct)
    pub threshold: u8,
    /// Total number of shares
    pub total_shares: u8,
    /// Share data (encrypted secret fragment)
    pub data: Vec<u8>,
    /// Checksum for integrity verification
    pub checksum: [u8; 4],
}

impl Share {
    /// Create a new share
    pub fn new(index: u8, threshold: u8, total_shares: u8, data: Vec<u8>) -> Self {
        let checksum = Self::compute_checksum(index, threshold, &data);
        Self {
            index,
            threshold,
            total_shares,
            data,
            checksum,
        }
    }

    /// Compute checksum for share integrity verification
    fn compute_checksum(index: u8, threshold: u8, data: &[u8]) -> [u8; 4] {
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update([index, threshold]);
        hasher.update(data);
        let result = hasher.finalize();
        let mut checksum = [0u8; 4];
        checksum.copy_from_slice(&result[0..4]);
        checksum
    }

    /// Verify the share checksum
    pub fn verify(&self) -> bool {
        self.checksum == Self::compute_checksum(self.index, self.threshold, &self.data)
    }

    /// Encode the share as a SLIP39 mnemonic phrase
    pub fn to_mnemonic(&self) -> Result<String> {
        slip39::encode_share(self)
    }

    /// Decode a share from a SLIP39 mnemonic phrase
    pub fn from_mnemonic(mnemonic: &str) -> Result<Self> {
        slip39::decode_share(mnemonic)
    }

    /// Get the length of the share data in bits
    pub fn bit_length(&self) -> usize {
        self.data.len() * 8
    }
}

/// Shamir's Secret Sharing implementation
///
/// Uses GF(256) arithmetic with polynomial interpolation for splitting
/// and combining secrets.
pub struct ShamirSecretSharing;

impl ShamirSecretSharing {
    /// Create a new Shamir's Secret Sharing instance
    pub fn new() -> Self {
        Self
    }

    /// Split a secret into N shares requiring M shares to reconstruct
    ///
    /// # Arguments
    ///
    /// * `secret` - The secret to split (typically 32 bytes for a 256-bit key)
    /// * `threshold` - The minimum number of shares needed (M)
    /// * `total_shares` - The total number of shares to generate (N)
    ///
    /// # Constraints
    ///
    /// * 2 ≤ threshold ≤ total_shares ≤ 16
    /// * threshold ≤ secret.len() (in bytes)
    ///
    /// # Example
    ///
    /// ```rust
    /// use sigil_shamir::ShamirSecretSharing;
    ///
    /// let sss = ShamirSecretSharing::new();
    /// let secret = b"my secret key data";
    /// let shares = sss.split(secret, 3, 5).unwrap();
    /// assert_eq!(shares.len(), 5);
    /// ```
    pub fn split(&self, secret: &[u8], threshold: usize, total_shares: usize) -> Result<Vec<Share>> {
        // Validate inputs
        if threshold < 2 {
            return Err(ShamirError::InvalidThreshold(
                "Threshold must be at least 2".to_string(),
            ));
        }
        if total_shares > 16 {
            return Err(ShamirError::InvalidTotalShares(
                "Total shares cannot exceed 16".to_string(),
            ));
        }
        if threshold > total_shares {
            return Err(ShamirError::InvalidThreshold(
                "Threshold cannot exceed total shares".to_string(),
            ));
        }
        if threshold > secret.len() {
            return Err(ShamirError::SecretTooShort(
                "Secret is too short for the threshold".to_string(),
            ));
        }

        // For each byte position, generate a polynomial with random coefficients
        // f_i(x) = secret[i] + a1*x + a2*x^2 + ... + a_{threshold-1}*x^{threshold-1}
        let mut all_coefficients = vec![vec![0u8; threshold]; secret.len()];
        let mut rng = rand::thread_rng();

        for byte_idx in 0..secret.len() {
            all_coefficients[byte_idx][0] = secret[byte_idx];
            // Fill remaining coefficients with random values
            for coeff_idx in 1..threshold {
                rng.fill_bytes(&mut all_coefficients[byte_idx][coeff_idx..=coeff_idx]);
            }
        }

        // Generate shares: f(1), f(2), ..., f(total_shares)
        let mut shares = Vec::with_capacity(total_shares);
        for i in 1..=total_shares {
            let index = i as u8;
            let mut share_data = vec![0u8; secret.len()];

            // Evaluate each polynomial at point x
            for byte_idx in 0..secret.len() {
                share_data[byte_idx] = Self::evaluate_polynomial_at(&all_coefficients[byte_idx], index);
            }

            shares.push(Share::new(
                index,
                threshold as u8,
                total_shares as u8,
                share_data,
            ));
        }

        Ok(shares)
    }

    /// Evaluate a single polynomial at point x using Horner's method
    ///
    /// f(x) = coefficients[0] + coefficients[1]*x + ... + coefficients[n-1]*x^{n-1}
    fn evaluate_polynomial_at(coefficients: &[u8], x: u8) -> u8 {
        let mut result = 0u8;
        for &coeff in coefficients.iter().rev() {
            result = gf256_mul(result, x);
            result = gf256_add(result, coeff);
        }
        result
    }

    /// Combine shares to reconstruct the original secret
    ///
    /// # Arguments
    ///
    /// * `shares` - A slice of shares to combine (must be at least threshold)
    ///
    /// # Example
    ///
    /// ```rust
    /// use sigil_shamir::ShamirSecretSharing;
    ///
    /// let sss = ShamirSecretSharing::new();
    /// let secret = b"my secret key data";
    /// let shares = sss.split(secret, 3, 5).unwrap();
    ///
    /// // Reconstruct with any 3 shares
    /// let reconstructed = sss.combine(&shares[0..3]).unwrap();
    /// assert_eq!(reconstructed, secret.to_vec());
    /// ```
    pub fn combine(&self, shares: &[Share]) -> Result<Vec<u8>> {
        if shares.is_empty() {
            return Err(ShamirError::InvalidShares(
                "No shares provided".to_string(),
            ));
        }

        let threshold = shares[0].threshold as usize;
        let share_length = shares[0].data.len();

        // Validate all shares
        for share in shares {
            if share.threshold != shares[0].threshold {
                return Err(ShamirError::InvalidShares(
                    "Shares have different thresholds".to_string(),
                ));
            }
            if share.data.len() != share_length {
                return Err(ShamirError::InvalidShares(
                    "Shares have different lengths".to_string(),
                ));
            }
            if !share.verify() {
                return Err(ShamirError::InvalidShares(
                    "Share checksum verification failed".to_string(),
                ));
            }
        }

        if shares.len() < threshold {
            return Err(ShamirError::InsufficientShares(format!(
                "Need at least {} shares, got {}",
                threshold,
                shares.len()
            )));
        }

        // Use Lagrange interpolation to reconstruct the secret at x=0
        // f(0) = Σ f(x_i) * l_i(0)
        // where l_i(0) = Π_{j≠i} (x_j / (x_j - x_i))
        let mut secret = vec![0u8; share_length];

        // Precompute Lagrange coefficients for the first 'threshold' shares
        // l_i(0) = Π_{j≠i} (x_j / (x_j - x_i))
        // In GF(256), subtraction is the same as addition (XOR)
        let mut lagrange_coeffs = vec![0u8; threshold];
        for (i, share_i) in shares.iter().take(threshold).enumerate() {
            let mut numerator = 1u8;
            let mut denominator = 1u8;

            for (j, share_j) in shares.iter().take(threshold).enumerate() {
                if i != j {
                    numerator = gf256_mul(numerator, share_j.index);
                    denominator = gf256_mul(denominator, gf256_add(share_j.index, share_i.index));
                }
            }

            lagrange_coeffs[i] = gf256_div(numerator, denominator);
        }

        // Apply Lagrange interpolation for each byte position
        for byte_idx in 0..share_length {
            let mut value = 0u8;

            for (i, share_i) in shares.iter().take(threshold).enumerate() {
                let term = gf256_mul(share_i.data[byte_idx], lagrange_coeffs[i]);
                value = gf256_add(value, term);
            }

            secret[byte_idx] = value;
        }

        Ok(secret)
    }


}

impl Default for ShamirSecretSharing {
    fn default() -> Self {
        Self::new()
    }
}

/// GF(256) multiplication
///
/// Uses the polynomial x^8 + x^4 + x^3 + x + 1 (0x11B) as the irreducible polynomial
#[inline]
fn gf256_mul(a: u8, b: u8) -> u8 {
    let mut result = 0u8;
    let mut a = a;
    let mut b = b;

    while b != 0 {
        if b & 1 != 0 {
            result ^= a;
        }
        a = (a << 1) ^ if a & 0x80 != 0 { 0x1B } else { 0 };
        b >>= 1;
    }

    result
}

/// GF(256) division
///
/// a / b = a * b^{-1} where b^{-1} is the multiplicative inverse
#[inline]
fn gf256_div(a: u8, b: u8) -> u8 {
    if b == 0 {
        panic!("Division by zero in GF(256)");
    }
    gf256_mul(a, gf256_inv(b))
}

/// GF(256) multiplicative inverse using Fermat's Little Theorem
///
/// a^{-1} = a^{254} in GF(256) since 2^8 - 1 = 255 and a^{255} = 1 for non-zero a
#[inline]
fn gf256_inv(mut a: u8) -> u8 {
    if a == 0 {
        return 0; // 0 has no inverse
    }
    if a == 1 {
        return 1; // 1^{-1} = 1
    }

    // Compute a^{254} using square-and-multiply
    // 254 = 0b11111110 = 2 + 4 + 8 + 16 + 32 + 64 + 128
    let mut result = 1u8;

    // a^2
    a = gf256_mul(a, a);
    result = gf256_mul(result, a);

    // a^4
    a = gf256_mul(a, a);
    result = gf256_mul(result, a);

    // a^8
    a = gf256_mul(a, a);
    result = gf256_mul(result, a);

    // a^16
    a = gf256_mul(a, a);
    result = gf256_mul(result, a);

    // a^32
    a = gf256_mul(a, a);
    result = gf256_mul(result, a);

    // a^64
    a = gf256_mul(a, a);
    result = gf256_mul(result, a);

    // a^128
    a = gf256_mul(a, a);
    result = gf256_mul(result, a);

    result
}

/// GF(256) addition (XOR)
#[inline]
fn gf256_add(a: u8, b: u8) -> u8 {
    a ^ b
}

/// Errors for Shamir operations
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ShamirError {
    /// Invalid threshold value
    InvalidThreshold(String),
    /// Invalid total shares value
    InvalidTotalShares(String),
    /// Secret is too short
    SecretTooShort(String),
    /// Invalid share data
    InvalidShares(String),
    /// Insufficient shares to reconstruct
    InsufficientShares(String),
    /// Checksum verification failed
    ChecksumFailed(String),
    /// Mnemonic encoding/decoding error
    MnemonicError(String),
}

impl std::fmt::Display for ShamirError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ShamirError::InvalidThreshold(msg) => write!(f, "Invalid threshold: {}", msg),
            ShamirError::InvalidTotalShares(msg) => write!(f, "Invalid total shares: {}", msg),
            ShamirError::SecretTooShort(msg) => write!(f, "Secret too short: {}", msg),
            ShamirError::InvalidShares(msg) => write!(f, "Invalid shares: {}", msg),
            ShamirError::InsufficientShares(msg) => write!(f, "Insufficient shares: {}", msg),
            ShamirError::ChecksumFailed(msg) => write!(f, "Checksum failed: {}", msg),
            ShamirError::MnemonicError(msg) => write!(f, "Mnemonic error: {}", msg),
        }
    }
}

impl std::error::Error for ShamirError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_share_creation() {
        let share = Share::new(1, 3, 5, vec![1, 2, 3, 4]);
        assert_eq!(share.index, 1);
        assert_eq!(share.threshold, 3);
        assert_eq!(share.total_shares, 5);
        assert!(share.verify());
    }

    #[test]
    fn test_share_checksum_verification() {
        let share = Share::new(2, 3, 5, vec![5, 6, 7, 8]);
        assert!(share.verify());

        // Corrupt the data
        let mut corrupted = share.clone();
        corrupted.data[0] = 0xFF;
        assert!(!corrupted.verify());
    }

    #[test]
    fn test_split_basic() {
        let sss = ShamirSecretSharing::new();
        let secret = b"hello world, this is a test";

        let shares = sss.split(secret, 3, 5).unwrap();
        assert_eq!(shares.len(), 5);

        for share in &shares {
            assert_eq!(share.threshold, 3);
            assert_eq!(share.total_shares, 5);
            assert!(share.verify());
        }
    }

    #[test]
    fn test_combine_basic() {
        let sss = ShamirSecretSharing::new();
        let secret = b"hello world, this is a test";

        let shares = sss.split(secret, 3, 5).unwrap();
        let reconstructed = sss.combine(&shares[0..3]).unwrap();

        assert_eq!(reconstructed, secret.to_vec());
    }

    #[test]
    fn test_combine_different_subsets() {
        let sss = ShamirSecretSharing::new();
        let secret = b"test secret data here";

        let shares = sss.split(secret, 3, 5).unwrap();

        // Try all combinations of 3 shares
        for i in 0..3 {
            for j in (i + 1)..4 {
                for k in (j + 1)..5 {
                    let subset = vec![shares[i].clone(), shares[j].clone(), shares[k].clone()];
                    let reconstructed = sss.combine(&subset).unwrap();
                    assert_eq!(reconstructed, secret.to_vec());
                }
            }
        }
    }

    #[test]
    fn test_insufficient_shares() {
        let sss = ShamirSecretSharing::new();
        let secret = b"test secret";

        let shares = sss.split(secret, 3, 5).unwrap();
        let result = sss.combine(&shares[0..2]);

        assert!(matches!(result, Err(ShamirError::InsufficientShares(_))));
    }

    #[test]
    fn test_invalid_threshold() {
        let sss = ShamirSecretSharing::new();
        let secret = b"test";

        // Threshold less than 2
        assert!(sss.split(secret, 1, 3).is_err());

        // Threshold greater than total shares
        assert!(sss.split(secret, 5, 3).is_err());
    }

    #[test]
    fn test_too_many_shares() {
        let sss = ShamirSecretSharing::new();
        let secret = b"test";

        // More than 16 shares
        assert!(sss.split(secret, 3, 17).is_err());
    }

    #[test]
    fn test_256_bit_key() {
        let sss = ShamirSecretSharing::new();
        let secret = [0u8; 32]; // 256-bit key

        let shares = sss.split(&secret, 3, 5).unwrap();
        let reconstructed = sss.combine(&shares[0..3]).unwrap();

        assert_eq!(reconstructed, secret.to_vec());
    }

    #[test]
    fn test_gf256_mul() {
        assert_eq!(gf256_mul(0, 0), 0);
        assert_eq!(gf256_mul(1, 1), 1);
        assert_eq!(gf256_mul(2, 3), 6);
        assert_eq!(gf256_mul(0x53, 0xCA), 0x01);
    }

    #[test]
    fn test_gf256_inv() {
        // Verify a * a^{-1} = 1 for non-zero values
        for a in 1u8..=10 {
            let inv = gf256_inv(a);
            assert_eq!(gf256_mul(a, inv), 1);
        }
    }
}
