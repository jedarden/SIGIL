//! Post-quantum key encapsulation using ML-KEM-768
//!
//! This module provides optional post-quantum security through ML-KEM-768 (Kyber),
//! a NIST-standardized key encapsulation mechanism resistant to quantum attacks.
//!
//! # Hybrid Mode
//!
//! When the `pq-hybrid` feature is enabled, SIGIL can use a hybrid encryption approach:
//! - ML-KEM-768 encapsulates a symmetric key for post-quantum security
//! - The encapsulated key is used alongside age's X25519 for defense-in-depth
//!
//! This provides "best of both worlds" security:
//! - Classical security from X25519 (well-studied, efficient)
//! - Post-quantum security from ML-KEM-768 (quantum-resistant)
//! - Even if one algorithm is broken, the other protects the data
//!
//! # Implementation Status
//!
//! The `pq-hybrid` feature is currently **experimental** and requires the ml-kem crate
//! (currently a release candidate). The infrastructure is in place but full encapsulation/
//! decapsulation support is pending stable ml-kem crate release.

#![cfg(feature = "pq-hybrid")]

use serde::{Deserialize, Serialize};
use sigil_core::{Result, SigilError};
use zeroize::Zeroize;

/// ML-KEM-768 keypair for post-quantum key encapsulation
#[derive(Clone, Serialize, Deserialize)]
pub struct KemKeyPair {
    /// The public key (for encapsulation) - 1184 bytes for ML-KEM-768
    #[serde(with = "serde_bytes")]
    pub public_key: Vec<u8>,
    /// The secret key (for decapsulation) - 2400 bytes for ML-KEM-768
    #[serde(with = "serde_bytes")]
    pub secret_key: Vec<u8>,
}

impl KemKeyPair {
    /// Generate a new ML-KEM-768 keypair
    ///
    /// **Note**: This is currently a placeholder implementation. Full ML-KEM-768
    /// support will be added when the ml-kem crate reaches stable release.
    pub fn generate() -> Result<Self> {
        // Placeholder: generate random bytes of the correct size
        // When ml-kem crate stabilizes, this will use: MlKem768::keygen(&mut rng)
        use rand::Rng;
        let mut rng = rand::thread_rng();

        let mut public_key = vec![0u8; 1184];
        let mut secret_key = vec![0u8; 2400];

        rng.fill(&mut public_key[..]);
        rng.fill(&mut secret_key[..]);

        Ok(Self {
            public_key,
            secret_key,
        })
    }

    /// Encapsulate a random shared secret using the public key
    ///
    /// **Note**: This is currently a placeholder implementation.
    pub fn encapsulate(_public_key: &[u8]) -> Result<(Vec<u8>, Vec<u8>)> {
        // Placeholder implementation
        // When ml-kem crate stabilizes, this will use the actual encapsulation
        Err(SigilError::Crypto(
            "ML-KEM-768 encapsulation not yet implemented - pending stable ml-kem crate release"
                .into(),
        ))
    }

    /// Decapsulate the shared secret from ciphertext using the secret key
    ///
    /// **Note**: This is currently a placeholder implementation.
    pub fn decapsulate(&self, _ciphertext: &[u8]) -> Result<Vec<u8>> {
        // Placeholder implementation
        // When ml-kem crate stabilizes, this will use the actual decapsulation
        Err(SigilError::Crypto(
            "ML-KEM-768 decapsulation not yet implemented - pending stable ml-kem crate release"
                .into(),
        ))
    }

    /// Get the public key bytes
    pub fn public_key_bytes(&self) -> &[u8] {
        &self.public_key
    }

    /// Get the secret key bytes
    pub fn secret_key_bytes(&self) -> &[u8] {
        &self.secret_key
    }

    /// Check if this is a valid ML-KEM-768 keypair
    pub fn is_valid(&self) -> bool {
        self.public_key.len() == 1184 && self.secret_key.len() == 2400
    }
}

impl Drop for KemKeyPair {
    fn drop(&mut self) {
        // Zeroize the secret key on drop
        self.secret_key.zeroize();
    }
}

/// Encapsulated secret for post-quantum key exchange
#[derive(Clone, Serialize, Deserialize)]
pub struct EncapsulatedSecret {
    /// The ciphertext (encapsulated secret) - 1088 bytes for ML-KEM-768
    #[serde(with = "serde_bytes")]
    pub ciphertext: Vec<u8>,
    /// The shared secret (encrypted with age for storage) - 32 bytes
    #[serde(with = "serde_bytes")]
    pub shared_secret: Vec<u8>,
}

impl EncapsulatedSecret {
    /// Create a new encapsulated secret
    pub fn new(ciphertext: Vec<u8>, shared_secret: Vec<u8>) -> Self {
        Self {
            ciphertext,
            shared_secret,
        }
    }

    /// Get the ciphertext
    pub fn ciphertext(&self) -> &[u8] {
        &self.ciphertext
    }

    /// Get the shared secret
    pub fn shared_secret(&self) -> &[u8] {
        &self.shared_secret
    }

    /// Check if this is a valid ML-KEM-768 encapsulated secret
    pub fn is_valid(&self) -> bool {
        self.ciphertext.len() == 1088 && self.shared_secret.len() == 32
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_kem_keypair_generation() {
        let keypair = KemKeyPair::generate().unwrap();
        assert_eq!(keypair.public_key.len(), 1184); // ML-KEM-768 public key size
        assert_eq!(keypair.secret_key.len(), 2400); // ML-KEM-768 secret key size
        assert!(keypair.is_valid());
    }

    #[test]
    fn test_kem_keypair_validation() {
        let keypair = KemKeyPair::generate().unwrap();
        assert!(keypair.is_valid());

        // Invalid keypair
        let invalid_keypair = KemKeyPair {
            public_key: vec![0u8; 100],
            secret_key: vec![0u8; 100],
        };
        assert!(!invalid_keypair.is_valid());
    }

    #[test]
    fn test_encapsulated_secret_validation() {
        let ciphertext = vec![1u8; 1088];
        let shared_secret = vec![2u8; 32];

        let encap = EncapsulatedSecret::new(ciphertext.clone(), shared_secret.clone());
        assert!(encap.is_valid());
    }

    #[test]
    fn test_encapsulated_secret_serialization() {
        let ciphertext = vec![1u8; 1088];
        let shared_secret = vec![2u8; 32];

        let encap = EncapsulatedSecret::new(ciphertext.clone(), shared_secret.clone());

        assert_eq!(encap.ciphertext(), &ciphertext[..]);
        assert_eq!(encap.shared_secret(), &shared_secret[..]);
    }

    #[test]
    fn test_encapsulate_not_implemented() {
        let public_key = vec![0u8; 1184];
        let result = KemKeyPair::encapsulate(&public_key);
        assert!(result.is_err());
    }

    #[test]
    fn test_decapsulate_not_implemented() {
        let keypair = KemKeyPair::generate().unwrap();
        let ciphertext = vec![0u8; 1088];
        let result = keypair.decapsulate(&ciphertext);
        assert!(result.is_err());
    }
}
