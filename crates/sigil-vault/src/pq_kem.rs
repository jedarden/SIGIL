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
//! The `pq-hybrid` feature is now **fully implemented** using the stable ml-kem crate (v0.3+).

#![cfg(feature = "pq-hybrid")]

use ml_kem::{
    kem::{Decapsulate, Encapsulate, Kem},
    KeyExport, MlKem768, Seed, SharedKey,
};
use serde::{Deserialize, Serialize};
use sigil_core::{Result, SigilError};
use zeroize::Zeroize;

/// ML-KEM-768 keypair for post-quantum key encapsulation
///
/// The secret key is stored as a 64-byte seed (not the 2400-byte expanded form)
/// for efficiency and compatibility with the ml-kem crate's preferred serialization.
#[derive(Clone, Serialize, Deserialize)]
pub struct KemKeyPair {
    /// The public key (for encapsulation) - 1184 bytes for ML-KEM-768
    #[serde(with = "serde_bytes")]
    pub public_key: Vec<u8>,
    /// The secret key seed (for decapsulation) - 64 bytes for ML-KEM-768
    #[serde(with = "serde_bytes")]
    pub secret_key: Vec<u8>,
}

impl KemKeyPair {
    /// Generate a new ML-KEM-768 keypair
    ///
    /// Uses the ml-kem crate's `MlKem768::generate_keypair()` to generate
    /// a cryptographically secure post-quantum keypair.
    ///
    /// The secret key is stored as a compact 64-byte seed (not the 2400-byte
    /// expanded form) for efficiency.
    pub fn generate() -> Result<Self> {
        let (decapsulation_key, encapsulation_key) = MlKem768::generate_keypair();

        // Export keys to bytes for storage/transmission
        // Encapsulation key: serialized form (1184 bytes)
        let public_key = encapsulation_key.to_bytes().to_vec();
        // Decapsulation key: seed form (64 bytes) - the preferred serialization
        let secret_key = decapsulation_key
            .to_seed()
            .ok_or_else(|| SigilError::Crypto("Failed to export ML-KEM seed".into()))?
            .to_vec();

        Ok(Self {
            public_key,
            secret_key,
        })
    }

    /// Encapsulate a random shared secret using the public key
    ///
    /// Returns the ciphertext (encapsulated secret) and the shared secret.
    pub fn encapsulate(public_key: &[u8]) -> Result<(Vec<u8>, Vec<u8>)> {
        type EncapKey = <MlKem768 as Kem>::EncapsulationKey;

        // Import the encapsulation key from bytes (1184 bytes for ML-KEM-768)
        let key_bytes: [u8; 1184] = public_key.try_into().map_err(|_| {
            SigilError::Crypto("Failed to import ML-KEM public key: wrong length".into())
        })?;

        // EncapsulationKey::new takes &Key<Self> which is &Array<u8, U1184>
        // Convert &[u8; 1184] to &Array<u8, U1184> using Into::into()
        let key_ref: &ml_kem::array::Array<u8, ml_kem::array::sizes::U1184> = (&key_bytes).into();
        let encapsulation_key = EncapKey::new(key_ref).map_err(|_| {
            SigilError::Crypto("Failed to create ML-KEM encapsulation key: invalid key".into())
        })?;

        // Encapsulate to get ciphertext and shared secret
        let (ciphertext, shared_secret) = encapsulation_key.encapsulate();

        Ok((ciphertext.to_vec(), shared_secret.to_vec()))
    }

    /// Decapsulate the shared secret from ciphertext using the secret key
    ///
    /// Recovers the shared secret from the encapsulated ciphertext.
    pub fn decapsulate(&self, ciphertext: &[u8]) -> Result<Vec<u8>> {
        type DecapKey = <MlKem768 as Kem>::DecapsulationKey;

        // Convert secret key Vec<u8> to Seed type ([u8; 64])
        let seed: Seed = self.secret_key.as_slice().try_into().map_err(|_| {
            SigilError::Crypto("Failed to import ML-KEM secret key: wrong length".into())
        })?;

        // Import the decapsulation key from seed
        let decapsulation_key = DecapKey::from_seed(seed);

        // Convert ciphertext bytes to the proper array type (1088 bytes for ML-KEM-768)
        let ct_bytes: [u8; 1088] = ciphertext.try_into().map_err(|_| {
            SigilError::Crypto("Failed to import ML-KEM ciphertext: wrong length".into())
        })?;

        // Ciphertext is just an Array type, convert using Into::into()
        let ct_ref: &ml_kem::array::Array<u8, ml_kem::array::sizes::U1088> = (&ct_bytes).into();
        let ct = ml_kem::ml_kem_768::Ciphertext::from(*ct_ref);

        // Decapsulate to recover the shared secret (returns SharedKey directly, not Result)
        let shared_secret: SharedKey = decapsulation_key.decapsulate(&ct);

        Ok(shared_secret.to_vec())
    }

    /// Get the public key bytes
    pub fn public_key_bytes(&self) -> &[u8] {
        &self.public_key
    }

    /// Get the secret key bytes (seed form)
    pub fn secret_key_bytes(&self) -> &[u8] {
        &self.secret_key
    }

    /// Check if this is a valid ML-KEM-768 keypair
    pub fn is_valid(&self) -> bool {
        self.public_key.len() == 1184 && self.secret_key.len() == 64
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
        assert_eq!(keypair.secret_key.len(), 64); // ML-KEM-768 seed size (not expanded)
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
    fn test_encapsulate_decapsulate_roundtrip() {
        // Generate a keypair
        let keypair = KemKeyPair::generate().unwrap();

        // Encapsulate a shared secret
        let (ciphertext, shared_secret_sender) =
            KemKeyPair::encapsulate(&keypair.public_key).unwrap();

        // Decapsulate to recover the shared secret
        let shared_secret_receiver = keypair.decapsulate(&ciphertext).unwrap();

        // The shared secrets should match
        assert_eq!(shared_secret_sender, shared_secret_receiver);
        assert_eq!(shared_secret_sender.len(), 32); // ML-KEM-768 shared secret size
    }

    #[test]
    fn test_multiple_encapsulations_different_secrets() {
        let keypair = KemKeyPair::generate().unwrap();

        // Encapsulate twice
        let (ct1, ss1) = KemKeyPair::encapsulate(&keypair.public_key).unwrap();
        let (ct2, ss2) = KemKeyPair::encapsulate(&keypair.public_key).unwrap();

        // Ciphertexts should be different (randomness in encapsulation)
        assert_ne!(ct1, ct2);

        // Shared secrets should be different
        assert_ne!(ss1, ss2);

        // But both should decapsulate correctly
        let recovered1 = keypair.decapsulate(&ct1).unwrap();
        let recovered2 = keypair.decapsulate(&ct2).unwrap();

        assert_eq!(ss1, recovered1);
        assert_eq!(ss2, recovered2);
    }

    #[test]
    fn test_wrong_ciphertext_implicit_rejection() {
        let keypair = KemKeyPair::generate().unwrap();

        // First, get a valid ciphertext and shared secret
        let (valid_ct, valid_ss) = KemKeyPair::encapsulate(&keypair.public_key).unwrap();

        // Use invalid ciphertext (all zeros)
        let invalid_ciphertext = vec![0u8; 1088];

        // ML-KEM uses implicit rejection: decapsulation succeeds but returns a random secret
        let invalid_ss = keypair.decapsulate(&invalid_ciphertext).unwrap();

        // The invalid ciphertext should produce a different shared secret than the valid one
        assert_ne!(valid_ss, invalid_ss);

        // The valid ciphertext should still decapsulate correctly
        let decapsulated_valid = keypair.decapsulate(&valid_ct).unwrap();
        assert_eq!(valid_ss, decapsulated_valid);
    }

    #[test]
    fn test_wrong_ciphertext_length() {
        let keypair = KemKeyPair::generate().unwrap();

        // Use ciphertext with wrong length
        let wrong_length = vec![0u8; 100];

        let result = keypair.decapsulate(&wrong_length);
        assert!(result.is_err());
    }

    #[test]
    fn test_invalid_public_key() {
        // Invalid public key (wrong length)
        let invalid_public_key = vec![0u8; 100];

        let result = KemKeyPair::encapsulate(&invalid_public_key);
        assert!(result.is_err());
    }

    #[test]
    fn test_secret_key_zeroized_on_drop() {
        // This test verifies that the secret key is zeroized when dropped
        // In practice, this is hard to test directly, but we can verify
        // that the Drop impl is present and compiles

        let keypair = KemKeyPair::generate().unwrap();
        let secret_before = keypair.secret_key.clone();

        drop(keypair);

        // After dropping, the original secret bytes are gone
        // (we can't inspect the dropped value, but this test ensures
        // the Drop implementation compiles and is present)
        assert_eq!(secret_before.len(), 64);
    }

    #[test]
    fn test_seed_efficiency() {
        // Verify that we're using the compact seed representation (64 bytes)
        // instead of the expanded form (2400 bytes)
        let keypair = KemKeyPair::generate().unwrap();
        assert_eq!(
            keypair.secret_key.len(),
            64,
            "Secret key should be 64-byte seed, not expanded form"
        );
    }
}
