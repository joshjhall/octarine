//! Hybrid keypair for post-quantum encryption.

use ml_kem::{
    MlKem1024,
    kem::{DecapsulationKey, EncapsulationKey, Generate, KeyExport, KeyInit},
};
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret};

use super::CryptoError;
use super::public_key::HybridPublicKey;

/// Hybrid keypair for receiving encrypted messages.
///
/// Contains both ML-KEM and X25519 keypairs for hybrid decryption.
/// The private keys are zeroized on drop.
pub struct HybridKeyPair {
    /// ML-KEM 1024 decapsulation key (private)
    pub(super) ml_kem_dk: DecapsulationKey<MlKem1024>,
    /// ML-KEM 1024 encapsulation key (public)
    pub(super) ml_kem_ek: EncapsulationKey<MlKem1024>,
    /// X25519 static secret (private)
    pub(super) x25519_sk: StaticSecret,
    /// X25519 public key
    pub(super) x25519_pk: X25519PublicKey,
}

impl HybridKeyPair {
    /// Generate a new hybrid keypair.
    ///
    /// Creates fresh ML-KEM 1024 and X25519 keypairs using the system CSPRNG.
    ///
    /// # Errors
    ///
    /// Returns `CryptoError::KeyGeneration` if key generation fails.
    pub fn generate() -> Result<Self, CryptoError> {
        // Generate ML-KEM 1024 keypair using system RNG
        let mut rng = rand_core::UnwrapErr(getrandom::SysRng);
        let ml_kem_dk = DecapsulationKey::<MlKem1024>::generate_from_rng(&mut rng);
        let ml_kem_ek = ml_kem_dk.encapsulation_key().clone();

        // Generate X25519 keypair (uses getrandom internally)
        let x25519_sk = StaticSecret::random();
        let x25519_pk = X25519PublicKey::from(&x25519_sk);

        Ok(Self {
            ml_kem_dk,
            ml_kem_ek,
            x25519_sk,
            x25519_pk,
        })
    }

    /// Get the public key for sharing with senders.
    pub fn public_key(&self) -> HybridPublicKey {
        HybridPublicKey {
            ml_kem_ek: self.ml_kem_ek.clone(),
            x25519_pk: self.x25519_pk,
        }
    }

    /// Export the X25519 secret key bytes (for key backup/restore).
    ///
    /// # Security Warning
    ///
    /// This exposes private key material. Handle with extreme care.
    pub fn x25519_secret_bytes(&self) -> [u8; 32] {
        self.x25519_sk.to_bytes()
    }

    /// Create a keypair from existing key material.
    ///
    /// # Arguments
    ///
    /// * `ml_kem_seed_bytes` - 64-byte ML-KEM seed (from `ml_kem_secret_bytes()`)
    /// * `x25519_sk_bytes` - X25519 secret key bytes
    ///
    /// # Errors
    ///
    /// Returns `CryptoError::InvalidKey` if key bytes are malformed.
    pub fn from_bytes(
        ml_kem_seed_bytes: &[u8],
        x25519_sk_bytes: &[u8; 32],
    ) -> Result<Self, CryptoError> {
        // Restore X25519 keypair
        let x25519_sk = StaticSecret::from(*x25519_sk_bytes);
        let x25519_pk = X25519PublicKey::from(&x25519_sk);

        // Restore ML-KEM keypair from 64-byte seed
        const ML_KEM_SEED_SIZE: usize = 64;
        if ml_kem_seed_bytes.len() != ML_KEM_SEED_SIZE {
            return Err(CryptoError::invalid_key(format!(
                "Invalid ML-KEM seed length: expected {}, got {}",
                ML_KEM_SEED_SIZE,
                ml_kem_seed_bytes.len()
            )));
        }

        let seed_arr: [u8; 64] = ml_kem_seed_bytes
            .try_into()
            .map_err(|_| CryptoError::invalid_key("Invalid ML-KEM seed bytes"))?;
        let ml_kem_dk = DecapsulationKey::<MlKem1024>::new(&seed_arr.into());
        let ml_kem_ek = ml_kem_dk.encapsulation_key().clone();

        Ok(Self {
            ml_kem_dk,
            ml_kem_ek,
            x25519_sk,
            x25519_pk,
        })
    }

    /// Export the ML-KEM seed bytes (for key backup/restore).
    ///
    /// Returns the 64-byte seed from which the decapsulation key can be
    /// deterministically regenerated.
    ///
    /// # Security Warning
    ///
    /// This exposes private key material. Handle with extreme care.
    pub fn ml_kem_secret_bytes(&self) -> Vec<u8> {
        self.ml_kem_dk.to_bytes().to_vec()
    }
}

impl std::fmt::Debug for HybridKeyPair {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HybridKeyPair")
            .field("ml_kem", &"[REDACTED]")
            .field("x25519", &"[REDACTED]")
            .finish()
    }
}

impl Drop for HybridKeyPair {
    fn drop(&mut self) {
        // StaticSecret has Zeroize implemented
        // DecapsulationKey also zeroizes on drop (with zeroize feature)
    }
}

#[cfg(test)]
#[allow(clippy::panic, clippy::expect_used)]
mod tests {
    use super::super::{HybridEncryption, ML_KEM_ENCAP_KEY_SIZE, X25519_PUBLIC_KEY_SIZE};
    use super::*;

    #[test]
    fn test_keypair_generation() {
        let keypair = HybridKeyPair::generate().expect("Failed to generate keypair");
        let public_key = keypair.public_key();

        // Verify public key sizes
        assert_eq!(public_key.ml_kem_bytes().len(), ML_KEM_ENCAP_KEY_SIZE);
        assert_eq!(public_key.x25519_bytes().len(), X25519_PUBLIC_KEY_SIZE);
    }

    #[test]
    fn test_keypair_restoration() {
        let original = HybridKeyPair::generate().expect("Failed to generate keypair");

        // Export key material
        let ml_kem_bytes = original.ml_kem_secret_bytes();
        let x25519_bytes = original.x25519_secret_bytes();

        // Encrypt with original public key
        let plaintext = b"key restoration test";
        let encrypted = HybridEncryption::encrypt_to(plaintext, &original.public_key())
            .expect("Failed to encrypt");

        // Restore keypair from bytes
        let restored = HybridKeyPair::from_bytes(&ml_kem_bytes, &x25519_bytes)
            .expect("Failed to restore keypair");

        // Decrypt with restored keypair
        let decrypted = encrypted
            .decrypt_with(&restored)
            .expect("Failed to decrypt");
        assert_eq!(decrypted.as_slice(), plaintext);
    }

    #[test]
    fn test_debug_redacts_sensitive_info() {
        let keypair = HybridKeyPair::generate().expect("Failed to generate keypair");
        let debug_str = format!("{:?}", keypair);

        assert!(debug_str.contains("HybridKeyPair"));
        assert!(debug_str.contains("[REDACTED]"));
    }
}
