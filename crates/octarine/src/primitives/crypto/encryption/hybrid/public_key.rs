//! Hybrid public key for post-quantum encryption.

use ml_kem::{
    MlKem1024,
    kem::{EncapsulationKey, KeyExport, TryKeyInit},
};
use x25519_dalek::PublicKey as X25519PublicKey;

use super::{CryptoError, ML_KEM_ENCAP_KEY_SIZE, X25519_PUBLIC_KEY_SIZE};

/// Hybrid public key containing both ML-KEM and X25519 components.
///
/// This is the recipient's public key that senders use to encrypt messages.
/// It can be serialized and shared publicly.
#[derive(Clone)]
pub struct HybridPublicKey {
    /// ML-KEM 1024 encapsulation key
    pub(super) ml_kem_ek: EncapsulationKey<MlKem1024>,
    /// X25519 public key
    pub(super) x25519_pk: X25519PublicKey,
}

impl HybridPublicKey {
    /// Get the ML-KEM encapsulation key bytes for serialization.
    pub fn ml_kem_bytes(&self) -> Vec<u8> {
        self.ml_kem_ek.to_bytes().to_vec()
    }

    /// Get the X25519 public key bytes for serialization.
    pub fn x25519_bytes(&self) -> [u8; X25519_PUBLIC_KEY_SIZE] {
        *self.x25519_pk.as_bytes()
    }

    /// Serialize the complete public key.
    ///
    /// Format: `[ml_kem_ek (1568 bytes)][x25519_pk (32 bytes)]`
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(ML_KEM_ENCAP_KEY_SIZE + X25519_PUBLIC_KEY_SIZE);
        bytes.extend_from_slice(self.ml_kem_ek.to_bytes().as_ref());
        bytes.extend_from_slice(self.x25519_pk.as_bytes());
        bytes
    }

    /// Deserialize a public key from bytes.
    ///
    /// # Errors
    ///
    /// Returns `CryptoError::InvalidKey` if the bytes are malformed.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, CryptoError> {
        if bytes.len() != ML_KEM_ENCAP_KEY_SIZE + X25519_PUBLIC_KEY_SIZE {
            return Err(CryptoError::invalid_key(format!(
                "Invalid hybrid public key length: expected {}, got {}",
                ML_KEM_ENCAP_KEY_SIZE + X25519_PUBLIC_KEY_SIZE,
                bytes.len()
            )));
        }

        let ml_kem_bytes = bytes
            .get(..ML_KEM_ENCAP_KEY_SIZE)
            .ok_or_else(|| CryptoError::invalid_key("Slice bounds check failed for ML-KEM key"))?;
        let x25519_bytes = bytes
            .get(ML_KEM_ENCAP_KEY_SIZE..)
            .ok_or_else(|| CryptoError::invalid_key("Slice bounds check failed for X25519 key"))?;

        // Convert bytes to fixed-size array for ML-KEM
        let ml_kem_ek_arr: [u8; ML_KEM_ENCAP_KEY_SIZE] = ml_kem_bytes
            .try_into()
            .map_err(|_| CryptoError::invalid_key("Invalid ML-KEM key bytes"))?;
        let ml_kem_ek = EncapsulationKey::<MlKem1024>::new(&ml_kem_ek_arr.into()).map_err(|e| {
            CryptoError::invalid_key(format!("Invalid ML-KEM encapsulation key: {e:?}"))
        })?;

        let x25519_arr: [u8; X25519_PUBLIC_KEY_SIZE] = x25519_bytes
            .try_into()
            .map_err(|_| CryptoError::invalid_key("Invalid X25519 public key bytes"))?;
        let x25519_pk = X25519PublicKey::from(x25519_arr);

        Ok(Self {
            ml_kem_ek,
            x25519_pk,
        })
    }

    /// Get the size of a serialized public key.
    #[inline]
    pub const fn serialized_size() -> usize {
        ML_KEM_ENCAP_KEY_SIZE + X25519_PUBLIC_KEY_SIZE
    }
}

impl std::fmt::Debug for HybridPublicKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HybridPublicKey")
            .field("ml_kem_size", &ML_KEM_ENCAP_KEY_SIZE)
            .field("x25519_size", &X25519_PUBLIC_KEY_SIZE)
            .finish()
    }
}

#[cfg(test)]
#[allow(clippy::panic, clippy::expect_used)]
mod tests {
    use super::super::HybridKeyPair;
    use super::*;

    #[test]
    fn test_public_key_serialization() {
        let keypair = HybridKeyPair::generate().expect("Failed to generate keypair");
        let public_key = keypair.public_key();

        // Serialize
        let bytes = public_key.to_bytes();
        assert_eq!(bytes.len(), HybridPublicKey::serialized_size());

        // Deserialize
        let restored = HybridPublicKey::from_bytes(&bytes).expect("Failed to restore public key");

        // Verify by encrypting with restored key
        let encrypted = super::super::HybridEncryption::encrypt_to(b"test", &restored)
            .expect("Failed to encrypt");
        let decrypted = encrypted.decrypt_with(&keypair).expect("Failed to decrypt");
        assert_eq!(decrypted.as_slice(), b"test");
    }
}
