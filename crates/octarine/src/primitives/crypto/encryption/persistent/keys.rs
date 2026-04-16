//! ML-KEM keypair management and key derivation.
//!
//! Internal module providing:
//! - Global ML-KEM 1024 keypair (generated once per process)
//! - Symmetric key derivation from shared secrets

use ml_kem::{
    MlKem1024,
    kem::{DecapsulationKey, EncapsulationKey, Generate},
};
use sha3::{Digest, Sha3_256};
use std::sync::{Arc, OnceLock};

use super::{AES_KEY_SIZE, CHACHA_KEY_SIZE, CryptoError};

/// Global ML-KEM keypair (generated once per process)
static GLOBAL_ML_KEM_KEYS: OnceLock<Arc<MlKemKeyPair>> = OnceLock::new();

/// ML-KEM 1024 keypair wrapper
pub(super) struct MlKemKeyPair {
    /// Decapsulation key (private)
    pub(super) decapsulation_key: DecapsulationKey<MlKem1024>,
    /// Encapsulation key (public)
    pub(super) encapsulation_key: EncapsulationKey<MlKem1024>,
}

impl MlKemKeyPair {
    /// Generate a new ML-KEM 1024 keypair
    fn generate() -> Result<Self, CryptoError> {
        // Generate keypair using system RNG
        let mut rng = rand_core::UnwrapErr(getrandom::SysRng);
        let dk = DecapsulationKey::<MlKem1024>::generate_from_rng(&mut rng);
        let ek = dk.encapsulation_key().clone();
        Ok(Self {
            decapsulation_key: dk,
            encapsulation_key: ek,
        })
    }
}

/// Get or initialize the global ML-KEM keypair
pub(super) fn get_global_keys() -> Result<Arc<MlKemKeyPair>, CryptoError> {
    // Use get_or_init with a closure that panics on failure
    // Key generation should only fail in extreme circumstances (out of entropy)
    #[allow(clippy::expect_used)] // Key generation only fails on catastrophic entropy exhaustion
    Ok(Arc::clone(GLOBAL_ML_KEM_KEYS.get_or_init(|| {
        Arc::new(
            MlKemKeyPair::generate()
                .expect("Failed to generate ML-KEM keypair - system entropy issue"),
        )
    })))
}

/// Derive symmetric keys from shared secret using SHA3-256.
///
/// Returns (chacha_key, aes_key) derived with domain separation.
pub(super) fn derive_symmetric_keys<T: AsRef<[u8]>>(
    shared_secret: &T,
) -> ([u8; CHACHA_KEY_SIZE], [u8; AES_KEY_SIZE]) {
    let shared_secret = shared_secret.as_ref();
    // Derive ChaCha key with domain separation
    let mut hasher = Sha3_256::new();
    hasher.update(shared_secret);
    hasher.update(b"chacha20poly1305");
    let chacha_hash = hasher.finalize();
    let mut chacha_key = [0u8; CHACHA_KEY_SIZE];
    chacha_key.copy_from_slice(&chacha_hash);

    // Derive AES key with domain separation
    let mut hasher = Sha3_256::new();
    hasher.update(shared_secret);
    hasher.update(b"aes256gcm");
    let aes_hash = hasher.finalize();
    let mut aes_key = [0u8; AES_KEY_SIZE];
    aes_key.copy_from_slice(&aes_hash);

    (chacha_key, aes_key)
}

#[cfg(test)]
#[allow(clippy::panic, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn test_global_keypair_reuse() {
        // Get keypair twice
        let keys1 = get_global_keys().expect("Failed to get keys 1");
        let keys2 = get_global_keys().expect("Failed to get keys 2");

        // They should be the same Arc (pointer equality)
        assert!(Arc::ptr_eq(&keys1, &keys2));
    }

    #[test]
    fn test_key_derivation_deterministic() {
        let shared_secret = b"test_shared_secret_32_bytes_long";

        let (chacha1, aes1) = derive_symmetric_keys(shared_secret);
        let (chacha2, aes2) = derive_symmetric_keys(shared_secret);

        // Same input should produce same keys
        assert_eq!(chacha1, chacha2);
        assert_eq!(aes1, aes2);

        // Different domain separation means different keys
        assert_ne!(chacha1, aes1);
    }

    #[test]
    fn test_key_derivation_different_inputs() {
        let secret1 = b"secret_one_32_bytes_long_xxxxxx";
        let secret2 = b"secret_two_32_bytes_long_xxxxxx";

        let (chacha1, aes1) = derive_symmetric_keys(secret1);
        let (chacha2, aes2) = derive_symmetric_keys(secret2);

        // Different inputs should produce different keys
        assert_ne!(chacha1, chacha2);
        assert_ne!(aes1, aes2);
    }
}
