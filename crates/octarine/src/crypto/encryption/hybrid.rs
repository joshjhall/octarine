//! Hybrid Encryption with observability
//!
//! Post-quantum hybrid encryption (ML-KEM + X25519) wrapped with
//! observe instrumentation for audit trails.
//!
//! # Security Properties
//!
//! - **Post-Quantum**: ML-KEM 1024 (FIPS 203, NIST Level 5)
//! - **Classical**: X25519 (RFC 7748) for defense in depth
//! - **Forward Secrecy**: Fresh ephemeral keys per encryption
//! - **Hybrid Security**: Safe if either algorithm is broken
//!
//! # Security Events
//!
//! - `encryption.hybrid_keygen` - Key pair generated
//! - `encryption.hybrid_encrypt` - Data encrypted to public key
//! - `encryption.hybrid_decrypt` - Hybrid ciphertext decrypted
//!
//! # Examples
//!
//! ```ignore
//! use octarine::crypto::encryption::hybrid;
//!
//! // Recipient generates keypair
//! let keypair = hybrid::generate_keypair()?;
//! let public_key = keypair.public_key();
//!
//! // Sender encrypts to recipient's public key
//! let encrypted = hybrid::encrypt(&public_key, b"secret-message")?;
//!
//! // Recipient decrypts with private key
//! let plaintext = hybrid::decrypt(&keypair, &encrypted)?;
//! ```

use crate::observe;
use crate::primitives::crypto::CryptoError;
use crate::primitives::crypto::encryption::{HybridEncryption, HybridKeyPair, HybridPublicKey};

// Re-export types
pub use crate::primitives::crypto::encryption::HybridEncryptedComponents;

/// Generate a hybrid key pair with audit trail.
///
/// Creates an ML-KEM 1024 + X25519 key pair for post-quantum
/// hybrid encryption.
///
/// # Security Events
///
/// Generates `encryption.hybrid_keygen` event.
pub fn generate_keypair() -> Result<HybridKeyPair, CryptoError> {
    let result = HybridKeyPair::generate();

    match &result {
        Ok(_) => {
            observe::info(
                "hybrid_keygen",
                "Hybrid keypair generated (ML-KEM 1024 + X25519)",
            );
        }
        Err(e) => {
            observe::warn(
                "hybrid_keygen",
                format!("Hybrid keypair generation failed: {e}"),
            );
        }
    }

    result
}

/// Encrypt data to a public key with audit trail.
///
/// Uses ML-KEM 1024 + X25519 hybrid encryption for post-quantum
/// security with classical defense in depth.
///
/// # Security Events
///
/// Generates `encryption.hybrid_encrypt` event with data size.
pub fn encrypt(public_key: &HybridPublicKey, data: &[u8]) -> Result<HybridEncryption, CryptoError> {
    let result = HybridEncryption::encrypt_to(data, public_key);

    match &result {
        Ok(_) => {
            observe::info(
                "hybrid_encrypt",
                format!("Hybrid encryption completed ({} bytes)", data.len()),
            );
        }
        Err(e) => {
            observe::warn("hybrid_encrypt", format!("Hybrid encryption failed: {e}"));
        }
    }

    result
}

/// Decrypt hybrid encrypted data with audit trail.
///
/// Uses the private key to derive the shared secret and decrypt.
///
/// # Security Events
///
/// Generates `encryption.hybrid_decrypt` event.
pub fn decrypt(
    keypair: &HybridKeyPair,
    encrypted: &HybridEncryption,
) -> Result<Vec<u8>, CryptoError> {
    let result = encrypted.decrypt_with(keypair);

    match &result {
        Ok(plaintext) => {
            observe::info(
                "hybrid_decrypt",
                format!("Hybrid decryption completed ({} bytes)", plaintext.len()),
            );
        }
        Err(e) => {
            observe::warn("hybrid_decrypt", format!("Hybrid decryption failed: {e}"));
        }
    }

    result
}

/// Serialize encrypted data to components for storage/transmission.
///
/// Returns the components needed to reconstruct the encrypted data.
pub fn to_components(encrypted: &HybridEncryption) -> HybridEncryptedComponents {
    encrypted.to_components()
}

/// Reconstruct encrypted data from components.
///
/// Use this to reconstruct after deserialization.
pub fn from_components(
    components: HybridEncryptedComponents,
) -> Result<HybridEncryption, CryptoError> {
    let (kem_ciphertext, ephemeral_x25519_pk, nonce, ciphertext) = components;
    HybridEncryption::from_components(kem_ciphertext, ephemeral_x25519_pk, nonce, ciphertext)
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
#[allow(clippy::panic, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_encrypt_decrypt() {
        let keypair = generate_keypair().expect("Keygen failed");
        let public_key = keypair.public_key();

        let data = b"test hybrid encryption";
        let encrypted = encrypt(&public_key, data).expect("Encryption failed");
        let decrypted = decrypt(&keypair, &encrypted).expect("Decryption failed");

        assert_eq!(decrypted.as_slice(), data);
    }

    #[test]
    fn test_components_roundtrip() {
        let keypair = generate_keypair().expect("Keygen failed");
        let public_key = keypair.public_key();

        let data = b"component test";
        let encrypted = encrypt(&public_key, data).expect("Encryption failed");

        let components = to_components(&encrypted);
        let restored = from_components(components).expect("Restore failed");
        let decrypted = decrypt(&keypair, &restored).expect("Decryption failed");

        assert_eq!(decrypted.as_slice(), data);
    }

    #[test]
    fn test_different_keypairs_cannot_decrypt() {
        let keypair1 = generate_keypair().expect("Keygen 1 failed");
        let keypair2 = generate_keypair().expect("Keygen 2 failed");

        let data = b"secret";
        let encrypted = encrypt(&keypair1.public_key(), data).expect("Encryption failed");

        // Wrong keypair should fail
        let result = decrypt(&keypair2, &encrypted);
        assert!(result.is_err());
    }

    #[test]
    fn test_encrypt_decrypt_empty_plaintext() {
        let keypair = generate_keypair().expect("Keygen failed");
        let public_key = keypair.public_key();

        let encrypted = encrypt(&public_key, b"").expect("Empty encrypt failed");
        let decrypted = decrypt(&keypair, &encrypted).expect("Empty decrypt failed");

        assert!(decrypted.is_empty());
    }
}
