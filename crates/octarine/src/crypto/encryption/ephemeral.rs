//! Ephemeral Encryption with observability
//!
//! Forward-secrecy encryption wrapped with observe instrumentation
//! for audit trails and compliance support.
//!
//! # Security Properties
//!
//! - **Forward Secrecy**: Each encryption uses a fresh random key
//! - **Key Destruction**: Keys are zeroized after use
//! - **Unique Ciphertext**: Same plaintext produces different ciphertext
//!
//! # Security Events
//!
//! - `encryption.ephemeral_encrypt` - Data encrypted with ephemeral key
//! - `encryption.ephemeral_decrypt` - Ephemeral ciphertext decrypted
//!
//! # Examples
//!
//! ```ignore
//! use octarine::crypto::encryption::ephemeral;
//!
//! // Encrypt with forward secrecy
//! let encrypted = ephemeral::encrypt(b"session-token")?;
//!
//! // Decrypt when needed
//! let plaintext = ephemeral::decrypt(&encrypted)?;
//! ```

use crate::observe;
use crate::primitives::crypto::CryptoError;
use crate::primitives::crypto::encryption::EphemeralEncryption;

// Re-export types
pub use crate::primitives::crypto::encryption::EncryptedComponents;

/// Encrypt data with ephemeral keys for maximum forward secrecy.
///
/// Generates a fresh random key and nonce for this encryption.
/// The key is stored with the ciphertext and will be zeroized
/// when the returned struct is dropped.
///
/// # Security Events
///
/// Generates `encryption.ephemeral_encrypt` event with plaintext size.
pub fn encrypt(data: &[u8]) -> Result<EphemeralEncryption, CryptoError> {
    let result = EphemeralEncryption::encrypt(data);

    match &result {
        Ok(_) => {
            observe::info(
                "ephemeral_encrypt",
                format!("Ephemeral encryption completed ({} bytes)", data.len()),
            );
        }
        Err(e) => {
            observe::warn(
                "ephemeral_encrypt",
                format!("Ephemeral encryption failed: {e}"),
            );
        }
    }

    result
}

/// Encrypt data and return serializable components.
///
/// Returns a tuple of (ciphertext, nonce, key) that can be stored
/// and later used with `from_components` to reconstruct.
///
/// # Security Warning
///
/// The key in the returned components is sensitive! Store it securely.
pub fn encrypt_to_components(data: &[u8]) -> Result<EncryptedComponents, CryptoError> {
    let result = EphemeralEncryption::encrypt_to_components(data);

    match &result {
        Ok(_) => {
            observe::info(
                "ephemeral_encrypt",
                format!(
                    "Ephemeral encryption to components completed ({} bytes)",
                    data.len()
                ),
            );
        }
        Err(e) => {
            observe::warn(
                "ephemeral_encrypt",
                format!("Ephemeral encryption to components failed: {e}"),
            );
        }
    }

    result
}

/// Decrypt ephemeral encrypted data.
///
/// # Security Events
///
/// Generates `encryption.ephemeral_decrypt` event on success or failure.
pub fn decrypt(encrypted: &EphemeralEncryption) -> Result<Vec<u8>, CryptoError> {
    let result = encrypted.decrypt();

    match &result {
        Ok(plaintext) => {
            observe::info(
                "ephemeral_decrypt",
                format!("Ephemeral decryption completed ({} bytes)", plaintext.len()),
            );
        }
        Err(e) => {
            observe::warn(
                "ephemeral_decrypt",
                format!("Ephemeral decryption failed: {e}"),
            );
        }
    }

    result
}

/// Decrypt and immediately destroy the encryption key.
///
/// After calling this, the `EphemeralEncryption` instance can no longer
/// decrypt (subsequent calls will fail). This provides explicit key
/// destruction for maximum forward secrecy.
pub fn decrypt_and_destroy(encrypted: &mut EphemeralEncryption) -> Result<Vec<u8>, CryptoError> {
    let result = encrypted.decrypt_and_destroy();

    match &result {
        Ok(plaintext) => {
            observe::info(
                "ephemeral_decrypt",
                format!(
                    "Ephemeral decryption with key destruction completed ({} bytes)",
                    plaintext.len()
                ),
            );
        }
        Err(e) => {
            observe::warn(
                "ephemeral_decrypt",
                format!("Ephemeral decryption with key destruction failed: {e}"),
            );
        }
    }

    result
}

/// Reconstruct an EphemeralEncryption from stored components.
///
/// Use this to reconstruct an encrypted message from serialized data.
pub fn from_components(
    ciphertext: Vec<u8>,
    nonce: &[u8],
    key: &[u8],
) -> Result<EphemeralEncryption, CryptoError> {
    EphemeralEncryption::from_components(ciphertext, nonce, key)
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
#[allow(clippy::panic, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn test_encrypt_decrypt() {
        let data = b"test message";
        let encrypted = encrypt(data).expect("Encryption failed");
        let decrypted = decrypt(&encrypted).expect("Decryption failed");
        assert_eq!(decrypted.as_slice(), data);
    }

    #[test]
    fn test_encrypt_to_components() {
        let data = b"component test";
        let (ciphertext, nonce, key) = encrypt_to_components(data).expect("Encryption failed");

        let restored = from_components(ciphertext, &nonce, &key).expect("Restore failed");
        let decrypted = decrypt(&restored).expect("Decryption failed");
        assert_eq!(decrypted.as_slice(), data);
    }

    #[test]
    fn test_decrypt_and_destroy() {
        let data = b"destroy after reading";
        let mut encrypted = encrypt(data).expect("Encryption failed");

        let decrypted = decrypt_and_destroy(&mut encrypted).expect("Decryption failed");
        assert_eq!(decrypted.as_slice(), data);

        // Key should now be destroyed - further decryption will fail
        assert!(encrypted.is_key_destroyed());
    }

    #[test]
    fn test_unique_ciphertext() {
        let data = b"same data";
        let enc1 = encrypt(data).expect("Encryption 1 failed");
        let enc2 = encrypt(data).expect("Encryption 2 failed");

        // Same plaintext should produce different ciphertext
        assert_ne!(enc1.ciphertext(), enc2.ciphertext());
    }
}
