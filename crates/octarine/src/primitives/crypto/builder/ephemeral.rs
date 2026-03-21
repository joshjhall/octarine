//! Ephemeral encryption builder for forward-secrecy encryption.

use super::super::CryptoError;
use super::super::encryption::{EncryptedComponents, EphemeralEncryption};

/// Builder for ephemeral encryption operations
///
/// Provides methods for one-time encryption with maximum forward secrecy.
/// Each encryption generates unique keys that can be destroyed after use.
///
/// # Security Features
///
/// - Fresh random key per encryption
/// - Key destruction after decryption
/// - Authenticated encryption (ChaCha20-Poly1305)
/// - Unique ciphertext for identical plaintext
#[derive(Debug, Clone, Default)]
pub struct EphemeralBuilder {
    _private: (),
}

impl EphemeralBuilder {
    /// Create a new EphemeralBuilder
    #[must_use]
    pub fn new() -> Self {
        Self { _private: () }
    }

    /// Encrypt data with ephemeral keys
    ///
    /// Generates a fresh random key and nonce. The key is stored with the
    /// ciphertext and zeroized when the encryption is dropped.
    ///
    /// # Arguments
    ///
    /// * `data` - The plaintext to encrypt
    ///
    /// # Returns
    ///
    /// An `EphemeralEncryption` that can decrypt the data.
    ///
    /// # Errors
    ///
    /// Returns `CryptoError` if encryption fails.
    ///
    /// # Example
    ///
    /// ```ignore
    /// let crypto = CryptoBuilder::new();
    /// let encrypted = crypto.ephemeral().encrypt(b"session-token")?;
    /// let decrypted = encrypted.decrypt()?;
    /// ```
    pub fn encrypt(&self, data: &[u8]) -> Result<EphemeralEncryption, CryptoError> {
        EphemeralEncryption::encrypt(data)
    }

    /// Encrypt data and return serializable components
    ///
    /// Returns an `EncryptedComponents` tuple for external storage.
    ///
    /// # Security Warning
    ///
    /// The key is sensitive! Store it securely.
    pub fn encrypt_to_components(&self, data: &[u8]) -> Result<EncryptedComponents, CryptoError> {
        EphemeralEncryption::encrypt_to_components(data)
    }

    /// Restore encryption from stored components
    ///
    /// # Arguments
    ///
    /// * `ciphertext` - The encrypted data
    /// * `nonce` - The 12-byte nonce
    /// * `key` - The 32-byte encryption key
    ///
    /// # Errors
    ///
    /// Returns `CryptoError` if component sizes are invalid.
    pub fn restore(
        &self,
        ciphertext: Vec<u8>,
        nonce: &[u8],
        key: &[u8],
    ) -> Result<EphemeralEncryption, CryptoError> {
        EphemeralEncryption::from_components(ciphertext, nonce, key)
    }
}

#[cfg(test)]
#[allow(clippy::panic, clippy::expect_used)]
mod tests {
    use super::super::CryptoBuilder;

    #[test]
    fn test_ephemeral_encrypt() {
        let crypto = CryptoBuilder::new();
        let encrypted = crypto
            .ephemeral()
            .encrypt(b"ephemeral-data")
            .expect("Failed to encrypt");

        let decrypted = encrypted.decrypt().expect("Failed to decrypt");
        assert_eq!(decrypted.as_slice(), b"ephemeral-data");
    }

    #[test]
    fn test_ephemeral_to_components() {
        let crypto = CryptoBuilder::new();
        let (ciphertext, nonce, key) = crypto
            .ephemeral()
            .encrypt_to_components(b"component-data")
            .expect("Failed to encrypt");

        let restored = crypto
            .ephemeral()
            .restore(ciphertext, &nonce, &key)
            .expect("Failed to restore");

        let decrypted = restored.decrypt().expect("Failed to decrypt");
        assert_eq!(decrypted.as_slice(), b"component-data");
    }

    #[test]
    fn test_ephemeral_unique_ciphertext() {
        let crypto = CryptoBuilder::new();
        let enc1 = crypto
            .ephemeral()
            .encrypt(b"same")
            .expect("Failed to encrypt 1");
        let enc2 = crypto
            .ephemeral()
            .encrypt(b"same")
            .expect("Failed to encrypt 2");

        // Same plaintext should produce different ciphertext
        assert_ne!(enc1.ciphertext(), enc2.ciphertext());
    }
}
