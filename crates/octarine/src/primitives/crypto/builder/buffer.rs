//! Buffer builder for secure in-memory storage.

use super::super::CryptoError;
use super::super::secrets::PrimitiveSecureBuffer;

/// Builder for secure buffer operations
///
/// Provides methods for creating and managing encrypted in-memory buffers
/// using ChaCha20-Poly1305 AEAD encryption.
///
/// # Security Features
///
/// - Per-buffer ephemeral keys
/// - Automatic zeroization on drop
/// - Closure-based access to prevent key leakage
/// - AEAD encryption with authentication
#[derive(Debug, Clone, Default)]
pub struct BufferBuilder {
    _private: (),
}

impl BufferBuilder {
    /// Create a new BufferBuilder
    #[must_use]
    pub fn new() -> Self {
        Self { _private: () }
    }

    /// Create a new secure buffer from plaintext data
    ///
    /// The data is immediately encrypted and the original is zeroized.
    ///
    /// # Arguments
    ///
    /// * `data` - The plaintext data to encrypt (consumed and zeroized)
    ///
    /// # Returns
    ///
    /// A `PrimitiveSecureBuffer` containing the encrypted data.
    ///
    /// # Errors
    ///
    /// Returns `CryptoError` if encryption fails.
    ///
    /// # Example
    ///
    /// ```ignore
    /// let crypto = CryptoBuilder::new();
    /// let buffer = crypto.buffer().create(b"my-secret".to_vec())?;
    /// ```
    pub fn create(&self, data: Vec<u8>) -> Result<PrimitiveSecureBuffer, CryptoError> {
        PrimitiveSecureBuffer::new(data)
    }

    /// Restore a secure buffer from existing encrypted components
    ///
    /// Use this to restore a previously serialized buffer.
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
    ) -> Result<PrimitiveSecureBuffer, CryptoError> {
        PrimitiveSecureBuffer::from_components(ciphertext, nonce, key)
    }

    /// Check if data is empty (without creating a buffer)
    ///
    /// Useful for validation before buffer creation.
    #[must_use]
    pub fn is_empty(&self, data: &[u8]) -> bool {
        data.is_empty()
    }
}

#[cfg(test)]
#[allow(clippy::panic, clippy::expect_used)]
mod tests {
    use super::super::CryptoBuilder;

    #[test]
    fn test_buffer_create() {
        let crypto = CryptoBuilder::new();
        let buffer = crypto
            .buffer()
            .create(b"test-secret".to_vec())
            .expect("Failed to create buffer");

        buffer
            .with_decrypted(|data| {
                assert_eq!(data, b"test-secret");
            })
            .expect("Failed to decrypt");
    }

    #[test]
    fn test_buffer_restore() {
        let crypto = CryptoBuilder::new();
        let buffer = crypto
            .buffer()
            .create(b"component-test".to_vec())
            .expect("Failed to create buffer");

        let (ciphertext, nonce, key) = buffer.export_components();

        let restored = crypto
            .buffer()
            .restore(ciphertext.to_vec(), nonce, key)
            .expect("Failed to restore");

        restored
            .with_decrypted(|data| {
                assert_eq!(data, b"component-test");
            })
            .expect("Failed to decrypt");
    }

    #[test]
    fn test_buffer_is_empty() {
        let crypto = CryptoBuilder::new();
        assert!(crypto.buffer().is_empty(&[]));
        assert!(!crypto.buffer().is_empty(b"data"));
    }
}
