//! SecureBuffer - Encrypted in-memory buffer with observability
//!
//! A wrapper around `PrimitiveSecureBuffer` that adds observability instrumentation
//! for audit trails. Data is encrypted at rest using ChaCha20-Poly1305 and only
//! decrypted when accessed via closures.
//!
//! # Features
//!
//! - **Encrypted at rest**: Data encrypted using ChaCha20-Poly1305 AEAD
//! - **Per-buffer keys**: Each buffer has unique ephemeral encryption keys
//! - **Automatic zeroization**: Keys and plaintext zeroized on drop
//! - **Closure-based access**: Prevents key leakage
//! - **Audit trails**: Operations logged via observe
//!
//! # Example
//!
//! ```ignore
//! use octarine::crypto::secrets::SecureBuffer;
//!
//! // Create a secure buffer
//! let buffer = SecureBuffer::new(b"my-secret-key".to_vec())?;
//!
//! // Data is encrypted - access via closure
//! buffer.with_decrypted(|data| {
//!     assert_eq!(data, b"my-secret-key");
//! })?;
//! ```
//!
//! # See Also
//!
//! - [`Secret`](super::Secret) - Simple wrapper with zeroization (no encryption)
//! - [`SecureMap`](super::SecureMap) - Named secret storage
//! - [`SecureEnvBuilder`](super::SecureEnvBuilder) - Subprocess environment builder

use crate::observe;
use crate::primitives::crypto::CryptoError;
use crate::primitives::crypto::secrets::PrimitiveSecureBuffer;

/// Encrypted in-memory buffer with observability
///
/// Wraps `PrimitiveSecureBuffer` with observe instrumentation for audit trails.
/// Data is encrypted using ChaCha20-Poly1305 with per-buffer ephemeral keys.
///
/// # Security Model
///
/// This buffer protects against:
/// - Memory dumps revealing plaintext
/// - Memory scanning for sensitive patterns
/// - Cold boot attacks (data encrypted, key zeroized on drop)
///
/// This buffer does NOT protect against:
/// - Active memory introspection during decryption
/// - Side-channel attacks on the local machine
/// - Compromised process memory access
///
/// # Example
///
/// ```ignore
/// use octarine::crypto::secrets::SecureBuffer;
///
/// // Store an API key securely
/// let api_key = b"sk-1234567890abcdef".to_vec();
/// let secure = SecureBuffer::new(api_key)?;
///
/// // Use the key (decrypted only in closure scope)
/// secure.with_decrypted(|key| {
///     let key_str = std::str::from_utf8(key).unwrap();
///     println!("Using key: {}...", &key_str[..8]);
/// })?;
/// ```
pub struct SecureBuffer {
    inner: PrimitiveSecureBuffer,
}

impl SecureBuffer {
    /// Create a new secure buffer with the given plaintext data.
    ///
    /// The data is immediately encrypted and the original plaintext is zeroized.
    /// A new ephemeral key is generated for this buffer.
    ///
    /// # Arguments
    ///
    /// * `data` - The plaintext data to encrypt. This will be consumed and zeroized.
    ///
    /// # Returns
    ///
    /// A new `SecureBuffer` containing the encrypted data.
    ///
    /// # Errors
    ///
    /// Returns `CryptoError::RandomGeneration` if key/nonce generation fails.
    /// Returns `CryptoError::Encryption` if encryption fails.
    ///
    /// # Example
    ///
    /// ```ignore
    /// use octarine::crypto::secrets::SecureBuffer;
    ///
    /// let secret = b"my-secret-password".to_vec();
    /// let buffer = SecureBuffer::new(secret)?;
    /// // `secret` is consumed, original Vec is gone
    /// ```
    pub fn new(data: Vec<u8>) -> Result<Self, CryptoError> {
        let len = data.len();
        let result = PrimitiveSecureBuffer::new(data);

        match &result {
            Ok(_) => {
                observe::debug(
                    "crypto.secrets.buffer.new",
                    format!("Created SecureBuffer with {} bytes", len),
                );
            }
            Err(e) => {
                observe::warn(
                    "crypto.secrets.buffer.new",
                    format!("Failed to create SecureBuffer: {}", e),
                );
            }
        }

        result.map(|inner| Self { inner })
    }

    /// Create a secure buffer from existing encrypted components.
    ///
    /// This is useful for deserializing a previously serialized SecureBuffer.
    ///
    /// # Arguments
    ///
    /// * `ciphertext` - The encrypted data (includes auth tag)
    /// * `nonce` - The 12-byte nonce used during encryption
    /// * `key` - The 32-byte encryption key
    ///
    /// # Returns
    ///
    /// A `SecureBuffer` that can decrypt the provided ciphertext.
    ///
    /// # Errors
    ///
    /// Returns `CryptoError::InvalidNonce` if the nonce is not 12 bytes.
    /// Returns `CryptoError::InvalidKey` if the key is not 32 bytes.
    ///
    /// # Security Note
    ///
    /// This function does NOT verify the ciphertext. Call `with_decrypted`
    /// to verify the data can be successfully decrypted.
    pub fn from_components(
        ciphertext: Vec<u8>,
        nonce: &[u8],
        key: &[u8],
    ) -> Result<Self, CryptoError> {
        let result = PrimitiveSecureBuffer::from_components(ciphertext, nonce, key);

        match &result {
            Ok(_) => {
                observe::debug(
                    "crypto.secrets.buffer.restore",
                    "Restored SecureBuffer from components",
                );
            }
            Err(e) => {
                observe::warn(
                    "crypto.secrets.buffer.restore",
                    format!("Failed to restore SecureBuffer: {}", e),
                );
            }
        }

        result.map(|inner| Self { inner })
    }

    /// Access the decrypted data via a closure.
    ///
    /// The data is decrypted into a temporary buffer, passed to the closure,
    /// and then zeroized immediately after the closure returns. This pattern
    /// ensures the plaintext exists in memory for the minimum time possible.
    ///
    /// # Arguments
    ///
    /// * `f` - A closure that receives a reference to the decrypted data
    ///
    /// # Returns
    ///
    /// The return value of the closure, or an error if decryption fails.
    ///
    /// # Errors
    ///
    /// Returns `CryptoError::Decryption` if decryption fails (e.g., data corrupted
    /// or tampered with).
    ///
    /// # Example
    ///
    /// ```ignore
    /// use octarine::crypto::secrets::SecureBuffer;
    ///
    /// let buffer = SecureBuffer::new(b"secret".to_vec())?;
    ///
    /// let length = buffer.with_decrypted(|data| {
    ///     data.len()
    /// })?;
    ///
    /// assert_eq!(length, 6);
    /// ```
    pub fn with_decrypted<F, R>(&self, f: F) -> Result<R, CryptoError>
    where
        F: FnOnce(&[u8]) -> R,
    {
        observe::trace(
            "crypto.secrets.buffer.access",
            "Decrypting buffer for read access",
        );
        self.inner.with_decrypted(f)
    }

    /// Access the decrypted data mutably via a closure.
    ///
    /// Similar to `with_decrypted`, but allows modifying the data. After the
    /// closure returns, the modified data is re-encrypted with a new nonce.
    ///
    /// # Arguments
    ///
    /// * `f` - A closure that receives a mutable reference to the decrypted data
    ///
    /// # Returns
    ///
    /// The return value of the closure, or an error if decryption/re-encryption fails.
    ///
    /// # Errors
    ///
    /// Returns `CryptoError::Decryption` if decryption fails.
    /// Returns `CryptoError::Encryption` if re-encryption fails.
    ///
    /// # Example
    ///
    /// ```ignore
    /// use octarine::crypto::secrets::SecureBuffer;
    ///
    /// let mut buffer = SecureBuffer::new(b"hello".to_vec())?;
    ///
    /// buffer.with_decrypted_mut(|data| {
    ///     data.push(b'!');
    /// })?;
    ///
    /// buffer.with_decrypted(|data| {
    ///     assert_eq!(data, b"hello!");
    /// })?;
    /// ```
    pub fn with_decrypted_mut<F, R>(&mut self, f: F) -> Result<R, CryptoError>
    where
        F: FnOnce(&mut Vec<u8>) -> R,
    {
        observe::trace(
            "crypto.secrets.buffer.access",
            "Decrypting buffer for write access",
        );
        self.inner.with_decrypted_mut(f)
    }

    /// Get the length of the plaintext data.
    ///
    /// This returns the length of the original (unencrypted) data without
    /// requiring decryption.
    #[inline]
    #[must_use]
    pub fn len(&self) -> usize {
        self.inner.len()
    }

    /// Check if the buffer is empty.
    #[inline]
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }

    /// Get the ciphertext for serialization.
    ///
    /// # Security Note
    ///
    /// The ciphertext alone cannot be decrypted without the key.
    /// Use `export_components` if you need to serialize the full buffer.
    #[inline]
    #[must_use]
    pub fn ciphertext(&self) -> &[u8] {
        self.inner.ciphertext()
    }

    /// Get the nonce for serialization.
    #[inline]
    #[must_use]
    pub fn nonce(&self) -> &[u8; 12] {
        self.inner.nonce()
    }

    /// Export components for serialization.
    ///
    /// Returns (ciphertext, nonce, key) for storing the buffer externally.
    ///
    /// # Security Warning
    ///
    /// The key is sensitive! Ensure it is stored securely (e.g., encrypted
    /// with a master key, stored in a hardware security module, etc.).
    ///
    /// # Returns
    ///
    /// A tuple of (ciphertext, nonce, key) that can be used to reconstruct
    /// the buffer via `from_components`.
    #[must_use]
    pub fn export_components(&self) -> (&[u8], &[u8; 12], &[u8; 32]) {
        observe::debug(
            "crypto.secrets.buffer.export",
            "Exporting SecureBuffer components",
        );
        self.inner.export_components()
    }

    /// Get a reference to the inner primitive buffer.
    ///
    /// This is useful for advanced operations or when you need to pass
    /// the buffer to functions expecting the primitive type.
    #[must_use]
    pub fn inner(&self) -> &PrimitiveSecureBuffer {
        &self.inner
    }

    /// Consume this wrapper and return the inner primitive buffer.
    #[must_use]
    pub fn into_inner(self) -> PrimitiveSecureBuffer {
        self.inner
    }
}

impl Clone for SecureBuffer {
    fn clone(&self) -> Self {
        observe::trace("crypto.secrets.buffer.clone", "Cloning SecureBuffer");
        Self {
            inner: self.inner.clone(),
        }
    }
}

impl std::fmt::Debug for SecureBuffer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SecureBuffer")
            .field("plaintext_len", &self.inner.len())
            .field("ciphertext_len", &self.inner.ciphertext().len())
            .field("nonce", &"[REDACTED]")
            .field("key", &"[REDACTED]")
            .finish()
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
#[allow(clippy::panic, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn test_new_and_decrypt() {
        let data = b"hello world".to_vec();
        let buffer = SecureBuffer::new(data).expect("Failed to create buffer");

        buffer
            .with_decrypted(|decrypted| {
                assert_eq!(decrypted, b"hello world");
            })
            .expect("Failed to decrypt");
    }

    #[test]
    fn test_empty_data() {
        let buffer = SecureBuffer::new(Vec::new()).expect("Failed to create buffer");
        assert!(buffer.is_empty());
        assert_eq!(buffer.len(), 0);

        buffer
            .with_decrypted(|decrypted| {
                assert!(decrypted.is_empty());
            })
            .expect("Failed to decrypt");
    }

    #[test]
    fn test_with_decrypted_mut() {
        let mut buffer = SecureBuffer::new(b"hello".to_vec()).expect("Failed to create buffer");

        buffer
            .with_decrypted_mut(|data| {
                data.extend_from_slice(b" world");
            })
            .expect("Failed to modify");

        buffer
            .with_decrypted(|decrypted| {
                assert_eq!(decrypted, b"hello world");
            })
            .expect("Failed to decrypt");
    }

    #[test]
    fn test_from_components() {
        let original = SecureBuffer::new(b"secret".to_vec()).expect("Failed to create buffer");

        let (ciphertext, nonce, key) = original.export_components();

        let restored = SecureBuffer::from_components(ciphertext.to_vec(), nonce, key)
            .expect("Failed to restore buffer");

        restored
            .with_decrypted(|decrypted| {
                assert_eq!(decrypted, b"secret");
            })
            .expect("Failed to decrypt");
    }

    #[test]
    fn test_clone() {
        let original = SecureBuffer::new(b"clone me".to_vec()).expect("Failed to create buffer");
        let cloned = original.clone();

        // Both should decrypt to same data
        original
            .with_decrypted(|decrypted| {
                assert_eq!(decrypted, b"clone me");
            })
            .expect("Failed to decrypt original");

        cloned
            .with_decrypted(|decrypted| {
                assert_eq!(decrypted, b"clone me");
            })
            .expect("Failed to decrypt clone");
    }

    #[test]
    fn test_debug_redacts_sensitive_info() {
        let buffer = SecureBuffer::new(b"secret".to_vec()).expect("Failed to create buffer");
        let debug_str = format!("{:?}", buffer);

        assert!(debug_str.contains("SecureBuffer"));
        assert!(debug_str.contains("[REDACTED]"));
        assert!(!debug_str.contains("secret"));
    }

    #[test]
    fn test_inner_access() {
        let buffer = SecureBuffer::new(b"test".to_vec()).expect("Failed to create buffer");

        // Can access inner primitive
        let inner = buffer.inner();
        assert_eq!(inner.len(), 4);

        // Can consume into inner
        let inner = buffer.into_inner();
        inner
            .with_decrypted(|data| {
                assert_eq!(data, b"test");
            })
            .expect("Failed to decrypt");
    }
}
