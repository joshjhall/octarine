//! PrimitiveSecureBuffer - Encrypted in-memory buffer (Layer 1 primitive)
//!
//! Encrypted in-memory buffer using ChaCha20-Poly1305 AEAD encryption.
//! Data is encrypted at rest and only decrypted when accessed via closures.
//!
//! This is the Layer 1 primitive without observability - use
//! `octarine::crypto::secrets::SecureBuffer` for the instrumented version.
//!
//! ## Security Features
//!
//! - **Per-buffer ephemeral keys**: Each buffer generates its own encryption key
//! - **Automatic zeroization**: Keys and plaintext are zeroized on drop
//! - **Safe access patterns**: Closure-based API prevents key leakage
//! - **AEAD encryption**: ChaCha20-Poly1305 provides authenticated encryption
//!
//! ## Limitations
//!
//! - **No streaming support**: Entire plaintext is loaded into memory during access.
//!   For large files, use chunked encryption at a higher layer.
//! - **Not persistent**: For long-term storage, use [`PersistentEncryption`].
//!
//! ## Example
//!
//! ```ignore
//! use crate::primitives::crypto::secrets::PrimitiveSecureBuffer;
//!
//! let secret = b"sensitive-data".to_vec();
//! let buffer = PrimitiveSecureBuffer::new(secret)?;
//!
//! // Data is encrypted in memory
//! // Access via closure - decrypted only during closure execution
//! buffer.with_decrypted(|data| {
//!     assert_eq!(data, b"sensitive-data");
//! })?;
//! ```
//!
//! ## See Also
//!
//! - [`EphemeralEncryption`](super::EphemeralEncryption) - Forward-secrecy encryption
//!   where each encryption has unique keys
//! - [`PersistentEncryption`](super::PersistentEncryption) - Post-quantum encryption
//!   for long-term storage
//! - [`LockedBox`](super::LockedBox) - Memory-locked container with mlock hints
//! - [`Secret`](super::Secret) - Zeroizing wrapper without encryption

// Allow dead_code: These are Layer 1 primitives that will be used by Layer 2/3 modules
#![allow(dead_code)]

use chacha20poly1305::{
    ChaCha20Poly1305, Nonce,
    aead::{Aead, KeyInit},
};
use zeroize::Zeroize;

use crate::primitives::crypto::{CryptoError, keys::fill_random};

/// ChaCha20-Poly1305 key size (256 bits)
const KEY_SIZE: usize = 32;

/// ChaCha20-Poly1305 nonce size (96 bits)
const NONCE_SIZE: usize = 12;

/// A secure buffer that encrypts data at rest in memory.
///
/// `PrimitiveSecureBuffer` provides encrypted storage for sensitive data. The data is
/// encrypted using ChaCha20-Poly1305 with a per-buffer ephemeral key. The key
/// is stored alongside the ciphertext but is zeroized when the buffer is dropped.
///
/// ## Security Model
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
/// ## Thread Safety
///
/// `PrimitiveSecureBuffer` is `Send + Sync` because:
/// - The ciphertext is immutable after creation
/// - Decryption creates a temporary copy (no shared mutable state)
/// - The key is only accessed during encrypt/decrypt operations
///
/// ## Example
///
/// ```ignore
/// use crate::primitives::crypto::secrets::PrimitiveSecureBuffer;
///
/// // Store an API key securely
/// let api_key = b"sk-1234567890abcdef".to_vec();
/// let secure = PrimitiveSecureBuffer::new(api_key)?;
///
/// // Use the key (decrypted only in closure scope)
/// secure.with_decrypted(|key| {
///     // Make API call with key
///     let key_str = std::str::from_utf8(key).unwrap();
///     println!("Using key: {}...", &key_str[..8]);
/// })?;
/// ```
pub struct PrimitiveSecureBuffer {
    /// The encrypted ciphertext (includes auth tag)
    ciphertext: Vec<u8>,

    /// The nonce used for encryption (unique per buffer)
    nonce: [u8; NONCE_SIZE],

    /// The encryption key (zeroized on drop)
    key: [u8; KEY_SIZE],

    /// Original plaintext length (for pre-allocation on decrypt)
    plaintext_len: usize,
}

impl Drop for PrimitiveSecureBuffer {
    fn drop(&mut self) {
        // Zeroize the key on drop - this is the sensitive material
        self.key.zeroize();
    }
}

impl PrimitiveSecureBuffer {
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
    /// A new `PrimitiveSecureBuffer` containing the encrypted data.
    ///
    /// # Errors
    ///
    /// Returns `CryptoError::RandomGeneration` if key/nonce generation fails.
    /// Returns `CryptoError::Encryption` if encryption fails.
    ///
    /// # Example
    ///
    /// ```ignore
    /// use crate::primitives::crypto::secrets::PrimitiveSecureBuffer;
    ///
    /// let secret = b"my-secret-password".to_vec();
    /// let buffer = PrimitiveSecureBuffer::new(secret)?;
    /// // `secret` is consumed, original Vec is gone
    /// ```
    pub fn new(mut data: Vec<u8>) -> Result<Self, CryptoError> {
        // Generate ephemeral key using internal random primitive
        let mut key = [0u8; KEY_SIZE];
        fill_random(&mut key)?;

        // Generate random nonce using internal random primitive
        let mut nonce = [0u8; NONCE_SIZE];
        fill_random(&mut nonce)?;

        // Store plaintext length for efficient reallocation
        let plaintext_len = data.len();

        // Encrypt the data
        let cipher = ChaCha20Poly1305::new_from_slice(&key)
            .map_err(|e| CryptoError::invalid_key(format!("Failed to create cipher: {e}")))?;

        let nonce_ref = Nonce::from_slice(&nonce);
        let ciphertext = cipher
            .encrypt(nonce_ref, data.as_slice())
            .map_err(|e| CryptoError::encryption(format!("Encryption failed: {e}")))?;

        // Zeroize the original plaintext
        data.zeroize();

        Ok(Self {
            ciphertext,
            nonce,
            key,
            plaintext_len,
        })
    }

    /// Create a secure buffer from existing encrypted components.
    ///
    /// This is useful for deserializing a previously serialized PrimitiveSecureBuffer.
    ///
    /// # Arguments
    ///
    /// * `ciphertext` - The encrypted data (includes auth tag)
    /// * `nonce` - The 12-byte nonce used during encryption
    /// * `key` - The 32-byte encryption key
    ///
    /// # Returns
    ///
    /// A `PrimitiveSecureBuffer` that can decrypt the provided ciphertext.
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
        if nonce.len() != NONCE_SIZE {
            return Err(CryptoError::invalid_nonce(format!(
                "Nonce must be {} bytes, got {}",
                NONCE_SIZE,
                nonce.len()
            )));
        }

        if key.len() != KEY_SIZE {
            return Err(CryptoError::invalid_key(format!(
                "Key must be {} bytes, got {}",
                KEY_SIZE,
                key.len()
            )));
        }

        let mut nonce_arr = [0u8; NONCE_SIZE];
        nonce_arr.copy_from_slice(nonce);

        let mut key_arr = [0u8; KEY_SIZE];
        key_arr.copy_from_slice(key);

        // Estimate plaintext length (ciphertext - auth tag)
        let plaintext_len = ciphertext.len().saturating_sub(16);

        Ok(Self {
            ciphertext,
            nonce: nonce_arr,
            key: key_arr,
            plaintext_len,
        })
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
    /// use crate::primitives::crypto::secrets::PrimitiveSecureBuffer;
    ///
    /// let buffer = PrimitiveSecureBuffer::new(b"secret".to_vec())?;
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
        let mut plaintext = self.decrypt()?;
        let result = f(&plaintext);
        plaintext.zeroize();
        Ok(result)
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
    /// use crate::primitives::crypto::secrets::PrimitiveSecureBuffer;
    ///
    /// let mut buffer = PrimitiveSecureBuffer::new(b"hello".to_vec())?;
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
        let mut plaintext = self.decrypt()?;
        let result = f(&mut plaintext);

        // Re-encrypt with new nonce (same key)
        self.encrypt_in_place(&mut plaintext)?;

        Ok(result)
    }

    /// Decrypt the buffer contents.
    ///
    /// Internal helper that decrypts the ciphertext and returns the plaintext.
    /// The caller is responsible for zeroizing the returned data.
    fn decrypt(&self) -> Result<Vec<u8>, CryptoError> {
        let cipher = ChaCha20Poly1305::new_from_slice(&self.key)
            .map_err(|e| CryptoError::invalid_key(format!("Failed to create cipher: {e}")))?;

        let nonce = Nonce::from_slice(&self.nonce);

        cipher
            .decrypt(nonce, self.ciphertext.as_slice())
            .map_err(|e| CryptoError::decryption(format!("Decryption failed: {e}")))
    }

    /// Re-encrypt the plaintext in place.
    ///
    /// Generates a new nonce and encrypts the plaintext.
    /// The plaintext is zeroized after encryption.
    fn encrypt_in_place(&mut self, plaintext: &mut Vec<u8>) -> Result<(), CryptoError> {
        // Generate new nonce using internal random primitive
        fill_random(&mut self.nonce)?;

        let cipher = ChaCha20Poly1305::new_from_slice(&self.key)
            .map_err(|e| CryptoError::invalid_key(format!("Failed to create cipher: {e}")))?;

        let nonce = Nonce::from_slice(&self.nonce);

        self.ciphertext = cipher
            .encrypt(nonce, plaintext.as_slice())
            .map_err(|e| CryptoError::encryption(format!("Encryption failed: {e}")))?;

        self.plaintext_len = plaintext.len();

        // Zeroize the plaintext
        plaintext.zeroize();

        Ok(())
    }

    /// Get the length of the plaintext data.
    ///
    /// This returns the length of the original (unencrypted) data without
    /// requiring decryption.
    #[inline]
    pub fn len(&self) -> usize {
        self.plaintext_len
    }

    /// Check if the buffer is empty.
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.plaintext_len == 0
    }

    /// Get the ciphertext for serialization.
    ///
    /// # Security Note
    ///
    /// The ciphertext alone cannot be decrypted without the key.
    /// Use `export_components` if you need to serialize the full buffer.
    #[inline]
    pub fn ciphertext(&self) -> &[u8] {
        &self.ciphertext
    }

    /// Get the nonce for serialization.
    #[inline]
    pub fn nonce(&self) -> &[u8; NONCE_SIZE] {
        &self.nonce
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
    pub fn export_components(&self) -> (&[u8], &[u8; NONCE_SIZE], &[u8; KEY_SIZE]) {
        (&self.ciphertext, &self.nonce, &self.key)
    }
}

impl Clone for PrimitiveSecureBuffer {
    /// Clone the secure buffer.
    ///
    /// The cloned buffer shares the same encrypted content but gets its own
    /// copy of the key. This is safe because the key is copied, not referenced.
    fn clone(&self) -> Self {
        Self {
            ciphertext: self.ciphertext.clone(),
            nonce: self.nonce,
            key: self.key,
            plaintext_len: self.plaintext_len,
        }
    }
}

impl std::fmt::Debug for PrimitiveSecureBuffer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PrimitiveSecureBuffer")
            .field("plaintext_len", &self.plaintext_len)
            .field("ciphertext_len", &self.ciphertext.len())
            .field("nonce", &"[REDACTED]")
            .field("key", &"[REDACTED]")
            .finish()
    }
}

// Note: PrimitiveSecureBuffer is automatically Send + Sync because all fields
// (Vec<u8>, [u8; N], usize) are Send + Sync. No manual implementation needed.

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
        let buffer = PrimitiveSecureBuffer::new(data).expect("Failed to create buffer");

        buffer
            .with_decrypted(|decrypted| {
                assert_eq!(decrypted, b"hello world");
            })
            .expect("Failed to decrypt");
    }

    #[test]
    fn test_empty_data() {
        let buffer = PrimitiveSecureBuffer::new(Vec::new()).expect("Failed to create buffer");
        assert!(buffer.is_empty());
        assert_eq!(buffer.len(), 0);

        buffer
            .with_decrypted(|decrypted| {
                assert!(decrypted.is_empty());
            })
            .expect("Failed to decrypt");
    }

    #[test]
    fn test_large_data() {
        let data: Vec<u8> = (0..10000).map(|i| (i % 256) as u8).collect();
        let expected = data.clone();

        let buffer = PrimitiveSecureBuffer::new(data).expect("Failed to create buffer");
        assert_eq!(buffer.len(), 10000);

        buffer
            .with_decrypted(|decrypted| {
                assert_eq!(decrypted, &expected);
            })
            .expect("Failed to decrypt");
    }

    #[test]
    fn test_with_decrypted_mut() {
        let mut buffer =
            PrimitiveSecureBuffer::new(b"hello".to_vec()).expect("Failed to create buffer");

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
    fn test_with_decrypted_mut_returns_value() {
        let mut buffer =
            PrimitiveSecureBuffer::new(b"test".to_vec()).expect("Failed to create buffer");

        let len = buffer
            .with_decrypted_mut(|data| {
                data.push(b'!');
                data.len()
            })
            .expect("Failed to modify");

        assert_eq!(len, 5);
    }

    #[test]
    fn test_from_components() {
        let original =
            PrimitiveSecureBuffer::new(b"secret".to_vec()).expect("Failed to create buffer");

        let (ciphertext, nonce, key) = original.export_components();

        let restored = PrimitiveSecureBuffer::from_components(ciphertext.to_vec(), nonce, key)
            .expect("Failed to restore buffer");

        restored
            .with_decrypted(|decrypted| {
                assert_eq!(decrypted, b"secret");
            })
            .expect("Failed to decrypt");
    }

    #[test]
    fn test_from_components_invalid_nonce() {
        let result =
            PrimitiveSecureBuffer::from_components(vec![1, 2, 3], &[0u8; 8], &[0u8; KEY_SIZE]);

        assert!(result.is_err());
        assert!(matches!(result, Err(CryptoError::InvalidNonce(_))));
    }

    #[test]
    fn test_from_components_invalid_key() {
        let result =
            PrimitiveSecureBuffer::from_components(vec![1, 2, 3], &[0u8; NONCE_SIZE], &[0u8; 16]);

        assert!(result.is_err());
        assert!(matches!(result, Err(CryptoError::InvalidKey(_))));
    }

    #[test]
    fn test_clone() {
        let original =
            PrimitiveSecureBuffer::new(b"clone me".to_vec()).expect("Failed to create buffer");
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
        let buffer =
            PrimitiveSecureBuffer::new(b"secret".to_vec()).expect("Failed to create buffer");
        let debug_str = format!("{:?}", buffer);

        assert!(debug_str.contains("PrimitiveSecureBuffer"));
        assert!(debug_str.contains("[REDACTED]"));
        assert!(!debug_str.contains("secret"));
    }

    #[test]
    fn test_ciphertext_differs_from_plaintext() {
        let data = b"sensitive data".to_vec();
        let buffer = PrimitiveSecureBuffer::new(data).expect("Failed to create buffer");

        // Ciphertext should not contain the plaintext
        let ciphertext_str = String::from_utf8_lossy(buffer.ciphertext());
        assert!(!ciphertext_str.contains("sensitive data"));
    }

    #[test]
    fn test_each_buffer_has_unique_encryption() {
        let buffer1 =
            PrimitiveSecureBuffer::new(b"same data".to_vec()).expect("Failed to create buffer 1");
        let buffer2 =
            PrimitiveSecureBuffer::new(b"same data".to_vec()).expect("Failed to create buffer 2");

        // Different keys should produce different ciphertext
        assert_ne!(buffer1.ciphertext(), buffer2.ciphertext());
    }

    #[test]
    fn test_nonce_changes_on_mutation() {
        let mut buffer =
            PrimitiveSecureBuffer::new(b"data".to_vec()).expect("Failed to create buffer");
        let original_nonce = *buffer.nonce();

        buffer
            .with_decrypted_mut(|data| {
                data.push(b'!');
            })
            .expect("Failed to modify");

        // Nonce should change after re-encryption
        assert_ne!(*buffer.nonce(), original_nonce);
    }

    #[test]
    fn test_len_and_is_empty() {
        let empty = PrimitiveSecureBuffer::new(Vec::new()).expect("Failed to create empty buffer");
        assert!(empty.is_empty());
        assert_eq!(empty.len(), 0);

        let non_empty =
            PrimitiveSecureBuffer::new(b"data".to_vec()).expect("Failed to create buffer");
        assert!(!non_empty.is_empty());
        assert_eq!(non_empty.len(), 4);
    }

    #[test]
    fn test_corrupted_ciphertext_fails_decryption() {
        let buffer =
            PrimitiveSecureBuffer::new(b"secret".to_vec()).expect("Failed to create buffer");
        let (mut ciphertext, nonce, key) = (
            buffer.ciphertext().to_vec(),
            *buffer.nonce(),
            // We need to extract the key, so we use export_components
            buffer.export_components().2,
        );

        // Corrupt the ciphertext
        if let Some(first) = ciphertext.first_mut() {
            *first ^= 0xFF;
        }

        let corrupted = PrimitiveSecureBuffer::from_components(ciphertext, &nonce, key)
            .expect("Failed to restore");

        let result = corrupted.with_decrypted(|_| {});
        assert!(result.is_err());
        assert!(matches!(result, Err(CryptoError::Decryption(_))));
    }

    #[test]
    fn test_thread_safety() {
        use std::sync::Arc;
        use std::thread;

        let buffer = Arc::new(
            PrimitiveSecureBuffer::new(b"shared secret".to_vec()).expect("Failed to create"),
        );

        let handles: Vec<_> = (0..4)
            .map(|_| {
                let buf = Arc::clone(&buffer);
                thread::spawn(move || {
                    buf.with_decrypted(|data| {
                        assert_eq!(data, b"shared secret");
                    })
                    .expect("Failed to decrypt");
                })
            })
            .collect();

        for handle in handles {
            handle.join().expect("Thread panicked");
        }
    }

    // =========================================================================
    // Edge Case Tests
    // =========================================================================

    #[test]
    fn test_sequential_mutations_multiple_rounds() {
        // Test that multiple sequential mutations work correctly
        // and that each mutation generates a new nonce
        let mut buffer =
            PrimitiveSecureBuffer::new(b"start".to_vec()).expect("Failed to create buffer");
        let mut nonces: Vec<[u8; NONCE_SIZE]> = Vec::new();
        nonces.push(*buffer.nonce());

        // Perform 5 sequential mutations
        for i in 0..5 {
            buffer
                .with_decrypted_mut(|data| {
                    data.push(b'0' + i as u8);
                })
                .expect("Failed to modify");
            nonces.push(*buffer.nonce());
        }

        // Verify final content
        buffer
            .with_decrypted(|data| {
                assert_eq!(data, b"start01234");
            })
            .expect("Failed to decrypt");

        // Verify all nonces are unique (each mutation re-encrypts with new nonce)
        for (i, nonce_i) in nonces.iter().enumerate() {
            for (j, nonce_j) in nonces.iter().enumerate().skip(i + 1) {
                assert_ne!(nonce_i, nonce_j, "Nonces {} and {} should differ", i, j);
            }
        }
    }

    #[test]
    fn test_mutation_with_clear_and_refill() {
        // Test clearing and refilling the buffer through mutation
        let mut buffer =
            PrimitiveSecureBuffer::new(b"original content".to_vec()).expect("Failed to create");

        // Clear and set new content
        buffer
            .with_decrypted_mut(|data| {
                data.clear();
                data.extend_from_slice(b"completely new content");
            })
            .expect("Failed to modify");

        buffer
            .with_decrypted(|data| {
                assert_eq!(data, b"completely new content");
            })
            .expect("Failed to decrypt");

        // Verify length updated correctly
        assert_eq!(buffer.len(), 22);
    }

    #[test]
    fn test_mutation_shrink_data() {
        // Test shrinking data through mutation
        let mut buffer = PrimitiveSecureBuffer::new(b"very long content here".to_vec())
            .expect("Failed to create");
        assert_eq!(buffer.len(), 22);

        buffer
            .with_decrypted_mut(|data| {
                data.truncate(4);
            })
            .expect("Failed to modify");

        buffer
            .with_decrypted(|data| {
                assert_eq!(data, b"very");
            })
            .expect("Failed to decrypt");

        assert_eq!(buffer.len(), 4);
    }

    #[test]
    fn test_decryption_closure_return_values() {
        // Test that closures properly return values through the encryption boundary
        let buffer = PrimitiveSecureBuffer::new(b"test data for computations".to_vec())
            .expect("Failed to create buffer");

        // Complex computation in closure
        let result = buffer
            .with_decrypted(|data| {
                let sum: u32 = data.iter().map(|&b| u32::from(b)).sum();
                let len = data.len();
                (sum, len, data.first().copied())
            })
            .expect("Failed to decrypt");

        assert!(result.0 > 0);
        assert_eq!(result.1, 26);
        assert_eq!(result.2, Some(b't'));
    }

    #[test]
    fn test_binary_data_with_null_bytes() {
        // Test handling of binary data containing null bytes
        let data = vec![0x00, 0x01, 0x00, 0x02, 0x00, 0xFF, 0x00];
        let buffer = PrimitiveSecureBuffer::new(data.clone()).expect("Failed to create buffer");

        buffer
            .with_decrypted(|decrypted| {
                assert_eq!(decrypted, &data);
            })
            .expect("Failed to decrypt");
    }
}
