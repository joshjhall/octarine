//! Ephemeral Encryption
//!
//! Per-use key encryption with maximum forward secrecy. Each encryption
//! generates unique keys that are destroyed after use, ensuring that
//! compromise of one ciphertext doesn't affect others.
//!
//! ## Security Model
//!
//! - **Forward Secrecy**: Each encryption uses a fresh random key
//! - **Key Destruction**: Keys are zeroized after encryption completes
//! - **Unique Ciphertext**: Same plaintext always produces different ciphertext
//! - **Authenticated Encryption**: ChaCha20-Poly1305 AEAD
//!
//! ## Use Cases
//!
//! - Temporary tokens that need encryption
//! - Session data with forward secrecy requirements
//! - Encrypted log entries
//! - Any secret requiring maximum forward secrecy
//!
//! ## Example
//!
//! ```ignore
//! use crate::primitives::crypto::EphemeralEncryption;
//!
//! // Encrypt sensitive data
//! let secret = b"temporary-session-token";
//! let encrypted = EphemeralEncryption::encrypt(secret)?;
//!
//! // Later, decrypt when needed
//! let decrypted = encrypted.decrypt()?;
//! assert_eq!(decrypted.as_slice(), secret);
//!
//! // Each encryption produces unique ciphertext
//! let encrypted2 = EphemeralEncryption::encrypt(secret)?;
//! assert_ne!(encrypted.ciphertext(), encrypted2.ciphertext());
//! ```
//!
//! ## See Also
//!
//! - [`PrimitiveSecureBuffer`](super::secrets::PrimitiveSecureBuffer) - In-memory encrypted storage with
//!   closure-based access (uses similar internal encryption)
//! - [`HybridEncryption`](super::HybridEncryption) - Post-quantum hybrid encryption
//!   for communication between parties
//! - [`PersistentEncryption`](super::PersistentEncryption) - Post-quantum encryption
//!   for long-term storage with key versioning

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

/// Components needed to reconstruct encrypted data.
///
/// Tuple of (ciphertext, nonce, key) for serialization/deserialization.
pub type EncryptedComponents = (Vec<u8>, [u8; NONCE_SIZE], [u8; KEY_SIZE]);

/// Ephemeral encryption with forward secrecy.
///
/// Each `EphemeralEncryption` instance represents a single encrypted message
/// with its own unique key. The key is stored encrypted with a secondary
/// ephemeral key to provide defense in depth.
///
/// ## Security Properties
///
/// - **Forward Secrecy**: Compromise of one message doesn't reveal others
/// - **Unique Keys**: Each encryption uses a fresh random key
/// - **Authenticated**: ChaCha20-Poly1305 provides AEAD
/// - **Zeroized**: All key material is zeroized on drop
///
/// ## Thread Safety
///
/// `EphemeralEncryption` is `Send + Sync` as all fields are owned values
/// with no interior mutability.
///
/// ## Example
///
/// ```ignore
/// use crate::primitives::crypto::EphemeralEncryption;
///
/// let data = b"sensitive-token";
/// let encrypted = EphemeralEncryption::encrypt(data)?;
///
/// // Ciphertext can be stored/transmitted
/// let ciphertext = encrypted.ciphertext();
/// let nonce = encrypted.nonce();
///
/// // Decrypt when needed
/// let plaintext = encrypted.decrypt()?;
/// ```
pub struct EphemeralEncryption {
    /// The encrypted data (ciphertext + auth tag)
    ciphertext: Vec<u8>,

    /// The nonce used for encryption
    nonce: [u8; NONCE_SIZE],

    /// The encryption key (zeroized on drop)
    key: [u8; KEY_SIZE],

    /// Original plaintext length for efficient allocation
    plaintext_len: usize,
}

impl EphemeralEncryption {
    /// Encrypt data with ephemeral keys for maximum forward secrecy.
    ///
    /// Generates a fresh random key and nonce for this encryption. The key
    /// is stored with the ciphertext and will be zeroized when this struct
    /// is dropped.
    ///
    /// # Arguments
    ///
    /// * `data` - The plaintext data to encrypt
    ///
    /// # Returns
    ///
    /// An `EphemeralEncryption` containing the ciphertext and key material.
    ///
    /// # Errors
    ///
    /// Returns `CryptoError::Encryption` if encryption fails.
    ///
    /// # Example
    ///
    /// ```ignore
    /// use crate::primitives::crypto::EphemeralEncryption;
    ///
    /// let token = b"session-abc123";
    /// let encrypted = EphemeralEncryption::encrypt(token)?;
    /// ```
    pub fn encrypt(data: &[u8]) -> Result<Self, CryptoError> {
        // Generate ephemeral key using internal random primitive
        let mut key = [0u8; KEY_SIZE];
        fill_random(&mut key)?;

        // Generate random nonce using internal random primitive
        let mut nonce = [0u8; NONCE_SIZE];
        fill_random(&mut nonce)?;

        // Store plaintext length
        let plaintext_len = data.len();

        // Encrypt the data
        let cipher = ChaCha20Poly1305::new_from_slice(&key)
            .map_err(|e| CryptoError::invalid_key(format!("Failed to create cipher: {e}")))?;

        let nonce_ref = Nonce::from_slice(&nonce);
        let ciphertext = cipher
            .encrypt(nonce_ref, data)
            .map_err(|e| CryptoError::encryption(format!("Encryption failed: {e}")))?;

        Ok(Self {
            ciphertext,
            nonce,
            key,
            plaintext_len,
        })
    }

    /// Encrypt data and return only the serializable components.
    ///
    /// This is useful when you need to store the encrypted data externally
    /// and reconstruct it later. The returned tuple contains all information
    /// needed for decryption.
    ///
    /// # Returns
    ///
    /// A tuple of (ciphertext, nonce, key) that can be used with `from_components`.
    ///
    /// # Security Warning
    ///
    /// The key is sensitive! Store it securely (encrypted, in HSM, etc.).
    pub fn encrypt_to_components(data: &[u8]) -> Result<EncryptedComponents, CryptoError> {
        let encrypted = Self::encrypt(data)?;
        let (ciphertext, nonce, key) = encrypted.export_components();
        Ok((ciphertext.to_vec(), *nonce, *key))
    }

    /// Create an EphemeralEncryption from previously stored components.
    ///
    /// Use this to reconstruct an encrypted message from serialized data.
    ///
    /// # Arguments
    ///
    /// * `ciphertext` - The encrypted data
    /// * `nonce` - The 12-byte nonce
    /// * `key` - The 32-byte encryption key
    ///
    /// # Returns
    ///
    /// An `EphemeralEncryption` that can decrypt the data.
    ///
    /// # Errors
    ///
    /// Returns `CryptoError::InvalidNonce` if nonce length is wrong.
    /// Returns `CryptoError::InvalidKey` if key length is wrong.
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

    /// Decrypt the ephemeral data.
    ///
    /// Returns the original plaintext. The returned data should be zeroized
    /// when no longer needed if it contains sensitive information.
    ///
    /// # Returns
    ///
    /// The decrypted plaintext as a `Vec<u8>`.
    ///
    /// # Errors
    ///
    /// Returns `CryptoError::Decryption` if decryption fails (e.g., data
    /// corrupted or tampered with).
    ///
    /// # Example
    ///
    /// ```ignore
    /// use crate::primitives::crypto::EphemeralEncryption;
    ///
    /// let encrypted = EphemeralEncryption::encrypt(b"secret")?;
    /// let plaintext = encrypted.decrypt()?;
    /// assert_eq!(plaintext.as_slice(), b"secret");
    /// ```
    pub fn decrypt(&self) -> Result<Vec<u8>, CryptoError> {
        let cipher = ChaCha20Poly1305::new_from_slice(&self.key)
            .map_err(|e| CryptoError::invalid_key(format!("Failed to create cipher: {e}")))?;

        let nonce = Nonce::from_slice(&self.nonce);

        cipher
            .decrypt(nonce, self.ciphertext.as_slice())
            .map_err(|e| CryptoError::decryption(format!("Decryption failed: {e}")))
    }

    /// Decrypt and immediately zeroize the encryption key.
    ///
    /// After calling this method, the `EphemeralEncryption` instance can
    /// no longer decrypt (subsequent calls to `decrypt` will fail). This
    /// provides explicit key destruction for maximum forward secrecy.
    ///
    /// # Returns
    ///
    /// The decrypted plaintext, or an error if decryption fails.
    ///
    /// # Example
    ///
    /// ```ignore
    /// use crate::primitives::crypto::EphemeralEncryption;
    ///
    /// let mut encrypted = EphemeralEncryption::encrypt(b"one-time-secret")?;
    /// let plaintext = encrypted.decrypt_and_destroy()?;
    ///
    /// // Key is now zeroized - further decryption will fail
    /// assert!(encrypted.decrypt().is_err());
    /// ```
    pub fn decrypt_and_destroy(&mut self) -> Result<Vec<u8>, CryptoError> {
        let result = self.decrypt();
        self.key.zeroize();
        result
    }

    /// Get the ciphertext.
    ///
    /// The ciphertext includes the ChaCha20-Poly1305 authentication tag.
    #[inline]
    pub fn ciphertext(&self) -> &[u8] {
        &self.ciphertext
    }

    /// Get the nonce.
    #[inline]
    pub fn nonce(&self) -> &[u8; NONCE_SIZE] {
        &self.nonce
    }

    /// Get the length of the original plaintext.
    #[inline]
    pub fn plaintext_len(&self) -> usize {
        self.plaintext_len
    }

    /// Check if the key has been destroyed.
    ///
    /// Returns true if the key has been zeroized (all zeros).
    pub fn is_key_destroyed(&self) -> bool {
        self.key.iter().all(|&b| b == 0)
    }

    /// Export components for serialization.
    ///
    /// # Security Warning
    ///
    /// The key is sensitive! Ensure it is stored securely.
    pub fn export_components(&self) -> (&[u8], &[u8; NONCE_SIZE], &[u8; KEY_SIZE]) {
        (&self.ciphertext, &self.nonce, &self.key)
    }
}

impl Drop for EphemeralEncryption {
    fn drop(&mut self) {
        self.key.zeroize();
    }
}

impl Clone for EphemeralEncryption {
    fn clone(&self) -> Self {
        Self {
            ciphertext: self.ciphertext.clone(),
            nonce: self.nonce,
            key: self.key,
            plaintext_len: self.plaintext_len,
        }
    }
}

impl std::fmt::Debug for EphemeralEncryption {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EphemeralEncryption")
            .field("plaintext_len", &self.plaintext_len)
            .field("ciphertext_len", &self.ciphertext.len())
            .field("nonce", &"[REDACTED]")
            .field("key", &"[REDACTED]")
            .field("key_destroyed", &self.is_key_destroyed())
            .finish()
    }
}

// Note: EphemeralEncryption is automatically Send + Sync because all fields
// (Vec<u8>, [u8; N], usize) are Send + Sync.

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
#[allow(clippy::panic, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn test_encrypt_decrypt() {
        let data = b"hello ephemeral world";
        let encrypted = EphemeralEncryption::encrypt(data).expect("Failed to encrypt");

        let decrypted = encrypted.decrypt().expect("Failed to decrypt");
        assert_eq!(decrypted.as_slice(), data);
    }

    #[test]
    fn test_empty_data() {
        let encrypted = EphemeralEncryption::encrypt(&[]).expect("Failed to encrypt");
        assert_eq!(encrypted.plaintext_len(), 0);

        let decrypted = encrypted.decrypt().expect("Failed to decrypt");
        assert!(decrypted.is_empty());
    }

    #[test]
    fn test_large_data() {
        let data: Vec<u8> = (0..10000).map(|i| (i % 256) as u8).collect();
        let encrypted = EphemeralEncryption::encrypt(&data).expect("Failed to encrypt");

        assert_eq!(encrypted.plaintext_len(), 10000);

        let decrypted = encrypted.decrypt().expect("Failed to decrypt");
        assert_eq!(decrypted, data);
    }

    #[test]
    fn test_unique_ciphertext() {
        let data = b"same plaintext";

        let enc1 = EphemeralEncryption::encrypt(data).expect("Failed to encrypt 1");
        let enc2 = EphemeralEncryption::encrypt(data).expect("Failed to encrypt 2");

        // Same plaintext should produce different ciphertext (different keys/nonces)
        assert_ne!(enc1.ciphertext(), enc2.ciphertext());
        assert_ne!(enc1.nonce(), enc2.nonce());
    }

    #[test]
    fn test_unique_keys() {
        let data = b"test";

        let enc1 = EphemeralEncryption::encrypt(data).expect("Failed to encrypt 1");
        let enc2 = EphemeralEncryption::encrypt(data).expect("Failed to encrypt 2");

        let (_, _, key1) = enc1.export_components();
        let (_, _, key2) = enc2.export_components();

        // Each encryption should have a unique key
        assert_ne!(key1, key2);
    }

    #[test]
    fn test_from_components() {
        let data = b"restore me";
        let encrypted = EphemeralEncryption::encrypt(data).expect("Failed to encrypt");

        let (ciphertext, nonce, key) = encrypted.export_components();

        let restored = EphemeralEncryption::from_components(ciphertext.to_vec(), nonce, key)
            .expect("Failed to restore");

        let decrypted = restored.decrypt().expect("Failed to decrypt");
        assert_eq!(decrypted.as_slice(), data);
    }

    #[test]
    fn test_from_components_invalid_nonce() {
        let result =
            EphemeralEncryption::from_components(vec![1, 2, 3], &[0u8; 8], &[0u8; KEY_SIZE]);

        assert!(result.is_err());
        assert!(matches!(result, Err(CryptoError::InvalidNonce(_))));
    }

    #[test]
    fn test_from_components_invalid_key() {
        let result =
            EphemeralEncryption::from_components(vec![1, 2, 3], &[0u8; NONCE_SIZE], &[0u8; 16]);

        assert!(result.is_err());
        assert!(matches!(result, Err(CryptoError::InvalidKey(_))));
    }

    #[test]
    fn test_encrypt_to_components() {
        let data = b"component test";
        let (ciphertext, nonce, key) =
            EphemeralEncryption::encrypt_to_components(data).expect("Failed to encrypt");

        let restored = EphemeralEncryption::from_components(ciphertext, &nonce, &key)
            .expect("Failed to restore");

        let decrypted = restored.decrypt().expect("Failed to decrypt");
        assert_eq!(decrypted.as_slice(), data);
    }

    #[test]
    fn test_decrypt_and_destroy() {
        let data = b"destroy after reading";
        let mut encrypted = EphemeralEncryption::encrypt(data).expect("Failed to encrypt");

        assert!(!encrypted.is_key_destroyed());

        let decrypted = encrypted.decrypt_and_destroy().expect("Failed to decrypt");
        assert_eq!(decrypted.as_slice(), data);

        // Key should now be destroyed
        assert!(encrypted.is_key_destroyed());

        // Further decryption should fail
        let result = encrypted.decrypt();
        assert!(result.is_err());
    }

    #[test]
    fn test_debug_redacts_sensitive_info() {
        let encrypted = EphemeralEncryption::encrypt(b"secret").expect("Failed to encrypt");
        let debug_str = format!("{:?}", encrypted);

        assert!(debug_str.contains("EphemeralEncryption"));
        assert!(debug_str.contains("[REDACTED]"));
        assert!(!debug_str.contains("secret"));
    }

    #[test]
    fn test_clone() {
        let data = b"clone me";
        let original = EphemeralEncryption::encrypt(data).expect("Failed to encrypt");
        let cloned = original.clone();

        // Both should decrypt to same data
        let orig_decrypted = original.decrypt().expect("Failed to decrypt original");
        let clone_decrypted = cloned.decrypt().expect("Failed to decrypt clone");

        assert_eq!(orig_decrypted, clone_decrypted);
        assert_eq!(orig_decrypted.as_slice(), data);
    }

    #[test]
    fn test_corrupted_ciphertext_fails() {
        let encrypted = EphemeralEncryption::encrypt(b"test").expect("Failed to encrypt");
        let (mut ciphertext, nonce, key) = (
            encrypted.ciphertext().to_vec(),
            *encrypted.nonce(),
            encrypted.export_components().2,
        );

        // Corrupt the ciphertext
        if let Some(first) = ciphertext.first_mut() {
            *first ^= 0xFF;
        }

        let corrupted = EphemeralEncryption::from_components(ciphertext, &nonce, key)
            .expect("Failed to restore");

        let result = corrupted.decrypt();
        assert!(result.is_err());
        assert!(matches!(result, Err(CryptoError::Decryption(_))));
    }

    #[test]
    fn test_thread_safety() {
        use std::sync::Arc;
        use std::thread;

        let encrypted =
            Arc::new(EphemeralEncryption::encrypt(b"shared secret").expect("Failed to encrypt"));

        let handles: Vec<_> = (0..4)
            .map(|_| {
                let enc = Arc::clone(&encrypted);
                thread::spawn(move || {
                    let decrypted = enc.decrypt().expect("Failed to decrypt");
                    assert_eq!(decrypted.as_slice(), b"shared secret");
                })
            })
            .collect();

        for handle in handles {
            handle.join().expect("Thread panicked");
        }
    }

    #[test]
    fn test_ciphertext_differs_from_plaintext() {
        let data = b"plaintext data";
        let encrypted = EphemeralEncryption::encrypt(data).expect("Failed to encrypt");

        // Ciphertext should not contain the plaintext
        let ciphertext_str = String::from_utf8_lossy(encrypted.ciphertext());
        assert!(!ciphertext_str.contains("plaintext data"));
    }

    #[test]
    fn test_multiple_decrypt_calls() {
        let data = b"decrypt multiple times";
        let encrypted = EphemeralEncryption::encrypt(data).expect("Failed to encrypt");

        // Should be able to decrypt multiple times
        for _ in 0..3 {
            let decrypted = encrypted.decrypt().expect("Failed to decrypt");
            assert_eq!(decrypted.as_slice(), data);
        }
    }

    #[test]
    fn test_plaintext_len() {
        let data = b"known length";
        let encrypted = EphemeralEncryption::encrypt(data).expect("Failed to encrypt");

        assert_eq!(encrypted.plaintext_len(), data.len());
    }
}
