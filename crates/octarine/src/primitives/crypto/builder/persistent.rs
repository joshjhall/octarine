//! Persistent encryption builder for post-quantum secure storage.

use super::super::CryptoError;
use super::super::encryption::{PersistentEncryption, SecureStorage};

/// Builder for persistent encryption operations
///
/// Provides methods for long-term encrypted storage with post-quantum
/// security using ML-KEM 1024 (FIPS 203) hybrid encryption.
///
/// # Security Features
///
/// - ML-KEM 1024 post-quantum key encapsulation
/// - ChaCha20-Poly1305 + AES-256-GCM dual encryption
/// - SHA3-256 key derivation with domain separation
/// - Automatic key zeroization
///
/// # Algorithm Details
///
/// ```text
/// ML-KEM 1024 → Shared Secret
///                    ↓
///              SHA3-256 (domain: "ENCRYPT")
///                    ↓
///              ChaCha20-Poly1305
///                    ↓
///              SHA3-256 (domain: "AES_LAYER")
///                    ↓
///              AES-256-GCM (second layer)
/// ```
#[derive(Debug, Clone, Default)]
pub struct PersistentBuilder {
    _private: (),
}

impl PersistentBuilder {
    /// Create a new PersistentBuilder
    #[must_use]
    pub fn new() -> Self {
        Self { _private: () }
    }

    /// Create a new secure storage instance
    ///
    /// Generates fresh ML-KEM keys for post-quantum secure storage.
    ///
    /// # Returns
    ///
    /// A `SecureStorage` instance ready for encrypting data.
    ///
    /// # Errors
    ///
    /// Returns `CryptoError` if key generation fails.
    ///
    /// # Example
    ///
    /// ```ignore
    /// let crypto = CryptoBuilder::new();
    /// let storage = crypto.persistent().create_storage()?;
    ///
    /// let encrypted = storage.encrypt(b"long-term-secret")?;
    /// let decrypted = storage.decrypt(&encrypted)?;
    /// ```
    pub fn create_storage(&self) -> Result<SecureStorage, CryptoError> {
        SecureStorage::new()
    }

    /// Create a PersistentEncryption from raw data
    ///
    /// Encrypts data directly with post-quantum security.
    ///
    /// # Arguments
    ///
    /// * `data` - The plaintext to encrypt
    ///
    /// # Returns
    ///
    /// A `PersistentEncryption` with the encrypted data and encapsulated key.
    ///
    /// # Errors
    ///
    /// Returns `CryptoError` if encryption fails.
    pub fn encrypt(&self, data: &[u8]) -> Result<PersistentEncryption, CryptoError> {
        let storage = SecureStorage::new()?;
        storage.encrypt(data)
    }

    /// Check if the persistent encryption module is available
    ///
    /// Always returns true as ML-KEM is a required dependency.
    #[must_use]
    pub fn is_available(&self) -> bool {
        true
    }

    /// Get the security level description
    ///
    /// Returns information about the post-quantum security level.
    #[must_use]
    pub fn security_level(&self) -> &'static str {
        "ML-KEM 1024 (NIST Level 5 equivalent, ~256-bit post-quantum security)"
    }
}

#[cfg(test)]
#[allow(clippy::panic, clippy::expect_used)]
mod tests {
    use super::super::CryptoBuilder;

    #[test]
    fn test_persistent_create_storage() {
        let crypto = CryptoBuilder::new();
        let storage = crypto
            .persistent()
            .create_storage()
            .expect("Failed to create storage");

        let encrypted = storage
            .encrypt(b"persistent-data")
            .expect("Failed to encrypt");
        let decrypted = storage.decrypt(&encrypted).expect("Failed to decrypt");

        assert_eq!(decrypted.as_slice(), b"persistent-data");
    }

    #[test]
    fn test_persistent_direct_encrypt() {
        let crypto = CryptoBuilder::new();
        // Note: This creates a new storage internally, so we can't decrypt
        // without the storage. This test just verifies the API works.
        let encrypted = crypto.persistent().encrypt(b"direct-data");
        assert!(encrypted.is_ok());
    }

    #[test]
    fn test_persistent_is_available() {
        let crypto = CryptoBuilder::new();
        assert!(crypto.persistent().is_available());
    }

    #[test]
    fn test_persistent_security_level() {
        let crypto = CryptoBuilder::new();
        let level = crypto.persistent().security_level();
        assert!(level.contains("ML-KEM"));
        assert!(level.contains("1024"));
    }
}
