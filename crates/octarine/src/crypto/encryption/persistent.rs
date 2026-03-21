//! Persistent Encryption with observability
//!
//! Long-term storage encryption with post-quantum security,
//! wrapped with observe instrumentation for audit trails.
//!
//! # Security Properties
//!
//! - **Post-Quantum**: ML-KEM 1024 (FIPS 203, NIST Level 5)
//! - **Dual Encryption**: ChaCha20-Poly1305 + AES-256-GCM defense in depth
//! - **Key Rotation**: Supports versioned keys with history
//!
//! # Security Events
//!
//! - `encryption.persistent_create` - Storage instance created
//! - `encryption.persistent_encrypt` - Data encrypted for storage
//! - `encryption.persistent_decrypt` - Persistent ciphertext decrypted
//! - `encryption.persistent_rotate` - Key rotation performed
//!
//! # Examples
//!
//! ```ignore
//! use octarine::crypto::encryption::persistent;
//!
//! // Create storage instance
//! let storage = persistent::create_storage()?;
//!
//! // Encrypt for long-term storage
//! let encrypted = persistent::encrypt(&storage, b"database-field")?;
//!
//! // Decrypt when needed
//! let plaintext = persistent::decrypt(&storage, &encrypted)?;
//! ```

use crate::observe;
use crate::primitives::crypto::CryptoError;
use crate::primitives::crypto::encryption::{PersistentEncryption, SecureStorage};

// Re-export types
pub use crate::primitives::crypto::encryption::{
    PersistentEncryptedComponents, SecureStorage as Storage,
};

/// Create a new secure storage instance with audit trail.
///
/// Generates a unique platform key for this instance while sharing
/// the global ML-KEM keypair for efficiency.
///
/// # Security Events
///
/// Generates `encryption.persistent_create` event.
pub fn create_storage() -> Result<SecureStorage, CryptoError> {
    let result = SecureStorage::new();

    match &result {
        Ok(_) => {
            observe::info("persistent_create", "Persistent encryption storage created");
        }
        Err(e) => {
            observe::warn(
                "persistent_create",
                format!("Failed to create persistent storage: {e}"),
            );
        }
    }

    result
}

/// Encrypt data with post-quantum dual encryption and audit trail.
///
/// Uses ML-KEM 1024 + ChaCha20-Poly1305 + AES-256-GCM for
/// post-quantum security with defense in depth.
///
/// # Security Events
///
/// Generates `encryption.persistent_encrypt` event with data size.
pub fn encrypt(storage: &SecureStorage, data: &[u8]) -> Result<PersistentEncryption, CryptoError> {
    let result = storage.encrypt(data);

    match &result {
        Ok(_) => {
            observe::info(
                "persistent_encrypt",
                format!(
                    "Persistent encryption completed ({} bytes, key version {})",
                    data.len(),
                    storage.key_version()
                ),
            );
        }
        Err(e) => {
            observe::warn(
                "persistent_encrypt",
                format!("Persistent encryption failed: {e}"),
            );
        }
    }

    result
}

/// Decrypt persistent encrypted data with audit trail.
///
/// Supports decryption of data encrypted with older key versions
/// if the keys are still in the storage's history.
///
/// # Security Events
///
/// Generates `encryption.persistent_decrypt` event.
pub fn decrypt(
    storage: &SecureStorage,
    encrypted: &PersistentEncryption,
) -> Result<Vec<u8>, CryptoError> {
    let result = storage.decrypt(encrypted);

    match &result {
        Ok(plaintext) => {
            observe::info(
                "persistent_decrypt",
                format!(
                    "Persistent decryption completed ({} bytes, key version {})",
                    plaintext.len(),
                    encrypted.key_version()
                ),
            );
        }
        Err(e) => {
            observe::warn(
                "persistent_decrypt",
                format!("Persistent decryption failed: {e}"),
            );
        }
    }

    result
}

/// Rotate to a new encryption key with audit trail.
///
/// The old key is retained in history for decrypting existing data.
/// New encryptions will use the new key.
///
/// # Returns
///
/// The new key version number.
///
/// # Security Events
///
/// Generates `encryption.persistent_rotate` event with version info.
pub fn rotate_key(storage: &mut SecureStorage) -> Result<u32, CryptoError> {
    let old_version = storage.key_version();
    let result = storage.rotate_key();

    match &result {
        Ok(new_version) => {
            observe::info(
                "persistent_rotate",
                format!(
                    "Key rotation completed (v{} -> v{})",
                    old_version, new_version
                ),
            );
        }
        Err(e) => {
            observe::warn("persistent_rotate", format!("Key rotation failed: {e}"));
        }
    }

    result
}

/// Re-encrypt data with the current key with audit trail.
///
/// Useful after key rotation to migrate data to the new key.
///
/// # Security Events
///
/// Generates `encryption.persistent_encrypt` event (same as new encryption).
pub fn re_encrypt(
    storage: &SecureStorage,
    encrypted: &PersistentEncryption,
) -> Result<PersistentEncryption, CryptoError> {
    let old_version = encrypted.key_version();
    let result = storage.re_encrypt(encrypted);

    match &result {
        Ok(new_encrypted) => {
            observe::info(
                "persistent_encrypt",
                format!(
                    "Re-encryption completed (v{} -> v{})",
                    old_version,
                    new_encrypted.key_version()
                ),
            );
        }
        Err(e) => {
            observe::warn("persistent_encrypt", format!("Re-encryption failed: {e}"));
        }
    }

    result
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
#[allow(clippy::panic, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn test_create_encrypt_decrypt() {
        let storage = create_storage().expect("Failed to create storage");
        let data = b"test persistent encryption";

        let encrypted = encrypt(&storage, data).expect("Encryption failed");
        let decrypted = decrypt(&storage, &encrypted).expect("Decryption failed");

        assert_eq!(decrypted.as_slice(), data);
    }

    #[test]
    fn test_key_rotation() {
        let mut storage = create_storage().expect("Failed to create storage");
        let data = b"rotate me";

        // Encrypt with initial key
        let encrypted = encrypt(&storage, data).expect("Encryption failed");
        let initial_version = encrypted.key_version();

        // Rotate key
        let new_version = rotate_key(&mut storage).expect("Rotation failed");
        assert!(new_version > initial_version);

        // Can still decrypt old data
        let decrypted = decrypt(&storage, &encrypted).expect("Decryption failed");
        assert_eq!(decrypted.as_slice(), data);

        // New encryption uses new version
        let new_encrypted = encrypt(&storage, data).expect("New encryption failed");
        assert_eq!(new_encrypted.key_version(), new_version);
    }

    #[test]
    fn test_re_encrypt() {
        let mut storage = create_storage().expect("Failed to create storage");
        let data = b"re-encrypt me";

        let encrypted = encrypt(&storage, data).expect("Encryption failed");
        let old_version = encrypted.key_version();

        rotate_key(&mut storage).expect("Rotation failed");

        let re_encrypted = re_encrypt(&storage, &encrypted).expect("Re-encryption failed");
        assert!(re_encrypted.key_version() > old_version);

        let decrypted = decrypt(&storage, &re_encrypted).expect("Decryption failed");
        assert_eq!(decrypted.as_slice(), data);
    }
}
