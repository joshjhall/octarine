//! Core SecureStorage struct and constructors
//!
//! Defines the SecureStorage struct and its initialization methods.

use std::sync::Arc;
use zeroize::Zeroize;

use super::super::keys::{MlKemKeyPair, get_global_keys};
use super::super::{CryptoError, fill_random};
use super::super::{MAX_KEY_HISTORY, PLATFORM_KEY_SIZE};

/// Secure storage for persistent encryption.
///
/// Uses ML-KEM 1024 for post-quantum security with dual symmetric
/// encryption (ChaCha20-Poly1305 + AES-256-GCM) for defense in depth.
///
/// ## Instance Isolation
///
/// Each `SecureStorage` instance has its own platform key, meaning
/// data encrypted by one instance cannot be decrypted by another.
/// This provides process-level isolation.
///
/// ## Key Rotation Support
///
/// The storage supports key rotation through:
/// - Key versioning: Each encryption records which key version was used
/// - Key history: Old keys can be retained for decrypting legacy data
/// - Re-encryption: Data can be re-encrypted with the current key
///
/// ```ignore
/// // Create storage with initial key
/// let mut storage = SecureStorage::new()?;
/// let encrypted = storage.encrypt(b"secret")?;
///
/// // Rotate to a new key (old key is retained)
/// storage.rotate_key()?;
///
/// // Can still decrypt data encrypted with old key
/// let decrypted = storage.decrypt(&encrypted)?;
///
/// // Re-encrypt with current key
/// let new_encrypted = storage.re_encrypt(&encrypted)?;
/// ```
///
/// ## Thread Safety
///
/// `SecureStorage` is `Send + Sync` and can be safely shared across threads.
pub struct SecureStorage {
    /// Global ML-KEM keypair (shared across instances)
    pub(super) ml_kem_keys: Arc<MlKemKeyPair>,

    /// Current platform key (used for new encryptions)
    pub(super) platform_key: [u8; PLATFORM_KEY_SIZE],

    /// Current key version
    pub(super) key_version: u32,

    /// Historical keys for decrypting old data (version -> key)
    /// Most recent first, limited to MAX_KEY_HISTORY entries
    pub(super) old_keys: Vec<(u32, [u8; PLATFORM_KEY_SIZE])>,
}

impl SecureStorage {
    /// Create a new secure storage instance.
    ///
    /// Generates a unique platform key for this instance while sharing
    /// the global ML-KEM keypair for efficiency.
    ///
    /// # Errors
    ///
    /// Returns `CryptoError` if key generation fails.
    pub fn new() -> Result<Self, CryptoError> {
        let ml_kem_keys = get_global_keys()?;

        // Generate instance-specific platform key using internal random primitive
        let mut platform_key = [0u8; PLATFORM_KEY_SIZE];
        fill_random(&mut platform_key)?;

        Ok(Self {
            ml_kem_keys,
            platform_key,
            key_version: 0,
            old_keys: Vec::new(),
        })
    }

    /// Create storage with a specific platform key.
    ///
    /// Useful for restoring a previous storage instance.
    ///
    /// # Arguments
    ///
    /// * `platform_key` - The 32-byte platform key
    ///
    /// # Errors
    ///
    /// Returns `CryptoError` if key initialization fails.
    pub fn with_platform_key(platform_key: [u8; PLATFORM_KEY_SIZE]) -> Result<Self, CryptoError> {
        Self::with_platform_key_versioned(platform_key, 0)
    }

    /// Create storage with a specific platform key and version.
    ///
    /// # Arguments
    ///
    /// * `platform_key` - The 32-byte platform key
    /// * `version` - The key version number
    ///
    /// # Errors
    ///
    /// Returns `CryptoError` if key initialization fails.
    pub fn with_platform_key_versioned(
        platform_key: [u8; PLATFORM_KEY_SIZE],
        version: u32,
    ) -> Result<Self, CryptoError> {
        let ml_kem_keys = get_global_keys()?;
        Ok(Self {
            ml_kem_keys,
            platform_key,
            key_version: version,
            old_keys: Vec::new(),
        })
    }

    /// Create storage with current key and historical keys.
    ///
    /// Use this to restore a storage instance with its full key history,
    /// enabling decryption of data encrypted with any historical key.
    ///
    /// # Arguments
    ///
    /// * `current_key` - The current platform key
    /// * `current_version` - The current key version
    /// * `old_keys` - Historical keys as (version, key) pairs
    ///
    /// # Errors
    ///
    /// Returns `CryptoError` if key initialization fails.
    pub fn with_key_history(
        current_key: [u8; PLATFORM_KEY_SIZE],
        current_version: u32,
        old_keys: Vec<(u32, [u8; PLATFORM_KEY_SIZE])>,
    ) -> Result<Self, CryptoError> {
        let ml_kem_keys = get_global_keys()?;

        // Limit old keys to MAX_KEY_HISTORY
        let old_keys = if old_keys.len() > MAX_KEY_HISTORY {
            old_keys.into_iter().take(MAX_KEY_HISTORY).collect()
        } else {
            old_keys
        };

        Ok(Self {
            ml_kem_keys,
            platform_key: current_key,
            key_version: current_version,
            old_keys,
        })
    }

    /// Get the platform key for serialization.
    ///
    /// # Security Warning
    ///
    /// The platform key is sensitive! Store it securely.
    pub fn platform_key(&self) -> &[u8; PLATFORM_KEY_SIZE] {
        &self.platform_key
    }

    /// Get the current key version.
    pub fn key_version(&self) -> u32 {
        self.key_version
    }

    /// Get historical keys for serialization.
    ///
    /// Returns (version, key) pairs for all retained historical keys.
    ///
    /// # Security Warning
    ///
    /// These keys are sensitive! Store them securely.
    pub fn old_keys(&self) -> &[(u32, [u8; PLATFORM_KEY_SIZE])] {
        &self.old_keys
    }
}

impl Drop for SecureStorage {
    fn drop(&mut self) {
        self.platform_key.zeroize();
        // Zeroize old keys
        for (_, key) in &mut self.old_keys {
            key.zeroize();
        }
    }
}

impl Clone for SecureStorage {
    fn clone(&self) -> Self {
        Self {
            ml_kem_keys: Arc::clone(&self.ml_kem_keys),
            platform_key: self.platform_key,
            key_version: self.key_version,
            old_keys: self.old_keys.clone(),
        }
    }
}

impl std::fmt::Debug for SecureStorage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SecureStorage")
            .field("platform_key", &"[REDACTED]")
            .field("key_version", &self.key_version)
            .field("old_keys_count", &self.old_keys.len())
            .field("ml_kem_keys", &"[GLOBAL_KEYPAIR]")
            .finish()
    }
}

#[cfg(test)]
#[allow(clippy::panic, clippy::expect_used)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::thread;

    #[test]
    fn test_create_storage() {
        let storage = SecureStorage::new().expect("Failed to create storage");
        assert_eq!(storage.key_version(), 0);
        assert!(storage.old_keys().is_empty());
    }

    #[test]
    fn test_with_platform_key() {
        let storage1 = SecureStorage::new().expect("Failed to create storage 1");
        let storage2 = SecureStorage::with_platform_key(*storage1.platform_key())
            .expect("Failed to create storage 2");

        // Same platform key
        assert_eq!(storage1.platform_key(), storage2.platform_key());
    }

    #[test]
    fn test_with_platform_key_versioned() {
        let key = [42u8; PLATFORM_KEY_SIZE];
        let storage =
            SecureStorage::with_platform_key_versioned(key, 5).expect("Failed to create storage");

        assert_eq!(storage.key_version(), 5);
        assert_eq!(*storage.platform_key(), key);
    }

    #[test]
    fn test_with_key_history() {
        let current_key = [1u8; PLATFORM_KEY_SIZE];
        let old_key = [2u8; PLATFORM_KEY_SIZE];
        let old_keys = vec![(0, old_key)];

        let storage = SecureStorage::with_key_history(current_key, 1, old_keys)
            .expect("Failed to create storage");

        assert_eq!(storage.key_version(), 1);
        assert_eq!(storage.old_keys().len(), 1);
    }

    #[test]
    fn test_key_history_limit() {
        let current_key = [1u8; PLATFORM_KEY_SIZE];
        let old_keys: Vec<_> = (0..10).map(|i| (i, [i as u8; PLATFORM_KEY_SIZE])).collect();

        let storage = SecureStorage::with_key_history(current_key, 10, old_keys)
            .expect("Failed to create storage");

        // Should be limited to MAX_KEY_HISTORY
        assert_eq!(storage.old_keys().len(), MAX_KEY_HISTORY);
    }

    #[test]
    fn test_debug_redacts_secrets() {
        let storage = SecureStorage::new().expect("Failed to create storage");
        let debug_str = format!("{:?}", storage);

        assert!(debug_str.contains("[REDACTED]"));
        assert!(!debug_str.contains(&format!("{:?}", storage.platform_key)));
    }

    #[test]
    fn test_global_keypair_reuse() {
        // Create multiple storage instances
        let storage1 = SecureStorage::new().expect("Failed to create storage 1");
        let storage2 = SecureStorage::new().expect("Failed to create storage 2");

        // They should share the same ML-KEM keypair (Arc pointer equality)
        assert!(Arc::ptr_eq(&storage1.ml_kem_keys, &storage2.ml_kem_keys));
    }

    #[test]
    fn test_thread_safety_creation() {
        // Verify storage can be created from multiple threads
        let handles: Vec<_> = (0..4)
            .map(|_| {
                thread::spawn(|| {
                    let storage = SecureStorage::new().expect("Failed to create storage");
                    storage.key_version()
                })
            })
            .collect();

        for handle in handles {
            let version = handle.join().expect("Thread panicked");
            assert_eq!(version, 0);
        }
    }
}
