//! Key rotation functionality
//!
//! Methods for rotating platform keys while maintaining history for decryption.

use zeroize::Zeroize;

use super::super::{CryptoError, fill_random};
use super::super::{MAX_KEY_HISTORY, PLATFORM_KEY_SIZE};
use super::core::SecureStorage;

impl SecureStorage {
    /// Rotate to a new platform key.
    ///
    /// The current key is moved to the history (for decrypting old data),
    /// and a new key is generated for future encryptions.
    ///
    /// # Key History
    ///
    /// Only the most recent `MAX_KEY_HISTORY` (5) keys are retained.
    /// Older keys are permanently discarded.
    ///
    /// # Returns
    ///
    /// The new key version number.
    ///
    /// # Errors
    ///
    /// Returns `CryptoError` if key generation fails.
    pub fn rotate_key(&mut self) -> Result<u32, CryptoError> {
        // Move current key to history
        self.old_keys
            .insert(0, (self.key_version, self.platform_key));

        // Trim history if needed
        if self.old_keys.len() > MAX_KEY_HISTORY {
            // Zeroize and remove oldest keys
            while self.old_keys.len() > MAX_KEY_HISTORY {
                if let Some((_, mut old_key)) = self.old_keys.pop() {
                    old_key.zeroize();
                }
            }
        }

        // Generate new key using internal random primitive
        fill_random(&mut self.platform_key)?;

        // Increment version (wrapping is fine, versions are relative)
        self.key_version = self.key_version.wrapping_add(1);

        Ok(self.key_version)
    }

    /// Get the key for a specific version.
    ///
    /// Returns the current key if version matches, otherwise searches history.
    pub(super) fn get_key_for_version(&self, version: u32) -> Option<&[u8; PLATFORM_KEY_SIZE]> {
        if version == self.key_version {
            Some(&self.platform_key)
        } else {
            self.old_keys
                .iter()
                .find(|(v, _)| *v == version)
                .map(|(_, k)| k)
        }
    }
}

#[cfg(test)]
#[allow(clippy::panic, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn test_key_version_initial() {
        let storage = SecureStorage::new().expect("Failed to create storage");
        assert_eq!(storage.key_version(), 0);
        assert!(storage.old_keys().is_empty());
    }

    #[test]
    fn test_key_rotation_increments_version() {
        let mut storage = SecureStorage::new().expect("Failed to create storage");

        assert_eq!(storage.key_version(), 0);
        let new_version = storage.rotate_key().expect("Rotation failed");
        assert_eq!(new_version, 1);
        assert_eq!(storage.key_version(), 1);
    }

    #[test]
    fn test_rotation_moves_key_to_history() {
        let mut storage = SecureStorage::new().expect("Failed to create storage");
        let original_key = *storage.platform_key();

        storage.rotate_key().expect("Rotation failed");

        // Original key should be in history
        assert_eq!(storage.old_keys().len(), 1);
        let first_old = storage.old_keys().first().expect("should have one old key");
        assert_eq!(first_old.0, 0); // Version 0
        assert_eq!(first_old.1, original_key);
    }

    #[test]
    fn test_rotation_generates_new_key() {
        let mut storage = SecureStorage::new().expect("Failed to create storage");
        let original_key = *storage.platform_key();

        storage.rotate_key().expect("Rotation failed");

        // New key should be different
        assert_ne!(*storage.platform_key(), original_key);
    }

    #[test]
    fn test_key_history_limit_enforced() {
        let mut storage = SecureStorage::new().expect("Failed to create storage");

        // Rotate more than MAX_KEY_HISTORY times
        for _ in 0..=MAX_KEY_HISTORY + 2 {
            storage.rotate_key().expect("Rotation failed");
        }

        // History should be limited
        assert_eq!(storage.old_keys().len(), MAX_KEY_HISTORY);
    }

    #[test]
    fn test_get_key_for_version_current() {
        let storage = SecureStorage::new().expect("Failed to create storage");

        let key = storage.get_key_for_version(0);
        assert!(key.is_some());
        assert_eq!(key.expect("key should exist"), storage.platform_key());
    }

    #[test]
    fn test_get_key_for_version_historical() {
        let mut storage = SecureStorage::new().expect("Failed to create storage");
        let key_v0 = *storage.platform_key();

        storage.rotate_key().expect("Rotation failed");

        // Can find historical version
        let key = storage.get_key_for_version(0);
        assert!(key.is_some());
        assert_eq!(*key.expect("historical key should exist"), key_v0);
    }

    #[test]
    fn test_get_key_for_version_not_found() {
        let storage = SecureStorage::new().expect("Failed to create storage");

        let key = storage.get_key_for_version(999);
        assert!(key.is_none());
    }

    #[test]
    fn test_key_history_order_preserved() {
        let mut storage = SecureStorage::new().expect("Failed to create storage");

        // Capture keys at each version
        let key_v0 = *storage.platform_key();
        storage.rotate_key().expect("Rotation 1");
        let key_v1 = *storage.platform_key();
        storage.rotate_key().expect("Rotation 2");
        let key_v2 = *storage.platform_key();

        // Check old_keys are in correct order (most recent first)
        let old_keys = storage.old_keys();
        assert_eq!(old_keys.len(), 2);

        let first = old_keys.first().expect("Should have first key");
        assert_eq!(first.0, 1); // Version 1
        assert_eq!(first.1, key_v1);

        let second = old_keys.get(1).expect("Should have second key");
        assert_eq!(second.0, 0); // Version 0
        assert_eq!(second.1, key_v0);

        // Current key should be v2
        assert_eq!(*storage.platform_key(), key_v2);
    }
}
