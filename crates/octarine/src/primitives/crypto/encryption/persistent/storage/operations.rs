//! Encryption and decryption operations
//!
//! Core cryptographic operations for SecureStorage.

use aes_gcm::{
    Aes256Gcm, Nonce as AesNonce,
    aead::{Aead, KeyInit},
};
use chacha20poly1305::{ChaCha20Poly1305, Nonce as ChachaNonce};
use getrandom::SysRng;
use ml_kem::kem::Encapsulate;
use rand_core::TryRngCore;
use zeroize::Zeroize;

use super::super::encryption::PersistentEncryption;
use super::super::keys::derive_symmetric_keys;
use super::super::{AES_NONCE_SIZE, CHACHA_NONCE_SIZE};
use super::super::{CryptoError, fill_random};
use super::core::SecureStorage;

impl SecureStorage {
    /// Encrypt data with post-quantum dual encryption.
    ///
    /// # Arguments
    ///
    /// * `data` - The plaintext data to encrypt
    ///
    /// # Returns
    ///
    /// A `PersistentEncryption` containing all ciphertext components.
    ///
    /// # Errors
    ///
    /// Returns `CryptoError` if encryption fails.
    pub fn encrypt(&self, data: &[u8]) -> Result<PersistentEncryption, CryptoError> {
        // Step 1: ML-KEM encapsulation using system RNG
        let mut rng = SysRng.unwrap_err();
        let (kem_ciphertext, shared_secret) = self
            .ml_kem_keys
            .encapsulation_key
            .encapsulate_with_rng(&mut rng)
            .map_err(|e| CryptoError::encryption(format!("ML-KEM encapsulation failed: {e:?}")))?;

        // Step 2: Derive symmetric keys from shared secret
        let (mut chacha_key, mut aes_key) = derive_symmetric_keys(&shared_secret);

        // Step 3: Generate nonces using internal random primitive
        let mut chacha_nonce = [0u8; CHACHA_NONCE_SIZE];
        let mut aes_nonce = [0u8; AES_NONCE_SIZE];
        fill_random(&mut chacha_nonce)?;
        fill_random(&mut aes_nonce)?;

        // Step 4: First layer - ChaCha20-Poly1305
        let chacha_cipher = ChaCha20Poly1305::new_from_slice(&chacha_key)
            .map_err(|e| CryptoError::encryption(format!("ChaCha cipher init failed: {e}")))?;

        let chacha_ciphertext = chacha_cipher
            .encrypt(ChachaNonce::from_slice(&chacha_nonce), data)
            .map_err(|e| CryptoError::encryption(format!("ChaCha encryption failed: {e}")))?;

        // Step 5: Second layer - AES-256-GCM
        let aes_cipher = Aes256Gcm::new_from_slice(&aes_key)
            .map_err(|e| CryptoError::encryption(format!("AES cipher init failed: {e}")))?;

        let aes_ciphertext = aes_cipher
            .encrypt(
                AesNonce::from_slice(&aes_nonce),
                chacha_ciphertext.as_slice(),
            )
            .map_err(|e| CryptoError::encryption(format!("AES encryption failed: {e}")))?;

        // Step 6: Encrypt shared secret with platform key for storage
        let mut platform_nonce = [0u8; CHACHA_NONCE_SIZE];
        fill_random(&mut platform_nonce)?;

        let platform_cipher = ChaCha20Poly1305::new_from_slice(&self.platform_key)
            .map_err(|e| CryptoError::encryption(format!("Platform cipher init failed: {e}")))?;

        let encrypted_shared_secret = platform_cipher
            .encrypt(
                ChachaNonce::from_slice(&platform_nonce),
                shared_secret.as_ref(),
            )
            .map_err(|e| CryptoError::encryption(format!("Platform key encryption failed: {e}")))?;

        // Zeroize sensitive material
        chacha_key.zeroize();
        aes_key.zeroize();

        Ok(PersistentEncryption {
            kem_ciphertext: AsRef::<[u8]>::as_ref(&kem_ciphertext).to_vec(),
            chacha_nonce,
            aes_ciphertext,
            aes_nonce,
            encrypted_shared_secret,
            platform_nonce,
            key_version: self.key_version,
        })
    }

    /// Decrypt data encrypted with this storage.
    ///
    /// Uses the key version stored in the encrypted data to find the
    /// correct decryption key. This allows decryption of data encrypted
    /// with previous key versions after key rotation.
    ///
    /// # Arguments
    ///
    /// * `encrypted` - The `PersistentEncryption` to decrypt
    ///
    /// # Returns
    ///
    /// The original plaintext data.
    ///
    /// # Errors
    ///
    /// Returns `CryptoError` if:
    /// - The key version is not found (key was rotated out of history)
    /// - Decryption fails (wrong key, corrupted data, etc.)
    pub fn decrypt(&self, encrypted: &PersistentEncryption) -> Result<Vec<u8>, CryptoError> {
        // Find the key for this version
        let platform_key = self
            .get_key_for_version(encrypted.key_version)
            .ok_or_else(|| {
                CryptoError::decryption(format!(
                    "Key version {} not found (current: {}, history: {})",
                    encrypted.key_version,
                    self.key_version,
                    self.old_keys.len()
                ))
            })?;

        // Step 1: Decrypt shared secret with platform key
        let platform_cipher = ChaCha20Poly1305::new_from_slice(platform_key)
            .map_err(|e| CryptoError::decryption(format!("Platform cipher init failed: {e}")))?;

        let shared_secret_bytes = platform_cipher
            .decrypt(
                ChachaNonce::from_slice(&encrypted.platform_nonce),
                encrypted.encrypted_shared_secret.as_slice(),
            )
            .map_err(|e| CryptoError::decryption(format!("Platform key decryption failed: {e}")))?;

        // Step 2: Derive symmetric keys from shared secret
        let (mut chacha_key, mut aes_key) = derive_symmetric_keys(&shared_secret_bytes);

        // Step 3: First decrypt AES-256-GCM layer
        let aes_cipher = Aes256Gcm::new_from_slice(&aes_key)
            .map_err(|e| CryptoError::decryption(format!("AES cipher init failed: {e}")))?;

        let chacha_ciphertext = aes_cipher
            .decrypt(
                AesNonce::from_slice(&encrypted.aes_nonce),
                encrypted.aes_ciphertext.as_slice(),
            )
            .map_err(|e| CryptoError::decryption(format!("AES decryption failed: {e}")))?;

        // Step 4: Then decrypt ChaCha20-Poly1305 layer
        let chacha_cipher = ChaCha20Poly1305::new_from_slice(&chacha_key)
            .map_err(|e| CryptoError::decryption(format!("ChaCha cipher init failed: {e}")))?;

        let plaintext = chacha_cipher
            .decrypt(
                ChachaNonce::from_slice(&encrypted.chacha_nonce),
                chacha_ciphertext.as_slice(),
            )
            .map_err(|e| CryptoError::decryption(format!("ChaCha decryption failed: {e}")))?;

        // Zeroize sensitive material
        chacha_key.zeroize();
        aes_key.zeroize();

        Ok(plaintext)
    }

    /// Re-encrypt data with the current key.
    ///
    /// Decrypts the data (using the original key version) and re-encrypts
    /// it with the current key. Use this after key rotation to migrate
    /// data to the new key.
    ///
    /// # Arguments
    ///
    /// * `encrypted` - The data to re-encrypt
    ///
    /// # Returns
    ///
    /// A new `PersistentEncryption` encrypted with the current key.
    ///
    /// # Errors
    ///
    /// Returns `CryptoError` if decryption or re-encryption fails.
    pub fn re_encrypt(
        &self,
        encrypted: &PersistentEncryption,
    ) -> Result<PersistentEncryption, CryptoError> {
        // Decrypt with the original key
        let plaintext = self.decrypt(encrypted)?;

        // Re-encrypt with current key
        self.encrypt(&plaintext)
    }

    /// Check if data needs re-encryption.
    ///
    /// Returns `true` if the data was encrypted with an older key version.
    #[must_use]
    pub fn needs_reencrypt(&self, encrypted: &PersistentEncryption) -> bool {
        encrypted.key_version != self.key_version
    }

    /// Check if data can be decrypted.
    ///
    /// Returns `true` if the key version is available (current or in history).
    #[must_use]
    pub fn can_decrypt(&self, encrypted: &PersistentEncryption) -> bool {
        self.get_key_for_version(encrypted.key_version).is_some()
    }
}

#[cfg(test)]
#[allow(clippy::panic, clippy::expect_used)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::thread;

    #[test]
    fn test_encrypt_decrypt() {
        let storage = SecureStorage::new().expect("Failed to create storage");
        let data = b"hello persistent encryption";

        let encrypted = storage.encrypt(data).expect("Failed to encrypt");
        let decrypted = storage.decrypt(&encrypted).expect("Failed to decrypt");

        assert_eq!(decrypted.as_slice(), data);
    }

    #[test]
    fn test_empty_data() {
        let storage = SecureStorage::new().expect("Failed to create storage");

        let encrypted = storage.encrypt(&[]).expect("Failed to encrypt");
        let decrypted = storage.decrypt(&encrypted).expect("Failed to decrypt");

        assert!(decrypted.is_empty());
    }

    #[test]
    fn test_large_data() {
        let storage = SecureStorage::new().expect("Failed to create storage");
        let data: Vec<u8> = (0..10000).map(|i| (i % 256) as u8).collect();

        let encrypted = storage.encrypt(&data).expect("Failed to encrypt");
        let decrypted = storage.decrypt(&encrypted).expect("Failed to decrypt");

        assert_eq!(decrypted, data);
    }

    #[test]
    fn test_unique_ciphertext() {
        let storage = SecureStorage::new().expect("Failed to create storage");
        let data = b"same plaintext";

        let enc1 = storage.encrypt(data).expect("Failed to encrypt 1");
        let enc2 = storage.encrypt(data).expect("Failed to encrypt 2");

        // Same plaintext should produce different ciphertext (different KEM encapsulation)
        assert_ne!(enc1.aes_ciphertext, enc2.aes_ciphertext);
        assert_ne!(enc1.kem_ciphertext, enc2.kem_ciphertext);
    }

    #[test]
    fn test_cross_instance_isolation() {
        let storage1 = SecureStorage::new().expect("Failed to create storage 1");
        let storage2 = SecureStorage::new().expect("Failed to create storage 2");
        let data = b"secret data";

        // Encrypt with storage1
        let encrypted = storage1.encrypt(data).expect("Failed to encrypt");

        // storage1 can decrypt
        let decrypted = storage1.decrypt(&encrypted).expect("Failed to decrypt");
        assert_eq!(decrypted.as_slice(), data);

        // storage2 should fail (different platform key)
        let result = storage2.decrypt(&encrypted);
        assert!(result.is_err(), "Different storage should not decrypt");
    }

    #[test]
    fn test_shared_platform_key_works() {
        let storage1 = SecureStorage::new().expect("Failed to create storage 1");
        let data = b"recoverable secret";

        // Encrypt with storage1
        let encrypted = storage1.encrypt(data).expect("Failed to encrypt");

        // Create storage2 with same platform key
        let storage2 = SecureStorage::with_platform_key(*storage1.platform_key())
            .expect("Failed to create storage 2");

        // storage2 should be able to decrypt
        let decrypted = storage2.decrypt(&encrypted).expect("Failed to decrypt");
        assert_eq!(decrypted.as_slice(), data);
    }

    #[test]
    fn test_corrupted_ciphertext_fails() {
        let storage = SecureStorage::new().expect("Failed to create storage");
        let data = b"test data";

        let mut encrypted = storage.encrypt(data).expect("Failed to encrypt");

        // Corrupt the AES ciphertext
        if let Some(first) = encrypted.aes_ciphertext.first_mut() {
            *first ^= 0xFF;
        }

        let result = storage.decrypt(&encrypted);
        assert!(result.is_err(), "Corrupted data should fail decryption");
    }

    #[test]
    fn test_thread_safety() {
        let storage = Arc::new(SecureStorage::new().expect("Failed to create storage"));
        let data = b"shared secret data";

        // Encrypt once
        let encrypted = Arc::new(storage.encrypt(data).expect("Failed to encrypt"));

        // Decrypt from multiple threads
        let handles: Vec<_> = (0..4)
            .map(|_| {
                let s = Arc::clone(&storage);
                let e = Arc::clone(&encrypted);
                thread::spawn(move || {
                    let decrypted = s.decrypt(&e).expect("Failed to decrypt");
                    assert_eq!(decrypted.as_slice(), data);
                })
            })
            .collect();

        for handle in handles {
            handle.join().expect("Thread panicked");
        }
    }

    #[test]
    fn test_clone_storage() {
        let storage1 = SecureStorage::new().expect("Failed to create storage");
        let storage2 = storage1.clone();
        let data = b"clone test";

        let encrypted = storage1.encrypt(data).expect("Failed to encrypt");
        let decrypted = storage2.decrypt(&encrypted).expect("Failed to decrypt");

        assert_eq!(decrypted.as_slice(), data);
    }

    #[test]
    fn test_decrypt_after_rotation() {
        let mut storage = SecureStorage::new().expect("Failed to create storage");
        let data = b"secret before rotation";

        // Encrypt with version 0
        let encrypted_v0 = storage.encrypt(data).expect("Failed to encrypt");
        assert_eq!(encrypted_v0.key_version(), 0);

        // Rotate key
        storage.rotate_key().expect("Rotation failed");

        // Should still decrypt data encrypted with old key
        let decrypted = storage.decrypt(&encrypted_v0).expect("Failed to decrypt");
        assert_eq!(decrypted.as_slice(), data);
    }

    #[test]
    fn test_new_encryption_uses_current_version() {
        let mut storage = SecureStorage::new().expect("Failed to create storage");

        storage.rotate_key().expect("Rotation failed");
        storage.rotate_key().expect("Rotation failed");

        let encrypted = storage.encrypt(b"test").expect("Failed to encrypt");
        assert_eq!(encrypted.key_version(), 2);
    }

    #[test]
    fn test_re_encrypt() {
        let mut storage = SecureStorage::new().expect("Failed to create storage");
        let data = b"data to migrate";

        // Encrypt with version 0
        let encrypted_v0 = storage.encrypt(data).expect("Failed to encrypt");
        assert_eq!(encrypted_v0.key_version(), 0);

        // Rotate key
        storage.rotate_key().expect("Rotation failed");

        // Re-encrypt with new key
        let encrypted_v1 = storage
            .re_encrypt(&encrypted_v0)
            .expect("Re-encrypt failed");
        assert_eq!(encrypted_v1.key_version(), 1);

        // Both should decrypt to same data
        let decrypted_v0 = storage.decrypt(&encrypted_v0).expect("Decrypt v0");
        let decrypted_v1 = storage.decrypt(&encrypted_v1).expect("Decrypt v1");
        assert_eq!(decrypted_v0, decrypted_v1);
        assert_eq!(decrypted_v0.as_slice(), data);
    }

    #[test]
    fn test_needs_reencrypt() {
        let mut storage = SecureStorage::new().expect("Failed to create storage");

        let encrypted = storage.encrypt(b"test").expect("Failed to encrypt");
        assert!(!storage.needs_reencrypt(&encrypted));

        storage.rotate_key().expect("Rotation failed");
        assert!(storage.needs_reencrypt(&encrypted));

        let reencrypted = storage.re_encrypt(&encrypted).expect("Re-encrypt failed");
        assert!(!storage.needs_reencrypt(&reencrypted));
    }

    #[test]
    fn test_can_decrypt() {
        let mut storage = SecureStorage::new().expect("Failed to create storage");

        let encrypted = storage.encrypt(b"test").expect("Failed to encrypt");
        assert!(storage.can_decrypt(&encrypted));

        // After rotation, old version should still be available
        storage.rotate_key().expect("Rotation failed");
        assert!(storage.can_decrypt(&encrypted));
    }

    #[test]
    fn test_key_history_limit() {
        let mut storage = SecureStorage::new().expect("Failed to create storage");
        let data = b"test data";

        // Encrypt at version 0
        let encrypted_v0 = storage.encrypt(data).expect("Failed to encrypt");

        // Rotate MAX_KEY_HISTORY + 1 times to push v0 out of history
        for _ in 0..=super::super::super::MAX_KEY_HISTORY {
            storage.rotate_key().expect("Rotation failed");
        }

        // Old key should be gone
        assert!(!storage.can_decrypt(&encrypted_v0));
        let result = storage.decrypt(&encrypted_v0);
        assert!(result.is_err());
    }

    #[test]
    fn test_with_key_history_decryption() {
        // Create original storage and encrypt some data
        let mut original = SecureStorage::new().expect("Failed to create storage");
        let data = b"persistent data";
        let encrypted = original.encrypt(data).expect("Failed to encrypt");

        original.rotate_key().expect("Rotation failed");

        // Create new storage with the key history
        let restored = SecureStorage::with_key_history(
            *original.platform_key(),
            original.key_version(),
            original.old_keys().to_vec(),
        )
        .expect("Failed to restore");

        // Should be able to decrypt old data
        let decrypted = restored.decrypt(&encrypted).expect("Failed to decrypt");
        assert_eq!(decrypted.as_slice(), data);
    }

    #[test]
    fn test_multiple_rotations_decrypt_all() {
        let mut storage = SecureStorage::new().expect("Failed to create storage");

        // Encrypt data at different versions
        let data_v0 = b"version 0 data";
        let encrypted_v0 = storage.encrypt(data_v0).expect("Encrypt v0");

        storage.rotate_key().expect("Rotation 1");
        let data_v1 = b"version 1 data";
        let encrypted_v1 = storage.encrypt(data_v1).expect("Encrypt v1");

        storage.rotate_key().expect("Rotation 2");
        let data_v2 = b"version 2 data";
        let encrypted_v2 = storage.encrypt(data_v2).expect("Encrypt v2");

        // All should still be decryptable
        assert_eq!(
            storage
                .decrypt(&encrypted_v0)
                .expect("Decrypt v0")
                .as_slice(),
            data_v0
        );
        assert_eq!(
            storage
                .decrypt(&encrypted_v1)
                .expect("Decrypt v1")
                .as_slice(),
            data_v1
        );
        assert_eq!(
            storage
                .decrypt(&encrypted_v2)
                .expect("Decrypt v2")
                .as_slice(),
            data_v2
        );
    }

    #[test]
    fn test_clone_preserves_key_history() {
        let mut storage1 = SecureStorage::new().expect("Failed to create storage");
        let data = b"clone history test";
        let encrypted = storage1.encrypt(data).expect("Failed to encrypt");

        storage1.rotate_key().expect("Rotation failed");

        let storage2 = storage1.clone();

        // Clone should have same history and decrypt old data
        assert_eq!(storage2.key_version(), storage1.key_version());
        assert_eq!(storage2.old_keys().len(), storage1.old_keys().len());

        let decrypted = storage2.decrypt(&encrypted).expect("Failed to decrypt");
        assert_eq!(decrypted.as_slice(), data);
    }

    #[test]
    fn test_cross_version_decryption_after_multiple_rotations() {
        let mut storage = SecureStorage::new().expect("Failed to create storage");

        // Encrypt data at versions 0, 1, 2, 3
        let data_v0 = b"data at version 0";
        let encrypted_v0 = storage.encrypt(data_v0).expect("Encrypt v0");
        assert_eq!(encrypted_v0.key_version(), 0);

        storage.rotate_key().expect("Rotation 1");
        let data_v1 = b"data at version 1";
        let encrypted_v1 = storage.encrypt(data_v1).expect("Encrypt v1");
        assert_eq!(encrypted_v1.key_version(), 1);

        storage.rotate_key().expect("Rotation 2");
        let data_v2 = b"data at version 2";
        let encrypted_v2 = storage.encrypt(data_v2).expect("Encrypt v2");
        assert_eq!(encrypted_v2.key_version(), 2);

        storage.rotate_key().expect("Rotation 3");
        let data_v3 = b"data at version 3";
        let encrypted_v3 = storage.encrypt(data_v3).expect("Encrypt v3");
        assert_eq!(encrypted_v3.key_version(), 3);

        // All versions should still be decryptable
        assert_eq!(
            storage
                .decrypt(&encrypted_v0)
                .expect("Decrypt v0")
                .as_slice(),
            data_v0
        );
        assert_eq!(
            storage
                .decrypt(&encrypted_v1)
                .expect("Decrypt v1")
                .as_slice(),
            data_v1
        );
        assert_eq!(
            storage
                .decrypt(&encrypted_v2)
                .expect("Decrypt v2")
                .as_slice(),
            data_v2
        );
        assert_eq!(
            storage
                .decrypt(&encrypted_v3)
                .expect("Decrypt v3")
                .as_slice(),
            data_v3
        );
    }

    #[test]
    fn test_version_rotated_out_of_history_fails_gracefully() {
        let mut storage = SecureStorage::new().expect("Failed to create storage");

        let data = b"old data";
        let encrypted = storage.encrypt(data).expect("Encrypt");
        assert_eq!(encrypted.key_version(), 0);

        // Rotate enough times to push v0 out of history
        for _ in 0..=super::super::super::MAX_KEY_HISTORY {
            storage.rotate_key().expect("Rotation");
        }

        // Verify v0 is gone from history
        assert!(!storage.can_decrypt(&encrypted));

        // Decryption should fail with informative error
        let result = storage.decrypt(&encrypted);
        assert!(result.is_err());
        match result {
            Err(CryptoError::Decryption(msg)) => {
                assert!(
                    msg.contains("version"),
                    "Error should mention version: {}",
                    msg
                );
            }
            other => panic!("Expected Decryption error, got: {:?}", other),
        }
    }

    #[test]
    fn test_re_encrypt_with_wrong_storage_fails() {
        let storage1 = SecureStorage::new().expect("Failed to create storage 1");
        let storage2 = SecureStorage::new().expect("Failed to create storage 2");

        let encrypted = storage1.encrypt(b"test").expect("Encrypt");

        // storage2 cannot re-encrypt (can't decrypt)
        let result = storage2.re_encrypt(&encrypted);
        assert!(result.is_err());
    }

    #[test]
    fn test_corrupted_shared_secret_fails() {
        let storage = SecureStorage::new().expect("Failed to create storage");

        let mut encrypted = storage.encrypt(b"test").expect("Encrypt");

        // Corrupt the encrypted shared secret
        if let Some(first) = encrypted.encrypted_shared_secret.first_mut() {
            *first ^= 0xFF;
        }

        let result = storage.decrypt(&encrypted);
        assert!(result.is_err());
    }

    #[test]
    fn test_wrong_key_version_number_fails() {
        let storage = SecureStorage::new().expect("Failed to create storage");

        let mut encrypted = storage.encrypt(b"test").expect("Encrypt");

        // Tamper with key version to a non-existent one
        encrypted.key_version = 999;

        let result = storage.decrypt(&encrypted);
        assert!(result.is_err());
        assert!(!storage.can_decrypt(&encrypted));
    }

    #[test]
    fn test_binary_data_with_all_byte_values() {
        // Test that all 256 byte values are handled correctly
        let storage = SecureStorage::new().expect("Failed to create storage");

        let plaintext: Vec<u8> = (0u8..=255).collect();
        assert_eq!(plaintext.len(), 256);

        let encrypted = storage.encrypt(&plaintext).expect("Encrypt");
        let decrypted = storage.decrypt(&encrypted).expect("Decrypt");

        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_platform_key_sensitivity() {
        // Verify that even a single bit flip in platform key prevents decryption
        let storage1 = SecureStorage::new().expect("Failed to create storage");
        let encrypted = storage1.encrypt(b"sensitive data").expect("Encrypt");

        // Create storage with slightly corrupted platform key
        let mut corrupted_key = *storage1.platform_key();
        corrupted_key[0] ^= 0x01; // Flip single bit

        let storage2 = SecureStorage::with_platform_key(corrupted_key)
            .expect("Failed to create storage with corrupted key");

        // Decryption should fail
        let result = storage2.decrypt(&encrypted);
        assert!(result.is_err());
    }
}
