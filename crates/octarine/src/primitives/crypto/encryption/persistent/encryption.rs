//! Persistent encryption data structure and serialization.
//!
//! Contains the `PersistentEncryption` struct which holds all components
//! needed to decrypt data encrypted with `SecureStorage`.

use super::{AES_NONCE_SIZE, CHACHA_NONCE_SIZE, CryptoError};

/// Components type for serialization.
///
/// Tuple of (kem_ciphertext, chacha_nonce, aes_ciphertext, aes_nonce,
///           encrypted_shared_secret, platform_nonce, key_version)
pub type PersistentEncryptedComponents = (
    Vec<u8>,
    [u8; CHACHA_NONCE_SIZE],
    Vec<u8>,
    [u8; AES_NONCE_SIZE],
    Vec<u8>,
    [u8; CHACHA_NONCE_SIZE],
    u32,
);

/// Persistent encryption data structure.
///
/// Contains all components needed to decrypt data:
/// - Encrypted shared secret (ML-KEM ciphertext encrypted with platform key)
/// - ChaCha20-Poly1305 nonce
/// - AES-256-GCM ciphertext (contains ChaCha ciphertext)
/// - AES-256-GCM nonce
#[derive(Clone)]
pub struct PersistentEncryption {
    /// ML-KEM ciphertext (encapsulated shared secret)
    pub(super) kem_ciphertext: Vec<u8>,

    /// ChaCha20-Poly1305 nonce
    pub(super) chacha_nonce: [u8; CHACHA_NONCE_SIZE],

    /// Final ciphertext (AES-GCM encrypted ChaCha ciphertext)
    pub(super) aes_ciphertext: Vec<u8>,

    /// AES-256-GCM nonce
    pub(super) aes_nonce: [u8; AES_NONCE_SIZE],

    /// Platform key encrypted shared secret
    pub(super) encrypted_shared_secret: Vec<u8>,

    /// Nonce for platform key encryption
    pub(super) platform_nonce: [u8; CHACHA_NONCE_SIZE],

    /// Key version used for encryption (for key rotation support)
    pub(super) key_version: u32,
}

impl PersistentEncryption {
    /// Get the KEM ciphertext for serialization
    pub fn kem_ciphertext(&self) -> &[u8] {
        &self.kem_ciphertext
    }

    /// Get the ChaCha nonce for serialization
    pub fn chacha_nonce(&self) -> &[u8; CHACHA_NONCE_SIZE] {
        &self.chacha_nonce
    }

    /// Get the AES ciphertext for serialization
    pub fn aes_ciphertext(&self) -> &[u8] {
        &self.aes_ciphertext
    }

    /// Get the AES nonce for serialization
    pub fn aes_nonce(&self) -> &[u8; AES_NONCE_SIZE] {
        &self.aes_nonce
    }

    /// Get the encrypted shared secret for serialization
    pub fn encrypted_shared_secret(&self) -> &[u8] {
        &self.encrypted_shared_secret
    }

    /// Get the platform nonce for serialization
    pub fn platform_nonce(&self) -> &[u8; CHACHA_NONCE_SIZE] {
        &self.platform_nonce
    }

    /// Get the key version used for encryption
    pub fn key_version(&self) -> u32 {
        self.key_version
    }

    /// Reconstruct from serialized components
    pub fn from_components(
        kem_ciphertext: Vec<u8>,
        chacha_nonce: [u8; CHACHA_NONCE_SIZE],
        aes_ciphertext: Vec<u8>,
        aes_nonce: [u8; AES_NONCE_SIZE],
        encrypted_shared_secret: Vec<u8>,
        platform_nonce: [u8; CHACHA_NONCE_SIZE],
    ) -> Self {
        Self::from_components_versioned(
            kem_ciphertext,
            chacha_nonce,
            aes_ciphertext,
            aes_nonce,
            encrypted_shared_secret,
            platform_nonce,
            0, // Default to version 0 for backwards compatibility
        )
    }

    /// Reconstruct from serialized components with version
    pub fn from_components_versioned(
        kem_ciphertext: Vec<u8>,
        chacha_nonce: [u8; CHACHA_NONCE_SIZE],
        aes_ciphertext: Vec<u8>,
        aes_nonce: [u8; AES_NONCE_SIZE],
        encrypted_shared_secret: Vec<u8>,
        platform_nonce: [u8; CHACHA_NONCE_SIZE],
        key_version: u32,
    ) -> Self {
        Self {
            kem_ciphertext,
            chacha_nonce,
            aes_ciphertext,
            aes_nonce,
            encrypted_shared_secret,
            platform_nonce,
            key_version,
        }
    }

    /// Export all components as a tuple for serialization.
    ///
    /// Returns (kem_ciphertext, chacha_nonce, aes_ciphertext, aes_nonce,
    ///          encrypted_shared_secret, platform_nonce, key_version)
    pub fn to_components(&self) -> PersistentEncryptedComponents {
        (
            self.kem_ciphertext.clone(),
            self.chacha_nonce,
            self.aes_ciphertext.clone(),
            self.aes_nonce,
            self.encrypted_shared_secret.clone(),
            self.platform_nonce,
            self.key_version,
        )
    }

    /// Serialize to a byte vector.
    ///
    /// Format (little-endian lengths):
    /// ```text
    /// [version: 4 bytes]
    /// [kem_ct_len: 4 bytes][kem_ciphertext]
    /// [chacha_nonce: 12 bytes]
    /// [aes_ct_len: 4 bytes][aes_ciphertext]
    /// [aes_nonce: 12 bytes]
    /// [ess_len: 4 bytes][encrypted_shared_secret]
    /// [platform_nonce: 12 bytes]
    /// ```
    pub fn to_bytes(&self) -> Vec<u8> {
        let capacity = 4_usize // version
            .saturating_add(4) // kem_ct_len
            .saturating_add(self.kem_ciphertext.len())
            .saturating_add(CHACHA_NONCE_SIZE)
            .saturating_add(4) // aes_ct_len
            .saturating_add(self.aes_ciphertext.len())
            .saturating_add(AES_NONCE_SIZE)
            .saturating_add(4) // ess_len
            .saturating_add(self.encrypted_shared_secret.len())
            .saturating_add(CHACHA_NONCE_SIZE);

        let mut bytes = Vec::with_capacity(capacity);

        // Version
        bytes.extend_from_slice(&self.key_version.to_le_bytes());

        // KEM ciphertext
        let kem_len = self.kem_ciphertext.len() as u32;
        bytes.extend_from_slice(&kem_len.to_le_bytes());
        bytes.extend_from_slice(&self.kem_ciphertext);

        // ChaCha nonce
        bytes.extend_from_slice(&self.chacha_nonce);

        // AES ciphertext
        let aes_len = self.aes_ciphertext.len() as u32;
        bytes.extend_from_slice(&aes_len.to_le_bytes());
        bytes.extend_from_slice(&self.aes_ciphertext);

        // AES nonce
        bytes.extend_from_slice(&self.aes_nonce);

        // Encrypted shared secret
        let ess_len = self.encrypted_shared_secret.len() as u32;
        bytes.extend_from_slice(&ess_len.to_le_bytes());
        bytes.extend_from_slice(&self.encrypted_shared_secret);

        // Platform nonce
        bytes.extend_from_slice(&self.platform_nonce);

        bytes
    }

    /// Deserialize from a byte slice.
    ///
    /// # Errors
    ///
    /// Returns `CryptoError::Decryption` if the bytes are malformed.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, CryptoError> {
        // Minimum size: version(4) + kem_len(4) + chacha_nonce(12) + aes_len(4) +
        //              aes_nonce(12) + ess_len(4) + platform_nonce(12) = 52 bytes
        const MIN_SIZE: usize =
            4 + 4 + CHACHA_NONCE_SIZE + 4 + AES_NONCE_SIZE + 4 + CHACHA_NONCE_SIZE;
        if bytes.len() < MIN_SIZE {
            return Err(CryptoError::decryption("Message too short"));
        }

        let mut offset = 0_usize;

        // Read version
        let version_end = offset
            .checked_add(4)
            .ok_or_else(|| CryptoError::decryption("Offset overflow"))?;
        let version_bytes: [u8; 4] = bytes
            .get(offset..version_end)
            .ok_or_else(|| CryptoError::decryption("Invalid version slice"))?
            .try_into()
            .map_err(|_| CryptoError::decryption("Invalid version bytes"))?;
        let key_version = u32::from_le_bytes(version_bytes);
        offset = version_end;

        // Read KEM ciphertext length
        let kem_len_end = offset
            .checked_add(4)
            .ok_or_else(|| CryptoError::decryption("Offset overflow"))?;
        let kem_len_bytes: [u8; 4] = bytes
            .get(offset..kem_len_end)
            .ok_or_else(|| CryptoError::decryption("Invalid KEM length slice"))?
            .try_into()
            .map_err(|_| CryptoError::decryption("Invalid KEM length bytes"))?;
        let kem_len = u32::from_le_bytes(kem_len_bytes) as usize;
        offset = kem_len_end;

        // Read KEM ciphertext
        let kem_end = offset
            .checked_add(kem_len)
            .ok_or_else(|| CryptoError::decryption("Offset overflow"))?;
        let kem_ciphertext = bytes
            .get(offset..kem_end)
            .ok_or_else(|| CryptoError::decryption("Invalid KEM ciphertext slice"))?
            .to_vec();
        offset = kem_end;

        // Read ChaCha nonce
        let chacha_nonce_end = offset
            .checked_add(CHACHA_NONCE_SIZE)
            .ok_or_else(|| CryptoError::decryption("Offset overflow"))?;
        let chacha_nonce: [u8; CHACHA_NONCE_SIZE] = bytes
            .get(offset..chacha_nonce_end)
            .ok_or_else(|| CryptoError::decryption("Invalid ChaCha nonce slice"))?
            .try_into()
            .map_err(|_| CryptoError::decryption("Invalid ChaCha nonce bytes"))?;
        offset = chacha_nonce_end;

        // Read AES ciphertext length
        let aes_len_end = offset
            .checked_add(4)
            .ok_or_else(|| CryptoError::decryption("Offset overflow"))?;
        let aes_len_bytes: [u8; 4] = bytes
            .get(offset..aes_len_end)
            .ok_or_else(|| CryptoError::decryption("Invalid AES length slice"))?
            .try_into()
            .map_err(|_| CryptoError::decryption("Invalid AES length bytes"))?;
        let aes_len = u32::from_le_bytes(aes_len_bytes) as usize;
        offset = aes_len_end;

        // Read AES ciphertext
        let aes_end = offset
            .checked_add(aes_len)
            .ok_or_else(|| CryptoError::decryption("Offset overflow"))?;
        let aes_ciphertext = bytes
            .get(offset..aes_end)
            .ok_or_else(|| CryptoError::decryption("Invalid AES ciphertext slice"))?
            .to_vec();
        offset = aes_end;

        // Read AES nonce
        let aes_nonce_end = offset
            .checked_add(AES_NONCE_SIZE)
            .ok_or_else(|| CryptoError::decryption("Offset overflow"))?;
        let aes_nonce: [u8; AES_NONCE_SIZE] = bytes
            .get(offset..aes_nonce_end)
            .ok_or_else(|| CryptoError::decryption("Invalid AES nonce slice"))?
            .try_into()
            .map_err(|_| CryptoError::decryption("Invalid AES nonce bytes"))?;
        offset = aes_nonce_end;

        // Read encrypted shared secret length
        let ess_len_end = offset
            .checked_add(4)
            .ok_or_else(|| CryptoError::decryption("Offset overflow"))?;
        let ess_len_bytes: [u8; 4] = bytes
            .get(offset..ess_len_end)
            .ok_or_else(|| CryptoError::decryption("Invalid ESS length slice"))?
            .try_into()
            .map_err(|_| CryptoError::decryption("Invalid ESS length bytes"))?;
        let ess_len = u32::from_le_bytes(ess_len_bytes) as usize;
        offset = ess_len_end;

        // Read encrypted shared secret
        let ess_end = offset
            .checked_add(ess_len)
            .ok_or_else(|| CryptoError::decryption("Offset overflow"))?;
        let encrypted_shared_secret = bytes
            .get(offset..ess_end)
            .ok_or_else(|| CryptoError::decryption("Invalid encrypted shared secret slice"))?
            .to_vec();
        offset = ess_end;

        // Read platform nonce
        let platform_nonce_end = offset
            .checked_add(CHACHA_NONCE_SIZE)
            .ok_or_else(|| CryptoError::decryption("Offset overflow"))?;
        let platform_nonce: [u8; CHACHA_NONCE_SIZE] = bytes
            .get(offset..platform_nonce_end)
            .ok_or_else(|| CryptoError::decryption("Invalid platform nonce slice"))?
            .try_into()
            .map_err(|_| CryptoError::decryption("Invalid platform nonce bytes"))?;

        Ok(Self {
            kem_ciphertext,
            chacha_nonce,
            aes_ciphertext,
            aes_nonce,
            encrypted_shared_secret,
            platform_nonce,
            key_version,
        })
    }
}

impl std::fmt::Debug for PersistentEncryption {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PersistentEncryption")
            .field("kem_ciphertext_len", &self.kem_ciphertext.len())
            .field("aes_ciphertext_len", &self.aes_ciphertext.len())
            .field("chacha_nonce", &"[REDACTED]")
            .field("aes_nonce", &"[REDACTED]")
            .finish()
    }
}

#[cfg(test)]
#[allow(clippy::panic, clippy::expect_used)]
mod tests {
    use super::super::SecureStorage;
    use super::*;

    #[test]
    fn test_persistent_encryption_debug() {
        let storage = SecureStorage::new().expect("Failed to create storage");
        let encrypted = storage.encrypt(b"test").expect("Failed to encrypt");

        let debug_str = format!("{:?}", encrypted);
        assert!(debug_str.contains("PersistentEncryption"));
        assert!(debug_str.contains("[REDACTED]"));
    }

    #[test]
    fn test_from_components() {
        let storage = SecureStorage::new().expect("Failed to create storage");
        let data = b"component test";

        let encrypted = storage.encrypt(data).expect("Failed to encrypt");

        // Extract and reconstruct
        let reconstructed = PersistentEncryption::from_components(
            encrypted.kem_ciphertext().to_vec(),
            *encrypted.chacha_nonce(),
            encrypted.aes_ciphertext().to_vec(),
            *encrypted.aes_nonce(),
            encrypted.encrypted_shared_secret().to_vec(),
            *encrypted.platform_nonce(),
        );

        let decrypted = storage.decrypt(&reconstructed).expect("Failed to decrypt");
        assert_eq!(decrypted.as_slice(), data);
    }

    #[test]
    fn test_from_components_versioned() {
        let storage = SecureStorage::new().expect("Failed to create storage");
        let data = b"versioned test";

        let encrypted = storage.encrypt(data).expect("Failed to encrypt");

        // Reconstruct with version
        let reconstructed = PersistentEncryption::from_components_versioned(
            encrypted.kem_ciphertext().to_vec(),
            *encrypted.chacha_nonce(),
            encrypted.aes_ciphertext().to_vec(),
            *encrypted.aes_nonce(),
            encrypted.encrypted_shared_secret().to_vec(),
            *encrypted.platform_nonce(),
            encrypted.key_version(),
        );

        let decrypted = storage.decrypt(&reconstructed).expect("Failed to decrypt");
        assert_eq!(decrypted.as_slice(), data);
    }

    #[test]
    fn test_to_bytes_from_bytes_roundtrip() {
        let storage = SecureStorage::new().expect("Failed to create storage");
        let data = b"serialization test data";

        let encrypted = storage.encrypt(data).expect("Failed to encrypt");

        // Serialize
        let bytes = encrypted.to_bytes();

        // Deserialize
        let restored =
            PersistentEncryption::from_bytes(&bytes).expect("Failed to restore from bytes");

        // Verify decryption works
        let decrypted = storage.decrypt(&restored).expect("Failed to decrypt");
        assert_eq!(decrypted.as_slice(), data);
    }

    #[test]
    fn test_to_bytes_from_bytes_preserves_version() {
        let mut storage = SecureStorage::new().expect("Failed to create storage");

        // Rotate key to get non-zero version
        storage.rotate_key().expect("Rotation failed");
        storage.rotate_key().expect("Rotation failed");

        let encrypted = storage.encrypt(b"version test").expect("Failed to encrypt");
        assert_eq!(encrypted.key_version(), 2);

        // Serialize and restore
        let bytes = encrypted.to_bytes();
        let restored =
            PersistentEncryption::from_bytes(&bytes).expect("Failed to restore from bytes");

        assert_eq!(restored.key_version(), 2);
    }

    #[test]
    fn test_to_bytes_from_bytes_empty_data() {
        let storage = SecureStorage::new().expect("Failed to create storage");

        let encrypted = storage.encrypt(&[]).expect("Failed to encrypt");

        let bytes = encrypted.to_bytes();
        let restored =
            PersistentEncryption::from_bytes(&bytes).expect("Failed to restore from bytes");

        let decrypted = storage.decrypt(&restored).expect("Failed to decrypt");
        assert!(decrypted.is_empty());
    }

    #[test]
    fn test_to_bytes_from_bytes_large_data() {
        let storage = SecureStorage::new().expect("Failed to create storage");
        let data: Vec<u8> = (0..50_000).map(|i| (i % 256) as u8).collect();

        let encrypted = storage.encrypt(&data).expect("Failed to encrypt");

        let bytes = encrypted.to_bytes();
        let restored =
            PersistentEncryption::from_bytes(&bytes).expect("Failed to restore from bytes");

        let decrypted = storage.decrypt(&restored).expect("Failed to decrypt");
        assert_eq!(decrypted, data);
    }

    #[test]
    fn test_from_bytes_too_short_fails() {
        // Less than minimum size (52 bytes)
        let short_bytes = vec![0u8; 20];
        let result = PersistentEncryption::from_bytes(&short_bytes);
        assert!(result.is_err());
    }

    #[test]
    fn test_from_bytes_truncated_fails() {
        let storage = SecureStorage::new().expect("Failed to create storage");
        let encrypted = storage.encrypt(b"test").expect("Failed to encrypt");

        let mut bytes = encrypted.to_bytes();
        // Truncate to break the format
        bytes.truncate(bytes.len() / 2);

        let result = PersistentEncryption::from_bytes(&bytes);
        assert!(result.is_err());
    }

    #[test]
    fn test_to_components_from_components_versioned_roundtrip() {
        let mut storage = SecureStorage::new().expect("Failed to create storage");
        storage.rotate_key().expect("Rotation failed");

        let data = b"components roundtrip";
        let encrypted = storage.encrypt(data).expect("Failed to encrypt");

        // Export components
        let (kem_ct, chacha_nonce, aes_ct, aes_nonce, ess, platform_nonce, version) =
            encrypted.to_components();

        // Restore from components
        let restored = PersistentEncryption::from_components_versioned(
            kem_ct,
            chacha_nonce,
            aes_ct,
            aes_nonce,
            ess,
            platform_nonce,
            version,
        );

        let decrypted = storage.decrypt(&restored).expect("Failed to decrypt");
        assert_eq!(decrypted.as_slice(), data);
    }

    #[test]
    fn test_serialization_matches_components() {
        let storage = SecureStorage::new().expect("Failed to create storage");
        let encrypted = storage.encrypt(b"match test").expect("Failed to encrypt");

        // Get via bytes
        let bytes = encrypted.to_bytes();
        let from_bytes =
            PersistentEncryption::from_bytes(&bytes).expect("Failed to restore from bytes");

        // Get via components
        let (kem_ct, chacha_nonce, aes_ct, aes_nonce, ess, platform_nonce, version) =
            encrypted.to_components();
        let from_components = PersistentEncryption::from_components_versioned(
            kem_ct,
            chacha_nonce,
            aes_ct,
            aes_nonce,
            ess,
            platform_nonce,
            version,
        );

        // Both should decrypt to same value
        let decrypted_bytes = storage.decrypt(&from_bytes).expect("Decrypt bytes");
        let decrypted_components = storage
            .decrypt(&from_components)
            .expect("Decrypt components");
        assert_eq!(decrypted_bytes, decrypted_components);
    }
}
