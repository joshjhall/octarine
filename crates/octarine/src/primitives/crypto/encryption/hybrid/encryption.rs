//! Hybrid encrypted message for post-quantum encryption.

use chacha20poly1305::{
    ChaCha20Poly1305, Nonce,
    aead::{Aead, KeyInit},
};
use ml_kem::{
    MlKem1024,
    kem::{Decapsulate, Encapsulate},
};
use sha3::{Digest, Sha3_256};
use x25519_dalek::{EphemeralSecret, PublicKey as X25519PublicKey};
use zeroize::Zeroize;

use super::keypair::HybridKeyPair;
use super::public_key::HybridPublicKey;
use super::{
    CHACHA_DOMAIN, CryptoError, HYBRID_DOMAIN, KEY_SIZE, ML_KEM_CIPHERTEXT_SIZE, NONCE_SIZE,
    X25519_PUBLIC_KEY_SIZE, fill_random,
};

/// Components of a hybrid encrypted message for serialization.
pub type HybridEncryptedComponents = (
    Vec<u8>,          // ML-KEM ciphertext
    [u8; 32],         // Ephemeral X25519 public key
    [u8; NONCE_SIZE], // ChaCha20-Poly1305 nonce
    Vec<u8>,          // Ciphertext
);

/// Hybrid encrypted message.
///
/// Contains all components needed for decryption:
/// - ML-KEM ciphertext (encapsulated shared secret)
/// - Ephemeral X25519 public key
/// - ChaCha20-Poly1305 nonce and ciphertext
#[derive(Clone)]
pub struct HybridEncryption {
    /// ML-KEM ciphertext (encapsulated shared secret)
    kem_ciphertext: Vec<u8>,
    /// Ephemeral X25519 public key from sender
    ephemeral_x25519_pk: [u8; X25519_PUBLIC_KEY_SIZE],
    /// ChaCha20-Poly1305 nonce
    nonce: [u8; NONCE_SIZE],
    /// Encrypted data (ciphertext + auth tag)
    ciphertext: Vec<u8>,
    /// Original plaintext length
    plaintext_len: usize,
}

impl HybridEncryption {
    /// Encrypt data to a recipient's hybrid public key.
    ///
    /// Uses ephemeral X25519 and ML-KEM key exchange to derive a shared
    /// encryption key, then encrypts with ChaCha20-Poly1305.
    ///
    /// # Arguments
    ///
    /// * `data` - The plaintext data to encrypt
    /// * `recipient_pk` - The recipient's hybrid public key
    ///
    /// # Returns
    ///
    /// A `HybridEncryption` containing the ciphertext and key exchange data.
    ///
    /// # Errors
    ///
    /// Returns `CryptoError::Encryption` if encryption fails.
    pub fn encrypt_to(data: &[u8], recipient_pk: &HybridPublicKey) -> Result<Self, CryptoError> {
        // Use system RNG for ML-KEM encapsulation
        let mut rng = rand_core::UnwrapErr(getrandom::SysRng);

        // Generate ephemeral X25519 keypair (uses getrandom internally)
        let ephemeral_x25519_sk = EphemeralSecret::random();
        let ephemeral_x25519_pk = X25519PublicKey::from(&ephemeral_x25519_sk);

        // X25519 key exchange
        let x25519_shared_secret = ephemeral_x25519_sk.diffie_hellman(&recipient_pk.x25519_pk);

        // ML-KEM encapsulation
        let (kem_ciphertext, kem_shared_secret) =
            recipient_pk.ml_kem_ek.encapsulate_with_rng(&mut rng);

        // Combine shared secrets with domain separation
        let combined_secret = Self::combine_secrets(
            x25519_shared_secret.as_bytes(),
            AsRef::<[u8]>::as_ref(&kem_shared_secret),
        );

        // Derive encryption key
        let mut encryption_key = [0u8; KEY_SIZE];
        Self::derive_key(&combined_secret, &mut encryption_key);

        // Generate random nonce using internal random primitive
        let mut nonce = [0u8; NONCE_SIZE];
        fill_random(&mut nonce)?;

        // Encrypt with ChaCha20-Poly1305
        let cipher = ChaCha20Poly1305::new_from_slice(&encryption_key)
            .map_err(|e| CryptoError::encryption(format!("Failed to create cipher: {e}")))?;

        let nonce_ref = Nonce::from_slice(&nonce);
        let ciphertext = cipher
            .encrypt(nonce_ref, data)
            .map_err(|e| CryptoError::encryption(format!("Encryption failed: {e}")))?;

        // Zeroize sensitive material (encryption_key is already mut)
        encryption_key.zeroize();

        Ok(Self {
            kem_ciphertext: AsRef::<[u8]>::as_ref(&kem_ciphertext).to_vec(),
            ephemeral_x25519_pk: *ephemeral_x25519_pk.as_bytes(),
            nonce,
            ciphertext,
            plaintext_len: data.len(),
        })
    }

    /// Decrypt the message with the recipient's private key.
    ///
    /// # Arguments
    ///
    /// * `recipient_keys` - The recipient's hybrid keypair
    ///
    /// # Returns
    ///
    /// The decrypted plaintext.
    ///
    /// # Errors
    ///
    /// Returns `CryptoError::Decryption` if decryption fails.
    pub fn decrypt_with(&self, recipient_keys: &HybridKeyPair) -> Result<Vec<u8>, CryptoError> {
        // X25519 key exchange with ephemeral public key
        let sender_pk = X25519PublicKey::from(self.ephemeral_x25519_pk);
        let x25519_shared_secret = recipient_keys.x25519_sk.diffie_hellman(&sender_pk);

        // ML-KEM decapsulation - convert byte slice to fixed-size array
        if self.kem_ciphertext.len() != ML_KEM_CIPHERTEXT_SIZE {
            return Err(CryptoError::decryption(format!(
                "Invalid ML-KEM ciphertext length: expected {}, got {}",
                ML_KEM_CIPHERTEXT_SIZE,
                self.kem_ciphertext.len()
            )));
        }

        // Convert to fixed-size array for ML-KEM ciphertext
        let kem_ct_arr: [u8; ML_KEM_CIPHERTEXT_SIZE] = self
            .kem_ciphertext
            .as_slice()
            .try_into()
            .map_err(|_| CryptoError::decryption("Failed to convert KEM ciphertext"))?;

        // The decapsulate trait expects the encoded ciphertext type
        // which is what from_bytes on the appropriate type creates
        let kem_ciphertext = ml_kem::Ciphertext::<MlKem1024>::from(kem_ct_arr);

        // ML-KEM decapsulation returns the shared secret directly
        let kem_shared_secret = recipient_keys.ml_kem_dk.decapsulate(&kem_ciphertext);

        // Combine shared secrets
        let combined_secret = Self::combine_secrets(
            x25519_shared_secret.as_bytes(),
            AsRef::<[u8]>::as_ref(&kem_shared_secret),
        );

        // Derive decryption key
        let mut decryption_key = [0u8; KEY_SIZE];
        Self::derive_key(&combined_secret, &mut decryption_key);

        // Decrypt with ChaCha20-Poly1305
        let cipher = ChaCha20Poly1305::new_from_slice(&decryption_key)
            .map_err(|e| CryptoError::decryption(format!("Failed to create cipher: {e}")))?;

        let nonce = Nonce::from_slice(&self.nonce);
        let plaintext = cipher
            .decrypt(nonce, self.ciphertext.as_slice())
            .map_err(|e| CryptoError::decryption(format!("Decryption failed: {e}")))?;

        // Zeroize sensitive material (decryption_key is already mut)
        decryption_key.zeroize();

        Ok(plaintext)
    }

    /// Combine X25519 and ML-KEM shared secrets.
    fn combine_secrets(x25519_ss: &[u8], ml_kem_ss: &[u8]) -> [u8; 32] {
        let mut hasher = Sha3_256::new();
        hasher.update(x25519_ss);
        hasher.update(ml_kem_ss);
        hasher.update(HYBRID_DOMAIN);
        hasher.finalize().into()
    }

    /// Derive encryption key from combined secret.
    fn derive_key(combined_secret: &[u8; 32], key: &mut [u8; KEY_SIZE]) {
        let mut hasher = Sha3_256::new();
        hasher.update(combined_secret);
        hasher.update(CHACHA_DOMAIN);
        let result = hasher.finalize();
        key.copy_from_slice(&result);
    }

    /// Get the ML-KEM ciphertext for serialization.
    pub fn kem_ciphertext(&self) -> &[u8] {
        &self.kem_ciphertext
    }

    /// Get the ephemeral X25519 public key.
    pub fn ephemeral_public_key(&self) -> &[u8; X25519_PUBLIC_KEY_SIZE] {
        &self.ephemeral_x25519_pk
    }

    /// Get the ChaCha20-Poly1305 nonce.
    pub fn nonce(&self) -> &[u8; NONCE_SIZE] {
        &self.nonce
    }

    /// Get the ciphertext.
    pub fn ciphertext(&self) -> &[u8] {
        &self.ciphertext
    }

    /// Get the original plaintext length.
    pub fn plaintext_len(&self) -> usize {
        self.plaintext_len
    }

    /// Export components for serialization.
    pub fn to_components(&self) -> HybridEncryptedComponents {
        (
            self.kem_ciphertext.clone(),
            self.ephemeral_x25519_pk,
            self.nonce,
            self.ciphertext.clone(),
        )
    }

    /// Reconstruct from serialized components.
    pub fn from_components(
        kem_ciphertext: Vec<u8>,
        ephemeral_x25519_pk: [u8; X25519_PUBLIC_KEY_SIZE],
        nonce: [u8; NONCE_SIZE],
        ciphertext: Vec<u8>,
    ) -> Result<Self, CryptoError> {
        if kem_ciphertext.len() != ML_KEM_CIPHERTEXT_SIZE {
            return Err(CryptoError::invalid_key(format!(
                "Invalid ML-KEM ciphertext length: expected {}, got {}",
                ML_KEM_CIPHERTEXT_SIZE,
                kem_ciphertext.len()
            )));
        }

        // Estimate plaintext length (ciphertext - auth tag)
        let plaintext_len = ciphertext.len().saturating_sub(16);

        Ok(Self {
            kem_ciphertext,
            ephemeral_x25519_pk,
            nonce,
            ciphertext,
            plaintext_len,
        })
    }

    /// Serialize the complete encrypted message.
    ///
    /// # Wire format
    ///
    /// `[kem_ct_len (4)][kem_ct][x25519_pk (32)][nonce (12)][ct_len (4)][ct]`
    ///
    /// All length fields use little-endian encoding. This is a canonical
    /// wire format, not native-endian, so ciphertexts remain portable
    /// between little-endian and big-endian hosts.
    pub fn to_bytes(&self) -> Vec<u8> {
        let kem_len = self.kem_ciphertext.len() as u32;
        let ct_len = self.ciphertext.len() as u32;

        let capacity = 4_usize
            .saturating_add(self.kem_ciphertext.len())
            .saturating_add(X25519_PUBLIC_KEY_SIZE)
            .saturating_add(NONCE_SIZE)
            .saturating_add(4)
            .saturating_add(self.ciphertext.len());
        let mut bytes = Vec::with_capacity(capacity);

        bytes.extend_from_slice(&kem_len.to_le_bytes());
        bytes.extend_from_slice(&self.kem_ciphertext);
        bytes.extend_from_slice(&self.ephemeral_x25519_pk);
        bytes.extend_from_slice(&self.nonce);
        bytes.extend_from_slice(&ct_len.to_le_bytes());
        bytes.extend_from_slice(&self.ciphertext);

        bytes
    }

    /// Deserialize an encrypted message from bytes.
    ///
    /// See [`to_bytes`](Self::to_bytes) for the wire format. All length
    /// fields are decoded as little-endian.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, CryptoError> {
        if bytes.len() < 4 {
            return Err(CryptoError::decryption("Message too short"));
        }

        let mut offset = 0_usize;

        // Read KEM ciphertext length
        let kem_len_end = offset
            .checked_add(4)
            .ok_or_else(|| CryptoError::decryption("Offset overflow"))?;
        let kem_len_bytes: [u8; 4] = bytes
            .get(offset..kem_len_end)
            .ok_or_else(|| CryptoError::decryption("Message too short for KEM length"))?
            .try_into()
            .map_err(|_| CryptoError::decryption("Invalid KEM length bytes"))?;
        let kem_len = u32::from_le_bytes(kem_len_bytes) as usize;
        offset = kem_len_end;

        // Calculate minimum required length
        let min_required = offset
            .checked_add(kem_len)
            .and_then(|v| v.checked_add(X25519_PUBLIC_KEY_SIZE))
            .and_then(|v| v.checked_add(NONCE_SIZE))
            .and_then(|v| v.checked_add(4))
            .ok_or_else(|| CryptoError::decryption("Size overflow"))?;

        if bytes.len() < min_required {
            return Err(CryptoError::decryption("Message too short for components"));
        }

        // Read KEM ciphertext
        let kem_end = offset
            .checked_add(kem_len)
            .ok_or_else(|| CryptoError::decryption("Offset overflow"))?;
        let kem_ciphertext = bytes
            .get(offset..kem_end)
            .ok_or_else(|| CryptoError::decryption("Invalid KEM ciphertext slice"))?
            .to_vec();
        offset = kem_end;

        // Read ephemeral X25519 public key
        let x25519_end = offset
            .checked_add(X25519_PUBLIC_KEY_SIZE)
            .ok_or_else(|| CryptoError::decryption("Offset overflow"))?;
        let ephemeral_x25519_pk: [u8; X25519_PUBLIC_KEY_SIZE] = bytes
            .get(offset..x25519_end)
            .ok_or_else(|| CryptoError::decryption("Invalid X25519 public key slice"))?
            .try_into()
            .map_err(|_| CryptoError::decryption("Invalid X25519 public key bytes"))?;
        offset = x25519_end;

        // Read nonce
        let nonce_end = offset
            .checked_add(NONCE_SIZE)
            .ok_or_else(|| CryptoError::decryption("Offset overflow"))?;
        let nonce: [u8; NONCE_SIZE] = bytes
            .get(offset..nonce_end)
            .ok_or_else(|| CryptoError::decryption("Invalid nonce slice"))?
            .try_into()
            .map_err(|_| CryptoError::decryption("Invalid nonce bytes"))?;
        offset = nonce_end;

        // Read ciphertext length
        let ct_len_end = offset
            .checked_add(4)
            .ok_or_else(|| CryptoError::decryption("Offset overflow"))?;
        let ct_len_bytes: [u8; 4] = bytes
            .get(offset..ct_len_end)
            .ok_or_else(|| CryptoError::decryption("Invalid ciphertext length slice"))?
            .try_into()
            .map_err(|_| CryptoError::decryption("Invalid ciphertext length bytes"))?;
        let ct_len = u32::from_le_bytes(ct_len_bytes) as usize;
        offset = ct_len_end;

        let ct_end = offset
            .checked_add(ct_len)
            .ok_or_else(|| CryptoError::decryption("Offset overflow"))?;
        if bytes.len() < ct_end {
            return Err(CryptoError::decryption("Message too short for ciphertext"));
        }

        // Read ciphertext
        let ciphertext = bytes
            .get(offset..ct_end)
            .ok_or_else(|| CryptoError::decryption("Invalid ciphertext slice"))?
            .to_vec();

        Self::from_components(kem_ciphertext, ephemeral_x25519_pk, nonce, ciphertext)
    }
}

impl std::fmt::Debug for HybridEncryption {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HybridEncryption")
            .field("plaintext_len", &self.plaintext_len)
            .field("ciphertext_len", &self.ciphertext.len())
            .field("kem_ciphertext_len", &self.kem_ciphertext.len())
            .field("nonce", &"[REDACTED]")
            .field("ephemeral_pk", &"[REDACTED]")
            .finish()
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
#[allow(clippy::panic, clippy::expect_used)]
mod tests {
    use super::super::{CryptoError, ML_KEM_CIPHERTEXT_SIZE, NONCE_SIZE, X25519_PUBLIC_KEY_SIZE};
    use super::*;

    #[test]
    fn test_encrypt_decrypt() {
        let recipient = HybridKeyPair::generate().expect("Failed to generate keypair");
        let recipient_pk = recipient.public_key();

        let plaintext = b"Hello, post-quantum world!";
        let encrypted =
            HybridEncryption::encrypt_to(plaintext, &recipient_pk).expect("Failed to encrypt");

        let decrypted = encrypted
            .decrypt_with(&recipient)
            .expect("Failed to decrypt");
        assert_eq!(decrypted.as_slice(), plaintext);
    }

    #[test]
    fn test_empty_data() {
        let recipient = HybridKeyPair::generate().expect("Failed to generate keypair");
        let recipient_pk = recipient.public_key();

        let encrypted =
            HybridEncryption::encrypt_to(&[], &recipient_pk).expect("Failed to encrypt");

        let decrypted = encrypted
            .decrypt_with(&recipient)
            .expect("Failed to decrypt");
        assert!(decrypted.is_empty());
    }

    #[test]
    fn test_large_data() {
        let recipient = HybridKeyPair::generate().expect("Failed to generate keypair");
        let recipient_pk = recipient.public_key();

        let plaintext: Vec<u8> = (0..100_000).map(|i| (i % 256) as u8).collect();
        let encrypted =
            HybridEncryption::encrypt_to(&plaintext, &recipient_pk).expect("Failed to encrypt");

        let decrypted = encrypted
            .decrypt_with(&recipient)
            .expect("Failed to decrypt");
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_unique_ciphertext() {
        let recipient = HybridKeyPair::generate().expect("Failed to generate keypair");
        let recipient_pk = recipient.public_key();

        let plaintext = b"same data";
        let enc1 =
            HybridEncryption::encrypt_to(plaintext, &recipient_pk).expect("Failed to encrypt 1");
        let enc2 =
            HybridEncryption::encrypt_to(plaintext, &recipient_pk).expect("Failed to encrypt 2");

        // Same plaintext should produce different ciphertext (different ephemeral keys)
        assert_ne!(enc1.ciphertext(), enc2.ciphertext());
        assert_ne!(enc1.ephemeral_public_key(), enc2.ephemeral_public_key());
    }

    #[test]
    fn test_wrong_key_fails() {
        let sender_recipient = HybridKeyPair::generate().expect("Failed to generate keypair 1");
        let wrong_recipient = HybridKeyPair::generate().expect("Failed to generate keypair 2");

        let encrypted = HybridEncryption::encrypt_to(b"secret", &sender_recipient.public_key())
            .expect("Failed to encrypt");

        // Decrypting with wrong key should fail
        let result = encrypted.decrypt_with(&wrong_recipient);
        assert!(result.is_err());
    }

    #[test]
    fn test_encryption_serialization() {
        let recipient = HybridKeyPair::generate().expect("Failed to generate keypair");
        let recipient_pk = recipient.public_key();

        let plaintext = b"serialize me";
        let encrypted =
            HybridEncryption::encrypt_to(plaintext, &recipient_pk).expect("Failed to encrypt");

        // Serialize
        let bytes = encrypted.to_bytes();

        // Deserialize
        let restored = HybridEncryption::from_bytes(&bytes).expect("Failed to restore encryption");

        // Verify decryption
        let decrypted = restored
            .decrypt_with(&recipient)
            .expect("Failed to decrypt");
        assert_eq!(decrypted.as_slice(), plaintext);
    }

    #[test]
    fn test_component_serialization() {
        let recipient = HybridKeyPair::generate().expect("Failed to generate keypair");
        let recipient_pk = recipient.public_key();

        let plaintext = b"component test";
        let encrypted =
            HybridEncryption::encrypt_to(plaintext, &recipient_pk).expect("Failed to encrypt");

        // Export components
        let (kem_ct, x25519_pk, nonce, ct) = encrypted.to_components();

        // Restore from components
        let restored = HybridEncryption::from_components(kem_ct, x25519_pk, nonce, ct)
            .expect("Failed to restore from components");

        // Verify decryption
        let decrypted = restored
            .decrypt_with(&recipient)
            .expect("Failed to decrypt");
        assert_eq!(decrypted.as_slice(), plaintext);
    }

    #[test]
    fn test_corrupted_ciphertext_fails() {
        let recipient = HybridKeyPair::generate().expect("Failed to generate keypair");
        let recipient_pk = recipient.public_key();

        let encrypted =
            HybridEncryption::encrypt_to(b"test", &recipient_pk).expect("Failed to encrypt");

        // Corrupt the ciphertext
        let (kem_ct, x25519_pk, nonce, mut ct) = encrypted.to_components();
        if let Some(first) = ct.first_mut() {
            *first ^= 0xFF;
        }

        let corrupted = HybridEncryption::from_components(kem_ct, x25519_pk, nonce, ct)
            .expect("Failed to create corrupted encryption");

        // Decryption should fail
        let result = corrupted.decrypt_with(&recipient);
        assert!(result.is_err());
    }

    #[test]
    fn test_debug_redacts_sensitive_info() {
        let keypair = HybridKeyPair::generate().expect("Failed to generate keypair");

        let encrypted = HybridEncryption::encrypt_to(b"test", &keypair.public_key())
            .expect("Failed to encrypt");
        let enc_debug = format!("{:?}", encrypted);

        assert!(enc_debug.contains("HybridEncryption"));
        assert!(enc_debug.contains("[REDACTED]"));
    }

    #[test]
    fn test_plaintext_len() {
        let recipient = HybridKeyPair::generate().expect("Failed to generate keypair");
        let plaintext = b"known length data";

        let encrypted = HybridEncryption::encrypt_to(plaintext, &recipient.public_key())
            .expect("Failed to encrypt");

        assert_eq!(encrypted.plaintext_len(), plaintext.len());
    }

    #[test]
    fn test_multiple_recipients() {
        let recipient1 = HybridKeyPair::generate().expect("Failed to generate keypair 1");
        let recipient2 = HybridKeyPair::generate().expect("Failed to generate keypair 2");

        let plaintext = b"multi-recipient message";

        // Encrypt to recipient 1
        let enc1 = HybridEncryption::encrypt_to(plaintext, &recipient1.public_key())
            .expect("Failed to encrypt to 1");

        // Encrypt to recipient 2
        let enc2 = HybridEncryption::encrypt_to(plaintext, &recipient2.public_key())
            .expect("Failed to encrypt to 2");

        // Each recipient can only decrypt their own message
        let dec1 = enc1.decrypt_with(&recipient1).expect("Failed to decrypt 1");
        let dec2 = enc2.decrypt_with(&recipient2).expect("Failed to decrypt 2");

        assert_eq!(dec1.as_slice(), plaintext);
        assert_eq!(dec2.as_slice(), plaintext);

        // Cross-decryption should fail
        assert!(enc1.decrypt_with(&recipient2).is_err());
        assert!(enc2.decrypt_with(&recipient1).is_err());
    }

    #[test]
    fn test_thread_safety() {
        use std::sync::Arc;
        use std::thread;

        let recipient = Arc::new(HybridKeyPair::generate().expect("Failed to generate keypair"));
        let recipient_pk = recipient.public_key();

        let handles: Vec<_> = (0..4)
            .map(|i| {
                let pk = recipient_pk.clone();
                let recv = Arc::clone(&recipient);
                thread::spawn(move || {
                    let msg = format!("message {}", i);
                    let encrypted = HybridEncryption::encrypt_to(msg.as_bytes(), &pk)
                        .expect("Failed to encrypt");
                    let decrypted = encrypted.decrypt_with(&recv).expect("Failed to decrypt");
                    assert_eq!(decrypted, msg.as_bytes());
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
    fn test_decrypt_with_mismatched_keypair_graceful_failure() {
        // Verify that decryption with wrong keypair fails gracefully
        // without panicking or leaking information
        let alice = HybridKeyPair::generate().expect("Failed to generate Alice's keypair");
        let bob = HybridKeyPair::generate().expect("Failed to generate Bob's keypair");
        let eve = HybridKeyPair::generate().expect("Failed to generate Eve's keypair");

        // Alice encrypts to Bob
        let plaintext = b"Secret message for Bob";
        let encrypted =
            HybridEncryption::encrypt_to(plaintext, &bob.public_key()).expect("Failed to encrypt");

        // Bob can decrypt
        let decrypted = encrypted.decrypt_with(&bob).expect("Bob should decrypt");
        assert_eq!(decrypted.as_slice(), plaintext);

        // Eve cannot decrypt (wrong keypair)
        let eve_result = encrypted.decrypt_with(&eve);
        assert!(eve_result.is_err());

        // Verify error type is appropriate
        match eve_result {
            Err(CryptoError::Decryption(_)) => {} // Expected
            other => panic!("Expected Decryption error, got: {:?}", other),
        }

        // Alice cannot decrypt (she's the sender, not recipient)
        let alice_result = encrypted.decrypt_with(&alice);
        assert!(alice_result.is_err());
    }

    #[test]
    fn test_corrupted_kem_ciphertext_fails() {
        let recipient = HybridKeyPair::generate().expect("Failed to generate keypair");

        let encrypted = HybridEncryption::encrypt_to(b"test", &recipient.public_key())
            .expect("Failed to encrypt");

        // Corrupt the KEM ciphertext
        let (mut kem_ct, x25519_pk, nonce, ct) = encrypted.to_components();
        if let Some(first) = kem_ct.first_mut() {
            *first ^= 0xFF;
        }

        let corrupted = HybridEncryption::from_components(kem_ct, x25519_pk, nonce, ct)
            .expect("Failed to create corrupted encryption");

        // Decryption should fail
        let result = corrupted.decrypt_with(&recipient);
        assert!(result.is_err());
    }

    #[test]
    fn test_corrupted_x25519_public_key_fails() {
        let recipient = HybridKeyPair::generate().expect("Failed to generate keypair");

        let encrypted = HybridEncryption::encrypt_to(b"test", &recipient.public_key())
            .expect("Failed to encrypt");

        // Corrupt the ephemeral X25519 public key
        let (kem_ct, mut x25519_pk, nonce, ct) = encrypted.to_components();
        x25519_pk[0] ^= 0xFF;

        let corrupted = HybridEncryption::from_components(kem_ct, x25519_pk, nonce, ct)
            .expect("Failed to create corrupted encryption");

        // Decryption should fail (wrong shared secret derived)
        let result = corrupted.decrypt_with(&recipient);
        assert!(result.is_err());
    }

    #[test]
    fn test_invalid_kem_ciphertext_length_rejected() {
        // Test that from_components rejects invalid KEM ciphertext lengths
        let invalid_kem = vec![0u8; 100]; // Wrong size (should be 1568)
        let x25519_pk = [0u8; X25519_PUBLIC_KEY_SIZE];
        let nonce = [0u8; NONCE_SIZE];
        let ciphertext = vec![0u8; 32];

        let result = HybridEncryption::from_components(invalid_kem, x25519_pk, nonce, ciphertext);
        assert!(result.is_err());
        match result {
            Err(CryptoError::InvalidKey(_)) => {} // Expected
            other => panic!("Expected InvalidKey error, got: {:?}", other),
        }
    }

    #[test]
    fn test_from_bytes_with_truncated_data() {
        let recipient = HybridKeyPair::generate().expect("Failed to generate keypair");

        let encrypted = HybridEncryption::encrypt_to(b"test data", &recipient.public_key())
            .expect("Failed to encrypt");

        let bytes = encrypted.to_bytes();

        // Test various truncation points
        for truncate_at in [0, 4, 10, 50, 100, bytes.len() / 2] {
            if let Some(truncated) = bytes.get(..truncate_at) {
                let result = HybridEncryption::from_bytes(truncated);
                assert!(
                    result.is_err(),
                    "Should fail at truncation point {}",
                    truncate_at
                );
            }
        }
    }

    #[test]
    fn test_binary_message_with_all_byte_values() {
        // Test that all 256 byte values are handled correctly
        let recipient = HybridKeyPair::generate().expect("Failed to generate keypair");

        let plaintext: Vec<u8> = (0u8..=255).collect();
        assert_eq!(plaintext.len(), 256);

        let encrypted = HybridEncryption::encrypt_to(&plaintext, &recipient.public_key())
            .expect("Failed to encrypt");

        let decrypted = encrypted
            .decrypt_with(&recipient)
            .expect("Failed to decrypt");
        assert_eq!(decrypted, plaintext);
    }
}
