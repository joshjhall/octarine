//! Hybrid encryption builder for post-quantum key exchange.

use super::super::CryptoError;
use super::super::encryption::{HybridEncryption, HybridKeyPair, HybridPublicKey};

/// Builder for hybrid post-quantum encryption operations
///
/// Provides methods for post-quantum safe key exchange and encryption using
/// a hybrid of ML-KEM 1024 (FIPS 203) and X25519 (RFC 7748).
///
/// # Security Features
///
/// - ML-KEM 1024: NIST Level 5 post-quantum security
/// - X25519: 128-bit classical security
/// - Hybrid derivation: Security if either algorithm holds
/// - Forward secrecy: Ephemeral keys per encryption
/// - ChaCha20-Poly1305 authenticated encryption
#[derive(Debug, Clone, Default)]
pub struct HybridBuilder {
    _private: (),
}

impl HybridBuilder {
    /// Create a new HybridBuilder
    #[must_use]
    pub fn new() -> Self {
        Self { _private: () }
    }

    /// Generate a new hybrid keypair
    ///
    /// Creates fresh ML-KEM 1024 and X25519 keypairs for receiving
    /// encrypted messages.
    ///
    /// # Example
    ///
    /// ```ignore
    /// let crypto = CryptoBuilder::new();
    /// let keypair = crypto.hybrid().generate_keypair()?;
    /// let public_key = keypair.public_key();
    /// // Share public_key with senders
    /// ```
    pub fn generate_keypair(&self) -> Result<HybridKeyPair, CryptoError> {
        HybridKeyPair::generate()
    }

    /// Encrypt data to a recipient's public key
    ///
    /// Uses ephemeral X25519 and ML-KEM key exchange to derive a shared
    /// encryption key, then encrypts with ChaCha20-Poly1305.
    ///
    /// # Arguments
    ///
    /// * `data` - The plaintext to encrypt
    /// * `recipient_pk` - The recipient's hybrid public key
    ///
    /// # Example
    ///
    /// ```ignore
    /// let crypto = CryptoBuilder::new();
    /// let encrypted = crypto.hybrid().encrypt_to(b"secret", &recipient_pk)?;
    /// ```
    pub fn encrypt_to(
        &self,
        data: &[u8],
        recipient_pk: &HybridPublicKey,
    ) -> Result<HybridEncryption, CryptoError> {
        HybridEncryption::encrypt_to(data, recipient_pk)
    }

    /// Decrypt data with a keypair
    ///
    /// # Arguments
    ///
    /// * `encrypted` - The encrypted message
    /// * `keypair` - The recipient's hybrid keypair
    ///
    /// # Example
    ///
    /// ```ignore
    /// let crypto = CryptoBuilder::new();
    /// let decrypted = crypto.hybrid().decrypt(&encrypted, &keypair)?;
    /// ```
    pub fn decrypt(
        &self,
        encrypted: &HybridEncryption,
        keypair: &HybridKeyPair,
    ) -> Result<Vec<u8>, CryptoError> {
        encrypted.decrypt_with(keypair)
    }

    /// Restore a public key from serialized bytes
    ///
    /// Use this to deserialize a public key received from another party.
    pub fn public_key_from_bytes(&self, bytes: &[u8]) -> Result<HybridPublicKey, CryptoError> {
        HybridPublicKey::from_bytes(bytes)
    }

    /// Restore a keypair from serialized key material
    ///
    /// # Security Warning
    ///
    /// Handle key material with extreme care.
    pub fn keypair_from_bytes(
        &self,
        ml_kem_seed_bytes: &[u8],
        x25519_sk_bytes: &[u8; 32],
    ) -> Result<HybridKeyPair, CryptoError> {
        HybridKeyPair::from_bytes(ml_kem_seed_bytes, x25519_sk_bytes)
    }

    /// Restore encrypted message from serialized bytes
    pub fn encryption_from_bytes(&self, bytes: &[u8]) -> Result<HybridEncryption, CryptoError> {
        HybridEncryption::from_bytes(bytes)
    }

    /// Restore encrypted message from components
    pub fn encryption_from_components(
        &self,
        kem_ciphertext: Vec<u8>,
        ephemeral_x25519_pk: [u8; 32],
        nonce: [u8; 12],
        ciphertext: Vec<u8>,
    ) -> Result<HybridEncryption, CryptoError> {
        HybridEncryption::from_components(kem_ciphertext, ephemeral_x25519_pk, nonce, ciphertext)
    }

    /// Get the security level description
    #[must_use]
    pub fn security_level(&self) -> &'static str {
        "ML-KEM 1024 (NIST Level 5) + X25519 (128-bit) hybrid post-quantum security"
    }
}

// Note: HybridBuilder tests are covered by the hybrid module's own tests.
// The builder just delegates to those types.
