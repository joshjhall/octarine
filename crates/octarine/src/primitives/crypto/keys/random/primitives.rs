//! Cryptographic random primitives (keys, nonces, salts).

use super::{CryptoError, random_bytes, random_bytes_vec};

// ============================================================================
// Cryptographic Primitives
// ============================================================================

/// Generate a random 256-bit (32-byte) encryption key.
///
/// Suitable for use with ChaCha20-Poly1305, AES-256-GCM, and other
/// 256-bit symmetric encryption algorithms.
///
/// # Example
///
/// ```ignore
/// use crate::primitives::crypto::random_key_256;
///
/// let key = random_key_256()?;
/// ```
#[inline]
pub fn random_key_256() -> Result<[u8; 32], CryptoError> {
    random_bytes()
}

/// Generate a random 128-bit (16-byte) encryption key.
///
/// Suitable for use with AES-128-GCM and other 128-bit symmetric
/// encryption algorithms.
#[inline]
pub fn random_key_128() -> Result<[u8; 16], CryptoError> {
    random_bytes()
}

/// Generate a random 96-bit (12-byte) nonce.
///
/// Standard nonce size for AEAD algorithms like ChaCha20-Poly1305
/// and AES-GCM.
///
/// # Example
///
/// ```ignore
/// use crate::primitives::crypto::random_nonce_12;
///
/// let nonce = random_nonce_12()?;
/// ```
#[inline]
pub fn random_nonce_12() -> Result<[u8; 12], CryptoError> {
    random_bytes()
}

/// Generate a random 192-bit (24-byte) nonce.
///
/// Extended nonce size for XChaCha20-Poly1305.
#[inline]
pub fn random_nonce_24() -> Result<[u8; 24], CryptoError> {
    random_bytes()
}

/// Generate a random 128-bit (16-byte) IV.
///
/// Standard IV size for AES-CBC and similar block cipher modes.
#[inline]
pub fn random_iv_16() -> Result<[u8; 16], CryptoError> {
    random_bytes()
}

/// Generate a random salt for key derivation.
///
/// Returns a 16-byte salt suitable for HKDF, PBKDF2, and Argon2.
///
/// # Example
///
/// ```ignore
/// use crate::primitives::crypto::random_salt;
///
/// let salt = random_salt()?;
/// let key = derive_key(password, &salt)?;
/// ```
#[inline]
pub fn random_salt() -> Result<[u8; 16], CryptoError> {
    random_bytes()
}

/// Generate a random salt with custom length.
///
/// # Arguments
///
/// * `len` - The salt length in bytes (recommended: 16-32)
///
/// # Errors
///
/// Returns an error if length is 0 or if the OS CSPRNG fails.
pub fn random_salt_sized(len: usize) -> Result<Vec<u8>, CryptoError> {
    if len == 0 {
        return Err(CryptoError::random_generation("Salt length cannot be zero"));
    }
    random_bytes_vec(len)
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
#[allow(clippy::panic, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn test_crypto_primitives() {
        let key_256 = random_key_256().expect("key_256");
        assert_eq!(key_256.len(), 32);

        let key_128 = random_key_128().expect("key_128");
        assert_eq!(key_128.len(), 16);

        let nonce_12 = random_nonce_12().expect("nonce_12");
        assert_eq!(nonce_12.len(), 12);

        let nonce_24 = random_nonce_24().expect("nonce_24");
        assert_eq!(nonce_24.len(), 24);

        let iv = random_iv_16().expect("iv");
        assert_eq!(iv.len(), 16);

        let salt = random_salt().expect("salt");
        assert_eq!(salt.len(), 16);
    }

    #[test]
    fn test_random_salt_sized() {
        let salt = random_salt_sized(32).expect("Sized salt");
        assert_eq!(salt.len(), 32);

        let result = random_salt_sized(0);
        assert!(result.is_err());
    }
}
