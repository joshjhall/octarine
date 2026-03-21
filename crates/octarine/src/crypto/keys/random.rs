//! Secure Random Generation
//!
//! Cryptographically secure random number generation. All randomness is
//! sourced from the operating system's CSPRNG (via getrandom).
//!
//! # Note on Observability
//!
//! Random generation is NOT instrumented with observe events because:
//! - Random operations are extremely frequent (would flood logs)
//! - They don't represent security-relevant events per se
//! - The primitive implementation is already secure
//!
//! # Examples
//!
//! ```ignore
//! use octarine::crypto::keys::random;
//!
//! // Generate cryptographic keys
//! let key = random::key_256()?;
//! let nonce = random::nonce_12()?;
//!
//! // Generate identifiers
//! let uuid = random::uuid_v4()?;
//! let token = random::base64_url(32)?;
//!
//! // Random numbers
//! let id = random::u64()?;
//! let bounded = random::u32_bounded(100)?; // 0-99
//! ```

// Re-export all random functions from primitives (no instrumentation)
pub use crate::primitives::crypto::keys::{
    // Core random functions
    fill_random,
    // Identifier generation
    random_base64,
    random_base64_url,
    random_bytes,
    random_bytes_vec,

    // Selection and shuffling
    random_choice,
    random_hex,
    // Cryptographic primitives
    random_iv_16,
    random_key_128,
    random_key_256,
    random_nonce_12,
    random_nonce_24,
    random_salt,
    random_salt_sized,

    random_sample,
    // Typed random numbers
    random_u8,
    random_u16,
    random_u32,
    random_u32_bounded,
    random_u32_range,
    random_u64,
    random_u64_bounded,
    random_u64_range,
    random_u128,
    random_usize,
    random_usize_bounded,

    random_uuid_v4,

    shuffle,
};

// ============================================================================
// Convenience Aliases (shorter names for common operations)
// ============================================================================

use crate::primitives::crypto::CryptoError;

/// Generate a 256-bit (32-byte) encryption key.
///
/// Alias for `random_key_256()`.
#[inline]
pub fn key_256() -> Result<[u8; 32], CryptoError> {
    random_key_256()
}

/// Generate a 128-bit (16-byte) encryption key.
///
/// Alias for `random_key_128()`.
#[inline]
pub fn key_128() -> Result<[u8; 16], CryptoError> {
    random_key_128()
}

/// Generate a 12-byte nonce for ChaCha20-Poly1305 / AES-GCM.
///
/// Alias for `random_nonce_12()`.
#[inline]
pub fn nonce_12() -> Result<[u8; 12], CryptoError> {
    random_nonce_12()
}

/// Generate a 24-byte nonce for XChaCha20-Poly1305.
///
/// Alias for `random_nonce_24()`.
#[inline]
pub fn nonce_24() -> Result<[u8; 24], CryptoError> {
    random_nonce_24()
}

/// Generate a 16-byte IV for AES-CBC.
///
/// Alias for `random_iv_16()`.
#[inline]
pub fn iv_16() -> Result<[u8; 16], CryptoError> {
    random_iv_16()
}

/// Generate a 16-byte salt.
///
/// Alias for `random_salt()`.
#[inline]
pub fn salt() -> Result<[u8; 16], CryptoError> {
    random_salt()
}

/// Generate a random UUID v4.
///
/// Alias for `random_uuid_v4()`.
#[inline]
pub fn uuid_v4() -> Result<String, CryptoError> {
    random_uuid_v4()
}

/// Generate random bytes as a fixed-size array.
///
/// Alias for `random_bytes()`.
#[inline]
pub fn bytes<const N: usize>() -> Result<[u8; N], CryptoError> {
    random_bytes()
}

/// Generate random bytes as a Vec.
///
/// Alias for `random_bytes_vec()`.
#[inline]
pub fn bytes_vec(len: usize) -> Result<Vec<u8>, CryptoError> {
    random_bytes_vec(len)
}

/// Generate a random u64.
///
/// Alias for `random_u64()`.
#[inline]
pub fn u64() -> Result<u64, CryptoError> {
    random_u64()
}

/// Generate a random u32.
///
/// Alias for `random_u32()`.
#[inline]
pub fn u32() -> Result<u32, CryptoError> {
    random_u32()
}

/// Generate a URL-safe base64 string of random bytes.
///
/// Alias for `random_base64_url()`.
#[inline]
pub fn base64_url(byte_len: usize) -> Result<String, CryptoError> {
    random_base64_url(byte_len)
}

/// Generate a hex string of random bytes.
///
/// Alias for `random_hex()`.
#[inline]
pub fn hex(byte_len: usize) -> Result<String, CryptoError> {
    random_hex(byte_len)
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
#[allow(clippy::panic, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn test_key_generation() {
        let key = key_256().expect("Key generation failed");
        assert_eq!(key.len(), 32);

        let key2 = key_256().expect("Key generation failed");
        assert_ne!(key, key2); // Should be different each time
    }

    #[test]
    fn test_nonce_generation() {
        let nonce = nonce_12().expect("Nonce generation failed");
        assert_eq!(nonce.len(), 12);
    }

    #[test]
    fn test_uuid_generation() {
        let uuid = uuid_v4().expect("UUID generation failed");
        assert_eq!(uuid.len(), 36); // UUID format: 8-4-4-4-12
        assert!(uuid.contains('-'));
    }

    #[test]
    fn test_random_bytes() {
        let bytes: [u8; 16] = bytes().expect("Bytes generation failed");
        assert!(bytes.iter().any(|&b| b != 0)); // Shouldn't be all zeros
    }

    #[test]
    fn test_base64_url() {
        let token = base64_url(32).expect("Token generation failed");
        assert!(!token.is_empty());
        // URL-safe base64 shouldn't have + or /
        assert!(!token.contains('+'));
        assert!(!token.contains('/'));
    }
}
