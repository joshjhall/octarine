//! HMAC-SHA3-256 Message Authentication
//!
//! Provides HMAC (Hash-based Message Authentication Code) using SHA3-256
//! as the underlying hash function for post-quantum security margins.
//!
//! ## Overview
//!
//! HMAC provides message integrity and authenticity verification. Given a
//! shared secret key, both sender and receiver can compute and verify
//! authentication tags.
//!
//! ## When to Use HMAC
//!
//! - **Message Authentication**: Verify data hasn't been tampered with
//! - **API Request Signing**: Authenticate API calls with shared secrets
//! - **Cookie/Token Integrity**: Ensure tokens haven't been modified
//! - **Commitment Schemes**: Create verifiable commitments to data
//!
//! ## Security Properties
//!
//! - **Unforgeability**: Cannot create valid MAC without the secret key
//! - **No Length Extension**: SHA3 is immune to length extension attacks
//! - **Post-Quantum Margins**: SHA3-256 provides 128-bit security against
//!   quantum computers (Grover's algorithm)
//!
//! ## Example
//!
//! ```ignore
//! use crate::primitives::crypto::hmac::{hmac_sha3_256, verify_hmac};
//!
//! let key = b"shared-secret-key";
//! let message = b"important data to authenticate";
//!
//! // Create MAC
//! let mac = hmac_sha3_256(key, message);
//!
//! // Verify MAC (constant-time comparison)
//! assert!(verify_hmac(key, message, &mac));
//! ```

// Allow dead_code: Layer 1 primitives used by Layer 2/3 modules
#![allow(dead_code)]

mod helpers;
mod streaming;

pub use helpers::{
    hmac_multipart, hmac_with_domain, verify_hmac_multipart, verify_hmac_with_domain,
};
pub use streaming::HmacSha3_256;

use sha3::{Digest, Sha3_256};
use zeroize::Zeroize;

use crate::primitives::crypto::CryptoError;

/// SHA3-256 output size in bytes (256 bits)
pub const MAC_LENGTH: usize = 32;

/// SHA3-256 internal block size in bytes
pub(super) const BLOCK_SIZE: usize = 136;

// ============================================================================
// Core HMAC Functions
// ============================================================================

/// Compute HMAC-SHA3-256 of a message.
///
/// Calculates a 256-bit message authentication code using the provided
/// key and message. The result can be used to verify message integrity
/// and authenticity.
///
/// # Arguments
///
/// * `key` - The secret key (any length, will be hashed if > 136 bytes)
/// * `message` - The message to authenticate
///
/// # Returns
///
/// A 32-byte authentication tag.
///
/// # Security Notes
///
/// - Key should be at least 32 bytes of cryptographically random data
/// - Never reuse keys across different protocols
/// - Use constant-time comparison when verifying
///
/// # Example
///
/// ```ignore
/// use crate::primitives::crypto::hmac::hmac_sha3_256;
///
/// let key = b"32-byte-secret-key-for-hmac!!!!";
/// let message = b"data to authenticate";
///
/// let mac = hmac_sha3_256(key, message);
/// assert_eq!(mac.len(), 32);
/// ```
#[must_use]
pub fn hmac_sha3_256(key: &[u8], message: &[u8]) -> [u8; MAC_LENGTH] {
    hmac_sha3_256_internal(key, message)
}

/// Compute HMAC-SHA3-256 and return as hex string.
///
/// Convenience function that returns the MAC as a lowercase hexadecimal
/// string, useful for logging or storage in text formats.
///
/// # Example
///
/// ```ignore
/// use crate::primitives::crypto::hmac::hmac_sha3_256_hex;
///
/// let mac = hmac_sha3_256_hex(b"key", b"message");
/// assert_eq!(mac.len(), 64); // 32 bytes = 64 hex chars
/// ```
#[must_use]
pub fn hmac_sha3_256_hex(key: &[u8], message: &[u8]) -> String {
    let mac = hmac_sha3_256(key, message);
    hex_encode(&mac)
}

/// Verify an HMAC-SHA3-256 tag in constant time.
///
/// Compares the provided tag against a freshly computed MAC using
/// constant-time comparison to prevent timing attacks.
///
/// # Arguments
///
/// * `key` - The secret key used to create the original MAC
/// * `message` - The message that was authenticated
/// * `expected_mac` - The MAC tag to verify
///
/// # Returns
///
/// `true` if the MAC is valid, `false` otherwise.
///
/// # Security Notes
///
/// - Always use this function instead of direct comparison
/// - Returns `false` for incorrect length MACs (timing-safe)
///
/// # Example
///
/// ```ignore
/// use crate::primitives::crypto::hmac::{hmac_sha3_256, verify_hmac};
///
/// let key = b"secret";
/// let message = b"data";
/// let valid_mac = hmac_sha3_256(key, message);
///
/// assert!(verify_hmac(key, message, &valid_mac));
/// assert!(!verify_hmac(key, b"wrong", &valid_mac));
/// ```
#[must_use]
pub fn verify_hmac(key: &[u8], message: &[u8], expected_mac: &[u8]) -> bool {
    // Constant-time length check
    if expected_mac.len() != MAC_LENGTH {
        return false;
    }

    let computed = hmac_sha3_256(key, message);
    super::ct_eq(&computed, expected_mac)
}

/// Verify an HMAC-SHA3-256 tag, returning a Result.
///
/// Like [`verify_hmac`] but returns a `Result` for use in error handling
/// chains. Useful when MAC verification failure should propagate as an error.
///
/// # Errors
///
/// Returns `CryptoError::MacVerification` if verification fails.
///
/// # Example
///
/// ```ignore
/// use crate::primitives::crypto::hmac::{hmac_sha3_256, verify_hmac_strict};
///
/// let key = b"secret";
/// let message = b"data";
/// let mac = hmac_sha3_256(key, message);
///
/// verify_hmac_strict(key, message, &mac)?;
/// // Continues if valid, returns error if invalid
/// ```
pub fn verify_hmac_strict(
    key: &[u8],
    message: &[u8],
    expected_mac: &[u8],
) -> Result<(), CryptoError> {
    if verify_hmac(key, message, expected_mac) {
        Ok(())
    } else {
        Err(CryptoError::mac_verification("HMAC verification failed"))
    }
}

/// Verify an HMAC from a hex-encoded string.
///
/// Convenience function for verifying hex-encoded MACs, common when
/// MACs are stored in text formats or transmitted as strings.
///
/// # Arguments
///
/// * `key` - The secret key
/// * `message` - The message that was authenticated
/// * `hex_mac` - The expected MAC as a hexadecimal string
///
/// # Returns
///
/// `true` if valid, `false` if invalid or malformed hex.
#[must_use]
pub fn verify_hmac_hex(key: &[u8], message: &[u8], hex_mac: &str) -> bool {
    match hex_decode(hex_mac) {
        Some(mac_bytes) => verify_hmac(key, message, &mac_bytes),
        None => false,
    }
}

// ============================================================================
// Internal Functions
// ============================================================================

/// Internal HMAC-SHA3-256 implementation.
fn hmac_sha3_256_internal(key: &[u8], message: &[u8]) -> [u8; MAC_LENGTH] {
    let (ipad, opad) = prepare_pads(key);

    // Inner hash: H(ipad || message)
    let mut inner_hasher = Sha3_256::new();
    inner_hasher.update(ipad);
    inner_hasher.update(message);
    let inner_hash = inner_hasher.finalize();

    // Outer hash: H(opad || inner_hash)
    let mut outer_hasher = Sha3_256::new();
    outer_hasher.update(opad);
    outer_hasher.update(inner_hash);
    let result = outer_hasher.finalize();

    let mut output = [0u8; MAC_LENGTH];
    output.copy_from_slice(&result);
    output
}

/// Prepare HMAC padding from key.
pub(super) fn prepare_pads(key: &[u8]) -> ([u8; BLOCK_SIZE], [u8; BLOCK_SIZE]) {
    // Prepare the key: if longer than block size, hash it; otherwise pad with zeros
    let mut k = [0u8; BLOCK_SIZE];
    if key.len() > BLOCK_SIZE {
        let mut hasher = Sha3_256::new();
        hasher.update(key);
        let hash = hasher.finalize();
        // Copy hash into first MAC_LENGTH bytes of k
        for (k_byte, hash_byte) in k.iter_mut().zip(hash.iter()) {
            *k_byte = *hash_byte;
        }
    } else {
        // Copy key into k (safe: key.len() <= BLOCK_SIZE)
        for (k_byte, key_byte) in k.iter_mut().zip(key.iter()) {
            *k_byte = *key_byte;
        }
    }

    // Inner padding (key XOR ipad)
    let mut ipad = [0x36u8; BLOCK_SIZE];
    for (ipad_byte, k_byte) in ipad.iter_mut().zip(k.iter()) {
        *ipad_byte ^= k_byte;
    }

    // Outer padding (key XOR opad)
    let mut opad = [0x5cu8; BLOCK_SIZE];
    for (opad_byte, k_byte) in opad.iter_mut().zip(k.iter()) {
        *opad_byte ^= k_byte;
    }

    // Zeroize key material
    k.zeroize();

    (ipad, opad)
}

/// Encode bytes as lowercase hex string.
pub(super) fn hex_encode(bytes: &[u8]) -> String {
    let mut result = String::with_capacity(bytes.len().saturating_mul(2));
    for byte in bytes {
        use std::fmt::Write;
        let _ = write!(result, "{:02x}", byte);
    }
    result
}

/// Decode hex string to bytes.
pub(super) fn hex_decode(hex: &str) -> Option<Vec<u8>> {
    // Must be even length
    if !hex.len().is_multiple_of(2) {
        return None;
    }

    let mut bytes = Vec::with_capacity(hex.len() / 2);
    let mut chars = hex.chars();

    while let (Some(h), Some(l)) = (chars.next(), chars.next()) {
        let high = h.to_digit(16)?;
        let low = l.to_digit(16)?;
        bytes.push(((high << 4) | low) as u8);
    }

    Some(bytes)
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
#[allow(clippy::panic, clippy::expect_used)]
mod tests {
    use super::*;

    // =========================================================================
    // Basic HMAC Tests
    // =========================================================================

    #[test]
    fn test_hmac_sha3_256_basic() {
        let key = b"secret-key";
        let message = b"test message";

        let mac = hmac_sha3_256(key, message);
        assert_eq!(mac.len(), MAC_LENGTH);
    }

    #[test]
    fn test_hmac_sha3_256_deterministic() {
        let key = b"secret-key";
        let message = b"test message";

        let mac1 = hmac_sha3_256(key, message);
        let mac2 = hmac_sha3_256(key, message);

        assert_eq!(mac1, mac2);
    }

    #[test]
    fn test_hmac_sha3_256_different_keys() {
        let message = b"same message";

        let mac1 = hmac_sha3_256(b"key1", message);
        let mac2 = hmac_sha3_256(b"key2", message);

        assert_ne!(mac1, mac2);
    }

    #[test]
    fn test_hmac_sha3_256_different_messages() {
        let key = b"same-key";

        let mac1 = hmac_sha3_256(key, b"message1");
        let mac2 = hmac_sha3_256(key, b"message2");

        assert_ne!(mac1, mac2);
    }

    #[test]
    fn test_hmac_sha3_256_empty_message() {
        let key = b"key";
        let mac = hmac_sha3_256(key, b"");
        assert_eq!(mac.len(), MAC_LENGTH);
    }

    #[test]
    fn test_hmac_sha3_256_empty_key() {
        let mac = hmac_sha3_256(b"", b"message");
        assert_eq!(mac.len(), MAC_LENGTH);
    }

    #[test]
    fn test_hmac_sha3_256_long_key() {
        // Key longer than block size (136 bytes)
        let long_key = vec![0xABu8; 200];
        let mac = hmac_sha3_256(&long_key, b"message");
        assert_eq!(mac.len(), MAC_LENGTH);
    }

    #[test]
    fn test_hmac_sha3_256_long_message() {
        let key = b"key";
        let long_message = vec![0xCDu8; 10000];
        let mac = hmac_sha3_256(key, &long_message);
        assert_eq!(mac.len(), MAC_LENGTH);
    }

    // =========================================================================
    // Hex Functions Tests
    // =========================================================================

    #[test]
    fn test_hmac_sha3_256_hex() {
        let mac = hmac_sha3_256_hex(b"key", b"message");
        assert_eq!(mac.len(), 64); // 32 bytes = 64 hex chars
        assert!(mac.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn test_hex_encode_decode_roundtrip() {
        let original = [0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x11, 0x22, 0x33];
        let encoded = hex_encode(&original);
        let decoded = hex_decode(&encoded).expect("decode failed");
        assert_eq!(decoded, original);
    }

    #[test]
    fn test_hex_decode_invalid() {
        assert!(hex_decode("not-hex").is_none());
        assert!(hex_decode("abc").is_none()); // Odd length
        assert!(hex_decode("GG").is_none()); // Invalid chars
    }

    // =========================================================================
    // Verification Tests
    // =========================================================================

    #[test]
    fn test_verify_hmac_valid() {
        let key = b"secret";
        let message = b"data";
        let mac = hmac_sha3_256(key, message);

        assert!(verify_hmac(key, message, &mac));
    }

    #[test]
    fn test_verify_hmac_wrong_message() {
        let key = b"secret";
        let mac = hmac_sha3_256(key, b"original");

        assert!(!verify_hmac(key, b"modified", &mac));
    }

    #[test]
    fn test_verify_hmac_wrong_key() {
        let message = b"data";
        let mac = hmac_sha3_256(b"key1", message);

        assert!(!verify_hmac(b"key2", message, &mac));
    }

    #[test]
    fn test_verify_hmac_wrong_length() {
        let key = b"secret";
        let message = b"data";

        // Too short
        assert!(!verify_hmac(key, message, &[0u8; 16]));
        // Too long
        assert!(!verify_hmac(key, message, &[0u8; 64]));
    }

    #[test]
    fn test_verify_hmac_modified_mac() {
        let key = b"secret";
        let message = b"data";
        let mut mac = hmac_sha3_256(key, message);

        // Flip one bit
        mac[0] ^= 1;
        assert!(!verify_hmac(key, message, &mac));
    }

    #[test]
    fn test_verify_hmac_strict() {
        let key = b"secret";
        let message = b"data";
        let mac = hmac_sha3_256(key, message);

        assert!(verify_hmac_strict(key, message, &mac).is_ok());
        assert!(verify_hmac_strict(key, b"wrong", &mac).is_err());
    }

    #[test]
    fn test_verify_hmac_hex() {
        let key = b"secret";
        let message = b"data";
        let mac_hex = hmac_sha3_256_hex(key, message);

        assert!(verify_hmac_hex(key, message, &mac_hex));
        assert!(!verify_hmac_hex(key, b"wrong", &mac_hex));
        assert!(!verify_hmac_hex(key, message, "invalid-hex"));
    }

    // =========================================================================
    // Edge Cases
    // =========================================================================

    #[test]
    fn test_hmac_block_boundary() {
        let key = b"k";
        // Message exactly at block size
        let message = vec![0u8; BLOCK_SIZE];
        let mac = hmac_sha3_256(key, &message);
        assert_eq!(mac.len(), MAC_LENGTH);
    }

    #[test]
    fn test_hmac_key_exactly_block_size() {
        let key = vec![0xABu8; BLOCK_SIZE];
        let mac = hmac_sha3_256(&key, b"message");
        assert_eq!(mac.len(), MAC_LENGTH);
    }

    #[test]
    fn test_hmac_key_one_over_block_size() {
        // This triggers key hashing
        let key = vec![0xABu8; BLOCK_SIZE + 1];
        let mac = hmac_sha3_256(&key, b"message");
        assert_eq!(mac.len(), MAC_LENGTH);
    }
}
