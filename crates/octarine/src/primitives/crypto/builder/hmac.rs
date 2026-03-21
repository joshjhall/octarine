//! HMAC builder for message authentication.

use crate::primitives::crypto::CryptoError;
use crate::primitives::crypto::auth::{
    HmacSha3_256, hmac_multipart, hmac_sha3_256, hmac_sha3_256_hex, hmac_with_domain, verify_hmac,
    verify_hmac_hex, verify_hmac_multipart, verify_hmac_strict, verify_hmac_with_domain,
};

/// Builder for HMAC-SHA3-256 message authentication operations
///
/// Provides methods for computing and verifying message authentication codes
/// using HMAC with SHA3-256 as the underlying hash function.
///
/// # Security Features
///
/// - SHA3-256: No length extension attacks, post-quantum margins
/// - Constant-time verification to prevent timing attacks
/// - Domain separation support for cross-protocol safety
/// - Multipart authentication for structured data
#[derive(Debug, Clone, Default)]
pub struct HmacBuilder {
    _private: (),
}

impl HmacBuilder {
    /// Create a new HmacBuilder
    #[must_use]
    pub fn new() -> Self {
        Self { _private: () }
    }

    /// Compute HMAC-SHA3-256 of a message
    ///
    /// Returns a 32-byte authentication tag.
    ///
    /// # Example
    ///
    /// ```ignore
    /// let crypto = CryptoBuilder::new();
    /// let mac = crypto.hmac().compute(b"key", b"message");
    /// assert_eq!(mac.len(), 32);
    /// ```
    #[must_use]
    pub fn compute(&self, key: &[u8], message: &[u8]) -> [u8; 32] {
        hmac_sha3_256(key, message)
    }

    /// Compute HMAC and return as hex string
    #[must_use]
    pub fn compute_hex(&self, key: &[u8], message: &[u8]) -> String {
        hmac_sha3_256_hex(key, message)
    }

    /// Verify an HMAC tag (constant-time)
    ///
    /// Returns `true` if the MAC is valid.
    #[must_use]
    pub fn verify(&self, key: &[u8], message: &[u8], mac: &[u8]) -> bool {
        verify_hmac(key, message, mac)
    }

    /// Verify an HMAC tag, returning a Result
    ///
    /// Useful for error handling chains.
    pub fn verify_strict(&self, key: &[u8], message: &[u8], mac: &[u8]) -> Result<(), CryptoError> {
        verify_hmac_strict(key, message, mac)
    }

    /// Verify an HMAC from a hex string
    #[must_use]
    pub fn verify_hex(&self, key: &[u8], message: &[u8], hex_mac: &str) -> bool {
        verify_hmac_hex(key, message, hex_mac)
    }

    /// Create an incremental HMAC for streaming data
    ///
    /// Use this when data arrives in chunks.
    ///
    /// # Example
    ///
    /// ```ignore
    /// let crypto = CryptoBuilder::new();
    /// let mut hmac = crypto.hmac().streaming(b"key");
    /// hmac.update(b"chunk1");
    /// hmac.update(b"chunk2");
    /// let mac = hmac.finalize();
    /// ```
    #[must_use]
    pub fn streaming(&self, key: &[u8]) -> HmacSha3_256 {
        HmacSha3_256::new(key)
    }

    /// Compute HMAC with domain separation
    ///
    /// Prevents cross-protocol attacks by including a domain separator.
    #[must_use]
    pub fn with_domain(&self, key: &[u8], domain: &str, message: &[u8]) -> [u8; 32] {
        hmac_with_domain(key, domain, message)
    }

    /// Verify an HMAC created with domain separation
    #[must_use]
    pub fn verify_with_domain(&self, key: &[u8], domain: &str, message: &[u8], mac: &[u8]) -> bool {
        verify_hmac_with_domain(key, domain, message, mac)
    }

    /// Compute HMAC for multiple message parts
    ///
    /// Authenticates structured data with length-prefixed parts
    /// to prevent concatenation attacks.
    #[must_use]
    pub fn multipart(&self, key: &[u8], parts: &[&[u8]]) -> [u8; 32] {
        hmac_multipart(key, parts)
    }

    /// Verify a multipart HMAC
    #[must_use]
    pub fn verify_multipart(&self, key: &[u8], parts: &[&[u8]], mac: &[u8]) -> bool {
        verify_hmac_multipart(key, parts, mac)
    }
}

// Note: HmacBuilder tests are covered by the hmac module's own tests.
// The builder just delegates to those functions.
