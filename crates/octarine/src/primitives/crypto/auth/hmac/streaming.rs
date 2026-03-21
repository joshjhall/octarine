//! Streaming HMAC computation.

use sha3::{Digest, Sha3_256};
use zeroize::Zeroize;

use super::{BLOCK_SIZE, MAC_LENGTH, hex_encode, prepare_pads};

/// Incremental HMAC computation for streaming data.
///
/// Allows computing HMAC over data that arrives in chunks, useful for:
/// - Large files that don't fit in memory
/// - Streaming network data
/// - Progressive hashing during data reception
///
/// # Security Notes
///
/// - The key is stored in memory until `finalize()` is called
/// - Call `finalize()` to get the result and zeroize internal state
///
/// # Example
///
/// ```ignore
/// use crate::primitives::crypto::hmac::HmacSha3_256;
///
/// let mut hmac = HmacSha3_256::new(b"secret-key");
/// hmac.update(b"chunk 1");
/// hmac.update(b"chunk 2");
/// hmac.update(b"chunk 3");
/// let mac = hmac.finalize();
///
/// // Equivalent to:
/// // hmac_sha3_256(b"secret-key", b"chunk 1chunk 2chunk 3")
/// ```
pub struct HmacSha3_256 {
    /// Inner hasher with ipad applied
    inner_hasher: Sha3_256,
    /// Prepared outer padding
    opad: [u8; BLOCK_SIZE],
    /// Whether finalize has been called
    finalized: bool,
}

impl HmacSha3_256 {
    /// Create a new incremental HMAC instance.
    ///
    /// # Arguments
    ///
    /// * `key` - The secret key for authentication
    #[must_use]
    pub fn new(key: &[u8]) -> Self {
        let (ipad, opad) = prepare_pads(key);

        let mut inner_hasher = Sha3_256::new();
        inner_hasher.update(ipad);

        Self {
            inner_hasher,
            opad,
            finalized: false,
        }
    }

    /// Add data to the HMAC computation.
    ///
    /// Can be called multiple times to process data incrementally.
    /// Must not be called after `finalize()`.
    ///
    /// # Panics
    ///
    /// Panics if called after `finalize()` has been called.
    pub fn update(&mut self, data: &[u8]) {
        assert!(!self.finalized, "Cannot update after finalize");
        self.inner_hasher.update(data);
    }

    /// Complete the HMAC computation and return the result.
    ///
    /// Consumes the HMAC instance and returns the authentication tag.
    /// The internal state is zeroized after this call.
    ///
    /// # Returns
    ///
    /// The 32-byte authentication tag.
    #[must_use]
    pub fn finalize(mut self) -> [u8; MAC_LENGTH] {
        self.finalized = true;

        // Complete inner hash: H(ipad || message)
        let inner_result = self.inner_hasher.finalize_reset();

        // Compute outer hash: H(opad || inner_hash)
        let mut outer_hasher = Sha3_256::new();
        outer_hasher.update(self.opad);
        outer_hasher.update(inner_result);
        let result = outer_hasher.finalize();

        // Zeroize sensitive state
        self.opad.zeroize();

        let mut output = [0u8; MAC_LENGTH];
        output.copy_from_slice(&result);
        output
    }

    /// Complete and return the MAC as a hex string.
    #[must_use]
    pub fn finalize_hex(self) -> String {
        hex_encode(&self.finalize())
    }
}

impl Drop for HmacSha3_256 {
    fn drop(&mut self) {
        self.opad.zeroize();
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
#[allow(clippy::panic, clippy::expect_used)]
mod tests {
    use super::super::{hmac_sha3_256, hmac_sha3_256_hex};
    use super::*;

    #[test]
    fn test_hmac_streaming_equivalent() {
        let key = b"streaming-key";
        let message = b"hello world from streaming";

        // One-shot
        let mac1 = hmac_sha3_256(key, message);

        // Streaming
        let mut hmac = HmacSha3_256::new(key);
        hmac.update(b"hello ");
        hmac.update(b"world ");
        hmac.update(b"from ");
        hmac.update(b"streaming");
        let mac2 = hmac.finalize();

        assert_eq!(mac1, mac2);
    }

    #[test]
    fn test_hmac_streaming_single_update() {
        let key = b"key";
        let message = b"message";

        let mac1 = hmac_sha3_256(key, message);

        let mut hmac = HmacSha3_256::new(key);
        hmac.update(message);
        let mac2 = hmac.finalize();

        assert_eq!(mac1, mac2);
    }

    #[test]
    fn test_hmac_streaming_empty() {
        let key = b"key";

        let mac1 = hmac_sha3_256(key, b"");

        let hmac = HmacSha3_256::new(key);
        let mac2 = hmac.finalize();

        assert_eq!(mac1, mac2);
    }

    #[test]
    fn test_hmac_finalize_hex() {
        let key = b"key";
        let message = b"message";

        let hex1 = hmac_sha3_256_hex(key, message);

        let mut hmac = HmacSha3_256::new(key);
        hmac.update(message);
        let hex2 = hmac.finalize_hex();

        assert_eq!(hex1, hex2);
    }
}
