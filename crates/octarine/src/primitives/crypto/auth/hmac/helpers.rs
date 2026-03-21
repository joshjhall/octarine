//! HMAC helper functions for domain separation and multipart messages.

use super::MAC_LENGTH;
use super::streaming::HmacSha3_256;

// ============================================================================
// Keyed Message Authentication Helpers
// ============================================================================

/// Create a MAC for a message with domain separation.
///
/// Adds a domain separator to prevent cross-protocol attacks. The domain
/// is prepended to the message before computing the MAC.
///
/// # Arguments
///
/// * `key` - The secret key
/// * `domain` - Domain separator string (e.g., "api-v1")
/// * `message` - The message to authenticate
///
/// # Example
///
/// ```ignore
/// use crate::primitives::crypto::hmac::hmac_with_domain;
///
/// // Different domains produce different MACs even for same key/message
/// let mac1 = hmac_with_domain(b"key", "service-a", b"data");
/// let mac2 = hmac_with_domain(b"key", "service-b", b"data");
/// assert_ne!(mac1, mac2);
/// ```
#[must_use]
pub fn hmac_with_domain(key: &[u8], domain: &str, message: &[u8]) -> [u8; MAC_LENGTH] {
    let mut hmac = HmacSha3_256::new(key);
    hmac.update(domain.as_bytes());
    hmac.update(b":");
    hmac.update(message);
    hmac.finalize()
}

/// Verify a MAC that was created with domain separation.
#[must_use]
pub fn verify_hmac_with_domain(
    key: &[u8],
    domain: &str,
    message: &[u8],
    expected_mac: &[u8],
) -> bool {
    let computed = hmac_with_domain(key, domain, message);
    super::super::ct_eq(&computed, expected_mac)
}

/// Create a MAC for multiple message parts.
///
/// Authenticates multiple pieces of data in a defined order, useful for
/// authenticating structured data with multiple fields.
///
/// # Arguments
///
/// * `key` - The secret key
/// * `parts` - Slices of data to authenticate
///
/// # Example
///
/// ```ignore
/// use crate::primitives::crypto::hmac::hmac_multipart;
///
/// let mac = hmac_multipart(b"key", &[
///     b"header",
///     b"body",
///     b"footer",
/// ]);
/// ```
#[must_use]
pub fn hmac_multipart(key: &[u8], parts: &[&[u8]]) -> [u8; MAC_LENGTH] {
    let mut hmac = HmacSha3_256::new(key);
    for (i, part) in parts.iter().enumerate() {
        if i > 0 {
            // Add separator between parts to prevent concatenation attacks
            hmac.update(&[0x00]);
        }
        // Add length prefix to prevent ambiguity
        let len_bytes = (part.len() as u64).to_le_bytes();
        hmac.update(&len_bytes);
        hmac.update(part);
    }
    hmac.finalize()
}

/// Verify a multipart MAC.
#[must_use]
pub fn verify_hmac_multipart(key: &[u8], parts: &[&[u8]], expected_mac: &[u8]) -> bool {
    let computed = hmac_multipart(key, parts);
    super::super::ct_eq(&computed, expected_mac)
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
#[allow(clippy::panic, clippy::expect_used)]
mod tests {
    use super::*;

    // =========================================================================
    // Domain Separation Tests
    // =========================================================================

    #[test]
    fn test_hmac_with_domain() {
        let key = b"shared-key";
        let message = b"data";

        let mac_a = hmac_with_domain(key, "service-a", message);
        let mac_b = hmac_with_domain(key, "service-b", message);

        assert_ne!(mac_a, mac_b);
    }

    #[test]
    fn test_verify_hmac_with_domain() {
        let key = b"key";
        let domain = "my-domain";
        let message = b"data";

        let mac = hmac_with_domain(key, domain, message);

        assert!(verify_hmac_with_domain(key, domain, message, &mac));
        assert!(!verify_hmac_with_domain(key, "other", message, &mac));
        assert!(!verify_hmac_with_domain(key, domain, b"wrong", &mac));
    }

    // =========================================================================
    // Multipart Tests
    // =========================================================================

    #[test]
    fn test_hmac_multipart() {
        let key = b"key";
        let parts: &[&[u8]] = &[b"part1", b"part2", b"part3"];

        let mac1 = hmac_multipart(key, parts);
        let mac2 = hmac_multipart(key, parts);

        assert_eq!(mac1, mac2);
    }

    #[test]
    fn test_hmac_multipart_different_order() {
        let key = b"key";

        let mac1 = hmac_multipart(key, &[b"a", b"b"]);
        let mac2 = hmac_multipart(key, &[b"b", b"a"]);

        assert_ne!(mac1, mac2);
    }

    #[test]
    fn test_hmac_multipart_prevents_concatenation() {
        let key = b"key";

        // These should produce different MACs even though concatenation is same
        let mac1 = hmac_multipart(key, &[b"ab", b"cd"]);
        let mac2 = hmac_multipart(key, &[b"abc", b"d"]);
        let mac3 = hmac_multipart(key, &[b"abcd"]);

        assert_ne!(mac1, mac2);
        assert_ne!(mac2, mac3);
        assert_ne!(mac1, mac3);
    }

    #[test]
    fn test_hmac_multipart_empty_parts() {
        let key = b"key";

        let mac1 = hmac_multipart(key, &[b"a", b"", b"b"]);
        let mac2 = hmac_multipart(key, &[b"a", b"b"]);

        // Empty part should still produce different result
        assert_ne!(mac1, mac2);
    }

    #[test]
    fn test_verify_hmac_multipart() {
        let key = b"key";
        let parts: &[&[u8]] = &[b"header", b"body"];

        let mac = hmac_multipart(key, parts);

        assert!(verify_hmac_multipart(key, parts, &mac));
        assert!(!verify_hmac_multipart(key, &[b"wrong"], &mac));
    }
}
