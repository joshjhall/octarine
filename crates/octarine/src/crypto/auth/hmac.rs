//! HMAC-SHA3-256 with observability
//!
//! Message authentication code operations wrapped with observe instrumentation
//! for audit trails and compliance support.
//!
//! # Security Events
//!
//! HMAC operations generate `security.hmac_*` events:
//! - `hmac_computed` - MAC computation completed
//! - `hmac_verified` - MAC verification attempted
//!
//! # Examples
//!
//! ```ignore
//! use octarine::crypto::auth;
//!
//! // Compute HMAC (generates security event)
//! let mac = auth::compute(&key, b"message");
//!
//! // Verify HMAC (generates security event with result)
//! let valid = auth::verify(&key, b"message", &mac);
//! ```

use crate::observe;
use crate::primitives::crypto::CryptoError;
use crate::primitives::crypto::auth as prim;

// ============================================================================
// Basic HMAC Operations
// ============================================================================

/// Compute HMAC-SHA3-256 of a message with audit trail.
///
/// Returns a 32-byte authentication tag.
///
/// # Security
///
/// - Key should be at least 32 bytes of cryptographically random data
/// - Never reuse keys across different protocols
/// - Use constant-time comparison when verifying (use `verify` function)
#[must_use]
pub fn compute(key: &[u8], message: &[u8]) -> [u8; 32] {
    let mac = prim::hmac_sha3_256(key, message);

    observe::info(
        "hmac_computed",
        format!("Computed HMAC-SHA3-256 for {} bytes", message.len()),
    );

    mac
}

/// Compute HMAC-SHA3-256 and return as hex string with audit trail.
#[must_use]
pub fn compute_hex(key: &[u8], message: &[u8]) -> String {
    let hex = prim::hmac_sha3_256_hex(key, message);

    observe::info(
        "hmac_computed",
        format!("Computed HMAC-SHA3-256 (hex) for {} bytes", message.len()),
    );

    hex
}

/// Verify an HMAC-SHA3-256 tag in constant time with audit trail.
///
/// Returns `true` if the MAC is valid, `false` otherwise.
///
/// # Security
///
/// - Uses constant-time comparison to prevent timing attacks
/// - Returns `false` for incorrect length MACs (timing-safe)
#[must_use]
pub fn verify(key: &[u8], message: &[u8], expected_mac: &[u8]) -> bool {
    let valid = prim::verify_hmac(key, message, expected_mac);

    if valid {
        observe::info(
            "hmac_verified",
            format!("HMAC verification succeeded for {} bytes", message.len()),
        );
    } else {
        observe::warn(
            "hmac_verified",
            format!("HMAC verification failed for {} bytes", message.len()),
        );
    }

    valid
}

/// Verify an HMAC-SHA3-256 tag, returning a Result with audit trail.
///
/// Useful for error handling chains.
///
/// # Errors
///
/// Returns `CryptoError::MacVerification` if verification fails.
pub fn verify_strict(key: &[u8], message: &[u8], expected_mac: &[u8]) -> Result<(), CryptoError> {
    let result = prim::verify_hmac_strict(key, message, expected_mac);

    match &result {
        Ok(()) => {
            observe::info(
                "hmac_verified",
                format!("HMAC verification succeeded for {} bytes", message.len()),
            );
        }
        Err(_) => {
            observe::warn(
                "hmac_verified",
                format!("HMAC verification failed for {} bytes", message.len()),
            );
        }
    }

    result
}

/// Verify an HMAC from a hex-encoded string with audit trail.
#[must_use]
pub fn verify_hex(key: &[u8], message: &[u8], hex_mac: &str) -> bool {
    let valid = prim::verify_hmac_hex(key, message, hex_mac);

    if valid {
        observe::info(
            "hmac_verified",
            format!(
                "HMAC (hex) verification succeeded for {} bytes",
                message.len()
            ),
        );
    } else {
        observe::warn(
            "hmac_verified",
            format!("HMAC (hex) verification failed for {} bytes", message.len()),
        );
    }

    valid
}

// ============================================================================
// Domain-Separated HMAC
// ============================================================================

/// Compute HMAC with domain separation with audit trail.
///
/// Prevents cross-protocol attacks by including a domain separator.
/// Different domains produce different MACs even for the same key/message.
///
/// # Example
///
/// ```ignore
/// use octarine::crypto::auth;
///
/// // API v1 and v2 produce different MACs
/// let mac_v1 = auth::with_domain(&key, "api:v1", b"data");
/// let mac_v2 = auth::with_domain(&key, "api:v2", b"data");
/// assert_ne!(mac_v1, mac_v2);
/// ```
#[must_use]
pub fn with_domain(key: &[u8], domain: &str, message: &[u8]) -> [u8; 32] {
    let mac = prim::hmac_with_domain(key, domain, message);

    observe::info(
        "hmac_computed",
        format!(
            "Computed domain-separated HMAC-SHA3-256 (domain={}) for {} bytes",
            domain,
            message.len()
        ),
    );

    mac
}

/// Verify an HMAC created with domain separation with audit trail.
#[must_use]
pub fn verify_with_domain(key: &[u8], domain: &str, message: &[u8], mac: &[u8]) -> bool {
    let valid = prim::verify_hmac_with_domain(key, domain, message, mac);

    if valid {
        observe::info(
            "hmac_verified",
            format!(
                "Domain-separated HMAC verification succeeded (domain={}) for {} bytes",
                domain,
                message.len()
            ),
        );
    } else {
        observe::warn(
            "hmac_verified",
            format!(
                "Domain-separated HMAC verification failed (domain={}) for {} bytes",
                domain,
                message.len()
            ),
        );
    }

    valid
}

// ============================================================================
// Multipart HMAC
// ============================================================================

/// Compute HMAC for multiple message parts with audit trail.
///
/// Authenticates structured data with length-prefixed parts to prevent
/// concatenation attacks.
///
/// # Example
///
/// ```ignore
/// use octarine::crypto::auth;
///
/// // Authenticate header and body separately
/// let mac = auth::multipart(&key, &[header, body]);
/// ```
#[must_use]
pub fn multipart(key: &[u8], parts: &[&[u8]]) -> [u8; 32] {
    let mac = prim::hmac_multipart(key, parts);

    let total_len: usize = parts.iter().map(|p| p.len()).sum();
    observe::info(
        "hmac_computed",
        format!(
            "Computed multipart HMAC-SHA3-256 ({} parts, {} total bytes)",
            parts.len(),
            total_len
        ),
    );

    mac
}

/// Verify a multipart HMAC with audit trail.
#[must_use]
pub fn verify_multipart(key: &[u8], parts: &[&[u8]], mac: &[u8]) -> bool {
    let valid = prim::verify_hmac_multipart(key, parts, mac);

    let total_len: usize = parts.iter().map(|p| p.len()).sum();
    if valid {
        observe::info(
            "hmac_verified",
            format!(
                "Multipart HMAC verification succeeded ({} parts, {} total bytes)",
                parts.len(),
                total_len
            ),
        );
    } else {
        observe::warn(
            "hmac_verified",
            format!(
                "Multipart HMAC verification failed ({} parts, {} total bytes)",
                parts.len(),
                total_len
            ),
        );
    }

    valid
}

// ============================================================================
// Validate Aliases (Standard Naming Convention)
// ============================================================================

/// Alias for `verify_strict` following naming conventions.
///
/// # Errors
///
/// Returns `CryptoError::MacVerification` if verification fails.
pub fn validate_strict(key: &[u8], message: &[u8], expected_mac: &[u8]) -> Result<(), CryptoError> {
    verify_strict(key, message, expected_mac)
}

/// Alias for `verify_hex` following naming conventions.
#[must_use]
pub fn validate_hex(key: &[u8], message: &[u8], hex_mac: &str) -> bool {
    verify_hex(key, message, hex_mac)
}

/// Alias for `verify_with_domain` following naming conventions.
#[must_use]
pub fn validate_with_domain(key: &[u8], domain: &str, message: &[u8], mac: &[u8]) -> bool {
    verify_with_domain(key, domain, message, mac)
}

/// Alias for `verify_multipart` following naming conventions.
#[must_use]
pub fn validate_multipart(key: &[u8], parts: &[&[u8]], mac: &[u8]) -> bool {
    verify_multipart(key, parts, mac)
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
#[allow(clippy::panic, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn test_compute() {
        let key = b"secret-key-32-bytes-long-here!!";
        let message = b"test message";

        let mac = compute(key, message);
        assert_eq!(mac.len(), 32);
    }

    #[test]
    fn test_compute_hex() {
        let key = b"secret-key";
        let message = b"test message";

        let mac = compute_hex(key, message);
        assert_eq!(mac.len(), 64); // 32 bytes = 64 hex chars
    }

    #[test]
    fn test_verify() {
        let key = b"secret-key";
        let message = b"test message";
        let mac = compute(key, message);

        assert!(verify(key, message, &mac));
        assert!(!verify(key, b"wrong message", &mac));
    }

    #[test]
    fn test_verify_strict() {
        let key = b"secret-key";
        let message = b"test message";
        let mac = compute(key, message);

        assert!(verify_strict(key, message, &mac).is_ok());
        assert!(verify_strict(key, b"wrong", &mac).is_err());
    }

    #[test]
    fn test_verify_hex() {
        let key = b"secret-key";
        let message = b"test message";
        let mac = compute_hex(key, message);

        assert!(verify_hex(key, message, &mac));
        assert!(!verify_hex(key, b"wrong", &mac));
    }

    #[test]
    fn test_with_domain() {
        let key = b"secret-key";
        let message = b"data";

        let mac_v1 = with_domain(key, "api:v1", message);
        let mac_v2 = with_domain(key, "api:v2", message);

        // Different domains produce different MACs
        assert_ne!(mac_v1, mac_v2);
    }

    #[test]
    fn test_verify_with_domain() {
        let key = b"secret-key";
        let message = b"data";

        let mac = with_domain(key, "api:v1", message);

        assert!(verify_with_domain(key, "api:v1", message, &mac));
        assert!(!verify_with_domain(key, "api:v2", message, &mac));
    }

    #[test]
    fn test_multipart() {
        let key = b"secret-key";
        let parts: &[&[u8]] = &[b"header", b"body"];

        let mac = multipart(key, parts);
        assert_eq!(mac.len(), 32);
    }

    #[test]
    fn test_verify_multipart() {
        let key = b"secret-key";
        let parts: &[&[u8]] = &[b"header", b"body"];

        let mac = multipart(key, parts);

        assert!(verify_multipart(key, parts, &mac));
        assert!(!verify_multipart(key, &[b"wrong", b"parts"], &mac));
    }

    #[test]
    fn test_compute_empty_key() {
        let mac = compute(b"", b"message");
        assert_eq!(mac.len(), 32);
    }

    #[test]
    fn test_compute_empty_message() {
        let mac = compute(b"secret-key", b"");
        assert_eq!(mac.len(), 32);
    }

    #[test]
    fn test_verify_wrong_length_mac() {
        let key = b"secret-key";
        let message = b"test message";

        // Too short (16 bytes)
        assert!(!verify(key, message, &[0u8; 16]));
        // Too long (64 bytes)
        assert!(!verify(key, message, &[0u8; 64]));
        // Empty
        assert!(!verify(key, message, &[]));
    }
}
