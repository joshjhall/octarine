//! Jwt validation functions
//!
//! Pure validation functions for token identifiers.

use super::super::detection::{JwtAlgorithm, detect_jwt_algorithm, is_jwt};
use crate::primitives::Problem;

// ============================================================================
// JWT Token Validation
// ============================================================================

/// Validate JWT token format (strict - returns Result)
///
/// Performs basic JWT format validation. Does not verify signature.
pub fn validate_jwt(token: &str) -> Result<(), Problem> {
    // Use detection layer for format validation
    if !is_jwt(token) {
        return Err(Problem::Validation("Invalid JWT format".into()));
    }

    // Basic length check
    if token.len() < 20 || token.len() > 10000 {
        return Err(Problem::Validation(
            "JWT token length out of expected range".into(),
        ));
    }

    // Verify all parts are present
    let parts: Vec<&str> = token.split('.').collect();
    if parts.len() != 3 {
        return Err(Problem::Validation("JWT must have exactly 3 parts".into()));
    }

    // Each part should be base64url encoded (basic check)
    for (i, part) in parts.iter().enumerate() {
        if part.is_empty() && i < 2 {
            // Header and payload can't be empty
            // Safe: i is from enumerate, max value is 2 (checked above), +1 cannot overflow
            return Err(Problem::Validation(format!(
                "JWT part {} is empty",
                i.saturating_add(1)
            )));
        }
    }

    Ok(())
}

/// Validate JWT algorithm security (strict - returns Result with algorithm)
///
/// Checks that the JWT uses a secure signing algorithm and returns the detected algorithm.
/// Rejects insecure algorithms like "none", "HS256" (when strict), and other weak algorithms.
///
/// # Security Considerations
///
/// - **"none" algorithm**: No signature - CRITICAL security vulnerability
/// - **"HS256"**: HMAC-SHA256 - Can be problematic in asymmetric key contexts
/// - This function decodes the JWT header and validates the "alg" field
///
/// # Arguments
///
/// * `token` - The JWT token to validate
/// * `allow_hmac` - If true, allow HMAC algorithms (HS256, HS384, HS512)
///
/// # Examples
///
/// ```ignore
/// use octarine::primitives::identifiers::token::validation::validate_jwt_algorithm;
///
/// // Reject "none" algorithm
/// assert!(validate_jwt_algorithm("eyJhbGciOiJub25lIn0.payload.signature", false).is_err());
///
/// // Allow RS256
/// let alg = validate_jwt_algorithm("eyJhbGciOiJSUzI1NiJ9.payload.signature", false)?;
/// assert_eq!(alg, JwtAlgorithm::Rs256);
/// ```
pub fn validate_jwt_algorithm(token: &str, allow_hmac: bool) -> Result<JwtAlgorithm, Problem> {
    // First validate basic format
    validate_jwt(token)?;

    // Detect algorithm
    let algorithm = detect_jwt_algorithm(token)?;

    // Validate algorithm security
    match algorithm {
        // CRITICAL: "none" algorithm means no signature
        JwtAlgorithm::None => Err(Problem::Validation(
            "JWT 'none' algorithm is insecure".into(),
        )),

        // HMAC algorithms - allowed only if explicitly permitted
        JwtAlgorithm::Hs256 | JwtAlgorithm::Hs384 | JwtAlgorithm::Hs512 => {
            if allow_hmac {
                Ok(algorithm)
            } else {
                Err(Problem::Validation(
                    "JWT HMAC algorithms require explicit permission".into(),
                ))
            }
        }

        // All other algorithms are secure
        _ => Ok(algorithm),
    }
}

// ============================================================================
#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::expect_used, clippy::indexing_slicing)]
    use super::*;
    use proptest::prelude::*;
    use serial_test::serial;

    #[test]
    fn test_adversarial_jwt_none_algorithm() {
        // The "none" algorithm vulnerability (CVE-2015-2951 and related)
        let none_jwt = "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiIxMjM0NTY3ODkwIn0.";

        // Should reject "none" algorithm
        assert!(validate_jwt_algorithm(none_jwt, false).is_err());
        assert!(validate_jwt_algorithm(none_jwt, true).is_err());
    }

    #[test]
    fn test_adversarial_jwt_case_variations() {
        // Trying to bypass "none" check with case variations
        let none_upper = "eyJhbGciOiJOT05FIiwidHlwIjoiSldUIn0.eyJzdWIiOiIxMjM0NTY3ODkwIn0.sig";
        let none_mixed = "eyJhbGciOiJOb25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiIxMjM0NTY3ODkwIn0.sig";

        // All variations should be rejected
        assert!(validate_jwt_algorithm(none_upper, false).is_err());
        assert!(validate_jwt_algorithm(none_mixed, false).is_err());
    }

    #[test]
    fn test_adversarial_jwt_malformed_header() {
        // Invalid base64 in header
        assert!(validate_jwt("invalid!!!.eyJzdWIiOiIxMjM0NTY3ODkwIn0.sig").is_err());

        // Invalid JSON in header (after base64 decode)
        assert!(
            validate_jwt_algorithm("eyJhbGciOg.eyJzdWIiOiIxMjM0NTY3ODkwIn0.sig", false).is_err()
        );

        // Missing parts
        assert!(validate_jwt("onlyonepart").is_err());
        assert!(validate_jwt("only.twoparts").is_err());

        // Too many parts
        assert!(validate_jwt("one.two.three.four").is_err());
    }

    #[test]
    fn test_adversarial_jwt_empty_segments() {
        // Empty header
        assert!(validate_jwt(".eyJzdWIiOiIxMjM0NTY3ODkwIn0.sig").is_err());

        // Empty payload
        assert!(validate_jwt("eyJhbGciOiJIUzI1NiJ9..sig").is_err());

        // Empty signature (might be valid for "none" algorithm, but we reject it)
        assert!(validate_jwt("eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.").is_err());
    }

    #[test]
    fn test_adversarial_jwt_unicode_in_header() {
        // Unicode characters in JWT header (should fail base64 decode)
        assert!(validate_jwt("eyJhbGci🚀.eyJzdWIiOiIxMjM0NTY3ODkwIn0.sig").is_err());

        // Null bytes
        assert!(validate_jwt("eyJhbGci\0.eyJzdWIiOiIxMjM0NTY3ODkwIn0.sig").is_err());

        // Control characters
        assert!(validate_jwt("eyJhbGci\n.eyJzdWIiOiIxMjM0NTY3ODkwIn0.sig").is_err());
    }

    #[test]
    fn test_adversarial_jwt_algorithm_unknown() {
        // Unknown/custom algorithms should be rejected
        let custom_alg = "eyJhbGciOiJDVVNUT00iLCJ0eXAiOiJKV1QifQ.eyJzdWIiOiIxMjM0NTY3ODkwIn0.sig";

        assert!(validate_jwt_algorithm(custom_alg, false).is_err());
    }

    #[test]
    fn test_adversarial_jwt_hmac_confusion() {
        // HMAC algorithms should require explicit permission
        // Use a real JWT token from jwt.io with proper signature length
        let hs256_jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";

        // Rejected by default
        assert!(validate_jwt_algorithm(hs256_jwt, false).is_err());

        // Allowed with permission
        assert!(validate_jwt_algorithm(hs256_jwt, true).is_ok());
    }

    #[test]
    #[serial]
    #[ignore = "perf test - run manually with: cargo test -p octarine test_perf_ -- --ignored"]
    fn test_perf_jwt_format_validation() {
        // JWT format validation should be fast
        let jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";
        let iterations = 5000;
        let start = std::time::Instant::now();

        for _ in 0..iterations {
            let _ = validate_jwt(jwt);
        }

        let duration = start.elapsed();
        let avg_micros = duration.as_micros() / iterations;

        // JWT format validation should be sub-500 microseconds
        // (relaxed from 100µs to account for CI runner variability)
        assert!(avg_micros < 500, "Average: {} µs", avg_micros);
    }

    #[test]
    #[serial]
    #[ignore = "perf test - run manually with: cargo test -p octarine test_perf_ -- --ignored"]
    fn test_perf_jwt_algorithm_validation() {
        // JWT algorithm validation (requires base64 decode + JSON parse)
        let jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";
        let iterations = 5000;
        let start = std::time::Instant::now();

        for _ in 0..iterations {
            let _ = validate_jwt_algorithm(jwt, true);
        }

        let duration = start.elapsed();
        let avg_micros = duration.as_micros() / iterations;

        // Algorithm validation includes decode/parse, should be sub-2000µs
        // (relaxed from 500µs to account for CI runner variability)
        assert!(avg_micros < 2000, "Average: {} µs", avg_micros);
    }

    #[test]
    #[serial]
    #[ignore = "perf test - run manually with: cargo test -p octarine test_perf_ -- --ignored"]
    fn test_perf_batch_jwt_validation() {
        // Batch validation of multiple JWTs
        let jwts = vec![
            "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c",
            "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiI5ODc2NTQzMjEwIn0.signature123",
            "eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiI1NTU1NTU1NTU1In0.signature456",
        ];

        let iterations = 1000;
        let start = std::time::Instant::now();

        for _ in 0..iterations {
            for jwt in &jwts {
                let _ = validate_jwt(jwt);
            }
        }

        let duration = start.elapsed();
        let total_ops = iterations * jwts.len() as u128;
        let avg_micros = duration.as_micros() / total_ops;

        // Batch JWT validation should maintain sub-500µs average
        // (relaxed from 100µs to account for CI runner variability)
        assert!(avg_micros < 500, "Average: {} µs", avg_micros);
    }

    // ===== JWT Algorithm Detection Tests =====

    #[test]
    fn test_detect_jwt_algorithm() {
        // HS256 (uses proper JWT format from jwt.io)
        let hs256_jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";
        assert_eq!(
            detect_jwt_algorithm(hs256_jwt).expect("Valid JWT should have detectable algorithm"),
            JwtAlgorithm::Hs256
        );

        // RS256 (just need valid header, signature format doesn't matter for detection)
        let rs256_jwt = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0.POstGetfAytaZS82wHcjoTyoqhMyxXiWdR7Nn7A29DNSl0EiXLdwJ6xC6AfgZWF1bOsS_TuYI3OG85AmiExREkrS6tDfTQ2B3WXlrr-wp5AokiRbz3_oB4OxG-W9KcEEbDRcZc0nH3L7LzYptiy1PtAylQGxHTWZXtGz4ht0bAecBgmpdgXMguEIcoqPJ1n3pIWk_dUZegpqx0Lka21H6XxUTxiy8OcaarA8zdnPUnV6AmNP3ecFawIFYdvJB_cm-GvpCSbr8G8y_Mllj8f4x9nBH8pQux89_6gUY618iYv7tuPWBFfEbLxtF2pZS6YC1aSfLQxeNe8djT9YjpvRZA";
        assert_eq!(
            detect_jwt_algorithm(rs256_jwt).expect("Valid JWT should have detectable algorithm"),
            JwtAlgorithm::Rs256
        );

        // ES256
        let es256_jwt = "eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.ABCDEFGHIJKLMNOPQRSTUVWXYZEXAMPLE0000000000KEY01abcdefwxyz";
        assert_eq!(
            detect_jwt_algorithm(es256_jwt).expect("Valid JWT should have detectable algorithm"),
            JwtAlgorithm::Es256
        );

        // PS256
        let ps256_jwt = "eyJhbGciOiJQUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.ABCDEFGHIJKLMNOPQRSTUVWXYZEXAMPLE0000000000KEY01abcdefwxyz";
        assert_eq!(
            detect_jwt_algorithm(ps256_jwt).expect("Valid JWT should have detectable algorithm"),
            JwtAlgorithm::Ps256
        );

        // EdDSA
        let eddsa_jwt = "eyJhbGciOiJFZERTQSIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.ABCDEFGHIJKLMNOPQRSTUVWXYZEXAMPLE0000000000KEY01abcdefwxyz";
        assert_eq!(
            detect_jwt_algorithm(eddsa_jwt).expect("Valid JWT should have detectable algorithm"),
            JwtAlgorithm::EdDsa
        );

        // none
        let none_jwt = "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.";
        assert_eq!(
            detect_jwt_algorithm(none_jwt).expect("Valid JWT should have detectable algorithm"),
            JwtAlgorithm::None
        );
    }

    #[test]
    fn test_validate_jwt_algorithm_returns_algorithm() {
        // Valid RS256 token (from jwt.io with proper signature format)
        let rs256_jwt = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0.POstGetfAytaZS82wHcjoTyoqhMyxXiWdR7Nn7A29DNSl0EiXLdwJ6xC6AfgZWF1bOsS_TuYI3OG85AmiExREkrS6tDfTQ2B3WXlrr-wp5AokiRbz3_oB4OxG-W9KcEEbDRcZc0nH3L7LzYptiy1PtAylQGxHTWZXtGz4ht0bAecBgmpdgXMguEIcoqPJ1n3pIWk_dUZegpqx0Lka21H6XxUTxiy8OcaarA8zdnPUnV6AmNP3ecFawIFYdvJB_cm-GvpCSbr8G8y_Mllj8f4x9nBH8pQux89_6gUY618iYv7tuPWBFfEbLxtF2pZS6YC1aSfLQxeNe8djT9YjpvRZA";
        let alg = validate_jwt_algorithm(rs256_jwt, false).expect("should validate");
        assert_eq!(alg, JwtAlgorithm::Rs256);

        // Valid HS256 token (with permission)
        let hs256_jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";
        let alg = validate_jwt_algorithm(hs256_jwt, true).expect("should validate");
        assert_eq!(alg, JwtAlgorithm::Hs256);

        // HS256 should fail without permission
        assert!(validate_jwt_algorithm(hs256_jwt, false).is_err());

        // none should always fail (note: "none" alg tokens typically have empty signature)
        let none_jwt = "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.";
        assert!(validate_jwt_algorithm(none_jwt, false).is_err());
        assert!(validate_jwt_algorithm(none_jwt, true).is_err());
    }

    #[test]
    fn test_jwt_algorithm_display() {
        assert_eq!(JwtAlgorithm::Hs256.to_string(), "HS256 (HMAC-SHA256)");
        assert_eq!(JwtAlgorithm::Rs256.to_string(), "RS256 (RSA-SHA256)");
        assert_eq!(JwtAlgorithm::Es256.to_string(), "ES256 (ECDSA-SHA256)");
        assert_eq!(JwtAlgorithm::Ps256.to_string(), "PS256 (RSA-PSS-SHA256)");
        assert_eq!(JwtAlgorithm::EdDsa.to_string(), "EdDSA (Edwards-curve)");
        assert_eq!(JwtAlgorithm::None.to_string(), "none (INSECURE)");
    }

    #[test]
    fn test_jwt_algorithm_helpers() {
        // Symmetric checks
        assert!(JwtAlgorithm::Hs256.is_symmetric());
        assert!(JwtAlgorithm::Hs384.is_symmetric());
        assert!(JwtAlgorithm::Hs512.is_symmetric());
        assert!(!JwtAlgorithm::Rs256.is_symmetric());
        assert!(!JwtAlgorithm::None.is_symmetric());

        // Asymmetric checks
        assert!(JwtAlgorithm::Rs256.is_asymmetric());
        assert!(JwtAlgorithm::Es256.is_asymmetric());
        assert!(JwtAlgorithm::Ps256.is_asymmetric());
        assert!(JwtAlgorithm::EdDsa.is_asymmetric());
        assert!(!JwtAlgorithm::Hs256.is_asymmetric());
        assert!(!JwtAlgorithm::None.is_asymmetric());

        // Secure checks
        assert!(JwtAlgorithm::Hs256.is_secure());
        assert!(JwtAlgorithm::Rs256.is_secure());
        assert!(JwtAlgorithm::Es256.is_secure());
        assert!(!JwtAlgorithm::None.is_secure());
    }

    #[test]
    fn test_jwt_algorithm_all_variants() {
        // Test all HMAC variants (use valid base64url for signature part)
        let hs384_jwt = "eyJhbGciOiJIUzM4NCIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.ABCDEFGHIJKLMNOPQRSTUVWXYZEXAMPLE0000000000KEY01abcdefwxyz";
        assert_eq!(
            detect_jwt_algorithm(hs384_jwt).expect("Valid JWT should have detectable algorithm"),
            JwtAlgorithm::Hs384
        );

        let hs512_jwt = "eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.ABCDEFGHIJKLMNOPQRSTUVWXYZEXAMPLE0000000000KEY01abcdefwxyz";
        assert_eq!(
            detect_jwt_algorithm(hs512_jwt).expect("Valid JWT should have detectable algorithm"),
            JwtAlgorithm::Hs512
        );

        // Test all RSA variants
        let rs384_jwt = "eyJhbGciOiJSUzM4NCIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.ABCDEFGHIJKLMNOPQRSTUVWXYZEXAMPLE0000000000KEY01abcdefwxyz";
        assert_eq!(
            detect_jwt_algorithm(rs384_jwt).expect("Valid JWT should have detectable algorithm"),
            JwtAlgorithm::Rs384
        );

        let rs512_jwt = "eyJhbGciOiJSUzUxMiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.ABCDEFGHIJKLMNOPQRSTUVWXYZEXAMPLE0000000000KEY01abcdefwxyz";
        assert_eq!(
            detect_jwt_algorithm(rs512_jwt).expect("Valid JWT should have detectable algorithm"),
            JwtAlgorithm::Rs512
        );

        // Test all ECDSA variants
        let es384_jwt = "eyJhbGciOiJFUzM4NCIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.ABCDEFGHIJKLMNOPQRSTUVWXYZEXAMPLE0000000000KEY01abcdefwxyz";
        assert_eq!(
            detect_jwt_algorithm(es384_jwt).expect("Valid JWT should have detectable algorithm"),
            JwtAlgorithm::Es384
        );

        let es512_jwt = "eyJhbGciOiJFUzUxMiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.ABCDEFGHIJKLMNOPQRSTUVWXYZEXAMPLE0000000000KEY01abcdefwxyz";
        assert_eq!(
            detect_jwt_algorithm(es512_jwt).expect("Valid JWT should have detectable algorithm"),
            JwtAlgorithm::Es512
        );

        // Test all PSS variants
        let ps384_jwt = "eyJhbGciOiJQUzM4NCIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.ABCDEFGHIJKLMNOPQRSTUVWXYZEXAMPLE0000000000KEY01abcdefwxyz";
        assert_eq!(
            detect_jwt_algorithm(ps384_jwt).expect("Valid JWT should have detectable algorithm"),
            JwtAlgorithm::Ps384
        );

        let ps512_jwt = "eyJhbGciOiJQUzUxMiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.ABCDEFGHIJKLMNOPQRSTUVWXYZEXAMPLE0000000000KEY01abcdefwxyz";
        assert_eq!(
            detect_jwt_algorithm(ps512_jwt).expect("Valid JWT should have detectable algorithm"),
            JwtAlgorithm::Ps512
        );
    }

    proptest! {

        #[test]
        fn prop_no_panic_jwt_validation(s in "\\PC*") {
                let _ = validate_jwt(&s);
                let _ = validate_jwt_algorithm(&s, false);
                let _ = validate_jwt_algorithm(&s, true);
                let _ = detect_jwt_algorithm(&s);
            }

        #[test]
        fn prop_jwt_three_parts(s in "[A-Za-z0-9_-]{25,50}\\.[A-Za-z0-9_-]{25,50}\\.[A-Za-z0-9_-]{25,50}") {
                // Strings with two dots and base64url chars of sufficient length should pass format check
                // The pattern ensures each part is 25-50 chars, well above the 20 char minimum
                assert!(validate_jwt(&s).is_ok(), "Valid JWT format not recognized: {}", s);
            }

    }
}
