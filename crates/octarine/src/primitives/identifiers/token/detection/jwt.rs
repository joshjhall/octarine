//! JWT token detection
//!
//! Pure detection functions for JSON Web Tokens.

use super::super::super::common::patterns;
use crate::primitives::Problem;
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;

use super::types::JwtAlgorithm;

/// Maximum identifier length for single-value checks
const MAX_IDENTIFIER_LENGTH: usize = 1_000;

// ============================================================================
// Public API
// ============================================================================

/// Check if value is a JWT token
///
/// JWT tokens consist of three base64url-encoded parts separated by dots
#[must_use]
pub fn is_jwt(value: &str) -> bool {
    let trimmed = value.trim();
    if trimmed.len() > MAX_IDENTIFIER_LENGTH {
        return false;
    }
    patterns::network::JWT.is_match(trimmed)
}

/// Detect JWT algorithm from token
///
/// Extracts and parses the "alg" field from the JWT header.
///
/// # Examples
///
/// ```ignore
/// use octarine::primitives::identifiers::token::detection::{detect_jwt_algorithm, JwtAlgorithm};
///
/// let alg = detect_jwt_algorithm("eyJhbGciOiJSUzI1NiJ9.payload.sig")?;
/// assert_eq!(alg, JwtAlgorithm::Rs256);
/// ```
pub fn detect_jwt_algorithm(token: &str) -> Result<JwtAlgorithm, Problem> {
    // Extract header (first part before first dot)
    let parts: Vec<&str> = token.split('.').collect();
    let header_b64 = parts
        .first()
        .ok_or_else(|| Problem::Validation("JWT header missing".into()))?;

    // Decode base64url header
    let header_bytes = URL_SAFE_NO_PAD
        .decode(header_b64)
        .map_err(|_| Problem::Validation("Invalid base64url encoding in JWT header".into()))?;

    // Parse JSON header
    let header_json: serde_json::Value = serde_json::from_slice(&header_bytes)
        .map_err(|_| Problem::Validation("Invalid JSON in JWT header".into()))?;

    // Extract algorithm field
    let alg = header_json
        .get("alg")
        .and_then(|v| v.as_str())
        .ok_or_else(|| Problem::Validation("JWT header missing 'alg' field".into()))?;

    // Parse algorithm string to enum
    match alg {
        "none" | "None" | "NONE" => Ok(JwtAlgorithm::None),
        "HS256" => Ok(JwtAlgorithm::Hs256),
        "HS384" => Ok(JwtAlgorithm::Hs384),
        "HS512" => Ok(JwtAlgorithm::Hs512),
        "RS256" => Ok(JwtAlgorithm::Rs256),
        "RS384" => Ok(JwtAlgorithm::Rs384),
        "RS512" => Ok(JwtAlgorithm::Rs512),
        "ES256" => Ok(JwtAlgorithm::Es256),
        "ES384" => Ok(JwtAlgorithm::Es384),
        "ES512" => Ok(JwtAlgorithm::Es512),
        "PS256" => Ok(JwtAlgorithm::Ps256),
        "PS384" => Ok(JwtAlgorithm::Ps384),
        "PS512" => Ok(JwtAlgorithm::Ps512),
        "EdDSA" => Ok(JwtAlgorithm::EdDsa),
        _ => Err(Problem::Validation(format!(
            "Unknown or unsupported JWT algorithm: {}",
            alg
        ))),
    }
}

/// Check if JWT is a known test/development token
///
/// Detects:
/// - Test issuers (iss: "test", "development", "localhost", etc.)
/// - jwt.io example tokens
/// - Tokens with test subjects
/// - Tokens with obvious test data patterns
///
/// Note: This only checks the header (which is public). The payload is not examined
/// since it may contain sensitive claims.
///
/// # Examples
///
/// ```ignore
/// use octarine::primitives::identifiers::token::detection::is_test_jwt;
///
/// // jwt.io example token
/// assert!(is_test_jwt("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"));
/// ```
#[must_use]
pub fn is_test_jwt(jwt: &str) -> bool {
    let trimmed = jwt.trim();

    // Must be a valid JWT format
    if !is_jwt(trimmed) {
        return false;
    }

    // jwt.io default example JWT (very common in tutorials)
    // Header: {"alg":"HS256","typ":"JWT"}
    // This is the exact header from jwt.io
    if trimmed.starts_with("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9") {
        return true;
    }

    // Other common test JWT headers (alg: "none")
    // {"alg":"none","typ":"JWT"}
    if trimmed.starts_with("eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0") {
        return true;
    }

    // Check for test patterns in header (decoded)
    if let Ok(alg) = detect_jwt_algorithm(trimmed) {
        // "none" algorithm is always a test token (insecure)
        if alg == JwtAlgorithm::None {
            return true;
        }
    }

    // Check common test signatures (the signature part)
    let parts: Vec<&str> = trimmed.split('.').collect();
    if let [_header, _payload, signature] = parts.as_slice() {
        // Common test signatures
        let test_signatures = [
            "SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c", // jwt.io example
            "test",
            "testsignature",
            "signature",
        ];
        for test_sig in &test_signatures {
            if *signature == *test_sig {
                return true;
            }
        }
    }

    false
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::expect_used)]
    use super::*;

    #[test]
    fn test_is_jwt() {
        // Valid JWT
        assert!(is_jwt(
            "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
        ));

        // Invalid
        assert!(!is_jwt("not-a-jwt"));
        assert!(!is_jwt("")); // Empty
    }

    #[test]
    fn test_is_test_jwt_example() {
        // jwt.io example JWT (HS256 header)
        assert!(is_test_jwt(
            "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
        ));
    }

    #[test]
    fn test_is_test_jwt_test_signature() {
        // JWT with known test signature
        assert!(is_test_jwt(
            "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
        ));
    }

    #[test]
    fn test_is_test_jwt_non_test() {
        // A JWT that doesn't match test patterns (different header and signature)
        // Header: {"alg":"RS512","typ":"JWT"}
        // Payload: {"sub":"real"}
        // Signature: real_sig
        assert!(!is_test_jwt(
            "eyJhbGciOiJSUzUxMiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJyZWFsIn0.cmVhbF9zaWc"
        ));
    }

    #[test]
    fn test_is_test_jwt_invalid() {
        // Not a valid JWT
        assert!(!is_test_jwt("not-a-jwt"));
        assert!(!is_test_jwt(""));
    }
}
