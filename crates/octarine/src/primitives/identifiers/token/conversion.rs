//! Token identifier format conversion (primitives layer)
//!
//! Pure conversion functions for extracting metadata from tokens.
//!
//! # Operations
//!
//! - **JWT Metadata Extraction**: Parse header to extract algorithm, type, and keys
//!
//! # Security Considerations
//!
//! **IMPORTANT: This module ONLY parses JWT headers (publicly visible metadata).**
//!
//! - **NO payload decoding** - Contains user claims and PII
//! - **NO signature validation** - Not our responsibility
//! - **NO secret extraction** - Headers are safe, payloads are not
//!
//! The JWT header is base64url-encoded but NOT encrypted. It contains only
//! algorithm and type information, which is safe to extract for logging,
//! metrics, and debugging purposes.
//!
//! # Architecture
//!
//! This is part of **Layer 1 (primitives)** - pure functions with NO logging.
//! - No observe:: dependencies
//! - Returns data, no side effects
//! - Used by observe/pii and security modules

use super::detection::{self, JwtAlgorithm};
use crate::primitives::Problem;
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;

// ============================================================================
// JWT Metadata Types
// ============================================================================

/// JWT header metadata (safe to extract - publicly visible)
///
/// Contains only the algorithm and type information from the JWT header.
/// Does NOT include payload claims or signature data.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JwtMetadata {
    /// Signing algorithm (e.g., RS256, HS256)
    pub algorithm: JwtAlgorithm,
    /// Token type (usually "JWT")
    pub token_type: Option<String>,
    /// All header field names (for debugging)
    pub header_keys: Vec<String>,
}

impl JwtMetadata {
    /// Check if the JWT uses a secure algorithm
    #[must_use]
    pub fn is_secure(&self) -> bool {
        self.algorithm.is_secure()
    }

    /// Check if the JWT uses symmetric (HMAC) signing
    #[must_use]
    pub fn is_symmetric(&self) -> bool {
        self.algorithm.is_symmetric()
    }

    /// Check if the JWT uses asymmetric (RSA/ECDSA) signing
    #[must_use]
    pub fn is_asymmetric(&self) -> bool {
        self.algorithm.is_asymmetric()
    }
}

// ============================================================================
// JWT Header Parsing
// ============================================================================

/// Extract metadata from JWT header (safe - header is publicly visible)
///
/// Parses the base64url-encoded JWT header to extract algorithm and type.
/// Does NOT decode or access the payload (which may contain PII).
///
/// # Security
///
/// This function ONLY accesses the JWT header, which is:
/// - Publicly visible (not encrypted)
/// - Contains no user data
/// - Safe to log and analyze
///
/// # Examples
///
/// ```ignore
/// use octarine::primitives::identifiers::token::conversion;
///
/// let jwt = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.payload.signature";
/// let metadata = conversion::extract_jwt_metadata(jwt)?;
///
/// assert_eq!(metadata.algorithm, JwtAlgorithm::Rs256);
/// assert_eq!(metadata.token_type, Some("JWT".to_string()));
/// ```
pub fn extract_jwt_metadata(token: &str) -> Result<JwtMetadata, Problem> {
    let token = token.trim();

    // Use detection layer first to validate JWT format
    if !detection::is_jwt(token) {
        return Err(Problem::Conversion("Invalid JWT format".into()));
    }

    // Extract header (first part before first dot)
    let header_b64 = token
        .split('.')
        .next()
        .ok_or_else(|| Problem::Conversion("JWT header missing".into()))?;

    // Decode base64url header
    let header_bytes = URL_SAFE_NO_PAD
        .decode(header_b64)
        .map_err(|_| Problem::Conversion("Invalid base64url encoding in JWT header".into()))?;

    // Parse JSON header
    let header_json: serde_json::Value = serde_json::from_slice(&header_bytes)
        .map_err(|_| Problem::Conversion("Invalid JSON in JWT header".into()))?;

    // Extract algorithm (required)
    let algorithm = detection::detect_jwt_algorithm(token)
        .map_err(|e| Problem::Conversion(format!("Failed to detect JWT algorithm: {}", e)))?;

    // Extract token type (optional, usually "JWT")
    let token_type = header_json
        .get("typ")
        .and_then(|v| v.as_str())
        .map(String::from);

    // Extract all header keys for debugging
    let header_keys = header_json
        .as_object()
        .map(|obj| obj.keys().cloned().collect())
        .unwrap_or_default();

    Ok(JwtMetadata {
        algorithm,
        token_type,
        header_keys,
    })
}

/// Parse JWT header and return the raw JSON object
///
/// Returns the decoded header as a JSON value for inspection.
/// Useful for debugging or examining non-standard header fields.
///
/// # Security
///
/// This function ONLY accesses the JWT header (publicly visible, no secrets).
///
/// # Examples
///
/// ```ignore
/// use octarine::primitives::identifiers::token::conversion;
///
/// let jwt = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.payload.signature";
/// let header = conversion::parse_jwt_header(jwt)?;
///
/// assert_eq!(header["alg"], "RS256");
/// ```
pub fn parse_jwt_header(token: &str) -> Result<serde_json::Value, Problem> {
    let token = token.trim();

    // Use detection layer first to validate JWT format
    if !detection::is_jwt(token) {
        return Err(Problem::Conversion("Invalid JWT format".into()));
    }

    // Extract header (first part before first dot)
    let header_b64 = token
        .split('.')
        .next()
        .ok_or_else(|| Problem::Conversion("JWT header missing".into()))?;

    // Decode base64url header
    let header_bytes = URL_SAFE_NO_PAD
        .decode(header_b64)
        .map_err(|_| Problem::Conversion("Invalid base64url encoding in JWT header".into()))?;

    // Parse and return JSON header
    serde_json::from_slice(&header_bytes)
        .map_err(|_| Problem::Conversion("Invalid JSON in JWT header".into()))
}

/// Extract the algorithm string from a JWT
///
/// Convenience function that returns just the algorithm name as a string.
///
/// # Examples
///
/// ```ignore
/// use octarine::primitives::identifiers::token::conversion;
///
/// let jwt = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.payload.signature";
/// let alg = conversion::extract_jwt_algorithm(jwt)?;
///
/// assert_eq!(alg, "RS256");
/// ```
pub fn extract_jwt_algorithm(token: &str) -> Result<String, Problem> {
    let header = parse_jwt_header(token)?;

    header
        .get("alg")
        .and_then(|v| v.as_str())
        .map(String::from)
        .ok_or_else(|| Problem::Conversion("JWT header missing 'alg' field".into()))
}

/// Extract the token type from a JWT
///
/// Returns the "typ" field from the JWT header, if present.
/// This is usually "JWT" but can be other values like "at+jwt" for access tokens.
///
/// # Examples
///
/// ```ignore
/// use octarine::primitives::identifiers::token::conversion;
///
/// let jwt = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.payload.signature";
/// let typ = conversion::extract_jwt_type(jwt)?;
///
/// assert_eq!(typ, Some("JWT".to_string()));
/// ```
pub fn extract_jwt_type(token: &str) -> Result<Option<String>, Problem> {
    let header = parse_jwt_header(token)?;

    Ok(header.get("typ").and_then(|v| v.as_str()).map(String::from))
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::expect_used)]
    use super::*;

    // Test JWT from jwt.io (HS256)
    const TEST_JWT_HS256: &str = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";

    // Test JWT with RS256 algorithm
    const TEST_JWT_RS256: &str = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0.POstGetfAytaZS82wHcjoTyoqhMyxXiWdR7Nn7A29DNSl0EiXLdwJ6xC6AfgZWF1bOsS_TuYI3OG85AmiExREkrS6tDfTQ2B3WXlrr-wp5AokiRbz3_oB4OxG-W9KcEEbDRcZc0nH3L7LzYptiy1PtAylQGxHTWZXtGz4ht0bAecBgmpdgXMguEIcoqPJ1n3pIWk_dUZegpqx0Lka21H6XxUTxiy8OcaarA8zdnPUnV6AmNP3ecFawIFYdvJB_cm-GvpCSbr8G8y_Mllj8f4x9nBH8pQux89_6gUY618iYv7tuPWBFfEbLxtF2pZS6YC1aSfLQxeNe8djT9YjpvRZA";

    // Test JWT with ES256 algorithm (no typ field)
    // Header: {"alg":"ES256"}, Payload: {"sub":"1234567890"}, Signature: valid base64url
    const TEST_JWT_ES256_NO_TYP: &str = "eyJhbGciOiJFUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";

    // ===== Metadata Extraction Tests =====

    #[test]
    fn test_extract_jwt_metadata_hs256() {
        let metadata = extract_jwt_metadata(TEST_JWT_HS256).expect("should parse HS256 JWT");

        assert_eq!(metadata.algorithm, JwtAlgorithm::Hs256);
        assert_eq!(metadata.token_type, Some("JWT".to_string()));
        assert!(metadata.header_keys.contains(&"alg".to_string()));
        assert!(metadata.header_keys.contains(&"typ".to_string()));
    }

    #[test]
    fn test_extract_jwt_metadata_rs256() {
        let metadata = extract_jwt_metadata(TEST_JWT_RS256).expect("should parse RS256 JWT");

        assert_eq!(metadata.algorithm, JwtAlgorithm::Rs256);
        assert_eq!(metadata.token_type, Some("JWT".to_string()));
        assert!(metadata.is_secure());
        assert!(metadata.is_asymmetric());
        assert!(!metadata.is_symmetric());
    }

    #[test]
    fn test_extract_jwt_metadata_no_typ() {
        let metadata =
            extract_jwt_metadata(TEST_JWT_ES256_NO_TYP).expect("should parse JWT without typ");

        assert_eq!(metadata.algorithm, JwtAlgorithm::Es256);
        assert_eq!(metadata.token_type, None);
        assert!(metadata.header_keys.contains(&"alg".to_string()));
        assert!(!metadata.header_keys.contains(&"typ".to_string()));
    }

    #[test]
    fn test_extract_jwt_metadata_invalid() {
        // Not a JWT
        let err = extract_jwt_metadata("not-a-jwt").expect_err("should fail for non-JWT");
        assert!(err.to_string().contains("Invalid JWT"));

        // Empty string
        let err = extract_jwt_metadata("").expect_err("should fail for empty");
        assert!(err.to_string().contains("Invalid JWT"));
    }

    // ===== Header Parsing Tests =====

    #[test]
    fn test_parse_jwt_header() {
        let header = parse_jwt_header(TEST_JWT_HS256).expect("should parse header");

        assert_eq!(header.get("alg").and_then(|v| v.as_str()), Some("HS256"));
        assert_eq!(header.get("typ").and_then(|v| v.as_str()), Some("JWT"));
    }

    #[test]
    fn test_parse_jwt_header_invalid() {
        let err = parse_jwt_header("invalid").expect_err("should fail for invalid");
        assert!(err.to_string().contains("Invalid JWT"));
    }

    // ===== Algorithm Extraction Tests =====

    #[test]
    fn test_extract_jwt_algorithm() {
        assert_eq!(
            extract_jwt_algorithm(TEST_JWT_HS256).expect("should extract alg"),
            "HS256"
        );
        assert_eq!(
            extract_jwt_algorithm(TEST_JWT_RS256).expect("should extract alg"),
            "RS256"
        );
    }

    #[test]
    fn test_extract_jwt_algorithm_invalid() {
        let err = extract_jwt_algorithm("not-a-jwt").expect_err("should fail");
        assert!(err.to_string().contains("Invalid JWT"));
    }

    // ===== Type Extraction Tests =====

    #[test]
    fn test_extract_jwt_type() {
        assert_eq!(
            extract_jwt_type(TEST_JWT_HS256).expect("should extract type"),
            Some("JWT".to_string())
        );

        // JWT without typ field
        assert_eq!(
            extract_jwt_type(TEST_JWT_ES256_NO_TYP).expect("should handle missing typ"),
            None
        );
    }

    // ===== Metadata Helper Tests =====

    #[test]
    fn test_jwt_metadata_helpers() {
        let metadata = extract_jwt_metadata(TEST_JWT_HS256).expect("should parse");

        // HS256 is symmetric
        assert!(metadata.is_symmetric());
        assert!(!metadata.is_asymmetric());
        assert!(metadata.is_secure());

        let metadata = extract_jwt_metadata(TEST_JWT_RS256).expect("should parse");

        // RS256 is asymmetric
        assert!(!metadata.is_symmetric());
        assert!(metadata.is_asymmetric());
        assert!(metadata.is_secure());
    }

    // ===== Edge Case Tests =====

    #[test]
    fn test_whitespace_handling() {
        // JWT with leading/trailing whitespace
        let jwt_with_spaces = format!("  {}  ", TEST_JWT_HS256);
        // Detection layer handles trimming
        let metadata = extract_jwt_metadata(&jwt_with_spaces).expect("should handle whitespace");
        assert_eq!(metadata.algorithm, JwtAlgorithm::Hs256);
    }
}
