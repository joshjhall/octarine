//! PEM format parsing
//!
//! Pure functions for parsing PEM-encoded cryptographic data.
//! Uses the `pem` crate for robust parsing.

use crate::primitives::types::Problem;

use super::types::ParsedPem;

/// Maximum PEM data size for ReDoS protection (1 MB)
const MAX_PEM_SIZE: usize = 1_048_576;

/// Parse a single PEM block from a string
///
/// # Arguments
/// * `data` - PEM-encoded string data
///
/// # Returns
/// Parsed PEM block or error if parsing fails
///
/// # Errors
/// Returns an error if:
/// - Input is too large (>1 MB)
/// - Input is not valid PEM
/// - Base64 decoding fails
pub fn parse_pem(data: &str) -> Result<ParsedPem, Problem> {
    if data.len() > MAX_PEM_SIZE {
        return Err(Problem::validation("PEM data exceeds maximum allowed size"));
    }

    #[cfg(feature = "crypto-validation")]
    {
        let parsed =
            pem::parse(data).map_err(|e| Problem::validation(format!("Invalid PEM: {e}")))?;

        Ok(ParsedPem {
            label: parsed.tag().to_string(),
            data: parsed.contents().to_vec(),
            headers: Vec::new(), // Basic pem crate doesn't preserve headers
        })
    }

    #[cfg(not(feature = "crypto-validation"))]
    {
        let _ = data;
        Err(Problem::validation("crypto-validation feature not enabled"))
    }
}

/// Parse all PEM blocks from a string
///
/// # Arguments
/// * `data` - PEM-encoded string data (may contain multiple blocks)
///
/// # Returns
/// Vector of parsed PEM blocks
///
/// # Errors
/// Returns an error if:
/// - Input is too large (>1 MB)
/// - Any PEM block fails to parse
pub fn parse_pem_many(data: &str) -> Result<Vec<ParsedPem>, Problem> {
    if data.len() > MAX_PEM_SIZE {
        return Err(Problem::validation("PEM data exceeds maximum allowed size"));
    }

    #[cfg(feature = "crypto-validation")]
    {
        let parsed =
            pem::parse_many(data).map_err(|e| Problem::validation(format!("Invalid PEM: {e}")))?;

        Ok(parsed
            .into_iter()
            .map(|p| ParsedPem {
                label: p.tag().to_string(),
                data: p.contents().to_vec(),
                headers: Vec::new(),
            })
            .collect())
    }

    #[cfg(not(feature = "crypto-validation"))]
    {
        let _ = data;
        Err(Problem::validation("crypto-validation feature not enabled"))
    }
}

/// Validate that a string is valid PEM format
///
/// # Arguments
/// * `data` - String to validate
///
/// # Returns
/// `Ok(())` if valid PEM, error otherwise
pub fn validate_pem_format(data: &str) -> Result<(), Problem> {
    if data.len() > MAX_PEM_SIZE {
        return Err(Problem::validation("PEM data exceeds maximum allowed size"));
    }

    #[cfg(feature = "crypto-validation")]
    {
        pem::parse(data).map_err(|e| Problem::validation(format!("Invalid PEM: {e}")))?;
        Ok(())
    }

    #[cfg(not(feature = "crypto-validation"))]
    {
        let _ = data;
        Err(Problem::validation("crypto-validation feature not enabled"))
    }
}

/// Normalize PEM formatting
///
/// Ensures consistent line endings and wrapping.
///
/// # Arguments
/// * `data` - PEM-encoded string
///
/// # Returns
/// Normalized PEM string with consistent formatting
pub fn normalize_pem(data: &str) -> Result<String, Problem> {
    if data.len() > MAX_PEM_SIZE {
        return Err(Problem::validation("PEM data exceeds maximum allowed size"));
    }

    #[cfg(feature = "crypto-validation")]
    {
        let parsed =
            pem::parse(data).map_err(|e| Problem::validation(format!("Invalid PEM: {e}")))?;

        // Re-encode with consistent formatting
        Ok(pem::encode(&parsed))
    }

    #[cfg(not(feature = "crypto-validation"))]
    {
        let _ = data;
        Err(Problem::validation("crypto-validation feature not enabled"))
    }
}

/// Encode data as PEM
///
/// # Arguments
/// * `label` - PEM label (e.g., "RSA PUBLIC KEY")
/// * `data` - Binary data to encode
///
/// # Returns
/// PEM-encoded string
#[cfg(feature = "crypto-validation")]
pub fn encode_pem(label: &str, data: &[u8]) -> String {
    let pem_block = pem::Pem::new(label, data);
    pem::encode(&pem_block)
}

#[cfg(not(feature = "crypto-validation"))]
pub fn encode_pem(_label: &str, _data: &[u8]) -> String {
    String::new()
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::expect_used)]
    use super::*;

    // Valid base64 of "FAKE_TEST_DATA_NOT_REAL" - obviously not real key material
    const SAMPLE_PEM: &str = r#"-----BEGIN RSA PUBLIC KEY-----
RkFLRV9URVNUX0RBVEFfTk9UX1JFQUw=
-----END RSA PUBLIC KEY-----"#;

    #[test]
    #[cfg(feature = "crypto-validation")]
    fn test_parse_pem() {
        let result = parse_pem(SAMPLE_PEM);
        assert!(result.is_ok());
        let parsed = result.expect("parse should succeed");
        assert_eq!(parsed.label, "RSA PUBLIC KEY");
        assert!(!parsed.data.is_empty());
    }

    #[test]
    #[cfg(feature = "crypto-validation")]
    fn test_parse_pem_invalid() {
        let result = parse_pem("not valid pem");
        assert!(result.is_err());
    }

    #[test]
    #[cfg(feature = "crypto-validation")]
    fn test_validate_pem_format() {
        assert!(validate_pem_format(SAMPLE_PEM).is_ok());
        assert!(validate_pem_format("invalid").is_err());
    }

    #[test]
    fn test_size_limit() {
        let huge = "x".repeat(MAX_PEM_SIZE + 1);
        assert!(parse_pem(&huge).is_err());
    }

    #[test]
    #[cfg(feature = "crypto-validation")]
    fn test_encode_pem() {
        let encoded = encode_pem("TEST", &[1, 2, 3, 4]);
        assert!(encoded.contains("-----BEGIN TEST-----"));
        assert!(encoded.contains("-----END TEST-----"));
    }
}
