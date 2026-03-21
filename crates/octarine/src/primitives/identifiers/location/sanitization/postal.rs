//! Postal code sanitization
//!
//! Redacts and masks postal codes with domain-specific redaction strategies.

use super::super::conversion;
use super::super::detection;
use super::super::redaction::PostalCodeRedactionStrategy;
use crate::primitives::Problem;
use crate::primitives::data::tokens::RedactionTokenCore;

// ============================================================================
// Postal Code Redaction
// ============================================================================

/// Redact postal code with explicit strategy
///
/// Provides type-safe postal code redaction with regional anonymization options
/// following HIPAA Safe Harbor guidelines.
///
/// # Arguments
///
/// * `code` - Postal code to redact
/// * `strategy` - Postal code-specific redaction strategy
///
/// # Returns
///
/// Redacted postal code according to strategy:
/// - **None**: Returns code as-is (dev/qa only)
/// - **ShowPrefix**: `"100**"` (first 3 digits, state-level, HIPAA compliant)
/// - **ShowRegion**: `"1****"` (first digit, USPS region)
/// - **Token**: `"[POSTAL_CODE]"`
/// - **Anonymous**: `"[REDACTED]"`
/// - **Asterisks**: `"*****"` (length-preserving)
/// - **Hashes**: `"#####"` (length-preserving)
///
/// # Security
///
/// Invalid postal codes return `[POSTAL_CODE]` token to avoid leaking partial information.
///
/// # Examples
///
/// ```ignore
/// use crate::primitives::identifiers::location::sanitization::*;
/// use crate::primitives::identifiers::location::redaction::PostalCodeRedactionStrategy;
///
/// let zip = "10001";
///
/// // State-level prefix (HIPAA Safe Harbor compliant)
/// assert_eq!(
///     redact_postal_code_with_strategy(zip, PostalCodeRedactionStrategy::ShowPrefix),
///     "100**"
/// );
///
/// // Regional prefix (USPS region)
/// assert_eq!(
///     redact_postal_code_with_strategy(zip, PostalCodeRedactionStrategy::ShowRegion),
///     "1****"
/// );
///
/// // Complete token redaction (recommended default)
/// assert_eq!(
///     redact_postal_code_with_strategy(zip, PostalCodeRedactionStrategy::Token),
///     "[POSTAL_CODE]"
/// );
/// ```
#[must_use]
pub fn redact_postal_code_with_strategy(
    code: &str,
    strategy: PostalCodeRedactionStrategy,
) -> String {
    // No redaction - return as-is (dev/qa only)
    if matches!(strategy, PostalCodeRedactionStrategy::Skip) {
        return code.to_string();
    }

    // Validate format first
    if !detection::is_postal_code(code) {
        return RedactionTokenCore::PostalCode.into();
    }

    let trimmed = code.trim();

    match strategy {
        PostalCodeRedactionStrategy::Skip => code.to_string(),

        PostalCodeRedactionStrategy::ShowPrefix => {
            // Show first 3 digits (US ZIP-3 level, HIPAA compliant)
            let digits: Vec<char> = trimmed.chars().filter(|c| c.is_ascii_digit()).collect();
            if digits.len() >= 5 {
                // US ZIP or ZIP+4
                let prefix: String = digits.iter().take(3).collect();
                format!("{}**", prefix)
            } else {
                RedactionTokenCore::PostalCode.into()
            }
        }

        PostalCodeRedactionStrategy::ShowRegion => {
            // Show first digit (USPS region)
            let digits: Vec<char> = trimmed.chars().filter(|c| c.is_ascii_digit()).collect();
            if digits.len() >= 5 {
                let region: String = digits.iter().take(1).collect();
                format!("{}****", region)
            } else {
                RedactionTokenCore::PostalCode.into()
            }
        }

        PostalCodeRedactionStrategy::Token => RedactionTokenCore::PostalCode.into(),
        PostalCodeRedactionStrategy::Anonymous => RedactionTokenCore::Redacted.into(),
        PostalCodeRedactionStrategy::Asterisks => "*".repeat(code.len()),
        PostalCodeRedactionStrategy::Hashes => "#".repeat(code.len()),
    }
}

/// Sanitize postal code strict (normalize format + validate)
///
/// Normalizes postal code to standard format and validates format.
/// Returns normalized postal code if valid, error otherwise.
///
/// # Examples
///
/// ```ignore
/// use crate::primitives::identifiers::location::sanitization;
///
/// // Normalize US ZIP+4
/// let sanitized = sanitization::sanitize_postal_code_strict("10001-1234")?;
/// assert_eq!(sanitized, "10001-1234");
///
/// // Normalize spacing
/// let sanitized = sanitization::sanitize_postal_code_strict("  10001  ")?;
/// assert_eq!(sanitized, "10001");
///
/// // Invalid postal code
/// assert!(sanitization::sanitize_postal_code_strict("invalid").is_err());
/// ```
pub fn sanitize_postal_code_strict(code: &str) -> Result<String, Problem> {
    // Normalize format (standardize spacing, formatting)
    let normalized =
        conversion::normalize_postal_code(code, conversion::PostalCodeNormalization::Preserve)?;

    // Validation happens inside normalize_postal_code via detect_postal_code_type

    Ok(normalized)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::expect_used, clippy::unwrap_used)]
    use super::*;

    #[test]
    fn test_redact_postal_code_with_strategy_token() {
        assert_eq!(
            redact_postal_code_with_strategy("10001", PostalCodeRedactionStrategy::Token),
            "[POSTAL_CODE]"
        );
    }

    #[test]
    fn test_redact_postal_code_with_strategy_show_prefix() {
        assert_eq!(
            redact_postal_code_with_strategy("10001", PostalCodeRedactionStrategy::ShowPrefix),
            "100**"
        );
        assert_eq!(
            redact_postal_code_with_strategy("90210-1234", PostalCodeRedactionStrategy::ShowPrefix),
            "902**"
        );
    }

    #[test]
    fn test_redact_postal_code_with_strategy_show_region() {
        assert_eq!(
            redact_postal_code_with_strategy("10001", PostalCodeRedactionStrategy::ShowRegion),
            "1****"
        );
    }

    #[test]
    fn test_redact_postal_code_with_strategy_show_prefix_variations() {
        // Show prefix with explicit strategy for HIPAA-compliant anonymization
        assert_eq!(
            redact_postal_code_with_strategy("10001", PostalCodeRedactionStrategy::ShowPrefix),
            "100**"
        );
        assert_eq!(
            redact_postal_code_with_strategy("90210", PostalCodeRedactionStrategy::ShowPrefix),
            "902**"
        );
        // Invalid postal codes return token
        assert_eq!(
            redact_postal_code_with_strategy("invalid", PostalCodeRedactionStrategy::ShowPrefix),
            "[POSTAL_CODE]"
        );
    }

    #[test]
    fn test_sanitize_postal_code_strict() {
        // Valid US ZIP
        let result = sanitize_postal_code_strict("10001");
        assert!(result.is_ok());

        // Valid US ZIP+4
        let result = sanitize_postal_code_strict("10001-1234");
        assert!(result.is_ok());

        // Invalid postal code
        let result = sanitize_postal_code_strict("invalid");
        assert!(result.is_err());
    }
}
