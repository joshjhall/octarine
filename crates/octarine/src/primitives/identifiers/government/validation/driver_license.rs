//! Driver's License validation
//!
//! Pure validation functions for US state driver's licenses.
//!
//! # Jurisdiction coverage
//!
//! Validation delegates to the jurisdiction registry in
//! [`super::super::licenses`], which covers the top 20 US states by
//! population. Four of them (California, Florida, Nebraska, Washington) carry
//! bespoke check-digit algorithms in `licenses::north_america`; the rest are
//! format-only rows in the `licenses::us_states` table.
//!
//! # Format vs check digit
//!
//! [`validate_driver_license`] checks the layout only.
//! [`validate_driver_license_with_checksum`] additionally verifies the check
//! digit for the four jurisdictions that publish one.
//!
//! # Unknown jurisdictions are rejected
//!
//! A state code the registry does not know is an **error**, not a
//! pass-through. The previous "6-13 alphanumeric" fallback accepted any
//! customer or order ID (`CUST123456`) as a driver's license for an unrecognised
//! state, which made `validate_driver_license` useless as a security gate.
//! Callers that genuinely want shape-only checking should use the detection
//! layer instead.

use super::super::licenses;
use crate::primitives::Problem;

// ============================================================================
// Driver's License Validation
// ============================================================================

/// Validate driver's license format for a specific state
///
/// Validates the **format** only — the state's accepted character layouts. A
/// jurisdiction's check digit (where one is published) is verified by
/// [`validate_driver_license_with_checksum`] instead, matching the
/// lenient/strict split used across this module.
///
/// # Arguments
///
/// * `license` - The license number
/// * `state` - Two-letter state code (e.g., "CA", "TX"), or a full
///   jurisdiction code (e.g., "US-CA")
///
/// # Returns
///
/// * `Ok(())` - If the license format is valid for the specified state
/// * `Err(Problem)` - If the format is invalid, or the state is not a
///   supported jurisdiction
///
/// # Examples
///
/// ```ignore
/// use crate::primitives::identifiers::government::validation;
///
/// // California: 1 letter + 7 digits
/// assert!(validation::validate_driver_license("A1234567", "CA").is_ok());
///
/// // Texas: 7-8 digits
/// assert!(validation::validate_driver_license("12345678", "TX").is_ok());
///
/// // Invalid format for the jurisdiction
/// assert!(validation::validate_driver_license("invalid", "CA").is_err());
///
/// // Unknown jurisdiction is rejected rather than waved through
/// assert!(validation::validate_driver_license("CUST123456", "XX").is_err());
/// ```
pub fn validate_driver_license(license: &str, state: &str) -> Result<(), Problem> {
    let jurisdiction = normalize_jurisdiction(state);

    let Some(result) = licenses::validate_license(license, &jurisdiction) else {
        return Err(Problem::Validation(format!(
            "Unknown driver's license jurisdiction '{state}' - supported jurisdictions: {}",
            supported_state_codes().join(", ")
        )));
    };

    if !result.format_valid {
        let (_, description) = licenses::jurisdiction_info(&jurisdiction).unwrap_or(("", ""));
        return Err(Problem::Validation(format!(
            "Invalid {} driver's license format - expected {}",
            result.jurisdiction_name, description
        )));
    }

    // Check digits are deliberately NOT enforced here — see
    // `validate_driver_license_with_checksum`.
    Ok(())
}

/// Validate driver's license format **and** check digit
///
/// The strict counterpart to [`validate_driver_license`]: it additionally
/// rejects a license whose jurisdiction publishes a check-digit algorithm and
/// whose check digit does not verify. For the jurisdictions with no published
/// algorithm (every row of `licenses::us_states`) this is equivalent to the
/// format-only variant, since there is no check digit to test.
///
/// This mirrors the lenient/strict `_with_checksum` split already used by Korea
/// RRN, Mexico CURP, Turkey TCKN, UK NHS, VIN, and Singapore UEN.
///
/// # Arguments
///
/// * `license` - The license number
/// * `state` - Two-letter state code, or a full jurisdiction code
///
/// # Returns
///
/// * `Ok(())` - Format is valid and the check digit verifies (or there is none)
/// * `Err(Problem)` - Invalid format, failing check digit, or unknown jurisdiction
///
/// # Examples
///
/// ```ignore
/// use crate::primitives::identifiers::government::validation;
///
/// // Format-only accepts any correctly-shaped California license
/// assert!(validation::validate_driver_license("A1234567", "CA").is_ok());
///
/// // The checksum variant additionally verifies California's check digit
/// assert!(validation::validate_driver_license_with_checksum("A1234567", "CA").is_err());
/// ```
pub fn validate_driver_license_with_checksum(license: &str, state: &str) -> Result<(), Problem> {
    validate_driver_license(license, state)?;

    let jurisdiction = normalize_jurisdiction(state);

    // The format check above already proved the jurisdiction is supported.
    let Some(result) = licenses::validate_license(license, &jurisdiction) else {
        return Err(Problem::Validation(format!(
            "Unknown driver's license jurisdiction '{state}'"
        )));
    };

    // `Some(false)` is a real check-digit failure; `None` means the
    // jurisdiction publishes no check digit, which is not an error.
    if result.checksum_valid == Some(false) {
        return Err(Problem::Validation(format!(
            "{} driver's license check digit is invalid",
            result.jurisdiction_name
        )));
    }

    Ok(())
}

/// Expand a bare two-letter state code into a registry jurisdiction code.
///
/// Accepts either form: `"ca"` and `"US-CA"` both resolve to `"US-CA"`. Any
/// input already containing a `-` is treated as a full jurisdiction code and
/// only uppercased, so Canadian provinces (`"CA-ON"`) are not mangled into a
/// US code.
fn normalize_jurisdiction(state: &str) -> String {
    let trimmed = state.trim().to_uppercase();

    if trimmed.contains('-') {
        trimmed
    } else {
        format!("US-{trimmed}")
    }
}

/// Two-letter codes of every supported US jurisdiction, sorted.
///
/// Used to make the unknown-jurisdiction error actionable.
fn supported_state_codes() -> Vec<&'static str> {
    let mut codes: Vec<&'static str> = licenses::supported_jurisdictions()
        .into_iter()
        .filter_map(|j| j.strip_prefix("US-"))
        .collect();
    codes.sort_unstable();
    codes
}

/// Check if a driver's license number appears to be a test pattern
///
/// # Examples
///
/// ```ignore
/// use crate::primitives::identifiers::government::validation;
///
/// assert!(validation::is_test_driver_license("A0000000"));
/// assert!(validation::is_test_driver_license("TEST1234"));
/// assert!(!validation::is_test_driver_license("D1234567"));
/// ```
#[must_use]
pub fn is_test_driver_license(license: &str) -> bool {
    let license_upper = license.to_uppercase().replace([' ', '-'], "");

    // Common test patterns
    if license_upper.starts_with("TEST")
        || license_upper.starts_with("DEMO")
        || license_upper.starts_with("SAMPLE")
        || license_upper.starts_with("FAKE")
    {
        return true;
    }

    // All zeros after letter
    if license_upper.len() >= 2
        && license_upper
            .chars()
            .next()
            .is_some_and(|c| c.is_ascii_alphabetic())
        && license_upper.chars().skip(1).all(|c| c == '0')
    {
        return true;
    }

    // Sequential patterns
    if license_upper.contains("12345678") || license_upper.contains("87654321") {
        return true;
    }

    // All same digit
    let digits: String = license_upper
        .chars()
        .filter(|c| c.is_ascii_digit())
        .collect();
    if digits.len() >= 4
        && digits
            .chars()
            .all(|c| c == digits.chars().next().unwrap_or('0'))
    {
        return true;
    }

    false
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::expect_used)]
    use super::*;

    #[test]
    fn test_driver_license_validation() {
        // California: 1 letter + 7 digits
        assert!(validate_driver_license("A1234567", "CA").is_ok());
        assert!(validate_driver_license("12345678", "CA").is_err()); // No letter

        // Texas: digits only
        assert!(validate_driver_license("12345678", "TX").is_ok());
        assert!(validate_driver_license("A1234567", "TX").is_err()); // Has letter
    }

    #[test]
    fn test_validate_driver_license_success() {
        // Bespoke check-digit jurisdictions (licenses::north_america)
        assert!(validate_driver_license("A1234567", "CA").is_ok());
        assert!(validate_driver_license("A123456789012", "FL").is_ok());

        // Table-driven jurisdictions (licenses::us_states)
        assert!(validate_driver_license("12345678", "TX").is_ok());
        assert!(validate_driver_license("123456789", "NY").is_ok());
        assert!(validate_driver_license("12345678", "PA").is_ok());
        assert!(validate_driver_license("A12345678901", "IL").is_ok());
        assert!(validate_driver_license("AB123", "OH").is_ok());
        assert!(validate_driver_license("123456789", "GA").is_ok());
        assert!(validate_driver_license("123456789", "NC").is_ok());
        assert!(validate_driver_license("A1234567890", "MI").is_ok());
        assert!(validate_driver_license("A12345678901234", "NJ").is_ok());
        assert!(validate_driver_license("A123456789", "VA").is_ok());
        assert!(validate_driver_license("A12345678", "AZ").is_ok());
        assert!(validate_driver_license("123456789", "TN").is_ok());
        assert!(validate_driver_license("S12345678", "MA").is_ok());
        assert!(validate_driver_license("A123456789", "IN").is_ok());
        assert!(validate_driver_license("A123456789", "MO").is_ok());
        assert!(validate_driver_license("A123456789012", "MD").is_ok());
        assert!(validate_driver_license("A1234567890123", "WI").is_ok());
    }

    #[test]
    fn test_each_state_rejects_a_neighbours_shape() {
        // Same length, wrong layout: each of these is valid for some OTHER
        // jurisdiction, so a validator that ignored layout would pass them.
        assert!(validate_driver_license("12345678", "CA").is_err()); // TX/PA shape
        assert!(validate_driver_license("A1234567", "PA").is_err()); // CA shape
        assert!(validate_driver_license("12345678", "NY").is_err()); // PA shape
        assert!(validate_driver_license("A123456789012", "WI").is_err()); // MD shape
        assert!(validate_driver_license("A12345678901", "MI").is_err()); // IL shape (MI is 10 or 12 digits)
    }

    #[test]
    fn test_unknown_jurisdiction_is_rejected() {
        // The headline regression from issue #440: the old generic "6-13
        // alphanumeric" fallback accepted any customer ID for an unrecognised
        // state.
        let result = validate_driver_license("CUST123456", "XX");
        assert!(result.is_err());
        let message = result.expect_err("expected error").to_string();
        assert!(message.contains("Unknown"), "message was: {message}");
        assert!(message.contains("XX"), "message was: {message}");

        // Even a well-formed-looking license is rejected for an unknown state.
        assert!(validate_driver_license("A1234567", "ZZ").is_err());
        assert!(validate_driver_license("", "XX").is_err());
    }

    #[test]
    fn test_unknown_jurisdiction_error_lists_supported_states() {
        let message = validate_driver_license("A1234567", "XX")
            .expect_err("expected error")
            .to_string();
        // The error is only actionable if it names where to look.
        assert!(message.contains("CA"), "message was: {message}");
        assert!(message.contains("TX"), "message was: {message}");
    }

    #[test]
    fn test_state_code_forms_are_equivalent() {
        // Bare code, lowercase, and full jurisdiction code all resolve.
        assert!(validate_driver_license("A1234567", "CA").is_ok());
        assert!(validate_driver_license("A1234567", "ca").is_ok());
        assert!(validate_driver_license("A1234567", "US-CA").is_ok());
        assert!(validate_driver_license("A1234567", " CA ").is_ok());
    }

    #[test]
    fn test_hyphenated_code_is_not_forced_to_us() {
        // "CA-ON" is Ontario, not California — it must not be rewritten to
        // "US-CA-ON" nor silently treated as California.
        let result = validate_driver_license("A1234567", "CA-ON");
        assert!(result.is_err());
        assert!(
            result
                .expect_err("expected error")
                .to_string()
                .contains("Unknown")
        );
    }

    #[test]
    fn test_validate_driver_license_errors() {
        // California: wrong length
        let result = validate_driver_license("A123", "CA");
        assert!(result.is_err());
        assert!(
            result
                .expect_err("expected error")
                .to_string()
                .contains("California")
        );

        // California: no letter at start
        let result = validate_driver_license("12345678", "CA");
        assert!(result.is_err());
        assert!(
            result
                .expect_err("expected error")
                .to_string()
                .contains("format")
        );

        // Texas: contains non-digits
        assert!(validate_driver_license("A1234567", "TX").is_err());

        // Florida: wrong length
        let result = validate_driver_license("A123", "FL");
        assert!(result.is_err());
        assert!(
            result
                .expect_err("expected error")
                .to_string()
                .contains("Florida")
        );
    }

    #[test]
    fn test_format_error_names_the_expected_shape() {
        let message = validate_driver_license("1", "PA")
            .expect_err("expected error")
            .to_string();
        assert!(message.contains("Pennsylvania"), "message was: {message}");
        assert!(message.contains("8 digits"), "message was: {message}");
    }

    #[test]
    fn test_driver_license_edge_cases() {
        // Empty
        assert!(validate_driver_license("", "CA").is_err());

        // Very long
        let long = "A".repeat(1000);
        assert!(validate_driver_license(&long, "CA").is_err());

        // Null bytes
        assert!(validate_driver_license("A1234\x00567", "CA").is_err());

        // Punctuation is never part of a license number
        assert!(validate_driver_license("ABC-123", "TX").is_err());
        assert!(validate_driver_license("A-1234567", "CA").is_err());
    }

    #[test]
    fn test_with_checksum_is_stricter_than_format_only() {
        // "A1234567" is a correctly-shaped California license whose check
        // digit does not verify. The two validators must disagree on it, or
        // the lenient/strict split is cosmetic.
        assert!(validate_driver_license("A1234567", "CA").is_ok());
        assert!(validate_driver_license_with_checksum("A1234567", "CA").is_err());
    }

    #[test]
    fn test_with_checksum_error_names_the_check_digit() {
        let message = validate_driver_license_with_checksum("A1234567", "CA")
            .expect_err("expected error")
            .to_string();
        assert!(message.contains("check digit"), "message was: {message}");
    }

    #[test]
    fn test_with_checksum_agrees_for_format_only_jurisdictions() {
        // A table-driven state publishes no check digit, so there is nothing
        // for the strict variant to add.
        assert!(validate_driver_license("12345678", "PA").is_ok());
        assert!(validate_driver_license_with_checksum("12345678", "PA").is_ok());
        assert!(validate_driver_license("123456789", "GA").is_ok());
        assert!(validate_driver_license_with_checksum("123456789", "GA").is_ok());
    }

    #[test]
    fn test_with_checksum_rejects_bad_format_and_unknown_state() {
        // Format and jurisdiction errors surface through the strict variant too.
        assert!(validate_driver_license_with_checksum("12345678", "CA").is_err());
        assert!(validate_driver_license_with_checksum("CUST123456", "XX").is_err());
    }

    #[test]
    fn test_is_test_driver_license() {
        // Test patterns
        assert!(is_test_driver_license("TEST1234"));
        assert!(is_test_driver_license("DEMO5678"));
        assert!(is_test_driver_license("A0000000"));
        assert!(is_test_driver_license("B12345678"));

        // All same digit
        assert!(is_test_driver_license("A1111111"));

        // Real-looking licenses (not test patterns)
        assert!(!is_test_driver_license("D1234567"));
        assert!(!is_test_driver_license("B9876543"));
        assert!(!is_test_driver_license("X5839201"));
    }
}
