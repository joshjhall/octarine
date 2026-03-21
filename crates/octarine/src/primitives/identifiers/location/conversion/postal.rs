//! Postal code conversion and normalization
//!
//! Provides normalization for various postal code formats.
//!
//! # Supported Formats
//!
//! - **US ZIP**: 5 digits or 5+4 format
//! - **UK Postcode**: Standard format with space
//! - **Canada**: Standard A1A 1B1 format

use crate::primitives::Problem;

// ============================================================================
// Types
// ============================================================================

/// Postal code type
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PostalCodeType {
    /// US ZIP code (5 digits or 5+4 format)
    UsZip,
    /// US ZIP+4 code (9 digits)
    UsZipPlus4,
    /// UK postcode (various formats with space)
    UkPostcode,
    /// Canadian postal code (A1A 1B1 format)
    CanadianPostal,
}

/// Postal code normalization mode
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PostalCodeNormalization {
    /// Keep original format (5 or 5+4 for US ZIP)
    Preserve,
    /// Normalize to base format (5 digits for US ZIP, remove +4)
    BaseOnly,
    /// Normalize to extended format (5+4 for US ZIP if available)
    Extended,
}

// ============================================================================
// Detection
// ============================================================================

/// Detect postal code type
///
/// Determines the type of postal code from the input format.
///
/// # Supported Types
///
/// - **UsZip**: 5-digit US ZIP code (e.g., "10001")
/// - **UsZipPlus4**: 9-digit US ZIP+4 code (e.g., "10001-1234")
/// - **UkPostcode**: UK postcode (e.g., "SW1A 1AA")
/// - **CanadianPostal**: Canadian postal code (e.g., "K1A 0B1")
pub fn detect_postal_code_type(input: &str) -> Option<PostalCodeType> {
    let trimmed = input.trim();
    let upper = trimmed.to_uppercase();

    // Try Canadian postal first (most specific pattern)
    if is_canadian_postal(&upper) {
        return Some(PostalCodeType::CanadianPostal);
    }

    // Try US ZIP
    if let Some(zip_type) = detect_us_zip_type(&upper) {
        return Some(zip_type);
    }

    // Try UK postcode
    if is_uk_postcode(&upper) {
        return Some(PostalCodeType::UkPostcode);
    }

    None
}

// ============================================================================
// Normalization
// ============================================================================

/// Normalize postal code to standard format
///
/// Converts various postal code formats to a standardized representation
/// with consistent spacing, capitalization, and formatting.
///
/// # Supported Formats
///
/// - **US ZIP**: 5 digits or 5+4 format
/// - **UK Postcode**: Standard format with space
/// - **Canada Postal**: Standard A1A 1B1 format
///
/// # Errors
///
/// Returns `Problem::validation` if:
/// - Input is not a recognized postal code format
/// - Input contains invalid characters
pub fn normalize_postal_code(
    input: &str,
    mode: PostalCodeNormalization,
) -> Result<String, Problem> {
    let trimmed = input.trim();
    let upper = trimmed.to_uppercase();

    // Try US ZIP code
    if let Some(normalized) = normalize_us_zip(&upper, mode) {
        return Ok(normalized);
    }

    // Try UK postcode
    if let Some(normalized) = normalize_uk_postcode(&upper) {
        return Ok(normalized);
    }

    // Try Canadian postal code
    if let Some(normalized) = normalize_canadian_postal(&upper) {
        return Ok(normalized);
    }

    Err(Problem::Validation(
        "Unrecognized postal code format".into(),
    ))
}

// ============================================================================
// Internal Helpers
// ============================================================================

/// Detect US ZIP code type
fn detect_us_zip_type(input: &str) -> Option<PostalCodeType> {
    // Check for valid characters only (digits and hyphen)
    if !input.chars().all(|c| c.is_ascii_digit() || c == '-') {
        return None;
    }

    let digits: String = input.chars().filter(|c| c.is_ascii_digit()).collect();

    match digits.len() {
        5 => Some(PostalCodeType::UsZip),
        9 => Some(PostalCodeType::UsZipPlus4),
        _ => None,
    }
}

/// Check if input matches Canadian postal code pattern
fn is_canadian_postal(input: &str) -> bool {
    let no_spaces = input.replace(' ', "");

    // Must be exactly 6 characters
    if no_spaces.len() != 6 {
        return false;
    }

    // Check Letter-Digit-Letter-Digit-Letter-Digit pattern
    let chars: Vec<char> = no_spaces.chars().collect();
    matches!(chars.first(), Some(c) if c.is_ascii_alphabetic())
        && matches!(chars.get(1), Some(c) if c.is_ascii_digit())
        && matches!(chars.get(2), Some(c) if c.is_ascii_alphabetic())
        && matches!(chars.get(3), Some(c) if c.is_ascii_digit())
        && matches!(chars.get(4), Some(c) if c.is_ascii_alphabetic())
        && matches!(chars.get(5), Some(c) if c.is_ascii_digit())
}

/// Check if input matches UK postcode pattern
fn is_uk_postcode(input: &str) -> bool {
    let no_spaces = input.replace(' ', "");

    // UK postcodes are 5-7 characters (excluding space)
    if !(5..=7).contains(&no_spaces.len()) {
        return false;
    }

    // Must be alphanumeric only
    if !no_spaces.chars().all(|c| c.is_ascii_alphanumeric()) {
        return false;
    }

    // Must have both letters and digits
    let has_letters = no_spaces.chars().any(|c| c.is_ascii_alphabetic());
    let has_digits = no_spaces.chars().any(|c| c.is_ascii_digit());

    if !has_letters || !has_digits {
        return false;
    }

    // UK postcodes must START with a letter (outward code area)
    if let Some(first_char) = no_spaces.chars().next()
        && !first_char.is_ascii_alphabetic()
    {
        return false;
    }

    true
}

/// Normalize US ZIP code
fn normalize_us_zip(input: &str, mode: PostalCodeNormalization) -> Option<String> {
    // Check for valid characters only (digits and hyphen)
    if !input.chars().all(|c| c.is_ascii_digit() || c == '-') {
        return None;
    }

    // Remove hyphens
    let digits: String = input.chars().filter(|c| c.is_ascii_digit()).collect();

    match digits.len() {
        5 => Some(digits), // Already 5-digit format
        9 => {
            // 9 digits - has +4 extension
            match mode {
                PostalCodeNormalization::BaseOnly => Some(digits[..5].to_string()),
                PostalCodeNormalization::Extended | PostalCodeNormalization::Preserve => {
                    Some(format!("{}-{}", &digits[..5], &digits[5..9]))
                }
            }
        }
        _ => None, // Invalid length
    }
}

/// Normalize UK postcode to standard format with space
fn normalize_uk_postcode(input: &str) -> Option<String> {
    // Remove spaces
    let no_spaces = input.replace(' ', "");

    // UK postcodes are 5-7 characters (excluding space)
    if !(5..=7).contains(&no_spaces.len()) {
        return None;
    }

    // Check if it looks like a UK postcode (letters and digits)
    if !no_spaces.chars().all(|c| c.is_ascii_alphanumeric()) {
        return None;
    }

    // Check if it has letters and digits
    let has_letters = no_spaces.chars().any(|c| c.is_ascii_alphabetic());
    let has_digits = no_spaces.chars().any(|c| c.is_ascii_digit());

    if !has_letters || !has_digits {
        return None;
    }

    // Insert space before last 3 characters (standard UK format)
    if no_spaces.len() >= 3 {
        #[allow(clippy::arithmetic_side_effects)] // Safe: we just checked len() >= 3
        let split_point = no_spaces.len() - 3;
        Some(format!(
            "{} {}",
            &no_spaces[..split_point],
            &no_spaces[split_point..]
        ))
    } else {
        None
    }
}

/// Normalize Canadian postal code to standard A1A 1B1 format
fn normalize_canadian_postal(input: &str) -> Option<String> {
    // Remove spaces
    let no_spaces = input.replace(' ', "");

    // Canadian postal codes are exactly 6 characters
    if no_spaces.len() != 6 {
        return None;
    }

    // Check pattern: Letter-Digit-Letter-Digit-Letter-Digit
    let chars: Vec<char> = no_spaces.chars().collect();
    if !(matches!(chars.first(), Some(c) if c.is_ascii_alphabetic())
        && matches!(chars.get(1), Some(c) if c.is_ascii_digit())
        && matches!(chars.get(2), Some(c) if c.is_ascii_alphabetic())
        && matches!(chars.get(3), Some(c) if c.is_ascii_digit())
        && matches!(chars.get(4), Some(c) if c.is_ascii_alphabetic())
        && matches!(chars.get(5), Some(c) if c.is_ascii_digit()))
    {
        return None;
    }

    // Format as A1A 1B1
    Some(format!("{} {}", &no_spaces[..3], &no_spaces[3..]))
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::expect_used, clippy::unwrap_used)]
    use super::*;

    // ===== US ZIP Tests =====

    #[test]
    fn test_normalize_us_zip_5_digit() {
        assert_eq!(
            normalize_postal_code("10001", PostalCodeNormalization::Preserve)
                .expect("Postal normalization should succeed"),
            "10001"
        );

        assert_eq!(
            normalize_postal_code("  10001  ", PostalCodeNormalization::Preserve)
                .expect("Postal normalization should succeed"),
            "10001"
        );
    }

    #[test]
    fn test_normalize_us_zip_plus4() {
        assert_eq!(
            normalize_postal_code("10001-1234", PostalCodeNormalization::Preserve)
                .expect("Postal normalization should succeed"),
            "10001-1234"
        );

        assert_eq!(
            normalize_postal_code("100011234", PostalCodeNormalization::Extended)
                .expect("Postal normalization should succeed"),
            "10001-1234"
        );

        assert_eq!(
            normalize_postal_code("10001-1234", PostalCodeNormalization::BaseOnly)
                .expect("Postal normalization should succeed"),
            "10001"
        );
    }

    #[test]
    fn test_detect_us_zip() {
        assert_eq!(
            detect_postal_code_type("10001"),
            Some(PostalCodeType::UsZip)
        );
        assert_eq!(
            detect_postal_code_type("10001-1234"),
            Some(PostalCodeType::UsZipPlus4)
        );
        assert_eq!(
            detect_postal_code_type("100011234"),
            Some(PostalCodeType::UsZipPlus4)
        );
    }

    // ===== UK Postcode Tests =====

    #[test]
    fn test_normalize_uk_postcode() {
        assert_eq!(
            normalize_postal_code("SW1A1AA", PostalCodeNormalization::Preserve)
                .expect("Postal normalization should succeed"),
            "SW1A 1AA"
        );

        assert_eq!(
            normalize_postal_code("SW1A 1AA", PostalCodeNormalization::Preserve)
                .expect("Postal normalization should succeed"),
            "SW1A 1AA"
        );

        assert_eq!(
            normalize_postal_code("sw1a 1aa", PostalCodeNormalization::Preserve)
                .expect("Postal normalization should succeed"),
            "SW1A 1AA"
        );
    }

    #[test]
    fn test_detect_uk_postcode() {
        assert_eq!(
            detect_postal_code_type("SW1A 1AA"),
            Some(PostalCodeType::UkPostcode)
        );
        assert_eq!(
            detect_postal_code_type("SW1A1AA"),
            Some(PostalCodeType::UkPostcode)
        );
        assert_eq!(
            detect_postal_code_type("M1 1AE"),
            Some(PostalCodeType::UkPostcode)
        );
    }

    // ===== Canadian Postal Tests =====

    #[test]
    fn test_normalize_canadian_postal() {
        assert_eq!(
            normalize_postal_code("K1A0B1", PostalCodeNormalization::Preserve)
                .expect("Postal normalization should succeed"),
            "K1A 0B1"
        );

        assert_eq!(
            normalize_postal_code("K1A 0B1", PostalCodeNormalization::Preserve)
                .expect("Postal normalization should succeed"),
            "K1A 0B1"
        );

        assert_eq!(
            normalize_postal_code("k1a 0b1", PostalCodeNormalization::Preserve)
                .expect("Postal normalization should succeed"),
            "K1A 0B1"
        );
    }

    #[test]
    fn test_detect_canadian_postal() {
        assert_eq!(
            detect_postal_code_type("K1A 0B1"),
            Some(PostalCodeType::CanadianPostal)
        );
        assert_eq!(
            detect_postal_code_type("K1A0B1"),
            Some(PostalCodeType::CanadianPostal)
        );
        assert_eq!(
            detect_postal_code_type("M5W 1E6"),
            Some(PostalCodeType::CanadianPostal)
        );
    }

    // ===== Invalid Input Tests =====

    #[test]
    fn test_normalize_postal_invalid() {
        assert!(normalize_postal_code("12", PostalCodeNormalization::Preserve).is_err());
        assert!(normalize_postal_code("12345678901", PostalCodeNormalization::Preserve).is_err());
        assert!(normalize_postal_code("ABCDE", PostalCodeNormalization::Preserve).is_err());
        assert!(normalize_postal_code("10001!", PostalCodeNormalization::Preserve).is_err());
    }

    #[test]
    fn test_detect_postal_invalid() {
        assert_eq!(detect_postal_code_type("12"), None);
        assert_eq!(detect_postal_code_type("12345678901"), None);
        assert_eq!(detect_postal_code_type("ABCDE"), None);
        assert_eq!(detect_postal_code_type("invalid"), None);
        assert_eq!(detect_postal_code_type(""), None);
    }

    // ===== Ambiguous Cases =====

    #[test]
    fn test_detect_postal_code_type_ambiguous() {
        // US ZIP (5 digits) detected first
        assert_eq!(
            detect_postal_code_type("12345"),
            Some(PostalCodeType::UsZip)
        );

        // Canadian postal has specific pattern
        assert_eq!(
            detect_postal_code_type("A1A 1B1"),
            Some(PostalCodeType::CanadianPostal)
        );

        // UK postcode (letters and digits, but not Canadian pattern)
        assert_eq!(
            detect_postal_code_type("AB1 2CD"),
            Some(PostalCodeType::UkPostcode)
        );
    }
}
