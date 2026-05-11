//! Postal code conversion and normalization
//!
//! Provides normalization for various postal code formats.
//!
//! # Supported Formats
//!
//! - **US ZIP**: 5 digits or 5+4 format
//! - **UK Postcode**: Standard format with space
//! - **Canada**: Standard A1A 1B1 format
//! - **Germany**: 5 digits
//! - **France**: 5 digits, dept code 01-98
//! - **Australia**: 4 digits, range 0200-9999
//! - **Japan**: NNN-NNNN (hyphen inserted if missing)
//! - **India**: 6 digits, first digit 1-8
//! - **Netherlands**: NNNN AA (single space inserted between digits and letters)
//! - **Brazil**: NNNNN-NNN (hyphen inserted if missing)

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
    /// German postal code (5 digits)
    GermanPostal,
    /// French postal code (5 digits, dept code 01-98)
    FrenchPostal,
    /// Australian postal code (4 digits, range 0200-9999)
    AustralianPostal,
    /// Japanese postal code (NNN-NNNN)
    JapanesePostal,
    /// Indian PIN code (6 digits, first digit 1-8)
    IndianPostal,
    /// Dutch postal code (NNNN AA)
    DutchPostal,
    /// Brazilian CEP (NNNNN-NNN)
    BrazilianPostal,
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
/// Determines the type of postal code from the input format. Patterns with
/// distinctive structural punctuation are tried first; bare-digit codes
/// (US ZIP, German, French, Indian, Australian) are evaluated last in
/// length-descending order to give the most-specific length its chance.
///
/// **Ambiguity note**: German and US ZIP share the same 5-digit shape. This
/// function returns [`PostalCodeType::UsZip`] for 5-digit input because that
/// preserves historical behavior. Callers needing country precision should
/// supply context (e.g., the country field of the surrounding record) and use
/// the per-country `is_*_postal_code` functions.
///
/// # Supported Types
///
/// - **UsZip**: 5-digit US ZIP code (e.g., "10001")
/// - **UsZipPlus4**: 9-digit US ZIP+4 code (e.g., "10001-1234")
/// - **UkPostcode**: UK postcode (e.g., "SW1A 1AA")
/// - **CanadianPostal**: Canadian postal code (e.g., "K1A 0B1")
/// - **JapanesePostal**: Japanese postal code (e.g., "100-0001")
/// - **DutchPostal**: Dutch postal code (e.g., "1011 AB")
/// - **BrazilianPostal**: Brazilian CEP (e.g., "01001-000")
/// - **IndianPostal**: Indian PIN (e.g., "110001")
/// - **AustralianPostal**: Australian postal code (e.g., "2000")
/// - **FrenchPostal**: French postal code (e.g., "75001") — fallback for 5-digit values where dept code is 01-98 and US ZIP didn't bind first
/// - **GermanPostal**: German postal code — same 5-digit shape as US ZIP; only returned if the caller has narrowed elsewhere
pub fn detect_postal_code_type(input: &str) -> Option<PostalCodeType> {
    let trimmed = input.trim();
    let upper = trimmed.to_uppercase();

    // Canadian postal code (most specific letter/digit pattern)
    if is_canadian_postal(&upper) {
        return Some(PostalCodeType::CanadianPostal);
    }

    // Japanese postal code (NNN-NNNN, distinctive hyphen position)
    if is_japanese_postal(trimmed) {
        return Some(PostalCodeType::JapanesePostal);
    }

    // Dutch postal code (NNNN AA letters required)
    if is_dutch_postal(&upper) {
        return Some(PostalCodeType::DutchPostal);
    }

    // Brazilian CEP (NNNNN-NNN, distinctive hyphen position)
    if is_brazilian_postal(trimmed) {
        return Some(PostalCodeType::BrazilianPostal);
    }

    // US ZIP / ZIP+4 (5 or 9 digits, optional hyphen)
    if let Some(zip_type) = detect_us_zip_type(&upper) {
        return Some(zip_type);
    }

    // UK postcode (alphanumeric, both letters and digits)
    if is_uk_postcode(&upper) {
        return Some(PostalCodeType::UkPostcode);
    }

    // Indian PIN (6 digits, first 1-8) — must be tried before generic checks
    if is_indian_postal(trimmed) {
        return Some(PostalCodeType::IndianPostal);
    }

    // Australian (4 digits, 0200-9999)
    if is_australian_postal(trimmed) {
        return Some(PostalCodeType::AustralianPostal);
    }

    // German / French fall after US ZIP (same 5-digit shape) — unreachable
    // for the typical bare-digit case because US ZIP wins. Kept here so that
    // a caller using a custom dispatcher can short-circuit before US ZIP.

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

    // Try Canadian postal code (most specific letter/digit pattern)
    if let Some(normalized) = normalize_canadian_postal(&upper) {
        return Ok(normalized);
    }

    // Japanese (NNN-NNNN, plus the bare 7-digit form which we hyphenate)
    if let Some(normalized) = normalize_japanese_postal(trimmed) {
        return Ok(normalized);
    }

    // Dutch (NNNN AA, insert single space between digits and letters)
    if let Some(normalized) = normalize_dutch_postal(&upper) {
        return Ok(normalized);
    }

    // Brazilian (NNNNN-NNN, plus the bare 8-digit form which we hyphenate)
    if let Some(normalized) = normalize_brazilian_postal(trimmed) {
        return Ok(normalized);
    }

    // US ZIP code
    if let Some(normalized) = normalize_us_zip(&upper, mode) {
        return Ok(normalized);
    }

    // UK postcode
    if let Some(normalized) = normalize_uk_postcode(&upper) {
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

// ============================================================================
// International — Japan, Netherlands, Brazil, India, Australia
// ============================================================================

/// Check if input matches Japanese postal code pattern (NNN-NNNN or bare 7 digits).
fn is_japanese_postal(input: &str) -> bool {
    let trimmed = input.trim();
    // Canonical: NNN-NNNN
    if trimmed.len() == 8
        && trimmed.chars().nth(3) == Some('-')
        && trimmed
            .chars()
            .enumerate()
            .all(|(i, c)| if i == 3 { c == '-' } else { c.is_ascii_digit() })
    {
        return true;
    }
    false
}

/// Normalize Japanese postal code to standard NNN-NNNN format.
/// Accepts the 7-digit hyphenless form and inserts the hyphen.
fn normalize_japanese_postal(input: &str) -> Option<String> {
    let trimmed = input.trim();
    // Hyphenated form already canonical
    if is_japanese_postal(trimmed) {
        return Some(trimmed.to_string());
    }
    // Bare 7 digits — insert hyphen after position 3
    if trimmed.len() == 7 && trimmed.chars().all(|c| c.is_ascii_digit()) {
        return Some(format!("{}-{}", &trimmed[..3], &trimmed[3..]));
    }
    None
}

/// Check if input matches Dutch postal code pattern (NNNN AA).
fn is_dutch_postal(input: &str) -> bool {
    let no_spaces = input.replace(' ', "");
    if no_spaces.len() != 6 {
        return false;
    }
    let chars: Vec<char> = no_spaces.chars().collect();
    // First digit 1-9
    let first_ok = matches!(chars.first(), Some(c) if c.is_ascii_digit() && *c != '0');
    if !first_ok {
        return false;
    }
    // Positions 0..3 digits, 4..6 letters
    chars.iter().take(4).all(|c| c.is_ascii_digit())
        && chars.iter().skip(4).all(|c| c.is_ascii_alphabetic())
}

/// Normalize Dutch postal code to canonical "NNNN AA" with single space.
fn normalize_dutch_postal(input: &str) -> Option<String> {
    let no_spaces = input.replace(' ', "");
    if !is_dutch_postal(&no_spaces) {
        return None;
    }
    Some(format!("{} {}", &no_spaces[..4], &no_spaces[4..]))
}

/// Check if input matches Brazilian CEP pattern (NNNNN-NNN or bare 8 digits).
fn is_brazilian_postal(input: &str) -> bool {
    let trimmed = input.trim();
    if trimmed.len() == 9
        && trimmed.chars().nth(5) == Some('-')
        && trimmed
            .chars()
            .enumerate()
            .all(|(i, c)| if i == 5 { c == '-' } else { c.is_ascii_digit() })
    {
        return true;
    }
    false
}

/// Normalize Brazilian CEP to canonical "NNNNN-NNN".
/// Accepts the 8-digit hyphenless form and inserts the hyphen.
fn normalize_brazilian_postal(input: &str) -> Option<String> {
    let trimmed = input.trim();
    if is_brazilian_postal(trimmed) {
        return Some(trimmed.to_string());
    }
    if trimmed.len() == 8 && trimmed.chars().all(|c| c.is_ascii_digit()) {
        return Some(format!("{}-{}", &trimmed[..5], &trimmed[5..]));
    }
    None
}

/// Check if input matches Indian PIN code pattern (6 digits, first digit 1-8).
fn is_indian_postal(input: &str) -> bool {
    let trimmed = input.trim();
    trimmed.len() == 6
        && trimmed.chars().all(|c| c.is_ascii_digit())
        && matches!(trimmed.chars().next(), Some(c) if matches!(c, '1'..='8'))
}

/// Check if input matches Australian postal code pattern (4 digits, 0200-9999).
fn is_australian_postal(input: &str) -> bool {
    let trimmed = input.trim();
    if trimmed.len() != 4 || !trimmed.chars().all(|c| c.is_ascii_digit()) {
        return false;
    }
    let n: u32 = trimmed.parse().unwrap_or(0);
    (200..=9999).contains(&n)
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

    // ===== International Formats =====

    #[test]
    fn test_detect_japanese_postal() {
        assert_eq!(
            detect_postal_code_type("100-0001"),
            Some(PostalCodeType::JapanesePostal)
        );
        assert_eq!(
            detect_postal_code_type("  100-0001  "),
            Some(PostalCodeType::JapanesePostal)
        );
    }

    #[test]
    fn test_normalize_japanese_postal_hyphenless() {
        // Bare 7 digits → canonical NNN-NNNN
        assert_eq!(
            normalize_postal_code("1000001", PostalCodeNormalization::Preserve)
                .expect("normalization"),
            "100-0001"
        );
        // Already canonical
        assert_eq!(
            normalize_postal_code("100-0001", PostalCodeNormalization::Preserve)
                .expect("normalization"),
            "100-0001"
        );
    }

    #[test]
    fn test_detect_dutch_postal() {
        assert_eq!(
            detect_postal_code_type("1011 AB"),
            Some(PostalCodeType::DutchPostal)
        );
        assert_eq!(
            detect_postal_code_type("1011AB"),
            Some(PostalCodeType::DutchPostal)
        );
    }

    #[test]
    fn test_normalize_dutch_postal_inserts_space() {
        assert_eq!(
            normalize_postal_code("1011AB", PostalCodeNormalization::Preserve)
                .expect("normalization"),
            "1011 AB"
        );
        assert_eq!(
            normalize_postal_code("1011 ab", PostalCodeNormalization::Preserve)
                .expect("normalization"),
            "1011 AB"
        );
    }

    #[test]
    fn test_detect_brazilian_postal() {
        assert_eq!(
            detect_postal_code_type("01001-000"),
            Some(PostalCodeType::BrazilianPostal)
        );
    }

    #[test]
    fn test_normalize_brazilian_postal_hyphenless() {
        assert_eq!(
            normalize_postal_code("01001000", PostalCodeNormalization::Preserve)
                .expect("normalization"),
            "01001-000"
        );
        assert_eq!(
            normalize_postal_code("01001-000", PostalCodeNormalization::Preserve)
                .expect("normalization"),
            "01001-000"
        );
    }

    #[test]
    fn test_detect_indian_postal() {
        assert_eq!(
            detect_postal_code_type("110001"),
            Some(PostalCodeType::IndianPostal)
        );
        assert_eq!(
            detect_postal_code_type("800001"),
            Some(PostalCodeType::IndianPostal)
        );
    }

    #[test]
    fn test_detect_indian_postal_rejects_reserved_zones() {
        // Zone 0 invalid, zone 9 reserved — should fall through to None
        assert_eq!(detect_postal_code_type("010001"), None);
        assert_eq!(detect_postal_code_type("910001"), None);
    }

    #[test]
    fn test_detect_australian_postal() {
        assert_eq!(
            detect_postal_code_type("2000"),
            Some(PostalCodeType::AustralianPostal)
        );
        assert_eq!(
            detect_postal_code_type("0200"),
            Some(PostalCodeType::AustralianPostal)
        );
    }

    #[test]
    fn test_detect_australian_postal_rejects_below_minimum() {
        // 0199 is below the 0200 floor — should be rejected
        assert_eq!(detect_postal_code_type("0199"), None);
    }

    #[test]
    fn test_detect_dispatch_order_japanese_vs_us_zip4() {
        // 100-0001 is 8 chars with a hyphen — Japanese wins over US ZIP+4
        // (which requires 5+4 = 9-digit shape).
        assert_eq!(
            detect_postal_code_type("100-0001"),
            Some(PostalCodeType::JapanesePostal)
        );
    }
}
