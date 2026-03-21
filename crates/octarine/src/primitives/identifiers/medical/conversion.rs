//! Medical identifier conversions (primitives layer)
//!
//! Pure conversion and formatting functions for medical identifiers.
//! No observe dependencies - used by Layer 2 and Layer 3 modules.
//!
//! # Supported Conversions
//!
//! ## NPI (National Provider Identifier)
//! - Format for display with dashes: `1234567890` → `1234-567-890`
//! - Validate Luhn mod-10 checksum (HIPAA requirement)
//!
//! ## ICD-10 (Diagnosis Codes)
//! - Normalize decimal placement: `A011` ↔ `A01.1`
//! - Consistent formatting for display
//!
//! # Architecture
//!
//! This is **Layer 1 (primitives)** - pure functions with:
//! - No observe:: dependencies
//! - No logging or side effects
//! - Returns data only

use crate::primitives::Problem;

// ============================================================================
// NPI Formatting and Validation
// ============================================================================

/// Display format style for NPI numbers
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NpiFormatStyle {
    /// Raw digits: `1234567890`
    Plain,
    /// Formatted with dashes: `1234-567-890`
    Dashed,
    /// With "NPI:" prefix: `NPI: 1234567890`
    Labeled,
    /// Labeled with dashes: `NPI: 1234-567-890`
    LabeledDashed,
}

/// Convert NPI to display format using specified style
///
/// Formats a 10-digit National Provider Identifier for human-readable display.
/// Does NOT validate the NPI - use `validate_npi_checksum()` for validation.
///
/// # Arguments
///
/// * `npi` - NPI string (may contain labels, spaces, dashes)
/// * `style` - Desired formatting style
///
/// # Returns
///
/// Formatted NPI string according to style.
///
/// # Examples
///
/// ```ignore
/// use octarine::primitives::identifiers::medical::{to_npi_display, NpiFormatStyle};
///
/// // Format with dashes
/// assert_eq!(to_npi_display("1234567890", NpiFormatStyle::Dashed), "1234-567-890");
///
/// // Format with label
/// assert_eq!(to_npi_display("NPI: 1234567890", NpiFormatStyle::Labeled), "NPI: 1234567890");
///
/// // Works with already-formatted input
/// assert_eq!(to_npi_display("1234-567-890", NpiFormatStyle::Plain), "1234567890");
/// ```
#[must_use]
pub fn to_npi_display(npi: &str, style: NpiFormatStyle) -> String {
    // Extract digits only
    let digits: String = npi.chars().filter(|c| c.is_ascii_digit()).collect();

    // Need exactly 10 digits for valid NPI
    if digits.len() != 10 {
        // Return original if not valid format
        return npi.to_string();
    }

    match style {
        NpiFormatStyle::Plain => digits,
        NpiFormatStyle::Dashed => format!("{}-{}-{}", &digits[0..4], &digits[4..7], &digits[7..10]),
        NpiFormatStyle::Labeled => format!("NPI: {}", digits),
        NpiFormatStyle::LabeledDashed => format!(
            "NPI: {}-{}-{}",
            &digits[0..4],
            &digits[4..7],
            &digits[7..10]
        ),
    }
}

/// Normalize NPI to canonical 10-digit format
///
/// Extracts digits from various input formats and returns plain 10-digit NPI.
/// Does NOT validate - use `sanitize_npi()` for validation.
///
/// # Arguments
///
/// * `npi` - NPI string (may contain labels, spaces, dashes)
///
/// # Returns
///
/// 10-digit NPI string if valid length, original if not.
///
/// # Examples
///
/// ```ignore
/// use octarine::primitives::identifiers::medical::normalize_npi;
///
/// assert_eq!(normalize_npi("NPI: 1234-567-890"), "1234567890");
/// assert_eq!(normalize_npi("1234567890"), "1234567890");
/// ```
#[must_use]
pub fn normalize_npi(npi: &str) -> String {
    let digits: String = npi.chars().filter(|c| c.is_ascii_digit()).collect();
    if digits.len() == 10 {
        digits
    } else {
        npi.to_string()
    }
}

/// Sanitize NPI strict (normalize format + validate checksum)
///
/// Strips non-digits, validates format and Luhn checksum, returns normalized NPI.
/// Use this when you want a clean, validated NPI value.
///
/// # Arguments
///
/// * `npi` - NPI string (may contain labels, spaces, dashes)
///
/// # Returns
///
/// `Ok(String)` with 10-digit NPI if valid, `Err(Problem)` if invalid.
///
/// # Examples
///
/// ```ignore
/// use octarine::primitives::identifiers::medical::sanitize_npi;
///
/// // Valid NPI with formatting
/// let sanitized = sanitize_npi("NPI: 1245-319-599")?;
/// assert_eq!(sanitized, "1245319599");
///
/// // Invalid checksum
/// assert!(sanitize_npi("1234567890").is_err());
/// ```
pub fn sanitize_npi(npi: &str) -> Result<String, Problem> {
    let normalized = normalize_npi(npi);
    validate_npi_checksum(&normalized)?;
    Ok(normalized)
}

/// Validate NPI checksum using Luhn mod-10 algorithm
///
/// The NPI checksum is calculated using the Luhn algorithm with mod-10,
/// as required by HIPAA standards (45 CFR 162.406).
///
/// # Algorithm
///
/// 1. Add constant 80840 prefix to create 15-digit number
/// 2. Double every other digit from right to left
/// 3. Sum all digits (treating doubled results as individual digits)
/// 4. Check if sum is divisible by 10
///
/// Reference: <https://www.cms.gov/Regulations-and-Guidance/Administrative-Simplification/NationalProvIdentStand/Downloads/NPIcheckdigit.pdf>
///
/// # Arguments
///
/// * `npi` - NPI string (may contain labels, spaces, dashes)
///
/// # Returns
///
/// `Ok(())` if checksum is valid, `Err(Problem)` if invalid.
///
/// # Examples
///
/// ```ignore
/// use octarine::primitives::identifiers::medical::validate_npi_checksum;
///
/// // Valid NPI with correct checksum
/// assert!(validate_npi_checksum("1245319599").is_ok());
///
/// // Invalid checksum
/// assert!(validate_npi_checksum("1234567890").is_err());
///
/// // Works with formatted input
/// assert!(validate_npi_checksum("NPI: 1245-319-599").is_ok());
/// ```
pub fn validate_npi_checksum(npi: &str) -> Result<(), Problem> {
    // Extract digits only
    let digits: String = npi.chars().filter(|c| c.is_ascii_digit()).collect();

    // Must be exactly 10 digits
    if digits.len() != 10 {
        return Err(Problem::validation("NPI must be exactly 10 digits"));
    }

    // Must start with 1 or 2
    if !digits.starts_with('1') && !digits.starts_with('2') {
        return Err(Problem::validation("NPI must start with 1 or 2"));
    }

    // Calculate Luhn checksum with 80840 prefix
    let prefixed = format!("80840{}", digits);
    let mut sum: u32 = 0;
    let mut alternate = false;

    // Process digits from right to left
    for ch in prefixed.chars().rev() {
        let mut digit = ch
            .to_digit(10)
            .ok_or_else(|| Problem::validation("Invalid digit in NPI"))?;

        if alternate {
            digit = digit.saturating_mul(2);
            if digit > 9 {
                digit = digit.saturating_sub(9);
            }
        }

        sum = sum.saturating_add(digit);
        alternate = !alternate;
    }

    if sum.is_multiple_of(10) {
        Ok(())
    } else {
        Err(Problem::validation("Invalid NPI checksum"))
    }
}

// ============================================================================
// ICD-10 Normalization
// ============================================================================

/// ICD-10 format style for display
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Icd10FormatStyle {
    /// Compact with decimal: `A01.1`
    Compact,
    /// Compact without decimal: `A011`
    CompactNoDecimal,
    /// Labeled with decimal: `ICD-10: A01.1`
    Labeled,
    /// Labeled without decimal: `ICD-10: A011`
    LabeledNoDecimal,
}

/// Normalize ICD-10 code format
///
/// Converts ICD-10 diagnosis codes to a consistent format with proper decimal
/// placement. Handles variations in formatting from different systems.
///
/// # ICD-10 Format
///
/// Valid ICD-10 codes have the structure:
/// - Letter (A-T, V-Z)
/// - 2 digits
/// - Optional decimal point
/// - 0-4 additional digits
/// - Optional letter suffix
///
/// # Arguments
///
/// * `code` - ICD-10 code (may include labels, spaces, varying decimal placement)
///
/// # Returns
///
/// Normalized ICD-10 code in compact format with decimal (e.g., `A01.1`),
/// or `Err(Problem)` if format is invalid.
///
/// # Examples
///
/// ```ignore
/// use octarine::primitives::identifiers::medical::normalize_icd10;
///
/// // Add missing decimal
/// assert_eq!(normalize_icd10("A011").unwrap(), "A01.1");
///
/// // Already normalized
/// assert_eq!(normalize_icd10("A01.1").unwrap(), "A01.1");
///
/// // Strip labels
/// assert_eq!(normalize_icd10("ICD-10: E11.9").unwrap(), "E11.9");
///
/// // Complex code with suffix
/// assert_eq!(normalize_icd10("S72341A").unwrap(), "S72.341A");
/// ```
pub fn normalize_icd10(code: &str) -> Result<String, Problem> {
    // Strip common label patterns first
    let trimmed = code
        .trim()
        .trim_start_matches("ICD-10:")
        .trim_start_matches("ICD10:")
        .trim_start_matches("ICD-10")
        .trim_start_matches("ICD10")
        .trim_start_matches("ICD:")
        .trim();

    // Extract alphanumeric and decimal only
    let cleaned: String = trimmed
        .chars()
        .filter(|c| c.is_alphanumeric() || *c == '.')
        .collect();

    if cleaned.is_empty() {
        return Err(Problem::validation("ICD-10 code cannot be empty"));
    }

    // Must start with valid letter (A-T, V-Z)
    let first = cleaned
        .chars()
        .next()
        .ok_or_else(|| Problem::validation("Invalid ICD-10 format"))?;

    if !first.is_ascii_uppercase() {
        return Err(Problem::validation(
            "ICD-10 code must start with uppercase letter",
        ));
    }

    if first == 'U' {
        return Err(Problem::validation("ICD-10 code cannot start with 'U'"));
    }

    // Split into letter, digits, and optional suffix
    let mut letter = String::new();
    let mut digits = String::new();
    let mut suffix = String::new();
    let mut in_suffix = false;

    for (i, ch) in cleaned.chars().enumerate() {
        if i == 0 {
            letter.push(ch);
        } else if ch == '.' {
            // Skip decimal, we'll add it back
            continue;
        } else if ch.is_ascii_digit() {
            if in_suffix {
                suffix.push(ch);
            } else {
                digits.push(ch);
            }
        } else if ch.is_ascii_alphabetic() {
            // Letter after digits = suffix
            in_suffix = true;
            suffix.push(ch);
        }
    }

    // Need at least 2 digits (AA format minimum for category level)
    if digits.len() < 2 {
        return Err(Problem::validation(
            "ICD-10 code must have at least 2 digits",
        ));
    }

    // Maximum 7 characters total (1 letter + 6 digits/letters)
    if digits.len().saturating_add(suffix.len()) > 6 {
        return Err(Problem::validation("ICD-10 code too long"));
    }

    // Format: A01 (category) or A01.1 (subcategory) or A01.123A (detailed)
    // Decimal goes after position 3 (letter + 2 digits) if there are more digits/suffix
    let result = if digits.len() == 2 && suffix.is_empty() {
        // Category level only: A01 (no decimal)
        format!("{}{}", letter, digits)
    } else {
        // Subcategory or more specific: A01.1 or A01.123A (with decimal)
        format!("{}{}.{}{}", letter, &digits[0..2], &digits[2..], suffix)
    };

    Ok(result)
}

/// Convert ICD-10 code to display format using specified style
///
/// Formats a normalized ICD-10 code according to display preferences.
/// Use `normalize_icd10()` first if input may be in varying formats.
///
/// # Arguments
///
/// * `code` - ICD-10 code (should be normalized first)
/// * `style` - Desired formatting style
///
/// # Returns
///
/// Formatted ICD-10 code string.
///
/// # Examples
///
/// ```ignore
/// use octarine::primitives::identifiers::medical::{to_icd10_display, Icd10FormatStyle};
///
/// // Format without decimal
/// assert_eq!(to_icd10_display("A01.1", Icd10FormatStyle::CompactNoDecimal), "A011");
///
/// // Format with label
/// assert_eq!(to_icd10_display("E11.9", Icd10FormatStyle::Labeled), "ICD-10: E11.9");
/// ```
#[must_use]
pub fn to_icd10_display(code: &str, style: Icd10FormatStyle) -> String {
    let without_decimal: String = code.chars().filter(|c| *c != '.').collect();

    match style {
        Icd10FormatStyle::Compact => code.to_string(),
        Icd10FormatStyle::CompactNoDecimal => without_decimal,
        Icd10FormatStyle::Labeled => format!("ICD-10: {}", code),
        Icd10FormatStyle::LabeledNoDecimal => format!("ICD-10: {}", without_decimal),
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::expect_used)]
    use super::*;

    // ===== NPI Formatting Tests =====

    #[test]
    fn test_to_npi_display_plain() {
        assert_eq!(
            to_npi_display("1234567890", NpiFormatStyle::Plain),
            "1234567890"
        );
        assert_eq!(
            to_npi_display("NPI: 1234567890", NpiFormatStyle::Plain),
            "1234567890"
        );
        assert_eq!(
            to_npi_display("1234-567-890", NpiFormatStyle::Plain),
            "1234567890"
        );
    }

    #[test]
    fn test_to_npi_display_dashed() {
        assert_eq!(
            to_npi_display("1234567890", NpiFormatStyle::Dashed),
            "1234-567-890"
        );
        assert_eq!(
            to_npi_display("NPI: 1234567890", NpiFormatStyle::Dashed),
            "1234-567-890"
        );
    }

    #[test]
    fn test_to_npi_display_labeled() {
        assert_eq!(
            to_npi_display("1234567890", NpiFormatStyle::Labeled),
            "NPI: 1234567890"
        );
        assert_eq!(
            to_npi_display("1234-567-890", NpiFormatStyle::Labeled),
            "NPI: 1234567890"
        );
    }

    #[test]
    fn test_to_npi_display_labeled_dashed() {
        assert_eq!(
            to_npi_display("1234567890", NpiFormatStyle::LabeledDashed),
            "NPI: 1234-567-890"
        );
    }

    #[test]
    fn test_to_npi_display_invalid_length() {
        // Too short - returns as-is
        assert_eq!(to_npi_display("123", NpiFormatStyle::Dashed), "123");

        // Too long - returns as-is
        assert_eq!(
            to_npi_display("12345678901", NpiFormatStyle::Dashed),
            "12345678901"
        );
    }

    // ===== NPI Normalization Tests =====

    #[test]
    fn test_normalize_npi() {
        // Plain digits
        assert_eq!(normalize_npi("1234567890"), "1234567890");

        // With dashes
        assert_eq!(normalize_npi("1234-567-890"), "1234567890");

        // With label
        assert_eq!(normalize_npi("NPI: 1234567890"), "1234567890");

        // With label and dashes
        assert_eq!(normalize_npi("NPI: 1234-567-890"), "1234567890");

        // Invalid length - returns original
        assert_eq!(normalize_npi("12345"), "12345");
    }

    // ===== NPI Sanitization Tests =====

    #[test]
    fn test_sanitize_npi_valid() {
        // Valid NPI with formatting
        assert_eq!(
            sanitize_npi("NPI: 1245-319-599").expect("Should sanitize"),
            "1245319599"
        );

        // Plain valid NPI
        assert_eq!(
            sanitize_npi("1679576722").expect("Should sanitize"),
            "1679576722"
        );
    }

    #[test]
    fn test_sanitize_npi_invalid() {
        // Invalid checksum
        assert!(sanitize_npi("1234567890").is_err());

        // Too short
        assert!(sanitize_npi("123456789").is_err());

        // Too long
        assert!(sanitize_npi("12345678901").is_err());
    }

    // ===== NPI Checksum Tests =====

    #[test]
    fn test_validate_npi_checksum_valid() {
        // Valid NPI from CMS examples
        assert!(validate_npi_checksum("1245319599").is_ok());
        assert!(validate_npi_checksum("1679576722").is_ok());
    }

    #[test]
    fn test_validate_npi_checksum_invalid() {
        // Invalid checksum
        assert!(validate_npi_checksum("1234567890").is_err());
        assert!(validate_npi_checksum("1111111111").is_err());
    }

    #[test]
    fn test_validate_npi_checksum_with_formatting() {
        // Works with dashes
        assert!(validate_npi_checksum("1245-319-599").is_ok());

        // Works with label
        assert!(validate_npi_checksum("NPI: 1245319599").is_ok());

        // Works with both
        assert!(validate_npi_checksum("NPI: 1245-319-599").is_ok());
    }

    #[test]
    fn test_validate_npi_checksum_invalid_format() {
        // Too short
        assert!(validate_npi_checksum("123456789").is_err());

        // Too long
        assert!(validate_npi_checksum("12345678901").is_err());

        // Doesn't start with 1 or 2
        assert!(validate_npi_checksum("3234567890").is_err());

        // Empty
        assert!(validate_npi_checksum("").is_err());
    }

    // ===== ICD-10 Normalization Tests =====

    #[test]
    fn test_normalize_icd10_basic() {
        // Add decimal
        assert_eq!(
            normalize_icd10("A011").expect("Should normalize A011"),
            "A01.1"
        );

        // Already normalized
        assert_eq!(
            normalize_icd10("A01.1").expect("Should normalize A01.1"),
            "A01.1"
        );

        // No decimal needed (category level)
        assert_eq!(normalize_icd10("A01").expect("Should normalize A01"), "A01");
    }

    #[test]
    fn test_normalize_icd10_complex() {
        // Multiple subcategories
        assert_eq!(
            normalize_icd10("E119").expect("Should normalize E119"),
            "E11.9"
        );
        assert_eq!(
            normalize_icd10("S72341A").expect("Should normalize S72341A"),
            "S72.341A"
        );

        // With existing decimal
        assert_eq!(
            normalize_icd10("E11.9").expect("Should normalize E11.9"),
            "E11.9"
        );
        assert_eq!(
            normalize_icd10("S72.341A").expect("Should normalize S72.341A"),
            "S72.341A"
        );
    }

    #[test]
    fn test_normalize_icd10_with_labels() {
        assert_eq!(
            normalize_icd10("ICD-10: A01.1").expect("Should normalize ICD-10: A01.1"),
            "A01.1"
        );
        assert_eq!(
            normalize_icd10("ICD-10: E119").expect("Should normalize ICD-10: E119"),
            "E11.9"
        );
    }

    #[test]
    fn test_normalize_icd10_case_variations() {
        // Uppercase required
        assert!(normalize_icd10("a01.1").is_err());

        // Valid uppercase
        assert_eq!(
            normalize_icd10("A01.1").expect("Should normalize A01.1"),
            "A01.1"
        );
        assert_eq!(
            normalize_icd10("Z00.00").expect("Should normalize Z00.00"),
            "Z00.00"
        );
    }

    #[test]
    fn test_normalize_icd10_invalid() {
        // Empty
        assert!(normalize_icd10("").is_err());

        // Too short
        assert!(normalize_icd10("A1").is_err());

        // Invalid starting letter (U reserved)
        assert!(normalize_icd10("U01.1").is_err());

        // Too long
        assert!(normalize_icd10("A0123456").is_err());
    }

    // ===== ICD-10 Formatting Tests =====

    #[test]
    fn test_to_icd10_display_compact() {
        assert_eq!(
            to_icd10_display("A01.1", Icd10FormatStyle::Compact),
            "A01.1"
        );
        assert_eq!(
            to_icd10_display("E11.9", Icd10FormatStyle::Compact),
            "E11.9"
        );
    }

    #[test]
    fn test_to_icd10_display_compact_no_decimal() {
        assert_eq!(
            to_icd10_display("A01.1", Icd10FormatStyle::CompactNoDecimal),
            "A011"
        );
        assert_eq!(
            to_icd10_display("E11.9", Icd10FormatStyle::CompactNoDecimal),
            "E119"
        );
    }

    #[test]
    fn test_to_icd10_display_labeled() {
        assert_eq!(
            to_icd10_display("A01.1", Icd10FormatStyle::Labeled),
            "ICD-10: A01.1"
        );
    }

    #[test]
    fn test_to_icd10_display_labeled_no_decimal() {
        assert_eq!(
            to_icd10_display("E11.9", Icd10FormatStyle::LabeledNoDecimal),
            "ICD-10: E119"
        );
    }

    #[test]
    fn test_to_icd10_display_with_suffix() {
        assert_eq!(
            to_icd10_display("S72.341A", Icd10FormatStyle::Compact),
            "S72.341A"
        );
        assert_eq!(
            to_icd10_display("S72.341A", Icd10FormatStyle::CompactNoDecimal),
            "S72341A"
        );
    }
}
