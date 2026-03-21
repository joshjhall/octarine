//! Personal identifier conversion primitives
//!
//! Pure conversion functions for personal identifiers (phone, email).
//! Follows detection-first pattern: validate format before transformation.
//!
//! ## Design Principles
//!
//! 1. **No Logging**: Pure functions, no trace/debug calls
//! 2. **No Side Effects**: Only format transformations
//! 3. **Detection-First**: Validate with detection layer before conversion
//! 4. **Reusable**: Used by observe/pii and security modules

use super::super::common::masking;
use crate::primitives::Problem;
use crate::primitives::types::{parse_eu_date, parse_iso_date, parse_us_date};

use super::detection;

// ============================================================================
// Age Calculation
// ============================================================================

/// Calculate age from birthdate string
///
/// Calculates the age in years based on a birthdate and the current system date.
/// Validates format using detection layer before parsing.
///
/// # Arguments
///
/// * `birthdate` - Date string in ISO (YYYY-MM-DD), US (MM/DD/YYYY), or EU (DD/MM/YYYY) format
///
/// # Returns
///
/// Age in years, or error if date cannot be parsed or is invalid.
///
/// # Examples
///
/// ```ignore
/// use crate::primitives::identifiers::personal::conversion;
///
/// // For someone born in 1990, age will vary based on current date
/// let age = conversion::calculate_age("1990-05-15").unwrap();
/// assert!(age >= 34 && age <= 35); // Depends on current date
/// ```
pub fn calculate_age(birthdate: &str) -> Result<u32, Problem> {
    let trimmed = birthdate.trim();

    // Validate format first using detection layer
    if !detection::is_birthdate(trimmed) {
        return Err(Problem::conversion("Invalid birthdate format"));
    }

    // Parse the date using shared date parsing functions
    // Try EU format first for dates where first number > 12 (unambiguously day)
    let (year, month, day) = if let Some(parsed) = parse_iso_date(trimmed) {
        parsed
    } else if let Some(parsed) = parse_eu_date(trimmed) {
        // EU format is tried first to catch day > 12 cases
        parsed
    } else if let Some(parsed) = parse_us_date(trimmed) {
        parsed
    } else {
        return Err(Problem::conversion("Cannot parse date format"));
    };

    // Get current date for age calculation
    use chrono::Datelike;
    let now = chrono::Utc::now();
    let current_year = now.year() as u32;
    let current_month = now.month();
    let current_day = now.day();

    if year > current_year {
        return Err(Problem::conversion("Birthdate cannot be in the future"));
    }

    if year < 1900 {
        return Err(Problem::conversion("Birth year too old"));
    }

    // Calculate age
    let mut age = current_year.saturating_sub(year);

    // Adjust if birthday hasn't occurred yet this year
    if month > current_month || (month == current_month && day > current_day) {
        age = age.saturating_sub(1);
    }

    Ok(age)
}

// Note: Date parsing helper functions moved to primitives/common/dates.rs
// and imported at top of file. This includes:
// - parse_iso_date(), parse_us_date(), parse_eu_date()
// These are shared across all identifier modules for consistent date handling.

/// Phone number display format styles
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PhoneFormatStyle {
    /// E.164 international format: +15551234567
    E164,
    /// National format: (555) 123-4567
    National,
    /// International format: +1 (555) 123-4567
    International,
}

// ============================================================================
// Phone Normalization
// ============================================================================

/// Normalize phone to E.164 format (+15551234567)
///
/// Converts various phone number formats to E.164 standard.
/// Validates format using detection layer before conversion.
///
/// # Arguments
///
/// * `phone` - Phone number in any format
/// * `default_country` - Country code to use if not present (e.g., "US")
///
/// # Examples
///
/// ```ignore
/// use crate::primitives::identifiers::personal::conversion;
///
/// let result = conversion::normalize_phone_e164("5551234567", "US");
/// assert_eq!(result.unwrap(), "+15551234567");
/// ```
pub fn normalize_phone_e164(phone: &str, default_country: &str) -> Result<String, Problem> {
    // Validate phone format first using detection layer
    if !detection::is_phone_number(phone) {
        return Err(Problem::conversion("Invalid phone number format"));
    }

    let digits_only = masking::digits_only(phone);

    // Already has country code
    if phone.starts_with('+') {
        return Ok(format!("+{digits_only}"));
    }

    // US phone number assumption
    if default_country == "US" && digits_only.len() == 10 {
        return Ok(format!("+1{digits_only}"));
    }

    // Check if it's already 11 digits with US country code
    if digits_only.len() == 11 && digits_only.starts_with('1') {
        return Ok(format!("+{digits_only}"));
    }

    Err(Problem::conversion("Cannot determine country code"))
}

/// Format phone for display
///
/// Formats phone numbers for human-readable display.
///
/// # Examples
///
/// ```ignore
/// use crate::primitives::identifiers::personal::conversion::{to_phone_display, PhoneFormatStyle};
///
/// assert_eq!(
///     to_phone_display("5551234567", PhoneFormatStyle::National),
///     "(555) 123-4567"
/// );
/// ```
#[must_use]
pub fn to_phone_display(phone: &str, style: PhoneFormatStyle) -> String {
    let digits_only = masking::digits_only(phone);

    match style {
        PhoneFormatStyle::International => {
            if digits_only.len() == 11 && digits_only.starts_with('1') {
                // US number with country code
                format!(
                    "+1 ({}) {}-{}",
                    &digits_only[1..4],
                    &digits_only[4..7],
                    &digits_only[7..11]
                )
            } else if digits_only.len() == 10 {
                // US number without country code
                format!(
                    "({}) {}-{}",
                    &digits_only[0..3],
                    &digits_only[3..6],
                    &digits_only[6..10]
                )
            } else {
                phone.to_string()
            }
        }
        PhoneFormatStyle::National => {
            if digits_only.len() >= 10 {
                let start: usize = if digits_only.starts_with('1') { 1 } else { 0 };
                format!(
                    "({}) {}-{}",
                    &digits_only[start..start.saturating_add(3)],
                    &digits_only[start.saturating_add(3)..start.saturating_add(6)],
                    &digits_only[start.saturating_add(6)..start.saturating_add(10)]
                )
            } else {
                phone.to_string()
            }
        }
        PhoneFormatStyle::E164 => {
            if digits_only.len() == 10 {
                format!("+1{digits_only}")
            } else if digits_only.len() == 11 && digits_only.starts_with('1') {
                format!("+{digits_only}")
            } else {
                phone.to_string()
            }
        }
    }
}

// ============================================================================
// Email Normalization
// ============================================================================

/// Normalize email address (lowercase, trim)
///
/// Converts email to lowercase and normalizes Gmail addresses.
/// Validates format using detection layer before conversion.
///
/// # Gmail Special Handling
///
/// - Removes dots from local part
/// - Removes +alias suffixes
/// - Converts googlemail.com to gmail.com
///
/// # Examples
///
/// ```ignore
/// use crate::primitives::identifiers::personal::conversion;
///
/// let result = conversion::normalize_email("User@Example.COM");
/// assert_eq!(result.unwrap(), "user@example.com");
///
/// let result = conversion::normalize_email("user.name+tag@gmail.com");
/// assert_eq!(result.unwrap(), "username@gmail.com");
/// ```
pub fn normalize_email(email: &str) -> Result<String, Problem> {
    let trimmed = email.trim();

    // Validate email format first using detection layer
    if !detection::is_email(trimmed) {
        return Err(Problem::conversion("Invalid email format"));
    }

    // Safe to split: detection layer validated @ exists and is valid
    let parts: Vec<&str> = trimmed.split('@').collect();
    #[allow(clippy::expect_used)]
    // Email validated by detection layer, guaranteed to have @ and both parts
    let local = parts
        .first()
        .expect("BUG: validated email must have local part")
        .to_lowercase();
    #[allow(clippy::expect_used)]
    let domain = parts
        .get(1)
        .expect("BUG: validated email must have domain part")
        .to_lowercase();

    // Gmail special handling - remove dots and +alias
    if domain == "gmail.com" || domain == "googlemail.com" {
        let clean_local = local.split('+').next().unwrap_or(&local).replace('.', "");
        Ok(format!("{clean_local}@gmail.com"))
    } else {
        Ok(format!("{local}@{domain}"))
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::expect_used)]
    use super::*;
    use chrono::Datelike;

    // ===== Phone E.164 Normalization Tests =====

    #[test]
    fn test_normalize_phone_e164() {
        // US 10-digit
        let result =
            normalize_phone_e164("5551234567", "US").expect("should normalize 10-digit US phone");
        assert_eq!(result, "+15551234567");

        // Already E.164
        let result =
            normalize_phone_e164("+15551234567", "US").expect("should preserve E.164 format");
        assert_eq!(result, "+15551234567");

        // 11-digit with leading 1
        let result = normalize_phone_e164("15551234567", "US")
            .expect("should normalize 11-digit with leading 1");
        assert_eq!(result, "+15551234567");

        // Invalid (fails detection - too short)
        let err = normalize_phone_e164("12345", "US").expect_err("should fail for short phone");
        assert!(err.to_string().contains("Invalid phone"));
    }

    // ===== Phone Display Format Tests =====

    #[test]
    fn test_to_phone_display_national() {
        assert_eq!(
            to_phone_display("5551234567", PhoneFormatStyle::National),
            "(555) 123-4567"
        );
        assert_eq!(
            to_phone_display("15551234567", PhoneFormatStyle::National),
            "(555) 123-4567"
        );
    }

    #[test]
    fn test_to_phone_display_international() {
        assert_eq!(
            to_phone_display("15551234567", PhoneFormatStyle::International),
            "+1 (555) 123-4567"
        );
        assert_eq!(
            to_phone_display("5551234567", PhoneFormatStyle::International),
            "(555) 123-4567"
        );
    }

    #[test]
    fn test_to_phone_display_e164() {
        assert_eq!(
            to_phone_display("5551234567", PhoneFormatStyle::E164),
            "+15551234567"
        );
        assert_eq!(
            to_phone_display("15551234567", PhoneFormatStyle::E164),
            "+15551234567"
        );
    }

    #[test]
    fn test_to_phone_display_invalid() {
        // Too short - returns as-is
        assert_eq!(
            to_phone_display("12345", PhoneFormatStyle::National),
            "12345"
        );
    }

    // ===== Email Normalization Tests =====

    #[test]
    fn test_normalize_email_basic() {
        let result = normalize_email("User@Example.COM").expect("should normalize basic email");
        assert_eq!(result, "user@example.com");
    }

    #[test]
    fn test_normalize_email_gmail_dots() {
        let result = normalize_email("user.name@gmail.com").expect("should remove dots from gmail");
        assert_eq!(result, "username@gmail.com");
    }

    #[test]
    fn test_normalize_email_gmail_plus() {
        let result =
            normalize_email("user+tag@gmail.com").expect("should remove +alias from gmail");
        assert_eq!(result, "user@gmail.com");
    }

    #[test]
    fn test_normalize_email_googlemail() {
        let result =
            normalize_email("user@googlemail.com").expect("should convert googlemail to gmail");
        assert_eq!(result, "user@gmail.com");
    }

    #[test]
    fn test_normalize_email_preserves_non_gmail() {
        let result =
            normalize_email("user.name+tag@example.com").expect("should preserve non-gmail format");
        assert_eq!(result, "user.name+tag@example.com");
    }

    #[test]
    fn test_normalize_email_invalid() {
        let err = normalize_email("invalid").expect_err("should fail for invalid email");
        assert!(err.to_string().contains("Invalid email"));

        let err = normalize_email("a@b@c").expect_err("should fail for multiple @ signs");
        assert!(err.to_string().contains("Invalid email"));
    }

    #[test]
    fn test_normalize_email_trim() {
        let result = normalize_email("  user@example.com  ").expect("should trim whitespace");
        assert_eq!(result, "user@example.com");
    }

    // ===== Edge Case Tests =====

    #[test]
    fn test_phone_format_edge_cases() {
        // Empty and short phones
        assert_eq!(to_phone_display("", PhoneFormatStyle::National), "");
        assert_eq!(to_phone_display("123", PhoneFormatStyle::National), "123");

        // Exactly 10 digits
        assert_eq!(
            to_phone_display("5551234567", PhoneFormatStyle::E164),
            "+15551234567"
        );

        // Exactly 11 digits with leading 1
        assert_eq!(
            to_phone_display("15551234567", PhoneFormatStyle::E164),
            "+15551234567"
        );

        // With various separators
        assert_eq!(
            to_phone_display("(555) 123-4567", PhoneFormatStyle::National),
            "(555) 123-4567"
        );
        assert_eq!(
            to_phone_display("555.123.4567", PhoneFormatStyle::National),
            "(555) 123-4567"
        );
    }

    #[test]
    fn test_phone_normalization_edge_cases() {
        // Already has + prefix
        let result = normalize_phone_e164("+15551234567", "US").expect("should handle + prefix");
        assert_eq!(result, "+15551234567");

        // With leading 1 (11 digits)
        let result = normalize_phone_e164("15551234567", "US").expect("should handle 11 digits");
        assert_eq!(result, "+15551234567");

        // Non-US country (currently limited - detection still passes for valid phone)
        let err = normalize_phone_e164("5551234567", "UK").expect_err("should fail for non-US");
        assert!(err.to_string().contains("country code"));

        // Too few digits (fails detection)
        let err = normalize_phone_e164("12345", "US").expect_err("should fail for short");
        assert!(err.to_string().contains("Invalid phone"));

        // Various separators should be stripped
        let result = normalize_phone_e164("(555) 123-4567", "US").expect("should strip separators");
        assert_eq!(result, "+15551234567");
    }

    #[test]
    fn test_email_normalization_edge_cases() {
        // All caps
        let result = normalize_email("USER@EXAMPLE.COM").expect("should lowercase all caps");
        assert_eq!(result, "user@example.com");

        // Mixed case
        let result = normalize_email("UsEr@ExAmPlE.CoM").expect("should lowercase mixed");
        assert_eq!(result, "user@example.com");

        // Gmail with multiple dots
        let result = normalize_email("u.s.e.r@gmail.com").expect("should remove all dots");
        assert_eq!(result, "user@gmail.com");

        // Gmail with dots and plus
        let result = normalize_email("u.s.e.r+tag@gmail.com").expect("should handle both");
        assert_eq!(result, "user@gmail.com");

        // Plus with empty tag
        let result = normalize_email("user+@gmail.com").expect("should handle empty tag");
        assert_eq!(result, "user@gmail.com");

        // Multiple @ signs
        let err = normalize_email("user@domain@extra.com").expect_err("should fail for multiple @");
        assert!(err.to_string().contains("Invalid email"));

        // No @ sign
        let err = normalize_email("userexample.com").expect_err("should fail for no @");
        assert!(err.to_string().contains("Invalid email"));

        // Only @
        let err = normalize_email("@").expect_err("should fail for only @");
        assert!(err.to_string().contains("Invalid email"));
    }

    #[test]
    fn test_gmail_variations() {
        // googlemail.com → gmail.com
        let result = normalize_email("user@googlemail.com").expect("should convert googlemail");
        assert_eq!(result, "user@gmail.com");

        // Preserve non-gmail
        let result = normalize_email("user.name+tag@outlook.com").expect("should preserve outlook");
        assert_eq!(result, "user.name+tag@outlook.com");

        // Edge case: domain containing gmail but not being gmail
        let result = normalize_email("user@notgmail.com").expect("should not convert");
        assert_eq!(result, "user@notgmail.com");
    }

    #[test]
    fn test_phone_format_styles_comprehensive() {
        let phone = "5551234567";

        // E164
        assert_eq!(
            to_phone_display(phone, PhoneFormatStyle::E164),
            "+15551234567"
        );

        // National
        assert_eq!(
            to_phone_display(phone, PhoneFormatStyle::National),
            "(555) 123-4567"
        );

        // International
        assert_eq!(
            to_phone_display(phone, PhoneFormatStyle::International),
            "(555) 123-4567"
        );

        // 11 digit with leading 1
        let phone11 = "15551234567";
        assert_eq!(
            to_phone_display(phone11, PhoneFormatStyle::International),
            "+1 (555) 123-4567"
        );
    }

    #[test]
    fn test_empty_inputs() {
        // Empty phone
        assert_eq!(to_phone_display("", PhoneFormatStyle::E164), "");

        // Empty email
        let err = normalize_email("").expect_err("should fail for empty");
        assert!(err.to_string().contains("Invalid email"));

        // Whitespace only
        let err = normalize_email("   ").expect_err("should fail for whitespace");
        assert!(err.to_string().contains("Invalid email"));
    }

    // ===== Age Calculation Tests =====

    #[test]
    fn test_calculate_age_iso_format() {
        let now = chrono::Utc::now();
        let current_year = now.year() as u32;

        // Test with someone born in 1990
        let age = calculate_age("1990-05-15").expect("should calculate age");
        assert!(
            (34..=35).contains(&age),
            "Age should be 34 or 35 for someone born in 1990"
        );

        // Test with someone born in 2000
        let age = calculate_age("2000-01-01").expect("should calculate age");
        let expected_age = current_year - 2000;
        assert!(
            (expected_age - 1..=expected_age).contains(&age),
            "Age calculation should be accurate"
        );
    }

    #[test]
    fn test_calculate_age_us_format() {
        // Test with someone born in 1990
        let age = calculate_age("05/15/1990").expect("should calculate age from US format");
        assert!(
            (34..=35).contains(&age),
            "Age should be 34 or 35 for someone born in 1990"
        );
    }

    #[test]
    fn test_calculate_age_eu_format() {
        // EU format: day/month/year (day > 12 to disambiguate)
        let age = calculate_age("15/05/1990").expect("should calculate age from EU format");
        assert!(
            (34..=35).contains(&age),
            "Age should be 34 or 35 for someone born in 1990"
        );
    }

    #[test]
    fn test_calculate_age_edge_cases() {
        let now = chrono::Utc::now();
        let current_year = now.year() as u32;

        // Minimum age (just born this year)
        let current_year_date = format!("{}-01-01", current_year);
        let age = calculate_age(&current_year_date).expect("should calculate age");
        assert_eq!(age, 0, "Someone born this year should be 0 years old");

        // Old but valid
        let age = calculate_age("1900-01-01").expect("should calculate age");
        let expected_age = current_year - 1900;
        assert!(
            (expected_age - 1..=expected_age).contains(&age),
            "Age calculation for 1900 should be accurate"
        );

        // Too old (rejected by detection layer for year < 1900)
        let err = calculate_age("1899-12-31").expect_err("should fail for too old");
        assert!(
            err.to_string().contains("Invalid birthdate") || err.to_string().contains("too old")
        );

        // Future date
        let future_year = current_year + 1;
        let future_date = format!("{}-01-01", future_year);
        let err = calculate_age(&future_date).expect_err("should fail for future");
        assert!(err.to_string().contains("future"));

        // Invalid format (rejected by detection layer)
        let err = calculate_age("invalid").expect_err("should fail for invalid");
        assert!(err.to_string().contains("Invalid birthdate") || err.to_string().contains("parse"));
    }

    #[test]
    fn test_calculate_age_birthday_boundary() {
        use chrono::Datelike;
        let current_year = chrono::Utc::now().year() as u32;

        // Test with date in the past (will always have had birthday on Jan 1)
        let age = calculate_age("1990-01-01").expect("should calculate age");
        let expected_age = current_year - 1990;
        assert!(
            ((expected_age - 1)..=(expected_age)).contains(&age),
            "Age should be {} or {}, got {}",
            expected_age - 1,
            expected_age,
            age
        );

        // Test with date far in future of year (December) - birthday may not have occurred
        let age = calculate_age("1990-12-31").expect("should calculate age");
        let expected_age_dec = current_year - 1990 - 1; // Usually one less since Dec 31 hasn't happened
        assert!(
            ((expected_age_dec - 1)..=(expected_age_dec + 1)).contains(&age),
            "Age should account for birthday occurrence, got {}",
            age
        );
    }
}
