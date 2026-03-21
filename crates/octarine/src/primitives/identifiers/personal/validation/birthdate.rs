//! Birthdate validation functions
//!
//! Validates birthdates in various formats with calendar validation.

use crate::primitives::Problem;
use crate::primitives::types::{
    get_current_year, is_leap_year, parse_eu_date, parse_iso_date, parse_us_date,
};

// ============================================================================
// Birthdate Validation
// ============================================================================

/// Validate birthdate format (returns Result)
///
/// Validates dates that could represent birthdates:
/// - Valid calendar date
/// - Not a future date
///
/// Note: This function does NOT enforce a minimum year. Historical dates
/// (e.g., 1850) are valid birthdates. Applications should implement their
/// own business logic for age limits if needed.
///
/// Supports formats: YYYY-MM-DD, MM/DD/YYYY, DD/MM/YYYY
///
/// # Examples
///
/// ```ignore
/// use crate::primitives::identifiers::personal::validation;
///
/// assert!(validation::validate_birthdate("1990-05-15").is_ok());
/// assert!(validation::validate_birthdate("05/15/1990").is_ok());
/// assert!(validation::validate_birthdate("1850-01-01").is_ok()); // Historical dates valid
/// assert!(validation::validate_birthdate("2099-01-01").is_err()); // Future dates invalid
/// ```
///
/// # Errors
///
/// Returns `Problem::validation` if:
/// - Date format is not recognized
/// - Date is invalid (e.g., Feb 30)
/// - Year is in the future
pub fn validate_birthdate(date: &str) -> Result<(), Problem> {
    let trimmed = date.trim();

    // Try to parse different formats
    // We try each format and validate it; if validation fails, try the next format
    let (year, month, day) = if let Some(parsed) = parse_iso_date(trimmed) {
        parsed
    } else if let Some(parsed) = parse_us_date(trimmed) {
        // US format: check if the parsed values are valid before accepting
        if parsed.1 <= 12 && parsed.2 <= 31 {
            parsed
        } else if let Some(eu_parsed) = parse_eu_date(trimmed) {
            eu_parsed
        } else {
            parsed // Return US and let validation fail with proper error
        }
    } else if let Some(parsed) = parse_eu_date(trimmed) {
        parsed
    } else {
        return Err(Problem::Validation("Invalid date format".into()));
    };

    // Validate not in the future
    let current_year = get_current_year();
    if year > current_year {
        return Err(Problem::Validation(
            "Birth year cannot be in the future".into(),
        ));
    }

    // Validate month
    if !(1..=12).contains(&month) {
        return Err(Problem::Validation("Invalid month".into()));
    }

    // Validate day based on month
    let days_in_month = match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 => {
            if is_leap_year(year) {
                29
            } else {
                28
            }
        }
        _ => return Err(Problem::Validation("Invalid month".into())),
    };

    if day < 1 || day > days_in_month {
        return Err(Problem::Validation("Invalid day for month".into()));
    }

    Ok(())
}

// ============================================================================
// Test Pattern Detection
// ============================================================================

/// Check if a birthdate is a known test/sample pattern
///
/// Test birthdates are commonly used in documentation, testing, and examples.
/// A "test birthdate" is one that:
/// 1. Is a valid date format (ISO, US, or EU)
/// 2. Is in the past (not a future date)
/// 3. Matches common placeholder patterns like 1/1/1970, 1/1/2000
///
/// # Examples
///
/// ```ignore
/// use crate::primitives::identifiers::personal::validation;
///
/// // Common test dates
/// assert!(validation::is_test_birthdate("1970-01-01")); // Unix epoch
/// assert!(validation::is_test_birthdate("2000-01-01")); // Y2K
/// assert!(validation::is_test_birthdate("1990-01-01")); // Common placeholder
///
/// // Real-looking birthdates (not test patterns)
/// assert!(!validation::is_test_birthdate("1985-07-23"));
/// assert!(!validation::is_test_birthdate("1992-11-15"));
///
/// // Invalid dates return false
/// assert!(!validation::is_test_birthdate("invalid"));
/// assert!(!validation::is_test_birthdate("2099-01-01")); // Future date
/// ```
#[must_use]
pub fn is_test_birthdate(date: &str) -> bool {
    let trimmed = date.trim();

    // First, try to parse the date in any supported format
    let (year, month, day) = if let Some(parsed) = parse_iso_date(trimmed) {
        parsed
    } else if let Some(parsed) = parse_us_date(trimmed) {
        // US format: validate before accepting
        if parsed.1 <= 12 && parsed.2 <= 31 {
            parsed
        } else if let Some(eu_parsed) = parse_eu_date(trimmed) {
            eu_parsed
        } else {
            return false; // Invalid format
        }
    } else if let Some(parsed) = parse_eu_date(trimmed) {
        parsed
    } else {
        return false; // Invalid format
    };

    // Must not be a future date
    let current_year = get_current_year();
    if year > current_year {
        return false; // Future date
    }

    // Validate month and day
    if !(1..=12).contains(&month) {
        return false;
    }

    let days_in_month = match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 => {
            if is_leap_year(year) {
                29
            } else {
                28
            }
        }
        _ => return false,
    };

    if day < 1 || day > days_in_month {
        return false;
    }

    // Check for well-known test/placeholder dates
    let test_dates = [
        (1970, 1, 1),   // Unix epoch
        (2000, 1, 1),   // Y2K / Millennium
        (1990, 1, 1),   // Common test year
        (1980, 1, 1),   // Common test year
        (1999, 12, 31), // Pre-Y2K
        (2001, 1, 1),   // Post-Y2K
        (1900, 1, 1),   // Century boundary
        (2000, 12, 31), // End of Y2K
        (1988, 8, 8),   // Lucky date (8/8/88)
        (1999, 9, 9),   // 9/9/99
        (2011, 11, 11), // 11/11/11
        (2020, 2, 20),  // 2/20/2020
        (2022, 2, 22),  // 2/22/2022
    ];

    if test_dates.contains(&(year, month, day)) {
        return true;
    }

    // Check for dates with all same digits in day/month (like 01/01, 11/11, 12/12)
    // These are often used as placeholders
    if month == day && (month == 1 || month == 11 || month == 12) {
        // Additional check: common test years
        if matches!(year, 1970 | 1980 | 1990 | 2000 | 2010 | 2020) {
            return true;
        }
    }

    // Check for first day of any year (often used as placeholder)
    if month == 1 && day == 1 {
        // Round years are often test dates
        if year % 10 == 0 {
            return true;
        }
    }

    false
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::expect_used)]
    use super::*;

    #[test]
    fn test_birthdate_validation() {
        // Valid dates
        assert!(validate_birthdate("1990-05-15").is_ok()); // ISO
        assert!(validate_birthdate("05/15/1990").is_ok()); // US
        assert!(validate_birthdate("2000-01-01").is_ok()); // Y2K
        assert!(validate_birthdate("1900-01-01").is_ok()); // Historical

        // Historical dates are now valid (no minimum year enforced)
        assert!(validate_birthdate("1899-12-31").is_ok());
        assert!(validate_birthdate("1800-01-01").is_ok());

        // Invalid - future
        assert!(validate_birthdate("2099-01-01").is_err());
        assert!(validate_birthdate("2030-01-01").is_err());

        // Invalid - bad format
        assert!(validate_birthdate("invalid").is_err());
        assert!(validate_birthdate("1990/05/15").is_err()); // Wrong separator for ISO
        assert!(validate_birthdate("05-15-1990").is_err()); // Wrong separator for US

        // Invalid - bad dates
        assert!(validate_birthdate("1990-13-01").is_err()); // Month 13
        assert!(validate_birthdate("1990-02-30").is_err()); // Feb 30
        assert!(validate_birthdate("1990-04-31").is_err()); // April 31
    }

    #[test]
    fn test_birthdate_leap_year() {
        // Leap year Feb 29
        assert!(validate_birthdate("2000-02-29").is_ok()); // Divisible by 400
        assert!(validate_birthdate("2004-02-29").is_ok()); // Divisible by 4

        // Non-leap year Feb 29
        assert!(validate_birthdate("1900-02-29").is_err()); // Divisible by 100 but not 400
        assert!(validate_birthdate("2001-02-29").is_err()); // Not divisible by 4
    }

    #[test]
    fn test_birthdate_validation_errors() {
        assert!(validate_birthdate("1990-05-15").is_ok());

        let err = validate_birthdate("2099-01-01").expect_err("should fail for future");
        assert!(err.to_string().contains("future"));

        let err = validate_birthdate("1990-02-30").expect_err("should fail for invalid day");
        assert!(err.to_string().contains("day"));
    }

    #[test]
    fn test_birthdate_eu_format() {
        // EU format (day > 12 disambiguates)
        assert!(validate_birthdate("15/05/1990").is_ok()); // 15th of May
        assert!(validate_birthdate("31/12/1990").is_ok()); // 31st of December
    }

    #[test]
    fn test_birthdate_edge_cases() {
        // Empty and whitespace
        assert!(validate_birthdate("").is_err());
        assert!(validate_birthdate("   ").is_err());

        // Historical dates are valid (no minimum year)
        assert!(validate_birthdate("1900-01-01").is_ok());
        assert!(validate_birthdate("1850-01-01").is_ok()); // Historical date valid

        // Current year should be valid
        let current_year = get_current_year();
        let current_year_date = format!("{}-12-31", current_year);
        assert!(validate_birthdate(&current_year_date).is_ok());

        // Future year should be invalid
        let future_year_date = format!("{}-01-01", current_year + 1);
        assert!(validate_birthdate(&future_year_date).is_err());

        // Month boundaries
        assert!(validate_birthdate("1990-01-31").is_ok()); // Jan 31
        assert!(validate_birthdate("1990-12-31").is_ok()); // Dec 31
        assert!(validate_birthdate("1990-00-15").is_err()); // Month 0
        assert!(validate_birthdate("1990-13-15").is_err()); // Month 13

        // Day boundaries
        assert!(validate_birthdate("1990-01-00").is_err()); // Day 0
        assert!(validate_birthdate("1990-01-32").is_err()); // Day 32
        assert!(validate_birthdate("1990-06-31").is_err()); // June 31 (invalid)
    }

    #[test]
    fn test_is_test_birthdate_known_patterns() {
        // Well-known test dates
        assert!(is_test_birthdate("1970-01-01")); // Unix epoch
        assert!(is_test_birthdate("2000-01-01")); // Y2K
        assert!(is_test_birthdate("1990-01-01")); // Common placeholder
        assert!(is_test_birthdate("1980-01-01")); // Common placeholder
        assert!(is_test_birthdate("1999-12-31")); // Pre-Y2K
        assert!(is_test_birthdate("1900-01-01")); // Century boundary
    }

    #[test]
    fn test_is_test_birthdate_special_dates() {
        // Lucky/memorable dates
        assert!(is_test_birthdate("1988-08-08")); // 8/8/88
        assert!(is_test_birthdate("1999-09-09")); // 9/9/99
        assert!(is_test_birthdate("2011-11-11")); // 11/11/11
        assert!(is_test_birthdate("2022-02-22")); // 2/22/2022
    }

    #[test]
    fn test_is_test_birthdate_round_years() {
        // First day of round years
        assert!(is_test_birthdate("1950-01-01"));
        assert!(is_test_birthdate("1960-01-01"));
        assert!(is_test_birthdate("2010-01-01"));
        assert!(is_test_birthdate("2020-01-01"));
    }

    #[test]
    fn test_is_test_birthdate_not_test_patterns() {
        // Real-looking birthdates (not test patterns)
        assert!(!is_test_birthdate("1985-07-23"));
        assert!(!is_test_birthdate("1992-11-15"));
        assert!(!is_test_birthdate("1978-03-12"));
        assert!(!is_test_birthdate("2003-05-29"));
    }

    #[test]
    fn test_is_test_birthdate_us_format() {
        // US format (MM/DD/YYYY)
        assert!(is_test_birthdate("01/01/1970")); // Unix epoch
        assert!(is_test_birthdate("01/01/2000")); // Y2K
        assert!(!is_test_birthdate("07/23/1985")); // Not a test pattern
    }

    #[test]
    fn test_is_test_birthdate_invalid_dates() {
        // Invalid formats should return false
        assert!(!is_test_birthdate("invalid"));
        assert!(!is_test_birthdate(""));
        assert!(!is_test_birthdate("2099-01-01")); // Future date
        assert!(!is_test_birthdate("1990-13-01")); // Invalid month
        assert!(!is_test_birthdate("1990-02-30")); // Invalid day

        // Historical dates are valid but not test patterns unless they match known patterns
        assert!(!is_test_birthdate("1823-07-15")); // Historical but not a test pattern
    }
}
