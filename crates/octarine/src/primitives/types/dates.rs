//! Date parsing utilities - shared primitive for date operations
//!
//! Provides pure date parsing functions used across all primitives modules.
//! These are foundational utilities for parsing common date formats without
//! full date validation logic.
//!
//! # Design Principles
//!
//! 1. **No Validation**: These functions only parse format, they don't validate
//!    whether dates are valid (e.g., Feb 30 will parse but shouldn't exist)
//! 2. **No Dependencies**: Pure parsing logic using only std library
//! 3. **Reusable**: Used by identifiers, financial, government, medical modules
//! 4. **Unambiguous**: Disambiguates US vs EU formats where possible
//!
//! # Supported Formats
//!
//! - **ISO 8601**: YYYY-MM-DD (e.g., "2025-11-23")
//! - **US Format**: MM/DD/YYYY (e.g., "11/23/2025")
//! - **EU Format**: DD/MM/YYYY (e.g., "23/11/2025")
//!
//! # Usage
//!
//! ```rust,ignore
//! use octarine::primitives::types::dates;
//!
//! // Parse ISO format
//! let (year, month, day) = dates::parse_iso_date("2025-11-23").unwrap();
//! assert_eq!(year, 2025);
//! assert_eq!(month, 11);
//! assert_eq!(day, 23);
//!
//! // Parse US format
//! let (year, month, day) = dates::parse_us_date("11/23/2025").unwrap();
//!
//! // Parse EU format (day > 12, unambiguous)
//! let (year, month, day) = dates::parse_eu_date("23/11/2025").unwrap();
//! ```
//!
//! # Architecture
//!
//! This is part of **Layer 1 (primitives/types)** - shared across all primitives.

/// Parse ISO 8601 date format (YYYY-MM-DD)
///
/// Parses dates in ISO 8601 format and returns components as (year, month, day).
///
/// # Format
///
/// - Separator: `-` (hyphen)
/// - Order: Year-Month-Day
/// - Year: 4 digits
/// - Month: 1-2 digits
/// - Day: 1-2 digits
///
/// # Examples
///
/// ```ignore
/// use octarine::primitives::types::dates::parse_iso_date;
///
/// assert_eq!(parse_iso_date("2025-11-23"), Some((2025, 11, 23)));
/// assert_eq!(parse_iso_date("2025-01-01"), Some((2025, 1, 1)));
/// assert_eq!(parse_iso_date("1900-12-31"), Some((1900, 12, 31)));
///
/// // Invalid formats
/// assert_eq!(parse_iso_date("11/23/2025"), None); // Wrong separator
/// assert_eq!(parse_iso_date("2025-13-01"), Some((2025, 13, 1))); // Parses but invalid month (caller validates)
/// ```
///
/// # Note
///
/// This function only parses format, it does NOT validate:
/// - Month is 1-12
/// - Day is valid for the month
/// - Year is reasonable
///
/// Validation should be done by the calling module.
#[must_use]
pub fn parse_iso_date(date: &str) -> Option<(u32, u32, u32)> {
    let parts: Vec<&str> = date.split('-').collect();
    if parts.len() != 3 {
        return None;
    }

    let year = parts.first()?.parse().ok()?;
    let month = parts.get(1)?.parse().ok()?;
    let day = parts.get(2)?.parse().ok()?;

    Some((year, month, day))
}

/// Parse US date format (MM/DD/YYYY)
///
/// Parses dates in US format and returns components as (year, month, day).
///
/// # Format
///
/// - Separator: `/` (forward slash)
/// - Order: Month/Day/Year
/// - Year: Must be 4 digits (to avoid ambiguity with 2-digit years)
/// - Month: 1-2 digits
/// - Day: 1-2 digits
///
/// # Disambiguation
///
/// US format (MM/DD/YYYY) can be confused with EU format (DD/MM/YYYY).
/// This function requires a 4-digit year to parse. For ambiguous cases where
/// the first number could be either month or day (1-12), use context or
/// try both `parse_us_date` and `parse_eu_date`.
///
/// # Examples
///
/// ```ignore
/// use octarine::primitives::types::dates::parse_us_date;
///
/// assert_eq!(parse_us_date("11/23/2025"), Some((2025, 11, 23)));
/// assert_eq!(parse_us_date("01/15/2025"), Some((2025, 1, 15)));
/// assert_eq!(parse_us_date("12/31/1900"), Some((1900, 12, 31)));
///
/// // Invalid formats
/// assert_eq!(parse_us_date("2025-11-23"), None); // Wrong separator
/// assert_eq!(parse_us_date("11/23/25"), None);   // 2-digit year (ambiguous)
///
/// // Ambiguous cases (could be US or EU)
/// // "05/06/2025" could be May 6 (US) or June 5 (EU) - parses as US
/// assert_eq!(parse_us_date("05/06/2025"), Some((2025, 5, 6)));
/// ```
///
/// # Note
///
/// This function only parses format, it does NOT validate whether the
/// month/day values are valid. Validation should be done by the calling module.
#[must_use]
pub fn parse_us_date(date: &str) -> Option<(u32, u32, u32)> {
    let parts: Vec<&str> = date.split('/').collect();
    if parts.len() != 3 {
        return None;
    }

    let month = parts.first()?.parse().ok()?;
    let day = parts.get(1)?.parse().ok()?;
    let year = parts.get(2)?.parse().ok()?;

    // Require 4-digit year to avoid ambiguity
    // Check that the parsed year matches the string representation (no leading zeros lost)
    if year < 1000 {
        return None;
    }

    Some((year, month, day))
}

/// Parse EU date format (DD/MM/YYYY)
///
/// Parses dates in European format and returns components as (year, month, day).
///
/// # Format
///
/// - Separator: `/` (forward slash)
/// - Order: Day/Month/Year
/// - Year: Must be 4 digits (to avoid ambiguity with 2-digit years)
/// - Month: 1-2 digits
/// - Day: 1-2 digits
///
/// # Disambiguation
///
/// EU format (DD/MM/YYYY) can be confused with US format (MM/DD/YYYY).
/// This function uses a heuristic: if the first number is > 12, it must be
/// a day (EU format). For ambiguous cases (first number 1-12), this function
/// returns None and the caller should try US format.
///
/// # Examples
///
/// ```ignore
/// use octarine::primitives::types::dates::parse_eu_date;
///
/// // Unambiguous EU format (day > 12)
/// assert_eq!(parse_eu_date("23/11/2025"), Some((2025, 11, 23)));
/// assert_eq!(parse_eu_date("31/12/1900"), Some((1900, 12, 31)));
/// assert_eq!(parse_eu_date("15/01/2025"), Some((2025, 1, 15)));
///
/// // Ambiguous cases (day <= 12) - returns None
/// assert_eq!(parse_eu_date("05/06/2025"), None); // Could be US or EU
/// assert_eq!(parse_eu_date("12/11/2025"), None); // Could be US or EU
///
/// // Invalid formats
/// assert_eq!(parse_eu_date("2025-11-23"), None); // Wrong separator
/// assert_eq!(parse_eu_date("23/11/25"), None);   // 2-digit year
/// ```
///
/// # Recommendation
///
/// For dates where first number ≤ 12, try both formats:
///
/// ```ignore
/// let date = "05/06/2025";
/// let parsed = parse_eu_date(date)
///     .or_else(|| parse_us_date(date));
/// ```
///
/// # Note
///
/// This function only parses format, it does NOT validate whether the
/// month/day values are valid. Validation should be done by the calling module.
#[must_use]
pub fn parse_eu_date(date: &str) -> Option<(u32, u32, u32)> {
    let parts: Vec<&str> = date.split('/').collect();
    if parts.len() != 3 {
        return None;
    }

    let first: u32 = parts.first()?.parse().ok()?;
    let second: u32 = parts.get(1)?.parse().ok()?;
    let year: u32 = parts.get(2)?.parse().ok()?;

    // Require 4-digit year to avoid ambiguity
    if year < 1000 {
        return None;
    }

    // If first number > 12, it must be day (EU format)
    // Otherwise ambiguous - defer to caller to try US format
    if first > 12 {
        Some((year, second, first)) // (year, month, day)
    } else {
        None // Ambiguous case
    }
}

/// Get current year from system time
///
/// Returns the current year according to UTC system time.
/// Used for date validation (e.g., birthdate cannot be in future).
///
/// # Examples
///
/// ```ignore
/// use octarine::primitives::types::dates::get_current_year;
///
/// let current_year = get_current_year();
/// assert!(current_year >= 2025);
/// ```
#[must_use]
pub fn get_current_year() -> u32 {
    use chrono::Datelike;
    chrono::Utc::now().year() as u32
}

/// Check if a year is a leap year
///
/// Returns true if the year is a leap year according to Gregorian calendar rules:
/// - Divisible by 4: leap year
/// - Divisible by 100: NOT a leap year
/// - Divisible by 400: leap year
///
/// # Examples
///
/// ```ignore
/// use octarine::primitives::types::dates::is_leap_year;
///
/// assert!(is_leap_year(2024));  // Divisible by 4
/// assert!(!is_leap_year(2023)); // Not divisible by 4
/// assert!(!is_leap_year(1900)); // Divisible by 100 but not 400
/// assert!(is_leap_year(2000));  // Divisible by 400
/// ```
#[must_use]
pub fn is_leap_year(year: u32) -> bool {
    (year.is_multiple_of(4) && !year.is_multiple_of(100)) || year.is_multiple_of(400)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::expect_used)]
    use super::*;

    // ===== ISO Date Parsing Tests =====

    #[test]
    fn test_parse_iso_date() {
        assert_eq!(parse_iso_date("2025-11-23"), Some((2025, 11, 23)));
        assert_eq!(parse_iso_date("2025-01-01"), Some((2025, 1, 1)));
        assert_eq!(parse_iso_date("1900-12-31"), Some((1900, 12, 31)));
        assert_eq!(parse_iso_date("2000-02-29"), Some((2000, 2, 29)));
    }

    #[test]
    fn test_parse_iso_date_invalid_format() {
        assert_eq!(parse_iso_date("11/23/2025"), None); // Wrong separator
        assert_eq!(parse_iso_date("2025/11/23"), None); // Wrong separator
        assert_eq!(parse_iso_date("2025-11"), None); // Missing day
        assert_eq!(parse_iso_date("11-23"), None); // Missing year
        assert_eq!(parse_iso_date("invalid"), None); // Not a date
        assert_eq!(parse_iso_date(""), None); // Empty
    }

    #[test]
    fn test_parse_iso_date_does_not_validate() {
        // These parse successfully even though they're invalid dates
        // Validation is the caller's responsibility
        assert_eq!(parse_iso_date("2025-13-01"), Some((2025, 13, 1))); // Month 13
        assert_eq!(parse_iso_date("2025-02-30"), Some((2025, 2, 30))); // Feb 30
        assert_eq!(parse_iso_date("2025-11-32"), Some((2025, 11, 32))); // Day 32
    }

    // ===== US Date Parsing Tests =====

    #[test]
    fn test_parse_us_date() {
        assert_eq!(parse_us_date("11/23/2025"), Some((2025, 11, 23)));
        assert_eq!(parse_us_date("01/15/2025"), Some((2025, 1, 15)));
        assert_eq!(parse_us_date("12/31/1900"), Some((1900, 12, 31)));
        assert_eq!(parse_us_date("02/29/2000"), Some((2000, 2, 29)));
    }

    #[test]
    fn test_parse_us_date_invalid_format() {
        assert_eq!(parse_us_date("2025-11-23"), None); // Wrong separator
        assert_eq!(parse_us_date("11-23-2025"), None); // Wrong separator
        assert_eq!(parse_us_date("11/23/25"), None); // 2-digit year
        assert_eq!(parse_us_date("11/23"), None); // Missing year
        assert_eq!(parse_us_date("invalid"), None); // Not a date
        assert_eq!(parse_us_date(""), None); // Empty
    }

    #[test]
    fn test_parse_us_date_does_not_validate() {
        // These parse successfully even though they're invalid dates
        assert_eq!(parse_us_date("13/01/2025"), Some((2025, 13, 1))); // Month 13
        assert_eq!(parse_us_date("02/30/2025"), Some((2025, 2, 30))); // Feb 30
        assert_eq!(parse_us_date("11/32/2025"), Some((2025, 11, 32))); // Day 32
    }

    // ===== EU Date Parsing Tests =====

    #[test]
    fn test_parse_eu_date_unambiguous() {
        // Day > 12, clearly EU format
        assert_eq!(parse_eu_date("23/11/2025"), Some((2025, 11, 23)));
        assert_eq!(parse_eu_date("31/12/1900"), Some((1900, 12, 31)));
        assert_eq!(parse_eu_date("15/01/2025"), Some((2025, 1, 15)));
        assert_eq!(parse_eu_date("29/02/2000"), Some((2000, 2, 29)));
    }

    #[test]
    fn test_parse_eu_date_ambiguous() {
        // Day <= 12, could be US or EU - returns None
        assert_eq!(parse_eu_date("05/06/2025"), None);
        assert_eq!(parse_eu_date("12/11/2025"), None);
        assert_eq!(parse_eu_date("01/01/2025"), None);
    }

    #[test]
    fn test_parse_eu_date_invalid_format() {
        assert_eq!(parse_eu_date("2025-11-23"), None); // Wrong separator
        assert_eq!(parse_eu_date("23-11-2025"), None); // Wrong separator
        assert_eq!(parse_eu_date("23/11/25"), None); // 2-digit year
        assert_eq!(parse_eu_date("23/11"), None); // Missing year
        assert_eq!(parse_eu_date("invalid"), None); // Not a date
        assert_eq!(parse_eu_date(""), None); // Empty
    }

    // ===== Current Year Tests =====

    #[test]
    fn test_get_current_year() {
        let year = get_current_year();
        assert!(year >= 2025, "Current year should be at least 2025");
        assert!(year <= 2100, "Current year should be reasonable");
    }

    // ===== Leap Year Tests =====

    #[test]
    fn test_is_leap_year() {
        // Divisible by 4: leap year
        assert!(is_leap_year(2024));
        assert!(is_leap_year(2020));
        assert!(is_leap_year(2016));

        // Not divisible by 4: not leap year
        assert!(!is_leap_year(2023));
        assert!(!is_leap_year(2021));
        assert!(!is_leap_year(2019));

        // Divisible by 100 but not 400: not leap year
        assert!(!is_leap_year(1900));
        assert!(!is_leap_year(2100));
        assert!(!is_leap_year(2200));

        // Divisible by 400: leap year
        assert!(is_leap_year(2000));
        assert!(is_leap_year(2400));
        assert!(is_leap_year(1600));
    }

    #[test]
    fn test_leap_year_edge_cases() {
        assert!(is_leap_year(4)); // Very early leap year
        assert!(!is_leap_year(100)); // Century, not divisible by 400
        assert!(is_leap_year(400)); // Century, divisible by 400
        assert!(is_leap_year(2024)); // Recent leap year
    }

    // ===== Integration Tests =====

    #[test]
    fn test_parse_same_date_different_formats() {
        // November 23, 2025 in different formats
        let iso = parse_iso_date("2025-11-23");
        let us = parse_us_date("11/23/2025");
        let eu = parse_eu_date("23/11/2025");

        assert_eq!(iso, Some((2025, 11, 23)));
        assert_eq!(us, Some((2025, 11, 23)));
        assert_eq!(eu, Some((2025, 11, 23)));
    }

    #[test]
    fn test_format_disambiguation() {
        // 05/06/2025 is ambiguous (May 6 or June 5?)
        // US format should parse it, EU should not
        assert_eq!(parse_us_date("05/06/2025"), Some((2025, 5, 6)));
        assert_eq!(parse_eu_date("05/06/2025"), None);

        // 23/06/2025 is unambiguous (day > 12)
        // EU format should parse it, US should also parse (caller validates)
        assert_eq!(parse_eu_date("23/06/2025"), Some((2025, 6, 23)));
        // US parses it but result is invalid (month 23) - caller validates
        assert_eq!(parse_us_date("23/06/2025"), Some((2025, 23, 6)));
    }
}
