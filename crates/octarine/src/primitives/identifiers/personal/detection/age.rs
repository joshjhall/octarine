//! Age expression detection
//!
//! Detects ages in free text per Presidio AGE entity. Designed to support
//! HIPAA Safe Harbor §164.514(b)(2)(i)(B), which requires aggregating ages
//! over 89 into a single category.
//!
//! ## Detection scope
//!
//! - Numeric forms: `"42-year-old"`, `"age 65"`, `"42 y.o."`
//! - Lexical forms: `"in his thirties"`, `"in her eighties"`
//!
//! Lexical decade words map to the start of the decade (`thirties` → 30,
//! `eighties` → 80) for HIPAA Safe Harbor comparisons.

use super::super::super::common::patterns;
use super::super::super::types::{IdentifierMatch, IdentifierType};

/// Maximum input length for ReDoS protection
const MAX_INPUT_LENGTH: usize = 10_000;

/// Maximum plausible human age. Numeric values above this are not treated
/// as ages — they are almost certainly something else (year, count, etc.).
const MAX_PLAUSIBLE_AGE: u32 = 150;

// ============================================================================
// Public API
// ============================================================================

/// Find all age expressions in text.
///
/// Detects numeric ages (`"42-year-old"`, `"age 65"`, `"42 y.o."`) and
/// lexical decade ranges (`"in her thirties"`).
///
/// # Examples
///
/// ```ignore
/// use crate::primitives::identifiers::personal::detection::detect_ages_in_text;
///
/// let text = "The 42-year-old patient, age 65 control, and grandmother in her eighties.";
/// let matches = detect_ages_in_text(text);
/// assert!(matches.len() >= 3);
/// ```
#[allow(clippy::expect_used)]
#[must_use]
pub fn detect_ages_in_text(text: &str) -> Vec<IdentifierMatch> {
    if text.len() > MAX_INPUT_LENGTH {
        return Vec::new();
    }

    let mut matches = Vec::new();

    for pattern in patterns::age::all() {
        for capture in pattern.captures_iter(text) {
            let full_match = capture.get(0).expect("BUG: capture group 0 always exists");

            // Numeric patterns capture an integer; reject implausible values.
            if let Some(num_capture) = capture.get(1)
                && let Ok(parsed) = num_capture.as_str().parse::<u32>()
                && parsed > MAX_PLAUSIBLE_AGE
            {
                continue;
            }

            matches.push(IdentifierMatch::high_confidence(
                full_match.start(),
                full_match.end(),
                full_match.as_str().to_string(),
                IdentifierType::Age,
            ));
        }
    }

    super::common::deduplicate_matches(matches)
}

/// Returns `true` if the input contains at least one age expression.
///
/// # Examples
///
/// ```ignore
/// use crate::primitives::identifiers::personal::detection::is_age;
///
/// assert!(is_age("the 42-year-old patient"));
/// assert!(is_age("age: 65"));
/// assert!(is_age("in her eighties"));
/// assert!(!is_age("the building has 42 floors"));
/// ```
#[must_use]
pub fn is_age(value: &str) -> bool {
    !detect_ages_in_text(value).is_empty()
}

/// Extract the first numeric age value from text.
///
/// Returns the parsed age as a `u8` (saturating). For decade words
/// (`"thirties"`, `"eighties"`), returns the start of the decade.
///
/// Returns `None` when no age pattern is present or the captured value
/// exceeds [`MAX_PLAUSIBLE_AGE`].
///
/// # Examples
///
/// ```ignore
/// use crate::primitives::identifiers::personal::detection::find_age_value;
///
/// assert_eq!(find_age_value("the 42-year-old patient"), Some(42));
/// assert_eq!(find_age_value("age 65"), Some(65));
/// assert_eq!(find_age_value("in her eighties"), Some(80));
/// assert_eq!(find_age_value("no age here"), None);
/// ```
#[allow(clippy::expect_used)]
#[must_use]
pub fn find_age_value(text: &str) -> Option<u8> {
    if text.len() > MAX_INPUT_LENGTH {
        return None;
    }

    for pattern in patterns::age::all() {
        for capture in pattern.captures_iter(text) {
            if let Some(group) = capture.get(1) {
                let group_text = group.as_str();
                if let Some(parsed) = parse_age_token(group_text) {
                    return Some(parsed);
                }
            }
        }
    }

    None
}

/// HIPAA Safe Harbor helper — returns `true` when the input contains an age
/// > 89.
///
/// Accepts either a bare age (`"95"`) or a free-text fragment
/// (`"95-year-old patient"`). Returns `false` when no age is present or the
/// parsed value is invalid.
///
/// # Examples
///
/// ```ignore
/// use crate::primitives::identifiers::personal::detection::is_age_over_89;
///
/// assert!(is_age_over_89("95"));
/// assert!(is_age_over_89("the 92-year-old patient"));
/// assert!(is_age_over_89("in her nineties"));
/// assert!(!is_age_over_89("42"));
/// assert!(!is_age_over_89("not a number"));
/// ```
#[must_use]
pub fn is_age_over_89(value: &str) -> bool {
    // Bare numeric input — accept directly.
    if let Ok(parsed) = value.trim().parse::<u32>() {
        return parsed > 89 && parsed <= MAX_PLAUSIBLE_AGE;
    }

    match find_age_value(value) {
        Some(age) => age > 89,
        None => false,
    }
}

// ============================================================================
// Internal helpers
// ============================================================================

/// Convert a captured age token into a numeric value.
///
/// Numeric strings parse normally; decade words map to the start of the
/// decade.
fn parse_age_token(token: &str) -> Option<u8> {
    if let Ok(parsed) = token.parse::<u32>() {
        if parsed <= u32::from(u8::MAX) && parsed <= MAX_PLAUSIBLE_AGE {
            return u8::try_from(parsed).ok();
        }
        return None;
    }

    match token.to_lowercase().as_str() {
        "twenties" => Some(20),
        "thirties" => Some(30),
        "forties" => Some(40),
        "fifties" => Some(50),
        "sixties" => Some(60),
        "seventies" => Some(70),
        "eighties" => Some(80),
        "nineties" => Some(90),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::expect_used)]
    use super::*;

    #[test]
    fn test_detect_year_old_form() {
        let matches = detect_ages_in_text("the 42-year-old patient");
        assert!(!matches.is_empty());
        let first = matches.first().expect("Should detect year-old form");
        assert_eq!(first.identifier_type, IdentifierType::Age);
        assert_eq!(first.matched_text, "42-year-old");
    }

    #[test]
    fn test_detect_age_label_form() {
        let matches = detect_ages_in_text("Patient: age 65, control: age: 70");
        assert!(matches.len() >= 2);
    }

    #[test]
    fn test_detect_short_form() {
        assert!(is_age("42 y.o."));
        assert!(is_age("65 yo"));
        assert!(is_age("80 yrs"));
    }

    #[test]
    fn test_detect_decade_form() {
        let matches = detect_ages_in_text("My grandmother is in her eighties");
        assert!(!matches.is_empty());
        assert!(matches.iter().any(|m| m.matched_text.contains("eighties")));
    }

    #[test]
    fn test_no_match_on_unrelated_numbers() {
        assert!(!is_age("the building has 42 floors"));
        assert!(!is_age("version 1.2.3"));
        assert!(!is_age("no age here"));
    }

    #[test]
    fn test_find_age_value_numeric() {
        assert_eq!(find_age_value("the 42-year-old patient"), Some(42));
        assert_eq!(find_age_value("age 65"), Some(65));
        assert_eq!(find_age_value("aged: 70"), Some(70));
        assert_eq!(find_age_value("80 yrs"), Some(80));
    }

    #[test]
    fn test_find_age_value_decade() {
        assert_eq!(find_age_value("in her eighties"), Some(80));
        assert_eq!(find_age_value("in his thirties"), Some(30));
        assert_eq!(find_age_value("in their nineties"), Some(90));
    }

    #[test]
    fn test_find_age_value_none() {
        assert_eq!(find_age_value("no age mentioned"), None);
        assert_eq!(find_age_value(""), None);
    }

    #[test]
    fn test_is_age_over_89_bare_numeric() {
        assert!(is_age_over_89("95"));
        assert!(is_age_over_89("90"));
        assert!(is_age_over_89(" 91 ")); // with whitespace
        assert!(!is_age_over_89("89"));
        assert!(!is_age_over_89("42"));
    }

    #[test]
    fn test_is_age_over_89_from_text() {
        assert!(is_age_over_89("92-year-old"));
        assert!(is_age_over_89("the 95-year-old patient"));
        assert!(is_age_over_89("in her nineties"));
        assert!(!is_age_over_89("42-year-old"));
        assert!(!is_age_over_89("in her thirties"));
    }

    #[test]
    fn test_is_age_over_89_rejects_invalid() {
        assert!(!is_age_over_89("not a number"));
        assert!(!is_age_over_89(""));
        // Implausible — over MAX_PLAUSIBLE_AGE
        assert!(!is_age_over_89("999"));
        // Negative interpretation falls through to find_age_value, which
        // also rejects.
        assert!(!is_age_over_89("-5"));
    }

    #[test]
    fn test_redos_protection() {
        let huge = "x".repeat(20_000);
        assert!(detect_ages_in_text(&huge).is_empty());
        assert_eq!(find_age_value(&huge), None);
    }

    #[test]
    fn test_implausible_age_rejected() {
        // 999-year-old should not be detected as an age.
        let matches = detect_ages_in_text("the 999-year-old artifact");
        assert!(matches.is_empty(), "implausible age should be rejected");
    }
}
