//! Passport format detection
//!
//! Detects both labeled passport mentions and bare passport-shape patterns.
//! Bare passport candidates require contextual keywords (passport, travel, etc.)
//! within ~20 chars to upgrade from Medium to High confidence.

use super::super::super::common::patterns;
use super::super::super::types::{DetectionConfidence, IdentifierMatch, IdentifierType};
use super::helpers::{MAX_INPUT_LENGTH, deduplicate_matches, exceeds_safe_length, get_full_match};

/// Check if a value matches passport format
#[must_use]
pub fn is_passport(value: &str) -> bool {
    patterns::passport::all().iter().any(|p| p.is_match(value))
}

/// Find all passport patterns in text
///
/// Detects:
/// - Explicit mentions: "Passport: 123456789", "Passport number: 123456789"
/// - With prefix: "PP# 987654321"
/// - Generic format: "C12345678" (with context checking)
///
/// # Examples
///
/// ```ignore
/// use crate::primitives::identifiers::government::detection;
///
/// let text = "Passport number: 123456789";
/// let matches = detection::find_passports_in_text(text);
/// assert_eq!(matches.len(), 1);
/// ```
#[must_use]
pub fn find_passports_in_text(text: &str) -> Vec<IdentifierMatch> {
    if exceeds_safe_length(text, MAX_INPUT_LENGTH) {
        return Vec::new();
    }

    let mut matches = Vec::new();

    for (i, pattern) in patterns::passport::all().iter().enumerate() {
        for capture in pattern.captures_iter(text) {
            let full_match = get_full_match(&capture);

            // For generic pattern (index 2), check context
            let confidence = if i == 2 {
                if is_likely_passport_context(text, full_match.as_str()) {
                    DetectionConfidence::High
                } else {
                    DetectionConfidence::Medium
                }
            } else {
                DetectionConfidence::High
            };

            matches.push(IdentifierMatch::new(
                full_match.start(),
                full_match.end(),
                full_match.as_str().to_string(),
                IdentifierType::Passport,
                confidence,
            ));
        }
    }

    deduplicate_matches(matches)
}

/// Check if a match is likely a passport based on surrounding context
fn is_likely_passport_context(text: &str, potential_passport: &str) -> bool {
    let context_keywords = ["passport", "pp", "travel", "document", "identification"];

    let passport_pos = text.find(potential_passport).unwrap_or(0);
    let start = passport_pos.saturating_sub(20);
    let end = passport_pos
        .saturating_add(potential_passport.len())
        .saturating_add(20)
        .min(text.len());
    let context = &text[start..end].to_lowercase();

    context_keywords
        .iter()
        .any(|&keyword| context.contains(keyword))
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::expect_used)]
    use super::*;

    #[test]
    fn test_is_passport() {
        assert!(is_passport("C12345678"));
        assert!(!is_passport("invalid"));
    }

    #[test]
    fn test_find_passports_in_text() {
        let text = "Passport: 123456789";
        let matches = find_passports_in_text(text);
        assert_eq!(matches.len(), 1);
        let first = matches.first().expect("Should detect passport pattern");
        assert_eq!(first.identifier_type, IdentifierType::Passport);
    }

    #[test]
    fn test_empty_input() {
        assert!(!is_passport(""));
    }
}
