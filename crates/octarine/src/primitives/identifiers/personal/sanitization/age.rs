//! Age sanitization and redaction
//!
//! Implements HIPAA Safe Harbor §164.514(b)(2)(i)(B): ages over 89 must
//! be aggregated into a single category. The `Bucket10Year` strategy maps
//! every age to its 10-year bucket; `OverEightyNine` performs the minimal
//! HIPAA transformation (only > 89 is altered).

use super::super::detection;
use super::super::redaction::AgeRedactionStrategy;

/// Redact an age value using the supplied strategy.
///
/// The input may be a bare number (`"42"`, `"95"`) or a free-text fragment
/// (`"the 42-year-old patient"`).
///
/// # Examples
///
/// ```ignore
/// use octarine::primitives::identifiers::personal::{
///     AgeRedactionStrategy, redact_age_with_strategy,
/// };
///
/// assert_eq!(
///     redact_age_with_strategy("42", AgeRedactionStrategy::Bucket10Year),
///     "40-49",
/// );
/// assert_eq!(
///     redact_age_with_strategy("95", AgeRedactionStrategy::OverEightyNine),
///     "[90+]",
/// );
/// assert_eq!(
///     redact_age_with_strategy("42", AgeRedactionStrategy::OverEightyNine),
///     "42",
/// );
/// ```
#[must_use]
pub fn redact_age_with_strategy(value: &str, strategy: AgeRedactionStrategy) -> String {
    if matches!(strategy, AgeRedactionStrategy::Skip) {
        return value.to_string();
    }

    if !detection::is_age(value) && value.trim().parse::<u32>().is_err() {
        return "[AGE]".to_string();
    }

    let trimmed = value.trim();
    let age = if let Ok(parsed) = trimmed.parse::<u32>() {
        u8::try_from(parsed).ok()
    } else {
        detection::find_age_value(value)
    };

    match strategy {
        AgeRedactionStrategy::Skip => value.to_string(),
        AgeRedactionStrategy::Bucket10Year => match age {
            Some(a) => bucket_10_year(a),
            None => "[AGE]".to_string(),
        },
        AgeRedactionStrategy::OverEightyNine => match age {
            Some(a) if a > 89 => "[90+]".to_string(),
            Some(_) => value.to_string(),
            None => "[AGE]".to_string(),
        },
        AgeRedactionStrategy::Token => "[AGE]".to_string(),
        AgeRedactionStrategy::Anonymous => "[REDACTED]".to_string(),
    }
}

/// Returns the 10-year bucket containing `age` as a string like `"40-49"`.
/// Ages > 89 are collapsed to `"[90+]"` per HIPAA Safe Harbor.
fn bucket_10_year(age: u8) -> String {
    if age > 89 {
        return "[90+]".to_string();
    }
    // `age <= 89` so `age / 10 <= 8`, and `(age / 10) * 10 <= 80`. The
    // saturating ops keep clippy::arithmetic_side_effects happy without
    // changing the result.
    let lower = age.saturating_div(10).saturating_mul(10);
    let upper = lower.saturating_add(9);
    format!("{lower}-{upper}")
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::expect_used)]
    use super::*;

    #[test]
    fn test_bucket_10_year_simple() {
        assert_eq!(
            redact_age_with_strategy("42", AgeRedactionStrategy::Bucket10Year),
            "40-49"
        );
        assert_eq!(
            redact_age_with_strategy("65", AgeRedactionStrategy::Bucket10Year),
            "60-69"
        );
        assert_eq!(
            redact_age_with_strategy("9", AgeRedactionStrategy::Bucket10Year),
            "0-9"
        );
    }

    #[test]
    fn test_bucket_10_year_collapses_over_89() {
        assert_eq!(
            redact_age_with_strategy("95", AgeRedactionStrategy::Bucket10Year),
            "[90+]"
        );
        assert_eq!(
            redact_age_with_strategy("110", AgeRedactionStrategy::Bucket10Year),
            "[90+]"
        );
    }

    #[test]
    fn test_over_eighty_nine_preserves_younger() {
        assert_eq!(
            redact_age_with_strategy("42", AgeRedactionStrategy::OverEightyNine),
            "42"
        );
        assert_eq!(
            redact_age_with_strategy("89", AgeRedactionStrategy::OverEightyNine),
            "89"
        );
    }

    #[test]
    fn test_over_eighty_nine_redacts_older() {
        assert_eq!(
            redact_age_with_strategy("90", AgeRedactionStrategy::OverEightyNine),
            "[90+]"
        );
        assert_eq!(
            redact_age_with_strategy("95", AgeRedactionStrategy::OverEightyNine),
            "[90+]"
        );
    }

    #[test]
    fn test_token() {
        assert_eq!(
            redact_age_with_strategy("42-year-old", AgeRedactionStrategy::Token),
            "[AGE]"
        );
    }

    #[test]
    fn test_anonymous() {
        assert_eq!(
            redact_age_with_strategy("42", AgeRedactionStrategy::Anonymous),
            "[REDACTED]"
        );
    }

    #[test]
    fn test_skip() {
        assert_eq!(
            redact_age_with_strategy("42-year-old", AgeRedactionStrategy::Skip),
            "42-year-old"
        );
    }

    #[test]
    fn test_extracts_from_text() {
        assert_eq!(
            redact_age_with_strategy("42-year-old", AgeRedactionStrategy::Bucket10Year),
            "40-49"
        );
        assert_eq!(
            redact_age_with_strategy("in her eighties", AgeRedactionStrategy::Bucket10Year),
            "80-89"
        );
    }

    #[test]
    fn test_garbage_returns_token() {
        assert_eq!(
            redact_age_with_strategy("not an age", AgeRedactionStrategy::Bucket10Year),
            "[AGE]"
        );
    }
}
