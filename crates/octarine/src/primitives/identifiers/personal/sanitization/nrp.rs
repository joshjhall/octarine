//! Nationality / Religion / Political Affiliation (NRP) sanitization
//!
//! GDPR Article 9 special-category data — full replacement only. No
//! partial reveal is offered because showing even the first character of
//! `"Catholic"` or `"American"` leaks the category.

use super::super::detection;
use super::super::redaction::NrpRedactionStrategy;

/// Redact a nationality value with the supplied strategy.
///
/// Returns `"[NATIONALITY]"` if the input is not a recognised nationality
/// reference (the safe default — better to flag a non-match than leak the
/// input).
#[must_use]
pub fn redact_nationality_with_strategy(value: &str, strategy: NrpRedactionStrategy) -> String {
    redact_with_token(value, strategy, "[NATIONALITY]", &detection::is_nationality)
}

/// Redact a religion value with the supplied strategy.
#[must_use]
pub fn redact_religion_with_strategy(value: &str, strategy: NrpRedactionStrategy) -> String {
    redact_with_token(value, strategy, "[RELIGION]", &detection::is_religion)
}

/// Redact a political-affiliation value with the supplied strategy.
#[must_use]
pub fn redact_political_affiliation_with_strategy(
    value: &str,
    strategy: NrpRedactionStrategy,
) -> String {
    redact_with_token(
        value,
        strategy,
        "[POLITICAL_AFFILIATION]",
        &detection::is_political_affiliation,
    )
}

fn redact_with_token(
    value: &str,
    strategy: NrpRedactionStrategy,
    token: &str,
    is_match: &dyn Fn(&str) -> bool,
) -> String {
    if matches!(strategy, NrpRedactionStrategy::Skip) {
        return value.to_string();
    }
    if !is_match(value) {
        return token.to_string();
    }
    match strategy {
        NrpRedactionStrategy::Skip => value.to_string(),
        NrpRedactionStrategy::Token => token.to_string(),
        NrpRedactionStrategy::Anonymous => "[REDACTED]".to_string(),
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::expect_used)]
    use super::*;

    #[test]
    fn test_nationality_token() {
        assert_eq!(
            redact_nationality_with_strategy("American", NrpRedactionStrategy::Token),
            "[NATIONALITY]"
        );
    }

    #[test]
    fn test_religion_token() {
        assert_eq!(
            redact_religion_with_strategy("Catholic", NrpRedactionStrategy::Token),
            "[RELIGION]"
        );
    }

    #[test]
    fn test_political_token() {
        assert_eq!(
            redact_political_affiliation_with_strategy("Democrat", NrpRedactionStrategy::Token),
            "[POLITICAL_AFFILIATION]"
        );
    }

    #[test]
    fn test_anonymous() {
        assert_eq!(
            redact_nationality_with_strategy("American", NrpRedactionStrategy::Anonymous),
            "[REDACTED]"
        );
        assert_eq!(
            redact_religion_with_strategy("Catholic", NrpRedactionStrategy::Anonymous),
            "[REDACTED]"
        );
        assert_eq!(
            redact_political_affiliation_with_strategy("Democrat", NrpRedactionStrategy::Anonymous),
            "[REDACTED]"
        );
    }

    #[test]
    fn test_skip() {
        assert_eq!(
            redact_nationality_with_strategy("American", NrpRedactionStrategy::Skip),
            "American"
        );
    }

    #[test]
    fn test_non_match_returns_token() {
        assert_eq!(
            redact_nationality_with_strategy("not a nationality", NrpRedactionStrategy::Token),
            "[NATIONALITY]"
        );
    }
}
