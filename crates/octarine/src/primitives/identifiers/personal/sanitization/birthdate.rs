//! Birthdate sanitization and redaction
//!
//! Pure sanitization functions for dates of birth.

use super::super::detection;
use super::super::redaction::BirthdateRedactionStrategy;
use crate::primitives::Problem;
use crate::primitives::types::{parse_eu_date, parse_iso_date, parse_us_date};

// ============================================================================
// Public API
// ============================================================================

/// Redact birthdate using domain-specific redaction strategy
///
/// Provides type-safe birthdate redaction with option to show year only.
/// Validates date format using detection before redaction. Supports ISO,
/// US, and EU date formats.
///
/// # Arguments
///
/// * `date` - Birthdate to redact
/// * `strategy` - Birthdate-specific redaction strategy (ShowYear, Token, etc.)
///
/// # Returns
///
/// Redacted date according to strategy:
/// - **None**: Returns date as-is (dev/qa only)
/// - **ShowYear**: `"****-**-** (1990)"` (ISO) or `"**/**/1990"` (US/EU)
/// - **Token**: `"[DATE]"`
/// - **Anonymous**: `"[REDACTED]"`
/// - **Asterisks**: `"**********"` (length-preserving)
/// - **Hashes**: `"##########"` (length-preserving)
///
/// # Examples
///
/// ```ignore
/// use octarine::primitives::identifiers::personal::{BirthdateRedactionStrategy, redact_birthdate};
///
/// assert_eq!(
///     redact_birthdate("1990-05-15", BirthdateRedactionStrategy::ShowYear),
///     "****-**-** (1990)"
/// );
/// assert_eq!(
///     redact_birthdate("05/15/1990", BirthdateRedactionStrategy::ShowYear),
///     "**/**/1990"
/// );
/// ```
#[must_use]
pub fn redact_birthdate_with_strategy(date: &str, strategy: BirthdateRedactionStrategy) -> String {
    if matches!(strategy, BirthdateRedactionStrategy::Skip) {
        return date.to_string();
    }

    // Validate date format
    if !detection::is_birthdate(date) {
        return "[DATE]".to_string();
    }

    match strategy {
        BirthdateRedactionStrategy::Skip => date.to_string(),

        BirthdateRedactionStrategy::ShowYear => {
            // Try to parse and extract year
            if let Some((year, _, _)) = parse_iso_date(date) {
                format!("****-**-** ({year})")
            } else if let Some((year, _, _)) = parse_us_date(date) {
                format!("**/**/{year}")
            } else if let Some((year, _, _)) = parse_eu_date(date) {
                format!("**/**/{year}")
            } else {
                "[DATE]".to_string()
            }
        }

        BirthdateRedactionStrategy::Token => "[DATE]".to_string(),
        BirthdateRedactionStrategy::Anonymous => "[REDACTED]".to_string(),
        BirthdateRedactionStrategy::Asterisks => "*".repeat(date.len()),
        BirthdateRedactionStrategy::Hashes => "#".repeat(date.len()),
    }
}

/// Sanitize and normalize birthdate to ISO 8601 format (YYYY-MM-DD)
///
/// Converts various date formats to ISO 8601 standard format.
///
/// # Examples
///
/// ```ignore
/// use crate::primitives::identifiers::personal::sanitization;
///
/// assert_eq!(sanitize_birthdate("05/15/1990")?, "1990-05-15");
/// assert_eq!(sanitize_birthdate("1990-05-15")?, "1990-05-15");
/// assert!(sanitize_birthdate("invalid").is_err());
/// ```
pub fn sanitize_birthdate(date: &str) -> Result<String, Problem> {
    let trimmed = date.trim();

    // Validate format using detection
    if !detection::is_birthdate(trimmed) {
        return Err(Problem::Validation("Invalid birthdate format".into()));
    }

    // Try to parse and normalize to ISO format
    if trimmed.contains('-') {
        // Already in ISO format (YYYY-MM-DD)
        let parts: Vec<&str> = trimmed.split('-').collect();
        if parts.len() == 3 {
            let year = parts
                .first()
                .ok_or_else(|| Problem::Validation("Missing year component".into()))?;
            let month = parts
                .get(1)
                .ok_or_else(|| Problem::Validation("Missing month component".into()))?;
            let day = parts
                .get(2)
                .ok_or_else(|| Problem::Validation("Missing day component".into()))?;

            // Pad with zeros if needed
            return Ok(format!("{:0>4}-{:0>2}-{:0>2}", year, month, day));
        }
    } else if trimmed.contains('/') {
        // US or EU format (MM/DD/YYYY or DD/MM/YYYY)
        let parts: Vec<&str> = trimmed.split('/').collect();
        if parts.len() == 3 {
            let year = parts
                .get(2)
                .ok_or_else(|| Problem::Validation("Missing year component".into()))?;
            let first = parts
                .first()
                .ok_or_else(|| Problem::Validation("Missing first component".into()))?;
            let second = parts
                .get(1)
                .ok_or_else(|| Problem::Validation("Missing second component".into()))?;

            // Assume MM/DD/YYYY (US format) if first part is 1-12
            // Otherwise assume DD/MM/YYYY (EU format)
            let (month, day) = if let Ok(first_num) = first.parse::<u32>() {
                if first_num <= 12 {
                    // US format: MM/DD/YYYY
                    (first, second)
                } else {
                    // EU format: DD/MM/YYYY
                    (second, first)
                }
            } else {
                return Err(Problem::Validation("Invalid date components".into()));
            };

            return Ok(format!("{:0>4}-{:0>2}-{:0>2}", year, month, day));
        }
    }

    Err(Problem::Validation("Unable to parse date format".into()))
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::expect_used)]
    use super::*;

    #[test]
    fn test_redact_birthdate_with_strategy() {
        assert_eq!(
            redact_birthdate_with_strategy("1990-05-15", BirthdateRedactionStrategy::ShowYear),
            "****-**-** (1990)"
        );
        assert_eq!(
            redact_birthdate_with_strategy("05/15/1990", BirthdateRedactionStrategy::ShowYear),
            "**/**/1990"
        );
        assert_eq!(
            redact_birthdate_with_strategy("invalid", BirthdateRedactionStrategy::ShowYear),
            "[DATE]"
        );
    }

    #[test]
    fn test_redact_birthdate_with_strategy_token() {
        assert_eq!(
            redact_birthdate_with_strategy("1990-05-15", BirthdateRedactionStrategy::Token),
            "[DATE]"
        );
    }
}
