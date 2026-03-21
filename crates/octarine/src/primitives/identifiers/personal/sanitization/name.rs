//! Name sanitization and redaction
//!
//! Pure sanitization functions for personal names.

use super::super::detection;
use super::super::redaction::NameRedactionStrategy;
use crate::primitives::Problem;

// ============================================================================
// Public API
// ============================================================================

/// Redact personal name using domain-specific redaction strategy
///
/// Provides type-safe name redaction with options for showing initials or
/// first name. Validates name format using detection (requires 2+ capitalized words).
///
/// # Arguments
///
/// * `name` - Name to redact
/// * `strategy` - Name-specific redaction strategy (ShowInitials, ShowFirst, Token, etc.)
///
/// # Returns
///
/// Redacted name according to strategy:
/// - **None**: Returns name as-is (dev/qa only)
/// - **ShowInitials**: `"J. S."` (show first initial of each part)
/// - **ShowFirst**: `"John ***"` (show first name only)
/// - **Token**: `"[NAME]"`
/// - **Anonymous**: `"[REDACTED]"`
/// - **Asterisks**: `"**********"` (length-preserving)
/// - **Hashes**: `"##########"` (length-preserving)
///
/// # Examples
///
/// ```ignore
/// use octarine::primitives::identifiers::personal::{NameRedactionStrategy, redact_name};
///
/// assert_eq!(redact_name("John Smith", NameRedactionStrategy::ShowInitials), "J. S.");
/// assert_eq!(redact_name("John Smith", NameRedactionStrategy::ShowFirst), "John ***");
/// ```
#[must_use]
pub fn redact_name_with_strategy(name: &str, strategy: NameRedactionStrategy) -> String {
    if matches!(strategy, NameRedactionStrategy::Skip) {
        return name.to_string();
    }

    // Validate name format (requires 2+ capitalized words)
    if !detection::is_name(name) {
        return "[NAME]".to_string();
    }

    match strategy {
        NameRedactionStrategy::Skip => name.to_string(),

        NameRedactionStrategy::ShowInitials => {
            let parts: Vec<&str> = name.split_whitespace().collect();
            if parts.is_empty() {
                return "[NAME]".to_string();
            }

            parts
                .iter()
                .filter_map(|part| part.chars().next())
                .map(|c| format!("{}.", c.to_uppercase()))
                .collect::<Vec<_>>()
                .join(" ")
        }

        NameRedactionStrategy::ShowFirst => {
            let parts: Vec<&str> = name.split_whitespace().collect();
            if parts.is_empty() {
                return "[NAME]".to_string();
            }

            if let Some(first) = parts.first() {
                let masked_len = name.len().saturating_sub(first.len()).saturating_sub(1);
                format!("{first} {}", "*".repeat(masked_len))
            } else {
                "[NAME]".to_string()
            }
        }

        NameRedactionStrategy::Token => "[NAME]".to_string(),
        NameRedactionStrategy::Anonymous => "[REDACTED]".to_string(),
        NameRedactionStrategy::Asterisks => "*".repeat(name.len()),
        NameRedactionStrategy::Hashes => "#".repeat(name.len()),
    }
}

/// Sanitize and normalize personal name to title case
///
/// Normalizes name to proper title case (First Letter Capitalized).
///
/// # Examples
///
/// ```ignore
/// use crate::primitives::identifiers::personal::sanitization;
///
/// assert_eq!(sanitize_name("john smith")?, "John Smith");
/// assert_eq!(sanitize_name("JOHN SMITH")?, "John Smith");
/// assert!(sanitize_name("John").is_err()); // Single word
/// ```
pub fn sanitize_name(name: &str) -> Result<String, Problem> {
    let trimmed = name.trim();

    // Validate format using detection (requires 2+ capitalized words)
    if !detection::is_name(trimmed) {
        return Err(Problem::Validation(
            "Invalid name format (requires at least 2 capitalized words)".into(),
        ));
    }

    // Normalize to title case
    let normalized: Vec<String> = trimmed
        .split_whitespace()
        .map(|word| {
            let mut chars = word.chars();
            match chars.next() {
                None => String::new(),
                Some(first) => {
                    let mut result = first.to_uppercase().collect::<String>();
                    result.push_str(&chars.as_str().to_lowercase());
                    result
                }
            }
        })
        .collect();

    Ok(normalized.join(" "))
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::expect_used)]
    use super::*;

    #[test]
    fn test_redact_name_with_strategy() {
        // Valid names (2+ capitalized words) get redacted to initials
        assert_eq!(
            redact_name_with_strategy("John Smith", NameRedactionStrategy::ShowInitials),
            "J. S."
        );
        assert_eq!(
            redact_name_with_strategy("John Michael Smith", NameRedactionStrategy::ShowInitials),
            "J. M. S."
        );

        // Invalid names return token (prevents false positives)
        assert_eq!(
            redact_name_with_strategy("John", NameRedactionStrategy::ShowInitials),
            "[NAME]"
        );
        assert_eq!(
            redact_name_with_strategy("", NameRedactionStrategy::ShowInitials),
            "[NAME]"
        );
        assert_eq!(
            redact_name_with_strategy("   ", NameRedactionStrategy::ShowInitials),
            "[NAME]"
        );
        assert_eq!(
            redact_name_with_strategy("hello world", NameRedactionStrategy::ShowInitials),
            "[NAME]"
        );
    }

    #[test]
    fn test_redact_name_with_strategy_token() {
        assert_eq!(
            redact_name_with_strategy("John Smith", NameRedactionStrategy::Token),
            "[NAME]"
        );
    }
}
