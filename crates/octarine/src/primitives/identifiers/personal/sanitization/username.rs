//! Username sanitization and redaction
//!
//! Pure sanitization functions for usernames.

use super::super::super::common::masking;
use super::super::redaction::UsernameRedactionStrategy;

// ============================================================================
// Public API
// ============================================================================

/// Redact username using domain-specific redaction strategy
///
/// Provides type-safe username redaction with common patterns for
/// showing first/last characters or complete redaction.
///
/// # Arguments
///
/// * `username` - Username to redact
/// * `strategy` - Username-specific redaction strategy (ShowFirstAndLast, ShowFirst, Token, etc.)
///
/// # Returns
///
/// Redacted username according to strategy:
/// - **None**: Returns username as-is (dev/qa only)
/// - **ShowFirstAndLast**: `"j******e"`
/// - **ShowFirst**: `"j*******"`
/// - **Token**: `"[USERNAME]"`
/// - **Anonymous**: `"[REDACTED]"`
/// - **Asterisks**: `"********"` (length-preserving)
/// - **Hashes**: `"########"` (length-preserving)
///
/// # Examples
///
/// ```ignore
/// use octarine::primitives::identifiers::personal::{UsernameRedactionStrategy, redact_username};
///
/// let username = "john_doe";
///
/// assert_eq!(
///     redact_username(username, UsernameRedactionStrategy::ShowFirstAndLast),
///     "j******e"
/// );
/// ```
#[must_use]
pub fn redact_username_with_strategy(
    username: &str,
    strategy: UsernameRedactionStrategy,
) -> String {
    if matches!(strategy, UsernameRedactionStrategy::Skip) {
        return username.to_string();
    }

    match strategy {
        UsernameRedactionStrategy::Skip => username.to_string(),

        UsernameRedactionStrategy::ShowFirstAndLast => {
            if username.len() <= 1 {
                masking::mask_all(username, '*')
            } else if username.len() == 2 {
                format!("{}*", &username[..1])
            } else {
                masking::show_first_and_last(username, 1, 1, '*')
            }
        }

        UsernameRedactionStrategy::ShowFirst => {
            if username.is_empty() {
                String::new()
            } else {
                let first = username.chars().next().unwrap_or('*');
                format!("{first}{}", "*".repeat(username.len().saturating_sub(1)))
            }
        }

        UsernameRedactionStrategy::Token => "[USERNAME]".to_string(),
        UsernameRedactionStrategy::Anonymous => "[REDACTED]".to_string(),
        UsernameRedactionStrategy::Asterisks => "*".repeat(username.len()),
        UsernameRedactionStrategy::Hashes => "#".repeat(username.len()),
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::expect_used)]
    use super::*;

    #[test]
    fn test_redact_username_with_strategy() {
        assert_eq!(
            redact_username_with_strategy("john_doe", UsernameRedactionStrategy::ShowFirstAndLast),
            "j******e"
        );
        assert_eq!(
            redact_username_with_strategy("ab", UsernameRedactionStrategy::ShowFirstAndLast),
            "a*"
        );
        assert_eq!(
            redact_username_with_strategy("a", UsernameRedactionStrategy::ShowFirstAndLast),
            "*"
        );
    }

    #[test]
    fn test_redact_username_with_strategy_token() {
        assert_eq!(
            redact_username_with_strategy("john_doe", UsernameRedactionStrategy::Token),
            "[USERNAME]"
        );
        assert_eq!(
            redact_username_with_strategy("", UsernameRedactionStrategy::Token),
            "[USERNAME]"
        );
    }
}
