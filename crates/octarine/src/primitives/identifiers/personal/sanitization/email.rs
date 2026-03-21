//! Email sanitization and redaction
//!
//! Pure sanitization functions for email addresses.

use super::super::super::common::masking;
use super::super::detection;
use super::super::redaction::EmailRedactionStrategy;
use crate::primitives::Problem;

// ============================================================================
// Public API
// ============================================================================

/// Redact email address using domain-specific redaction strategy
///
/// Provides type-safe email redaction with compile-time guarantees that only
/// valid email strategies can be applied. Validates format using detection
/// layer before redaction to prevent information leakage.
///
/// # Arguments
///
/// * `email` - Email address to redact
/// * `strategy` - Email-specific redaction strategy (ShowFirst, ShowDomain, Token, etc.)
///
/// # Returns
///
/// Redacted email string according to strategy:
/// - **None**: Returns email as-is (dev/qa only)
/// - **ShowFirst**: `"u***@example.com"`
/// - **ShowDomain**: `"****@example.com"`
/// - **Token**: `"[EMAIL]"`
/// - **Anonymous**: `"[REDACTED]"`
/// - **Asterisks**: `"****************"` (length-preserving)
/// - **Hashes**: `"################"` (length-preserving)
///
/// # Security
///
/// Invalid emails return full redaction token to avoid leaking partial
/// information. For example, `@example.com` returns `[EMAIL]` instead of
/// `***@example.com` which would leak the domain.
///
/// # Examples
///
/// ```ignore
/// use octarine::primitives::identifiers::personal::{EmailRedactionStrategy, redact_email};
///
/// let email = "user@example.com";
///
/// // Partial redaction - show first char
/// assert_eq!(redact_email(email, EmailRedactionStrategy::ShowFirst), "u***@example.com");
///
/// // Partial redaction - show domain only
/// assert_eq!(redact_email(email, EmailRedactionStrategy::ShowDomain), "****@example.com");
///
/// // Full redaction - type token
/// assert_eq!(redact_email(email, EmailRedactionStrategy::Token), "[EMAIL]");
/// ```
#[must_use]
pub fn redact_email_with_strategy(email: &str, strategy: EmailRedactionStrategy) -> String {
    // No redaction - return as-is (dev/qa)
    if matches!(strategy, EmailRedactionStrategy::Skip) {
        return email.to_string();
    }

    // Validate format first to prevent information leakage
    if !detection::is_email(email) {
        return "[EMAIL]".to_string();
    }

    match strategy {
        EmailRedactionStrategy::Skip => email.to_string(),

        EmailRedactionStrategy::ShowFirst => {
            // Show first character and domain: "u***@example.com"
            if let Some(at_pos) = email.find('@') {
                let local = &email[..at_pos];
                let domain = &email[at_pos..];

                if local.is_empty() {
                    format!("***{domain}")
                } else {
                    let first = local.chars().next().unwrap_or('*');
                    format!("{first}***{domain}")
                }
            } else {
                "[EMAIL]".to_string()
            }
        }

        EmailRedactionStrategy::ShowDomain => {
            // Show domain only: "****@example.com"
            if let Some(at_pos) = email.find('@') {
                let domain = &email[at_pos..];
                format!("****{domain}")
            } else {
                "[EMAIL]".to_string()
            }
        }

        EmailRedactionStrategy::Token => "[EMAIL]".to_string(),
        EmailRedactionStrategy::Anonymous => "[REDACTED]".to_string(),
        EmailRedactionStrategy::Asterisks => "*".repeat(email.len()),
        EmailRedactionStrategy::Hashes => "#".repeat(email.len()),
    }
}

/// Sanitize and normalize email address to canonical format
///
/// Normalizes email to lowercase and validates format.
///
/// # Examples
///
/// ```ignore
/// use crate::primitives::identifiers::personal::sanitization;
///
/// assert_eq!(sanitize_email("User@EXAMPLE.COM")?, "user@example.com");
/// assert_eq!(sanitize_email("  user@example.com  ")?, "user@example.com");
/// assert!(sanitize_email("invalid").is_err());
/// ```
pub fn sanitize_email(email: &str) -> Result<String, Problem> {
    let trimmed = email.trim();

    // Validate format using detection
    if !detection::is_email(trimmed) {
        return Err(Problem::Validation("Invalid email format".into()));
    }

    // Normalize to lowercase
    Ok(trimmed.to_lowercase())
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::expect_used)]
    use super::*;

    #[test]
    fn test_redact_email_with_strategy() {
        // Valid emails get redacted with ShowFirst strategy
        assert_eq!(
            redact_email_with_strategy("user@example.com", EmailRedactionStrategy::ShowFirst),
            "u***@example.com"
        );
        assert_eq!(
            redact_email_with_strategy("a@example.com", EmailRedactionStrategy::ShowFirst),
            "a***@example.com"
        );

        // Invalid emails return token (prevents information leakage)
        assert_eq!(
            redact_email_with_strategy("@example.com", EmailRedactionStrategy::ShowFirst),
            "[EMAIL]"
        );
        assert_eq!(
            redact_email_with_strategy("invalid", EmailRedactionStrategy::ShowFirst),
            "[EMAIL]"
        );
    }

    #[test]
    fn test_redact_email_with_strategy_token() {
        assert_eq!(
            redact_email_with_strategy("user@example.com", EmailRedactionStrategy::Token),
            "[EMAIL]"
        );
        assert_eq!(
            redact_email_with_strategy("invalid", EmailRedactionStrategy::Token),
            "[EMAIL]"
        );
    }
}
