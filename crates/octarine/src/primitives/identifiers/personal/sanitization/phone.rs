//! Phone sanitization and redaction
//!
//! Pure sanitization functions for phone numbers.

use super::super::super::common::masking;
use super::super::detection;
use super::super::redaction::PhoneRedactionStrategy;
use crate::primitives::Problem;

// ============================================================================
// Public API
// ============================================================================

/// Redact phone number using domain-specific redaction strategy
///
/// Provides type-safe phone redaction with PCI-DSS compliant ShowLastFour option.
/// Validates E.164 format (7-15 digits) using detection layer before redaction.
///
/// # Arguments
///
/// * `phone` - Phone number to redact
/// * `strategy` - Phone-specific redaction strategy (ShowLastFour, ShowCountryCode, Token, etc.)
///
/// # Returns
///
/// Redacted phone string according to strategy:
/// - **None**: Returns phone as-is (dev/qa only)
/// - **ShowLastFour**: `"***-***-4567"` (PCI-DSS compliant)
/// - **ShowCountryCode**: `"+1-***-***-****"`
/// - **Token**: `"[PHONE]"`
/// - **Anonymous**: `"[REDACTED]"`
/// - **Asterisks**: `"**************"` (length-preserving)
/// - **Hashes**: `"##############"` (length-preserving)
///
/// # Examples
///
/// ```ignore
/// use octarine::primitives::identifiers::personal::{PhoneRedactionStrategy, redact_phone};
///
/// let phone = "+1-555-123-4567";
///
/// // Partial - show last four (PCI-DSS)
/// assert_eq!(redact_phone(phone, PhoneRedactionStrategy::ShowLastFour), "***-***-4567");
///
/// // Full - type token
/// assert_eq!(redact_phone(phone, PhoneRedactionStrategy::Token), "[PHONE]");
/// ```
#[must_use]
pub fn redact_phone_with_strategy(phone: &str, strategy: PhoneRedactionStrategy) -> String {
    // No redaction
    if matches!(strategy, PhoneRedactionStrategy::Skip) {
        return phone.to_string();
    }

    // Validate E.164 format to prevent information leakage
    if !detection::is_phone_number(phone) {
        return "[PHONE]".to_string();
    }

    match strategy {
        PhoneRedactionStrategy::Skip => phone.to_string(),

        PhoneRedactionStrategy::ShowLastFour => {
            // PCI-DSS compliant: show last 4 digits
            let digits_only = masking::digits_only(phone);
            if digits_only.len() >= 10 {
                let last_four = &digits_only[digits_only.len().saturating_sub(4)..];
                format!("***-***-{last_four}")
            } else if digits_only.len() >= 7 {
                let last_four = &digits_only[digits_only.len().saturating_sub(4)..];
                format!("***-{last_four}")
            } else {
                "[PHONE]".to_string()
            }
        }

        PhoneRedactionStrategy::ShowCountryCode => {
            // Show country code (+ and first 1-3 digits)
            if let Some(plus_idx) = phone.find('+') {
                let after_plus = &phone[plus_idx.saturating_add(1)..];
                let digits_only = masking::digits_only(after_plus);

                // Country codes are 1-3 digits
                let country_code_len = digits_only.len().min(3);
                if country_code_len > 0 {
                    let country_code = &digits_only[..country_code_len];
                    format!("+{country_code}-***-***-****")
                } else {
                    "[PHONE]".to_string()
                }
            } else {
                // No country code present
                "***-***-****".to_string()
            }
        }

        PhoneRedactionStrategy::Token => "[PHONE]".to_string(),
        PhoneRedactionStrategy::Anonymous => "[REDACTED]".to_string(),
        PhoneRedactionStrategy::Asterisks => "*".repeat(phone.len()),
        PhoneRedactionStrategy::Hashes => "#".repeat(phone.len()),
    }
}

/// Sanitize and normalize phone number to E.164 format
///
/// Converts phone numbers to E.164 international format (+[country][number]).
/// For numbers without country code, defaults to +1 (North America).
///
/// # Examples
///
/// ```ignore
/// use crate::primitives::identifiers::personal::sanitization;
///
/// assert_eq!(sanitize_phone("(555) 123-4567")?, "+15551234567");
/// assert_eq!(sanitize_phone("+1-555-123-4567")?, "+15551234567");
/// assert!(sanitize_phone("123").is_err());
/// ```
pub fn sanitize_phone(phone: &str) -> Result<String, Problem> {
    let trimmed = phone.trim();

    // Validate format using detection
    if !detection::is_phone_number(trimmed) {
        return Err(Problem::Validation("Invalid phone number format".into()));
    }

    // Extract digits only
    let digits_only: String = trimmed
        .chars()
        .filter(|c| c.is_ascii_digit() || *c == '+')
        .collect();

    // If already in E.164 format with +, return normalized
    if digits_only.starts_with('+') {
        return Ok(digits_only);
    }

    // If 10 digits (US format), add +1
    let digit_count = digits_only.chars().filter(|c| c.is_ascii_digit()).count();
    if digit_count == 10 {
        return Ok(format!("+1{digits_only}"));
    }

    // If 11 digits starting with 1 (US with country code), add +
    if digit_count == 11 && digits_only.starts_with('1') {
        return Ok(format!("+{digits_only}"));
    }

    // For other international numbers, add + if missing
    if !digits_only.starts_with('+') {
        return Ok(format!("+{digits_only}"));
    }

    Ok(digits_only)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::expect_used)]
    use super::*;

    #[test]
    fn test_redact_phone_with_strategy() {
        assert_eq!(
            redact_phone_with_strategy("+1-555-123-4567", PhoneRedactionStrategy::ShowLastFour),
            "***-***-4567"
        );
        assert_eq!(
            redact_phone_with_strategy("5551234567", PhoneRedactionStrategy::ShowLastFour),
            "***-***-4567"
        );
        assert_eq!(
            redact_phone_with_strategy("1234567", PhoneRedactionStrategy::ShowLastFour),
            "***-4567"
        );
        assert_eq!(
            redact_phone_with_strategy("123", PhoneRedactionStrategy::ShowLastFour),
            "[PHONE]"
        );
    }

    #[test]
    fn test_redact_phone_with_strategy_token() {
        assert_eq!(
            redact_phone_with_strategy("+1-555-123-4567", PhoneRedactionStrategy::Token),
            "[PHONE]"
        );
    }
}
