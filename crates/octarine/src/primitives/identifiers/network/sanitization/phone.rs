//! Phone number redaction functions
//!
//! Redaction for international phone numbers.

use super::super::detection;
use super::super::redaction::PhoneRedactionStrategy;
use crate::primitives::data::tokens::RedactionTokenCore;

// ============================================================================
// Individual Redaction
// ============================================================================

/// Redact a single phone number with explicit strategy
///
/// # Arguments
/// * `phone` - The phone number to redact
/// * `strategy` - How to redact the phone number
#[must_use]
pub fn redact_phone_with_strategy(phone: &str, strategy: PhoneRedactionStrategy) -> String {
    if matches!(strategy, PhoneRedactionStrategy::Skip) {
        return phone.to_string();
    }

    // For invalid input, still redact but use simplified strategy
    if !detection::is_phone_international(phone) {
        return match strategy {
            PhoneRedactionStrategy::Skip => phone.to_string(),
            PhoneRedactionStrategy::ShowCountryCode | PhoneRedactionStrategy::Token => {
                RedactionTokenCore::Phone.into()
            }
            PhoneRedactionStrategy::Anonymous => RedactionTokenCore::Redacted.into(),
            PhoneRedactionStrategy::Asterisks => "*".repeat(phone.len()),
            PhoneRedactionStrategy::Hashes => "#".repeat(phone.len()),
        };
    }

    match strategy {
        PhoneRedactionStrategy::Skip => phone.to_string(),
        PhoneRedactionStrategy::ShowCountryCode => {
            // Show country code (+1, +44, etc.)
            if phone.starts_with('+') {
                if let Some(dash_pos) = phone.find('-') {
                    format!("{}***", &phone[..=dash_pos])
                } else {
                    RedactionTokenCore::Phone.into()
                }
            } else {
                RedactionTokenCore::Phone.into()
            }
        }
        PhoneRedactionStrategy::Token => RedactionTokenCore::Phone.into(),
        PhoneRedactionStrategy::Anonymous => RedactionTokenCore::Redacted.into(),
        PhoneRedactionStrategy::Asterisks => "*".repeat(phone.len()),
        PhoneRedactionStrategy::Hashes => "#".repeat(phone.len()),
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::expect_used, clippy::indexing_slicing)]
    use super::*;

    #[test]
    fn test_redact_phone_with_strategy_token() {
        assert_eq!(
            redact_phone_with_strategy("+1-555-123-4567", PhoneRedactionStrategy::Token),
            "[PHONE]"
        );
    }

    #[test]
    fn test_redact_phone_with_strategy_show_country_code() {
        assert_eq!(
            redact_phone_with_strategy("+1-555-123-4567", PhoneRedactionStrategy::ShowCountryCode),
            "+1-***"
        );
    }
}
