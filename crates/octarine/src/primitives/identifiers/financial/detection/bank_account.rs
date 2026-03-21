//! Bank account and payment token detection
//!
//! Pure detection functions for bank accounts and payment tokens including:
//! - Bank account number heuristics (8-17 digits)
//! - IBAN pattern detection
//! - Payment token patterns (Stripe, PayPal)

use super::super::super::common::patterns;
use super::super::super::types::{IdentifierMatch, IdentifierType};

use super::credit_card::is_luhn_checksum_valid;

// ============================================================================
// Constants
// ============================================================================

/// Maximum input length for ReDoS protection
const MAX_INPUT_LENGTH: usize = 10_000;

// ============================================================================
// Public API
// ============================================================================

/// Check if value is likely a bank account (heuristic)
#[must_use]
pub fn is_bank_account(value: &str) -> bool {
    is_bank_account_likely(value)
}

/// Find all payment tokens in text
///
/// Scans text for payment processor token patterns (Stripe, PayPal).
/// Includes ReDoS protection for large inputs.
///
/// # Examples
///
/// ```ignore
/// use crate::primitives::identifiers::financial::detection;
///
/// let text = "Token: tok_1A2B3C4D5E6F7G8H9I0J1K2L";
/// let matches = detection::detect_payment_tokens_in_text(text);
/// assert!(!matches.is_empty());
/// ```
#[must_use]
pub fn detect_payment_tokens_in_text(text: &str) -> Vec<IdentifierMatch> {
    // ReDoS protection
    if text.len() > MAX_INPUT_LENGTH {
        return Vec::new();
    }

    let mut matches = Vec::new();

    for pattern in patterns::payment_token::all() {
        for capture in pattern.captures_iter(text) {
            if let Some(full_match) = capture.get(0) {
                matches.push(IdentifierMatch::high_confidence(
                    full_match.start(),
                    full_match.end(),
                    full_match.as_str().to_string(),
                    IdentifierType::PaymentToken,
                ));
            }
        }
    }

    super::common::deduplicate_matches(matches)
}

/// Find all bank account numbers in text
///
/// Scans text for bank account patterns including IBAN and US routing+account.
/// Includes ReDoS protection for large inputs.
///
/// # Examples
///
/// ```ignore
/// use crate::primitives::identifiers::financial::detection;
///
/// let text = "IBAN: XX00 TEST 0000 0000 0000 01";
/// let matches = detection::detect_bank_accounts_in_text(text);
/// assert!(!matches.is_empty());
/// ```
#[must_use]
pub fn detect_bank_accounts_in_text(text: &str) -> Vec<IdentifierMatch> {
    // ReDoS protection
    if text.len() > MAX_INPUT_LENGTH {
        return Vec::new();
    }

    let mut matches = Vec::new();

    for pattern in patterns::bank_account::all() {
        for capture in pattern.captures_iter(text) {
            if let Some(full_match) = capture.get(0) {
                matches.push(IdentifierMatch::high_confidence(
                    full_match.start(),
                    full_match.end(),
                    full_match.as_str().to_string(),
                    IdentifierType::BankAccount,
                ));
            }
        }
    }

    super::common::deduplicate_matches(matches)
}

// ============================================================================
// Internal Helpers
// ============================================================================

/// Check if value is likely a bank account (heuristic)
fn is_bank_account_likely(value: &str) -> bool {
    let digits_only = value
        .chars()
        .filter(|c| c.is_ascii_digit())
        .collect::<String>();

    // Bank accounts are typically 8-17 digits and NOT credit cards
    digits_only.len() >= 8 && digits_only.len() <= 17 && !is_luhn_checksum_valid(&digits_only)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::expect_used)]
    use super::*;

    #[test]
    fn test_detect_payment_tokens_in_text() {
        let text = "Token: tok_1A2B3C4D5E6F7G8H9I0J1K2L";
        let matches = detect_payment_tokens_in_text(text);
        assert!(!matches.is_empty());
        let first = matches
            .first()
            .expect("Should detect payment token pattern");
        assert_eq!(first.identifier_type, IdentifierType::PaymentToken);
    }

    #[test]
    fn test_detect_bank_accounts_in_text() {
        let text = "IBAN: XX00 TEST 0000 0000 0000 01";
        let matches = detect_bank_accounts_in_text(text);
        assert!(!matches.is_empty());
        let first = matches.first().expect("Should detect bank account pattern");
        assert_eq!(first.identifier_type, IdentifierType::BankAccount);
    }

    #[test]
    fn test_is_bank_account() {
        // Bank account-like: 8-17 digits that don't pass Luhn
        assert!(is_bank_account("12345678")); // 8 digits, fails Luhn
        assert!(!is_bank_account("1234567")); // Too short
    }

    #[test]
    fn test_empty_input() {
        assert!(!is_bank_account(""));
        assert_eq!(detect_bank_accounts_in_text("").len(), 0);
        assert_eq!(detect_payment_tokens_in_text("").len(), 0);
    }
}
