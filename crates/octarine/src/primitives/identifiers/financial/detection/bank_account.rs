//! Bank account and payment token detection
//!
//! Pure detection functions for bank accounts and payment tokens including:
//! - Bank account number heuristics (8-17 digits)
//! - IBAN pattern detection
//! - Payment token patterns (Stripe, PayPal)

use super::super::super::common::{KeywordLanguage, patterns};
use super::super::super::confidence::context_keywords;
use super::super::super::types::{
    DetectionConfidence, DetectionResult, IdentifierMatch, IdentifierType,
};

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

/// Detect a bank account with context-aware confidence scoring.
///
/// Bank account numbers have no self-validating checksum, so a bare 8-17 digit
/// string is inherently ambiguous. This detector returns a confidence level and
/// lets the caller decide how to act on it:
///
/// - No surrounding context → [`DetectionConfidence::Low`] (heuristic length match only)
/// - A bank-account context keyword nearby → [`DetectionConfidence::Medium`]
///
/// Unlike the previous heuristic, this does **not** exclude Luhn-valid strings:
/// real account numbers routinely satisfy the Luhn checksum by chance, so
/// excluding them produced a measurable false-reject rate. Credit-card
/// disambiguation is handled upstream by trying [`detect_credit_card_with_context`]
/// first (see `find_financial_identifier`).
///
/// [`detect_credit_card_with_context`]: super::credit_card::detect_credit_card_with_context
///
/// # Arguments
///
/// * `value` - The candidate account number (digits, optionally formatted)
/// * `context` - Optional surrounding text to scan for bank-account keywords
///
/// # Returns
///
/// `Some(DetectionResult)` when `value` is a plausible account number (8-17
/// digits), or `None` when the length rules it out.
#[must_use]
pub fn detect_bank_account_with_context(
    value: &str,
    context: Option<&str>,
) -> Option<DetectionResult> {
    if !is_bank_account_likely(value) {
        return None;
    }

    let has_context = context.is_some_and(has_bank_account_context);
    let confidence = if has_context {
        DetectionConfidence::Medium
    } else {
        DetectionConfidence::Low
    };

    Some(DetectionResult {
        identifier_type: IdentifierType::BankAccount,
        confidence,
        is_sensitive: true,
    })
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
///
/// Bank accounts are typically 8-17 digits. We deliberately do **not** exclude
/// Luhn-valid strings: real account numbers frequently pass the Luhn checksum by
/// chance, so excluding them produced false rejects. Credit-card disambiguation
/// is the caller's responsibility (try credit-card detection first).
fn is_bank_account_likely(value: &str) -> bool {
    let digit_count = value.chars().filter(|c| c.is_ascii_digit()).count();

    (8..=17).contains(&digit_count)
}

/// Check whether any bank-account context keyword appears in `context`.
///
/// Scans every language's keyword table (case-insensitive) so a caller need not
/// specify the language of the surrounding text.
fn has_bank_account_context(context: &str) -> bool {
    let context_lower = context.to_lowercase();
    KeywordLanguage::all().any(|language| {
        context_keywords(&IdentifierType::BankAccount, language)
            .iter()
            .any(|kw| context_lower.contains(kw))
    })
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::expect_used)]
    use super::super::credit_card::is_luhn_checksum_valid;
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
        // Bank account-like: any 8-17 digit string, regardless of Luhn
        assert!(is_bank_account("12345678")); // 8 digits
        assert!(is_bank_account("12345678901234567")); // 17 digits (max)
        assert!(!is_bank_account("1234567")); // Too short (7 digits)
        assert!(!is_bank_account("123456789012345678")); // Too long (18 digits)
    }

    #[test]
    fn test_is_bank_account_accepts_luhn_valid() {
        // Regression for the inverted-Luhn false-reject (issue #426).
        // "4532015112830366" is a 16-digit string that passes the Luhn checksum;
        // the old heuristic wrongly rejected such strings as bank accounts.
        assert!(is_luhn_checksum_valid("4532015112830366"));
        assert!(is_bank_account("4532015112830366"));
    }

    #[test]
    fn test_detect_bank_account_with_context_low_without_context() {
        // No surrounding context → Low confidence, not a hard reject.
        let result = detect_bank_account_with_context("4532015112830366", None)
            .expect("Luhn-valid 16-digit string should still be a candidate account");
        assert_eq!(result.identifier_type, IdentifierType::BankAccount);
        assert_eq!(result.confidence, DetectionConfidence::Low);
        assert!(result.is_sensitive);
    }

    #[test]
    fn test_detect_bank_account_with_context_medium_with_keyword() {
        // A bank-account context keyword nearby → Medium confidence.
        let result = detect_bank_account_with_context("12345678", Some("bank account number"))
            .expect("8-digit string with context should be a candidate account");
        assert_eq!(result.confidence, DetectionConfidence::Medium);
    }

    #[test]
    fn test_detect_bank_account_with_context_rejects_bad_length() {
        // Too short / too long → None regardless of context.
        assert!(detect_bank_account_with_context("1234567", Some("bank account")).is_none());
        assert!(
            detect_bank_account_with_context("123456789012345678", Some("bank account")).is_none()
        );
    }

    #[test]
    fn test_empty_input() {
        assert!(!is_bank_account(""));
        assert!(detect_bank_account_with_context("", None).is_none());
        assert_eq!(detect_bank_accounts_in_text("").len(), 0);
        assert_eq!(detect_payment_tokens_in_text("").len(), 0);
    }
}
