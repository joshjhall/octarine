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
    // `is_bank_account_likely` enforces the MAX_INPUT_LENGTH ReDoS guard, so no
    // separate length check is needed here.
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
///
/// Guards against unbounded input (`> MAX_INPUT_LENGTH`) before scanning, so
/// every entry point sharing this helper — the public `is_bank_account` and
/// `detect_bank_account_with_context` — enforces the same ReDoS/allocation
/// ceiling, not just the ones that guard separately.
fn is_bank_account_likely(value: &str) -> bool {
    if value.len() > MAX_INPUT_LENGTH {
        return false;
    }

    let digit_count = value.chars().filter(|c| c.is_ascii_digit()).count();

    (8..=17).contains(&digit_count)
}

/// Check whether any bank-account context keyword appears in `context`.
///
/// Scans every language's keyword table (case-insensitive) so a caller need not
/// specify the language of the surrounding text. Only English currently defines
/// `BankAccount` keywords; the other language tables resolve to empty slices
/// until they are backfilled, so non-English context is effectively unmatched
/// today. The scan is bounded to `MAX_INPUT_LENGTH` bytes to cap the cost of a
/// large `context` blob.
fn has_bank_account_context(context: &str) -> bool {
    // Bound the scan to MAX_INPUT_LENGTH chars (char-based, so always on a UTF-8
    // boundary) before lowercasing, capping the cost of a large context blob.
    let context_lower: String = context
        .chars()
        .take(MAX_INPUT_LENGTH)
        .flat_map(char::to_lowercase)
        .collect();
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
    fn test_detect_bank_account_with_context_low_with_irrelevant_context() {
        // Some(context) but no bank-account keyword → still Low (distinct code
        // path from the None case via `is_some_and`).
        let result = detect_bank_account_with_context("12345678", Some("just some unrelated text"))
            .expect("8-digit string should be a candidate account");
        assert_eq!(result.confidence, DetectionConfidence::Low);
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
    fn test_detect_bank_account_with_context_redos_guard() {
        // Oversized value → None via the MAX_INPUT_LENGTH short-circuit, before
        // the digit-count heuristic runs.
        let oversized = "1".repeat(MAX_INPUT_LENGTH + 1);
        assert!(detect_bank_account_with_context(&oversized, None).is_none());
    }

    #[test]
    fn test_is_bank_account_redos_guard() {
        // #695: the public is_bank_account entry point shares the same
        // MAX_INPUT_LENGTH guard as detect_bank_account_with_context, so an
        // oversized value is rejected before the digit scan runs.
        let oversized = "1".repeat(MAX_INPUT_LENGTH + 1);
        assert!(!is_bank_account(&oversized));
    }

    #[test]
    fn test_has_bank_account_context_non_english() {
        // #695: non-English BankAccount keyword tables are backfilled, so a
        // keyword in any supported language is now matched (case-insensitively).
        assert!(has_bank_account_context("Bitte die Kontonummer angeben")); // de
        assert!(has_bank_account_context("numéro de compte bancaire")); // fr
        assert!(has_bank_account_context("cuenta bancaria")); // es
        assert!(has_bank_account_context("銀行口座")); // ja
        assert!(has_bank_account_context("은행 계좌")); // ko
        // A string with no bank-account keyword in any language stays unmatched.
        assert!(!has_bank_account_context("just some unrelated text"));
    }

    #[test]
    fn test_empty_input() {
        assert!(!is_bank_account(""));
        assert!(detect_bank_account_with_context("", None).is_none());
        assert_eq!(detect_bank_accounts_in_text("").len(), 0);
        assert_eq!(detect_payment_tokens_in_text("").len(), 0);
    }
}
