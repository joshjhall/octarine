//! Common detection utilities and aggregate functions
//!
//! Provides aggregate detection functions that span multiple financial identifier types.

use super::super::super::common::{luhn, patterns};
use super::super::super::types::{DetectionResult, IdentifierMatch, IdentifierType};

use super::bank_account::{detect_bank_account_with_context, detect_bank_accounts_in_text};
use super::credit_card::{
    detect_credit_card_with_context, detect_credit_cards_in_text, is_suspicious_pattern_present,
};
use super::routing::{detect_routing_number, detect_routing_numbers_in_text};

// ============================================================================
// Aggregate Detection Functions
// ============================================================================

/// Find financial identifier type (lenient, context-free aggregate).
///
/// Finds credit cards, routing numbers, and bank accounts. This is a
/// **detection-layer** entry point and is intentionally lenient: it passes no
/// surrounding text, so the bank-account branch resolves to a `Low`-confidence
/// 8–17-digit length match and is accepted **by design**. Any 8–17-digit string
/// with no credit-card/routing match (invoice numbers, tracking numbers, zip+4,
/// employee IDs) therefore classifies as [`IdentifierType::BankAccount`]. Per the
/// project security model, detection favors recall (false positives are
/// acceptable); precision is the caller's job.
///
/// For precision, use [`find_financial_identifier_with_context`] (or
/// [`super::detect_bank_account_with_context`] directly) with the real
/// surrounding text — a bank-account keyword nearby lifts the match to `Medium`,
/// letting callers distinguish a keyword-confirmed account from a bare
/// coincidental number. The credit-card branch here already gates on
/// `confidence != Low` because credit-card confidence is reachable without
/// context (Luhn + BIN); the bank heuristic has no such context-free signal, so
/// gating it would make bare numbers unclassifiable — hence the deliberate
/// asymmetry.
///
/// `is_financial_identifier` / `detect_financial_identifier` intentionally have
/// no `_with_context` sibling — [`find_financial_identifier_with_context`] is the
/// single precision entry point.
///
/// # Examples
///
/// ```ignore
/// use crate::primitives::identifiers::financial::detection;
///
/// assert_eq!(
///     detection::find_financial_identifier("4242424242424242"),
///     Some(IdentifierType::CreditCard)
/// );
/// assert_eq!(
///     detection::find_financial_identifier("121000358"),
///     Some(IdentifierType::RoutingNumber)
/// );
/// ```
#[must_use]
pub fn find_financial_identifier(value: &str) -> Option<IdentifierType> {
    find_financial_identifier_with_context(value, None).map(|result| result.identifier_type)
}

/// Find financial identifier with surrounding-text context (precision path).
///
/// Same three-branch aggregate as [`find_financial_identifier`], but threads
/// `context` into the confidence-aware credit-card and bank-account detectors
/// and returns the full [`DetectionResult`] — including `confidence` — so
/// callers can actually act on the precision this path provides. A bank-account
/// context keyword lifts the bank-account branch from `Low` to `Medium` (see
/// [`super::detect_bank_account_with_context`]); the returned `confidence`
/// distinguishes a keyword-confirmed account from a bare coincidental number,
/// which [`find_financial_identifier`] (returning only the type) cannot.
///
/// Use this when the caller has the text surrounding `value` and wants
/// confidence-scored classification rather than the lenient context-free type.
#[must_use]
pub fn find_financial_identifier_with_context(
    value: &str,
    context: Option<&str>,
) -> Option<DetectionResult> {
    use crate::primitives::identifiers::types::DetectionConfidence;

    // Try credit card detection first. Gated on non-Low because credit-card
    // confidence is reachable without context (Luhn + BIN).
    if let Some(result) = detect_credit_card_with_context(value, context)
        && result.confidence != DetectionConfidence::Low
    {
        return Some(result);
    }

    // Try routing number detection (no context signal — ABA checksum only).
    if let Some(result) = detect_routing_number(value) {
        return Some(result);
    }

    // Bank account detection (heuristic, confidence-aware). Ungated by design:
    // a Low-confidence length match is accepted so context-free callers still
    // classify bare account numbers; a bank-account keyword in `context` lifts
    // the returned `confidence` to Medium for precision callers.
    if let Some(result) = detect_bank_account_with_context(value, context) {
        return Some(result);
    }

    None
}

/// Check if value is a financial identifier
#[must_use]
pub fn is_financial_identifier(value: &str) -> bool {
    find_financial_identifier(value).is_some()
}

/// Detect financial identifier type (dual-API contract alias).
///
/// Every identifier domain exposes the pair `detect_{domain}_identifier` /
/// `is_{domain}_identifier`. This is the aggregate entry point that returns
/// which specific `IdentifierType` matched — the bool counterpart is
/// [`is_financial_identifier`].
///
/// Semantically identical to [`find_financial_identifier`]; kept as an alias
/// for contract consistency across domains.
#[must_use]
pub fn detect_financial_identifier(value: &str) -> Option<IdentifierType> {
    find_financial_identifier(value)
}

/// Detect all financial identifiers in text
///
/// Comprehensive scanner that detects all financial PII types in one pass:
/// credit cards, routing numbers, bank accounts, payment tokens.
///
/// # Examples
///
/// ```ignore
/// use crate::primitives::identifiers::financial::detection;
///
/// let text = "Card: 4242-4242-4242-4242, Token: tok_abc123";
/// let matches = detection::detect_all_financial_in_text(text);
/// assert!(!matches.is_empty());
/// ```
#[must_use]
pub fn detect_all_financial_in_text(text: &str) -> Vec<IdentifierMatch> {
    let mut all_matches = Vec::new();

    all_matches.extend(detect_credit_cards_in_text(text));
    all_matches.extend(detect_routing_numbers_in_text(text));
    all_matches.extend(super::bank_account::detect_payment_tokens_in_text(text));
    all_matches.extend(detect_bank_accounts_in_text(text));
    all_matches.extend(super::crypto::detect_crypto_addresses_in_text(text));
    all_matches.extend(super::iban::detect_ibans_in_text(text));
    all_matches.extend(super::upi::find_india_upis_in_text(text));

    deduplicate_matches(all_matches)
}

/// Check if text contains any financial identifier
#[must_use]
pub fn is_financial_present(text: &str) -> bool {
    !detect_all_financial_in_text(text).is_empty()
}

/// Check if text contains payment data (credit cards with valid Luhn)
///
/// Scans text for digit sequences that match credit card patterns and validates
/// them with Luhn checksum. This is useful for detecting payment data in logs,
/// messages, or other text content.
///
/// # Examples
///
/// ```ignore
/// use crate::primitives::identifiers::financial::detection;
///
/// assert!(detection::is_payment_data_present("My card is 4111111111111111"));
/// assert!(detection::is_payment_data_present("Number: 5555 5555 5555 4444"));
/// assert!(!detection::is_payment_data_present("Just some regular text"));
/// assert!(!detection::is_payment_data_present("Invalid card 1234567890123456"));
/// ```
#[must_use]
pub fn is_payment_data_present(text: &str) -> bool {
    // Extract digit sequences
    let mut current_digits = String::new();
    let mut digit_sequences = Vec::new();

    for ch in text.chars() {
        if ch.is_numeric() {
            current_digits.push(ch);
        } else if !current_digits.is_empty() {
            // Continue accumulating if in middle of formatted card
            if ch == ' ' || ch == '-' {
                continue;
            }
            // End of digit sequence
            if current_digits.len() >= 13 && current_digits.len() <= 19 {
                digit_sequences.push(current_digits.clone());
            }
            current_digits.clear();
        }
    }

    // Don't forget the last sequence
    if current_digits.len() >= 13 && current_digits.len() <= 19 {
        digit_sequences.push(current_digits);
    }

    // Also check for formatted credit cards
    for capture in patterns::credit_card::FORMATTED.find_iter(text) {
        let digits: String = capture
            .as_str()
            .chars()
            .filter(|c| c.is_numeric())
            .collect();
        if digits.len() >= 13 && digits.len() <= 19 {
            digit_sequences.push(digits);
        }
    }

    // Check each potential card number with Luhn
    for potential_card in digit_sequences {
        if luhn::is_valid(&potential_card) {
            return true;
        }
    }

    false
}

// ============================================================================
// Internal Helpers
// ============================================================================

/// Deduplicate overlapping matches (keep longest/highest confidence)
pub(super) fn deduplicate_matches(mut matches: Vec<IdentifierMatch>) -> Vec<IdentifierMatch> {
    if matches.is_empty() {
        return matches;
    }

    // Sort by position, then length (descending), then confidence
    matches.sort_by(|a, b| {
        a.start
            .cmp(&b.start)
            .then_with(|| b.len().cmp(&a.len()))
            .then_with(|| b.confidence.cmp(&a.confidence))
    });

    let mut deduped = Vec::new();
    let mut last_end = 0;

    for m in matches {
        if m.start >= last_end {
            last_end = m.end;
            deduped.push(m);
        }
    }

    deduped
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::expect_used)]
    use crate::primitives::identifiers::types::DetectionConfidence;

    use super::*;

    #[test]
    fn test_find_financial_identifier() {
        // Credit card
        assert_eq!(
            find_financial_identifier("4242424242424242"),
            Some(IdentifierType::CreditCard)
        );

        // Routing number
        assert_eq!(
            find_financial_identifier("121000358"),
            Some(IdentifierType::RoutingNumber)
        );

        // Bank account — an 8-digit string that is neither a credit-card
        // length/Luhn match nor a routing number falls through to the
        // confidence-aware bank-account branch.
        assert_eq!(
            find_financial_identifier("12345678"),
            Some(IdentifierType::BankAccount)
        );
    }

    #[test]
    fn test_find_financial_identifier_lenient_unchanged() {
        // Regression guard for #694: the context-free aggregate stays lenient by
        // design — a bare 8-17 digit string still classifies as BankAccount.
        // Option 3 (documented looseness) explicitly does NOT gate this out.
        assert_eq!(
            find_financial_identifier("12345678"),
            Some(IdentifierType::BankAccount)
        );
        // The context variant with no context yields the same type as find().
        let no_ctx = find_financial_identifier_with_context("12345678", None)
            .expect("bare 8-digit string is a Low-confidence bank account");
        assert_eq!(no_ctx.identifier_type, IdentifierType::BankAccount);
        assert_eq!(no_ctx.confidence, DetectionConfidence::Low);
    }

    #[test]
    fn test_find_financial_identifier_with_context_bank_keyword() {
        // #694 precision path: a bank-account keyword in context keeps the type
        // AND surfaces Medium confidence directly on the aggregate result — the
        // whole point of returning DetectionResult rather than just the type.
        let with_ctx =
            find_financial_identifier_with_context("12345678", Some("bank account number"))
                .expect("8-digit string with bank context is a candidate account");
        assert_eq!(with_ctx.identifier_type, IdentifierType::BankAccount);
        assert_eq!(with_ctx.confidence, DetectionConfidence::Medium);

        // Same value, no context → Low. The context argument is now observable
        // through the aggregate's return value (previously it was inert).
        let no_ctx = find_financial_identifier_with_context("12345678", None)
            .expect("8-digit string is a candidate account");
        assert_eq!(no_ctx.confidence, DetectionConfidence::Low);
        assert_ne!(with_ctx.confidence, no_ctx.confidence);
    }

    #[test]
    fn test_find_financial_identifier_with_context_credit_card_still_gated() {
        // The credit-card branch keeps its `!= Low` gate under the context
        // variant; a genuine card still classifies as CreditCard.
        let result = find_financial_identifier_with_context("4242424242424242", None)
            .expect("valid card should classify");
        assert_eq!(result.identifier_type, IdentifierType::CreditCard);
    }

    #[test]
    fn test_is_financial_identifier() {
        assert!(is_financial_identifier("4242424242424242"));
        assert!(is_financial_identifier("121000358"));
        assert!(!is_financial_identifier("not financial"));
    }

    #[test]
    fn test_detect_financial_identifier() {
        assert_eq!(
            detect_financial_identifier("4242424242424242"),
            Some(IdentifierType::CreditCard)
        );
        assert_eq!(
            detect_financial_identifier("121000358"),
            Some(IdentifierType::RoutingNumber)
        );
        assert_eq!(detect_financial_identifier("not financial"), None);
        assert_eq!(detect_financial_identifier(""), None);
    }

    #[test]
    fn test_detect_all_financial_in_text() {
        let text = "Card: 4242-4242-4242-4242, Token: tok_1A2B3C4D5E6F7G8H9I0J1K2L";
        let matches = detect_all_financial_in_text(text);
        assert!(!matches.is_empty());
    }

    #[test]
    fn test_is_financial_present() {
        assert!(is_financial_present("Card: 4242-4242-4242-4242"));
        assert!(!is_financial_present("No financial data here"));
    }

    #[test]
    fn test_is_payment_data_present() {
        // Valid cards
        assert!(is_payment_data_present("My card is 4111111111111111"));
        assert!(is_payment_data_present("Number: 5555 5555 5555 4444"));

        // No payment data
        assert!(!is_payment_data_present("Just some regular text"));
        assert!(!is_payment_data_present("Invalid card 1234567890123456"));

        // Empty
        assert!(!is_payment_data_present(""));

        // Edge cases
        assert!(is_payment_data_present("Please pay with 4111111111111111"));
        assert!(is_payment_data_present(
            "Use card 5555-5555-5555-4444 for payment"
        ));
        assert!(is_payment_data_present(
            "My card number is 3782 822463 10005 (Amex)"
        ));

        // Not enough digits (order number vs card)
        assert!(is_payment_data_present("Order #4111111111111111"));

        // Too short (not card-like)
        assert!(!is_payment_data_present("Phone: 411-111-1111"));

        // Invalid Luhn checksum
        assert!(!is_payment_data_present("1234567890123456"));
    }

    #[test]
    fn test_deduplicate_matches() {
        let matches = vec![
            IdentifierMatch::high_confidence(
                0,
                10,
                "test1".to_string(),
                IdentifierType::CreditCard,
            ),
            IdentifierMatch::high_confidence(
                0,
                15,
                "test1long".to_string(),
                IdentifierType::CreditCard,
            ),
            IdentifierMatch::high_confidence(
                20,
                30,
                "test2".to_string(),
                IdentifierType::CreditCard,
            ),
        ];

        let deduped = deduplicate_matches(matches);
        assert_eq!(deduped.len(), 2);
        let first = deduped.first().expect("Should have first match");
        let second = deduped.get(1).expect("Should have second match");
        assert_eq!(first.matched_text, "test1long");
        assert_eq!(second.matched_text, "test2");
    }

    #[test]
    fn test_empty_input() {
        assert!(!is_financial_identifier(""));
        assert_eq!(detect_all_financial_in_text("").len(), 0);
    }
}
