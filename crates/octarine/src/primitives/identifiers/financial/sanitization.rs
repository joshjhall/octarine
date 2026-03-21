//! Financial identifier sanitization (primitives layer)
//!
//! Pure sanitization functions for financial identifiers with no observe dependencies.
//! Provides masking and redaction for credit cards, bank accounts, routing numbers.
//!
//! # PCI-DSS Compliance
//!
//! All masking strategies follow PCI-DSS guidelines:
//! - Last 4 digits may be shown for customer support
//! - First 6 digits (BIN) may be shown to identify issuer
//! - First 6 + Last 4 together is compliant
//!
//! # Architecture
//!
//! This is part of **Layer 1 (primitives)** - pure functions with NO logging.
//! - No observe:: dependencies
//! - Returns data, no side effects
//! - Used by observe/pii and security modules

use super::super::common::{masking, patterns};
use super::conversion;
use super::detection;
use super::redaction::{
    BankAccountRedactionStrategy, CreditCardRedactionStrategy, PaymentTokenRedactionStrategy,
    RoutingNumberRedactionStrategy, TextRedactionPolicy,
};
use super::validation;
use crate::primitives::Problem;
use crate::primitives::data::tokens::RedactionTokenCore;
use std::borrow::Cow;

// ============================================================================
// Credit Card Sanitization
// ============================================================================

/// Redact credit card with explicit strategy
///
/// # PCI-DSS Compliance
///
/// PCI-DSS allows showing:
/// - Last 4 digits (for customer support)
/// - First 6 digits (BIN - identifies issuer/type)
/// - First 6 + Last 4 together
///
/// # Examples
///
/// ```ignore
/// use crate::primitives::identifiers::financial::sanitization::{
///     redact_credit_card_with_strategy, CreditCardRedactionStrategy
/// };
///
/// // Token replacement
/// let token = redact_credit_card_with_strategy("4242424242424242", CreditCardRedactionStrategy::Token);
/// assert_eq!(token, "[CREDIT_CARD]");
///
/// // Show last 4 (PCI-DSS)
/// let last4 = redact_credit_card_with_strategy("4242424242424242", CreditCardRedactionStrategy::ShowLast4);
/// assert_eq!(last4, "************4242");
///
/// // Show BIN + last 4 (PCI-DSS)
/// let bin_last4 = redact_credit_card_with_strategy("4242424242424242", CreditCardRedactionStrategy::ShowBinLast4);
/// assert_eq!(bin_last4, "424242******4242");
/// ```
#[must_use]
pub fn redact_credit_card_with_strategy(
    card: &str,
    strategy: CreditCardRedactionStrategy,
) -> String {
    // No redaction requested - return as-is
    if matches!(strategy, CreditCardRedactionStrategy::Skip) {
        return card.to_string();
    }

    // Validate format first to prevent information leakage
    // Use pattern detection (format + Luhn) to verify it's actually a credit card
    if !detection::is_credit_card_pattern(card) {
        return RedactionTokenCore::CreditCard.into();
    }

    let digits_only = masking::digits_only(card);

    match strategy {
        CreditCardRedactionStrategy::Skip => card.to_string(), // Already handled above

        CreditCardRedactionStrategy::ShowLast4 => masking::show_last_n(&digits_only, 4, '*'),

        CreditCardRedactionStrategy::ShowBinLast4 => {
            masking::show_first_and_last(&digits_only, 6, 4, '*')
        }

        CreditCardRedactionStrategy::ShowBrand => {
            if let Some(card_type) = detection::detect_card_brand(&digits_only) {
                format!("[{}-****]", card_type.to_string().to_uppercase())
            } else {
                "[CARD-****]".to_string()
            }
        }

        CreditCardRedactionStrategy::Token => RedactionTokenCore::CreditCard.into(),

        CreditCardRedactionStrategy::Anonymous => RedactionTokenCore::Redacted.into(),

        CreditCardRedactionStrategy::Asterisks => masking::create_mask(digits_only.len(), '*'),

        CreditCardRedactionStrategy::Hashes => masking::create_mask(digits_only.len(), '#'),
    }
}

/// Sanitize credit card strict (normalize format + validate)
///
/// Removes formatting (spaces, dashes) and validates the card number.
/// Returns normalized digits if valid, error otherwise.
///
/// This combines normalization and validation in one step - the most
/// common pattern for accepting credit card input.
///
/// # Arguments
///
/// * `card` - Credit card number with or without formatting
///
/// # Returns
///
/// * `Ok(String)` - Normalized card number (digits only) if valid
/// * `Err(Problem)` - If card is invalid (bad format, failed Luhn, etc.)
///
/// # Examples
///
/// ```ignore
/// use crate::primitives::identifiers::financial::sanitization;
///
/// // With dashes
/// let clean = sanitization::sanitize_credit_card_strict("4242-4242-4242-4242")?;
/// assert_eq!(clean, "4242424242424242");
///
/// // With spaces
/// let clean = sanitization::sanitize_credit_card_strict("4242 4242 4242 4242")?;
/// assert_eq!(clean, "4242424242424242");
///
/// // Invalid card
/// assert!(sanitization::sanitize_credit_card_strict("1234").is_err());
/// ```
pub fn sanitize_credit_card_strict(card: &str) -> Result<String, Problem> {
    // Normalize format (remove spaces, dashes, etc.)
    let normalized = conversion::normalize_card_number(card);

    // Validate using validation layer (includes Luhn check and card type detection)
    validation::validate_credit_card(&normalized)?;

    Ok(normalized)
}

/// Sanitize routing number strict (normalize format + validate)
///
/// Removes formatting and validates the routing number using ABA checksum.
/// Returns normalized 9-digit string if valid, error otherwise.
///
/// # Arguments
///
/// * `routing` - Routing number with or without formatting
///
/// # Returns
///
/// * `Ok(String)` - Normalized routing number (9 digits) if valid
/// * `Err(Problem)` - If routing number is invalid (bad format, failed checksum)
///
/// # Examples
///
/// ```ignore
/// use crate::primitives::identifiers::financial::sanitization;
///
/// // With dashes
/// let clean = sanitization::sanitize_routing_number_strict("021-000-021")?;
/// assert_eq!(clean, "021000021");
///
/// // Already clean
/// let clean = sanitization::sanitize_routing_number_strict("021000021")?;
/// assert_eq!(clean, "021000021");
///
/// // Invalid routing
/// assert!(sanitization::sanitize_routing_number_strict("123456789").is_err());
/// ```
pub fn sanitize_routing_number_strict(routing: &str) -> Result<String, Problem> {
    // Normalize format (remove dashes, spaces, etc.)
    let normalized = conversion::normalize_routing_number(routing);

    // Validate using validation layer (includes ABA checksum)
    validation::validate_routing_number(&normalized)?;

    Ok(normalized)
}

/// Sanitize account number strict (normalize format + validate)
///
/// Removes formatting and validates the account number.
/// Returns normalized digits if valid, error otherwise.
///
/// # Arguments
///
/// * `account` - Account number with or without formatting
///
/// # Returns
///
/// * `Ok(String)` - Normalized account number (digits only) if valid
/// * `Err(Problem)` - If account is invalid (bad format, invalid length)
///
/// # Examples
///
/// ```ignore
/// use crate::primitives::identifiers::financial::sanitization;
///
/// // With dashes
/// let clean = sanitization::sanitize_account_number_strict("12345-6789")?;
/// assert_eq!(clean, "123456789");
///
/// // Already clean
/// let clean = sanitization::sanitize_account_number_strict("123456789")?;
/// assert_eq!(clean, "123456789");
///
/// // Too short
/// assert!(sanitization::sanitize_account_number_strict("123").is_err());
/// ```
pub fn sanitize_account_number_strict(account: &str) -> Result<String, Problem> {
    // Normalize format (remove dashes, spaces, etc.)
    let normalized = conversion::normalize_account_number(account);

    // Validate using validation layer (length and format checks)
    validation::validate_account_number(&normalized)?;

    Ok(normalized)
}

// ============================================================================
// Bank Account Sanitization
// ============================================================================

/// Redact bank account with configurable strategy
///
/// # Examples
///
/// ```ignore
/// use crate::primitives::identifiers::financial::{
///     redact_bank_account_with_strategy, BankAccountRedactionStrategy
/// };
///
/// let token = redact_bank_account_with_strategy("12345678901234567", BankAccountRedactionStrategy::Token);
/// assert_eq!(token, "[BANK_ACCOUNT]");
///
/// let last4 = redact_bank_account_with_strategy("12345678901234567", BankAccountRedactionStrategy::ShowLast4);
/// assert_eq!(last4, "****4567");
/// ```
#[must_use]
pub fn redact_bank_account_with_strategy(
    account: &str,
    strategy: BankAccountRedactionStrategy,
) -> String {
    if matches!(strategy, BankAccountRedactionStrategy::Skip) {
        return account.to_string();
    }

    // Validate format first to prevent information leakage
    if !detection::is_bank_account(account) {
        return RedactionTokenCore::BankAccount.into();
    }

    let digits_only = masking::digits_only(account);

    match strategy {
        BankAccountRedactionStrategy::Skip => account.to_string(),
        BankAccountRedactionStrategy::ShowLast4 => {
            // Use fixed 4-asterisk prefix to not reveal account length
            let last_four = &digits_only[digits_only.len().saturating_sub(4)..];
            format!("{}{}", masking::create_mask(4, '*'), last_four)
        }
        BankAccountRedactionStrategy::Token => RedactionTokenCore::BankAccount.into(),
        BankAccountRedactionStrategy::Anonymous => RedactionTokenCore::Redacted.into(),
        BankAccountRedactionStrategy::Asterisks => masking::create_mask(digits_only.len(), '*'),
        BankAccountRedactionStrategy::Hashes => masking::create_mask(digits_only.len(), '#'),
    }
}

// ============================================================================
// Routing Number Sanitization
// ============================================================================

/// Redact routing number with configurable strategy
///
/// # Examples
///
/// ```ignore
/// use crate::primitives::identifiers::financial::{
///     redact_routing_number_with_strategy, RoutingNumberRedactionStrategy
/// };
///
/// let token = redact_routing_number_with_strategy("021000021", RoutingNumberRedactionStrategy::Token);
/// assert_eq!(token, "[ROUTING_NUMBER]");
/// ```
#[must_use]
pub fn redact_routing_number_with_strategy(
    routing: &str,
    strategy: RoutingNumberRedactionStrategy,
) -> String {
    if matches!(strategy, RoutingNumberRedactionStrategy::Skip) {
        return routing.to_string();
    }

    let digits_only = masking::digits_only(routing);

    // Validate basic format (9 digits)
    if digits_only.len() != 9 {
        return RedactionTokenCore::RoutingNumber.into();
    }

    match strategy {
        RoutingNumberRedactionStrategy::Skip => routing.to_string(),
        RoutingNumberRedactionStrategy::Token => RedactionTokenCore::RoutingNumber.into(),
        RoutingNumberRedactionStrategy::Anonymous => RedactionTokenCore::Redacted.into(),
        RoutingNumberRedactionStrategy::Asterisks => masking::create_mask(9, '*'),
        RoutingNumberRedactionStrategy::Hashes => masking::create_mask(9, '#'),
    }
}

// ============================================================================
// Payment Token Sanitization
// ============================================================================

/// Redact payment token
///
/// # Examples
///
/// ```ignore
/// use crate::primitives::identifiers::financial::{
///     redact_payment_token_with_strategy, PaymentTokenRedactionStrategy
/// };
///
/// let redacted = redact_payment_token_with_strategy(
///     "tok_1A2B3C4D5E6F7G8H",
///     PaymentTokenRedactionStrategy::Token
/// );
/// assert_eq!(redacted, "[PAYMENT_TOKEN]");
/// ```
#[must_use]
pub fn redact_payment_token_with_strategy(
    token: &str,
    strategy: PaymentTokenRedactionStrategy,
) -> String {
    if matches!(strategy, PaymentTokenRedactionStrategy::Skip) {
        return token.to_string();
    }

    match strategy {
        PaymentTokenRedactionStrategy::Skip => token.to_string(),
        PaymentTokenRedactionStrategy::ShowLast4 => {
            let len = token.len();
            let last_four = &token[len.saturating_sub(4)..];
            format!(
                "{}{}",
                masking::create_mask(len.saturating_sub(4), '*'),
                last_four
            )
        }
        PaymentTokenRedactionStrategy::Token => RedactionTokenCore::PaymentToken.into(),
        PaymentTokenRedactionStrategy::Anonymous => RedactionTokenCore::Redacted.into(),
        PaymentTokenRedactionStrategy::Asterisks => masking::create_mask(token.len(), '*'),
        PaymentTokenRedactionStrategy::Hashes => masking::create_mask(token.len(), '#'),
    }
}

// ============================================================================
// Text Redaction (Find and Replace in Documents)
// ============================================================================

/// Redact all credit card patterns in text with explicit strategy
///
/// # Examples
///
/// ```ignore
/// use crate::primitives::identifiers::financial::sanitization::{
///     redact_credit_cards_in_text_with_strategy, CreditCardRedactionStrategy
/// };
///
/// let text = "Card: 4242-4242-4242-4242";
///
/// // Token replacement
/// let token = redact_credit_cards_in_text_with_strategy(text, CreditCardRedactionStrategy::Token);
/// assert!(token.contains("[CREDIT_CARD]"));
///
/// // Last 4 (PCI-DSS)
/// let last4 = redact_credit_cards_in_text_with_strategy(text, CreditCardRedactionStrategy::ShowLast4);
/// assert!(last4.contains("4242"));
/// ```
#[must_use]
pub fn redact_credit_cards_in_text_with_strategy(
    text: &str,
    strategy: CreditCardRedactionStrategy,
) -> Cow<'_, str> {
    let mut result = Cow::Borrowed(text);

    for pattern in patterns::credit_card::all() {
        if pattern.is_match(&result) {
            let owned = pattern
                .replace_all(&result, |caps: &regex::Captures<'_>| {
                    let card = caps.get(0).map_or("", |m| m.as_str());
                    redact_credit_card_with_strategy(card, strategy)
                })
                .into_owned();
            result = Cow::Owned(owned);
        }
    }

    result
}

/// Redact all payment tokens in text with explicit strategy
///
/// Scans text for payment processor token patterns and redacts them
/// using the specified redaction strategy.
///
/// # Returns
///
/// `Cow<'_, str>` - Borrowed if no tokens found, owned if replacements made.
///
/// # Examples
///
/// ```ignore
/// use crate::primitives::identifiers::financial::{
///     redact_payment_tokens_in_text_with_strategy, PaymentTokenRedactionStrategy
/// };
///
/// let text = "Token: tok_1A2B3C4D5E6F7G8H9I0J1K2L";
/// let safe = redact_payment_tokens_in_text_with_strategy(text, PaymentTokenRedactionStrategy::Token);
/// assert!(safe.contains("[PAYMENT_TOKEN]"));
/// ```
#[must_use]
pub fn redact_payment_tokens_in_text_with_strategy(
    text: &str,
    strategy: PaymentTokenRedactionStrategy,
) -> Cow<'_, str> {
    if matches!(strategy, PaymentTokenRedactionStrategy::Skip) {
        return Cow::Borrowed(text);
    }

    let mut result = Cow::Borrowed(text);

    for pattern in patterns::payment_token::all() {
        if pattern.is_match(&result) {
            let owned = pattern
                .replace_all(&result, |caps: &regex::Captures<'_>| {
                    let matched = caps.get(0).map_or("", |m| m.as_str());
                    redact_payment_token_with_strategy(matched, strategy)
                })
                .into_owned();
            result = Cow::Owned(owned);
        }
    }

    result
}

/// Redact all bank account numbers in text with explicit strategy
///
/// Scans text for bank account patterns including IBAN and US routing+account
/// using the specified redaction strategy.
///
/// # Returns
///
/// `Cow<'_, str>` - Borrowed if no accounts found, owned if replacements made.
///
/// # Examples
///
/// ```ignore
/// use crate::primitives::identifiers::financial::{
///     redact_bank_accounts_in_text_with_strategy, BankAccountRedactionStrategy
/// };
///
/// let text = "IBAN: XX00 TEST 0000 0000 0000 01";
/// let safe = redact_bank_accounts_in_text_with_strategy(text, BankAccountRedactionStrategy::Token);
/// assert!(safe.contains("[BANK_ACCOUNT]"));
/// ```
#[must_use]
pub fn redact_bank_accounts_in_text_with_strategy(
    text: &str,
    strategy: BankAccountRedactionStrategy,
) -> Cow<'_, str> {
    if matches!(strategy, BankAccountRedactionStrategy::Skip) {
        return Cow::Borrowed(text);
    }

    let mut result = Cow::Borrowed(text);

    for pattern in patterns::bank_account::all() {
        if pattern.is_match(&result) {
            let owned = pattern
                .replace_all(&result, |caps: &regex::Captures<'_>| {
                    let matched = caps.get(0).map_or("", |m| m.as_str());
                    redact_bank_account_with_strategy(matched, strategy)
                })
                .into_owned();
            result = Cow::Owned(owned);
        }
    }

    result
}

/// Redact all financial identifiers in text with explicit policy
///
/// Comprehensive redaction for credit cards, payment tokens, and bank accounts
/// using the specified text redaction policy.
///
/// # Examples
///
/// ```ignore
/// use crate::primitives::identifiers::financial::{sanitization, TextRedactionPolicy};
///
/// let text = "Card: 4242-4242-4242-4242, Token: tok_1A2B3C4D5E6F7G8H9I0J1K2L";
///
/// // Complete redaction (type tokens)
/// let safe = sanitization::redact_all_financial_in_text_with_policy(text, TextRedactionPolicy::Complete);
/// assert!(safe.contains("[CREDIT_CARD]"));
///
/// // Partial redaction (show last 4 for cards)
/// let safe = sanitization::redact_all_financial_in_text_with_policy(text, TextRedactionPolicy::Partial);
/// assert!(safe.contains("4242"));
/// ```
#[must_use]
pub fn redact_all_financial_in_text_with_policy(text: &str, policy: TextRedactionPolicy) -> String {
    // For Skip policy, return unchanged
    if matches!(policy, TextRedactionPolicy::Skip) {
        return text.to_string();
    }

    // Apply credit card redaction with strategy
    let result = redact_credit_cards_in_text_with_strategy(text, policy.to_credit_card_strategy());
    // Apply payment token redaction with strategy
    let result =
        redact_payment_tokens_in_text_with_strategy(&result, policy.to_payment_token_strategy());
    // Apply bank account redaction with strategy
    let result =
        redact_bank_accounts_in_text_with_strategy(&result, policy.to_bank_account_strategy());

    result.into_owned()
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::expect_used)]
    use super::*;

    // ===== Sanitize Strict Functions Tests =====

    #[test]
    fn test_sanitize_credit_card_strict() {
        // Valid card with dashes
        assert_eq!(
            sanitize_credit_card_strict("4242-4242-4242-4242").expect("Valid card should sanitize"),
            "4242424242424242"
        );

        // Valid card with spaces
        assert_eq!(
            sanitize_credit_card_strict("4242 4242 4242 4242").expect("Valid card should sanitize"),
            "4242424242424242"
        );

        // Already clean
        assert_eq!(
            sanitize_credit_card_strict("4242424242424242").expect("Valid card should sanitize"),
            "4242424242424242"
        );

        // Invalid card (bad Luhn)
        assert!(sanitize_credit_card_strict("4242424242424243").is_err());

        // Too short
        assert!(sanitize_credit_card_strict("1234").is_err());
    }

    #[test]
    fn test_sanitize_routing_number_strict() {
        // Valid routing with dashes
        assert_eq!(
            sanitize_routing_number_strict("021-000-021").expect("Valid routing should sanitize"),
            "021000021"
        );

        // Already clean
        assert_eq!(
            sanitize_routing_number_strict("021000021").expect("Valid routing should sanitize"),
            "021000021"
        );

        // Invalid checksum
        assert!(sanitize_routing_number_strict("123456789").is_err());

        // Too short
        assert!(sanitize_routing_number_strict("12345").is_err());
    }

    #[test]
    fn test_sanitize_account_number_strict() {
        // Valid account with dashes
        assert_eq!(
            sanitize_account_number_strict("12345-6789").expect("Valid account should sanitize"),
            "123456789"
        );

        // Already clean
        assert_eq!(
            sanitize_account_number_strict("123456789").expect("Valid account should sanitize"),
            "123456789"
        );

        // Too short (must be at least 1 digit)
        assert!(sanitize_account_number_strict("").is_err());

        // Too long (max 17 digits)
        assert!(sanitize_account_number_strict("123456789012345678").is_err());
    }

    // ===== Credit Card Redaction Tests =====

    #[test]
    fn test_redact_credit_card_with_strategies() {
        // Token
        assert_eq!(
            redact_credit_card_with_strategy(
                "4242424242424242",
                CreditCardRedactionStrategy::Token
            ),
            "[CREDIT_CARD]"
        );

        // Show last 4 (PCI-DSS)
        assert_eq!(
            redact_credit_card_with_strategy(
                "4242424242424242",
                CreditCardRedactionStrategy::ShowLast4
            ),
            "************4242"
        );

        // Show BIN + Last 4 (PCI-DSS)
        assert_eq!(
            redact_credit_card_with_strategy(
                "4242424242424242",
                CreditCardRedactionStrategy::ShowBinLast4
            ),
            "424242******4242"
        );

        // Show brand
        assert_eq!(
            redact_credit_card_with_strategy(
                "4242424242424242",
                CreditCardRedactionStrategy::ShowBrand
            ),
            "[VISA-****]"
        );

        // Anonymous
        assert_eq!(
            redact_credit_card_with_strategy(
                "4242424242424242",
                CreditCardRedactionStrategy::Anonymous
            ),
            "[REDACTED]"
        );

        // Asterisks (length-preserving)
        assert_eq!(
            redact_credit_card_with_strategy(
                "4242424242424242",
                CreditCardRedactionStrategy::Asterisks
            ),
            "****************"
        );

        // Hashes (length-preserving)
        assert_eq!(
            redact_credit_card_with_strategy(
                "4242424242424242",
                CreditCardRedactionStrategy::Hashes
            ),
            "################"
        );

        // Edge case: invalid card
        assert_eq!(
            redact_credit_card_with_strategy("123", CreditCardRedactionStrategy::ShowLast4),
            "[CREDIT_CARD]"
        );
    }

    // ===== Bank Account Tests =====

    #[test]
    fn test_redact_bank_account_with_strategy() {
        // ShowLast4 strategy
        assert_eq!(
            redact_bank_account_with_strategy("000000001", BankAccountRedactionStrategy::ShowLast4),
            "****0001"
        );
        assert_eq!(
            redact_bank_account_with_strategy(
                "00000000000000001",
                BankAccountRedactionStrategy::ShowLast4
            ),
            "****0001"
        );
        // Invalid accounts return token
        assert_eq!(
            redact_bank_account_with_strategy("123", BankAccountRedactionStrategy::ShowLast4),
            "[BANK_ACCOUNT]"
        );
        // Token strategy
        assert_eq!(
            redact_bank_account_with_strategy("000000001", BankAccountRedactionStrategy::Token),
            "[BANK_ACCOUNT]"
        );
    }

    // ===== Routing Number Tests =====

    #[test]
    fn test_redact_routing_number_with_strategy() {
        // Token strategy
        assert_eq!(
            redact_routing_number_with_strategy("000000001", RoutingNumberRedactionStrategy::Token),
            "[ROUTING_NUMBER]"
        );
        // Invalid routing numbers return token
        assert_eq!(
            redact_routing_number_with_strategy("12345", RoutingNumberRedactionStrategy::Token),
            "[ROUTING_NUMBER]"
        );
        // Asterisks strategy
        assert_eq!(
            redact_routing_number_with_strategy(
                "000000001",
                RoutingNumberRedactionStrategy::Asterisks
            ),
            "*********"
        );
    }

    // ===== Payment Token Tests =====

    #[test]
    fn test_redact_payment_token_with_strategy() {
        assert_eq!(
            redact_payment_token_with_strategy(
                "tok_1A2B3C4D",
                PaymentTokenRedactionStrategy::Token
            ),
            "[PAYMENT_TOKEN]"
        );
        // tok_1A2B3C4D is 12 chars, last 4 = "3C4D", mask = 8 asterisks
        assert_eq!(
            redact_payment_token_with_strategy(
                "tok_1A2B3C4D",
                PaymentTokenRedactionStrategy::ShowLast4
            ),
            "********3C4D"
        );
    }

    // ===== Text Redaction Tests =====

    #[test]
    fn test_redact_credit_cards_in_text_with_strategy() {
        let text = "Card: 4242-4242-4242-4242";

        // Token strategy
        let result =
            redact_credit_cards_in_text_with_strategy(text, CreditCardRedactionStrategy::Token);
        assert!(result.contains("[CREDIT_CARD]"));
        assert!(!result.contains("4242"));

        // ShowLast4 strategy
        let result =
            redact_credit_cards_in_text_with_strategy(text, CreditCardRedactionStrategy::ShowLast4);
        assert!(result.contains("4242"));
    }

    #[test]
    fn test_redact_credit_cards_multiple_with_strategy() {
        let text = "Cards: 4242424242424242 and 5555555555554444";
        let result =
            redact_credit_cards_in_text_with_strategy(text, CreditCardRedactionStrategy::Token);
        assert!(result.matches("[CREDIT_CARD]").count() >= 1);
    }

    #[test]
    fn test_redact_payment_tokens_in_text_with_strategy() {
        let text = "Token: tok_1A2B3C4D5E6F7G8H9I0J1K2L";
        let result =
            redact_payment_tokens_in_text_with_strategy(text, PaymentTokenRedactionStrategy::Token);
        assert!(result.contains("[PAYMENT_TOKEN]"));
    }

    #[test]
    fn test_redact_bank_accounts_in_text_with_strategy() {
        let text = "IBAN: XX00 TEST 0000 0000 0000 01";
        let result =
            redact_bank_accounts_in_text_with_strategy(text, BankAccountRedactionStrategy::Token);
        assert!(result.contains("[BANK_ACCOUNT]"));
    }

    #[test]
    fn test_redact_all_financial_in_text_with_policy() {
        let text = "Card: 4242-4242-4242-4242, Token: tok_1A2B3C4D5E6F7G8H9I0J1K2L";

        // Complete policy (token replacement)
        let result = redact_all_financial_in_text_with_policy(text, TextRedactionPolicy::Complete);
        assert!(result.contains("[CREDIT_CARD]"));
        assert!(result.contains("[PAYMENT_TOKEN]"));

        // Partial policy (show last 4)
        let result = redact_all_financial_in_text_with_policy(text, TextRedactionPolicy::Partial);
        assert!(result.contains("4242")); // Credit card last 4 visible
        // Payment token with Partial shows last 4 chars: "1K2L"
        assert!(result.contains("1K2L"));
    }

    #[test]
    fn test_no_redaction_in_clean_text_with_policy() {
        let text = "This text contains no payment identifiers";
        let result = redact_all_financial_in_text_with_policy(text, TextRedactionPolicy::Complete);
        assert_eq!(result, text);
    }

    #[test]
    fn test_cow_optimization_with_strategy() {
        // Clean text should return borrowed
        let text = "Clean text";
        let result =
            redact_credit_cards_in_text_with_strategy(text, CreditCardRedactionStrategy::Token);
        assert!(matches!(result, Cow::Borrowed(_)));

        // Dirty text should return owned
        let text = "Card: 4242424242424242";
        let result =
            redact_credit_cards_in_text_with_strategy(text, CreditCardRedactionStrategy::Token);
        assert!(matches!(result, Cow::Owned(_)));
    }

    // ===== Edge Case Tests =====

    #[test]
    fn test_empty_inputs_with_strategy() {
        // Empty inputs return consistent token format
        assert_eq!(
            redact_credit_card_with_strategy("", CreditCardRedactionStrategy::Token),
            "[CREDIT_CARD]"
        );
        assert_eq!(
            redact_bank_account_with_strategy("", BankAccountRedactionStrategy::Token),
            "[BANK_ACCOUNT]"
        );
        assert_eq!(
            redact_routing_number_with_strategy("", RoutingNumberRedactionStrategy::Token),
            "[ROUTING_NUMBER]"
        );

        let result = redact_all_financial_in_text_with_policy("", TextRedactionPolicy::Complete);
        assert_eq!(result, "");
    }

    #[test]
    fn test_formatted_cards_with_strategy() {
        // With dashes
        assert_eq!(
            redact_credit_card_with_strategy(
                "4242-4242-4242-4242",
                CreditCardRedactionStrategy::ShowLast4
            ),
            "************4242"
        );

        // With spaces
        assert_eq!(
            redact_credit_card_with_strategy(
                "4242 4242 4242 4242",
                CreditCardRedactionStrategy::ShowLast4
            ),
            "************4242"
        );
    }
}
