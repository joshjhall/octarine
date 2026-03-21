//! Financial identifier format conversion (primitives layer)
//!
//! Pure conversion functions for normalizing and formatting financial identifiers.
//!
//! # Operations
//!
//! - **Normalization**: Remove formatting characters from card numbers
//! - **Formatting**: Add standard formatting (dashes, spaces)
//! - **Type conversion**: Extract card metadata
//!
//! # Architecture
//!
//! This is part of **Layer 1 (primitives)** - pure functions with NO logging.
//! - No observe:: dependencies
//! - Returns data, no side effects
//! - Used by observe/pii and security modules

use super::super::common::masking;
use super::super::types::CreditCardType;
use super::detection;

// ============================================================================
// Card Number Normalization
// ============================================================================

/// Normalize credit card number by removing all formatting
///
/// Removes spaces, dashes, and other non-digit characters.
///
/// # Examples
///
/// ```ignore
/// use crate::primitives::identifiers::financial::conversion;
///
/// let normalized = conversion::normalize_card_number("4242-4242-4242-4242");
/// assert_eq!(normalized, "4242424242424242");
///
/// let normalized = conversion::normalize_card_number("4242 4242 4242 4242");
/// assert_eq!(normalized, "4242424242424242");
/// ```
#[must_use]
pub fn normalize_card_number(card: &str) -> String {
    masking::digits_only(card)
}

/// Convert credit card number to standard dash formatting
///
/// Formats as: `XXXX-XXXX-XXXX-XXXX` for 16-digit cards,
/// or `XXXX-XXXXXX-XXXXX` for 15-digit Amex cards.
///
/// # Examples
///
/// ```ignore
/// use crate::primitives::identifiers::financial::conversion;
///
/// // Visa/Mastercard (16 digits)
/// let formatted = conversion::to_card_with_dashes("4242424242424242");
/// assert_eq!(formatted, "4242-4242-4242-4242");
///
/// // Amex (15 digits)
/// let formatted = conversion::to_card_with_dashes("378282246310005");
/// assert_eq!(formatted, "3782-822463-10005");
/// ```
#[must_use]
pub fn to_card_with_dashes(card: &str) -> String {
    let digits = normalize_card_number(card);

    match digits.len() {
        15 => {
            // Amex format: XXXX-XXXXXX-XXXXX
            format!("{}-{}-{}", &digits[0..4], &digits[4..10], &digits[10..15])
        }
        16 => {
            // Standard format: XXXX-XXXX-XXXX-XXXX
            format!(
                "{}-{}-{}-{}",
                &digits[0..4],
                &digits[4..8],
                &digits[8..12],
                &digits[12..16]
            )
        }
        13 => {
            // Short Visa format: XXXX-XXX-XXX-XXX
            format!(
                "{}-{}-{}-{}",
                &digits[0..4],
                &digits[4..7],
                &digits[7..10],
                &digits[10..13]
            )
        }
        _ => digits, // Return as-is if unusual length
    }
}

/// Convert credit card number to space formatting
///
/// Formats as: `XXXX XXXX XXXX XXXX` for 16-digit cards,
/// or `XXXX XXXXXX XXXXX` for 15-digit Amex cards.
///
/// # Examples
///
/// ```ignore
/// use crate::primitives::identifiers::financial::conversion;
///
/// let formatted = conversion::to_card_with_spaces("4242424242424242");
/// assert_eq!(formatted, "4242 4242 4242 4242");
/// ```
#[must_use]
pub fn to_card_with_spaces(card: &str) -> String {
    to_card_with_dashes(card).replace('-', " ")
}

// ============================================================================
// Card Metadata Extraction
// ============================================================================

/// Extract card type and last 4 digits for display
///
/// Returns a tuple of (card type, last 4 digits).
///
/// # Examples
///
/// ```ignore
/// use crate::primitives::identifiers::financial::conversion;
/// use crate::primitives::identifiers::financial::validation::CreditCardType;
///
/// let (card_type, last4) = conversion::extract_card_display_info("4242424242424242");
/// assert_eq!(card_type, CreditCardType::Visa);
/// assert_eq!(last4, "4242");
/// ```
#[must_use]
pub fn extract_card_display_info(card: &str) -> (CreditCardType, String) {
    let digits = normalize_card_number(card);
    let card_type = detection::detect_card_brand(&digits).unwrap_or(CreditCardType::Unknown);
    let last4 = if digits.len() >= 4 {
        digits[digits.len().saturating_sub(4)..].to_string()
    } else {
        digits
    };

    (card_type, last4)
}

/// Extract BIN (Bank Identification Number) from card
///
/// The BIN is the first 6 digits, identifying the issuing bank.
///
/// # Examples
///
/// ```ignore
/// use crate::primitives::identifiers::financial::conversion;
///
/// let bin = conversion::extract_bin("4242424242424242");
/// assert_eq!(bin, Some("424242".to_string()));
/// ```
#[must_use]
pub fn extract_bin(card: &str) -> Option<String> {
    let digits = normalize_card_number(card);
    if digits.len() >= 6 {
        Some(digits[0..6].to_string())
    } else {
        None
    }
}

/// Extract last N digits from card
///
/// # Examples
///
/// ```ignore
/// use crate::primitives::identifiers::financial::conversion;
///
/// let last4 = conversion::extract_last_digits("4242424242424242", 4);
/// assert_eq!(last4, Some("4242".to_string()));
/// ```
#[must_use]
pub fn extract_last_digits(card: &str, n: usize) -> Option<String> {
    let digits = normalize_card_number(card);
    if digits.len() >= n {
        Some(digits[digits.len().saturating_sub(n)..].to_string())
    } else {
        None
    }
}

// ============================================================================
// Bank Account Normalization
// ============================================================================

/// Normalize bank account number by removing formatting
///
/// # Examples
///
/// ```ignore
/// use crate::primitives::identifiers::financial::conversion;
///
/// let normalized = conversion::normalize_account_number("1234-5678-9012");
/// assert_eq!(normalized, "123456789012");
/// ```
#[must_use]
pub fn normalize_account_number(account: &str) -> String {
    masking::digits_only(account)
}

/// Normalize routing number by removing formatting
///
/// # Examples
///
/// ```ignore
/// use crate::primitives::identifiers::financial::conversion;
///
/// let normalized = conversion::normalize_routing_number("021-000-021");
/// assert_eq!(normalized, "021000021");
/// ```
#[must_use]
pub fn normalize_routing_number(routing: &str) -> String {
    masking::digits_only(routing)
}

// ============================================================================
// Display Formatting
// ============================================================================

/// Convert card to display string with type prefix
///
/// Returns a string like "Visa ending in 4242".
///
/// # Examples
///
/// ```ignore
/// use crate::primitives::identifiers::financial::conversion;
///
/// let display = conversion::to_card_display("4242424242424242");
/// assert_eq!(display, "Visa ending in 4242");
/// ```
#[must_use]
pub fn to_card_display(card: &str) -> String {
    let (card_type, last4) = extract_card_display_info(card);
    format!("{} ending in {}", card_type, last4)
}

/// Convert bank account to display string
///
/// Returns a string like "Account ending in 4567".
///
/// # Examples
///
/// ```ignore
/// use crate::primitives::identifiers::financial::conversion;
///
/// let display = conversion::to_account_display("12345678901234567");
/// assert_eq!(display, "Account ending in 4567");
/// ```
#[must_use]
pub fn to_account_display(account: &str) -> String {
    let digits = normalize_account_number(account);
    if digits.len() >= 4 {
        format!(
            "Account ending in {}",
            &digits[digits.len().saturating_sub(4)..]
        )
    } else {
        "Account".to_string()
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::expect_used)]
    use super::*;

    // ===== Normalization Tests =====

    #[test]
    fn test_normalize_card_number() {
        assert_eq!(
            normalize_card_number("4242-4242-4242-4242"),
            "4242424242424242"
        );
        assert_eq!(
            normalize_card_number("4242 4242 4242 4242"),
            "4242424242424242"
        );
        assert_eq!(
            normalize_card_number("4242424242424242"),
            "4242424242424242"
        );
        assert_eq!(normalize_card_number(""), "");
    }

    // ===== Format Tests =====

    #[test]
    fn test_to_card_with_dashes() {
        // 16-digit card
        assert_eq!(
            to_card_with_dashes("4242424242424242"),
            "4242-4242-4242-4242"
        );

        // 15-digit Amex
        assert_eq!(to_card_with_dashes("378282246310005"), "3782-822463-10005");

        // 13-digit short card
        assert_eq!(to_card_with_dashes("4111111111111"), "4111-111-111-111");

        // Already formatted
        assert_eq!(
            to_card_with_dashes("4242-4242-4242-4242"),
            "4242-4242-4242-4242"
        );
    }

    #[test]
    fn test_to_card_with_spaces() {
        assert_eq!(
            to_card_with_spaces("4242424242424242"),
            "4242 4242 4242 4242"
        );
    }

    // ===== Metadata Extraction Tests =====

    #[test]
    fn test_extract_card_display_info() {
        let (card_type, last4) = extract_card_display_info("4242424242424242");
        assert_eq!(card_type, CreditCardType::Visa);
        assert_eq!(last4, "4242");

        let (card_type, last4) = extract_card_display_info("5555555555554444");
        assert_eq!(card_type, CreditCardType::Mastercard);
        assert_eq!(last4, "4444");
    }

    #[test]
    fn test_extract_bin() {
        assert_eq!(extract_bin("4242424242424242"), Some("424242".to_string()));
        assert_eq!(extract_bin("12345"), None);
    }

    #[test]
    fn test_extract_last_digits() {
        assert_eq!(
            extract_last_digits("4242424242424242", 4),
            Some("4242".to_string())
        );
        assert_eq!(
            extract_last_digits("4242424242424242", 6),
            Some("424242".to_string())
        );
        assert_eq!(extract_last_digits("123", 4), None);
    }

    // ===== Account Normalization Tests =====

    #[test]
    fn test_normalize_account_number() {
        assert_eq!(normalize_account_number("1234-5678-9012"), "123456789012");
        assert_eq!(normalize_account_number("123456789012"), "123456789012");
    }

    #[test]
    fn test_normalize_routing_number() {
        assert_eq!(normalize_routing_number("021-000-021"), "021000021");
        assert_eq!(normalize_routing_number("021000021"), "021000021");
    }

    // ===== Display Format Tests =====

    #[test]
    fn test_to_card_display() {
        assert_eq!(to_card_display("4242424242424242"), "Visa ending in 4242");
        assert_eq!(
            to_card_display("5555555555554444"),
            "Mastercard ending in 4444"
        );
        assert_eq!(
            to_card_display("378282246310005"),
            "American Express ending in 0005"
        );
    }

    #[test]
    fn test_to_account_display() {
        assert_eq!(
            to_account_display("12345678901234567"),
            "Account ending in 4567"
        );
        assert_eq!(to_account_display("123"), "Account");
    }

    // ===== Edge Case Tests =====

    #[test]
    fn test_empty_inputs() {
        assert_eq!(normalize_card_number(""), "");
        assert_eq!(to_card_with_dashes(""), "");
        assert_eq!(extract_bin(""), None);
        assert_eq!(extract_last_digits("", 4), None);
    }

    #[test]
    fn test_short_card_numbers() {
        // Short numbers should return as-is when formatting
        assert_eq!(to_card_with_dashes("12345678"), "12345678");
    }
}
