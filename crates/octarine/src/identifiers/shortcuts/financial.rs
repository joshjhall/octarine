//! Financial identifier shortcuts (credit card, routing number, bank account, IBAN, crypto).
//!
//! Convenience functions over [`FinancialBuilder`](super::super::FinancialBuilder).

use crate::observe::Problem;
use crate::primitives::identifiers::{CreditCardRedactionStrategy, CryptoAddressRedactionStrategy};

use super::super::FinancialBuilder;
use super::super::types::{CreditCardType, CryptoAddressType, IdentifierMatch};

// ============================================================
// CREDIT CARD SHORTCUTS
// ============================================================

/// Check if value is a credit card number
#[must_use]
pub fn is_credit_card(value: &str) -> bool {
    FinancialBuilder::new().is_credit_card(value)
}

/// Detect all credit cards in text
#[must_use]
pub fn detect_credit_cards(text: &str) -> Vec<IdentifierMatch> {
    FinancialBuilder::new().detect_credit_cards_in_text(text)
}

/// Validate a credit card number (returns card type on success)
pub fn validate_credit_card(card: &str) -> Result<CreditCardType, Problem> {
    FinancialBuilder::new().validate_credit_card(card)
}

/// Redact all credit cards in text
#[must_use]
pub fn redact_credit_cards(text: &str) -> String {
    FinancialBuilder::new()
        .redact_credit_cards_in_text_with_strategy(text, CreditCardRedactionStrategy::ShowLast4)
        .to_string()
}

// ============================================================
// ROUTING NUMBER SHORTCUTS
// ============================================================

/// Check if value is a routing number
#[must_use]
pub fn is_routing_number(value: &str) -> bool {
    FinancialBuilder::new().is_routing_number(value)
}

/// Detect all routing numbers in text with ABA checksum validation
#[must_use]
pub fn detect_routing_numbers(text: &str) -> Vec<IdentifierMatch> {
    FinancialBuilder::new().detect_routing_numbers_in_text(text)
}

/// Validate a routing number
pub fn validate_routing_number(routing: &str) -> Result<(), Problem> {
    FinancialBuilder::new().validate_routing_number(routing)
}

// ============================================================
// BANK ACCOUNT SHORTCUTS
// ============================================================

/// Check if value is a bank account number
#[must_use]
pub fn is_bank_account(value: &str) -> bool {
    FinancialBuilder::new().is_bank_account(value)
}

// ============================================================
// IBAN SHORTCUTS
// ============================================================

/// Check if value is a valid IBAN (format + MOD-97 checksum)
#[must_use]
pub fn is_iban(value: &str) -> bool {
    FinancialBuilder::new().is_iban(value)
}

/// Detect all IBANs in text with MOD-97 checksum validation
#[must_use]
pub fn detect_ibans(text: &str) -> Vec<IdentifierMatch> {
    FinancialBuilder::new().detect_ibans_in_text(text)
}

// ============================================================
// CRYPTO ADDRESS SHORTCUTS
// ============================================================

/// Check if value is a Bitcoin address (P2PKH, P2SH, or Bech32/Bech32m)
#[must_use]
pub fn is_bitcoin_address(value: &str) -> bool {
    FinancialBuilder::new().is_bitcoin_address(value)
}

/// Check if value is an Ethereum address (0x + 40 hex chars)
#[must_use]
pub fn is_ethereum_address(value: &str) -> bool {
    FinancialBuilder::new().is_ethereum_address(value)
}

/// Check if value is any supported cryptocurrency wallet address
#[must_use]
pub fn is_crypto_address(value: &str) -> bool {
    FinancialBuilder::new().is_crypto_address(value)
}

/// Detect all cryptocurrency addresses in text
#[must_use]
pub fn detect_crypto_addresses(text: &str) -> Vec<IdentifierMatch> {
    FinancialBuilder::new().detect_crypto_addresses_in_text(text)
}

/// Validate a cryptocurrency wallet address (returns the chain type on success).
pub fn validate_crypto_address(addr: &str) -> Result<CryptoAddressType, Problem> {
    FinancialBuilder::new().validate_crypto_address(addr)
}

/// Sanitize a crypto address (trim + validate checksum).
pub fn sanitize_crypto_address(addr: &str) -> Result<String, Problem> {
    FinancialBuilder::new().sanitize_crypto_address(addr)
}

/// Redact a single crypto address using the bank-statement default
/// (first 4 + last 4 characters visible).
#[must_use]
pub fn redact_crypto_address(addr: &str) -> String {
    FinancialBuilder::new()
        .redact_crypto_address_with_strategy(addr, CryptoAddressRedactionStrategy::ShowPrefix)
}

/// Redact all crypto addresses found in text with the bank-statement
/// default (first 4 + last 4).
#[must_use]
pub fn redact_crypto_addresses(text: &str) -> String {
    FinancialBuilder::new()
        .redact_crypto_addresses_in_text_with_strategy(
            text,
            CryptoAddressRedactionStrategy::ShowPrefix,
        )
        .to_string()
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::expect_used)]
    use super::*;

    #[test]
    fn test_validate_credit_card_shortcut() {
        // Valid Visa test number (passes Luhn)
        assert!(validate_credit_card("4111111111111111").is_ok());
        assert!(validate_credit_card("not-a-card").is_err());
    }

    #[test]
    fn test_routing_number_shortcuts() {
        // Valid ABA routing number (passes checksum)
        assert!(is_routing_number("021000021"));
        assert!(!is_routing_number("000000000"));
        assert!(validate_routing_number("021000021").is_ok());
        assert!(validate_routing_number("invalid").is_err());

        let matches = detect_routing_numbers("ABA routing: 021000021");
        assert!(!matches.is_empty());
        assert!(detect_routing_numbers("no routing here").is_empty());
    }

    #[test]
    fn test_bank_account_shortcut() {
        assert!(is_bank_account("1234567890"));
        assert!(!is_bank_account("ab"));
    }

    #[test]
    fn test_validate_crypto_address_shortcut() {
        assert_eq!(
            validate_crypto_address("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa").expect("valid"),
            CryptoAddressType::BitcoinP2PKH,
        );
        assert!(validate_crypto_address("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNb").is_err());
    }

    #[test]
    fn test_sanitize_crypto_address_shortcut() {
        assert_eq!(
            sanitize_crypto_address("  1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa  ").expect("valid"),
            "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"
        );
    }

    #[test]
    fn test_redact_crypto_address_shortcut() {
        let out = redact_crypto_address("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa");
        assert!(out.starts_with("1A1z"));
        assert!(out.ends_with("vfNa"));
        assert!(out.contains("****"));
    }

    #[test]
    fn test_redact_crypto_addresses_in_text_shortcut() {
        let out = redact_crypto_addresses("Wallet: 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa");
        assert!(out.contains("1A1z"));
        assert!(out.contains("vfNa"));
        assert!(!out.contains("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"));
    }
}
