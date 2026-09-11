//! Financial PII scanning (credit card, bank account, IBAN, crypto)
//!
//! Part of the PII scanner domain split (issue #411).

use super::super::super::types::PiiType;
use crate::primitives::identifiers::FinancialIdentifierBuilder;

/// Scan for financial PII (credit card, bank account, routing number, IBAN, crypto)
pub(super) fn scan_financial(text: &str, pii_types: &mut Vec<PiiType>) {
    let financial = FinancialIdentifierBuilder::new();

    if financial.is_financial_present(text) {
        if !financial.detect_credit_cards_in_text(text).is_empty() {
            pii_types.push(PiiType::CreditCard);
        }
        if !financial.detect_bank_accounts_in_text(text).is_empty() {
            pii_types.push(PiiType::BankAccount);
        }
        if !financial.detect_routing_numbers_in_text(text).is_empty() {
            pii_types.push(PiiType::RoutingNumber);
        }
        if !financial.detect_payment_tokens_in_text(text).is_empty() {
            pii_types.push(PiiType::PaymentToken);
        }
        if !financial.detect_ibans_in_text(text).is_empty() {
            pii_types.push(PiiType::Iban);
        }
        if !financial.detect_crypto_addresses_in_text(text).is_empty() {
            pii_types.push(PiiType::CryptoAddress);
        }
        if !financial.find_india_upis_in_text(text).is_empty() {
            pii_types.push(PiiType::IndiaUpi);
        }
    }
}

/// Coarse pre-filter for the financial domain.
pub(super) fn is_financial_present(text: &str) -> bool {
    FinancialIdentifierBuilder::new().is_financial_present(text)
}
