//! Financial data redaction functions
//!
//! Redacts credit cards, bank accounts, and routing numbers.

use super::super::config::RedactionProfile;
use crate::primitives::identifiers::{
    BankAccountRedactionStrategy, FinancialIdentifierBuilder, PaymentTokenRedactionStrategy,
};

/// Redact credit cards based on profile using primitives
pub(super) fn redact_credit_cards(text: &str, profile: RedactionProfile) -> String {
    let strategy = profile.credit_card_strategy();
    let builder = FinancialIdentifierBuilder::new();
    builder
        .redact_credit_cards_in_text_with_strategy(text, strategy)
        .into_owned()
}

/// Redact bank accounts based on profile
pub(super) fn redact_bank_accounts(text: &str, profile: RedactionProfile) -> String {
    let strategy = match profile {
        RedactionProfile::ProductionStrict | RedactionProfile::ProductionLenient => {
            BankAccountRedactionStrategy::Token
        }
        RedactionProfile::Development | RedactionProfile::Testing => {
            BankAccountRedactionStrategy::Skip
        }
    };
    let builder = FinancialIdentifierBuilder::new();
    builder
        .redact_bank_accounts_in_text_with_strategy(text, strategy)
        .into_owned()
}

/// Redact payment tokens based on profile
pub(super) fn redact_routing_numbers(text: &str, profile: RedactionProfile) -> String {
    let strategy = match profile {
        RedactionProfile::ProductionStrict | RedactionProfile::ProductionLenient => {
            PaymentTokenRedactionStrategy::Token
        }
        RedactionProfile::Development | RedactionProfile::Testing => {
            PaymentTokenRedactionStrategy::Skip
        }
    };
    let builder = FinancialIdentifierBuilder::new();
    builder
        .redact_payment_tokens_in_text_with_strategy(text, strategy)
        .into_owned()
}
