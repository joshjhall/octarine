//! Japanese (`ja`) context keywords for identifier confidence scoring.
//!
//! Relocated from the previously flat `ApiKey` keyword list. Additional
//! identifier translations are added by the follow-up translation PRs.

use crate::primitives::identifiers::IdentifierType;

/// Japanese context keyword table, keyed by identifier type.
pub(super) static KEYWORDS: &[(IdentifierType, &[&str])] = &[
    (
        IdentifierType::ApiKey,
        &["apiキー", "認証", "トークン", "秘密鍵"],
    ),
    (
        IdentifierType::BankAccount,
        &["銀行口座", "口座番号", "口座", "iban", "swift", "bic"],
    ),
];
