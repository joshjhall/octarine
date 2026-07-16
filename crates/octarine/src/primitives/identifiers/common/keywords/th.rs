//! Thai (`th`) context keywords for identifier confidence scoring.
//!
//! Keyword data is sourced from Presidio's MIT-licensed `country_specific/th`
//! files with attribution. Keywords are lowercase — the analyzer lowercases the
//! text window before matching.

use crate::primitives::identifiers::IdentifierType;

/// Thai (`th`) context keyword table, keyed by identifier type.
pub(super) static KEYWORDS: &[(IdentifierType, &[&str])] = &[(
    IdentifierType::BankAccount,
    &[
        "บัญชีธนาคาร",
        "เลขที่บัญชี",
        "หมายเลขบัญชี",
        "บัญชี",
        "iban",
        "swift",
        "bic",
    ],
)];
