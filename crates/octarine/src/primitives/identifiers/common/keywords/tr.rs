//! Turkish (`tr`) context keywords for identifier confidence scoring.
//!
//! Keyword data is sourced from Presidio's MIT-licensed `country_specific/tr`
//! files with attribution. Keywords are lowercase — the analyzer lowercases the
//! text window before matching.

use crate::primitives::identifiers::IdentifierType;

/// Turkish (`tr`) context keyword table, keyed by identifier type.
pub(super) static KEYWORDS: &[(IdentifierType, &[&str])] = &[(
    IdentifierType::BankAccount,
    &[
        "banka hesabı",
        "hesap numarası",
        "hesap no",
        "iban",
        "swift",
        "bic",
    ],
)];
