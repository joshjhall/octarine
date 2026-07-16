//! Polish (`pl`) context keywords for identifier confidence scoring.
//!
//! Keyword data is sourced from Presidio's MIT-licensed `country_specific/pl`
//! files with attribution. Keywords are lowercase — the analyzer lowercases the
//! text window before matching.

use crate::primitives::identifiers::IdentifierType;

/// Polish (`pl`) context keyword table, keyed by identifier type.
pub(super) static KEYWORDS: &[(IdentifierType, &[&str])] = &[(
    IdentifierType::BankAccount,
    &[
        "konto bankowe",
        "numer konta",
        "numer rachunku",
        "rachunek bankowy",
        "iban",
        "swift",
        "bic",
    ],
)];
