//! Italian (`it`) context keywords for identifier confidence scoring.
//!
//! Keyword data is sourced from Presidio's MIT-licensed `country_specific/it`
//! files with attribution. Keywords are lowercase — the analyzer lowercases the
//! text window before matching.

use crate::primitives::identifiers::IdentifierType;

/// Italian (`it`) context keyword table, keyed by identifier type.
pub(super) static KEYWORDS: &[(IdentifierType, &[&str])] = &[(
    IdentifierType::BankAccount,
    &[
        "conto bancario",
        "numero di conto",
        "numero conto",
        "conto corrente",
        "iban",
        "swift",
        "bic",
    ],
)];
