//! French (`fr`) context keywords for identifier confidence scoring.
//!
//! Keyword data is sourced from Presidio's MIT-licensed `country_specific/fr`
//! files with attribution. Keywords are lowercase — the analyzer lowercases the
//! text window before matching.

use crate::primitives::identifiers::IdentifierType;

/// French (`fr`) context keyword table, keyed by identifier type.
pub(super) static KEYWORDS: &[(IdentifierType, &[&str])] = &[(
    IdentifierType::BankAccount,
    &[
        "compte bancaire",
        "numéro de compte",
        "numero de compte",
        "compte courant",
        "compte épargne",
        "rib",
        "iban",
        "swift",
        "bic",
    ],
)];
