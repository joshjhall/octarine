//! Spanish (`es`) context keywords for identifier confidence scoring.
//!
//! Keyword data is sourced from Presidio's MIT-licensed `country_specific/es`
//! files with attribution. Keywords are lowercase — the analyzer lowercases the
//! text window before matching.

use crate::primitives::identifiers::IdentifierType;

/// Spanish (`es`) context keyword table, keyed by identifier type.
pub(super) static KEYWORDS: &[(IdentifierType, &[&str])] = &[
    (
        IdentifierType::SpainPassport,
        &[
            "pasaporte",
            "número de pasaporte",
            "numero de pasaporte",
            "pasaporte español",
        ],
    ),
    (
        IdentifierType::BankAccount,
        &[
            "cuenta bancaria",
            "número de cuenta",
            "numero de cuenta",
            "cuenta corriente",
            "iban",
            "swift",
            "bic",
        ],
    ),
];
