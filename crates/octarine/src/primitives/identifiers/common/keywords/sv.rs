//! Swedish (`sv`) context keywords for identifier confidence scoring.
//!
//! Keyword data is sourced from Presidio's MIT-licensed `country_specific/sv`
//! files with attribution. Keywords are lowercase — the analyzer lowercases the
//! text window before matching.

use crate::primitives::identifiers::IdentifierType;

/// Swedish (`sv`) context keyword table, keyed by identifier type.
pub(super) static KEYWORDS: &[(IdentifierType, &[&str])] = &[(
    IdentifierType::BankAccount,
    &[
        "bankkonto",
        "kontonummer",
        "konto",
        "clearingnummer",
        "iban",
        "swift",
        "bic",
    ],
)];
