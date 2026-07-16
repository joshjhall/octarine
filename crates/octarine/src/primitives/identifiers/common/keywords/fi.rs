//! Finnish (`fi`) context keywords for identifier confidence scoring.
//!
//! Keyword data is sourced from Presidio's MIT-licensed `country_specific/fi`
//! files with attribution. Keywords are lowercase — the analyzer lowercases the
//! text window before matching.

use crate::primitives::identifiers::IdentifierType;

/// Finnish (`fi`) context keyword table, keyed by identifier type.
pub(super) static KEYWORDS: &[(IdentifierType, &[&str])] = &[(
    IdentifierType::BankAccount,
    &["pankkitili", "tilinumero", "tili", "iban", "swift", "bic"],
)];
