//! Hindi (`hi`) context keywords for identifier confidence scoring.
//!
//! Relocated from the previously flat `ApiKey` keyword list. Additional
//! identifier translations are added by the follow-up translation PRs.

use crate::primitives::identifiers::IdentifierType;

/// Hindi context keyword table, keyed by identifier type.
pub(super) static KEYWORDS: &[(IdentifierType, &[&str])] = &[
    (IdentifierType::ApiKey, &["एपीआई कुंजी", "टोकन", "प्रमाणीकरण"]),
    (
        IdentifierType::BankAccount,
        &["बैंक खाता", "खाता संख्या", "खाता नंबर", "iban", "swift", "bic"],
    ),
];
