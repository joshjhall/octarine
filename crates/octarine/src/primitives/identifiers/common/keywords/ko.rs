//! Korean (`ko`) context keywords for identifier confidence scoring.
//!
//! Relocated from the previously flat `ApiKey` keyword list. Additional
//! identifier translations are added by the follow-up translation PRs.

use crate::primitives::identifiers::IdentifierType;

/// Korean context keyword table, keyed by identifier type.
pub(super) static KEYWORDS: &[(IdentifierType, &[&str])] = &[
    (IdentifierType::ApiKey, &["api키", "인증", "토큰", "비밀키"]),
    (
        IdentifierType::BankAccount,
        &[
            "은행 계좌",
            "계좌 번호",
            "계좌번호",
            "계좌",
            "iban",
            "swift",
            "bic",
        ],
    ),
];
