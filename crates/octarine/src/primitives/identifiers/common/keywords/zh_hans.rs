//! Chinese Simplified (`zh-Hans`) context keywords for identifier confidence
//! scoring.
//!
//! Relocated from the previously flat `ApiKey` keyword list. Additional
//! identifier translations are added by the follow-up translation PRs.

use crate::primitives::identifiers::IdentifierType;

/// Chinese Simplified context keyword table, keyed by identifier type.
pub(super) static KEYWORDS: &[(IdentifierType, &[&str])] = &[
    (IdentifierType::ApiKey, &["api密钥", "认证", "令牌", "密钥"]),
    (
        IdentifierType::BankAccount,
        &[
            "银行账户",
            "账号",
            "账户号码",
            "银行卡号",
            "iban",
            "swift",
            "bic",
        ],
    ),
];
