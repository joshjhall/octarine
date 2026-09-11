//! Chinese Simplified (`zh-Hans`) context keywords for identifier confidence
//! scoring.
//!
//! Keyword data is sourced from Presidio's MIT-licensed language YAMLs with
//! attribution. Keywords are lowercase — the analyzer lowercases the text
//! window before matching.
//!
//! # Word boundaries
//!
//! Chinese is written without spaces and the analyzer matches by substring, so
//! single-character fragments would boost on unrelated text. Entries below are
//! distinctive multi-character terms for that reason.

use crate::primitives::identifiers::IdentifierType;

/// Chinese Simplified context keyword table, keyed by identifier type.
pub(super) static KEYWORDS: &[(IdentifierType, &[&str])] = &[
    (
        IdentifierType::Ssn,
        &["身份证号", "身份证号码", "社会保障号", "纳税人识别号"],
    ),
    (
        IdentifierType::CreditCard,
        &["信用卡", "信用卡号", "卡号", "借记卡", "银行卡"],
    ),
    (
        IdentifierType::Email,
        &["电子邮件", "电子邮箱", "邮箱地址", "邮件地址"],
    ),
    (
        IdentifierType::PhoneNumber,
        &["电话号码", "手机号码", "手机号", "联系电话"],
    ),
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
    (
        IdentifierType::RoutingNumber,
        &["银行代码", "支行代码", "联行号"],
    ),
    (
        IdentifierType::DriverLicense,
        &["驾驶证", "驾照", "驾驶证号"],
    ),
    (IdentifierType::Passport, &["护照", "护照号码", "护照号"]),
    (IdentifierType::Birthdate, &["出生日期", "生日", "出生年月"]),
    (IdentifierType::IpAddress, &["ip地址", "网络地址"]),
    (IdentifierType::ApiKey, &["api密钥", "认证", "令牌", "密钥"]),
    (
        IdentifierType::PersonalName,
        &["姓名", "名字", "全名", "姓氏"],
    ),
    (
        IdentifierType::Iban,
        &["iban", "国际银行账号", "bic", "swift"],
    ),
];
