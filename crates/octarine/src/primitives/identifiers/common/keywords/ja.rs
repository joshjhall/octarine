//! Japanese (`ja`) context keywords for identifier confidence scoring.
//!
//! Keyword data is sourced from Presidio's MIT-licensed language YAMLs with
//! attribution. Keywords are lowercase — the analyzer lowercases the text
//! window before matching.
//!
//! # Word boundaries
//!
//! Japanese is written without spaces and the analyzer matches by substring,
//! so single-character fragments would boost on unrelated text. Entries below
//! are distinctive multi-character terms for that reason.

use crate::primitives::identifiers::IdentifierType;

/// Japanese context keyword table, keyed by identifier type.
pub(super) static KEYWORDS: &[(IdentifierType, &[&str])] = &[
    (
        IdentifierType::Ssn,
        &["マイナンバー", "個人番号", "社会保障番号", "納税者番号"],
    ),
    (
        IdentifierType::CreditCard,
        &[
            "クレジットカード",
            "カード番号",
            "デビットカード",
            "決済カード",
        ],
    ),
    (
        IdentifierType::Email,
        &["メールアドレス", "電子メール", "メール"],
    ),
    (
        IdentifierType::PhoneNumber,
        &["電話番号", "携帯電話", "携帯番号", "固定電話"],
    ),
    (
        IdentifierType::BankAccount,
        &["銀行口座", "口座番号", "口座", "iban", "swift", "bic"],
    ),
    (IdentifierType::RoutingNumber, &["銀行コード", "支店コード"]),
    (
        IdentifierType::DriverLicense,
        &["運転免許証", "免許証番号", "運転免許"],
    ),
    (
        IdentifierType::Passport,
        &["パスポート", "旅券番号", "パスポート番号"],
    ),
    (IdentifierType::Birthdate, &["生年月日", "誕生日", "生まれ"]),
    (
        IdentifierType::IpAddress,
        &["ipアドレス", "ネットワークアドレス"],
    ),
    (
        IdentifierType::ApiKey,
        &["apiキー", "認証", "トークン", "秘密鍵"],
    ),
    (
        IdentifierType::PersonalName,
        &["氏名", "名前", "姓名", "フルネーム"],
    ),
    (
        IdentifierType::Iban,
        &["iban", "国際銀行口座番号", "bic", "swift"],
    ),
];
