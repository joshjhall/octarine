//! Chinese Traditional (`zh-Hant`) context keywords for identifier confidence
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

/// Chinese Traditional context keyword table, keyed by identifier type.
pub(super) static KEYWORDS: &[(IdentifierType, &[&str])] = &[
    (
        IdentifierType::Ssn,
        &["身分證字號", "身分證號碼", "社會保障號", "納稅人識別號"],
    ),
    (
        IdentifierType::CreditCard,
        &["信用卡", "信用卡號", "卡號", "金融卡", "銀行卡"],
    ),
    (
        IdentifierType::Email,
        &["電子郵件", "電子信箱", "郵件地址", "信箱地址"],
    ),
    (
        IdentifierType::PhoneNumber,
        &["電話號碼", "手機號碼", "行動電話", "聯絡電話"],
    ),
    (
        IdentifierType::BankAccount,
        &[
            "銀行帳戶",
            "帳號",
            "帳戶號碼",
            "銀行卡號",
            "iban",
            "swift",
            "bic",
        ],
    ),
    (IdentifierType::RoutingNumber, &["銀行代碼", "分行代碼"]),
    (
        IdentifierType::DriverLicense,
        &["駕駛執照", "駕照", "駕照號碼"],
    ),
    (IdentifierType::Passport, &["護照", "護照號碼", "護照號"]),
    (IdentifierType::Birthdate, &["出生日期", "生日", "出生年月"]),
    (IdentifierType::IpAddress, &["ip位址", "網路位址"]),
    (IdentifierType::ApiKey, &["api密鑰", "認證", "密鑰"]),
    (
        IdentifierType::PersonalName,
        &["姓名", "名字", "全名", "姓氏"],
    ),
    (
        IdentifierType::Iban,
        &["iban", "國際銀行帳號", "bic", "swift"],
    ),
];
