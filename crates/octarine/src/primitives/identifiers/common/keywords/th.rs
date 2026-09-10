//! Thai (`th`) context keywords for identifier confidence scoring.
//!
//! Keyword data is sourced from Presidio's MIT-licensed `country_specific/th`
//! files and language YAMLs with attribution. Keywords are lowercase — the
//! analyzer lowercases the text window before matching.
//!
//! # Word boundaries
//!
//! Thai is written without spaces between words and the analyzer matches by
//! substring, so short fragments would boost on unrelated text. Entries below
//! are distinctive multi-syllable terms for that reason.

use crate::primitives::identifiers::IdentifierType;

/// Thai (`th`) context keyword table, keyed by identifier type.
pub(super) static KEYWORDS: &[(IdentifierType, &[&str])] = &[
    (
        IdentifierType::Ssn,
        &[
            "เลขประจำตัวประชาชน",
            "หมายเลขประจำตัวประชาชน",
            "บัตรประชาชน",
            "เลขประจำตัวผู้เสียภาษี",
        ],
    ),
    (
        IdentifierType::CreditCard,
        &["บัตรเครดิต", "หมายเลขบัตรเครดิต", "เลขที่บัตร", "บัตรเดบิต"],
    ),
    (
        IdentifierType::Email,
        &["อีเมล", "ที่อยู่อีเมล", "จดหมายอิเล็กทรอนิกส์"],
    ),
    (
        IdentifierType::PhoneNumber,
        &["หมายเลขโทรศัพท์", "เบอร์โทรศัพท์", "โทรศัพท์มือถือ", "เบอร์มือถือ"],
    ),
    (
        IdentifierType::BankAccount,
        &[
            "บัญชีธนาคาร",
            "เลขที่บัญชี",
            "หมายเลขบัญชี",
            "บัญชี",
            "iban",
            "swift",
            "bic",
        ],
    ),
    (IdentifierType::RoutingNumber, &["รหัสธนาคาร", "รหัสสาขา"]),
    (
        IdentifierType::DriverLicense,
        &["ใบขับขี่", "ใบอนุญาตขับขี่", "เลขที่ใบขับขี่"],
    ),
    (
        IdentifierType::Passport,
        &["หนังสือเดินทาง", "เลขที่หนังสือเดินทาง", "พาสปอร์ต"],
    ),
    (
        IdentifierType::Birthdate,
        &["วันเกิด", "วันเดือนปีเกิด", "วันที่เกิด"],
    ),
    (IdentifierType::IpAddress, &["ที่อยู่ไอพี", "หมายเลขไอพี"]),
    (IdentifierType::ApiKey, &["คีย์ api", "รหัสลับ", "โทเค็น"]),
    (
        IdentifierType::PersonalName,
        &["ชื่อ", "นามสกุล", "ชื่อ-นามสกุล", "ชื่อเต็ม"],
    ),
    (
        IdentifierType::Iban,
        &["iban", "หมายเลขบัญชีระหว่างประเทศ", "bic", "swift"],
    ),
    (
        IdentifierType::ThailandTnin,
        &["เลขประจำตัวประชาชน", "หมายเลขประจำตัวประชาชน", "บัตรประชาชน"],
    ),
];
