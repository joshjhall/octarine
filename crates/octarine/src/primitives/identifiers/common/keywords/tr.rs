//! Turkish (`tr`) context keywords for identifier confidence scoring.
//!
//! Keyword data is sourced from Presidio's MIT-licensed `country_specific/tr`
//! files and language YAMLs with attribution. Keywords are lowercase — the
//! analyzer lowercases the text window before matching.
//!
//! # Turkish casing
//!
//! Turkish distinguishes dotted and dotless `i`. Rust's `to_lowercase` is
//! locale-independent, so `I` lowercases to `i` (not `ı`). Every entry below is
//! written in already-lowercase form and satisfies `kw == kw.to_lowercase()`;
//! `test_all_keywords_are_lowercase` enforces this.

use crate::primitives::identifiers::IdentifierType;

/// Turkish (`tr`) context keyword table, keyed by identifier type.
pub(super) static KEYWORDS: &[(IdentifierType, &[&str])] = &[
    (
        IdentifierType::Ssn,
        &[
            "tc kimlik",
            "kimlik numarası",
            "kimlik no",
            "sosyal güvenlik numarası",
            "vergi numarası",
        ],
    ),
    (
        IdentifierType::CreditCard,
        &[
            "kredi kartı",
            "kart numarası",
            "kart no",
            "banka kartı",
            "visa",
            "mastercard",
        ],
    ),
    (
        IdentifierType::Email,
        &["e-posta", "eposta", "e-posta adresi", "iletişim"],
    ),
    (
        IdentifierType::PhoneNumber,
        &["telefon", "telefon numarası", "cep telefonu", "cep no"],
    ),
    (
        IdentifierType::BankAccount,
        &[
            "banka hesabı",
            "hesap numarası",
            "hesap no",
            "iban",
            "swift",
            "bic",
        ],
    ),
    (IdentifierType::RoutingNumber, &["banka kodu", "şube kodu"]),
    (
        IdentifierType::DriverLicense,
        &["ehliyet", "sürücü belgesi", "ehliyet numarası"],
    ),
    (
        IdentifierType::Passport,
        &["pasaport", "pasaport numarası", "pasaport no"],
    ),
    (
        IdentifierType::Birthdate,
        &["doğum tarihi", "doğum günü", "doğumlu"],
    ),
    (IdentifierType::IpAddress, &["ip adresi", "ağ adresi"]),
    (
        IdentifierType::ApiKey,
        &["api anahtarı", "gizli anahtar", "erişim anahtarı", "token"],
    ),
    (
        IdentifierType::PersonalName,
        &["ad", "soyad", "isim", "ad soyad", "tam ad"],
    ),
    (
        IdentifierType::Iban,
        &["iban", "uluslararası hesap numarası", "bic", "swift"],
    ),
];
