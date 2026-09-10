//! Arabic (`ar`) context keywords for identifier confidence scoring.
//!
//! Keyword data is sourced from Presidio's MIT-licensed language YAMLs with
//! attribution. Keywords are lowercase — the analyzer lowercases the text
//! window before matching.

use crate::primitives::identifiers::IdentifierType;

/// Arabic context keyword table, keyed by identifier type.
pub(super) static KEYWORDS: &[(IdentifierType, &[&str])] = &[
    (
        IdentifierType::Ssn,
        &[
            "رقم الهوية",
            "رقم الضمان الاجتماعي",
            "الرقم الوطني",
            "رقم قومي",
        ],
    ),
    (
        IdentifierType::CreditCard,
        &["بطاقة ائتمان", "رقم البطاقة", "بطاقة الخصم", "بطاقة الدفع"],
    ),
    (
        IdentifierType::Email,
        &["بريد إلكتروني", "البريد الإلكتروني", "عنوان البريد"],
    ),
    (
        IdentifierType::PhoneNumber,
        &["رقم الهاتف", "هاتف محمول", "رقم الجوال", "الهاتف"],
    ),
    (
        IdentifierType::BankAccount,
        &[
            "حساب بنكي",
            "رقم الحساب",
            "حساب مصرفي",
            "iban",
            "swift",
            "bic",
        ],
    ),
    (IdentifierType::RoutingNumber, &["رمز البنك", "رمز الفرع"]),
    (
        IdentifierType::DriverLicense,
        &["رخصة القيادة", "رخصة قيادة", "رقم الرخصة"],
    ),
    (
        IdentifierType::Passport,
        &["جواز السفر", "رقم جواز السفر", "جواز سفر"],
    ),
    (
        IdentifierType::Birthdate,
        &["تاريخ الميلاد", "تاريخ الولادة", "عيد الميلاد"],
    ),
    (IdentifierType::IpAddress, &["عنوان ip", "عنوان الشبكة"]),
    (IdentifierType::ApiKey, &["مفتاح api", "رمز", "مصادقة"]),
    (
        IdentifierType::PersonalName,
        &["الاسم", "اسم", "الاسم الكامل", "اسم العائلة"],
    ),
    (
        IdentifierType::Iban,
        &["iban", "رقم الحساب المصرفي الدولي", "bic", "swift"],
    ),
];
