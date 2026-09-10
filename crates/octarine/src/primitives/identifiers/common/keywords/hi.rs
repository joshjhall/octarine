//! Hindi (`hi`) context keywords for identifier confidence scoring.
//!
//! Keyword data is sourced from Presidio's MIT-licensed language YAMLs with
//! attribution. Keywords are lowercase — the analyzer lowercases the text
//! window before matching.

use crate::primitives::identifiers::IdentifierType;

/// Hindi context keyword table, keyed by identifier type.
pub(super) static KEYWORDS: &[(IdentifierType, &[&str])] = &[
    (
        IdentifierType::Ssn,
        &["आधार संख्या", "स्थायी खाता संख्या", "करदाता संख्या"],
    ),
    (
        IdentifierType::CreditCard,
        &["क्रेडिट कार्ड", "कार्ड नंबर", "कार्ड संख्या", "डेबिट कार्ड"],
    ),
    (IdentifierType::Email, &["ईमेल", "ईमेल पता", "इलेक्ट्रॉनिक मेल"]),
    (
        IdentifierType::PhoneNumber,
        &["फ़ोन नंबर", "फोन नंबर", "मोबाइल नंबर", "दूरभाष"],
    ),
    (
        IdentifierType::BankAccount,
        &["बैंक खाता", "खाता संख्या", "खाता नंबर", "iban", "swift", "bic"],
    ),
    (
        IdentifierType::RoutingNumber,
        &["आईएफएससी", "बैंक कोड", "शाखा कोड"],
    ),
    (
        IdentifierType::DriverLicense,
        &["ड्राइविंग लाइसेंस", "चालक अनुज्ञप्ति", "लाइसेंस नंबर"],
    ),
    (
        IdentifierType::Passport,
        &["पासपोर्ट", "पासपोर्ट संख्या", "पासपोर्ट नंबर"],
    ),
    (
        IdentifierType::Birthdate,
        &["जन्म तिथि", "जन्मदिन", "जन्म दिनांक"],
    ),
    (IdentifierType::IpAddress, &["आईपी पता", "नेटवर्क पता"]),
    (IdentifierType::ApiKey, &["एपीआई कुंजी", "टोकन", "प्रमाणीकरण"]),
    (
        IdentifierType::PersonalName,
        &["नाम", "पूरा नाम", "उपनाम", "प्रथम नाम"],
    ),
    (
        IdentifierType::Iban,
        &["iban", "अंतर्राष्ट्रीय खाता संख्या", "bic", "swift"],
    ),
    (
        IdentifierType::IndiaAadhaar,
        &["आधार", "आधार संख्या", "आधार नंबर", "आधार कार्ड"],
    ),
    (
        IdentifierType::IndiaPan,
        &["पैन", "पैन कार्ड", "पैन नंबर", "स्थायी खाता संख्या"],
    ),
];
