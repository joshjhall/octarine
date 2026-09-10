//! Finnish (`fi`) context keywords for identifier confidence scoring.
//!
//! Keyword data is sourced from Presidio's MIT-licensed `country_specific/fi`
//! files and language YAMLs with attribution. Keywords are lowercase — the
//! analyzer lowercases the text window before matching.

use crate::primitives::identifiers::IdentifierType;

/// Finnish (`fi`) context keyword table, keyed by identifier type.
pub(super) static KEYWORDS: &[(IdentifierType, &[&str])] = &[
    (
        IdentifierType::Ssn,
        &[
            "henkilötunnus",
            "henkilotunnus",
            "hetu",
            "sosiaaliturvatunnus",
            "sotu",
        ],
    ),
    (
        IdentifierType::CreditCard,
        &[
            "luottokortti",
            "luottokortin numero",
            "kortin numero",
            "maksukortti",
            "pankkikortti",
            "visa",
            "mastercard",
        ],
    ),
    (
        IdentifierType::Email,
        &[
            "sähköposti",
            "sahkoposti",
            "sähköpostiosoite",
            "yhteystiedot",
        ],
    ),
    (
        IdentifierType::PhoneNumber,
        &["puhelin", "puhelinnumero", "matkapuhelin", "gsm"],
    ),
    (
        IdentifierType::BankAccount,
        &["pankkitili", "tilinumero", "tili", "iban", "swift", "bic"],
    ),
    (
        IdentifierType::RoutingNumber,
        &["pankkitunnus", "pankin tunnus"],
    ),
    (
        IdentifierType::DriverLicense,
        &["ajokortti", "ajokortin numero", "ajokorttinumero"],
    ),
    (
        IdentifierType::Passport,
        &["passi", "passin numero", "passinumero"],
    ),
    (
        IdentifierType::Birthdate,
        &["syntymäaika", "syntymaaika", "syntynyt", "syntymäpäivä"],
    ),
    (
        IdentifierType::IpAddress,
        &["ip-osoite", "ip osoite", "verkko-osoite"],
    ),
    (
        IdentifierType::ApiKey,
        &["api-avain", "api avain", "salainen avain", "tunniste"],
    ),
    (
        IdentifierType::PersonalName,
        &["nimi", "etunimi", "sukunimi", "koko nimi"],
    ),
    (
        IdentifierType::Iban,
        &["iban", "kansainvälinen tilinumero", "bic", "swift"],
    ),
    (
        IdentifierType::FinlandHetu,
        &[
            "henkilötunnus",
            "henkilotunnus",
            "hetu",
            "henkilökohtainen tunnus",
            "sosiaaliturvatunnus",
        ],
    ),
];
