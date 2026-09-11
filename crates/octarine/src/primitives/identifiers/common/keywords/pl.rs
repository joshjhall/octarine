//! Polish (`pl`) context keywords for identifier confidence scoring.
//!
//! Keyword data is sourced from Presidio's MIT-licensed `country_specific/pl`
//! files and language YAMLs with attribution. Keywords are lowercase — the
//! analyzer lowercases the text window before matching.

use crate::primitives::identifiers::IdentifierType;

/// Polish (`pl`) context keyword table, keyed by identifier type.
pub(super) static KEYWORDS: &[(IdentifierType, &[&str])] = &[
    (
        IdentifierType::Ssn,
        &[
            "pesel",
            "numer pesel",
            "numer ubezpieczenia społecznego",
            "nip",
        ],
    ),
    (
        IdentifierType::CreditCard,
        &[
            "karta kredytowa",
            "numer karty",
            "karta płatnicza",
            "karta debetowa",
            "visa",
            "mastercard",
        ],
    ),
    (
        IdentifierType::Email,
        &["adres e-mail", "e-mail", "email", "poczta elektroniczna"],
    ),
    (
        IdentifierType::PhoneNumber,
        &["telefon", "numer telefonu", "komórka", "telefon komórkowy"],
    ),
    (
        IdentifierType::BankAccount,
        &[
            "konto bankowe",
            "numer konta",
            "numer rachunku",
            "rachunek bankowy",
            "iban",
            "swift",
            "bic",
        ],
    ),
    (
        IdentifierType::RoutingNumber,
        &["numer rozliczeniowy", "kod banku"],
    ),
    (
        IdentifierType::DriverLicense,
        &["prawo jazdy", "numer prawa jazdy"],
    ),
    (IdentifierType::Passport, &["paszport", "numer paszportu"]),
    (
        IdentifierType::Birthdate,
        &["data urodzenia", "urodzony", "urodzona", "urodziny"],
    ),
    (
        IdentifierType::IpAddress,
        &["adres ip", "ip", "adres sieciowy"],
    ),
    (
        IdentifierType::ApiKey,
        &["klucz api", "tajny klucz", "token", "token dostępu"],
    ),
    (
        IdentifierType::PersonalName,
        &["imię", "nazwisko", "imię i nazwisko", "pełne imię"],
    ),
    (
        IdentifierType::Iban,
        &["iban", "międzynarodowy numer rachunku", "bic", "swift"],
    ),
    (
        IdentifierType::PolandPesel,
        &[
            "pesel",
            "numer pesel",
            "numer ewidencyjny",
            "powszechny elektroniczny system ewidencji ludności",
        ],
    ),
];
