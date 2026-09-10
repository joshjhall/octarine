//! German (`de`) context keywords for identifier confidence scoring.
//!
//! Keyword data is sourced from Presidio's MIT-licensed `country_specific/de`
//! files and language YAMLs with attribution. Keywords are lowercase — the
//! analyzer lowercases the text window before matching.

use crate::primitives::identifiers::IdentifierType;

/// German (`de`) context keyword table, keyed by identifier type.
pub(super) static KEYWORDS: &[(IdentifierType, &[&str])] = &[
    (
        IdentifierType::Ssn,
        &[
            "sozialversicherungsnummer",
            "sozialversicherung",
            "rentenversicherungsnummer",
            "versicherungsnummer",
            "steuer-id",
            "steueridentifikationsnummer",
            "steuernummer",
        ],
    ),
    (
        IdentifierType::CreditCard,
        &[
            "kreditkarte",
            "kreditkartennummer",
            "kartennummer",
            "zahlungskarte",
            "debitkarte",
            "visa",
            "mastercard",
        ],
    ),
    (
        IdentifierType::Email,
        &[
            "e-mail",
            "email",
            "e-mail-adresse",
            "mailadresse",
            "kontakt",
        ],
    ),
    (
        IdentifierType::PhoneNumber,
        &[
            "telefon",
            "telefonnummer",
            "rufnummer",
            "mobiltelefon",
            "handynummer",
            "handy",
            "festnetz",
        ],
    ),
    (
        IdentifierType::BankAccount,
        &[
            "bankkonto",
            "kontonummer",
            "konto",
            "girokonto",
            "sparkonto",
            "bankleitzahl",
            "blz",
            "iban",
            "swift",
            "bic",
        ],
    ),
    (
        IdentifierType::RoutingNumber,
        &["bankleitzahl", "blz", "bankidentifikation"],
    ),
    (
        IdentifierType::DriverLicense,
        &[
            "führerschein",
            "fuehrerschein",
            "führerscheinnummer",
            "fahrerlaubnis",
        ],
    ),
    (
        IdentifierType::Passport,
        &[
            "reisepass",
            "pass",
            "passnummer",
            "reisepassnummer",
            "ausweis",
            "personalausweis",
        ],
    ),
    (
        IdentifierType::Birthdate,
        &["geburtsdatum", "geboren am", "geburtstag", "geb."],
    ),
    (
        IdentifierType::IpAddress,
        &["ip-adresse", "ip adresse", "netzwerkadresse", "host"],
    ),
    (
        IdentifierType::ApiKey,
        &[
            "api-schlüssel",
            "api schlüssel",
            "zugangsschlüssel",
            "geheimer schlüssel",
            "token",
        ],
    ),
    (
        IdentifierType::PersonalName,
        &[
            "name",
            "vorname",
            "nachname",
            "familienname",
            "vollständiger name",
        ],
    ),
    (
        IdentifierType::Iban,
        &["iban", "internationale bankkontonummer", "bic", "swift"],
    ),
];
