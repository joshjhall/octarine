//! French (`fr`) context keywords for identifier confidence scoring.
//!
//! Keyword data is sourced from Presidio's MIT-licensed `country_specific/fr`
//! files and language YAMLs with attribution. Keywords are lowercase — the
//! analyzer lowercases the text window before matching.

use crate::primitives::identifiers::IdentifierType;

/// French (`fr`) context keyword table, keyed by identifier type.
pub(super) static KEYWORDS: &[(IdentifierType, &[&str])] = &[
    (
        IdentifierType::Ssn,
        &[
            "numéro de sécurité sociale",
            "numero de securite sociale",
            "sécurité sociale",
            "securite sociale",
            "numéro insee",
            "insee",
        ],
    ),
    (
        IdentifierType::CreditCard,
        &[
            "carte de crédit",
            "carte de credit",
            "carte bancaire",
            "numéro de carte",
            "numero de carte",
            "carte de débit",
            "visa",
            "mastercard",
        ],
    ),
    (
        IdentifierType::Email,
        &[
            "adresse électronique",
            "adresse electronique",
            "courriel",
            "e-mail",
            "email",
            "contact",
        ],
    ),
    (
        IdentifierType::PhoneNumber,
        &[
            "téléphone",
            "telephone",
            "numéro de téléphone",
            "numero de telephone",
            "portable",
            "mobile",
            "fixe",
        ],
    ),
    (
        IdentifierType::BankAccount,
        &[
            "compte bancaire",
            "numéro de compte",
            "numero de compte",
            "compte courant",
            "compte épargne",
            "rib",
            "iban",
            "swift",
            "bic",
        ],
    ),
    (
        IdentifierType::RoutingNumber,
        &["code banque", "code guichet", "rib", "code établissement"],
    ),
    (
        IdentifierType::DriverLicense,
        &[
            "permis de conduire",
            "numéro de permis",
            "numero de permis",
            "permis",
        ],
    ),
    (
        IdentifierType::Passport,
        &[
            "passeport",
            "numéro de passeport",
            "numero de passeport",
            "titre de voyage",
        ],
    ),
    (
        IdentifierType::Birthdate,
        &[
            "date de naissance",
            "né le",
            "ne le",
            "née le",
            "anniversaire",
        ],
    ),
    (
        IdentifierType::IpAddress,
        &["adresse ip", "ip", "adresse réseau", "adresse reseau"],
    ),
    (
        IdentifierType::ApiKey,
        &[
            "clé api",
            "cle api",
            "clé secrète",
            "jeton",
            "jeton d'accès",
        ],
    ),
    (
        IdentifierType::PersonalName,
        &["nom", "prénom", "prenom", "nom de famille", "nom complet"],
    ),
    (
        IdentifierType::Iban,
        &["iban", "numéro de compte international", "bic", "swift"],
    ),
];
