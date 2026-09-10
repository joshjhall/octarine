//! Italian (`it`) context keywords for identifier confidence scoring.
//!
//! Keyword data is sourced from Presidio's MIT-licensed `country_specific/it`
//! files and language YAMLs with attribution. Keywords are lowercase — the
//! analyzer lowercases the text window before matching.

use crate::primitives::identifiers::IdentifierType;

/// Italian (`it`) context keyword table, keyed by identifier type.
pub(super) static KEYWORDS: &[(IdentifierType, &[&str])] = &[
    (
        IdentifierType::Ssn,
        &[
            "codice fiscale",
            "numero di previdenza sociale",
            "previdenza sociale",
            "tessera sanitaria",
        ],
    ),
    (
        IdentifierType::CreditCard,
        &[
            "carta di credito",
            "numero di carta",
            "numero carta",
            "carta di debito",
            "visa",
            "mastercard",
        ],
    ),
    (
        IdentifierType::Email,
        &[
            "indirizzo email",
            "posta elettronica",
            "e-mail",
            "email",
            "contatto",
        ],
    ),
    (
        IdentifierType::PhoneNumber,
        &[
            "telefono",
            "numero di telefono",
            "numero telefonico",
            "cellulare",
            "fisso",
        ],
    ),
    (
        IdentifierType::BankAccount,
        &[
            "conto bancario",
            "numero di conto",
            "numero conto",
            "conto corrente",
            "iban",
            "swift",
            "bic",
        ],
    ),
    (
        IdentifierType::RoutingNumber,
        &["codice abi", "codice cab", "coordinate bancarie"],
    ),
    (
        IdentifierType::DriverLicense,
        &[
            "patente",
            "patente di guida",
            "numero di patente",
            "numero patente",
        ],
    ),
    (
        IdentifierType::Passport,
        &["passaporto", "numero di passaporto", "numero passaporto"],
    ),
    (
        IdentifierType::Birthdate,
        &["data di nascita", "nato il", "nata il", "compleanno"],
    ),
    (
        IdentifierType::IpAddress,
        &["indirizzo ip", "ip", "indirizzo di rete"],
    ),
    (
        IdentifierType::ApiKey,
        &["chiave api", "chiave segreta", "token", "token di accesso"],
    ),
    (
        IdentifierType::PersonalName,
        &["nome", "cognome", "nome completo", "nominativo"],
    ),
    (
        IdentifierType::Iban,
        &["iban", "coordinate bancarie internazionali", "bic", "swift"],
    ),
    (
        IdentifierType::ItalyFiscalCode,
        &[
            "codice fiscale",
            "cod. fiscale",
            "cod fiscale",
            "codice contribuente",
            "partita iva",
        ],
    ),
];
